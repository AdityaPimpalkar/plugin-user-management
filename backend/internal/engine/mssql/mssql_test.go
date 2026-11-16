package mssql

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"

	mssqldb "github.com/microsoft/go-mssqldb"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	kubefake "k8s.io/client-go/kubernetes/fake"

	"github.com/openeverest/plugin-user-management/backend/internal/engine"
)

var target = engine.Target{Namespace: "ns", Instance: "sql"}

func agObject(spec map[string]any, state string) *unstructured.Unstructured {
	if spec == nil {
		spec = map[string]any{}
	}
	spec["saPasswordSecret"] = "everest-secrets-sql"
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "mssql.solanica.io/v1alpha1",
		"kind":       "MSSQLAvailabilityGroup",
		"metadata":   map[string]any{"name": "sql", "namespace": "ns"},
		"spec":       spec,
		"status":     map[string]any{"state": state},
	}}
}

func instanceObject(spec map[string]any, state string) *unstructured.Unstructured {
	obj := agObject(spec, state)
	obj.SetKind("MSSQLInstance")
	return obj
}

func passwordSecret(name, value string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "ns"},
		Data:       map[string][]byte{"password": []byte(value)},
	}
}

type fakeSession struct {
	loginList   []login
	passwords   map[string]string
	dbs         []database
	executed    []stmt
	failOn      string
	idle        []int64
	busy        int
	killed      []int64
	lockHeld    bool
	underLock   []stmt
	lockedByOps bool
}

func (f *fakeSession) logins(context.Context) ([]login, error) { return f.loginList, nil }
func (f *fakeSession) passwordMatches(_ context.Context, name, password string) (bool, error) {
	return f.passwords[name] == password, nil
}
func (f *fakeSession) databases(context.Context) ([]database, error) { return f.dbs, nil }
func (f *fakeSession) exec(stmts []stmt) error {
	for _, s := range stmts {
		if f.failOn != "" && strings.Contains(s.sql, f.failOn) {
			return mssqldb.Error{Number: 15118, Message: "Password validation failed."}
		}
		f.executed = append(f.executed, s)
		if f.lockHeld {
			f.underLock = append(f.underLock, s)
		}
	}
	return nil
}
func (f *fakeSession) execTx(_ context.Context, stmts []stmt) error   { return f.exec(stmts) }
func (f *fakeSession) execEach(_ context.Context, stmts []stmt) error { return f.exec(stmts) }
func (f *fakeSession) databaseSessions(context.Context, string) ([]int64, int, error) {
	return f.idle, f.busy, nil
}
func (f *fakeSession) loginSessions(context.Context, string) ([]int64, error) { return f.idle, nil }
func (f *fakeSession) kill(_ context.Context, ids []int64) error {
	f.killed = append(f.killed, ids...)
	return nil
}
func (f *fakeSession) withAGLock(_ context.Context, fn func() error) error {
	if f.lockedByOps {
		return engine.ErrInProgress
	}
	f.lockHeld = true
	defer func() { f.lockHeld = false }()
	return fn()
}
func (f *fakeSession) close() {}

func (f *fakeSession) sqls() []string {
	out := make([]string, len(f.executed))
	for i, s := range f.executed {
		out[i] = s.database + ": " + s.sql
	}
	return out
}

func newTestEngine(s *fakeSession, obj *unstructured.Unstructured, secrets ...runtime.Object) *Engine {
	gvrs := map[schema.GroupVersionResource]string{
		agResource:       "MSSQLAvailabilityGroupList",
		instanceResource: "MSSQLInstanceList",
	}
	var objects []runtime.Object
	if obj != nil {
		objects = append(objects, obj)
	}
	return &Engine{
		kube: kubefake.NewClientset(secrets...),
		dyn:  dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), gvrs, objects...),
		dial: func(context.Context, cluster) (session, error) { return s, nil },
	}
}

func managedLogin(name string) login {
	return login{name: name, sid: loginSID(name), kind: "S", managed: true}
}

func managedDB(name string, dbo []byte, users ...dbUser) database {
	return database{name: name, id: 5, state: "ONLINE", detailed: true, marker: managedValue, dboSID: dbo, users: users}
}

var systemDatabases = []database{{name: "master", id: 1, state: "ONLINE"}, {name: "tempdb", id: 2, state: "ONLINE"}}

func TestNormalizeRoles(t *testing.T) {
	got, err := normalizeRoles([]engine.RoleGrant{
		{Role: roleRead, Database: "orders"},
		{Role: roleDBOwner, Database: "orders"},
		{Role: roleReadWrite, Database: "orders"},
		{Role: roleMonitor, Database: "orders"},
		{Role: roleReadWrite, Database: "stock"},
		{Role: roleMonitor},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []engine.RoleGrant{{Role: roleDBOwner, Database: "orders"}, {Role: roleMonitor}, {Role: roleReadWrite, Database: "stock"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for _, bad := range [][]engine.RoleGrant{
		{{Role: "sysadmin"}},
		{{Role: roleRead}},
		{{Role: roleRead, Database: "Orders"}},
	} {
		if _, err := normalizeRoles(bad); !errors.Is(err, engine.ErrInvalid) {
			t.Errorf("%v: err = %v, want ErrInvalid", bad, err)
		}
	}
}

// The UI rejects a role next to one that includes it on the same database:
// those are exactly the roles normalizeRoles drops.
func TestRoleIncludesMatchNormalize(t *testing.T) {
	for _, r := range roleCatalog {
		for _, other := range roleCatalog {
			if r.Name == other.Name || r.Scope != engine.ScopeDatabase || other.Scope != engine.ScopeDatabase {
				continue
			}
			got, err := normalizeRoles([]engine.RoleGrant{{Role: r.Name, Database: "orders"}, {Role: other.Name, Database: "orders"}})
			if err != nil {
				t.Fatal(err)
			}
			kept := []engine.RoleGrant{{Role: r.Name, Database: "orders"}}
			if slices.Contains(r.Includes, other.Name) != reflect.DeepEqual(got, kept) {
				t.Errorf("%s with %s = %v, but %s includes %v", r.Name, other.Name, got, r.Name, r.Includes)
			}
		}
	}
}

func TestValidateUser(t *testing.T) {
	for _, name := range []string{"sa", "SA", "openeverest_managed", "##MS_Agent##", `DOMAIN\user`, "NT SERVICE\\x", strings.Repeat("a", 129)} {
		if err := validateUser(engine.DesiredUser{Username: name}); !errors.Is(err, engine.ErrInvalid) {
			t.Errorf("%q: err = %v, want ErrInvalid", name, err)
		}
	}
	if err := validateUser(engine.DesiredUser{Username: "app-user.1"}); err != nil {
		t.Fatal(err)
	}
}

func TestClusterFrom(t *testing.T) {
	ag := clusterFrom(agObject(map[string]any{"port": int64(1500)}, "Ready"), true)
	if ag.host != "sql-primary.ns.svc.cluster.local" || ag.port != 1500 || ag.ag != "sql-ag" || !ag.tls ||
		ag.tlsSecret != "sql-tls-certs" || ag.tlsServerName != "sql.ns.svc.cluster.local" || !ag.ready || ag.unsupported != "" {
		t.Fatalf("AG: %+v", ag)
	}
	named := clusterFrom(agObject(map[string]any{
		"availabilityGroup": map[string]any{"name": "orders", "contained": true},
		"tls":               map[string]any{"certificateSecret": "mine"},
	}, "Creating"), true)
	if named.ag != "orders" || named.unsupported == "" || named.tlsSecret != "mine" || named.tlsServerName != "" || named.ready {
		t.Fatalf("contained AG: %+v", named)
	}
	single := clusterFrom(instanceObject(map[string]any{"size": int64(1), "tls": map[string]any{"enabled": false}}, "Ready"), false)
	if single.host != "sql.ns.svc.cluster.local" || single.isAG() || single.tls || single.unsupported != "" {
		t.Fatalf("standalone: %+v", single)
	}
	if many := clusterFrom(instanceObject(map[string]any{"size": int64(3)}, "Ready"), false); many.unsupported == "" {
		t.Fatalf("standalone of 3 is supported: %+v", many)
	}
}

func TestNotReady(t *testing.T) {
	for name, e := range map[string]*Engine{
		"missing":      newTestEngine(&fakeSession{}, nil),
		"initializing": newTestEngine(&fakeSession{}, agObject(nil, "Creating")),
		"unsupported":  newTestEngine(&fakeSession{}, instanceObject(map[string]any{"size": int64(2)}, "Ready")),
	} {
		if _, err := e.ListUsers(context.Background(), target); !errors.Is(err, engine.ErrNotReady) {
			t.Errorf("%s: err = %v, want ErrNotReady", name, err)
		}
	}
}

func TestPlanLogin(t *testing.T) {
	stmts, err := planLogin("app", "Secret1x", true, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(stmts) != 4 || !strings.HasPrefix(stmts[0].sql, "CREATE LOGIN [app] WITH PASSWORD = N'Secret1x', SID = 0x") ||
		!strings.Contains(stmts[0].sql, "CHECK_POLICY = ON") ||
		stmts[1].sql != "ALTER SERVER ROLE [openeverest_managed] ADD MEMBER [app]" ||
		stmts[2].sql != "GRANT VIEW SERVER STATE TO [app]" || stmts[3].sql != "GRANT VIEW ANY DEFINITION TO [app]" {
		t.Fatalf("create: %v", stmts)
	}

	current := managedLogin("app")
	current.permissions = monitorPermissions
	stmts, err = planLogin("app", "Secret1x", false, &current, true)
	if err != nil {
		t.Fatal(err)
	}
	if want := []stmt{{sql: "REVOKE VIEW SERVER STATE FROM [app]"}, {sql: "REVOKE VIEW ANY DEFINITION FROM [app]"}}; !reflect.DeepEqual(stmts, want) {
		t.Fatalf("revoke: %v", stmts)
	}
	plain := managedLogin("app")
	if stmts, _ = planLogin("app", "it's", false, &plain, false); len(stmts) != 1 || stmts[0].sql != "ALTER LOGIN [app] WITH PASSWORD = N'it''s'" {
		t.Fatalf("password: %v", stmts)
	}
	for _, l := range []login{{name: "app", kind: "S"}, {name: "app", kind: "U", managed: true}} {
		if _, err := planLogin("app", "x", false, &l, false); !errors.As(err, new(errUnmanagedLogin)) {
			t.Errorf("%+v: err = %v, want errUnmanagedLogin", l, err)
		}
	}
}

func TestPlanDatabaseAccess(t *testing.T) {
	got := planDatabaseAccess("orders", "app", roleReadWrite, nil)
	want := []stmt{
		{database: "orders", sql: "CREATE USER [app] FOR LOGIN [app]"},
		{database: "orders", sql: "ALTER ROLE [db_datareader] ADD MEMBER [app]"},
		{database: "orders", sql: "ALTER ROLE [db_datawriter] ADD MEMBER [app]"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("create: %v", got)
	}
	existing := &dbUser{name: "app_user", roles: []string{"db_datareader", "db_datawriter", "db_owner"}}
	got = planDatabaseAccess("orders", "app", roleRead, existing)
	want = []stmt{
		{database: "orders", sql: "ALTER ROLE [db_datawriter] DROP MEMBER [app_user]"},
		{database: "orders", sql: "ALTER ROLE [db_owner] DROP MEMBER [app_user]"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("downgrade: %v", got)
	}
	if got := planDatabaseAccess("orders", "app", "", existing); !reflect.DeepEqual(got, []stmt{{database: "orders", sql: "DROP USER [app_user]"}}) {
		t.Fatalf("revoke: %v", got)
	}
	if got := planDatabaseAccess("orders", "app", "", nil); got != nil {
		t.Fatalf("none: %v", got)
	}
}

func TestSyncUsers(t *testing.T) {
	owner := managedLogin("owner")
	s := &fakeSession{
		loginList: []login{owner, {name: "sa", sid: []byte{1}, kind: "S"}, {name: "legacy", sid: []byte{9}, kind: "S"}},
		passwords: map[string]string{"owner": "OwnerPw1"},
		dbs: append(slices.Clone(systemDatabases),
			managedDB("orders", owner.sid),
			database{name: "legacydb", id: 6, state: "ONLINE", detailed: true, dboSID: []byte{1}},
			database{name: "offline", id: 7, state: "RESTORING"},
		),
	}
	e := newTestEngine(s, agObject(nil, "Ready"),
		passwordSecret("app-credentials", "AppPw1"), passwordSecret("owner-credentials", "OwnerPw1"), passwordSecret("legacy-credentials", "x"))
	users := []engine.DesiredUser{
		{Username: "app", Password: engine.SecretKeyRef{Name: "app-credentials", Key: "password"}, Roles: []engine.RoleGrant{
			{Role: roleRead, Database: "orders"}, {Role: roleRead, Database: "legacydb"}, {Role: roleRead, Database: "offline"}, {Role: roleRead, Database: "gone"},
		}},
		{Username: "owner", Password: engine.SecretKeyRef{Name: "owner-credentials", Key: "password"}, Roles: []engine.RoleGrant{{Role: roleDBOwner, Database: "orders"}}},
		{Username: "legacy", Password: engine.SecretKeyRef{Name: "legacy-credentials", Key: "password"}},
		{Username: "nopw", Password: engine.SecretKeyRef{Name: "missing", Key: "password"}},
	}
	if err := e.SyncUsers(context.Background(), target, users); err != nil {
		t.Fatal(err)
	}
	got := s.sqls()
	if len(got) != 5 || !strings.Contains(got[0], "CREATE SERVER ROLE [openeverest_managed]") ||
		!strings.HasPrefix(got[1], ": CREATE LOGIN [app]") ||
		got[2] != ": ALTER SERVER ROLE [openeverest_managed] ADD MEMBER [app]" ||
		got[3] != "orders: CREATE USER [app] FOR LOGIN [app]" ||
		got[4] != "orders: ALTER ROLE [db_datareader] ADD MEMBER [app]" {
		t.Fatalf("executed:\n%s", strings.Join(got, "\n"))
	}
	reason := e.PendingReason(context.Background(), target, "app")
	for _, want := range []string{`"legacydb" isn't managed`, `"offline" is restoring`, `"gone" doesn't exist`} {
		if !strings.Contains(reason, want) {
			t.Errorf("app reason %q lacks %q", reason, want)
		}
	}
	if reason := e.PendingReason(context.Background(), target, "legacy"); !strings.Contains(reason, "isn't managed by OpenEverest") {
		t.Errorf("legacy reason = %q", reason)
	}
	if reason := e.PendingReason(context.Background(), target, "nopw"); !strings.Contains(reason, `"missing" not found`) {
		t.Errorf("nopw reason = %q", reason)
	}

	// The owner is dbo of orders: its role there is reported as granted.
	listed, err := e.ListUsers(context.Background(), target)
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]engine.User{}
	for _, u := range listed {
		byName[u.Username] = u
	}
	if want := []engine.RoleGrant{{Role: roleDBOwner, Database: "orders"}}; !reflect.DeepEqual(byName["owner"].Roles, want) {
		t.Errorf("owner roles = %v, want %v", byName["owner"].Roles, want)
	}
	if !byName["sa"].System || byName["legacy"].System {
		t.Errorf("system: sa %v, legacy %v", byName["sa"].System, byName["legacy"].System)
	}
}

func TestSyncUsersServerError(t *testing.T) {
	s := &fakeSession{dbs: systemDatabases, failOn: "CREATE LOGIN"}
	e := newTestEngine(s, agObject(nil, "Ready"), passwordSecret("app-credentials", "short"))
	err := e.SyncUsers(context.Background(), target, []engine.DesiredUser{{Username: "app", Password: engine.SecretKeyRef{Name: "app-credentials", Key: "password"}}})
	if err != nil {
		t.Fatal(err)
	}
	if reason := e.PendingReason(context.Background(), target, "app"); reason != "SQL Server can't apply the user: Password validation failed." {
		t.Fatalf("reason = %q", reason)
	}
}

func TestListUsersGrants(t *testing.T) {
	app := managedLogin("app")
	app.permissions = []string{"VIEW SERVER STATE", "VIEW ANY DEFINITION", "CONNECT SQL"}
	half := managedLogin("half")
	half.permissions = []string{"VIEW SERVER STATE"}
	s := &fakeSession{
		loginList: []login{app, half},
		dbs: []database{
			managedDB("orders", []byte{1}, dbUser{name: "app", sid: app.sid, roles: []string{"db_datareader", "db_datawriter", operatorMarkerRole}}),
			managedDB("stock", []byte{1}, dbUser{name: "app", sid: app.sid, roles: []string{"db_datawriter"}}),
			{name: "other", id: 8, state: "ONLINE", detailed: true, users: []dbUser{{name: "app", sid: app.sid, roles: []string{"db_owner"}}}},
		},
	}
	users, err := newTestEngine(s, agObject(nil, "Ready")).ListUsers(context.Background(), target)
	if err != nil {
		t.Fatal(err)
	}
	if want := []engine.RoleGrant{{Role: roleMonitor}, {Role: roleReadWrite, Database: "orders"}}; !reflect.DeepEqual(users[0].Roles, want) {
		t.Errorf("app roles = %v, want %v", users[0].Roles, want)
	}
	if len(users[1].Roles) != 0 {
		t.Errorf("half roles = %v, want none", users[1].Roles)
	}
}

func TestDropUser(t *testing.T) {
	app := managedLogin("app")
	s := &fakeSession{
		loginList: []login{app},
		dbs:       append(slices.Clone(systemDatabases), managedDB("orders", []byte{1}, dbUser{name: "app", sid: app.sid})),
		idle:      []int64{51},
	}
	e := newTestEngine(s, agObject(nil, "Ready"))
	if err := e.DropUser(context.Background(), target, "app"); err != nil {
		t.Fatal(err)
	}
	if want := []string{"orders: DROP USER [app]", ": DROP LOGIN [app]"}; !reflect.DeepEqual(s.sqls(), want) {
		t.Fatalf("executed %v, want %v", s.sqls(), want)
	}
	if !reflect.DeepEqual(s.killed, []int64{51}) {
		t.Fatalf("killed %v", s.killed)
	}

	// Logins the plugin didn't create, or that own a database, stay.
	s = &fakeSession{loginList: []login{{name: "legacy", sid: []byte{9}, kind: "S"}, app}, dbs: []database{managedDB("orders", app.sid)}}
	e = newTestEngine(s, agObject(nil, "Ready"))
	if err := e.DropUser(context.Background(), target, "legacy"); err != nil || len(s.executed) != 0 {
		t.Fatalf("legacy: err %v, executed %v", err, s.sqls())
	}
	if err := e.DropUser(context.Background(), target, "app"); !errors.Is(err, engine.ErrInProgress) || len(s.executed) != 0 {
		t.Fatalf("owner: err %v, executed %v", err, s.sqls())
	}
}

func TestSyncDatabase(t *testing.T) {
	owner := managedLogin("owner")
	s := &fakeSession{loginList: []login{owner}, dbs: systemDatabases}
	e := newTestEngine(s, instanceObject(nil, "Ready"))
	want := engine.DesiredDatabase{Name: "orders", Owner: "owner"}
	// The fake doesn't create it: the database isn't there yet.
	if err := e.SyncDatabase(context.Background(), target, want); !errors.Is(err, engine.ErrInProgress) {
		t.Fatalf("err = %v, want ErrInProgress", err)
	}
	if got := s.sqls(); !reflect.DeepEqual(got, []string{": CREATE DATABASE [orders]"}) {
		t.Fatalf("executed %v", got)
	}

	// A database the owner had a user in, created but not yet marked.
	s.executed = nil
	s.dbs = append(slices.Clone(systemDatabases), database{
		name: "orders", id: 5, state: "ONLINE", detailed: true, dboSID: []byte{1},
		users: []dbUser{{name: "owner_user", sid: owner.sid}},
	})
	if err := e.SyncDatabase(context.Background(), target, want); err != nil {
		t.Fatal(err)
	}
	if got, want := s.sqls(), []string{
		"orders: EXEC sys.sp_addextendedproperty @name = N'openeverest_managed', @value = N'Managed by OpenEverest'",
		"orders: DROP USER [owner_user]",
		": ALTER AUTHORIZATION ON DATABASE::[orders] TO [owner]",
	}; !reflect.DeepEqual(got, want) {
		t.Fatalf("executed:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}

	// Applied, but not yet in the Availability Group.
	s.executed = nil
	s.dbs = []database{managedDB("orders", owner.sid)}
	e = newTestEngine(s, agObject(nil, "Ready"))
	if err := e.SyncDatabase(context.Background(), target, want); !errors.Is(err, engine.ErrInProgress) || len(s.executed) != 0 {
		t.Fatalf("not in AG: err %v, executed %v", err, s.sqls())
	}
	s.dbs[0].inAG = true
	if err := e.SyncDatabase(context.Background(), target, want); err != nil {
		t.Fatal(err)
	}
	if err := e.SyncDatabase(context.Background(), target, engine.DesiredDatabase{Name: "orders", Owner: "nobody"}); !errors.Is(err, engine.ErrInProgress) {
		t.Fatalf("missing owner: err = %v", err)
	}
}

func TestListDatabases(t *testing.T) {
	owner := managedLogin("owner")
	s := &fakeSession{loginList: []login{owner}, dbs: []database{
		{name: "master", id: 1, state: "ONLINE", ownerName: "sa"},
		// After a failover, sys.databases names another owner than dbo.
		func() database { d := managedDB("orders", owner.sid); d.ownerName = "sa"; return d }(),
	}}
	got, err := newTestEngine(s, agObject(nil, "Ready")).ListDatabases(context.Background(), target)
	if err != nil {
		t.Fatal(err)
	}
	want := []engine.Database{{Name: "master", Owner: "sa", System: true}, {Name: "orders", Owner: "owner"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestReleaseDatabase(t *testing.T) {
	inAG := managedDB("orders", []byte{1})
	inAG.inAG = true
	s := &fakeSession{dbs: []database{inAG, {name: "legacy", id: 6, state: "ONLINE", detailed: true}}, idle: []int64{60, 61}}
	e := newTestEngine(s, agObject(map[string]any{"availabilityGroup": map[string]any{"name": "ag1"}}, "Ready"))
	if err := e.ReleaseDatabase(context.Background(), target, "orders", true); err != nil {
		t.Fatal(err)
	}
	want := []stmt{{sql: "ALTER AVAILABILITY GROUP [ag1] REMOVE DATABASE [orders]"}, {sql: "DROP DATABASE [orders]"}}
	if !reflect.DeepEqual(s.underLock, want) || !reflect.DeepEqual(s.killed, []int64{60, 61}) {
		t.Fatalf("under lock %v, killed %v", s.underLock, s.killed)
	}

	s = &fakeSession{dbs: []database{inAG}, busy: 1}
	if err := newTestEngine(s, agObject(nil, "Ready")).ReleaseDatabase(context.Background(), target, "orders", true); !errors.Is(err, engine.ErrInProgress) || len(s.executed) != 0 {
		t.Fatalf("busy: err %v, executed %v", err, s.sqls())
	}
	s = &fakeSession{dbs: []database{inAG}, lockedByOps: true}
	if err := newTestEngine(s, agObject(nil, "Ready")).ReleaseDatabase(context.Background(), target, "orders", true); !errors.Is(err, engine.ErrInProgress) || len(s.executed) != 0 {
		t.Fatalf("locked: err %v, executed %v", err, s.sqls())
	}

	s = &fakeSession{dbs: []database{inAG, {name: "legacy", id: 6, state: "ONLINE", detailed: true}}}
	e = newTestEngine(s, agObject(nil, "Ready"))
	if err := e.ReleaseDatabase(context.Background(), target, "legacy", true); err != nil || len(s.executed) != 0 {
		t.Fatalf("unmanaged: err %v, executed %v", err, s.sqls())
	}
	if err := e.ReleaseDatabase(context.Background(), target, "orders", false); err != nil {
		t.Fatal(err)
	}
	if got := s.sqls(); !reflect.DeepEqual(got, []string{"orders: EXEC sys.sp_dropextendedproperty @name = N'openeverest_managed'"}) {
		t.Fatalf("retain: %v", got)
	}
}

func TestConnectionURI(t *testing.T) {
	uri, err := newTestEngine(nil, agObject(nil, "Creating")).ConnectionURI(context.Background(), target, "app", "p@ss")
	if err != nil {
		t.Fatal(err)
	}
	if uri != "sqlserver://app:p%40ss@sql-primary.ns.svc.cluster.local:1433" {
		t.Fatalf("uri = %q", uri)
	}
}
