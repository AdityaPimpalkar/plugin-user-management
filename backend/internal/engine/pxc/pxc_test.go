package pxc

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/go-sql-driver/mysql"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	kubefake "k8s.io/client-go/kubernetes/fake"

	"github.com/openeverest/plugin-user-management/backend/internal/engine"
)

var target = engine.Target{Namespace: "ns", Instance: "db"}

// allPrivileges are mysql.db's privilege columns on MySQL 8.0.
var allPrivileges = []string{
	"Alter_priv", "Alter_routine_priv", "Create_priv", "Create_routine_priv", "Create_tmp_table_priv",
	"Create_view_priv", "Delete_priv", "Drop_priv", "Event_priv", "Execute_priv", "Grant_priv",
	"Index_priv", "Insert_priv", "Lock_tables_priv", "References_priv", "Select_priv",
	"Show_view_priv", "Trigger_priv", "Update_priv",
}

func pxcObject(spec map[string]any, state string) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "pxc.percona.com/v1",
		"kind":       "PerconaXtraDBCluster",
		"metadata":   map[string]any{"name": "db", "namespace": "ns"},
		"spec":       spec,
		"status":     map[string]any{"state": state},
	}}
}

type fakeSession struct {
	snap     *snapshot
	executed []string
	failOn   string
}

func (f *fakeSession) ensureCatalog(context.Context) error         { return nil }
func (f *fakeSession) snapshot(context.Context) (*snapshot, error) { return f.snap, nil }
func (f *fakeSession) close()                                      {}
func (f *fakeSession) exec(_ context.Context, stmts []stmt) error {
	for _, s := range stmts {
		if f.failOn != "" && strings.Contains(s.sql, f.failOn) {
			return &mysql.MySQLError{Number: 1819, Message: "Your password does not satisfy the current policy requirements"}
		}
		f.executed = append(f.executed, s.sql)
	}
	return nil
}

func emptySnapshot() *snapshot {
	return &snapshot{
		accounts:         map[string]*mysqlAccount{},
		grants:           map[string]map[string][]string{},
		allPrivileges:    allPrivileges,
		schemas:          []string{"information_schema", "mysql", "performance_schema", "sys", catalogDatabase},
		managedUsers:     map[string]string{},
		managedDatabases: map[string]string{},
	}
}

func newTestEngine(t *testing.T, s *fakeSession, spec map[string]any) *Engine {
	t.Helper()
	if spec == nil {
		spec = map[string]any{"haproxy": map[string]any{"enabled": true}}
	}
	gvr := schema.GroupVersionResource{Group: "pxc.percona.com", Version: "v1", Resource: "perconaxtradbclusters"}
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(),
		map[schema.GroupVersionResource]string{gvr: "PerconaXtraDBClusterList"}, pxcObject(spec, "ready"))
	kube := kubefake.NewSimpleClientset(
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "everest-secrets-db", Namespace: "ns"}, Data: map[string][]byte{"root": []byte("rootpw")}},
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "db-ssl", Namespace: "ns"}, Data: map[string][]byte{"ca.crt": []byte("ca")}},
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "app-pw", Namespace: "ns"}, Data: map[string][]byte{"password": []byte("s3cret")}},
	)
	e := New(kube, dyn)
	e.dial = func(_ context.Context, c cluster) (session, error) {
		if c.rootPassword != "rootpw" || string(c.caPEM) != "ca" {
			t.Fatalf("dialed without credentials: %+v", c)
		}
		return s, nil
	}
	return e
}

func appUser(roles ...engine.RoleGrant) engine.DesiredUser {
	return engine.DesiredUser{Username: "app", Roles: roles, Password: engine.SecretKeyRef{Name: "app-pw", Key: "password"}}
}

func managedApp(t *testing.T, snap *snapshot) {
	t.Helper()
	fp, err := fingerprint("s3cret")
	if err != nil {
		t.Fatal(err)
	}
	snap.accounts["app"] = &mysqlAccount{name: "app", anyHost: true}
	snap.managedUsers["app"] = fp
}

func TestClusterFrom(t *testing.T) {
	c := clusterFrom(pxcObject(map[string]any{"proxysql": map[string]any{"enabled": true}, "secretsName": "custom"}, "ready"))
	if c.host != "db-proxysql.ns.svc.cluster.local" || c.secretsName != "custom" || c.sslSecret != "db-ssl" || !c.tls || !c.ready() {
		t.Fatalf("proxysql cluster = %+v", c)
	}
	c = clusterFrom(pxcObject(map[string]any{
		"haproxy":     map[string]any{"enabled": true},
		"tls":         map[string]any{"enabled": false},
		"unsafeFlags": map[string]any{"tls": true},
	}, "initializing"))
	if c.host != "db-haproxy.ns.svc.cluster.local" || c.tls || c.ready() || c.serverName() != "db-pxc" {
		t.Fatalf("haproxy cluster = %+v", c)
	}
}

func TestConnectWaitsForReadyCluster(t *testing.T) {
	gvr := schema.GroupVersionResource{Group: "pxc.percona.com", Version: "v1", Resource: "perconaxtradbclusters"}
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(),
		map[schema.GroupVersionResource]string{gvr: "PerconaXtraDBClusterList"}, pxcObject(map[string]any{}, "initializing"))
	e := New(kubefake.NewSimpleClientset(), dyn)
	if _, err := e.ListUsers(context.Background(), target); !errors.Is(err, engine.ErrNotReady) {
		t.Fatalf("ListUsers() error = %v, want ErrNotReady", err)
	}
}

func TestSyncUsersCreatesUser(t *testing.T) {
	s := &fakeSession{snap: emptySnapshot()}
	e := newTestEngine(t, s, nil)
	user := appUser(engine.RoleGrant{Role: roleReadWrite, Database: "orders"}, engine.RoleGrant{Role: roleMonitor})
	if err := e.SyncUsers(context.Background(), target, []engine.DesiredUser{user}); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"INSERT IGNORE INTO `openeverest_user_management`.`managed_users` (name) VALUES (?)",
		"CREATE USER IF NOT EXISTS 'app'@'%' IDENTIFIED BY ?",
		"UPDATE `openeverest_user_management`.`managed_users` SET password_fingerprint = ? WHERE name = ?",
		"GRANT SELECT, INSERT, UPDATE, DELETE ON `orders`.* TO 'app'@'%'",
		"GRANT PROCESS, REPLICATION CLIENT ON *.* TO 'app'@'%'",
	}
	if !slices.Equal(s.executed, want) {
		t.Fatalf("executed:\n%s\nwant:\n%s", strings.Join(s.executed, "\n"), strings.Join(want, "\n"))
	}
	if p := e.UserProblem(target, "app"); p != "" {
		t.Fatalf("UserProblem() = %q", p)
	}
}

func TestSyncUsersReconcilesPrivileges(t *testing.T) {
	snap := emptySnapshot()
	managedApp(t, snap)
	snap.accounts["app"].process = true
	snap.managedDatabases["owned"] = "app"
	snap.grants["app"] = map[string][]string{
		`orders`: {"Select_priv"},
		`stale`:  {"Select_priv"},
		`owned`:  allPrivileges,
		`kept`:   rolePrivileges[roleRead],
	}
	s := &fakeSession{snap: snap}
	e := newTestEngine(t, s, nil)
	user := appUser(
		engine.RoleGrant{Role: roleDBOwner, Database: "orders"},
		engine.RoleGrant{Role: roleRead, Database: "kept"},
		engine.RoleGrant{Role: roleRead, Database: "owned"},
	)
	if err := e.SyncUsers(context.Background(), target, []engine.DesiredUser{user}); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"REVOKE ALL PRIVILEGES ON `orders`.* FROM 'app'@'%'",
		"GRANT ALL PRIVILEGES ON `orders`.* TO 'app'@'%' WITH GRANT OPTION",
		"REVOKE ALL PRIVILEGES ON `stale`.* FROM 'app'@'%'",
		"REVOKE PROCESS, REPLICATION CLIENT ON *.* FROM 'app'@'%'",
	}
	if !slices.Equal(s.executed, want) {
		t.Fatalf("executed:\n%s\nwant:\n%s", strings.Join(s.executed, "\n"), strings.Join(want, "\n"))
	}

	snap.grants["app"] = map[string][]string{`orders`: allPrivileges, `kept`: {"Select_priv"}, `owned`: allPrivileges}
	snap.accounts["app"].process = false
	users, err := e.ListUsers(context.Background(), target)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := e.NormalizeRoles(users[0].Roles)
	if !engine.SameRoles(got, user.Roles) {
		t.Fatalf("ListUsers() roles = %+v, want %+v", users[0].Roles, user.Roles)
	}
}

func TestSyncUsersChangesPassword(t *testing.T) {
	snap := emptySnapshot()
	managedApp(t, snap)
	snap.managedUsers["app"], _ = fingerprint("old")
	s := &fakeSession{snap: snap}
	e := newTestEngine(t, s, nil)
	if err := e.SyncUsers(context.Background(), target, []engine.DesiredUser{appUser()}); err != nil {
		t.Fatal(err)
	}
	if len(s.executed) != 2 || s.executed[0] != "ALTER USER 'app'@'%' IDENTIFIED BY ?" {
		t.Fatalf("executed = %q", s.executed)
	}
}

func TestSyncUsersReportsProblems(t *testing.T) {
	snap := emptySnapshot()
	snap.accounts["app"] = &mysqlAccount{name: "app", anyHost: true}
	s := &fakeSession{snap: snap}
	e := newTestEngine(t, s, nil)
	if err := e.SyncUsers(context.Background(), target, []engine.DesiredUser{appUser()}); err != nil {
		t.Fatal(err)
	}
	if p := e.UserProblem(target, "app"); !strings.Contains(p, "isn't managed by OpenEverest") || len(s.executed) != 0 {
		t.Fatalf("unmanaged user: problem %q, executed %q", p, s.executed)
	}

	s = &fakeSession{snap: emptySnapshot(), failOn: "CREATE USER"}
	e = newTestEngine(t, s, nil)
	if err := e.SyncUsers(context.Background(), target, []engine.DesiredUser{appUser()}); err != nil {
		t.Fatal(err)
	}
	if p := e.PendingReason(context.Background(), target, "app"); !strings.Contains(p, "password does not satisfy") {
		t.Fatalf("PendingReason() = %q", p)
	}
}

func TestListUsers(t *testing.T) {
	snap := emptySnapshot()
	managedApp(t, snap)
	snap.accounts["app"].process, snap.accounts["app"].replClient = true, true
	snap.accounts["operator"] = &mysqlAccount{name: "operator", anyHost: true}
	snap.accounts["mysql.sys"] = &mysqlAccount{name: "mysql.sys"}
	snap.accounts["legacy"] = &mysqlAccount{name: "legacy", anyHost: true}
	snap.grants["app"] = map[string][]string{
		`my\_db`: rolePrivileges[roleReadWrite],
		`my_db`:  {"Select_priv"},
		`odd`:    {"Select_priv", "Insert_priv"},
	}
	e := newTestEngine(t, &fakeSession{snap: snap}, nil)
	users, err := e.ListUsers(context.Background(), target)
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]engine.User{}
	for _, u := range users {
		byName[u.Username] = u
	}
	wantRoles := []engine.RoleGrant{{Role: roleMonitor}, {Role: roleReadWrite, Database: "my_db"}}
	if !slices.Equal(byName["app"].Roles, wantRoles) || byName["app"].System {
		t.Fatalf("app = %+v", byName["app"])
	}
	if !byName["operator"].System || !byName["mysql.sys"].System || byName["legacy"].System {
		t.Fatalf("system flags: %+v", users)
	}
}

func TestDropUser(t *testing.T) {
	snap := emptySnapshot()
	managedApp(t, snap)
	snap.managedDatabases["orders"] = "app"
	s := &fakeSession{snap: snap}
	e := newTestEngine(t, s, nil)
	if err := e.DropUser(context.Background(), target, "app"); !errors.Is(err, engine.ErrInProgress) {
		t.Fatalf("DropUser() of an owner = %v, want ErrInProgress", err)
	}
	delete(snap.managedDatabases, "orders")
	if err := e.DropUser(context.Background(), target, "app"); err != nil {
		t.Fatal(err)
	}
	if err := e.DropUser(context.Background(), target, "legacy"); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"DROP USER IF EXISTS 'app'@'%'",
		"DELETE FROM `openeverest_user_management`.`managed_users` WHERE name = ?",
	}
	if !slices.Equal(s.executed, want) {
		t.Fatalf("executed = %q", s.executed)
	}
}

func TestSyncDatabase(t *testing.T) {
	snap := emptySnapshot()
	managedApp(t, snap)
	s := &fakeSession{snap: snap}
	e := newTestEngine(t, s, nil)
	ctx := context.Background()

	if err := e.SyncDatabase(ctx, target, engine.DesiredDatabase{Name: "orders", Owner: "nobody"}); !errors.Is(err, engine.ErrInProgress) {
		t.Fatalf("SyncDatabase() without owner = %v, want ErrInProgress", err)
	}
	snap.schemas = append(snap.schemas, "legacy")
	if err := e.SyncDatabase(ctx, target, engine.DesiredDatabase{Name: "legacy", Owner: "app"}); !errors.Is(err, engine.ErrInvalid) {
		t.Fatalf("SyncDatabase() of an unmanaged database = %v, want ErrInvalid", err)
	}

	if err := e.SyncDatabase(ctx, target, engine.DesiredDatabase{Name: "my_db", Owner: "app"}); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"INSERT IGNORE INTO `openeverest_user_management`.`managed_databases` (name, owner) VALUES (?, ?)",
		"CREATE DATABASE IF NOT EXISTS `my_db`",
		"GRANT ALL PRIVILEGES ON `my\\_db`.* TO 'app'@'%' WITH GRANT OPTION",
	}
	if !slices.Equal(s.executed, want) {
		t.Fatalf("executed:\n%s", strings.Join(s.executed, "\n"))
	}

	// A new owner gets the database and the previous one loses it.
	s.executed = nil
	snap.schemas = append(snap.schemas, "my_db")
	snap.managedDatabases["my_db"] = "app"
	snap.accounts["bob"] = &mysqlAccount{name: "bob", anyHost: true}
	snap.managedUsers["bob"] = ""
	snap.grants["app"] = map[string][]string{`my\_db`: allPrivileges}
	snap.grants["bob"] = map[string][]string{`my\_db`: {"Select_priv"}}
	if err := e.SyncDatabase(ctx, target, engine.DesiredDatabase{Name: "my_db", Owner: "bob"}); err != nil {
		t.Fatal(err)
	}
	want = []string{
		"REVOKE ALL PRIVILEGES ON `my\\_db`.* FROM 'bob'@'%'",
		"GRANT ALL PRIVILEGES ON `my\\_db`.* TO 'bob'@'%' WITH GRANT OPTION",
		"UPDATE `openeverest_user_management`.`managed_databases` SET owner = ? WHERE name = ?",
		"REVOKE ALL PRIVILEGES ON `my\\_db`.* FROM 'app'@'%'",
		"REVOKE GRANT OPTION ON `my\\_db`.* FROM 'app'@'%'",
	}
	if !slices.Equal(s.executed, want) {
		t.Fatalf("executed:\n%s", strings.Join(s.executed, "\n"))
	}
}

func TestReleaseDatabase(t *testing.T) {
	snap := emptySnapshot()
	managedApp(t, snap)
	snap.schemas = append(snap.schemas, "orders", "legacy")
	snap.managedDatabases["orders"] = "app"
	snap.grants["app"] = map[string][]string{`orders`: allPrivileges}
	s := &fakeSession{snap: snap}
	e := newTestEngine(t, s, nil)
	ctx := context.Background()

	if err := e.ReleaseDatabase(ctx, target, "legacy", true); err != nil || len(s.executed) != 0 {
		t.Fatalf("ReleaseDatabase() of an unmanaged database: %v, executed %q", err, s.executed)
	}
	if err := e.ReleaseDatabase(ctx, target, "orders", false); err != nil {
		t.Fatal(err)
	}
	if len(s.executed) != 1 || !strings.HasPrefix(s.executed[0], "DELETE FROM") {
		t.Fatalf("retain executed = %q", s.executed)
	}
	s.executed = nil
	if err := e.ReleaseDatabase(ctx, target, "orders", true); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"REVOKE ALL PRIVILEGES ON `orders`.* FROM 'app'@'%'",
		"REVOKE GRANT OPTION ON `orders`.* FROM 'app'@'%'",
		"DROP DATABASE IF EXISTS `orders`",
		"DELETE FROM `openeverest_user_management`.`managed_databases` WHERE name = ?",
	}
	if !slices.Equal(s.executed, want) {
		t.Fatalf("drop executed = %q", s.executed)
	}
}

func TestNormalizeRolesRejectsSystemDatabases(t *testing.T) {
	for _, db := range []string{"mysql", "sys", catalogDatabase} {
		if _, err := normalizeRoles([]engine.RoleGrant{{Role: roleRead, Database: db}}); !errors.Is(err, engine.ErrInvalid) {
			t.Errorf("normalizeRoles(read on %s) error = %v, want ErrInvalid", db, err)
		}
	}
}

func TestRejectsNamesTooLongOnceEscaped(t *testing.T) {
	tooLong := strings.Repeat("a", 59) + "___" // 62 characters, 65 once escaped
	if validateDatabase(tooLong) == nil {
		t.Fatal("validateDatabase() accepted a name too long once escaped")
	}
	if _, err := normalizeRoles([]engine.RoleGrant{{Role: roleRead, Database: tooLong}}); !errors.Is(err, engine.ErrInvalid) {
		t.Fatalf("normalizeRoles() error = %v, want ErrInvalid", err)
	}
	fits := strings.Repeat("a", 60) + "__" // 64 once escaped
	if err := validateDatabase(fits); err != nil {
		t.Fatalf("validateDatabase() rejected a name that fits: %v", err)
	}
}

func TestGrantPatterns(t *testing.T) {
	if got := grantPattern("my_db"); got != `my\_db` {
		t.Fatalf("grantPattern() = %q", got)
	}
	if db, ok := literalDatabase(`my\_db`); !ok || db != "my_db" {
		t.Fatalf("literalDatabase(escaped) = %q, %v", db, ok)
	}
	if _, ok := literalDatabase(`my_db`); ok {
		t.Fatal("literalDatabase() accepted a wildcard")
	}
}

func TestFingerprint(t *testing.T) {
	fp, err := fingerprint("s3cret")
	if err != nil {
		t.Fatal(err)
	}
	if !fingerprintMatches(fp, "s3cret") || fingerprintMatches(fp, "other") || fingerprintMatches("", "s3cret") {
		t.Fatal("fingerprintMatches() is wrong")
	}
}
