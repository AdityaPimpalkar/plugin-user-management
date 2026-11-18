package mariadb

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	kubefake "k8s.io/client-go/kubernetes/fake"

	"github.com/openeverest/plugin-user-management/backend/internal/engine"
)

var testTarget = engine.Target{Namespace: "team", Instance: "orders-db"}

func testCluster() cluster {
	return cluster{
		name:        testTarget.Instance,
		namespace:   testTarget.Namespace,
		uid:         "mariadb-uid",
		host:        "orders-db.team.svc.cluster.local",
		port:        3306,
		database:    "everest",
		systemUsers: map[string]bool{"root": true, "mariadb.sys": true, "everest": true},
	}
}

type fakeSession struct {
	userList []databaseUser
	dbList   []databaseSchema
}

func (s *fakeSession) users(context.Context) ([]databaseUser, error) { return s.userList, nil }
func (s *fakeSession) databases(context.Context) ([]databaseSchema, error) {
	return s.dbList, nil
}
func (s *fakeSession) close() {}

func newFakeEngine(objects []runtime.Object, dbSession session) *Engine {
	gvrs := map[schema.GroupVersionResource]string{
		mariadbResource:  "MariaDBList",
		userResource:     "UserList",
		grantResource:    "GrantList",
		databaseResource: "DatabaseList",
	}
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), gvrs, objects...)
	e := &Engine{
		kube:    kubefake.NewClientset(),
		dyn:     dyn,
		resolve: func(context.Context, engine.Target) (cluster, error) { return testCluster(), nil },
		dial: func(context.Context, cluster) (session, error) {
			return dbSession, nil
		},
	}
	e.apply = e.applyObject
	return e
}

func ready(obj *unstructured.Unstructured) *unstructured.Unstructured {
	_ = unstructured.SetNestedSlice(obj.Object, []any{map[string]any{
		"type": "Ready", "status": "True", "reason": "Created", "message": "Created",
	}}, "status", "conditions")
	return obj
}

func readyGrant(c cluster, username string, grant engine.RoleGrant) *unstructured.Unstructured {
	obj := ready(grantApplyConfiguration(c, username, grant))
	_ = unstructured.SetNestedStringSlice(obj.Object, privilegesByRole[grant.Role], "status", "currentPrivileges")
	return obj
}

func TestNormalizeRoles(t *testing.T) {
	got, err := normalizeRoles([]engine.RoleGrant{
		{Role: roleRead, Database: "orders"},
		{Role: roleReadWrite, Database: "orders"},
		{Role: roleDBOwner, Database: "orders"},
		{Role: roleMonitor, Database: "orders"},
		{Role: roleRead, Database: "stock"},
		{Role: roleMonitor},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []engine.RoleGrant{
		{Role: roleDBOwner, Database: "orders"},
		{Role: roleMonitor},
		{Role: roleRead, Database: "stock"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("roles = %v, want %v", got, want)
	}
	for _, grants := range [][]engine.RoleGrant{
		{{Role: "ALL"}},
		{{Role: roleRead}},
		{{Role: roleRead, Database: "Orders"}},
	} {
		if _, err := normalizeRoles(grants); !errors.Is(err, engine.ErrInvalid) {
			t.Errorf("%v: error = %v, want ErrInvalid", grants, err)
		}
	}
}

func TestResourceConfigurations(t *testing.T) {
	c := testCluster()
	user := engine.DesiredUser{
		Username: "orders_svc",
		Password: engine.SecretKeyRef{Name: "orders-password", Key: "password"},
	}
	obj := userApplyConfiguration(c, user)
	if got := obj.GetLabels()[instanceLabel]; got != c.name {
		t.Fatalf("instance label = %q", got)
	}
	name, _, _ := unstructured.NestedString(obj.Object, "spec", "name")
	host, _, _ := unstructured.NestedString(obj.Object, "spec", "host")
	secret, _, _ := unstructured.NestedString(obj.Object, "spec", "passwordSecretKeyRef", "name")
	if name != user.Username || host != "%" || secret != user.Password.Name {
		t.Fatalf("unexpected User: %v", obj.Object)
	}

	grant := grantApplyConfiguration(c, user.Username, engine.RoleGrant{Role: roleReadWrite, Database: "orders"})
	privileges, _, _ := unstructured.NestedStringSlice(grant.Object, "spec", "privileges")
	if !reflect.DeepEqual(privileges, privilegesByRole[roleReadWrite]) {
		t.Fatalf("privileges = %v", privileges)
	}
	ownerGrant := ownerGrantApplyConfiguration(c, engine.DesiredDatabase{Name: "orders", Owner: user.Username})
	grantOption, _, _ := unstructured.NestedBool(ownerGrant.Object, "spec", "grantOption")
	if !grantOption || ownerGrant.GetLabels()[purposeLabel] != purposeOwner {
		t.Fatalf("owner grant = %v", ownerGrant.Object)
	}
}

func TestListUsersUsesAppliedAccessAndReportsForeignDeclarations(t *testing.T) {
	c := testCluster()
	access := readyGrant(c, "app", engine.RoleGrant{Role: roleReadWrite, Database: "orders"})
	owner := readyGrant(c, "app", engine.RoleGrant{Role: roleDBOwner, Database: "internal"})
	labels := owner.GetLabels()
	labels[purposeLabel] = purposeOwner
	owner.SetLabels(labels)
	owner.SetName(ownerGrantName(c.name, "internal", "app"))

	foreign := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": userResource.GroupVersion().String(),
		"kind":       "User",
		"metadata":   map[string]any{"name": "foreign-declaration", "namespace": c.namespace},
		"spec": map[string]any{
			"mariaDbRef": map[string]any{"name": c.name},
			"name":       "pending",
		},
	}}
	e := newFakeEngine([]runtime.Object{access, owner, foreign}, &fakeSession{
		userList: []databaseUser{{name: "app", host: "%"}, {name: "root", host: "localhost"}, {name: "everest", host: "%"}},
	})

	users, err := e.ListUsers(context.Background(), testTarget)
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]engine.User{}
	for _, user := range users {
		byName[user.Username] = user
	}
	if !byName["root"].System || !byName["everest"].System {
		t.Fatalf("system users = %v", users)
	}
	if got := byName["app"].Roles; !reflect.DeepEqual(got, []engine.RoleGrant{{Role: roleReadWrite, Database: "orders"}}) {
		t.Fatalf("app roles = %v", got)
	}
	if _, found := byName["pending"]; !found {
		t.Fatalf("foreign declaration was not reported: %v", users)
	}
}

func TestSyncUsersRevokesObsoleteGrantWithoutBlockingStatus(t *testing.T) {
	c := testCluster()
	obsolete := readyGrant(c, "app", engine.RoleGrant{Role: roleRead, Database: "old"})
	password := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{
		Name: "app-password", Namespace: c.namespace,
	}, Data: map[string][]byte{"password": []byte("secret")}}
	e := newFakeEngine([]runtime.Object{obsolete}, &fakeSession{})
	e.kube = kubefake.NewClientset(password)
	var applied []*unstructured.Unstructured
	e.apply = func(_ context.Context, obj *unstructured.Unstructured) error {
		applied = append(applied, obj.DeepCopy())
		return nil
	}

	err := e.SyncUsers(context.Background(), testTarget, []engine.DesiredUser{{
		Username: "app",
		Password: engine.SecretKeyRef{Name: password.Name, Key: "password"},
		Roles:    []engine.RoleGrant{{Role: roleReadWrite, Database: "orders"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(applied) != 2 || applied[0].GetKind() != "User" || applied[1].GetKind() != "Grant" {
		t.Fatalf("applied = %v", applied)
	}
	secret, err := e.kube.CoreV1().Secrets(c.namespace).Get(context.Background(), password.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if secret.Labels[reloadLabel] != "true" {
		t.Fatalf("password Secret labels = %v", secret.Labels)
	}
}

func TestListDatabasesUsesManagedOwnerAndBlocksForeignTakeover(t *testing.T) {
	c := testCluster()
	database := ready(databaseApplyConfiguration(c, engine.DesiredDatabase{Name: "orders", Owner: "owner"}))
	foreign := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": databaseResource.GroupVersion().String(),
		"kind":       "Database",
		"metadata": map[string]any{
			"name": "future", "namespace": c.namespace,
		},
		"spec": map[string]any{
			"mariaDbRef": map[string]any{"name": c.name},
			"name":       "future",
		},
	}}
	e := newFakeEngine([]runtime.Object{database, foreign}, &fakeSession{dbList: []databaseSchema{
		{name: "orders"}, {name: "everest"}, {name: "mysql"},
	}})

	databases, err := e.ListDatabases(context.Background(), testTarget)
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]engine.Database{}
	for _, database := range databases {
		byName[database.Name] = database
	}
	if byName["orders"].Owner != "owner" || byName["orders"].System {
		t.Fatalf("orders = %+v", byName["orders"])
	}
	if !byName["everest"].System || !byName["mysql"].System {
		t.Fatalf("system databases = %v", databases)
	}
	if _, found := byName["future"]; !found || byName["future"].System {
		t.Fatalf("foreign database = %+v", byName["future"])
	}
}

func TestDatabaseOwnerWaitsForOperatorResources(t *testing.T) {
	e := newFakeEngine(nil, &fakeSession{})
	var applied []*unstructured.Unstructured
	e.apply = func(_ context.Context, obj *unstructured.Unstructured) error {
		applied = append(applied, obj.DeepCopy())
		return nil
	}

	err := e.SyncDatabase(context.Background(), testTarget, engine.DesiredDatabase{
		Name: "orders", Owner: "owner",
	})
	if !errors.Is(err, engine.ErrInProgress) {
		t.Fatalf("error = %v, want ErrInProgress", err)
	}
	if len(applied) != 2 || applied[0].GetKind() != "Database" || applied[1].GetKind() != "Grant" {
		t.Fatalf("applied = %v", applied)
	}
}

func TestDropUserKeepsDatabaseOwner(t *testing.T) {
	c := testCluster()
	owner := ownerGrantApplyConfiguration(c, engine.DesiredDatabase{Name: "orders", Owner: "owner"})
	e := newFakeEngine([]runtime.Object{owner}, &fakeSession{})

	err := e.DropUser(context.Background(), testTarget, "owner")
	if !errors.Is(err, engine.ErrInProgress) || !strings.Contains(err.Error(), "owns database") {
		t.Fatalf("error = %v", err)
	}
	if _, err := e.dyn.Resource(grantResource).Namespace(c.namespace).
		Get(context.Background(), owner.GetName(), metav1.GetOptions{}); err != nil {
		t.Fatalf("owner grant was deleted: %v", err)
	}
}

func TestConnectionURIUsesMariaDBEndpointAndTLS(t *testing.T) {
	c := testCluster()
	c.tlsEnabled = true
	e := &Engine{resolve: func(context.Context, engine.Target) (cluster, error) { return c, nil }}
	uri, err := e.ConnectionURI(context.Background(), testTarget, "app@example", "p@ss/word")
	if err != nil {
		t.Fatal(err)
	}
	want := "mysql://app%40example:p%40ss%2Fword@orders-db.team.svc.cluster.local:3306?tls=true"
	if uri != want {
		t.Fatalf("URI = %q, want %q", uri, want)
	}
}
