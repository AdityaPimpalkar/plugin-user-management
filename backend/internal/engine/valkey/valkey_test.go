package valkey

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
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

var target = engine.Target{Namespace: "ns", Instance: "vk"}

func valkeyCluster(conditions ...any) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "valkey.io/v1alpha1",
		"kind":       "ValkeyCluster",
		"metadata":   map[string]any{"name": "vk", "namespace": "ns"},
		"status":     map[string]any{"conditions": conditions},
	}}
}

func valkeyNode(name string, ready bool, revision string) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "valkey.io/v1alpha1",
		"kind":       "ValkeyNode",
		"metadata":   map[string]any{"name": name, "namespace": "ns", "labels": map[string]any{clusterLabel: "vk"}},
		"status":     map[string]any{"ready": ready, "appliedACLRevision": revision},
	}}
}

func secret(name string, data map[string]string) *corev1.Secret {
	s := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "ns"}, Data: map[string][]byte{}}
	for k, v := range data {
		s.Data[k] = []byte(v)
	}
	return s
}

// renderEntry renders a spec.acl.users entry as the operator's buildUserAcl
// does (valkey-operator internal/controller/users.go).
func renderEntry(t *testing.T, entry map[string]any, passwordHash string) string {
	t.Helper()
	strs := func(path ...string) []string {
		v, _, err := unstructured.NestedStringSlice(entry, path...)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	var b strings.Builder
	fmt.Fprintf(&b, "user %s on #%s", entry["name"], passwordHash)
	for _, k := range strs("keys", "readWrite") {
		b.WriteString(" ~" + k)
	}
	if ch := strs("channels", "patterns"); len(ch) > 0 {
		b.WriteString(" resetchannels")
		for _, c := range ch {
			b.WriteString(" &" + c)
		}
	}
	for _, c := range strs("commands", "allow") {
		b.WriteString(" +" + c)
	}
	for _, c := range strs("commands", "deny") {
		b.WriteString(" -" + c)
	}
	b.WriteString(" ")
	return b.String()
}

func aclFile(lines ...string) string {
	return strings.Join(append(append([]string{
		"user default on #abc ~* &* +@all",
	}, lines...),
		"user _operator on #def +@connection +cluster|nodes",
		"user _replication on #ghi -@all +psync +@write ~*",
		"user _operator_acl_revision off resetchannels -@all #rev1",
	), "\n") + "\n"
}

func aclSecret(file string) *corev1.Secret {
	return secret("internal-vk-acl", map[string]string{aclFileKey: file})
}

type testEngine struct {
	*Engine
	applied []*unstructured.Unstructured
}

func newTestEngine(objects []runtime.Object, secrets ...runtime.Object) *testEngine {
	gvrs := map[schema.GroupVersionResource]string{
		clusterResource: "ValkeyClusterList",
		nodeResource:    "ValkeyNodeList",
	}
	te := &testEngine{}
	te.Engine = &Engine{
		kube: kubefake.NewClientset(secrets...),
		dyn:  dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), gvrs, objects...),
		apply: func(_ context.Context, _ engine.Target, obj *unstructured.Unstructured) error {
			te.applied = append(te.applied, obj)
			return nil
		},
	}
	return te
}

func (te *testEngine) setSecret(t *testing.T, s *corev1.Secret) {
	t.Helper()
	if _, err := te.kube.CoreV1().Secrets("ns").Update(context.Background(), s, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
}

func (te *testEngine) setNode(t *testing.T, n *unstructured.Unstructured) {
	t.Helper()
	if _, err := te.dyn.Resource(nodeResource).Namespace("ns").Update(context.Background(), n, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
}

func TestNormalizeRoles(t *testing.T) {
	e := New(nil, nil)
	got, err := e.NormalizeRoles([]engine.RoleGrant{{Role: rolePubSub}, {Role: roleRead}, {Role: roleReadWrite}, {Role: rolePubSub}})
	if err != nil {
		t.Fatal(err)
	}
	want := []engine.RoleGrant{{Role: roleReadWrite}, {Role: rolePubSub}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("normalized = %+v, want %+v", got, want)
	}

	for name, grants := range map[string][]engine.RoleGrant{
		"none":     nil,
		"unknown":  {{Role: "admin"}},
		"database": {{Role: roleRead, Database: "0"}},
	} {
		if _, err := e.NormalizeRoles(grants); !errors.Is(err, engine.ErrInvalid) {
			t.Errorf("%s: err = %v, want ErrInvalid", name, err)
		}
	}
}

func TestValidateUser(t *testing.T) {
	e := New(nil, nil)
	if err := e.ValidateUser(engine.DesiredUser{Username: "default"}); !errors.Is(err, engine.ErrInvalid) {
		t.Errorf("default: err = %v, want ErrInvalid", err)
	}
	if err := e.ValidateUser(engine.DesiredUser{Username: "app"}); err != nil {
		t.Errorf("app: %v", err)
	}
}

// The roles read back from the aclfile the operator renders for an entry
// are the roles the entry was declared with.
func TestRolesRoundTrip(t *testing.T) {
	for _, grants := range [][]engine.RoleGrant{
		{{Role: roleRead}},
		{{Role: roleReadWrite}},
		{{Role: rolePubSub}},
		{{Role: roleRead}, {Role: rolePubSub}},
		{{Role: roleReadWrite}, {Role: rolePubSub}},
	} {
		roles, err := normalizeRoles(grants)
		if err != nil {
			t.Fatal(err)
		}
		line := renderEntry(t, aclEntry(engine.DesiredUser{Username: "app", Roles: roles}), "h")
		entries, _ := parseACLFile(line)
		if got := fromRules(strings.Fields(entries["app"])); !reflect.DeepEqual(got, roles) {
			t.Errorf("%s: roles = %+v, want %+v", line, got, roles)
		}
	}
}

func TestPermissions(t *testing.T) {
	p := toPermissions([]engine.RoleGrant{{Role: rolePubSub}})
	if len(p.keys) != 0 || !reflect.DeepEqual(p.channels, []string{"*"}) {
		t.Errorf("pubsub: keys %v, channels %v; want no keys, all channels", p.keys, p.channels)
	}
	p = toPermissions([]engine.RoleGrant{{Role: roleReadWrite}})
	if !reflect.DeepEqual(p.keys, []string{"*"}) || len(p.channels) != 0 {
		t.Errorf("readWrite: keys %v, channels %v; want all keys, no channels", p.keys, p.channels)
	}
	if !reflect.DeepEqual(p.deny, []string{"@admin", "@dangerous"}) {
		t.Errorf("deny = %v", p.deny)
	}
}

func TestSyncUsers(t *testing.T) {
	te := newTestEngine([]runtime.Object{valkeyCluster()},
		secret("app-credentials", map[string]string{"password": "s3cret"}),
		secret("empty", map[string]string{}),
		secret("hashed", map[string]string{"password": "#" + strings.Repeat("a", 64)}),
	)
	ctx := context.Background()
	users := []engine.DesiredUser{
		{Username: "app", Roles: []engine.RoleGrant{{Role: roleReadWrite}}, Password: engine.SecretKeyRef{Name: "app-credentials", Key: "password"}},
		{Username: "missing", Roles: []engine.RoleGrant{{Role: roleRead}}, Password: engine.SecretKeyRef{Name: "nope", Key: "password"}},
		{Username: "nokey", Roles: []engine.RoleGrant{{Role: roleRead}}, Password: engine.SecretKeyRef{Name: "empty", Key: "password"}},
		{Username: "hashed", Roles: []engine.RoleGrant{{Role: roleRead}}, Password: engine.SecretKeyRef{Name: "hashed", Key: "password"}},
	}
	if err := te.SyncUsers(ctx, target, users); err != nil {
		t.Fatal(err)
	}
	obj := te.applied[0]
	declared, _, _ := unstructured.NestedSlice(obj.Object, "spec", "acl", "users")
	if len(declared) != 1 {
		t.Fatalf("declared %d users, want only app: %+v", len(declared), declared)
	}
	entry := declared[0].(map[string]any)
	want := aclEntry(users[0])
	if !reflect.DeepEqual(entry, want) {
		t.Errorf("entry = %+v, want %+v", entry, want)
	}
	if name, _, _ := unstructured.NestedString(entry, "password", "secret", "name"); name != "app-credentials" {
		t.Errorf("password secret = %q", name)
	}
	for _, u := range []string{"missing", "nokey", "hashed"} {
		if te.UserProblem(target, u) == "" {
			t.Errorf("%s: no problem reported", u)
		}
	}
	if p := te.UserProblem(target, "app"); p != "" {
		t.Errorf("app: problem %q", p)
	}

	// A new password changes the annotation, so the operator renders it.
	digest := obj.GetAnnotations()[passwordsAnnotation]
	if digest == "" {
		t.Fatal("no passwords annotation")
	}
	te.setSecret(t, secret("app-credentials", map[string]string{"password": "rotated"}))
	if err := te.SyncUsers(ctx, target, users[:1]); err != nil {
		t.Fatal(err)
	}
	if next := te.applied[1].GetAnnotations()[passwordsAnnotation]; next == digest || next == "" {
		t.Errorf("annotation %q after password change, was %q", next, digest)
	}

	// No users releases the list and the annotation.
	if err := te.SyncUsers(ctx, target, nil); err != nil {
		t.Fatal(err)
	}
	last := te.applied[2]
	if _, found, _ := unstructured.NestedFieldNoCopy(last.Object, "spec", "acl"); found || len(last.GetAnnotations()) > 0 {
		t.Errorf("apply with no users = %+v", last.Object)
	}
}

func TestSyncUsersClusterMissing(t *testing.T) {
	te := newTestEngine(nil)
	if err := te.SyncUsers(context.Background(), target, nil); !errors.Is(err, engine.ErrNotReady) {
		t.Fatalf("err = %v, want ErrNotReady", err)
	}
	if len(te.applied) > 0 {
		t.Fatal("applied a missing cluster")
	}
}

func appLine(t *testing.T, roles []engine.RoleGrant, password string) string {
	sum := sha256.Sum256([]byte(password))
	return renderEntry(t, aclEntry(engine.DesiredUser{Username: "app", Roles: roles, Password: engine.SecretKeyRef{Name: "s", Key: "password"}}), fmt.Sprintf("%x", sum))
}

func usernames(users []engine.User) []string {
	var names []string
	for _, u := range users {
		if !u.Hidden {
			names = append(names, u.Username)
		}
	}
	return names
}

func TestListUsers(t *testing.T) {
	file := aclFile(appLine(t, []engine.RoleGrant{{Role: roleReadWrite}, {Role: rolePubSub}}, "p"))
	te := newTestEngine([]runtime.Object{valkeyCluster(), valkeyNode("n0", true, "rev1"), valkeyNode("n1", false, "")}, aclSecret(file))
	users, err := te.ListUsers(context.Background(), target)
	if err != nil {
		t.Fatal(err)
	}
	if got := usernames(users); !reflect.DeepEqual(got, []string{"_operator", "_replication", "app", "default"}) {
		t.Fatalf("users = %v", got)
	}
	for _, u := range users {
		switch u.Username {
		case "app":
			want := []engine.RoleGrant{{Role: roleReadWrite}, {Role: rolePubSub}}
			if u.System || !reflect.DeepEqual(u.Roles, want) {
				t.Errorf("app = %+v", u)
			}
		case aclRevisionUser:
			if !u.System || !u.Hidden {
				t.Errorf("revision user = %+v", u)
			}
		default:
			if !u.System || len(u.Roles) > 0 {
				t.Errorf("system user %+v", u)
			}
		}
	}
}

// While a node hasn't loaded the current aclfile, only the users whose entry
// every node had loaded are listed.
func TestListUsersDuringRollout(t *testing.T) {
	read := []engine.RoleGrant{{Role: roleRead}}
	te := newTestEngine([]runtime.Object{valkeyCluster(), valkeyNode("n0", true, "rev1"), valkeyNode("n1", true, "rev1")},
		aclSecret(aclFile(appLine(t, read, "p"))))
	ctx := context.Background()
	if _, err := te.ListUsers(ctx, target); err != nil {
		t.Fatal(err)
	}

	changed := strings.Replace(aclFile(appLine(t, read, "p"), "user other on #x ~* +@read"), "#rev1", "#rev2", 1)
	te.setSecret(t, aclSecret(changed))
	te.setNode(t, valkeyNode("n0", true, "rev2"))
	users, err := te.ListUsers(ctx, target)
	if err != nil {
		t.Fatal(err)
	}
	if got := usernames(users); !reflect.DeepEqual(got, []string{"_operator", "_replication", "app", "default"}) {
		t.Errorf("users = %v, want the new user left out", got)
	}
	if r := te.PendingReason(ctx, target, "other"); r != "waiting for 1 of 2 Valkey nodes to load the ACL" {
		t.Errorf("pending reason = %q", r)
	}

	rotated := strings.Replace(aclFile(appLine(t, read, "new")), "#rev1", "#rev3", 1)
	te.setSecret(t, aclSecret(rotated))
	users, _ = te.ListUsers(ctx, target)
	if got := usernames(users); !reflect.DeepEqual(got, []string{"_operator", "_replication", "default"}) {
		t.Errorf("users = %v, want app left out until its new password is loaded", got)
	}

	// After a restart nothing is known to be loaded.
	fresh := &Engine{kube: te.kube, dyn: te.dyn}
	users, _ = fresh.ListUsers(ctx, target)
	if got := usernames(users); !reflect.DeepEqual(got, []string{"_operator", "_replication", "default"}) {
		t.Errorf("users = %v", got)
	}

	te.setNode(t, valkeyNode("n0", true, "rev3"))
	te.setNode(t, valkeyNode("n1", true, "rev3"))
	users, _ = te.ListUsers(ctx, target)
	if got := usernames(users); !reflect.DeepEqual(got, []string{"_operator", "_replication", "app", "default"}) {
		t.Errorf("users = %v", got)
	}
}

func TestListUsersNotReady(t *testing.T) {
	for name, te := range map[string]*testEngine{
		"no cluster": newTestEngine(nil),
		"no aclfile": newTestEngine([]runtime.Object{valkeyCluster(), valkeyNode("n0", true, "rev1")}),
		"no node":    newTestEngine([]runtime.Object{valkeyCluster(), valkeyNode("n0", false, "rev1")}, aclSecret(aclFile())),
	} {
		if _, err := te.ListUsers(context.Background(), target); !errors.Is(err, engine.ErrNotReady) {
			t.Errorf("%s: err = %v, want ErrNotReady", name, err)
		}
	}
}

func TestDropUser(t *testing.T) {
	ctx := context.Background()
	te := newTestEngine([]runtime.Object{valkeyCluster(), valkeyNode("n0", true, "rev1"), valkeyNode("n1", true, "rev1")},
		aclSecret(aclFile(appLine(t, []engine.RoleGrant{{Role: roleRead}}, "p"))))
	if err := te.DropUser(ctx, target, "app"); !errors.Is(err, engine.ErrInProgress) {
		t.Fatalf("declared user: err = %v, want ErrInProgress", err)
	}

	te.setSecret(t, aclSecret(strings.Replace(aclFile(), "#rev1", "#rev2", 1)))
	te.setNode(t, valkeyNode("n0", true, "rev2"))
	if err := te.DropUser(ctx, target, "app"); !errors.Is(err, engine.ErrInProgress) {
		t.Fatalf("node still on the old aclfile: err = %v, want ErrInProgress", err)
	}

	te.setNode(t, valkeyNode("n1", true, "rev2"))
	if err := te.DropUser(ctx, target, "app"); err != nil {
		t.Fatalf("removed user: %v", err)
	}

	if err := newTestEngine(nil).DropUser(ctx, target, "app"); err != nil {
		t.Fatalf("cluster gone: %v", err)
	}
}

func TestPendingReasonDegraded(t *testing.T) {
	degraded := map[string]any{"type": "Degraded", "status": "True", "reason": reasonUsersACLUnresolved, "message": "user app: Secret s not found"}
	te := newTestEngine([]runtime.Object{valkeyCluster(degraded), valkeyNode("n0", true, "rev1")}, aclSecret(aclFile()))
	if r := te.PendingReason(context.Background(), target, "app"); !strings.Contains(r, "Secret s not found") {
		t.Errorf("pending reason = %q", r)
	}
}

func TestConnection(t *testing.T) {
	ctx := context.Background()
	te := newTestEngine(nil, secret("vk-conn", map[string]string{
		"host": "valkey-vk.ns.svc.cluster.local", "port": "6379", "ssl": "true", "ca.crt": "CA",
		"tls.crt": "default user cert", "tls.key": "default user key",
	}))
	uri, err := te.ConnectionURI(ctx, target, "app", "p@ss/word")
	if err != nil {
		t.Fatal(err)
	}
	if want := "rediss://app:p%40ss%2Fword@valkey-vk.ns.svc.cluster.local:6379"; uri != want {
		t.Errorf("uri = %q, want %q", uri, want)
	}
	props, err := te.ConnectionProperties(ctx, target)
	if err != nil {
		t.Fatal(err)
	}
	if want := map[string]string{"ssl": "true", "ca.crt": "CA"}; !reflect.DeepEqual(props, want) {
		t.Errorf("properties = %v, want %v", props, want)
	}

	plain := newTestEngine(nil, secret("vk-conn", map[string]string{"host": "h"}))
	if uri, _ := plain.ConnectionURI(ctx, target, "app", "p"); uri != "redis://app:p@h:6379" {
		t.Errorf("uri = %q", uri)
	}
	if _, err := newTestEngine(nil).ConnectionURI(ctx, target, "app", "p"); !errors.Is(err, engine.ErrNotReady) {
		t.Errorf("no connection secret: err = %v, want ErrNotReady", err)
	}
}
