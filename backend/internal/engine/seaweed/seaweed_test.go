package seaweed

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

var target = engine.Target{Namespace: "ns", Instance: "object-store"}

func seaweed() *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": seaweedResource.GroupVersion().String(),
		"kind":       "Seaweed",
		"metadata": map[string]any{
			"name": target.Instance, "namespace": target.Namespace, "uid": "seaweed-uid",
		},
	}}
}

func connectionSecret() *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: target.Instance + "-conn", Namespace: target.Namespace},
		Data: map[string][]byte{
			"type":              []byte("s3"),
			"endpointURL":       []byte("https://object-store-s3.ns.svc:8334"),
			"forcePathStyle":    []byte("true"),
			"region":            []byte("us-east-1"),
			"verifyTLS":         []byte("false"),
			"AWS_ACCESS_KEY_ID": []byte("admin-access-key"),
		},
	}
}

func credentialsSecret(accessKey string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "alice-credentials", Namespace: target.Namespace},
		Data: map[string][]byte{
			"username":     []byte("alice"),
			"password":     []byte("secret-access-key"),
			accessKeyField: []byte(accessKey),
		},
	}
}

func newEngine(objects []runtime.Object, secrets ...*corev1.Secret) *Engine {
	listKinds := map[schema.GroupVersionResource]string{
		seaweedResource:    "SeaweedList",
		identityResource:   "S3IdentityList",
		credentialResource: "S3CredentialsList",
		policyResource:     "S3PolicyList",
		bindingResource:    "S3PolicyBindingList",
	}
	kubeObjects := make([]runtime.Object, len(secrets))
	for i := range secrets {
		kubeObjects[i] = secrets[i]
	}
	return New(
		kubefake.NewClientset(kubeObjects...),
		dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), listKinds, objects...),
	)
}

func desiredUser(grants ...engine.RoleGrant) engine.DesiredUser {
	return engine.DesiredUser{
		Username: "alice",
		Roles:    grants,
		Password: engine.SecretKeyRef{
			Name: "alice-credentials",
			Key:  "password",
		},
		ManagedCredentials: true,
	}
}

func TestRoles(t *testing.T) {
	e := New(nil, nil)
	got, err := e.NormalizeRoles([]engine.RoleGrant{
		{Role: RoleRead, Bucket: "uploads"},
		{Role: RoleReadWrite, Bucket: "uploads"},
		{Role: RoleRead, Bucket: "backups"},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []engine.RoleGrant{
		{Role: RoleReadWrite, Bucket: "uploads"},
		{Role: RoleRead, Bucket: "backups"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("NormalizeRoles = %+v, want %+v", got, want)
	}

	for name, grants := range map[string][]engine.RoleGrant{
		"none":           nil,
		"unknown role":   {{Role: "owner", Bucket: "uploads"}},
		"missing bucket": {{Role: RoleRead}},
		"database":       {{Role: RoleRead, Database: "uploads", Bucket: "uploads"}},
		"uppercase":      {{Role: RoleRead, Bucket: "Uploads"}},
		"ip address":     {{Role: RoleRead, Bucket: "192.168.0.1"}},
		"double dot":     {{Role: RoleRead, Bucket: "photo..archive"}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := e.NormalizeRoles(grants); !errors.Is(err, engine.ErrInvalid) {
				t.Fatalf("error = %v, want ErrInvalid", err)
			}
		})
	}
}

func TestCredentialKindAndAccessKey(t *testing.T) {
	e := New(nil, nil)
	if got := engine.CredentialKindOf(e); got != engine.CredentialS3 {
		t.Fatalf("CredentialKindOf = %q", got)
	}
	data := map[string][]byte{"password": []byte("secret")}
	if err := e.PrepareCredentialSecret(context.Background(), target, "alice", "secret", data); err != nil {
		t.Fatal(err)
	}
	key := data[accessKeyField]
	if len(key) != accessKeyIDLength {
		t.Fatalf("access key length = %d", len(key))
	}
	if err := e.PrepareCredentialSecret(context.Background(), target, "alice", "new-secret", data); err != nil {
		t.Fatal(err)
	}
	if got := data[accessKeyField]; !reflect.DeepEqual(got, key) {
		t.Fatalf("access key changed on secret rotation: %q -> %q", key, got)
	}
	if err := e.ValidateUser(engine.DesiredUser{
		Username:           "admin",
		Roles:              []engine.RoleGrant{{Role: RoleRead, Bucket: "uploads"}},
		ManagedCredentials: true,
	}); !errors.Is(err, engine.ErrInvalid) {
		t.Fatalf("reserved user error = %v", err)
	}
	if err := e.ValidateUser(engine.DesiredUser{
		Username:           "alice",
		Roles:              []engine.RoleGrant{{Role: RoleRead, Bucket: "uploads"}},
		ManagedCredentials: false,
	}); !errors.Is(err, engine.ErrInvalid) {
		t.Fatalf("external credentials error = %v", err)
	}
}

func TestSyncUsers(t *testing.T) {
	e := newEngine([]runtime.Object{seaweed()}, credentialsSecret("AKIAALICE00000000001"))
	user := desiredUser(engine.RoleGrant{Role: RoleReadWrite, Bucket: "uploads"})

	if err := e.SyncUsers(context.Background(), target, []engine.DesiredUser{user}); err != nil {
		t.Fatal(err)
	}

	identity, err := e.dyn.Resource(identityResource).Namespace(target.Namespace).Get(
		context.Background(), identityName(target, user.Username), metav1.GetOptions{},
	)
	if err != nil {
		t.Fatal(err)
	}
	name, _, _ := unstructured.NestedString(identity.Object, "spec", "name")
	if name != identity.GetName() {
		t.Fatalf("identity name = %q", name)
	}
	displayName, _, _ := unstructured.NestedString(identity.Object, "spec", "account", "displayName")
	if displayName != user.Username {
		t.Fatalf("display name = %q", displayName)
	}
	if identity.GetLabels()[managedByLabel] != managedBy {
		t.Fatalf("identity labels = %v", identity.GetLabels())
	}

	credential, err := e.dyn.Resource(credentialResource).Namespace(target.Namespace).Get(
		context.Background(), credentialsName(target, user.Username), metav1.GetOptions{},
	)
	if err != nil {
		t.Fatal(err)
	}
	secretName, _, _ := unstructured.NestedString(credential.Object, "spec", "secretRef", "name")
	accessField, _, _ := unstructured.NestedString(credential.Object, "spec", "secretRef", "accessKeyField")
	secretField, _, _ := unstructured.NestedString(credential.Object, "spec", "secretRef", "secretKeyField")
	if secretName != user.Password.Name || accessField != accessKeyField || secretField != user.Password.Key {
		t.Fatalf("secretRef = name %q access %q secret %q", secretName, accessField, secretField)
	}

	policy, err := e.dyn.Resource(policyResource).Namespace(target.Namespace).Get(
		context.Background(), policyName(target, user.Username, user.Roles[0]), metav1.GetOptions{},
	)
	if err != nil {
		t.Fatal(err)
	}
	statements, _, _ := unstructured.NestedSlice(policy.Object, "spec", "statements")
	if len(statements) != 2 {
		t.Fatalf("statements = %+v", statements)
	}
	resources, _, _ := unstructured.NestedStringSlice(
		statements[0].(map[string]any), "resources",
	)
	if !reflect.DeepEqual(resources, []string{"uploads"}) {
		t.Fatalf("bucket resources = %v", resources)
	}

	binding, err := e.dyn.Resource(bindingResource).Namespace(target.Namespace).Get(
		context.Background(), bindingName(target, user.Username, user.Roles[0]), metav1.GetOptions{},
	)
	if err != nil {
		t.Fatal(err)
	}
	subjects, _, _ := unstructured.NestedSlice(binding.Object, "spec", "subjects")
	subject := subjects[0].(map[string]any)
	if subject["kind"] != "S3Identity" || subject["name"] != identity.GetName() {
		t.Fatalf("binding subject = %+v", subject)
	}

	users, err := e.ListUsers(context.Background(), target)
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 1 || users[0].Username != user.Username ||
		!reflect.DeepEqual(users[0].Roles, user.Roles) {
		t.Fatalf("ListUsers = %+v", users)
	}
}

func TestSyncRejectsForeignIdentityResource(t *testing.T) {
	foreign := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": identityResource.GroupVersion().String(),
		"kind":       "S3Identity",
		"metadata": map[string]any{
			"name": identityName(target, "alice"), "namespace": target.Namespace,
		},
		"spec": map[string]any{
			"seaweedRef": map[string]any{"name": target.Instance},
			"name":       "alice",
		},
	}}
	e := newEngine([]runtime.Object{seaweed(), foreign}, credentialsSecret("AKIAALICE00000000001"))
	err := e.SyncUsers(context.Background(), target, []engine.DesiredUser{
		desiredUser(engine.RoleGrant{Role: RoleRead, Bucket: "uploads"}),
	})
	if err == nil || !strings.Contains(err.Error(), "not managed by the plugin") {
		t.Fatalf("SyncUsers error = %v", err)
	}
}

func TestDropUserWaitsForIdentityFinalizer(t *testing.T) {
	e := newEngine([]runtime.Object{seaweed()}, credentialsSecret("AKIAALICE00000000001"))
	user := desiredUser(engine.RoleGrant{Role: RoleRead, Bucket: "uploads"})
	if err := e.SyncUsers(context.Background(), target, []engine.DesiredUser{user}); err != nil {
		t.Fatal(err)
	}
	err := e.DropUser(context.Background(), target, user.Username)
	if !errors.Is(err, engine.ErrInProgress) {
		t.Fatalf("DropUser error = %v, want ErrInProgress", err)
	}
	if err := e.DropUser(context.Background(), target, user.Username); err != nil {
		t.Fatalf("second DropUser: %v", err)
	}
}

func TestConnectionAndNotReady(t *testing.T) {
	e := newEngine([]runtime.Object{seaweed()}, connectionSecret())
	uri, err := e.ConnectionURI(context.Background(), target, "alice", "secret")
	if err != nil || uri != "https://object-store-s3.ns.svc:8334" {
		t.Fatalf("ConnectionURI = %q, %v", uri, err)
	}
	props, err := e.ConnectionProperties(context.Background(), target)
	if err != nil || props["forcePathStyle"] != "true" || props["region"] != "us-east-1" {
		t.Fatalf("ConnectionProperties = %v, %v", props, err)
	}

	missing := newEngine(nil)
	_, err = missing.ListUsers(context.Background(), target)
	if !errors.Is(err, engine.ErrNotReady) {
		t.Fatalf("ListUsers error = %v, want ErrNotReady", err)
	}
}

func TestPendingReason(t *testing.T) {
	e := newEngine([]runtime.Object{seaweed()}, credentialsSecret("AKIAALICE00000000001"))
	user := desiredUser(engine.RoleGrant{Role: RoleRead, Bucket: "uploads"})
	if err := e.SyncUsers(context.Background(), target, []engine.DesiredUser{user}); err != nil {
		t.Fatal(err)
	}
	if reason := e.UserProblem(target, user.Username); !strings.Contains(reason, "become Ready") {
		t.Fatalf("UserProblem = %q", reason)
	}
}

func TestForeignIdentityIsListed(t *testing.T) {
	foreign := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": identityResource.GroupVersion().String(),
		"kind":       "S3Identity",
		"metadata": map[string]any{
			"name": "alice", "namespace": target.Namespace,
		},
		"spec": map[string]any{
			"seaweedRef": map[string]any{"name": target.Instance},
			"name":       "alice",
		},
	}}
	e := newEngine([]runtime.Object{seaweed(), foreign})
	users, err := e.ListUsers(context.Background(), target)
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 1 || users[0].Username != "alice" {
		t.Fatalf("ListUsers = %+v", users)
	}
}
