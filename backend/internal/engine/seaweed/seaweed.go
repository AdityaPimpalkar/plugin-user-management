// Package seaweed reconciles S3 users and bucket grants for
// provider-seaweedfs through the operator's native IAM CRDs.
package seaweed

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"reflect"
	"sort"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"

	"github.com/openeverest/plugin-user-management/backend/internal/engine"
)

const (
	accessKeyField       = "AWS_ACCESS_KEY_ID"
	accessKeyIDLength    = 20
	accessKeyIDAlphabet  = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	connectionSecretType = "s3"
)

// Engine implements engine.Engine for SeaweedFS instances.
type Engine struct {
	kube kubernetes.Interface
	dyn  dynamic.Interface

	problems sync.Map
}

// New returns an engine that manages the SeaweedFS operator's S3 IAM CRDs.
func New(kube kubernetes.Interface, dyn dynamic.Interface) *Engine {
	return &Engine{kube: kube, dyn: dyn}
}

func (e *Engine) Roles() []engine.Role {
	return roleCatalog
}

func (e *Engine) AuthDatabase() string {
	return ""
}

func (e *Engine) NormalizeRoles(grants []engine.RoleGrant) ([]engine.RoleGrant, error) {
	return normalizeRoles(grants)
}

func (e *Engine) CredentialKind() engine.CredentialKind {
	return engine.CredentialS3
}

func (e *Engine) ValidateUser(user engine.DesiredUser) error {
	if user.Username == "admin" || user.Username == "anonymous" {
		return fmt.Errorf("%w: user %q is reserved by SeaweedFS", engine.ErrInvalid, user.Username)
	}
	if !user.ManagedCredentials {
		return fmt.Errorf("%w: SeaweedFS users currently require plugin-managed credentials", engine.ErrInvalid)
	}
	// The controller may temporarily withhold every role while a managed
	// InstanceBucket is still becoming available. The identity and key still
	// need to exist first so that it can own the bucket. The HTTP create path
	// already requires NormalizeRoles to receive at least one declared role.
	if len(user.Roles) == 0 {
		return nil
	}
	_, err := e.NormalizeRoles(user.Roles)
	return err
}

func (e *Engine) PrepareCredentialSecret(
	_ context.Context,
	_ engine.Target,
	_ string,
	password string,
	data map[string][]byte,
) error {
	if password == "" {
		return fmt.Errorf("secret access key is empty")
	}
	if len(data[accessKeyField]) > 0 {
		return nil
	}
	accessKey, err := randomAccessKey()
	if err != nil {
		return err
	}
	data[accessKeyField] = []byte(accessKey)
	return nil
}

func randomAccessKey() (string, error) {
	limit := big.NewInt(int64(len(accessKeyIDAlphabet)))
	out := make([]byte, accessKeyIDLength)
	for i := range out {
		n, err := rand.Int(rand.Reader, limit)
		if err != nil {
			return "", fmt.Errorf("generate S3 access key: %w", err)
		}
		out[i] = accessKeyIDAlphabet[n.Int64()]
	}
	return string(out), nil
}

func (e *Engine) SyncUsers(ctx context.Context, target engine.Target, users []engine.DesiredUser) error {
	seaweed, err := e.dyn.Resource(seaweedResource).Namespace(target.Namespace).Get(
		ctx, target.Instance, metav1.GetOptions{},
	)
	if apierrors.IsNotFound(err) {
		return fmt.Errorf("%w: Seaweed cluster is not found", engine.ErrNotReady)
	}
	if err != nil {
		return fmt.Errorf("get Seaweed cluster: %w", err)
	}

	desiredGrants := map[string]bool{}
	desiredIdentities := map[string]bool{}
	for _, user := range users {
		key := problemKey(target, user.Username)
		if err := e.ValidateUser(user); err != nil {
			e.problems.Store(key, err.Error())
			continue
		}
		secret, problem, err := e.credentialsSecret(ctx, target.Namespace, user.Password)
		if err != nil {
			return err
		}
		if problem != "" {
			e.problems.Store(key, problem)
			continue
		}
		if len(secret.Data[accessKeyField]) == 0 {
			e.problems.Store(key, fmt.Sprintf("credentials Secret %q has no %q key", user.Password.Name, accessKeyField))
			continue
		}
		e.problems.Delete(key)

		identity, err := e.apply(ctx, identityResource, identityObject(target, seaweed, user.Username))
		if err != nil {
			return err
		}
		desiredIdentities[identity.GetName()] = true
		_, err = e.apply(ctx, credentialResource, credentialsObject(target, identity, user))
		if err != nil {
			return err
		}

		for _, grant := range user.Roles {
			policy, err := e.apply(ctx, policyResource, policyObject(target, identity, grant))
			if err != nil {
				return err
			}
			_, err = e.apply(ctx, bindingResource, bindingObject(target, identity, grant, policy))
			if err != nil {
				return err
			}
			desiredGrants[policy.GetName()] = true
			desiredGrants[bindingName(target, user.Username, grant)] = true
		}
		if problem := e.userProblem(ctx, target, user.Username); problem != "" {
			e.problems.Store(key, problem)
		} else {
			e.problems.Delete(key)
		}
	}

	for _, gvr := range []schema.GroupVersionResource{bindingResource, policyResource} {
		list, err := e.dyn.Resource(gvr).Namespace(target.Namespace).List(ctx, metav1.ListOptions{})
		if err != nil {
			return fmt.Errorf("list %s: %w", gvr.Resource, err)
		}
		for i := range list.Items {
			obj := &list.Items[i]
			if !isManaged(obj) || obj.GetLabels()[instanceLabel] != target.Instance || desiredGrants[obj.GetName()] {
				continue
			}
			identity := obj.GetAnnotations()[identityAnnotation]
			if identity != "" && !desiredIdentities[identity] {
				// The identity owner will clean up these after DropUser.
				continue
			}
			if err := e.dyn.Resource(gvr).Namespace(target.Namespace).Delete(ctx, obj.GetName(), metav1.DeleteOptions{}); err != nil &&
				!apierrors.IsNotFound(err) {
				return fmt.Errorf("delete stale %s %q: %w", obj.GetKind(), obj.GetName(), err)
			}
		}
	}
	return nil
}

func (e *Engine) credentialsSecret(
	ctx context.Context,
	namespace string,
	ref engine.SecretKeyRef,
) (*corev1.Secret, string, error) {
	secret, err := e.kube.CoreV1().Secrets(namespace).Get(ctx, ref.Name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil, fmt.Sprintf("credentials Secret %q is not found", ref.Name), nil
	}
	if err != nil {
		return nil, "", fmt.Errorf("get credentials Secret %q: %w", ref.Name, err)
	}
	if len(secret.Data[ref.Key]) == 0 {
		return secret, fmt.Sprintf("credentials Secret %q has no %q key", ref.Name, ref.Key), nil
	}
	return secret, "", nil
}

func (e *Engine) apply(
	ctx context.Context,
	gvr schema.GroupVersionResource,
	obj *unstructured.Unstructured,
) (*unstructured.Unstructured, error) {
	resource := e.dyn.Resource(gvr).Namespace(obj.GetNamespace())
	existing, err := resource.Get(ctx, obj.GetName(), metav1.GetOptions{})
	switch {
	case apierrors.IsNotFound(err):
	case err != nil:
		return nil, fmt.Errorf("get %s %q: %w", obj.GetKind(), obj.GetName(), err)
	case !isManaged(existing) || existing.GetLabels()[instanceLabel] != obj.GetLabels()[instanceLabel]:
		return nil, fmt.Errorf("%s %q exists and is not managed by the plugin", obj.GetKind(), obj.GetName())
	}
	applied, err := resource.Apply(ctx, obj.GetName(), obj, metav1.ApplyOptions{
		FieldManager: FieldManager,
		Force:        true,
	})
	if apierrors.IsNotFound(err) {
		return resource.Create(ctx, obj, metav1.CreateOptions{FieldManager: FieldManager})
	}
	if err != nil {
		return nil, fmt.Errorf("apply %s %q: %w", obj.GetKind(), obj.GetName(), err)
	}
	return applied, nil
}

func (e *Engine) ListUsers(ctx context.Context, target engine.Target) ([]engine.User, error) {
	if _, err := e.dyn.Resource(seaweedResource).Namespace(target.Namespace).Get(ctx, target.Instance, metav1.GetOptions{}); apierrors.IsNotFound(err) {
		return nil, fmt.Errorf("%w: Seaweed cluster is not found", engine.ErrNotReady)
	} else if err != nil {
		return nil, fmt.Errorf("get Seaweed cluster: %w", err)
	}

	identities, err := e.dyn.Resource(identityResource).Namespace(target.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list S3Identity resources: %w", err)
	}
	grants, err := e.bucketGrants(ctx, target)
	if err != nil {
		return nil, err
	}
	users := make([]engine.User, 0, len(identities.Items))
	for i := range identities.Items {
		identity := &identities.Items[i]
		if !matchingIdentity(identity, target) {
			continue
		}
		username := identityUsername(identity)
		if username == "" {
			continue
		}
		users = append(users, engine.User{
			Username: username,
			Roles:    grants[identity.GetName()],
			System:   username == "admin" || username == "anonymous",
		})
	}
	sort.Slice(users, func(i, j int) bool { return users[i].Username < users[j].Username })
	return users, nil
}

// ValidateBucket implements engine.BucketEngine with the operator's S3 bucket
// naming contract.
func (e *Engine) ValidateBucket(name string) error {
	if !validBucketName(name) {
		return fmt.Errorf("%w: %q is not a valid S3 bucket name", engine.ErrInvalid, name)
	}
	return nil
}

// ListBuckets implements engine.BucketEngine. Buckets represented by native
// Bucket CRs are visible; buckets created directly in SeaweedFS without a CR
// are not discoverable through Kubernetes.
func (e *Engine) ListBuckets(ctx context.Context, target engine.Target) ([]engine.Bucket, error) {
	if _, err := e.dyn.Resource(seaweedResource).Namespace(target.Namespace).Get(
		ctx, target.Instance, metav1.GetOptions{},
	); apierrors.IsNotFound(err) {
		return nil, fmt.Errorf("%w: Seaweed cluster is not found", engine.ErrNotReady)
	} else if err != nil {
		return nil, fmt.Errorf("get Seaweed cluster: %w", err)
	}
	list, err := e.dyn.Resource(bucketResource).Namespace(target.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list Bucket resources: %w", err)
	}
	owners, err := e.identityDisplayNames(ctx, target)
	if err != nil {
		return nil, err
	}
	buckets := make([]engine.Bucket, 0, len(list.Items))
	for i := range list.Items {
		obj := &list.Items[i]
		if !matchingBucket(obj, target) {
			continue
		}
		name, _, _ := unstructured.NestedString(obj.Object, "spec", "name")
		if name == "" {
			name = obj.GetName()
		}
		owner, _, _ := unstructured.NestedString(obj.Object, "status", "ownerIdentity")
		if visible := owners[owner]; visible != "" {
			owner = visible
		}
		buckets = append(buckets, engine.Bucket{Name: name, Owner: owner})
	}
	sort.Slice(buckets, func(i, j int) bool { return buckets[i].Name < buckets[j].Name })
	return buckets, nil
}

func (e *Engine) identityDisplayNames(ctx context.Context, target engine.Target) (map[string]string, error) {
	list, err := e.dyn.Resource(identityResource).Namespace(target.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list S3Identity resources: %w", err)
	}
	owners := map[string]string{}
	for i := range list.Items {
		identity := &list.Items[i]
		if !matchingIdentity(identity, target) {
			continue
		}
		iamName, _, _ := unstructured.NestedString(identity.Object, "spec", "name")
		owners[iamName] = identityUsername(identity)
	}
	return owners, nil
}

// SyncBucket implements engine.BucketEngine using the SeaweedFS operator's
// native Bucket CR.
func (e *Engine) SyncBucket(ctx context.Context, target engine.Target, bucket engine.DesiredBucket) error {
	seaweed, err := e.dyn.Resource(seaweedResource).Namespace(target.Namespace).Get(
		ctx, target.Instance, metav1.GetOptions{},
	)
	if apierrors.IsNotFound(err) {
		return fmt.Errorf("%w: Seaweed cluster is not found", engine.ErrNotReady)
	}
	if err != nil {
		return fmt.Errorf("get Seaweed cluster: %w", err)
	}
	desired := bucketObject(target, seaweed, bucket)
	resource := e.dyn.Resource(bucketResource).Namespace(target.Namespace)
	existing, err := resource.Get(ctx, desired.GetName(), metav1.GetOptions{})
	switch {
	case err == nil:
		if !isManaged(existing) || existing.GetLabels()[instanceLabel] != target.Instance {
			return fmt.Errorf("Bucket %q exists and is not managed by the plugin", desired.GetName())
		}
		desiredSpec, _, _ := unstructured.NestedMap(desired.Object, "spec")
		existingSpec, _, _ := unstructured.NestedMap(existing.Object, "spec")
		if reflect.DeepEqual(existingSpec, desiredSpec) {
			if problem := readyProblem(existing); problem != "" {
				if bucketAlreadyExists(existing) {
					return fmt.Errorf("%w: %s", engine.ErrInvalid, problem)
				}
				return fmt.Errorf("%w: %s", engine.ErrInProgress, problem)
			}
			return nil
		}
	case apierrors.IsNotFound(err):
	case err != nil:
		return fmt.Errorf("get Bucket %q: %w", desired.GetName(), err)
	}
	applied, err := e.apply(ctx, bucketResource, desired)
	if err != nil {
		return err
	}
	if problem := readyProblem(applied); problem != "" {
		if bucketAlreadyExists(applied) {
			return fmt.Errorf("%w: %s", engine.ErrInvalid, problem)
		}
		return fmt.Errorf("%w: %s", engine.ErrInProgress, problem)
	}
	return nil
}

// ReleaseBucket removes the native Bucket CR, retaining or deleting the
// underlying S3 bucket according to drop.
func (e *Engine) ReleaseBucket(ctx context.Context, target engine.Target, name string, drop bool) error {
	resource := e.dyn.Resource(bucketResource).Namespace(target.Namespace)
	resourceName := bucketName(target, name)
	obj, err := resource.Get(ctx, resourceName, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("get Bucket %q: %w", resourceName, err)
	}
	if !isManaged(obj) || obj.GetLabels()[instanceLabel] != target.Instance {
		return fmt.Errorf("Bucket %q is not managed by the plugin", resourceName)
	}
	policy := "Retain"
	if drop {
		policy = "Delete"
	}
	current, _, _ := unstructured.NestedString(obj.Object, "spec", "reclaimPolicy")
	if current != policy && obj.GetDeletionTimestamp() == nil {
		obj = obj.DeepCopy()
		if err := unstructured.SetNestedField(obj.Object, policy, "spec", "reclaimPolicy"); err != nil {
			return err
		}
		obj, err = resource.Update(ctx, obj, metav1.UpdateOptions{})
		if err != nil {
			return fmt.Errorf("set Bucket reclaim policy: %w", err)
		}
	}
	if obj.GetDeletionTimestamp() == nil {
		if err := resource.Delete(ctx, resourceName, metav1.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("delete Bucket %q: %w", resourceName, err)
		}
	}
	return fmt.Errorf("%w: SeaweedFS is releasing bucket %q", engine.ErrInProgress, name)
}

func (e *Engine) bucketGrants(ctx context.Context, target engine.Target) (map[string][]engine.RoleGrant, error) {
	bindings, err := e.dyn.Resource(bindingResource).Namespace(target.Namespace).List(ctx, metav1.ListOptions{
		LabelSelector: managedByLabel + "=" + managedBy,
	})
	if err != nil {
		return nil, fmt.Errorf("list S3PolicyBindings: %w", err)
	}
	grants := map[string][]engine.RoleGrant{}
	for i := range bindings.Items {
		binding := &bindings.Items[i]
		if binding.GetLabels()[instanceLabel] != target.Instance {
			continue
		}
		annotations := binding.GetAnnotations()
		grant := engine.RoleGrant{Role: annotations[roleAnnotation], Bucket: annotations[bucketAnnotation]}
		identity := binding.GetAnnotations()[identityAnnotation]
		if grant.Role != "" && grant.Bucket != "" && identity != "" {
			grants[identity] = append(grants[identity], grant)
		}
	}
	for identity := range grants {
		sort.Slice(grants[identity], func(i, j int) bool {
			a, b := grants[identity][i], grants[identity][j]
			if a.Bucket != b.Bucket {
				return a.Bucket < b.Bucket
			}
			return a.Role < b.Role
		})
	}
	return grants, nil
}

func (e *Engine) DropUser(ctx context.Context, target engine.Target, username string) error {
	name := identityName(target, username)
	buckets, err := e.dyn.Resource(bucketResource).Namespace(metav1.NamespaceAll).List(
		ctx, metav1.ListOptions{},
	)
	if err != nil {
		return fmt.Errorf("list buckets before dropping S3 user: %w", err)
	}
	for i := range buckets.Items {
		bucket := &buckets.Items[i]
		if !matchingBucket(bucket, target) {
			continue
		}
		owner, _, _ := unstructured.NestedString(bucket.Object, "spec", "owner")
		if owner == name {
			return fmt.Errorf("%w: bucket %q is still owned by user %q", engine.ErrInProgress, matchingBucketName(bucket), username)
		}
	}
	resource := e.dyn.Resource(identityResource).Namespace(target.Namespace)
	identity, err := resource.Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		e.problems.Delete(problemKey(target, username))
		return nil
	}

	if err != nil {
		return fmt.Errorf("get S3Identity %q: %w", name, err)
	}
	if !isManaged(identity) {
		return nil
	}
	if identity.GetDeletionTimestamp() == nil {
		if err := resource.Delete(ctx, name, metav1.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("delete S3Identity %q: %w", name, err)
		}
	}
	return fmt.Errorf("%w: SeaweedFS is deleting IAM user %q", engine.ErrInProgress, username)
}

func matchingBucketName(bucket *unstructured.Unstructured) string {
	name, _, _ := unstructured.NestedString(bucket.Object, "spec", "name")
	if name == "" {
		return bucket.GetName()
	}
	return name
}

func (e *Engine) ConnectionURI(ctx context.Context, target engine.Target, _, _ string) (string, error) {
	connection, err := e.connection(ctx, target)
	if err != nil {
		return "", err
	}
	return connection["endpointURL"], nil
}

func (e *Engine) ConnectionProperties(ctx context.Context, target engine.Target) (map[string]string, error) {
	return e.connection(ctx, target)
}

func (e *Engine) connection(ctx context.Context, target engine.Target) (map[string]string, error) {
	secret, err := e.kube.CoreV1().Secrets(target.Namespace).Get(ctx, target.Instance+"-conn", metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil, fmt.Errorf("%w: S3 connection details are not ready", engine.ErrNotReady)
	}
	if err != nil {
		return nil, fmt.Errorf("get S3 connection Secret: %w", err)
	}
	if string(secret.Data["type"]) != connectionSecretType {
		return nil, fmt.Errorf("%w: the instance has no S3 connection details", engine.ErrNotReady)
	}
	properties := map[string]string{}
	for _, key := range []string{
		"endpointURL",
		"externalEndpointURL",
		"forcePathStyle",
		"verifyTLS",
		"externalVerifyTLS",
		"region",
	} {
		if len(secret.Data[key]) > 0 {
			properties[key] = string(secret.Data[key])
		}
	}
	if properties["endpointURL"] == "" {
		return nil, fmt.Errorf("%w: the S3 endpoint is not ready", engine.ErrNotReady)
	}
	return properties, nil
}

func problemKey(target engine.Target, username string) string {
	return target.Namespace + "/" + target.Instance + "/" + username
}

func (e *Engine) UserProblem(target engine.Target, username string) string {
	if value, ok := e.problems.Load(problemKey(target, username)); ok {
		return value.(string)
	}
	return ""
}

func (e *Engine) userProblem(ctx context.Context, target engine.Target, username string) string {
	for _, gvr := range []schema.GroupVersionResource{identityResource, credentialResource} {
		name := identityName(target, username)
		if gvr == credentialResource {
			name = credentialsName(target, username)
		}
		obj, err := e.dyn.Resource(gvr).Namespace(target.Namespace).Get(ctx, name, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			return fmt.Sprintf("waiting for %s %q to be created", gvr.Resource, name)
		}
		if err != nil {
			return ""
		}
		if reason := readyProblem(obj); reason != "" {
			return reason
		}
	}
	for _, gvr := range []schema.GroupVersionResource{policyResource, bindingResource} {
		list, err := e.dyn.Resource(gvr).Namespace(target.Namespace).List(ctx, metav1.ListOptions{
			LabelSelector: usernameLabel + "=" + identityLabel(identityName(target, username)),
		})
		if err == nil {
			for i := range list.Items {
				if reason := readyProblem(&list.Items[i]); reason != "" {
					return reason
				}
			}
		}
	}
	return ""
}

func (e *Engine) PendingReason(ctx context.Context, target engine.Target, username string) string {
	if reason := e.UserProblem(target, username); reason != "" {
		return reason
	}
	if reason := e.userProblem(ctx, target, username); reason != "" {
		return reason
	}
	return "waiting for SeaweedFS IAM to apply the user"
}

func (e *Engine) ResyncInterval() time.Duration {
	return 5 * time.Minute
}
