package seaweed

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/openeverest/plugin-user-management/backend/internal/engine"
)

const (
	ProviderName = "provider-seaweedfs"
	FieldManager = "plugin-user-management"

	managedByLabel = "app.kubernetes.io/managed-by"
	managedBy      = "plugin-user-management"
	instanceLabel  = "plugin-user-management.plugins.openeverest.io/instance"
	usernameLabel  = "plugin-user-management.plugins.openeverest.io/s3-user"

	identityAnnotation = "plugin-user-management.plugins.openeverest.io/s3-identity"
	usernameAnnotation = "plugin-user-management.plugins.openeverest.io/username"
	roleAnnotation     = "plugin-user-management.plugins.openeverest.io/s3-role"
	bucketAnnotation   = "plugin-user-management.plugins.openeverest.io/s3-bucket"

	maxPolicyNameLength   = 128
	maxResourceNameLength = 230
)

var (
	seaweedResource    = schema.GroupVersionResource{Group: "seaweed.seaweedfs.com", Version: "v1", Resource: "seaweeds"}
	identityResource   = schema.GroupVersionResource{Group: "seaweed.seaweedfs.com", Version: "v1", Resource: "s3identities"}
	credentialResource = schema.GroupVersionResource{
		Group: "seaweed.seaweedfs.com", Version: "v1", Resource: "s3credentials",
	}
	policyResource  = schema.GroupVersionResource{Group: "seaweed.seaweedfs.com", Version: "v1", Resource: "s3policies"}
	bucketResource  = schema.GroupVersionResource{Group: "seaweed.seaweedfs.com", Version: "v1", Resource: "buckets"}
	bindingResource = schema.GroupVersionResource{
		Group: "seaweed.seaweedfs.com", Version: "v1", Resource: "s3policybindings",
	}
)

var invalidNameChars = regexp.MustCompile(`[^a-z0-9-]+`)

func identityName(target engine.Target, username string) string {
	return resourceName(maxResourceNameLength, target.Instance, "s3-user", username)
}

func credentialsName(target engine.Target, username string) string {
	return resourceName(maxResourceNameLength, target.Instance, "s3-user", username, "credentials")
}

func bucketName(target engine.Target, name string) string {
	return resourceName(maxResourceNameLength, target.Instance, "bucket", name)
}

func policyName(target engine.Target, username string, grant engine.RoleGrant) string {
	return resourceName(maxPolicyNameLength, target.Instance, "s3", username, grant.Role, grant.Bucket)
}

func bindingName(target engine.Target, username string, grant engine.RoleGrant) string {
	return policyName(target, username, grant) + "-binding"
}

func resourceName(limit int, parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	suffix := "-" + hex.EncodeToString(sum[:])[:10]
	stem := invalidNameChars.ReplaceAllString(strings.ToLower(strings.Join(parts, "-")), "-")
	stem = strings.Trim(stem, "-")
	maxStem := limit - len(suffix)
	if len(stem) > maxStem {
		stem = strings.TrimRight(stem[:maxStem], "-")
	}
	return strings.TrimRight(stem, "-") + suffix
}

func identityLabel(name string) string {
	sum := sha256.Sum256([]byte(name))
	return hex.EncodeToString(sum[:])[:12]
}

func ownerReference(obj *unstructured.Unstructured) map[string]any {
	return map[string]any{
		"apiVersion": obj.GetAPIVersion(),
		"kind":       obj.GetKind(),
		"name":       obj.GetName(),
		"uid":        string(obj.GetUID()),
	}
}

func identityObject(target engine.Target, seaweed *unstructured.Unstructured, username string) *unstructured.Unstructured {
	name := identityName(target, username)
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": identityResource.GroupVersion().String(),
		"kind":       "S3Identity",
		"metadata": map[string]any{
			"name":      name,
			"namespace": target.Namespace,
			"labels": map[string]any{
				managedByLabel: managedBy,
				instanceLabel:  target.Instance,
				usernameLabel:  identityLabel(name),
			},
			"annotations":     map[string]any{usernameAnnotation: username},
			"ownerReferences": []any{ownerReference(seaweed)},
		},
		"spec": map[string]any{
			"seaweedRef": map[string]any{"name": target.Instance},
			"name":       name,
			"account":    map[string]any{"displayName": username},
		},
	}}
}

func credentialsObject(
	target engine.Target,
	identity *unstructured.Unstructured,
	user engine.DesiredUser,
) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": credentialResource.GroupVersion().String(),
		"kind":       "S3Credentials",
		"metadata": map[string]any{
			"name":      credentialsName(target, user.Username),
			"namespace": target.Namespace,
			"labels": map[string]any{
				managedByLabel: managedBy,
				instanceLabel:  target.Instance,
				usernameLabel:  identityLabel(identity.GetName()),
			},
			"ownerReferences": []any{ownerReference(identity)},
		},
		"spec": map[string]any{
			"seaweedRef":  map[string]any{"name": target.Instance},
			"identityRef": map[string]any{"name": identity.GetName()},
			"secretRef": map[string]any{
				"name":           user.Password.Name,
				"accessKeyField": accessKeyField,
				"secretKeyField": user.Password.Key,
			},
		},
	}}
}

func policyObject(
	target engine.Target,
	identity *unstructured.Unstructured,
	grant engine.RoleGrant,
) *unstructured.Unstructured {
	name := policyName(target, identityUsername(identity), grant)
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": policyResource.GroupVersion().String(),
		"kind":       "S3Policy",
		"metadata": map[string]any{
			"name":      name,
			"namespace": target.Namespace,
			"labels": map[string]any{
				managedByLabel: managedBy,
				instanceLabel:  target.Instance,
				usernameLabel:  identityLabel(identity.GetName()),
			},
			"annotations": map[string]any{
				identityAnnotation: identity.GetName(),
				roleAnnotation:     grant.Role,
				bucketAnnotation:   grant.Bucket,
			},
			"ownerReferences": []any{ownerReference(identity)},
		},
		"spec": map[string]any{
			"seaweedRef": map[string]any{"name": target.Instance},
			"statements": policyStatements(grant),
		},
	}}
}

func bindingObject(
	target engine.Target,
	identity *unstructured.Unstructured,
	grant engine.RoleGrant,
	policy *unstructured.Unstructured,
) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": bindingResource.GroupVersion().String(),
		"kind":       "S3PolicyBinding",
		"metadata": map[string]any{
			"name":      bindingName(target, identityUsername(identity), grant),
			"namespace": target.Namespace,
			"labels": map[string]any{
				managedByLabel: managedBy,
				instanceLabel:  target.Instance,
				usernameLabel:  identityLabel(identity.GetName()),
			},
			"annotations": map[string]any{
				identityAnnotation: identity.GetName(),
				roleAnnotation:     grant.Role,
				bucketAnnotation:   grant.Bucket,
			},
			"ownerReferences": []any{ownerReference(identity)},
		},
		"spec": map[string]any{
			"seaweedRef": map[string]any{"name": target.Instance},
			"policyRef":  map[string]any{"name": policy.GetName()},
			"subjects": []any{map[string]any{
				"kind": "S3Identity",
				"name": identity.GetName(),
			}},
		},
	}}
}

func bucketObject(
	target engine.Target,
	seaweed *unstructured.Unstructured,
	bucket engine.DesiredBucket,
) *unstructured.Unstructured {
	owner := ""
	if bucket.Owner != "" {
		owner = identityName(target, bucket.Owner)
	}
	spec := map[string]any{
		"clusterRef":    map[string]any{"name": target.Instance},
		"name":          bucket.Name,
		"reclaimPolicy": "Retain",
	}
	if owner != "" {
		spec["owner"] = owner
	}
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": bucketResource.GroupVersion().String(),
		"kind":       "Bucket",
		"metadata": map[string]any{
			"name":      bucketName(target, bucket.Name),
			"namespace": target.Namespace,
			"labels": map[string]any{
				managedByLabel: managedBy,
				instanceLabel:  target.Instance,
			},
			"annotations":     map[string]any{usernameAnnotation: bucket.Owner},
			"ownerReferences": []any{ownerReference(seaweed)},
		},
		"spec": spec,
	}}
}

func identityUsername(identity *unstructured.Unstructured) string {
	if isManaged(identity) {
		if username := identity.GetAnnotations()[usernameAnnotation]; username != "" {
			return username
		}
	}
	name, _, _ := unstructured.NestedString(identity.Object, "spec", "name")
	return name
}

func observedPhase(obj *unstructured.Unstructured) string {
	phase, _, _ := unstructured.NestedString(obj.Object, "status", "phase")
	return phase
}

func readyProblem(obj *unstructured.Unstructured) string {
	observed, _, _ := unstructured.NestedInt64(obj.Object, "status", "observedGeneration")
	if observed != obj.GetGeneration() {
		return fmt.Sprintf("waiting for %s %q generation %d to be observed", obj.GetKind(), obj.GetName(), obj.GetGeneration())
	}
	switch observedPhase(obj) {
	case "Ready":
		return ""
	case "Failed":
		message, _, _ := unstructured.NestedString(obj.Object, "status", "message")
		conditions, _, _ := unstructured.NestedSlice(obj.Object, "status", "conditions")
		for _, raw := range conditions {
			condition, ok := raw.(map[string]any)
			if ok && condition["type"] == "Ready" && condition["status"] == "False" && condition["message"] != "" {
				message, _ = condition["message"].(string)
				break
			}
		}
		if message == "" {
			message = fmt.Sprintf("%s reported Failed", obj.GetKind())
		}
		return message
	default:
		return fmt.Sprintf("waiting for %s %q to become Ready", obj.GetKind(), obj.GetName())
	}
}

func matchingIdentity(obj *unstructured.Unstructured, target engine.Target) bool {
	name, _, _ := unstructured.NestedString(obj.Object, "spec", "seaweedRef", "name")
	return name == target.Instance
}

func matchingBucket(obj *unstructured.Unstructured, target engine.Target) bool {
	name, _, _ := unstructured.NestedString(obj.Object, "spec", "seaweedRef", "name")
	namespace, _, _ := unstructured.NestedString(obj.Object, "spec", "seaweedRef", "namespace")
	if name == "" {
		name, _, _ = unstructured.NestedString(obj.Object, "spec", "clusterRef", "name")
		namespace, _, _ = unstructured.NestedString(obj.Object, "spec", "clusterRef", "namespace")
	}
	if namespace == "" {
		namespace = obj.GetNamespace()
	}
	return name == target.Instance && namespace == target.Namespace
}

func bucketAlreadyExists(obj *unstructured.Unstructured) bool {
	conditions, _, _ := unstructured.NestedSlice(obj.Object, "status", "conditions")
	for _, raw := range conditions {
		condition, ok := raw.(map[string]any)
		if ok &&
			condition["type"] == "BucketAlreadyExists" &&
			condition["status"] == "True" {
			return true
		}
	}
	return false
}

func isManaged(obj metav1.Object) bool {
	return obj.GetLabels()[managedByLabel] == managedBy
}
