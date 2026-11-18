package mariadb

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"

	"github.com/openeverest/plugin-user-management/backend/internal/engine"
)

var (
	userResource     = schema.GroupVersionResource{Group: mariadbResource.Group, Version: mariadbResource.Version, Resource: "users"}
	grantResource    = schema.GroupVersionResource{Group: mariadbResource.Group, Version: mariadbResource.Version, Resource: "grants"}
	databaseResource = schema.GroupVersionResource{Group: mariadbResource.Group, Version: mariadbResource.Version, Resource: "databases"}
)

const (
	FieldManager = "plugin-user-management"

	instanceLabel = "plugin-user-management.plugins.openeverest.io/instance"
	managedLabel  = "plugin-user-management.plugins.openeverest.io/managed"
	purposeLabel  = "plugin-user-management.plugins.openeverest.io/purpose"
	usernameAnno  = "plugin-user-management.plugins.openeverest.io/username"
	databaseAnno  = "plugin-user-management.plugins.openeverest.io/database"
	roleAnno      = "plugin-user-management.plugins.openeverest.io/role"
	ownerAnno     = "plugin-user-management.plugins.openeverest.io/owner"
	reloadLabel   = "k8s.mariadb.com/watch"
	purposeAccess = "access"
	purposeOwner  = "owner"
)

func objectName(kind, instance string, identity ...string) string {
	sum := sha256.Sum256([]byte(instance + "\x00" + strings.Join(identity, "\x00")))
	return "openeverest-" + kind + "-" + hex.EncodeToString(sum[:10])
}

func userName(instance, username string) string {
	return objectName("user", instance, username)
}

func grantName(instance, username, database, role string) string {
	return objectName("grant", instance, username, database, role)
}

func ownerGrantName(instance, database, owner string) string {
	return objectName("owner", instance, database, owner)
}

func databaseObjectName(instance, database string) string {
	return objectName("database", instance, database)
}

func managedMetadata(c cluster, name, purpose string) map[string]any {
	metadata := map[string]any{
		"name":      name,
		"namespace": c.namespace,
		"labels": map[string]any{
			instanceLabel: c.name,
			managedLabel:  "true",
		},
		"ownerReferences": []any{map[string]any{
			"apiVersion": mariadbResource.GroupVersion().String(),
			"kind":       "MariaDB",
			"name":       c.name,
			"uid":        c.uid,
		}},
	}
	if purpose != "" {
		metadata["labels"].(map[string]any)[purposeLabel] = purpose
	}
	return metadata
}

func setAnnotation(obj *unstructured.Unstructured, key, value string) {
	annotations := obj.GetAnnotations()
	if annotations == nil {
		annotations = map[string]string{}
	}
	annotations[key] = value
	obj.SetAnnotations(annotations)
}

func userApplyConfiguration(c cluster, user engine.DesiredUser) *unstructured.Unstructured {
	metadata := managedMetadata(c, userName(c.name, user.Username), "")
	obj := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": userResource.GroupVersion().String(),
		"kind":       "User",
		"metadata":   metadata,
		"spec": map[string]any{
			"mariaDbRef": map[string]any{"name": c.name},
			"name":       user.Username,
			"host":       "%",
			"passwordSecretKeyRef": map[string]any{
				"name": user.Password.Name,
				"key":  user.Password.Key,
			},
			"cleanupPolicy": "Delete",
		},
	}}
	setAnnotation(obj, usernameAnno, user.Username)
	return obj
}

func grantApplyConfiguration(c cluster, username string, grant engine.RoleGrant) *unstructured.Unstructured {
	database := grant.Database
	table := "*"
	privileges := privilegesByRole[grant.Role]
	name := grantName(c.name, username, database, grant.Role)
	if grant.Role == roleMonitor {
		database, table = "*", "*"
		name = grantName(c.name, username, "*", roleMonitor)
	}
	metadata := managedMetadata(c, name, purposeAccess)
	obj := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": grantResource.GroupVersion().String(),
		"kind":       "Grant",
		"metadata":   metadata,
		"spec": map[string]any{
			"mariaDbRef":    map[string]any{"name": c.name},
			"privileges":    toAny(privileges),
			"database":      database,
			"table":         table,
			"username":      username,
			"host":          "%",
			"grantOption":   grant.Role == roleDBOwner,
			"cleanupPolicy": "Delete",
		},
	}}
	setAnnotation(obj, usernameAnno, username)
	setAnnotation(obj, databaseAnno, database)
	setAnnotation(obj, roleAnno, grant.Role)
	return obj
}

func ownerGrantApplyConfiguration(c cluster, database engine.DesiredDatabase) *unstructured.Unstructured {
	obj := grantApplyConfiguration(c, database.Owner, engine.RoleGrant{Role: roleDBOwner, Database: database.Name})
	obj.SetName(ownerGrantName(c.name, database.Name, database.Owner))
	labels := obj.GetLabels()
	labels[purposeLabel] = purposeOwner
	obj.SetLabels(labels)
	return obj
}

func databaseApplyConfiguration(c cluster, database engine.DesiredDatabase) *unstructured.Unstructured {
	obj := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": databaseResource.GroupVersion().String(),
		"kind":       "Database",
		"metadata":   managedMetadata(c, databaseObjectName(c.name, database.Name), ""),
		"spec": map[string]any{
			"mariaDbRef":    map[string]any{"name": c.name},
			"name":          database.Name,
			"cleanupPolicy": "Delete",
		},
	}}
	setAnnotation(obj, databaseAnno, database.Name)
	setAnnotation(obj, ownerAnno, database.Owner)
	return obj
}

func toAny(values []string) []any {
	out := make([]any, len(values))
	for i := range values {
		out[i] = values[i]
	}
	return out
}

func (e *Engine) applyObject(ctx context.Context, obj *unstructured.Unstructured) error {
	gvr := userResource
	switch obj.GetKind() {
	case "Grant":
		gvr = grantResource
	case "Database":
		gvr = databaseResource
	}
	_, err := e.dyn.Resource(gvr).Namespace(obj.GetNamespace()).
		Apply(ctx, obj.GetName(), obj, metav1.ApplyOptions{FieldManager: FieldManager, Force: true})
	if err != nil {
		return fmt.Errorf("apply %s: %w", obj.GetKind(), err)
	}
	return nil
}

func (e *Engine) managedObjects(ctx context.Context, gvr schema.GroupVersionResource, target engine.Target) ([]unstructured.Unstructured, error) {
	list, err := e.dyn.Resource(gvr).Namespace(target.Namespace).List(ctx, metav1.ListOptions{
		LabelSelector: instanceLabel + "=" + target.Instance + "," + managedLabel + "=true",
	})
	if err != nil {
		return nil, fmt.Errorf("list %s: %w", gvr.Resource, err)
	}
	return list.Items, nil
}

func (e *Engine) allObjects(ctx context.Context, gvr schema.GroupVersionResource, namespace string) ([]unstructured.Unstructured, error) {
	list, err := e.dyn.Resource(gvr).Namespace(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list %s: %w", gvr.Resource, err)
	}
	return list.Items, nil
}

func (e *Engine) ensureWatchLabel(ctx context.Context, namespace, name string) error {
	secrets := e.kube.CoreV1().Secrets(namespace)
	secret, err := secrets.Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("get password Secret %q: %w", name, err)
	}
	if _, found := secret.Labels[reloadLabel]; found {
		return nil
	}
	patch := fmt.Appendf(nil, `{"metadata":{"labels":{%q:"true"}}}`, reloadLabel)
	if _, err := secrets.Patch(ctx, name, types.MergePatchType, patch, metav1.PatchOptions{FieldManager: FieldManager}); err != nil {
		return fmt.Errorf("label password Secret %q: %w", name, err)
	}
	return nil
}

func (e *Engine) deleteObject(ctx context.Context, gvr schema.GroupVersionResource, namespace, name, cleanupPolicy, what string) error {
	objects := e.dyn.Resource(gvr).Namespace(namespace)
	obj, err := objects.Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("get %s %q: %w", what, name, err)
	}
	if obj.GetDeletionTimestamp() != nil {
		if reason := failureReason(obj); reason != "" {
			return fmt.Errorf("%w: MariaDB can't drop the %s: %s", engine.ErrInProgress, what, reason)
		}
		return fmt.Errorf("%w: MariaDB is dropping the %s", engine.ErrInProgress, what)
	}
	current, _, _ := unstructured.NestedString(obj.Object, "spec", "cleanupPolicy")
	if current != cleanupPolicy {
		patch := fmt.Appendf(nil, `{"spec":{"cleanupPolicy":%q}}`, cleanupPolicy)
		if _, err := objects.Patch(ctx, name, types.MergePatchType, patch, metav1.PatchOptions{FieldManager: FieldManager}); err != nil {
			return fmt.Errorf("set %s cleanup policy: %w", what, err)
		}
	}
	if err := objects.Delete(ctx, name, metav1.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("delete %s: %w", what, err)
	}
	return fmt.Errorf("%w: MariaDB is dropping the %s", engine.ErrInProgress, what)
}

func failureReason(obj *unstructured.Unstructured) string {
	conditions, _, _ := unstructured.NestedSlice(obj.Object, "status", "conditions")
	for _, item := range conditions {
		condition, ok := item.(map[string]any)
		if !ok || condition["type"] != "Ready" || condition["status"] != "False" {
			continue
		}
		message, _ := condition["message"].(string)
		return message
	}
	return ""
}

func objectReady(obj *unstructured.Unstructured) bool {
	conditions, _, _ := unstructured.NestedSlice(obj.Object, "status", "conditions")
	for _, item := range conditions {
		condition, ok := item.(map[string]any)
		if ok && condition["type"] == "Ready" && condition["status"] == "True" {
			return true
		}
	}
	return false
}

func grantReady(obj *unstructured.Unstructured) bool {
	if !objectReady(obj) {
		return false
	}
	current, currentFound, _ := unstructured.NestedStringSlice(obj.Object, "status", "currentPrivileges")
	desired, desiredFound, _ := unstructured.NestedStringSlice(obj.Object, "spec", "privileges")
	if !currentFound || !desiredFound || len(current) != len(desired) {
		return false
	}
	for _, privilege := range desired {
		found := false
		for _, applied := range current {
			if applied == privilege {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func deleteUnwantedGrants(ctx context.Context, e *Engine, target engine.Target, users map[string]bool, wanted map[string]bool) error {
	grants, err := e.managedObjects(ctx, grantResource, target)
	if err != nil {
		return err
	}
	for _, grant := range grants {
		if grant.GetLabels()[purposeLabel] != purposeAccess {
			continue
		}
		username := grant.GetAnnotations()[usernameAnno]
		if !users[username] || wanted[grant.GetName()] {
			continue
		}
		err := e.deleteObject(ctx, grantResource, target.Namespace, grant.GetName(), "Delete", "grant")
		if err != nil && !errors.Is(err, engine.ErrInProgress) {
			return err
		}
	}
	return nil
}

func expectedGrantNames(c cluster, users []engine.DesiredUser) map[string]bool {
	wanted := map[string]bool{}
	for _, user := range users {
		for _, role := range user.Roles {
			grant := grantApplyConfiguration(c, user.Username, role)
			wanted[grant.GetName()] = true
		}
	}
	return wanted
}

func grantIn(g *unstructured.Unstructured) engine.RoleGrant {
	annotations := g.GetAnnotations()
	database := annotations[databaseAnno]
	if database == "*" {
		database = ""
	}
	return engine.RoleGrant{Role: annotations[roleAnno], Database: database}
}

func readyAccessGrants(grants []unstructured.Unstructured, username string) []engine.RoleGrant {
	var roles []engine.RoleGrant
	for i := range grants {
		g := &grants[i]
		annotations := g.GetAnnotations()
		if g.GetLabels()[purposeLabel] == purposeAccess &&
			annotations[usernameAnno] == username &&
			grantReady(g) {
			roles = append(roles, grantIn(g))
		}
	}
	normalized, err := normalizeRoles(roles)
	if err == nil {
		return normalized
	}
	return []engine.RoleGrant{}
}
