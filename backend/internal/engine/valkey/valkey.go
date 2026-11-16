// Package valkey reconciles users of Valkey instances served by
// provider-valkey through the valkey-operator's ACL API: the plugin declares
// users in the ValkeyCluster's spec.acl.users next to the provider's default
// user, and the operator renders them into an aclfile that every node loads.
package valkey

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"
	"sync"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"

	"github.com/openeverest/plugin-user-management/backend/internal/engine"
)

// ProviderName is the provider (Instance spec.providerRef.name) this engine serves.
const ProviderName = "valkey"

const (
	// FieldManager owns the plugin's entries of ValkeyCluster spec.acl.users.
	// The provider applies its default user under its own field manager;
	// the list is keyed by name, so the two don't conflict.
	FieldManager = "plugin-user-management"
	// passwordsAnnotation carries a digest of the declared users' passwords.
	// The operator doesn't watch the plugin's Secrets: changing the
	// annotation makes it render a new password into the aclfile.
	passwordsAnnotation = "plugin-user-management.plugins.openeverest.io/passwords"

	// defaultUser is the provider's user; Valkey always has one.
	defaultUser = "default"
	// Valkey's users starting with "_" are the operator's.
	systemUserPrefix = "_"
	// The operator takes a 65 character value starting with "#" as a SHA-256
	// hash rather than a password.
	preHashedLength = 65
)

// Engine implements engine.Engine for Valkey.
type Engine struct {
	kube  kubernetes.Interface
	dyn   dynamic.Interface
	apply func(ctx context.Context, target engine.Target, obj *unstructured.Unstructured) error
	// loaded keeps, by namespace/instance, the aclfile entries every ready
	// node had loaded when last seen, so users whose entry didn't change
	// stay listed while a new revision rolls out.
	loaded sync.Map
	// problems keeps why a user couldn't be declared in the last SyncUsers,
	// by namespace/instance/username.
	problems sync.Map
}

// New returns an engine that writes ValkeyCluster spec.acl.users and reads
// the operator's aclfile and ValkeyNodes.
func New(kube kubernetes.Interface, dyn dynamic.Interface) *Engine {
	e := &Engine{kube: kube, dyn: dyn}
	e.apply = e.applyCluster
	return e
}

// Roles implements engine.Engine.
func (e *Engine) Roles() []engine.Role {
	return roleCatalog
}

// AuthDatabase implements engine.Engine. Valkey users belong to the whole instance.
func (e *Engine) AuthDatabase() string {
	return ""
}

// NormalizeRoles implements engine.Engine.
func (e *Engine) NormalizeRoles(grants []engine.RoleGrant) ([]engine.RoleGrant, error) {
	return normalizeRoles(grants)
}

// ValidateUser implements engine.Engine. The InstanceUser username pattern
// already keeps out the operator's "_" users and whitespace.
func (e *Engine) ValidateUser(user engine.DesiredUser) error {
	if user.Username == defaultUser || strings.HasPrefix(user.Username, systemUserPrefix) {
		return fmt.Errorf("%w: user %q is reserved", engine.ErrInvalid, user.Username)
	}
	return nil
}

func targetKey(target engine.Target) string {
	return target.Namespace + "/" + target.Instance
}

func problemKey(target engine.Target, username string) string {
	return targetKey(target) + "/" + username
}

// SyncUsers implements engine.Engine. A user whose password can't be read is
// left out: the operator stops updating the whole aclfile when one password
// is missing.
func (e *Engine) SyncUsers(ctx context.Context, target engine.Target, users []engine.DesiredUser) error {
	if _, err := e.getCluster(ctx, target); err != nil {
		return err
	}
	entries := make([]any, 0, len(users))
	digest := sha256.New()
	users = append([]engine.DesiredUser{}, users...)
	sort.Slice(users, func(i, j int) bool { return users[i].Username < users[j].Username })
	for _, u := range users {
		key := problemKey(target, u.Username)
		if err := e.ValidateUser(u); err != nil {
			e.problems.Store(key, err.Error())
			continue
		}
		password, problem, err := e.readPassword(ctx, target, u.Password)
		if err != nil {
			return err
		}
		if problem != "" {
			e.problems.Store(key, problem)
			continue
		}
		e.problems.Delete(key)
		sum := sha256.Sum256(password)
		fmt.Fprintf(digest, "%s\x00%x\n", u.Username, sum)
		entries = append(entries, aclEntry(u))
	}

	obj := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": clusterResource.GroupVersion().String(),
		"kind":       "ValkeyCluster",
		"metadata":   map[string]any{"name": target.Instance, "namespace": target.Namespace},
		"spec":       map[string]any{},
	}}
	// With no users, applying neither releases the plugin's entries and
	// annotation, which the API server then removes.
	if len(entries) > 0 {
		obj.SetAnnotations(map[string]string{passwordsAnnotation: hex.EncodeToString(digest.Sum(nil))})
		obj.Object["spec"] = map[string]any{"acl": map[string]any{"users": entries}}
	}
	return e.apply(ctx, target, obj)
}

// readPassword reads a user's password, or tells why it can't be used.
func (e *Engine) readPassword(ctx context.Context, target engine.Target, ref engine.SecretKeyRef) ([]byte, string, error) {
	secret, err := e.kube.CoreV1().Secrets(target.Namespace).Get(ctx, ref.Name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil, fmt.Sprintf("password Secret %q not found", ref.Name), nil
	}
	if err != nil {
		return nil, "", fmt.Errorf("get password secret %q: %w", ref.Name, err)
	}
	password := secret.Data[ref.Key]
	switch {
	case len(password) == 0:
		return nil, fmt.Sprintf("password Secret %q has no key %q", ref.Name, ref.Key), nil
	case len(password) == preHashedLength && password[0] == '#':
		return nil, fmt.Sprintf("the password in Secret %q looks like a SHA-256 hash (\"#\" and 64 characters), which Valkey would take as the hash", ref.Name), nil
	}
	return password, "", nil
}

// aclEntry is the spec.acl.users entry of a user.
func aclEntry(u engine.DesiredUser) map[string]any {
	p := toPermissions(u.Roles)
	entry := map[string]any{
		"name":  u.Username,
		"state": "Enabled",
		"password": map[string]any{
			"type":   "Secret",
			"secret": map[string]any{"name": u.Password.Name, "keys": []any{u.Password.Key}},
		},
		"commands": map[string]any{"allow": toAny(p.allow), "deny": toAny(p.deny)},
	}
	if len(p.keys) > 0 {
		entry["keys"] = map[string]any{"readWrite": toAny(p.keys)}
	}
	if len(p.channels) > 0 {
		entry["channels"] = map[string]any{"patterns": toAny(p.channels)}
	}
	return entry
}

func toAny(s []string) []any {
	out := make([]any, len(s))
	for i, v := range s {
		out[i] = v
	}
	return out
}

func (e *Engine) applyCluster(ctx context.Context, target engine.Target, obj *unstructured.Unstructured) error {
	_, err := e.dyn.Resource(clusterResource).Namespace(target.Namespace).Apply(ctx, target.Instance, obj,
		metav1.ApplyOptions{FieldManager: FieldManager, Force: true})
	if err != nil {
		return fmt.Errorf("apply ValkeyCluster users: %w", err)
	}
	return nil
}

// ListUsers implements engine.Engine. Users are read from the aclfile the
// operator renders, and listed once every ready node has loaded their
// current entry: in cluster mode, a user missing on one shard fails on the
// keys it holds.
func (e *Engine) ListUsers(ctx context.Context, target engine.Target) ([]engine.User, error) {
	s, err := e.readACL(ctx, target)
	if err != nil {
		return nil, err
	}
	entries := s.entries
	if s.pendingNodes == 0 {
		e.loaded.Store(targetKey(target), s.entries)
	} else {
		var loaded map[string]string
		if v, ok := e.loaded.Load(targetKey(target)); ok {
			loaded = v.(map[string]string)
		}
		entries = map[string]string{}
		for name, rules := range s.entries {
			if isSystemUser(name) || loaded[name] == rules {
				entries[name] = rules
			}
		}
	}

	users := make([]engine.User, 0, len(entries))
	for name, rules := range entries {
		u := engine.User{
			Username: name,
			Roles:    []engine.RoleGrant{},
			System:   isSystemUser(name),
			Hidden:   name == aclRevisionUser,
		}
		// System users' ACLs aren't made of the catalog's roles: matching
		// them would show, for example, _replication as readWrite.
		if !u.System {
			u.Roles = fromRules(strings.Fields(rules))
		}
		users = append(users, u)
	}
	sort.Slice(users, func(i, j int) bool { return users[i].Username < users[j].Username })
	return users, nil
}

func isSystemUser(name string) bool {
	return name == defaultUser || strings.HasPrefix(name, systemUserPrefix)
}

// DropUser implements engine.Engine. Users left out of spec.acl.users are
// removed by the operator, which reloads the aclfile without them.
func (e *Engine) DropUser(ctx context.Context, target engine.Target, username string) error {
	e.problems.Delete(problemKey(target, username))
	if _, err := e.dyn.Resource(clusterResource).Namespace(target.Namespace).Get(ctx, target.Instance, metav1.GetOptions{}); apierrors.IsNotFound(err) {
		return nil
	}
	s, err := e.readACL(ctx, target)
	if errors.Is(err, engine.ErrNotReady) {
		return fmt.Errorf("%w: %v", engine.ErrInProgress, err)
	}
	if err != nil {
		return err
	}
	if _, found := s.entries[username]; found {
		return fmt.Errorf("%w: waiting for the operator to remove the user from the ACL", engine.ErrInProgress)
	}
	if s.pendingNodes > 0 {
		return fmt.Errorf("%w: waiting for %d of %d Valkey nodes to load the ACL", engine.ErrInProgress, s.pendingNodes, s.readyNodes)
	}
	return nil
}

// UserProblem implements engine.UserProblemReporter.
func (e *Engine) UserProblem(target engine.Target, username string) string {
	if v, ok := e.problems.Load(problemKey(target, username)); ok {
		return v.(string)
	}
	return ""
}

// PendingReason implements engine.PendingReasoner.
func (e *Engine) PendingReason(ctx context.Context, target engine.Target, username string) string {
	s, err := e.readACL(ctx, target)
	if err != nil {
		return ""
	}
	if s.problem != "" {
		return "the operator can't apply the ACL: " + s.problem
	}
	if _, found := s.entries[username]; found && s.pendingNodes > 0 {
		return fmt.Sprintf("waiting for %d of %d Valkey nodes to load the ACL", s.pendingNodes, s.readyNodes)
	}
	return ""
}

// ConnectionURI implements engine.Engine with the instance's address from
// its connection Secret.
func (e *Engine) ConnectionURI(ctx context.Context, target engine.Target, username, password string) (string, error) {
	c, err := e.readConnection(ctx, target)
	if err != nil {
		return "", err
	}
	scheme := "redis"
	if c.tls {
		scheme = "rediss"
	}
	uri := url.URL{Scheme: scheme, User: url.UserPassword(username, password), Host: net.JoinHostPort(c.host, c.port)}
	return uri.String(), nil
}

// ConnectionProperties implements engine.ConnectionPropertiesProvider: with
// TLS on, clients need the instance's CA. The provider's client certificate
// is the default user's and is never handed out.
func (e *Engine) ConnectionProperties(ctx context.Context, target engine.Target) (map[string]string, error) {
	c, err := e.readConnection(ctx, target)
	if err != nil {
		return nil, err
	}
	if !c.tls {
		return map[string]string{}, nil
	}
	props := map[string]string{"ssl": "true"}
	if c.ca != "" {
		props[caCertKey] = c.ca
	}
	return props, nil
}
