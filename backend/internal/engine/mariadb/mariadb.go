// Package mariadb reconciles users and databases of MariaDB instances served
// by provider-mariadb. The mariadb-operator owns the SQL changes through its
// User, Grant and Database resources; the plugin uses the root account only
// to inspect the accounts and schemas that actually exist.
package mariadb

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"

	"github.com/openeverest/plugin-user-management/backend/internal/engine"
)

const ProviderName = "mariadb"

// Engine implements user and database management for MariaDB.
type Engine struct {
	kube    kubernetes.Interface
	dyn     dynamic.Interface
	resolve func(context.Context, engine.Target) (cluster, error)
	dial    dialer
	apply   func(context.Context, *unstructured.Unstructured) error
}

var (
	_ engine.Engine               = (*Engine)(nil)
	_ engine.DatabaseEngine       = (*Engine)(nil)
	_ engine.GrantedConnectEngine = (*Engine)(nil)
	_ engine.PendingReasoner      = (*Engine)(nil)
	_ engine.Resyncer             = (*Engine)(nil)
)

// New returns an engine using mariadb-operator resources and the MariaDB root account.
func New(kube kubernetes.Interface, dyn dynamic.Interface) *Engine {
	resolver := &clusterResolver{kube: kube, dyn: dyn}
	e := &Engine{kube: kube, dyn: dyn, resolve: resolver.resolve, dial: dialDriver}
	e.apply = e.applyObject
	return e
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

func (e *Engine) ValidateUser(user engine.DesiredUser) error {
	return validateUser(user)
}

func (e *Engine) ResyncInterval() time.Duration {
	return 5 * time.Minute
}

// OnlyGrantedConnect is enabled by the database-scoped Grant resources.
func (e *Engine) OnlyGrantedConnect() {}

// SyncUsers declares a User and one Grant per database-scoped role, plus one
// global monitoring Grant. Password Secrets are watched by mariadb-operator.
func (e *Engine) SyncUsers(ctx context.Context, target engine.Target, users []engine.DesiredUser) error {
	c, err := e.resolve(ctx, target)
	if err != nil {
		return err
	}
	users = append([]engine.DesiredUser(nil), users...)
	sort.Slice(users, func(i, j int) bool { return users[i].Username < users[j].Username })
	usernames := make(map[string]bool, len(users))
	normalizedUsers := make([]engine.DesiredUser, 0, len(users))
	for _, user := range users {
		usernames[user.Username] = true
		roles, err := normalizeRoles(user.Roles)
		if err != nil {
			return fmt.Errorf("user %q: %w", user.Username, err)
		}
		if err := validateUser(user); err != nil {
			return err
		}
		user.Roles = roles
		normalizedUsers = append(normalizedUsers, user)
		if err := e.ensureWatchLabel(ctx, target.Namespace, user.Password.Name); err != nil {
			return err
		}
		if err := e.apply(ctx, userApplyConfiguration(c, user)); err != nil {
			return err
		}
		for _, role := range user.Roles {
			if err := e.apply(ctx, grantApplyConfiguration(c, user.Username, role)); err != nil {
				return fmt.Errorf("apply grant for user %q: %w", user.Username, err)
			}
		}
	}
	if err := deleteUnwantedGrants(ctx, e, target, usernames, expectedGrantNames(c, normalizedUsers)); err != nil {
		return err
	}
	return nil
}

// ListUsers reads actual MariaDB accounts. Roles are reported only from the
// plugin's ready Grant resources, so an in-flight revocation stays Pending.
func (e *Engine) ListUsers(ctx context.Context, target engine.Target) ([]engine.User, error) {
	c, err := e.resolve(ctx, target)
	if err != nil {
		return nil, err
	}
	s, err := e.dial(ctx, c)
	if err != nil {
		return nil, err
	}
	defer s.close()
	actual, err := s.users(ctx)
	if err != nil {
		return nil, err
	}
	grants, err := e.managedObjects(ctx, grantResource, target)
	if err != nil {
		return nil, err
	}

	byName := map[string]engine.User{}
	for _, dbUser := range actual {
		user, found := byName[dbUser.name]
		if !found {
			user = engine.User{
				Username: dbUser.name,
				Roles:    []engine.RoleGrant{},
				System:   c.systemUsers[dbUser.name],
			}
		}
		user.Roles = readyAccessGrants(grants, dbUser.name)
		byName[dbUser.name] = user
	}

	all, err := e.allObjects(ctx, userResource, target.Namespace)
	if err != nil {
		return nil, err
	}
	for i := range all {
		obj := all[i]
		ref, _, _ := unstructured.NestedString(obj.Object, "spec", "mariaDbRef", "name")
		if ref != target.Instance || obj.GetLabels()[managedLabel] == "true" {
			continue
		}
		name, _, _ := unstructured.NestedString(obj.Object, "spec", "name")
		if name == "" {
			name = obj.GetName()
		}
		if _, found := byName[name]; !found {
			byName[name] = engine.User{Username: name, Roles: []engine.RoleGrant{}, System: false}
		}
	}

	users := make([]engine.User, 0, len(byName))
	for _, user := range byName {
		users = append(users, user)
	}
	sort.Slice(users, func(i, j int) bool { return users[i].Username < users[j].Username })
	return users, nil
}

// DropUser removes grants before its operator User resource.
func (e *Engine) DropUser(ctx context.Context, target engine.Target, username string) error {
	grants, err := e.managedObjects(ctx, grantResource, target)
	if err != nil {
		return err
	}
	for _, grant := range grants {
		if grant.GetAnnotations()[usernameAnno] == username && grant.GetLabels()[purposeLabel] == purposeOwner {
			database := grant.GetAnnotations()[databaseAnno]
			return fmt.Errorf("%w: user %q owns database %q; give the database another owner first", engine.ErrInProgress, username, database)
		}
	}
	pending := false
	for _, grant := range grants {
		if grant.GetAnnotations()[usernameAnno] != username {
			continue
		}
		err := e.deleteObject(ctx, grantResource, target.Namespace, grant.GetName(), "Delete", "grant")
		if errors.Is(err, engine.ErrInProgress) {
			pending = true
		} else if err != nil {
			return err
		}
	}
	if pending {
		return fmt.Errorf("%w: MariaDB is revoking the user's grants", engine.ErrInProgress)
	}
	return e.deleteObject(ctx, userResource, target.Namespace, userName(target.Instance, username), "Delete", "user")
}

func (e *Engine) PendingReason(ctx context.Context, target engine.Target, username string) string {
	user, err := e.dyn.Resource(userResource).Namespace(target.Namespace).
		Get(ctx, userName(target.Instance, username), metav1.GetOptions{})
	if err == nil {
		if reason := failureReason(user); reason != "" {
			return "MariaDB can't apply the user: " + reason
		}
		if !objectReady(user) {
			return "applying the user in MariaDB"
		}
	}
	grants, err := e.managedObjects(ctx, grantResource, target)
	if err == nil {
		for i := range grants {
			grant := &grants[i]
			if grant.GetAnnotations()[usernameAnno] != username || grant.GetDeletionTimestamp() != nil {
				continue
			}
			if reason := failureReason(grant); reason != "" {
				return "MariaDB can't grant access: " + reason
			}
			if !objectReady(grant) {
				return "applying the user's grants in MariaDB"
			}
		}
	}
	return "applying the user in MariaDB"
}

func (e *Engine) ConnectionURI(ctx context.Context, target engine.Target, username, password string) (string, error) {
	c, err := e.resolve(ctx, target)
	if err != nil {
		return "", err
	}
	uri := url.URL{
		Scheme: "mysql",
		User:   url.UserPassword(username, password),
		Host:   fmt.Sprintf("%s:%d", c.host, c.port),
	}
	if c.tlsEnabled {
		uri.RawQuery = url.Values{"tls": {"true"}}.Encode()
	}
	return uri.String(), nil
}
