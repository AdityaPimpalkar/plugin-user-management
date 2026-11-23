// Package pxc reconciles users and databases of Percona XtraDB Cluster
// instances served by provider-percona-xtradb-cluster. The operator's
// spec.users never revokes grants nor drops users, so the plugin manages
// accounts and databases directly in SQL as root, through the cluster's
// proxy. Galera replicates the account statements to every node. Which
// users and databases the plugin manages, and their owners, are kept in a
// catalog schema in the cluster.
package pxc

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"

	"github.com/openeverest/plugin-user-management/backend/internal/engine"
)

// ProviderName is the provider (Instance spec.providerRef.name) this engine serves.
const ProviderName = "percona-xtradb-cluster"

// resyncInterval is how often Ready users and databases are checked again,
// as privileges can be changed in SQL without the plugin noticing.
const resyncInterval = 5 * time.Minute

// Engine implements engine.Engine and engine.DatabaseEngine for Percona
// XtraDB Cluster.
type Engine struct {
	kube kubernetes.Interface
	dyn  dynamic.Interface
	dial dialer
	// problems keeps why a user couldn't be applied in the last SyncUsers,
	// by namespace/instance/username, for PendingReason.
	problems sync.Map
	// ownedGrants keeps, by namespace/instance/username, the roles last
	// declared for a user on databases it owns. The owner has every
	// privilege there, so they are reported as granted.
	ownedGrants sync.Map
}

var (
	_ engine.GrantedConnectEngine = (*Engine)(nil)
	_ engine.PendingReasoner      = (*Engine)(nil)
	_ engine.UserProblemReporter  = (*Engine)(nil)
	_ engine.Resyncer             = (*Engine)(nil)
)

// New returns an engine that reads PerconaXtraDBCluster resources and
// manages users and databases with go-sql-driver/mysql.
func New(kube kubernetes.Interface, dyn dynamic.Interface) *Engine {
	return &Engine{kube: kube, dyn: dyn, dial: dialDriver}
}

// Roles implements engine.Engine.
func (e *Engine) Roles() []engine.Role {
	return roleCatalog
}

// AuthDatabase implements engine.Engine. Users belong to the server.
func (e *Engine) AuthDatabase() string {
	return ""
}

// NormalizeRoles implements engine.Engine.
func (e *Engine) NormalizeRoles(grants []engine.RoleGrant) ([]engine.RoleGrant, error) {
	return normalizeRoles(grants)
}

// ValidateUser implements engine.Engine.
func (e *Engine) ValidateUser(user engine.DesiredUser) error {
	return validateUser(user)
}

// ResyncInterval implements engine.Resyncer.
func (e *Engine) ResyncInterval() time.Duration {
	return resyncInterval
}

// OnlyGrantedConnect implements engine.GrantedConnectEngine: MySQL users
// only see the databases they have privileges on.
func (e *Engine) OnlyGrantedConnect() {}

func userKey(target engine.Target, username string) string {
	return target.Namespace + "/" + target.Instance + "/" + username
}

// connect connects as root once the cluster is ready.
func (e *Engine) connect(ctx context.Context, target engine.Target) (cluster, session, error) {
	c, err := e.resolve(ctx, target)
	if err != nil {
		return cluster{}, nil, err
	}
	if !c.ready() {
		state := c.state
		if state == "" {
			state = "initializing"
		}
		msg := fmt.Sprintf("Percona XtraDB Cluster is %q", state)
		if c.message != "" {
			msg += ": " + c.message
		}
		return cluster{}, nil, fmt.Errorf("%w: %s", engine.ErrNotReady, msg)
	}
	if err := e.credentials(ctx, &c); err != nil {
		return cluster{}, nil, err
	}
	s, err := e.dial(ctx, c)
	if err != nil {
		return cluster{}, nil, err
	}
	return c, s, nil
}

// connectCatalog connects and reads the server, with the catalog created.
func (e *Engine) connectCatalog(ctx context.Context, target engine.Target) (session, *snapshot, error) {
	_, s, err := e.connect(ctx, target)
	if err != nil {
		return nil, nil, err
	}
	if err := s.ensureCatalog(ctx); err != nil {
		s.close()
		return nil, nil, err
	}
	snap, err := s.snapshot(ctx)
	if err != nil {
		s.close()
		return nil, nil, err
	}
	return s, snap, nil
}

// SyncUsers implements engine.Engine. Each user is a 'user'@'%' account
// with the user's password, the global monitoring privileges when granted
// monitor, and on each database the privileges of its role there. The
// plugin owns the database privileges of the users it manages: those no
// role declares are revoked. Users that leave the set keep their account
// as last applied until DropUser.
func (e *Engine) SyncUsers(ctx context.Context, target engine.Target, users []engine.DesiredUser) error {
	if len(users) == 0 {
		return nil
	}
	s, snap, err := e.connectCatalog(ctx, target)
	if err != nil {
		return err
	}
	defer s.close()

	var errs []error
	for _, u := range users {
		problem, err := e.declareUser(ctx, s, snap, target, u)
		if err != nil {
			errs = append(errs, fmt.Errorf("user %q: %w", u.Username, err))
			continue
		}
		if problem != "" {
			e.problems.Store(userKey(target, u.Username), problem)
		} else {
			e.problems.Delete(userKey(target, u.Username))
		}
	}
	return errors.Join(errs...)
}

// declareUser applies one user. A problem keeps the user from being applied
// until the user or the cluster changes; an error is worth retrying.
func (e *Engine) declareUser(ctx context.Context, s session, snap *snapshot, target engine.Target, user engine.DesiredUser) (problem string, err error) {
	if err := validateUser(user); err != nil {
		return err.Error(), nil
	}
	roles, err := normalizeRoles(user.Roles)
	if err != nil {
		return err.Error(), nil
	}
	name := user.Username
	current := snap.accounts[name]
	stored, managed := snap.managedUsers[name]
	if current != nil && !managed {
		return fmt.Sprintf("user %q already exists in MySQL and isn't managed by OpenEverest", name), nil
	}
	password, problem, err := e.readPassword(ctx, target.Namespace, user.Password)
	if err != nil || problem != "" {
		return problem, err
	}

	var stmts []stmt
	if !managed {
		// Claimed before it's created, so it's never mistaken for a user
		// created out of the plugin.
		stmts = append(stmts, stmt{
			sql:  "INSERT IGNORE INTO " + catalogTable(usersTable) + " (name) VALUES (?)",
			args: []any{name},
		})
	}
	passwordChanged := current == nil || !current.anyHost || !fingerprintMatches(stored, password)
	if passwordChanged {
		fp, err := fingerprint(password)
		if err != nil {
			return "", err
		}
		verb := "ALTER USER "
		if current == nil || !current.anyHost {
			verb = "CREATE USER IF NOT EXISTS "
		}
		stmts = append(stmts,
			stmt{sql: verb + account(name) + " IDENTIFIED BY ?", args: []any{password}},
			stmt{sql: "UPDATE " + catalogTable(usersTable) + " SET password_fingerprint = ? WHERE name = ?", args: []any{fp, name}},
		)
	}
	if err := s.exec(ctx, stmts); err != nil {
		if reason := serverReason(err); reason != "" {
			return "MySQL can't apply the user: " + reason, nil
		}
		return "", err
	}

	owned := snap.owned(name)
	var ownedRoles []engine.RoleGrant
	wanted := map[string]string{}
	monitor := false
	for _, g := range roles {
		switch {
		case g.Role == roleMonitor:
			monitor = true
		case owned[g.Database]:
			ownedRoles = append(ownedRoles, g)
		default:
			wanted[grantPattern(g.Database)] = g.Role
		}
	}
	e.ownedGrants.Store(userKey(target, name), ownedRoles)

	var problems []string
	for _, st := range planGrants(name, snap, wanted, owned, monitor) {
		if err := s.exec(ctx, []stmt{st}); err != nil {
			reason := serverReason(err)
			if reason == "" {
				return "", err
			}
			problems = append(problems, "MySQL can't apply the user's privileges: "+reason)
		}
	}
	return strings.Join(problems, "; "), nil
}

// planGrants returns the statements that give the user the wanted role on
// each database pattern, and the monitoring privileges when monitor is
// set. Privileges on databases the user owns are left to SyncDatabase.
func planGrants(name string, snap *snapshot, wanted map[string]string, owned map[string]bool, monitor bool) []stmt {
	current := snap.grants[name]
	patterns := make([]string, 0, len(current)+len(wanted))
	for pattern := range current {
		patterns = append(patterns, pattern)
	}
	for pattern := range wanted {
		if _, found := current[pattern]; !found {
			patterns = append(patterns, pattern)
		}
	}
	sort.Strings(patterns)

	var stmts []stmt
	for _, pattern := range patterns {
		if database, literal := literalDatabase(pattern); literal && owned[database] {
			continue
		}
		have := current[pattern]
		role := wanted[pattern]
		var want []string
		if role != "" {
			want = desiredPrivileges(role, snap.allPrivileges)
		}
		if slices.Equal(have, want) {
			continue
		}
		stmts = append(stmts, revokeStatements(pattern, name, have)...)
		if role != "" {
			stmts = append(stmts, grantStatement(role, pattern, name))
		}
	}

	a := snap.accounts[name]
	hasMonitor := a != nil && a.process && a.replClient
	hasAny := a != nil && (a.process || a.replClient)
	switch {
	case monitor && !hasMonitor:
		stmts = append(stmts, stmt{sql: "GRANT PROCESS, REPLICATION CLIENT ON *.* TO " + account(name)})
	case !monitor && hasAny:
		stmts = append(stmts, stmt{sql: "REVOKE PROCESS, REPLICATION CLIENT ON *.* FROM " + account(name)})
	}
	return stmts
}

// readPassword returns the user's password, or a problem that keeps the
// user from having one.
func (e *Engine) readPassword(ctx context.Context, namespace string, ref engine.SecretKeyRef) (password, problem string, err error) {
	secret, err := e.kube.CoreV1().Secrets(namespace).Get(ctx, ref.Name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return "", fmt.Sprintf("password Secret %q not found", ref.Name), nil
	}
	if err != nil {
		return "", "", fmt.Errorf("get password secret %q: %w", ref.Name, err)
	}
	password = string(secret.Data[ref.Key])
	if password == "" {
		return "", fmt.Sprintf("password Secret %q has no %q key", ref.Name, ref.Key), nil
	}
	return password, "", nil
}

// ListUsers implements engine.Engine. A user's roles are read from its
// privileges; on a database it owns, they're the roles last declared.
func (e *Engine) ListUsers(ctx context.Context, target engine.Target) ([]engine.User, error) {
	_, s, err := e.connect(ctx, target)
	if err != nil {
		return nil, err
	}
	defer s.close()
	snap, err := s.snapshot(ctx)
	if err != nil {
		return nil, err
	}
	users := make([]engine.User, 0, len(snap.accounts))
	for name := range snap.accounts {
		_, managed := snap.managedUsers[name]
		users = append(users, engine.User{
			Username: name,
			Roles:    e.grants(target, name, snap),
			System:   !managed && isSystemUser(name),
		})
	}
	sort.Slice(users, func(i, j int) bool { return users[i].Username < users[j].Username })
	return users, nil
}

func (e *Engine) grants(target engine.Target, name string, snap *snapshot) []engine.RoleGrant {
	grants := []engine.RoleGrant{}
	if a := snap.accounts[name]; a.process && a.replClient {
		grants = append(grants, engine.RoleGrant{Role: roleMonitor})
	}
	owned := snap.owned(name)
	if v, ok := e.ownedGrants.Load(userKey(target, name)); ok {
		for _, g := range v.([]engine.RoleGrant) {
			if owned[g.Database] {
				grants = append(grants, g)
			}
		}
	}
	patterns := make([]string, 0, len(snap.grants[name]))
	for pattern := range snap.grants[name] {
		patterns = append(patterns, pattern)
	}
	sort.Strings(patterns)
	for _, pattern := range patterns {
		database, literal := literalDatabase(pattern)
		if !literal || owned[database] {
			continue
		}
		if role := roleFor(snap.grants[name][pattern], snap.allPrivileges); role != "" {
			grants = append(grants, engine.RoleGrant{Role: role, Database: database})
		}
	}
	return grants
}

// DropUser implements engine.Engine. Only users the plugin created are
// dropped. A user that owns a database stays until the database gets
// another owner. MySQL lets the user's open connections run until they end.
func (e *Engine) DropUser(ctx context.Context, target engine.Target, username string) error {
	if validateUser(engine.DesiredUser{Username: username}) != nil {
		return nil
	}
	_, s, err := e.connect(ctx, target)
	if err != nil {
		return err
	}
	defer s.close()
	snap, err := s.snapshot(ctx)
	if err != nil {
		return err
	}
	if _, managed := snap.managedUsers[username]; !managed {
		e.forget(target, username)
		return nil
	}
	databases := make([]string, 0, len(snap.managedDatabases))
	for database, owner := range snap.managedDatabases {
		if owner == username {
			databases = append(databases, database)
		}
	}
	if len(databases) > 0 {
		sort.Strings(databases)
		return fmt.Errorf("%w: user %q owns database %q; give the database another owner first", engine.ErrInProgress, username, databases[0])
	}
	err = s.exec(ctx, []stmt{
		{sql: "DROP USER IF EXISTS " + account(username)},
		{sql: "DELETE FROM " + catalogTable(usersTable) + " WHERE name = ?", args: []any{username}},
	})
	if err != nil {
		return inProgress(err, "MySQL can't drop the user")
	}
	e.forget(target, username)
	return nil
}

func (e *Engine) forget(target engine.Target, username string) {
	e.problems.Delete(userKey(target, username))
	e.ownedGrants.Delete(userKey(target, username))
}

// inProgress reports a server error as ErrInProgress with what failed;
// other errors are returned as they are, to be retried.
func inProgress(err error, what string) error {
	if reason := serverReason(err); reason != "" {
		return fmt.Errorf("%w: %s: %s", engine.ErrInProgress, what, reason)
	}
	return err
}

// PendingReason implements engine.PendingReasoner. Without a problem, the
// user was just applied and shows up on the next reconcile.
func (e *Engine) PendingReason(_ context.Context, target engine.Target, username string) string {
	if problem := e.UserProblem(target, username); problem != "" {
		return problem
	}
	return "applying the user in Percona XtraDB Cluster"
}

// UserProblem implements engine.UserProblemReporter.
func (e *Engine) UserProblem(target engine.Target, username string) string {
	if v, ok := e.problems.Load(userKey(target, username)); ok {
		return v.(string)
	}
	return ""
}

// ConnectionURI implements engine.Engine. It connects through the proxy, as
// the Instance's own connection details do.
func (e *Engine) ConnectionURI(ctx context.Context, target engine.Target, username, password string) (string, error) {
	c, err := e.resolve(ctx, target)
	if err != nil {
		return "", err
	}
	uri := url.URL{
		Scheme: "mysql",
		User:   url.UserPassword(username, password),
		Host:   net.JoinHostPort(c.host, strconv.Itoa(c.port)),
	}
	return uri.String(), nil
}
