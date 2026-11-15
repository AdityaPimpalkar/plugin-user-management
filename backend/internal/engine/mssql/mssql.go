// Package mssql reconciles users and databases of SQL Server instances run
// by the Solanica MSSQL operator (provider "mssql"). The operator doesn't
// manage logins, so the plugin creates, alters and drops them directly, as
// sa, on the primary. On Availability Groups the operator copies logins,
// server roles and server permissions to the secondaries, and adds the
// databases the plugin creates to the group; database users and role
// memberships live in the databases and move with them.
package mssql

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
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
const ProviderName = "mssql"

// resyncInterval is how often Ready users and databases are checked again:
// a failover of an Availability Group can lose the last changes the
// operator hadn't copied to the new primary yet.
const resyncInterval = 5 * time.Minute

// Engine implements engine.Engine and engine.DatabaseEngine for SQL Server.
type Engine struct {
	kube kubernetes.Interface
	dyn  dynamic.Interface
	dial dialer
	// problems keeps why a user couldn't be applied in the last SyncUsers,
	// by namespace/instance/username, for PendingReason.
	problems sync.Map
	// ownedGrants keeps, by namespace/instance/username, the grants last
	// declared for a user on databases it owns. The owner is dbo there,
	// which holds every role, so they are reported as granted.
	ownedGrants sync.Map
}

var (
	_ engine.GrantedConnectEngine = (*Engine)(nil)
	_ engine.PendingReasoner      = (*Engine)(nil)
	_ engine.Resyncer             = (*Engine)(nil)
)

// New returns an engine that reads the operator's resources and manages
// logins and databases with go-mssqldb.
func New(kube kubernetes.Interface, dyn dynamic.Interface) *Engine {
	return &Engine{kube: kube, dyn: dyn, dial: sqlDialer(kube)}
}

// Roles implements engine.Engine.
func (e *Engine) Roles() []engine.Role {
	return roleCatalog
}

// AuthDatabase implements engine.Engine. Logins belong to the server.
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

// OnlyGrantedConnect implements engine.GrantedConnectEngine: SQL Server
// only lets a login into a database where it has a user, which the plugin
// creates for the owner and the users granted a role on it.
func (e *Engine) OnlyGrantedConnect() {}

func userKey(target engine.Target, username string) string {
	return target.Namespace + "/" + target.Instance + "/" + username
}

// connect connects to the primary once the instance is ready.
func (e *Engine) connect(ctx context.Context, target engine.Target) (cluster, session, error) {
	c, err := e.resolve(ctx, target)
	if err != nil {
		return cluster{}, nil, err
	}
	if c.unsupported != "" {
		return cluster{}, nil, fmt.Errorf("%w: %s", engine.ErrNotReady, c.unsupported)
	}
	if !c.ready {
		state := c.state
		if state == "" {
			state = "Initializing"
		}
		return cluster{}, nil, fmt.Errorf("%w: SQL Server instance is %q", engine.ErrNotReady, state)
	}
	s, err := e.dial(ctx, c)
	if err != nil {
		return cluster{}, nil, err
	}
	return c, s, nil
}

const ensureManagedRole = `IF NOT EXISTS (SELECT 1 FROM sys.server_principals WHERE name = N'` + managedRole + `' AND type = 'R')
CREATE SERVER ROLE ` + "[" + managedRole + "]"

// SyncUsers implements engine.Engine. Each user is a SQL login with the
// user's password, a member of the plugin's server role, and a user in each
// managed database it's granted a role on. Users that leave the set keep
// their login as last applied until DropUser.
func (e *Engine) SyncUsers(ctx context.Context, target engine.Target, users []engine.DesiredUser) error {
	if len(users) == 0 {
		return nil
	}
	c, s, err := e.connect(ctx, target)
	if err != nil {
		return err
	}
	defer s.close()
	if err := s.execEach(ctx, []stmt{{sql: ensureManagedRole}}); err != nil {
		return fmt.Errorf("create server role %s: %w", managedRole, err)
	}
	logins, err := s.logins(ctx)
	if err != nil {
		return err
	}
	byName := map[string]*login{}
	for i := range logins {
		byName[logins[i].name] = &logins[i]
	}
	dbs, err := s.databases(ctx)
	if err != nil {
		return err
	}

	var errs []error
	for _, u := range users {
		problem, err := e.declareUser(ctx, c, s, target, u, byName[u.Username], dbs)
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
// until the user or the database changes; an error is worth retrying.
func (e *Engine) declareUser(ctx context.Context, c cluster, s session, target engine.Target,
	user engine.DesiredUser, current *login, dbs []database,
) (problem string, err error) {
	if err := validateUser(user); err != nil {
		return err.Error(), nil
	}
	if current != nil && isSystemLogin(*current) {
		return fmt.Sprintf("user %q is reserved for SQL Server", user.Username), nil
	}
	roles, err := normalizeRoles(user.Roles)
	if err != nil {
		return err.Error(), nil
	}
	password, problem, err := e.readPassword(ctx, c.namespace, user.Password)
	if err != nil || problem != "" {
		return problem, err
	}
	passwordOK := false
	if current != nil && current.managed && current.kind == "S" {
		if passwordOK, err = s.passwordMatches(ctx, user.Username, password); err != nil {
			return "", err
		}
	}
	monitor := false
	wanted := map[string]string{}
	for _, g := range roles {
		if g.Role == roleMonitor {
			monitor = true
		} else {
			wanted[g.Database] = g.Role
		}
	}
	stmts, err := planLogin(user.Username, password, monitor, current, passwordOK)
	var unmanaged errUnmanagedLogin
	if errors.As(err, &unmanaged) {
		return unmanaged.Error(), nil
	}
	if err != nil {
		return "", err
	}
	if len(stmts) > 0 {
		if err := s.execTx(ctx, stmts); err != nil {
			if reason := serverReason(err); reason != "" {
				return "SQL Server can't apply the user: " + reason, nil
			}
			return "", err
		}
	}
	sid := loginSID(user.Username)
	if current != nil {
		sid = current.sid
	}

	var problems []string
	var owned []engine.RoleGrant
	found := map[string]bool{}
	for _, d := range dbs {
		if d.system() {
			continue
		}
		found[d.name] = true
		role := wanted[d.name]
		switch {
		case !d.detailed:
			if role != "" {
				problems = append(problems, fmt.Sprintf("database %q is %s", d.name, strings.ToLower(d.state)))
			}
			continue
		case string(d.dboSID) == string(sid):
			if role != "" {
				owned = append(owned, engine.RoleGrant{Role: role, Database: d.name})
			}
			continue
		case !d.managed():
			// The plugin leaves databases it doesn't manage alone.
			if role != "" {
				problems = append(problems, fmt.Sprintf("database %q isn't managed by OpenEverest", d.name))
			}
			continue
		}
		dbStmts := planDatabaseAccess(d.name, user.Username, role, d.userFor(sid))
		if len(dbStmts) == 0 {
			continue
		}
		if err := s.execTx(ctx, dbStmts); err != nil {
			reason := serverReason(err)
			if reason == "" {
				return "", err
			}
			problems = append(problems, fmt.Sprintf("SQL Server can't grant access to database %q: %s", d.name, reason))
		}
	}
	for _, g := range roles {
		if g.Database != "" && !found[g.Database] {
			problems = append(problems, fmt.Sprintf("database %q doesn't exist", g.Database))
		}
	}
	e.ownedGrants.Store(userKey(target, user.Username), owned)
	return strings.Join(problems, "; "), nil
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

// ListUsers implements engine.Engine. Grants are read from the managed
// databases: the user's memberships of the fixed roles, or, on a database
// it owns, the grants last declared.
func (e *Engine) ListUsers(ctx context.Context, target engine.Target) ([]engine.User, error) {
	_, s, err := e.connect(ctx, target)
	if err != nil {
		return nil, err
	}
	defer s.close()
	logins, err := s.logins(ctx)
	if err != nil {
		return nil, err
	}
	dbs, err := s.databases(ctx)
	if err != nil {
		return nil, err
	}
	users := make([]engine.User, 0, len(logins))
	for _, l := range logins {
		users = append(users, engine.User{
			Username: l.name,
			Roles:    e.grants(target, l, dbs),
			System:   isSystemLogin(l),
		})
	}
	return users, nil
}

func (e *Engine) grants(target engine.Target, l login, dbs []database) []engine.RoleGrant {
	grants := []engine.RoleGrant{}
	if hasMonitor(l.permissions) {
		grants = append(grants, engine.RoleGrant{Role: roleMonitor})
	}
	var owned []engine.RoleGrant
	if v, ok := e.ownedGrants.Load(userKey(target, l.name)); ok {
		owned = v.([]engine.RoleGrant)
	}
	for _, d := range dbs {
		if d.system() || !d.detailed || !d.managed() {
			continue
		}
		if string(d.dboSID) == string(l.sid) {
			for _, g := range owned {
				if g.Database == d.name {
					grants = append(grants, g)
				}
			}
			continue
		}
		if u := d.userFor(l.sid); u != nil {
			if role := grantFor(u.roles); role != "" {
				grants = append(grants, engine.RoleGrant{Role: role, Database: d.name})
			}
		}
	}
	return grants
}

// DropUser implements engine.Engine. Only logins the plugin created are
// dropped, with their users in the databases and their sessions. A login
// that owns a database stays until the database gets another owner.
func (e *Engine) DropUser(ctx context.Context, target engine.Target, username string) error {
	if validateUser(engine.DesiredUser{Username: username}) != nil {
		return nil
	}
	_, s, err := e.connect(ctx, target)
	if err != nil {
		return err
	}
	defer s.close()
	logins, err := s.logins(ctx)
	if err != nil {
		return err
	}
	var current *login
	for i := range logins {
		if logins[i].name == username {
			current = &logins[i]
		}
	}
	if current == nil || !current.managed || current.kind != "S" || isSystemLogin(*current) {
		e.forget(target, username)
		return nil
	}
	dbs, err := s.databases(ctx)
	if err != nil {
		return err
	}
	var stmts []stmt
	for _, d := range dbs {
		if d.system() || !d.detailed {
			continue
		}
		if string(d.dboSID) == string(current.sid) {
			return fmt.Errorf("%w: user %q owns database %q; give the database another owner first", engine.ErrInProgress, username, d.name)
		}
		if u := d.userFor(current.sid); u != nil {
			stmts = append(stmts, stmt{database: d.name, sql: "DROP USER " + quoteName(u.name)})
		}
	}
	if err := s.execEach(ctx, stmts); err != nil {
		return inProgress(err, "SQL Server can't drop the user's database users")
	}
	sessions, err := s.loginSessions(ctx, username)
	if err != nil {
		return err
	}
	if err := s.kill(ctx, sessions); err != nil {
		return inProgress(err, "SQL Server can't end the user's sessions")
	}
	if err := s.execEach(ctx, []stmt{{sql: "DROP LOGIN " + quoteName(username)}}); err != nil {
		return inProgress(err, "SQL Server can't drop the login")
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
// login was just applied and shows up on the next reconcile.
func (e *Engine) PendingReason(_ context.Context, target engine.Target, username string) string {
	if v, ok := e.problems.Load(userKey(target, username)); ok {
		return v.(string)
	}
	return "applying the user in SQL Server"
}

// ConnectionURI implements engine.Engine. It connects to the primary, as
// the Instance's own connection details do.
func (e *Engine) ConnectionURI(ctx context.Context, target engine.Target, username, password string) (string, error) {
	c, err := e.resolve(ctx, target)
	if err != nil {
		return "", err
	}
	uri := url.URL{
		Scheme: "sqlserver",
		User:   url.UserPassword(username, password),
		Host:   net.JoinHostPort(c.host, strconv.FormatInt(c.port, 10)),
	}
	return uri.String(), nil
}
