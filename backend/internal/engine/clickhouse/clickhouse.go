// Package clickhouse reconciles users and databases of ClickHouse instances
// served by provider-altinity-clickhouse. Access-control entities are managed
// with ClickHouse SQL and replicated with ON CLUSTER on Keeper-backed
// installations.
package clickhouse

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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

const (
	// ProviderName is the canonical provider name from definition/provider.yaml.
	ProviderName = "provider-altinity-clickhouse"
	// ChartProviderName is the default metadata.name used by the provider chart.
	ChartProviderName = "altinity-clickhouse"
)

const resyncInterval = 5 * time.Minute

// Engine implements user and database management for ClickHouse.
type Engine struct {
	kube         kubernetes.Interface
	resolve      func(context.Context, engine.Target) (cluster, error)
	dial         dialer
	readPassword func(context.Context, string, engine.SecretKeyRef) (string, string, error)

	locksMu  sync.Mutex
	locks    map[string]*sync.Mutex
	problems sync.Map
}

var (
	_ engine.Engine                       = (*Engine)(nil)
	_ engine.DatabaseEngine               = (*Engine)(nil)
	_ engine.GrantedConnectEngine         = (*Engine)(nil)
	_ engine.ConnectionPropertiesProvider = (*Engine)(nil)
	_ engine.PendingReasoner              = (*Engine)(nil)
	_ engine.UserProblemReporter          = (*Engine)(nil)
	_ engine.Resyncer                     = (*Engine)(nil)
)

// New returns an engine that reads Altinity resources and manages access with
// ClickHouse SQL as the provider's administrative user.
func New(kube kubernetes.Interface, dyn dynamic.Interface) *Engine {
	resolver := &clusterResolver{kube: kube, dyn: dyn}
	e := &Engine{
		kube:    kube,
		resolve: resolver.resolve,
		dial:    dialDriver,
		locks:   map[string]*sync.Mutex{},
	}
	e.readPassword = e.password
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
	return resyncInterval
}

// OnlyGrantedConnect reflects ClickHouse access control: a database's owner
// and users with a grant can use it; ordinary users have no implicit access.
func (e *Engine) OnlyGrantedConnect() {}

func targetKey(target engine.Target) string {
	return target.Namespace + "/" + target.Instance
}

func problemKey(target engine.Target, username string) string {
	return targetKey(target) + "/" + username
}

// lock serializes user and database reconciliation for one installation.
// Both controllers share this engine while their writes otherwise overlap.
func (e *Engine) lock(target engine.Target) func() {
	key := targetKey(target)
	e.locksMu.Lock()
	mu := e.locks[key]
	if mu == nil {
		mu = &sync.Mutex{}
		e.locks[key] = mu
	}
	e.locksMu.Unlock()
	mu.Lock()
	return mu.Unlock
}

func (e *Engine) connect(ctx context.Context, target engine.Target) (cluster, session, error) {
	c, err := e.resolve(ctx, target)
	if err != nil {
		return cluster{}, nil, err
	}
	s, err := e.dial(ctx, c)
	if err != nil {
		return cluster{}, nil, err
	}
	return c, s, nil
}

// SyncUsers applies each declared user. A user dropped from the declaration
// is left at its last state until the InstanceUser finalizer calls DropUser.
func (e *Engine) SyncUsers(ctx context.Context, target engine.Target, users []engine.DesiredUser) error {
	if len(users) == 0 {
		return nil
	}
	unlock := e.lock(target)
	defer unlock()

	c, s, err := e.connect(ctx, target)
	if err != nil {
		return err
	}
	defer s.close()
	if err := s.exec(ctx, "CREATE ROLE IF NOT EXISTS "+quoteIdent(managedRole)+c.onCluster()); err != nil {
		return fmt.Errorf("create ClickHouse managed role: %w", err)
	}
	currentUsers, err := s.users(ctx)
	if err != nil {
		return err
	}
	existing := map[string]bool{}
	for _, user := range currentUsers {
		existing[user.name] = true
	}
	members, err := s.roleMembers(ctx)
	if err != nil {
		return err
	}
	databases, err := s.databases(ctx)
	if err != nil {
		return err
	}
	owners := databaseOwners(databases)
	managedDatabases := databaseNamesManaged(databases)

	var errs []error
	for _, user := range users {
		if err := validateUser(user); err != nil {
			errs = append(errs, err)
			continue
		}
		roles, err := normalizeRoles(user.Roles)
		if err != nil {
			errs = append(errs, fmt.Errorf("user %q: %w", user.Username, err))
			continue
		}
		password, problem, err := e.readPassword(ctx, target.Namespace, user.Password)
		if err != nil {
			errs = append(errs, fmt.Errorf("user %q: %w", user.Username, err))
			continue
		}
		if problem != "" {
			e.problems.Store(problemKey(target, user.Username), problem)
			continue
		}
		if existing[user.Username] && !members[user.Username] {
			e.problems.Store(problemKey(target, user.Username),
				fmt.Sprintf("user %q already exists in ClickHouse and isn't managed by OpenEverest", user.Username))
			continue
		}

		hash := sha256Hex([]byte(password))
		statements := userStatements(c, user.Username, hash, roles, owners, managedDatabases)
		var applied error
		for _, statement := range statements {
			if err := s.exec(ctx, statement); err != nil {
				applied = err
				break
			}
		}
		if applied != nil {
			errs = append(errs, fmt.Errorf("apply user %q: %w", user.Username, applied))
			continue
		}
		e.problems.Delete(problemKey(target, user.Username))
	}
	return errors.Join(errs...)
}

func userStatements(c cluster, username, passwordHash string, roles []engine.RoleGrant,
	owners map[string]string, managedDatabases []string,
) []string {
	user := quoteIdent(username)
	hash := quoteString(passwordHash)
	statements := []string{
		"CREATE USER IF NOT EXISTS " + user + c.onCluster() +
			" IDENTIFIED WITH sha256_hash BY " + hash +
			" HOST ANY DEFAULT DATABASE " + quoteIdent(defaultDatabase),
		"GRANT" + c.onCluster() + " " + quoteIdent(managedRole) + " TO " + user,
		"ALTER USER " + user + c.onCluster() + " IDENTIFIED WITH sha256_hash BY " + hash,
		"REVOKE" + c.onCluster() + " SELECT ON `system`.* FROM " + user,
	}
	for _, database := range managedDatabases {
		statements = append(statements, "REVOKE"+c.onCluster()+" ALL PRIVILEGES ON "+
			quoteIdent(database)+".* FROM "+user)
	}
	for _, grant := range roles {
		switch grant.Role {
		case roleMonitor:
			statements = append(statements,
				"GRANT"+c.onCluster()+" SELECT ON "+quoteIdent("system")+".* TO "+user)
		default:
			option := ""
			if grant.Role == roleDBOwner {
				option = " WITH GRANT OPTION"
			}
			statements = append(statements, "GRANT"+c.onCluster()+" "+
				strings.Join(rolePrivileges(grant.Role), ", ")+" ON "+
				quoteIdent(grant.Database)+".* TO "+user+option)
		}
	}
	for database, owner := range owners {
		if owner == username {
			statements = append(statements, "GRANT"+c.onCluster()+
				" ALL ON "+quoteIdent(database)+".* TO "+user+" WITH GRANT OPTION")
		}
	}
	return statements
}

// ListUsers reads SQL users and their direct grants. The hidden managed role
// marks which accounts the plugin may later alter or drop.
func (e *Engine) ListUsers(ctx context.Context, target engine.Target) ([]engine.User, error) {
	unlock := e.lock(target)
	defer unlock()

	c, s, err := e.connect(ctx, target)
	if err != nil {
		return nil, err
	}
	defer s.close()
	users, err := s.users(ctx)
	if err != nil {
		return nil, err
	}
	grants, err := s.grants(ctx)
	if err != nil {
		return nil, err
	}
	databases, err := s.databases(ctx)
	if err != nil {
		return nil, err
	}
	owners := databaseOwners(databases)
	roleGrants := grantsForUsers(grants, owners)

	out := make([]engine.User, 0, len(users))
	for _, user := range users {
		out = append(out, engine.User{
			Username: user.name,
			Roles:    roleGrants[user.name],
			System:   c.systemUsers[user.name],
		})
	}
	return out, nil
}

func grantsForUsers(grants []databaseGrant, owners map[string]string) map[string][]engine.RoleGrant {
	byUserDatabase := map[string]map[string]map[string]bool{}
	grantOptions := map[string]map[string]bool{}
	monitor := map[string]bool{}
	for _, grant := range grants {
		if grant.database == "system" && (grant.table == "" || grant.table == "*") &&
			grant.accessType == "SELECT" {
			monitor[grant.username] = true
			continue
		}
		if grant.database == "" || (grant.table != "" && grant.table != "*") {
			continue
		}
		if byUserDatabase[grant.username] == nil {
			byUserDatabase[grant.username] = map[string]map[string]bool{}
		}
		if byUserDatabase[grant.username][grant.database] == nil {
			byUserDatabase[grant.username][grant.database] = map[string]bool{}
		}
		byUserDatabase[grant.username][grant.database][grant.accessType] = true
		if grantOptions[grant.username] == nil {
			grantOptions[grant.username] = map[string]bool{}
		}
		grantOptions[grant.username][grant.database] = grantOptions[grant.username][grant.database] || grant.grantOption
	}

	out := map[string][]engine.RoleGrant{}
	for username, databases := range byUserDatabase {
		for database, privileges := range databases {
			if owners[database] == username {
				continue
			}
			role := roleForPrivileges(privileges, grantOptions[username][database])
			if role != "" {
				out[username] = append(out[username], engine.RoleGrant{Role: role, Database: database})
			}
		}
	}
	for username := range monitor {
		out[username] = append(out[username], engine.RoleGrant{Role: roleMonitor})
	}
	return out
}

// DropUser drops only users carrying the plugin's marker role. Owners must
// first lose their InstanceDatabase or be replaced by another owner.
func (e *Engine) DropUser(ctx context.Context, target engine.Target, username string) error {
	if validateUser(engine.DesiredUser{Username: username}) != nil {
		return nil
	}
	unlock := e.lock(target)
	defer unlock()

	c, s, err := e.connect(ctx, target)
	if err != nil {
		return err
	}
	defer s.close()
	members, err := s.roleMembers(ctx)
	if err != nil {
		return err
	}
	if !members[username] {
		e.problems.Delete(problemKey(target, username))
		return nil
	}
	databases, err := s.databases(ctx)
	if err != nil {
		return err
	}
	owners := databaseOwners(databases)
	for database, owner := range owners {
		if owner == username {
			return fmt.Errorf("%w: user %q owns database %q; give the database another owner first",
				engine.ErrInProgress, username, database)
		}
	}
	if err := s.exec(ctx, "DROP USER IF EXISTS "+quoteIdent(username)+c.onCluster()); err != nil {
		return fmt.Errorf("drop ClickHouse user: %w", err)
	}
	e.problems.Delete(problemKey(target, username))
	return nil
}

func (e *Engine) password(ctx context.Context, namespace string, ref engine.SecretKeyRef) (value, problem string, err error) {
	secret, err := e.kube.CoreV1().Secrets(namespace).Get(ctx, ref.Name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return "", fmt.Sprintf("password Secret %q not found", ref.Name), nil
	}
	if err != nil {
		return "", "", fmt.Errorf("get password Secret %q: %w", ref.Name, err)
	}
	value = string(secret.Data[ref.Key])
	if value == "" {
		return "", fmt.Sprintf("password Secret %q has no %q key", ref.Name, ref.Key), nil
	}
	return value, "", nil
}

func (e *Engine) PendingReason(_ context.Context, _ engine.Target, _ string) string {
	return "applying the user in ClickHouse"
}

func (e *Engine) UserProblem(target engine.Target, username string) string {
	if problem, ok := e.problems.Load(problemKey(target, username)); ok {
		return problem.(string)
	}
	return ""
}

func (e *Engine) ConnectionURI(ctx context.Context, target engine.Target, username, password string) (string, error) {
	c, err := e.resolve(ctx, target)
	if err != nil {
		return "", err
	}
	query := url.Values{}
	if c.tls {
		query.Set("secure", "true")
	}
	uri := url.URL{
		Scheme:   "clickhouse",
		User:     url.UserPassword(username, password),
		Host:     net.JoinHostPort(c.host, strconv.Itoa(c.port)),
		Path:     "/" + defaultDatabase,
		RawQuery: query.Encode(),
	}
	return uri.String(), nil
}

func (e *Engine) ConnectionProperties(ctx context.Context, target engine.Target) (map[string]string, error) {
	c, err := e.resolve(ctx, target)
	if err != nil {
		return nil, err
	}
	if !c.tls {
		return nil, nil
	}
	return map[string]string{"ca.crt": string(c.caPEM)}, nil
}

func (c cluster) onCluster() string {
	if !c.distributed {
		return ""
	}
	return " ON CLUSTER " + quoteIdent(clickHouseCluster)
}

func quoteIdent(value string) string {
	return "`" + strings.ReplaceAll(value, "`", "``") + "`"
}

func quoteString(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "\\'") + "'"
}

func sha256Hex(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}
