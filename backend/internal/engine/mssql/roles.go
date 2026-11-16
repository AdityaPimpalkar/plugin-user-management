package mssql

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/openeverest/plugin-user-management/backend/internal/engine"
)

// Roles of the catalog.
const (
	roleRead      = "read"
	roleReadWrite = "readWrite"
	roleDBOwner   = "dbOwner"
	roleMonitor   = "monitor"
)

// The roles the plugin grants: SQL Server's fixed database roles on one
// InstanceDatabase, and read-only server permissions for monitoring.
// Deliberately excludes sysadmin and the other fixed server roles: they
// would let anyone who can use the plugin take over the server.
var roleCatalog = []engine.Role{
	{Name: roleRead, Scope: engine.ScopeDatabase, Description: "Connect to the database and read all its tables and views (db_datareader)."},
	{Name: roleReadWrite, Scope: engine.ScopeDatabase, Description: "Connect to the database, read, insert, update and delete rows in all its tables (db_datareader and db_datawriter).", Includes: []string{roleRead}},
	{Name: roleDBOwner, Scope: engine.ScopeDatabase, Description: "Do anything in the database, including changing its schema and its users' permissions (db_owner).", Includes: []string{roleRead, roleReadWrite}},
	{Name: roleMonitor, Scope: engine.ScopeCluster, Description: "Read server state and the definitions of all objects, as monitoring tools need (VIEW SERVER STATE and VIEW ANY DEFINITION)."},
}

// databaseRoles are the fixed database roles each database-scoped role is
// granted with. Users are members of exactly these, of the plugin's ones.
var databaseRoles = map[string][]string{
	roleRead:      {"db_datareader"},
	roleReadWrite: {"db_datareader", "db_datawriter"},
	roleDBOwner:   {"db_owner"},
}

// fixedRoles are the fixed database roles the plugin manages memberships of.
var fixedRoles = []string{"db_datareader", "db_datawriter", "db_owner"}

// rank orders database-scoped roles: each includes those before it.
var rank = map[string]int{roleRead: 1, roleReadWrite: 2, roleDBOwner: 3}

// monitorPermissions are the server permissions of the monitor role.
var monitorPermissions = []string{"VIEW SERVER STATE", "VIEW ANY DEFINITION"}

const (
	// SQL Server's sysname is 128 characters.
	maxNameLength = 128
	// managedRole is the server role the logins the plugin created are
	// members of, so it never alters or drops ones it doesn't manage. The
	// operator replicates it to the Availability Group's secondaries.
	managedRole = "openeverest_managed"
	// managedProperty is the database extended property marking the
	// databases the plugin created; it moves with the database.
	managedProperty = "openeverest_managed"
	managedValue    = "Managed by OpenEverest"
	// operatorMarkerRole marks the logins the operator copied to secondaries.
	operatorMarkerRole = "mssql_operator_replicated"
)

// reservedUsernames are SQL Server's and the operator's principals.
var reservedUsernames = []string{"sa", "public", "sysadmin", managedRole, operatorMarkerRole}

// Mirrors the InstanceDatabase name pattern.
var databaseName = regexp.MustCompile(`^[a-z_][a-z0-9_]{0,62}$`)

// reservedDatabases are SQL Server's own.
var reservedDatabases = []string{"master", "model", "msdb", "tempdb", "mssqlsystemresource"}

func isCatalogRole(name string) bool {
	for _, r := range roleCatalog {
		if r.Name == name {
			return true
		}
	}
	return false
}

// normalizeRoles validates grants. Database-scoped roles keep their
// database, and only the strongest per database is kept, as a member of
// db_owner, or of db_datareader and db_datawriter, holds the weaker ones;
// monitor applies to the server and loses its database.
func normalizeRoles(grants []engine.RoleGrant) ([]engine.RoleGrant, error) {
	normalized := make([]engine.RoleGrant, 0, len(grants))
	byDatabase := map[string]int{}
	monitor := false
	for _, g := range grants {
		if !isCatalogRole(g.Role) {
			return nil, fmt.Errorf("%w: role %q can't be granted", engine.ErrInvalid, g.Role)
		}
		if g.Role == roleMonitor {
			if !monitor {
				monitor = true
				normalized = append(normalized, engine.RoleGrant{Role: roleMonitor})
			}
			continue
		}
		if g.Database == "" {
			return nil, fmt.Errorf("%w: role %q needs a database", engine.ErrInvalid, g.Role)
		}
		if !databaseName.MatchString(g.Database) {
			return nil, fmt.Errorf("%w: database %q can't be managed: names are lowercase letters, digits and underscores", engine.ErrInvalid, g.Database)
		}
		i, seen := byDatabase[g.Database]
		switch {
		case !seen:
			byDatabase[g.Database] = len(normalized)
			normalized = append(normalized, engine.RoleGrant{Role: g.Role, Database: g.Database})
		case rank[g.Role] > rank[normalized[i].Role]:
			normalized[i].Role = g.Role
		}
	}
	return normalized, nil
}

// grantFor maps the fixed roles a database user is a member of back to the
// role granted on the database, or "" for none.
func grantFor(memberOf []string) string {
	switch {
	case slices.Contains(memberOf, "db_owner"):
		return roleDBOwner
	case slices.Contains(memberOf, "db_datareader") && slices.Contains(memberOf, "db_datawriter"):
		return roleReadWrite
	case slices.Contains(memberOf, "db_datareader"):
		return roleRead
	}
	return ""
}

func hasMonitor(permissions []string) bool {
	for _, p := range monitorPermissions {
		if !slices.Contains(permissions, p) {
			return false
		}
	}
	return true
}

// validateUser rejects usernames SQL Server or the operator reserve. The
// plugin reads the password itself, so any Secret key works.
func validateUser(user engine.DesiredUser) error {
	name := user.Username
	if len([]rune(name)) > maxNameLength {
		return fmt.Errorf("%w: SQL Server usernames are at most %d characters", engine.ErrInvalid, maxNameLength)
	}
	if slices.ContainsFunc(reservedUsernames, func(r string) bool { return strings.EqualFold(r, name) }) {
		return fmt.Errorf("%w: user %q is reserved", engine.ErrInvalid, name)
	}
	if strings.HasPrefix(name, "##") || strings.HasPrefix(strings.ToUpper(name), "NT ") || strings.Contains(name, `\`) {
		return fmt.Errorf("%w: user %q is reserved for SQL Server", engine.ErrInvalid, name)
	}
	return nil
}

// isSystemLogin tells the logins SQL Server and the operator use: sa,
// SQL Server's internal and Windows service logins, and the
// certificate-mapped logins of the Availability Group's endpoints.
func isSystemLogin(l login) bool {
	return string(l.sid) == "\x01" || strings.EqualFold(l.name, "sa") ||
		strings.HasPrefix(l.name, "##") || strings.HasPrefix(strings.ToUpper(l.name), "NT ") ||
		l.kind == "C" || l.kind == "K"
}

// loginSID is the SID of the login the plugin creates for the username. It
// is the same whenever the login is created again, e.g. when a failover
// lost it, so the users mapped to it in the databases keep working.
func loginSID(username string) []byte {
	sum := sha256.Sum256([]byte("openeverest-plugin-user-management/" + username))
	return sum[:16]
}

// errUnmanagedLogin means the login exists but the plugin didn't create it.
type errUnmanagedLogin string

func (e errUnmanagedLogin) Error() string {
	return fmt.Sprintf("user %q already exists in the database and isn't managed by OpenEverest", string(e))
}

// planLogin returns the server statements that make the login match the
// user: a SQL login with the password, a member of the plugin's role, with
// the monitor permissions when granted. current is nil when the login
// doesn't exist; passwordOK tells whether it has the password.
func planLogin(username, password string, monitor bool, current *login, passwordOK bool) ([]stmt, error) {
	name := quoteName(username)
	var stmts []string
	var permissions []string
	if current == nil {
		stmts = append(stmts,
			fmt.Sprintf("CREATE LOGIN %s WITH PASSWORD = %s, SID = 0x%s, DEFAULT_DATABASE = [master], CHECK_POLICY = ON, CHECK_EXPIRATION = OFF",
				name, quoteString(password), strings.ToUpper(hex.EncodeToString(loginSID(username)))),
			fmt.Sprintf("ALTER SERVER ROLE %s ADD MEMBER %s", quoteName(managedRole), name),
		)
	} else {
		if !current.managed || current.kind != "S" {
			return nil, errUnmanagedLogin(username)
		}
		if !passwordOK {
			stmts = append(stmts, fmt.Sprintf("ALTER LOGIN %s WITH PASSWORD = %s", name, quoteString(password)))
		}
		permissions = current.permissions
	}
	for _, p := range monitorPermissions {
		has := slices.Contains(permissions, p)
		switch {
		case monitor && !has:
			stmts = append(stmts, fmt.Sprintf("GRANT %s TO %s", p, name))
		case !monitor && has:
			stmts = append(stmts, fmt.Sprintf("REVOKE %s FROM %s", p, name))
		}
	}
	out := make([]stmt, len(stmts))
	for i, s := range stmts {
		out[i] = stmt{sql: s}
	}
	return out, nil
}

// planDatabaseAccess returns the statements, run in the database, that give
// the login the role granted on it ("" for none): a user mapped to the login,
// a member of exactly the role's fixed roles, or no user at all. The
// database's owner already maps to dbo there and is never planned for.
func planDatabaseAccess(database, username, role string, current *dbUser) []stmt {
	var stmts []string
	want := databaseRoles[role]
	switch {
	case len(want) == 0 && current == nil:
		return nil
	case len(want) == 0:
		stmts = append(stmts, "DROP USER "+quoteName(current.name))
	default:
		var memberOf []string
		user := username
		if current == nil {
			stmts = append(stmts, fmt.Sprintf("CREATE USER %s FOR LOGIN %s", quoteName(username), quoteName(username)))
		} else {
			user, memberOf = current.name, current.roles
		}
		for _, r := range fixedRoles {
			wanted, has := slices.Contains(want, r), slices.Contains(memberOf, r)
			switch {
			case wanted && !has:
				stmts = append(stmts, fmt.Sprintf("ALTER ROLE %s ADD MEMBER %s", quoteName(r), quoteName(user)))
			case !wanted && has:
				stmts = append(stmts, fmt.Sprintf("ALTER ROLE %s DROP MEMBER %s", quoteName(r), quoteName(user)))
			}
		}
	}
	out := make([]stmt, len(stmts))
	for i, s := range stmts {
		out[i] = stmt{database: database, sql: s}
	}
	return out
}

// quoteName quotes an identifier, as QUOTENAME does.
func quoteName(name string) string {
	return "[" + strings.ReplaceAll(name, "]", "]]") + "]"
}

// quoteString quotes a Unicode string literal.
func quoteString(s string) string {
	return "N'" + strings.ReplaceAll(s, "'", "''") + "'"
}
