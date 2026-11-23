package pxc

import (
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/openeverest/plugin-user-management/backend/internal/engine"
)

const (
	roleRead      = "read"
	roleReadWrite = "readWrite"
	roleDBOwner   = "dbOwner"
	roleMonitor   = "monitor"

	// catalogDatabase keeps which users and databases the plugin manages,
	// and the owner of each database. It works on every PXC version (5.7
	// has no user attributes) and Galera replicates it with the accounts.
	catalogDatabase = "openeverest_user_management"
	usersTable      = "managed_users"
	databasesTable  = "managed_databases"

	// maxUsernameLength is MySQL's limit since 5.7.8.
	maxUsernameLength = 32
)

var roleCatalog = []engine.Role{
	{Name: roleRead, Scope: engine.ScopeDatabase, Description: "Read all tables and views in the database (SELECT)."},
	{Name: roleReadWrite, Scope: engine.ScopeDatabase, Description: "Read, insert, update and delete rows in the database's tables (SELECT, INSERT, UPDATE, DELETE).", Includes: []string{roleRead}},
	{Name: roleDBOwner, Scope: engine.ScopeDatabase, Description: "Do anything in the database, including changing its schema and other users' grants (ALL PRIVILEGES WITH GRANT OPTION).", Includes: []string{roleRead, roleReadWrite}},
	{Name: roleMonitor, Scope: engine.ScopeCluster, Description: "Read server status and replication state for monitoring (PROCESS and REPLICATION CLIENT)."},
}

var (
	databaseName = regexp.MustCompile(`^[a-z_][a-z0-9_]{0,62}$`)
	// reservedUsernames are the operator's system users (pkg/pxc/users).
	reservedUsernames = []string{
		"root", "operator", "monitor", "xtrabackup", "replication", "proxyadmin",
		"clustercheck", "pmmserver", "pmmserverkey", "pmmservertoken",
	}
	reservedDatabases = []string{"information_schema", "mysql", "performance_schema", "sys", catalogDatabase}
	rank              = map[string]int{roleRead: 1, roleReadWrite: 2, roleDBOwner: 3}
	// rolePrivileges are the sorted mysql.db columns each database role
	// sets; dbOwner sets every privilege column of mysql.db.
	rolePrivileges = map[string][]string{
		roleRead:      {"Select_priv"},
		roleReadWrite: {"Delete_priv", "Insert_priv", "Select_priv", "Update_priv"},
	}
	roleGrantSQL = map[string]string{
		roleRead:      "SELECT",
		roleReadWrite: "SELECT, INSERT, UPDATE, DELETE",
		roleDBOwner:   "ALL PRIVILEGES",
	}
)

func isCatalogRole(name string) bool {
	return slices.ContainsFunc(roleCatalog, func(r engine.Role) bool { return r.Name == name })
}

func normalizeRoles(grants []engine.RoleGrant) ([]engine.RoleGrant, error) {
	normalized := make([]engine.RoleGrant, 0, len(grants))
	byDatabase := map[string]int{}
	monitor := false
	for _, grant := range grants {
		if !isCatalogRole(grant.Role) {
			return nil, fmt.Errorf("%w: role %q can't be granted", engine.ErrInvalid, grant.Role)
		}
		if grant.Role == roleMonitor {
			if !monitor {
				normalized = append(normalized, engine.RoleGrant{Role: roleMonitor})
				monitor = true
			}
			continue
		}
		if grant.Database == "" {
			return nil, fmt.Errorf("%w: role %q needs a database", engine.ErrInvalid, grant.Role)
		}
		if !databaseName.MatchString(grant.Database) || !grantable(grant.Database) {
			return nil, fmt.Errorf("%w: database %q can't be managed", engine.ErrInvalid, grant.Database)
		}
		// Privileges on the system schemas would let users change accounts.
		if slices.Contains(reservedDatabases, grant.Database) {
			return nil, fmt.Errorf("%w: roles can't be granted on database %q", engine.ErrInvalid, grant.Database)
		}
		i, found := byDatabase[grant.Database]
		switch {
		case !found:
			byDatabase[grant.Database] = len(normalized)
			normalized = append(normalized, engine.RoleGrant{Role: grant.Role, Database: grant.Database})
		case rank[grant.Role] > rank[normalized[i].Role]:
			normalized[i].Role = grant.Role
		}
	}
	return normalized, nil
}

func validateUser(user engine.DesiredUser) error {
	name := user.Username
	if name == "" || len(name) > maxUsernameLength {
		return fmt.Errorf("%w: MySQL usernames are 1 to %d characters", engine.ErrInvalid, maxUsernameLength)
	}
	if strings.ContainsAny(name, "'\\`") {
		return fmt.Errorf("%w: username %q has a quote or backslash", engine.ErrInvalid, name)
	}
	if isSystemUser(name) {
		return fmt.Errorf("%w: user %q is reserved", engine.ErrInvalid, name)
	}
	return nil
}

// isSystemUser tells the operator's users and MySQL's own accounts, such as
// mysql.sys and mysql.pxc.sst.role.
func isSystemUser(name string) bool {
	return strings.HasPrefix(strings.ToLower(name), "mysql.") ||
		slices.ContainsFunc(reservedUsernames, func(r string) bool { return strings.EqualFold(r, name) })
}

func validateDatabase(name string) error {
	if !databaseName.MatchString(name) {
		return fmt.Errorf("%w: database names are 1 to 63 lowercase letters, digits and underscores, not starting with a digit", engine.ErrInvalidDatabase)
	}
	if !grantable(name) {
		return fmt.Errorf("%w: database names count each underscore twice and are at most %d characters so", engine.ErrInvalidDatabase, maxGrantPattern)
	}
	if slices.Contains(reservedDatabases, name) {
		return fmt.Errorf("%w: database %q is reserved", engine.ErrInvalidDatabase, name)
	}
	return nil
}

// maxGrantPattern is MySQL's identifier limit, which applies to the escaped
// name in GRANT. 5.7 truncates longer ones, onto another database's name.
const maxGrantPattern = 64

func grantable(database string) bool {
	return len(grantPattern(database)) <= maxGrantPattern
}

// desiredPrivileges returns the sorted mysql.db columns a role sets.
func desiredPrivileges(role string, all []string) []string {
	if role == roleDBOwner {
		return all
	}
	return rolePrivileges[role]
}

// roleFor tells the role whose privileges are exactly privs, or "".
func roleFor(privs, all []string) string {
	switch {
	case len(all) > 0 && slices.Equal(privs, all):
		return roleDBOwner
	case slices.Equal(privs, rolePrivileges[roleReadWrite]):
		return roleReadWrite
	case slices.Equal(privs, rolePrivileges[roleRead]):
		return roleRead
	}
	return ""
}

func grantStatement(role, pattern, username string) stmt {
	sql := fmt.Sprintf("GRANT %s ON %s.* TO %s", roleGrantSQL[role], quoteIdent(pattern), account(username))
	if role == roleDBOwner {
		sql += " WITH GRANT OPTION"
	}
	return stmt{sql: sql}
}

// revokeStatements revoke the privileges the user has on the pattern. ALL
// PRIVILEGES leaves GRANT OPTION, which takes its own statement.
func revokeStatements(pattern, username string, have []string) []stmt {
	var stmts []stmt
	if len(have) == 0 {
		return nil
	}
	grantOption := slices.Contains(have, "Grant_priv")
	if len(have) > 1 || !grantOption {
		stmts = append(stmts, stmt{sql: fmt.Sprintf("REVOKE ALL PRIVILEGES ON %s.* FROM %s", quoteIdent(pattern), account(username))})
	}
	if grantOption {
		stmts = append(stmts, stmt{sql: fmt.Sprintf("REVOKE GRANT OPTION ON %s.* FROM %s", quoteIdent(pattern), account(username))})
	}
	return stmts
}

// grantPattern escapes the wildcards GRANT gives _ and % in database names,
// the way mysql.db keeps literal names.
func grantPattern(database string) string {
	return strings.NewReplacer(`\`, `\\`, `_`, `\_`, `%`, `\%`).Replace(database)
}

// literalDatabase returns the database a mysql.db pattern names, unless the
// pattern has a wildcard.
func literalDatabase(pattern string) (string, bool) {
	var b strings.Builder
	for i := 0; i < len(pattern); i++ {
		switch ch := pattern[i]; ch {
		case '\\':
			if i+1 == len(pattern) {
				return "", false
			}
			i++
			b.WriteByte(pattern[i])
		case '_', '%':
			return "", false
		default:
			b.WriteByte(ch)
		}
	}
	return b.String(), true
}

func quoteIdent(name string) string {
	return "`" + strings.ReplaceAll(name, "`", "``") + "`"
}

// quoteString quotes a username, which validateUser keeps free of quotes
// and backslashes.
func quoteString(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}

// account is the only account form the plugin manages: the user from any host.
func account(username string) string {
	return quoteString(username) + "@'%'"
}
