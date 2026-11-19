package mariadb

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
)

var roleCatalog = []engine.Role{
	{Name: roleRead, Scope: engine.ScopeDatabase, Description: "Read all tables and views in the database (SELECT)."},
	{Name: roleReadWrite, Scope: engine.ScopeDatabase, Description: "Read, insert, update and delete rows in the database's tables (SELECT, INSERT, UPDATE, DELETE).", Includes: []string{roleRead}},
	{Name: roleDBOwner, Scope: engine.ScopeDatabase, Description: "Do anything in the database, including changing its schema and other users' grants (ALL PRIVILEGES).", Includes: []string{roleRead, roleReadWrite}},
	{Name: roleMonitor, Scope: engine.ScopeCluster, Description: "Read server status and replication state for monitoring (PROCESS and REPLICATION CLIENT)."},
}

var (
	databaseName      = regexp.MustCompile(`^[a-z_][a-z0-9_]{0,62}$`)
	reservedUsernames = []string{"root", "mariadb.sys", "mysql", "everest"}
	reservedDatabases = []string{"information_schema", "mysql", "performance_schema", "sys", "everest"}
	privilegesByRole  = map[string][]string{
		roleRead:      {"SELECT"},
		roleReadWrite: {"SELECT", "INSERT", "UPDATE", "DELETE"},
		roleDBOwner:   {"ALL PRIVILEGES"},
		roleMonitor:   {"PROCESS", "REPLICATION CLIENT"},
	}
	rank = map[string]int{roleRead: 1, roleReadWrite: 2, roleDBOwner: 3}
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
		if !databaseName.MatchString(grant.Database) {
			return nil, fmt.Errorf("%w: database %q can't be managed", engine.ErrInvalid, grant.Database)
		}
		i, found := byDatabase[grant.Database]
		switch {
		case !found:
			byDatabase[grant.Database] = len(normalized)
			normalized = append(normalized, grant)
		case rank[grant.Role] > rank[normalized[i].Role]:
			normalized[i].Role = grant.Role
		}
	}
	return normalized, nil
}

func validateUser(user engine.DesiredUser) error {
	name := user.Username
	if len([]rune(name)) > 80 {
		return fmt.Errorf("%w: MariaDB usernames are at most 80 characters", engine.ErrInvalid)
	}
	if slices.ContainsFunc(reservedUsernames, func(r string) bool {
		return strings.EqualFold(r, name)
	}) {
		return fmt.Errorf("%w: user %q is reserved", engine.ErrInvalid, name)
	}
	return nil
}

func validateDatabase(name string) error {
	if !databaseName.MatchString(name) {
		return fmt.Errorf("%w: database names are 1 to 63 lowercase letters, digits and underscores, not starting with a digit", engine.ErrInvalidDatabase)
	}
	if slices.Contains(reservedDatabases, name) {
		return fmt.Errorf("%w: database %q is reserved", engine.ErrInvalidDatabase, name)
	}
	return nil
}
