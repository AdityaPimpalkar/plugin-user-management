package clickhouse

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

	managedRole = "openeverest_managed"
)

var roleCatalog = []engine.Role{
	{Name: roleRead, Scope: engine.ScopeDatabase, Description: "Read all current and future tables and views in the database (SELECT)."},
	{Name: roleReadWrite, Scope: engine.ScopeDatabase, Description: "Read, insert, update and delete rows in all current and future tables in the database.", Includes: []string{roleRead}},
	{Name: roleDBOwner, Scope: engine.ScopeDatabase, Description: "Manage all database objects, run its DDL across the cluster and grant its privileges to other users.", Includes: []string{roleRead, roleReadWrite}},
	{Name: roleMonitor, Scope: engine.ScopeCluster, Description: "Read ClickHouse system tables for monitoring."},
}

var (
	databaseName      = regexp.MustCompile(`^[a-z_][a-z0-9_]{0,62}$`)
	reservedUsernames = []string{"admin", "default", "interserver", "clickhouse_operator", managedRole}
	reservedDatabases = []string{"default", "system", "information_schema", "INFORMATION_SCHEMA", "_temporary_and_external_tables"}
	rank              = map[string]int{roleRead: 1, roleReadWrite: 2, roleDBOwner: 3}
)

func normalizeRoles(grants []engine.RoleGrant) ([]engine.RoleGrant, error) {
	normalized := make([]engine.RoleGrant, 0, len(grants))
	byDatabase := map[string]int{}
	monitor := false
	for _, grant := range grants {
		if !slices.ContainsFunc(roleCatalog, func(role engine.Role) bool { return role.Name == grant.Role }) {
			return nil, fmt.Errorf("%w: role %q can't be granted", engine.ErrInvalid, grant.Role)
		}
		if grant.Role == roleMonitor {
			if !monitor {
				normalized = append(normalized, engine.RoleGrant{Role: roleMonitor})
				monitor = true
			}
			continue
		}
		if err := validateDatabase(grant.Database); err != nil {
			return nil, fmt.Errorf("%w: role %q needs a valid database", err, grant.Role)
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
	if len([]rune(user.Username)) > 64 {
		return fmt.Errorf("%w: ClickHouse usernames are at most 64 characters", engine.ErrInvalid)
	}
	if slices.ContainsFunc(reservedUsernames, func(name string) bool {
		return strings.EqualFold(name, user.Username)
	}) {
		return fmt.Errorf("%w: user %q is reserved", engine.ErrInvalid, user.Username)
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

func rolePrivileges(role string) []string {
	switch role {
	case roleRead:
		return []string{"SELECT"}
	case roleReadWrite:
		return []string{"SELECT", "INSERT", "ALTER UPDATE", "ALTER DELETE"}
	case roleDBOwner:
		return []string{"ALL"}
	default:
		return nil
	}
}

func roleForPrivileges(privileges map[string]bool, grantOption bool) string {
	switch {
	case privileges["ALL"] && grantOption:
		return roleDBOwner
	case privileges["SELECT"] && privileges["INSERT"] &&
		privileges["ALTER UPDATE"] && privileges["ALTER DELETE"]:
		return roleReadWrite
	case privileges["SELECT"]:
		return roleRead
	default:
		return ""
	}
}
