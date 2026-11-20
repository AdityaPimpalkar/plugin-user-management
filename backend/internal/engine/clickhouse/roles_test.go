package clickhouse

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openeverest/plugin-user-management/backend/internal/engine"
)

func TestNormalizeRoles(t *testing.T) {
	roles, err := normalizeRoles([]engine.RoleGrant{
		{Role: roleRead, Database: "orders"},
		{Role: roleReadWrite, Database: "orders"},
		{Role: roleRead, Database: "archive"},
		{Role: roleRead, Database: "archive"},
		{Role: roleMonitor, Database: "ignored"},
		{Role: roleMonitor},
	})
	require.NoError(t, err)
	assert.Equal(t, []engine.RoleGrant{
		{Role: roleReadWrite, Database: "orders"},
		{Role: roleRead, Database: "archive"},
		{Role: roleMonitor},
	}, roles)
}

func TestNormalizeRolesRejectsInvalidGrant(t *testing.T) {
	_, err := normalizeRoles([]engine.RoleGrant{{Role: "superuser", Database: "orders"}})
	assert.ErrorIs(t, err, engine.ErrInvalid)

	_, err = normalizeRoles([]engine.RoleGrant{{Role: roleRead}})
	assert.ErrorIs(t, err, engine.ErrInvalid)

	_, err = normalizeRoles([]engine.RoleGrant{{Role: roleRead, Database: "system"}})
	assert.ErrorIs(t, err, engine.ErrInvalid)
}

func TestValidateUserRejectsReservedNames(t *testing.T) {
	for _, name := range reservedUsernames {
		assert.ErrorIs(t, validateUser(engine.DesiredUser{Username: name}), engine.ErrInvalid)
	}
	assert.NoError(t, validateUser(engine.DesiredUser{Username: "orders-app"}))
}

func TestGrantsForUsers(t *testing.T) {
	grants := []databaseGrant{
		{username: "app", accessType: "SELECT", database: "orders"},
		{username: "app", accessType: "INSERT", database: "orders"},
		{username: "app", accessType: "ALTER UPDATE", database: "orders"},
		{username: "app", accessType: "ALTER DELETE", database: "orders"},
		{username: "owner", accessType: "ALL", database: "orders", grantOption: true},
		{username: "dba", accessType: "ALL", database: "audit", grantOption: true},
		{username: "metrics", accessType: "SELECT", database: "system", table: "*"},
	}
	got := grantsForUsers(grants, map[string]string{"orders": "owner"})
	assert.ElementsMatch(t, []engine.RoleGrant{{Role: roleReadWrite, Database: "orders"}}, got["app"])
	assert.Empty(t, got["owner"], "database ownership is implicit, not an InstanceUser role")
	assert.ElementsMatch(t, []engine.RoleGrant{{Role: roleDBOwner, Database: "audit"}}, got["dba"])
	assert.ElementsMatch(t, []engine.RoleGrant{{Role: roleMonitor}}, got["metrics"])
}

func TestUserStatementsUseHashAndScopedPrivileges(t *testing.T) {
	queries := userStatements(
		cluster{distributed: true},
		"orders-app",
		"0123456789abcdef",
		[]engine.RoleGrant{{Role: roleReadWrite, Database: "orders"}, {Role: roleMonitor}},
		map[string]string{"owned": "orders-app"},
		[]string{"orders", "owned"},
	)

	joined := stringsJoin(queries)
	assert.Contains(t, joined, "ON CLUSTER `clickhouse`")
	assert.Contains(t, joined, "IDENTIFIED WITH sha256_hash BY '0123456789abcdef'")
	assert.Contains(t, joined, "ROLE `openeverest_managed`")
	assert.Contains(t, joined, "SELECT, INSERT, ALTER UPDATE, ALTER DELETE ON `orders`.*")
	assert.Contains(t, joined, "SELECT ON `system`.*")
	assert.Contains(t, joined, "ALL ON `owned`.* TO `orders-app` WITH GRANT OPTION")
	assert.NotContains(t, joined, "password")
}

func stringsJoin(values []string) string {
	joined := ""
	for _, value := range values {
		joined += value + "\n"
	}
	return joined
}
