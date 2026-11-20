package clickhouse

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openeverest/plugin-user-management/backend/internal/engine"
)

func TestSyncDatabaseCreatesOwnerAndManagedMarker(t *testing.T) {
	s := &fakeSession{membersValue: map[string]bool{"owner": true}}
	e := testEngine(s)

	err := e.SyncDatabase(context.Background(), engine.Target{Namespace: "team-a", Instance: "events"},
		engine.DesiredDatabase{Name: "orders", Owner: "owner"})
	require.NoError(t, err)
	queries := strings.Join(s.queries, "\n")
	assert.Contains(t, queries, "CREATE DATABASE IF NOT EXISTS `orders` ON CLUSTER `clickhouse` ENGINE = Atomic")
	assert.Contains(t, queries, "COMMENT 'Managed by OpenEverest; owner=owner'")
	assert.Contains(t, queries, "GRANT ON CLUSTER `clickhouse` ALL ON `orders`.* TO `owner` WITH GRANT OPTION")
	assert.Contains(t, queries, "MODIFY COMMENT")
}

func TestSyncDatabaseChangesOwnerWithoutTakeover(t *testing.T) {
	s := &fakeSession{
		membersValue: map[string]bool{"old": true, "new": true},
		databasesValue: []databaseRecord{{
			name: "orders", comment: managedDatabaseComment("old"),
		}},
	}
	e := testEngine(s)

	err := e.SyncDatabase(context.Background(), engine.Target{Namespace: "team-a", Instance: "events"},
		engine.DesiredDatabase{Name: "orders", Owner: "new"})
	require.NoError(t, err)
	queries := strings.Join(s.queries, "\n")
	assert.Contains(t, queries, "GRANT ON CLUSTER `clickhouse` ALL ON `orders`.* TO `new`")
	assert.Contains(t, queries, "REVOKE ON CLUSTER `clickhouse` ALL PRIVILEGES ON `orders`.* FROM `old`")
	assert.Contains(t, queries, "MODIFY COMMENT 'Managed by OpenEverest; owner=new'")
}

func TestSyncDatabaseRefusesExistingUnmanagedDatabase(t *testing.T) {
	s := &fakeSession{
		membersValue:   map[string]bool{"owner": true},
		databasesValue: []databaseRecord{{name: "orders", comment: "application database"}},
	}
	e := testEngine(s)
	err := e.SyncDatabase(context.Background(), engine.Target{Namespace: "team-a", Instance: "events"},
		engine.DesiredDatabase{Name: "orders", Owner: "owner"})
	assert.ErrorIs(t, err, engine.ErrInProgress)
	assert.Empty(t, s.queries)
}

func TestReleaseDatabaseRetainsOrDropsOnlyManagedDatabase(t *testing.T) {
	managed := &fakeSession{databasesValue: []databaseRecord{{
		name: "orders", comment: managedDatabaseComment("owner"),
	}}}
	e := testEngine(managed)
	target := engine.Target{Namespace: "team-a", Instance: "events"}
	require.NoError(t, e.ReleaseDatabase(context.Background(), target, "orders", false))
	assert.Contains(t, managed.queries[0], "MODIFY COMMENT ''")

	require.NoError(t, e.ReleaseDatabase(context.Background(), target, "orders", true))
	assert.Contains(t, managed.queries[1], "DROP DATABASE IF EXISTS `orders` ON CLUSTER `clickhouse` SYNC")

	external := &fakeSession{databasesValue: []databaseRecord{{name: "orders", comment: "keep"}}}
	e = testEngine(external)
	require.NoError(t, e.ReleaseDatabase(context.Background(), target, "orders", true))
	assert.Empty(t, external.queries)
}
