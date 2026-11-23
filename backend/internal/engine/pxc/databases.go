package pxc

import (
	"context"
	"fmt"
	"slices"
	"sort"

	"github.com/openeverest/plugin-user-management/backend/internal/engine"
)

// ValidateDatabase implements engine.DatabaseEngine.
func (e *Engine) ValidateDatabase(name string) error {
	return validateDatabase(name)
}

// ListDatabases implements engine.DatabaseEngine. Owners come from the
// plugin's catalog.
func (e *Engine) ListDatabases(ctx context.Context, target engine.Target) ([]engine.Database, error) {
	_, s, err := e.connect(ctx, target)
	if err != nil {
		return nil, err
	}
	defer s.close()
	snap, err := s.snapshot(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]engine.Database, 0, len(snap.schemas))
	for _, name := range snap.schemas {
		out = append(out, engine.Database{
			Name:   name,
			Owner:  snap.managedDatabases[name],
			System: slices.Contains(reservedDatabases, name),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// SyncDatabase implements engine.DatabaseEngine: it claims the database in
// the catalog, creates it, and gives its owner every privilege on it with
// GRANT OPTION. A previous owner's privileges on it are revoked. The
// controller only declares a database it claimed before it existed, so an
// existing database the catalog doesn't have was created out of the plugin.
func (e *Engine) SyncDatabase(ctx context.Context, target engine.Target, want engine.DesiredDatabase) error {
	if err := validateDatabase(want.Name); err != nil {
		return err
	}
	s, snap, err := e.connectCatalog(ctx, target)
	if err != nil {
		return err
	}
	defer s.close()
	if _, managed := snap.managedUsers[want.Owner]; !managed || snap.accounts[want.Owner] == nil {
		return fmt.Errorf("%w: waiting for the owner's user %q to be created", engine.ErrInProgress, want.Owner)
	}
	previous, managed := snap.managedDatabases[want.Name]
	if !managed && snap.hasSchema(want.Name) {
		return fmt.Errorf("%w: database %q already exists and isn't managed by OpenEverest", engine.ErrInvalidDatabase, want.Name)
	}
	if err := s.exec(ctx, planDatabase(snap, want, previous, managed)); err != nil {
		return inProgress(err, "MySQL can't apply the database")
	}
	return nil
}

func planDatabase(snap *snapshot, want engine.DesiredDatabase, previous string, managed bool) []stmt {
	var stmts []stmt
	if !managed {
		// Claimed before it's created: Galera applies them in this order, so
		// the database is never seen without its claim.
		stmts = append(stmts, stmt{
			sql:  "INSERT IGNORE INTO " + catalogTable(databasesTable) + " (name, owner) VALUES (?, ?)",
			args: []any{want.Name, want.Owner},
		})
	}
	if !snap.hasSchema(want.Name) {
		stmts = append(stmts, stmt{sql: "CREATE DATABASE IF NOT EXISTS " + quoteIdent(want.Name)})
	}
	pattern := grantPattern(want.Name)
	if have := snap.grants[want.Owner][pattern]; !slices.Equal(have, snap.allPrivileges) || len(have) == 0 {
		stmts = append(stmts, revokeStatements(pattern, want.Owner, have)...)
		stmts = append(stmts, grantStatement(roleDBOwner, pattern, want.Owner))
	}
	if managed && previous != want.Owner {
		stmts = append(stmts, stmt{
			sql:  "UPDATE " + catalogTable(databasesTable) + " SET owner = ? WHERE name = ?",
			args: []any{want.Owner, want.Name},
		})
		stmts = append(stmts, revokeStatements(pattern, previous, snap.grants[previous][pattern])...)
	}
	return stmts
}

// ReleaseDatabase implements engine.DatabaseEngine. Only databases the
// plugin created are touched. Dropping one revokes its owner's privileges
// first, so a database created later with the same name isn't theirs. A
// retained database leaves the catalog; its former owner then keeps only
// the roles its user declares on it. While transactions use the database,
// DROP DATABASE times out and ErrInProgress says so.
func (e *Engine) ReleaseDatabase(ctx context.Context, target engine.Target, name string, drop bool) error {
	if validateDatabase(name) != nil {
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
	owner, managed := snap.managedDatabases[name]
	if !managed {
		return nil
	}
	var stmts []stmt
	if drop {
		pattern := grantPattern(name)
		stmts = append(stmts, revokeStatements(pattern, owner, snap.grants[owner][pattern])...)
		stmts = append(stmts, stmt{sql: "DROP DATABASE IF EXISTS " + quoteIdent(name)})
	}
	stmts = append(stmts, stmt{
		sql:  "DELETE FROM " + catalogTable(databasesTable) + " WHERE name = ?",
		args: []any{name},
	})
	verb := "release"
	if drop {
		verb = "drop"
	}
	return inProgress(s.exec(ctx, stmts), "MySQL can't "+verb+" the database")
}
