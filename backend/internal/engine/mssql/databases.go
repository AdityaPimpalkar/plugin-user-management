package mssql

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/openeverest/plugin-user-management/backend/internal/engine"
)

// ValidateDatabase implements engine.DatabaseEngine.
func (e *Engine) ValidateDatabase(name string) error {
	if !databaseName.MatchString(name) {
		return fmt.Errorf("%w: database names are 1 to 63 lowercase letters, digits and underscores, not starting with a digit", engine.ErrInvalidDatabase)
	}
	if slices.Contains(reservedDatabases, name) {
		return fmt.Errorf("%w: database %q is reserved", engine.ErrInvalidDatabase, name)
	}
	return nil
}

// ListDatabases implements engine.DatabaseEngine. A database's owner is the
// login its dbo maps to, which, unlike sys.databases, is the same on every
// replica of an Availability Group.
func (e *Engine) ListDatabases(ctx context.Context, target engine.Target) ([]engine.Database, error) {
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
	out := make([]engine.Database, 0, len(dbs))
	for _, d := range dbs {
		out = append(out, engine.Database{Name: d.name, Owner: ownerOf(d, logins), System: d.system()})
	}
	return out, nil
}

func ownerOf(d database, logins []login) string {
	if d.detailed {
		for _, l := range logins {
			if string(l.sid) == string(d.dboSID) {
				return l.name
			}
		}
	}
	return d.ownerName
}

func findDatabase(dbs []database, name string) *database {
	for i := range dbs {
		if dbs[i].name == name {
			return &dbs[i]
		}
	}
	return nil
}

// SyncDatabase implements engine.DatabaseEngine: it creates the database,
// marked as managed, and makes the owner its owner (dbo). On an
// Availability Group, the database is available once the operator added it
// to the group. The controller only declares a database it claimed before
// it existed, so an existing database without the mark is one whose
// creation was interrupted.
func (e *Engine) SyncDatabase(ctx context.Context, target engine.Target, want engine.DesiredDatabase) error {
	if err := e.ValidateDatabase(want.Name); err != nil {
		return err
	}
	c, s, err := e.connect(ctx, target)
	if err != nil {
		return err
	}
	defer s.close()
	logins, err := s.logins(ctx)
	if err != nil {
		return err
	}
	var owner *login
	for i := range logins {
		if logins[i].name == want.Owner {
			owner = &logins[i]
		}
	}
	if owner == nil {
		return fmt.Errorf("%w: waiting for the owner's login %q to be created", engine.ErrInProgress, want.Owner)
	}
	dbs, err := s.databases(ctx)
	if err != nil {
		return err
	}
	current := findDatabase(dbs, want.Name)
	if current == nil {
		if err := s.execEach(ctx, []stmt{{sql: "CREATE DATABASE " + quoteName(want.Name)}}); err != nil {
			return inProgress(err, "SQL Server can't create the database")
		}
		if dbs, err = s.databases(ctx); err != nil {
			return err
		}
		if current = findDatabase(dbs, want.Name); current == nil {
			return fmt.Errorf("%w: waiting for the database to be created", engine.ErrInProgress)
		}
	}
	if !current.detailed {
		return fmt.Errorf("%w: database %q is %s", engine.ErrInProgress, want.Name, strings.ToLower(current.state))
	}
	if stmts := planDatabase(*current, *owner); len(stmts) > 0 {
		if err := s.execEach(ctx, stmts); err != nil {
			return inProgress(err, "SQL Server can't apply the database")
		}
	}
	if c.isAG() && !current.inAG {
		return fmt.Errorf("%w: waiting for the operator to add the database to Availability Group %q", engine.ErrInProgress, c.ag)
	}
	return nil
}

// planDatabase returns the statements that mark the database as managed and
// make the owner its dbo. A user the owner had in the database is dropped
// first, as SQL Server requires; dbo holds every role.
func planDatabase(current database, owner login) []stmt {
	var stmts []stmt
	switch current.marker {
	case managedValue:
	case "":
		stmts = append(stmts, stmt{database: current.name, sql: fmt.Sprintf(
			"EXEC sys.sp_addextendedproperty @name = %s, @value = %s", quoteString(managedProperty), quoteString(managedValue))})
	default:
		stmts = append(stmts, stmt{database: current.name, sql: fmt.Sprintf(
			"EXEC sys.sp_updateextendedproperty @name = %s, @value = %s", quoteString(managedProperty), quoteString(managedValue))})
	}
	if string(current.dboSID) != string(owner.sid) {
		if u := current.userFor(owner.sid); u != nil {
			stmts = append(stmts, stmt{database: current.name, sql: "DROP USER " + quoteName(u.name)})
		}
		stmts = append(stmts, stmt{sql: fmt.Sprintf("ALTER AUTHORIZATION ON DATABASE::%s TO %s", quoteName(current.name), quoteName(owner.name))})
	}
	return stmts
}

// ReleaseDatabase implements engine.DatabaseEngine. Only databases the
// plugin created are touched: dropped, or unmarked so they're no longer
// managed. Idle sessions are ended before dropping; while sessions run
// requests in the database, it isn't dropped and ErrInProgress says so. On
// an Availability Group, the database is removed from the group and dropped
// holding the operator's lock, so the operator doesn't add it back in
// between; the operator drops the secondaries' copies.
func (e *Engine) ReleaseDatabase(ctx context.Context, target engine.Target, name string, drop bool) error {
	if e.ValidateDatabase(name) != nil {
		return nil
	}
	c, s, err := e.connect(ctx, target)
	if err != nil {
		return err
	}
	defer s.close()
	dbs, err := s.databases(ctx)
	if err != nil {
		return err
	}
	current := findDatabase(dbs, name)
	if current == nil || current.system() {
		return nil
	}
	if !current.detailed {
		return fmt.Errorf("%w: database %q is %s", engine.ErrInProgress, name, strings.ToLower(current.state))
	}
	if !current.managed() {
		return nil
	}
	if !drop {
		unmark := stmt{database: name, sql: "EXEC sys.sp_dropextendedproperty @name = " + quoteString(managedProperty)}
		return inProgress(s.execEach(ctx, []stmt{unmark}), "SQL Server can't release the database")
	}
	dropDatabase := func() error {
		idle, busy, err := s.databaseSessions(ctx, name)
		if err != nil {
			return err
		}
		if busy > 0 {
			return fmt.Errorf("%w: %d sessions are running requests in database %q", engine.ErrInProgress, busy, name)
		}
		if err := s.kill(ctx, idle); err != nil {
			return inProgress(err, "SQL Server can't end the database's sessions")
		}
		var stmts []stmt
		if current.inAG {
			stmts = append(stmts, stmt{sql: fmt.Sprintf("ALTER AVAILABILITY GROUP %s REMOVE DATABASE %s", quoteName(c.ag), quoteName(name))})
		}
		stmts = append(stmts, stmt{sql: "DROP DATABASE " + quoteName(name)})
		return inProgress(s.execEach(ctx, stmts), "SQL Server can't drop the database")
	}
	if c.isAG() {
		return s.withAGLock(ctx, dropDatabase)
	}
	return dropDatabase()
}
