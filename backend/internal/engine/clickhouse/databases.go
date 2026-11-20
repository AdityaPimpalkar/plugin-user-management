package clickhouse

import (
	"context"
	"fmt"
	"strings"

	"github.com/openeverest/plugin-user-management/backend/internal/engine"
)

const managedDatabasePrefix = "Managed by OpenEverest; owner="

func (e *Engine) ValidateDatabase(name string) error {
	return validateDatabase(name)
}

// ListDatabases reports every ClickHouse database. Databases created by the
// plugin carry their owner in the comment; other Atomic databases stay
// unmanaged so no InstanceDatabase takes them over.
func (e *Engine) ListDatabases(ctx context.Context, target engine.Target) ([]engine.Database, error) {
	unlock := e.lock(target)
	defer unlock()

	_, s, err := e.connect(ctx, target)
	if err != nil {
		return nil, err
	}
	defer s.close()
	databases, err := s.databases(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]engine.Database, 0, len(databases))
	for _, database := range databases {
		owner, _ := databaseOwner(database.comment)
		out = append(out, engine.Database{
			Name:   database.name,
			Owner:  owner,
			System: reservedDatabase(database.name) || database.name == "system",
		})
	}
	return out, nil
}

func reservedDatabase(name string) bool {
	for _, reserved := range reservedDatabases {
		if name == reserved {
			return true
		}
	}
	return false
}

// SyncDatabase creates an Atomic database and grants its owner all scoped
// privileges with grant option. ClickHouse has no database owner object, so
// the managed owner is persisted in the database comment.
func (e *Engine) SyncDatabase(ctx context.Context, target engine.Target, want engine.DesiredDatabase) error {
	if err := validateDatabase(want.Name); err != nil {
		return err
	}
	unlock := e.lock(target)
	defer unlock()

	c, s, err := e.connect(ctx, target)
	if err != nil {
		return err
	}
	defer s.close()
	records, err := s.databases(ctx)
	if err != nil {
		return err
	}
	current := findDatabase(records, want.Name)
	if current != nil {
		_, managed := databaseOwner(current.comment)
		if !managed {
			return fmt.Errorf("%w: database %q exists and isn't managed by OpenEverest",
				engine.ErrInProgress, want.Name)
		}
	}
	members, err := s.roleMembers(ctx)
	if err != nil {
		return err
	}
	if !members[want.Owner] {
		return fmt.Errorf("%w: waiting for the owner's ClickHouse user %q to be created",
			engine.ErrInProgress, want.Owner)
	}

	comment := managedDatabaseComment(want.Owner)
	if current == nil {
		query := "CREATE DATABASE IF NOT EXISTS " + quoteIdent(want.Name) + c.onCluster() +
			" ENGINE = Atomic COMMENT " + quoteString(comment)
		if err := s.exec(ctx, query); err != nil {
			return inProgress(err, "ClickHouse can't create the database")
		}
	}
	oldOwner := ""
	if current != nil {
		oldOwner, _ = databaseOwner(current.comment)
	}
	owner := quoteIdent(want.Owner)
	database := quoteIdent(want.Name)
	if err := s.exec(ctx, "GRANT"+c.onCluster()+" ALL ON "+database+".* TO "+owner+
		" WITH GRANT OPTION"); err != nil {
		return inProgress(err, "ClickHouse can't grant the database owner")
	}
	if err := s.exec(ctx, "GRANT"+c.onCluster()+" CLUSTER ON *.* TO "+owner); err != nil {
		return inProgress(err, "ClickHouse can't grant cluster DDL to the database owner")
	}
	if oldOwner != "" && oldOwner != want.Owner {
		if err := s.exec(ctx, "REVOKE"+c.onCluster()+" ALL PRIVILEGES ON "+database+
			".* FROM "+quoteIdent(oldOwner)); err != nil {
			return inProgress(err, "ClickHouse can't revoke the previous database owner")
		}
	}
	if current == nil || current.comment != comment {
		if err := s.exec(ctx, "ALTER DATABASE "+database+c.onCluster()+
			" MODIFY COMMENT "+quoteString(comment)); err != nil {
			return inProgress(err, "ClickHouse can't record the database owner")
		}
	}
	return nil
}

// ReleaseDatabase removes the ownership marker for Retain, or drops the
// database synchronously for Delete. An unmanaged database is never touched.
func (e *Engine) ReleaseDatabase(ctx context.Context, target engine.Target, name string, drop bool) error {
	if validateDatabase(name) != nil {
		return nil
	}
	unlock := e.lock(target)
	defer unlock()

	c, s, err := e.connect(ctx, target)
	if err != nil {
		return err
	}
	defer s.close()
	records, err := s.databases(ctx)
	if err != nil {
		return err
	}
	current := findDatabase(records, name)
	if current == nil {
		return nil
	}
	if _, managed := databaseOwner(current.comment); !managed {
		return nil
	}
	query := "ALTER DATABASE " + quoteIdent(name) + c.onCluster() + " MODIFY COMMENT ''"
	if drop {
		query = "DROP DATABASE IF EXISTS " + quoteIdent(name) + c.onCluster() + " SYNC"
	}
	return inProgress(s.exec(ctx, query), "ClickHouse can't release the database")
}

func findDatabase(databases []databaseRecord, name string) *databaseRecord {
	for i := range databases {
		if databases[i].name == name {
			return &databases[i]
		}
	}
	return nil
}

func managedDatabaseComment(owner string) string {
	return managedDatabasePrefix + owner
}

func databaseOwner(comment string) (string, bool) {
	owner, found := strings.CutPrefix(comment, managedDatabasePrefix)
	return owner, found && owner != ""
}

func databaseOwners(databases []databaseRecord) map[string]string {
	owners := map[string]string{}
	for _, database := range databases {
		if owner, managed := databaseOwner(database.comment); managed {
			owners[database.name] = owner
		}
	}
	return owners
}

func databaseNamesManaged(databases []databaseRecord) []string {
	names := make([]string, 0, len(databases))
	for _, database := range databases {
		if _, managed := databaseOwner(database.comment); managed {
			names = append(names, database.name)
		}
	}
	return names
}

func inProgress(err error, what string) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%w: %s: %v", engine.ErrInProgress, what, err)
}
