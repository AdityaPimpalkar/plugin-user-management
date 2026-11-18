package mariadb

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/openeverest/plugin-user-management/backend/internal/engine"
)

func (e *Engine) ValidateDatabase(name string) error {
	return validateDatabase(name)
}

// ListDatabases reads schemas from MariaDB, then supplies the owner stored on
// the plugin's Database resource. Owner privileges are deliberately not
// reported as roles on the owner's InstanceUser.
func (e *Engine) ListDatabases(ctx context.Context, target engine.Target) ([]engine.Database, error) {
	c, err := e.resolve(ctx, target)
	if err != nil {
		return nil, err
	}
	s, err := e.dial(ctx, c)
	if err != nil {
		return nil, err
	}
	defer s.close()
	actual, err := s.databases(ctx)
	if err != nil {
		return nil, err
	}
	managed, err := e.managedObjects(ctx, databaseResource, target)
	if err != nil {
		return nil, err
	}
	owners := map[string]string{}
	for i := range managed {
		obj := &managed[i]
		owners[obj.GetAnnotations()[databaseAnno]] = obj.GetAnnotations()[ownerAnno]
	}

	byName := map[string]engine.Database{}
	for _, schema := range actual {
		byName[schema.name] = engine.Database{
			Name:   schema.name,
			Owner:  owners[schema.name],
			System: schema.name == c.database || reservedDatabase(schema.name),
		}
	}
	all, err := e.allObjects(ctx, databaseResource, target.Namespace)
	if err != nil {
		return nil, err
	}
	for i := range all {
		obj := &all[i]
		ref, _, _ := unstructured.NestedString(obj.Object, "spec", "mariaDbRef", "name")
		if ref != target.Instance || obj.GetLabels()[managedLabel] == "true" {
			continue
		}
		name, _, _ := unstructured.NestedString(obj.Object, "spec", "name")
		if name == "" {
			name = obj.GetName()
		}
		if _, found := byName[name]; !found {
			byName[name] = engine.Database{Name: name, System: false}
		}
	}

	databases := make([]engine.Database, 0, len(byName))
	for _, database := range byName {
		databases = append(databases, database)
	}
	sort.Slice(databases, func(i, j int) bool { return databases[i].Name < databases[j].Name })
	return databases, nil
}

func reservedDatabase(name string) bool {
	for _, reserved := range reservedDatabases {
		if name == reserved {
			return true
		}
	}
	return false
}

// SyncDatabase creates the schema and an all-privileges Grant for its owner.
// The old owner Grant is removed before the operation is reported complete.
func (e *Engine) SyncDatabase(ctx context.Context, target engine.Target, database engine.DesiredDatabase) error {
	if err := validateDatabase(database.Name); err != nil {
		return err
	}
	c, err := e.resolve(ctx, target)
	if err != nil {
		return err
	}
	if err := e.apply(ctx, databaseApplyConfiguration(c, database)); err != nil {
		return err
	}
	desiredOwner := ownerGrantApplyConfiguration(c, database)
	if err := e.apply(ctx, desiredOwner); err != nil {
		return err
	}

	grants, err := e.managedObjects(ctx, grantResource, target)
	if err != nil {
		return err
	}
	dbs, err := e.managedObjects(ctx, databaseResource, target)
	if err != nil {
		return err
	}
	if !findReadyObject(dbs, desiredDatabaseName(c, database.Name)) ||
		!findReadyGrant(grants, desiredOwner.GetName()) {
		return fmt.Errorf("%w: MariaDB is applying the database owner", engine.ErrInProgress)
	}

	pending := false
	for i := range grants {
		grant := &grants[i]
		if grant.GetLabels()[purposeLabel] != purposeOwner ||
			grant.GetAnnotations()[databaseAnno] != database.Name ||
			grant.GetName() == desiredOwner.GetName() {
			continue
		}
		err := e.deleteObject(ctx, grantResource, target.Namespace, grant.GetName(), "Delete", "owner grant")
		if errors.Is(err, engine.ErrInProgress) {
			pending = true
		} else if err != nil {
			return err
		}
	}
	if pending {
		return fmt.Errorf("%w: MariaDB is revoking the previous database owner", engine.ErrInProgress)
	}
	return nil
}

func findReadyGrant(objects []unstructured.Unstructured, name string) bool {
	for i := range objects {
		if objects[i].GetName() == name {
			return grantReady(&objects[i])
		}
	}
	return false
}

func desiredDatabaseName(c cluster, database string) string {
	return databaseObjectName(c.name, database)
}

func findReadyObject(objects []unstructured.Unstructured, name string) bool {
	for i := range objects {
		if objects[i].GetName() == name {
			return objectReady(&objects[i])
		}
	}
	return false
}

// ReleaseDatabase removes the owner Grant and Database resource. Retain leaves
// SQL objects intact by changing the mariadb-operator cleanup policy to Skip.
func (e *Engine) ReleaseDatabase(ctx context.Context, target engine.Target, name string, drop bool) error {
	if validateDatabase(name) != nil {
		return nil
	}
	policy := "Skip"
	verb := "releasing"
	if drop {
		policy, verb = "Delete", "dropping"
	}
	grants, err := e.managedObjects(ctx, grantResource, target)
	if err != nil {
		return err
	}
	pending := false
	for _, grant := range grants {
		if grant.GetLabels()[purposeLabel] != purposeOwner || grant.GetAnnotations()[databaseAnno] != name {
			continue
		}
		err := e.deleteObject(ctx, grantResource, target.Namespace, grant.GetName(), policy, "owner grant")
		if errors.Is(err, engine.ErrInProgress) {
			pending = true
		} else if err != nil {
			return err
		}
	}
	if pending {
		return fmt.Errorf("%w: MariaDB is %s the database owner's grant", engine.ErrInProgress, verb)
	}
	return e.deleteObject(ctx, databaseResource, target.Namespace, databaseObjectName(target.Instance, name), policy, "database")
}
