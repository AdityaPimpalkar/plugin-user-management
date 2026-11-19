import { describe, expect, it } from 'vitest';
import { Role } from 'types/users.types';
import {
  canAddRoleRow,
  hasErrors,
  initialFormValues,
  toRoleGrants,
  validateUserForm,
} from './user-form-dialog.utils';
import { Messages } from './user-form-dialog.messages';

const roles: Role[] = [
  { name: 'readWrite', scope: 'database', description: '' },
  { name: 'readAnyDatabase', scope: 'cluster', description: '' },
];

describe('validateUserForm', () => {
  it('accepts a user with a generated password and valid roles', () => {
    const errors = validateUserForm(
      {
        username: 'app',
        password: '',
        roles: [
          { role: 'readWrite', database: 'shop', bucket: '' },
          { role: 'readAnyDatabase', database: '', bucket: '' },
        ],
      },
      roles,
      'create'
    );
    expect(hasErrors(errors)).toBe(false);
  });

  it('requires a database only for database-scoped roles', () => {
    const errors = validateUserForm(
      {
        username: 'app',
        password: '',
        roles: [
          { role: 'readWrite', database: ' ', bucket: '' },
          { role: 'readAnyDatabase', database: '', bucket: '' },
          { role: '', database: '', bucket: '' },
        ],
      },
      roles,
      'create'
    );
    expect(errors.roleRows[0].database).toBeDefined();
    expect(errors.roleRows[1]).toEqual({
      role: undefined,
      database: undefined,
      bucket: undefined,
    });
    expect(errors.roleRows[2].role).toBeDefined();
    expect(hasErrors(errors)).toBe(true);
  });

  it('rejects short passwords and missing usernames when creating', () => {
    const errors = validateUserForm(
      {
        username: ' ',
        password: 'short',
        roles: [{ role: 'readAnyDatabase', database: '', bucket: '' }],
      },
      roles,
      'create'
    );
    expect(errors.username).toBeDefined();
    expect(errors.password).toBeDefined();
  });

  it('ignores username and password when editing roles', () => {
    const errors = validateUserForm(
      {
        username: '',
        password: 'x',
        roles: [{ role: 'readAnyDatabase', database: '', bucket: '' }],
      },
      roles,
      'editRoles'
    );
    expect(hasErrors(errors)).toBe(false);
  });

  it('requires at least one role', () => {
    const errors = validateUserForm({ username: 'a', password: '', roles: [] }, roles, 'create');
    expect(errors.roles).toBeDefined();
  });

  it('rejects a role granted twice on the same database', () => {
    const errors = validateUserForm(
      {
        username: 'a',
        password: '',
        roles: [
          { role: 'readWrite', database: 'shop', bucket: '' },
          { role: 'readWrite', database: 'blog', bucket: '' },
          { role: 'readWrite', database: ' shop ', bucket: '' },
        ],
      },
      roles,
      'create'
    );
    expect(errors.roleRows.map((r) => r.role)).toEqual([undefined, undefined, Messages.roleDuplicate]);
  });

  it('rejects a role another one already includes, on the same database only', () => {
    const withIncludes: Role[] = [
      { name: 'read', scope: 'database', description: '' },
      { name: 'readWrite', scope: 'database', description: '', includes: ['read'] },
    ];
    const errors = validateUserForm(
      {
        username: 'a',
        password: '',
        roles: [
          { role: 'read', database: 'shop', bucket: '' },
          { role: 'read', database: 'blog', bucket: '' },
          { role: 'readWrite', database: 'shop', bucket: '' },
        ],
      },
      withIncludes,
      'create'
    );
    expect(errors.roleRows.map((r) => r.role)).toEqual([
      Messages.roleIncluded('readWrite'),
      undefined,
      undefined,
    ]);
  });

  it('compares included roles on the same bucket only', () => {
    const bucketRoles: Role[] = [
      { name: 'read', scope: 'bucket', description: '' },
      { name: 'readWrite', scope: 'bucket', description: '', includes: ['read'] },
    ];
    const errors = validateUserForm(
      {
        username: 'app',
        password: '',
        roles: [
          { role: 'read', database: '', bucket: 'uploads' },
          { role: 'read', database: '', bucket: 'backups' },
          { role: 'readWrite', database: '', bucket: 'uploads' },
        ],
      },
      bucketRoles,
      'create'
    );
    expect(errors.roleRows.map((row) => row.role)).toEqual([
      Messages.roleIncluded('readWrite'),
      undefined,
      undefined,
    ]);
  });
});

describe('toRoleGrants', () => {
  it('drops the database of cluster-scoped roles and trims the rest', () => {
    expect(
      toRoleGrants(
        [
          { role: 'readWrite', database: ' shop ', bucket: '' },
          { role: 'readAnyDatabase', database: 'leftover', bucket: '' },
        ],
        roles
      )
    ).toEqual([{ role: 'readWrite', database: 'shop' }, { role: 'readAnyDatabase' }]);
  });

  it('keeps a bucket grant and drops unrelated database input', () => {
    const bucketRoles: Role[] = [
      { name: 'readWrite', scope: 'bucket', description: '' },
    ];
    expect(
      toRoleGrants(
        [{ role: 'readWrite', database: 'leftover', bucket: ' uploads ' }],
        bucketRoles
      )
    ).toEqual([{ role: 'readWrite', bucket: 'uploads' }]);
  });
});

describe('initialFormValues', () => {
  it('starts with one empty role row for new users', () => {
    expect(initialFormValues().roles).toEqual([{ role: '', database: '', bucket: '' }]);
  });

  it('pre-fills the roles of an edited user', () => {
    expect(initialFormValues([{ role: 'readAnyDatabase' }, { role: 'readWrite', database: 'x' }]).roles).toEqual([
      { role: 'readAnyDatabase', database: '', bucket: '' },
      { role: 'readWrite', database: 'x', bucket: '' },
    ]);
  });

  it('starts with no role row when roles are optional', () => {
    const invoke: Role[] = [{ name: 'invoke', scope: 'cluster', description: '' }];
    expect(initialFormValues([], roles, false).roles).toEqual([]);
    expect(initialFormValues([], invoke, false).roles).toEqual([]);
  });

  it('pre-selects the only role there is', () => {
    const invoke: Role[] = [{ name: 'invoke', scope: 'cluster', description: '' }];
    expect(initialFormValues([], invoke).roles).toEqual([
      { role: 'invoke', database: '', bucket: '' },
    ]);
    expect(initialFormValues([], roles).roles).toEqual([
      { role: '', database: '', bucket: '' },
    ]);
  });
});

describe('canAddRoleRow', () => {
  const clusterRoles: Role[] = [
    { name: 'pg_read_all_data', scope: 'cluster', description: '' },
    { name: 'pg_monitor', scope: 'cluster', description: '' },
  ];
  const row = (role: string) => ({ role, database: '', bucket: '' });

  it('always allows another row when roles are granted per database', () => {
    expect(canAddRoleRow([row('readWrite'), row('readAnyDatabase')], roles)).toBe(true);
  });

  it('always allows another row when roles are granted per bucket', () => {
    const bucketRoles: Role[] = [
      { name: 'read', scope: 'bucket', description: '' },
      { name: 'readWrite', scope: 'bucket', description: '' },
    ];
    expect(canAddRoleRow([row('read'), row('readWrite')], bucketRoles)).toBe(true);
  });

  it('allows one row per role when every role applies to the whole instance', () => {
    expect(canAddRoleRow([row('pg_monitor')], clusterRoles)).toBe(true);
    expect(canAddRoleRow([row('pg_monitor'), row('pg_read_all_data')], clusterRoles)).toBe(false);
  });
});
