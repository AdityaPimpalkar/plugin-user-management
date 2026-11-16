export const Messages = {
  editRolesTitle: (username: string) => `Edit roles of ${username}`,
  passwordHelper: 'Leave empty to generate a strong password.',
  roles: 'Roles',
  role: 'Role',
  database: 'Database',
  allDatabases: 'All databases',
  addRole: 'Add role',
  removeRole: 'Remove role',
  cancel: 'Cancel',
  create: 'Create',
  save: 'Save',
  usernameRequired: 'Enter a username.',
  passwordLength: (min: number, max: number) =>
    `Use ${min} to ${max} characters, or leave empty to generate one.`,
  rolesRequired: 'Grant at least one role.',
  roleRequired: 'Select a role.',
  databaseRequired: 'Enter a database.',
  databaseChoose: 'Choose a database.',
  noDatabases: 'No databases yet. To own one, a user needs no role.',
  noRoles:
    'No roles: the user can log in but not use any data. That is all the owner of a database needs: create the user, then its database in Databases.',
};
