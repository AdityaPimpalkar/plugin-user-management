import { IconButton, ListItemText, MenuItem, Stack, TextField, Tooltip } from '@mui/material';
import DeleteOutlineIcon from '@mui/icons-material/DeleteOutline';
import { Role } from 'types/users.types';
import { findRole } from 'utils/roles.utils';
import { RoleGrantDraft, RoleGrantErrors } from '../user-form-dialog.types';
import { Messages } from '../user-form-dialog.messages';

interface RoleGrantRowProps {
  value: RoleGrantDraft;
  roles: Role[];
  errors: RoleGrantErrors;
  showErrors: boolean;
  canRemove: boolean;
  // False when no role of the engine is granted on a database.
  showDatabase: boolean;
  // False when no role of the engine is granted on an S3 bucket.
  showBucket: boolean;
  // The databases roles can be granted on, when the instance's databases are
  // managed; the database is typed in otherwise.
  databases?: string[];
  // Buckets roles can be granted on; undefined keeps a free-text field.
  buckets?: string[];
  onChange: (value: RoleGrantDraft) => void;
  onRemove: () => void;
}

export const RoleGrantRow = ({
  value,
  roles,
  errors,
  showErrors,
  canRemove,
  showDatabase,
  showBucket,
  databases,
  buckets,
  onChange,
  onRemove,
}: RoleGrantRowProps) => {
  const isClusterScoped = findRole(roles, value.role)?.scope === 'cluster';
  const isBucketScoped = findRole(roles, value.role)?.scope === 'bucket';
  // Keeps a granted database that's no longer offered, e.g. while it's deleted.
  const databaseOptions =
    databases && value.database && !databases.includes(value.database)
      ? [...databases, value.database]
      : databases;
  const bucketOptions =
    buckets && value.bucket && !buckets.includes(value.bucket)
      ? [...buckets, value.bucket]
      : buckets;
  return (
    <Stack direction="row" sx={{ gap: 1, alignItems: 'flex-start' }}>
      <TextField
        select
        size="small"
        label={Messages.role}
        value={value.role}
        onChange={(e) => onChange({ ...value, role: e.target.value })}
        error={showErrors && !!errors.role}
        helperText={showErrors ? errors.role : undefined}
        sx={{ flex: 1 }}
        slotProps={{ select: { renderValue: (selected) => String(selected) } }}
      >
        {roles.map((role) => (
          <MenuItem key={role.name} value={role.name}>
            <ListItemText primary={role.name} secondary={role.description} />
          </MenuItem>
        ))}
      </TextField>
      {showDatabase && databaseOptions && !isClusterScoped && (
        <TextField
          select
          size="small"
          label={Messages.database}
          value={value.database}
          onChange={(e) => onChange({ ...value, database: e.target.value })}
          error={showErrors && !!errors.database}
          helperText={
            (showErrors && errors.database && (databaseOptions.length ? Messages.databaseChoose : Messages.noDatabases)) ||
            (databaseOptions.length ? undefined : Messages.noDatabases)
          }
          sx={{ flex: 1 }}
        >
          {databaseOptions.map((name) => (
            <MenuItem key={name} value={name}>
              {name}
            </MenuItem>
          ))}
        </TextField>
      )}
      {showDatabase && (!databaseOptions || isClusterScoped) && (
        <TextField
          size="small"
          label={Messages.database}
          value={isClusterScoped ? Messages.allDatabases : value.database}
          disabled={isClusterScoped}
          onChange={(e) => onChange({ ...value, database: e.target.value })}
          error={showErrors && !!errors.database}
          helperText={showErrors ? errors.database : undefined}
          sx={{ flex: 1 }}
        />
      )}
      {showBucket && bucketOptions && isBucketScoped && (
        <TextField
          select
          size="small"
          label={Messages.bucket}
          value={value.bucket}
          onChange={(e) => onChange({ ...value, bucket: e.target.value })}
          error={showErrors && !!errors.bucket}
          helperText={showErrors ? errors.bucket : undefined}
          sx={{ flex: 1 }}
        >
          {bucketOptions.map((name) => (
            <MenuItem key={name} value={name}>
              {name}
            </MenuItem>
          ))}
        </TextField>
      )}
      {showBucket && (!bucketOptions || !isBucketScoped) && (
        <TextField
          size="small"
          label={Messages.bucket}
          value={isBucketScoped ? value.bucket : Messages.allBuckets}
          disabled={!isBucketScoped}
          onChange={(e) => onChange({ ...value, bucket: e.target.value })}
          error={showErrors && !!errors.bucket}
          helperText={showErrors ? errors.bucket : undefined}
          sx={{ flex: 1 }}
        />
      )}
      <Tooltip title={Messages.removeRole}>
        <span>
          <IconButton aria-label={Messages.removeRole} onClick={onRemove} disabled={!canRemove}>
            <DeleteOutlineIcon />
          </IconButton>
        </span>
      </Tooltip>
    </Stack>
  );
};
