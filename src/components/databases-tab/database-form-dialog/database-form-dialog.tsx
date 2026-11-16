import { FormEvent, useState } from 'react';
import {
  Alert,
  Autocomplete,
  Button,
  Chip,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  FormControl,
  FormControlLabel,
  FormLabel,
  MenuItem,
  Radio,
  RadioGroup,
  Stack,
  TextField,
  Typography,
} from '@mui/material';
import { DatabaseConnect, NewDatabase, PostgreSQLExtension } from 'types/databases.types';
import { NEW_OWNER, OwnerOption } from '../databases-tab.types';
import { validateDatabaseForm } from '../databases-tab.utils';
import { Messages } from '../databases-tab.messages';

const CONNECT_OPTIONS: DatabaseConnect[] = ['Public', 'Granted'];

interface DatabaseFormDialogProps {
  // The database being edited; creates one when absent.
  initial?: NewDatabase;
  owners: OwnerOption[];
  // Offers the choice of who can connect; when false, only the owner and the
  // users granted a role can.
  connectChoice?: boolean;
  // Extensions users may create, on PostgreSQL instances; no picker otherwise.
  extensions?: PostgreSQLExtension[];
  // Why the extensions can't be listed.
  extensionsError?: string;
  // Offers creating the owner along with the database, as a user with no roles.
  canCreateOwner?: boolean;
  isSubmitting: boolean;
  error?: string;
  // newOwner is the username of the owner to create first, if any.
  onSubmit: (database: NewDatabase, newOwner?: string) => void;
  onClose: () => void;
}

export const DatabaseFormDialog = ({
  initial,
  owners,
  connectChoice = true,
  extensions,
  extensionsError,
  canCreateOwner = false,
  isSubmitting,
  error,
  onSubmit,
  onClose,
}: DatabaseFormDialogProps) => {
  const isCreate = !initial;
  const offerNewOwner = isCreate && canCreateOwner;
  const [values, setValues] = useState<NewDatabase>(() => {
    if (initial) {
      return initial;
    }
    let ownerId = owners.length === 1 ? owners[0].id : '';
    if (owners.length === 0 && offerNewOwner) {
      ownerId = NEW_OWNER;
    }
    return { name: '', ownerId, connect: connectChoice ? 'Public' : 'Granted' };
  });
  const [newOwner, setNewOwner] = useState('');
  const [submitted, setSubmitted] = useState(false);
  const isNewOwner = offerNewOwner && values.ownerId === NEW_OWNER;
  const errors = validateDatabaseForm(values, isCreate, isNewOwner ? newOwner : undefined);

  const handleSubmit = (e: FormEvent) => {
    e.preventDefault();
    setSubmitted(true);
    if (Object.values(errors).some(Boolean)) {
      return;
    }
    const { postgresql, ...rest } = values;
    const database = {
      ...rest,
      ownerId: isNewOwner ? '' : values.ownerId,
      name: values.name.trim(),
      ...(extensions ? { postgresql: { extensions: postgresql?.extensions ?? [] } } : {}),
    };
    if (isNewOwner) {
      onSubmit(database, newOwner.trim());
    } else {
      onSubmit(database);
    }
  };

  return (
    <Dialog open onClose={onClose} fullWidth maxWidth="sm">
      <form onSubmit={handleSubmit} noValidate>
        <DialogTitle>{isCreate ? Messages.createTitle : Messages.editTitle(values.name)}</DialogTitle>
        <DialogContent>
          <Stack sx={{ gap: 2, pt: 1 }}>
            {isCreate && (
              <TextField
                autoFocus
                size="small"
                label={Messages.name}
                value={values.name}
                onChange={(e) => setValues((v) => ({ ...v, name: e.target.value }))}
                error={submitted && !!errors.name}
                helperText={(submitted && errors.name) || Messages.nameHelper}
              />
            )}
            <TextField
              select
              size="small"
              label={Messages.owner}
              value={values.ownerId}
              onChange={(e) => setValues((v) => ({ ...v, ownerId: e.target.value }))}
              error={submitted && !!errors.ownerId}
              helperText={(submitted && errors.ownerId) || Messages.ownerHelper}
              disabled={owners.length === 0 && !offerNewOwner}
            >
              {owners.map((o) => (
                <MenuItem key={o.id} value={o.id}>
                  {o.username}
                </MenuItem>
              ))}
              {offerNewOwner && <MenuItem value={NEW_OWNER}>{Messages.newOwner}</MenuItem>}
            </TextField>
            {isNewOwner && (
              <TextField
                size="small"
                label={Messages.newOwnerName}
                value={newOwner}
                onChange={(e) => setNewOwner(e.target.value)}
                error={submitted && !!errors.newOwner}
                helperText={(submitted && errors.newOwner) || Messages.newOwnerHelper}
              />
            )}
            {owners.length === 0 && !offerNewOwner && <Alert severity="info">{Messages.noOwners}</Alert>}
            {connectChoice && (
              <FormControl>
                <FormLabel id="database-connect">{Messages.whoCanConnect}</FormLabel>
                <RadioGroup
                  aria-labelledby="database-connect"
                  value={values.connect}
                  onChange={(e) => setValues((v) => ({ ...v, connect: e.target.value as DatabaseConnect }))}
                >
                  {CONNECT_OPTIONS.map((option) => (
                    <FormControlLabel
                      key={option}
                      value={option}
                      control={<Radio size="small" />}
                      label={
                        <Stack>
                          <Typography variant="body2">{Messages.connect[option]}</Typography>
                          <Typography variant="caption" color="text.secondary">
                            {Messages.connectHelp[option]}
                          </Typography>
                        </Stack>
                      }
                      sx={{ alignItems: 'flex-start', mt: 1, '& .MuiRadio-root': { pt: 0.25 } }}
                    />
                  ))}
                </RadioGroup>
              </FormControl>
            )}
            {extensions && (
              <ExtensionsPicker
                available={extensions}
                error={extensionsError}
                value={values.postgresql?.extensions ?? []}
                onChange={(names) => setValues((v) => ({ ...v, postgresql: { extensions: names } }))}
              />
            )}
            {error && <Alert severity="error">{error}</Alert>}
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={onClose}>{Messages.cancel}</Button>
          <Button type="submit" variant="contained" disabled={isSubmitting}>
            {isCreate ? Messages.create : Messages.save}
          </Button>
        </DialogActions>
      </form>
    </Dialog>
  );
};

interface ExtensionsPickerProps {
  available: PostgreSQLExtension[];
  error?: string;
  value: string[];
  onChange: (names: string[]) => void;
}

const ExtensionsPicker = ({ available, error, value, onChange }: ExtensionsPickerProps) => {
  // Keeps extensions the database has that are no longer offered.
  const options = [...available.map((e) => e.name), ...value.filter((n) => !available.some((e) => e.name === n))];
  const describe = (name: string) => available.find((e) => e.name === name);
  return (
    <>
      <Autocomplete
        multiple
        size="small"
        options={options}
        value={value}
        onChange={(_, names) => onChange(names)}
        renderValue={(names, getItemProps) =>
          names.map((name, index) => {
            const { key, ...itemProps } = getItemProps({ index });
            return <Chip key={key} size="small" label={name} {...itemProps} />;
          })
        }
        renderOption={({ key, ...props }, name) => {
          const ext = describe(name);
          return (
            <li key={key} {...props}>
              <Stack>
                <Typography variant="body2">
                  {name}
                  {ext?.trusted && (
                    <Typography component="span" variant="caption" color="text.secondary">
                      {` (${Messages.trusted})`}
                    </Typography>
                  )}
                </Typography>
                {ext?.description && (
                  <Typography variant="caption" color="text.secondary">
                    {ext.description}
                  </Typography>
                )}
              </Stack>
            </li>
          );
        }}
        renderInput={(params) => (
          <TextField
            {...params}
            label={Messages.extensions}
            helperText={available.length || value.length ? Messages.extensionsHelper : Messages.noExtensions}
          />
        )}
      />
      {error && <Alert severity="warning">{Messages.extensionsUnavailable(error)}</Alert>}
    </>
  );
};
