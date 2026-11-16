import { useMemo, useState } from 'react';
import { Alert, Box, Button, CircularProgress, Stack, Tooltip, Typography } from '@mui/material';
import AddIcon from '@mui/icons-material/Add';
import { useCreateDatabase, useDatabases, useDeleteDatabase, useUpdateDatabase } from 'hooks/useDatabases';
import { useCreateUser, useUsers } from 'hooks/useUsers';
import { CredentialsDialog } from 'components/credentials-dialog/credentials-dialog';
import { useTerms } from 'components/terms-context/terms.context';
import { Credentials } from 'types/users.types';
import { NewDatabase } from 'types/databases.types';
import { DatabasesTable } from './databases-table/databases-table';
import { DatabaseFormDialog } from './database-form-dialog/database-form-dialog';
import { DeleteDatabaseDialog } from './delete-database-dialog/delete-database-dialog';
import { DatabasesDialogState } from './databases-tab.types';
import { ownerOptions } from './databases-tab.utils';
import { Messages } from './databases-tab.messages';

interface DatabasesTabProps {
  namespace: string;
  instanceName: string;
}

export const DatabasesTab = ({ namespace, instanceName }: DatabasesTabProps) => {
  const target = useMemo(() => ({ namespace, instanceName }), [namespace, instanceName]);
  const [dialog, setDialog] = useState<DatabasesDialogState>(null);
  const { data, isLoading, error } = useDatabases(target);
  const users = useUsers(target);
  const createDatabase = useCreateDatabase(target);
  const updateDatabase = useUpdateDatabase(target);
  const deleteDatabase = useDeleteDatabase(target);
  const createUser = useCreateUser(target);
  const terms = useTerms();
  // An owner created along with a database whose creation then failed: a retry
  // reuses it, and its credentials are shown however the dialog closes.
  const [createdOwner, setCreatedOwner] = useState<Credentials | null>(null);
  const [shown, setShown] = useState<Credentials | null>(null);

  if (isLoading) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', p: 4 }}>
        <CircularProgress />
      </Box>
    );
  }
  if (error || !data) {
    return (
      <Alert severity="error" sx={{ mt: 2 }}>
        {Messages.loadFailed(error?.message ?? '')}
      </Alert>
    );
  }
  if (!data.supported) {
    return (
      <Alert severity="info" sx={{ mt: 2 }}>
        {Messages.unsupported}
      </Alert>
    );
  }

  const { databases, canManage, connectChoice, databaseError, postgresql } = data;
  const owners = ownerOptions(users.data?.users ?? []);
  const canCreateOwner = !!users.data?.canManage && users.data.rolesRequired === false;
  const close = () => {
    [createDatabase, updateDatabase, deleteDatabase, createUser].forEach((m) => m.reset());
    setDialog(null);
    if (createdOwner) {
      setShown(createdOwner);
      setCreatedOwner(null);
    }
  };

  const create = async (db: NewDatabase, newOwner?: string) => {
    let owner: Credentials | null = null;
    try {
      if (newOwner !== undefined) {
        owner =
          createdOwner?.username === newOwner
            ? createdOwner
            : await createUser.mutateAsync({ username: newOwner, roles: [] });
        setCreatedOwner(owner);
        createUser.reset();
      }
      await createDatabase.mutateAsync(owner ? { ...db, ownerId: owner.id } : db);
    } catch {
      // Shown in the dialog from the mutations' state.
      return;
    }
    [createDatabase, createUser].forEach((m) => m.reset());
    setDialog(null);
    setCreatedOwner(null);
    if (owner) {
      setShown(owner);
    }
  };

  return (
    <Stack sx={{ gap: 2, mt: 2 }}>
      <Stack direction="row" sx={{ alignItems: 'center', justifyContent: 'space-between', gap: 2 }}>
        <Box>
          <Typography variant="h6">{Messages.title}</Typography>
          <Typography variant="body2" color="text.secondary">
            {Messages.subtitle}
          </Typography>
        </Box>
        <Tooltip title={canManage ? '' : Messages.readOnly}>
          <span>
            <Button
              variant="contained"
              startIcon={<AddIcon />}
              disabled={!canManage}
              onClick={() => setDialog({ kind: 'create' })}
            >
              {Messages.createDatabase}
            </Button>
          </span>
        </Tooltip>
      </Stack>
      {!canManage && <Alert severity="info">{Messages.readOnly}</Alert>}
      {databaseError && <Alert severity="warning">{Messages.databaseError(databaseError)}</Alert>}
      {!databases.some((d) => d.managed) && <Alert severity="info">{Messages.noDatabases}</Alert>}
      <DatabasesTable
        databases={databases}
        showExtensions={!!postgresql}
        showConnect={connectChoice}
        canManage={canManage}
        onAction={(kind, database) => setDialog({ kind, database })}
      />
      {dialog?.kind === 'create' && (
        <DatabaseFormDialog
          owners={owners}
          connectChoice={connectChoice}
          extensions={postgresql?.extensions}
          extensionsError={postgresql?.extensionsError}
          canCreateOwner={canCreateOwner}
          isSubmitting={createDatabase.isPending || createUser.isPending}
          error={(createUser.error ?? createDatabase.error)?.message}
          onClose={close}
          onSubmit={create}
        />
      )}
      {dialog?.kind === 'edit' && (
        <DatabaseFormDialog
          initial={{
            name: dialog.database.name,
            ownerId: dialog.database.ownerId ?? '',
            connect: dialog.database.connect ?? 'Public',
            postgresql: dialog.database.postgresql,
          }}
          owners={owners}
          connectChoice={connectChoice}
          extensions={postgresql?.extensions}
          extensionsError={postgresql?.extensionsError}
          isSubmitting={updateDatabase.isPending}
          error={updateDatabase.error?.message}
          onClose={close}
          onSubmit={({ ownerId, connect, postgresql: pg }) =>
            updateDatabase.mutate(
              { id: dialog.database.id, settings: { ownerId, connect, postgresql: pg } },
              { onSuccess: close }
            )
          }
        />
      )}
      {shown && (
        <CredentialsDialog
          title={terms.createdTitle(shown.username)}
          credentials={shown}
          onClose={() => setShown(null)}
        />
      )}
      {dialog?.kind === 'delete' && (
        <DeleteDatabaseDialog
          name={dialog.database.name}
          isSubmitting={deleteDatabase.isPending}
          error={deleteDatabase.error?.message}
          onClose={close}
          onConfirm={(drop) => deleteDatabase.mutate({ id: dialog.database.id, drop }, { onSuccess: close })}
        />
      )}
    </Stack>
  );
};
