import { FormEvent, useMemo, useState } from 'react';
import {
  Alert,
  Box,
  Button,
  Chip,
  CircularProgress,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  FormControlLabel,
  Checkbox,
  IconButton,
  MenuItem,
  Stack,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableRow,
  TextField,
  Tooltip,
  Typography,
} from '@mui/material';
import AddIcon from '@mui/icons-material/Add';
import EditIcon from '@mui/icons-material/Edit';
import DeleteIcon from '@mui/icons-material/Delete';
import { useBuckets, useCreateBucket, useDeleteBucket, useUpdateBucket } from 'hooks/useBuckets';
import { useUsers } from 'hooks/useUsers';
import { Bucket, NewBucket } from 'types/buckets.types';

interface BucketsTabProps {
  namespace: string;
  instanceName: string;
}

type DialogState =
  | { kind: 'create' }
  | { kind: 'edit' | 'delete'; bucket: Bucket & { id: string } }
  | null;

export const BucketsTab = ({ namespace, instanceName }: BucketsTabProps) => {
  const target = useMemo(() => ({ namespace, instanceName }), [namespace, instanceName]);
  const [dialog, setDialog] = useState<DialogState>(null);
  const buckets = useBuckets(target);
  const users = useUsers(target);
  const create = useCreateBucket(target);
  const update = useUpdateBucket(target);
  const remove = useDeleteBucket(target);

  if (buckets.isLoading) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', p: 4 }}>
        <CircularProgress />
      </Box>
    );
  }
  if (buckets.error || !buckets.data) {
    return <Alert severity="error">Buckets could not be loaded: {buckets.error?.message}</Alert>;
  }
  if (!buckets.data.supported) {
    return <Alert severity="info">Buckets are not supported for this provider.</Alert>;
  }

  const owners = (users.data?.users ?? [])
    .filter((user) => user.managed && user.id)
    .map((user) => ({ id: user.id as string, username: user.username }));
  const close = () => {
    [create, update, remove].forEach((mutation) => mutation.reset());
    setDialog(null);
  };

  return (
    <Stack sx={{ gap: 2, mt: 2 }}>
      <Stack direction="row" sx={{ alignItems: 'center', justifyContent: 'space-between' }}>
        <Box>
          <Typography variant="h6">Buckets</Typography>
          <Typography variant="body2" color="text.secondary">
            Create S3 buckets and assign an optional managed user as owner.
          </Typography>
        </Box>
        <Tooltip title={buckets.data.canManage ? '' : 'Requires read-connection permission.'}>
          <span>
            <Button
              variant="contained"
              startIcon={<AddIcon />}
              disabled={!buckets.data.canManage}
              onClick={() => setDialog({ kind: 'create' })}
            >
              Create bucket
            </Button>
          </span>
        </Tooltip>
      </Stack>
      {!buckets.data.canManage && (
        <Alert severity="info">Requires permission to read this instance's connection details.</Alert>
      )}
      {buckets.data.bucketError && (
        <Alert severity="warning">Some existing buckets could not be listed: {buckets.data.bucketError}</Alert>
      )}
      {!buckets.data.buckets.some((bucket) => bucket.managed) && (
        <Alert severity="info">No managed buckets yet.</Alert>
      )}
      <Table size="small">
        <TableHead>
          <TableRow>
            <TableCell>Name</TableCell>
            <TableCell>Owner</TableCell>
            <TableCell>Status</TableCell>
            <TableCell align="right">Actions</TableCell>
          </TableRow>
        </TableHead>
        <TableBody>
          {buckets.data.buckets.map((bucket) => (
            <TableRow key={bucket.id ?? bucket.name}>
              <TableCell>{bucket.name}</TableCell>
              <TableCell>{bucket.owner || '—'}</TableCell>
              <TableCell>
                <Tooltip title={bucket.message || ''}>
                  <Chip
                    size="small"
                    color={
                      bucket.phase === 'Ready'
                        ? 'success'
                        : bucket.phase === 'Failed'
                          ? 'error'
                          : bucket.managed
                            ? 'default'
                            : 'secondary'
                    }
                    label={bucket.managed ? bucket.phase || 'Pending' : 'Unmanaged'}
                  />
                </Tooltip>
              </TableCell>
              <TableCell align="right">
                {bucket.managed && bucket.id && (
                  <>
                    <IconButton
                      aria-label={`Edit ${bucket.name}`}
                      disabled={!buckets.data?.canManage}
                      onClick={() => setDialog({ kind: 'edit', bucket: bucket as Bucket & { id: string } })}
                    >
                      <EditIcon />
                    </IconButton>
                    <IconButton
                      aria-label={`Delete ${bucket.name}`}
                      disabled={!buckets.data?.canManage}
                      onClick={() => setDialog({ kind: 'delete', bucket: bucket as Bucket & { id: string } })}
                    >
                      <DeleteIcon />
                    </IconButton>
                  </>
                )}
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
      {(dialog?.kind === 'create' || dialog?.kind === 'edit') && (
        <BucketFormDialog
          bucket={dialog.kind === 'edit' ? dialog.bucket : undefined}
          owners={owners}
          isSubmitting={create.isPending || update.isPending}
          error={(create.error ?? update.error)?.message}
          onClose={close}
          onSubmit={(value) => {
            if (dialog.kind === 'create') {
              create.mutate(value, { onSuccess: close });
            } else {
              update.mutate(
                { id: dialog.bucket.id, settings: { ownerId: value.ownerId } },
                { onSuccess: close }
              );
            }
          }}
        />
      )}
      {dialog?.kind === 'delete' && (
        <DeleteBucketDialog
          name={dialog.bucket.name}
          isSubmitting={remove.isPending}
          error={remove.error?.message}
          onClose={close}
          onConfirm={(drop) =>
            remove.mutate({ id: dialog.bucket.id, drop }, { onSuccess: close })
          }
        />
      )}
    </Stack>
  );
};

interface BucketFormDialogProps {
  bucket?: Bucket;
  owners: { id: string; username: string }[];
  isSubmitting: boolean;
  error?: string;
  onClose: () => void;
  onSubmit: (bucket: NewBucket) => void;
}

const BucketFormDialog = ({
  bucket,
  owners,
  isSubmitting,
  error,
  onClose,
  onSubmit,
}: BucketFormDialogProps) => {
  const [name, setName] = useState(bucket?.name ?? '');
  const [ownerId, setOwnerId] = useState(bucket?.ownerId ?? '');
  const [submitted, setSubmitted] = useState(false);
  const isCreate = !bucket;
  const validName =
    /^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/.test(name.trim()) &&
    !name.includes('..') &&
    !/^[0-9]+[.][0-9]+[.][0-9]+[.][0-9]+$/.test(name.trim());

  const submit = (event: FormEvent) => {
    event.preventDefault();
    setSubmitted(true);
    if (isCreate && !validName) {
      return;
    }
    onSubmit({ name: name.trim(), ownerId: ownerId || undefined });
  };

  return (
    <Dialog open onClose={onClose} fullWidth maxWidth="sm">
      <form onSubmit={submit}>
        <DialogTitle>{isCreate ? 'Create bucket' : `Edit ${bucket.name}`}</DialogTitle>
        <DialogContent>
          <Stack sx={{ gap: 2, pt: 1 }}>
            {isCreate && (
              <TextField
                autoFocus
                size="small"
                label="Bucket name"
                value={name}
                onChange={(event) => setName(event.target.value)}
                error={submitted && !validName}
                helperText={
                  submitted && !validName
                    ? 'Use a valid S3 bucket name.'
                    : '3-63 lowercase letters, digits, dots or hyphens.'
                }
              />
            )}
            <TextField
              select
              size="small"
              label="Owner"
              value={ownerId}
              onChange={(event) => setOwnerId(event.target.value)}
              helperText="Optional. The owner identity must already exist in this instance."
            >
              <MenuItem value="">No owner (admin only)</MenuItem>
              {owners.map((owner) => (
                <MenuItem key={owner.id} value={owner.id}>
                  {owner.username}
                </MenuItem>
              ))}
            </TextField>
            {error && <Alert severity="error">{error}</Alert>}
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="contained" disabled={isSubmitting}>
            {isCreate ? 'Create' : 'Save'}
          </Button>
        </DialogActions>
      </form>
    </Dialog>
  );
};

interface DeleteBucketDialogProps {
  name: string;
  isSubmitting: boolean;
  error?: string;
  onClose: () => void;
  onConfirm: (drop: boolean) => void;
}

const DeleteBucketDialog = ({
  name,
  isSubmitting,
  error,
  onClose,
  onConfirm,
}: DeleteBucketDialogProps) => {
  const [drop, setDrop] = useState(false);
  return (
    <Dialog open onClose={onClose} fullWidth maxWidth="sm">
      <DialogTitle>Delete bucket {name}?</DialogTitle>
      <DialogContent>
        <Stack sx={{ gap: 2 }}>
          <Alert severity={drop ? 'error' : 'info'}>
            {drop
              ? 'The bucket and all its objects will be permanently deleted.'
              : 'OpenEverest will stop managing the bucket and keep its objects.'}
          </Alert>
          <FormControlLabel
            control={<Checkbox checked={drop} onChange={(event) => setDrop(event.target.checked)} />}
            label="Delete the bucket and all objects"
          />
          {error && <Alert severity="error">{error}</Alert>}
        </Stack>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>Cancel</Button>
        <Button
          variant="contained"
          color={drop ? 'error' : 'primary'}
          disabled={isSubmitting}
          onClick={() => onConfirm(drop)}
        >
          {drop ? 'Delete data' : 'Keep data and unmanage'}
        </Button>
      </DialogActions>
    </Dialog>
  );
};
