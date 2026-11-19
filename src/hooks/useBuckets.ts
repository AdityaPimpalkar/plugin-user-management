import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { createBucket, deleteBucket, getBuckets, updateBucket } from 'api/buckets-api';
import { usePluginApi } from 'components/plugin-api-context/plugin-api.context';
import { BucketsResponse, BucketSettings, NewBucket } from 'types/buckets.types';
import { InstanceTarget } from 'types/users.types';

const SETTLING_REFETCH_MS = 3_000;

export const bucketsQueryKey = (target: InstanceTarget) => [
  'db-buckets',
  target.namespace,
  target.instanceName,
];

const isSettling = (data?: BucketsResponse) =>
  !!data?.buckets.some((bucket) => bucket.phase === 'Pending' || bucket.phase === 'Deleting');

export const useBuckets = (target: InstanceTarget, enabled = true) => {
  const api = usePluginApi();
  return useQuery({
    queryKey: bucketsQueryKey(target),
    queryFn: () => getBuckets(api.fetch, target),
    enabled,
    refetchInterval: (query) => (isSettling(query.state.data) ? SETTLING_REFETCH_MS : false),
  });
};

const useBucketsMutation = <TVariables>(
  target: InstanceTarget,
  mutate: (variables: TVariables) => Promise<void>
) => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: mutate,
    onSuccess: () =>
      Promise.all([
        queryClient.invalidateQueries({ queryKey: bucketsQueryKey(target) }),
        queryClient.invalidateQueries({
          queryKey: ['db-users', target.namespace, target.instanceName],
        }),
      ]),
  });
};

export const useCreateBucket = (target: InstanceTarget) => {
  const api = usePluginApi();
  return useBucketsMutation(target, (bucket: NewBucket) =>
    createBucket(api.fetch, target, bucket)
  );
};

export const useUpdateBucket = (target: InstanceTarget) => {
  const api = usePluginApi();
  return useBucketsMutation(
    target,
    ({ id, settings }: { id: string; settings: BucketSettings }) =>
      updateBucket(api.fetch, target, id, settings)
  );
};

export const useDeleteBucket = (target: InstanceTarget) => {
  const api = usePluginApi();
  return useBucketsMutation(
    target,
    ({ id, drop }: { id: string; drop: boolean }) =>
      deleteBucket(api.fetch, target, id, drop)
  );
};
