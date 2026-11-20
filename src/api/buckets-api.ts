import { BucketsResponse, BucketSettings, NewBucket } from 'types/buckets.types';
import { InstanceTarget } from 'types/users.types';
import { instanceParams, PluginFetch, request } from './plugin-request';

const bucketPath = (id: string, target: InstanceTarget, params?: Record<string, string>) => {
  const query = instanceParams(target);
  Object.entries(params ?? {}).forEach(([key, value]) => query.set(key, value));
  return `/api/buckets/${encodeURIComponent(id)}?${query}`;
};

export const getBuckets = async (
  pluginFetch: PluginFetch,
  target: InstanceTarget
): Promise<BucketsResponse> => {
  const response = await request(pluginFetch, `/api/buckets?${instanceParams(target)}`);
  return response.json();
};

export const createBucket = async (
  pluginFetch: PluginFetch,
  target: InstanceTarget,
  bucket: NewBucket
): Promise<void> => {
  await request(pluginFetch, `/api/buckets?${instanceParams(target)}`, {
    method: 'POST',
    body: JSON.stringify(bucket),
  });
};

export const updateBucket = async (
  pluginFetch: PluginFetch,
  target: InstanceTarget,
  id: string,
  settings: BucketSettings
): Promise<void> => {
  await request(pluginFetch, bucketPath(id, target), {
    method: 'PUT',
    body: JSON.stringify(settings),
  });
};

export const deleteBucket = async (
  pluginFetch: PluginFetch,
  target: InstanceTarget,
  id: string,
  drop: boolean
): Promise<void> => {
  await request(
    pluginFetch,
    bucketPath(id, target, drop ? { drop: 'true' } : undefined),
    { method: 'DELETE' }
  );
};
