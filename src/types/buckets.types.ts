import { UserPhase } from './users.types';

export interface Bucket {
  id?: string;
  name: string;
  owner?: string;
  ownerId?: string;
  deletionPolicy?: 'Retain' | 'Delete';
  managed: boolean;
  phase?: UserPhase;
  message?: string;
}

export interface BucketsResponse {
  buckets: Bucket[];
  supported: boolean;
  canManage: boolean;
  bucketError?: string;
}

export interface BucketSettings {
  ownerId?: string;
}

export interface NewBucket extends BucketSettings {
  name: string;
}
