import { afterEach, describe, expect, it } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import type { PluginApi } from '@openeverest/plugin-sdk';
import { PluginApiContext } from 'components/plugin-api-context/plugin-api.context';
import { BucketsTab } from './buckets-tab';

const json = (body: unknown) => new Response(JSON.stringify(body), { status: 200 });

const renderTab = (fetch: PluginApi['fetch']) =>
  render(
    <PluginApiContext.Provider value={{ fetch } as PluginApi}>
      <QueryClientProvider client={new QueryClient()}>
        <BucketsTab namespace="ns" instanceName="store" />
      </QueryClientProvider>
    </PluginApiContext.Provider>
  );

describe('BucketsTab', () => {
  afterEach(cleanup);

  it('creates a bucket without an owner', async () => {
    const requests: { path: string; init?: RequestInit }[] = [];
    renderTab(async (path, init) => {
      requests.push({ path: String(path), init });
      if (String(path).startsWith('/api/users')) {
        return json({ users: [], roles: [], canManage: true });
      }
      if (init?.method === 'POST') {
        return json({});
      }
      return json({ buckets: [], supported: true, canManage: true });
    });

    fireEvent.click(await screen.findByRole('button', { name: 'Create bucket' }));
    fireEvent.change(screen.getByLabelText('Bucket name'), {
      target: { value: 'uploads.bucket' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Create' }));

    await waitFor(() =>
      expect(
        requests.some(
          ({ path, init }) =>
            path.startsWith('/api/buckets') &&
            init?.method === 'POST' &&
            init.body === '{"name":"uploads.bucket"}'
        )
      ).toBe(true)
    );
  });

  it('keeps data by default when unmanaging a bucket', async () => {
    const requests: { path: string; init?: RequestInit }[] = [];
    renderTab(async (path, init) => {
      requests.push({ path: String(path), init });
      if (String(path).startsWith('/api/users')) {
        return json({ users: [], roles: [], canManage: true });
      }
      if (init?.method === 'DELETE') {
        return json({});
      }
      return json({
        buckets: [
          {
            id: 'store-uploads',
            name: 'uploads',
            managed: true,
            phase: 'Ready',
            deletionPolicy: 'Retain',
          },
        ],
        supported: true,
        canManage: true,
      });
    });

    fireEvent.click(await screen.findByRole('button', { name: 'Delete uploads' }));
    fireEvent.click(screen.getByRole('button', { name: 'Keep data and unmanage' }));

    await waitFor(() =>
      expect(
        requests.some(
          ({ path, init }) =>
            init?.method === 'DELETE' &&
            path.startsWith('/api/buckets/store-uploads') &&
            !path.includes('drop=true')
        )
      ).toBe(true)
    );
  });
});
