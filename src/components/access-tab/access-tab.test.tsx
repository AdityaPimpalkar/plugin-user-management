import { afterEach, describe, expect, it } from 'vitest';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import type { PluginApi } from '@openeverest/plugin-sdk';
import { PluginApiContext } from 'components/plugin-api-context/plugin-api.context';
import { AccessTab } from './access-tab';
import { Messages } from './access-tab.messages';

const json = (body: unknown) => new Response(JSON.stringify(body), { status: 200 });

// A plugin API whose backend reports which scoped resources the engine manages.
const fakeApi = (databasesSupported: boolean, bucketsSupported = false) =>
  ({
    fetch: async (path: string) =>
      path.startsWith('/api/databases')
        ? json({ databases: [], supported: true, canManage: true })
        : path.startsWith('/api/buckets')
          ? json({ buckets: [], supported: true, canManage: true })
        : json({
            users: [],
            roles: [],
            canManage: true,
            credentialKind: 'password',
            rolesRequired: !databasesSupported,
            databasesSupported,
            bucketsSupported,
          }),
  }) as unknown as PluginApi;

const renderTab = (databasesSupported: boolean, bucketsSupported = false) =>
  render(
    <PluginApiContext.Provider value={fakeApi(databasesSupported, bucketsSupported)}>
      <QueryClientProvider client={new QueryClient()}>
        <AccessTab namespace="ns" instanceName="pg" />
      </QueryClientProvider>
    </PluginApiContext.Provider>
  );

describe('AccessTab', () => {
  afterEach(cleanup);

  it('shows users and databases as sections where databases are managed', async () => {
    renderTab(true);
    const tabs = await screen.findByRole('tablist', { name: Messages.sectionsLabel });
    expect(tabs.textContent).toBe('UsersDatabases');
    expect(await screen.findByText('Database users')).toBeTruthy();

    fireEvent.click(screen.getByRole('tab', { name: Messages.sections.databases }));
    expect(await screen.findByRole('button', { name: 'Create database' })).toBeTruthy();
  });

  it('shows only the users where databases are not managed', async () => {
    renderTab(false);
    expect(await screen.findByText('Database users')).toBeTruthy();
    expect(screen.queryByRole('tablist')).toBeNull();
  });

  it('shows users and buckets as sections where buckets are managed', async () => {
    renderTab(false, true);
    const tabs = await screen.findByRole('tablist', { name: Messages.sectionsLabel });
    expect(tabs.textContent).toBe('UsersBuckets');

    fireEvent.click(screen.getByRole('tab', { name: Messages.sections.buckets }));
    expect(await screen.findByRole('button', { name: 'Create bucket' })).toBeTruthy();
  });
});
