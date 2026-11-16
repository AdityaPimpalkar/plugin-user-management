import { afterEach, describe, expect, it } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';
import { CredentialsDialog } from './credentials-dialog';

const CA = '-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n';

describe('CredentialsDialog', () => {
  afterEach(cleanup);

  it('shows multi-line properties such as a CA certificate with their line breaks', () => {
    render(
      <CredentialsDialog
        title="User app declared"
        credentials={{
          id: 'app',
          username: 'app',
          password: 'secret',
          uri: 'rediss://app:secret@vk:6379',
          secret: 'vk-app',
          properties: { ssl: 'true', 'ca.crt': CA },
        }}
        onClose={() => {}}
      />
    );
    const ca = screen.getByLabelText('CA certificate');
    expect(ca.tagName).toBe('TEXTAREA');
    expect((ca as HTMLTextAreaElement).value).toBe(CA);
    expect(screen.getByLabelText('TLS').tagName).toBe('INPUT');
  });
});
