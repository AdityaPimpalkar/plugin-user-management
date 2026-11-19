export const Messages = {
  storedIn: (secret: string) =>
    `Stored in Secret ${secret} in this namespace, so applications can mount it. Anyone who can manage this instance's users can see it here.`,
  // Labels of further connection details, by Secret key.
  property: (key: string) =>
    (
      ({
        model: 'Model',
        ssl: 'TLS',
        'ca.crt': 'CA certificate',
        AWS_ACCESS_KEY_ID: 'Access key ID',
        endpointURL: 'S3 endpoint',
        externalEndpointURL: 'External S3 endpoint',
        forcePathStyle: 'Force path style',
        region: 'Region',
        verifyTLS: 'Verify TLS',
        externalVerifyTLS: 'Verify external TLS',
      }) as Record<string, string>
    )[key] ?? key,
  copy: 'Copy',
  copied: 'Copied',
  copyLabel: (field: string) => `Copy ${field}`,
  done: 'Done',
};
