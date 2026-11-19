import { useMemo, useState } from 'react';
import { Box, CircularProgress, Tab, Tabs } from '@mui/material';
import { useUsers } from 'hooks/useUsers';
import { UsersTab } from 'components/users-tab/users-tab';
import { DatabasesTab } from 'components/databases-tab/databases-tab';
import { BucketsTab } from 'components/buckets-tab/buckets-tab';
import { Messages } from './access-tab.messages';

type Section = keyof typeof Messages.sections;

interface AccessTabProps {
  namespace: string;
  instanceName: string;
}

// The instance's Access tab: users plus any scoped resources the engine manages.
export const AccessTab = ({ namespace, instanceName }: AccessTabProps) => {
  const target = useMemo(() => ({ namespace, instanceName }), [namespace, instanceName]);
  const [section, setSection] = useState<Section>('users');
  const { data, isLoading } = useUsers(target);

  if (isLoading) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', p: 4 }}>
        <CircularProgress />
      </Box>
    );
  }
  const sections = (['users', 'databases', 'buckets'] as Section[]).filter((candidate) => {
    if (candidate === 'databases') {
      return data?.databasesSupported;
    }
    if (candidate === 'buckets') {
      return data?.bucketsSupported;
    }
    return true;
  });
  if (sections.length === 1) {
    return <UsersTab namespace={namespace} instanceName={instanceName} />;
  }
  return (
    <Box>
      <Tabs
        value={section}
        onChange={(_, value: Section) => setSection(value)}
        aria-label={Messages.sectionsLabel}
        sx={{ borderBottom: 1, borderColor: 'divider' }}
      >
        {sections.map((key) => (
          <Tab key={key} value={key} label={Messages.sections[key]} />
        ))}
      </Tabs>
      {section === 'users' ? (
        <UsersTab namespace={namespace} instanceName={instanceName} />
      ) : section === 'databases' ? (
        <DatabasesTab namespace={namespace} instanceName={instanceName} />
      ) : (
        <BucketsTab namespace={namespace} instanceName={instanceName} />
      )}
    </Box>
  );
};
