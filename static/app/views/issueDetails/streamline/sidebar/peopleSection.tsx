import {Flex} from 'sentry/components/core/layout';
import {t} from 'sentry/locale';
import type {TeamParticipant, UserParticipant} from 'sentry/types/group';
import type {User} from 'sentry/types/user';
import ParticipantList from 'sentry/views/issueDetails/streamline/sidebar/participantList';
import {SidebarSectionTitle} from 'sentry/views/issueDetails/streamline/sidebar/sidebar';

export default function PeopleSection({
  userParticipants,
  teamParticipants,
  viewers,
}: {
  teamParticipants: TeamParticipant[];
  userParticipants: UserParticipant[];
  viewers: User[];
}) {
  const hasParticipants = userParticipants.length > 0 || teamParticipants.length > 0;
  const hasViewers = viewers.length > 0;

  return (
    <div>
      <SidebarSectionTitle>{t('People')}</SidebarSectionTitle>
      {hasParticipants && (
        <Flex gap="xs" align="center">
          <ParticipantList
            users={userParticipants}
            teams={teamParticipants}
            hideTimestamp
          />
          {t('participating')}
        </Flex>
      )}
      {hasViewers && (
        <Flex gap="xs" align="center">
          <ParticipantList users={viewers} />
          {t('viewed')}
        </Flex>
      )}
    </div>
  );
}
