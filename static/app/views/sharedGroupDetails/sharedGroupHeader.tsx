import styled from '@emotion/styled';

import {Tooltip} from 'sentry/components/core/tooltip';
import {DateTime} from 'sentry/components/dateTime';
import EventMessage from 'sentry/components/events/eventMessage';
import ProjectBadge from 'sentry/components/idBadge/projectBadge';
import ShortId from 'sentry/components/shortId';
import {t} from 'sentry/locale';
import {space} from 'sentry/styles/space';
import type {Group} from 'sentry/types/group';
import EventCreatedTooltip from 'sentry/views/issueDetails/eventCreatedTooltip';

type Props = {
  group: Group;
};

function SharedGroupHeader({group}: Props) {
  const date = new Date(
    (group.latestEvent?.dateCreated ?? group.latestEvent?.dateReceived) as string
  );
  const event = group.latestEvent;

  return (
    <Wrapper>
      <Details>
        <TitleWrap>
          <Title>{group.title}</Title>
          <ShortIdWrapper>
            <ShortId
              shortId={group.shortId}
              avatar={<ProjectBadge project={group.project} avatarSize={20} hideName />}
            />
          </ShortIdWrapper>
          {event && (event.dateCreated ?? event.dateReceived) && (
            <TimeStamp data-test-id="sgh-timestamp">
              {t('Last seen ')}
              <EventTimeLabel>
                <Tooltip
                  isHoverable
                  showUnderline
                  title={<EventCreatedTooltip event={event} />}
                  overlayStyle={{maxWidth: 300}}
                >
                  <DateTime date={date} />
                </Tooltip>
              </EventTimeLabel>
            </TimeStamp>
          )}
        </TitleWrap>
        <EventMessage
          showUnhandled={group.isUnhandled}
          message={group.culprit}
          level={group.level}
          type={group.type}
          data={group}
        />
      </Details>
    </Wrapper>
  );
}

export default SharedGroupHeader;

const Wrapper = styled('div')`
  padding: ${space(3)} ${space(4)} ${space(3)} ${space(4)};
  border-bottom: 1px solid ${p => p.theme.border};
  position: relative;
`;

const Details = styled('div')`
  max-width: 960px;
  margin: 0 auto;
`;

const ShortIdWrapper = styled('div')`
  display: flex;
`;

const TitleWrap = styled('div')`
  display: grid;
  grid-template-columns: 1fr max-content;
  align-items: center;
  margin-bottom: ${space(1)};
`;

const Title = styled('h3')`
  color: ${p => p.theme.headingColor};
  font-size: ${p => p.theme.fontSize.xl};
  line-height: ${p => p.theme.text.lineHeightHeading};
  margin-right: ${space(2)};
  margin-bottom: 0;
  ${p => p.theme.overflowEllipsis};

  @media (min-width: ${props => props.theme.breakpoints.sm}) {
    font-size: ${p => p.theme.headerFontSize};
  }
`;

const TimeStamp = styled('div')`
  color: ${p => p.theme.headingColor};
  font-size: ${p => p.theme.fontSize.md};
  line-height: ${p => p.theme.text.lineHeightHeading};
  margin-top: ${space(0.25)};
`;

const EventTimeLabel = styled('span')`
  color: ${p => p.theme.subText};
  margin-left: ${space(0.25)};
`;
