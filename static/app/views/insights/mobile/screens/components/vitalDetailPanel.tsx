import React from 'react';
import styled from '@emotion/styled';

import {ExternalLink} from 'sentry/components/core/link';
import {DrawerHeader} from 'sentry/components/globalDrawer/components';
import {t} from 'sentry/locale';
import {space} from 'sentry/styles/space';
import {PageAlert, PageAlertProvider} from 'sentry/utils/performance/contexts/pageAlert';
import {makePerformanceScoreColors} from 'sentry/views/insights/browser/webVitals/utils/performanceScoreColors';
import {SampleDrawerBody} from 'sentry/views/insights/common/components/sampleDrawerBody';
import useCrossPlatformProject from 'sentry/views/insights/mobile/common/queries/useCrossPlatformProject';
import {
  PerformanceScore,
  type VitalItem,
  type VitalStatus,
} from 'sentry/views/insights/mobile/screens/utils';

export function VitalDetailPanel({
  vital,
  status,
}: {
  status: VitalStatus | undefined;
  vital: VitalItem | undefined;
}) {
  const {selectedPlatform} = useCrossPlatformProject();

  const platformDocsLink = vital?.platformDocLinks[selectedPlatform];
  const sdkDocsLink = vital?.sdkDocLinks[selectedPlatform];

  return (
    <PageAlertProvider>
      <DrawerHeader />

      <SampleDrawerBody>
        {vital && (
          <React.Fragment>
            <VitalDetailTitle>{vital.title}</VitalDetailTitle>
            {status && (
              <h2>
                {status.formattedValue ?? '-'}{' '}
                {status.score !== PerformanceScore.NONE && (
                  <Badge status={status.score}>{status.description}</Badge>
                )}
              </h2>
            )}
            <p>{vital.docs}</p>
            {vital.setup && <p>{vital.setup}</p>}
            {(platformDocsLink || sdkDocsLink) && (
              <React.Fragment>
                <SubHeading>{t('Learn more')}</SubHeading>
                <ul>
                  {sdkDocsLink && (
                    <li>
                      <ExternalLink href={sdkDocsLink}>
                        {t('Sentry SDK documentation')}
                      </ExternalLink>
                    </li>
                  )}
                  {platformDocsLink && (
                    <li>
                      <ExternalLink href={platformDocsLink}>
                        {t('Platform documentation')}
                      </ExternalLink>
                    </li>
                  )}
                </ul>
              </React.Fragment>
            )}
          </React.Fragment>
        )}
        <PageAlert />
      </SampleDrawerBody>
    </PageAlertProvider>
  );
}

const VitalDetailTitle = styled('h4')`
  margin-bottom: ${space(1)};
`;

const Badge = styled('div')<{status: PerformanceScore}>`
  white-space: nowrap;
  border-radius: 12px;
  color: ${p => makePerformanceScoreColors(p.theme)[p.status].normal};
  background-color: ${p => makePerformanceScoreColors(p.theme)[p.status].light};
  border: solid 1px ${p => makePerformanceScoreColors(p.theme)[p.status].light};
  font-size: ${p => p.theme.fontSize.sm};
  padding: 0 ${space(1)};
  display: inline-block;
  height: 17px;
  vertical-align: middle;
`;

const SubHeading = styled('div')`
  font-weight: ${p => p.theme.fontWeight.bold};
  margin-bottom: ${space(1)};
`;
