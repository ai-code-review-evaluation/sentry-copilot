import styled from '@emotion/styled';

import {ExternalLink} from 'sentry/components/core/link';
import QuestionTooltip from 'sentry/components/questionTooltip';
import {t} from 'sentry/locale';
import {space} from 'sentry/styles/space';

type TooltipProps = Omit<React.ComponentProps<typeof QuestionTooltip>, 'size'>;

interface PageHeadingQuestionTooltipProps extends TooltipProps {
  /**
   * The link to the documentation for this page.
   */
  docsUrl: string;
  /**
   * The label to use for the external link.
   */
  linkLabel?: React.ReactNode;
}

export function PageHeadingQuestionTooltip({
  docsUrl,
  title,
  linkLabel,
  ...props
}: PageHeadingQuestionTooltipProps) {
  const contents = (
    <Container>
      {title}
      <ExternalLink href={docsUrl}>{linkLabel ?? t('Read the Docs')}</ExternalLink>
    </Container>
  );

  return (
    <QuestionTooltip isHoverable position="right" size="sm" title={contents} {...props} />
  );
}

const Container = styled('div')`
  display: inline-flex;
  flex-direction: column;
  align-items: flex-start;
  text-align: left;
  gap: ${space(1)};
`;
