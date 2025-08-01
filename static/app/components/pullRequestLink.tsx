import styled from '@emotion/styled';

import {LinkButton} from 'sentry/components/core/button/linkButton';
import {ExternalLink} from 'sentry/components/core/link';
import {IconBitbucket, IconGithub, IconGitlab} from 'sentry/icons';
import {space} from 'sentry/styles/space';
import type {PullRequest, Repository} from 'sentry/types/integrations';

function renderIcon(repo: Repository) {
  if (!repo.provider) {
    return null;
  }

  const {id} = repo.provider;
  const providerId = id.includes(':') ? id.split(':').pop() : id;

  switch (providerId) {
    case 'github':
      return <IconGithub size="xs" data-test-id="pull-request-github" />;
    case 'gitlab':
      return <IconGitlab size="xs" data-test-id="pull-request-gitlab" />;
    case 'bitbucket':
      return <IconBitbucket size="xs" />;
    default:
      return null;
  }
}

type Props = {
  pullRequest: PullRequest;
  repository: Repository;
  inline?: boolean;
};

function PullRequestLink({pullRequest, repository, inline}: Props) {
  const displayId = `${repository.name} #${pullRequest.id}: ${pullRequest.title}`;

  if (!pullRequest.externalUrl) {
    return <span>{displayId}</span>;
  }

  return inline ? (
    <ExternalPullLink href={pullRequest.externalUrl}>
      {renderIcon(repository)}
      {displayId}
    </ExternalPullLink>
  ) : (
    <LinkButton
      external
      href={pullRequest.externalUrl}
      size="sm"
      icon={renderIcon(repository)}
    >
      {displayId}
    </LinkButton>
  );
}

const ExternalPullLink = styled(ExternalLink)`
  display: inline-flex;
  align-items: center;
  gap: ${space(0.5)};

  svg {
    flex-shrink: 0;
  }
`;

export default PullRequestLink;
