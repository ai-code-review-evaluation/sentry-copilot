import type {ReactElement} from 'react';
import {Fragment} from 'react';
import styled from '@emotion/styled';

import {Badge} from 'sentry/components/core/badge';
import {FeatureBadge} from 'sentry/components/core/badge/featureBadge';
import {Tooltip} from 'sentry/components/core/tooltip';
import HookOrDefault from 'sentry/components/hookOrDefault';
import {t} from 'sentry/locale';
import {space} from 'sentry/styles/space';
import {SecondaryNav} from 'sentry/views/nav/secondary/secondary';

type Props = {
  label: React.ReactNode;
  to: string;
  badge?: string | number | null | ReactElement;
  id?: string;
  index?: boolean;
  onClick?: (e: React.MouseEvent) => void;
};

const LabelHook = HookOrDefault({
  hookName: 'sidebar:item-label',
  defaultComponent: ({children}) => <Fragment>{children}</Fragment>,
});

function SettingsNavBadge({badge}: {badge: string | number | null | ReactElement}) {
  if (badge === 'new' || badge === 'beta' || badge === 'alpha') {
    return <FeatureBadge type={badge} />;
  }
  if (badge === 'warning') {
    return (
      <Tooltip title={t('This setting needs review')} position="right">
        <StyledBadge type="warning">{badge}</StyledBadge>
      </Tooltip>
    );
  }
  if (typeof badge === 'string' || typeof badge === 'number') {
    return <StyledBadge type="default">{badge}</StyledBadge>;
  }

  return badge;
}

function SettingsNavItem({badge, label, id, to, index, ...props}: Props) {
  return (
    <SecondaryNav.Item
      to={to}
      end={index}
      trailingItems={badge ? <SettingsNavBadge badge={badge} /> : null}
      analyticsItemName={id ? `settings_${id}` : undefined}
      {...props}
    >
      <LabelHook id={id}>{label}</LabelHook>
    </SecondaryNav.Item>
  );
}

const StyledBadge = styled(Badge)`
  font-weight: ${p => p.theme.fontWeight.normal};
  height: auto;
  line-height: 1;
  font-size: ${p => p.theme.fontSize.xs};
  padding: 3px ${space(0.75)};
  vertical-align: middle;
`;

export default SettingsNavItem;
