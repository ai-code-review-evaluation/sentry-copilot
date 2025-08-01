import type {DO_NOT_USE_ChonkTheme} from '@emotion/react';

import type {InputStylesProps} from 'sentry/components/core/input';
import type {StrictCSSObject} from 'sentry/utils/theme';

export const chonkInputStyles = ({
  theme,
  monospace,
  readOnly,
  size = 'md',
}: InputStylesProps & {theme: DO_NOT_USE_ChonkTheme}): StrictCSSObject => ({
  display: 'block',
  width: '100%',
  color: theme.tokens.content.primary,
  background: theme.tokens.background.secondary,
  boxShadow: `0px 2px 0px 0px ${theme.tokens.border.primary} inset`,
  border: `1px solid ${theme.tokens.border.primary}`,
  fontWeight: theme.fontWeight.normal,
  resize: 'vertical',
  transition: 'border 0.1s, box-shadow 0.1s',
  ...(monospace ? {fontFamily: theme.text.familyMono} : {}),
  ...(readOnly ? {cursor: 'default'} : {}),

  ...theme.form[size],
  ...theme.formPadding[size],
  ...theme.formRadius[size],

  '&::placeholder': {
    color: theme.tokens.content.muted,
    opacity: 1,
  },

  "&[disabled], &[aria-disabled='true']": {
    color: theme.disabled,
    cursor: 'not-allowed',
    opacity: '60%',

    '&::placeholder': {
      color: theme.disabled,
    },
  },

  '&:focus, &:focus-visible, :focus-within': {
    ...theme.focusRing,
  },
  "&[type='number']": {
    appearance: 'textfield',
    MozAppearance: 'textfield',
    fontVariantNumeric: 'tabular-nums',
  },
  '&::-webkit-outer-spin-button, &::-webkit-inner-spin-button': {
    WebkitAppearance: 'none',
    margin: 0,
  },
});
