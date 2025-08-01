import {useCallback, useMemo} from 'react';
import styled from '@emotion/styled';

import type {SelectKey, SelectOption} from 'sentry/components/core/compactSelect';
import {CompactSelect} from 'sentry/components/core/compactSelect';
import {Tooltip} from 'sentry/components/core/tooltip';
import {t} from 'sentry/locale';
import type {Sort} from 'sentry/utils/discover/fields';
import {
  ToolbarHeader,
  ToolbarLabel,
  ToolbarRow,
  ToolbarSection,
} from 'sentry/views/explore/components/toolbar/styles';
import {
  useExploreFields,
  useExploreGroupBys,
  useExploreMode,
  useExploreSortBys,
  useExploreVisualizes,
  useSetExploreSortBys,
} from 'sentry/views/explore/contexts/pageParamsContext';
import {Mode} from 'sentry/views/explore/contexts/pageParamsContext/mode';
import {useSortByFields} from 'sentry/views/explore/hooks/useSortByFields';
import {Tab, useTab} from 'sentry/views/explore/hooks/useTab';

export function ToolbarSortBy() {
  const mode = useExploreMode();
  const fields = useExploreFields();
  const groupBys = useExploreGroupBys();
  const visualizes = useExploreVisualizes();

  const sorts = useExploreSortBys();
  const setSorts = useSetExploreSortBys();

  const [tab] = useTab();

  // traces table is only sorted by timestamp so disable the sort by
  const disabled = mode === Mode.SAMPLES && tab === Tab.TRACE;

  const fieldOptions = useSortByFields({
    fields,
    yAxes: visualizes.map(v => v.yAxis),
    groupBys,
    mode,
  });

  const setSortField = useCallback(
    (i: number, {value}: SelectOption<SelectKey>) => {
      if (sorts[i] && typeof value === 'string') {
        setSorts([
          {
            field: value,
            kind: sorts[i].kind,
          },
        ]);
      }
    },
    [setSorts, sorts]
  );

  const kindOptions: Array<SelectOption<Sort['kind']>> = useMemo(() => {
    return [
      {
        label: 'Desc',
        value: 'desc',
        textValue: t('Descending'),
      },
      {
        label: 'Asc',
        value: 'asc',
        textValue: t('Ascending'),
      },
    ];
  }, []);

  const setSortKind = useCallback(
    (i: number, {value}: SelectOption<SelectKey>) => {
      if (sorts[i]) {
        setSorts([
          {
            field: sorts[i].field,
            kind: value as Sort['kind'],
          },
        ]);
      }
    },
    [setSorts, sorts]
  );

  let toolbarRow = (
    <ToolbarRow>
      <ColumnCompactSelect
        options={fieldOptions}
        value={sorts[0]?.field}
        onChange={newSortField => setSortField(0, newSortField)}
        disabled={disabled}
      />
      <DirectionCompactSelect
        options={kindOptions}
        value={sorts[0]?.kind}
        onChange={newSortKind => setSortKind(0, newSortKind)}
        disabled={disabled}
      />
    </ToolbarRow>
  );

  if (disabled) {
    toolbarRow = (
      <FullWidthTooltip
        position="top"
        title={t('Sort by is not applicable to trace results.')}
      >
        {toolbarRow}
      </FullWidthTooltip>
    );
  }

  return (
    <ToolbarSection data-test-id="section-sort-by">
      <ToolbarHeader>
        <Tooltip
          position="right"
          title={t('Results you see first and last in your samples or aggregates.')}
        >
          <ToolbarLabel disabled={disabled}>{t('Sort By')}</ToolbarLabel>
        </Tooltip>
      </ToolbarHeader>
      <div>{toolbarRow}</div>
    </ToolbarSection>
  );
}

const FullWidthTooltip = styled(Tooltip)`
  width: 100%;
`;

const ColumnCompactSelect = styled(CompactSelect)`
  flex: 1 1;
  min-width: 0;

  > button {
    width: 100%;
  }
`;

const DirectionCompactSelect = styled(CompactSelect)`
  width: 90px;

  > button {
    width: 100%;
  }
`;
