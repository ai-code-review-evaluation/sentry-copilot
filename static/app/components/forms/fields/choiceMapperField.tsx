import {Component, Fragment} from 'react';
import styled from '@emotion/styled';

import {Button} from 'sentry/components/core/button';
import {
  CompactSelect,
  type SelectOption,
  type SingleSelectProps,
} from 'sentry/components/core/compactSelect';
import {Flex} from 'sentry/components/core/layout';
import type {ControlProps} from 'sentry/components/core/select';
import {Select} from 'sentry/components/core/select';
import FormField from 'sentry/components/forms/formField';
import {IconAdd, IconDelete} from 'sentry/icons';
import {t} from 'sentry/locale';
import {space} from 'sentry/styles/space';
import {defined} from 'sentry/utils';
import {isEmptyObject} from 'sentry/utils/object/isEmptyObject';

// XXX(epurkhiser): This is wrong, it should not be inheriting these props
import type {InputFieldProps} from './inputField';

interface DefaultProps {
  /**
   * Text used for the 'add row' button.
   */
  addButtonText: NonNullable<React.ReactNode>;
  /**
   * Automatically save even if fields are empty
   */
  allowEmpty: boolean;
  /**
   * If using mappedSelectors to specifically map different choice selectors
   * per item specify this as true.
   */
  perItemMapping: boolean;
}

const defaultProps: DefaultProps = {
  addButtonText: t('Add Item'),
  perItemMapping: false,
  allowEmpty: false,
};

type MappedSelectors = Record<string, Partial<ControlProps>>;

export interface ChoiceMapperProps extends DefaultProps {
  /**
   * Props forwarded to the add mapping dropdown.
   */
  addDropdown: Omit<SingleSelectProps<string>, 'options'> & {
    items: Array<SelectOption<string>>;
    noResultsMessage?: string;
  };
  /**
   * A list of column labels (headers) for the multichoice table. This should
   * have the same mapping keys as the mappedSelectors prop.
   */
  columnLabels: Record<string, React.ReactNode>;
  /**
   * Since we're saving an object, there isn't a great way to render the
   * change within the toast. Just turn off displaying the from/to portion of
   * the message.
   */
  formatMessageValue: boolean;
  /**
   * mappedSelectors controls how the Select control should render for each
   * column. This can be generalised so that each column renders the same set
   * of choices for each mapped item by providing an object with column
   * label keys mapping to the select descriptor, OR you may specify the set
   * of select descriptors *specific* to a mapped item, where the item value
   * maps to the object of column label keys to select descriptor.
   *
   * Example - All selects are the same per column:
   *
   * {
   *   'column_key1: {...select1},
   *   'column_key2: {...select2},
   * }
   *
   * Example - Selects differ for each of the items available:
   *
   * {
   *   'my_object_value':  {'column_key1': {...select1}, 'column_key2': {...select2}},
   *   'other_object_val': {'column_key1': {...select3}, 'column_key2': {...select4}},
   * }
   */
  mappedSelectors: MappedSelectors;
  onChange: InputFieldProps['onChange'];
  // TODO(ts) tighten this up.
  value: Record<string, any>;

  /**
   * Field controls get a boolean.
   */
  disabled?: boolean;

  /**
   * The label to show above the row name selected from the dropdown.
   */
  mappedColumnLabel?: React.ReactNode;

  // TODO(ts) This isn't aligned with InputField but that's what the runtime code had.
  onBlur?: () => void;
}

export interface ChoiceMapperFieldProps
  extends ChoiceMapperProps,
    Omit<
      InputFieldProps,
      'onBlur' | 'onChange' | 'value' | 'formatMessageValue' | 'disabled'
    > {}

export default class ChoiceMapperField extends Component<ChoiceMapperFieldProps> {
  static defaultProps = defaultProps;

  hasValue = (value: InputFieldProps['value']) => defined(value) && !isEmptyObject(value);

  renderField = (props: ChoiceMapperFieldProps) => {
    const {
      onChange,
      onBlur,
      addButtonText,
      addDropdown,
      mappedColumnLabel,
      columnLabels,
      mappedSelectors,
      perItemMapping,
      disabled,
      allowEmpty,
    } = props;

    const mappedKeys = Object.keys(columnLabels);
    const emptyValue = mappedKeys.reduce((a, v) => ({...a, [v]: null}), {});

    const valueIsEmpty = this.hasValue(props.value);
    const value = valueIsEmpty ? props.value : {};

    const saveChanges = (nextValue: ChoiceMapperFieldProps['value']) => {
      onChange?.(nextValue, {});

      const validValues = !Object.values(nextValue)
        .map(o => Object.values(o).find(v => v === null))
        .includes(null);

      if (allowEmpty || validValues) {
        onBlur?.();
      }
    };

    const addRow = (data: SelectOption<string>) => {
      saveChanges({...value, [data.value]: emptyValue});
    };

    const removeRow = (itemKey: string) => {
      saveChanges(
        Object.fromEntries(Object.entries(value).filter(([key, _]) => key !== itemKey))
      );
    };

    const setValue = (
      itemKey: string,
      fieldKey: string,
      fieldValue: string | number | null
    ) => {
      saveChanges({...value, [itemKey]: {...value[itemKey], [fieldKey]: fieldValue}});
    };

    // Remove already added values from the items list
    const selectableValues =
      addDropdown.items?.filter(i => !value.hasOwnProperty(i.value)) ?? [];

    const valueMap =
      addDropdown.items?.reduce<Record<string, React.ReactNode>>((map, item) => {
        map[item.value] = item.label;
        return map;
      }, {}) ?? {};

    const dropdown = (
      <CompactSelect
        {...addDropdown}
        emptyMessage={
          selectableValues.length === 0
            ? addDropdown.emptyMessage
            : addDropdown.noResultsMessage
        }
        size="xs"
        searchable
        disabled={false}
        options={selectableValues}
        menuWidth={250}
        onChange={addRow}
        triggerLabel={
          <Flex gap="xs">
            <IconAdd isCircled /> {addButtonText}
          </Flex>
        }
      />
    );

    // The field will be set to inline when there is no value set for the
    // field, just show the dropdown.
    if (!valueIsEmpty) {
      return <div>{dropdown}</div>;
    }

    return (
      <Fragment>
        <Header>
          <LabelColumn>
            <HeadingItem>{mappedColumnLabel}</HeadingItem>
          </LabelColumn>
          {mappedKeys.map((fieldKey, i) => (
            <Heading key={fieldKey}>
              <HeadingItem>{columnLabels[fieldKey]}</HeadingItem>
              {i === mappedKeys.length - 1 && dropdown}
            </Heading>
          ))}
        </Header>
        {Object.keys(value).map(itemKey => (
          <Row key={itemKey}>
            <LabelColumn>{valueMap[itemKey]}</LabelColumn>
            {mappedKeys.map((fieldKey, i) => (
              <Column key={fieldKey}>
                <Control>
                  <Select
                    {...(perItemMapping
                      ? mappedSelectors[itemKey]![fieldKey]
                      : mappedSelectors[fieldKey])}
                    height={30}
                    disabled={disabled}
                    onChange={(v: any) => setValue(itemKey, fieldKey, v ? v.value : null)}
                    value={value[itemKey][fieldKey]}
                  />
                </Control>
                {i === mappedKeys.length - 1 && (
                  <Actions>
                    <Button
                      icon={<IconDelete />}
                      size="sm"
                      disabled={disabled}
                      onClick={() => removeRow(itemKey)}
                      aria-label={t('Delete')}
                    />
                  </Actions>
                )}
              </Column>
            ))}
          </Row>
        ))}
      </Fragment>
    );
  };

  render() {
    return (
      <FormField
        {...this.props}
        inline={({model}: any) => !this.hasValue(model.getValue(this.props.name))}
      >
        {this.renderField}
      </FormField>
    );
  }
}

const Header = styled('div')`
  display: flex;
  align-items: center;
`;

const Heading = styled('div')`
  display: flex;
  margin-left: ${space(1)};
  flex: 1 0 0;
  align-items: center;
  justify-content: space-between;
`;

const Row = styled('div')`
  display: flex;
  margin-top: ${space(1)};
  align-items: center;
`;

const Column = styled('div')`
  display: flex;
  margin-left: ${space(1)};
  align-items: center;
  flex: 1 0 0;
`;

const Control = styled('div')`
  flex: 1;
`;

const LabelColumn = styled('div')`
  flex: 0 0 200px;
`;

const HeadingItem = styled('div')`
  font-size: 0.8em;
  text-transform: uppercase;
  color: ${p => p.theme.subText};
`;

const Actions = styled('div')`
  margin-left: ${space(1)};
`;
