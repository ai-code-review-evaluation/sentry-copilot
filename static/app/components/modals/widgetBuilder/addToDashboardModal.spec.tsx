import {LocationFixture} from 'sentry-fixture/locationFixture';

import {initializeOrg} from 'sentry-test/initializeOrg';
import {render, screen, userEvent, waitFor} from 'sentry-test/reactTestingLibrary';
import selectEvent from 'sentry-test/selectEvent';

import type {ModalRenderProps} from 'sentry/actionCreators/modal';
import AddToDashboardModal from 'sentry/components/modals/widgetBuilder/addToDashboardModal';
import type {DashboardDetails, DashboardListItem} from 'sentry/views/dashboards/types';
import {
  DashboardWidgetSource,
  DisplayType,
  WidgetType,
} from 'sentry/views/dashboards/types';
import {convertWidgetToBuilderStateParams} from 'sentry/views/dashboards/widgetBuilder/utils/convertWidgetToBuilderStateParams';

const stubEl = (props: {children?: React.ReactNode}) => <div>{props.children}</div>;

jest.mock('sentry/components/lazyRender', () => ({
  LazyRender: ({children}: {children: React.ReactNode}) => children,
}));

describe('add to dashboard modal', () => {
  let eventsStatsMock!: jest.Mock;
  let initialData!: ReturnType<typeof initializeOrg>;

  const testDashboardListItem: DashboardListItem = {
    id: '1',
    title: 'Test Dashboard',
    createdBy: undefined,
    dateCreated: '2020-01-01T00:00:00.000Z',
    widgetDisplay: [DisplayType.AREA],
    widgetPreview: [],
    projects: [],
    environment: [],
    filters: {},
  };
  const testDashboard: DashboardDetails = {
    id: '1',
    title: 'Test Dashboard',
    createdBy: undefined,
    dateCreated: '2020-01-01T00:00:00.000Z',
    widgets: [],
    environment: [],
    projects: [1],
    period: '1h',
    filters: {release: ['abc@v1.2.0']},
  };
  let widget = {
    title: 'Test title',
    description: 'Test description',
    displayType: DisplayType.LINE,
    interval: '5m',
    queries: [
      {
        conditions: '',
        fields: ['count()'],
        aggregates: ['count()'],
        fieldAliases: [],
        columns: [] as string[],
        orderby: '',
        name: '',
      },
    ],
  };
  const defaultSelection = {
    projects: [],
    environments: [],
    datetime: {
      start: null,
      end: null,
      period: '24h',
      utc: false,
    },
  };

  beforeEach(() => {
    initialData = initializeOrg();

    MockApiClient.addMockResponse({
      url: '/organizations/org-slug/dashboards/',
      body: [{...testDashboardListItem, widgetDisplay: [DisplayType.AREA]}],
    });

    MockApiClient.addMockResponse({
      url: '/organizations/org-slug/dashboards/1/',
      body: testDashboard,
    });

    MockApiClient.addMockResponse({
      url: '/organizations/org-slug/releases/stats/',
      body: [],
    });

    eventsStatsMock = MockApiClient.addMockResponse({
      url: '/organizations/org-slug/events-stats/',
      body: [],
    });
  });

  afterEach(() => {
    MockApiClient.clearMockResponses();
    jest.clearAllMocks();
  });

  it('renders with the widget title and description', async function () {
    render(
      <AddToDashboardModal
        Header={stubEl}
        Footer={stubEl as ModalRenderProps['Footer']}
        Body={stubEl as ModalRenderProps['Body']}
        CloseButton={stubEl}
        closeModal={() => undefined}
        organization={initialData.organization}
        widget={widget}
        selection={defaultSelection}
        router={initialData.router}
        location={LocationFixture()}
      />
    );

    await waitFor(() => {
      expect(screen.getByText('Select Dashboard')).toBeEnabled();
    });

    expect(screen.getByText('Test title')).toBeInTheDocument();
    expect(screen.getByText('Select Dashboard')).toBeInTheDocument();
    expect(
      screen.getByText(
        /This is a preview of how the widget will appear in your dashboard./
      )
    ).toBeInTheDocument();
    expect(screen.getByRole('button', {name: 'Add + Stay on this Page'})).toBeDisabled();
    expect(screen.getByRole('button', {name: 'Open in Widget Builder'})).toBeDisabled();
  });

  it('enables the buttons when a dashboard is selected', async function () {
    render(
      <AddToDashboardModal
        Header={stubEl}
        Footer={stubEl as ModalRenderProps['Footer']}
        Body={stubEl as ModalRenderProps['Body']}
        CloseButton={stubEl}
        closeModal={() => undefined}
        organization={initialData.organization}
        widget={widget}
        selection={defaultSelection}
        router={initialData.router}
        location={LocationFixture()}
      />
    );

    await waitFor(() => {
      expect(screen.getByText('Select Dashboard')).toBeEnabled();
    });

    expect(screen.getByRole('button', {name: 'Add + Stay on this Page'})).toBeDisabled();
    expect(screen.getByRole('button', {name: 'Open in Widget Builder'})).toBeDisabled();

    await selectEvent.select(screen.getByText('Select Dashboard'), 'Test Dashboard');

    expect(screen.getByRole('button', {name: 'Add + Stay on this Page'})).toBeEnabled();
    expect(screen.getByRole('button', {name: 'Open in Widget Builder'})).toBeEnabled();
  });

  it('includes a New Dashboard option in the selector with saved dashboards', async function () {
    render(
      <AddToDashboardModal
        Header={stubEl}
        Footer={stubEl as ModalRenderProps['Footer']}
        Body={stubEl as ModalRenderProps['Body']}
        CloseButton={stubEl}
        closeModal={() => undefined}
        organization={initialData.organization}
        widget={widget}
        selection={defaultSelection}
        router={initialData.router}
        location={LocationFixture()}
      />
    );

    await waitFor(() => {
      expect(screen.getByText('Select Dashboard')).toBeEnabled();
    });

    await selectEvent.openMenu(screen.getByText('Select Dashboard'));
    expect(screen.getByText('+ Create New Dashboard')).toBeInTheDocument();
    expect(screen.getByText('Test Dashboard')).toBeInTheDocument();
  });

  it('applies dashboard saved filters to visualization', async function () {
    render(
      <AddToDashboardModal
        Header={stubEl}
        Footer={stubEl as ModalRenderProps['Footer']}
        Body={stubEl as ModalRenderProps['Body']}
        CloseButton={stubEl}
        closeModal={() => undefined}
        organization={initialData.organization}
        widget={widget}
        selection={defaultSelection}
        router={initialData.router}
        location={LocationFixture()}
      />
    );

    await waitFor(() => {
      expect(screen.getByText('Select Dashboard')).toBeEnabled();
    });

    expect(eventsStatsMock).toHaveBeenCalledWith(
      '/organizations/org-slug/events-stats/',
      expect.objectContaining({
        query: expect.objectContaining({
          environment: [],
          project: [],
          interval: '5m',
          orderby: '',
          statsPeriod: '24h',
          yAxis: ['count()'],
        }),
      })
    );

    await selectEvent.select(screen.getByText('Select Dashboard'), 'Test Dashboard');

    expect(eventsStatsMock).toHaveBeenLastCalledWith(
      '/organizations/org-slug/events-stats/',
      expect.objectContaining({
        query: expect.objectContaining({
          environment: [],
          interval: '1m',
          orderby: '',
          partial: '1',
          project: [1],
          query: ' release:"abc@v1.2.0" ',
          statsPeriod: '1h',
          yAxis: ['count()'],
        }),
      })
    );
  });

  it('calls the events stats endpoint with the query and selection values', async function () {
    render(
      <AddToDashboardModal
        Header={stubEl}
        Footer={stubEl as ModalRenderProps['Footer']}
        Body={stubEl as ModalRenderProps['Body']}
        CloseButton={stubEl}
        closeModal={() => undefined}
        organization={initialData.organization}
        widget={widget}
        selection={defaultSelection}
        router={initialData.router}
        location={LocationFixture()}
      />
    );

    await waitFor(() => {
      expect(screen.getByText('Select Dashboard')).toBeEnabled();
    });

    expect(eventsStatsMock).toHaveBeenCalledWith(
      '/organizations/org-slug/events-stats/',
      expect.objectContaining({
        query: expect.objectContaining({
          environment: [],
          project: [],
          interval: '5m',
          orderby: '',
          statsPeriod: '24h',
          yAxis: ['count()'],
        }),
      })
    );
  });

  it('navigates to the widget builder when clicking Open in Widget Builder', async () => {
    render(
      <AddToDashboardModal
        Header={stubEl}
        Footer={stubEl as ModalRenderProps['Footer']}
        Body={stubEl as ModalRenderProps['Body']}
        CloseButton={stubEl}
        closeModal={() => undefined}
        organization={initialData.organization}
        widget={widget}
        selection={defaultSelection}
        router={initialData.router}
        source={DashboardWidgetSource.DISCOVERV2}
        location={LocationFixture()}
      />
    );

    await waitFor(() => {
      expect(screen.getByText('Select Dashboard')).toBeEnabled();
    });
    await selectEvent.select(screen.getByText('Select Dashboard'), 'Test Dashboard');

    await userEvent.click(screen.getByText('Open in Widget Builder'));
    expect(initialData.router.push).toHaveBeenCalledWith({
      pathname: '/organizations/org-slug/dashboard/1/widget-builder/widget/new/',
      query: {
        ...convertWidgetToBuilderStateParams(widget),
        environment: [],
        end: undefined,
        start: undefined,
        utc: undefined,
        project: [1],
        source: DashboardWidgetSource.DISCOVERV2,
        statsPeriod: '1h',
        title: 'Test title',
      },
    });
  });

  it('navigates to the widget builder with saved filters', async () => {
    render(
      <AddToDashboardModal
        Header={stubEl}
        Footer={stubEl as ModalRenderProps['Footer']}
        Body={stubEl as ModalRenderProps['Body']}
        CloseButton={stubEl}
        closeModal={() => undefined}
        organization={initialData.organization}
        widget={widget}
        selection={defaultSelection}
        router={initialData.router}
        source={DashboardWidgetSource.DISCOVERV2}
        location={LocationFixture()}
      />
    );

    await waitFor(() => {
      expect(screen.getByText('Select Dashboard')).toBeEnabled();
    });
    await selectEvent.select(screen.getByText('Select Dashboard'), 'Test Dashboard');

    await userEvent.click(screen.getByText('Open in Widget Builder'));
    expect(initialData.router.push).toHaveBeenCalledWith({
      pathname: '/organizations/org-slug/dashboard/1/widget-builder/widget/new/',
      query: expect.objectContaining({
        title: 'Test title',
        description: 'Test description',
        field: [],
        query: [''],
        yAxis: ['count()'],
        sort: [''],
        displayType: DisplayType.LINE,
        dataset: WidgetType.ERRORS,
        project: [1],
        statsPeriod: '1h',
        source: DashboardWidgetSource.DISCOVERV2,
      }),
    });
  });

  it('updates the selected dashboard with the widget when clicking Add + Stay in Discover', async () => {
    const dashboardDetailGetMock = MockApiClient.addMockResponse({
      url: '/organizations/org-slug/dashboards/1/',
      body: {id: '1', widgets: []},
    });
    const dashboardDetailPutMock = MockApiClient.addMockResponse({
      url: '/organizations/org-slug/dashboards/1/',
      method: 'PUT',
      body: {},
    });
    render(
      <AddToDashboardModal
        Header={stubEl}
        Footer={stubEl as ModalRenderProps['Footer']}
        Body={stubEl as ModalRenderProps['Body']}
        CloseButton={stubEl}
        closeModal={() => undefined}
        organization={initialData.organization}
        widget={{...widget, widgetType: WidgetType.ERRORS}}
        selection={defaultSelection}
        router={initialData.router}
        location={LocationFixture()}
      />
    );

    await waitFor(() => {
      expect(screen.getByText('Select Dashboard')).toBeEnabled();
    });
    await selectEvent.select(screen.getByText('Select Dashboard'), 'Test Dashboard');

    await userEvent.click(screen.getByText('Add + Stay on this Page'));
    expect(dashboardDetailGetMock).toHaveBeenCalled();

    // mocked widgets response is an empty array, assert this new widget
    // is sent as an update to the dashboard
    await waitFor(() => {
      expect(dashboardDetailPutMock).toHaveBeenCalledWith(
        '/organizations/org-slug/dashboards/1/',
        expect.objectContaining({
          data: expect.objectContaining({
            widgets: [{...widget, widgetType: WidgetType.ERRORS}],
          }),
        })
      );
    });
  });

  it('clears sort when clicking Add + Stay in Discover with line chart', async () => {
    const dashboardDetailGetMock = MockApiClient.addMockResponse({
      url: '/organizations/org-slug/dashboards/1/',
      body: {id: '1', widgets: []},
    });
    const dashboardDetailPutMock = MockApiClient.addMockResponse({
      url: '/organizations/org-slug/dashboards/1/',
      method: 'PUT',
      body: {},
    });
    widget = {
      ...widget,
      queries: [
        {
          conditions: '',
          fields: ['count()'],
          aggregates: ['count()'],
          fieldAliases: [],
          columns: [],
          orderby: '-project',
          name: '',
        },
      ],
    };
    render(
      <AddToDashboardModal
        Header={stubEl}
        Footer={stubEl as ModalRenderProps['Footer']}
        Body={stubEl as ModalRenderProps['Body']}
        CloseButton={stubEl}
        closeModal={() => undefined}
        organization={initialData.organization}
        widget={widget}
        selection={defaultSelection}
        router={initialData.router}
        location={LocationFixture()}
      />
    );

    await waitFor(() => {
      expect(screen.getByText('Select Dashboard')).toBeEnabled();
    });
    await selectEvent.select(screen.getByText('Select Dashboard'), 'Test Dashboard');

    await userEvent.click(screen.getByText('Add + Stay on this Page'));
    expect(dashboardDetailGetMock).toHaveBeenCalled();

    // mocked widgets response is an empty array, assert this new widget
    // is sent as an update to the dashboard
    await waitFor(() => {
      expect(dashboardDetailPutMock).toHaveBeenCalledWith(
        '/organizations/org-slug/dashboards/1/',
        expect.objectContaining({
          data: expect.objectContaining({
            widgets: [
              {
                description: 'Test description',
                displayType: 'line',
                interval: '5m',
                queries: [
                  {
                    aggregates: ['count()'],
                    columns: [],
                    conditions: '',
                    fieldAliases: [],
                    fields: ['count()'],
                    name: '',
                    orderby: '',
                  },
                ],
                title: 'Test title',
              },
            ],
          }),
        })
      );
    });
  });

  it('saves sort when clicking Add + Stay in Discover with top period chart', async () => {
    const dashboardDetailGetMock = MockApiClient.addMockResponse({
      url: '/organizations/org-slug/dashboards/1/',
      body: {id: '1', widgets: []},
    });
    const dashboardDetailPutMock = MockApiClient.addMockResponse({
      url: '/organizations/org-slug/dashboards/1/',
      method: 'PUT',
      body: {},
    });
    widget = {
      ...widget,
      displayType: DisplayType.TOP_N,
      queries: [
        {
          conditions: '',
          fields: ['count()'],
          aggregates: ['count()'],
          fieldAliases: [],
          columns: ['project'],
          orderby: '-project',
          name: '',
        },
      ],
    };
    render(
      <AddToDashboardModal
        Header={stubEl}
        Footer={stubEl as ModalRenderProps['Footer']}
        Body={stubEl as ModalRenderProps['Body']}
        CloseButton={stubEl}
        closeModal={() => undefined}
        organization={initialData.organization}
        widget={widget}
        selection={defaultSelection}
        router={initialData.router}
        location={LocationFixture()}
      />
    );

    await waitFor(() => {
      expect(screen.getByText('Select Dashboard')).toBeEnabled();
    });
    await selectEvent.select(screen.getByText('Select Dashboard'), 'Test Dashboard');

    await userEvent.click(screen.getByText('Add + Stay on this Page'));
    expect(dashboardDetailGetMock).toHaveBeenCalled();

    // mocked widgets response is an empty array, assert this new widget
    // is sent as an update to the dashboard
    await waitFor(() => {
      expect(dashboardDetailPutMock).toHaveBeenCalledWith(
        '/organizations/org-slug/dashboards/1/',
        expect.objectContaining({
          data: expect.objectContaining({
            widgets: [
              {
                description: 'Test description',
                displayType: 'top_n',
                interval: '5m',
                limit: 5,
                queries: [
                  {
                    aggregates: ['count()'],
                    columns: ['project'],
                    conditions: '',
                    fieldAliases: [],
                    fields: ['count()'],
                    name: '',
                    orderby: '-project',
                  },
                ],
                title: 'Test title',
              },
            ],
          }),
        })
      );
    });
  });

  it('disables Add + Stay in Discover when a new dashboard is selected', async () => {
    render(
      <AddToDashboardModal
        Header={stubEl}
        Footer={stubEl as ModalRenderProps['Footer']}
        Body={stubEl as ModalRenderProps['Body']}
        CloseButton={stubEl}
        closeModal={() => undefined}
        organization={initialData.organization}
        widget={widget}
        selection={defaultSelection}
        router={initialData.router}
        location={LocationFixture()}
      />
    );

    await waitFor(() => {
      expect(screen.getByText('Select Dashboard')).toBeEnabled();
    });
    await selectEvent.select(
      screen.getByText('Select Dashboard'),
      '+ Create New Dashboard'
    );

    expect(screen.getByRole('button', {name: 'Add + Stay on this Page'})).toBeDisabled();
    expect(screen.getByRole('button', {name: 'Open in Widget Builder'})).toBeEnabled();
  });
});
