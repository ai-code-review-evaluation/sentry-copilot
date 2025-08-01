import type {Location, LocationDescriptorObject} from 'history';

import {ExternalLink} from 'sentry/components/core/link';
import {t, tct} from 'sentry/locale';
import type {Event} from 'sentry/types/event';
import type {Group, GroupTombstoneHelper} from 'sentry/types/group';
import type {Organization} from 'sentry/types/organization';

export const DEFAULT_QUERY = 'is:unresolved issue.priority:[high, medium]';

export enum Query {
  FOR_REVIEW = 'is:unresolved is:for_review assigned_or_suggested:[me, my_teams, none]',
  PRIORITIZED = DEFAULT_QUERY, // eslint-disable-line @typescript-eslint/prefer-literal-enum-member
  UNRESOLVED = 'is:unresolved',
  IGNORED = 'is:ignored',
  NEW = 'is:new',
  ARCHIVED = 'is:archived',
  ESCALATING = 'is:escalating',
  REGRESSED = 'is:regressed',
  REPROCESSING = 'is:reprocessing',
}

export const CUSTOM_TAB_VALUE = '__custom__';

type OverviewTab = {
  /**
   * Emitted analytics event tab name
   */
  analyticsName: string;
  /**
   * Will fetch a count to display on this tab
   */
  count: boolean;
  /**
   * Tabs can be disabled via flag
   */
  enabled: boolean;
  name: string;
  hidden?: boolean;
  /**
   * Tooltip text to be hoverable when text has links
   */
  tooltipHoverable?: boolean;
  /**
   * Tooltip text for each tab
   */
  tooltipTitle?: React.ReactNode;
};

/**
 * Get a list of currently active tabs
 */
export function getTabs() {
  const tabs: Array<[string, OverviewTab]> = [
    [
      Query.PRIORITIZED,
      {
        name: t('Prioritized'),
        analyticsName: 'prioritized',
        count: true,
        enabled: true,
      },
    ],
    [
      Query.FOR_REVIEW,
      {
        name: t('For Review'),
        analyticsName: 'needs_review',
        count: true,
        enabled: true,
        tooltipTitle: t(
          'Issues are marked for review if they are new or escalating, and have not been resolved or archived. Issues are automatically marked reviewed in 7 days.'
        ),
      },
    ],
    [
      Query.REGRESSED,
      {
        name: t('Regressed'),
        analyticsName: 'regressed',
        count: true,
        enabled: true,
      },
    ],
    [
      Query.ESCALATING,
      {
        name: t('Escalating'),
        analyticsName: 'escalating',
        count: true,
        enabled: true,
      },
    ],
    [
      Query.ARCHIVED,
      {
        name: t('Archived'),
        analyticsName: 'archived',
        count: true,
        enabled: true,
      },
    ],
    [
      Query.IGNORED,
      {
        name: t('Ignored'),
        analyticsName: 'ignored',
        count: true,
        enabled: false,
        tooltipTitle: t(`Ignored issues don’t trigger alerts. When their ignore
        conditions are met they become Unresolved and are flagged for review.`),
      },
    ],
    [
      Query.REPROCESSING,
      {
        name: t('Reprocessing'),
        analyticsName: 'reprocessing',
        count: true,
        enabled: true,
        tooltipTitle: tct(
          `These [link:reprocessing issues] will take some time to complete.
        Any new issues that are created during reprocessing will be flagged for review.`,
          {
            link: (
              <ExternalLink href="https://docs.sentry.io/product/error-monitoring/reprocessing/" />
            ),
          }
        ),
        tooltipHoverable: true,
      },
    ],
    [
      // Hidden tab to account for custom queries that don't match any of the queries
      // above. It's necessary because if Tabs's value doesn't match that of any tab item
      // then Tabs will fall back to a default value, causing unexpected behaviors.
      CUSTOM_TAB_VALUE,
      {
        name: t('Custom'),
        analyticsName: 'custom',
        hidden: true,
        count: false,
        enabled: true,
      },
    ],
  ];

  return tabs.filter(([_query, tab]) => tab.enabled);
}

/**
 * @returns queries that should have counts fetched
 */
export function getTabsWithCounts() {
  const tabs = getTabs();
  return tabs.filter(([_query, tab]) => tab.count).map(([query]) => query);
}

export function isForReviewQuery(query: string | undefined) {
  return !!query && /\bis:for_review\b/.test(query);
}

// the tab counts will look like 99+
export const TAB_MAX_COUNT = 99;

type QueryCount = {
  count: number;
  hasMore: boolean;
};

export type QueryCounts = Partial<Record<Query, QueryCount>>;

export enum IssueSortOptions {
  DATE = 'date',
  NEW = 'new',
  TRENDS = 'trends',
  FREQ = 'freq',
  USER = 'user',
  INBOX = 'inbox',
}

export const DEFAULT_ISSUE_STREAM_SORT = IssueSortOptions.DATE;

export function isDefaultIssueStreamSearch({query, sort}: {query: string; sort: string}) {
  return query === DEFAULT_QUERY && sort === DEFAULT_ISSUE_STREAM_SORT;
}

export function getSortLabel(key: string) {
  switch (key) {
    case IssueSortOptions.NEW:
      return t('Age');
    case IssueSortOptions.TRENDS:
      return t('Trends');
    case IssueSortOptions.FREQ:
      return t('Events');
    case IssueSortOptions.USER:
      return t('Users');
    case IssueSortOptions.INBOX:
      return t('Date Added');
    case IssueSortOptions.DATE:
    default:
      return t('Last Seen');
  }
}

export const DISCOVER_EXCLUSION_FIELDS: string[] = [
  'query',
  'status',
  'bookmarked_by',
  'assigned',
  'assigned_to',
  'unassigned',
  'subscribed_by',
  'active_at',
  'first_release',
  'first_seen',
  'is',
  '__text',
  'issue.priority',
  'issue.category',
  'issue.type',
  'issue.seer_actionability',
  'issue.seer_last_run',
];

export const FOR_REVIEW_QUERIES: string[] = [Query.FOR_REVIEW];

export const SAVED_SEARCHES_SIDEBAR_OPEN_LOCALSTORAGE_KEY =
  'issue-stream-saved-searches-sidebar-open';

export function createIssueLink({
  organization,
  data,
  eventId,
  referrer,
  location,
  query,
}: {
  data: Event | Group | GroupTombstoneHelper;
  location: Location;
  organization: Organization;
  eventId?: string;
  query?: string;
  referrer?: string;
}): LocationDescriptorObject {
  const {id, project} = data as Group;
  const {eventID: latestEventId, groupID} = data as Event;

  // If we have passed in a custom event ID, use it; otherwise use default
  const finalEventId = eventId ?? latestEventId;

  return {
    pathname: `/organizations/${organization.slug}/issues/${
      latestEventId ? groupID : id
    }/${finalEventId ? `events/${finalEventId}/` : ''}`,
    query: {
      referrer: referrer || 'event-or-group-header',
      query,
      // Add environment to the query if it was selected
      ...(location.query.environment === undefined
        ? {}
        : {environment: location.query.environment}),
      // This adds sort to the query if one was selected from the
      // issues list page
      ...(location.query.sort === undefined ? {} : {sort: location.query.sort}),
      // This appends _allp to the URL parameters if they have no
      // project selected ("all" projects included in results). This is
      // so that when we enter the issue details page and lock them to
      // a project, we can properly take them back to the issue list
      // page with no project selected (and not the locked project
      // selected)
      ...(location.query.project === undefined ? {_allp: 1} : {}),
      ...(project ? {project: project.id} : {}),
    },
  };
}
