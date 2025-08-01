import normalizeUrl from 'sentry/utils/url/normalizeUrl';

export const makeMonitorBasePathname = (orgSlug: string) => {
  return normalizeUrl(`/organizations/${orgSlug}/issues/monitors/`);
};

export const makeMonitorDetailsPathname = (orgSlug: string, monitorId: string) => {
  return normalizeUrl(`${makeMonitorBasePathname(orgSlug)}${monitorId}/`);
};

export const makeMonitorCreatePathname = (orgSlug: string) => {
  return normalizeUrl(`${makeMonitorBasePathname(orgSlug)}new/`);
};
