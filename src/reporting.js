/**
 * @typedef {{ name: string; url: string; maxAge?: number }} ReportingEndpoint
 * @typedef {{ endpoints?: ReportingEndpoint[]; reportUri?: string; reportTo?: string | ReportingEndpoint }} ReportingConfig
 */

/**
 * Normalize reporting settings from config / CLI into endpoint list + CSP directive names.
 * @param {ReportingConfig & { reportTo?: string | ReportingEndpoint }} input
 * @returns {{ endpoints: ReportingEndpoint[]; reportToName?: string; reportUri?: string }}
 */
export function normalizeReporting(input = {}) {
  /** @type {ReportingEndpoint[]} */
  const endpoints = [...(input.endpoints || [])];
  let reportToName;
  let reportUri = input.reportUri;

  const rt = input.reportTo;
  if (rt && typeof rt === 'object' && rt.name && rt.url) {
    endpoints.push({ name: rt.name, url: rt.url, maxAge: rt.maxAge });
    reportToName = rt.name;
  } else if (typeof rt === 'string') {
    reportToName = rt;
    const match = endpoints.find((e) => e.name === rt);
    if (!match && input.reportingEndpointUrl) {
      endpoints.push({ name: rt, url: input.reportingEndpointUrl });
    }
  }

  return { endpoints, reportToName: reportToName || (typeof rt === 'string' ? rt : rt?.name), reportUri };
}

/**
 * Serialize the Reporting-Endpoints response header value.
 * @param {ReportingEndpoint[]} endpoints
 * @returns {string}
 */
export function formatReportingEndpoints(endpoints) {
  return endpoints
    .filter((e) => e.name && e.url)
    .map((e) => `${e.name}="${String(e.url).replace(/"/g, '%22')}"`)
    .join(', ');
}

/**
 * Build Reporting-Endpoints header from config.
 * @param {ReportingConfig} config
 * @returns {string}
 */
export function reportingEndpointsHeader(config) {
  const { endpoints } = normalizeReporting(config);
  return formatReportingEndpoints(endpoints);
}

/**
 * Optional Reporting-Endpoints JSON body for NEL-style endpoint registration (documentation helper).
 * @param {ReportingEndpoint[]} endpoints
 * @returns {string}
 */
export function reportingEndpointsJson(endpoints) {
  return JSON.stringify({ endpoints }, null, 2);
}

/**
 * Apply report-uri / report-to directives on a directive map.
 * @param {Record<string, string[]>} dirs
 * @param {ReportingConfig} config
 * @returns {Record<string, string[]>}
 */
export function applyReportingDirectives(dirs, config) {
  const { reportToName, reportUri } = normalizeReporting(config);
  const out = { ...dirs };
  if (reportUri) out['report-uri'] = [reportUri];
  if (reportToName) out['report-to'] = [reportToName];
  return out;
}
