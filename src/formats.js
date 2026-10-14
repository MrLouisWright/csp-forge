import { serialize, META_UNSUPPORTED } from './policy.js';
import { reportingEndpointsHeader } from './reporting.js';

export const FORMATS = ['header', 'meta', 'nginx', 'apache', 'netlify', 'vercel', 'express', 'helmet', 'json', 'reporting-endpoints'];
const camel = (k) => k.replace(/-([a-z])/g, (_, c) => c.toUpperCase());
const esc = (s) => s.replace(/&/g, '&amp;').replace(/"/g, '&quot;');

/**
 * @param {import('./reporting.js').ReportingConfig} [reporting]
 * @returns {string}
 */
function reportingHeaderLine(reporting) {
  const v = reportingEndpointsHeader(reporting || {});
  return v ? `Reporting-Endpoints: ${v}` : '';
}

/** Render a directive map in the requested format. */
export function render(dirs, format = 'header', { reportOnly = false, scan, reporting } = {}) {
  const name = reportOnly ? 'Content-Security-Policy-Report-Only' : 'Content-Security-Policy';
  const value = serialize(dirs);
  const rep = reportingHeaderLine(reporting);
  switch (format) {
    case 'header': return rep ? `${name}: ${value}\n${rep}` : `${name}: ${value}`;
    case 'raw': return value;
    case 'meta':
      if (reportOnly) throw new Error('report-only policies cannot be delivered in a <meta> tag; use a header format');
      return `<meta http-equiv="Content-Security-Policy" content="${esc(serialize(dirs, { meta: true }))}">`;
    case 'nginx': {
      const csp = `add_header ${name} "${value.replace(/"/g, '\\"')}" always;`;
      if (!rep) return csp;
      const repNginx = `add_header Reporting-Endpoints "${rep.replace(/^Reporting-Endpoints: /, '').replace(/"/g, '\\"')}" always;`;
      return `${csp}\n${repNginx}`;
    }
    case 'apache': {
      const csp = `Header always set ${name} "${value.replace(/"/g, '\\"')}"`;
      if (!rep) return csp;
      return `${csp}\nHeader always set Reporting-Endpoints "${rep.replace(/^Reporting-Endpoints: /, '').replace(/"/g, '\\"')}"`;
    }
    case 'netlify': {
      const lines = [`  ${name}: ${value}`];
      if (rep) lines.push(`  Reporting-Endpoints: ${rep.replace(/^Reporting-Endpoints: /, '')}`);
      return `/*\n${lines.join('\n')}`;
    }
    case 'vercel': {
      /** @type {{ key: string; value: string }[]} */
      const headers = [{ key: name, value }];
      const repVal = rep ? rep.replace(/^Reporting-Endpoints: /, '') : '';
      if (repVal) headers.push({ key: 'Reporting-Endpoints', value: repVal });
      return JSON.stringify({ headers: [{ source: '/(.*)', headers }] }, null, 2);
    }
    case 'reporting-endpoints':
      if (!rep) throw new Error('reporting-endpoints format requires reportTo / reportingEndpoints in config');
      return rep;
    case 'express': case 'helmet': {
      const body = '{\n' + Object.entries(dirs).map(([k, v]) => `      ${camel(k)}: ${JSON.stringify(v)},`).join('\n') + '\n    }';
      return `import helmet from 'helmet';\n\napp.use(\n  helmet.contentSecurityPolicy({\n    useDefaults: false,${reportOnly ? '\n    reportOnly: true,' : ''}\n    directives: ${body},\n  })\n);`;
    }
    case 'json': {
      const out = { header: name, policy: value, metaPolicy: serialize(dirs, { meta: true }), directives: dirs };
      if (scan) {
        out.files = scan.files;
        out.inline = scan.inline;
        out.review = scan.review;
        out.warnings = scan.warnings;
        out.sources = Object.fromEntries(Object.entries(scan.sources).map(([d, m]) => [d, Object.fromEntries([...m].map(([s, e]) => [s, { where: [...e.where], review: e.review }]))]));
      }
      return JSON.stringify(out, null, 2);
    }
    default: throw new Error(`unknown format "${format}" (use ${FORMATS.join(', ')})`);
  }
}
export { META_UNSUPPORTED };
