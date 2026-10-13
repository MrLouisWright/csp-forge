import { serialize, META_UNSUPPORTED } from './policy.js';

export const FORMATS = ['header', 'meta', 'nginx', 'apache', 'netlify', 'vercel', 'express', 'helmet', 'json'];
const camel = (k) => k.replace(/-([a-z])/g, (_, c) => c.toUpperCase());
const esc = (s) => s.replace(/&/g, '&amp;').replace(/"/g, '&quot;');

/** Render a directive map in the requested format. */
export function render(dirs, format = 'header', { reportOnly = false, scan } = {}) {
  const name = reportOnly ? 'Content-Security-Policy-Report-Only' : 'Content-Security-Policy';
  const value = serialize(dirs);
  switch (format) {
    case 'header': return `${name}: ${value}`;
    case 'raw': return value;
    case 'meta':
      if (reportOnly) throw new Error('report-only policies cannot be delivered in a <meta> tag; use a header format');
      return `<meta http-equiv="Content-Security-Policy" content="${esc(serialize(dirs, { meta: true }))}">`;
    case 'nginx': return `add_header ${name} "${value.replace(/"/g, '\\"')}" always;`;
    case 'apache': return `Header always set ${name} "${value.replace(/"/g, '\\"')}"`;
    case 'netlify': return `/*\n  ${name}: ${value}`;
    case 'vercel': return JSON.stringify({ headers: [{ source: '/(.*)', headers: [{ key: name, value }] }] }, null, 2);
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
