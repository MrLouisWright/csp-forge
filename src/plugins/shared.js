import { resolve } from 'node:path';
import { generate, render } from '../index.js';
import { injectMeta, writeHeadersFile } from '../write.js';
import { reportingEndpointsHeader } from '../reporting.js';

/**
 * @typedef {import('../config.js').Config & {
 *   dir?: string;
 *   format?: string;
 *   reportOnly?: boolean;
 *   write?: boolean;
 *   quiet?: boolean;
 * }} PluginOptions
 */

/**
 * Run csp-forge after a bundler build.
 * @param {PluginOptions} options
 * @param {string} defaultDir
 */
export async function runForgeBuild(options, defaultDir) {
  const dir = resolve(options.dir || defaultDir);
  const { dir: _dir, format: fmt, reportOnly: ro, write: w, quiet: q, config: nested, ...rest } = options;
  const config = { ...(nested || rest) };
  const { scan, directives } = await generate({ dir, config });
  const format = fmt || 'header';
  const reportOnly = Boolean(ro);
  const headerName = reportOnly ? 'Content-Security-Policy-Report-Only' : 'Content-Security-Policy';
  const reporting = { reportUri: config.reportUri, reportTo: config.reportTo, reportingEndpoints: config.reportingEndpoints, reportingEndpointUrl: config.reportingEndpointUrl };
  const policyValue = render(directives, 'raw');
  const out = render(directives, format, { reportOnly, scan, reporting });
  const repHeader = reportingEndpointsHeader(reporting);
  if (w) {
    if (format === 'meta') {
      const metaTag = render(directives, 'meta');
      await injectMeta(dir, scan.files, metaTag);
    } else if (format === 'netlify') {
      await writeHeadersFile(dir, headerName, policyValue);
      if (repHeader) await writeHeadersFile(dir, 'Reporting-Endpoints', repHeader);
    }
  }
  if (!q) {
    process.stderr.write(`csp-forge: wrote policy for ${scan.files.length} file(s) from ${dir}\n`);
    if (repHeader) process.stderr.write(`csp-forge: Reporting-Endpoints: ${repHeader}\n`);
  }
  return { scan, directives, policy: policyValue, output: out, reportingEndpoints: repHeader };
}
