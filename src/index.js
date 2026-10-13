import { readFile } from 'node:fs/promises';
import { scanDir, scanUrl, newResult, merge, scanHtml, scanCss, scanJs, sha256, toSource } from './scan.js';
import { buildPolicy, serialize, parsePolicy, effective, allows, collapseOrigins, DEFAULTS } from './policy.js';
import { render, FORMATS } from './formats.js';
import { checkPolicy, shouldFail } from './check.js';
import { loadConfig } from './config.js';
import { toSarif } from './sarif.js';
import { pretty, summary } from './format.js';
import { injectMeta, writeHeadersFile } from './write.js';

export { scanDir, scanUrl, newResult, merge, scanHtml, scanCss, scanJs, sha256, toSource,
  buildPolicy, serialize, parsePolicy, effective, allows, collapseOrigins, DEFAULTS,
  render, FORMATS, checkPolicy, shouldFail, loadConfig, toSarif, pretty, summary, injectMeta, writeHeadersFile };

/** Scan a directory and/or URL and return { scan, directives, policy }. */
export async function generate({ dir, url, config = {}, timeout } = {}) {
  if (!dir && !url) throw new Error('generate() needs a dir and/or url');
  const scan = newResult();
  const selfOrigin = url ? new URL(url).origin : config.origin;
  if (dir) await scanDir(dir, { ignore: config.ignore, selfOrigin, result: scan });
  if (url) await scanUrl(url, { ignore: config.ignore, timeout, result: scan });
  const directives = buildPolicy(scan, config);
  return { scan, directives, policy: serialize(directives) };
}

/** Resolve a --check argument: literal policy, file (HTML meta, _headers, config text) or URL (response header). */
export async function resolveExisting(arg, { timeout } = {}) {
  if (/^https?:\/\//i.test(arg)) {
    const r = await fetch(arg, { redirect: 'follow', signal: AbortSignal.timeout(timeout || 15000), headers: { 'user-agent': 'csp-forge' } });
    const h = r.headers.get('content-security-policy');
    if (h) return { policy: h, source: `${arg} (header)` };
    const html = await r.text();
    const m = metaFrom(html);
    return { policy: m || '', source: `${arg}${m ? ' (meta)' : ''}`, meta: Boolean(m) };
  }
  if (/[;']|-src\b/.test(arg) && !/\.(html?|json|conf|txt|toml)$|_headers$|\.htaccess$/.test(arg)) return { policy: arg, source: 'policy string' };
  const text = await readFile(arg, 'utf8');
  const meta = metaFrom(text);
  if (meta) return { policy: meta, source: `${arg} (meta)`, meta: true };
  const m = /Content-Security-Policy["']?\s*[:,]?\s*(?:"value"\s*:\s*)?["']?\s*((?:default|script|style|img|connect|font|object|base|frame|form|media|worker|child|manifest|upgrade)[^"'\n]*)/i.exec(text);
  return { policy: (m ? m[1] : text).trim(), source: arg };
}
function metaFrom(html) {
  for (const m of html.matchAll(/<meta\b[^>]*>/gi)) {
    if (/http-equiv\s*=\s*["']?content-security-policy["'\s>]/i.test(m[0])) {
      const c = /content\s*=\s*(?:"([^"]*)"|'([^']*)')/i.exec(m[0]);
      if (c) return (c[1] ?? c[2]).replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&amp;/g, '&');
    }
  }
  return null;
}
