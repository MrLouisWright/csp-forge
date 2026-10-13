import { readFile, readdir, stat } from 'node:fs/promises';
import { join, relative, extname, sep } from 'node:path';
import { createHash } from 'node:crypto';

export const sha256 = (s) => `'sha256-${createHash('sha256').update(s, 'utf8').digest('base64')}'`;

const EXEC_SCRIPT_TYPES = new Set(['', 'text/javascript', 'application/javascript', 'module', 'text/ecmascript', 'application/ecmascript', 'text/jscript']);
const EVENT_ATTR = /^on[a-z]+$/;
// Well-known URLs that appear in bundles but are never fetched.
const NON_NETWORK = [/^https?:\/\/(www\.)?w3\.org\//, /^https?:\/\/(www\.)?(reactjs|react)\.(org|dev)\/(docs\/)?(error|errors)/,
  /^https?:\/\/(fb\.me|github\.com|npms?\.im|bit\.ly|vuejs\.org|svelte\.dev|developer\.mozilla\.org|tc39\.es|schema\.org|ogp\.me|purl\.org|xmlns\.com)/,
  /^https?:\/\/(localhost|127\.0\.0\.1|0\.0\.0\.0|example\.(com|org|net))([:/]|$)/, /^https?:\/\/[^/]*\.example\.(com|org)/];

export function globToRegExp(g) {
  let re = '';
  for (let i = 0; i < g.length; i++) {
    const ch = g[i];
    if (ch === '*') { if (g[i + 1] === '*') { re += '.*'; i++; if (g[i + 1] === '/') i++; } else re += '[^/]*'; }
    else if (ch === '?') re += '[^/]';
    else re += ch.replace(/[.+^${}()|[\]\\]/g, '\\$&');
  }
  return new RegExp(`^${re}$`);
}
export function makeIgnore(patterns = []) {
  const res = patterns.map((p) => (/[*?]/.test(p) ? globToRegExp(p) : null));
  return (s) => patterns.some((p, i) => (res[i] ? res[i].test(s) : s.includes(p)));
}

const ENT = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", '#39': "'", '#x27': "'", '#47': '/', '#x2F': '/' };
const decode = (s) => s.replace(/&(#x?[0-9a-f]+|[a-z]+);/gi, (m, e) => {
  if (ENT[e] !== undefined) return ENT[e];
  if (e[0] === '#') { const n = e[1].toLowerCase() === 'x' ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10); return Number.isFinite(n) ? String.fromCodePoint(n) : m; }
  return m;
});

export function parseAttrs(s) {
  const attrs = {};
  const re = /([^\s=>\/"']+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>"'`]+)))?/g;
  let m;
  while ((m = re.exec(s))) {
    const k = m[1].toLowerCase();
    if (!(k in attrs)) attrs[k] = m[2] ?? m[3] ?? m[4] ?? '';
  }
  // Raw values (needed for hashing attributes exactly as the browser sees them after decoding)
  for (const k in attrs) attrs[k] = decode(attrs[k]);
  return attrs;
}

/** Classify a URL reference into a CSP source expression, or null for same-document refs. */
export function toSource(raw, ctx = {}) {
  let u = String(raw || '').trim();
  if (!u || u.startsWith('#') || /^(about:|javascript:|mailto:|tel:|sms:)/i.test(u)) return null;
  if (/^data:/i.test(u)) return 'data:';
  if (/^blob:/i.test(u)) return 'blob:';
  if (u.startsWith('//')) u = (ctx.scheme || 'https:') + u;
  const m = /^([a-z][a-z0-9+.-]*):\/\/([^/?#]+)/i.exec(u);
  if (!m) return /^[a-z][a-z0-9+.-]*:/i.test(u) ? null : "'self'"; // relative path
  const origin = `${m[1].toLowerCase()}://${m[2].toLowerCase().replace(/^[^@]*@/, '')}`
    .replace(/:443$/, (x) => (m[1].toLowerCase() === 'https' || m[1].toLowerCase() === 'wss' ? '' : x))
    .replace(/:80$/, (x) => (m[1].toLowerCase() === 'http' || m[1].toLowerCase() === 'ws' ? '' : x));
  if (ctx.selfOrigin && origin === ctx.selfOrigin) return "'self'";
  return origin;
}

export function newResult() {
  return { files: [], sources: {}, hashes: { script: new Set(), style: new Set(), scriptAttr: new Set(), styleAttr: new Set() },
    inline: { scripts: 0, styles: 0, styleAttrs: 0, handlers: 0 }, review: [], warnings: [], existing: [] };
}
const add = (res, dir, src, where, review = false) => {
  if (!src) return;
  (res.sources[dir] ||= new Map());
  const e = res.sources[dir].get(src) || { where: new Set(), review: true };
  e.where.add(where);
  if (!review) e.review = false;
  res.sources[dir].set(src, e);
};
const warn = (res, id, message, file, fix) => res.warnings.push({ id, severity: 'warn', message, file, fix });

export function scanCss(css, res, file, ctx) {
  const ign = ctx.ignore || (() => false);
  const body = css.replace(/\/\*[\s\S]*?\*\//g, '');
  const ffRanges = [];
  for (const m of body.matchAll(/@font-face\s*\{[^}]*\}/gi)) ffRanges.push([m.index, m.index + m[0].length]);
  for (const m of body.matchAll(/@import\s+(?:url\(\s*)?["']?([^"')\s;]+)["']?\s*\)?/gi)) {
    if (!ign(m[1])) add(res, 'style-src', toSource(m[1], ctx), file);
  }
  for (const m of body.matchAll(/url\(\s*(["']?)([^"')]*?)\1\s*\)/gi)) {
    const u = m[2];
    if (ign(u) || /^#/.test(u)) continue;
    const pre = body.slice(Math.max(0, m.index - 20), m.index);
    if (/@import\s*$/i.test(pre)) continue;
    const inFont = ffRanges.some(([a, b]) => m.index > a && m.index < b);
    add(res, inFont ? 'font-src' : 'img-src', toSource(u, ctx), file);
  }
}

export function scanJs(js, res, file, ctx) {
  const ign = ctx.ignore || (() => false);
  const seen = new Set();
  const api = [
    [/\bfetch\s*\(\s*(["'`])([^"'`]+)\1/g, 'connect-src'],
    [/\.open\s*\(\s*["'][A-Za-z]+["']\s*,\s*(["'`])([^"'`]+)\1/g, 'connect-src'],
    [/\bnew\s+WebSocket\s*\(\s*(["'`])([^"'`]+)\1/g, 'connect-src'],
    [/\bnew\s+EventSource\s*\(\s*(["'`])([^"'`]+)\1/g, 'connect-src'],
    [/\bnavigator\.sendBeacon\s*\(\s*(["'`])([^"'`]+)\1/g, 'connect-src'],
    [/\bnew\s+(?:Shared)?Worker\s*\(\s*(["'`])([^"'`]+)\1/g, 'worker-src'],
    [/\bimportScripts\s*\(\s*(["'`])([^"'`]+)\1/g, 'script-src'],
  ];
  for (const [re, dir] of api) for (const m of js.matchAll(re)) {
    const u = m[2].replace(/\$\{[^}]*\}.*$/, '');
    if (!u || ign(u)) continue;
    const s = toSource(u, ctx);
    if (!s) continue;
    seen.add(u);
    add(res, dir, s, file, s !== "'self'");
    if (s !== "'self'") res.review.push({ directive: dir, source: s, url: u, file, how: 'api-call' });
  }
  for (const m of js.matchAll(/(["'`])((?:https?|wss?):\/\/[a-z0-9.-]+(?::\d+)?[^"'`\s]*)\1/gi)) {
    const u = m[2];
    if (seen.has(u) || ign(u) || NON_NETWORK.some((r) => r.test(u))) continue;
    if (/^[a-z]+:\/\/[^/]*[${]/i.test(u)) continue;
    if (/\b(href|action|xmlns(:\w+)?)\s*[=:]\s*\\?$/i.test(js.slice(Math.max(0, m.index - 12), m.index))) continue; // links in templates are navigation, not fetches
    const s = toSource(u, ctx);
    if (!s || s === "'self'") continue;
    seen.add(u);
    add(res, 'connect-src', s, file, true);
    res.review.push({ directive: 'connect-src', source: s, url: u, file, how: 'url-literal' });
  }
  if (/(^|[^.\w$])eval\s*\(/.test(js) || /\bnew\s+Function\s*\(/.test(js) || /\b(setTimeout|setInterval)\s*\(\s*["'`]/.test(js)) {
    res.usesEval = true;
    warn(res, 'eval', "Code uses eval()/new Function()/string timers; this is blocked unless script-src has 'unsafe-eval'.", file,
      "Refactor to avoid string evaluation (often a library option such as a CSP-safe build), or allow it explicitly with config \"allowEval\": true.");
  }
}

export function scanHtml(html, res, file, ctx) {
  const ign = ctx.ignore || (() => false);
  const src = (dir, u) => { if (u && !ign(u)) add(res, dir, toSource(u, ctx), file); };
  const noComments = html.replace(/<!--[\s\S]*?-->/g, '');
  // script/style blocks first (their content is raw text)
  const blocks = /<(script|style)\b((?:"[^"]*"|'[^']*'|[^'">])*)>([\s\S]*?)<\/\1\s*>/gi;
  let rest = '';
  let last = 0;
  for (const m of noComments.matchAll(blocks)) {
    rest += noComments.slice(last, m.index) + `<${m[1]}${m[2]}>`;
    last = m.index + m[0].length;
    const tag = m[1].toLowerCase();
    const a = parseAttrs(m[2]);
    const body = m[3];
    if (tag === 'script') {
      const type = (a.type || '').trim().toLowerCase();
      if (a.src !== undefined) continue; // handled with other tags below
      if (!EXEC_SCRIPT_TYPES.has(type)) continue; // data blocks (JSON, templates) are not executed
      if (!body.length) continue;
      res.inline.scripts++;
      res.hashes.script.add(sha256(body));
      scanJs(body, res, file + ' (inline)', ctx);
    } else {
      if (a.media === 'not all') { /* still loaded */ }
      res.inline.styles++;
      res.hashes.style.add(sha256(body));
      scanCss(body, res, file + ' (inline)', ctx);
    }
  }
  rest += noComments.slice(last);

  const tagRe = /<(\/?[a-zA-Z][\w-]*)((?:"[^"]*"|'[^']*'|[^'">])*)>/g;
  let base = null;
  for (const m of rest.matchAll(tagRe)) {
    const tag = m[1].toLowerCase();
    const a = parseAttrs(m[2].replace(/\/$/, ''));
    for (const k of Object.keys(a)) {
      if (EVENT_ATTR.test(k) && a[k].trim()) {
        res.inline.handlers++;
        res.hashes.scriptAttr.add(sha256(a[k]));
        warn(res, 'inline-handler', `Inline event handler <${tag} ${k}="..."> needs 'unsafe-hashes' in script-src (or refactor to addEventListener).`, file,
          `Move the handler into a script file: el.addEventListener('${k.slice(2)}', ...). csp-forge emits 'unsafe-hashes' plus the exact hash meanwhile.`);
      }
    }
    if (a.style !== undefined && a.style.trim()) {
      res.inline.styleAttrs++;
      res.hashes.styleAttr.add(sha256(a.style));
      scanCss(a.style, res, file + ' (style attr)', ctx);
    }
    for (const k of ['href', 'src', 'action', 'formaction']) if (a[k] && /^\s*javascript:/i.test(a[k]))
      warn(res, 'javascript-url', `javascript: URL in <${tag} ${k}> is blocked by CSP without 'unsafe-inline'.`, file, 'Replace with a button + addEventListener.');
    switch (tag) {
      case 'base': if (a.href) { base = a.href; src('base-uri', a.href); } break;
      case 'script': if (a.src !== undefined) src('script-src', a.src); break;
      case 'link': {
        const rel = (a.rel || '').toLowerCase().split(/\s+/);
        if (!a.href) break;
        if (rel.includes('stylesheet')) src('style-src', a.href);
        else if (rel.includes('preload') || rel.includes('modulepreload') || rel.includes('prefetch')) {
          const as = (a.as || (rel.includes('modulepreload') ? 'script' : '')).toLowerCase();
          const dir = { script: 'script-src', style: 'style-src', font: 'font-src', image: 'img-src', fetch: 'connect-src', audio: 'media-src', video: 'media-src', track: 'media-src', worker: 'worker-src', document: 'frame-src' }[as];
          if (dir) src(dir, a.href);
        } else if (rel.some((r) => r === 'icon' || r === 'apple-touch-icon' || r === 'mask-icon')) src('img-src', a.href);
        else if (rel.includes('manifest')) src('manifest-src', a.href);
        break;
      }
      case 'source':
        if (ctx.lastMedia || /^(video|audio)\//i.test(a.type || '')) src('media-src', a.src);
        else src('img-src', a.src);
        for (const part of (a.srcset || '').split(/,(?=\s*\S)/)) src('img-src', part.trim().split(/\s+/)[0]);
        break;
      case 'img': case 'input':
        if (tag === 'input' && (a.type || '').toLowerCase() !== 'image') break;
        src('img-src', a.src);
        for (const part of (a.srcset || '').split(/,(?=\s*\S)/)) src('img-src', part.trim().split(/\s+/)[0]);
        break;
      case 'track': src('media-src', a.src); break;
      case 'object': case 'embed':
        src('object-src', a.data || a.src);
        warn(res, 'object', `<${tag}> found; object-src 'none' will block it.`, file, 'Replace plugins with <video>/<iframe>/<img>, or add the origin to object-src in config.');
        break;
      case 'video': case 'audio': ctx.lastMedia = true; src('media-src', a.src); if (a.poster) src('img-src', a.poster); break;
      case 'iframe': case 'frame': src('frame-src', a.src); break;
      case 'form': src('form-action', a.action || './'); break;
      case 'button': if (a.formaction) src('form-action', a.formaction); break;
      case 'svg': case 'image': case 'use': if (a.href || a['xlink:href']) { const h = a.href || a['xlink:href']; if (!h.startsWith('#')) src('img-src', h.split('#')[0]); } break;
      case 'meta': {
        const he = (a['http-equiv'] || '').toLowerCase();
        if (he === 'content-security-policy' || he === 'content-security-policy-report-only') res.existing.push({ file, policy: a.content || '', reportOnly: he.endsWith('report-only') });
        if (he === 'refresh') { const u = /url\s*=\s*['"]?([^'"]+)/i.exec(a.content || ''); if (u) { /* navigation, not CSP */ } }
        break;
      }
    }
    if (tag === '/video' || tag === '/audio') ctx.lastMedia = false;
  }
  void base;
}

async function walk(dir, root, out, ign) {
  for (const ent of await readdir(dir, { withFileTypes: true })) {
    const p = join(dir, ent.name);
    const rel = relative(root, p).split(sep).join('/');
    if (ent.name === 'node_modules' || ent.name === '.git' || ign(rel)) continue;
    if (ent.isDirectory()) await walk(p, root, out, ign);
    else if (ent.isFile()) out.push(p);
  }
  return out;
}

/** Scan a built static site directory. */
export async function scanDir(dir, opts = {}) {
  const res = opts.result || newResult();
  const ign = makeIgnore(opts.ignore);
  const ctx = { ignore: ign, selfOrigin: opts.selfOrigin };
  const st = await stat(dir);
  if (!st.isDirectory()) throw new Error(`not a directory: ${dir}`);
  const files = (await walk(dir, dir, [], ign)).sort();
  for (const f of files) {
    const ext = extname(f).toLowerCase();
    const rel = relative(dir, f).split(sep).join('/');
    if (['.html', '.htm'].includes(ext)) { scanHtml(await readFile(f, 'utf8'), res, rel, { ...ctx }); res.files.push(rel); }
    else if (ext === '.css') { scanCss(await readFile(f, 'utf8'), res, rel, ctx); res.files.push(rel); }
    else if (['.js', '.mjs', '.cjs'].includes(ext)) { scanJs(await readFile(f, 'utf8'), res, rel, ctx); res.files.push(rel); }
  }
  return res;
}

/** Scan a live page (and its same-origin CSS/JS). */
export async function scanUrl(url, opts = {}) {
  const res = opts.result || newResult();
  const ign = makeIgnore(opts.ignore);
  const u = new URL(url);
  const ctx = { ignore: ign, selfOrigin: u.origin, scheme: u.protocol };
  const get = async (h) => {
    const r = await fetch(h, { redirect: 'follow', signal: AbortSignal.timeout(opts.timeout || 15000), headers: { 'user-agent': 'csp-forge' } });
    return r;
  };
  const r = await get(u.href);
  const html = await r.text();
  const headerCsp = r.headers.get('content-security-policy');
  if (headerCsp) res.existing.push({ file: u.href, policy: headerCsp, header: true });
  const temp = newResult();
  scanHtml(html, temp, u.href, ctx);
  merge(res, temp);
  res.files.push(u.href);
  // follow same-origin stylesheets & scripts
  const refs = [...html.matchAll(/<(?:script[^>]*\ssrc|link[^>]*\shref)\s*=\s*["']?([^"'\s>]+)/gi)].map((m) => m[1]);
  const max = opts.maxAssets ?? 30;
  let n = 0;
  for (const ref of refs) {
    let abs; try { abs = new URL(decode(ref), u); } catch { continue; }
    if (abs.origin !== u.origin || !/\.(m?js|css)(\?|$)/i.test(abs.pathname + abs.search) || n++ >= max) continue;
    try {
      const body = await (await get(abs.href)).text();
      if (/\.css/i.test(abs.pathname)) scanCss(body, res, abs.href, ctx); else scanJs(body, res, abs.href, ctx);
      res.files.push(abs.href);
    } catch (e) { warn(res, 'fetch', `Could not fetch ${abs.href}: ${e.message}`, abs.href); }
  }
  return res;
}

export function merge(into, from) {
  for (const [d, m] of Object.entries(from.sources)) for (const [s, e] of m) {
    for (const w of e.where) add(into, d, s, w, e.review);
  }
  for (const k of Object.keys(into.hashes)) for (const h of from.hashes[k]) into.hashes[k].add(h);
  for (const k of Object.keys(into.inline)) into.inline[k] += from.inline[k];
  into.review.push(...from.review); into.warnings.push(...from.warnings); into.existing.push(...from.existing);
  into.usesEval ||= from.usesEval;
  return into;
}
