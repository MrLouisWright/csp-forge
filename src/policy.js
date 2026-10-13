export const FETCH_DIRECTIVES = ['script-src', 'style-src', 'img-src', 'font-src', 'connect-src', 'media-src', 'frame-src', 'worker-src', 'manifest-src', 'object-src'];
const ORDER = ['default-src', 'script-src', 'style-src', 'img-src', 'font-src', 'connect-src', 'media-src', 'frame-src', 'worker-src', 'manifest-src', 'object-src', 'base-uri', 'form-action', 'frame-ancestors'];
const KEYWORD_ORDER = ["'none'", "'self'", "'strict-dynamic'", "'unsafe-hashes'", "'unsafe-eval'", "'unsafe-inline'", "'wasm-unsafe-eval'"];
export const META_UNSUPPORTED = ['frame-ancestors', 'report-uri', 'report-to', 'sandbox'];

export const DEFAULTS = {
  frameAncestors: "'none'",
  baseUri: "'self'",
  objectSrc: "'none'",
  upgradeInsecureRequests: true,
  allowWildcards: false,
  wildcardThreshold: 3,
  allowEval: false,
  nonce: false,
  reportUri: undefined,
  directives: {},
};

const sortSources = (arr) => [...new Set(arr)].sort((a, b) => {
  const ia = KEYWORD_ORDER.indexOf(a), ib = KEYWORD_ORDER.indexOf(b);
  const ka = a.startsWith("'") ? (ia < 0 ? 50 : ia) : 100, kb = b.startsWith("'") ? (ib < 0 ? 50 : ib) : 100;
  if (ka !== kb) return ka - kb;
  const sa = /^[a-z-]+:$/.test(a), sb = /^[a-z-]+:$/.test(b);
  if (sa !== sb) return sa ? 1 : -1;
  return a.localeCompare(b);
});

/** Collapse hosts into https://*.example.com when allowed and >= threshold siblings. */
export function collapseOrigins(sources, { allowWildcards = false, wildcardThreshold = 3 } = {}) {
  const list = [...new Set(sources)];
  // drop http://x when https://x also present? no - keep both; but upgrade-insecure-requests makes http->https
  if (!allowWildcards) return list;
  const groups = new Map();
  for (const s of list) {
    const m = /^(https|wss):\/\/([a-z0-9-]+)\.([a-z0-9-]+\.[a-z0-9.-]+)$/.exec(s);
    if (!m) continue;
    const key = `${m[1]}://*.${m[3]}`;
    (groups.get(key) || groups.set(key, []).get(key)).push(s);
  }
  let out = list;
  for (const [wild, members] of groups) if (members.length >= wildcardThreshold) out = out.filter((s) => !members.includes(s)).concat(wild);
  return out;
}

/** Build a directive map from a scan result. */
export function buildPolicy(scan, config = {}) {
  const c = { ...DEFAULTS, ...config, directives: { ...(config.directives || {}) } };
  const d = {};
  const srcs = (name) => [...(scan.sources[name]?.keys() || [])];
  const upgrade = (list) => (c.upgradeInsecureRequests ? list.map((s) => s.replace(/^http:\/\//, 'https://').replace(/^ws:\/\//, 'wss://')) : list);
  const fin = (list) => collapseOrigins(upgrade(list), c);
  d['default-src'] = ["'self'"];

  const nonce = c.nonce ? `'nonce-${c.nonce === true ? '{{NONCE}}' : c.nonce}'` : null;
  const script = ["'self'", ...fin(srcs('script-src'))];
  if (scan.hashes.script.size) script.push(...(nonce ? [nonce] : scan.hashes.script));
  if (scan.hashes.scriptAttr.size) script.push("'unsafe-hashes'", ...scan.hashes.scriptAttr);
  if (c.allowEval && scan.usesEval) script.push("'unsafe-eval'");
  d['script-src'] = script;

  const style = ["'self'", ...fin(srcs('style-src'))];
  if (scan.hashes.style.size) style.push(...(nonce ? [nonce] : scan.hashes.style));
  if (scan.hashes.styleAttr.size) style.push("'unsafe-hashes'", ...scan.hashes.styleAttr);
  d['style-src'] = style;

  for (const name of ['img-src', 'font-src', 'connect-src']) d[name] = ["'self'", ...fin(srcs(name))];
  for (const name of ['media-src', 'frame-src', 'worker-src', 'manifest-src']) {
    const s = fin(srcs(name));
    if (s.length) d[name] = s;
    else if (name === 'media-src' || name === 'frame-src') d[name] = ["'none'"];
  }
  // worker-src falls back to script-src; manifest-src to default-src ('self') — omit when only 'self'
  if (d['manifest-src'] && d['manifest-src'].every((s) => s === "'self'")) delete d['manifest-src'];
  d['object-src'] = srcs('object-src').length && c.objectSrc !== "'none'" ? fin(srcs('object-src')) : [c.objectSrc];
  d['base-uri'] = [c.baseUri, ...fin(srcs('base-uri')).filter((s) => s !== "'self'" || c.baseUri !== "'self'")];
  d['form-action'] = ["'self'", ...fin(srcs('form-action'))];
  if (c.frameAncestors && c.frameAncestors !== false) d['frame-ancestors'] = String(c.frameAncestors).split(/\s+/);

  for (const [k, v] of Object.entries(c.directives)) {
    const vals = Array.isArray(v) ? v : String(v).split(/\s+/);
    d[k] = [...(d[k] || []), ...vals];
  }
  for (const k of Object.keys(d)) {
    let v = sortSources(d[k]);
    if (v.includes("'none'") && v.length > 1) v = v.filter((x) => x !== "'none'");
    if (!c.allowWildcards) {
      const bad = v.filter((x) => x === '*' || /\*/.test(x));
      if (bad.length) throw new Error(`wildcard source ${bad.join(' ')} in ${k} requires "allowWildcards": true`);
    }
    d[k] = v;
  }
  if (c.upgradeInsecureRequests) d['upgrade-insecure-requests'] = [];
  if (c.reportUri) d['report-uri'] = [c.reportUri];
  if (c.reportTo) d['report-to'] = [c.reportTo];
  return d;
}

export function serialize(dirs, { meta = false } = {}) {
  const keys = Object.keys(dirs).sort((a, b) => {
    const ia = ORDER.indexOf(a), ib = ORDER.indexOf(b);
    return (ia < 0 ? 99 : ia) - (ib < 0 ? 99 : ib);
  });
  return keys.filter((k) => !(meta && META_UNSUPPORTED.includes(k)))
    .map((k) => (dirs[k].length ? `${k} ${dirs[k].join(' ')}` : k)).join('; ');
}

export function parsePolicy(str) {
  const dirs = {};
  for (const part of String(str || '').split(';')) {
    const [name, ...vals] = part.trim().split(/\s+/);
    if (name && !(name.toLowerCase() in dirs)) dirs[name.toLowerCase()] = vals.filter(Boolean);
  }
  return dirs;
}

/** Effective source list for a fetch directive, applying CSP fallback rules. */
export function effective(dirs, name) {
  const chain = {
    'script-src-elem': ['script-src-elem', 'script-src', 'default-src'],
    'style-src-elem': ['style-src-elem', 'style-src', 'default-src'],
    'worker-src': ['worker-src', 'child-src', 'script-src', 'default-src'],
    'frame-src': ['frame-src', 'child-src', 'default-src'],
  }[name] || (FETCH_DIRECTIVES.includes(name) ? [name, 'default-src'] : [name]);
  for (const c of chain) if (dirs[c]) return { from: c, list: dirs[c] };
  return { from: null, list: null };
}

const hostMatch = (pattern, host) => {
  if (pattern.startsWith('*.')) return host.endsWith(pattern.slice(1)) && host.length > pattern.length - 1;
  return pattern === host;
};
/** Does an existing source list allow `src` (a source expression produced by the scanner)? */
export function allows(list, src, selfOrigin, opts = {}) {
  if (!list) return true; // no restriction
  if (list.includes("'none'") && list.length === 1) return false;
  if (list.includes(src)) return true;
  if (src.startsWith("'sha")) {
    if (list.includes("'unsafe-inline'") && !list.some((x) => /^'(nonce-|sha\d+-|strict-dynamic)/.test(x))) return true;
    return Boolean(opts.inlineAttr ? false : list.some((x) => x.startsWith("'nonce-")));
  }
  if (src.startsWith("'")) return false;
  if (src === "'self'") return false;
  if (/^[a-z-]+:$/.test(src)) return list.includes(src) || (list.includes('*') && !['data:', 'blob:', 'filesystem:'].includes(src));
  const m = /^([a-z]+):\/\/([^/:]+)(?::(\d+))?/.exec(src);
  if (!m) return false;
  const [, scheme, host, port] = m;
  if (selfOrigin && src === selfOrigin && list.includes("'self'")) return true;
  for (const e of list) {
    if (e === '*') return true;
    if (e === `${scheme}:`) return true;
    if (e === 'https:' && scheme === 'http') return false;
    if (scheme === 'http' && e === 'http:') return true;
    if ((scheme === 'wss' && e === 'https:') || (scheme === 'https' && e === 'wss:')) continue;
    const em = /^(?:([a-z]+):\/\/)?(\*\.[^/:]+|[^/:*]+)(?::(\d+|\*))?/.exec(e);
    if (!em || e.startsWith("'")) continue;
    const [, es, eh, ep] = em;
    const schemeOk = !es ? ['http', 'https'].includes(scheme) || scheme.startsWith('ws') : es === scheme || (es === 'http' && scheme === 'https') || (es === 'ws' && scheme === 'wss') || (es === 'https' && scheme === 'wss');
    const portOk = ep === '*' || (ep || '') === (port || '');
    if (schemeOk && portOk && hostMatch(eh, host)) return true;
  }
  return false;
}
