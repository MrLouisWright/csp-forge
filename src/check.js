import { parsePolicy, effective, allows, FETCH_DIRECTIVES } from './policy.js';

const f = (id, severity, title, message, fix) => ({ id, severity, title, message, fix });
const hints = (ex) => `Example: Content-Security-Policy: ${ex}\n` +
  `  Nginx:   add_header Content-Security-Policy "..." always;\n` +
  `  Express: app.use(helmet.contentSecurityPolicy({ directives: {...} }))\n` +
  `  Vercel/Netlify: vercel.json "headers" / _headers file  (or run: npx csp-forge <dir> --format vercel|netlify)`;

/**
 * Compare an existing policy against what the site needs.
 * @param {string} existing policy string
 * @param {Record<string,string[]>} needed directive map from buildPolicy()
 * @param {object} scan scan result (for hashes / attr hashes / where info)
 */
export function checkPolicy(existing, needed, scan, opts = {}) {
  const out = [];
  const have = parsePolicy(existing);
  const selfOrigin = opts.selfOrigin;
  if (!existing || !Object.keys(have).length) return [f('csp-missing', 'error', 'No Content-Security-Policy to check', 'The policy given to --check is empty.', hints(serializeShort(needed)))];

  const attrHashes = new Set([...(scan?.hashes.scriptAttr || []), ...(scan?.hashes.styleAttr || [])]);
  // 1. Missing sources
  for (const [d, vals] of Object.entries(needed)) {
    if (!FETCH_DIRECTIVES.includes(d) && d !== 'form-action' && d !== 'base-uri') continue;
    if (d === 'base-uri' && !scan?.sources['base-uri']) continue; // no <base> element: any base-uri works
    const eff = effective(have, d);
    const missing = [];
    for (const s of vals) {
      if (s === "'none'" || s === "'unsafe-hashes'" || s === "'self'" && (!eff.list || eff.list.includes("'self'") || eff.list.includes('*'))) continue;
      if (s === "'self'") { missing.push(s); continue; }
      if (s.startsWith("'nonce-")) { if (!eff.list || eff.list.some((x) => x.startsWith("'nonce-") || x === "'unsafe-inline'")) continue; missing.push(s); continue; }
      if (s.startsWith("'unsafe-")) continue;
      const isAttr = attrHashes.has(s);
      if (isAttr && eff.list && eff.list.includes(s) && !eff.list.includes("'unsafe-hashes'") && !eff.list.includes("'unsafe-inline'")) {
        out.push(f('csp-unsafe-hashes', 'error', `${d} hashes inline attributes without 'unsafe-hashes'`, `Hashes for event handlers/style attributes only work together with 'unsafe-hashes' (in ${eff.from}).`, hints(`${d} ... 'unsafe-hashes' ${s}`)));
        continue;
      }
      if (!allows(eff.list, s, selfOrigin, { inlineAttr: isAttr })) missing.push(s);
    }
    const isReview = (x) => Boolean(scan?.sources[d]?.get(x)?.review);
    const report = (list, heuristic) => {
      if (!list.length) return;
      const where = list.filter((x) => !x.startsWith("'sha")).map((x) => scan?.sources[d]?.get(x)).filter(Boolean).map((e) => [...e.where][0]);
      const hashes = list.filter((x) => x.startsWith("'sha")).length;
      const named = list.filter((x) => !x.startsWith("'sha"));
      const parts = [named.length ? named.join(' ') : '', hashes ? `${hashes} inline ${d.startsWith('style') ? 'style' : 'script'} hash(es)` : ''].filter(Boolean).join(' + ');
      out.push(f(heuristic ? 'csp-missing-source-review' : 'csp-missing-source', heuristic ? 'warn' : 'error',
        heuristic ? `${d} may block sources detected in JS (please review)` : `${d} blocks sources the site uses`,
        `${eff.from ? `Effective ${eff.from}` : d} does not allow ${parts}${where.length ? ` (used in ${[...new Set(where)].slice(0, 3).join(', ')})` : ''}.`,
        hints(`${d} ${[...new Set([...(eff.from === d && eff.list ? eff.list : ["'self'"]).filter((x) => !["'none'", "'unsafe-inline'", '*', 'https:', 'http:'].includes(x)), ...list])].join(' ')}`)));
    };
    report(missing.filter((x) => !isReview(x)), false);
    report(missing.filter(isReview), true);
  }
  // 2. Overly loose
  const loose = (d, vals) => {
    if (vals.includes("'unsafe-inline'") && !vals.some((x) => /^'(nonce-|sha(256|384|512)-|strict-dynamic)/.test(x)))
      out.push(f('csp-unsafe-inline', d.startsWith('style') ? 'warn' : 'error', `${d} allows 'unsafe-inline'`, `'unsafe-inline' in ${d} defeats XSS protection; csp-forge computed hashes for every inline block.`, `Replace 'unsafe-inline' with the hashes from: npx csp-forge <dir> --format header  (or use --nonce)`));
    if (vals.includes("'unsafe-eval'") && !scan?.usesEval)
      out.push(f('csp-unsafe-eval', 'error', `${d} allows 'unsafe-eval' but no eval() was detected`, `'unsafe-eval' in ${d} allows string-to-code execution and nothing in the build needs it.`, "Remove 'unsafe-eval'."));
    else if (vals.includes("'unsafe-eval'"))
      out.push(f('csp-unsafe-eval', 'warn', `${d} allows 'unsafe-eval'`, 'The build uses eval()/new Function(); consider refactoring.', "Remove 'unsafe-eval' once eval usage is gone."));
    const wild = vals.filter((x) => x === '*' || x === 'http:' || x === 'https:' || (x === 'data:' && /script|default/.test(d)));
    const hostWild = opts.allowWildcards ? [] : vals.filter((x) => /^([a-z]+:\/\/)?\*\./.test(x));
    if (hostWild.length) out.push(f('csp-wildcard-host', 'warn', `${d} uses subdomain wildcard ${hostWild.join(' ')}`, 'Any subdomain (including forgotten or user-content hosts) is trusted.', `Prefer explicit hosts: ${d} ${(needed[d] || needed['default-src'] || ["'self'"]).filter((x) => !x.startsWith("'sha")).join(' ')}`));
    if (wild.length) out.push(f('csp-wildcard', 'error', `${d} uses overly broad source ${wild.join(' ')}`, `${d} allows loading from far more origins than the site uses.`, `List the explicit origins instead: ${d} ${(needed[d] || needed['default-src'] || ["'self'"]).filter((x) => !x.startsWith("'sha")).join(' ')}`));
    if (vals.includes('http:') || vals.some((x) => /^http:\/\//.test(x))) out.push(f('csp-insecure-source', 'warn', `${d} allows plain http:`, 'Insecure sources can be tampered with in transit.', 'Use https:// origins and add upgrade-insecure-requests.'));
  };
  for (const [d, vals] of Object.entries(have)) if (d.endsWith('-src')) loose(d, vals);

  // 3. Unused sources (allowed but not needed)
  for (const [d, vals] of Object.entries(have)) {
    if (!FETCH_DIRECTIVES.includes(d) && d !== 'form-action') continue;
    const need = d === 'default-src' ? null : needed[d] || [];
    if (!need) continue;
    const extra = vals.filter((v) => /^(https?|wss?):\/\/[^*]+$/.test(v) && !need.includes(v) && !(selfOrigin && v === selfOrigin));
    if (extra.length) out.push(f('csp-unused-source', 'warn', `${d} allows sources the site does not use`, `${extra.join(' ')} ${extra.length > 1 ? 'are' : 'is'} not referenced by the scanned build.`, `Remove them, or ignore this warning if they are loaded dynamically: ${d} ${need.filter((x) => !x.startsWith("'sha")).join(' ')}`));
    const staleHashes = vals.filter((v) => /^'sha(256|384|512)-/.test(v) && !need.includes(v));
    if (staleHashes.length) out.push(f('csp-stale-hash', 'warn', `${d} contains ${staleHashes.length} hash(es) that match no inline block`, 'Probably left over from an older build.', 'Regenerate with csp-forge after each build.'));
  }
  // 4. Hardening directives
  if (!have['object-src'] && !(have['default-src'] || []).includes("'none'")) out.push(f('csp-missing-object-src', 'warn', "object-src not set to 'none'", 'Plugins (<object>/<embed>) are allowed via default-src.', "Add \"object-src 'none'\"."));
  if (!have['base-uri']) out.push(f('csp-missing-base-uri', 'warn', 'base-uri missing', 'base-uri is not covered by default-src; <base> injection can redirect relative scripts.', "Add \"base-uri 'self'\"."));
  if (!have['frame-ancestors'] && !opts.meta) out.push(f('csp-missing-frame-ancestors', 'warn', 'frame-ancestors missing', 'Clickjacking protection not covered by default-src.', "Add \"frame-ancestors 'none'\" (header only; ignored in <meta>)."));
  if (!have['default-src']) out.push(f('csp-missing-default-src', 'warn', 'default-src missing', 'Directives you did not list are unrestricted.', "Add \"default-src 'self'\"."));
  return out;
}

function serializeShort(d) { return Object.entries(d).slice(0, 4).map(([k, v]) => `${k} ${v.filter((x) => !x.startsWith("'sha")).join(' ')}`).join('; ') + '; ...'; }

export function shouldFail(findings, failOn = 'error') {
  if (failOn === 'none') return false;
  return findings.some((x) => x.severity === 'error' || (failOn === 'warn' && x.severity === 'warn'));
}
