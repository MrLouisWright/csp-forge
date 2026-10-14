import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { generate, buildPolicy, serialize, parsePolicy, allows, collapseOrigins, render, FORMATS, newResult, checkPolicy, shouldFail, toSarif, pretty, resolveExisting } from '../src/index.js';

const fx = (n) => fileURLToPath(new URL(`./fixtures/${n}`, import.meta.url));

test('generated policy for basic fixture', async () => {
  const { directives: d, policy } = await generate({ dir: fx('basic') });
  assert.deepEqual(d['default-src'], ["'self'"]);
  assert.deepEqual(d['object-src'], ["'none'"]);
  assert.deepEqual(d['frame-ancestors'], ["'none'"]);
  assert.deepEqual(d['upgrade-insecure-requests'], []);
  assert.ok(d['script-src'].includes("'unsafe-hashes'"));
  assert.ok(!policy.includes("'unsafe-inline'"));
  assert.ok(!policy.includes("'unsafe-eval'"));
  assert.ok(!/\s\*|\*\./.test(policy), 'no wildcards');
  assert.ok(policy.startsWith("default-src 'self'; script-src 'self'"));
  assert.ok(policy.endsWith('upgrade-insecure-requests'));
});

test('clean site gets minimal policy with none for media/frame', async () => {
  const { policy } = await generate({ dir: fx('clean') });
  assert.equal(policy, "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'; media-src 'none'; frame-src 'none'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; upgrade-insecure-requests");
});

test('config: extra directives, nonce, frame-ancestors, report-uri, eval, no upgrade', async () => {
  const { directives: d } = await generate({ dir: fx('basic'), config: { nonce: true, frameAncestors: "'self'", reportUri: '/csp', allowEval: true, upgradeInsecureRequests: false, directives: { 'connect-src': ['https://extra.example.org'] } } });
  assert.ok(d['script-src'].includes("'nonce-{{NONCE}}'"));
  assert.ok(d['style-src'].includes("'nonce-{{NONCE}}'"));
  assert.ok(d['script-src'].includes("'unsafe-eval'"));
  assert.ok(d['connect-src'].includes('https://extra.example.org'));
  assert.deepEqual(d['frame-ancestors'], ["'self'"]);
  assert.deepEqual(d['report-uri'], ['/csp']);
  assert.ok(!('upgrade-insecure-requests' in d));
  const { directives: d2 } = await generate({ dir: fx('basic'), config: { nonce: 'abc123' } });
  assert.ok(d2['script-src'].includes("'nonce-abc123'"));
});

test('wildcards are refused unless allowed, collapse when allowed', () => {
  const scan = newResult();
  assert.throws(() => buildPolicy(scan, { directives: { 'img-src': ['*'] } }), /allowWildcards/);
  const list = ['https://a.cdn.com', 'https://b.cdn.com', 'https://c.cdn.com', 'https://x.org'];
  assert.deepEqual(collapseOrigins(list), list);
  assert.deepEqual(collapseOrigins(list, { allowWildcards: true }).sort(), ['https://*.cdn.com', 'https://x.org']);
});

test('http origins upgraded', () => {
  const scan = newResult();
  scan.sources['img-src'] = new Map([['http://old.example.org', { where: new Set(['x']), review: false }]]);
  assert.ok(buildPolicy(scan)['img-src'].includes('https://old.example.org'));
  assert.ok(buildPolicy(scan, { upgradeInsecureRequests: false })['img-src'].includes('http://old.example.org'));
});

test('parse / serialize round trip and allows()', () => {
  const p = "default-src 'self'; img-src https://*.cdn.com data:; upgrade-insecure-requests";
  assert.equal(serialize(parsePolicy(p)), p);
  assert.ok(allows(['https://*.cdn.com'], 'https://a.cdn.com'));
  assert.ok(!allows(['https://*.cdn.com'], 'https://cdn.com'));
  assert.ok(allows(['https:'], 'https://x.com'));
  assert.ok(allows(['cdn.com'], 'https://cdn.com'));
  assert.ok(allows(['http://cdn.com'], 'https://cdn.com'));
  assert.ok(!allows(["'self'"], 'https://x.com'));
  assert.ok(allows(['*'], 'https://x.com'));
  assert.ok(!allows(['*'], 'data:'));
  assert.ok(allows(["'unsafe-inline'"], "'sha256-abc='"));
  assert.ok(!allows(["'unsafe-inline'", "'sha256-zzz='"], "'sha256-abc='"));
  assert.ok(allows(["'nonce-x'"], "'sha256-abc='"));
});

test('every format renders', async () => {
  const reporting = { reportTo: { name: 'csp', url: 'https://example.com/r' } };
  const { directives, scan } = await generate({ dir: fx('basic'), config: { reportUri: '/r', reportTo: reporting.reportTo } });
  const out = Object.fromEntries(FORMATS.map((f) => [f, render(directives, f, { scan, reporting })]));
  assert.match(out.header, /^Content-Security-Policy: default-src 'self';/);
  assert.match(out.meta, /^<meta http-equiv="Content-Security-Policy" content="default-src/);
  assert.ok(!out.meta.includes('frame-ancestors') && !out.meta.includes('report-uri'));
  assert.match(out.nginx, /^add_header Content-Security-Policy ".*" always;\nadd_header Reporting-Endpoints/);
  assert.match(out.apache, /^Header always set Content-Security-Policy "/);
  assert.match(out.netlify, /^\/\*\n {2}Content-Security-Policy: /);
  assert.equal(JSON.parse(out.vercel).headers[0].headers[0].key, 'Content-Security-Policy');
  assert.match(out.express, /helmet\.contentSecurityPolicy/);
  assert.match(out.express, /scriptSrc:/);
  const j = JSON.parse(out.json);
  assert.ok(j.policy && j.directives && j.sources['connect-src'] && j.review.length);
  assert.match(render(directives, 'header', { reportOnly: true }), /^Content-Security-Policy-Report-Only:/);
  assert.throws(() => render(directives, 'meta', { reportOnly: true }));
  assert.throws(() => render(directives, 'bogus'));
});

test('checkPolicy: generated policy passes, loose and incomplete ones fail', async () => {
  const { directives, scan, policy } = await generate({ dir: fx('basic'), config: { allowEval: true } });
  const ok = checkPolicy(policy, directives, scan);
  assert.equal(ok.filter((x) => x.severity === 'error').length, 0, JSON.stringify(ok, null, 1));
  const loose = checkPolicy("default-src * 'unsafe-inline' 'unsafe-eval'", directives, scan);
  const ids = loose.map((x) => x.id);
  assert.ok(ids.includes('csp-wildcard') && ids.includes('csp-unsafe-inline'));
  assert.ok(shouldFail(loose));
  const missing = checkPolicy("default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'", directives, scan);
  const m = missing.filter((x) => x.id === 'csp-missing-source');
  assert.ok(m.some((x) => x.title.startsWith('script-src') && /cdn\.jsdelivr\.net/.test(x.message) && /hash/.test(x.message)));
  assert.ok(m.every((x) => /Nginx:/.test(x.fix) && /Express:/.test(x.fix) && /Vercel\/Netlify:/.test(x.fix)));
  const attr = checkPolicy(policy.replace(/'unsafe-hashes' /g, ''), directives, scan);
  assert.ok(attr.some((x) => x.id === 'csp-unsafe-hashes'));
  const extra = checkPolicy(policy.replace('connect-src', 'connect-src https://unused.example.org') + "; img-src 'sha256-stale='", directives, scan);
  assert.ok(extra.some((x) => x.id === 'csp-unused-source'));
  assert.ok(!shouldFail([{ severity: 'warn' }]) && shouldFail([{ severity: 'warn' }], 'warn') && !shouldFail([{ severity: 'error' }], 'none'));
});

test('sarif + pretty output', async () => {
  const { directives, scan } = await generate({ dir: fx('clean') });
  const findings = checkPolicy("default-src 'self'", directives, scan);
  const results = [{ target: 'x', files: 3, findings }];
  const s = toSarif(results, '1.0.0');
  assert.equal(s.version, '2.1.0');
  assert.equal(s.runs[0].tool.driver.name, 'csp-forge');
  const txt = pretty(results, { color: false });
  assert.match(txt, /⚠ warn {2}base-uri missing \[csp-missing-base-uri\]/);
  assert.match(txt, /fix: /);
  assert.ok(!txt.includes('\x1b['));
  assert.ok(pretty(results, { color: true }).includes('\x1b['));
});

test('resolveExisting reads strings, html meta and _headers', async () => {
  assert.equal((await resolveExisting("default-src 'self'")).policy, "default-src 'self'");
  const m = await resolveExisting(fx('clean/index.html'));
  assert.equal(m.policy, "default-src 'self'");
  assert.ok(m.meta);
});
