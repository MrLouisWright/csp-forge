import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import {
  generateNonce, nonceSource, applyNonceToPolicyString, injectNoncesIntoHtml,
  strictDynamicScriptSrc, serializeWithNonce, generate,
} from '../src/index.js';

const fx = (n) => fileURLToPath(new URL(`./fixtures/${n}`, import.meta.url));

test('generateNonce and nonce helpers', () => {
  const n = generateNonce();
  assert.match(n, /^[A-Za-z0-9+/=]+$/);
  assert.equal(nonceSource('abc'), "'nonce-abc'");
  assert.equal(applyNonceToPolicyString("script-src 'nonce-{{NONCE}}'", 'xyz'), "script-src 'nonce-xyz'");
  assert.deepEqual(strictDynamicScriptSrc('n', ["'self'", 'https://cdn.example.com']), ["'nonce-n'", "'strict-dynamic'", "'self'", 'https://cdn.example.com']);
});

test('injectNoncesIntoHtml adds nonce to inline script/style only', () => {
  const html = '<script>1</script><script src="/a.js"></script><style>x{}</style>';
  const out = injectNoncesIntoHtml(html, 'SECRET');
  assert.match(out, /<script nonce="SECRET">1<\/script>/);
  assert.match(out, /<script src="\/a.js"><\/script>/);
  assert.match(out, /<style nonce="SECRET">/);
});

test('strict-dynamic policy uses nonce without inline script hashes', async () => {
  const { directives, policy, scan } = await generate({ dir: fx('basic'), config: { strictDynamic: true, nonce: true } });
  assert.ok(directives['script-src'].includes("'strict-dynamic'"));
  assert.ok(directives['script-src'].includes("'nonce-{{NONCE}}'"));
  for (const h of scan.hashes.script) assert.ok(!directives['script-src'].includes(h));
  assert.ok(policy.includes("'strict-dynamic'"));
  const live = serializeWithNonce(directives, 'live-nonce');
  assert.ok(live.includes("'nonce-live-nonce'"));
  assert.ok(!live.includes('{{NONCE}}'));
});
