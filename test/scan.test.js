import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { scanDir, newResult, scanHtml, scanCss, scanJs, toSource, sha256, parseAttrs } from '../src/scan.js';

const fx = (n) => fileURLToPath(new URL(`./fixtures/${n}`, import.meta.url));
const has = (r, d, s) => Boolean(r.sources[d]?.has(s));

test('toSource classifies urls', () => {
  assert.equal(toSource('/a.js'), "'self'");
  assert.equal(toSource('a.js'), "'self'");
  assert.equal(toSource('https://CDN.example.com:443/x'), 'https://cdn.example.com');
  assert.equal(toSource('http://x.com:8080/y'), 'http://x.com:8080');
  assert.equal(toSource('//x.com/y'), 'https://x.com');
  assert.equal(toSource('data:image/png;base64,AA'), 'data:');
  assert.equal(toSource('blob:https://x'), 'blob:');
  assert.equal(toSource('#top'), null);
  assert.equal(toSource('javascript:void(0)'), null);
  assert.equal(toSource('https://me.dev/a', { selfOrigin: 'https://me.dev' }), "'self'");
});

test('sha256 matches browser algorithm', () => {
  const body = 'alert(1)';
  assert.equal(sha256(body), `'sha256-${createHash('sha256').update(body).digest('base64')}'`);
  assert.equal(sha256("alert('Hello, world.');"), "'sha256-qznLcsROx4GACP2dm0UCKCzCG+HiZ1guq6ZZDob/Tng='"); // example from the CSP spec
});

test('parseAttrs handles quoting and entities', () => {
  assert.deepEqual(parseAttrs(` href="a?b=1&amp;c=2" rel=stylesheet data-x='y' defer`), { href: 'a?b=1&c=2', rel: 'stylesheet', 'data-x': 'y', defer: '' });
});

test('scanDir finds every source class in the basic fixture', async () => {
  const r = await scanDir(fx('basic'));
  assert.deepEqual(r.files.sort(), ['assets/app.css', 'assets/app.js', 'blog/post.html', 'index.html']);
  assert.ok(has(r, 'script-src', 'https://cdn.jsdelivr.net'));
  assert.ok(has(r, 'style-src', 'https://fonts.googleapis.com'));
  assert.ok(has(r, 'style-src', 'https://cdn.jsdelivr.net'), '@import');
  assert.ok(has(r, 'font-src', 'https://fonts.gstatic.com'), 'preload as=font');
  assert.ok(has(r, 'font-src', 'https://use.typekit.net'), '@font-face');
  assert.ok(has(r, 'font-src', "'self'"));
  for (const s of ['https://images.unsplash.com', 'https://cdn.imgix.net', 'https://cdn2.imgix.net', 'https://img.example-cdn.com', 'https://posters.example-video.com', 'data:'])
    assert.ok(has(r, 'img-src', s), s);
  for (const s of ['https://media.example-video.com', 'https://media2.example-video.com', 'https://audio.example-pod.com']) assert.ok(has(r, 'media-src', s), s);
  assert.ok(!has(r, 'img-src', 'https://media2.example-video.com'));
  assert.ok(has(r, 'frame-src', 'https://www.youtube-nocookie.com'));
  assert.ok(has(r, 'form-action', 'https://formspree.io'));
  assert.ok(has(r, 'manifest-src', "'self'"));
  for (const s of ['https://api.example-backend.com', 'wss://realtime.example-backend.com', 'https://events.example-sse.com', 'https://legacy.example-xhr.com'])
    assert.ok(has(r, 'connect-src', s), s);
  assert.ok(!has(r, 'connect-src', 'http://www.w3.org'), 'namespace urls ignored');
  assert.ok(!has(r, 'connect-src', 'https://reactjs.org'));
  assert.ok(!JSON.stringify([...Object.values(r.sources)].map((m) => [...m.keys()])).includes('commented.example.net'), 'comments ignored');
  assert.equal(r.inline.scripts, 2, 'ld+json is not hashed');
  assert.equal(r.inline.styles, 1);
  assert.equal(r.inline.handlers, 1);
  assert.equal(r.inline.styleAttrs, 1);
  assert.ok(r.hashes.script.has(sha256('window.dataLayer = window.dataLayer || [];')));
  assert.ok(r.hashes.style.has(sha256('body{margin:0}')));
  assert.ok(r.hashes.scriptAttr.has(sha256("track('submit')")));
  assert.ok(r.hashes.styleAttr.has(sha256('color: red')));
  assert.ok(r.usesEval);
  const ids = new Set(r.warnings.map((w) => w.id));
  for (const id of ['eval', 'inline-handler', 'javascript-url']) assert.ok(ids.has(id), id);
  assert.ok(r.review.length >= 4 && r.review.every((x) => x.source !== "'self'"));
});

test('ignore patterns skip files and urls', async () => {
  const r = await scanDir(fx('basic'), { ignore: ['blog/**', 'https://images.unsplash.com/*', 'typekit'] });
  assert.ok(!r.files.includes('blog/post.html'));
  assert.ok(!has(r, 'img-src', 'https://images.unsplash.com'));
  assert.ok(!has(r, 'font-src', 'https://use.typekit.net'));
  assert.ok(!has(r, 'media-src', 'https://audio.example-pod.com'));
});

test('existing meta CSP is recorded', async () => {
  const r = await scanDir(fx('clean'));
  assert.equal(r.existing.length, 1);
  assert.equal(r.existing[0].policy, "default-src 'self'");
});

test('css and js scanners in isolation', () => {
  const r = newResult();
  scanCss('@import "https://a.com/x.css"; @font-face{src:url(//f.com/a.woff)} a{background:url(#svg)}', r, 'x.css', {});
  assert.ok(r.sources['style-src'].has('https://a.com'));
  assert.ok(r.sources['font-src'].has('https://f.com'));
  scanJs('navigator.sendBeacon("https://b.com/c"); new Worker("/w.js"); const u = `https://${host}/x`;', r, 'x.js', {});
  assert.ok(r.sources['connect-src'].has('https://b.com'));
  assert.ok(r.sources['worker-src'].has("'self'"));
  assert.ok(!r.usesEval);
  scanHtml('<script type="text/template"><b>x</b></script><script></script><input type="image" src="https://i.com/x.png">', r, 'x.html', {});
  assert.equal(r.inline.scripts, 0);
  assert.ok(r.sources['img-src'].has('https://i.com'));
});
