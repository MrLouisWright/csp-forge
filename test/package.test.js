import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const require = createRequire(import.meta.url);
const root = fileURLToPath(new URL('..', import.meta.url));

test('dist supports ESM import and CommonJS require', async () => {
  const esm = await import('../dist/index.js');
  assert.equal(typeof esm.generate, 'function');
  assert.equal(typeof esm.generateNonce, 'function');
  const cjs = require('../dist/index.cjs');
  assert.equal(typeof cjs.buildPolicy, 'function');
  assert.equal(typeof cjs.createNonceMiddleware, 'function');
});

test('dist cli runs', () => {
  const cli = fileURLToPath(new URL('../dist/cli.js', import.meta.url));
  const r = spawnSync(process.execPath, [cli, '--version'], { encoding: 'utf8', cwd: root });
  assert.equal(r.status, 0);
  assert.equal(r.stdout.trim(), JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')).version);
});

test('subpath vite and webpack plugins load', async () => {
  const vite = await import('../dist/vite.js');
  const webpack = await import('../dist/webpack.js');
  assert.equal(typeof vite.cspForge, 'function');
  assert.equal(typeof vite.default, 'function');
  assert.equal(typeof webpack.CspForgeWebpackPlugin, 'function');
  const VitePlugin = require('../dist/vite.cjs');
  assert.equal(typeof VitePlugin.cspForge, 'function');
});
