import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { cpSync, mkdtempSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const bin = fileURLToPath(new URL('../dist/cli.js', import.meta.url));
const fx = (n) => fileURLToPath(new URL(`./fixtures/${n}`, import.meta.url));
const env = { ...process.env, NO_COLOR: '1' };
delete env.FORCE_COLOR;
const run = (args, opts = {}) => spawnSync(process.execPath, [bin, ...args], { encoding: 'utf8', env, ...opts });

test('--help / --version exit 0', () => {
  assert.equal(run(['--help']).status, 0);
  assert.match(run(['--version']).stdout, /^\d+\.\d+\.\d+/);
});

test('usage errors exit 2', () => {
  assert.equal(run(['--bogus']).status, 2);
  assert.equal(run([fx('clean'), '--format', 'nope']).status, 2);
  assert.equal(run([fx('clean'), '--fail-on', 'maybe', '--check', "default-src 'self'"]).status, 2);
  assert.equal(run([fx('clean'), '--format', 'meta', '--report-only']).status, 2);
  assert.equal(run([fx('clean'), '--format', 'nginx', '--write']).status, 2);
  assert.equal(run([fx('does-not-exist')]).status, 2);
});

test('generate prints policy on stdout, summary on stderr', () => {
  const r = run([fx('basic'), '--format', 'nginx']);
  assert.equal(r.status, 0);
  assert.match(r.stdout, /^add_header Content-Security-Policy "default-src 'self';/);
  assert.match(r.stderr, /scanned 4 file\(s\)/);
  assert.match(r.stderr, /⚠ warn {2}.*\[inline-handler\]/);
  assert.match(r.stderr, /detected heuristically in JS — please review/);
  assert.ok(!r.stderr.includes('\x1b['), 'NO_COLOR respected');
  assert.equal(run([fx('basic'), '-q']).stderr, '');
  assert.match(run([fx('basic'), '--report-only', '--report-uri', '/csp-report']).stdout, /^Content-Security-Policy-Report-Only: .*report-uri \/csp-report/);
  assert.match(run([fx('basic'), '--nonce', '-q']).stdout, /'nonce-\{\{NONCE\}\}'/);
  assert.match(run([fx('basic'), '--strict-dynamic', '-q']).stdout, /'strict-dynamic'/);
  assert.match(run([fx('basic'), '--report-to', 'csp', '--reporting-endpoint-url', 'https://example.com/csp', '-f', 'reporting-endpoints', '-q']).stdout, /^Reporting-Endpoints: csp="https:\/\/example.com\/csp"/);
});

test('--check exit codes, --json, --sarif, --fail-on', () => {
  const good = run([fx('basic'), '-q']).stdout.replace(/^Content-Security-Policy: /, '').trim();
  const pass = run([fx('basic'), '--check', good]);
  assert.equal(pass.status, 0, pass.stdout);
  assert.match(pass.stdout, /0 errors/);
  const fail = run([fx('basic'), '--check', "default-src 'self' 'unsafe-inline'"]);
  assert.equal(fail.status, 1);
  assert.match(fail.stdout, /✖ error .*\[csp-missing-source\]/);
  assert.match(fail.stdout, /fix: Example: Content-Security-Policy:/);
  assert.match(fail.stdout, /Nginx: {3}add_header/);
  assert.equal(run([fx('basic'), '--check', "default-src 'self'", '--fail-on', 'none']).status, 0);
  const warnOnly = run([fx('clean'), '--check', "default-src 'self'"]);
  assert.equal(warnOnly.status, 0);
  assert.equal(run([fx('clean'), '--check', "default-src 'self'", '--fail-on', 'warn']).status, 1);
  const j = JSON.parse(run([fx('clean'), '--check', "default-src 'self'", '--json']).stdout);
  assert.ok(Array.isArray(j[0].findings) && j[0].recommended);
  const s = JSON.parse(run([fx('clean'), '--check', "default-src 'self'", '--sarif']).stdout);
  assert.equal(s.version, '2.1.0');
  const dir = mkdtempSync(join(tmpdir(), 'cspf-'));
  const file = join(dir, 'out.sarif');
  run([fx('clean'), '--check', "default-src 'self'", '--sarif', file]);
  assert.equal(JSON.parse(readFileSync(file, 'utf8')).runs[0].tool.driver.name, 'csp-forge');
  // check against a file (meta tag in html)
  assert.equal(run([fx('clean'), '--check', fx('clean/index.html')]).status, 0);
  rmSync(dir, { recursive: true });
});

test('--write meta injects into HTML and is idempotent; --write netlify writes _headers', () => {
  const dir = mkdtempSync(join(tmpdir(), 'cspf-'));
  cpSync(fx('basic'), dir, { recursive: true });
  assert.equal(run([dir, '--format', 'meta', '--write', '-q']).status, 0);
  run([dir, '--format', 'meta', '--write', '-q']);
  const html = readFileSync(join(dir, 'index.html'), 'utf8');
  assert.equal((html.match(/http-equiv="Content-Security-Policy"/g) || []).length, 1);
  assert.match(html, /<head>\n {4}<meta http-equiv="Content-Security-Policy"/);
  assert.match(readFileSync(join(dir, 'blog/post.html'), 'utf8'), /Content-Security-Policy/);
  writeFileSync(join(dir, '_headers'), '/*\n  X-Frame-Options: DENY\n');
  assert.equal(run([dir, '--format', 'netlify', '--write', '-q']).status, 0);
  run([dir, '--format', 'netlify', '--write', '-q']);
  const h = readFileSync(join(dir, '_headers'), 'utf8');
  assert.equal((h.match(/Content-Security-Policy:/g) || []).length, 1);
  assert.match(h, /X-Frame-Options: DENY/);
  rmSync(dir, { recursive: true });
});

test('config file is picked up from cwd', () => {
  const dir = mkdtempSync(join(tmpdir(), 'cspf-'));
  writeFileSync(join(dir, '.csp-forgerc.json'), JSON.stringify({ directives: { 'img-src': ['https://extra.example.org'] }, frameAncestors: "'self'" }));
  const r = run([fx('clean'), '-q'], { cwd: dir });
  assert.match(r.stdout, /img-src 'self' https:\/\/extra\.example\.org/);
  assert.match(r.stdout, /frame-ancestors 'self'/);
  writeFileSync(join(dir, '.csp-forgerc.json'), JSON.stringify({ directives: { 'img-src': ['*'] } }));
  assert.equal(run([fx('clean'), '-q'], { cwd: dir }).status, 2);
  rmSync(dir, { recursive: true });
});
