#!/usr/bin/env node
import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { generate, render, FORMATS, checkPolicy, shouldFail, loadConfig, toSarif, pretty, summary, resolveExisting, injectMeta, writeHeadersFile } from '../src/index.js';

const VERSION = JSON.parse(readFileSync(new URL('../package.json', import.meta.url))).version;
const HELP = `csp-forge ${VERSION} — generate a tight Content-Security-Policy from a built static site

Usage:
  csp-forge [dir] [options]              generate a policy (dir defaults to dist/build/out/public if present)
  csp-forge [dir] --check <policy|file|url>   compare an existing CSP with what the site needs (CI)

Scan:
  -u, --url <url>           Also scan a live page (and its same-origin CSS/JS); its origin counts as 'self'
      --origin <url>        Treat this absolute origin as 'self' when scanning a directory
  -c, --config <file>       JSON config (default: .csp-forgerc.json / .cspbuilderrc.json / package.json "csp-forge")
Generate:
  -f, --format <fmt>        ${FORMATS.join(' | ')}  (default: header)
      --nonce[=value]       Use 'nonce-<value>' (default placeholder {{NONCE}}) instead of inline hashes
      --report-only         Emit Content-Security-Policy-Report-Only
      --report-uri <url>    Add report-uri
      --frame-ancestors <v> Default 'none' (e.g. "'self'"); "off" omits it
      --allow-wildcards     Allow collapsing 3+ subdomains to https://*.domain
      --no-upgrade          Omit upgrade-insecure-requests
      --write               meta: inject <meta> into every HTML file; netlify: write <dir>/_headers
  -q, --quiet               No summary on stderr
Check:
      --check <x>           Policy string, file (HTML meta, _headers, nginx conf, vercel.json) or URL (header/meta)
      --fail-on <level>     error | warn | none   (default: error)
      --json                Print JSON results
      --sarif [file]        Print SARIF 2.1.0 (or write to file) for GitHub code scanning
  -t, --timeout <ms>        Network timeout (default: 15000)
  -h, --help / -v, --version

Exit codes: 0 pass, 1 failed checks (--check), 2 usage error. NO_COLOR disables colours.`;

function die(m) { console.error(`csp-forge: ${m}\n\n${HELP}`); process.exit(2); }

function parse(argv) {
  const o = { positional: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const next = () => { const v = argv[++i]; if (v === undefined) die(`${a} needs a value`); return v; };
    const eq = a.includes('=') && a.startsWith('--') ? a.slice(a.indexOf('=') + 1) : undefined;
    const key = eq !== undefined ? a.slice(0, a.indexOf('=')) : a;
    const val = () => (eq !== undefined ? eq : next());
    switch (key) {
      case '-h': case '--help': console.log(HELP); process.exit(0); break;
      case '-v': case '--version': console.log(VERSION); process.exit(0); break;
      case '-u': case '--url': o.url = val(); break;
      case '--origin': o.origin = val(); break;
      case '-c': case '--config': o.config = val(); break;
      case '-f': case '--format': o.format = val(); break;
      case '--nonce': o.nonce = eq !== undefined ? eq : true; break;
      case '--report-only': o.reportOnly = true; break;
      case '--report-uri': o.reportUri = val(); break;
      case '--frame-ancestors': o.frameAncestors = val(); break;
      case '--allow-wildcards': o.allowWildcards = true; break;
      case '--no-upgrade': o.upgrade = false; break;
      case '--write': o.write = true; break;
      case '-q': case '--quiet': o.quiet = true; break;
      case '--check': o.check = val(); break;
      case '--fail-on': o.failOn = val(); break;
      case '--json': o.json = true; break;
      case '--sarif': o.sarif = true; if (eq !== undefined) o.sarifFile = eq; else if (argv[i + 1] && /\.sarif(\.json)?$/i.test(argv[i + 1])) o.sarifFile = argv[++i]; break;
      case '-t': case '--timeout': o.timeout = Number(val()); break;
      default:
        if (a.startsWith('-')) die(`unknown option ${a}`);
        o.positional.push(a);
    }
  }
  return o;
}

const o = parse(process.argv.slice(2));
if (o.positional.length > 1) die('only one directory may be given');
let dir = o.positional[0];
if (!dir && !o.url) {
  const { existsSync } = await import('node:fs');
  dir = ['dist', 'build', 'out', 'public', '_site'].find((d) => existsSync(d));
  if (!dir) die('no directory given and none of dist/ build/ out/ public/ _site/ exists');
}
let config;
try { config = await loadConfig(process.cwd(), o.config); } catch (e) { die(`config: ${e.message}`); }
const cfg = { ...config };
if (o.nonce !== undefined) cfg.nonce = o.nonce;
if (o.reportUri) cfg.reportUri = o.reportUri;
if (o.frameAncestors) cfg.frameAncestors = o.frameAncestors === 'off' ? false : o.frameAncestors;
if (o.allowWildcards) cfg.allowWildcards = true;
if (o.upgrade === false) cfg.upgradeInsecureRequests = false;
if (o.origin) cfg.origin = new URL(o.origin).origin;
const format = o.format || config.format || (o.json ? 'json' : 'header');
if (!FORMATS.includes(format) && format !== 'raw') die(`unknown --format ${format}`);
const failOn = o.failOn || config.failOn || 'error';
if (!['error', 'warn', 'none'].includes(failOn)) die('--fail-on must be error, warn or none');
if (o.write && !['meta', 'netlify'].includes(format)) die('--write supports --format meta or netlify');
if (o.write && !dir) die('--write needs a directory');
if (o.reportOnly && format === 'meta') die('report-only policies cannot be delivered via <meta>; use a header format');
if (o.timeout !== undefined && !(o.timeout > 0)) die('--timeout must be a positive number');

let result;
try { result = await generate({ dir: dir && resolve(dir), url: o.url, config: cfg, timeout: o.timeout }); }
catch (e) { if (/wildcard/.test(e.message)) die(e.message); console.error(`csp-forge: ${e.message}`); process.exit(2); }
const { scan, directives } = result;

if (o.check) {
  let existing;
  try { existing = await resolveExisting(o.check, { timeout: o.timeout }); } catch (e) { die(`--check: ${e.message}`); }
  const findings = checkPolicy(existing.policy, directives, scan, { selfOrigin: o.url ? new URL(o.url).origin : cfg.origin, allowWildcards: cfg.allowWildcards, meta: existing.meta });
  const results = [{ target: existing.source, policy: existing.policy, files: scan.files.length, findings, recommended: render(directives, 'raw') }];
  if (o.sarif) {
    const s = JSON.stringify(toSarif(results, VERSION), null, 2);
    if (o.sarifFile) { writeFileSync(o.sarifFile, s); if (!o.json) console.log(pretty(results)); } else console.log(s);
  }
  if (o.json) console.log(JSON.stringify(results, null, 2));
  else if (!o.sarif) console.log(pretty(results));
  process.exitCode = shouldFail(findings, failOn) ? 1 : 0;
} else {
  if (!o.quiet) console.error(summary(scan));
  let out;
  try { out = render(directives, format, { reportOnly: o.reportOnly, scan }); } catch (e) { die(e.message); }
  if (o.write && format === 'meta') {
    const changed = await injectMeta(resolve(dir), scan.files, out);
    console.error(`csp-forge: injected <meta> CSP into ${changed.length} HTML file(s) (frame-ancestors/report-uri are not supported in <meta>; set them as headers)`);
  } else if (o.write && format === 'netlify') {
    const p = await writeHeadersFile(resolve(dir), o.reportOnly ? 'Content-Security-Policy-Report-Only' : 'Content-Security-Policy', render(directives, 'raw'));
    console.error(`csp-forge: wrote ${p}`);
  }
  console.log(out);
}
