# csp-forge

[![npm](https://img.shields.io/npm/v/csp-forge.svg)](https://www.npmjs.com/package/csp-forge)
[![CI](https://github.com/MrLouisWright/csp-forge/actions/workflows/ci.yml/badge.svg)](https://github.com/MrLouisWright/csp-forge/actions/workflows/ci.yml)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![node >=18](https://img.shields.io/badge/node-%3E%3D18-brightgreen)
![zero deps](https://img.shields.io/badge/dependencies-0-success)

Point it at your **built** static site (`dist/`, `build/`, `out/`) and optionally a live URL. It works out exactly which sources the site loads and generates a **tight Content-Security-Policy** — either **sha256 hashes** for static sites or **nonce + `strict-dynamic`** for server-rendered apps. Output comes ready to paste for Nginx, Apache, Netlify, Vercel, Express/Helmet or a `<meta>` tag, with optional **`report-uri` / `report-to`** and **`Reporting-Endpoints`** for report-only rollouts. Vite and webpack plugins run the scan at build time. `--check` mode fails CI when your deployed CSP is missing sources or too loose. Zero **runtime** dependencies, Node ≥ 18, dual ESM/CJS, JSON and SARIF output.

## Install

```bash
npm i -D csp-forge        # or run ad-hoc:
npx csp-forge dist
```

## Usage

```
csp-forge [dir] [options]                     generate a policy (dir defaults to dist/build/out/public/_site)
csp-forge [dir] --check <policy|file|url>     compare an existing CSP with what the site needs

  -u, --url <url>           Also scan a live page (+ same-origin CSS/JS); its origin counts as 'self'
      --origin <url>        Treat this absolute origin as 'self' when scanning a directory
  -c, --config <file>       JSON config (default: .csp-forgerc.json / .cspbuilderrc.json / package.json "csp-forge")
  -f, --format <fmt>        header | raw | meta | nginx | apache | netlify | vercel | express | helmet | json | reporting-endpoints
      --nonce[=value]       'nonce-{{NONCE}}' (or 'nonce-<value>') instead of inline hashes
      --strict-dynamic      Nonce mode with 'strict-dynamic' (omits inline script hashes; best for SSR)
      --report-only         Emit Content-Security-Policy-Report-Only
      --report-uri <url>    Add report-uri (legacy reporting)
      --report-to <name>    Add report-to (use with --reporting-endpoint-url)
      --reporting-endpoint-url <url>  URL for Reporting-Endpoints header (pairs with --report-to)
      --frame-ancestors <v> Default 'none'; "off" omits it
      --allow-wildcards     Allow collapsing 3+ subdomains into https://*.domain
      --no-upgrade          Omit upgrade-insecure-requests
      --write               meta: inject <meta> into every HTML file; netlify: write <dir>/_headers
  -q, --quiet               No summary on stderr
      --check <x>           Policy string, file (HTML meta, _headers, nginx conf, vercel.json) or URL
      --fail-on <level>     error | warn | none   (default: error)
      --json                Print JSON results
      --sarif [file]        Print SARIF 2.1.0 (or write to file)
  -t, --timeout <ms>        Network timeout (default: 15000)
```

Exit codes: `0` pass, `1` findings at or above `--fail-on` (in `--check` mode), `2` usage error. The policy goes to stdout and the scan summary to stderr, so `csp-forge dist > csp.txt` stays clean. Colours turn off when `NO_COLOR` is set or the output is not a TTY (`FORCE_COLOR=1` forces them).

### Sample output

```
$ npx csp-forge dist
csp-forge: scanned 4 file(s) — 2 inline script(s), 1 inline style(s), 1 style attribute(s), 1 event handler(s)
  ⚠ warn  Inline event handler <button onclick="..."> needs 'unsafe-hashes' in script-src (or refactor to addEventListener). [inline-handler]
          in index.html
          fix: Move the handler into a script file: el.addEventListener('click', ...). csp-forge emits 'unsafe-hashes' plus the exact hash meanwhile.
  ⚠ review 4 source(s) detected heuristically in JS — please review [js-detected]
          connect-src https://api.example-backend.com (api-call in assets/app.js: https://api.example-backend.com/v1/items)
          connect-src wss://realtime.example-backend.com (api-call in assets/app.js: wss://realtime.example-backend.com/socket)
          fix: Drop false positives with "ignore": ["https://unused.example/*"] in .csp-forgerc.json
Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-hashes' 'sha256-aVhr…' 'sha256-kGUQ…' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-hashes' 'sha256-IAdw…' https://fonts.googleapis.com; img-src 'self' https://images.unsplash.com data:; font-src 'self' https://fonts.gstatic.com; connect-src 'self' https://api.example-backend.com wss://realtime.example-backend.com; media-src 'none'; frame-src https://www.youtube-nocookie.com; object-src 'none'; base-uri 'self'; form-action 'self' https://formspree.io; frame-ancestors 'none'; upgrade-insecure-requests
```

```
$ npx csp-forge dist --check "default-src 'self' 'unsafe-inline'; img-src *"

policy string checked against 4 scanned file(s)
  ✖ error script-src blocks sources the site uses [csp-missing-source]
          Effective default-src does not allow https://cdn.jsdelivr.net (used in index.html).
          fix: Example: Content-Security-Policy: script-src 'self' https://cdn.jsdelivr.net
            Nginx:   add_header Content-Security-Policy "..." always;
            Express: app.use(helmet.contentSecurityPolicy({ directives: {...} }))
            Vercel/Netlify: vercel.json "headers" / _headers file  (or run: npx csp-forge <dir> --format vercel|netlify)
  ✖ error default-src allows 'unsafe-inline' [csp-unsafe-inline]
          'unsafe-inline' in default-src defeats XSS protection; csp-forge computed hashes for every inline block.
          fix: Replace 'unsafe-inline' with the hashes from: npx csp-forge <dir> --format header  (or use --nonce)
  ✖ error img-src uses overly broad source * [csp-wildcard]
          img-src allows loading from far more origins than the site uses.
          fix: List the explicit origins instead: img-src 'self' https://images.unsplash.com data:
  ⚠ warn  base-uri missing [csp-missing-base-uri]
          base-uri is not covered by default-src; <base> injection can redirect relative scripts.
          fix: Add "base-uri 'self'".

1 policy(ies) checked: 3 error(s), 1 warning(s)
```

## What it detects

| Source | Directive |
|---|---|
| `<script src>`, `<link rel=modulepreload>`, `importScripts()` | `script-src` |
| inline `<script>` (executable types only; JSON/template blocks skipped) | `script-src 'sha256-…'` |
| inline event handlers (`onclick=` …) | `script-src 'unsafe-hashes' 'sha256-…'` + warning |
| `<link rel=stylesheet>`, CSS `@import` | `style-src` |
| inline `<style>` / `style=""` attributes | `style-src 'sha256-…'` / `'unsafe-hashes' 'sha256-…'` |
| `<img>`, `srcset`, `<picture><source>`, `poster`, `<link rel=icon>`, CSS `url()` | `img-src` |
| `@font-face` `url()`, `<link rel=preload as=font>` | `font-src` |
| `fetch`, XHR `.open`, `WebSocket`, `EventSource`, `sendBeacon`, absolute URL literals in JS | `connect-src` (heuristic, flagged for review) |
| `<video>`, `<audio>`, `<source>` inside media, `<track>` | `media-src` |
| `<iframe>` | `frame-src` |
| `new Worker()` | `worker-src` |
| `<link rel=manifest>` | `manifest-src` |
| `<form action>`, `formaction` | `form-action` |
| `<object>`/`<embed>` | warning (`object-src 'none'` blocks them) |
| `eval`, `new Function`, string timers | warning (`allowEval` adds `'unsafe-eval'`) |
| `javascript:` URLs | warning |
| `<meta http-equiv=Content-Security-Policy>` | recorded; replaced by `--write` |

Fixed hardening: `default-src 'self'`, `object-src 'none'`, `base-uri 'self'`, `frame-ancestors 'none'` (configurable), `upgrade-insecure-requests`. `media-src`/`frame-src` become `'none'` when unused. `http://` origins are upgraded to `https://`. Wildcards are never emitted unless you set `allowWildcards`.

## Output formats

```bash
npx csp-forge dist -f header     # Content-Security-Policy: ...
npx csp-forge dist -f raw        # just the policy value
```

**Nginx**
```bash
npx csp-forge dist -f nginx
# add_header Content-Security-Policy "default-src 'self'; script-src 'self'; ..." always;
```

**Apache** (`.htaccess` / vhost)
```bash
npx csp-forge dist -f apache
# Header always set Content-Security-Policy "default-src 'self'; ..."
```

**Netlify / Cloudflare Pages** (`_headers`)
```bash
npx csp-forge dist -f netlify --write    # creates/updates dist/_headers, keeps other headers
```

**Vercel** (merge into `vercel.json`)
```bash
npx csp-forge dist -f vercel
# { "headers": [ { "source": "/(.*)", "headers": [ { "key": "Content-Security-Policy", "value": "..." } ] } ] }
```

**Express + Helmet**
```bash
npx csp-forge dist -f express
# app.use(helmet.contentSecurityPolicy({ useDefaults: false, directives: { defaultSrc: ["'self'"], ... } }))
```

**`<meta>` tag** (`frame-ancestors`/`report-uri` are dropped because browsers ignore them in meta)
```bash
npx csp-forge dist -f meta --write       # injects/replaces the tag right after <head> in every HTML file
```

**JSON** (policy, directive map, every source with the files that use it, review list, warnings)
```bash
npx csp-forge dist -f json > csp.json
```

Rolling out safely: start with `--report-only --report-uri /csp-report` (or modern `report-to` + `Reporting-Endpoints`), watch reports, then switch to enforcing.

### Nonce + strict-dynamic (SSR)

For server-rendered HTML, hashes do not scale as well as a per-request nonce:

```bash
npx csp-forge dist --strict-dynamic -f header   # 'nonce-{{NONCE}}' 'strict-dynamic' 'self' …
```

Programmatic helpers (zero deps):

```js
import {
  generate, generateNonce, injectNoncesIntoHtml, serializeWithNonce, createNonceMiddleware,
} from 'csp-forge';

const { directives } = await generate({ dir: 'dist', config: { strictDynamic: true, nonce: true } });
const nonce = generateNonce();
const policy = serializeWithNonce(directives, nonce);
const html = injectNoncesIntoHtml(template, nonce);

// Express-style middleware: sets res.locals.cspNonce + CSP + Reporting-Endpoints
app.use(createNonceMiddleware({
  getDirectives: () => directives,
  reportOnly: true,
  reporting: { reportTo: { name: 'csp-endpoint', url: 'https://example.com/csp' } },
}));
```

Keep scanned host allowlists in `script-src` after `'strict-dynamic'` for legacy browsers.

### Vite / webpack plugins

Run the scan automatically after each production build:

```js
// vite.config.js
import { cspForge } from 'csp-forge/vite';

export default {
  plugins: [
    cspForge({ format: 'netlify', write: true, reportOnly: true, reportUri: '/csp-report' }),
  ],
};
```

```js
// webpack.config.js
import CspForgeWebpackPlugin from 'csp-forge/webpack';

export default {
  plugins: [new CspForgeWebpackPlugin({ format: 'header', strictDynamic: true, nonce: true })],
};
```

### Framework notes

- **Vite / Astro / SvelteKit static / Next `output: 'export'` / Eleventy**: use the plugin above or `"postbuild": "csp-forge dist -f netlify --write -q"`.
- Hashes change whenever inline code changes, so regenerate on every build (or put `--check` in CI).

## Config

`.csp-forgerc.json` (or `.cspforgerc.json`, `.cspbuilderrc.json`, `"csp-forge"` in `package.json`, or `--config path`):

```json
{
  "directives": {
    "connect-src": ["https://api.example.com", "https://*.sentry.io"],
    "img-src": ["https://images.example-cdn.com"]
  },
  "ignore": ["admin/**", "https://unused-literal.example.org/*", "localhost"],
  "frameAncestors": "'self'",
  "allowWildcards": true,
  "allowEval": false,
  "nonce": false,
  "strictDynamic": false,
  "reportUri": "https://example.report-uri.com/r/d/csp/enforce",
  "reportTo": { "name": "csp-endpoint", "url": "https://example.com/api/csp-report" },
  "upgradeInsecureRequests": true,
  "origin": "https://example.com",
  "failOn": "error"
}
```

`ignore` entries containing `*` are globs (`**` crosses folders); anything else is a substring match. Each entry is checked against scanned file paths and against every URL found.

## `--check` rules

| id | severity | what |
|---|---|---|
| `csp-missing-source` | error | a source the build uses (incl. inline hashes) is not allowed by the effective directive |
| `csp-missing-source-review` | warn | same, but only for heuristically detected JS URLs |
| `csp-unsafe-hashes` | error | attribute hashes present without `'unsafe-hashes'` |
| `csp-unsafe-inline` | error (script) / warn (style) | `'unsafe-inline'` without nonce/hash |
| `csp-unsafe-eval` | error / warn | `'unsafe-eval'` when no eval was found (error) or eval is used (warn) |
| `csp-wildcard` | error | `*`, `http:`, `https:` (or `data:` in script/default) |
| `csp-wildcard-host` | warn | `*.example.com` subdomain wildcards |
| `csp-insecure-source` | warn | plain `http:` sources |
| `csp-unused-source` / `csp-stale-hash` | warn | allowed origins or hashes the build doesn't use |
| `csp-missing-object-src` / `-base-uri` / `-frame-ancestors` / `-default-src` | warn | hardening directives missing |

## CI

```yaml
# .github/workflows/csp.yml
name: CSP
on: [push, pull_request]
permissions: { contents: read, security-events: write }
jobs:
  csp:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: 20 }
      - run: npm ci && npm run build
      # the policy you ship (e.g. dist/_headers or a header from staging) must cover the build
      - run: npx csp-forge@1 dist --check dist/_headers --sarif csp.sarif
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with: { sarif_file: csp.sarif }
```

## Pairs with header-sentinel

[header-sentinel](https://www.npmjs.com/package/header-sentinel), also by Louis Wright, checks the security headers a **deployed** URL actually sends (HSTS, CSP present, COOP, cookies…). csp-forge **writes** the CSP for your build. Used together:

```bash
npx csp-forge dist -f netlify --write          # 1. generate the policy at build time
# ...deploy...
npx header-sentinel https://example.com        # 2. confirm the headers are actually served
npx csp-forge dist --check https://example.com # 3. confirm the served CSP still matches the build
```

## API

```js
const cspForge = require('csp-forge'); // or: import { generate, ... } from 'csp-forge'

const { scan, directives, policy } = await cspForge.generate({ dir: 'dist', config: { frameAncestors: "'self'" } });
console.log(cspForge.render(directives, 'nginx', { reporting: { reportTo: { name: 'csp', url: 'https://example.com/r' } } }));

const findings = cspForge.checkPolicy(currentPolicy, directives, scan);
if (cspForge.shouldFail(findings, 'error')) process.exit(1);
```

Also exported: SSR helpers (`generateNonce`, `injectNoncesIntoHtml`, `createNonceMiddleware`, …), reporting helpers (`reportingEndpointsHeader`, …), `scanDir`, `scanUrl`, scanners, `buildPolicy`, `serialize`, `parsePolicy`, `allows`, `toSarif`, `pretty`, `injectMeta`, `writeHeadersFile`. Subpaths: `csp-forge/vite`, `csp-forge/webpack`. Types are generated into `dist/*.d.ts`.

## Limitations

- Static analysis only. Sources added at runtime (third-party scripts that inject more scripts, tag managers, analytics beacons, URLs built from variables) can't be seen. Use `--report-only` first, and add them via `directives` in config.
- JS URL detection is a heuristic. It can miss URLs (string concatenation) and over-report (strings that are never fetched), which is why those sources are flagged "please review".
- HTML is parsed with a careful regex tokenizer rather than a full HTML5 parser. Very malformed markup may be misread.
- Hash lists can get long on sites with many distinct inline snippets; use `--strict-dynamic` / SSR nonce helpers instead.
- One site-wide policy is produced, not one per page.
- `--url` fetches only the given page and up to 30 of its same-origin CSS/JS files.

## Releasing

```bash
npm version patch   # or minor / major — bumps package.json, commits and tags
git push --follow-tags
```

Then create a GitHub release from the new tag. `.github/workflows/release.yml` runs the tests on Node 22 and publishes to npmjs (`npm publish --provenance`, needs the `NPM_TOKEN` secret) and to GitHub Packages as `@mrlouiswright/csp-forge`. Versions that already exist are skipped.

## License

MIT © Louis Wright ([Louis Wright](https://github.com/MrLouisWright))
