# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/) and the project uses [Semantic Versioning](https://semver.org/).

## [1.1.0] - 2026-10-14

### Added
- **Nonce + strict-dynamic SSR mode**: `strictDynamic` config / `--strict-dynamic` CLI flag, per-request `generateNonce()`, `injectNoncesIntoHtml()`, `serializeWithNonce()`, `createNonceMiddleware()`, and `strictDynamicScriptSrc()` helpers.
- **Reporting**: `report-to` with `Reporting-Endpoints` header output (`--report-to`, `--reporting-endpoint-url`, `reporting-endpoints` format); nginx/apache/netlify/vercel renderers emit both CSP and reporting headers when configured.
- **Bundler plugins**: `csp-forge/vite` and `csp-forge/webpack` scan the build output and emit or inject policies (`--write` for meta / `_headers`).
- Dual **ESM + CommonJS** builds under `dist/` with conditional `exports`; TypeScript declarations generated from JSDoc via `tsc`.

### Changed
- Package entrypoints and CLI now ship from `dist/` (run `npm run build` before pack/publish).
- README documents SSR helpers, plugins, and reporting rollout.

## [1.0.1] - 2026-10-13

### Changed
- CI: harden workflows (actions pinned to SHAs, least-privilege permissions, persist-credentials: false)

## [1.0.0] - 2026-10-13

### Added
- Scan built static sites (HTML, CSS, JS) and optionally a live URL (plus its same-origin CSS/JS).
- HTML: `<script src>`, `<link rel=stylesheet|preload|modulepreload|icon|manifest>`, `<img>`/`<source>`/`srcset`, `<video>`/`<audio>`/`<track>`/`poster`, `<iframe>`, `<form action>`, `<object>`/`<embed>`, `<base>`, existing `<meta http-equiv=CSP>`.
- sha256 hashes for every inline `<script>`/`<style>`; `'unsafe-hashes'` + hashes for event handlers and `style=` attributes (with warnings); `--nonce` placeholder mode.
- CSS `url()`, `@import`, `@font-face` → `img-src` / `style-src` / `font-src`.
- JS heuristics for `fetch`, XHR, `WebSocket`, `EventSource`, `sendBeacon`, `Worker`, absolute URL literals → `connect-src` (flagged for review); `eval`/`new Function` warnings.
- Formats: header, raw, meta, nginx, apache, netlify, vercel, express/helmet, json. `--report-only`, `--report-uri`, `--write` (meta injection / `_headers`).
- `--check` mode for CI with `--json`, `--sarif`, `--fail-on`; exit codes 0/1/2.
- Config via `.csp-forgerc.json`, `.cspforgerc.json`, `.cspbuilderrc.json` or `package.json` `"csp-forge"`.
- Programmatic API. Zero runtime dependencies.
