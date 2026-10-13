# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/) and the project uses [Semantic Versioning](https://semver.org/).

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
- Programmatic API with hand-written TypeScript types. Zero dependencies.
