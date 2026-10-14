import { randomBytes } from 'node:crypto';
import { buildPolicy, serialize } from './policy.js';
import { reportingEndpointsHeader } from './reporting.js';

/** Default placeholder replaced in generated policies when `nonce: true`. */
export const NONCE_PLACEHOLDER = '{{NONCE}}';

/**
 * Generate a cryptographically random CSP nonce (base64).
 * @param {number} [bytes=16]
 * @returns {string}
 */
export function generateNonce(bytes = 16) {
  return randomBytes(bytes).toString('base64');
}

/**
 * Format a nonce token for use in a CSP source list.
 * @param {string} nonce
 * @returns {string}
 */
export function nonceSource(nonce) {
  return `'nonce-${nonce}'`;
}

/**
 * Replace `{{NONCE}}` placeholders in a serialized policy string.
 * @param {string} policy
 * @param {string} nonce
 * @returns {string}
 */
export function applyNonceToPolicyString(policy, nonce) {
  return policy.split(NONCE_PLACEHOLDER).join(nonce);
}

/**
 * Build directive map for a request, using a concrete nonce (strict-dynamic when enabled).
 * @param {import('./scan.js').ScanResult} scan
 * @param {import('./policy.js').BuildConfig} [config]
 * @param {string} nonce
 * @returns {import('./policy.js').DirectiveMap}
 */
export function buildDirectivesWithNonce(scan, config, nonce) {
  return buildPolicy(scan, { ...config, nonce });
}

/**
 * Serialize a policy for a response, substituting a per-request nonce.
 * @param {import('./policy.js').DirectiveMap} directives
 * @param {string} nonce
 * @param {{ meta?: boolean }} [opts]
 * @returns {string}
 */
export function serializeWithNonce(directives, nonce, opts) {
  return applyNonceToPolicyString(serialize(directives, opts), nonce);
}

const SCRIPT_OPEN = /<script\b([^>]*)>/gi;
const STYLE_OPEN = /<style\b([^>]*)>/gi;

/**
 * Add `nonce="..."` to inline `<script>` / `<style>` tags that do not already have one.
 * Skips `<script src>` external tags unless they are module scripts without src handling — only inline blocks.
 * @param {string} html
 * @param {string} nonce
 * @param {{ scripts?: boolean; styles?: boolean }} [opts]
 * @returns {string}
 */
export function injectNoncesIntoHtml(html, nonce, { scripts = true, styles = true } = {}) {
  let out = html;
  if (scripts) {
    out = out.replace(SCRIPT_OPEN, (full, attrs) => {
      if (/\bnonce\s*=/.test(attrs)) return full;
      if (/\bsrc\s*=/.test(attrs)) return full;
      return `<script nonce="${escapeAttr(nonce)}"${attrs}>`;
    });
  }
  if (styles) {
    out = out.replace(STYLE_OPEN, (full, attrs) => {
      if (/\bnonce\s*=/.test(attrs)) return full;
      return `<style nonce="${escapeAttr(nonce)}"${attrs}>`;
    });
  }
  return out;
}

function escapeAttr(s) {
  return String(s).replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;');
}

/**
 * Recommended `script-src` for nonce + strict-dynamic SSR (legacy host fallbacks listed after).
 * @param {string} nonce
 * @param {string[]} [legacyHosts] e.g. `["'self'", 'https://cdn.example.com']`
 * @returns {string[]}
 */
export function strictDynamicScriptSrc(nonce, legacyHosts = ["'self'"]) {
  return [nonceSource(nonce), "'strict-dynamic'", ...legacyHosts];
}

/**
 * Express-style middleware: sets `res.locals.cspNonce`, optional CSP + Reporting-Endpoints headers.
 * @param {{
 *   getDirectives?: (req: import('node:http').IncomingMessage, res: import('node:http').ServerResponse, nonce: string) => import('./policy.js').DirectiveMap | Promise<import('./policy.js').DirectiveMap>;
 *   policy?: string | import('./policy.js').DirectiveMap;
 *   reportOnly?: boolean;
 *   reporting?: import('./reporting.js').ReportingConfig;
 *   onNonce?: (nonce: string, req: import('node:http').IncomingMessage, res: import('node:http').ServerResponse) => void;
 * }} [options]
 * @returns {(req: import('node:http').IncomingMessage, res: import('node:http').ServerResponse, next: () => void) => void}
 */
function setReportingHeaders(res, reporting) {
  if (!reporting) return;
  const rep = reportingEndpointsHeader(reporting);
  if (rep) res.setHeader('Reporting-Endpoints', rep);
}

export function createNonceMiddleware(options = {}) {
  const header = options.reportOnly ? 'Content-Security-Policy-Report-Only' : 'Content-Security-Policy';
  return (req, res, next) => {
    const nonce = generateNonce();
    res.locals = res.locals || {};
    res.locals.cspNonce = nonce;
    options.onNonce?.(nonce, req, res);
    const finish = (value) => {
      if (value) res.setHeader(header, value);
      setReportingHeaders(res, options.reporting);
      next();
    };
    try {
      if (options.getDirectives) {
        const dirs = options.getDirectives(req, res, nonce);
        if (dirs && typeof dirs.then === 'function') {
          dirs.then((d) => finish(serializeWithNonce(d, nonce))).catch(next);
          return;
        }
        finish(serializeWithNonce(dirs, nonce));
        return;
      }
      if (typeof options.policy === 'string') finish(applyNonceToPolicyString(options.policy, nonce));
      else if (options.policy && typeof options.policy === 'object') finish(serializeWithNonce(options.policy, nonce));
      else {
        setReportingHeaders(res, options.reporting);
        next();
      }
    } catch (e) {
      next(e);
    }
  };
}
