export type Directive = string;
export type DirectiveMap = Record<Directive, string[]>;
export type Format = 'header' | 'raw' | 'meta' | 'nginx' | 'apache' | 'netlify' | 'vercel' | 'express' | 'helmet' | 'json';
export type Severity = 'error' | 'warn';
export type FailOn = 'error' | 'warn' | 'none';

export interface SourceEntry { where: Set<string>; /** true when only detected heuristically in JS */ review: boolean }
export interface ReviewItem { directive: string; source: string; url: string; file: string; how: 'api-call' | 'url-literal' }
export interface ScanWarning { id: string; severity: 'warn'; message: string; file?: string; fix?: string }
export interface ScanResult {
  files: string[];
  sources: Record<Directive, Map<string, SourceEntry>>;
  hashes: { script: Set<string>; style: Set<string>; scriptAttr: Set<string>; styleAttr: Set<string> };
  inline: { scripts: number; styles: number; styleAttrs: number; handlers: number };
  review: ReviewItem[];
  warnings: ScanWarning[];
  existing: { file: string; policy: string; reportOnly?: boolean; header?: boolean }[];
  usesEval?: boolean;
}

export interface Config {
  /** Extra sources per directive, e.g. { "img-src": ["https://cdn.example.com"] } */
  directives?: Record<Directive, string[] | string>;
  /** Globs (with * / **) or substrings matched against file paths and URLs */
  ignore?: string[];
  /** Default "'none'"; false omits the directive */
  frameAncestors?: string | false;
  baseUri?: string;
  objectSrc?: string;
  upgradeInsecureRequests?: boolean;
  allowWildcards?: boolean;
  wildcardThreshold?: number;
  /** Add 'unsafe-eval' when eval() is detected */
  allowEval?: boolean;
  /** true => 'nonce-{{NONCE}}', string => 'nonce-<value>' instead of inline hashes */
  nonce?: boolean | string;
  reportUri?: string;
  reportTo?: string;
  /** Absolute origin treated as 'self' when scanning a directory */
  origin?: string;
  format?: Format;
  failOn?: FailOn;
}

export interface Finding { id: string; severity: Severity; title: string; message: string; fix?: string }
export interface CheckResult { target: string; files: number; findings: Finding[]; policy?: string; recommended?: string }

export const FORMATS: Format[];
export const DEFAULTS: Required<Pick<Config, 'frameAncestors' | 'baseUri' | 'objectSrc' | 'upgradeInsecureRequests' | 'allowWildcards' | 'wildcardThreshold' | 'allowEval' | 'nonce'>> & Config;

export function generate(opts: { dir?: string; url?: string; config?: Config; timeout?: number }): Promise<{ scan: ScanResult; directives: DirectiveMap; policy: string }>;
export function scanDir(dir: string, opts?: { ignore?: string[]; selfOrigin?: string; result?: ScanResult }): Promise<ScanResult>;
export function scanUrl(url: string, opts?: { ignore?: string[]; timeout?: number; maxAssets?: number; result?: ScanResult }): Promise<ScanResult>;
export function scanHtml(html: string, result: ScanResult, file: string, ctx?: object): void;
export function scanCss(css: string, result: ScanResult, file: string, ctx?: object): void;
export function scanJs(js: string, result: ScanResult, file: string, ctx?: object): void;
export function newResult(): ScanResult;
export function merge(into: ScanResult, from: ScanResult): ScanResult;
export function sha256(text: string): string;
export function toSource(url: string, ctx?: { selfOrigin?: string; scheme?: string }): string | null;

export function buildPolicy(scan: ScanResult, config?: Config): DirectiveMap;
export function serialize(directives: DirectiveMap, opts?: { meta?: boolean }): string;
export function parsePolicy(policy: string): DirectiveMap;
export function effective(directives: DirectiveMap, name: Directive): { from: string | null; list: string[] | null };
export function allows(list: string[] | null, source: string, selfOrigin?: string, opts?: { inlineAttr?: boolean }): boolean;
export function collapseOrigins(sources: string[], opts?: { allowWildcards?: boolean; wildcardThreshold?: number }): string[];
export function render(directives: DirectiveMap, format?: Format, opts?: { reportOnly?: boolean; scan?: ScanResult }): string;

export function checkPolicy(existing: string, needed: DirectiveMap, scan?: ScanResult, opts?: { selfOrigin?: string; allowWildcards?: boolean; meta?: boolean }): Finding[];
export function shouldFail(findings: Pick<Finding, 'severity'>[], failOn?: FailOn): boolean;
export function resolveExisting(arg: string, opts?: { timeout?: number }): Promise<{ policy: string; source: string; meta?: boolean }>;
export function loadConfig(cwd?: string, explicit?: string): Promise<Config>;
export function toSarif(results: CheckResult[], version?: string): object;
export function pretty(results: CheckResult[], opts?: { color?: boolean }): string;
export function summary(scan: ScanResult, opts?: { color?: boolean }): string;
export function injectMeta(dir: string, files: string[], metaTag: string): Promise<string[]>;
export function writeHeadersFile(dir: string, headerName: string, value: string): Promise<string>;
