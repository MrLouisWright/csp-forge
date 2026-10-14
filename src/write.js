import { readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';

const META_RE = /[ \t]*<meta\b[^>]*http-equiv\s*=\s*["']?content-security-policy["']?[^>]*>\s*\n?/gi;

/** Insert/replace the CSP meta tag right after <head>. Returns files changed. */
export async function injectMeta(dir, files, metaTag) {
  const changed = [];
  for (const rel of files.filter((f) => /\.html?$/i.test(f))) {
    const p = join(dir, rel);
    const html = await readFile(p, 'utf8');
    let out = html.replace(META_RE, '');
    if (/<head\b[^>]*>/i.test(out)) out = out.replace(/<head\b[^>]*>/i, (m) => `${m}\n    ${metaTag}`);
    else if (/<html\b[^>]*>/i.test(out)) out = out.replace(/<html\b[^>]*>/i, (m) => `${m}\n<head>${metaTag}</head>`);
    else out = `${metaTag}\n${out}`;
    if (out !== html) { await writeFile(p, out); changed.push(rel); }
  }
  return changed;
}

/** Write or update a Netlify/Cloudflare Pages style _headers file. */
export async function writeHeadersFile(dir, headerName, value) {
  const p = join(dir, '_headers');
  let text = '';
  try { text = await readFile(p, 'utf8'); } catch { /* new */ }
  const line = `  ${headerName}: ${value}`;
  const re = new RegExp(`^[ \\t]+${headerName.replace(/[.*+?^${}()|[\\]\\\\]/g, '\\$&')}:.*$`, 'm');
  if (re.test(text)) text = text.replace(re, line);
  else if (/^\/\*\s*$/m.test(text)) text = text.replace(/^\/\*\s*$/m, `/*\n${line}`);
  else if (/^\/\*\n/m.test(text)) text = text.replace(/^\/\*\n/m, `/*\n${line}\n`);
  else text = `${text}${text && !text.endsWith('\n') ? '\n' : ''}/*\n${line}\n`;
  await writeFile(p, text);
  return p;
}
