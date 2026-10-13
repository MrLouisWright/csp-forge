import { readFile, access } from 'node:fs/promises';
import { join, resolve } from 'node:path';

export const CONFIG_FILES = ['.csp-forgerc.json', '.cspforgerc.json', '.cspbuilderrc.json'];

/** Load config: explicit path, else first rc file found, else package.json "csp-forge" key. */
export async function loadConfig(cwd = process.cwd(), explicit) {
  if (explicit) return JSON.parse(await readFile(resolve(cwd, explicit), 'utf8'));
  for (const f of CONFIG_FILES) {
    const p = join(cwd, f);
    try { await access(p); } catch { continue; }
    return JSON.parse(await readFile(p, 'utf8'));
  }
  try {
    const pkg = JSON.parse(await readFile(join(cwd, 'package.json'), 'utf8'));
    if (pkg['csp-forge']) return pkg['csp-forge'];
  } catch { /* none */ }
  return {};
}
