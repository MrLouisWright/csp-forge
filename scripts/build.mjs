import * as esbuild from 'esbuild';
import { execSync } from 'node:child_process';
import { mkdirSync, rmSync } from 'node:fs';

const entries = [
  { in: 'src/index.js', out: 'index' },
  { in: 'src/plugins/vite.js', out: 'vite' },
  { in: 'src/plugins/webpack.js', out: 'webpack' },
  { in: 'bin/csp-forge.js', out: 'cli' },
];

rmSync('dist', { recursive: true, force: true });
mkdirSync('dist', { recursive: true });

for (const { in: input, out } of entries) {
  const base = { entryPoints: [input], bundle: true, platform: 'node', target: 'node18', sourcemap: true };
  const banner = out === 'cli' ? { js: '#!/usr/bin/env node' } : undefined;
  await esbuild.build({ ...base, outfile: `dist/${out}.js`, format: 'esm', banner });
  if (out !== 'cli') {
    await esbuild.build({ ...base, outfile: `dist/${out}.cjs`, format: 'cjs', banner });
  }
}

execSync('npx tsc -p tsconfig.build.json', { stdio: 'inherit' });
