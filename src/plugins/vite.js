import { runForgeBuild } from './shared.js';

/**
 * Vite plugin: scan the build output and emit / inject a CSP after `closeBundle`.
 * @param {import('./shared.js').PluginOptions} [options]
 * @returns {{ name: string; apply: string; configResolved: (config: { build?: { outDir?: string } }) => void; closeBundle: () => Promise<void> }}
 */
export function cspForge(options = {}) {
  let outDir = 'dist';
  return {
    name: 'csp-forge',
    apply: 'build',
    configResolved(config) {
      outDir = config.build?.outDir || outDir;
    },
    async closeBundle() {
      await runForgeBuild(options, outDir);
    },
  };
}

export default cspForge;
