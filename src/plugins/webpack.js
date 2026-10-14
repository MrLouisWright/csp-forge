import { runForgeBuild } from './shared.js';

/**
 * Webpack plugin: generate CSP from compiler output path on `afterEmit`.
 * @param {import('./shared.js').PluginOptions} [options]
 */
export class CspForgeWebpackPlugin {
  constructor(options = {}) {
    this.options = options;
  }

  /** @param {import('webpack').Compiler} compiler */
  apply(compiler) {
    const pluginName = 'CspForgeWebpackPlugin';
    compiler.hooks.afterEmit.tapAsync(pluginName, async (compilation, callback) => {
      try {
        const outDir = compiler.options.output?.path || 'dist';
        await runForgeBuild(this.options, outDir);
        callback();
      } catch (err) {
        callback(err instanceof Error ? err : new Error(String(err)));
      }
    });
  }
}

export default CspForgeWebpackPlugin;
