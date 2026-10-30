import { build } from 'esbuild';
import { globSync } from 'glob';
import semver from 'semver';
import { esbuildPluginBrowserslist } from 'esbuild-plugin-browserslist';
import browserslist from 'browserslist';
import packageJson from './package.json' with { type: 'json' };

const entryPoints = globSync('src/**/!(*.d).ts', { cwd: import.meta.dirname });

const nodeVersion = semver.minVersion(packageJson.engines.node, { loose: false })?.version;
if (!nodeVersion) {
  throw new Error('Missing engines.node version from package.json');
}

await Promise.all([
  build({
    bundle: false,
    sourcemap: false,
    platform: 'node',
    target: `node${nodeVersion}`,
    outdir: 'src',
    format: 'cjs',
    entryPoints,
  }),
  build({
    bundle: false,
    sourcemap: false,
    platform: 'node',
    target: `node${nodeVersion}`,
    outdir: 'src',
    format: 'esm',
    outExtension: {
      '.js': '.mjs',
    },
    entryPoints,
  }),
  build({
    bundle: true,
    platform: 'browser',
    format: 'esm',
    plugins: [
      esbuildPluginBrowserslist(browserslist('defaults'), {
        printUnknownTargets: false,
      }),
    ],
    outfile: 'src/browser.js',
    entryPoints: ['src/index.ts'],
  }),
]);
