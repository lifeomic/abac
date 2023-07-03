import { build } from 'esbuild';
import { globSync } from 'glob';
import semver from 'semver';
import { engines } from './package.json';
import { esbuildPluginBrowserslist } from 'esbuild-plugin-browserslist';
import browserslist from 'browserslist';

const entryPoints = globSync('src/**/!(*.d).ts', { cwd: __dirname });

const nodeVersion = semver.minVersion(engines.node, { loose: false })?.version;
if (!nodeVersion) {
  throw new Error('Missing engines.node version from package.json');
}

void build({
  bundle: false,
  sourcemap: false,
  platform: 'node',
  target: `node${nodeVersion}`,
  outdir: 'src',
  format: 'cjs',
  entryPoints,
});

void build({
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
});

void build({
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
});
