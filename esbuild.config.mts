import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
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

const toMjsSpecifier = (file: string, specifier: string) => {
  const base = join(dirname(file), specifier);
  if (existsSync(`${base}.ts`)) return `${specifier}.mjs`;
  if (existsSync(join(base, 'index.ts'))) return `${specifier}/index.mjs`;
  throw new Error(`Cannot resolve ${specifier} from ${file}`);
};

const writeWithMjsSpecifiers = ({ outputFiles = [] }: { outputFiles?: { path: string; text: string }[] }) => {
  for (const { path, text } of outputFiles) {
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(
      path,
      text.replace(
        /(\bfrom\s*|\bimport\s*\(?\s*)"(\.{1,2}\/[^"]+)"/g,
        (_, prefix: string, specifier: string) => `${prefix}"${toMjsSpecifier(path, specifier)}"`,
      ),
    );
  }
};

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
    write: false,
  }).then(writeWithMjsSpecifiers),
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
