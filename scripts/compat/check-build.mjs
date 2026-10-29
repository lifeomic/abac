import { execFileSync } from 'node:child_process';
import { cpSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { gzipSync } from 'node:zlib';

import { build } from 'esbuild';

const root = join(import.meta.dirname, '..', '..');
const require = createRequire(join(root, 'package.json'));
const publishedDir = dirname(require.resolve('abac-published'));
const { exportKinds } = require('./scripts/compat/cases.cjs');

// Both typescript and typescript7 install a `tsc` bin; declarations are checked with 5.x.
const TSC = join(root, 'node_modules', 'typescript', 'bin', 'tsc');
const runTsc = (file, { module, moduleResolution, skipLibCheck = false }) =>
  execFileSync(
    process.execPath,
    [TSC, '--noEmit', '--strict', ...(skipLibCheck ? ['--skipLibCheck'] : []), '--module', module, '--moduleResolution', moduleResolution, file],
    { stdio: 'inherit' },
  );

const run = (env) =>
  execFileSync(process.execPath, [join(import.meta.dirname, 'smoke.cjs')], {
    cwd: root,
    env: { ...process.env, ...env },
    stdio: 'inherit',
  });

run({ ABAC_CANDIDATE: join(root, 'src', 'index.js') });

const kinds = (module) => JSON.stringify(exportKinds(module));
const browser = await import(join(root, 'src', 'browser.js'));
const publishedBrowser = await import(join(publishedDir, 'browser.js'));
if (kinds(browser) !== kinds(publishedBrowser)) {
  throw new Error(`browser.js exports differ\n${kinds(browser)}\n${kinds(publishedBrowser)}`);
}
console.log('browser.js exports match 5.0.0');

const VALUE_NAMES = Object.keys(require('abac-published'));
const TYPE_NAMES = ['AbacPolicy', 'AbacRule', 'AbacRules', 'AbacComparison', 'AbacReduceOptions'];
const SCHEMA_NAMES = ['Policy', 'Rule', 'Rules', 'Comparison', 'ReduceOptions', 'OperationNames'];

const workDir = join(root, 'node_modules', '.cache', 'abac-compat');
rmSync(workDir, { recursive: true, force: true });
mkdirSync(workDir, { recursive: true });
const declarationsOnly = (source) => source.endsWith('.d.ts') || !/\.[cm]?[jt]s$/.test(source);
cpSync(publishedDir, join(workDir, 'published'), { recursive: true, filter: declarationsOnly });
cpSync(join(root, 'src'), join(workDir, 'built'), { recursive: true, filter: declarationsOnly });

writeFileSync(
  join(workDir, 'check.ts'),
  [
    "import type * as Published from './published/index';",
    "import type * as Built from './built/index';",
    'type Eq<X, Y> = (<T>() => T extends X ? 1 : 2) extends <T>() => T extends Y ? 1 : 2 ? true : false;',
    'type Assert<T extends true> = T;',
    'export type Checks = [',
    '  Assert<Eq<keyof typeof Published, keyof typeof Built>>,',
    ...VALUE_NAMES.map((name) => `  Assert<Eq<typeof Published.${name}, typeof Built.${name}>>,`),
    ...TYPE_NAMES.map((name) => `  Assert<Eq<Published.${name}, Built.${name}>>,`),
    ...SCHEMA_NAMES.map((name) => `  Assert<Eq<typeof Published.${name}, typeof Built.${name}>>,`),
    '];',
    '',
  ].join('\n'),
);

runTsc(join(workDir, 'check.ts'), { module: 'commonjs', moduleResolution: 'node10' });
console.log('declarations are type-equivalent to 5.0.0');

const consumerDir = join(workDir, 'consumer');
const installedDir = join(consumerDir, 'node_modules', '@lifeomic', 'abac');
const [{ files: packedFiles }] = JSON.parse(execFileSync('npm', ['pack', '--dry-run', '--json', '--ignore-scripts'], { cwd: root, encoding: 'utf8' }));
for (const { path } of packedFiles) {
  mkdirSync(dirname(join(installedDir, path)), { recursive: true });
  cpSync(join(root, path), join(installedDir, path));
}
writeFileSync(join(consumerDir, 'package.json'), '{ "private": true }\n');

for (const script of ['cases.cjs', 'subpaths.mjs']) {
  cpSync(join(import.meta.dirname, script), join(consumerDir, script));
}
execFileSync(process.execPath, [join(consumerDir, 'subpaths.mjs')], { cwd: consumerDir, stdio: ['ignore', 'inherit', 'inherit'] });

const slim = await build({
  stdin: { contents: "export { enforceLenient } from '@lifeomic/abac/enforce-lenient';", resolveDir: consumerDir },
  bundle: true,
  minify: true,
  format: 'esm',
  platform: 'browser',
  write: false,
  metafile: true,
});
const slimGzip = gzipSync(slim.outputFiles[0].text).length;
const slimInputs = Object.keys(slim.metafile.inputs).join('\n');
if (slimGzip >= 2048 || /\b(ajv|deep-equal)\b/.test(slimInputs)) {
  throw new Error(`enforce-lenient bundle is ${slimGzip} bytes gzipped from\n${slimInputs}`);
}
console.log(`@lifeomic/abac/enforce-lenient bundles to ${slimGzip} bytes gzipped without ajv or deep-equal`);

writeFileSync(
  join(consumerDir, 'resolve.ts'),
  [
    "import { enforce, validate as rootValidate, type AbacPolicy as RootPolicy } from '@lifeomic/abac';",
    "import { enforceLenient } from '@lifeomic/abac/enforce-lenient';",
    "import { validate } from '@lifeomic/abac/validate';",
    "import type { AbacPolicy, AbacRule, AbacComparison } from '@lifeomic/abac/types';",
    'const policy: AbacPolicy = { rules: { readData: true } };',
    'const rule: AbacRule | AbacComparison | undefined = undefined;',
    'const same: RootPolicy = policy;',
    'export const results = [enforce("readData", same), enforceLenient("readData", policy), validate(policy), rootValidate(policy), rule];',
    '',
  ].join('\n'),
);
for (const [module, moduleResolution] of [['commonjs', 'node10'], ['node16', 'node16'], ['esnext', 'bundler']]) {
  execFileSync(
    process.execPath,
    [
      join(root, 'node_modules', 'typescript', 'bin', 'tsc'),
      '--noEmit',
      '--strict',
      '--skipLibCheck',
      '--module',
      module,
      '--moduleResolution',
      moduleResolution,
      join(consumerDir, 'resolve.ts'),
    ],
    { stdio: 'inherit' },
  );
}
console.log('root and subpath types resolve under node10, node16, and bundler');
