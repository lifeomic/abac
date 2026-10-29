import { execFileSync } from 'node:child_process';
import { cpSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';

const root = join(import.meta.dirname, '..', '..');
const require = createRequire(join(root, 'package.json'));
const publishedDir = dirname(require.resolve('abac-published'));

const run = (env) =>
  execFileSync(process.execPath, [join(import.meta.dirname, 'smoke.cjs')], {
    cwd: root,
    env: { ...process.env, ...env },
    stdio: 'inherit',
  });

run({ ABAC_CANDIDATE: join(root, 'src', 'index.js') });

const kinds = (module) => Object.keys(module).sort().map((key) => `${key}:${typeof module[key]}`).join(',');
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

execFileSync(
  process.execPath,
  [
    join(root, 'node_modules', 'typescript', 'bin', 'tsc'),
    '--noEmit',
    '--strict',
    '--module',
    'commonjs',
    '--moduleResolution',
    'node10',
    join(workDir, 'check.ts'),
  ],
  { stdio: 'inherit' },
);
console.log('declarations are type-equivalent to 5.0.0');
