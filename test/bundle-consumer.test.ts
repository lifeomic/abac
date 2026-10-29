import { gzipSync } from 'node:zlib';
import { join } from 'node:path';

import { build } from 'esbuild';

const root = join(__dirname, '..');

const bundle = async (contents: string) => {
  const result = await build({
    stdin: { contents, resolveDir: root, loader: 'ts' },
    bundle: true,
    minify: true,
    format: 'esm',
    platform: 'browser',
    write: false,
    metafile: true,
    logLevel: 'silent',
  });
  const code = result.outputFiles[0].text;
  return {
    code,
    gzipBytes: gzipSync(code).length,
    packages: [...new Set(Object.keys(result.metafile.inputs).flatMap((input) => /node_modules\/(?!\.pnpm)((?:@[^/]+\/)?[^/]+)/.exec(input)?.[1] ?? []))].sort(),
  };
};

test('enforce-lenient bundles to under 2 KB gzipped with only deep-clone', async () => {
  const { code, gzipBytes, packages } = await bundle(
    "import { enforceLenient } from './src/enforce-lenient'; export default enforceLenient;",
  );

  expect(packages).toStrictEqual(['deep-clone']);
  expect(code).not.toMatch(/new Function|\beval\(/);
  expect(gzipBytes).toBeLessThan(2048);
});

test('types bundles to nothing', async () => {
  const { code, packages } = await bundle("export type { AbacPolicy } from './src/types';");

  expect(packages).toStrictEqual([]);
  expect(code.trim()).toBe('');
});

test('the root entry still bundles validation', async () => {
  const { packages } = await bundle("export { enforceLenient } from './src/index';");

  expect(packages).toContain('ajv');
  expect(packages).not.toContain('deep-equal');
});
