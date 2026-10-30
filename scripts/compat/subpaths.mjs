import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';

const require = createRequire(import.meta.url);
const { DEFAULT_SEED, enforceLenientMismatches, generateInputs } = require('./cases.cjs');
const published = require('abac-published');

const expected = {
  '@lifeomic/abac': Object.keys(published),
  '@lifeomic/abac/enforce-lenient': ['enforceLenient'],
  '@lifeomic/abac/types': [],
};

const exportNames = (module) =>
  Object.keys(module).filter((key) => key !== 'default' && key !== 'module.exports').sort();

for (const [specifier, names] of Object.entries(expected)) {
  for (const [kind, module] of [['require', require(specifier)], ['import', await import(specifier)]]) {
    if (JSON.stringify(exportNames(module)) !== JSON.stringify([...names].sort())) {
      throw new Error(`${kind}('${specifier}') exports ${exportNames(module).join(', ')}`);
    }
  }
}

const packageDir = join(dirname(require.resolve('@lifeomic/abac')), '..');
for (const subpath of ['enforce-lenient', 'types']) {
  const stub = require(join(packageDir, subpath));
  if (JSON.stringify(exportNames(stub)) !== JSON.stringify(exportNames(require(`@lifeomic/abac/${subpath}`)))) {
    throw new Error(`the ${subpath} directory stub exports ${exportNames(stub).join(', ')}`);
  }
}

const { enforceLenient } = await import('@lifeomic/abac/enforce-lenient');
const count = Number(process.env.ABAC_COMPAT_COUNT || 2000);
const mismatches = enforceLenientMismatches(published, enforceLenient, () => generateInputs(DEFAULT_SEED, count));
if (mismatches.length > 0) {
  console.error(JSON.stringify(mismatches.slice(0, 3), null, 2));
  throw new Error(`${mismatches.length} enforce-lenient mismatches against 5.0.0`);
}

console.log(`node ${process.version}: every subpath loads through require, import, and its directory stub, and enforce-lenient matches 5.0.0`);
