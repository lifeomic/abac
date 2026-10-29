import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const { DEFAULT_SEED, generateInputs } = require('./cases.cjs');
const published = require('abac-published');

const expected = {
  '@lifeomic/abac': Object.keys(published),
  '@lifeomic/abac/enforce-lenient': ['enforceLenient'],
  '@lifeomic/abac/validate': ['validate'],
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

const { enforceLenient } = await import('@lifeomic/abac/enforce-lenient');
const { validate } = await import('@lifeomic/abac/validate');
const isValid = (policy) => {
  try {
    return validate(policy);
  } catch (error) {
    return false;
  }
};

const count = Number(process.env.ABAC_COMPAT_COUNT || 2000);
const mismatches = generateInputs(DEFAULT_SEED, count).filter(
  ({ policy, operation, attributes }) =>
    isValid(policy) && enforceLenient(operation, policy, attributes) !== published.enforceLenient(operation, policy, attributes),
);
if (mismatches.length > 0) {
  console.error(JSON.stringify(mismatches.slice(0, 3), null, 2));
  throw new Error(`${mismatches.length} enforce-lenient mismatches against 5.0.0`);
}

console.log(`node ${process.version}: every subpath loads through require and import, and enforce-lenient matches 5.0.0`);
