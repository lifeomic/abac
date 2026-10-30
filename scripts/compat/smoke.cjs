'use strict';

const { DEFAULT_SEED, compareImplementations, exportKinds, generateInputs, loosePairInputs } = require('./cases.cjs');

const candidate = require(process.env.ABAC_CANDIDATE || '@lifeomic/abac');
const published = require('abac-published');
const count = Number(process.env.ABAC_COMPAT_COUNT || 2000);

const kinds = (module) => JSON.stringify(exportKinds(module));

if (kinds(candidate) !== kinds(published)) {
  console.error('export mismatch', kinds(candidate), kinds(published));
  process.exit(1);
}

const mismatches = compareImplementations(published, candidate, loosePairInputs, 'loose').concat(
  compareImplementations(published, candidate, () => generateInputs(DEFAULT_SEED, count), 'generated'),
);

if (mismatches.length > 0) {
  console.error(`node ${process.version}: ${mismatches.length} mismatches`);
  console.error(JSON.stringify(mismatches.slice(0, 3), null, 2));
  process.exit(1);
}

console.log(`node ${process.version}, ajv ${require('ajv/package.json').version}: ${count} generated cases and loose pairs match 5.0.0`);
