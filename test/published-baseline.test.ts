import { createRequire } from 'node:module';

import type * as Published from 'abac-published';

import * as cases from '../scripts/compat/cases.cjs';
import * as local from '../src';

const require = createRequire(__filename);
const published = require('abac-published') as typeof Published;

const seed = Number(process.env.ABAC_COMPAT_SEED ?? cases.DEFAULT_SEED);
const count = Number(process.env.ABAC_COMPAT_COUNT ?? cases.DEFAULT_COUNT);

const report = (mismatches: unknown[]) => ({ seed, mismatches: mismatches.length, sample: mismatches.slice(0, 3) });

test('exports the same names and kinds as 5.0.0', () => {
  expect(cases.exportKinds(local)).toStrictEqual(cases.exportKinds(published));
  expect(local.COMPARISON_REVERSION_MAP).toStrictEqual(published.COMPARISON_REVERSION_MAP);
});

test('matches 5.0.0 on loose equality pairs', () => {
  const mismatches = cases.compareImplementations(published, local, cases.loosePairInputs, 'loose');
  expect(report(mismatches)).toStrictEqual(report([]));
});

test(`matches 5.0.0 on ${count} generated cases`, () => {
  const mismatches = cases.compareImplementations(published, local, () => cases.generateInputs(seed, count), 'generated');
  expect(report(mismatches)).toStrictEqual(report([]));
}, 60_000);
