import { createRequire } from 'node:module';

import * as local from '../src';

type Abac = typeof local;
type Input = Record<string, unknown>;
interface Cases {
  DEFAULT_COUNT: number;
  DEFAULT_SEED: number;
  compareImplementations: (expected: Abac, actual: Abac, makeInputs: () => Input[], label: string) => unknown[];
  generateInputs: (seed: number, count: number) => Input[];
  loosePairInputs: () => Input[];
}

const require = createRequire(__filename);
const published = require('abac-published') as Abac;
const cases = require('../scripts/compat/cases.cjs') as Cases;

const seed = Number(process.env.ABAC_COMPAT_SEED ?? cases.DEFAULT_SEED);
const count = Number(process.env.ABAC_COMPAT_COUNT ?? cases.DEFAULT_COUNT);

const report = (mismatches: unknown[]) => ({ seed, mismatches: mismatches.length, sample: mismatches.slice(0, 3) });

test('exports the same names and kinds as 5.0.0', () => {
  const kinds = (module: Abac) =>
    Object.fromEntries(Object.entries(module).sort().map(([key, value]) => [key, typeof value]));

  expect(kinds(local)).toStrictEqual(kinds(published));
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
