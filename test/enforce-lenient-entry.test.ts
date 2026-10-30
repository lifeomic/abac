import { createRequire } from 'node:module';

import * as cases from '../scripts/compat/cases.cjs';
import { enforceLenient } from '../src/enforce-lenient';
import type { AbacPolicy } from '../src/types';
import type * as Published from 'abac-published';

const require = createRequire(__filename);
const published = require('abac-published') as typeof Published;

const seed = Number(process.env.ABAC_COMPAT_SEED ?? cases.DEFAULT_SEED);
const count = Number(process.env.ABAC_COMPAT_COUNT ?? cases.DEFAULT_COUNT);

const differences = (makeInputs: () => cases.Input[]) =>
  cases.enforceLenientMismatches(published, enforceLenient, makeInputs);

test('matches 5.0.0 enforceLenient on loose equality pairs with valid policies', () => {
  expect(differences(cases.loosePairInputs).slice(0, 3)).toStrictEqual([]);
});

test(`matches 5.0.0 enforceLenient on ${count} generated valid policies and returns a boolean for invalid ones`, () => {
  const inputs = () => cases.generateInputs(seed, count);
  expect({ seed, differences: differences(inputs).slice(0, 3) }).toStrictEqual({ seed, differences: [] });
  const valid = inputs().filter(({ policy }) => {
    try {
      return published.validate(policy);
    } catch (error) {
      return false;
    }
  });
  expect(valid.length).toBeGreaterThan(count / 2);
}, 60_000);

test.each([
  ['an undefined policy', undefined],
  ['a null policy', null],
  ['a policy without rules', {}],
  ['null rules', { rules: null }],
  ['array rules', { rules: [true] }],
  ['string rules', { rules: 'readData' }],
  ['a rule with a non-object comparison', { rules: { readData: [{ 'user.id': 7 }] } }],
])('returns false instead of throwing for %s', (_, policy) => {
  expect(enforceLenient('readData', policy as unknown as AbacPolicy, { user: { id: 7 } })).toBe(false);
});

test('allows an operation whose rules are still pending on unknown attributes', () => {
  const policy: AbacPolicy = {
    rules: { readData: [{ 'resource.owner': { comparison: 'equals', target: 'user.id' } }] },
  };

  expect(enforceLenient('readData', policy, {})).toBe(true);
  expect(enforceLenient('readData', policy, { user: { id: 'a' }, resource: { owner: 'b' } })).toBe(false);
  expect(enforceLenient('writeData', policy, {})).toBe(false);
});

test('returns false where the root export throws for operations inherited from Object.prototype', () => {
  const policy: AbacPolicy = { rules: { readData: true } };

  expect(() => published.enforceLenient('toString', policy)).toThrow(TypeError);
  expect(enforceLenient('toString', policy)).toBe(false);
});
