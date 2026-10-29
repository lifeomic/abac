import { createRequire } from 'node:module';

import { enforceLenient } from '../src/enforce-lenient';
import type { AbacPolicy } from '../src/types';

type Input = { policy: AbacPolicy; operation: string; attributes: Record<string, unknown> };
interface Cases {
  DEFAULT_COUNT: number;
  DEFAULT_SEED: number;
  generateInputs: (seed: number, count: number) => Input[];
  loosePairInputs: () => Input[];
}

const require = createRequire(__filename);
const published = require('abac-published') as typeof import('../src');
const cases = require('../scripts/compat/cases.cjs') as Cases;

const seed = Number(process.env.ABAC_COMPAT_SEED ?? cases.DEFAULT_SEED);
const count = Number(process.env.ABAC_COMPAT_COUNT ?? cases.DEFAULT_COUNT);

const isValid = (policy: AbacPolicy) => {
  try {
    return published.validate(policy);
  } catch (error) {
    return false;
  }
};

const differences = (makeInputs: () => Input[]) => {
  const expected = makeInputs().map(({ policy, operation, attributes }) =>
    isValid(policy) ? published.enforceLenient(operation, policy, attributes) : 'invalid',
  );
  return makeInputs().flatMap(({ policy, operation, attributes }, index) => {
    const actual = enforceLenient(operation, policy, attributes);
    const matches = expected[index] === 'invalid' ? typeof actual === 'boolean' : actual === expected[index];
    return matches ? [] : [{ index, policy, operation, attributes, expected: expected[index], actual }];
  });
};

test('matches 5.0.0 enforceLenient on loose equality pairs with valid policies', () => {
  expect(differences(cases.loosePairInputs).slice(0, 3)).toStrictEqual([]);
});

test(`matches 5.0.0 enforceLenient on ${count} generated valid policies and returns a boolean for invalid ones`, () => {
  const inputs = () => cases.generateInputs(seed, count);
  expect({ seed, differences: differences(inputs).slice(0, 3) }).toStrictEqual({ seed, differences: [] });
  expect(inputs().filter(({ policy }) => isValid(policy)).length).toBeGreaterThan(count / 2);
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
