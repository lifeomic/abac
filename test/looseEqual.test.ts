import deepClone from 'deep-clone';
import deepEqual from 'deep-equal';

import { looseEqual } from '../src/core/looseEqual';

const SEED = Number(process.env.ABAC_COMPAT_SEED ?? 0xabac);
const PAIRS = Number(process.env.ABAC_LOOSE_EQUAL_PAIRS ?? 30000);

const mulberry32 = (seed: number) => {
  let state = seed | 0;
  return () => {
    state = (state + 0x6d2b79f5) | 0;
    let t = Math.imul(state ^ (state >>> 15), 1 | state);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
};

const PRIMITIVES = [
  0, -0, 1, -1, 2, 10, 1.5, 1e21, Infinity, -Infinity, NaN,
  '0', '1', '-1', '2', '10', '1.5', '', ' ', '\n', 'a', 'abc', 'NaN', 'Infinity', '1e1', '0x1', '0b1', '01', 'true',
  'false', 'null', true, false, null, undefined,
];

const LOOSE_ALTERNATIVES = new Map<unknown, unknown[]>([
  [1, ['1', true, ' 1', '1.0', '0x1']],
  [0, ['0', '', ' ', false, '0x0', '-0']],
  [10, ['10', '1e1', '0xa']],
  ['1', [1, true]],
  ['0', [0, false]],
  ['', [0, false]],
  [true, [1, '1']],
  [false, [0, '0', '']],
  [null, [undefined]],
  [undefined, [null]],
  [Infinity, ['Infinity']],
  [1.5, ['1.5']],
  [2, ['2']],
]);

type Domain = 'cloned' | 'raw';

const createPairGenerator = (random: () => number, includeExotic: boolean) => {
  const pick = <T>(list: T[]): T => list[Math.floor(random() * list.length)];

  const leaf = (): unknown => {
    const roll = random();
    if (roll < 0.05) return new Date(pick([0, 1, 86400000, NaN]));
    if (includeExotic && roll < 0.09) {
      const kind = pick(['number', 'string', 'boolean']);
      if (kind === 'number') return new Number(pick([0, 1, 2, NaN]));
      if (kind === 'string') return new String(pick(['', '1', 'a', 'ab']));
      return new Boolean(pick([true, false]));
    }
    return pick(PRIMITIVES);
  };

  const value = (depth: number): unknown => {
    const roll = random();
    if (depth <= 0 || roll < 0.45) return leaf();
    if (roll < 0.72) {
      const array = Array.from({ length: Math.floor(random() * 4) }, () => value(depth - 1));
      if (includeExotic && random() < 0.03) delete array[0];
      return array;
    }
    const object: Record<string, unknown> = includeExotic && random() < 0.03 ? Object.create(null) : {};
    for (let count = Math.floor(random() * 4); count > 0; count--) {
      object[pick(['a', 'b', 'c', '0', '1', 'length'])] = value(depth - 1);
    }
    return object;
  };

  const loosen = (input: unknown): unknown => {
    if (Array.isArray(input)) return input.map(loosen);
    if (input instanceof Date) return random() < 0.8 ? new Date(input.getTime()) : input.getTime();
    if (input instanceof Number || input instanceof String || input instanceof Boolean) {
      return random() < 0.5 ? input.valueOf() : input;
    }
    if (input && typeof input === 'object') {
      const prototype = Object.getPrototypeOf(input) as object | null;
      const result: Record<string, unknown> = prototype === null && random() < 0.5 ? {} : Object.create(prototype);
      for (const key of Object.keys(input)) result[key] = loosen((input as Record<string, unknown>)[key]);
      return result;
    }
    const alternatives = LOOSE_ALTERNATIVES.get(input);
    return alternatives && random() < 0.6 ? pick(alternatives) : input;
  };

  const mutate = (input: unknown): unknown => {
    if (Array.isArray(input) && input.length > 0 && random() < 0.7) {
      const copy = input.slice();
      const index = Math.floor(random() * copy.length);
      copy[index] = mutate(copy[index]);
      return copy;
    }
    if (input && typeof input === 'object' && !(input instanceof Date) && random() < 0.7) {
      const keys = Object.keys(input);
      if (keys.length > 0) {
        const copy: Record<string, unknown> = { ...input };
        const key = pick(keys);
        copy[key] = mutate(copy[key]);
        return copy;
      }
    }
    return value(1);
  };

  return (): [unknown, unknown] => {
    const left = value(3);
    const roll = random();
    if (roll < 0.2) return [left, value(3)];
    if (roll < 0.35) return [left, deepClone(left)];
    if (roll < 0.8) return [left, loosen(left)];
    return [left, mutate(left)];
  };
};

const fuzz = (domain: Domain, includeExotic: boolean) => {
  const nextPair = createPairGenerator(mulberry32(SEED), includeExotic);
  const mismatches: string[] = [];
  let equalPairs = 0;
  for (let i = 0; i < PAIRS; i++) {
    let [left, right] = nextPair();
    if (domain === 'cloned') {
      left = deepClone(left);
      right = deepClone(right);
    }
    const expected = deepEqual(left, right);
    if (expected) equalPairs++;
    if (looseEqual(left, right) !== expected && mismatches.length < 5) {
      mismatches.push(`${String(i)}: deep-equal says ${String(expected)}`);
    }
  }
  return { mismatches, equalPairs };
};

test.each([
  ['cloned JSON and Dates', 'cloned', false],
  ['cloned exotic values', 'cloned', true],
  ['raw exotic values', 'raw', true],
] as const)(`matches deep-equal@2.2.1 on ${PAIRS} %s`, (_, domain, includeExotic) => {
  const { mismatches, equalPairs } = fuzz(domain, includeExotic);
  expect({ seed: SEED, mismatches }).toStrictEqual({ seed: SEED, mismatches: [] });
  expect(equalPairs).toBeGreaterThan(PAIRS * 0.3);
  expect(equalPairs).toBeLessThan(PAIRS * 0.8);
}, 60_000);

test('treats cycles as equal when their structure matches', () => {
  const left: Record<string, unknown> = { a: 1 };
  left.self = left;
  const right: Record<string, unknown> = { a: '1' };
  right.self = right;

  expect(looseEqual(left, right)).toBe(deepEqual(left, right));
  expect(looseEqual(left, right)).toBe(true);
});

test('compares functions by identity only', () => {
  const fn = () => 1;

  expect(looseEqual(fn, fn)).toBe(true);
  expect(looseEqual(fn, () => 1)).toBe(false);
  expect(looseEqual(fn, 'fn')).toBe(false);
});

test('compares Dates by time', () => {
  expect(looseEqual(new Date(0), new Date(0))).toBe(true);
  expect(looseEqual(new Date(0), new Date(1))).toBe(false);
  expect(looseEqual(new Date(NaN), new Date(NaN))).toBe(false);
});
