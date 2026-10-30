import vm from 'node:vm';

import deepClone from 'deep-clone';
import deepEqual from 'deep-equal';

import { mulberry32 } from '../scripts/compat/cases.cjs';
import { looseEqual } from '../src/core/looseEqual';

const SEED = Number(process.env.ABAC_COMPAT_SEED ?? 0xabac);
const PAIRS = Number(process.env.ABAC_LOOSE_EQUAL_PAIRS ?? 30000);

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

const SHARED_FUNCTION = () => 1;
const REGEXP_SOURCES = ['a', 'b', '^admin$'];
const REGEXP_FLAGS = ['', 'g', 'i', 'gi'];
const ERROR_MESSAGES = ['', 'a', 'denied'];
const TYPED_ARRAYS = [Uint8Array, Int8Array, Float64Array];

type Domain = 'cloned' | 'raw';

const foreign = <T>(source: string): T => vm.runInNewContext(source) as T;

class BufferLike {
  static isBuffer = (value: unknown) => value instanceof BufferLike;
  copy() {}
  slice() {}
}
const bufferLike = (bytes: number[]) => Object.assign(new BufferLike(), bytes, { length: bytes.length });

const createPairGenerator = (random: () => number, includeExotic: boolean) => {
  const pick = <T>(list: readonly T[]): T => list[Math.floor(random() * list.length)];
  const bytes = () => Array.from({ length: Math.floor(random() * 3) }, () => pick([0, 1, 2, 255]));

  const exoticLeaf = (depth: number): unknown => {
    switch (pick(['boxed', 'set', 'map', 'regexp', 'error', 'arrayBuffer', 'buffer', 'typed', 'weakMap', 'function', 'foreign'])) {
      case 'boxed': {
        const kind = pick(['number', 'string', 'boolean']);
        if (kind === 'number') return new Number(pick([0, 1, 2, NaN]));
        if (kind === 'string') return new String(pick(['', '1', 'a', 'ab']));
        return new Boolean(pick([true, false]));
      }
      case 'set':
        return new Set(Array.from({ length: Math.floor(random() * 4) }, () => value(depth - 1)));
      case 'map':
        return new Map(Array.from({ length: Math.floor(random() * 3) }, () => [random() < 0.7 ? pick(PRIMITIVES) : value(depth - 1), value(depth - 1)]));
      case 'regexp':
        return new RegExp(pick(REGEXP_SOURCES), pick(REGEXP_FLAGS));
      case 'error':
        return new (pick([Error, TypeError]))(pick(ERROR_MESSAGES));
      case 'arrayBuffer':
        return new Uint8Array(bytes()).buffer;
      case 'buffer':
        return Buffer.from(bytes());
      case 'typed':
        return new (pick(TYPED_ARRAYS))(bytes());
      case 'weakMap':
        return new WeakMap();
      case 'function':
        return random() < 0.5 ? SHARED_FUNCTION : () => 1;
      default:
        return foreign(pick(['({ a: 1 })', '[1]', 'new Set([1])', 'new Error("a")', '/a/g', 'new Date(0)', 'new Map([[1, 1]])']));
    }
  };

  const leaf = (depth: number): unknown => {
    const roll = random();
    if (roll < 0.05) return new Date(pick([0, 1, 86400000, NaN]));
    if (includeExotic && roll < 0.2) return exoticLeaf(depth);
    return pick(PRIMITIVES);
  };

  const value = (depth: number): unknown => {
    const roll = random();
    if (depth <= 0 || roll < 0.45) return leaf(depth);
    if (roll < 0.72) {
      const array = Array.from({ length: Math.floor(random() * 4) }, () => value(depth - 1));
      if (includeExotic && random() < 0.03) delete array[0];
      return array;
    }
    const object: Record<string, unknown> = includeExotic && random() < 0.1 ? Object.create(null) : {};
    for (let count = Math.floor(random() * 4); count > 0; count--) {
      object[pick(['a', 'b', 'c', '0', '1', 'length'])] = value(depth - 1);
    }
    return object;
  };

  const loosen = (input: unknown): unknown => {
    const tag = Object.prototype.toString.call(input);
    if (Array.isArray(input)) return input.map(loosen);
    if (input instanceof Date) return random() < 0.8 ? new Date(input.getTime()) : input.getTime();
    if (input instanceof Number || input instanceof String || input instanceof Boolean) {
      return random() < 0.5 ? input.valueOf() : input;
    }
    if (input instanceof Set) return new Set(Array.from(input, loosen));
    if (input instanceof Map) return new Map(Array.from(input, ([key, item]) => [loosen(key), loosen(item)]));
    if (input instanceof RegExp) return new RegExp(input.source, random() < 0.8 ? input.flags : pick(REGEXP_FLAGS));
    if (input instanceof Error) return new (random() < 0.8 ? (input.constructor as ErrorConstructor) : Error)(input.message);
    if (input instanceof ArrayBuffer) return input.slice(0);
    if (Buffer.isBuffer(input)) return random() < 0.5 ? Buffer.from(input) : new Uint8Array(input);
    if (ArrayBuffer.isView(input)) {
      const view = input as Uint8Array;
      return new (random() < 0.8 ? (view.constructor as Uint8ArrayConstructor) : pick(TYPED_ARRAYS))(Array.from(view));
    }
    if (input && typeof input === 'object' && tag === '[object Object]') {
      const prototype = Object.getPrototypeOf(input) as object | null;
      const result: Record<string, unknown> = prototype === null && random() < 0.5 ? {} : Object.create(prototype);
      for (const key of Object.keys(input)) result[key] = loosen((input as Record<string, unknown>)[key]);
      return result;
    }
    if (typeof input === 'object' || typeof input === 'function') return input;
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
    if (input && Object.prototype.toString.call(input) === '[object Object]' && random() < 0.7) {
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
] as const)(`matches deep-equal@2.2.3 on ${PAIRS} %s`, (_, domain, includeExotic) => {
  const { mismatches, equalPairs } = fuzz(domain, includeExotic);
  expect({ seed: SEED, mismatches }).toStrictEqual({ seed: SEED, mismatches: [] });
  expect(equalPairs).toBeGreaterThan(PAIRS * 0.25);
  expect(equalPairs).toBeLessThan(PAIRS * 0.8);
}, 60_000);

test.each([
  ['Sets by loose membership', new Set([1, { a: 1 }]), new Set(['1', { a: '1' }]), true],
  ['Sets with different members', new Set([1]), new Set([2]), false],
  ['Maps by loose keys and values', new Map([[1, 'x']]), new Map([['1', 'x']]), true],
  ['Maps with different values', new Map([['a', 1]]), new Map([['a', 2]]), false],
  ['RegExps by flags', /a/g, /a/i, false],
  ['Errors by message', new Error('a'), new Error('b'), false],
  ['ArrayBuffers by bytes', new Uint8Array([1]).buffer, new Uint8Array([2]).buffer, false],
  ['a Buffer and a Uint8Array with the same bytes', Buffer.from([1]), new Uint8Array([1]), true],
  ['typed arrays of different kinds', new Uint8Array([1]), new Int8Array([1]), false],
  ['a typed array and an object with its tag', new Uint8Array(), { [Symbol.toStringTag]: 'Uint8Array' }, false],
  ['typed arrays with different elements', new Float64Array([NaN]), new Float64Array([NaN]), false],
  ['a cross-realm Error and a local one', foreign<Error>('new Error("a")'), new Error('a'), false],
  ['cross-realm RegExps', foreign<RegExp>('/a/g'), /a/g, true],
  ['ArrayBuffers of different lengths', new ArrayBuffer(1), new ArrayBuffer(2), false],
  ['Sets of different sizes', new Set([1]), new Set([1, 2]), false],
  ['Sets with a missing non-numeric string', new Set(['a']), new Set(['b']), false],
  ['Sets with a missing symbol', new Set([Symbol.iterator]), new Set([Symbol.asyncIterator]), false],
  ['Sets with null and undefined', new Set([null]), new Set([undefined]), true],
  ['Maps of different sizes', new Map([[1, 1]]), new Map([[1, 1], [2, 2]]), false],
  ['Maps with a missing non-numeric key', new Map([['a', 1]]), new Map([['b', 1]]), false],
  ['Maps with null and undefined keys', new Map([[null, 1]]), new Map([[undefined, 1]]), true],
  ['Maps with null and undefined keys and different values', new Map([[null, 1]]), new Map([[undefined, 2]]), false],
  ['Maps where only one side has an undefined key', new Map([[null, 1]]), new Map([['x', 1]]), false],
  ['buffer-likes with the same bytes', bufferLike([1]), bufferLike([1]), true],
  ['buffer-likes with different bytes', bufferLike([1]), bufferLike([2]), false],
  ['a buffer-like and a plain object', bufferLike([1]), { ...bufferLike([1]), constructor: Object }, false],
])('compares %s like deep-equal', (_, left, right, expected) => {
  expect(deepEqual(left, right)).toBe(expected);
  expect(looseEqual(left, right)).toBe(expected);
});

test('treats cycles as equal when their structure matches', () => {
  const left: Record<string, unknown> = { a: 1 };
  left.self = left;
  const right: Record<string, unknown> = { a: '1' };
  right.self = right;

  expect(looseEqual(left, right)).toBe(deepEqual(left, right));
  expect(looseEqual(left, right)).toBe(true);
});

test('compares shared references that were already paired with other values', () => {
  const a = { v: 1 };
  const c = { v: 1 };
  const b = { v: '1' };
  const d = { v: 1 };
  const left = [a, c, a];
  const right = [d, d, b];

  expect(deepEqual(left, right)).toBe(true);
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
