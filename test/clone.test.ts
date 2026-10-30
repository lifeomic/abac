import vm from 'node:vm';

import oracle from 'deep-clone';

import { mulberry32 } from '../scripts/compat/cases.cjs';
import { deepClone } from '../src/core/clone';

type Clone = (value: unknown) => unknown;
type Log = { active: boolean; events: string[] };

const SEED = Number(process.env.ABAC_COMPAT_SEED ?? 0xabac);
const CASES = Number(process.env.ABAC_CLONE_CASES ?? 20000);
const SYMBOLS = [Symbol('a'), Symbol.iterator];
const foreign = <T>(source: string): T => vm.runInNewContext(source) as T;

class Point {
  constructor(public x: number) {}
  get double() {
    return this.x * 2;
  }
}
class LaterDate extends Date {}

const createValue = (seed: number, log: Log) => {
  const random = mulberry32(seed);
  const int = (max: number) => Math.floor(random() * max);
  const pick = <T>(items: readonly T[]): T => items[int(items.length)];
  const record = (event: string) => {
    if (log.active) log.events.push(event);
  };
  const pool: object[] = [];
  const share = <T extends object>(value: T): T => {
    pool.push(value);
    return value;
  };

  const primitive = () => pick([0, -0, 1, NaN, '', 'a', '1', true, false, null, undefined, 1n, ...SYMBOLS]);

  const node = (depth: number, ancestors: object[]): unknown => {
    const child = () => node(depth + 1, ancestors);
    if (depth > 3) return primitive();
    if (pool.length > 0 && random() < 0.08) return pick(pool);
    if (ancestors.length > 0 && random() < 0.04) return pick(ancestors);

    const container = <T extends object>(value: T, fill: (value: T) => void): T => {
      share(value);
      ancestors.push(value);
      fill(value);
      ancestors.pop();
      return value;
    };
    const fillKeys = (target: Record<string, unknown>) => {
      for (let i = int(4); i > 0; i--) target[pick(['a', 'b', '2', '1', 'length', 'constructor'])] = child();
    };

    switch (int(24)) {
      case 0:
      case 1:
        return primitive();
      case 2:
      case 3:
        return container({} as Record<string, unknown>, fillKeys);
      case 4:
        return container([] as unknown[], (array) => {
          for (let i = int(4); i > 0; i--) array.push(child());
        });
      case 5:
        return container([] as unknown[], (array) => {
          array[int(3) + 1] = child();
          if (random() < 0.5) (array as unknown as Record<string, unknown>).extra = child();
        });
      case 6:
        return share(pick([new Date(0), new Date(NaN), new LaterDate(5)]));
      case 7: {
        const date = new Date(7);
        date.valueOf = () => {
          record('valueOf');
          return 9;
        };
        return share(date);
      }
      case 8:
        return container(Object.create(null) as Record<string, unknown>, fillKeys);
      case 9:
        return share(
          pick([
            () => foreign<object>('({ a: 1, b: [2] })'),
            () => foreign<object>('[1, { a: 2 }]'),
            () => foreign<object>('new Date(3)'),
            () => foreign<object>('(function f() {})'),
          ])(),
        );
      case 10:
        return container(Object.assign(() => 1, { a: 1 }), (fn) => {
          (fn as unknown as Record<string, unknown>).b = child();
        });
      case 11:
        return share(
          pick([
            () => new Set([1, 2]),
            () => new Map([[1, 2]]),
            () => /a/g,
            () => new Error('e'),
            () => new Uint8Array([1, 2]),
            () => Buffer.from([3]),
            () => new Number(1),
            () => new String('ab'),
            () => new WeakMap(),
          ])(),
        );
      case 12:
        return share(new Point(int(3)));
      case 13:
        return container({ [pick(SYMBOLS)]: 1, a: 1 } as Record<string, unknown>, (target) => {
          Object.defineProperty(target, 'hidden', { value: child(), enumerable: false });
        });
      case 14:
        return container({} as Record<string, unknown>, (target) => {
          fillKeys(target);
          const value = child();
          Object.defineProperty(target, pick(['a', 'b']), {
            enumerable: true,
            get: () => {
              record('get');
              return value;
            },
          });
        });
      case 15:
        return share(
          Object.defineProperty({}, 'a', {
            enumerable: true,
            get: () => {
              record('get throws');
              throw new RangeError('getter');
            },
          }),
        );
      case 16:
        return container(JSON.parse(pick(['{"__proto__": {"a": 1}}', '{"__proto__": 1, "b": 2}', '{"__proto__": [1]}'])), () => {});
      case 17:
      case 18: {
        const target = node(depth + 1, ancestors);
        if (target === null || typeof target !== 'object') return target;
        return share(
          new Proxy(target, {
            get: (object, key, receiver) => {
              record(`get ${String(key)}`);
              return Reflect.get(object, key, receiver) as unknown;
            },
            ownKeys: (object) => {
              record('ownKeys');
              return Reflect.ownKeys(object);
            },
            getOwnPropertyDescriptor: (object, key) => {
              record(`descriptor ${String(key)}`);
              return Reflect.getOwnPropertyDescriptor(object, key);
            },
          }),
        );
      }
      case 19:
        return share(Object.create(Date.prototype) as object);
      default:
        return container({ a: child(), b: [child(), child()] }, () => {});
    }
  };

  return node(0, []);
};

const inputIds = (value: unknown) => {
  const ids = new Map<unknown, number>();
  const visit = (item: unknown) => {
    if (item === null || (typeof item !== 'object' && typeof item !== 'function') || ids.has(item)) return;
    ids.set(item, ids.size);
    for (const key of Reflect.ownKeys(item)) {
      const descriptor = Reflect.getOwnPropertyDescriptor(item, key);
      if (descriptor && 'value' in descriptor) visit(descriptor.value);
    }
  };
  visit(value);
  return ids;
};

const describe = (output: unknown, inputs: Map<unknown, number>) => {
  const seen = new Map<unknown, number>();
  const prototypeName = (proto: unknown): unknown => {
    if (proto === null) return 'null';
    if (inputs.has(proto)) return `input ${inputs.get(proto)}`;
    for (const name of ['Object', 'Array', 'Date'] as const) {
      if (proto === globalThis[name].prototype) return name;
    }
    return visit(proto);
  };
  const visit = (item: unknown): unknown => {
    if (typeof item === 'symbol') return { symbol: SYMBOLS.indexOf(item) };
    if (typeof item === 'number') return { number: Object.is(item, -0) ? '-0' : String(item) };
    if (typeof item === 'bigint') return { bigint: String(item) };
    if (item === null || (typeof item !== 'object' && typeof item !== 'function')) return { [typeof item]: item };
    if (inputs.has(item)) return { input: inputs.get(item) };
    if (seen.has(item)) return { ref: seen.get(item) };
    seen.set(item, seen.size);
    const result: Record<string, unknown> = {
      id: seen.get(item),
      prototype: prototypeName(Object.getPrototypeOf(item)),
      keys: Reflect.ownKeys(item).map((key) => {
        const { value, get, set, ...flags } = Reflect.getOwnPropertyDescriptor(item, key)!;
        return [typeof key === 'symbol' ? { symbol: SYMBOLS.indexOf(key) } : key, flags, !!get, !!set, visit(value)];
      }),
    };
    if (item instanceof Date) result.time = String(Date.prototype.getTime.call(item));
    return result;
  };
  return visit(output);
};

const run = (clone: Clone, seed: number) => {
  const log: Log = { active: false, events: [] };
  const input = createValue(seed, log);
  const inputs = inputIds(input);
  log.active = true;
  try {
    const output = clone(input);
    log.active = false;
    return { events: log.events, output: describe(output, inputs) };
  } catch (error) {
    log.active = false;
    return { events: log.events, error: `${(error as Error).name}: ${(error as Error).message}` };
  }
};

const mismatches = (clone: Clone, count: number) => {
  const found: { seed: number; expected: unknown; actual: unknown }[] = [];
  for (let i = 0; i < count && found.length < 3; i++) {
    const seed = SEED + i;
    const expected = JSON.stringify(run(oracle, seed));
    const actual = JSON.stringify(run(clone, seed));
    if (expected !== actual) found.push({ seed, expected, actual });
  }
  return found;
};

test(`matches deep-clone@3.0.3 on ${CASES} generated values`, () => {
  expect(mismatches(deepClone, CASES)).toStrictEqual([]);
}, 120_000);

test('generates every outcome deep-clone can produce', () => {
  const runs = Array.from({ length: 2000 }, (_, i) => run(oracle, SEED + i));
  const text = runs.map((result) => JSON.stringify(result));
  expect(runs.some((result) => 'error' in result)).toBe(true);
  for (const marker of ['"input":', '"ref":', '"prototype":"Date"', '"prototype":"null"', '"prototype":{"id"', 'valueOf', 'get throws', 'ownKeys']) {
    expect({ marker, found: text.some((result) => result.includes(marker)) }).toStrictEqual({ marker, found: true });
  }
});

const dateLike = (value: unknown) => value instanceof Date;
const ownKeys = (value: object) => Object.keys(value);

test.each<[string, Clone]>([
  ['structuredClone', (value) => structuredClone(value)],
  ['JSON round-trip', (value) => JSON.parse(JSON.stringify(value) ?? 'null') as unknown],
  [
    'memoized Dates',
    (() => {
      const variant = (value: unknown, refs = new Map<unknown, unknown>()): unknown => {
        if (refs.has(value)) return refs.get(value);
        if (Array.isArray(value)) {
          const clone: unknown[] = [];
          refs.set(value, clone);
          for (let i = 0; i < value.length; i++) clone[i] = variant(value[i], refs);
          return clone;
        }
        if (dateLike(value)) {
          const clone = new Date((value as Date).valueOf());
          refs.set(value, clone);
          return clone;
        }
        if (!(value instanceof Object)) return value;
        const clone: Record<string, unknown> = {};
        refs.set(value, clone);
        for (const key of ownKeys(value)) clone[key] = variant((value as Record<string, unknown>)[key], refs);
        return clone;
      };
      return (value: unknown) => variant(value);
    })(),
  ],
  [
    'typeof instead of instanceof Object',
    (() => {
      const variant = (value: unknown, refs = new Map<unknown, unknown>()): unknown => {
        if (refs.get(value)) return refs.get(value);
        if (Array.isArray(value)) {
          const clone: unknown[] = [];
          refs.set(value, clone);
          for (let i = 0; i < value.length; i++) clone[i] = variant(value[i], refs);
          return clone;
        }
        if (dateLike(value)) return new Date((value as Date).valueOf());
        if (value === null || typeof value !== 'object') return value;
        const clone: Record<string, unknown> = {};
        refs.set(value, clone);
        for (const key of ownKeys(value)) clone[key] = variant((value as Record<string, unknown>)[key], refs);
        return clone;
      };
      return (value: unknown) => variant(value);
    })(),
  ],
  [
    'defineProperty instead of assignment',
    (() => {
      const variant = (value: unknown, refs = new Map<unknown, unknown>()): unknown => {
        if (refs.get(value)) return refs.get(value);
        if (Array.isArray(value)) {
          const clone: unknown[] = [];
          refs.set(value, clone);
          for (let i = 0; i < value.length; i++) clone[i] = variant(value[i], refs);
          return clone;
        }
        if (dateLike(value)) return new Date((value as Date).valueOf());
        if (!(value instanceof Object)) return value;
        const clone: Record<string, unknown> = {};
        refs.set(value, clone);
        for (const key of ownKeys(value)) {
          Object.defineProperty(clone, key, { value: variant((value as Record<string, unknown>)[key], refs), enumerable: true, writable: true, configurable: true });
        }
        return clone;
      };
      return (value: unknown) => variant(value);
    })(),
  ],
  [
    'Array.prototype.map, which skips holes',
    (() => {
      const variant = (value: unknown, refs = new Map<unknown, unknown>()): unknown => {
        if (refs.get(value)) return refs.get(value);
        if (Array.isArray(value)) {
          const clone = (value as unknown[]).map((item) => variant(item, refs));
          refs.set(value, clone);
          return clone;
        }
        return deepClone(value);
      };
      return (value: unknown) => variant(value);
    })(),
  ],
])('the differential test catches %s', (_, variant) => {
  expect(mismatches(variant, 2000).length).toBeGreaterThan(0);
});
