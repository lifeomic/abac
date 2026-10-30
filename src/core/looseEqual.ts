/* eslint-disable @typescript-eslint/no-explicit-any */

type Channel = Map<unknown, object | undefined>;

const tagOf = (value: unknown) => Object.prototype.toString.call(value);

const BOXED_BRANDS: [string, (value: unknown) => unknown][] = [
  ['String', (value) => String.prototype.valueOf.call(value)],
  ['Number', (value) => Number.prototype.valueOf.call(value)],
  ['Boolean', (value) => Boolean.prototype.valueOf.call(value)],
  ['Symbol', (value) => Symbol.prototype.valueOf.call(value)],
  ['BigInt', (value) => BigInt.prototype.valueOf.call(value)],
];

const boxedKind = (value: unknown) => {
  if (value === null || (typeof value !== 'object' && typeof value !== 'function')) {
    return null;
  }
  for (const [kind, valueOf] of BOXED_BRANDS) {
    try {
      valueOf(value);
      return kind;
    } catch (error) {
      // not this kind of boxed primitive
    }
  }
  return undefined;
};

const typedArrayKind = (value: unknown) =>
  ArrayBuffer.isView(value) && tagOf(value) !== '[object DataView]' && tagOf(value);

const isBuffer = (value: any) =>
  typeof value.length === 'number' &&
  typeof value.copy === 'function' &&
  typeof value.slice === 'function' &&
  !(value.length > 0 && typeof value[0] !== 'number') &&
  !!value.constructor?.isBuffer?.(value);

const bytesEqual = (a: ArrayLike<number>, b: ArrayLike<number>) => {
  if (a.length !== b.length) {
    return false;
  }
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) {
      return false;
    }
  }
  return true;
};

const looseAlternative = (primitive: unknown) => {
  if (typeof primitive === 'undefined') return null;
  if (typeof primitive === 'object') return undefined;
  if (typeof primitive === 'symbol') return false;
  if (typeof primitive === 'string' || typeof primitive === 'number') return +primitive === +primitive;
  return true;
};

const takeEqualElement = (pending: Set<unknown>, value: unknown, channel: Channel) => {
  for (const candidate of pending) {
    if (equal(value, candidate, channel)) {
      pending.delete(candidate);
      return true;
    }
  }
  return false;
};

const takeEqualEntry = (
  pending: Set<unknown>,
  map: Map<unknown, unknown>,
  key: unknown,
  item: unknown,
  channel: Channel,
) => {
  for (const candidate of pending) {
    if (equal(key, candidate, channel) && equal(item, map.get(candidate), channel)) {
      pending.delete(candidate);
      return true;
    }
  }
  return false;
};

const setMightHaveLooseValue = (a: Set<unknown>, b: Set<unknown>, value: unknown) => {
  const alternative = looseAlternative(value);
  if (alternative !== null && alternative !== undefined) {
    return alternative;
  }
  return b.has(alternative) && !a.has(alternative);
};

const setsEqual = (a: Set<unknown>, b: Set<unknown>, channel: Channel) => {
  if (a.size !== b.size) {
    return false;
  }
  const pending = new Set<unknown>();
  for (const value of a) {
    if (value && typeof value === 'object') {
      pending.add(value);
    } else if (!b.has(value)) {
      if (!setMightHaveLooseValue(a, b, value)) {
        return false;
      }
      pending.add(value);
    }
  }
  if (pending.size === 0) {
    return true;
  }
  for (const value of b) {
    if (value && typeof value === 'object') {
      if (!takeEqualElement(pending, value, channel)) {
        return false;
      }
    } else if (!a.has(value) && !takeEqualElement(pending, value, channel)) {
      return false;
    }
  }
  return pending.size === 0;
};

const mapMightHaveLooseKey = (
  a: Map<unknown, unknown>,
  b: Map<unknown, unknown>,
  key: unknown,
  item: unknown,
  channel: Channel,
) => {
  const alternative = looseAlternative(key);
  if (alternative !== null && alternative !== undefined) {
    return alternative;
  }
  const other = b.get(alternative);
  if ((typeof other === 'undefined' && !b.has(alternative)) || !equal(item, other, channel)) {
    return false;
  }
  return !a.has(alternative) && equal(item, other, channel);
};

const mapsEqual = (a: Map<unknown, unknown>, b: Map<unknown, unknown>, channel: Channel) => {
  if (a.size !== b.size) {
    return false;
  }
  const pending = new Set<unknown>();
  for (const [key, item] of a) {
    if (key && typeof key === 'object') {
      pending.add(key);
    } else {
      const other = b.get(key);
      if ((typeof other === 'undefined' && !b.has(key)) || !equal(item, other, channel)) {
        if (!mapMightHaveLooseKey(a, b, key, item, channel)) {
          return false;
        }
        pending.add(key);
      }
    }
  }
  if (pending.size === 0) {
    return true;
  }
  for (const [key, item] of b) {
    if (key && typeof key === 'object') {
      if (!takeEqualEntry(pending, a, key, item, channel)) {
        return false;
      }
    } else if (
      (!a.has(key) || !equal(a.get(key), item, channel)) &&
      !takeEqualEntry(pending, a, key, item, channel)
    ) {
      return false;
    }
  }
  return pending.size === 0;
};

const objectsEqual = (a: any, b: any, channel: Channel): boolean => {
  if (typeof a !== typeof b) {
    return false;
  }

  const tag = tagOf(a);
  if (tag !== tagOf(b) || Array.isArray(a) !== Array.isArray(b)) {
    return false;
  }

  const aIsError = a instanceof Error;
  if (aIsError !== b instanceof Error || (aIsError && (a.name !== b.name || a.message !== b.message))) {
    return false;
  }

  if (tag === '[object RegExp]' && (a.source !== b.source || a.flags !== b.flags)) {
    return false;
  }

  if (tag === '[object Date]' && Date.prototype.getTime.call(a) !== Date.prototype.getTime.call(b)) {
    return false;
  }

  const aTypedArray = typedArrayKind(a);
  if (aTypedArray !== typedArrayKind(b)) {
    return false;
  }
  if (aTypedArray) {
    return bytesEqual(a as ArrayLike<number>, b as ArrayLike<number>);
  }

  const aIsBuffer = isBuffer(a);
  if (aIsBuffer !== isBuffer(b)) {
    return false;
  }
  if (aIsBuffer) {
    return bytesEqual(a as ArrayLike<number>, b as ArrayLike<number>);
  }

  if (tag === '[object ArrayBuffer]' || tag === '[object SharedArrayBuffer]') {
    return bytesEqual(new Uint8Array(a as ArrayBuffer), new Uint8Array(b as ArrayBuffer));
  }

  const aKeys = Object.keys(a as object).sort();
  const bKeys = Object.keys(b as object).sort();
  if (aKeys.length !== bKeys.length) {
    return false;
  }
  for (let i = aKeys.length - 1; i >= 0; i--) {
    if (aKeys[i] !== bKeys[i]) {
      return false;
    }
  }
  for (let i = aKeys.length - 1; i >= 0; i--) {
    if (!equal(a[aKeys[i]], b[aKeys[i]], channel)) {
      return false;
    }
  }

  if (tag === '[object Set]') {
    return setsEqual(a as Set<unknown>, b as Set<unknown>, channel);
  }
  if (tag === '[object Map]') {
    return mapsEqual(a as Map<unknown, unknown>, b as Map<unknown, unknown>, channel);
  }
  return true;
};

const equal = (a: any, b: any, channel: Channel): boolean => {
  if (a === b) {
    return true;
  }

  if (boxedKind(a) !== boxedKind(b)) {
    return false;
  }

  if (!a || !b || (typeof a !== 'object' && typeof b !== 'object')) {
    // eslint-disable-next-line eqeqeq
    return a == b;
  }

  const hasA = channel.has(a);
  const hasB = channel.has(b);
  let sentinel: object | undefined;
  if (hasA && hasB) {
    if (channel.get(a) === channel.get(b)) {
      return true;
    }
  } else {
    sentinel = {};
  }
  if (!hasA) channel.set(a, sentinel);
  if (!hasB) channel.set(b, sentinel);

  return objectsEqual(a, b, channel);
};

/**
 * A port of the default (non-strict) comparison in `deep-equal@2.2.3`, the
 * version `@lifeomic/abac` 5.0.0 resolves for `equals` and `notEquals`.
 * Primitives use `==`; objects must share a `toString` tag, boxed-primitive
 * kind, and own enumerable keys; Errors, RegExps, Dates, typed arrays, buffers,
 * Sets, and Maps also compare their contents. Prototypes are ignored. Previously seen pairs short-circuit
 * through the same memo deep-equal uses, so cycles terminate.
 */
export const looseEqual = (a: unknown, b: unknown): boolean => equal(a, b, new Map());
