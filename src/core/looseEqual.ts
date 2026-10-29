const toTag = (value: object) => Object.prototype.toString.call(value);

const isObject = (value: unknown): value is Record<string, unknown> =>
  value !== null && typeof value === 'object';

const equal = (a: unknown, b: unknown, seen: unknown[]): boolean => {
  if (a === b) {
    return true;
  }

  if (!isObject(a) || !isObject(b)) {
    return (
      !isObject(a) &&
      !isObject(b) &&
      typeof a !== 'function' &&
      typeof b !== 'function' &&
      // eslint-disable-next-line eqeqeq
      a == b
    );
  }

  const tag = toTag(a);
  if (tag !== toTag(b)) {
    return false;
  }

  if (tag === '[object Date]' && (a as unknown as Date).getTime() !== (b as unknown as Date).getTime()) {
    return false;
  }

  for (let i = 0; i < seen.length; i += 2) {
    if (seen[i] === a && seen[i + 1] === b) {
      return true;
    }
  }

  const keys = Object.keys(a);
  if (keys.length !== Object.keys(b).length) {
    return false;
  }

  if (!keys.every((key) => Object.prototype.propertyIsEnumerable.call(b, key))) {
    return false;
  }

  seen.push(a, b);
  const result = keys.every((key) => equal(a[key], b[key], seen));
  seen.length -= 2;
  return result;
};

/**
 * Compare two values with the same semantics as `deep-equal@2` in its default
 * (non-strict) mode for every value `deep-clone` can produce: primitives use
 * `==`, objects must share a `toString` tag and own enumerable keys, Dates
 * compare by time, and prototypes are ignored.
 */
export const looseEqual = (a: unknown, b: unknown): boolean => equal(a, b, []);
