const cloneValue = (value: unknown, refs: Map<unknown, unknown>): unknown => {
  const cloned = refs.get(value);
  if (cloned) return cloned;

  if (Array.isArray(value)) {
    const clone: unknown[] = [];
    refs.set(value, clone);
    for (let i = 0; i < value.length; i++) {
      clone[i] = cloneValue(value[i], refs);
    }
    return clone;
  }

  if (value instanceof Date) return new Date(value.valueOf());
  if (!(value instanceof Object)) return value;

  const clone: Record<string, unknown> = {};
  refs.set(value, clone);
  const keys = Object.keys(value);
  for (let i = 0; i < keys.length; i++) {
    clone[keys[i]] = cloneValue((value as Record<string, unknown>)[keys[i]], refs);
  }
  return clone;
};

/**
 * A port of `deep-clone@3.0.3`, which `@lifeomic/abac` 5.0.0 used to copy
 * rules and attributes. Arrays and local Dates are copied; any other value
 * that is not `instanceof Object` (primitives, null-prototype objects, and
 * objects from another realm) is returned as is; everything else, including
 * functions, Sets, Maps, and typed arrays, becomes a plain object of its own
 * enumerable string keys. Dates are not memoized, so a shared Date is copied
 * once per reference.
 */
export const deepClone = <T>(value: T): T => cloneValue(value, new Map()) as T;
