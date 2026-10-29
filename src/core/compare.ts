import deepEqual from 'deep-equal';

import type { AbacComparison } from '../schemas';
import { getAttribute } from './attributes';

const isString = (value: any): value is string =>
  typeof value === 'string' || value instanceof String;

const getCompareValue = (
  condition: AbacComparison,
  attributes?: Record<string, any>,
) => {
  if ('target' in condition) {
    return getAttribute(attributes, condition.target as string);
  }
  return condition.value;
};

/**
 * @returns `true` if the comparison matches, `false` if there is a mismatch,
 *           and `undefined` if the target value is not known to compute the
 *           result.
 */
export const compare = (
  condition: AbacComparison,
  value?: any,
  attributes?: Record<string, any>,
): boolean | undefined => {
  const compareValue = getCompareValue(condition, attributes);

  // "exists" can have an undefined value.
  if (compareValue === undefined && condition.comparison !== 'exists') {
    return undefined;
  }

  switch (condition.comparison) {
    case 'includes':
      return Array.isArray(value) && value.includes(compareValue as string);

    case 'in':
      return (
        Array.isArray(compareValue) && compareValue.includes(value as string)
      );

    case 'equals':
      return deepEqual(value, compareValue);

    case 'exists':
      return value !== undefined;

    case 'notEquals':
      return !deepEqual(value, compareValue);

    case 'notIn':
      return (
        Array.isArray(compareValue) && !compareValue.includes(value as string)
      );

    case 'notIncludes':
      return Array.isArray(value) && !value.includes(compareValue as string);

    case 'superset':
      return (
        Array.isArray(value) &&
        Array.isArray(compareValue) &&
        compareValue.every((x) => value.includes(x as string))
      );

    case 'subset':
      return (
        Array.isArray(value) &&
        Array.isArray(compareValue) &&
        value.every((x) => compareValue.includes(x))
      );

    case 'startsWith':
      return isString(value) && value.startsWith(compareValue as string);

    case 'prefixOf':
      return (
        isString(value) &&
        isString(compareValue) &&
        compareValue.startsWith(value)
      );

    case 'endsWith':
      return isString(value) && value.endsWith(compareValue as string);

    case 'suffixOf':
      return (
        isString(value) &&
        isString(compareValue) &&
        compareValue.endsWith(value)
      );

    default:
      // for unknown comparison types simply deny access:
      return false;
  }
};
