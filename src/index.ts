import * as schemas from './schemas';
import Ajv from 'ajv';
import deepEqual from 'deep-equal';
import deepClone from 'deep-clone';
import type { AbacComparison, AbacPolicy, AbacRule, AbacReduceOptions } from './schemas';
export type * from './schemas';

const ajv = new Ajv({
  schemas: Object.values(schemas),
});

export const COMPARISON_REVERSION_MAP = {
  endsWith: 'suffixOf',
  equals: 'equals',
  in: 'includes',
  includes: 'in',
  notEquals: 'notEquals',
  notIn: 'notIncludes',
  notIncludes: 'notIn',
  prefixOf: 'startsWith',
  startsWith: 'prefixOf',
  subset: 'superset',
  suffixOf: 'endsWith',
  superset: 'subset',
} as const;

const TARGETLESS_COMPARISON_OPERATORS = ['exists'];

const isString = (value: any): value is string =>
  typeof value === 'string' || value instanceof String;

// We reverse conditions when we have a known "key" value and an unknown
// "target" value.
const maybeReverseCondition = (
  pathToCheck: string,
  condition: AbacComparison,
  attributes?: Record<string, any>,
): { condition: AbacComparison; pathToCheck: string; } => {
  const noOp = {
    pathToCheck,
    condition,
  };

  if (
    !condition?.target ||
    TARGETLESS_COMPARISON_OPERATORS.includes(condition.comparison as string)
  ) {
    return noOp;
  }

  const originalPathToCheckValue = getAttribute(attributes, pathToCheck);
  const originalTargetValue = getAttribute(attributes, condition.target as string);

  if (
    originalPathToCheckValue !== undefined &&
    originalTargetValue === undefined
  ) {
    return {
      pathToCheck: condition.target,
      condition: {
        comparison: COMPARISON_REVERSION_MAP[condition.comparison as any as keyof typeof COMPARISON_REVERSION_MAP],
        target: pathToCheck,
      },
    };
  }

  return noOp;
};

/**
 * Validate value with AJV.
 *
 * @param {string} schemaName the name of the JSON schema to use for validation.
 * @param {AbacPolicy} policy the value to validate.
 * @returns {boolean} true if the value is valid based on specified schema.
 * @throws Error if the value is invalid based on the specified schema.
 */
const validateJsonSchema = (
  schemaName: string,
  policy: Record<string, any>,
): true => {
  const valid = ajv.validate(schemaName, policy) as boolean;

  if (!valid) {
    throw new Error(ajv.errorsText());
  }

  return valid;
};

/**
 * Validate value with AJV, and the Policy schema.
 *
 * @param {AbacPolicy} policy the value to validate.
 * @returns {boolean} true if the value is valid based on specified schema.
 * @throws Error if the value is invalid based on the specified schema.
 */
export const validate = (policy: AbacPolicy): true =>
  validateJsonSchema('Policy', policy);

/**
 * Merge multiple policies into a single policy with the same effect.
 *
 * @param {Array[AbacPolicy]} policies array of policies to merge
 * @returns {AbacPolicy} the merged policy
 * @throws {Error} if any of the policies is invalid
 */
export const merge = (policies: AbacPolicy[]): AbacPolicy => {
  const result: AbacPolicy['rules'] = {};

  for (const policy of policies) {
    validate(policy);
    Object.entries(policy.rules).forEach(([operation, rules]) => {
      if (!Array.isArray(rules)) {
        result[operation] = rules;
      } else if (result[operation]) {
        if (result[operation] !== true) {
          (result[operation] as AbacRule[]).push(...rules);
        }
      } else {
        result[operation] = [...rules];
      }
    });
  }

  return { rules: result };
};

// returns an array of values for each instance of the attribute under the given privileges
export const extract = (
  policy: AbacPolicy,
  privileges: string[],
  attribute: string,
) => {
  validate(policy);
  const comparisons = Object.entries(policy.rules)
    .map(([operation, rules]) => {
      if (Array.isArray(rules) && privileges.includes(operation)) {
        return rules.map((rule) => rule[attribute]).filter(Boolean);
      }
    })
    .filter(Boolean);
  return comparisons.flat(1);
};

/**
 * Get a list of all values matching the path (including wildcards).
 */
const getAttributeValues = (
  attributes: Record<string, any> | null | undefined,
  path: string[],
): any[] => {
  if (attributes === undefined || attributes === null) {
    return [];
  }

  if (path.length === 0) {
    return [attributes];
  }

  const name = path[0];

  switch (name) {
    case '*':
      const keys = Object.keys(attributes as Record<string, any>);
      let values: Record<string, string>[] = [];

      for (const key of keys) {
        const result = getAttributeValues(
          attributes[key] as Record<string, any>,
          path.slice(1),
        );

        // If a single sub-path fails to evaluate fail the entire traversal.
        if (result.length === 0) {
          values = [];
          break;
        } else {
          values = values.concat(result);
        }
      }

      return values;
    case '%keys':
      return getAttributeValues(
        Object.keys(attributes as Record<string, any>),
        path.slice(1),
      );
    default:
      const unescapedName = name.replace(/^%%/, '%');
      return getAttributeValues(
        attributes[unescapedName] as Record<string, any>,
        path.slice(1),
      );
  }
};

/**
 * Get the attribute value identified by path.
 *
 * @param {object} attributes attributes as nested objects
 * @param {string} path string path (e.g. 'user.groups')
 */
const getAttribute = (
  attributes: Record<string, any> | undefined,
  path: string,
) => {
  const name = path.split('.');
  return getAttributeValues(attributes, name)[0];
};

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
const compare = (
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

const isSubpath = (compare: string, subject: string) => {
  const subpaths = subject.split('.');
  const superpathPortion = compare.split('.').slice(0, subpaths.length);

  return subject === superpathPortion.join('.');
};

const reduceRule = (
  rule: AbacRule,
  attributes?: Record<string, any>,
  inlineTargets?: string[],
): AbacRule | boolean => {
  const result: AbacRule = {};

  for (const [key, value] of Object.entries(deepClone(rule))) {
    const { pathToCheck, condition } = maybeReverseCondition(
      key,
      value,
      attributes,
    );

    // When we already know the value of the target, we replace it with an
    // in-line value (if configured in inline targets).
    if (
      condition?.target &&
      inlineTargets &&
      inlineTargets.some((inlineTarget) =>
        isSubpath(condition.target as string, inlineTarget),
      )
    ) {
      const inLineTargetValue = getAttribute(attributes, condition.target as string);

      if (inLineTargetValue) {
        condition.value = inLineTargetValue;
        delete condition.target;
      }
    }

    const values = getAttributeValues(attributes, pathToCheck.split('.'));

    if (values.length === 0) {
      result[pathToCheck] = condition;
    } else {
      for (const value of values) {
        const compareResult = compare(condition, value, attributes);

        if (compareResult === undefined) {
          result[pathToCheck] = condition;
          break;
        } else if (compareResult === false) {
          return false;
        }
      }
    }
  }

  if (Object.keys(result).length === 0) {
    return true;
  }

  return result;
};

const reduceRules = (
  rules: AbacRule[] | boolean,
  attributes?: Record<string, any>,
  inlineTargets?: string[],
) => {
  const attributesClone = deepClone(attributes);

  const result: AbacRule[] = [];

  if (rules === true || rules === false) {
    return rules;
  }

  for (const rule of deepClone(rules)) {
    const reducedRule = reduceRule(rule, attributesClone, inlineTargets);

    if (reducedRule === true) {
      return true;
    } else if (reducedRule) {
      result.push(reducedRule);
    }
  }

  return result;
};

/**
 * Performs a synchronous reduction for whether the given policy might
 * allow the operations. This function's intended use is for client applications
 * that need a simple check to disable or annotate UI elements.
 *
 * When a rule where the "key" is known and the "target" is unknown, a
 * reversion and in-line replacement will occur so the policy can be
 * evaluated immediately without consumers needing to be aware of the
 * target attributes.
 *
 * @param {object} policy the policy to evaluate
 * @param {object} attributes the attributes to use for the evaluation
 * @param {object} options optional function config
 * @param {array} options.inlineTargets optional list of attribute paths that
 * should be eagerly evaluated when reducing the policy. Eager evaluation makes
 * sure that a rule with a known target will be inverted and replaced with the
 * known value in-line.
 * @returns {object} the policy reduced to conditions involving attributes not given
 * @throws {Error} if the policy is invalid
 */
export const reduce = (
  policy: AbacPolicy,
  attributes?: Record<string, any>,
  options: AbacReduceOptions = {},
): AbacPolicy => {
  validate(policy);
  validateJsonSchema('ReduceOptions', options);

  const result: AbacPolicy['rules'] = {};

  Object.entries(policy.rules).forEach(([operation, rules]) => {
    const newRules = reduceRules(rules, attributes, options.inlineTargets);

    if (newRules === true || (Array.isArray(newRules) && newRules.length > 0)) {
      result[operation] = newRules;
    }
  });

  return { rules: result };
};

/**
 * Check whether the given policy allows the operation with the given attributes.
 *
 * @param {string} operationName the requested operation
 * @param {AbacPolicy} policy the policy to use to check access
 * @param {object} attributes the attributes to use to check access
 * @returns {boolean} true iff access is allowed, and false otherwise
 * @throws {Error} Error if the policy is invalid
 */
export const enforce = (
  operationName: string,
  policy: AbacPolicy,
  attributes?: Record<string, any>,
): boolean => {
  try {
    // Before using the policy, make sure it's valid
    validate(policy);
  } catch (error) {
    return false;
  }

  const rules =
    policy.rules && policy.rules[operationName]
      ? policy.rules[operationName]
      : [];
  return reduceRules(rules, attributes) === true;
};

/**
 * Performs a check for whether the given policy might
 * allow the operation.  This function's intended use is for
 * client applications that need a simple check to disable
 * or annotate UI elements. If a rule has not been completely
 * reduced for given operation then this function will assume
 * `true` for the policy evaluation (not safe for server-side
 * enforcement of ABAC policy!).
 *
 * @param {string} operationName the requested operation
 * @param {AbacPolicy} policy the policy to use to check access
 * @param {object} attributes the attributes to use to check access
 * @returns {boolean} true iff access is allowed, and false otherwise
 * @throws {Error} Error if the policy is invalid
 */
export const enforceLenient = (
  operationName: string,
  policy: AbacPolicy,
  attributes?: Record<string, any>,
): boolean => {
  try {
    // Before using the policy, make sure it's valid
    validate(policy);
  } catch (error) {
    return false;
  }

  const rules =
    policy.rules && policy.rules[operationName]
      ? policy.rules[operationName]
      : [];
  const reducedRules = reduceRules(rules, attributes);
  return reducedRules && (reducedRules === true || reducedRules.length > 0);
};

/**
 * Check whether the given policy allows one of a list of operations
 * with the given attributes.
 *
 * @param {string[]} operationNames the requested operations
 * @param {object} policy the policy to use to check access
 * @param {object} attributes the attributes to use to check access
 * @returns {boolean|string} - the first allowed operation or false
 * @throws {Error} Error if the policy is invalid
 */
export const enforceAny = (
  operationNames: string[],
  policy: AbacPolicy,
  attributes?: Record<string, any>,
): boolean | string => {
  for (const operation of operationNames) {
    if (enforce(operation, policy, attributes)) {
      return operation;
    }
  }

  return false;
};

/**
 * Return the list of privileges that the given policy
 * allows against the given attributes.
 *
 * @param {AbacPolicy} policy the policy to use to check access
 * @param {object} attributes the attributes to use to check access
 * @returns {string[]} - the list of privileges
 * @throws {Error} Error if the policy is invalid
 */
export const privileges = (
  policy: AbacPolicy,
  attributes?: Record<string, any>,
): string[] => {
  const rules = reduce(policy, attributes).rules;
  return Object.entries(rules)
    .filter(([, rules]) => rules === true)
    .map(([privilege]) => privilege);
};

/**
 * Synchronously return the list of privileges that the given policy
 * might allow against the given attributes. This function's intended use is for
 * client applications that need a simple check to disable
 * or annotate UI elements. Not safe for server-side!
 *
 * @param {object} policy the policy to use to check access
 * @param {AbacPolicy} attributes the attributes to use to check access
 * @returns {string[]} - the list of privileges
 * @throws {Error} Error if the policy is invalid
 */
export const privilegesLenient = (
  policy: AbacPolicy,
  attributes?: Record<string, any>,
): string[] => {
  const rules = reduce(policy, attributes).rules;
  return Object.entries(rules).map(([privilege]) => privilege);
};

/**
 * Return true iff left is a path prefix of right
 */
const isPathPrefix = (left: string, right: string) => {
  const lhs = left.split('.');
  const rhs = right.split('.');

  if (lhs.length > rhs.length) {
    return false;
  }

  for (let i = 0; i < lhs.length; ++i) {
    if (lhs[i] !== rhs[i]) {
      return false;
    }
  }

  return true;
};

/**
 * Synchronously determines if a given attribute path is used in the rules
 * for a given policy. This may be useful for determining if additional metadata
 * should be fetched before enforcing a policy.
 *
 * @param {object} policy the policy to check
 * @param {string} attribute the attribute path, e.g. 'user.patients'
 * @returns {boolean} True if the attribute is in the rules list
 */
export const policyRequiresAttribute = (
  policy: AbacPolicy,
  attribute: string,
): boolean => {
  const rules = Object.values(policy.rules)
    .filter((rule): rule is AbacRule[] => Array.isArray(rule))
    .reduce((left, right) => left.concat(right), []);

  for (const rule of rules) {
    for (const key in rule) {
      if (isPathPrefix(attribute, key)) {
        return true;
      }
      const target = rule[key]?.target as string;
      if (target && isPathPrefix(attribute, target)) {
        return true;
      }
    }
  }
  return false;
};
