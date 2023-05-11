import * as schemas from './schemas';
import Ajv from 'ajv';
import equals from 'fast-deep-equal';
import cloneDeep from 'lodash.clonedeep';

const ajv = new Ajv({
  schemas: Object.values(schemas),
});

export type AbacRuleComparison =
  | {
      comparison:
        | 'superset'
        | 'subset'
        | 'in'
        | 'notIn'
        | 'equals'
        | 'notEquals';
      value: (string | number)[];
      target?: undefined;
    }
  | {
      comparison: 'includes' | 'notIncludes' | 'equals' | 'notEquals';
      value: number | string;
      target?: undefined;
    }
  | {
      comparison: 'startsWith' | 'prefixOf' | 'suffixOf' | 'endsWith';
      value?: string;
      target?: string;
    }
  | {
      comparison: 'equals' | 'notEquals';
      value: boolean;
      target?: undefined;
    }
  | {
      comparison:
        | 'superset'
        | 'subset'
        | 'in'
        | 'equals'
        | 'includes'
        | 'notIncludes'
        | 'notEquals'
        | 'notIn';
      value?: undefined;
      target: string;
    }
  | {
      comparison: Omit<
        | 'superset'
        | 'subset'
        | 'in'
        | 'equals'
        | 'includes'
        | 'notIncludes'
        | 'notEquals'
        | 'notIn'
        | 'startsWith'
        | 'prefixOf'
        | 'endsWith'
        | 'suffixOf',
        string
      >;
      value?: undefined;
      target?: undefined;
    }
  | {
      comparison: 'exists';
      value?: string;
      target?: undefined;
    };

export type AbacRule = Record<string, AbacRuleComparison | undefined>;

export interface AbacPolicy {
  rules: Record<string, AbacRule[] | undefined>;
}

export interface AbacReducedPolicy {
  rules: Record<string, AbacRule[] | boolean | undefined>;
}

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
  condition?: AbacRuleComparison,
  attributes?: Record<string, any>
) => {
  const noOp = {
    pathToCheck,
    condition,
  };

  if (
    !condition?.target ||
    TARGETLESS_COMPARISON_OPERATORS.includes(condition.comparison)
  ) {
    return noOp;
  }

  const originalPathToCheckValue = getAttribute(attributes, pathToCheck);
  const originalTargetValue = getAttribute(attributes, condition.target);

  if (originalPathToCheckValue && originalTargetValue === undefined) {
    return {
      pathToCheck: condition.target,
      condition: {
        comparison: COMPARISON_REVERSION_MAP[condition.comparison],
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
  policy: Record<string, any>
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
 * @param {object} policy the value to validate.
 * @returns {boolean} true if the value is valid based on specified schema.
 * @throws Error if the value is invalid based on the specified schema.
 */
export const validate = (policy: AbacPolicy | AbacReducedPolicy): true =>
  validateJsonSchema('Policy', policy);

/**
 * Merge multiple policies into a single policy with the same effect.
 *
 * @param {Array[AbacReducedPolicy]} policies array of policies to merge
 * @returns {AbacReducedPolicy} the merged policy
 * @throws {Error} if any of the policies is invalid
 */
export const merge = (policies: AbacReducedPolicy[]): AbacReducedPolicy => {
  const result: AbacReducedPolicy['rules'] = {};

  for (const policy of policies) {
    validate(policy);
    Object.entries(policy.rules).forEach(([operation, rules]) => {
      if (rules === true || !rules) {
        result[operation] = !!rules;
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
  attribute: string
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
 *
 * @param attributes attributes as nested objects
 * @param {array[string]} path array of path segments
 */
const getAttributeValues = (attributes: any, path: string[]): any[] => {
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
        const result = getAttributeValues(attributes[key], path.slice(1));

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
        path.slice(1)
      );
    default:
      const unescapedName = name.replace(/^%%/, '%');
      return getAttributeValues(attributes[unescapedName], path.slice(1));
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
  path: string
) => {
  const name = path.split('.');
  return getAttributeValues(attributes, name)[0];
};

const getCompareValue = (
  condition: AbacRuleComparison,
  attributes?: Record<string, any>
) => {
  if ('target' in condition) {
    return getAttribute(attributes, condition.target as string);
  }
  return condition.value;
};

/**
 * @returns `true` if the comparision matches, `false` if there is a mismatch,
 *           and `undefined` if the target value is not known to compute the
 *           result.
 */
const compare = (
  condition: AbacRuleComparison | undefined,
  value?: any,
  attributes?: Record<string, any>
): boolean | undefined => {
  if (!condition) {
    return false;
  }
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
      return equals(value, compareValue);

    case 'exists':
      return value !== undefined;

    case 'notEquals':
      return !equals(value, compareValue);

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
  inlineTargets?: string[]
): AbacRule | boolean => {
  const result: AbacRule = {};

  for (const [pathToCheck, condition] of Object.entries(cloneDeep(rule))) {
    const { pathToCheck: newPathToCheck, condition: newCondition } =
      maybeReverseCondition(pathToCheck, condition, attributes);

    // When we already know the value of the target, we replace it with an
    // in-line value (if configured in inline targets).
    if (
      newCondition?.target &&
      inlineTargets &&
      inlineTargets.some((inlineTarget) =>
        // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
        isSubpath(newCondition!.target as string, inlineTarget)
      )
    ) {
      const inLineTargetValue = getAttribute(attributes, newCondition.target);

      if (inLineTargetValue) {
        // @ts-ignore-error
        newCondition.value = inLineTargetValue;
        // @ts-ignore-error
        delete condition.target;
      }
    }

    const values = getAttributeValues(attributes, newPathToCheck.split('.'));

    if (values.length === 0) {
      result[newPathToCheck] = condition;
    } else {
      for (const value of values) {
        const compareResult = compare(condition, value, attributes);

        if (compareResult === undefined) {
          result[newPathToCheck] = condition;
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
  rules: AbacRule[] | boolean | undefined,
  attributes?: Record<string, any>,
  inlineTargets?: string[]
) => {
  const attributesClone = cloneDeep(attributes);

  const result: AbacRule[] = [];

  if (rules === true || rules === false) {
    return rules;
  } else if (rules === undefined) {
    return false;
  }

  for (const rule of cloneDeep(rules)) {
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
 * @returns {object} the policy reduced to conditions involving attributes not
 * not given
 * @throws {Error} if the policy is invalid
 */
export const reduce = (
  policy: AbacReducedPolicy,
  attributes?: Record<string, any>,
  options: { inlineTargets?: string[] } = {}
): AbacReducedPolicy => {
  validate(policy);
  validateJsonSchema('ReduceOptions', options);

  const result: AbacReducedPolicy['rules'] = {};

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
 * @param {AbacReducedPolicy} policy the policy to use to check access
 * @param {object} attributes the attributes to use to check access
 * @returns {boolean} true iff access is allowed, and false otherwise
 * @throws {Error} Error if the policy is invalid
 */
export const enforce = (
  operationName: string,
  policy: AbacReducedPolicy,
  attributes?: Record<string, any>
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
 * @param {AbacReducedPolicy} policy the policy to use to check access
 * @param {object} attributes the attributes to use to check access
 * @returns {boolean} true iff access is allowed, and false otherwise
 * @throws {Error} Error if the policy is invalid
 */
export const enforceLenient = (
  operationName: string,
  policy: AbacReducedPolicy,
  attributes?: Record<string, any>
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
  policy: AbacReducedPolicy,
  attributes?: Record<string, any>
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
 * @param {AbacReducedPolicy} policy the policy to use to check access
 * @param {object} attributes the attributes to use to check access
 * @returns {string[]} - the list of privileges
 * @throws {Error} Error if the policy is invalid
 */
export const privileges = (
  policy: AbacReducedPolicy,
  attributes?: Record<string, any>
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
 * @param {AbacReducedPolicy} attributes the attributes to use to check access
 * @returns {string[]} - the list of privileges
 * @throws {Error} Error if the policy is invalid
 */
export const privilegesLenient = (
  policy: AbacReducedPolicy,
  attributes?: Record<string, any>
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
  policy: AbacReducedPolicy,
  attribute: string
): boolean => {
  const rules = Object.values(policy.rules)
    .filter((rule): rule is AbacRule[] => Array.isArray(rule))
    .reduce((left, right) => left.concat(right), []);

  for (const rule of rules) {
    for (const key in rule) {
      if (isPathPrefix(attribute, key)) {
        return true;
      }
      const target = rule[key]?.target;
      if (target && isPathPrefix(attribute, target)) {
        return true;
      }
    }
  }
  return false;
};
