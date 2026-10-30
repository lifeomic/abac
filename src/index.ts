import type { AbacPolicy, AbacReduceOptions, AbacRule } from './schemas';
import { isPathPrefix } from './core/attributes';
import { reduceRules } from './core/reduce';
import { validate, validateJsonSchema } from './validation';

export type * from './schemas';
export { COMPARISON_REVERSION_MAP } from './core/reduce';
export { validate } from './validation';

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
