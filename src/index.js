'use strict';

import schemas from './schemas';
import Ajv from 'ajv';
import deprecate from 'util-deprecate';
import equals from 'fast-deep-equal';
import cloneDeep from 'lodash.clonedeep';
import curry from 'lodash.curry';

const ajv = new Ajv();

Object.entries(schemas).forEach(([key, schema]) => ajv.addSchema(schema, key));

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
};

const TARGETLESS_COMPARISON_OPERATORS = ['exists'];

const isString = (value) =>
  typeof value === 'string' || value instanceof String;

// We reverse conditions when we have a known "key" value and an unknown
// "target" value.
const maybeReverseCondition = (pathToCheck, condition, attributes) => {
  const noOp = {
    pathToCheck,
    condition,
  };

  if (
    !condition.target ||
    TARGETLESS_COMPARISON_OPERATORS.includes(condition.comparison)
  ) {
    return noOp;
  }

  const originalPathToCheckValue = getAttribute(attributes, pathToCheck);
  const originalTargetValue = getAttribute(attributes, condition.target);

  if (originalPathToCheckValue && !originalTargetValue) {
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
 * @param {object} value the value to validate.
 * @returns {boolean} true if the value is valid based on specified schema.
 * @throws Error if the the value is invalid based on the specified schema.
 */
const validateJsonSchema = curry((schemaName, value) => {
  const valid = ajv.validate(schemaName, value);

  if (!valid) {
    throw new Error(ajv.errorsText());
  }

  return valid;
});

const validate = validateJsonSchema('Policy');

/**
 * Merge multiple policies into a single policy with the same effect.
 *
 * @param {Array[object]} policies array of policies to merge
 * @returns {object} the merged policy
 * @throws {Error} if any of the policies is invalid
 */
const merge = (policies) => {
  const result = {};

  for (const policy of policies) {
    validate(policy);
    Object.entries(policy.rules).forEach(([operation, rules]) => {
      if (rules === true) {
        result[operation] = true;
      } else if (result[operation]) {
        if (result[operation] !== true) {
          result[operation].push(...rules);
        }
      } else {
        result[operation] = [...rules];
      }
    });
  }

  return { rules: result };
};

// returns an array of values for each instance of the attribute under the given privileges
const extract = (policy, privileges, attribute) => {
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
 * @param {object} attributes attributes as nested objects
 * @param {array} path array of path segments
 */
const getAttributeValues = (attributes, path) => {
  if (attributes === undefined || attributes === null) {
    return [];
  }

  if (path.length === 0) {
    return [attributes];
  }

  const name = path[0];

  switch (name) {
    case '*':
      const keys = Object.keys(attributes);
      let values = [];

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
      return getAttributeValues(Object.keys(attributes), path.slice(1));
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
const getAttribute = (attributes, name) => {
  const path = name.split('.');
  return getAttributeValues(attributes, path)[0];
};

const getCompareValue = (condition, attributes) => {
  if ('target' in condition) {
    return getAttribute(attributes, condition.target);
  }
  return condition.value;
};

/**
 * @returns `true` if the comparision matches, `false` if there is a mismatch,
 *           and `undefined` if the target value is not known to compute the
 *           result.
 */
const compare = (condition, value, attributes) => {
  const compareValue = getCompareValue(condition, attributes);

  // "exists" can have an undefined value.
  if (compareValue === undefined && condition.comparison !== 'exists') {
    return undefined;
  }

  switch (condition.comparison) {
    case 'includes':
      return Array.isArray(value) && value.includes(compareValue);

    case 'in':
      return Array.isArray(compareValue) && compareValue.includes(value);

    case 'equals':
      return equals(value, compareValue);

    case 'exists':
      return value !== undefined;

    case 'notEquals':
      return !equals(value, compareValue);

    case 'notIn':
      return Array.isArray(compareValue) && !compareValue.includes(value);

    case 'notIncludes':
      return Array.isArray(value) && !value.includes(compareValue);

    case 'superset':
      return (
        Array.isArray(value) &&
        Array.isArray(compareValue) &&
        compareValue.every((x) => value.includes(x))
      );

    case 'subset':
      return (
        Array.isArray(value) &&
        Array.isArray(compareValue) &&
        value.every((x) => compareValue.includes(x))
      );

    case 'startsWith':
      return isString(value) && value.startsWith(compareValue);

    case 'prefixOf':
      return (
        isString(value) &&
        isString(compareValue) &&
        compareValue.startsWith(value)
      );

    case 'endsWith':
      return isString(value) && value.endsWith(compareValue);

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

const isSubpath = (compare, subject) => {
  const subpaths = subject.split('.');
  const superpathPortion = compare.split('.').slice(0, subpaths.length);

  return subject === superpathPortion.join('.');
};

const reduceRule = (rule, attributes, inlineTargets) => {
  const result = {};

  for (let [pathToCheck, condition] of Object.entries(cloneDeep(rule))) {
    const { pathToCheck: newPathToCheck, condition: newCondition } =
      maybeReverseCondition(pathToCheck, condition, attributes);
    pathToCheck = newPathToCheck;
    condition = newCondition;

    // When we already know the value of the target, we replace it with an
    // in-line value (if configured in inline targets).
    if (
      condition.target &&
      inlineTargets &&
      inlineTargets.some((inlineTarget) =>
        isSubpath(condition.target, inlineTarget)
      )
    ) {
      const inLineTargetValue = getAttribute(attributes, condition.target);

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

const reduceRules = (rules, attributes, inlineTargets) => {
  const attributesClone = cloneDeep(attributes);

  const result = [];

  if (rules === true) {
    return true;
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
const reduce = (policy, attributes, options = {}) => {
  validate(policy);
  validateJsonSchema('ReduceOptions', options);

  const result = {};

  Object.entries(policy.rules).forEach(([operation, rules]) => {
    rules = reduceRules(rules, attributes, options.inlineTargets);

    if (rules === true || (Array.isArray(rules) && rules.length > 0)) {
      result[operation] = rules;
    }
  });

  return { rules: result };
};

/**
 * @deprecated use `reduce(...)` instead
 */
const reduceSync = deprecate(
  reduce,
  '@lifeomic/abac reduceSync(...) is deprecated. Use reduce(...) instead.'
);

/**
 * Check whether the given policy allows the operation with the given attributes.
 *
 * @param {string} operation the requested operation
 * @param {object} policy the policy to use to check access
 * @param {object} attributes the attributes to use to check access
 * @returns {boolean} true iff access is allowed, and false otherwise
 * @throws {Error} Error if the policy is invalid
 */
const enforce = (operation, policy, attributes) => {
  try {
    // Before using the policy, make sure it's valid
    validate(policy);
  } catch (error) {
    return false;
  }

  const rules =
    policy.rules && policy.rules[operation] ? policy.rules[operation] : [];
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
 * @param {string} operation the requested operation
 * @param {object} policy the policy to use to check access
 * @param {object} attributes the attributes to use to check access
 * @returns {boolean} true iff access is allowed, and false otherwise
 * @throws {Error} Error if the policy is invalid
 */
const enforceLenient = (operation, policy, attributes) => {
  try {
    // Before using the policy, make sure it's valid
    validate(policy);
  } catch (error) {
    return false;
  }

  const rules =
    policy.rules && policy.rules[operation] ? policy.rules[operation] : [];
  const reducedRules = reduceRules(rules, attributes);
  return reducedRules && (reducedRules === true || reducedRules.length > 0);
};

/**
 * @deprecated use `enforceLenient(...)` instead
 */
const enforceSync = deprecate(
  enforceLenient,
  '@lifeomic/abac enforceSync(...) is deprecated. Use enforceLenient(...) instead.'
);

/**
 * Check whether the given policy allows one of a list of operations
 * with the given attributes.
 *
 * @param {string[]} operations the requested operations
 * @param {object} policy the policy to use to check access
 * @param {object} attributes the attributes to use to check access
 * @returns {boolean|string} - the first allowed operation or false
 * @throws {Error} Error if the policy is invalid
 */
const enforceAny = (operations, policy, attributes) => {
  for (const operation of operations) {
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
 * @param {object} policy the policy to use to check access
 * @param {object} attributes the attributes to use to check access
 * @returns {string[]} - the list of privileges
 * @throws {Error} Error if the policy is invalid
 */
const privileges = (policy, attributes) => {
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
 * @param {object} attributes the attributes to use to check access
 * @returns {string[]} - the list of privileges
 * @throws {Error} Error if the policy is invalid
 */
const privilegesLenient = (policy, attributes) => {
  const rules = reduce(policy, attributes).rules;
  return Object.entries(rules).map(([privilege]) => privilege);
};

/**
 * @deprecated use `privilegesLenient(...)` instead
 */
const privilegesSync = deprecate(
  privilegesLenient,
  '@lifeomic/abac privilegesSync(...) is deprecated. Use privilegesLenient(...) instead.'
);

/**
 * Return true iff left is a path prefix of right
 */
const isPathPrefix = (left, right) => {
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
const policyRequiresAttribute = (policy, attribute) => {
  const rules = Object.values(policy.rules)
    .filter((rule) => Array.isArray(rule))
    .reduce((left, right) => left.concat(right), []);

  for (const rule of rules) {
    for (const key in rule) {
      if (isPathPrefix(attribute, key)) {
        return true;
      }
      const target = rule[key].target;
      if (target && isPathPrefix(attribute, target)) {
        return true;
      }
    }
  }
  return false;
};

export {
  validate,
  merge,
  reduce,
  reduceSync /* deprecated */,
  enforce,
  enforceLenient,
  enforceSync /* deprecated */,
  enforceAny,
  extract,
  privileges,
  privilegesLenient,
  privilegesSync /* deprecated */,
  policyRequiresAttribute,
};
