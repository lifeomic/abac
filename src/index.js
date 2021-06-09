'use strict';

import schemas from './schemas';
import Ajv from 'ajv';
import deprecate from 'util-deprecate';
import equals from 'fast-deep-equal';
import RE2 from 're2';

const ajv = new Ajv();

Object.entries(schemas).forEach(([key, schema]) => ajv.addSchema(schema, key));

/**
 * Validate a policy.
 * @param {object} policy - the policy to validate
 * @returns {boolean} true iff the policy is valid
 * @throws Error if the policy is invalid
 */
const validate = policy => {
  const valid = ajv.validate('Policy', policy);

  if (!valid) {
    throw new Error(ajv.errorsText());
  }

  return valid;
};

/**
 * Merge multiple policies into a single policy with the same effect.
 * @param {Array[object]} policies - array of policies to merge
 * @returns {object} the merged policy
 * @throws {Error} if any of the policies is invalid
 */
const merge = (policies) => {
  const result = {};

  for (const policy of policies) {
    validate(policy);
    Object.entries(policy.rules).forEach(([operation, rules]) => {
      if (rules === true) {
        // It is safe to ignore the injection attach here because the operation
        // name has been validated by the policy schema before getting this far
        // eslint-disable-next-line security/detect-object-injection
        result[operation] = true;

      // It is safe to ignore the injection attach here because the operation
      // name has been validated by the policy schema before getting this far
      // eslint-disable-next-line security/detect-object-injection
      } else if (result[operation]) {
        // It is safe to ignore the injection attach here because the operation
        // name has been validated by the policy schema before getting this far
        // eslint-disable-next-line security/detect-object-injection
        if (result[operation] !== true) {
          // It is safe to ignore the injection attach here because the operation
          // name has been validated by the policy schema before getting this far
          // eslint-disable-next-line security/detect-object-injection
          result[operation].push(...rules);
        }
      } else {
        // It is safe to ignore the injection attach here because the operation
        // name has been validated by the policy schema before getting this far
        // eslint-disable-next-line security/detect-object-injection
        result[operation] = [...rules];
      }
    });
  }

  return {rules: result};
};

// returns an array of values for each instance of the attribute under the given privileges
const extract = (policy, privileges, attribute) => {
  validate(policy);
  const comparisons = Object.entries(policy.rules).map(([operation, rules]) => {
    if (Array.isArray(rules) && privileges.includes(operation)) {
      return rules.map(rule => rule[attribute]).filter(Boolean);
    }
  }).filter(Boolean);
  return comparisons.flat(1);
};

/**
 * Get a list of all values matching the path (including wildcards).
 * @param {object} attributes - attributes as nested objects
 * @param {array} path - array of path segments
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
 * @param {object} attributes - attributes as nested objects
 * @param {string} path - string path (e.g. 'user.groups')
 */
const getAttribute = (attributes, name) => {
  const path = name.split('.');
  return getAttributeValues(attributes, path)[0];
};

const getCompareValue = function (condition, attributes) {
  if ('target' in condition) {
    return getAttribute(attributes, condition.target);
  } else {
    return condition.value;
  }
};

/**
 * @returns `true` if the comparision matches, `false` if there is a mismatch,
 *          and `undefined` if the target value is not known to compute the
 *          result
 */
const compare = (condition, value, attributes) => {
  const compareValue = getCompareValue(condition, attributes);
  switch (condition.comparison) {
    case 'includes':
      if (compareValue === undefined) return undefined;
      return Array.isArray(value) && value.includes(compareValue);

    case 'in':
      if (compareValue === undefined) return undefined;
      return Array.isArray(compareValue) && compareValue.includes(value);

    case 'equals':
      if (compareValue === undefined) return undefined;
      return equals(value, compareValue);

    case 'exists':
      return value !== undefined;

    case 'notEquals':
      if (compareValue === undefined) return undefined;
      return !equals(value, compareValue);

    case 'notIn':
      if (compareValue === undefined) return undefined;
      return Array.isArray(compareValue) && !compareValue.includes(value);

    case 'superset':
      if (compareValue === undefined) return undefined;
      return Array.isArray(value) && Array.isArray(compareValue) && compareValue.every(x => value.includes(x));

    case 'subset':
      if (compareValue === undefined) return undefined;
      return Array.isArray(value) && Array.isArray(compareValue) && value.every(x => compareValue.includes(x));

    case 'matches':
      // we want to construct expression here
      // eslint-disable-next-line security/detect-non-literal-regexp
      const regex = new RE2(compareValue);
      return regex.test(value);

    default:
      // for unknown comparison types simply deny access:
      return false;
  }
};

const reduceRule = (rule, attributes) => {
  const result = {};

  for (const [name, condition] of Object.entries(rule)) {
    const values = getAttributeValues(attributes, name.split('.'));

    if (values.length === 0) {
      result[name] = condition;
    } else {
      for (const value of values) {
        const compareResult = compare(condition, value, attributes);
        if (compareResult === undefined) {
          result[name] = condition;
          break;
        } else {
          if (compareResult === false) {
            return false;
          }
        }
      }
    }
  }

  if (Object.keys(result).length === 0) {
    return true;
  } else {
    return result;
  }
};

const reduceRules = (rules, attributes) => {
  const result = [];

  if (rules === true) {
    return true;
  }

  for (const rule of rules) {
    const reducedRule = reduceRule(rule, attributes);
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
 * allow the operations.  This function's intended use is for
 * client applications that need a simple check to disable
 * or annotate UI elements.
 * @param {object} policy - the policy to evaluate
 * @param {object} attributes - the attributes to use for the evaluation
 * @returns {object} the policy reduced to conditions involving attributes not not given
 * @throws {Error} if the policy is invalid
 */
const reduce = (policy, attributes) => {
  const result = {};

  validate(policy);
  Object.entries(policy.rules).forEach(([operation, rules]) => {
    rules = reduceRules(rules, attributes);
    if (rules === true || (Array.isArray(rules) && rules.length > 0)) {
      // It is safe to ignore the injection attach here because the operation name
      // comes from the policy which has been validated already.
      // eslint-disable-next-line security/detect-object-injection
      result[operation] = rules;
    }
  });

  return {rules: result};
};

/**
 * @deprecated use `reduce(...)` instead
 */
const reduceSync = deprecate(reduce,
  '@lifeomic/abac reduceSync(...) is deprecated. Use reduce(...) instead.');

/**
 * Check whether the given policy allows the operation with the given attributes.
 * @param {string} operation - the requested operation
 * @param {object} policy - the policy to use to check access
 * @param {object} attributes - the attributes to use to check access
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

  // It is safe to ignore the injection attach here because the operation name has been validated
  // against the allowed operation names
  // eslint-disable-next-line security/detect-object-injection
  const rules = (policy.rules && policy.rules[operation]) ? policy.rules[operation] : [];
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
 * @param {string} operation - the requested operation
 * @param {object} policy - the policy to use to check access
 * @param {object} attributes - the attributes to use to check access
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

  // It is safe to ignore the injection attach here because the operation name has been validated
  // against the allowed operation names
  // eslint-disable-next-line security/detect-object-injection
  const rules = (policy.rules && policy.rules[operation]) ? policy.rules[operation] : [];
  const reducedRules = reduceRules(rules, attributes);
  return reducedRules && (reducedRules === true || reducedRules.length > 0);
};

/**
 * @deprecated use `enforceLenient(...)` instead
 */
const enforceSync = deprecate(enforceLenient,
  '@lifeomic/abac enforceSync(...) is deprecated. Use enforceLenient(...) instead.');

/**
 * Check whether the given policy allows one of a list of operations
 * with the given attributes.
 * @param {string[]} operations - the requested operations
 * @param {object} policy - the policy to use to check access
 * @param {object} attributes - the attributes to use to check access
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
 * @param {object} policy - the policy to use to check access
 * @param {object} attributes - the attributes to use to check access
 * @returns {string[]} - the list of privileges
 * @throws {Error} Error if the policy is invalid
 */
const privileges = (policy, attributes) => {
  const rules = reduce(policy, attributes).rules;
  return Object
    .entries(rules)
    .filter(([, rules]) => rules === true)
    .map(([privilege]) => privilege);
};

/**
 * Synchronously return the list of privileges that the given policy
 * might allow against the given attributes. This function's intended use is for
 * client applications that need a simple check to disable
 * or annotate UI elements. Not safe for server-side!
 * @param {object} policy - the policy to use to check access
 * @param {object} attributes - the attributes to use to check access
 * @returns {string[]} - the list of privileges
 * @throws {Error} Error if the policy is invalid
 */
const privilegesLenient = (policy, attributes) => {
  const rules = reduce(policy, attributes).rules;
  return Object
    .entries(rules)
    .map(([privilege]) => privilege);
};

/**
 * @deprecated use `privilegesLenient(...)` instead
 */
const privilegesSync = deprecate(privilegesLenient,
  '@lifeomic/abac privilegesSync(...) is deprecated. Use privilegesLenient(...) instead.');

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
 * @param {object} policy - the policy to check
 * @param {string} attribute - the attribute path, e.g. 'user.patients'
 * @returns {boolean} True if the attribute is in the rules list
 */
const policyRequiresAttribute = (policy, attribute) => {
  const rules = Object.values(policy.rules)
    .filter(rule => Array.isArray(rule))
    .reduce((left, right) => left.concat(right), []);

  for (const rule of rules) {
    for (const key in rule) {
      if (isPathPrefix(attribute, key)) {
        return true;
      } else {
        const target = rule[key].target;
        if (target && isPathPrefix(attribute, target)) {
          return true;
        }
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
  policyRequiresAttribute
};
