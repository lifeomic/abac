import AjvModule from 'ajv';

import { Comparison, OperationNames, Policy, ReduceOptions, Rule, Rules } from './schemas';
import type { AbacPolicy } from './schemas';

// ajv 7 sets only `exports.default`, so a Node ESM default import gets the exports object.
const Ajv = (AjvModule as unknown as { default?: typeof AjvModule }).default ?? AjvModule;

// Not `Object.values` of a namespace import: bundler interop can add a `default` entry holding every schema.
const ajv = new Ajv({
  schemas: [Comparison, Policy, Rule, Rules, OperationNames, ReduceOptions],
});

/**
 * Validate value with AJV.
 *
 * @param {string} schemaName the name of the JSON schema to use for validation.
 * @param {AbacPolicy} policy the value to validate.
 * @returns {boolean} true if the value is valid based on specified schema.
 * @throws Error if the value is invalid based on the specified schema.
 */
export const validateJsonSchema = (
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
