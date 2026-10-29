import type { AbacPolicy } from './schemas';
import { mightAllow } from './core/enforce';

/**
 * Performs a check for whether the given policy might allow the operation,
 * without validating the policy. Use it only for policies a server already
 * validated, such as the ones `readIfViewerCan` returns. It never loads AJV,
 * so it stays small enough for browser bundles.
 *
 * For a valid policy this returns exactly what `enforceLenient` from
 * `@lifeomic/abac` returns. If a rule has not been completely reduced for the
 * operation it assumes `true`, so it is not safe for server-side enforcement.
 *
 * @param {string} operationName the requested operation
 * @param {AbacPolicy} policy a policy that already passed `validate`
 * @param {object} attributes the attributes to use to check access
 * @returns {boolean} true if access might be allowed, and false otherwise.
 * It never throws, and returns false when `policy.rules` is not an object.
 * Other malformed policies get an unspecified boolean, so validate first.
 */
export const enforceLenient = (
  operationName: string,
  policy: AbacPolicy,
  attributes?: Record<string, any>,
): boolean => {
  const rules: unknown = policy?.rules;
  if (rules === null || typeof rules !== 'object' || Array.isArray(rules)) {
    return false;
  }

  try {
    return mightAllow(operationName, policy, attributes);
  } catch (error) {
    return false;
  }
};
