export type AbacRuleComparison = (
    {
      comparison: string;
      value: string[];
    } | {
      comparison: ('equals' | 'includes');
      value: string;
    } |
    {
      comparison: ('equals' | 'includes' | 'superset');
      target: string;
    } |
    {
      comparison: string;
    }
  );

  export type AbacRule = Record<string, AbacRuleComparison | undefined>;

  export interface AbacPolicy {
    rules: Record<string, AbacRule[] | undefined>;
  }

  export interface AbacReducedPolicy {
    rules: Record<string, AbacRule[] | boolean | undefined>;
  }

  /**
   * Validate a policy.
   * @param {object} policy - the policy to validate
   * @returns {boolean} true iff the policy is valid
   * @throws Error if the policy is invalid
   */
  export function validate(policy: AbacPolicy): boolean;

  /**
   * Merge multiple policies into a single policy with the same effect.
   * @param {Array[object]} policies - array of policies to merge
   * @returns {object} the merged policy
   * @throws {Error} if any of the policies is invalid
   */
  export function merge(policies: AbacPolicy[]): AbacPolicy;

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
  export function reduce(policy: AbacReducedPolicy, attributes: object): AbacReducedPolicy;

  /**
   * Extract a rule for a given list of privileges and attribute from the policy.
   * The function's intended use is to provide the comparison and values (e.g. uuids) for a resource type
   * e.g. resource.cohort: {comparison: 'equals', value: uuid}
   * @param policy - the policy to evaluate
   * @param privileges - the privileges to use for the evaluation
   * @param attribute - the attribute to use for the evaluation
   * @returns {object} An array of rules matching the privileges and attribute
   * @throws {Error} Error if the policy is invalid
   */
  export function extract(policy: AbacReducedPolicy, privileges: string[], attribute: string): AbacRuleComparison[];

  /**
   * Check whether the given policy allows the operation with the given attributes.
   * @param {string} operation - the requested operation
   * @param {object} policy - the policy to use to check access
   * @param {object} attributes - the attributes to use to check access
   * @returns {boolean} true iff access is allowed, and false otherwise
   * @throws {Error} Error if the policy is invalid
   */
  export function enforce(operationName: string, policy: AbacReducedPolicy, attributes?: object): boolean;

  /**
   * Performs a check for whether the given policy might
   * allow the operation.  This function's intended use is for
   * client applications that need a simple check to disable
   * or annotate UI elements. If a rule has not been completely
   * reduced for given operation then this function will assume
   * `true` for the policy evaluation(not safe for server-side
   * enforcement of ABAC policy!).
   *
   * @param {string} operation - the requested operation
   * @param {object} policy - the policy to use to check access
   * @param {object} attributes - the attributes to use to check access
   * @returns {boolean} true iff access is allowed, and false otherwise
   * @throws {Error} Error if the policy is invalid
   */
  export function enforceLenient(operationName: string, policy: AbacReducedPolicy, attributes?: object): boolean;

  /**
   * Check whether the given policy allows one of a list of operations
   * with the given attributes.
   * @param {string[]} operations - the requested operations
   * @param {object} policy - the policy to use to check access
   * @param {object} attributes - the attributes to use to check access
   * @returns {boolean|string} - the first allowed operation or false
   * @throws {Error} Error if the policy is invalid
   */
  export function enforceAny(operationName: string[], policy: AbacReducedPolicy, attributes?: object): boolean;

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
  export function privilegesLenient(policy: AbacReducedPolicy, attributes?: object): string[];

  /**
   * Return the list of privileges that the given policy
   * allows against the given attributes.
   * @param {object} policy - the policy to use to check access
   * @param {object} attributes - the attributes to use to check access
   * @returns {string[]} - the list of privileges
   * @throws {Error} Error if the policy is invalid
   */
  export function privileges(policy: AbacReducedPolicy, attributes?: object): string[];

  /**
   * Synchronously determines if a given attribute path is in the list of rules
   * for a given policy. This may be useful for determining if additional metadata
   * should be fetched before enforcing a policy.
   *
   * @param {object} policy - the policy to check
   * @param {string} attribute - the attribute path, e.g. 'user.patients'
   * @returns {boolean} True if the attribute is in the rules list
   */
  export function policyRequiresAttribute(policy: AbacReducedPolicy, attribute: string): boolean;
