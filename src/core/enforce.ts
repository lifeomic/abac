import type { AbacPolicy } from '../schemas';
import { isPossible, reduceRules } from './reduce';

const operationRules = (policy: AbacPolicy, operationName: string) =>
  policy.rules && policy.rules[operationName]
    ? policy.rules[operationName]
    : [];

export const allows = (
  operationName: string,
  policy: AbacPolicy,
  attributes?: Record<string, any>,
): boolean => reduceRules(operationRules(policy, operationName), attributes) === true;

export const mightAllow = (
  operationName: string,
  policy: AbacPolicy,
  attributes?: Record<string, any>,
): boolean => isPossible(reduceRules(operationRules(policy, operationName), attributes));
