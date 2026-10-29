import deepClone from 'deep-clone';

import type { AbacComparison, AbacRule } from '../schemas';
import { getAttribute, getAttributeValues } from './attributes';
import { compare } from './compare';

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

export const reduceRules = (
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
