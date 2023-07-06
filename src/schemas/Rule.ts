import { AbacComparison } from './Comparison';

export type AbacRule = Record<string, AbacComparison>;

export const Rule = {
  $schema: 'http://json-schema.org/draft-07/schema#',
  $id: 'Rule',
  title: 'Rule',
  description: 'An individual ABAC policy rule',
  type: 'object',
  patternProperties: {
    '^(([$%a-zA-Z_][$%0-9a-zA-Z_]*)|\\*)(\\.([$%0-9a-zA-Z_]*)|\\*)*$': {
      $ref: 'Comparison',
    },
  },
  additionalProperties: false,
} as const;
