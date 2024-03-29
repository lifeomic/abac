import { AbacRule } from './Rule';

export type AbacRules = AbacRule[] | boolean;

export const Rules = {
  $schema: 'http://json-schema.org/draft-07/schema#',
  $id: 'Rules',
  title: 'Rules',
  description: 'An ABAC rules list or true.',
  oneOf: [
    {
      type: 'array',
      items: {
        $ref: 'Rule',
      },
      minItems: 1,
    },
    {
      type: 'boolean',
      const: true,
    },
  ],
} as const;
