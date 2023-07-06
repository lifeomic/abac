import { AbacRules } from './Rules';

export interface AbacPolicy {
  rules: Record<string, AbacRules>;
}

export const Policy = {
  $schema: 'http://json-schema.org/draft-07/schema#',
  $id: 'Policy',
  title: 'Policy',
  description: 'An ABAC policy document.',
  type: 'object',
  properties: {
    rules: {
      type: 'object',
      propertyNames: { $ref: 'OperationNames' },
      additionalProperties: { $ref: 'Rules' },
    },
  },
  required: ['rules'],
  additionalProperties: false,
} as const;
