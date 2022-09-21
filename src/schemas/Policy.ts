export default {
  $schema: 'http://json-schema.org/draft-07/schema#',
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
};
