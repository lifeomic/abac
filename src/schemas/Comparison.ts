export default {
  $schema: 'http://json-schema.org/draft-07/schema#',
  definitions: {
    ValidTargetString: {
      type: 'string',
      pattern:
        '^(([$%a-zA-Z_][$%0-9a-zA-Z_]*)|\\*)(\\.([$%0-9a-zA-Z_]*)|\\*)*$',
    },
  },
  $id: 'Comparison',
  title: 'Comparison',
  description: 'An individual ABAC attribute comparison',
  type: 'object',
  oneOf: [
    {
      properties: {
        comparison: {
          type: 'string',
          enum: ['superset', 'subset', 'in', 'notIn', 'equals', 'notEquals'],
        },
        value: {
          type: 'array',
          items: {
            type: ['number', 'string'],
          },
        },
      },
      required: ['comparison', 'value'],
      additionalProperties: false,
    },
    {
      properties: {
        comparison: {
          type: 'string',
          enum: ['includes', 'notIncludes', 'equals', 'notEquals'],
        },
        value: {
          type: ['number', 'string'],
        },
      },
      required: ['comparison', 'value'],
      additionalProperties: false,
    },
    {
      properties: {
        comparison: {
          type: 'string',
          enum: ['startsWith', 'prefixOf', 'suffixOf', 'endsWith'],
        },
        value: {
          type: ['string'],
        },
        target: {
          $ref: '#/definitions/ValidTargetString',
        },
      },
      required: ['comparison'],
      additionalProperties: false,
    },
    {
      properties: {
        comparison: {
          type: 'string',
          enum: ['equals', 'notEquals'],
        },
        value: {
          type: 'boolean',
        },
      },
      required: ['comparison', 'value'],
      additionalProperties: false,
    },
    {
      properties: {
        comparison: {
          type: 'string',
          enum: [
            'superset',
            'subset',
            'in',
            'equals',
            'includes',
            'notIncludes',
            'notEquals',
            'notIn',
          ],
        },
        target: {
          $ref: '#/definitions/ValidTargetString',
        },
      },
      required: ['comparison', 'target'],
      additionalProperties: false,
    },
    {
      properties: {
        comparison: {
          type: 'string',
          not: {
            enum: [
              'superset',
              'subset',
              'in',
              'equals',
              'includes',
              'notIncludes',
              'notEquals',
              'notIn',
              'startsWith',
              'prefixOf',
              'endsWith',
              'suffixOf',
            ],
          },
        },
      },
      required: ['comparison'],
      additionalProperties: true,
    },
  ],
};
