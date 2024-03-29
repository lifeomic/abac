export interface AbacReduceOptions {
  inlineTargets?: [string, ...string[]];
}

export const ReduceOptions = {
  $schema: 'http://json-schema.org/draft-07/schema#',
  $id: 'ReduceOptions',
  title: 'ReduceOptions',
  description:
    'An options object that can be passed to the reduce function for configuration.',
  type: 'object',
  properties: {
    inlineTargets: {
      type: 'array',
      items: {
        type: ['string'],
      },
      minItems: 1,
    },
  },
  additionalProperties: false,
} as const;
