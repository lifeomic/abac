export default {
  $schema: 'http://json-schema.org/draft-07/schema#',
  $id: 'OperationNames',
  title: 'OperationNames',
  description: 'The set of valid operation names',
  type: 'string',
  minLength: 2,
  maxLength: 64,
  pattern: '[a-zA-z]+',
} as const;
