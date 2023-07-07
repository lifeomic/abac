export interface StringOrNumberArrayComparison {
  comparison: 'superset' | 'subset' | 'in' | 'notIn' | 'equals' | 'notEquals';
  value: (string | number)[];
  target?: undefined;
}

const stringOrNumberArrayComparison = {
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
};

export interface StringOrNumberDirectComparison {
  comparison: 'includes' | 'notIncludes' | 'equals' | 'notEquals';
  value: number | string;
  target?: undefined;
}

const stringOrNumberDirectComparison = {
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
};

export interface StringPrePostFixComparison {
  comparison: 'startsWith' | 'prefixOf' | 'suffixOf' | 'endsWith';
  value?: string;
  target?: string;
}

const stringPrePostFix = {
  properties: {
    comparison: {
      type: 'string',
      enum: ['startsWith', 'prefixOf', 'suffixOf', 'endsWith'],
    },
    value: {
      type: 'string',
    },
    target: {
      $ref: '#/definitions/ValidTargetString',
    },
  },
  required: ['comparison'],
  additionalProperties: false,
};

export interface BoolComparison {
  comparison: 'equals' | 'notEquals';
  value: boolean;
  target?: undefined;
}

const boolComparison = {
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
};

export interface TargetStringComparison {
  comparison:
    | 'superset'
    | 'subset'
    | 'in'
    | 'equals'
    | 'includes'
    | 'notIncludes'
    | 'notEquals'
    | 'notIn';
  target: string;
  value?: undefined;
}

const targetStringComparison = {
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
};

export interface UnknownComparisonType extends Record<string, any> {
  comparison: Omit<
    | 'superset'
    | 'subset'
    | 'in'
    | 'equals'
    | 'includes'
    | 'notIncludes'
    | 'notEquals'
    | 'notIn'
    | 'startsWith'
    | 'prefixOf'
    | 'endsWith'
    | 'suffixOf',
    string
  >;
  target?: string;
  value?: string;
}

const invalidComparisonType = {
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
};

// Not in the Comparison schema
export interface ExistsComparison {
  comparison: 'exists';
  value?: string;
  target?: undefined;
}

export type AbacComparison =
  | StringOrNumberArrayComparison
  | StringOrNumberDirectComparison
  | StringPrePostFixComparison
  | BoolComparison
  | TargetStringComparison
  | UnknownComparisonType
  | ExistsComparison;

export const Comparison = {
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
    stringOrNumberArrayComparison,
    stringOrNumberDirectComparison,
    stringPrePostFix,
    boolComparison,
    targetStringComparison,
    invalidComparisonType,
  ],
} as const;
