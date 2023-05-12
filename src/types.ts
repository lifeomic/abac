export type AbacComparison =
  | {
      comparison:
        | 'superset'
        | 'subset'
        | 'in'
        | 'notIn'
        | 'equals'
        | 'notEquals';
      value: (string | number)[];
      target?: undefined;
    }
  | {
      comparison: 'includes' | 'notIncludes' | 'equals' | 'notEquals';
      value: number | string;
      target?: undefined;
    }
  | {
      comparison: 'startsWith' | 'prefixOf' | 'suffixOf' | 'endsWith';
      value?: string;
      target?: string;
    }
  | {
      comparison: 'equals' | 'notEquals';
      value: boolean;
      target?: undefined;
    }
  | {
      comparison:
        | 'superset'
        | 'subset'
        | 'in'
        | 'equals'
        | 'includes'
        | 'notIncludes'
        | 'notEquals'
        | 'notIn';
      value?: undefined;
      target: string;
    }
  | {
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
      value?: undefined;
      target?: undefined;
    }
  // Not in the Comparison schema
  | {
      comparison: 'exists';
      value?: string;
      target?: undefined;
    };

export type AbacRule = Record<string, AbacComparison>;

export type AbacRules = AbacRule[] | true;

export interface AbacPolicy {
  rules: Record<string, AbacRules>;
}

export interface AbacReduceOptions {
  inlineTargets: string[];
}
