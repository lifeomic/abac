export type OperationNames = string;

export type Comparison = (
    {
        comparison: string;
        value: string[];
    } | {
        comparison: ('equals' | 'includes');
        value: string;
    } | 
    {
        comparison: ('equals' | 'includes' | 'superset');
        target: string;
    } | 
    { 
        comparison: string; 
    }
);

export interface Rule {
    [key: string]: Comparison;
}

export interface Rules extends Array<Rule> {}

export interface Policy {
    rules: {
        [k: string]: Rules;
    };
}

export interface ReducedPolicy {
    rules: {
        [k: string]: Rules | boolean;
    };
}

export function validate(policy: Policy) : boolean;
export function merge(policies: Array<Policy>): Policy;
export function reduce(policy: Policy, attribute: object): ReducedPolicy;
export function enforce(operation: string, policy: Policy, attributes: object): Promise<boolean>;
export function enforceSync(operation: string, policy: Policy, attributes: object): boolean;
export function enforceAny(operation: string[], policy: Policy, attributes: object): Promise<boolean>;
export function privilegesSync(policy: Policy, attribute: object): string[];
export function privileges(policy: Policy, attribute: object): Promise<string[]>;