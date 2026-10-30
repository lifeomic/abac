import type { AbacPolicy } from '../../src/schemas';

export interface Input {
  policy: AbacPolicy;
  otherPolicy: AbacPolicy;
  attributes?: Record<string, unknown>;
  options?: { inlineTargets?: string[] };
  operation: string;
  operations: string[];
  path: string;
}

export type Mismatch = Record<string, unknown>;

export const DEFAULT_COUNT: number;
export const DEFAULT_SEED: number;
export function compareImplementations(
  expected: object,
  actual: object,
  makeInputs: () => Input[],
  label: string,
): Mismatch[];
export function enforceLenientMismatches(
  published: object,
  enforceLenient: (operation: string, policy: AbacPolicy, attributes?: Record<string, unknown>) => boolean,
  makeInputs: () => Input[],
): Mismatch[];
export function exportKinds(module: object): [string, string][];
export function generateInputs(seed: number, count: number): Input[];
export function loosePairInputs(): Input[];
export function mulberry32(seed: number): () => number;
export function runCase(abac: object, input: Input): Record<string, { value?: unknown; error?: string }>;
