'use strict';

const OPERATIONS = ['readData', 'writeData', 'deleteData', 'accessAdmin'];

const COMPARISONS = [
  'equals',
  'notEquals',
  'in',
  'notIn',
  'includes',
  'notIncludes',
  'superset',
  'subset',
  'startsWith',
  'prefixOf',
  'endsWith',
  'suffixOf',
  'exists',
  'bogus',
];

const PATHS = [
  'a',
  'b',
  'user.id',
  'user.groups',
  'user.name',
  'resource.dataset',
  'resource.owner',
  'user.*',
  'user.%keys',
  'resource.%%keys',
  '*.id',
];

const STRINGS = ['abc', 'ab', 'bc', 'a', '', '1', '0', 'project'];

const SCALARS = [0, 1, 2, 42, '0', '1', '', 'a', 'b', 'abc', 'project'];

const LOOSE_VALUES = [0, 1, 2, '0', '1', '', true, false, null, [1], ['1'], [0], [false]];

const VALUES = [
  ...LOOSE_VALUES,
  'abc',
  'ab',
  'bc',
  'project',
  ['a', 'b'],
  ['a', 'b', 'c'],
  [1, 2, 3],
  [],
  { a: 1 },
  { a: '1' },
  { a: [1, 2] },
  NaN,
  42,
];

const nullPrototype = (entries) => Object.assign(Object.create(null), entries);

// eslint-disable-next-line no-sparse-arrays
const sparse = () => [, 1];

const loosePairs = () => [
  [1, '1'],
  [false, 0],
  ['', 0],
  [true, '1'],
  [[1], ['1']],
  [null, 0],
  [null, undefined],
  [NaN, NaN],
  [{ a: 1 }, { a: '1' }],
  [[], {}],
  [[1, 2], ['1', '2']],
  ['1', 1],
  [0, false],
  [[0], [false]],
  [{ a: null }, { a: undefined }],
  [[null], [undefined]],
  [sparse(), [undefined, 1]],
  [new Number(1), new Number(2)],
  [new String('a'), 'a'],
  [nullPrototype({ a: 1 }), { a: '1' }],
  [{ a: nullPrototype({ b: new Boolean(true) }) }, { a: { b: {} } }],
  [new Date(0), new Date(0)],
  [new Date(0), 0],
  [new Date(0), { a: 1 }],
  [{ a: [true] }, { a: ['1'] }],
  [{ b: 1, a: 2 }, { a: '2', b: '1' }],
  [{ a: 1 }, { a: 1, b: 2 }],
];

const mulberry32 = (seed) => {
  let state = seed >>> 0;
  return () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
};

const clone = (value) => {
  if (Array.isArray(value)) return value.map(clone);
  if (value instanceof Date) return new Date(value.getTime());
  if (value && typeof value === 'object') {
    const result = {};
    for (const key of Object.keys(value)) result[key] = clone(value[key]);
    return result;
  }
  return value;
};

const createGenerator = (seed) => {
  const random = mulberry32(seed);
  const pick = (list) => clone(list[Math.floor(random() * list.length)]);
  const chance = (p) => random() < p;
  const int = (min, max) => min + Math.floor(random() * (max - min + 1));

  const scalar = () => pick(SCALARS);
  const scalarArray = () => Array.from({ length: int(0, 3) }, scalar);

  const validComparison = () => {
    switch (int(0, 6)) {
      case 0:
        return { comparison: pick(['superset', 'subset', 'in', 'notIn', 'equals', 'notEquals']), value: scalarArray() };
      case 1:
        return { comparison: pick(['includes', 'notIncludes', 'equals', 'notEquals']), value: scalar() };
      case 2: {
        const result = { comparison: pick(['startsWith', 'prefixOf', 'suffixOf', 'endsWith']) };
        if (chance(0.5)) result.value = pick(STRINGS);
        else result.target = pick(PATHS);
        return result;
      }
      case 3:
        return { comparison: pick(['equals', 'notEquals']), value: chance(0.5) };
      case 4:
        return {
          comparison: pick(['superset', 'subset', 'in', 'equals', 'includes', 'notIncludes', 'notEquals', 'notIn']),
          target: pick(PATHS),
        };
      case 5:
        return { comparison: 'exists' };
      default:
        return { comparison: 'bogus', value: pick(VALUES) };
    }
  };

  const comparison = () => {
    if (chance(0.9)) return validComparison();
    const result = { comparison: pick(COMPARISONS) };
    if (chance(0.5)) result.target = pick(PATHS);
    else result.value = pick(VALUES);
    if (chance(0.2)) result.extra = 'field';
    return result;
  };

  const rule = () => {
    const result = {};
    for (let i = int(1, 2); i > 0; i--) result[pick(PATHS)] = comparison();
    return result;
  };

  const policy = () => {
    if (chance(0.02)) return pick([{}, { rules: 'x' }, { rules: [] }, { rules: {}, extra: 1 }]);
    const rules = {};
    for (let i = int(0, 3); i > 0; i--) {
      const operation = pick(OPERATIONS);
      if (chance(0.1)) rules[operation] = chance(0.8);
      else rules[operation] = Array.from({ length: int(chance(0.05) ? 0 : 1, 2) }, rule);
    }
    return { rules };
  };

  const attributeValue = (depth) => {
    if (depth < 2 && chance(0.25)) return randomAttributes(depth + 1);
    if (chance(0.03)) return new Date(0);
    return pick(VALUES);
  };

  const randomAttributes = (depth) => {
    const result = {};
    for (const key of ['a', 'b', 'user', 'resource', 'id', 'groups', 'name', 'dataset', 'owner', '%keys']) {
      if (chance(depth === 0 ? 0.6 : 0.4)) result[key] = attributeValue(depth);
    }
    return result;
  };

  const loosen = (value) => {
    if (typeof value === 'number') return String(value);
    if (typeof value === 'string' && value !== '' && !Number.isNaN(Number(value))) return Number(value);
    if (typeof value === 'boolean') return value ? 1 : 0;
    if (Array.isArray(value)) return value.map(loosen);
    return value;
  };

  const satisfying = (condition) => {
    const value = condition.value;
    if (Array.isArray(value) && value.length > 0 && chance(0.5)) return pick(value);
    if (typeof value === 'string' && chance(0.5)) {
      return pick([value + 'x', 'x' + value, value.slice(0, 1), value.slice(1)]);
    }
    if (value !== undefined && chance(0.2)) return [value];
    return value;
  };

  const setPath = (target, path, value) => {
    const parts = path.split('.');
    if (parts.some((part) => part === '*' || part.startsWith('%'))) return;
    let node = target;
    for (const part of parts.slice(0, -1)) {
      if (!node[part] || typeof node[part] !== 'object') node[part] = {};
      node = node[part];
    }
    node[parts[parts.length - 1]] = value;
  };

  const attributesFor = (currentPolicy) => {
    const result = randomAttributes(0);
    const rules = currentPolicy && currentPolicy.rules;
    if (!rules || typeof rules !== 'object') return result;
    for (const ruleList of Object.values(rules)) {
      if (!Array.isArray(ruleList)) continue;
      for (const currentRule of ruleList) {
        for (const [path, condition] of Object.entries(currentRule)) {
          if (!chance(0.7)) continue;
          if (condition.target) {
            const shared = pick(VALUES);
            setPath(result, path, shared);
            if (chance(0.8)) setPath(result, condition.target, chance(0.3) ? loosen(shared) : clone(shared));
          } else if (condition.comparison === 'exists') {
            setPath(result, path, pick(VALUES));
          } else if (condition.value !== undefined) {
            const planted = satisfying(condition);
            setPath(result, path, chance(0.25) ? loosen(planted) : planted);
          }
        }
      }
    }
    return result;
  };

  const reduceOptions = () => {
    if (chance(0.5)) return undefined;
    if (chance(0.05)) return { inlineTargets: 'user' };
    return { inlineTargets: Array.from({ length: int(0, 2) }, () => pick(['user', 'user.id', 'resource', 'a'])) };
  };

  return {
    policy,
    attributes: (currentPolicy) => (chance(0.05) ? undefined : attributesFor(currentPolicy)),
    reduceOptions,
    operation: (currentPolicy) => {
      const defined = currentPolicy && currentPolicy.rules && typeof currentPolicy.rules === 'object'
        ? Object.keys(currentPolicy.rules)
        : [];
      return defined.length > 0 && chance(0.8) ? pick(defined) : pick(OPERATIONS.concat(['unknownOperation']));
    },
    operations: () => Array.from({ length: int(0, 3) }, () => pick(OPERATIONS)),
    path: () => pick(PATHS.concat(['user', 'resource', 'nothing'])),
  };
};

const capture = (fn) => {
  try {
    return { value: fn() };
  } catch (error) {
    return { error: error && error.message };
  }
};

const runCase = (abac, input) => {
  const { policy, otherPolicy, attributes, options, operation, operations, path } = input;
  return {
    validate: capture(() => abac.validate(policy)),
    merge: capture(() => abac.merge([policy, otherPolicy])),
    extract: capture(() => abac.extract(policy, operations, path)),
    reduce: capture(() => abac.reduce(policy, attributes)),
    reduceWithOptions: capture(() => abac.reduce(policy, attributes, options)),
    enforce: capture(() => abac.enforce(operation, policy, attributes)),
    enforceLenient: capture(() => abac.enforceLenient(operation, policy, attributes)),
    enforceAny: capture(() => abac.enforceAny(operations, policy, attributes)),
    privileges: capture(() => abac.privileges(policy, attributes)),
    privilegesLenient: capture(() => abac.privilegesLenient(policy, attributes)),
    policyRequiresAttribute: capture(() => abac.policyRequiresAttribute(policy, path)),
  };
};

const generateInputs = (seed, count) => {
  const generator = createGenerator(seed);
  const inputs = [];
  for (let i = 0; i < count; i++) {
    const policy = generator.policy();
    inputs.push({
      policy,
      otherPolicy: generator.policy(),
      attributes: generator.attributes(policy),
      options: generator.reduceOptions(),
      operation: generator.operation(policy),
      operations: generator.operations(),
      path: generator.path(),
    });
  }
  return inputs;
};

const loosePairInputs = () => {
  const inputs = [];
  const pair = (index) => loosePairs()[index];
  loosePairs().forEach((_, index) => {
    for (const comparison of ['equals', 'notEquals']) {
      inputs.push({
        policy: { rules: { readData: [{ a: { comparison, value: pair(index)[1] } }] } },
        otherPolicy: { rules: {} },
        attributes: { a: pair(index)[0] },
        operation: 'readData',
        operations: ['readData'],
        path: 'a',
      });
      inputs.push({
        policy: { rules: { readData: [{ a: { comparison, target: 'b' } }] } },
        otherPolicy: { rules: {} },
        attributes: { a: pair(index)[0], b: pair(index)[1] },
        operation: 'readData',
        operations: ['readData'],
        path: 'a',
      });
    }
  });
  return inputs;
};

const normalize = (value) => {
  if (typeof value === 'number' && Number.isNaN(value)) return { $nan: true };
  if (value === undefined) return { $undefined: true };
  if (value instanceof Date) return { $date: value.getTime() };
  if (value instanceof Number || value instanceof String || value instanceof Boolean) {
    return { $boxed: value.valueOf() };
  }
  if (Array.isArray(value)) {
    return Array.from({ length: value.length }, (_, index) => (index in value ? normalize(value[index]) : { $hole: true }));
  }
  if (value && typeof value === 'object') {
    const result = Object.getPrototypeOf(value) === null ? { $nullPrototype: true } : {};
    for (const key of Object.keys(value)) result[key] = normalize(value[key]);
    return result;
  }
  return value;
};

const compareImplementations = (expected, actual, makeInputs, label) => {
  const mismatches = [];
  const expectedInputs = makeInputs();
  makeInputs().forEach((input, index) => {
    const before = JSON.stringify(normalize(input));
    const want = JSON.stringify(normalize(runCase(expected, expectedInputs[index])));
    const got = JSON.stringify(normalize(runCase(actual, input)));
    if (want !== got) mismatches.push({ label, index, input: before, expected: want, actual: got });
    if (JSON.stringify(normalize(input)) !== before) {
      mismatches.push({ label, index, input: before, mutated: JSON.stringify(normalize(input)) });
    }
  });
  return mismatches;
};

const DEFAULT_SEED = 0xabac;
const DEFAULT_COUNT = 10000;

module.exports = {
  DEFAULT_COUNT,
  DEFAULT_SEED,
  compareImplementations,
  generateInputs,
  loosePairInputs,
  runCase,
};
