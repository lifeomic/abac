import { validate, AbacPolicy } from '../src';

test('RFC example should validate', () => {
  const policy: AbacPolicy = {
    rules: {
      accessAdmin: [
        {
          'user.groups': {
            comparison: 'includes',
            value: '1af3ed70-018b-46cc-ba41-7b731fcb182f',
          },
        },
      ],
      billingAdmin: [
        {
          'user.groups': {
            comparison: 'includes',
            value: '1af3ed70-018b-46cc-ba41-7b731fcb182f',
          },
        },
      ],
      readData: [
        {
          'user.groups': {
            comparison: 'includes',
            value: '1af3ed70-018b-46cc-ba41-7b731fcb182f',
          },
        },
        {
          'user.groups': {
            comparison: 'superset',
            value: [
              '1af3ed70-018b-46cc-ba41-7b731fcb182f',
              '1af3ed70-018b-46cc-ba41-7b731fcb182f',
            ],
          },
          'resource.dataset': {
            comparison: 'equals',
            value: '1af3ed70-018b-46cc-ba41-7b731fcb182f',
          },
        },
      ],
    },
  };

  expect(validate(policy)).toBe(true);
});

test('target should support wildcards', () => {
  const policy: AbacPolicy = {
    rules: {
      readData: [
        {
          'resource.tags': {
            comparison: 'superset',
            target: 'patient.consents.*.tags',
          },
        },
      ],
    },
  };

  expect(validate(policy)).toBe(true);
});

test('equals and notEquals should support bools', () => {
  const policy: AbacPolicy = {
    rules: {
      readData: [
        {
          'resource.hot': {
            comparison: 'equals',
            value: true,
          },
        },
        {
          'resource.cold': {
            comparison: 'notEquals',
            value: false,
          },
        },
      ],
    },
  };

  expect(validate(policy)).toBe(true);
});

test('All access should validate', () => {
  const policy: AbacPolicy = {
    rules: {
      accessAdmin: true,
      billingAdmin: true,
      projectAdmin: true,
      accountAdmin: true,
      createData: true,
      readData: true,
      updateData: true,
      deleteData: true,
      downloadFile: true,
    },
  };

  expect(validate(policy)).toBe(true);
});

test('No access should validate', () => {
  const policy = { rules: {} };

  expect(validate(policy)).toBe(true);
});

test('Unknown operation should validate', () => {
  const policy: AbacPolicy = {
    rules: {
      root: [
        {
          'user.groups': {
            comparison: 'includes',
            value: '1af3ed70-018b-46cc-ba41-7b731fcb182f',
          },
        },
      ],
    },
  };

  expect(validate(policy)).toBe(true);
});

test('Unknown comparison field should not validate', () => {
  const policy: AbacPolicy = {
    rules: {
      accessAdmin: [
        {
          'user.groups': {
            comparison: 'includes',
            value: '1af3ed70-018b-46cc-ba41-7b731fcb182f',
            type: 'string',
          },
        },
      ],
    },
  };

  expect(() => validate(policy)).toThrow();
});

test('Missing comparison field should not validate', () => {
  const policy: AbacPolicy = {
    rules: {
      accessAdmin: [
        {
          'user.groups': {
            comparison: 'includes',
          },
        },
      ],
    },
  };

  expect(() => validate(policy)).toThrow();
});

test('Wrong value type should not validate', () => {
  const policy: AbacPolicy = {
    rules: {
      accessAdmin: [
        {
          // @ts-expect-error
          'user.groups': {
            comparison: 'includes',
            value: ['A', 'B'],
          },
        },
      ],
    },
  };

  expect(() => validate(policy)).toThrow();
});

test('Empty rule list should not validate', () => {
  const policy: AbacPolicy = {
    rules: {
      accessAdmin: [],
    },
  };

  expect(() => validate(policy)).toThrow();
});

test('Rejects policies containing both target and value keys', () => {
  const policy: AbacPolicy = {
    rules: {
      readData: [
        {
          'resource.ownerId': {
            comparison: 'equals',
            target: 'user.id',
            value: 'value',
          },
        },
      ],
    },
  };

  expect(() => validate(policy)).toThrow();
});

test('A policy with LIFE operations is allowed', () => {
  const policy: AbacPolicy = {
    rules: {
      createLifeData: true,
      readLifeData: true,
      updateLifeData: true,
      deleteLifeData: true,
    },
  };

  expect(validate(policy)).toBe(true);
});

test('A policy with a new operation is allowed', () => {
  const policy: AbacPolicy = {
    rules: {
      someNewThing: true,
      readData: true,
    },
  };

  expect(validate(policy)).toBe(true);
});

test('Allows policies containing unknown comparisons and target', () => {
  const policy: AbacPolicy = {
    rules: {
      readData: [
        {
          'resource.type': {
            comparison: 'not-entirely-unlike',
            target: 'user.favoriteDrink',
          },
        },
      ],
    },
  };

  expect(validate(policy)).toBe(true);
});

test('Allows policies containing unknown comparisons and value', () => {
  const policy: AbacPolicy = {
    rules: {
      readData: [
        {
          'resource.type': {
            comparison: 'not-entirely-unlike',
            value: 'tea',
          },
        },
      ],
    },
  };

  expect(validate(policy)).toBe(true);
});

test('Allows policies containing unknown comparisons and arbitrary other fields', () => {
  const policy: AbacPolicy = {
    rules: {
      readData: [
        {
          'resource.type': {
            comparison: 'not-entirely-unlike',
            flavor: 'tea',
          },
        },
      ],
    },
  };

  expect(validate(policy)).toBe(true);
});
