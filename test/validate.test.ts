import { AbacPolicy, AbacReducedPolicy, validate } from '../src';
import test from 'ava';

test('RFC example should validate', (t) => {
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

  t.true(validate(policy));
});

test('target should support wildcards', (t) => {
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

  t.true(validate(policy));
});

test('equals and notEquals should support bools', (t) => {
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

  t.true(validate(policy));
});

test('All access should validate', (t) => {
  const policy = {
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

  t.true(validate(policy));
});

test('No access should validate', (t) => {
  const policy = { rules: {} };

  t.true(validate(policy));
});

test('Unknown operation should validate', (t) => {
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

  t.true(validate(policy));
});

test('Unknown comparison field should not validate', (t) => {
  const policy: AbacReducedPolicy = {
    rules: {
      accessAdmin: [
        {
          'user.groups': {
            comparison: 'includes',
            // @ts-expect-error Invalid rule field
            value: '1af3ed70-018b-46cc-ba41-7b731fcb182f',
            type: 'string',
          },
        },
      ],
    },
  };

  t.throws(() => validate(policy), { instanceOf: Error });
});

test('Missing comparison field should not validate', (t) => {
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

  t.throws(() => validate(policy), { instanceOf: Error });
});

test('Wrong value type should not validate', (t) => {
  const policy: AbacPolicy = {
    rules: {
      accessAdmin: [
        {
          'user.groups': {
            comparison: 'includes',
            value: ['A', 'B'],
          },
        },
      ],
    },
  };

  t.throws(() => validate(policy), { instanceOf: Error });
});

test('Empty rule list should not validate', (t) => {
  const policy: AbacPolicy = {
    rules: {
      accessAdmin: [],
    },
  };

  t.throws(() => validate(policy), { instanceOf: Error });
});

test('Rejects policies containing both target and value keys', (t) => {
  const policy: AbacPolicy = {
    rules: {
      readData: [
        {
          // Allow reading if the current user is the owner
          'resource.ownerId': {
            comparison: 'equals',
            // @ts-expect-error
            target: 'user.id',
            // @ts-expect-error
            value: 'value',
          },
        },
      ],
    },
  };

  t.throws(() => validate(policy), { instanceOf: Error });
});

test('A policy with LIFE operations is allowed', (t) => {
  const policy: AbacReducedPolicy = {
    rules: {
      createLifeData: true,
      readLifeData: true,
      updateLifeData: true,
      deleteLifeData: true,
    },
  };

  t.true(validate(policy));
});

test('A policy with a new operation is allowed', (t) => {
  const policy: AbacReducedPolicy = {
    rules: {
      someNewThing: true,
      readData: true,
    },
  };

  t.true(validate(policy));
});

test('Allows policies containing unknown comparisons and target', (t) => {
  const policy: AbacReducedPolicy = {
    rules: {
      readData: [
        {
          'resource.type': {
            comparison: 'not-entirely-unlike',
            // @ts-expect-error
            target: 'user.favoriteDrink',
          },
        },
      ],
    },
  };

  t.true(validate(policy));
});

test('Allows policies containing unknown comparisons and value', (t) => {
  const policy: AbacReducedPolicy = {
    rules: {
      readData: [
        {
          'resource.type': {
            comparison: 'not-entirely-unlike',
            // @ts-expect-error
            value: 'tea',
          },
        },
      ],
    },
  };

  t.true(validate(policy));
});

test('Allows policies containing unknown comparisons and arbitrary other fields', (t) => {
  const policy: AbacPolicy = {
    rules: {
      readData: [
        {
          'resource.type': {
            comparison: 'not-entirely-unlike',
            // @ts-expect-error
            flavor: 'tea',
          },
        },
      ],
    },
  };

  t.true(validate(policy));
});
