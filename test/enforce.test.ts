import { enforce, enforceAny, AbacPolicy } from '../src';

test('RFC example should enforce properly', () => {
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
              '8cfdd7b2-236e-4001-8d98-75d931877bbb',
              '1456d7e3-1bc0-4849-8c50-940a4eb3c07c',
            ],
          },
          'resource.dataset': {
            comparison: 'equals',
            value: '6a2db2e4-f0fc-4db7-9a8f-28ab14667257',
          },
        },
      ],
    },
  };

  // admin group gets access to all three operations:
  let user = { groups: ['1af3ed70-018b-46cc-ba41-7b731fcb182f'] };
  let resource = { dataset: '6a2db2e4-f0fc-4db7-9a8f-28ab14667257' };
  expect(enforce('accessAdmin', policy, { user, resource })).toBe(true);
  expect(enforce('billingAdmin', policy, { user, resource })).toBe(true);
  expect(enforce('readData', policy, { user, resource })).toBe(true);
  expect(enforce('downloadFile', policy, { user, resource })).toBe(false);

  // members of both TNBC and Doctors gets readData for the TNBC dataset:
  user = {
    groups: [
      '8cfdd7b2-236e-4001-8d98-75d931877bbb',
      '1456d7e3-1bc0-4849-8c50-940a4eb3c07c',
      'a5e15ccd-d853-4da2-8d1c-63630a47ba5d',
    ],
  };
  resource = { dataset: '6a2db2e4-f0fc-4db7-9a8f-28ab14667257' };
  expect(enforce('accessAdmin', policy, { user, resource })).toBe(false);
  expect(enforce('billingAdmin', policy, { user, resource })).toBe(false);
  expect(enforce('readData', policy, { user, resource })).toBe(true);
  expect(enforce('downloadFile', policy, { user, resource })).toBe(false);

  // members of both TNBC and Doctors gets no access to PED dataset:
  user = {
    groups: [
      '8cfdd7b2-236e-4001-8d98-75d931877bbb',
      '1456d7e3-1bc0-4849-8c50-940a4eb3c07c',
      'a5e15ccd-d853-4da2-8d1c-63630a47ba5d',
    ],
  };
  resource = { dataset: '62271b6b-35f2-4565-83d8-c1d7a32ec95b' };
  expect(enforce('accessAdmin', policy, { user, resource })).toBe(false);
  expect(enforce('billingAdmin', policy, { user, resource })).toBe(false);
  expect(enforce('readData', policy, { user, resource })).toBe(false);
  expect(enforce('downloadFile', policy, { user, resource })).toBe(false);

  // user in no groups gets no access:
  user = { groups: [] };
  resource = { dataset: '6a2db2e4-f0fc-4db7-9a8f-28ab14667257' };
  expect(enforce('accessAdmin', policy, { user, resource })).toBe(false);
  expect(enforce('billingAdmin', policy, { user, resource })).toBe(false);
  expect(enforce('readData', policy, { user, resource })).toBe(false);
  expect(enforce('downloadFile', policy, { user, resource })).toBe(false);

  // user just in TNBC group, but not doctor gets no access:
  user = { groups: ['8cfdd7b2-236e-4001-8d98-75d931877bbb'] };
  resource = { dataset: '6a2db2e4-f0fc-4db7-9a8f-28ab14667257' };
  expect(enforce('accessAdmin', policy, { user, resource })).toBe(false);
  expect(enforce('billingAdmin', policy, { user, resource })).toBe(false);
  expect(enforce('readData', policy, { user, resource })).toBe(false);
  expect(enforce('downloadFile', policy, { user, resource })).toBe(false);
});

test('A policy that has no access, gives everyone no access', () => {
  let user = { groups: ['1af3ed70-018b-46cc-ba41-7b731fcb182f'] };
  let resource = { dataset: '6a2db2e4-f0fc-4db7-9a8f-28ab14667257' };
  expect(enforce('readData', { rules: {} }, { user, resource })).toBe(false);

  user = { groups: [] };
  resource = { dataset: '6a2db2e4-f0fc-4db7-9a8f-28ab14667257' };
  expect(enforce('readData', { rules: {} }, { user, resource })).toBe(false);
});

test('A policy with all access, gives everyone access to everything', () => {
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

  let user = { groups: ['1af3ed70-018b-46cc-ba41-7b731fcb182f'] };
  expect(enforce('accessAdmin', policy, { user })).toBe(true);
  expect(enforce('readData', policy, { user })).toBe(true);

  user = { groups: [] };
  expect(enforce('accessAdmin', policy, { user })).toBe(true);
  expect(enforce('readData', policy, { user })).toBe(true);
});

test('can enforce positive exists conditionals', () => {
  const policy: AbacPolicy = {
    rules: {
      readLifeData: [
        {
          // Allow reading any educational content
          educationalContent: {
            comparison: 'exists',
          },
        },
      ],
    },
  };

  // Test that a user can read educational content
  const user = { id: 'testuser' };
  const educationalContent = { id: 'some content' };
  expect(enforce('readLifeData', policy, { user, educationalContent })).toBe(
    true,
  );

  // Test that a user cannot read fasting data
  const fastingData = { id: 'some fast' };
  expect(enforce('readLifeData', policy, { user, fastingData })).toBe(false);
});

test('supports target attributes', () => {
  const policy: AbacPolicy = {
    rules: {
      readData: [
        {
          // Allow reading if the current user is the owner
          'resource.ownerId': {
            comparison: 'equals',
            target: 'user.id',
          },
        },
      ],
    },
  };

  // Test that a user can read their own resources
  const user = { id: 'testuser' };
  const resource1 = { ownerId: 'testuser' };
  expect(enforce('readData', policy, { user, resource: resource1 })).toBe(true);

  // Test that a user cannot read a different user's resource
  const resource2 = { ownerId: 'testuser2' };
  expect(enforce('readData', policy, { user, resource: resource2 })).toBe(false);
});

test('returns false when target attributes are missing', () => {
  const policy: AbacPolicy = {
    rules: {
      readData: [
        {
          'user.patients': {
            comparison: 'includes',
            target: 'resource.subject',
          },
        },
      ],
    },
  };

  const user1 = { patients: ['patient1'] };
  const resource1 = {};
  expect(enforce('readData', policy, { user: user1, resource: resource1 })).toBe(false);

  const user2 = {};
  const resource2 = { subject: 'patient2' };
  expect(enforce('readData', policy, { user: user2, resource: resource2 })).toBe(false);
});

test('returns false for invalid operation names', () => {
  expect(enforce('not-an-operation', { rules: {} }, {})).toBe(false);
});

test('returns false for permissions containing unknown comparisons and target', () => {
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
      createData: true,
    },
  };

  expect(enforce('readData', policy, {
    user: { favoriteDrink: 'tea' },
    resource: { type: 'sort of tea' },
  })).toBe(false);
  expect(enforce('createData', policy, {
    user: { favoriteDrink: 'tea' },
    resource: { type: 'sort of tea' },
  })).toBe(true);
});

test('returns false for permissions containing unknown comparisons and value', () => {
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
      createData: true,
    },
  };

  expect(enforce('readData', policy, { resource: { type: 'sort of tea' } })).toBe(false);
  expect(enforce('createData', policy, { resource: { type: 'sort of tea' } })).toBe(true);
});

test('supports the in comparison with target', () => {
  const policy: AbacPolicy = {
    rules: {
      readData: [
        {
          'resource.type': {
            comparison: 'in',
            target: 'user.favoriteDrinks',
          },
        },
      ],
    },
  };

  expect(enforce('readData', policy, {
    user: { favoriteDrinks: ['tea', 'coffee'] },
    resource: { type: 'tea' },
  })).toBe(true);

  expect(enforce('readData', policy, { resource: { type: 'tea' } })).toBe(false);
});

test('supports the in comparison with value', () => {
  const policy: AbacPolicy = {
    rules: {
      readData: [
        {
          'resource.type': {
            comparison: 'in',
            value: ['tea', 'coffee'],
          },
        },
      ],
    },
  };

  expect(enforce('readData', policy, { resource: { type: 'tea' } })).toBe(true);
  expect(enforce('readData', policy, { resource: { type: 'chai' } })).toBe(false);
});

test('A policy with a new operation works as expected', () => {
  const policy: AbacPolicy = {
    rules: {
      someNewThing: true,
    },
  };

  let user = { groups: ['1af3ed70-018b-46cc-ba41-7b731fcb182f'] };
  expect(enforce('someNewThing', policy, { user })).toBe(true);
  expect(enforce('readData', policy, { user })).toBe(false);

  user = { groups: [] };
  expect(enforce('someNewThing', policy, { user })).toBe(true);
  expect(enforce('readData', policy, { user })).toBe(false);
});

test('enforceAny returns the first allowed operation when multiple are allowed', () => {
  const policy: AbacPolicy = {
    rules: {
      readData: true,
      readAnonData: true,
    },
  };

  expect(enforceAny(['readData', 'readAnonData'], policy, {})).toBe('readData');
});

test('enforceAny returns the first allowed operation when only one is allowed', () => {
  const policy: AbacPolicy = {
    rules: {
      readAnonData: true,
    },
  };

  expect(enforceAny(['readData', 'readAnonData'], policy, {})).toBe('readAnonData');
});

test('enforceAny returns false when none of the operations are allowed', () => {
  const policy: AbacPolicy = {
    rules: {
      billingAdmin: true,
    },
  };

  expect(enforceAny(['readData', 'readAnonData'], policy, {})).toBe(false);
});

test('rules can reference values in an array', () => {
  const policy: AbacPolicy = {
    rules: {
      readData: [
        {
          'array.0.value': {
            comparison: 'equals',
            value: 'test',
          },
        },
      ],
    },
  };

  expect(enforce('readData', policy, { array: [{ value: 'test' }] })).toBe(true);
  expect(enforce('readData', policy, { array: [{ value: 'bogus' }] })).toBe(false);
});

test('rules can target array values', () => {
  const policy: AbacPolicy = {
    rules: {
      readData: [
        {
          value: {
            comparison: 'equals',
            target: 'array.0.value',
          },
        },
      ],
    },
  };

  expect(enforce('readData', policy, { value: 'test', array: [{ value: 'test' }] })).toBe(true);
  expect(
    enforce('readData', policy, { value: 'test', array: [{ value: 'bogus' }] }),
  ).toBe(false);
});

test('rules can end with a wildcard', () => {
  const policy: AbacPolicy = {
    rules: {
      readData: [
        {
          'some.*': {
            comparison: 'equals',
            value: 'test',
          },
        },
      ],
    },
  };

  expect(enforce('readData', policy, { some: { a: 'test', b: 'test' } })).toBe(true);
  expect(enforce('readData', policy, { some: { a: 'test', b: 'bogus' } })).toBe(false);
  expect(enforce('readData', policy, { some: ['test', 'test'] })).toBe(true);
  expect(enforce('readData', policy, { some: ['test', 'bogus'] })).toBe(false);
});

test('rules can start with a wildcard', () => {
  const policy: AbacPolicy = {
    rules: {
      readData: [
        {
          '*.some': {
            comparison: 'equals',
            value: 'test',
          },
        },
      ],
    },
  };

  expect(enforce('readData', policy, { a: { some: 'test' }, b: { some: 'test' } })).toBe(true);
  expect(enforce('readData', policy, { a: { some: 'bogus' }, b: { some: 'test' } })).toBe(false);
  expect(enforce('readData', policy, [{ some: 'test' }, { some: 'test' }])).toBe(true);
  expect(enforce('readData', policy, [{ some: 'test' }, { some: 'bogus' }])).toBe(false);
});

test('rules can contain a wildcard', () => {
  const policy: AbacPolicy = {
    rules: {
      readData: [
        {
          'some.*.property': {
            comparison: 'equals',
            value: 'test',
          },
        },
      ],
    },
  };

  expect(enforce('readData', policy, {
    some: { a: { property: 'test' }, b: { property: 'test' } },
  })).toBe(true);
  expect(enforce('readData', policy, {
    some: { a: { property: 'test' }, b: { property: 'bogus' } },
  })).toBe(false);
  expect(enforce('readData', policy, {
    some: [{ property: 'test' }, { property: 'test' }],
  })).toBe(true);
  expect(enforce('readData', policy, {
    some: [{ property: 'test' }, { property: 'bogus' }],
  })).toBe(false);
});

test('wildcard evaluation fails if attribute resolution fails', () => {
  const policy: AbacPolicy = {
    rules: {
      readData: [
        {
          'some.*.property': {
            comparison: 'equals',
            value: 'test',
          },
        },
      ],
    },
  };

  expect(enforce('readData', policy, {})).toBe(false);
  expect(enforce('readData', policy, { some: { property: 'test' } })).toBe(false);
  expect(enforce('readData', policy, {
    some: [{ property: 'test' }, { bogus: 'test' }],
  })).toBe(false);
});

test('wildcard evaluation fails if target resolution fails', () => {
  const policy: AbacPolicy = {
    rules: {
      readData: [
        {
          'some.*.property': {
            comparison: 'equals',
            target: 'missing',
          },
        },
      ],
    },
  };

  expect(enforce('readData', policy, {
    some: [{ property: 'test' }, { property: 'test' }],
  })).toBe(false);
});

test('rules can contain multiple wildcards', () => {
  const policy: AbacPolicy = {
    rules: {
      readData: [
        {
          'some.*.property.*': {
            comparison: 'equals',
            value: 'test',
          },
        },
      ],
    },
  };

  expect(enforce('readData', policy, {
    some: [{ property: ['test', 'test'] }, { property: ['test', 'test'] }],
  })).toBe(true);
  expect(enforce('readData', policy, {
    some: [{ property: ['test', 'bogus'] }, { property: ['test', 'test'] }],
  })).toBe(false);
  expect(enforce('readData', policy, {
    some: [{ property: ['test', 'test'] }, { bogus: ['test', 'test'] }],
  })).toBe(false);
});

test('rules can use numeric comparison values', () => {
  const policy: AbacPolicy = {
    rules: {
      readData: [
        {
          'some.value': {
            comparison: 'equals',
            value: 0,
          },
        },
      ],
    },
  };

  expect(enforce('readData', policy, { some: { value: 0 } })).toBe(true);
  expect(enforce('readData', policy, { some: { value: 1 } })).toBe(false);
});

test('rules can match object keys', () => {
  const policy: AbacPolicy = {
    rules: {
      readData: [
        {
          'some.object.%keys.*': {
            comparison: 'in',
            value: ['a', 'b', 'c'],
          },
          'some.object.%keys.length': {
            comparison: 'equals',
            value: 2,
          },
        },
      ],
    },
  };

  expect(enforce('readData', policy, { some: { object: { a: 1, b: 2 } } })).toBe(true);
  expect(enforce('readData', policy, { some: { object: { a: 1, d: 2 } } })).toBe(false);
  expect(enforce('readData', policy, { some: { object: { a: 1, b: 2, c: 3 } } })).toBe(false);
});

test('rules can match top-level object keys', () => {
  const policy: AbacPolicy = {
    rules: {
      readData: [
        {
          '%keys.*': {
            comparison: 'in',
            value: ['a', 'b', 'c'],
          },
          '%keys.length': {
            comparison: 'equals',
            value: 2,
          },
        },
      ],
    },
  };

  expect(enforce('readData', policy, { a: 1, b: 2 })).toBe(true);
  expect(enforce('readData', policy, { a: 1, d: 2 })).toBe(false);
  expect(enforce('readData', policy, { a: 1, b: 2, c: 3 })).toBe(false);
});

test('rules can match literal %keys attribute', () => {
  const policy: AbacPolicy = {
    rules: {
      readData: [
        {
          'object.%%keys': {
            comparison: 'equals',
            value: 'test',
          },
        },
      ],
    },
  };

  expect(enforce('readData', policy, { object: { '%keys': 'test' } })).toBe(true);
  expect(enforce('readData', policy, { object: { '%keys': 'bogus' } })).toBe(false);
});

test('rules can match top-level literal %keys attribute', () => {
  const policy: AbacPolicy = {
    rules: {
      readData: [
        {
          '%%keys': {
            comparison: 'equals',
            value: 'test',
          },
        },
      ],
    },
  };

  expect(enforce('readData', policy, { '%keys': 'test' })).toBe(true);
  expect(enforce('readData', policy, { '%keys': 'bogus' })).toBe(false);
});

test('returns false for invalid policy', () => {
  const policy: AbacPolicy = {
    rules: {
      readData: {
        // @ts-expect-error
        '?!*bogus*!?': {
          comparison: 'equals',
          value: 'test',
        },
      },
    },
  };

  expect(enforce('readData', policy, {})).toBe(false);
});

test('rules can use equals with complex types', () => {
  const policy: AbacPolicy = {
    rules: {
      readData: [
        {
          a: {
            comparison: 'equals',
            target: 'b',
          },
        },
      ],
    },
  };

  expect(enforce('readData', policy, { a: [1, 2, 3], b: [1, 2, 3] })).toBe(true);
  expect(enforce('readData', policy, { a: [1, 2, 3], b: ['one', 'two', 'three'] })).toBe(false);
  expect(enforce('readData', policy, { a: true, b: true })).toBe(true);
  expect(enforce('readData', policy, { a: 'A', b: 'A' })).toBe(true);
  expect(enforce('readData', policy, { a: 'A', b: 'B' })).toBe(false);
  expect(enforce('readData', policy, { a: true, b: false })).toBe(false);
});

test('rules can use not equals with complex types', () => {
  const policy: AbacPolicy = {
    rules: {
      readData: [
        {
          a: {
            comparison: 'notEquals',
            target: 'b',
          },
        },
      ],
    },
  };

  expect(enforce('readData', policy, { a: [1, 2, 3], b: [1, 2, 3] })).toBe(false);
  expect(enforce('readData', policy, { a: [1, 2, 3], b: ['one', 'two', 'three'] })).toBe(true);
  expect(enforce('readData', policy, { a: true, b: true })).toBe(false);
  expect(enforce('readData', policy, { a: 'A', b: 'A' })).toBe(false);
  expect(enforce('readData', policy, { a: 'A', b: 'B' })).toBe(true);
  expect(enforce('readData', policy, { a: true, b: false })).toBe(true);
});

test('rules can use subset with value', () => {
  const policy: AbacPolicy = {
    rules: {
      readData: [
        {
          a: {
            comparison: 'subset',
            value: [1, 2, 3],
          },
        },
      ],
    },
  };

  expect(enforce('readData', policy, { a: [1, 2, 3] })).toBe(true);
  expect(enforce('readData', policy, { a: [1] })).toBe(true);
  expect(enforce('readData', policy, { a: [4, 5, 6] })).toBe(false);
});

test('rules can use subset with target', () => {
  const policy: AbacPolicy = {
    rules: {
      readData: [
        {
          a: {
            comparison: 'subset',
            target: 'b',
          },
        },
      ],
    },
  };

  expect(enforce('readData', policy, { a: [1, 2, 3], b: [1, 2, 3] })).toBe(true);
  expect(enforce('readData', policy, { a: [1], b: [1, 2, 3] })).toBe(true);
  expect(enforce('readData', policy, { a: [4, 5, 6], b: [1, 2, 3] })).toBe(false);
  expect(enforce('readData', policy, { a: [4, 5, 6] })).toBe(false);
  expect(enforce('readData', policy, { a: '12', b: '123' })).toBe(false);
});

test('rules can use notEquals with explicit values', () => {
  const policy: AbacPolicy = {
    rules: {
      readData: [
        {
          'object.key': {
            comparison: 'notEquals',
            value: 42,
          },
        },
      ],
    },
  };

  expect(enforce('readData', policy, { object: { key: 13 } })).toBe(true);
  expect(enforce('readData', policy, { object: { key: 42 } })).toBe(false);
});

test('rules can use notEquals with referenced values', () => {
  const policy: AbacPolicy = {
    rules: {
      readData: [
        {
          'object.key': {
            comparison: 'notEquals',
            target: 'object.value',
          },
        },
      ],
    },
  };

  expect(enforce('readData', policy, { object: { key: 13, value: 42 } })).toBe(true);
  expect(enforce('readData', policy, { object: { key: 42, value: 42 } })).toBe(false);
  expect(enforce('readData', policy, { object: { key: 13 } })).toBe(false);
});

test('rules can use notIn with explicit values', () => {
  const policy: AbacPolicy = {
    rules: {
      readData: [
        {
          'object.key': {
            comparison: 'notIn',
            value: [1, 2],
          },
        },
      ],
    },
  };

  expect(enforce('readData', policy, { object: { key: 3 } })).toBe(true);
  expect(enforce('readData', policy, { object: { key: 1 } })).toBe(false);
  expect(enforce('readData', policy, { object: { key: 2 } })).toBe(false);
});

test('rules can use notIn with referenced values', () => {
  const policy: AbacPolicy = {
    rules: {
      readData: [
        {
          'object.key': {
            comparison: 'notIn',
            target: 'object.value',
          },
        },
      ],
    },
  };

  expect(enforce('readData', policy, { object: { key: 3, value: [1, 2] } })).toBe(true);
  expect(enforce('readData', policy, { object: { key: 1, value: [1, 2] } })).toBe(false);
  expect(enforce('readData', policy, { object: { key: 2, value: [1, 2] } })).toBe(false);
  expect(enforce('readData', policy, { object: { key: 3 } })).toBe(false);
});

test('rules can use startsWith operator with value', () => {
  const policy: AbacPolicy = {
    rules: {
      readData: [
        {
          'object.value': {
            comparison: 'startsWith',
            value: 'lifeomic/boo/foo',
          },
        },
      ],
    },
  };

  expect(enforce('readData', policy, { object: { value: 'lifeomic/boo/foo' } })).toBe(true);
  expect(enforce('readData', policy, { object: { value: 'dd/lifeomic/boo/foo' } })).toBe(false);
  expect(enforce('readData', policy, { object: { value: undefined } })).toBe(false);
  expect(enforce('readData', policy, { object: { value: null } })).toBe(false);
  expect(enforce('readData', policy, { object: { value: 1 } })).toBe(false);
  expect(enforce('readData', policy, { object: { value: ' ' } })).toBe(false);
});

test('rules can use startsWith operator with no value', () => {
  const policy: AbacPolicy = {
    rules: {
      readData: [
        {
          'object.value': {
            comparison: 'startsWith',
          },
        },
      ],
    },
  };

  expect(enforce('readData', policy, { object: { value: 'foo' } })).toBe(false);
});

test('rules can use startsWith operator with no target value', () => {
  const policy: AbacPolicy = {
    rules: {
      readData: [
        {
          'object.value': {
            comparison: 'startsWith',
            target: 'object.id',
          },
        },
      ],
    },
  };

  expect(enforce('readData', policy, { object: { value: 'foo' } })).toBe(false);
});

test('rules can use startsWith operator with with target value', () => {
  const policy: AbacPolicy = {
    rules: {
      readData: [
        {
          'object.value': {
            comparison: 'startsWith',
            target: 'object.id',
          },
        },
      ],
    },
  };

  expect(enforce('readData', policy, { object: { id: 'foo!', value: 'foo!' } })).toBe(true);
});

test('rules can use endsWith operator with value', () => {
  const policy: AbacPolicy = {
    rules: {
      readData: [
        {
          'object.value': {
            comparison: 'endsWith',
            value: 'lifeomic/boo/foo',
          },
        },
      ],
    },
  };

  expect(enforce('readData', policy, {
    object: { value: 'lifeomic/boo/foo/bar/bar' },
  })).toBe(false);
  expect(enforce('readData', policy, { object: { value: 'dd/lifeomic/boo/foo' } })).toBe(true);
  expect(enforce('readData', policy, { object: { value: undefined } })).toBe(false);
  expect(enforce('readData', policy, { object: { value: null } })).toBe(false);
  expect(enforce('readData', policy, { object: { value: 1 } })).toBe(false);
  expect(enforce('readData', policy, { object: { value: ' ' } })).toBe(false);
});

test('rules can use endsWith operator with no value', () => {
  const policy: AbacPolicy = {
    rules: {
      readData: [
        {
          'object.value': {
            comparison: 'endsWith',
          },
        },
      ],
    },
  };

  expect(enforce('readData', policy, { object: { value: 'foo' } })).toBe(false);
});

test('rules can use endsWith operator with no target value', () => {
  const policy: AbacPolicy = {
    rules: {
      readData: [
        {
          'object.value': {
            comparison: 'endsWith',
            target: 'object.id',
          },
        },
      ],
    },
  };

  expect(enforce('readData', policy, { object: { value: 'foo' } })).toBe(false);
});

test('rules can use endsWith operator with with target value', () => {
  const policy: AbacPolicy = {
    rules: {
      readData: [
        {
          'object.value': {
            comparison: 'endsWith',
            target: 'object.id',
          },
        },
      ],
    },
  };

  expect(enforce('readData', policy, { object: { id: 'foo!', value: 'foo!' } })).toBe(true);
});

test('rules can use notIncludes operator with value', () => {
  const policy: AbacPolicy = {
    rules: {
      readData: [
        {
          'patient.sauces': {
            comparison: 'notIncludes',
            value: 'forbidden-sauce',
          },
        },
      ],
    },
  };

  expect(enforce('readData', policy, {
    patient: { sauces: ['ketchup', 'mustard'] },
  })).toBe(true);

  expect(enforce('readData', policy, {
    patient: { sauces: ['ketchup', 'forbidden-sauce'] },
  })).toBe(false);

  expect(enforce(
    'readData',
    {
      rules: {
        readData: [
          {
            'patient.sauces': {
              comparison: 'notIncludes',
              value: undefined,
            },
          },
        ],
      },
    },
    {
      patient: { sauces: ['ketchup', 'forbidden-sauce'] },
    },
  )).toBe(false);
});

test('rules can use notIncludes operator with target', () => {
  const policy: AbacPolicy = {
    rules: {
      readData: [
        {
          'resource.sauces': {
            comparison: 'notIncludes',
            target: 'patient.favoriteSauce',
          },
        },
      ],
    },
  };

  expect(enforce('readData', policy, {
    patient: { favoriteSauce: 'ketchup' },
    resource: {
      sauces: ['mustard', 'mayo'],
    },
  })).toBe(true);

  expect(enforce('readData', policy, {
    patient: { favoriteSauce: 'ketchup' },
    resource: {
      sauces: ['mustard', 'mayo', 'ketchup'],
    },
  })).toBe(false);

  expect(enforce('readData', policy, {
    patient: { favoriteSauce: 'ketchup' },
    resource: {
      sauces: undefined,
    },
  })).toBe(false);
});

test('rules can use prefixOf operator with value', () => {
  const policy: AbacPolicy = {
    rules: {
      readData: [
        {
          'patient.favoriteSauce': {
            comparison: 'prefixOf',
            value: 'honey-mustard',
          },
        },
      ],
    },
  };

  expect(enforce('readData', policy, {
    patient: { favoriteSauce: 'honey' },
  })).toBe(true);

  expect(enforce('readData', policy, {
    patient: { favoriteSauce: 'ranch' },
  })).toBe(false);

  expect(enforce('readData', policy, {
    patient: { favoriteSauce: undefined },
  })).toBe(false);
});

test('rules can use prefixOf operator with target', () => {
  const policy: AbacPolicy = {
    rules: {
      readData: [
        {
          'patient.favoriteSauce': {
            comparison: 'prefixOf',
            target: 'resource.secretSauce',
          },
        },
      ],
    },
  };

  expect(enforce('readData', policy, {
    patient: { favoriteSauce: 'honey-mayo' },
    resource: {
      secretSauce: 'honey-mayo-spicy',
    },
  })).toBe(true);

  expect(enforce('readData', policy, {
    patient: { favoriteSauce: 'ketchup' },
    resource: {
      secretSauce: 'honey-mayo-spicy',
    },
  })).toBe(false);

  expect(enforce('readData', policy, {
    patient: { favoriteSauce: 'ketchup' },
    resource: {
      secretSauce: undefined,
    },
  })).toBe(false);
});

test('rules can use suffixOf operator with value', () => {
  const policy: AbacPolicy = {
    rules: {
      readData: [
        {
          'patient.favoriteSauce': {
            comparison: 'suffixOf',
            value: 'honey-mustard',
          },
        },
      ],
    },
  };

  expect(enforce('readData', policy, {
    patient: { favoriteSauce: 'mustard' },
  })).toBe(true);

  expect(enforce('readData', policy, {
    patient: { favoriteSauce: 'ranch' },
  })).toBe(false);

  expect(enforce('readData', policy, {
    patient: { favoriteSauce: undefined },
  })).toBe(false);
});

test('rules can use suffixOf operator with target', () => {
  const policy: AbacPolicy = {
    rules: {
      readData: [
        {
          'patient.favoriteSauce': {
            comparison: 'suffixOf',
            target: 'resource.secretSauce',
          },
        },
      ],
    },
  };

  expect(enforce('readData', policy, {
    patient: { favoriteSauce: 'mayo' },
    resource: {
      secretSauce: 'honey-mayo',
    },
  })).toBe(true);

  expect(enforce('readData', policy, {
    patient: { favoriteSauce: 'ketchup' },
    resource: {
      secretSauce: 'honey-mayo',
    },
  })).toBe(false);

  expect(enforce('readData', policy, {
    patient: { favoriteSauce: 'ketchup' },
    resource: {
      secretSauce: undefined,
    },
  })).toBe(false);
});
