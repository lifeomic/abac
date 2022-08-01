'use strict';

import { reduce } from '../dist';
import test from 'ava';

test('RFC example should reduce properly', (t) => {
  const policy = {
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
  let expected = {
    rules: {
      accessAdmin: true,
      billingAdmin: true,
      readData: true,
    },
  };
  t.deepEqual(reduce(policy, { user }), expected);

  // members of both TNBC and Doctors gets readData for the TNBC dataset:
  user = {
    groups: [
      '8cfdd7b2-236e-4001-8d98-75d931877bbb',
      '1456d7e3-1bc0-4849-8c50-940a4eb3c07c',
      'a5e15ccd-d853-4da2-8d1c-63630a47ba5d',
    ],
  };
  expected = {
    rules: {
      readData: [
        {
          'resource.dataset': {
            comparison: 'equals',
            value: '6a2db2e4-f0fc-4db7-9a8f-28ab14667257',
          },
        },
      ],
    },
  };
  t.deepEqual(reduce(policy, { user }), expected);

  // user in no groups gets no access:
  user = { groups: [] };
  expected = { rules: {} };
  t.deepEqual(reduce(policy, { user }), expected);

  // user just in TNBC group, but not doctor gets no access:
  user = { groups: ['8cfdd7b2-236e-4001-8d98-75d931877bbb'] };
  expected = { rules: {} };
  t.deepEqual(reduce(policy, { user }), expected);
});

test('A policy that has no access, gives everyone no access', (t) => {
  let user = { groups: ['1af3ed70-018b-46cc-ba41-7b731fcb182f'] };
  t.deepEqual(reduce({ rules: {} }, { user }), { rules: {} });

  user = { groups: [] };
  t.deepEqual(reduce({ rules: {} }, { user }), { rules: {} });
});

test('A policy with all access, gives everyone access', (t) => {
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

  let user = { groups: ['1af3ed70-018b-46cc-ba41-7b731fcb182f'] };
  t.deepEqual(reduce(policy, { user }), policy);

  user = { groups: [] };
  t.deepEqual(reduce(policy, { user }), policy);
});

test('supports target attributes', (t) => {
  const policy = {
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
  const expectedPolicy1 = {
    rules: {
      readData: true,
    },
  };

  t.deepEqual(reduce(policy, { user, resource: resource1 }), expectedPolicy1);

  // Test that a user cannot read a different user's resource
  const resource2 = { ownerId: 'testuser2' };
  const expectedPolicy2 = {
    rules: {},
  };
  t.deepEqual(reduce(policy, { user, resource: resource2 }), expectedPolicy2);
});

const assertComparisonNotReduced = (t, comparison, value = 'test') => {
  const policy = {
    rules: {
      readData: [
        {
          'user.id': {
            comparison,
            target: 'circle.owner.id',
          },
        },
      ],
    },
  };

  const user = { id: value };
  const expected = {
    rules: {
      readData: policy.rules.readData,
    },
  };
  t.deepEqual(reduce(policy, { user }), expected);
};

test('rules with undefined comparison targets should not be reduced', (t) => {
  assertComparisonNotReduced(t, 'equals');
  assertComparisonNotReduced(t, 'superset', ['test']);
  assertComparisonNotReduced(t, 'includes', ['test']);
  assertComparisonNotReduced(t, 'notEquals');
  assertComparisonNotReduced(t, 'notIn', ['test']);
});
