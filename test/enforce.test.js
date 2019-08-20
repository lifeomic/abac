'use strict';

import {enforce, enforceAny} from '../dist';
import test from 'ava';

test('RFC example should enforce properly', t => {
  const policy = {
    rules: {
      accessAdmin: [
        {
          'user.groups': {
            comparison: 'includes',
            value: '1af3ed70-018b-46cc-ba41-7b731fcb182f'
          }
        }
      ],
      billingAdmin: [
        {
          'user.groups': {
            comparison: 'includes',
            value: '1af3ed70-018b-46cc-ba41-7b731fcb182f'
          }
        }
      ],
      readData: [
        {
          'user.groups': {
            comparison: 'includes',
            value: '1af3ed70-018b-46cc-ba41-7b731fcb182f'
          }
        },
        {
          'user.groups': {
            comparison: 'superset',
            value: ['8cfdd7b2-236e-4001-8d98-75d931877bbb', '1456d7e3-1bc0-4849-8c50-940a4eb3c07c']
          },
          'resource.dataset': {
            comparison: 'equals',
            value: '6a2db2e4-f0fc-4db7-9a8f-28ab14667257'
          }
        }
      ]
    }
  };

  // admin group gets access to all three operations:
  let user = {groups: ['1af3ed70-018b-46cc-ba41-7b731fcb182f']};
  let resource = {dataset: '6a2db2e4-f0fc-4db7-9a8f-28ab14667257'};
  t.true(enforce('accessAdmin', policy, {user, resource}));
  t.true(enforce('billingAdmin', policy, {user, resource}));
  t.true(enforce('readData', policy, {user, resource}));
  t.false(enforce('downloadFile', policy, {user, resource}));

  // members of both TNBC and Doctors gets readData for the TNBC dataset:
  user = {
    groups: [
      '8cfdd7b2-236e-4001-8d98-75d931877bbb',
      '1456d7e3-1bc0-4849-8c50-940a4eb3c07c',
      'a5e15ccd-d853-4da2-8d1c-63630a47ba5d'
    ]};
  resource = {dataset: '6a2db2e4-f0fc-4db7-9a8f-28ab14667257'};
  t.false(enforce('accessAdmin', policy, {user, resource}));
  t.false(enforce('billingAdmin', policy, {user, resource}));
  t.true(enforce('readData', policy, {user, resource}));
  t.false(enforce('downloadFile', policy, {user, resource}));

  // members of both TNBC and Doctors gets no access to PED dataset:
  user = {
    groups: [
      '8cfdd7b2-236e-4001-8d98-75d931877bbb',
      '1456d7e3-1bc0-4849-8c50-940a4eb3c07c',
      'a5e15ccd-d853-4da2-8d1c-63630a47ba5d'
    ]};
  resource = {dataset: '62271b6b-35f2-4565-83d8-c1d7a32ec95b'};
  t.false(enforce('accessAdmin', policy, {user, resource}));
  t.false(enforce('billingAdmin', policy, {user, resource}));
  t.false(enforce('readData', policy, {user, resource}));
  t.false(enforce('downloadFile', policy, {user, resource}));

  // user in no groups gets no access:
  user = {groups: []};
  resource = {dataset: '6a2db2e4-f0fc-4db7-9a8f-28ab14667257'};
  t.false(enforce('accessAdmin', policy, {user, resource}));
  t.false(enforce('billingAdmin', policy, {user, resource}));
  t.false(enforce('readData', policy, {user, resource}));
  t.false(enforce('downloadFile', policy, {user, resource}));

  // user just in TNBC group, but not doctor gets no access:
  user = {groups: ['8cfdd7b2-236e-4001-8d98-75d931877bbb']};
  resource = {dataset: '6a2db2e4-f0fc-4db7-9a8f-28ab14667257'};
  t.false(enforce('accessAdmin', policy, {user, resource}));
  t.false(enforce('billingAdmin', policy, {user, resource}));
  t.false(enforce('readData', policy, {user, resource}));
  t.false(enforce('downloadFile', policy, {user, resource}));
});

test('A policy that has no access, gives everyone no access', t => {
  let user = {groups: ['1af3ed70-018b-46cc-ba41-7b731fcb182f']};
  let resource = {dataset: '6a2db2e4-f0fc-4db7-9a8f-28ab14667257'};
  t.false(enforce('readData', {rules: {}}, {user, resource}));

  user = {groups: []};
  resource = {dataset: '6a2db2e4-f0fc-4db7-9a8f-28ab14667257'};
  t.false(enforce('readData', {rules: {}}, {user, resource}));
});

test('A policy with all access, gives everyone access to everything', t => {
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
      downloadFile: true
    }
  };

  let user = {groups: ['1af3ed70-018b-46cc-ba41-7b731fcb182f']};
  t.true(enforce('accessAdmin', policy, {user}));
  t.true(enforce('readData', policy, {user}));

  user = {groups: []};
  t.true(enforce('accessAdmin', policy, {user}));
  t.true(enforce('readData', policy, {user}));
});

test('can enforce positive exists conditionals', t => {
  const policy = {
    rules: {
      readLifeData: [
        {
          // Allow reading any educational content
          'educationalContent': {
            comparison: 'exists'
          }
        }
      ]
    }
  };

  // Test that a user can read educational content
  const user = {id: 'testuser'};
  const educationalContent = {id: 'some content'};
  t.true(enforce('readLifeData', policy, {user, educationalContent}));

  // Test that a user cannot read fasting data
  const fastingData = {id: 'some fast'};
  t.false(enforce('readLifeData', policy, {user, fastingData}));
});

test('supports target attributes', t => {
  const policy = {
    rules: {
      readData: [
        {
          // Allow reading if the current user is the owner
          'resource.ownerId': {
            comparison: 'equals',
            target: 'user.id'
          }
        }
      ]
    }
  };

  // Test that a user can read their own resources
  const user = {id: 'testuser'};
  const resource1 = {ownerId: 'testuser'};
  t.true(enforce('readData', policy, {user, resource: resource1}));

  // Test that a user cannot read a different user's resource
  const resource2 = {ownerId: 'testuser2'};
  t.false(enforce('readData', policy, {user, resource: resource2}));
});

test('returns false for invalid operation names', t => {
  t.false(enforce('not-an-operation', {rules: {}}, {}));
});

test('A policy with a new operation works as expected', t => {
  const policy = {
    rules: {
      someNewThing: true
    }
  };

  let user = {groups: ['1af3ed70-018b-46cc-ba41-7b731fcb182f']};
  t.true(enforce('someNewThing', policy, {user}));
  t.false(enforce('readData', policy, {user}));

  user = {groups: []};
  t.true(enforce('someNewThing', policy, {user}));
  t.false(enforce('readData', policy, {user}));
});

test('enforceAny returns the first allowed operation when multiple are allowed', t => {
  const policy = {
    rules: {
      readData: true,
      readAnonData: true
    }
  };

  t.is(enforceAny(['readData', 'readAnonData'], policy, {}), 'readData');
});

test('enforceAny returns the first allowed operation when only one is allowed', t => {
  const policy = {
    rules: {
      readAnonData: true
    }
  };

  t.is(enforceAny(['readData', 'readAnonData'], policy, {}), 'readAnonData');
});

test('enforceAny returns false when none of the operations are allowed', t => {
  const policy = {
    rules: {
      billingAdmin: true
    }
  };

  t.false(enforceAny(['readData', 'readAnonData'], policy, {}));
});
