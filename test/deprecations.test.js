'use strict';

import * as abac from '../dist';
import test from 'ava';

test('deprecated enforceSync(...) should still work but call enforceLenient(...)', t => {
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
      billingAdmin: true
    }
  };

  {
    const enforceSyncResult = abac.enforceSync('accessAdmin', policy);
    const enforceLenientResult = abac.enforceLenient('accessAdmin', policy);

    t.is(enforceSyncResult, enforceLenientResult);
    t.true(enforceLenientResult);
  }

  {
    const enforceSyncResult = abac.enforceSync('billingAdmin', policy);
    const enforceLenientResult = abac.enforceLenient('billingAdmin', policy);

    t.is(enforceSyncResult, enforceLenientResult);
    t.true(enforceLenientResult);
  }
});

test('deprecated reduceSync(...) should still work but call reduce(...)', t => {
  const policy = {
    rules: {
      accessAdmin: [
        {
          'user.groups': {
            comparison: 'includes',
            value: 'xyz'
          }
        }
      ],
      billingAdmin: true,
      readData: [
        {
          'resource.id': {
            comparison: 'equals',
            value: 'abc'
          }
        }
      ]
    }
  };

  const attributes = {
    user: {
      groups: ['abc', 'xyz']
    }
  };

  const reduceSyncResult = abac.reduceSync(policy, attributes);
  const reduceResult = abac.reduce(policy, attributes);

  t.deepEqual(reduceSyncResult, reduceResult);
  t.deepEqual(reduceSyncResult, {
    rules: {
      accessAdmin: true,
      billingAdmin: true,
      readData: policy.rules.readData
    }
  });
});

test('deprecated privilegesSync(...) should still work but call privilegesLenient(...)', t => {
  const policy = {
    rules: {
      accessAdmin: [
        {
          'user.groups': {
            comparison: 'includes',
            value: 'xyz'
          }
        }
      ],
      billingAdmin: true,
      readData: [
        {
          'resource.id': {
            comparison: 'equals',
            value: 'abc'
          }
        }
      ],
      writeData: [
        {
          'user.groups': {
            comparison: 'includes',
            value: 'blah'
          }
        }
      ]
    }
  };

  const attributes = {
    user: {
      groups: ['abc', 'xyz']
    }
  };

  const privilegesSyncResult = abac.privilegesSync(policy, attributes);
  const privelegesLenientResult = abac.privilegesLenient(policy, attributes);

  privilegesSyncResult.sort();
  privelegesLenientResult.sort();

  t.deepEqual(privilegesSyncResult, privelegesLenientResult);
  t.deepEqual(privelegesLenientResult, ['accessAdmin', 'billingAdmin', 'readData']);
});
