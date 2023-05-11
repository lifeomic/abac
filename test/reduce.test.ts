import test, { ExecutionContext } from 'ava';
import {
  reduce,
  COMPARISON_REVERSION_MAP,
  enforce,
  AbacReducedPolicy,
  AbacRule,
} from '../src';

test('RFC example should reduce properly', (t) => {
  const policy: AbacReducedPolicy = {
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
  let expected: AbacReducedPolicy = {
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
  const policy: AbacReducedPolicy = {
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

const assertComparisonNotReduced = (
  t: ExecutionContext,
  comparison: keyof typeof COMPARISON_REVERSION_MAP,
  value: string | string[] = 'test'
) => {
  const user = { id: value };
  const originalPolicy: AbacReducedPolicy = {
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
  const expectedPolicy: AbacReducedPolicy = {
    rules: {
      readData: [
        {
          'circle.owner.id': {
            comparison: COMPARISON_REVERSION_MAP[comparison],
            target: 'user.id',
          },
        },
      ],
    },
  };

  t.deepEqual(reduce(originalPolicy, { user }), expectedPolicy);
};

const getUserCustomConditions = (resourceName: string): AbacRule => {
  return {
    'user.customAttributes.secret': {
      comparison: 'suffixOf',
      target: `${resourceName}.secret`,
    },
    'user.customAttributes.id': {
      comparison: 'equals',
      target: `${resourceName}.id`,
    },
    'user.customAttributes.isActive': {
      comparison: 'exists',
    },
    'user.customAttributes.patient': {
      comparison: 'in',
      target: `${resourceName}.patients`,
    },
    'user.customAttributes.patients': {
      comparison: 'includes',
      target: `${resourceName}.patient`,
    },
    'user.customAttributes.orgName': {
      comparison: 'notEquals',
      target: `${resourceName}.orgName`,
    },
    'user.customAttributes.name': {
      comparison: 'notIn',
      target: `${resourceName}.forbiddenNames`,
    },
    'user.customAttributes.actions': {
      comparison: 'notIncludes',
      target: `${resourceName}.forbiddenAction`,
    },
    'user.customAttributes.rank': {
      comparison: 'prefixOf',
      target: `${resourceName}.rankOrder`,
    },
    'user.customAttributes.group': {
      comparison: 'startsWith',
      target: `${resourceName}.parentGroup`,
    },
    'user.customAttributes.permissions': {
      comparison: 'subset',
      target: `${resourceName}.permissions`,
    },
    'user.customAttributes.nameSuffix': {
      comparison: 'suffixOf',
      target: `${resourceName}.allowedSuffix`,
    },
    'user.customAttributes.positions': {
      comparison: 'superset',
      target: `${resourceName}.positions`,
    },
  };
};

test.only('reverses conditions when key value is known and target value is unknown', (t) => {
  const user = {
    customAttributes: {
      secret: 'confidential',
      id: 'user-id',
      patient: 'patient-zero',
      patients: ['patient-one', 'patient-two'],
      orgName: 'LifeOmic',
      name: 'John Doe',
      actions: ['ENFORCE', 'PROMOTE'],
      rank: '1-2-3',
      group: 'hikers-pro',
      permissions: ['ADMIN', 'SUPER_ADMIN'],
      nameSuffix: 'The Third',
      positions: ['ADMIRAL', 'CAPTAIN'],
    },
  };
  const resource = {
    carrierName: 'verizon',
    lastName: 'Johnson',
  };
  const initialPolicy = {
    rules: {
      readData: [
        Object.assign(getUserCustomConditions('resource'), {
          'user.customAttributes.favoriteSauce': {
            comparison: 'in',
            value: ['ketchup', 'mayo'],
          },
          'user.customAttributes.lastNames': {
            comparison: 'includes',
            target: 'resource.lastName',
          },
          'user.customAttributes.carrierNames': {
            comparison: 'notIncludes',
            target: 'resource.carrierName',
          },
        }),
      ],
    },
  };

  const expectedPolicy: AbacReducedPolicy = {
    rules: {
      readData: [
        {
          'resource.secret': {
            comparison: 'endsWith',
            target: 'user.customAttributes.secret',
          },
          'resource.id': {
            comparison: 'equals',
            target: 'user.customAttributes.id',
          },
          'resource.patients': {
            comparison: 'includes',
            target: 'user.customAttributes.patient',
          },
          'resource.patient': {
            comparison: 'in',
            target: 'user.customAttributes.patients',
          },
          'resource.orgName': {
            comparison: 'notEquals',
            target: 'user.customAttributes.orgName',
          },
          'resource.forbiddenNames': {
            comparison: 'notIncludes',
            target: 'user.customAttributes.name',
          },
          'resource.forbiddenAction': {
            comparison: 'notIn',
            target: 'user.customAttributes.actions',
          },
          'resource.rankOrder': {
            comparison: 'startsWith',
            target: 'user.customAttributes.rank',
          },
          'resource.parentGroup': {
            comparison: 'prefixOf',
            target: 'user.customAttributes.group',
          },
          'resource.permissions': {
            comparison: 'superset',
            target: 'user.customAttributes.permissions',
          },
          'resource.allowedSuffix': {
            comparison: 'endsWith',
            target: 'user.customAttributes.nameSuffix',
          },
          'resource.positions': {
            comparison: 'subset',
            target: 'user.customAttributes.positions',
          },
          // Conditions with known target values should not be reversed.
          'user.customAttributes.lastNames': {
            comparison: 'includes',
            target: 'resource.lastName',
          },
          // Conditions with unknown keys should not be reversed.
          'user.customAttributes.carrierNames': {
            comparison: 'notIncludes',
            target: 'resource.carrierName',
          },
          // Conditions with "value" should not be reversed.
          'user.customAttributes.favoriteSauce': {
            comparison: 'in',
            value: ['ketchup', 'mayo'],
          },
          // 'exists' can't be used with a target, so assert that its
          // condition wasn't reversed.
          'user.customAttributes.isActive': {
            comparison: 'exists',
          },
        },
      ],
    },
  };

  t.deepEqual(
    reduce(initialPolicy, {
      user,
      resource,
    }),
    expectedPolicy
  );
});

test('that reversed conditions still correctly reduce final policy', (t) => {
  const user = {
    customAttributes: {
      actions: ['HIKE', 'SNOWBOARD'],
      group: 'pro-hikers elite',
      rank: '1-2-3',
      id: 'user-id',
      isActive: true,
      name: 'John Doe',
      nameSuffix: 'The Third',
      orgName: 'LifeOmic',
      patient: 'patient-zero',
      patients: ['patient-zero', 'patient-one', 'patient-two', 'patient-three'],
      permissions: ['READ', 'WRITE'],
      positions: ['BOSS'],
      secret: 'confidential',
    },
  };
  const matchingResource = Object.assign({}, user.customAttributes, {
    allowedSuffix: 'The Third',
    forbiddenAction: 'leave',
    forbiddenNames: ['conor'],
    orgName: 'Acme',
    parentGroup: 'pro-hikers',
    rankOrder: '1-2-3-4-5-6-7',
  });
  const privateResource = {
    actions: ['HIKE'],
    allowedSuffix: 'The Third',
    forbiddenAction: 'leave',
    forbiddenNames: ['conor'],
    group: 'pro skiers',
    id: 'resource-id',
    isActive: false,
    name: 'Mac Miller',
    nameSuffix: 'Knight The Third',
    orgName: 'Acme',
    parentGroup: 'pro-hikers',
    patient: 'patient-zero',
    patients: ['patient-x'],
    permissions: ['READ'],
    positions: ['BOSS', 'VP'],
    rankOrder: '1-2',
    secret: 'super-secret-stuff',
  };

  const initialPolicy: AbacReducedPolicy = {
    rules: {
      // Not expected to be in final policy since the custom conditions
      // are not supposed to match.
      writeData: [getUserCustomConditions('privateResource')],
      // Expected to be true in the final policy since the custom conditions
      // are supposed to match.
      readData: [getUserCustomConditions('matchingResource')],
      // Expected to not be evaluated and just have literal policy values
      deleteData: [
        getUserCustomConditions('privateResource'),
        {
          'user.customAttributes.favoriteSauce': {
            comparison: 'in',
            value: ['ketchup', 'mayo'],
          },
        },
      ],
    },
  };
  const expectedPolicy: AbacReducedPolicy = {
    rules: {
      readData: true,
      deleteData: [
        {
          'user.customAttributes.favoriteSauce': {
            comparison: 'in',
            value: ['ketchup', 'mayo'],
          },
        },
      ],
    },
  };
  const attributes = {
    user,
    matchingResource,
    privateResource,
  };
  const reducedPolicy = reduce(initialPolicy, attributes);

  t.deepEqual(reducedPolicy, expectedPolicy);
  // Enforce that the original policy is enforced in the same way as the
  // reduced policy with reversions.
  t.deepEqual(
    enforce('writeData', initialPolicy, attributes),
    enforce('writeData', reducedPolicy, attributes)
  );
  t.deepEqual(
    enforce('readData', initialPolicy, attributes),
    enforce('readData', reducedPolicy, attributes)
  );
  t.deepEqual(
    enforce('deleteData', initialPolicy, attributes),
    enforce('deleteData', reducedPolicy, attributes)
  );
});

test('that known inline target attributes are replaced with in-line values', (t) => {
  const initialPolicy: AbacReducedPolicy = {
    rules: {
      readData: [
        {
          'resource.id': {
            comparison: 'in',
            target: 'user.customAttributes.myCustomPatients',
          },
          'resource.orgId': {
            comparison: 'notEquals',
            target: 'user.customAttributes.forbiddenOrgId',
          },
          'resource.isPastDue': {
            comparison: 'notEquals',
            target: 'user.customAttributes.isPastDue',
          },
        },
        {
          'resource.secret': {
            comparison: 'equals',
            target: 'user.customAttributes.myCustomSecret',
          },
          'resource.anotherSecret': {
            comparison: 'equals',
            // Validate that keys starting with the same name as the inline
            // target don't actually get inlined. We want to check for
            // exact paths.
            target: 'user.customAttributesEdgeCase',
          },
          'resource.isActive': {
            comparison: 'equals',
            target: 'user.customAttributes.isActive',
          },
        },
      ],
    },
  };

  const expectedPolicy: AbacReducedPolicy = {
    rules: {
      readData: [
        {
          'resource.id': {
            comparison: 'in',
            value: ['patient-one', 'patient-two', 'patient-three'],
          },
          'resource.orgId': {
            comparison: 'notEquals',
            value: 'e-corp',
          },
          'resource.isPastDue': {
            comparison: 'notEquals',
            value: true,
          },
        },
        {
          'resource.secret': {
            comparison: 'equals',
            value: 'secret-sauce',
          },
          'resource.anotherSecret': {
            comparison: 'equals',
            target: 'user.customAttributesEdgeCase',
          },
          'resource.isActive': {
            comparison: 'equals',
            target: 'user.customAttributes.isActive',
          },
        },
      ],
    },
  };

  t.deepEqual(
    reduce(
      initialPolicy,
      {
        user: {
          customAttributes: {
            myCustomPatients: ['patient-one', 'patient-two', 'patient-three'],
            myCustomSecret: 'secret-sauce',
            forbiddenOrgId: 'e-corp',
            isPastDue: true,
          },
          customAttributesEdgeCase: 'some-value',
        },
        resource: { ownerId: 'testuser' },
      },
      {
        inlineTargets: ['user.customAttributes'],
      }
    ),
    expectedPolicy
  );
});

test('rules with undefined comparison targets should not be reduced', (t) => {
  assertComparisonNotReduced(t, 'equals');
  assertComparisonNotReduced(t, 'superset', ['test']);
  assertComparisonNotReduced(t, 'includes', ['test']);
  assertComparisonNotReduced(t, 'notEquals');
  assertComparisonNotReduced(t, 'notIn', ['test']);
});

test('validates reduce options', (t) => {
  const policy: AbacReducedPolicy = {
    rules: {
      accessAdmin: [
        {
          'user.groups': {
            comparison: 'includes',
            value: 'some-id',
          },
        },
      ],
    },
  };

  // @ts-expect-error
  t.throws(() => reduce(policy, { user: { groups: [] } }, []), {
    message: 'data should be object',
  });
  t.throws(
    () =>
      reduce(
        policy,
        { user: { groups: [] } },
        // @ts-expect-error
        { invalidOption: ['1'], inlineTargets: ['user.customAttributes'] }
      ),
    { message: 'data should NOT have additional properties' }
  );
  t.throws(
    () => reduce(policy, { user: { groups: [] } }, { inlineTargets: [] }),
    { message: 'data.inlineTargets should NOT have fewer than 1 items' }
  );
  t.throws(
    () =>
      // @ts-expect-error
      reduce(policy, { user: { groups: [] } }, { inlineTargets: [{ id: 1 }] }),
    { message: 'data.inlineTargets[0] should be string' }
  );
  t.notThrows(() =>
    reduce(policy, { user: { groups: [] } }, { inlineTargets: ['1'] })
  );
});
