import {
  reduce,
  COMPARISON_REVERSION_MAP,
  enforce,
  AbacPolicy,
  AbacRule,
} from '../src';

test('RFC example should reduce properly', () => {
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
  let expected: AbacPolicy = {
    rules: {
      accessAdmin: true,
      billingAdmin: true,
      readData: true,
    },
  };
  expect(reduce(policy, { user })).toEqual(expected);

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
  expect(reduce(policy, { user })).toEqual(expected);

  // user in no groups gets no access:
  user = { groups: [] };
  expected = { rules: {} };
  expect(reduce(policy, { user })).toEqual(expected);

  // user just in TNBC group, but not doctor gets no access:
  user = { groups: ['8cfdd7b2-236e-4001-8d98-75d931877bbb'] };
  expected = { rules: {} };
  expect(reduce(policy, { user })).toEqual(expected);
});

test('A policy that has no access, gives everyone no access', () => {
  let user = { groups: ['1af3ed70-018b-46cc-ba41-7b731fcb182f'] };
  expect(reduce({ rules: {} }, { user })).toEqual({ rules: {} });

  user = { groups: [] };
  expect(reduce({ rules: {} }, { user })).toEqual({ rules: {} });
});

test('A policy with all access, gives everyone access', () => {
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
  expect(reduce(policy, { user })).toEqual(policy);

  user = { groups: [] };
  expect(reduce(policy, { user })).toEqual(policy);
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
  const expectedPolicy1: AbacPolicy = {
    rules: {
      readData: true,
    },
  };

  expect(reduce(policy, { user, resource: resource1 })).toEqual(expectedPolicy1);

  // Test that a user cannot read a different user's resource
  const resource2 = { ownerId: 'testuser2' };
  const expectedPolicy2 = {
    rules: {},
  };
  expect(reduce(policy, { user, resource: resource2 })).toEqual(expectedPolicy2);
});

const assertComparisonNotReduced = (
  comparison: keyof typeof COMPARISON_REVERSION_MAP,
  value: string | string[] = 'test',
) => {
  const user = { id: value };
  const originalPolicy: AbacPolicy = {
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
  const expectedPolicy: AbacPolicy = {
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

  expect(reduce(originalPolicy, { user })).toEqual(expectedPolicy);
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

test(
  'reverses conditions when key value is known and target value is unknown',
  () => {
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

    const expectedPolicy: AbacPolicy = {
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

    expect(reduce(initialPolicy, {
      user,
      resource,
    })).toEqual(expectedPolicy);
  },
);

test('that reversed conditions still correctly reduce final policy', () => {
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

  const initialPolicy: AbacPolicy = {
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
  const expectedPolicy: AbacPolicy = {
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

  expect(reducedPolicy).toEqual(expectedPolicy);
  // Enforce that the original policy is enforced in the same way as the
  // reduced policy with reversions.
  expect(enforce('writeData', initialPolicy, attributes)).toEqual(enforce('writeData', reducedPolicy, attributes));
  expect(enforce('readData', initialPolicy, attributes)).toEqual(enforce('readData', reducedPolicy, attributes));
  expect(enforce('deleteData', initialPolicy, attributes)).toEqual(enforce('deleteData', reducedPolicy, attributes));
});

test('that known inline target attributes are replaced with in-line values', () => {
  const initialPolicy: AbacPolicy = {
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

  const expectedPolicy: AbacPolicy = {
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

  expect(reduce(
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
    },
  )).toEqual(expectedPolicy);
});

test('rules with undefined comparison targets should not be reduced', () => {
  assertComparisonNotReduced( 'equals');
  assertComparisonNotReduced( 'superset', ['test']);
  assertComparisonNotReduced( 'includes', ['test']);
  assertComparisonNotReduced( 'notEquals');
  assertComparisonNotReduced( 'notIn', ['test']);
});

test('validates reduce options', () => {
  const policy: AbacPolicy = {
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

  expect(() => reduce(
    policy,
    { user: { groups: [] } },
    // @ts-expect-error
    [],
  )).toThrow(/data (should|must) be object/);

  expect(() =>
    reduce(
      policy,
      { user: { groups: [] } },
      {
        // @ts-expect-error
        invalidOption: ['1'],
        inlineTargets: ['user.customAttributes'],
      },
    )).toThrow(/data (should|must) NOT have additional properties/);
  expect(() => reduce(
    policy,
    { user: { groups: [] } },
    // @ts-expect-error A single entry is required
    { inlineTargets: [] },
  ))
    .toThrow(/data[./]inlineTargets (should|must) NOT have fewer than 1 items/);
  expect(() =>
    // @ts-expect-error
    reduce(policy, { user: { groups: [] } }, { inlineTargets: [{ id: 1 }] }))
    .toThrow(/data[./]inlineTargets(\[0]|\/0) (should|must) be string/);
  expect(() =>
    reduce(policy, { user: { groups: [] } }, { inlineTargets: ['1'] })).not.toThrow();
});
