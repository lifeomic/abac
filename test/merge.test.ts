import { merge, AbacPolicy } from '../src';

test('Two halves of the RFC example should merge to produce the full example', () => {
  const policies: AbacPolicy[] = [
    {
      rules: {
        accessAdmin: [
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
        ],
      },
    },
    {
      rules: {
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
    },
  ];

  const expected: AbacPolicy = {
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

  const original = JSON.parse(JSON.stringify(policies));

  expect(merge(policies)).toEqual(expected);

  // The original policies should be unchanged:
  expect(policies).toEqual(original);
});

test('rules that are true should trump all others', () => {
  const policies: AbacPolicy[] = [
    {
      rules: {
        readData: true,
        deleteData: [
          {
            'user.groups': {
              comparison: 'includes',
              value: '1af3ed70-018b-46cc-ba41-7b731fcb182f',
            },
          },
        ],
      },
    },
    {
      rules: {
        readData: [
          {
            'user.groups': {
              comparison: 'includes',
              value: '1af3ed70-018b-46cc-ba41-7b731fcb182f',
            },
          },
        ],
        deleteData: true,
      },
    },
  ];

  const expected: AbacPolicy = {
    rules: {
      readData: true,
      deleteData: true,
    },
  };

  expect(merge(policies)).toEqual(expected);
});

test('merging a single policy should produce the single policy', () => {
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

  expect(merge([policy])).toEqual(policy);
});

test('merging nothing should produce a deny all policy', () => {
  expect(merge([])).toEqual({ rules: {} });
});
