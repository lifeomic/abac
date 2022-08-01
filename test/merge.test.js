'use strict';

import { merge } from '../dist';
import test from 'ava';

test('Two halves of the RFC example should merge to produce the full example', (t) => {
  const policies = [
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

  const expected = {
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

  t.deepEqual(merge(policies), expected);

  // The original policies should be unchanged:
  t.deepEqual(policies, original);
});

test('rules that are true should trump all others', (t) => {
  const policies = [
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

  const expected = {
    rules: {
      readData: true,
      deleteData: true,
    },
  };

  t.deepEqual(merge(policies), expected);
});

test('merging a single policy should produce the single policy', (t) => {
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

  t.deepEqual(merge([policy]), policy);
});

test('merging nothing should produce a deny all policy', (t) => {
  t.deepEqual(merge([]), { rules: {} });
});
