import { privileges, privilegesLenient, AbacPolicy } from '../src';

test('privileges should work', () => {
  const policy: AbacPolicy = {
    rules: {
      accessAdmin: true,
      readData: true,
      deleteData: [
        {
          'resource.dataset': {
            comparison: 'equals',
            value: 'project',
          },
        },
      ],
      updateData: [
        {
          'resource.ownerId': {
            comparison: 'equals',
            target: 'user.id',
          },
        },
      ],
    },
  };

  expect(privileges(policy)).toEqual(['accessAdmin', 'readData']);
  expect(
    privileges(policy, { resource: { ownerId: 'john' }, user: { id: 'jane' } }),
  ).toEqual(['accessAdmin', 'readData']);
  expect(privileges(policy, { resource: { dataset: 'project' } })).toEqual([
    'accessAdmin',
    'readData',
    'deleteData',
  ]);
  expect(privileges(policy, { resource: { dataset: 'project2' } })).toEqual([
    'accessAdmin',
    'readData',
  ]);
});

test('privilegesLenient should work', () => {
  const policy: AbacPolicy = {
    rules: {
      accessAdmin: true,
      readData: true,
      deleteData: [
        {
          'resource.dataset': {
            comparison: 'equals',
            value: 'project',
          },
        },
      ],
      updateData: [
        {
          'resource.ownerId': {
            comparison: 'equals',
            target: 'user.id',
          },
        },
      ],
    },
  };

  // privilegesLenient does the best it can given incomplete information
  // and is permissive:
  expect(privilegesLenient(policy)).toEqual([
    'accessAdmin',
    'readData',
    'deleteData',
    'updateData',
  ]);
  expect(privilegesLenient(policy, {
    resource: { ownerId: 'john' },
    user: { id: 'jane' },
  })).toEqual(['accessAdmin', 'readData', 'deleteData']);
  expect(privilegesLenient(policy, { resource: { dataset: 'project' } })).toEqual([
    'accessAdmin',
    'readData',
    'deleteData',
    'updateData',
  ]);

  // given full information, privilegesLenient gives correct answers:
  expect(privilegesLenient(policy, {
    resource: { dataset: 'project', ownerId: 'john' },
    user: { id: 'john' },
  })).toEqual(['accessAdmin', 'readData', 'deleteData', 'updateData']);
  expect(privilegesLenient(policy, {
    resource: { dataset: 'project2', ownerId: 'john' },
    user: { id: 'jane' },
  })).toEqual(['accessAdmin', 'readData']);
});
