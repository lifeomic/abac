import { enforceLenient, AbacPolicy } from '../src';

test('Partially evaluated policy should enforce properly', () => {
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

  expect(enforceLenient('accessAdmin', policy)).toBe(true);
  expect(enforceLenient('readData', policy)).toBe(true);
  expect(enforceLenient('billingAdmin', policy)).toBeFalsy();

  // updateData and deleteData are allowed, because
  // the rules allow them for some attributes, so
  // in the absence of the full attribute set
  // the best we can do is allow it. This is why
  // enforceLenient shouldn't be used for actually
  // securing access, but is fine for a client application.
  expect(enforceLenient('updateData', policy)).toBe(true);
  expect(enforceLenient('deleteData', policy)).toBe(true);

  // Given full information enforceLenient does give correct answers:
  expect(enforceLenient('updateData', policy, {
    resource: { ownerId: 'john' },
    user: { id: 'jane' },
  })).toBeFalsy();
  expect(enforceLenient('deleteData', policy, { resource: { dataset: 'project' } })).toBe(true);
  expect(
    enforceLenient('deleteData', policy, { resource: { dataset: 'project2' } }),
  ).toBeFalsy();
});

test('returns false for invalid operation names', () => {
  expect(enforceLenient('not-an-operation', { rules: {} })).toBe(false);
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

  expect(enforceLenient('readData', policy, {})).toBe(false);
});
