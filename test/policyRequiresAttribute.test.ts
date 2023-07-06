import { AbacPolicy, policyRequiresAttribute } from '../src';

test('should return true when attribute is required', () => {
  const policy: AbacPolicy = {
    rules: {
      writeData: true,
      readData: [
        {
          'user.patients': {
            comparison: 'includes',
            target: 'resource.subject',
          },
        },
        {
          'user.consents.*.tags': {
            comparison: 'superset',
            target: 'resource.tags',
          },
        },
        {
          something: {
            comparison: 'equals',
            target: 'other.value',
          },
        },
      ],
    },
  };

  expect(policyRequiresAttribute(policy, 'user.patients')).toBe(true);
  expect(policyRequiresAttribute(policy, 'resource.subject')).toBe(true);
  expect(policyRequiresAttribute(policy, 'user.consents')).toBe(true);
  expect(policyRequiresAttribute(policy, 'other')).toBe(true);

  expect(policyRequiresAttribute(policy, 'consent')).toBe(false); // not a prefix
  expect(policyRequiresAttribute(policy, 'some')).toBe(false); // some !== something
  expect(policyRequiresAttribute(policy, 'user.sobaNoodles')).toBe(false);
});
