import test from 'ava';
import { AbacPolicy, policyRequiresAttribute } from '../src';

test('should return true when attribute is required', (t) => {
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

  t.true(policyRequiresAttribute(policy, 'user.patients'));
  t.true(policyRequiresAttribute(policy, 'resource.subject'));
  t.true(policyRequiresAttribute(policy, 'user.consents'));
  t.true(policyRequiresAttribute(policy, 'other'));

  t.false(policyRequiresAttribute(policy, 'consent')); // not a prefix
  t.false(policyRequiresAttribute(policy, 'some')); // some !== something
  t.false(policyRequiresAttribute(policy, 'user.sobaNoodles'));
});
