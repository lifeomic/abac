import { policyRequiresAttribute } from '../dist';
import test from 'ava';

test('should return true when attribute is required', t => {
  const policy = {
    rules: {
      accessAdmin: false,
      writeData: true,
      readData: [
        {
          'user.patients': {
            comparison: 'includes',
            target: 'resource.subject'
          }
        }
      ]
    }
  };

  t.true(policyRequiresAttribute(policy, 'user.patients'));
  t.false(policyRequiresAttribute(policy, 'user.sobaNoodles'));
});
