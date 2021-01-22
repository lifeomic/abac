import { extract } from '../dist';
import uuid from 'uuid';
import test from 'ava';

test('should return rule values', t => {
  const expectedId1 = uuid();
  const expectedId2 = uuid();
  const policy = {
    rules: {
      accessAdmin: true,
      writeData: true,
      readData: [
        {
          'user.patients': {
            comparison: 'includes',
            target: 'resource.subject'
          }
        },
        {
          'resource.cohort': {
            comparison: 'in',
            target: [expectedId1, expectedId2]
          }
        },
        {
          'something': {
            comparison: 'equals',
            target: 'other.value'
          }
        }
      ]
    }
  };

  t.deepEqual(extract(policy, 'readData', 'resource.cohort'), [{target: [expectedId1, expectedId2], comparison: 'in'}]);
});

test('should return attribute values and comparison value only for privilege to be checked', t => {
  const expectedId1 = uuid();
  const expectedId2 = uuid();
  const policy = {
    rules: {
      accessAdmin: true,
      writeData: [{
        'resource.cohort': {
          comparison: 'equals',
          target: expectedId1
        }
      }],
      readData: [
        {
          'user.patients': {
            comparison: 'includes',
            target: 'resource.subject'
          }
        },
        {
          'resource.cohort': {
            comparison: 'in',
            target: [expectedId1, expectedId2]
          }
        },
        {
          'something': {
            comparison: 'equals',
            target: 'other.value'
          }
        }
      ]
    }
  };

  t.deepEqual(extract(policy, 'writeData', 'resource.cohort'), [{target: expectedId1, comparison: 'equals'}]);
});

test('No rules should be extracted for a boolean operation', t => {
  const expectedId1 = uuid();
  const expectedId2 = uuid();
  const policy = {
    rules: {
      accessAdmin: true,
      writeData: true,
      readData: [
        {
          'user.patients': {
            comparison: 'includes',
            target: 'resource.subject'
          }
        },
        {
          'resource.cohort': {
            comparison: 'in',
            target: [expectedId1, expectedId2]
          }
        },
        {
          'something': {
            comparison: 'equals',
            target: 'other.value'
          }
        }
      ]
    }
  };

  t.deepEqual(extract(policy, 'writeData', 'resource.cohort'), []);
});
