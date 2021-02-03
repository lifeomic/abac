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
          'resource.cohorts': {
            comparison: 'subset',
            value: [expectedId1, expectedId2]
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

  t.deepEqual(extract(policy, ['readData'], 'resource.cohorts'), [{value: [expectedId1, expectedId2], comparison: 'subset'}]);
});

test('should return attribute values and comparison value only for privilege to be checked', t => {
  const expectedId1 = uuid();
  const expectedId2 = uuid();
  const policy = {
    rules: {
      accessAdmin: true,
      writeData: [{
        'resource.cohorts': {
          comparison: 'includes',
          value: expectedId1
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
          'resource.cohorts': {
            comparison: 'subset',
            value: [expectedId1, expectedId2]
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

  t.deepEqual(extract(policy, ['writeData'], 'resource.cohorts'), [{value: expectedId1, comparison: 'includes'}]);
});

test('should return attribute values and comparison value for mutliple privileges', t => {
  const expectedId1 = uuid();
  const expectedId2 = uuid();
  const policy = {
    rules: {
      accessAdmin: true,
      readMaskedData: [{
        'resource.cohorts': {
          comparison: 'includes',
          value: expectedId1
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
          'resource.cohorts': {
            comparison: 'subset',
            value: [expectedId1, expectedId2]
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

  t.deepEqual(extract(policy, ['readData', 'readMaskedData'], 'resource.cohorts'), [{value: expectedId1, comparison: 'includes'}, {value: [expectedId1, expectedId2], comparison: 'subset'}]);
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
          'resource.cohorts': {
            comparison: 'subset',
            value: [expectedId1, expectedId2]
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

  t.deepEqual(extract(policy, ['writeData'], 'resource.cohorts'), []);
});
