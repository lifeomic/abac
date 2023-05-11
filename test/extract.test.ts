import test from 'ava';
import { extract, AbacPolicy } from '../src';
import { randomUUID } from 'crypto';

test('should return rule values', (t) => {
  const expectedId1 = randomUUID();
  const expectedId2 = randomUUID();
  const policy: AbacPolicy = {
    rules: {
      readData: [
        {
          'user.patients': {
            comparison: 'includes',
            target: 'resource.subject',
          },
        },
        {
          'resource.cohorts': {
            comparison: 'subset',
            value: [expectedId1, expectedId2],
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

  t.deepEqual(extract(policy, ['readData'], 'resource.cohorts'), [
    { value: [expectedId1, expectedId2], comparison: 'subset' },
  ]);
});

test('should return attribute values and comparison value only for privilege to be checked', (t) => {
  const expectedId1 = randomUUID();
  const expectedId2 = randomUUID();
  const policy: AbacPolicy = {
    rules: {
      writeData: [
        {
          'resource.cohorts': {
            comparison: 'includes',
            value: expectedId1,
          },
        },
      ],
      readData: [
        {
          'user.patients': {
            comparison: 'includes',
            target: 'resource.subject',
          },
        },
        {
          'resource.cohorts': {
            comparison: 'subset',
            value: [expectedId1, expectedId2],
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

  t.deepEqual(extract(policy, ['writeData'], 'resource.cohorts'), [
    { value: expectedId1, comparison: 'includes' },
  ]);
});

test('should return attribute values and comparison value for mutliple privileges', (t) => {
  const expectedId1 = randomUUID();
  const expectedId2 = randomUUID();
  const policy: AbacPolicy = {
    rules: {
      readMaskedData: [
        {
          'resource.cohorts': {
            comparison: 'includes',
            value: expectedId1,
          },
        },
      ],
      readData: [
        {
          'user.patients': {
            comparison: 'includes',
            target: 'resource.subject',
          },
        },
        {
          'resource.cohorts': {
            comparison: 'subset',
            value: [expectedId1, expectedId2],
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

  t.deepEqual(
    extract(policy, ['readData', 'readMaskedData'], 'resource.cohorts'),
    [
      { value: expectedId1, comparison: 'includes' },
      { value: [expectedId1, expectedId2], comparison: 'subset' },
    ]
  );
});

test('No rules should be extracted for a boolean operation', (t) => {
  const expectedId1 = randomUUID();
  const expectedId2 = randomUUID();
  const policy: AbacPolicy = {
    rules: {
      readData: [
        {
          'user.patients': {
            comparison: 'includes',
            target: 'resource.subject',
          },
        },
        {
          'resource.cohorts': {
            comparison: 'subset',
            value: [expectedId1, expectedId2],
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

  t.deepEqual(extract(policy, ['writeData'], 'resource.cohorts'), []);
});
