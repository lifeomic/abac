'use strict';

import {privileges, privilegesLenient} from '../dist';
import test from 'ava';

test('privileges should work', t => {
  const policy = {
    rules: {
      accessAdmin: true,
      readData: true,
      deleteData: [
        {
          'resource.dataset': {
            comparison: 'equals',
            value: 'project'
          }
        }
      ],
      updateData: [
        {
          'resource.ownerId': {
            comparison: 'equals',
            target: 'user.id'
          }
        }
      ]
    }
  };

  t.deepEqual(privileges(policy), ['accessAdmin', 'readData']);
  t.deepEqual(
    privileges(policy, {resource: {ownerId: 'john'}, user: {id: 'jane'}}),
    ['accessAdmin', 'readData']);
  t.deepEqual(
    privileges(policy, {resource: {dataset: 'project'}}),
    ['accessAdmin', 'readData', 'deleteData']);
  t.deepEqual(
    privileges(policy, {resource: {dataset: 'project2'}}),
    ['accessAdmin', 'readData']);
});

test('privilegesLenient should work', t => {
  const policy = {
    rules: {
      accessAdmin: true,
      readData: true,
      deleteData: [
        {
          'resource.dataset': {
            comparison: 'equals',
            value: 'project'
          }
        }
      ],
      updateData: [
        {
          'resource.ownerId': {
            comparison: 'equals',
            target: 'user.id'
          }
        }
      ]
    }
  };

  // privilegesLenient does the best it can given incomplete information
  // and is permissive:
  t.deepEqual(privilegesLenient(policy), ['accessAdmin', 'readData', 'deleteData', 'updateData']);
  t.deepEqual(
    privilegesLenient(policy, {resource: {ownerId: 'john'}, user: {id: 'jane'}}),
    ['accessAdmin', 'readData', 'deleteData']);
  t.deepEqual(
    privilegesLenient(policy, {resource: {dataset: 'project'}}),
    ['accessAdmin', 'readData', 'deleteData', 'updateData']);

  // given full information, privilegesLenient gives correct answers:
  t.deepEqual(
    privilegesLenient(policy, {resource: {dataset: 'project', ownerId: 'john'}, user: {id: 'john'}}),
    ['accessAdmin', 'readData', 'deleteData', 'updateData']);
  t.deepEqual(
    privilegesLenient(policy, {resource: {dataset: 'project2', ownerId: 'john'}, user: {id: 'jane'}}),
    ['accessAdmin', 'readData']);
});
