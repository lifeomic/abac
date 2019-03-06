'use strict';

import {privileges, privilegesSync} from '../dist';
import test from 'ava';

test('async privileges should work', async t => {
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

  t.deepEqual(await privileges(policy), ['accessAdmin', 'readData']);
  t.deepEqual(
    await privileges(policy, {resource: {ownerId: 'john'}, user: {id: 'jane'}}),
    ['accessAdmin', 'readData']);
  t.deepEqual(
    await privileges(policy, {resource: {dataset: 'project'}}),
    ['accessAdmin', 'readData', 'deleteData']);
  t.deepEqual(
    await privileges(policy, {resource: {dataset: 'project2'}}),
    ['accessAdmin', 'readData']);
});

test('sync privileges should work', async t => {
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

  // privilagesSync does the best it can given incomplete information
  // and is permissive:
  t.deepEqual(privilegesSync(policy), ['accessAdmin', 'readData', 'deleteData', 'updateData']);
  t.deepEqual(
    privilegesSync(policy, {resource: {ownerId: 'john'}, user: {id: 'jane'}}),
    ['accessAdmin', 'readData', 'deleteData']);
  t.deepEqual(
    privilegesSync(policy, {resource: {dataset: 'project'}}),
    ['accessAdmin', 'readData', 'deleteData', 'updateData']);

  // given full information, privilegesSync gives correct answers:
  t.deepEqual(
    privilegesSync(policy, {resource: {dataset: 'project', ownerId: 'john'}, user: {id: 'john'}}),
    ['accessAdmin', 'readData', 'deleteData', 'updateData']);
  t.deepEqual(
    privilegesSync(policy, {resource: {dataset: 'project2', ownerId: 'john'}, user: {id: 'jane'}}),
    ['accessAdmin', 'readData']);
});
