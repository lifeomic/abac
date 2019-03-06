'use strict';

import {enforceSync} from '../dist';
import test from 'ava';

test('Partially evaluated policy should enforce properly', async t => {
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

  t.true(enforceSync('accessAdmin', policy));
  t.true(enforceSync('readData', policy));
  t.falsy(enforceSync('billingAdmin', policy));

  // updateData and deleteData are allowed, because
  // the rules allow them for some attributes, so
  // in the absence of the full attribute set
  // the best we can do is allow it. This is why
  // enforceSync shouldn't be used for actually
  // securing access, but is fine for a client application.
  t.true(enforceSync('updateData', policy));
  t.true(enforceSync('deleteData', policy));

  // Given full information enforceSync does give correct answers:
  t.falsy(enforceSync('updateData', policy, {resource: {ownerId: 'john'}, user: {id: 'jane'}}));
  t.true(enforceSync('deleteData', policy, {resource: {dataset: 'project'}}));
  t.falsy(enforceSync('deleteData', policy, {resource: {dataset: 'project2'}}));
});

test('returns false for invalid operation names', async t => {
  t.false(enforceSync('not-an-operation', {rules: {}}));
});
