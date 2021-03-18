'use strict';

import {enforce, enforceAny} from '../dist';
import test from 'ava';

test('RFC example should enforce properly', t => {
  const policy = {
    rules: {
      accessAdmin: [
        {
          'user.groups': {
            comparison: 'includes',
            value: '1af3ed70-018b-46cc-ba41-7b731fcb182f'
          }
        }
      ],
      billingAdmin: [
        {
          'user.groups': {
            comparison: 'includes',
            value: '1af3ed70-018b-46cc-ba41-7b731fcb182f'
          }
        }
      ],
      readData: [
        {
          'user.groups': {
            comparison: 'includes',
            value: '1af3ed70-018b-46cc-ba41-7b731fcb182f'
          }
        },
        {
          'user.groups': {
            comparison: 'superset',
            value: ['8cfdd7b2-236e-4001-8d98-75d931877bbb', '1456d7e3-1bc0-4849-8c50-940a4eb3c07c']
          },
          'resource.dataset': {
            comparison: 'equals',
            value: '6a2db2e4-f0fc-4db7-9a8f-28ab14667257'
          }
        }
      ]
    }
  };

  // admin group gets access to all three operations:
  let user = {groups: ['1af3ed70-018b-46cc-ba41-7b731fcb182f']};
  let resource = {dataset: '6a2db2e4-f0fc-4db7-9a8f-28ab14667257'};
  t.true(enforce('accessAdmin', policy, {user, resource}));
  t.true(enforce('billingAdmin', policy, {user, resource}));
  t.true(enforce('readData', policy, {user, resource}));
  t.false(enforce('downloadFile', policy, {user, resource}));

  // members of both TNBC and Doctors gets readData for the TNBC dataset:
  user = {
    groups: [
      '8cfdd7b2-236e-4001-8d98-75d931877bbb',
      '1456d7e3-1bc0-4849-8c50-940a4eb3c07c',
      'a5e15ccd-d853-4da2-8d1c-63630a47ba5d'
    ]};
  resource = {dataset: '6a2db2e4-f0fc-4db7-9a8f-28ab14667257'};
  t.false(enforce('accessAdmin', policy, {user, resource}));
  t.false(enforce('billingAdmin', policy, {user, resource}));
  t.true(enforce('readData', policy, {user, resource}));
  t.false(enforce('downloadFile', policy, {user, resource}));

  // members of both TNBC and Doctors gets no access to PED dataset:
  user = {
    groups: [
      '8cfdd7b2-236e-4001-8d98-75d931877bbb',
      '1456d7e3-1bc0-4849-8c50-940a4eb3c07c',
      'a5e15ccd-d853-4da2-8d1c-63630a47ba5d'
    ]};
  resource = {dataset: '62271b6b-35f2-4565-83d8-c1d7a32ec95b'};
  t.false(enforce('accessAdmin', policy, {user, resource}));
  t.false(enforce('billingAdmin', policy, {user, resource}));
  t.false(enforce('readData', policy, {user, resource}));
  t.false(enforce('downloadFile', policy, {user, resource}));

  // user in no groups gets no access:
  user = {groups: []};
  resource = {dataset: '6a2db2e4-f0fc-4db7-9a8f-28ab14667257'};
  t.false(enforce('accessAdmin', policy, {user, resource}));
  t.false(enforce('billingAdmin', policy, {user, resource}));
  t.false(enforce('readData', policy, {user, resource}));
  t.false(enforce('downloadFile', policy, {user, resource}));

  // user just in TNBC group, but not doctor gets no access:
  user = {groups: ['8cfdd7b2-236e-4001-8d98-75d931877bbb']};
  resource = {dataset: '6a2db2e4-f0fc-4db7-9a8f-28ab14667257'};
  t.false(enforce('accessAdmin', policy, {user, resource}));
  t.false(enforce('billingAdmin', policy, {user, resource}));
  t.false(enforce('readData', policy, {user, resource}));
  t.false(enforce('downloadFile', policy, {user, resource}));
});

test('A policy that has no access, gives everyone no access', t => {
  let user = {groups: ['1af3ed70-018b-46cc-ba41-7b731fcb182f']};
  let resource = {dataset: '6a2db2e4-f0fc-4db7-9a8f-28ab14667257'};
  t.false(enforce('readData', {rules: {}}, {user, resource}));

  user = {groups: []};
  resource = {dataset: '6a2db2e4-f0fc-4db7-9a8f-28ab14667257'};
  t.false(enforce('readData', {rules: {}}, {user, resource}));
});

test('A policy with all access, gives everyone access to everything', t => {
  const policy = {
    rules: {
      accessAdmin: true,
      billingAdmin: true,
      projectAdmin: true,
      accountAdmin: true,
      createData: true,
      readData: true,
      updateData: true,
      deleteData: true,
      downloadFile: true
    }
  };

  let user = {groups: ['1af3ed70-018b-46cc-ba41-7b731fcb182f']};
  t.true(enforce('accessAdmin', policy, {user}));
  t.true(enforce('readData', policy, {user}));

  user = {groups: []};
  t.true(enforce('accessAdmin', policy, {user}));
  t.true(enforce('readData', policy, {user}));
});

test('can enforce positive exists conditionals', t => {
  const policy = {
    rules: {
      readLifeData: [
        {
          // Allow reading any educational content
          'educationalContent': {
            comparison: 'exists'
          }
        }
      ]
    }
  };

  // Test that a user can read educational content
  const user = {id: 'testuser'};
  const educationalContent = {id: 'some content'};
  t.true(enforce('readLifeData', policy, {user, educationalContent}));

  // Test that a user cannot read fasting data
  const fastingData = {id: 'some fast'};
  t.false(enforce('readLifeData', policy, {user, fastingData}));
});

test('supports target attributes', t => {
  const policy = {
    rules: {
      readData: [
        {
          // Allow reading if the current user is the owner
          'resource.ownerId': {
            comparison: 'equals',
            target: 'user.id'
          }
        }
      ]
    }
  };

  // Test that a user can read their own resources
  const user = {id: 'testuser'};
  const resource1 = {ownerId: 'testuser'};
  t.true(enforce('readData', policy, {user, resource: resource1}));

  // Test that a user cannot read a different user's resource
  const resource2 = {ownerId: 'testuser2'};
  t.false(enforce('readData', policy, {user, resource: resource2}));
});

test('returns false when target attributes are missing', t => {
  const policy = {
    rules: {
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

  const user1 = { patients: ['patient1'] };
  const resource1 = {};
  t.false(enforce('readData', policy, {user: user1, resource: resource1}));

  const user2 = {};
  const resource2 = { subject: 'patient2' };
  t.false(enforce('readData', policy, {user: user2, resource: resource2}));
});

test('returns false for invalid operation names', t => {
  t.false(enforce('not-an-operation', {rules: {}}, {}));
});

test('returns false for permissions containing unknown comparisons and target', t => {
  const policy = {
    rules: {
      readData: [
        {
          'resource.type': {
            comparison: 'not-entirely-unlike',
            target: 'user.favoriteDrink'
          }
        }
      ],
      createData: true
    }
  };

  t.false(enforce('readData', policy, {user: {favoriteDrink: 'tea'}, resource: {type: 'sort of tea'}}));
  t.true(enforce('createData', policy, {user: {favoriteDrink: 'tea'}, resource: {type: 'sort of tea'}}));
});

test('returns false for permissions containing unknown comparisons and value', t => {
  const policy = {
    rules: {
      readData: [
        {
          'resource.type': {
            comparison: 'not-entirely-unlike',
            value: 'tea'
          }
        }
      ],
      createData: true
    }
  };

  t.false(enforce('readData', policy, {resource: {type: 'sort of tea'}}));
  t.true(enforce('createData', policy, {resource: {type: 'sort of tea'}}));
});

test('supports the in comparison with target', t => {
  const policy = {
    rules: {
      readData: [
        {
          'resource.type': {
            comparison: 'in',
            target: 'user.favoriteDrinks'
          }
        }
      ]
    }
  };

  t.true(enforce('readData', policy, {user: {favoriteDrinks: ['tea', 'coffee']}, resource: {type: 'tea'}}));
});

test('supports the in comparison with target', t => {
  const policy = {
    rules: {
      readData: [
        {
          'resource.type': {
            comparison: 'in',
            target: 'user.favoriteDrinks'
          }
        }
      ]
    }
  };

  t.false(enforce('readData', policy, {resource: {type: 'tea'}}));
});

test('supports the in comparison with value', t => {
  const policy = {
    rules: {
      readData: [
        {
          'resource.type': {
            comparison: 'in',
            value: ['tea', 'coffee']
          }
        }
      ]
    }
  };

  t.true(enforce('readData', policy, {resource: {type: 'tea'}}));
});

test('supports the in comparison with value', t => {
  const policy = {
    rules: {
      readData: [
        {
          'resource.type': {
            comparison: 'in',
            value: ['tea', 'coffee']
          }
        }
      ]
    }
  };

  t.false(enforce('readData', policy, {resource: {type: 'chai'}}));
});

test('A policy with a new operation works as expected', t => {
  const policy = {
    rules: {
      someNewThing: true
    }
  };

  let user = {groups: ['1af3ed70-018b-46cc-ba41-7b731fcb182f']};
  t.true(enforce('someNewThing', policy, {user}));
  t.false(enforce('readData', policy, {user}));

  user = {groups: []};
  t.true(enforce('someNewThing', policy, {user}));
  t.false(enforce('readData', policy, {user}));
});

test('enforceAny returns the first allowed operation when multiple are allowed', t => {
  const policy = {
    rules: {
      readData: true,
      readAnonData: true
    }
  };

  t.is(enforceAny(['readData', 'readAnonData'], policy, {}), 'readData');
});

test('enforceAny returns the first allowed operation when only one is allowed', t => {
  const policy = {
    rules: {
      readAnonData: true
    }
  };

  t.is(enforceAny(['readData', 'readAnonData'], policy, {}), 'readAnonData');
});

test('enforceAny returns false when none of the operations are allowed', t => {
  const policy = {
    rules: {
      billingAdmin: true
    }
  };

  t.false(enforceAny(['readData', 'readAnonData'], policy, {}));
});

test('rules can reference values in an array', t => {
  const policy = {
    rules: {
      readData: [
        {
          'array.0.value': {
            comparison: 'equals',
            value: 'test'
          }
        }
      ]
    }
  };

  t.true(enforce('readData', policy, {array: [{value: 'test'}]}));
  t.false(enforce('readData', policy, {array: [{value: 'bogus'}]}));
});

test('rules can target array values', t => {
  const policy = {
    rules: {
      readData: [
        {
          value: {
            comparison: 'equals',
            target: 'array.0.value'
          }
        }
      ]
    }
  };

  t.true(enforce('readData', policy, {value: 'test', array: [{value: 'test'}]}));
  t.false(enforce('readData', policy, {value: 'test', array: [{value: 'bogus'}]}));
});

test('rules can end with a wildcard', t => {
  const policy = {
    rules: {
      readData: [
        {
          'some.*': {
            comparison: 'equals',
            value: 'test'
          }
        }
      ]
    }
  };

  t.true(enforce('readData', policy, {some: {a: 'test', b: 'test'}}));
  t.false(enforce('readData', policy, {some: {a: 'test', b: 'bogus'}}));
  t.true(enforce('readData', policy, {some: ['test', 'test']}));
  t.false(enforce('readData', policy, {some: ['test', 'bogus']}));
});

test('rules can start with a wildcard', t => {
  const policy = {
    rules: {
      readData: [
        {
          '*.some': {
            comparison: 'equals',
            value: 'test'
          }
        }
      ]
    }
  };

  t.true(enforce('readData', policy, {a: {some: 'test'}, b: {some: 'test'}}));
  t.false(enforce('readData', policy, {a: {some: 'bogus'}, b: {some: 'test'}}));
  t.true(enforce('readData', policy, [{some: 'test'}, {some: 'test'}]));
  t.false(enforce('readData', policy, [{some: 'test'}, {some: 'bogus'}]));
});

test('rules can contain a wildcard', t => {
  const policy = {
    rules: {
      readData: [
        {
          'some.*.property': {
            comparison: 'equals',
            value: 'test'
          }
        }
      ]
    }
  };

  t.true(enforce('readData', policy, {some: {a: {property: 'test'}, b: {property: 'test'}}}));
  t.false(enforce('readData', policy, {some: {a: {property: 'test'}, b: {property: 'bogus'}}}));
  t.true(enforce('readData', policy, {some: [{property: 'test'}, {property: 'test'}]}));
  t.false(enforce('readData', policy, {some: [{property: 'test'}, {property: 'bogus'}]}));
});

test('wildcard evaluation fails if attribute resolution fails', t => {
  const policy = {
    rules: {
      readData: [
        {
          'some.*.property': {
            comparison: 'equals',
            value: 'test'
          }
        }
      ]
    }
  };

  t.false(enforce('readData', policy, {}));
  t.false(enforce('readData', policy, {some: {property: 'test'}}));
  t.false(enforce('readData', policy, {some: [{property: 'test'}, {bogus: 'test'}]}));
});

test('wildcard evaluation fails if target resolution fails', t => {
  const policy = {
    rules: {
      readData: [
        {
          'some.*.property': {
            comparison: 'equals',
            target: 'missing'
          }
        }
      ]
    }
  };

  t.false(enforce('readData', policy, {some: [{property: 'test'}, {property: 'test'}]}));
});

test('rules can contain multiple wildcards', t => {
  const policy = {
    rules: {
      readData: [
        {
          'some.*.property.*': {
            comparison: 'equals',
            value: 'test'
          }
        }
      ]
    }
  };

  t.true(enforce('readData', policy, {some: [{property: ['test', 'test']}, {property: ['test', 'test']}]}));
  t.false(enforce('readData', policy, {some: [{property: ['test', 'bogus']}, {property: ['test', 'test']}]}));
  t.false(enforce('readData', policy, {some: [{property: ['test', 'test']}, {bogus: ['test', 'test']}]}));
});

test('rules can use numeric comparison values', t => {
  const policy = {
    rules: {
      readData: [
        {
          'some.value': {
            comparison: 'equals',
            value: 0
          }
        }
      ]
    }
  };

  t.true(enforce('readData', policy, {some: {value: 0}}));
  t.false(enforce('readData', policy, {some: {value: 1}}));
});

test('rules can match object keys', t => {
  const policy = {
    rules: {
      readData: [
        {
          'some.object.%keys.*': {
            comparison: 'in',
            value: ['a', 'b', 'c']
          },
          'some.object.%keys.length': {
            comparison: 'equals',
            value: 2
          }
        }
      ]
    }
  };

  t.true(enforce('readData', policy, {some: {object: {a: 1, b: 2}}}));
  t.false(enforce('readData', policy, {some: {object: {a: 1, d: 2}}}));
  t.false(enforce('readData', policy, {some: {object: {a: 1, b: 2, c: 3}}}));
});

test('rules can match top-level object keys', t => {
  const policy = {
    rules: {
      readData: [
        {
          '%keys.*': {
            comparison: 'in',
            value: ['a', 'b', 'c']
          },
          '%keys.length': {
            comparison: 'equals',
            value: 2
          }
        }
      ]
    }
  };

  t.true(enforce('readData', policy, {a: 1, b: 2}));
  t.false(enforce('readData', policy, {a: 1, d: 2}));
  t.false(enforce('readData', policy, {a: 1, b: 2, c: 3}));
});

test('rules can match literal %keys attribute', t => {
  const policy = {
    rules: {
      readData: [
        {
          'object.%%keys': {
            comparison: 'equals',
            value: 'test'
          }
        }
      ]
    }
  };

  t.true(enforce('readData', policy, {object: {'%keys': 'test'}}));
  t.false(enforce('readData', policy, {object: {'%keys': 'bogus'}}));
});

test('rules can match top-level literal %keys attribute', t => {
  const policy = {
    rules: {
      readData: [
        {
          '%%keys': {
            comparison: 'equals',
            value: 'test'
          }
        }
      ]
    }
  };

  t.true(enforce('readData', policy, {'%keys': 'test'}));
  t.false(enforce('readData', policy, {'%keys': 'bogus'}));
});

test('returns false for invalid policy', t => {
  const policy = {
    rules: {
      readData: {
        '?!*bogus*!?': {
          comparison: 'equals',
          value: 'test'
        }
      }
    }
  };

  t.false(enforce('readData', policy, {}));
});

test('rules can use equals with complex types', t => {
  const policy = {
    rules: {
      readData: [
        {
          'a': {
            comparison: 'equals',
            target: 'b'
          }
        }
      ]
    }
  };

  t.true(enforce('readData', policy, {a: [1, 2, 3], b: [1, 2, 3]}));
  t.false(enforce('readData', policy, {a: [1, 2, 3], b: ['one', 'two', 'three']}));
  t.true(enforce('readData', policy, {a: true, b: true}));
  t.true(enforce('readData', policy, {a: 'A', b: 'A'}));
  t.false(enforce('readData', policy, {a: 'A', b: 'B'}));
  t.false(enforce('readData', policy, {a: true, b: false}));
});

test('rules can use not equals with complex types', t => {
  const policy = {
    rules: {
      readData: [
        {
          'a': {
            comparison: 'notEquals',
            target: 'b'
          }
        }
      ]
    }
  };

  t.false(enforce('readData', policy, {a: [1, 2, 3], b: [1, 2, 3]}));
  t.true(enforce('readData', policy, {a: [1, 2, 3], b: ['one', 'two', 'three']}));
  t.false(enforce('readData', policy, {a: true, b: true}));
  t.false(enforce('readData', policy, {a: 'A', b: 'A'}));
  t.true(enforce('readData', policy, {a: 'A', b: 'B'}));
  t.true(enforce('readData', policy, {a: true, b: false}));
});

test('rules can use subset with value', t => {
  const policy = {
    rules: {
      readData: [
        {
          'a': {
            comparison: 'subset',
            value: [1, 2, 3]
          }
        }
      ]
    }
  };

  t.true(enforce('readData', policy, {a: [1, 2, 3]}));
  t.true(enforce('readData', policy, {a: [1]}));
  t.false(enforce('readData', policy, {a: [4, 5, 6]}));
});

test('rules can use subset with target', t => {
  const policy = {
    rules: {
      readData: [
        {
          'a': {
            comparison: 'subset',
            target: 'b'
          }
        }
      ]
    }
  };

  t.true(enforce('readData', policy, {a: [1, 2, 3], b: [1, 2, 3]}));
  t.true(enforce('readData', policy, {a: [1], b: [1, 2, 3]}));
  t.false(enforce('readData', policy, {a: [4, 5, 6], b: [1, 2, 3]}));
  t.false(enforce('readData', policy, {a: [4, 5, 6]}));
  t.false(enforce('readData', policy, {a: '12', b: '123'}));
});

test('rules can use notEquals with explicit values', t => {
  const policy = {
    rules: {
      readData: [
        {
          'object.key': {
            comparison: 'notEquals',
            value: 42
          }
        }
      ]
    }
  };

  t.true(enforce('readData', policy, {object: {key: 13}}));
  t.false(enforce('readData', policy, {object: {key: 42}}));
});

test('rules can use notEquals with referenced values', t => {
  const policy = {
    rules: {
      readData: [
        {
          'object.key': {
            comparison: 'notEquals',
            target: 'object.value'
          }
        }
      ]
    }
  };

  t.true(enforce('readData', policy, {object: {key: 13, value: 42}}));
  t.false(enforce('readData', policy, {object: {key: 42, value: 42}}));
  t.false(enforce('readData', policy, {object: {key: 13}}));
});

test('rules can use notIn with explicit values', t => {
  const policy = {
    rules: {
      readData: [
        {
          'object.key': {
            comparison: 'notIn',
            value: [1, 2]
          }
        }
      ]
    }
  };

  t.true(enforce('readData', policy, {object: {key: 3}}));
  t.false(enforce('readData', policy, {object: {key: 1}}));
  t.false(enforce('readData', policy, {object: {key: 2}}));
});

test('rules can use notIn with referenced values', t => {
  const policy = {
    rules: {
      readData: [
        {
          'object.key': {
            comparison: 'notIn',
            target: 'object.value'
          }
        }
      ]
    }
  };

  t.true(enforce('readData', policy, {object: {key: 3, value: [1, 2]}}));
  t.false(enforce('readData', policy, {object: {key: 1, value: [1, 2]}}));
  t.false(enforce('readData', policy, {object: {key: 2, value: [1, 2]}}));
  t.false(enforce('readData', policy, {object: {key: 3}}));
});

test('return true for policy with boolean value when attribute is not set', t => {
  const policy = {
    'rules': {
      'readData': [{
        'resource.cohorts': {
          'value': '642390ca-4c15-4e7f-b459-28b16def2c2b',
          'comparison': 'includes'
        }
      },
      {
        'resource.cohortAffinity': {
          'value': true, 'comparison': 'notEquals'
        }
      }]
    }
  };
  const any = enforce('readData', policy, {});
  t.true(any);
});

test('return false for policy with boolean value when attribute is set', t => {
  const policy = {
    'rules': {
      'readData': [{
        'resource.cohorts': {
          'value': '642390ca-4c15-4e7f-b459-28b16def2c2b',
          'comparison': 'includes'
        }
      },
      {
        'resource.cohortAffinity': {
          'value': true, 'comparison': 'notEquals'
        }
      }]
    }
  };
  const any = enforce('readData', policy, {resource: {cohortAffinity: true}});
  t.false(any);
});
