# abac

This is a Javascript implementation of Attribute Based Access Control
use in Lifeomic products.

This module is suitable for use in both UIs and backend node.js services.

## Installation

```bash
yarn install @lifeomic/abac
```

## Terminology

- Rules
  - Comparison
    - `endsWith`: value being checked that ends with an exact string value
    - `equals`: value being checked is exactly equal to the value defined in the ABAC policy
    - `in`: value being checked is contained within the array in ABAC policy
    - `includes`: array of values includes the value in the ABAC policy
    - `notEquals`: value being checked does not equal the value defined in the ABAC policy
    - `notIn`: value not in ABAC array
    - `notIncludes`: array of values does not include the value in the ABAC policy
    - `prefixOf`: value being checked is a prefix of the value defined in the ABAC policy
    - `startsWith`: value being checked starts with an exact string value
    - `subset`: array of values is a subset of the array in the ABAC policy
    - `suffixOf`: value being checked is a suffix of the value defined in the ABAC policy
    - `superset`: array of values is a superset of the array in the ABAC policy
  - Target
    - Value of another attribute
  - Value
    - Literal value

## Usage

**TypeScript usage:**

```typescript
import * as abac from '@lifeomic/abac';

abac.validate(policy);
abac.merge(policies);
abac.reduce(policy, attributes);
abac.extract(policy, privileges, attribute);
abac.enforce(operationName, policy, attributes);
abac.enforceLenient(operationName, policy, attributes);
abac.enforceAny(operationName, policy, attributes);
abac.privileges(policy, attributes);
abac.privilegesLenient(policy, attributes);
abac.policyRequiresAttribute(policy, attribute);
```

See unit tests in `/test` folder - many good examples.

## Release process

Increment the version in `package.json`, make a PR, merge the PR,
and then finally create a new release using the github UI. Creating
the release will publish the head of master to npm. Name the
release `vX.Y.Z` to match the version in `package.json`.
