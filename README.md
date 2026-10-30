# abac

This is a Javascript implementation of Attribute Based Access Control
use in Lifeomic products.

This module is suitable for use in both UIs and backend node.js services.

## Installation

```bash
npm install @lifeomic/abac ajv
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

### Smaller imports

The root import validates every policy with `ajv`, which most browser bundles
do not need. These subpaths load only what they export:

```typescript
import type { AbacPolicy } from '@lifeomic/abac/types';
import { enforceLenient } from '@lifeomic/abac/enforce-lenient';
```

- `@lifeomic/abac/enforce-lenient` skips schema validation and never loads
  `ajv`. Use it only for policies a server already validated. It never throws,
  and returns `false` when `policy.rules` is not an object. For a valid policy it
  returns what `enforceLenient` from `@lifeomic/abac` returns, except for
  operation names inherited from `Object.prototype` such as `toString`, where
  the root import throws a `TypeError` and this returns `false`. It is under
  3 KB minified and gzipped.
- `@lifeomic/abac/types` exports the policy types and no runtime code.

Each subpath also has a directory with a `package.json`, so tools that ignore
`exports`, such as older Jest and Metro, still resolve it.

## Development

Use the Node version in `.nvmrc`. The build runs `esbuild.config.mts`
directly with Node, which needs Node 22.18 or later; the published package
still supports Node 14.

TypeScript 7 typechecks (`pnpm run typecheck`), while TypeScript 5.9 emits
the declarations and backs eslint. Both install a `tsc` binary and
`pnpm exec tsc` runs 7, so use the package scripts.

```bash
pnpm install
pnpm test
pnpm run build
```

## Release process

Increment the version in `package.json`, make a PR, merge the PR,
and then finally create a new release using the github UI. Creating
the release will publish the head of master to npm. Name the
release `vX.Y.Z` to match the version in `package.json`.
