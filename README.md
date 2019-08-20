# abac

This is a Javascript implementation of Attribute Based Access Control
use in Lifeomic products.

This module is suitable for use in both UIs and backend node.js services.

## Installation

```bash
yarn install @lifeomic/abac
```

## Usage

**TypeScript usage:**

```typescript
import * as abac from '@lifeomic/abac';

abac.validate(policy);
abac.merge(policies);
abac.reduce(policy, attributes);
abac.enforce(operationName, policy, attributes);
abac.enforceLenient(operationName, policy, attributes);
abac.enforceAny(operationName, policy, attributes);
abac.privileges(policy, attributes);
abac.privilegesLenient(policy, attributes);
```

See unit tests in `/test` folder - many good examples.
