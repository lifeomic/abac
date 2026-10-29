#!/bin/sh
# CI runs this on Node versions too old for pnpm, so it must stay POSIX sh + npm.
set -eu

package=$(ls "$PWD"/lifeomic-abac-*.tgz)
mkdir -p smoke
cd smoke
npm init -y >/dev/null
npm install --no-audit --no-fund "$package" ajv@8

node -e "
const abac = require('@lifeomic/abac');
if (abac.enforce('readData', { rules: { readData: true } }) !== true) {
  throw new Error('enforce did not allow a granted operation');
}
console.log('node ' + process.version + ': @lifeomic/abac loads and enforces');
"
