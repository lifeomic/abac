#!/bin/sh
# CI runs this on Node versions too old for pnpm, so it must stay POSIX sh + npm.
set -eu

package=$(ls "$PWD"/lifeomic-abac-*.tgz)
mkdir -p smoke
cd smoke
npm init -y >/dev/null
npm install --no-audit --no-fund "$package" abac-published@npm:@lifeomic/abac@5.0.0
cp ../scripts/compat/cases.cjs ../scripts/compat/smoke.cjs .

for ajv in 6 7 8; do
  npm install --no-audit --no-fund "ajv@$ajv"
  node smoke.cjs
done
