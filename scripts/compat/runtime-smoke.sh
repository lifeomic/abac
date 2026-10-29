#!/bin/sh
# CI runs this on Node versions too old for pnpm, so it must stay POSIX sh + npm.
set -eu

package=$(ls "$PWD"/lifeomic-abac-*.tgz)
mkdir -p smoke
cd smoke
npm init -y >/dev/null
npm install --no-audit --no-fund "$package" abac-published@npm:@lifeomic/abac@5.0.0 ajv@8
cp ../scripts/compat/cases.cjs ../scripts/compat/smoke.cjs .

node smoke.cjs
