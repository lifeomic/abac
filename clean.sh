#!/usr/bin/env bash

pnpm exec tsc --build --clean
rm -rf tsconfig.build.tsbuildinfo tsconfig.tsbuildinfo
find src/ -name "*.js" -type f -delete
find src/ -name "*.cjs" -type f -delete
find src/ -name "*.mjs" -type f -delete
