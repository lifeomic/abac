#!/usr/bin/env bash

yarn tsc --build --clean
rm -rf tsconfig.build.tsbuildinfo tsconfig.tsbuildinfo
rm -rf lib/
find src/ -name "*.js" -type f -delete
find src/ -name "*.cjs" -type f -delete
find src/ -name "*.mjs" -type f -delete
