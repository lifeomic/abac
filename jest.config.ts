import { Config } from '@jest/types';
import inspector from 'inspector';

// If we are debugging then extend the timeout to max value, otherwise use the default.
const testTimeout = inspector.url() ? 1e8 : undefined;

const config: Config.InitialOptions = {
  rootDir: __dirname,
  coverageDirectory: '<rootDir>/coverage',
  collectCoverageFrom: ['<rootDir>/src/**/*.ts'],
  collectCoverage: true,
  coverageThreshold: {
    global: {
      branches: 100,
      functions: 100,
      lines: 100,
      statements: 100,
    },
  },
  coveragePathIgnorePatterns: ['<rootDir>/test/', '/node_modules/'],
  preset: 'ts-jest',
  testEnvironment: 'node',
  clearMocks: true,
  restoreMocks: true,
  resetMocks: true,
  verbose: true,
  testMatch: ['<rootDir>/test/**/*.test.ts'],
  testTimeout,
};

export default config;
