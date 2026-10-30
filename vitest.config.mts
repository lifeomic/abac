import inspector from 'node:inspector';
import { defineConfig } from 'vitest/config';

export default defineConfig({
  resolve: {
    extensions: ['.ts', '.mjs', '.js', '.json'],
  },
  test: {
    globals: true,
    include: ['test/**/*.test.ts'],
    // While debugging, don't let breakpoints trip the timeout.
    testTimeout: inspector.url() ? 1e8 : undefined,
    clearMocks: true,
    restoreMocks: true,
    mockReset: true,
    coverage: {
      enabled: true,
      provider: 'v8',
      include: ['src/**/*.ts'],
      exclude: ['src/**/*.d.ts'],
      thresholds: {
        branches: 100,
        functions: 100,
        lines: 100,
        statements: 100,
      },
    },
  },
});
