import { defineConfig } from 'vitest/config';

export default defineConfig({
  resolve: {
    extensions: ['.ts', '.mjs', '.js', '.json'],
  },
  test: {
    globals: true,
    include: ['test/**/*.test.ts'],
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
