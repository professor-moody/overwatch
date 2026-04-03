import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: [
      'src/**/*.test.ts',
    ],
    exclude: [
      'dist/**',
      'src/__tests__/mcp-server.integration.test.ts',
      'src/__tests__/http-transport.integration.test.ts',
    ],
    testTimeout: 30000,
    coverage: {
      provider: 'v8',
      include: ['src/**/*.ts'],
      exclude: ['src/**/*.test.ts', 'src/**/__tests__/**'],
    },
  },
});
