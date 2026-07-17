import { defineConfig } from 'vitest/config';
import { fileURLToPath } from 'node:url';

export default defineConfig({
  resolve: {
    alias: {
      '@overwatch/dashboard-contracts': fileURLToPath(new URL('./src/contracts/dashboard-v1.ts', import.meta.url)),
      '@overwatch/dashboard-api-contracts': fileURLToPath(new URL('./src/contracts/dashboard-api-v1.ts', import.meta.url)),
    },
  },
  test: {
    globalSetup: ['./src/test-support/artifact-hygiene-global.ts'],
    setupFiles: ['./src/test-support/setup-hermetic.ts'],
    sequence: { hooks: 'stack', setupFiles: 'list' },
    include: [
      'src/**/*.test.ts',
    ],
    exclude: [
      'dist/**',
      'src/__tests__/mcp-server.integration.test.ts',
      'src/__tests__/http-transport.integration.test.ts',
      'src/__tests__/approval-over-http.integration.test.ts',
      'src/__tests__/headless-runner.integration.test.ts',
    ],
    testTimeout: 30000,
    coverage: {
      provider: 'v8',
      include: ['src/**/*.ts'],
      exclude: ['src/**/*.test.ts', 'src/**/__tests__/**'],
    },
  },
});
