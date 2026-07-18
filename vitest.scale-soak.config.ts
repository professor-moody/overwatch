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
    include: ['src/**/*scale-soak.test.ts'],
    fileParallelism: false,
    maxWorkers: 1,
    testTimeout: 90_000,
    hookTimeout: 90_000,
  },
});
