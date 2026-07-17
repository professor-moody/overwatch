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
    environment: 'happy-dom',
    globalSetup: ['./src/test-support/artifact-hygiene-global.ts'],
    include: ['src/dashboard-next/src/**/*.dom.test.tsx'],
    setupFiles: [
      './src/test-support/setup-hermetic.ts',
      './src/dashboard-next/src/test/setup-dom.ts',
    ],
    sequence: { hooks: 'stack', setupFiles: 'list' },
    testTimeout: 15_000,
  },
});
