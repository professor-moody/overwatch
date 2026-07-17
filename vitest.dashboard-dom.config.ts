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
    include: ['src/dashboard-next/src/**/*.dom.test.tsx'],
    setupFiles: ['./src/dashboard-next/src/test/setup-dom.ts'],
    testTimeout: 15_000,
  },
});
