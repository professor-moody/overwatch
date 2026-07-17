import { defineConfig } from 'vitest/config';
import { fileURLToPath } from 'node:url';

// A deliberately small, named restart/crash gate. The source suite still owns
// exhaustive unit coverage; this selection pins the cross-slice journeys that
// must never become conditional or disappear during test reorganization.
export default defineConfig({
  resolve: {
    alias: {
      '@overwatch/dashboard-contracts': fileURLToPath(new URL('./src/contracts/dashboard-v1.ts', import.meta.url)),
      '@overwatch/dashboard-api-contracts': fileURLToPath(new URL('./src/contracts/dashboard-api-v1.ts', import.meta.url)),
    },
  },
  test: {
    include: [
      'src/services/__tests__/wal-recovery.test.ts',
      'src/services/__tests__/config-write-through.integration.test.ts',
      'src/services/__tests__/engine-transaction.test.ts',
      'src/services/__tests__/application-command-service.test.ts',
      'src/services/__tests__/playbook-run-service.test.ts',
      'src/services/__tests__/runtime-ownership-recovery.test.ts',
      'src/services/__tests__/session-lifecycle.test.ts',
      'src/services/__tests__/graph-correction-command-service.test.ts',
      'src/services/__tests__/semantic-operator-journey.test.ts',
      'src/services/__tests__/pr14-restart-journeys.test.ts',
    ],
    testTimeout: 30_000,
  },
});
