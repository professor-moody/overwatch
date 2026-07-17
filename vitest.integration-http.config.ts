import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globalSetup: ['./src/test-support/artifact-hygiene-global.ts'],
    setupFiles: ['./src/test-support/setup-hermetic.ts'],
    sequence: { hooks: 'stack', setupFiles: 'list' },
    include: [
      'src/__tests__/http-transport.integration.test.ts',
      'src/__tests__/approval-over-http.integration.test.ts',
      'src/__tests__/headless-runner.integration.test.ts',
      'src/__tests__/archetype-capability.integration.test.ts',
      'src/__tests__/prompt-eval-smoke.integration.test.ts',
      'src/__tests__/orchestration-eval-smoke.integration.test.ts',
    ],
    exclude: [
      'dist/**',
    ],
  },
});
