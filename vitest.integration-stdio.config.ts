import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globalSetup: ['./src/test-support/artifact-hygiene-global.ts'],
    setupFiles: ['./src/test-support/setup-hermetic.ts'],
    sequence: { hooks: 'stack', setupFiles: 'list' },
    include: [
      'src/__tests__/mcp-server.integration.test.ts',
    ],
    exclude: [
      'dist/**',
    ],
  },
});
