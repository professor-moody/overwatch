import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: [
      'src/__tests__/mcp-server.integration.test.ts',
    ],
    exclude: [
      'dist/**',
    ],
  },
});
