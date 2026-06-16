import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: [
      'src/__tests__/http-transport.integration.test.ts',
      'src/__tests__/approval-over-http.integration.test.ts',
    ],
    exclude: [
      'dist/**',
    ],
  },
});
