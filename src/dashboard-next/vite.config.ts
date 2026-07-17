import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import path from 'path';
import type { Plugin } from 'vite';

const apiPort = process.env.OVERWATCH_DASHBOARD_PORT || process.env.OVERWATCH_DEMO_DASHBOARD_PORT || '8384';
const apiTarget = `http://localhost:${apiPort}`;
const wsTarget = `ws://localhost:${apiPort}`;
const ENTRY_CHUNK_BUDGET_BYTES = 500_000;

function entryChunkBudget(): Plugin {
  return {
    name: 'overwatch-entry-chunk-budget',
    apply: 'build',
    generateBundle(_options, bundle) {
      for (const artifact of Object.values(bundle)) {
        if (artifact.type !== 'chunk' || !artifact.isEntry) continue;
        const bytes = Buffer.byteLength(artifact.code, 'utf8');
        if (bytes >= ENTRY_CHUNK_BUDGET_BYTES) {
          this.error(
            `Dashboard entry chunk ${artifact.fileName} is ${bytes.toLocaleString()} bytes; `
            + `the budget is below ${ENTRY_CHUNK_BUDGET_BYTES.toLocaleString()} bytes. `
            + 'Lazy-load top-level panels or remove eager entry dependencies.',
          );
        }
      }
    },
  };
}

export default defineConfig({
  plugins: [react(), entryChunkBudget()],
  root: __dirname,
  base: process.env.GITHUB_PAGES ? '/overwatch/' : '/',
  resolve: {
    alias: {
      '@': path.resolve(__dirname, 'src'),
      '@overwatch/types': path.resolve(__dirname, '..', 'types.ts'),
      '@overwatch/dashboard-contracts': path.resolve(__dirname, '..', 'contracts', 'dashboard-v1.ts'),
      '@overwatch/dashboard-api-contracts': path.resolve(__dirname, '..', 'contracts', 'dashboard-api-v1.ts'),
    },
  },
  build: {
    outDir: path.resolve(__dirname, '..', '..', 'dist', 'dashboard-next'),
    emptyOutDir: true,
    sourcemap: true,
  },
  server: {
    port: 5173,
    proxy: {
      '/api': apiTarget,
      '/ws': {
        target: wsTarget,
        ws: true,
      },
    },
  },
});
