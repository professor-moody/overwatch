import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import path from 'path';

const apiPort = process.env.OVERWATCH_DASHBOARD_PORT || process.env.OVERWATCH_DEMO_DASHBOARD_PORT || '8384';
const apiTarget = `http://localhost:${apiPort}`;
const wsTarget = `ws://localhost:${apiPort}`;

export default defineConfig({
  plugins: [react()],
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
