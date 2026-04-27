import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import path from 'path';

export default defineConfig({
  plugins: [react()],
  root: __dirname,
  base: '/',
  resolve: {
    alias: {
      '@': path.resolve(__dirname, 'src'),
      '@overwatch/types': path.resolve(__dirname, '..', 'types.ts'),
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
      '/api': 'http://localhost:8384',
      '/ws': {
        target: 'ws://localhost:8384',
        ws: true,
      },
    },
  },
});
