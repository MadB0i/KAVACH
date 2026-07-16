import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  base: '/dashboard/',
  build: { outDir: 'dist', sourcemap: false },
  server: { port: 7422, proxy: { '/api': { target: 'http://127.0.0.1:7421', changeOrigin: true }, '/health': { target: 'http://127.0.0.1:7421', changeOrigin: true }, '/ready': { target: 'http://127.0.0.1:7421', changeOrigin: true } } },
  test: { environment: 'jsdom', setupFiles: './src/setupTests.ts', globals: true },
});
