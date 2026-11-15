import { defineConfig } from 'vite';
import vue from '@vitejs/plugin-vue';

// 개발 서버(npm run dev)에서는 /api 를 로컬 탐지 서버로 넘긴다. 운영 빌드는 nginx 가 프록시한다.
export default defineConfig({
  plugins: [vue()],
  server: {
    port: 5173,
    proxy: {
      '/api': { target: process.env.API_TARGET ?? 'http://localhost:8000', changeOrigin: true },
    },
  },
  build: { outDir: 'dist', chunkSizeWarningLimit: 1500 },
});
