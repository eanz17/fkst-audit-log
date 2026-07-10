import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

const adapterPort = Number(process.env.FKST_WEB_API_PORT || 5174);

export default defineConfig({
  plugins: [react()],
  server: {
    host: '127.0.0.1',
    port: Number(process.env.FKST_WEB_PORT || 5173),
    strictPort: true,
    proxy: {
      '/api': {
        target: `http://127.0.0.1:${adapterPort}`,
        changeOrigin: true
      }
    }
  },
  preview: {
    host: '127.0.0.1',
    port: Number(process.env.FKST_WEB_PORT || 5173),
    strictPort: true,
    proxy: {
      '/api': {
        target: `http://127.0.0.1:${adapterPort}`,
        changeOrigin: true
      }
    }
  }
});
