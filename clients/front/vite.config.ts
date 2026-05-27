import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5175,
    proxy: {
      // 开发时代理 API 请求到 clients
      '/api': {
        target: 'http://localhost:1026',
        changeOrigin: true,
      },
    },
  },
  build: {
    outDir: 'dist',
    // 生产构建产物将被 embed 到 Go 二进制
    assetsDir: 'assets',
    rollupOptions: {
      output: {
        manualChunks: {
          vendor: ['react', 'react-dom', 'react-router-dom'],
          antd: ['antd', '@ant-design/icons'],
        },
      },
    },
  },
})
