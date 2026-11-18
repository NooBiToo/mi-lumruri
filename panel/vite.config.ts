import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

// Панель отдаётся отдельным uhttpd из подкаталога, поэтому пути относительные.
// В режиме dev запросы API уходят на локальный стенд (stand/server.mjs), который вызывает контроллер как CGI.
export default defineConfig({
  base: './',
  plugins: [vue()],
  build: {
    target: 'es2020',
    outDir: 'dist',
    assetsDir: 'assets',
    sourcemap: false,
    modulePreload: { polyfill: false },
    reportCompressedSize: false,
  },
  server: {
    host: '127.0.0.1',
    proxy: { '/cgi-bin': 'http://127.0.0.1:8787' },
  },
})
