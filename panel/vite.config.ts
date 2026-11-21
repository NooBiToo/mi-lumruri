import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

// Панель отдаётся отдельным uhttpd из подкаталога, поэтому пути относительные.
// В режиме dev запросы API уходят на локальный стенд (stand/server.mjs, HTTPS), который вызывает контроллер как CGI.
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
    // один бандл с PrimeVue и словарями трёх языков (~0,75 МБ, ~0,2 МБ в gzip) — осознанно: панель грузится один раз по LAN
    chunkSizeWarningLimit: 850,
  },
  server: {
    host: '127.0.0.1',
    // стенд работает только по HTTPS с временным самоподписанным сертификатом; проверка отключена лишь у dev-прокси
    proxy: { '/cgi-bin': { target: 'https://127.0.0.1:8787', secure: false } },
  },
})
