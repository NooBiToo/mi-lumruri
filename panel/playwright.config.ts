// Сквозные тесты панели (e2e/*.e2e.ts): собранная панель на стенде stand/server.mjs — HTTPS, CGI, настоящий контроллер.
// Нужны panel/dist (npm run build) и mi-tt-ctl, mi-tt-admin (MITT_BIN_DIR, по умолчанию controller/target/release).
import { defineConfig } from '@playwright/test'

export default defineConfig({
  testDir: 'e2e',
  testMatch: '**/*.e2e.ts',
  workers: 1,
  timeout: 60_000,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? [['list'], ['html', { open: 'never', outputFolder: '../out/e2e-report' }]] : 'list',
  outputDir: '../out/e2e-results',
  use: { browserName: 'chromium', ignoreHTTPSErrors: true, trace: 'retain-on-failure', viewport: { width: 1280, height: 860 } },
})
