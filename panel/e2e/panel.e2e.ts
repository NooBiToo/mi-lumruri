// Сквозной сценарий панели: вход паролем и TOTP, обзор, смена настройки с записью на «роутер» (config.json стенда),
// язык интерфейса (ru → en → zh), резервная копия, диагностика. Без ошибок в консоли браузера.
import { execFileSync } from 'node:child_process'
import { randomBytes } from 'node:crypto'
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { expect, test, type Page } from '@playwright/test'
// @ts-expect-error — модули стенда на JavaScript без объявлений типов
import { createStand } from '../../stand/server.mjs'
// @ts-expect-error — см. выше
import { totp } from '../../stand/totp.mjs'

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..')
const binDir = process.env.MITT_BIN_DIR ?? join(ROOT, 'controller', 'target', 'release')
const exe = (n: string) => join(binDir, process.platform === 'win32' ? `${n}.exe` : n)
const STATE = mkdtempSync(join(tmpdir(), 'mitt-e2e-'))

let stand: { listen: (p: number) => Promise<number>; close: () => Promise<void>; opts: { authDir: string; sessionDir: string; config: string } }
let origin = ''
let password = ''
let secret = ''
// TOTP-код одноразовый (защита от повтора): каждый вход — своим recovery-кодом
let recovery: string[] = []
const consoleErrors: string[] = []

test.beforeAll(async () => {
  stand = createStand({ stateDir: join(STATE, 'stand'), bin: exe('mi-tt-ctl'), admin: exe('mi-tt-admin'), seed: join(ROOT, 'fixtures', 'lab', 'config.json') })
  const port = await stand.listen(0)
  origin = `https://127.0.0.1:${port}`
  password = 'pw-' + randomBytes(18).toString('base64url')
  const env = { MI_TT_AUTH_DIR: stand.opts.authDir, MI_TT_SESSION_DIR: stand.opts.sessionDir, ...(process.env.SystemRoot ? { SystemRoot: process.env.SystemRoot } : {}) }
  const init = JSON.parse(execFileSync(exe('mi-tt-admin'), ['auth', 'init', '--stdin', '--with-totp'], { input: `${password}\n${password}\n`, env }).toString())
  secret = init.totp_secret_base32
  recovery = [...init.recovery_codes]
  execFileSync(exe('mi-tt-admin'), ['auth', 'confirm', '--stdin'], { input: totp(secret) + '\n', env })
})
test.afterAll(async () => {
  await stand?.close()
  rmSync(STATE, { recursive: true, force: true })
})

async function login(page: Page, locale = 'ru-RU') {
  page.on('console', (m) => { if (m.type() === 'error') consoleErrors.push(m.text()) })
  page.on('pageerror', (e) => consoleErrors.push(String(e)))
  await page.addInitScript((l) => { try { localStorage.setItem('mitt.lang', l) } catch { /* без хранилища */ } }, locale.slice(0, 2))
  await page.goto(origin)
  await page.locator('#login-password').fill(password)
  await page.getByRole('button', { name: /Войти|Sign in|登录/ }).click()
  await page.getByRole('button', { name: /Войти recovery-кодом|Sign in with a recovery code|恢复码/ }).click()
  const code = recovery.shift()
  if (!code) throw new Error('recovery-коды закончились')
  await page.locator('#login-recovery').fill(code)
  await page.getByRole('button', { name: /Подтвердить код|Confirm code|确认/ }).click()
  await expect(page.locator('.side__nav')).toBeVisible()
}
const config = () => JSON.parse(readFileSync(stand.opts.config, 'utf8'))
const nav = (page: Page, name: RegExp) => page.locator('.side__nav').getByRole('link', { name })

test('вход: пароль и одноразовый код, обзор с трафиком', async ({ page }) => {
  await login(page)
  await expect(page.getByRole('heading', { name: 'Обзор', level: 1 })).toBeVisible()
  await expect(page.getByRole('heading', { name: 'Трафик' })).toBeVisible()
  await expect(nav(page, /Настройки/)).toBeVisible()
})

test('частота проверки новой версии сохраняется на роутере', async ({ page }) => {
  await login(page)
  await nav(page, /Настройки/).click()
  await page.getByRole('tab', { name: 'Обновление' }).click()
  const group = page.getByRole('radiogroup', { name: 'Как часто роутер сам проверяет новую версию' })
  await group.getByRole('radio', { name: 'Раз в неделю' }).check({ force: true })
  await expect.poll(() => config().schedule?.update_check, { timeout: 10_000 }).toBe('weekly')
  await group.getByRole('radio', { name: 'Вручную' }).check({ force: true })
  await expect.poll(() => config().schedule?.update_check, { timeout: 10_000 }).toBe('manual')
})

test('язык интерфейса: English и 简体中文', async ({ page }) => {
  await login(page)
  await nav(page, /Настройки/).click()
  await page.getByRole('tab', { name: 'Панель' }).click()
  const pick = (name: string) => page.getByRole('radio', { name, exact: true }).check({ force: true })
  await pick('English')
  await expect(nav(page, /Settings/)).toBeVisible()
  await expect(page.getByRole('tab', { name: 'Network and DNS' })).toBeVisible()
  await pick('简体中文')
  await expect(nav(page, /设置/)).toBeVisible()
  await pick('Русский')
  await expect(nav(page, /Настройки/)).toBeVisible()
})

test('резервная копия скачивается без паролей', async ({ page }) => {
  await login(page)
  await nav(page, /Настройки/).click()
  await page.getByRole('tab', { name: 'Обновление' }).click()
  const [dl] = await Promise.all([page.waitForEvent('download'), page.getByRole('button', { name: 'Скачать копию' }).click()])
  const file = await dl.path()
  const b = JSON.parse(readFileSync(file!, 'utf8'))
  expect(b.format).toBe('mi-lumruri-backup')
  expect(b.secrets).toBeUndefined()
  expect(b.config.schema_version).toBe(config().schema_version)
})

test('адрес обратного прокси добавляется в «Адреса панели» и сохраняется на роутере', async ({ page }) => {
  await login(page)
  await nav(page, /Настройки/).click()
  await page.getByRole('tab', { name: 'Панель' }).click()
  await page.locator('#origin-new').fill('https://Router.Home.Example/')
  await page.getByRole('group', { name: 'Адреса панели' }).getByRole('button', { name: 'Добавить' }).click()
  await expect.poll(() => config().panel_origins, { timeout: 10_000 }).toEqual(['https://router.home.example'])
  await page.locator('#origin-new').fill('http://bad')
  await expect(page.getByText('Адрес — https://хост или https://хост:порт, без пути')).toBeVisible()
  await page.getByRole('button', { name: 'Убрать https://router.home.example' }).click()
  await expect.poll(() => config().panel_origins ?? [], { timeout: 10_000 }).toEqual([])
})

test('вкладки «Настроек»: адрес вкладки в ссылке, прежний #hosts ведёт к своим DNS-записям', async ({ page }) => {
  await login(page)
  await nav(page, /Настройки/).click()
  await expect(page.getByRole('tab', { name: 'Сеть и DNS', selected: true })).toBeVisible()
  await expect(page.getByRole('heading', { name: 'Свои DNS-записи' })).toBeVisible()
  await page.getByRole('tab', { name: 'Уведомления' }).click()
  await expect(page).toHaveURL(/#more\/notify$/)
  await expect(page.getByText('Уведомления в Telegram')).toBeVisible()
  await page.keyboard.press('ArrowRight')
  await expect(page.getByRole('tab', { name: 'Обновление', selected: true })).toBeVisible()
  await page.goto(origin + '/#hosts')
  await expect(page.getByRole('heading', { name: 'Свои DNS-записи' })).toBeVisible()
  await expect(page).toHaveURL(/#more\/dns$/)
})

test('экраны открываются без ошибок в консоли', async ({ page }) => {
  await login(page)
  for (const name of [/Сервер/, /Сайты/, /Устройства/, /Диагностика/, /Настройки/, /Обзор/]) {
    const link = nav(page, name)
    if (await link.count()) {
      await link.click()
      await expect(page.locator('main, .sect').first()).toBeVisible()
    }
  }
  // ответы 4xx/5xx на необязательные запросы (нет службы на стенде) браузер пишет как ошибки сети — их пропускаем
  expect(consoleErrors.filter((e) => !/Failed to load resource/.test(e))).toEqual([])
})
