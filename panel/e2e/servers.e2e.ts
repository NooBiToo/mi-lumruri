// Несколько серверов и страница «Модули» на стенде: второй сервер добавляется на экране «Сервер» и получает свободный
// номер туннеля, сервис на «Сайтах» направляется через него (группа vpn-sites--<сервер> на «роутере»), удаление сервера
// возвращает сервис на сервер по умолчанию; «Модули» показывают накопители из storage.json службы.
import { execFileSync } from 'node:child_process'
import { randomBytes } from 'node:crypto'
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
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
const STATE = mkdtempSync(join(tmpdir(), 'mitt-e2e-srv-'))

let stand: { listen: (p: number) => Promise<number>; close: () => Promise<void>; opts: { authDir: string; sessionDir: string; config: string; stateDir: string } }
let origin = ''
let password = ''
let recovery: string[] = []
const consoleErrors: string[] = []

test.beforeAll(async () => {
  // простой вид из config.valid.json и сервер из лабораторной фикстуры
  const cfg = JSON.parse(readFileSync(join(ROOT, 'fixtures', 'config.valid.json'), 'utf8'))
  cfg.profiles[0].endpoint = JSON.parse(readFileSync(join(ROOT, 'fixtures', 'lab', 'config.json'), 'utf8')).profiles[0].endpoint
  const seed = join(STATE, 'config.json')
  writeFileSync(seed, JSON.stringify(cfg, null, 2))
  stand = createStand({ stateDir: join(STATE, 'stand'), bin: exe('mi-tt-ctl'), admin: exe('mi-tt-admin'), seed })
  const run = join(stand.opts.stateDir, 'run')
  mkdirSync(run, { recursive: true })
  writeFileSync(join(run, 'storage.json'), JSON.stringify({
    at: 1,
    data: { path: '/data/mi-lumruri', device: '', fs: '', total: 40960000, free: 18432000, writable: true, exec: true },
    usb: [{ path: '/mnt/usb-5f2a', device: '/dev/sda1', fs: 'vfat', total: 15360000000, free: 14336000000, writable: true, exec: true, vendor: 'SanDisk', model: 'Ultra Fit' }],
  }))
  const port = await stand.listen(0)
  origin = `https://127.0.0.1:${port}`
  password = 'pw-' + randomBytes(18).toString('base64url')
  const env = { MI_TT_AUTH_DIR: stand.opts.authDir, MI_TT_SESSION_DIR: stand.opts.sessionDir, ...(process.env.SystemRoot ? { SystemRoot: process.env.SystemRoot } : {}) }
  const init = JSON.parse(execFileSync(exe('mi-tt-admin'), ['auth', 'init', '--stdin', '--with-totp'], { input: `${password}\n${password}\n`, env }).toString())
  recovery = [...init.recovery_codes]
  execFileSync(exe('mi-tt-admin'), ['auth', 'confirm', '--stdin'], { input: totp(init.totp_secret_base32) + '\n', env })
})
test.afterAll(async () => {
  await stand?.close()
  rmSync(STATE, { recursive: true, force: true })
})

const nav = (page: Page, name: RegExp) => page.locator('.side__nav').getByRole('link', { name })
async function login(page: Page) {
  page.on('console', (m) => { if (m.type() === 'error') consoleErrors.push(m.text()) })
  page.on('pageerror', (e) => consoleErrors.push(String(e)))
  await page.addInitScript(() => { try { localStorage.setItem('mitt.lang', 'ru') } catch { /* без хранилища */ } })
  await page.goto(origin)
  await page.locator('#login-password').fill(password)
  await page.getByRole('button', { name: 'Войти' }).click()
  await page.getByRole('button', { name: 'Войти recovery-кодом' }).click()
  await page.locator('#login-recovery').fill(recovery.shift()!)
  await page.getByRole('button', { name: 'Подтвердить код' }).click()
  await expect(page.locator('.side__nav')).toBeVisible()
}
/** Фикстура собрана не панелью: один раз привести к простому виду на «Сайтах» — как сделал бы пользователь. */
async function simplify(page: Page) {
  await nav(page, /Сайты/).click()
  await page.locator('.tiles, .manual').first().waitFor({ timeout: 15_000 })
  const manual = page.getByRole('heading', { name: 'Настройки изменены вручную' })
  if (await manual.isVisible()) {
    await page.getByRole('button', { name: 'Привести к простому виду' }).first().click()
    await page.getByRole('alertdialog').getByRole('button', { name: 'Привести к простому виду' }).click()
  }
  await expect(page.locator('.tiles').first()).toBeVisible({ timeout: 20_000 })
}
const config = () => JSON.parse(readFileSync(stand.opts.config, 'utf8'))

test('второй сервер: добавление, выбор для сервиса, удаление', async ({ page }) => {
  await login(page)
  await simplify(page)

  // второй сервер — свободный номер туннеля 1
  await nav(page, /Сервер/).click()
  await page.getByRole('button', { name: 'Добавить сервер' }).click()
  await page.locator('#srv-name').fill('Второй')
  await page.locator('#srv-host').fill('203.0.113.20')
  await page.locator('#srv-user').fill('u2')
  await page.locator('#srv-pass').fill('pw-' + randomBytes(9).toString('base64url'))
  await page.getByRole('button', { name: 'Сохранить' }).click()
  await expect.poll(() => config().profiles.length, { timeout: 10_000 }).toBe(2)
  const second = config().profiles.find((p: { name: string }) => p.name === 'Второй')
  expect(second.tunnel).toBe(1)
  await expect(page.getByRole('button', { name: /Второй/ })).toHaveAttribute('aria-pressed', 'true')

  // YouTube через VPN и через второй сервер
  await nav(page, /Сайты/).click()
  const yt = page.locator('.tile', { hasText: 'YouTube' }).first()
  await yt.getByRole('radio', { name: /^VPN/ }).check({ force: true })
  await yt.getByRole('combobox', { name: 'Сервер для «YouTube»' }).selectOption({ label: 'Второй' })
  await expect.poll(() => config().groups.find((g: { id: string }) => g.id === `vpn-sites--${second.id}`)?.destinations, { timeout: 15_000 })
    .toEqual([{ type: 'category', id: 'svc-youtube' }])
  expect(config().rules.some((r: { id: string; action: { id?: string } }) => r.id.endsWith(`--${second.id}`) && r.action.id === second.id)).toBe(true)

  // DNS для сайтов через VPN — выбор сервера появился
  await nav(page, /Настройки/).click()
  await expect(page.locator('#dns-tunnel')).toBeVisible()

  // удаление второго сервера: YouTube остаётся через VPN, но на сервере по умолчанию
  await nav(page, /Сервер/).click()
  await page.getByRole('button', { name: /Второй/ }).click()
  await page.getByRole('button', { name: 'Удалить сервер' }).click()
  await page.getByRole('button', { name: 'Точно удалить «Второй»?' }).click()
  await expect.poll(() => config().profiles.length, { timeout: 10_000 }).toBe(1)
  expect(config().groups.some((g: { id: string }) => g.id.startsWith('vpn-sites--'))).toBe(false)
  expect(config().groups.find((g: { id: string }) => g.id === 'vpn-sites')?.destinations).toContainEqual({ type: 'category', id: 'svc-youtube' })
  expect(consoleErrors).toEqual([])
})

test('«Модули»: внутренняя память и флешка из сведений службы', async ({ page }) => {
  await login(page)
  await nav(page, /Модули/).click()
  await expect(page.getByRole('heading', { name: 'Накопители' })).toBeVisible()
  await expect(page.getByText('Внутренняя память')).toBeVisible()
  await expect(page.getByText('SanDisk Ultra Fit')).toBeVisible()
  await expect(page.getByText('/mnt/usb-5f2a · vfat')).toBeVisible()
  expect(consoleErrors).toEqual([])
})
