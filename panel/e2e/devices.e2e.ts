// Экран «Устройства» на стенде: имена из сети (names.json службы), производитель по MAC (oui.txt прошивки), скрытый MAC,
// подробности и переименование — имя сохраняется на «роутере» отдельно от выбора VPN.
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
const STATE = mkdtempSync(join(tmpdir(), 'mitt-e2e-dev-'))

let stand: { listen: (p: number) => Promise<number>; close: () => Promise<void>; opts: { authDir: string; sessionDir: string; config: string; stateDir: string } }
let origin = ''
let password = ''
let recovery: string[] = []

test.beforeAll(async () => {
  const leases = join(STATE, 'dhcp.leases')
  writeFileSync(leases, [
    '1800000000 aa:bb:cc:dd:ee:20 192.168.31.20 android-5f2a *',
    '1800000000 3c:d9:2b:00:00:05 192.168.31.30 * *',
    '1800000000 a2:61:34:76:10:68 192.168.31.40 * *',
  ].join('\n') + '\n')
  // настройки: простой вид из config.valid.json и сервер из лабораторной фикстуры (без сервера панель ведёт на «Сервер»)
  const cfg = JSON.parse(readFileSync(join(ROOT, 'fixtures', 'config.valid.json'), 'utf8'))
  cfg.profiles[0].endpoint = JSON.parse(readFileSync(join(ROOT, 'fixtures', 'lab', 'config.json'), 'utf8')).profiles[0].endpoint
  const seed = join(STATE, 'config.json')
  writeFileSync(seed, JSON.stringify(cfg, null, 2))
  stand = createStand({ stateDir: join(STATE, 'stand'), bin: exe('mi-tt-ctl'), admin: exe('mi-tt-admin'), seed, leases })
  // файлы службы: таблица производителей и имена, найденные в сети
  const run = join(stand.opts.stateDir, 'run')
  mkdirSync(run, { recursive: true })
  writeFileSync(join(run, 'oui.txt'), '3C-D9-2B Hewlett Packard ICON:device_list_hp.png\n')
  writeFileSync(join(run, 'names.json'), JSON.stringify({ at: 1, devices: { 'aa:bb:cc:dd:ee:20': { name: 'Гостиная', kind: 'tv', model: 'Chromecast', source: 'mdns', rank: 9, seen: 1 } } }))
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

async function login(page: Page) {
  await page.addInitScript(() => { try { localStorage.setItem('mitt.lang', 'ru') } catch { /* без хранилища */ } })
  await page.goto(origin)
  await page.locator('#login-password').fill(password)
  await page.getByRole('button', { name: 'Войти' }).click()
  await page.getByRole('button', { name: 'Войти recovery-кодом' }).click()
  await page.locator('#login-recovery').fill(recovery.shift()!)
  await page.getByRole('button', { name: 'Подтвердить код' }).click()
  await page.locator('.side__nav').getByRole('link', { name: /Устройства/ }).click()
  // фикстура собрана не панелью: один раз привести к простому виду (сервер сохраняется) — как сделал бы пользователь
  const manual = page.getByRole('heading', { name: 'Настройки изменены вручную' })
  await page.locator('ul.devs, .manual').first().waitFor({ timeout: 15_000 })
  if (await manual.isVisible()) {
    await page.getByRole('button', { name: 'Привести к простому виду' }).first().click()
    await page.getByRole('alertdialog').getByRole('button', { name: 'Привести к простому виду' }).click()
  }
  await expect(page.locator('ul.devs')).toBeVisible({ timeout: 20_000 })
}
const config = () => JSON.parse(readFileSync(stand.opts.config, 'utf8'))

test('имена из сети, производитель, скрытый MAC и подробности', async ({ page }) => {
  await login(page)
  const list = page.locator('ul.devs')
  await expect(list.getByText('Гостиная', { exact: true })).toBeVisible()
  await expect(list.getByText('Устройство Hewlett Packard')).toBeVisible()
  await expect(list.getByText('Устройство со скрытым адресом')).toBeVisible()
  await expect(list.getByText('скрытый MAC', { exact: true }).first()).toBeVisible()
  const tv = list.locator('li', { hasText: 'Гостиная' })
  await tv.getByRole('button', { name: 'Подробнее' }).click()
  await expect(tv.getByText('Называет себя в сети')).toBeVisible()
  await expect(tv.getByText('Гостиная · Chromecast')).toBeVisible()
  await expect(tv.getByText('android-5f2a')).toBeVisible()
})

test('переименование сохраняется на роутере и не включает VPN для устройства', async ({ page }) => {
  await login(page)
  const before = config()
  await page.getByRole('button', { name: 'Переименовать Устройство Hewlett Packard' }).click()
  const input = page.locator('#rename-3c\\:d9\\:2b\\:00\\:00\\:05')
  await input.fill('Принтер в кабинете')
  await input.press('Enter')
  await expect.poll(() => config().device_names?.['3c:d9:2b:00:00:05'], { timeout: 10_000 }).toBe('Принтер в кабинете')
  expect(config().devices).toEqual(before.devices)
  await expect(page.locator('ul.devs').getByText('Принтер в кабинете')).toBeVisible()
})
