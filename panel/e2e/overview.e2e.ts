// «Обзор» на стенде: состояние роутера (подставные /proc и /sys) в шапке и карточке, скорость маршрутов из замера,
// имена устройств в «Трафике» из переименований, журнал трафика на странице «Модули».
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
const STATE = mkdtempSync(join(tmpdir(), 'mitt-e2e-ov-'))
const MAC = 'aa:bb:cc:dd:ee:20'

let stand: { listen: (p: number) => Promise<number>; close: () => Promise<void>; opts: { authDir: string; sessionDir: string; config: string; stateDir: string } }
let origin = ''
let password = ''
let recovery: string[] = []
const consoleErrors: string[] = []

function put(path: string, text: string) { mkdirSync(dirname(path), { recursive: true }); writeFileSync(path, text) }

test.beforeAll(async () => {
  const cfg = JSON.parse(readFileSync(join(ROOT, 'fixtures', 'config.valid.json'), 'utf8'))
  cfg.profiles[0].endpoint = JSON.parse(readFileSync(join(ROOT, 'fixtures', 'lab', 'config.json'), 'utf8')).profiles[0].endpoint
  cfg.device_names = { [MAC]: 'Телевизор в зале' }
  const seed = join(STATE, 'config.json')
  writeFileSync(seed, JSON.stringify(cfg, null, 2))
  const proc = join(STATE, 'proc'), sys = join(STATE, 'sys')
  put(join(proc, 'stat'), 'cpu  100 0 100 800 0 0 0 0 0 0\ncpu0 50 0 50 400 0 0 0 0\n')
  put(join(proc, 'meminfo'), 'MemTotal: 1000000 kB\nMemFree: 300000 kB\nMemAvailable: 600000 kB\n')
  put(join(proc, 'loadavg'), '0.42 0.30 0.25 1/200 1234\n')
  put(join(proc, 'uptime'), '273600.5 1000.0\n')
  put(join(proc, 'net', 'route'), 'Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\neth4\t00000000\t0100A8C0\t0003\t0\t0\t0\t00000000\n')
  put(join(proc, 'sys', 'net', 'netfilter', 'nf_conntrack_count'), '412\n')
  put(join(proc, 'sys', 'net', 'netfilter', 'nf_conntrack_max'), '65536\n')
  // как на BE7000: безымянные датчики чипа tsens_tz_sensorN
  for (const [z, ty, c] of [['thermal_zone0', 'tsens_tz_sensor3', '56200'], ['thermal_zone1', 'tsens_tz_sensor4', '61000'], ['thermal_zone2', 'tsens_tz_sensor13', '52000'], ['thermal_zone3', 'tsens_tz_sensor14', '53000']]) {
    put(join(sys, 'class', 'thermal', z!, 'type'), ty!)
    put(join(sys, 'class', 'thermal', z!, 'temp'), c!)
  }
  for (const d of ['eth4', 'mitt0']) { put(join(sys, 'class', 'net', d, 'statistics', 'rx_bytes'), '1000000'); put(join(sys, 'class', 'net', d, 'statistics', 'tx_bytes'), '500000') }
  stand = createStand({ stateDir: join(STATE, 'stand'), bin: exe('mi-tt-ctl'), admin: exe('mi-tt-admin'), seed, proc, sys })
  const run = join(stand.opts.stateDir, 'run')
  const now = Math.floor(Date.now() / 1000)
  put(join(run, 'speed.json'), JSON.stringify({ state: 'done', started: now - 60, at: now - 30, ping: { primary: 40, backup: null }, direct: { mbps: 100.4, bytes: 1 }, tunnel: { mbps: 199.2, bytes: 1 } }))
  const h0 = Math.floor(now / 3600) * 3600
  put(join(run, 'stats.json'), JSON.stringify({ last: { at: now, dev: {} }, hours: [{ t: h0 - 3600, vpn: 1e9, wan: 3e9, dev: { [MAC]: 2e9 } }, { t: h0, vpn: 5e8, wan: 1e9, dev: { [MAC]: 4e8 } }] }))
  put(join(run, 'storage.json'), JSON.stringify({ at: 1, data: { path: '/data/mi-lumruri', device: '', fs: '', total: 40960000, free: 18432000, writable: true, exec: true },
    usb: [{ path: '/mnt/usb-5f2a', device: '/dev/sda1', fs: 'vfat', total: 15360000000, free: 14336000000, writable: true, exec: true, vendor: 'SanDisk', model: 'Ultra Fit' }] }))
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
async function simplify(page: Page) {
  await nav(page, /Сайты/).click()
  await page.locator('.tiles, .manual').first().waitFor({ timeout: 15_000 })
  if (await page.getByRole('heading', { name: 'Настройки изменены вручную' }).isVisible()) {
    await page.getByRole('button', { name: 'Привести к простому виду' }).first().click()
    await page.getByRole('alertdialog').getByRole('button', { name: 'Привести к простому виду' }).click()
  }
  await expect(page.locator('.tiles').first()).toBeVisible({ timeout: 20_000 })
}
const config = () => JSON.parse(readFileSync(stand.opts.config, 'utf8'))

test('«Обзор»: плитки «Сейчас», карточки маршрутов со скоростью, имена в «Трафике»; значки в шапке — на других страницах', async ({ page }) => {
  await login(page)
  await simplify(page)
  const chips = page.getByRole('button', { name: /Состояние роутера/ })
  await expect(chips).toContainText('61°')
  await nav(page, /Обзор/).click()
  await expect(chips).toHaveCount(0)
  const tile = (name: string) => page.getByRole('region', { name, exact: true })
  await expect(tile('Процессор')).toContainText('0,42')
  await expect(tile('Температура')).toContainText('61°C')
  await expect(tile('Температура')).toContainText('среднее 56 °C')
  await expect(tile('Задержка')).toContainText('40мс')
  await expect(tile('Память')).toContainText('40%')
  await expect(page.getByText('без перезагрузки 3 дня 4 ч · 412 соединений')).toBeVisible()
  await expect(page.locator('.rcard__cap--vpn')).toHaveText('199Мбит/с')
  await expect(page.locator('.rcard__cap--direct')).toHaveText('100Мбит/с')
  await expect(page.locator('.stats__name', { hasText: 'Телевизор в зале' })).toBeVisible()
  if (process.env.SHOT) {
    await page.emulateMedia({ colorScheme: 'dark' })
    await page.setViewportSize({ width: 1440, height: 1100 })
    await page.waitForTimeout(6000)
    await page.screenshot({ path: process.env.SHOT, fullPage: true })
    await page.setViewportSize({ width: 390, height: 844 })
    await page.screenshot({ path: process.env.SHOT.replace('.png', '-phone.png'), fullPage: true })
  }
  expect(consoleErrors).toEqual([])
})

test('журнал трафика на «Модулях»: включается на флешке, в «Трафике» появляется «Месяц»', async ({ page }) => {
  await login(page)
  await simplify(page)
  await nav(page, /Модули/).click()
  await page.locator('#hist-on').check({ force: true })
  await page.locator('#hist-months').selectOption('3')
  await expect(page.getByRole('radio', { name: /SanDisk Ultra Fit/ })).toBeChecked()
  await page.getByRole('group', { name: 'Журнал трафика' }).getByRole('button', { name: 'Сохранить' }).click()
  await expect.poll(() => config().history, { timeout: 10_000 }).toEqual({ months: 3, target: '/mnt/usb-5f2a' })
  await nav(page, /Обзор/).click()
  await expect(page.getByRole('radio', { name: '3 месяца' })).toBeAttached()
  await expect(page.getByRole('radio', { name: 'Год' })).toHaveCount(0)
  expect(consoleErrors).toEqual([])
})
