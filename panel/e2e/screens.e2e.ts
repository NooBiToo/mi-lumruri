// Скриншоты для README и руководства (docs/img): стенд с правдоподобными данными — служба запущена, 4 ядра,
// 13 датчиков, трафик за сутки, устройства с именами, флешка. Запуск: SCREENS=1 npx playwright test e2e/screens.e2e.ts
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

test.skip(!process.env.SCREENS, 'только по SCREENS=1')

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..')
const IMG = join(ROOT, 'docs', 'img')
const binDir = process.env.MITT_BIN_DIR ?? join(ROOT, 'controller', 'target', 'release')
const exe = (n: string) => join(binDir, process.platform === 'win32' ? `${n}.exe` : n)
const STATE = mkdtempSync(join(tmpdir(), 'mitt-screens-'))

const DEVICES: [string, string, string, number][] = [
  ['aa:bb:cc:dd:ee:20', '192.168.31.20', 'Телевизор в зале', 3.1e9],
  ['3c:d9:2b:10:20:31', '192.168.31.21', 'Ноутбук', 2.4e9],
  ['a2:61:34:76:10:68', '192.168.31.22', 'Телефон', 1.2e9],
  ['70:4f:57:11:22:33', '192.168.31.23', 'Приставка', 0.8e9],
  ['f0:18:98:44:55:66', '192.168.31.24', 'Планшет', 0.6e9],
  ['b8:27:eb:77:88:99', '192.168.31.25', 'Домашний сервер', 0.4e9],
  ['dc:a6:32:01:02:03', '192.168.31.26', 'Колонка', 0.1e9],
  ['5c:cf:7f:04:05:06', '192.168.31.27', 'Пылесос', 0.02e9],
]

let stand: { listen: (p: number) => Promise<number>; close: () => Promise<void>; opts: { authDir: string; sessionDir: string; config: string; stateDir: string } }
let origin = ''
let password = ''
let recovery: string[] = []
let ticker: NodeJS.Timeout | undefined

function put(path: string, text: string) { mkdirSync(dirname(path), { recursive: true }); writeFileSync(path, text) }

test.beforeAll(async () => {
  const cfg = JSON.parse(readFileSync(join(ROOT, 'fixtures', 'config.valid.json'), 'utf8'))
  cfg.profiles[0] = { ...cfg.profiles[0], name: 'Домашний сервер', endpoint: { server: '203.0.113.10', port: 443, sni: 'vpn.example.com', username: 'home' } }
  cfg.device_names = Object.fromEntries(DEVICES.map(([mac, , name]) => [mac, name]))
  const seed = join(STATE, 'config.json')
  writeFileSync(seed, JSON.stringify(cfg, null, 2))
  const leases = join(STATE, 'dhcp.leases')
  writeFileSync(leases, DEVICES.map(([mac, ip]) => `1900000000 ${mac} ${ip} * *`).join('\n') + '\n')

  // /proc и /sys: счётчики процессора растут, чтобы два снимка службы различались
  const proc = join(STATE, 'proc'), sys = join(STATE, 'sys')
  let tick = 0
  const stat = () => {
    tick += 1
    const core = (k: number) => `${1000 + tick * (6 + k * 3)} 0 ${500 + tick * (3 + k)} ${9000 + tick * 90} 0 0 0 0 0 0`
    put(join(proc, 'stat'), `cpu  ${1000 + tick * 42} 0 ${500 + tick * 18} ${36000 + tick * 360} 0 0 0 0 0 0\n` + [0, 1, 2, 3].map((k) => `cpu${k} ${core(k)}\n`).join(''))
  }
  stat()
  ticker = setInterval(stat, 40)
  put(join(proc, 'meminfo'), 'MemTotal: 804864 kB\nMemFree: 210000 kB\nMemAvailable: 386048 kB\n')
  put(join(proc, 'loadavg'), '1.09 1.11 1.09 1/200 1234\n')
  put(join(proc, 'uptime'), '501000.5 1000.0\n')
  put(join(proc, 'net', 'route'), 'Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\neth0\t00000000\t0100A8C0\t0003\t0\t0\t0\t00000000\n')
  put(join(proc, 'sys', 'net', 'netfilter', 'nf_conntrack_count'), '1674\n')
  put(join(proc, 'sys', 'net', 'netfilter', 'nf_conntrack_max'), '81920\n')
  const temps = [55.2, 54.1, 52.8, 53.9, 54.6, 53.2, 52.4, 54.0, 53.5, 54.8, 52.9, 53.6, 55.0]
  temps.forEach((c, i) => {
    put(join(sys, 'class', 'thermal', `thermal_zone${i}`, 'type'), `tsens_tz_sensor${i + 3}`)
    put(join(sys, 'class', 'thermal', `thermal_zone${i}`, 'temp'), String(Math.round(c * 1000)))
  })
  // счётчики байт WAN и туннеля растут: «сейчас» в плитках и карточках маршрутов
  let bytes = 0
  const net = () => {
    bytes += 1
    put(join(sys, 'class', 'net', 'eth0', 'statistics', 'rx_bytes'), String(9e9 + bytes * 7.2e5))
    put(join(sys, 'class', 'net', 'eth0', 'statistics', 'tx_bytes'), String(2e9 + bytes * 3.8e4))
    put(join(sys, 'class', 'net', 'mitt0', 'statistics', 'rx_bytes'), String(4e9 + bytes * 6.2e5))
    put(join(sys, 'class', 'net', 'mitt0', 'statistics', 'tx_bytes'), String(1e9 + bytes * 1.3e4))
  }
  net()
  const netTicker = setInterval(net, 1000)
  netTicker.unref()

  stand = createStand({ stateDir: join(STATE, 'stand'), bin: exe('mi-tt-ctl'), admin: exe('mi-tt-admin'), seed, leases, proc, sys })
  const run = join(stand.opts.stateDir, 'run')
  const now = Math.floor(Date.now() / 1000)
  put(join(run, 'status.json'), JSON.stringify({ at: now, release: '0.14.0', protection: 'none', endpoint: 'primary',
    engines: { trusttunnel: true, nfqws2: true, nginx: true, uhttpd: true, service: true }, last_apply: null, render: null, apply: null }))
  put(join(run, 'speed.json'), JSON.stringify({ state: 'done', started: now - 900, at: now - 870, ping: { primary: 42, backup: null },
    direct: { mbps: 103.4, bytes: 5e7 }, tunnel: { mbps: 91.2, bytes: 5e7 } }))
  const h0 = Math.floor(now / 3600) * 3600
  const shape = [20, 14, 10, 8, 8, 12, 22, 34, 30, 26, 38, 44, 40, 36, 42, 50, 58, 72, 88, 96, 84, 66, 44, 30]
  const hours = shape.map((p, i) => ({ t: h0 - (23 - i) * 3600, wan: p * 5e6, vpn: p * 2e6, dev: {} }))
  put(join(run, 'stats.json'), JSON.stringify({ last: { at: now, dev: {} }, hours: hours.map((h, i) => ({ ...h, dev: i === 23 ? Object.fromEntries(DEVICES.map(([mac, , , b]) => [mac, b])) : {} })) }))
  put(join(run, 'storage.json'), JSON.stringify({ at: 1, data: { path: '/data/mi-lumruri', device: '', fs: '', total: 21600000, free: 6800000, writable: true, exec: true },
    usb: [{ path: '/mnt/usb-5f2a', device: '/dev/sda1', fs: 'vfat', total: 15360000000, free: 14336000000, writable: true, exec: true, vendor: 'SanDisk', model: 'Ultra Fit' }] }))
  put(join(run, 'modules-catalog.json'), JSON.stringify({ modules: [
    { name: 'sing-box', version: '1.14.4', title: 'sing-box', protocols: ['VLESS', 'Hysteria2', 'Trojan', 'Shadowsocks'], kinds: ['vless', 'hysteria2', 'trojan', 'shadowsocks'],
      asset: 'mitt-mod-sing-box-1.14.4.tar', tar_sha256: 'ab'.repeat(32), tar_bytes: 19906560, unpacked_bytes: 86155608 },
    { name: 'amneziawg', version: '3.1.20261116', title: 'AmneziaWG', protocols: ['AmneziaWG'], kinds: ['amneziawg'],
      asset: 'mitt-mod-amneziawg-3.1.20261116.tar', tar_sha256: 'cd'.repeat(32), tar_bytes: 1054720, unpacked_bytes: 3145728 },
  ] }))
  put(join(run, 'oui.txt'), '3C-D9-2B Hewlett Packard ICON:device_list_hp.png\n')
  put(join(run, 'names.json'), JSON.stringify({ at: 1, devices: { 'aa:bb:cc:dd:ee:20': { name: 'Гостиная', kind: 'tv', model: 'Chromecast', source: 'mdns', rank: 9, seen: 1 } } }))

  const port = await stand.listen(0)
  origin = `https://127.0.0.1:${port}`
  password = 'pw-' + randomBytes(18).toString('base64url')
  const env = { MI_TT_AUTH_DIR: stand.opts.authDir, MI_TT_SESSION_DIR: stand.opts.sessionDir, ...(process.env.SystemRoot ? { SystemRoot: process.env.SystemRoot } : {}) }
  const init = JSON.parse(execFileSync(exe('mi-tt-admin'), ['auth', 'init', '--stdin', '--with-totp'], { input: `${password}\n${password}\n`, env }).toString())
  recovery = [...init.recovery_codes]
  execFileSync(exe('mi-tt-admin'), ['auth', 'confirm', '--stdin'], { input: totp(init.totp_secret_base32) + '\n', env })
})
test.afterAll(async () => {
  clearInterval(ticker)
  await stand?.close()
  rmSync(STATE, { recursive: true, force: true })
})

const nav = (page: Page, name: RegExp) => page.locator('.side__nav').getByRole('link', { name })
async function login(page: Page, scheme: 'dark' | 'light') {
  await page.emulateMedia({ colorScheme: scheme })
  await page.addInitScript(() => { try { localStorage.setItem('mitt.lang', 'ru') } catch { /* без хранилища */ } })
  await page.goto(origin)
  await page.locator('#login-password').fill(password)
  await page.getByRole('button', { name: 'Войти' }).click()
  await page.getByRole('button', { name: 'Войти recovery-кодом' }).click()
  await page.locator('#login-recovery').fill(recovery.shift()!)
  await page.getByRole('button', { name: 'Подтвердить код' }).click()
}
/** Снимок без заявки на применение: на стенде её некому забрать, иначе вверху «Применяю настройки…». */
async function shot(page: Page, name: string, fullPage = true, prepare?: () => Promise<void>) {
  rmSync(join(stand.opts.stateDir, 'run', 'apply.request'), { force: true })
  await page.reload()
  await prepare?.()
  await page.waitForTimeout(name === 'overview' || name === 'mobile' ? 12_000 : 2500)
  await page.screenshot({ path: join(IMG, `${name}.png`), fullPage, animations: 'disabled' })
}

test('скриншоты', async ({ page }) => {
  test.setTimeout(180_000)
  await page.setViewportSize({ width: 1440, height: 900 })
  await login(page, 'dark')
  await expect(nav(page, /Сайты/)).toBeVisible()
  // сайты: простой вид, сервисы через VPN и с обходом
  await nav(page, /Сайты/).click()
  await page.locator('.tiles, .manual').first().waitFor({ timeout: 15_000 })
  if (await page.getByRole('heading', { name: 'Настройки изменены вручную' }).isVisible()) {
    await page.getByRole('button', { name: 'Привести к простому виду' }).first().click()
    await page.getByRole('alertdialog').getByRole('button', { name: 'Привести к простому виду' }).click()
  }
  await expect(page.locator('.tiles').first()).toBeVisible({ timeout: 20_000 })
  const route = (id: string, v: 'vpn' | 'zapret') => page.locator(`input[name="route-${id}"][value="${v}"]`).evaluate((el) => (el as HTMLInputElement).click())
  for (const id of ['youtube', 'meta', 'telegram', 'google_ai', 'google_meet', 'tiktok', 'twitter', 'anime', 'news', 'block']) await route(id, 'vpn')
  await route('discord', 'zapret')
  // автосохранение: дождаться, пока выбор дойдёт до настроек на «роутере»
  await expect.poll(() => readFileSync(stand.opts.config, 'utf8').includes('discord'), { timeout: 20_000 }).toBe(true)
  await page.waitForTimeout(3000)
  await shot(page, 'sites', false)

  await nav(page, /Обзор/).click()
  await expect(page.locator('.rcard').first()).toBeVisible()
  await shot(page, 'overview')

  await nav(page, /Устройства/).click()
  await expect(page.locator('ul.devs')).toBeVisible({ timeout: 15_000 })
  await shot(page, 'devices')

  await nav(page, /Сервер/).click()
  await page.waitForTimeout(1500)
  await shot(page, 'server')

  await nav(page, /Модули/).click()
  await page.waitForTimeout(1500)
  await shot(page, 'modules')

  await nav(page, /Zapret/).click()
  await page.waitForTimeout(1500)
  await shot(page, 'zapret')

  await nav(page, /Диагностика/).click()
  // итог проверки в формате mitt-diag.sh: на стенде службы нет, проверку выполняет роутер
  const dd = join(stand.opts.stateDir, 'run', 'diag')
  const t0 = Math.floor(Date.now() / 1000)
  put(join(dd, 'checks.tsv'), [
    ['service', 'ok', 'работает'], ['autostart', 'ok', 'служба запустится после перезагрузки роутера'], ['firmware', 'ok', '1.1.38'],
    ['client', 'ok', 'подключён к серверу, задержка 42 мс, на связи 5 дн 19 ч, клиент 1.3.0'],
    ['watch', 'ok', 'трафик через туннель идёт, проверка 0 мин назад'], ['exit', 'ok', 'выход через туннель 203.0.113.10, напрямую 198.51.100.7'],
    ['route', 'ok', 'трафик сайтов из списка уходит в туннель'], ['firewall', 'ok', 'трафик устройств сортируется: mitt_vpn mitt_zapret'],
    ['dns', 'ok', 'DNS роутера отвечает, youtube.com разрешается'], ['secure', 'skip', 'защищённый DNS выключен'],
    ['zapret', 'ok', 'nfqws2 работает'], ['restarts', 'ok', 'за последние 10 минут программы не падали'],
  ].map((r) => r.join('\t')).join('\n') + '\n')
  put(join(dd, 'started'), String(t0 - 14))
  put(join(dd, 'finished'), String(t0 - 2))
  put(join(dd, 'log-service.txt'), 'применены настройки: 11 сервисов через VPN, 1 с обходом блокировок\nсторож: туннель работает\n')
  await shot(page, 'diag')

  // телефон, светлая тема
  await page.emulateMedia({ colorScheme: 'light' })
  await page.setViewportSize({ width: 390, height: 844 })
  await page.goto(`${origin}/#status`)
  await expect(page.locator('.rcard').first()).toBeVisible()
  await shot(page, 'mobile', false)
})
