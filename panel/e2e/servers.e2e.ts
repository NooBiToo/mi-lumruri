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
  writeFileSync(join(run, 'modules-catalog.json'), JSON.stringify({ modules: [{ name: 'sing-box', version: '1.14.4', title: 'sing-box', protocols: ['VLESS', 'Hysteria2', 'Trojan', 'Shadowsocks'],
    kinds: ['vless', 'hysteria2', 'trojan', 'shadowsocks'], asset: 'mitt-mod-sing-box-1.14.4.tar', tar_sha256: 'ab'.repeat(32), tar_bytes: 19906560, unpacked_bytes: 86155608 }] }))
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
  const drives = page.locator('ul.drives')
  await expect(drives.getByText('Внутренняя память')).toBeVisible()
  await expect(drives.getByText('SanDisk Ultra Fit')).toBeVisible()
  await expect(page.getByText('/mnt/usb-5f2a · vfat')).toBeVisible()
  expect(consoleErrors).toEqual([])
})

test('сервер VLESS по ссылке: сводка в настройках, ссылка — только в секретах; без модуля — предупреждение', async ({ page }) => {
  await login(page)
  await simplify(page)
  await nav(page, /Сервер/).click()
  await page.getByRole('button', { name: 'Добавить сервер' }).click()
  const link = 'vless://bf000d23-0752-40b4-affe-68f7707a9661@203.0.113.5:443?type=tcp&security=reality&sni=www.example.com&pbk=jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0&sid=01ab#VLESS%20дом' // secret-scan: allow тестовая ссылка
  await page.locator('#paste').fill(link)
  await page.getByRole('button', { name: 'Распознать' }).click()
  await expect(page.getByText('Для серверов VLESS нужен модуль sing-box', { exact: false })).toBeVisible()
  await expect(page.locator('#srv-name')).toHaveValue('VLESS дом')
  await page.getByRole('button', { name: 'Сохранить' }).click()
  await expect.poll(() => config().profiles.find((p: { kind: string }) => p.kind === 'vless')?.proxy, { timeout: 10_000 })
    .toEqual({ server: '203.0.113.5', port: 443, security: 'reality', transport: 'tcp' })
  expect(JSON.stringify(config())).not.toContain('bf000d23')
  const secrets = readFileSync(join(dirname(stand.opts.config), 'secrets.json'), 'utf8')
  await expect.poll(() => readFileSync(join(dirname(stand.opts.config), 'secrets.json'), 'utf8'), { timeout: 10_000 }).toContain('bf000d23')
  void secrets
  expect(consoleErrors).toEqual([])
})

test('«Модули»: установка на флешку ставит заявку службе', async ({ page }) => {
  await login(page)
  await nav(page, /Модули/).click()
  await expect(page.getByRole('heading', { name: /sing-box/ })).toBeVisible()
  await expect(page.getByText('Протоколы: VLESS, Hysteria2, Trojan, Shadowsocks')).toBeVisible()
  // внутренняя память мала (18 МБ свободно) — недоступна, флешка выбрана сама
  await expect(page.getByRole('radio', { name: /Внутренняя память/ })).toBeDisabled()
  await expect(page.getByRole('radio', { name: /SanDisk Ultra Fit/ })).toBeChecked()
  await page.getByRole('button', { name: 'Установить' }).click()
  const req = join(stand.opts.stateDir, 'run', 'module.request')
  await expect.poll(() => { try { return JSON.parse(readFileSync(req, 'utf8')) } catch { return null } }, { timeout: 10_000 })
    .toMatchObject({ action: 'install', name: 'sing-box', dir: '/mnt/usb-5f2a/mi-lumruri-modules/sing-box' })
  expect(consoleErrors).toEqual([])
})

test('подписка сервера sing-box: добавление ссылкой https, список от роутера, выбор сервера', async ({ page }) => {
  await login(page)
  await simplify(page)
  await nav(page, /Сервер/).click()
  await page.getByRole('button', { name: 'Добавить сервер' }).click()
  await page.locator('#paste').fill('https://bob:pw@sub.example.com/list') // secret-scan: allow тестовая подписка
  await page.getByRole('button', { name: 'Распознать' }).click()
  await page.locator('#srv-name').fill('Провайдер')
  await page.getByRole('button', { name: 'Сохранить' }).click()
  await expect.poll(() => config().profiles.find((p: { name: string }) => p.name === 'Провайдер')?.kind, { timeout: 10_000 }).toBe('vless')
  const id = config().profiles.find((p: { name: string }) => p.name === 'Провайдер').id
  const sec = () => readFileSync(join(dirname(stand.opts.config), 'secrets.json'), 'utf8')
  await expect.poll(sec, { timeout: 10_000 }).toContain('sub.example.com/list')
  // служба скачала список: тот же импорт, что делает mitt-sub.sh
  const list = join(STATE, 'list.txt')
  writeFileSync(list, Buffer.from('vless://bf000d23-0752-40b4-affe-68f7707a9661@a.example.com:443?security=tls#A\nhy2://pw@b.example.com:443#B\n').toString('base64')) // secret-scan: allow тестовые ссылки
  const out = execFileSync(exe('mi-tt-ctl'), ['proxy-sub-import', stand.opts.config, id, list], { env: { MI_TT_RUN_DIR: join(stand.opts.stateDir, 'run'), ...(process.env.SystemRoot ? { SystemRoot: process.env.SystemRoot } : {}) } }).toString()
  expect(JSON.parse(out)).toMatchObject({ changed: true, count: 2, picked: 'A' })
  await page.reload()
  await nav(page, /Сервер/).click()
  await page.getByRole('button', { name: /Провайдер/ }).click()
  const subList = page.getByRole('radiogroup', { name: 'Сервер из подписки' })
  await expect(subList.getByRole('radio', { checked: true })).toContainText('A')
  await subList.getByRole('radio', { name: /B/ }).click()
  await expect.poll(() => config().profiles.find((p: { id: string }) => p.id === id)?.kind, { timeout: 10_000 }).toBe('hysteria2')
  expect(config().profiles.find((p: { id: string }) => p.id === id).sub_pick).toBe('B')
  // автовыбор: без замера задержки остаётся текущий сервер, в настройках — sub_auto
  await page.locator('label[for="sub-auto"]').click()
  await expect.poll(() => config().profiles.find((p: { id: string }) => p.id === id)?.sub_auto, { timeout: 10_000 }).toBe(true)
  await expect(subList.getByRole('radio', { checked: true })).toContainText('авто')
  // выбор вручную выключает автовыбор
  await subList.getByRole('radio', { name: /A/ }).click()
  await expect.poll(() => config().profiles.find((p: { id: string }) => p.id === id)?.sub_auto ?? false, { timeout: 10_000 }).toBe(false)
  expect(consoleErrors).toEqual([])
})

test('сервер AmneziaWG из конфигурации .conf: сводка в настройках, конфигурация — только в секретах', async ({ page }) => {
  await login(page)
  await simplify(page)
  await nav(page, /Сервер/).click()
  await page.getByRole('button', { name: 'Добавить сервер' }).click()
  const conf = '[Interface]\nPrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=\nAddress = 10.8.0.2/32\nJc = 4\nJmin = 40\nJmax = 70\nH1 = 1-2\n\n[Peer]\nPublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\nAllowedIPs = 0.0.0.0/0\nEndpoint = awg.example.com:51820\n' // secret-scan: allow тестовый ключ
  await page.locator('#paste').fill(conf)
  await page.getByRole('button', { name: 'Распознать' }).click()
  await expect(page.getByText('Обфускация')).toBeVisible()
  await page.locator('#srv-name').fill('AWG дом')
  await page.getByRole('button', { name: 'Сохранить' }).click()
  await expect.poll(() => config().profiles.find((p: { name: string }) => p.name === 'AWG дом')?.proxy, { timeout: 10_000 })
    .toEqual({ server: 'awg.example.com', port: 51820, security: 'awg', transport: 'udp' })
  expect(config().profiles.find((p: { name: string }) => p.name === 'AWG дом').kind).toBe('amneziawg')
  expect(JSON.stringify(config())).not.toContain('yAnz5TF')
  await expect.poll(() => readFileSync(join(dirname(stand.opts.config), 'secrets.json'), 'utf8'), { timeout: 10_000 }).toContain('Jmin = 40')
  expect(consoleErrors).toEqual([])
})

test('Telegram через WebSocket: положение «WS» только у Telegram, запасной путь — сервер VPN или напрямую', async ({ page }) => {
  await login(page)
  await simplify(page)
  await nav(page, /Сайты/).click()
  await expect(page.locator('input[name="route-youtube"][value="ws"]')).toHaveCount(0)
  await page.locator('input[name="route-telegram"][value="ws"]').evaluate((el) => (el as HTMLInputElement).click())
  const via = page.getByRole('combobox', { name: 'Запасной путь Telegram, если WebSocket не работает' })
  await expect(via).toBeVisible()
  // модуля tgws в каталоге стенда нет — подсказка
  await expect(page.getByText('Нужен модуль tgws')).toBeVisible()
  const def = config().profiles[0].id
  await expect(via).toHaveValue(def)
  await expect.poll(() => config().rules.some((r: { action: { type: string } }) => r.action.type === 'tg_ws'), { timeout: 15_000 }).toBe(true)
  expect(config().tgws).toEqual({ via: def })
  await via.selectOption('')
  await expect.poll(() => JSON.stringify(config().tgws), { timeout: 15_000 }).toBe('{}')
  expect(consoleErrors).toEqual([])
})
