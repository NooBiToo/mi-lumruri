// Сквозная проверка стенда: HTTPS → CGI → контроллер, вход паролем и TOTP, отдача собранной панели.
// Запуск: node --test stand/   (нужны controller/target/release/mi-tt-ctl[.exe], mi-tt-admin[.exe], panel/dist и openssl)
// Пароль и секрет TOTP создаются заново в каждом тесте; TOTP считается независимой реализацией stand/totp.mjs.

import { after, test } from 'node:test'
import assert from 'node:assert/strict'
import { request } from 'node:https'
import { checkServerIdentity } from 'node:tls'
import { execFileSync } from 'node:child_process'
import { randomBytes } from 'node:crypto'
import { mkdtempSync, readFileSync, readdirSync, rmSync } from 'node:fs'
import { readFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createStand, defaults } from './server.mjs'
import { totp } from './totp.mjs'

const fx = (p) => join(defaults().seed, '..', p)
const STATE = mkdtempSync(join(tmpdir(), 'mitt-stand-'))
after(() => rmSync(STATE, { recursive: true, force: true }))
const now = () => Math.floor(Date.now() / 1000)

async function open(name, seed) {
  const s = createStand({ stateDir: join(STATE, name), ...(seed ? { seed } : {}) })
  const port = await s.listen(0)
  return { s, port, origin: `https://127.0.0.1:${port}` }
}

/** HTTPS-запрос с проверкой временного сертификата стенда (ca), без глобального отключения проверки TLS. */
function call(st, { method = 'GET', path = '/cgi-bin/api/config', headers = {}, body } = {}) {
  return new Promise((ok, fail) => {
    const r = request({ host: '127.0.0.1', port: st.port, method, path, headers, ca: st.s.ca,
      // сертификат проверяется для 127.0.0.1 и при подменённом Host (проверка DNS rebinding)
      checkServerIdentity: (_h, cert) => checkServerIdentity('127.0.0.1', cert) }, (res) => {
      const chunks = []
      res.on('data', (c) => chunks.push(c))
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString()
        let json = null
        try { json = JSON.parse(text) } catch {}
        ok({ status: res.statusCode, headers: res.headers, body: json, text })
      })
    })
    r.on('error', fail)
    r.end(body)
  })
}

/** Настройка входа так, как это делает оператор: mi-tt-admin auth init/confirm, секреты — только через stdin. */
function enroll(st) {
  const password = 'pw-' + randomBytes(18).toString('base64url')
  const env = { MI_TT_AUTH_DIR: st.s.opts.authDir, MI_TT_SESSION_DIR: st.s.opts.sessionDir, ...(process.env.SystemRoot ? { SystemRoot: process.env.SystemRoot } : {}) }
  const init = JSON.parse(execFileSync(st.s.opts.admin, ['auth', 'init', '--stdin', '--with-totp'], { input: `${password}\n${password}\n`, env }).toString())
  execFileSync(st.s.opts.admin, ['auth', 'confirm', '--stdin'], { input: totp(init.totp_secret_base32) + '\n', env })
  return { password, secret: init.totp_secret_base32, recovery: init.recovery_codes }
}

/** Клиент со своим «хранилищем cookie», как у браузера. */
class Client {
  constructor(st) {
    this.st = st
    this.cookies = new Map()
    this.csrf = null
  }
  async req(method, path, data, { origin = this.st.origin, csrf = this.csrf, type = 'application/json' } = {}) {
    const headers = {}
    const body = data === undefined ? undefined : typeof data === 'string' || Buffer.isBuffer(data) ? data : JSON.stringify(data)
    if (body !== undefined) Object.assign(headers, { 'Content-Type': type, 'Content-Length': Buffer.byteLength(body) })
    if (method !== 'GET' && origin) Object.assign(headers, { Origin: origin, 'Sec-Fetch-Site': 'same-origin' })
    if (method !== 'GET' && csrf) headers['X-MITT-CSRF'] = csrf
    if (this.cookies.size) headers.Cookie = [...this.cookies].map(([k, v]) => `${k}=${v}`).join('; ')
    const r = await call(this.st, { method, path: '/cgi-bin/api' + path, headers, body })
    for (const c of r.headers['set-cookie'] ?? []) {
      const [kv] = c.split(';')
      const [k, v] = kv.split('=')
      if (/Max-Age=0/.test(c)) this.cookies.delete(k)
      else this.cookies.set(k, v)
    }
    return r
  }
  async login(cred, second = { totp: totp(cred.secret, now() + 30) }) {
    const r1 = await this.req('POST', '/auth/login', { password: cred.password })
    assert.equal(r1.status, 200, r1.text)
    const r2 = await this.req('POST', '/auth/second', second)
    assert.equal(r2.status, 200, r2.text)
    this.csrf = r2.body.csrf
    return r2
  }
}

test('панель: index.html и все ассеты отдаются по HTTPS с заголовками защиты', async () => {
  const st = await open('static')
  try {
    const r = await call(st, { path: '/' })
    assert.equal(r.status, 200)
    assert.match(r.headers['content-security-policy'], /frame-ancestors 'none'/)
    assert.equal(r.headers['x-frame-options'], 'DENY')
    assert.match(r.headers['strict-transport-security'], /max-age=/)
    const assets = [...r.text.matchAll(/(?:src|href)="\.\/(assets\/[^"]+)"/g)].map((m) => m[1])
    assert.ok(assets.length >= 2, r.text)
    for (const a of assets) assert.equal((await call(st, { path: '/' + a })).status, 200, a)
    for (const p of ['/../ARCHITECTURE.md', '/%2e%2e/ARCHITECTURE.md', '/assets/../../ARCHITECTURE.md', '/..%5cARCHITECTURE.md']) {
      assert.equal((await call(st, { path: p })).status, 404, p)
    }
  } finally {
    await st.s.close()
  }
})

test('без настройки входа и без входа API закрыт', async () => {
  const st = await open('closed')
  try {
    const c = new Client(st)
    let r = await c.req('GET', '/config')
    assert.deepEqual([r.status, r.body.error.code], [503, 'auth_not_configured'])
    enroll(st)
    r = await c.req('GET', '/config')
    assert.deepEqual([r.status, r.body.error.code], [401, 'auth_required'])
    assert.equal(r.body.config, undefined)
    r = await c.req('POST', '/preview', await readFile(fx('request.tv-video-trusttunnel.json')))
    assert.deepEqual([r.status, r.body.error.code], [401, 'auth_required'])
    r = await c.req('GET', '/auth/session')
    assert.deepEqual([r.body.authenticated, r.body.stage], [false, 'password'])
  } finally {
    await st.s.close()
  }
})

test('вход: пароль → TOTP, cookie __Host- Secure/HttpOnly/SameSite=Strict, чтение и preview, выход', async () => {
  const st = await open('login')
  try {
    const cred = enroll(st)
    const c = new Client(st)
    let r = await c.req('POST', '/auth/login', { password: 'wrong-' + cred.password })
    assert.deepEqual([r.status, r.body.error.code], [401, 'invalid_credentials'])
    r = await c.req('POST', '/auth/login', { password: cred.password })
    assert.equal(r.status, 200)
    const pre = r.headers['set-cookie'][0]
    assert.match(pre, /^__Host-mitt_pre=[0-9a-f]{64}; Path=\/; Max-Age=300; Secure; HttpOnly; SameSite=Strict$/)
    // только пароль — API закрыт
    assert.equal((await c.req('GET', '/config')).status, 401)
    r = await c.req('POST', '/auth/second', { totp: totp(cred.secret, now() + 30) })
    assert.equal(r.status, 200, r.text)
    c.csrf = r.body.csrf
    const sess = r.headers['set-cookie'].find((x) => x.startsWith('__Host-mitt_sess='))
    assert.match(sess, /^__Host-mitt_sess=[0-9a-f]{64}; Path=\/; Max-Age=28800; Secure; HttpOnly; SameSite=Strict$/)
    assert.ok(!c.cookies.has('__Host-mitt_pre'), 'cookie первого этапа стёрта')

    r = await c.req('GET', '/config')
    assert.equal(r.status, 200)
    assert.equal(r.headers['cache-control'], 'no-store')
    assert.equal(r.body.config.devices.length, 2)
    r = await c.req('POST', '/preview', await readFile(fx('request.tv-video-trusttunnel.json')))
    assert.equal(r.status, 200)
    const p = r.body.preview
    assert.equal(p.applied, false)
    assert.equal(p.probes[0].before.rule_id, 'r-home-video')
    assert.equal(p.probes[0].after.rule_id, 'r-tv-video')

    // ошибочный ввод после входа
    r = await c.req('POST', '/preview', await readFile(fx('invalid/request.unknown-refs.json')))
    assert.equal(r.status, 422)
    assert.deepEqual(r.body.issues.map((i) => i.code), ['unknown_device', 'unknown_group', 'unknown_profile'])
    assert.equal((await c.req('POST', '/preview', '{"rule":')).status, 400)
    assert.equal((await c.req('POST', '/preview', '{}', { type: 'text/plain' })).status, 415)
    assert.equal((await c.req('POST', '/preview', JSON.stringify({ pad: 'x'.repeat(70 * 1024) }))).status, 413)
    assert.equal((await c.req('POST', '/apply', '{}')).status, 404)
    assert.equal((await c.req('DELETE', '/config')).status, 405)
    // без CSRF-заголовка изменяющий запрос отклоняется
    r = await c.req('POST', '/preview', await readFile(fx('request.tv-video-trusttunnel.json')), { csrf: null })
    assert.deepEqual([r.status, r.body.error.code], [403, 'csrf_failed'])

    r = await c.req('POST', '/auth/logout', {})
    assert.equal(r.status, 200)
    assert.equal(c.cookies.size, 0)
    assert.equal((await c.req('GET', '/config')).status, 401)
  } finally {
    await st.s.close()
  }
})

test('повтор кода и одновременные запросы с одним кодом: проходит ровно один', async () => {
  const st = await open('replay')
  try {
    const cred = enroll(st)
    const code = totp(cred.secret, now() + 30)
    const clients = [0, 1, 2, 3].map(() => new Client(st))
    for (const c of clients) assert.equal((await c.req('POST', '/auth/login', { password: cred.password })).status, 200)
    const res = await Promise.all(clients.map((c) => c.req('POST', '/auth/second', { totp: code })))
    const st200 = res.filter((r) => r.status === 200)
    assert.equal(st200.length, 1, JSON.stringify(res.map((r) => [r.status, r.body?.error?.code])))
    for (const r of res.filter((x) => x.status !== 200)) assert.deepEqual([r.status, r.body.error.code], [401, 'code_reused'])
    // тот же код позже — снова отказ
    const late = new Client(st)
    await late.req('POST', '/auth/login', { password: cred.password })
    const r = await late.req('POST', '/auth/second', { totp: code })
    assert.equal(r.body.error.code, 'code_reused')
    // recovery-код работает один раз
    const rc = new Client(st)
    await rc.login(cred, { recovery_code: cred.recovery[0] })
    const again = new Client(st)
    await again.req('POST', '/auth/login', { password: cred.password })
    assert.equal((await again.req('POST', '/auth/second', { recovery_code: cred.recovery[0] })).body.error.code, 'invalid_code')
  } finally {
    await st.s.close()
  }
})

test('API: недоступный контроллер даёт 502, а не падение стенда', async () => {
  const broken = createStand({ stateDir: join(STATE, 'broken'), bin: join(defaults().bin, '..', 'no-such-binary') })
  const port = await broken.listen(0)
  try {
    const r = await call({ s: broken, port }, {})
    assert.equal(r.status, 502)
    assert.equal(r.body.error.code, 'cgi_failed')
  } finally {
    await broken.close()
  }
})

// ---------- этап 2: запись через стенд, теперь только после входа ----------

const labSeed = fx('lab/config.json')
const rule = { id: 'r-tv-video', source: { type: 'device', id: 'tv' }, destination: { type: 'group', id: 'video' }, action: { type: 'profile', id: 'tt-lab' } }

test('запись: сохранение после входа, повторное чтение после перезапуска стенда', async () => {
  let st = await open('save', labSeed)
  const dir = st.s.opts.stateDir
  const cred = enroll(st)
  const c = new Client(st)
  await c.login(cred)
  const cfg = (await c.req('GET', '/config')).body
  assert.equal(cfg.config.rules.length, 0)
  const r = await c.req('POST', '/rules', { base_revision: cfg.revision, rule })
  assert.equal(r.status, 200, r.text)
  assert.equal(r.body.mode, 'add')
  const again = await c.req('POST', '/rules', { base_revision: cfg.revision, rule: { ...rule, id: 'r-2' } })
  assert.deepEqual([again.status, again.body.error.code], [409, 'revision_conflict'])
  await st.s.close()
  // новый процесс стенда (новый порт и сертификат) на том же каталоге: сессия и настройки сохранились
  st = await open('save', labSeed)
  c.st = st
  const reread = (await c.req('GET', '/config')).body
  assert.equal(reread.revision, r.body.revision)
  assert.deepEqual(reread.config.rules.map((x) => x.id), ['r-tv-video'])
  assert.equal(JSON.parse(readFileSync(join(dir, 'config.json'), 'utf8')).rules.length, 1)
  // «перезагрузка роутера»: каталог сессий очищен — нужен новый вход, настройки входа на месте
  rmSync(st.s.opts.sessionDir, { recursive: true, force: true })
  assert.equal((await c.req('GET', '/config')).status, 401)
  await c.login(cred, { recovery_code: cred.recovery[1] })
  assert.equal((await c.req('GET', '/config')).status, 200)
  await st.s.close()
  assert.equal(JSON.parse(readFileSync(labSeed, 'utf8')).rules.length, 0, 'фикстура не изменилась')
})

test('запись: чужой origin, отсутствие Origin, cross-site и чужой Host отклоняются даже с сессией', async () => {
  const st = await open('deny', labSeed)
  try {
    const cred = enroll(st)
    const c = new Client(st)
    await c.login(cred)
    const before = readFileSync(join(st.s.opts.stateDir, 'config.json'))
    const cfg = (await c.req('GET', '/config')).body
    const body = { base_revision: cfg.revision, rule }
    let r = await c.req('POST', '/rules', body, { origin: 'https://evil.example' })
    assert.deepEqual([r.status, r.body.error.code], [403, 'origin_forbidden'])
    r = await c.req('POST', '/rules', body, { origin: `http://127.0.0.1:${st.port}` })
    assert.deepEqual([r.status, r.body.error.code], [403, 'origin_forbidden'], 'http-origin не допускается')
    r = await c.req('POST', '/rules', body, { origin: null })
    assert.deepEqual([r.status, r.body.error.code], [403, 'origin_required'])
    const json = JSON.stringify(body)
    const h = { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(json), Cookie: [...c.cookies].map(([k, v]) => `${k}=${v}`).join('; '), 'X-MITT-CSRF': c.csrf }
    r = await call(st, { method: 'POST', path: '/cgi-bin/api/rules', headers: { ...h, Origin: st.origin, 'Sec-Fetch-Site': 'cross-site' }, body: json })
    assert.deepEqual([r.status, r.body.error.code], [403, 'cross_site'])
    // DNS rebinding: страница злоумышленника под своим именем, указывающим на 127.0.0.1
    r = await call(st, { headers: { Host: `evil.example:${st.port}` } })
    assert.deepEqual([r.status, r.body.error.code], [403, 'bad_host'])
    r = await call(st, { method: 'POST', path: '/cgi-bin/api/rules', headers: { ...h, Host: `evil.example:${st.port}`, Origin: `https://evil.example:${st.port}` }, body: json })
    assert.equal(r.status, 403)
    assert.deepEqual(readFileSync(join(st.s.opts.stateDir, 'config.json')), before)
    // секреты входа лежат вне каталога панели
    assert.ok(!readdirSync(defaults().www, { recursive: true }).some((f) => String(f).includes('auth')))
  } finally {
    await st.s.close()
  }
})
