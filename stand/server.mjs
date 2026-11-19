// Локальный стенд вместо uhttpd: раздаёт собранную панель и вызывает контроллер как CGI
// (переменные окружения + тело в stdin, ответ с заголовком Status). Слушает только 127.0.0.1.
// Это имитация для проверки цепочки панель → CGI → контроллер, а не сервер для роутера.
// Только HTTPS (как uhttpd с TLS на роутере): если сертификат не задан, стенд создаёт временный самоподписанный
// для 127.0.0.1/localhost (openssl) во временном каталоге и удаляет его при закрытии. Слушает только loopback;
// запросы с чужим Host отклоняются (DNS rebinding). Вход (пароль + TOTP), Origin, CSRF и cookie проверяет контроллер.
// Настройки живут в каталоге состояния (по умолчанию out/stand-state/<имя исходного файла>), фикстуры не меняются;
// там же auth/ (настройки входа, создаёт `mi-tt-admin auth init`) и sessions/ (сессии).

import { execFileSync, spawn } from 'node:child_process'
import { createServer } from 'node:https'
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { readFile, stat } from 'node:fs/promises'
import { basename, extname, join, resolve, sep } from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = resolve(fileURLToPath(new URL('..', import.meta.url)))
const API_PREFIX = '/cgi-bin/api'
const MAX_FORWARD_BODY = 1024 * 1024 // стенд не буферизует больше; лимит 64 КиБ проверяет сам контроллер
const CGI_TIMEOUT_MS = 5000
const SECURITY_HEADERS = {
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Content-Security-Policy': "default-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
  'Referrer-Policy': 'no-referrer',
  'Strict-Transport-Security': 'max-age=31536000',
}
const TYPES = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.svg': 'image/svg+xml', '.ico': 'image/x-icon', '.woff2': 'font/woff2' }

export function defaults() {
  const exe = process.platform === 'win32' ? 'mi-tt-ctl.exe' : 'mi-tt-ctl'
  const adm = process.platform === 'win32' ? 'mi-tt-admin.exe' : 'mi-tt-admin'
  return {
    host: '127.0.0.1',
    port: 8787,
    seed: join(ROOT, 'fixtures', 'config.valid.json'),
    stateDir: null,
    bin: join(ROOT, 'controller', 'target', 'release', exe),
    admin: join(ROOT, 'controller', 'target', 'release', adm),
    www: join(ROOT, 'panel', 'dist'),
  }
}

function runCgi(opts, req, body) {
  return new Promise((done) => {
    const url = new URL(req.url, 'http://stand')
    const env = {
      GATEWAY_INTERFACE: 'CGI/1.1',
      SERVER_PROTOCOL: 'HTTP/1.1',
      REQUEST_METHOD: req.method,
      PATH_INFO: url.pathname.slice(API_PREFIX.length) || '/',
      QUERY_STRING: url.search.slice(1),
      MI_TT_CONFIG: opts.config,
      MI_TT_ALLOWED_ORIGINS: opts.allowedOrigins.join(','),
      MI_TT_AUTH_DIR: opts.authDir,
      MI_TT_SESSION_DIR: opts.sessionDir,
      MI_TT_RUN_DIR: join(opts.stateDir, 'run'),
      HTTPS: 'on',
    }
    if (opts.leases) env.MI_TT_LEASES = opts.leases
    for (const h of ['origin', 'host', 'sec-fetch-site', 'cookie', 'x-mitt-csrf']) {
      if (req.headers[h]) env['HTTP_' + h.toUpperCase().replace(/-/g, '_')] = String(req.headers[h])
    }
    if (body) env.CONTENT_LENGTH = String(body.length)
    if (req.headers['content-type']) env.CONTENT_TYPE = req.headers['content-type']
    if (process.platform === 'win32' && process.env.SystemRoot) env.SystemRoot = process.env.SystemRoot
    const child = spawn(opts.bin, ['cgi'], { env, stdio: ['pipe', 'pipe', 'ignore'], windowsHide: true })
    const out = []
    const timer = setTimeout(() => child.kill(), CGI_TIMEOUT_MS)
    child.stdout.on('data', (c) => out.push(c))
    child.on('error', (e) => { clearTimeout(timer); done({ error: e.message }) })
    child.on('close', (code) => { clearTimeout(timer); done({ code, raw: Buffer.concat(out) }) })
    child.stdin.on('error', () => {})
    child.stdin.end(body ?? undefined)
  })
}

function parseCgi(raw) {
  const sepAt = raw.indexOf('\r\n\r\n')
  if (sepAt < 0) return null
  const headers = {}
  let status = 200
  for (const line of raw.subarray(0, sepAt).toString('latin1').split('\r\n')) {
    const i = line.indexOf(':')
    if (i < 0) continue
    const k = line.slice(0, i).trim()
    const v = line.slice(i + 1).trim()
    if (k.toLowerCase() === 'status') status = Number.parseInt(v, 10)
    else if (k.toLowerCase() === 'set-cookie') (headers['Set-Cookie'] ??= []).push(v)
    else headers[k] = v
  }
  return { status, headers, body: raw.subarray(sepAt + 4) }
}

function sendJson(res, status, obj) {
  const b = Buffer.from(JSON.stringify(obj))
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Content-Length': b.length, 'Cache-Control': 'no-store' })
  res.end(b)
}

async function readBody(req) {
  const chunks = []
  let n = 0
  for await (const c of req) {
    n += c.length
    if (n > MAX_FORWARD_BODY) return { tooLarge: true }
    chunks.push(c)
  }
  return { body: Buffer.concat(chunks) }
}

async function serveStatic(opts, req, res) {
  const url = new URL(req.url, 'http://stand')
  let rel
  try { rel = decodeURIComponent(url.pathname) } catch { rel = '' }
  if (rel.endsWith('/')) rel += 'index.html'
  const www = resolve(opts.www)
  const file = resolve(www, '.' + rel)
  if (!rel || rel.includes('\0') || (file !== www && !file.startsWith(www + sep))) return sendJson(res, 404, { ok: false })
  try {
    if (!(await stat(file)).isFile()) throw new Error('not a file')
    const data = await readFile(file)
    res.writeHead(200, { 'Content-Type': TYPES[extname(file)] ?? 'application/octet-stream', 'Content-Length': data.length, ...SECURITY_HEADERS })
    res.end(req.method === 'HEAD' ? undefined : data)
  } catch {
    sendJson(res, 404, { ok: false, error: { code: 'not_found', message: 'файл не найден' } })
  }
}

function prepareState(opts) {
  const seed = resolve(opts.seed)
  const dir = resolve(opts.stateDir ?? join(ROOT, 'out', 'stand-state', basename(seed, extname(seed))))
  mkdirSync(dir, { recursive: true })
  const config = join(dir, 'config.json')
  if (opts.reset || !existsSync(config)) copyFileSync(seed, config)
  return { ...opts, stateDir: dir, config, authDir: join(dir, 'auth'), sessionDir: join(dir, 'sessions') }
}

/** Временный самоподписанный сертификат для 127.0.0.1 и localhost (сутки), ключ — во временном каталоге. */
export function tempCert() {
  const dir = mkdtempSync(join(tmpdir(), 'mitt-tls-'))
  const key = join(dir, 'key.pem')
  const cert = join(dir, 'cert.pem')
  execFileSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-days', '1',
    '-subj', '/CN=mi-trusttunnel-stand', '-addext', 'subjectAltName=IP:127.0.0.1,DNS:localhost',
    '-keyout', key, '-out', cert], { stdio: 'ignore', env: { ...process.env, MSYS_NO_PATHCONV: '1', MSYS2_ARG_CONV_EXCL: '*' } })
  return { key: readFileSync(key), cert: readFileSync(cert), certFile: cert, cleanup: () => rmSync(dir, { recursive: true, force: true }) }
}

export function createStand(overrides = {}) {
  const opts = prepareState({ ...defaults(), ...Object.fromEntries(Object.entries(overrides).filter(([, v]) => v !== undefined)) })
  opts.allowedOrigins = []
  let allowedHosts = []
  const tls = opts.tlsKey && opts.tlsCert ? { key: readFileSync(opts.tlsKey), cert: readFileSync(opts.tlsCert), certFile: opts.tlsCert, cleanup: () => {} } : tempCert()
  const server = createServer({ key: tls.key, cert: tls.cert, minVersion: 'TLSv1.2' }, async (req, res) => {
    try {
      if (!allowedHosts.includes(String(req.headers.host ?? '').toLowerCase())) {
        return sendJson(res, 403, { ok: false, error: { code: 'bad_host', message: 'стенд отвечает только на 127.0.0.1 и localhost' }, issues: [] })
      }
      const path = new URL(req.url, 'http://stand').pathname
      if (path === API_PREFIX || path.startsWith(API_PREFIX + '/')) {
        let body = null
        if (req.method === 'POST' || req.method === 'PUT') {
          const r = await readBody(req)
          if (r.tooLarge) return sendJson(res, 413, { ok: false, error: { code: 'too_large', message: 'тело запроса слишком большое' }, issues: [] })
          body = r.body
        }
        const r = await runCgi(opts, req, body)
        const parsed = r.raw && parseCgi(r.raw)
        if (!parsed) return sendJson(res, 502, { ok: false, error: { code: 'cgi_failed', message: r.error ?? `контроллер завершился с кодом ${r.code}` }, issues: [] })
        res.writeHead(parsed.status, { ...parsed.headers, 'Strict-Transport-Security': SECURITY_HEADERS['Strict-Transport-Security'] })
        return res.end(parsed.body)
      }
      if (req.method !== 'GET' && req.method !== 'HEAD') return sendJson(res, 405, { ok: false })
      return serveStatic(opts, req, res)
    } catch (e) {
      sendJson(res, 500, { ok: false, error: { code: 'stand', message: String(e) } })
    }
  })
  return {
    opts,
    server,
    ca: tls.cert,
    certFile: tls.certFile,
    listen: (port = opts.port) =>
      new Promise((ok) =>
        server.listen(port, opts.host, () => {
          const p = server.address().port
          allowedHosts = [`127.0.0.1:${p}`, `localhost:${p}`]
          opts.allowedOrigins = allowedHosts.map((h) => `https://${h}`)
          ok(p)
        }),
      ),
    close: () => new Promise((ok) => { server.closeAllConnections?.(); server.close(() => { tls.cleanup(); ok() }) }),
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = Object.fromEntries(process.argv.slice(2).map((a) => a.replace(/^--/, '').split('=')))
  if (args.port) args.port = Number(args.port)
  if (args.config) { args.seed = args.config; delete args.config } // совместимость с этапом 1: файл — исходник, не цель записи
  if (args['state-dir']) { args.stateDir = args['state-dir']; delete args['state-dir'] }
  if ('reset' in args) args.reset = true
  if (args.cert) { args.tlsCert = args.cert; args.tlsKey = args.key; delete args.cert; delete args.key }
  const stand = createStand(args)
  const port = await stand.listen()
  console.log(`стенд: https://127.0.0.1:${port}/  (сертификат=${stand.certFile}, настройки=${stand.opts.config}, вход=${stand.opts.authDir}, bin=${stand.opts.bin})`)
  if (!existsSync(join(stand.opts.authDir, 'auth.json'))) {
    console.log(`вход не настроен: MI_TT_AUTH_DIR=${stand.opts.authDir} MI_TT_SESSION_DIR=${stand.opts.sessionDir} ${stand.opts.admin} auth init`)
  }
  const stop = () => stand.close().then(() => process.exit(0))
  process.on('SIGINT', stop)
  process.on('SIGTERM', stop)
}
