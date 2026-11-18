// Локальный стенд вместо uhttpd: раздаёт собранную панель и вызывает контроллер как CGI
// (переменные окружения + тело в stdin, ответ с заголовком Status). Слушает только 127.0.0.1.
// Это имитация для проверки цепочки панель → CGI → контроллер, а не сервер для роутера.
// Аутентификации пока нет, поэтому: только loopback; запросы с чужим Host отклоняются (защита от DNS rebinding);
// Origin/Sec-Fetch-Site передаются контроллеру, который допускает запись только с origin самой панели.
// Настройки живут в каталоге состояния (по умолчанию out/stand-state/<имя исходного файла>), фикстуры не меняются.

import { spawn } from 'node:child_process'
import { createServer } from 'node:http'
import { copyFileSync, existsSync, mkdirSync } from 'node:fs'
import { readFile, stat } from 'node:fs/promises'
import { basename, extname, join, resolve, sep } from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = resolve(fileURLToPath(new URL('..', import.meta.url)))
const API_PREFIX = '/cgi-bin/api'
const MAX_FORWARD_BODY = 1024 * 1024 // стенд не буферизует больше; лимит 64 КиБ проверяет сам контроллер
const CGI_TIMEOUT_MS = 5000
const TYPES = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.svg': 'image/svg+xml', '.ico': 'image/x-icon' }

export function defaults() {
  const exe = process.platform === 'win32' ? 'mi-tt-ctl.exe' : 'mi-tt-ctl'
  return {
    host: '127.0.0.1',
    port: 8787,
    seed: join(ROOT, 'fixtures', 'config.valid.json'),
    stateDir: null,
    bin: join(ROOT, 'controller', 'target', 'release', exe),
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
    }
    for (const h of ['origin', 'host', 'sec-fetch-site']) {
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
    res.writeHead(200, { 'Content-Type': TYPES[extname(file)] ?? 'application/octet-stream', 'Content-Length': data.length, 'X-Content-Type-Options': 'nosniff' })
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
  return { ...opts, stateDir: dir, config }
}

export function createStand(overrides = {}) {
  const opts = prepareState({ ...defaults(), ...Object.fromEntries(Object.entries(overrides).filter(([, v]) => v !== undefined)) })
  opts.allowedOrigins = []
  let allowedHosts = []
  const server = createServer(async (req, res) => {
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
        res.writeHead(parsed.status, parsed.headers)
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
    listen: (port = opts.port) =>
      new Promise((ok) =>
        server.listen(port, opts.host, () => {
          const p = server.address().port
          allowedHosts = [`127.0.0.1:${p}`, `localhost:${p}`]
          opts.allowedOrigins = allowedHosts.map((h) => `http://${h}`)
          ok(p)
        }),
      ),
    close: () => new Promise((ok) => server.close(ok)),
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = Object.fromEntries(process.argv.slice(2).map((a) => a.replace(/^--/, '').split('=')))
  if (args.port) args.port = Number(args.port)
  if (args.config) { args.seed = args.config; delete args.config } // совместимость с этапом 1: файл — исходник, не цель записи
  if (args['state-dir']) { args.stateDir = args['state-dir']; delete args['state-dir'] }
  if ('reset' in args) args.reset = true
  const stand = createStand(args)
  const port = await stand.listen()
  console.log(`стенд: http://127.0.0.1:${port}/  (настройки=${stand.opts.config}, исходник=${stand.opts.seed}, bin=${stand.opts.bin})`)
}
