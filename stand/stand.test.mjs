// Сквозная проверка стенда: HTTP → CGI → контроллер, плюс отдача собранной панели.
// Запуск: node --test stand/   (нужны controller/target/release/mi-tt-ctl[.exe] и panel/dist)

import { after, before, test } from 'node:test'
import assert from 'node:assert/strict'
import { request } from 'node:http'
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { readFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createStand, defaults } from './server.mjs'

const fx = (p) => join(defaults().seed, '..', p)
const STATE = mkdtempSync(join(tmpdir(), 'mitt-stand-'))
let stand
let base

before(async () => {
  stand = createStand({ stateDir: join(STATE, 'stage1') })
  base = `http://127.0.0.1:${await stand.listen(0)}`
})
after(async () => {
  await stand.close()
  rmSync(STATE, { recursive: true, force: true })
})

function raw(port, { method = 'GET', path = '/cgi-bin/api/config', headers = {}, body } = {}) {
  return new Promise((ok, fail) => {
    const r = request({ host: '127.0.0.1', port, method, path, headers }, (res) => {
      const chunks = []
      res.on('data', (c) => chunks.push(c))
      res.on('end', () => ok({ status: res.statusCode, body: JSON.parse(Buffer.concat(chunks).toString() || 'null') }))
    })
    r.on('error', fail)
    r.end(body)
  })
}

const post = (path, body, type = 'application/json') =>
  fetch(base + path, { method: 'POST', headers: { 'Content-Type': type }, body })

test('панель: index.html и все ассеты отдаются', async () => {
  const r = await fetch(base + '/')
  assert.equal(r.status, 200)
  const html = await r.text()
  const assets = [...html.matchAll(/(?:src|href)="\.\/(assets\/[^"]+)"/g)].map((m) => m[1])
  assert.ok(assets.length >= 2, html)
  for (const a of assets) assert.equal((await fetch(`${base}/${a}`)).status, 200, a)
})

test('статика: выход за каталог панели закрыт', async () => {
  for (const p of ['/../ARCHITECTURE.md', '/%2e%2e/ARCHITECTURE.md', '/assets/../../ARCHITECTURE.md', '/..%5cARCHITECTURE.md']) {
    assert.equal((await fetch(base + p)).status, 404, p)
  }
})

test('API: чтение настроек', async () => {
  const r = await fetch(base + '/cgi-bin/api/config')
  assert.equal(r.status, 200)
  assert.equal(r.headers.get('cache-control'), 'no-store')
  const b = await r.json()
  assert.equal(b.ok, true)
  assert.equal(b.config.devices.length, 2)
})

test('API: предпросмотр TrustTunnel для телевизора', async () => {
  const r = await post('/cgi-bin/api/preview', await readFile(fx('request.tv-video-trusttunnel.json')))
  assert.equal(r.status, 200)
  const { preview: p } = await r.json()
  assert.equal(p.applied, false)
  assert.equal(p.position, 1)
  assert.equal(p.probes[0].before.rule_id, 'r-home-video')
  assert.equal(p.probes[0].after.rule_id, 'r-tv-video')
  assert.equal(p.probes[1].changed, false)
})

test('API: ошибочный ввод', async () => {
  let r = await post('/cgi-bin/api/preview', await readFile(fx('invalid/request.unknown-refs.json')))
  assert.equal(r.status, 422)
  assert.deepEqual((await r.json()).issues.map((i) => i.code), ['unknown_device', 'unknown_group', 'unknown_profile'])
  r = await post('/cgi-bin/api/preview', '{"rule":')
  assert.equal(r.status, 400)
  r = await post('/cgi-bin/api/preview', '{}', 'text/plain')
  assert.equal(r.status, 415)
  r = await post('/cgi-bin/api/preview', JSON.stringify({ pad: 'x'.repeat(70 * 1024) }))
  assert.equal(r.status, 413)
  r = await post('/cgi-bin/api/apply', '{}')
  assert.equal(r.status, 404)
  r = await fetch(base + '/cgi-bin/api/config', { method: 'DELETE' })
  assert.equal(r.status, 405)
})

test('API: недоступный контроллер даёт 502, а не падение стенда', async () => {
  const broken = createStand({ stateDir: join(STATE, 'broken'), bin: join(defaults().bin, '..', 'no-such-binary') })
  const port = await broken.listen(0)
  try {
    const r = await fetch(`http://127.0.0.1:${port}/cgi-bin/api/config`)
    assert.equal(r.status, 502)
    assert.equal((await r.json()).error.code, 'cgi_failed')
  } finally {
    await broken.close()
  }
})

// ---------- этап 2: запись через стенд ----------

const labSeed = fx('lab/config.json')
const rule = { id: 'r-tv-video', source: { type: 'device', id: 'tv' }, destination: { type: 'group', id: 'video' }, action: { type: 'profile', id: 'tt-lab' } }

test('запись: сохранение с origin панели, повторное чтение после перезапуска стенда', async () => {
  const dir = join(STATE, 'save')
  let s = createStand({ stateDir: dir, seed: labSeed })
  let port = await s.listen(0)
  const origin = `http://127.0.0.1:${port}`
  const cfg = await (await fetch(`${origin}/cgi-bin/api/config`)).json()
  assert.equal(cfg.config.rules.length, 0)
  const r = await fetch(`${origin}/cgi-bin/api/rules`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Origin: origin },
    body: JSON.stringify({ base_revision: cfg.revision, rule }),
  })
  assert.equal(r.status, 200)
  const saved = await r.json()
  assert.equal(saved.mode, 'add')
  // повтор на старой ревизии — конфликт
  const again = await fetch(`${origin}/cgi-bin/api/rules`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Origin: origin },
    body: JSON.stringify({ base_revision: cfg.revision, rule: { ...rule, id: 'r-2' } }),
  })
  assert.equal(again.status, 409)
  assert.equal((await again.json()).error.code, 'revision_conflict')
  await s.close()
  // новый процесс стенда на том же каталоге: исходник не перезаписывает сохранённое
  s = createStand({ stateDir: dir, seed: labSeed })
  port = await s.listen(0)
  const reread = await (await fetch(`http://localhost:${port}/cgi-bin/api/config`)).json()
  assert.equal(reread.revision, saved.revision)
  assert.deepEqual(reread.config.rules.map((x) => x.id), ['r-tv-video'])
  assert.equal(JSON.parse(readFileSync(join(dir, 'config.json'), 'utf8')).rules.length, 1)
  await s.close()
  assert.equal(JSON.parse(readFileSync(labSeed, 'utf8')).rules.length, 0, 'фикстура не изменилась')
})

test('запись: чужой origin, отсутствие Origin и чужой Host отклоняются, файл не меняется', async () => {
  const dir = join(STATE, 'deny')
  const s = createStand({ stateDir: dir, seed: labSeed })
  const port = await s.listen(0)
  const before = readFileSync(join(dir, 'config.json'))
  const cfg = await (await fetch(`http://127.0.0.1:${port}/cgi-bin/api/config`)).json()
  const body = JSON.stringify({ base_revision: cfg.revision, rule })
  const json = { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) }
  let r = await raw(port, { method: 'POST', path: '/cgi-bin/api/rules', headers: { ...json, Origin: 'http://evil.example' }, body })
  assert.deepEqual([r.status, r.body.error.code], [403, 'origin_forbidden'])
  r = await raw(port, { method: 'POST', path: '/cgi-bin/api/rules', headers: json, body })
  assert.deepEqual([r.status, r.body.error.code], [403, 'origin_required'])
  r = await raw(port, { method: 'POST', path: '/cgi-bin/api/rules', headers: { ...json, Origin: `http://127.0.0.1:${port}`, 'Sec-Fetch-Site': 'cross-site' }, body })
  assert.deepEqual([r.status, r.body.error.code], [403, 'cross_site'])
  // DNS rebinding: страница злоумышленника под своим именем, указывающим на 127.0.0.1
  r = await raw(port, { headers: { Host: `evil.example:${port}` } })
  assert.deepEqual([r.status, r.body.error.code], [403, 'bad_host'])
  r = await raw(port, { method: 'POST', path: '/cgi-bin/api/rules', headers: { ...json, Host: `evil.example:${port}`, Origin: `http://evil.example:${port}` }, body })
  assert.equal(r.status, 403)
  assert.deepEqual(readFileSync(join(dir, 'config.json')), before)
  await s.close()
})
