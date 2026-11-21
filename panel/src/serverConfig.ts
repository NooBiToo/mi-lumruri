// Разбор конфигурации клиента TrustTunnel, которую пользователь вставляет на экране «Сервер»: ссылка `tt://?…`
// (вывод `trusttunnel_endpoint … -c <клиент>` по умолчанию, формат — DEEP_LINK.md TrustTunnel) или client.toml
// (вывод с `--format toml`). Из TOML понимается подмножество этих файлов: пары «ключ = значение» (строки всех четырёх
// видов, логические, числа, массивы строк) и таблицы; берутся ключи верхнего уровня и [endpoint].

import type { Endpoint, TlsProfile } from './api'

/** Отпечатки TLS в порядке тега 0x10 ссылки tt:// (DEEP_LINK.md: 0x00 = chrome … 0x06 = boringssl). */
export const TLS_PROFILES: TlsProfile[] = ['chrome', 'chrome_canary', 'safari', 'firefox', 'okhttp', 'openssl', 'boringssl']

/** Профиль TLS из client.toml: `default` — устаревшее имя boringssl; chrome (по умолчанию) не записывается. */
function tlsProfileOf(v: string): TlsProfile | 'bad' | undefined {
  const p = v.toLowerCase() === 'default' ? 'boringssl' : v.toLowerCase()
  if (!(TLS_PROFILES as string[]).includes(p)) return 'bad'
  return p === 'chrome' ? undefined : (p as TlsProfile)
}

/** client_random и ключ: пустые не пишутся; если заданы оба, клиент берёт ключ — так же поступаем и мы. */
function clientRandom(endpoint: Partial<Endpoint>, prefix: string | undefined, key: string | undefined): void {
  if (key) endpoint.client_random_auth_key = key
  else if (prefix) endpoint.client_random = prefix
}

/**
 * Поля точки подключения, пароль, имя сервера (`name`) и предупреждения о параметрах, которые роутер не поддерживает
 * (другое имя в TLS, отключённая проверка сертификата).
 */
export type ParsedServer = { endpoint: Partial<Endpoint>; password?: string; name?: string; warnings?: string[]; subscription?: string } | { error: string }

type Value = string | number | boolean | Value[]

class TomlError extends Error {}

const ESCAPES: Record<string, string> = { b: '\b', t: '\t', n: '\n', f: '\f', r: '\r', '"': '"', '\\': '\\' }

/** Разбор значения с позиции `i`; возвращает значение и позицию за ним. */
function value(t: string, i: number): [Value, number] {
  const multi = (q: string): [string, number] => {
    const end = t.indexOf(q, i + 3)
    if (end < 0) throw new TomlError('не закрыта многострочная строка')
    let s = t.slice(i + 3, end)
    if (s.startsWith('\r\n')) s = s.slice(2)
    else if (s.startsWith('\n')) s = s.slice(1)
    return [q === '"""' ? unescape(s) : s, end + 3]
  }
  if (t.startsWith("'''", i)) return multi("'''")
  if (t.startsWith('"""', i)) return multi('"""')
  const c = t[i]
  if (c === "'") {
    const end = t.indexOf("'", i + 1)
    if (end < 0 || t.slice(i + 1, end).includes('\n')) throw new TomlError('не закрыта строка')
    return [t.slice(i + 1, end), end + 1]
  }
  if (c === '"') {
    let j = i + 1
    while (j < t.length && t[j] !== '"' && t[j] !== '\n') j += t[j] === '\\' ? 2 : 1
    if (t[j] !== '"') throw new TomlError('не закрыта строка')
    return [unescape(t.slice(i + 1, j)), j + 1]
  }
  if (c === '[') {
    const arr: Value[] = []
    let j = skip(t, i + 1, true)
    while (t[j] !== ']') {
      const [v, k] = value(t, j)
      arr.push(v)
      j = skip(t, k, true)
      if (t[j] === ',') j = skip(t, j + 1, true)
      else if (t[j] !== ']') throw new TomlError('ожидалась «,» или «]» в массиве')
    }
    return [arr, j + 1]
  }
  const m = /^(true|false|[+-]?\d[\d_]*)(?=[\s,\]#]|$)/.exec(t.slice(i))
  if (!m || !m[1]) throw new TomlError('значение не распознано')
  const v = m[1] === 'true' ? true : m[1] === 'false' ? false : Number(m[1].replace(/_/g, ''))
  return [v, i + m[1].length]
}

function unescape(s: string): string {
  return s.replace(/\\(u[0-9a-fA-F]{4}|U[0-9a-fA-F]{8}|.)/gs, (all, e: string) => {
    if (e.length > 1) return String.fromCodePoint(parseInt(e.slice(1), 16))
    const r = ESCAPES[e]
    if (r === undefined) throw new TomlError(`неизвестная последовательность ${all}`)
    return r
  })
}

/** Пропуск пробелов (и переводов строк с комментариями — внутри массивов). */
function skip(t: string, i: number, newlines: boolean): number {
  for (;;) {
    while (i < t.length && (t[i] === ' ' || t[i] === '\t' || (newlines && (t[i] === '\n' || t[i] === '\r')))) i++
    if (newlines && t[i] === '#') {
      while (i < t.length && t[i] !== '\n') i++
      continue
    }
    return i
  }
}

/** Ключи верхнего уровня и таблиц: `{ '': {...}, endpoint: {...} }`. */
function parseToml(text: string): Map<string, Map<string, Value>> {
  const t = text.replace(/^﻿/, '')
  const tables = new Map<string, Map<string, Value>>([['', new Map()]])
  let table = tables.get('')!
  let i = 0
  while (i < t.length) {
    i = skip(t, i, true)
    if (i >= t.length) break
    const header = /^\[\[?\s*([A-Za-z0-9_.-]+)\s*\]\]?/.exec(t.slice(i))
    if (header?.[1]) {
      const name = header[1]
      if (!tables.has(name)) tables.set(name, new Map())
      table = tables.get(name)!
      i += header[0].length
    } else {
      const kv = /^([A-Za-z0-9_-]+)[ \t]*=[ \t]*/.exec(t.slice(i))
      if (!kv?.[1]) throw new TomlError('ожидалась строка вида «ключ = значение»')
      const [v, j] = value(t, i + kv[0].length)
      table.set(kv[1], v)
      i = j
    }
    i = skip(t, i, false)
    if (t[i] === '#') while (i < t.length && t[i] !== '\n') i++
    if (i < t.length && t[i] !== '\n' && t[i] !== '\r') throw new TomlError('лишние символы в конце строки')
  }
  return tables
}

/** «IP:порт» или «[IPv6]:порт». */
function splitAddress(a: string): { server: string; port: number } | null {
  const m = /^\[([0-9A-Fa-f:.]+)\]:(\d{1,5})$/.exec(a) ?? /^([^:\s]+):(\d{1,5})$/.exec(a)
  if (!m?.[1] || !m[2]) return null
  const port = Number(m[2])
  return port >= 1 && port <= 65535 ? { server: m[1], port } : null
}

const NOT_CLIENT = 'это не похоже на конфигурацию клиента TrustTunnel: нужны addresses и hostname'

/**
 * Поля точки подключения из конфигурации клиента. Имя сервера — `hostname` (по нему проверяется сертификат),
 * `custom_sni` — только если `hostname` нет. Значения не проверяются: это сделает контроллер при сохранении.
 */
export function parseClientToml(text: string): ParsedServer {
  let tables: Map<string, Map<string, Value>>
  try {
    tables = parseToml(text)
  } catch (e) {
    return { error: e instanceof TomlError ? `не удалось разобрать конфигурацию: ${e.message}` : NOT_CLIENT }
  }
  const ep = tables.get('endpoint')
  const get = (k: string): Value | undefined => ep?.get(k) ?? tables.get('')!.get(k)
  const str = (k: string): string | undefined => {
    const v = get(k)
    return typeof v === 'string' && v.trim() !== '' ? v.trim() : undefined
  }
  const addresses = get('addresses')
  const first = Array.isArray(addresses) ? addresses[0] : typeof addresses === 'string' ? addresses : undefined
  const host = str('hostname') ?? str('custom_sni')
  if (typeof first !== 'string' || !host) return { error: NOT_CLIENT }
  const addr = splitAddress(first.trim())
  if (!addr) return { error: `адрес сервера «${first}» ожидается в виде IP:порт` }

  const endpoint: Partial<Endpoint> = { server: addr.server, port: addr.port, sni: host }
  const user = str('username')
  if (user !== undefined) endpoint.username = user
  const proto = str('upstream_protocol')
  if (proto !== undefined) endpoint.quic = proto.toLowerCase() === 'http3'
  const anti = get('anti_dpi')
  if (typeof anti === 'boolean') endpoint.anti_dpi = anti
  const cert = str('certificate')
  if (cert !== undefined) endpoint.certificate = cert
  const tls = str('tls_profile')
  if (tls !== undefined) {
    const p = tlsProfileOf(tls)
    if (p === 'bad') return { error: `профиль TLS «${tls}» неизвестен (tls_profile)` }
    if (p) endpoint.tls_profile = p
  }
  clientRandom(endpoint, str('client_random'), str('client_random_auth_key'))
  const pass = get('password')
  return finish(endpoint, typeof pass === 'string' ? pass : undefined, str('name'), unsupported(host, str('custom_sni'), get('skip_verification') === true), str('subscription_url'))
}

/** Параметры, которые клиент роутера не поддерживает: пользователь должен знать, что они не перенесены. */
function unsupported(host: string, customSni: string | undefined, skipVerification: boolean): string[] {
  const w: string[] = []
  if (customSni && customSni !== host) {
    w.push(`сервер задаёт для TLS другое имя («${customSni}», custom_sni) — роутер так не умеет и подключается по имени «${host}»`)
  }
  if (skipVerification) w.push('в конфигурации отключена проверка сертификата (skip_verification) — роутер всегда проверяет сертификат сервера')
  return w
}

function finish(endpoint: Partial<Endpoint>, password: string | undefined, name: string | undefined, warnings: string[], subscription?: string): ParsedServer {
  const out: { endpoint: Partial<Endpoint>; password?: string; name?: string; warnings?: string[]; subscription?: string } = { endpoint }
  if (subscription && /^https:\/\/\S+$/.test(subscription)) out.subscription = subscription
  if (password) out.password = password
  if (name) out.name = name
  if (warnings.length) out.warnings = warnings
  return out
}

// ---------- ссылка tt://? ----------

const NOT_LINK = 'ссылка tt:// повреждена — проверьте, что она скопирована целиком'

/** DER-сертификаты подряд → PEM; длина каждого — из заголовка SEQUENCE. */
function derToPem(der: Uint8Array): string | null {
  const out: string[] = []
  let i = 0
  while (i < der.length) {
    if (der[i] !== 0x30) return null
    let len = der[i + 1] ?? 0
    let head = 2
    if (len & 0x80) {
      const n = len & 0x7f
      if (n < 1 || n > 3) return null
      len = 0
      for (let k = 0; k < n; k++) len = len * 256 + (der[i + 2 + k] ?? 0)
      head += n
    }
    const end = i + head + len
    if (end > der.length) return null
    let bin = ''
    for (const b of der.subarray(i, end)) bin += String.fromCharCode(b)
    const lines = btoa(bin).match(/.{1,64}/g) ?? []
    out.push(['-----BEGIN CERTIFICATE-----', ...lines, '-----END CERTIFICATE-----'].join('\n'))
    i = end
  }
  return out.length ? out.join('\n') : null
}

class LinkError extends Error {}

/** Ссылка `tt://?<base64url>`: записи «тег — длина — значение», тег и длина — varint QUIC (RFC 9000 §16). */
export function parseDeepLink(link: string): ParsedServer {
  const m = /^tt:\/\/\??([A-Za-z0-9_-]+)=*$/.exec(link.trim())
  if (!m?.[1]) return { error: NOT_LINK }
  let bytes: Uint8Array
  try {
    bytes = Uint8Array.from(atob(m[1].replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0))
  } catch {
    return { error: NOT_LINK }
  }
  let i = 0
  const varint = (): number => {
    const f = bytes[i]
    if (f === undefined) throw new LinkError()
    const n = 1 << (f >> 6)
    if (n > 4 || i + n > bytes.length) throw new LinkError()
    let v = f & 0x3f
    for (let k = 1; k < n; k++) v = v * 256 + bytes[i + k]!
    i += n
    return v
  }
  const utf8 = new TextDecoder('utf-8', { fatal: true })
  const fields = new Map<number, Uint8Array>()
  const addresses: string[] = []
  try {
    while (i < bytes.length) {
      const tag = varint()
      const len = varint()
      if (i + len > bytes.length) throw new LinkError()
      const v = bytes.subarray(i, i + len)
      i += len
      if (tag === 0x02) addresses.push(utf8.decode(v))
      else fields.set(tag, v) // повтор тега — побеждает последний (DEEP_LINK.md)
    }
  } catch {
    return { error: NOT_LINK }
  }
  const text = (tag: number): string | undefined => {
    const v = fields.get(tag)
    try {
      const s = v ? utf8.decode(v).trim() : ''
      return s === '' ? undefined : s
    } catch {
      return undefined
    }
  }
  const flag = (tag: number): boolean => fields.get(tag)?.[0] === 1
  const host = text(0x01)
  const first = addresses[0]?.trim()
  const sub = text(0x0e)
  // ссылка только с подпиской: параметры сервера роутер получит по ней сам
  if (sub && (!host || !first)) {
    if (!/^https:\/\/\S+$/.test(sub)) return { error: 'ссылка-подписка в tt:// должна начинаться с https://' }
    return finish({}, undefined, text(0x0c), [], sub)
  }
  if (!host || !first) return { error: NOT_LINK }
  const addr = splitAddress(first)
  if (!addr) return { error: `адрес сервера «${first}» ожидается в виде IP:порт` }

  const endpoint: Partial<Endpoint> = { server: addr.server, port: addr.port, sni: host, quic: fields.get(0x09)?.[0] === 2, anti_dpi: flag(0x0a) }
  const user = text(0x05)
  if (user !== undefined) endpoint.username = user
  const der = fields.get(0x08)
  if (der?.length) {
    const pem = derToPem(der)
    if (!pem) return { error: 'сертификат в ссылке tt:// повреждён' }
    endpoint.certificate = pem
  }
  // 0x10 — один байт, номер профиля; неизвестный номер ссылка не должна молча терять (DEEP_LINK.md: «MUST reject»)
  const tls = fields.get(0x10)
  if (tls) {
    const p = tls.length === 1 ? TLS_PROFILES[tls[0]!] : undefined
    if (!p) return { error: 'профиль TLS в ссылке tt:// неизвестен — обновите панель роутера' }
    if (p !== 'chrome') endpoint.tls_profile = p
  }
  clientRandom(endpoint, text(0x0b), text(0x0f))
  let pass: string | undefined
  try {
    pass = fields.has(0x06) ? utf8.decode(fields.get(0x06)!) : undefined
  } catch {
    return { error: NOT_LINK }
  }
  return finish(endpoint, pass, text(0x0c), unsupported(host, text(0x03), flag(0x07)), sub)
}

/** Вставленный текст: ссылка `tt://` или client.toml. */
export function parseServer(text: string): ParsedServer {
  return /^\s*tt:\/\//.test(text) ? parseDeepLink(text) : parseClientToml(text)
}
