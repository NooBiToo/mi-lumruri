// Разбор конфигурации клиента TrustTunnel (client.toml или вывод `trusttunnel_endpoint … --format toml`), которую
// пользователь вставляет на экране «Сервер». Понимается подмножество TOML этих файлов: пары «ключ = значение»
// (строки всех четырёх видов, логические, числа, массивы строк) и таблицы; берутся ключи верхнего уровня и [endpoint].

import type { Endpoint } from './api'

export type ParsedServer = { endpoint: Partial<Endpoint>; password?: string } | { error: string }

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
  const pass = get('password')
  return typeof pass === 'string' && pass !== '' ? { endpoint, password: pass } : { endpoint }
}
