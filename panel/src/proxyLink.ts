// Сводка ссылки сервера модуля sing-box (vless://, hysteria2:// и hy2://, trojan://, ss://) для экрана «Сервер».
// Только то, что нужно показать и сохранить в настройках (протокол, адрес, порт, шифрование, транспорт, имя); полную
// проверку делает контроллер (controller/src/proxy.rs) при записи ссылки в секреты.

import type { ProfileKind, ProxyInfo } from './api'

export interface ProxySummary { kind: Exclude<ProfileKind, 'trusttunnel'>; info: ProxyInfo; name?: string }

const SCHEMES: Record<string, ProxySummary['kind']> = { vless: 'vless', hysteria2: 'hysteria2', hy2: 'hysteria2', trojan: 'trojan', ss: 'shadowsocks' }

export const PROTOCOL_LABEL: Record<ProxySummary['kind'], string> = { vless: 'VLESS', hysteria2: 'Hysteria2', trojan: 'Trojan', shadowsocks: 'Shadowsocks', amneziawg: 'AmneziaWG' }

/** Похоже на конфигурацию WireGuard/AmneziaWG (как controller/src/awg.rs). */
export function isAwgConf(text: string): boolean {
  return text.includes('[Interface]') && text.includes('[Peer]')
}

/** Сводка конфигурации AmneziaWG: сервер из Endpoint; ключи и параметры проверит контроллер. */
export function parseAwgConf(text: string): ProxySummary | { error: string } {
  const get = (k: string) => new RegExp(`^\\s*${k}\\s*=\\s*(.+?)\\s*$`, 'im').exec(text)?.[1]
  if (!get('PrivateKey')) return { error: 'в [Interface] нет PrivateKey' }
  if (!get('PublicKey')) return { error: 'в [Peer] нет PublicKey' }
  const ep = get('Endpoint')
  const hp = ep ? hostPort(ep) : null
  if (!hp) return { error: 'в [Peer] нет Endpoint адрес:порт' }
  return { kind: 'amneziawg', info: { ...hp, security: 'awg', transport: 'udp' } }
}

/** Это ссылка сервера модуля sing-box (по схеме). */
export function isProxyLink(text: string): boolean {
  const m = /^([a-z0-9]+):\/\//i.exec(text.trim())
  return !!m && m[1]!.toLowerCase() in SCHEMES
}

function dec(s: string): string {
  try { return decodeURIComponent(s) } catch { return s }
}

function b64(s: string): string | null {
  try {
    const t = s.replace(/-/g, '+').replace(/_/g, '/')
    return atob(t + '='.repeat((4 - (t.length % 4)) % 4))
  } catch { return null }
}

function hostPort(hp: string): { server: string; port: number } | null {
  const m = /^\[([0-9a-f:.]+)\]:(\d+)$/i.exec(hp) ?? /^([^:\[\]]+):(\d+)$/.exec(hp)
  if (!m) return null
  const port = Number(m[2])
  return port >= 1 && port <= 65535 ? { server: m[1]!, port } : null
}

/** Сводка или текст ошибки. */
export function parseProxyLink(text: string): ProxySummary | { error: string } {
  const link = text.trim()
  const m = /^([a-z0-9]+):\/\/(.*)$/is.exec(link)
  const kind = m ? SCHEMES[m[1]!.toLowerCase()] : undefined
  if (!m || !kind) return { error: 'это не ссылка VLESS, Hysteria2, Trojan или Shadowsocks' }
  let rest = m[2]!
  let name: string | undefined
  const hash = rest.indexOf('#')
  if (hash >= 0) { name = dec(rest.slice(hash + 1)).trim() || undefined; rest = rest.slice(0, hash) }
  const qi = rest.indexOf('?')
  const query = new URLSearchParams(qi >= 0 ? rest.slice(qi + 1) : '')
  let main = (qi >= 0 ? rest.slice(0, qi) : rest).replace(/\/+$/, '')
  if (kind === 'shadowsocks' && !main.includes('@')) main = b64(main) ?? main
  const at = main.lastIndexOf('@')
  if (at < 0) return { error: 'в ссылке нет учётных данных (часть до @)' }
  const hp = hostPort(main.slice(at + 1))
  if (!hp) return { error: 'в ссылке нет адреса и порта сервера' }
  const info: ProxyInfo = { ...hp }
  if (kind === 'vless' || kind === 'trojan') {
    const sec = (query.get('security') ?? (kind === 'trojan' ? 'tls' : 'none')).toLowerCase()
    info.security = sec === 'xtls' ? 'tls' : sec
    const ty = (query.get('type') ?? 'tcp').toLowerCase()
    info.transport = ty === 'raw' ? 'tcp' : ty === 'websocket' ? 'ws' : ty === 'h2' ? 'http' : ty
  } else if (kind === 'hysteria2') {
    info.security = 'tls'
    info.transport = 'quic'
  }
  return { kind, info, ...(name ? { name: name.slice(0, 64) } : {}) }
}
