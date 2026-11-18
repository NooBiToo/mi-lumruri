// Логика экранов управления без DOM: форма профиля ↔ Profile, разбор строк ввода, описание правил.

import type { Device, Lease, Network, Action, Config, Destination, DnsConfig, Profile, ProfileKind, ProfileSecret, Rule } from './api'

export interface ProfileForm {
  id: string
  name: string
  kind: ProfileKind
  onFailure: 'block' | 'direct'
  server: string
  port: string
  sni: string
  certSha256: string
  username: string
  quic: boolean
  obfs: boolean
  security: 'tls' | 'reality'
  vision: boolean
  realityKey: string
  realityShortId: string
  publicKey: string
  address: string
  mtu: string
  awg: boolean
  awgText: string
  // секреты: только ввод, наружу не отображаются
  secret1: string
  secret2: string
}

export function emptyProfileForm(kind: ProfileKind = 'hysteria2'): ProfileForm {
  return {
    id: '', name: '', kind, onFailure: 'block', server: '', port: kind === 'wireguard' ? '51820' : '443', sni: '', certSha256: '', username: '',
    quic: false, obfs: false, security: 'tls', vision: true, realityKey: '', realityShortId: '', publicKey: '', address: '', mtu: '', awg: false,
    awgText: 'jc=4 jmin=40 jmax=70 s1=37 s2=61 h1=1361409513 h2=2016328541 h3=726101713 h4=1919296617', secret1: '', secret2: '',
  }
}

export function profileToForm(p: Profile): ProfileForm {
  const f = emptyProfileForm(p.kind)
  const e = p.endpoint
  Object.assign(f, { id: p.id, name: p.name, onFailure: p.on_failure })
  if (!e) return f
  Object.assign(f, {
    server: e.server, port: String(e.port), sni: e.sni ?? '', certSha256: e.cert_sha256 ?? '', username: e.username ?? '', quic: !!e.quic,
    obfs: e.obfs === 'salamander', security: e.security ?? 'tls', vision: e.flow === 'xtls-rprx-vision', realityKey: e.reality?.public_key ?? '',
    realityShortId: e.reality?.short_id ?? '', publicKey: e.public_key ?? '', address: e.address ?? '', mtu: e.mtu ? String(e.mtu) : '', awg: !!e.awg,
  })
  if (e.awg) f.awgText = Object.entries(e.awg).map(([k, v]) => `${k}=${v}`).join(' ')
  return f
}

/** «jc=4 jmin=40 …» → объект; неизвестные ключи и нечисла — ошибка. */
export function parseAwg(text: string): Record<string, number> | string {
  const keys = ['jc', 'jmin', 'jmax', 's1', 's2', 'h1', 'h2', 'h3', 'h4']
  const out: Record<string, number> = {}
  for (const part of text.trim().split(/[\s,;]+/).filter(Boolean)) {
    const [k, v] = part.split('=')
    if (!k || !keys.includes(k) || v === undefined || !/^\d+$/.test(v)) return `неверный параметр AmneziaWG: ${part}`
    out[k] = Number(v)
  }
  const missing = keys.filter((k) => !(k in out))
  return missing.length ? `не хватает параметров AmneziaWG: ${missing.join(', ')}` : out
}

/** Профиль из формы; проверку значений выполняет контроллер. */
export function formToProfile(f: ProfileForm): Profile | string {
  const port = Number(f.port)
  const e: Record<string, unknown> = { server: f.server.trim(), port }
  const opt = (k: string, v: string) => { if (v.trim()) e[k] = v.trim() }
  switch (f.kind) {
    case 'trusttunnel':
      e.username = f.username.trim(); opt('sni', f.sni); opt('cert_sha256', f.certSha256); if (f.quic) e.quic = true
      break
    case 'hysteria2':
      opt('sni', f.sni); opt('cert_sha256', f.certSha256); if (f.obfs) e.obfs = 'salamander'
      break
    case 'vless':
      e.security = f.security; opt('sni', f.sni); if (f.vision) e.flow = 'xtls-rprx-vision'
      if (f.security === 'reality') e.reality = { public_key: f.realityKey.trim(), short_id: f.realityShortId.trim() }
      else opt('cert_sha256', f.certSha256)
      break
    case 'wireguard': {
      opt('public_key', f.publicKey); opt('address', f.address); if (f.mtu.trim()) e.mtu = Number(f.mtu)
      if (f.awg) {
        const a = parseAwg(f.awgText)
        if (typeof a === 'string') return a
        e.awg = a
      }
      break
    }
  }
  return { id: f.id.trim(), name: f.name.trim(), kind: f.kind, on_failure: f.onFailure, endpoint: e as unknown as Profile['endpoint'] }
}

/** Секрет для записи по виду профиля; пустой ввод — нечего записывать. */
export function formToSecret(f: ProfileForm): ProfileSecret | null {
  const a = f.secret1.trim()
  const b = f.secret2.trim()
  if (!a) return null
  switch (f.kind) {
    case 'trusttunnel': return { password: a }
    case 'hysteria2': return f.obfs ? { password: a, obfs_password: b } : { password: a }
    case 'vless': return { uuid: a }
    case 'wireguard': return b ? { private_key: a, preshared_key: b } : { private_key: a }
  }
}

export function secretLabels(f: ProfileForm): [string, string | null] {
  switch (f.kind) {
    case 'trusttunnel': return ['Пароль', null]
    case 'hysteria2': return ['Пароль', f.obfs ? 'Пароль obfs' : null]
    case 'vless': return ['UUID клиента', null]
    case 'wireguard': return ['Закрытый ключ клиента', 'Общий ключ (необязательно)']
  }
}

export function destinationText(d: Destination, c: Config): string {
  switch (d.type) {
    case 'group': return `группа «${c.groups.find((g) => g.id === d.id)?.name ?? d.id}»`
    case 'category': return `категория «${c.categories?.find((g) => g.id === d.id)?.name ?? d.id}»`
    case 'domain': return d.value
    case 'domain_suffix': return `*.${d.value}`
    case 'cidr': return d.value
  }
}

export function actionText(a: Action, c: Config): string {
  switch (a.type) {
    case 'profile': return c.profiles.find((p) => p.id === a.id)?.name ?? a.id
    case 'direct': return 'напрямую'
    case 'direct_zapret': return 'напрямую с Zapret'
    case 'block': return 'блокировка'
  }
}

export function sourceText(r: Rule, c: Config): string {
  const s = r.source
  if (s.type === 'device') return `устройство «${c.devices.find((d) => d.id === s.id)?.name ?? s.id}»`
  if (s.type === 'network') return `сеть «${c.networks.find((n) => n.id === s.id)?.name ?? s.id}»`
  return 'вся LAN'
}

export function dnsDefault(): DnsConfig {
  return { transport: 'doh', servers: [{ host: '', ip: '' }], adblock: { enabled: false, exceptions: [] } }
}

// ---- сети (SSID) и устройства ----
export interface NetworkForm { id: string; name: string; ssid: string; subnet: string; bridge: string; ports: string }

export function emptyNetworkForm(): NetworkForm { return { id: '', name: '', ssid: '', subnet: '', bridge: 'br-lan', ports: '' } }

export function networkToForm(n: Network): NetworkForm {
  return { id: n.id, name: n.name, ssid: n.ssid, subnet: n.subnet ?? '', bridge: n.bridge ?? '', ports: (n.ports ?? []).join(' ') }
}

/** Порты моста — интерфейсы SSID (например wl0 wl1), через пробел или запятую. Подробная проверка — на сервере. */
export function formToNetwork(f: NetworkForm): Network | string {
  const id = f.id.trim(), name = f.name.trim(), ssid = f.ssid.trim()
  if (!id || !name || !ssid) return 'Укажите идентификатор, название и SSID сети.'
  const ports = f.ports.split(/[\s,]+/).filter(Boolean)
  if (ports.length && !f.bridge.trim()) return 'Порты SSID задаются только вместе с мостом.'
  return { id, name, ssid, ...(f.subnet.trim() ? { subnet: f.subnet.trim() } : {}), ...(f.bridge.trim() ? { bridge: f.bridge.trim() } : {}), ...(ports.length ? { ports } : {}) }
}

/** Устройство из аренды DHCP: идентификатор из имени клиента (только [a-z0-9-]), MAC как есть. */
export function deviceFromLease(l: Lease, network: string): Device {
  const base = l.hostname.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 32)
  return { id: base || `dev-${l.mac.replace(/:/g, '').slice(-6)}`, name: l.hostname || l.mac, mac: l.mac, network }
}
