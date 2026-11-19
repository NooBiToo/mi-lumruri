// Логика экранов управления без DOM: форма профиля TrustTunnel ↔ Profile, форма DNS, разбор строк ввода, описание правил.

import type { Device, Lease, Network, Action, Config, Destination, DnsConfig, Endpoint, Profile, ProfileSecret, Rule } from './api'

export interface ProfileForm {
  id: string
  name: string
  onFailure: 'block' | 'direct'
  server: string
  port: string
  sni: string
  username: string
  quic: boolean
  antiDpi: boolean
  certificate: string
  // пароль: только ввод, сохранённое значение панель не получает
  password: string
}

export function emptyProfileForm(): ProfileForm {
  return { id: '', name: '', onFailure: 'block', server: '', port: '443', sni: '', username: '', quic: false, antiDpi: false, certificate: '', password: '' }
}

export function profileToForm(p: Profile): ProfileForm {
  const f = emptyProfileForm()
  Object.assign(f, { id: p.id, name: p.name, onFailure: p.on_failure })
  const e = p.endpoint
  if (!e) return f
  Object.assign(f, {
    server: e.server, port: String(e.port), sni: e.sni ?? '', username: e.username ?? '', quic: !!e.quic, antiDpi: !!e.anti_dpi, certificate: e.certificate ?? '',
  })
  return f
}

/** Профиль TrustTunnel из формы. Здесь только сборка JSON и проверка порта; адрес, SNI, имя и сертификат проверяет контроллер. */
export function formToProfile(f: ProfileForm): Profile | string {
  const port = Number(f.port.trim())
  if (!Number.isInteger(port) || port < 1 || port > 65535) return 'Порт — целое число от 1 до 65535.'
  const endpoint: Endpoint = { server: f.server.trim(), port, username: f.username.trim(), quic: f.quic, anti_dpi: f.antiDpi }
  if (f.sni.trim()) endpoint.sni = f.sni.trim()
  // PEM из textarea: переводы строк приводим к \n, пустые строки по краям убираем
  const cert = f.certificate.replace(/\r\n?/g, '\n').trim()
  if (cert) endpoint.certificate = `${cert}\n`
  return { id: f.id.trim(), name: f.name.trim(), kind: 'trusttunnel', on_failure: f.onFailure, endpoint }
}

/** Пароль для записи; пустое поле — пароль не меняется. Пробелы не обрезаются: они могут быть частью пароля. */
export function formToSecret(f: ProfileForm): ProfileSecret | null {
  return f.password ? { password: f.password } : null
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

// ---- DNS ----
/** Резолвер туннеля по умолчанию (controller/src/model.rs: DEFAULT_TUNNEL_RESOLVER). */
export const DEFAULT_TUNNEL_RESOLVER = '1.1.1.1'

export interface DnsForm { resolver: string; adblock: boolean; exceptions: string }

export function dnsDefault(): DnsForm {
  return { resolver: DEFAULT_TUNNEL_RESOLVER, adblock: false, exceptions: '' }
}

export function dnsToForm(d: DnsConfig | undefined): DnsForm {
  if (!d) return dnsDefault()
  return { resolver: d.tunnel_resolver ?? DEFAULT_TUNNEL_RESOLVER, adblock: !!d.adblock?.enabled, exceptions: (d.adblock?.exceptions ?? []).join('\n') }
}

/** Настройки DNS из формы; всё по умолчанию — null (контроллер возьмёт 1.1.1.1 и не блокирует рекламу). Адрес и домены проверяет контроллер. */
export function formToDns(f: DnsForm): DnsConfig | null {
  const resolver = f.resolver.trim()
  const exceptions = f.exceptions.split(/[\s,]+/).filter(Boolean)
  const d: DnsConfig = {}
  if (resolver && resolver !== DEFAULT_TUNNEL_RESOLVER) d.tunnel_resolver = resolver
  if (f.adblock || exceptions.length) d.adblock = { enabled: f.adblock, ...(exceptions.length ? { exceptions } : {}) }
  return Object.keys(d).length ? d : null
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
