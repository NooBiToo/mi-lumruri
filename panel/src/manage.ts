// Формы без DOM: профиль TrustTunnel ↔ Profile (экран «Сервер»), DNS (экран «Дополнительно»).

import type { DnsConfig, Endpoint, Profile, ProfileSecret } from './api'

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

/** Готовый DNS-сервер для сайтов через VPN; значок — `dnsIcon(id)` в brand.ts. */
export interface DnsPreset { id: string; name: string; ip: string; desc: string; note?: string }

export const DNS_PRESETS: DnsPreset[] = [
  { id: 'cloudflare', name: 'Cloudflare', ip: '1.1.1.1', desc: 'Быстрый, без фильтров. Выбран по умолчанию.' },
  { id: 'quad9', name: 'Quad9', ip: '9.9.9.9', desc: 'Не открывает опасные и мошеннические сайты.' },
  { id: 'google', name: 'Google', ip: '8.8.8.8', desc: 'Надёжный, без фильтров.' },
  { id: 'adguard', name: 'AdGuard DNS', ip: '94.140.14.14', desc: 'Блокирует рекламу и трекеры.' },
  {
    id: 'nextdns', name: 'NextDNS', ip: '45.90.28.0', desc: 'Свои фильтры в личном кабинете.',
    note: 'Привяжите IP вашего VPN-сервера в кабинете NextDNS (Linked IP), иначе фильтры не применятся.',
  },
]
export const CUSTOM_DNS = 'custom'

/** Какой готовый сервер выбран по адресу: пустой — по умолчанию (Cloudflare), незнакомый — «Свой адрес». */
export function dnsPresetOf(resolver: string): string {
  const ip = resolver.trim() || DEFAULT_TUNNEL_RESOLVER
  return DNS_PRESETS.find((p) => p.ip === ip)?.id ?? CUSTOM_DNS
}

/** Адрес готового сервера или null для «Свой адрес» и неизвестных id. */
export function dnsPresetIp(id: string): string | null {
  return DNS_PRESETS.find((p) => p.id === id)?.ip ?? null
}
