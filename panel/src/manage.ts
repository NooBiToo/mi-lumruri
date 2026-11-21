// Формы без DOM: профиль TrustTunnel ↔ Profile (экран «Сервер»), DNS (экран «Дополнительно»).

import type { AdblockSource, DnsConfig, Endpoint, HostRecord, SecureDns, SecureServer, Profile, ProfileSecret, TlsProfile } from './api'
import { t } from './i18n'

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
  tlsProfile: TlsProfile
  clientRandom: string
  clientRandomAuthKey: string
  // пароль и ссылка-подписка: только ввод, сохранённые значения панель не получает
  password: string
  subscriptionUrl: string
}

export function emptyProfileForm(): ProfileForm {
  return {
    id: '', name: '', onFailure: 'block', server: '', port: '443', sni: '', username: '', quic: false, antiDpi: false, certificate: '',
    tlsProfile: 'chrome', clientRandom: '', clientRandomAuthKey: '', password: '', subscriptionUrl: '',
  }
}

export function profileToForm(p: Profile): ProfileForm {
  const f = emptyProfileForm()
  Object.assign(f, { id: p.id, name: p.name, onFailure: p.on_failure })
  const e = p.endpoint
  if (!e) return f
  Object.assign(f, {
    server: e.server, port: String(e.port), sni: e.sni ?? '', username: e.username ?? '', quic: !!e.quic, antiDpi: !!e.anti_dpi, certificate: e.certificate ?? '',
    tlsProfile: e.tls_profile ?? 'chrome', clientRandom: e.client_random ?? '', clientRandomAuthKey: e.client_random_auth_key ?? '',
  })
  return f
}

/** Профиль TrustTunnel из формы. Здесь только сборка JSON и проверка порта; адрес, SNI, имя и сертификат проверяет контроллер. */
export function formToProfile(f: ProfileForm, subscription = false): Profile | string {
  // только подписка: адрес и логин сервер пришлёт сам — профиль без точки подключения
  if (subscription && !f.server.trim() && !f.username.trim()) return { id: f.id.trim(), name: f.name.trim(), kind: 'trusttunnel', on_failure: f.onFailure }
  const port = Number(f.port.trim())
  if (!Number.isInteger(port) || port < 1 || port > 65535) return t('Порт — целое число от 1 до 65535.')
  const endpoint: Endpoint = { server: f.server.trim(), port, username: f.username.trim(), quic: f.quic, anti_dpi: f.antiDpi }
  if (f.sni.trim()) endpoint.sni = f.sni.trim()
  // PEM из textarea: переводы строк приводим к \n, пустые строки по краям убираем
  const cert = f.certificate.replace(/\r\n?/g, '\n').trim()
  if (cert) endpoint.certificate = `${cert}\n`
  // по умолчанию (chrome, пустые client_random) поля не пишутся: настройки старых версий остаются прежними
  if (f.tlsProfile !== 'chrome') endpoint.tls_profile = f.tlsProfile
  const random = f.clientRandom.trim().toLowerCase()
  const key = f.clientRandomAuthKey.trim().toLowerCase()
  if (random) endpoint.client_random = random
  if (key) endpoint.client_random_auth_key = key
  return { id: f.id.trim(), name: f.name.trim(), kind: 'trusttunnel', on_failure: f.onFailure, endpoint }
}

/** Секреты для записи; пустое поле — значение не меняется. Пробелы в пароле не обрезаются: они могут быть его частью. */
export function formToSecret(f: ProfileForm): ProfileSecret | null {
  const s: ProfileSecret = {}
  if (f.password) s.password = f.password
  if (f.subscriptionUrl.trim()) s.subscription_url = f.subscriptionUrl.trim()
  return Object.keys(s).length ? s : null
}

// ---- DNS ----
/** Резолвер туннеля по умолчанию (controller/src/model.rs: DEFAULT_TUNNEL_RESOLVER). */
export const DEFAULT_TUNNEL_RESOLVER = '1.1.1.1'

/** Защищённый DNS в форме: выключен, DoH или DoT; сервер — готовый или свой (ссылка/имя и IP через запятую). */
export type SecureMode = 'off' | 'doh' | 'dot'
export interface DnsForm {
  resolver: string; adblock: boolean; adblockSource: AdblockSource; adblockUrl: string; exceptions: string; hosts: HostRecord[]
  secure: SecureMode; secureServer: SecureServer; nextdnsId: string; secureUrl: string; secureIps: string
  /** Шифрование DNS для сайтов через VPN (DoH/DoT поверх туннеля). */
  tunnelSecure: SecureMode
}

/** Какое шифрование DNS через VPN доступно для резолвера туннеля (контроллер: DnsConfig::tunnel_proxy_args). */
export function tunnelSecureModes(resolver: string): SecureMode[] {
  if (['1.1.1.1', '1.0.0.1', '8.8.8.8', '8.8.4.4', '94.140.14.14', '94.140.15.15'].includes(resolver)) return ['off', 'doh', 'dot']
  if (['9.9.9.9', '149.112.112.112'].includes(resolver)) return ['off', 'dot']
  return ['off']
}

export function dnsDefault(): DnsForm {
  return { resolver: DEFAULT_TUNNEL_RESOLVER, adblock: false, adblockSource: 'light', adblockUrl: '', exceptions: '', hosts: [],
    secure: 'off', secureServer: 'cloudflare', nextdnsId: '', secureUrl: '', secureIps: '', tunnelSecure: 'off' }
}

export function dnsToForm(d: DnsConfig | undefined): DnsForm {
  if (!d) return dnsDefault()
  const s = d.secure
  return { resolver: d.tunnel_resolver ?? DEFAULT_TUNNEL_RESOLVER, adblock: !!d.adblock?.enabled, adblockSource: d.adblock?.source ?? 'light',
    adblockUrl: d.adblock?.url ?? '', exceptions: (d.adblock?.exceptions ?? []).join('\n'),
    hosts: (d.hosts ?? []).map((h) => ({ domain: h.domain, address: h.address })),
    secure: s?.protocol ?? 'off', secureServer: s?.server ?? 'cloudflare', nextdnsId: s?.nextdns_id ?? '', secureUrl: s?.url ?? '', secureIps: (s?.ips ?? []).join(', '),
    tunnelSecure: d.tunnel_secure ?? 'off' }
}

/** Раздел `secure` из формы: поля NextDNS и своего сервера — только для них. Точнее проверит контроллер. */
function formToSecure(f: DnsForm): SecureDns | null {
  if (f.secure === 'off') return null
  const s: SecureDns = { protocol: f.secure, server: f.secureServer }
  if (f.secureServer === 'nextdns') s.nextdns_id = f.nextdnsId.trim().toLowerCase()
  if (f.secureServer === 'custom') {
    s.url = f.secureUrl.trim()
    s.ips = f.secureIps.split(/[\s,;]+/).filter(Boolean)
  }
  return s
}

/** Настройки DNS из формы; всё по умолчанию — null (контроллер возьмёт 1.1.1.1 и не блокирует рекламу). Адрес и домены проверяет контроллер. */
export function formToDns(f: DnsForm): DnsConfig | null {
  const resolver = f.resolver.trim()
  const exceptions = f.exceptions.split(/[\s,]+/).filter(Boolean)
  const d: DnsConfig = {}
  if (resolver && resolver !== DEFAULT_TUNNEL_RESOLVER) d.tunnel_resolver = resolver
  // шифрование — только если оно доступно для выбранного сервера (иначе контроллер отклонит настройки)
  if (f.tunnelSecure !== 'off' && tunnelSecureModes(resolver || DEFAULT_TUNNEL_RESOLVER).includes(f.tunnelSecure)) d.tunnel_secure = f.tunnelSecure
  // источник по умолчанию (Light) не пишется; ссылка — только для «Своя ссылка» (недописанная при другом источнике не сохраняется)
  const url = f.adblockSource === 'url' ? f.adblockUrl.trim() : ''
  if (f.adblock || exceptions.length || f.adblockSource !== 'light') {
    d.adblock = { enabled: f.adblock, ...(exceptions.length ? { exceptions } : {}), ...(f.adblockSource !== 'light' ? { source: f.adblockSource } : {}), ...(url ? { url } : {}) }
  }
  const secure = formToSecure(f)
  if (secure) d.secure = secure
  if (f.hosts.length) d.hosts = f.hosts.map((h) => ({ domain: h.domain, address: h.address }))
  return Object.keys(d).length ? d : null
}

/** Готовый DNS-сервер для сайтов через VPN; значок — `dnsIcon(id)` в brand.ts. */
export interface DnsPreset { id: string; name: string; ip: string; desc: string; note?: string }

// desc и note — геттеры: текст на текущем языке интерфейса в момент чтения
export const DNS_PRESETS: DnsPreset[] = [
  { id: 'cloudflare', name: 'Cloudflare', ip: '1.1.1.1', get desc() { return t('Быстрый, без фильтров. Выбран по умолчанию.') } },
  { id: 'quad9', name: 'Quad9', ip: '9.9.9.9', get desc() { return t('Не открывает опасные и мошеннические сайты') } },
  { id: 'google', name: 'Google', ip: '8.8.8.8', get desc() { return t('Надёжный, без фильтров') } },
  { id: 'adguard', name: 'AdGuard DNS', ip: '94.140.14.14', get desc() { return t('Блокирует рекламу и трекеры') } },
  {
    id: 'nextdns', name: 'NextDNS', ip: '45.90.28.0', get desc() { return t('Свои фильтры в личном кабинете') },
    get note() { return t('Привяжите IP вашего VPN-сервера в кабинете NextDNS (Linked IP), иначе фильтры не применятся.') },
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
