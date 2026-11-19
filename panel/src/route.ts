// Представление маршрута «Источник → Назначение → Действие» и состояния службы для панели. Без DOM.

import type { Action, Config, Destination, ManageResponse, Source } from './api'

/** Вид действия маршрута; от него зависит цвет плашки во всей панели. */
export type RouteKind = 'tunnel' | 'direct' | 'zapret' | 'block'

export function routeKind(a: Action): RouteKind {
  switch (a.type) {
    case 'profile': return 'tunnel'
    case 'direct': return 'direct'
    case 'direct_zapret': return 'zapret'
    case 'block': return 'block'
  }
}

/** Подпись плашки действия: имя профиля TrustTunnel или понятное название действия. */
export function routeLabel(a: Action, c: Config): string {
  switch (a.type) {
    case 'profile': return c.profiles.find((p) => p.id === a.id)?.name ?? a.id
    case 'direct': return 'Напрямую'
    case 'direct_zapret': return 'Напрямую с Zapret'
    case 'block': return 'Блокировать'
  }
}

/** Короткое имя источника: «Телевизор», «Гостевая сеть», «Вся LAN». */
export function sourceShort(s: Source, c: Config): string {
  if (s.type === 'device') return c.devices.find((d) => d.id === s.id)?.name ?? s.id
  if (s.type === 'network') return c.networks.find((n) => n.id === s.id)?.name ?? s.id
  return 'Вся LAN'
}

/** Короткое имя назначения: имя группы или категории, домен, *.суффикс, подсеть. */
export function destShort(d: Destination, c: Config): string {
  switch (d.type) {
    case 'group': return c.groups.find((g) => g.id === d.id)?.name ?? d.id
    case 'category': return c.categories?.find((g) => g.id === d.id)?.name ?? d.id
    case 'domain': return d.value
    case 'domain_suffix': return `*.${d.value}`
    case 'cidr': return d.value
  }
}

/** Вид выхода по строке контроллера (preview.rs: action_label), например «VPN «Дом» (TrustTunnel)» или «маршрут по умолчанию: прямой выход». */
export function exitKind(exit: string): RouteKind | null {
  const s = exit.replace(/^маршрут по умолчанию:\s*/, '').trim().toLowerCase()
  if (s.startsWith('vpn')) return 'tunnel'
  if (s.includes('zapret')) return 'zapret'
  if (s.startsWith('прямой') || s.startsWith('напрямую')) return 'direct'
  if (s.startsWith('блок')) return 'block'
  return null
}

/** Короткая подпись выхода для плашки, тем же словарём, что и действия правил: «VPN «Дом» (TrustTunnel)» → «Дом». */
export function exitShort(exit: string): string {
  const s = exit.replace(/^маршрут по умолчанию:\s*/, '').trim()
  const vpn = /^VPN «(.+)»/.exec(s)
  if (vpn?.[1]) return vpn[1]
  switch (exitKind(s)) {
    case 'zapret': return 'Напрямую с Zapret'
    case 'direct': return 'Напрямую'
    case 'block': return 'Блокировать'
    default: return s
  }
}

/** Состояние, которое служба роутера пишет в status.json (package/scripts/mitt-lib.sh: status_write). */
export interface ServiceStatus {
  at?: number
  release?: string
  protection?: 'full' | 'guard' | 'none' | string
  engines?: Record<string, boolean>
  last_apply?: { tag?: string; exit?: number; at?: number } | null
}

export type TunnelTone = 'ok' | 'warn' | 'bad' | 'idle'
export interface TunnelState { tone: TunnelTone; title: string; detail: string | null }

/** Строка состояния туннеля для верхней полосы панели по ответу /status и настройкам. */
export function tunnelState(s: ManageResponse | null, c: Config | null): TunnelState {
  if (!s || !s.ok) return { tone: 'idle', title: 'Состояние службы неизвестно', detail: 'Откройте раздел «Состояние», чтобы обновить.' }
  const svc = (s.service ?? null) as ServiceStatus | null
  if (!svc || svc.engines?.service === false) {
    return { tone: 'bad', title: 'Служба не запущена', detail: 'Настройки сохраняются, но к сети не применяются.' }
  }
  const profile = c?.profiles[0]
  if (!profile) return { tone: 'idle', title: 'Туннель не настроен', detail: 'Добавьте сервер TrustTunnel в разделе «Профили».' }
  const tt = svc.engines?.trusttunnel
  if (tt === true) return { tone: 'ok', title: 'Туннель работает', detail: null }
  const blocked = profile.on_failure !== 'direct' || svc.protection === 'guard'
  if (tt === false || svc.protection === 'guard') {
    return blocked
      ? { tone: 'bad', title: 'Туннель не подключён — трафик правил блокируется', detail: null }
      : { tone: 'warn', title: 'Туннель не подключён — трафик правил идёт напрямую', detail: null }
  }
  return { tone: 'warn', title: 'Туннель не запущен', detail: 'Примените настройки в разделе «Состояние».' }
}

/** Число и слово в нужной форме: 1 правило, 2 правила, 5 правил. */
export function plural(n: number, one: string, few: string, many: string): string {
  const m10 = n % 10
  const m100 = n % 100
  const w = m10 === 1 && m100 !== 11 ? one : m10 >= 2 && m10 <= 4 && (m100 < 12 || m100 > 14) ? few : many
  return `${n} ${w}`
}
