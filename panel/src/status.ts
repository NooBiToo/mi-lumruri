// Логика экранов простой панели без DOM: состояние туннеля, ответы пользователя из настроек, устройства, тексты подбора Zapret.

import type { Config, Lease, ListCatalog, ManageResponse, ZapretConfig, ZapretTestState } from './api'
import { defaultSimple, fromConfig, normalizeMac, type KnownDevice, type Simple } from './simple'

/** Состояние, которое служба роутера пишет в status.json (package/scripts/mitt-lib.sh: status_write). */
export interface ServiceStatus {
  at?: number
  release?: string
  protection?: 'full' | 'guard' | 'none' | string
  engines?: Record<string, boolean>
  last_apply?: { tag?: string; exit?: number; at?: number } | null
}

/** Число и слово в нужной форме: 1 сайт, 2 сайта, 5 сайтов. */
export function plural(n: number, one: string, few: string, many: string): string {
  const m10 = n % 10
  const m100 = n % 100
  const w = m10 === 1 && m100 !== 11 ? one : m10 >= 2 && m10 <= 4 && (m100 < 12 || m100 > 14) ? few : many
  return `${n} ${w}`
}

/**
 * Ответы пользователя из настроек. Свежая установка (ничего не настроено, кроме, может быть, сервера) — простые
 * настройки по умолчанию: «изменено вручную» тут показывать нечего.
 */
export function readSimple(cfg: Config): ReturnType<typeof fromConfig> {
  const fresh = !cfg.networks.length && !cfg.devices.length && !cfg.groups.length && !cfg.rules.length && !cfg.categories?.length
    && cfg.default_action.type === 'direct'
  if (fresh) return { canonical: true, simple: defaultSimple() }
  return fromConfig(cfg)
}

export type Tone = 'ok' | 'warn' | 'bad' | 'idle'
export interface TunnelState { tone: Tone; title: string; detail: string | null }

/** Состояние для строки вверху и экрана «Состояние»: простыми словами, без названий служб. */
export function tunnelState(s: ManageResponse | null, c: Config | null, simple: Simple | null): TunnelState {
  const profile = c?.profiles[0]
  if (c && !profile?.endpoint) return { tone: 'idle', title: 'Сервер VPN не настроен', detail: 'Откройте «Сервер» и вставьте ссылку от своего сервера.' }
  if (simple && !simple.enabled) return { tone: 'idle', title: 'VPN выключен', detail: 'Все сайты открываются напрямую.' }
  if (!s || !s.ok) return { tone: 'idle', title: 'Проверяю состояние…', detail: null }
  const svc = (s.service ?? null) as ServiceStatus | null
  if (!svc || svc.engines?.service === false) {
    return { tone: 'bad', title: 'Служба роутера не запущена', detail: 'Настройки сохраняются, но не действуют. Перезагрузите роутер.' }
  }
  if (s.apply_pending) return { tone: 'warn', title: 'Применяю настройки…', detail: 'Обычно это занимает несколько секунд.' }
  const tt = svc.engines?.trusttunnel
  if (tt === true) return { tone: 'ok', title: 'VPN работает', detail: null }
  if (tt === false || svc.protection === 'guard') {
    return profile?.on_failure === 'direct'
      ? { tone: 'warn', title: 'Нет связи с сервером VPN', detail: 'Сайты из списка пока открываются напрямую.' }
      : { tone: 'bad', title: 'Нет связи с сервером VPN', detail: 'Сайты из списка не откроются, пока связь не восстановится.' }
  }
  if (simple && !simple.services.length && !simple.customDomains.length && simple.mode === 'selected') {
    return { tone: 'idle', title: 'VPN готов', detail: 'Выберите сайты, которые открывать через VPN.' }
  }
  return { tone: 'warn', title: 'VPN ещё не запущен', detail: 'Роутер применит настройки в течение минуты.' }
}

/**
 * Устройства для `toConfig`: аренды DHCP с именами, поверх — имена из настроек (они важнее), поверх — переименования,
 * которые пользователь сделал сейчас. Без переименования сохранённое имя не меняется.
 */
export function knownDevices(leases: Lease[], cfg: Config, renames: Record<string, string>): KnownDevice[] {
  const names = new Map<string, string>()
  for (const l of leases) {
    const m = normalizeMac(l.mac)
    if (m && l.hostname) names.set(m, l.hostname)
  }
  for (const d of cfg.devices) {
    const m = normalizeMac(d.mac)
    if (m && d.name) names.set(m, d.name)
  }
  for (const [mac, name] of Object.entries(renames)) {
    const m = normalizeMac(mac)
    if (m && name.trim()) names.set(m, name.trim())
  }
  return [...names].map(([mac, name]) => ({ mac, name }))
}

/** Строка устройства на экране: имя (или «Устройство без имени»), IP, MAC, в сети ли сейчас. */
export interface DeviceRow { mac: string; name: string; ip: string | null; online: boolean }

export function deviceRows(leases: Lease[], cfg: Config, renames: Record<string, string>, selected: string[]): DeviceRow[] {
  const known = new Map(knownDevices(leases, cfg, renames).map((k) => [k.mac, k.name]))
  const rows = new Map<string, DeviceRow>()
  for (const l of leases) {
    const m = normalizeMac(l.mac)
    if (m && !rows.has(m)) rows.set(m, { mac: m, name: known.get(m) ?? '', ip: l.ip, online: true })
  }
  for (const mac of [...cfg.devices.map((d) => d.mac), ...selected]) {
    const m = normalizeMac(mac)
    if (m && !rows.has(m)) rows.set(m, { mac: m, name: known.get(m) ?? '', ip: null, online: false })
  }
  return [...rows.values()].sort((a, b) => Number(b.online) - Number(a.online) || (a.name || '￿').localeCompare(b.name || '￿', 'ru'))
}

/** Разбор текстового поля «по домену в строке»: пробелы, запятые и пустые строки не важны. */
export function lines(text: string): string[] {
  return text.split(/[\s,;]+/).map((x) => x.trim()).filter(Boolean)
}

/** Что идёт через VPN — одной строкой для экрана «Состояние». */
export function sitesSummary(s: Simple, catalog: ListCatalog | null): string {
  if (s.mode === 'all') {
    return s.exceptions.length ? `Все сайты, кроме ${plural(s.exceptions.length, 'исключения', 'исключений', 'исключений')}` : 'Все сайты'
  }
  const names = s.services.map((id) => catalog?.services.find((x) => x.id === id)?.name ?? id)
  const parts: string[] = []
  if (names.length) parts.push(names.length <= 3 ? names.join(', ') : `${names.slice(0, 3).join(', ')} и ещё ${names.length - 3}`)
  if (s.customDomains.length) parts.push(plural(s.customDomains.length, 'свой сайт', 'своих сайта', 'своих сайтов'))
  return parts.length ? parts.join(' · ') : 'Пока ничего не выбрано'
}

export function devicesSummary(s: Simple): string {
  return s.devices === 'all' ? 'Все устройства дома' : `Только ${plural(s.devices.length, 'выбранное устройство', 'выбранных устройства', 'выбранных устройств')}`
}

export const AUTO = 'auto'

/** Название стратегии Zapret для людей: id каталога («v4») не показываем никогда. */
export function strategyLabel(z: ZapretConfig | undefined, tested?: number | null): string {
  if ((z?.strategy ?? AUTO) === AUTO && (z?.youtube ?? AUTO) === AUTO) return 'Автоматически (рекомендуется)'
  return tested ? `Подобран автоматически ${when(tested)}` : 'Подобран автоматически'
}

/** Когда последний подбор применил способ (для подписи «Подобран автоматически …»), иначе null. */
export function testedAt(t: ZapretTestState | null | undefined): number | null {
  return t && t.state === 'done' && t.applied ? t.finished ?? t.started ?? null : null
}

/** Строка прогресса подбора: «Проверяю способы обхода: 5 из 11». */
export function zapretProgress(t: ZapretTestState): string {
  const p = t.progress
  if (!p || !p.total) return 'Готовлю проверку…'
  const what = p.current === 'control' ? 'Проверяю, что открывается без обхода' : 'Проверяю способы обхода'
  return `${what}: ${Math.min(p.done + 1, p.total)} из ${p.total}`
}

/** Итог последнего подбора: «Открылось 47 из 54, без обхода — 12» и что сделано — без id стратегий. */
export function zapretResult(t: ZapretTestState): { summary: string | null; message: string } {
  const c = t.control
  const summary = t.best && c ? `Открылось ${t.best.opened} из ${c.total}, без обхода — ${c.opened}` : null
  let message: string
  if (t.state === 'done') message = t.applied ? 'Лучший способ применён.' : 'Способа лучше, чем без обхода, не нашлось — оставлен прежний.'
  // сообщения сбоя сценария могут называть стратегии по id: заменяем их словом «способ»
  else {
    const m = (t.message ?? 'Подбор не удался.').replace(/стратеги\S* y?v\d+/gi, 'способ').replace(/\s*\((?:y?v\d+|auto)\)/g, '')
      .replace(/\b(?:y?v\d+)\b/g, 'новый способ').replace(/\s+/g, ' ').trim()
    message = m.charAt(0).toUpperCase() + m.slice(1)
  }
  return { summary, message }
}

/** Дата и время по-русски: «18 ноября, 14:05». */
export function when(sec: number | null | undefined): string {
  if (!sec) return '—'
  return new Date(sec * 1000).toLocaleString('ru-RU', { day: 'numeric', month: 'long', hour: '2-digit', minute: '2-digit' })
}
