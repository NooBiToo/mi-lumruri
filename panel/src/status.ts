// Логика экранов простой панели без DOM: состояние туннеля, ответы пользователя из настроек, устройства, тексты подбора Zapret.

import type { Config, Lease, ListCatalog, ManageResponse, ZapretConfig, ZapretTestState } from './api'
import { defaultSimple, fromConfig, normalizeMac, type KnownDevice, type Simple } from './simple'
import { AUTO, pickedByTest, strategyName } from './zapret'
import { dateTag, plural, t } from './i18n'

export { AUTO }

/** Состояние, которое служба роутера пишет в status.json (package/scripts/mitt-lib.sh: status_write). */
export interface ServiceStatus {
  at?: number
  release?: string
  protection?: 'full' | 'guard' | 'none' | string
  engines?: Record<string, boolean>
  last_apply?: { tag?: string; exit?: number; at?: number } | null
  /** Итог последнего рендера настроек: не прошёл — роутер работает по прежним. */
  render?: { ok?: boolean; at?: number; error?: string } | null
  /** Итог последнего полного применения (защитный вызов после сбоя его не перезаписывает). */
  apply?: { tag?: string; exit?: number; at?: number; error?: string | null } | null
}

/** Почему последние настройки не применены (рендер или полное применение не прошли), иначе null. */
export function applyFailure(svc: ServiceStatus | null): string | null {
  const cut = (x: string) => (x.length > 200 ? `${x.slice(0, 200)}…` : x)
  if (svc?.render?.ok === false) return cut(svc.render.error || t('настройки не удалось подготовить'))
  if (svc?.apply && typeof svc.apply.exit === 'number' && svc.apply.exit !== 0) return cut(svc.apply.error || t('ошибка применения (код {c})', { c: svc.apply.exit }))
  return null
}

/** Число и слово в нужной форме (1 сайт, 2 сайта, 5 сайтов) — с переводом, см. i18n. */
export { plural } from './i18n'

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
  if (c && !profile?.endpoint) return { tone: 'idle', title: t('Сервер VPN не настроен'), detail: t('Откройте «Сервер» и вставьте ссылку от своего сервера.') }
  const svc = s?.ok ? ((s.service ?? null) as ServiceStatus | null) : null
  // сбой применения важнее всего остального (и выключенного VPN): роутер работает не так, как показано на экранах
  const failed = svc && svc.engines?.service !== false && !s?.apply_pending ? applyFailure(svc) : null
  if (failed) {
    const guard = svc?.protection === 'guard'
    return { tone: 'bad', title: t('Настройки не применены'), detail: `${failed.charAt(0).toUpperCase()}${failed.slice(1)}. `
      + (guard ? t('Действует защита: сайты из списка не откроются, пока настройки не применятся.') : t('Роутер работает по прежним настройкам.')) }
  }
  if (simple && !simple.enabled) {
    return { tone: 'idle', title: t('VPN выключен'), detail: hasZapretSites(simple)
      ? t('Все сайты открываются напрямую. Сайты с обходом блокировок по-прежнему открываются с Zapret.')
      : t('Все сайты открываются напрямую, обход блокировок (Zapret) тоже выключен.') }
  }
  if (!s || !s.ok) return { tone: 'idle', title: t('Проверяю состояние…'), detail: null }
  if (!svc || svc.engines?.service === false) {
    return { tone: 'bad', title: t('Служба роутера не запущена'), detail: t('Настройки сохраняются, но не действуют. Перезагрузите роутер.') }
  }
  if (s.apply_pending) return { tone: 'warn', title: t('Применяю настройки…'), detail: t('Обычно это занимает несколько секунд.') }
  const tt = svc.engines?.trusttunnel
  if (tt === true) return { tone: 'ok', title: t('VPN работает'), detail: null }
  if (tt === false || svc.protection === 'guard') {
    return profile?.on_failure === 'direct'
      ? { tone: 'warn', title: t('Нет связи с сервером VPN'), detail: t('Сайты из списка пока открываются напрямую.') }
      : { tone: 'bad', title: t('Нет связи с сервером VPN'), detail: t('Сайты из списка не откроются, пока связь не восстановится.') }
  }
  if (simple && !simple.services.length && !simple.customDomains.length && simple.mode === 'selected') {
    return { tone: 'idle', title: t('VPN готов'), detail: t('Выберите сайты, которые открывать через VPN.') }
  }
  return { tone: 'warn', title: t('VPN ещё не запущен'), detail: t('Роутер применит настройки в течение минуты.') }
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
    return s.exceptions.length ? t('Все сайты, кроме {n}', { n: plural(s.exceptions.length, 'исключения', 'исключений', 'исключений') }) : t('Все сайты')
  }
  const names = s.services.map((id) => t(catalog?.services.find((x) => x.id === id)?.name ?? id))
  const parts: string[] = []
  if (names.length) parts.push(names.length <= 3 ? names.join(', ') : t('{names} и ещё {n}', { names: names.slice(0, 3).join(', '), n: names.length - 3 }))
  if (s.customDomains.length) parts.push(plural(s.customDomains.length, 'свой сайт', 'своих сайта', 'своих сайтов'))
  return parts.length ? parts.join(' · ') : t('Пока ничего не выбрано')
}

export function devicesSummary(s: Simple): string {
  return s.devices === 'all' ? t('Все устройства дома') : t('Только {n}', { n: plural(s.devices.length, 'выбранное устройство', 'выбранных устройства', 'выбранных устройств') })
}

/** Есть сайты с обходом блокировок без VPN и устройства, для которых они действуют (правила `zapret-<src>`). */
export function hasZapretSites(s: Simple): boolean {
  return (s.zapretServices.length > 0 || s.zapretDomains.length > 0) && (s.devices === 'all' || s.devices.length > 0)
}

/** Использует ли простой вид обход блокировок: «остальные сайты» с Zapret или свои сайты с обходом. */
export function usesZapret(s: Simple | null): boolean {
  return !!s && (s.rest === 'zapret' || hasZapretSites(s))
}

/**
 * Почему выбранный обход блокировок (Zapret) сейчас не действует, или null. Без правил «напрямую с Zapret» служба
 * nfqws2 не запускает и подбирать способ не на чем: VPN выключен или всё (без исключений, для всех устройств) идёт
 * через VPN. Сайты с обходом блокировок действуют всегда, и при выключенном VPN тоже.
 */
export function zapretIdle(s: Simple | null): string | null {
  if (!s || s.rest !== 'zapret' || hasZapretSites(s)) return null
  if (!s.enabled) return t('Сейчас VPN выключен, а с ним и обход блокировок: все сайты открываются напрямую. Подобрать способ можно, когда VPN включён.')
  if (s.mode === 'all' && s.devices === 'all' && !s.exceptions.length) {
    return t('Сейчас все сайты всех устройств идут через VPN, поэтому обход блокировок не используется и подбирать способ не на чем. Он заработает для сайтов из «Не пускать через VPN» или для устройств, которые не идут через VPN.')
  }
  return null
}

/**
 * Способ обхода для людей: «Способ 4, YouTube: способ 2», id каталога («v4») не показываем никогда. Если способ поставил
 * последний подбор — с припиской «подобран автоматически» и датой.
 */
export function strategyLabel(z: ZapretConfig | undefined, test?: ZapretTestState | null): string {
  const general = z?.strategy ?? AUTO
  const youtube = z?.youtube ?? AUTO
  if (general === AUTO && youtube === AUTO) return t('Автоматически (рекомендуется)')
  const parts: string[] = []
  if (general !== AUTO) parts.push(strategyName('general', general))
  if (youtube !== AUTO) parts.push(strategyName('youtube', youtube))
  const p = pickedByTest(z, test)
  return p.general || p.youtube ? t('{s} — подобран автоматически {d}', { s: parts.join(', '), d: when(testedAt(test)) }) : parts.join(', ')
}

/** Когда последний подбор применил способ (для подписи «Подобран автоматически …»), иначе null. */
export function testedAt(t: ZapretTestState | null | undefined): number | null {
  return t && t.state === 'done' && t.applied ? t.finished ?? t.started ?? null : null
}

/** Строка прогресса подбора: «Проверяю способы обхода: 5 из 11». */
export function zapretProgress(st: ZapretTestState): string {
  const p = st.progress
  if (!p || !p.total) return t('Готовлю проверку…')
  const n = { n: Math.min(p.done + 1, p.total), total: p.total }
  return p.current === 'control' ? t('Проверяю, что открывается без обхода: {n} из {total}', n) : t('Проверяю способы обхода: {n} из {total}', n)
}

/**
 * Итог последнего подбора: «Открылось 47 из 54, без обхода — 12» и что сделано — без id стратегий. Если применён только
 * способ для YouTube, цифры — прохода YouTube: результат для всех сайтов тогда не применялся.
 */
export function zapretResult(st: ZapretTestState): { summary: string | null; message: string } {
  const c = st.control
  const y = st.youtube
  const ytOnly = st.state === 'done' && st.applied && st.general === false && !!y
  let summary: string | null
  if (ytOnly && y) summary = t('YouTube: открылось {o} из {n}', { o: y.opened, n: y.total }) + (y.control !== undefined ? t(', без обхода — {c}', { c: y.control }) : '')
  else summary = st.best && c ? t('Открылось {o} из {n}, без обхода — {c}', { o: st.best.opened, n: c.total, c: c.opened }) : null
  let message: string
  if (st.state === 'done') {
    message = ytOnly ? t('Для всех сайтов лучше не нашлось — оставлен прежний способ; для YouTube применён лучший.')
      : st.applied ? t('Лучший способ применён.') : t('Способа лучше, чем без обхода, не нашлось — оставлен прежний.')
  } else message = failureText(st.message)
  return { summary, message }
}

/**
 * Сообщение сбоя сценария подбора — без id стратегий: файлы до 0.3.0 называли их («стратегия v4», «(v3)»,
 * «general=v3 youtube=yv2»). «Способ» — мужского рода: «прежний способ», «вернуть прежний».
 */
export function failureText(raw: string | undefined): string {
  const m = (raw ?? t('Подбор не удался.'))
    .replace(/:?(?:\s*\b(?:general|youtube)=\S+)+/g, '')
    .replace(/восстановлена/g, 'восстановлен').replace(/она оставлена/g, 'он оставлен')
    .replace(/прежн\S*\s+стратеги\S*/gi, 'прежний способ').replace(/прежнюю/g, 'прежний')
    .replace(/стратеги\S* y?v\d+/gi, 'способ').replace(/\s*\((?:y?v\d+|auto)\)/g, '')
    .replace(/\b(?:y?v\d+)\b/g, 'новый способ').replace(/стратеги\S*/gi, 'способ').replace(/\s+/g, ' ').trim()
  return m.charAt(0).toUpperCase() + m.slice(1)
}

/** Дата и время по-русски: «18 ноября, 14:05». */
export function when(sec: number | null | undefined): string {
  if (!sec) return '—'
  return new Date(sec * 1000).toLocaleString(dateTag(), { day: 'numeric', month: 'long', hour: '2-digit', minute: '2-digit' })
}
