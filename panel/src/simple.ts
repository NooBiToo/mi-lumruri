// Простые настройки панели (ответы пользователя) и их канонический вид в модели контроллера.
//
// Канонический вид:
// - сеть `home` — мост и подсеть LAN роутера;
// - категории `svc-<id>` (домены) и `svc-<id>-ip` (подсети IPv4) отмеченных списков; файлы списков служба роутера
//   кладёт в categories/ сама по каталогу релиза;
// - группы `vpn-sites` (списки и свои домены), `zapret-sites` (сайты с обходом блокировок без VPN: списки и домены),
//   `vpn-except` (исключения), `vpn-all` (весь IPv4: 0.0.0.0/1 и 128.0.0.0/1), `tgws-sites` (Telegram через
//   WebSocket, модуль tgws); сервис каталога — только в одной из них (категория `svc-<id>` одна);
// - устройства `dev-<mac без двоеточий>` — только выбранные;
// - для каждого источника (`lan` или выбранное устройство) по порядку: `except-<src>` → `vpn-except` → «остальные
//   сайты»; `zapret-<src>` → `zapret-sites` → напрямую с Zapret; `tgws-<src>` → `tgws-sites` → Telegram через
//   WebSocket (запасной путь — `tgws.via`: профиль или напрямую); `vpn-<src>` → `vpn-sites` (режим «выбранные») или
//   `vpn-all` (режим «всё») → профиль. Исключения важнее всего, а сайты с обходом не уходят в VPN и в режиме «всё»;
// - устройства «весь интернет через VPN» (режим «выбранные»): перед правилами источников — `except-<dev>`,
//   `zapret-<dev>` и `vpnall-<dev>` → `vpn-all` → профиль;
// - несколько серверов: сервер по умолчанию — профиль с наименьшим номером туннеля; сервисы другого сервера — в группе
//   `vpn-sites--<профиль>` (вместе со своими доменами этого сервера), их правило `vpn-<src>--<профиль>` стоит перед `vpn-<src>`; устройство «весь интернет через
//   VPN» может идти через свой сервер (действие правила `vpnall-<dev>`);
// - `default_action`: профиль в режиме «всё» для всей сети, иначе «остальные сайты» (напрямую или с Zapret);
// - последнее правило-метка, всегда выключенное (на маршрутизацию не влияет): `rest-lan`, а при выключенном VPN —
//   `vpn-off`; его действие — выбор «остальные сайты», чтобы выбор не терялся, когда по правилам его не видно.
// Выключенный VPN: правила VPN и исключений `enabled: false`, `default_action` напрямую; галочки остаются в группах и
// правилах. С `vpn_off_block` (режим «выбранные») правила `vpn-<src>` и `vpn-<src>--<профиль>` остаются включёнными с
// действием «блокировать»: сайты из списка VPN не открываются, пока VPN выключен. Правила `zapret-<src>` остаются включёнными: обход блокировок без VPN от VPN не зависит.
// Настройки без `zapret-sites` (как до появления сайтов с обходом) — тоже канонические, с пустыми списками.
//
// `fromConfig` считает настройки простыми, только если `toConfig` от разобранных ответов даёт ровно их же.

import type { Action, Category, Config, Destination, Device, Group, Lan, ListCatalog, Network, Rule, Source } from './api'
import { t } from './i18n'

export interface Simple {
  enabled: boolean
  mode: 'selected' | 'all'
  /** id сервисов каталога списков. */
  services: string[]
  customDomains: string[]
  /** id сервисов каталога, которые открываются напрямую с обходом блокировок (Zapret); с `services` не пересекаются. */
  zapretServices: string[]
  /** Свои домены с обходом блокировок без VPN. */
  zapretDomains: string[]
  exceptions: string[]
  rest: 'direct' | 'zapret'
  /** 'all' — все устройства дома, иначе MAC выбранных устройств. */
  devices: 'all' | string[]
  /** MAC устройств, у которых в режиме «выбранные» через VPN идёт весь интернет (исключения и сайты с обходом — как у всех). */
  vpnAll?: string[]
  /** Сервисы через другой сервер (не по умолчанию): id сервиса → id профиля. */
  serviceServer?: Record<string, string>
  /** Свои домены через другой сервер (не по умолчанию): домен → id профиля. */
  domainServer?: Record<string, string>
  /** Устройства «весь интернет через VPN» через другой сервер: MAC → id профиля. */
  deviceServer?: Record<string, string>
  /** Сервисы через WebSocket (модуль tgws, только Telegram); с `services` и `zapretServices` не пересекаются. */
  wsServices?: string[]
  /** Запасной путь WebSocket: id профиля (через VPN) или '' (напрямую); undefined — не выбирался. */
  tgwsVia?: string
  /** Выключенный VPN: сайты из списка VPN не открываются (иначе — напрямую). */
  offBlock?: boolean
}

/** Устройство, известное панели (аренды DHCP и настройки); `name` — как его показывать и сохранять. */
export interface KnownDevice { mac: string; name: string }

export type FromConfig = { simple: Simple; canonical: true } | { canonical: false; reason: string }

export const HOME = 'home'
export const HOME_NAME = 'Домашняя сеть'
export const SITES = 'vpn-sites'
export const ZAPRET_SITES = 'zapret-sites'
export const EXCEPT = 'vpn-except'
export const ALL = 'vpn-all'
export const TG_SITES = 'tgws-sites'
/** Сервисы, которые умеют идти через WebSocket (модуль tgws): только Telegram. */
export const WS_SERVICES = ['telegram']
/** Группа сервисов сервера, кроме сервера по умолчанию: `vpn-sites--<id профиля>`. */
export const SITES_AT = `${SITES}--`
const REST_ON = 'rest-lan'
const REST_OFF = 'vpn-off'
const SOURCE_PREFIX = 'itdoginfo:'
const ALL_NETS: Destination[] = [{ type: 'cidr', value: '0.0.0.0/1' }, { type: 'cidr', value: '128.0.0.0/1' }]

export function defaultSimple(): Simple {
  return { enabled: true, mode: 'selected', services: [], customDomains: [], zapretServices: [], zapretDomains: [], exceptions: [], rest: 'direct', devices: 'all' }
}

/** Как открывается сервис каталога: через VPN, напрямую с обходом блокировок (Zapret) или как все остальные сайты. */
export type ServiceRoute = 'vpn' | 'zapret' | 'ws' | 'off'
type ServiceLists = Pick<Simple, 'services' | 'zapretServices' | 'wsServices'>

export function serviceRoute(s: ServiceLists, id: string): ServiceRoute {
  return s.services.includes(id) ? 'vpn' : s.zapretServices.includes(id) ? 'zapret' : s.wsServices?.includes(id) ? 'ws' : 'off'
}

/** Списки сервисов после выбора `route` для `id`: сервис остаётся не больше чем в одном из них. */
export function setServiceRoute(s: ServiceLists, id: string, route: ServiceRoute): ServiceLists {
  const services = s.services.filter((x) => x !== id)
  const zapretServices = s.zapretServices.filter((x) => x !== id)
  const wsServices = (s.wsServices ?? []).filter((x) => x !== id)
  if (route === 'vpn') services.push(id)
  if (route === 'zapret') zapretServices.push(id)
  if (route === 'ws' && WS_SERVICES.includes(id)) wsServices.push(id)
  return { services, zapretServices, wsServices: wsServices.length ? wsServices : undefined }
}

/** MAC в виде aa:bb:cc:dd:ee:ff или null, если это не MAC устройства (как normalize_mac контроллера). */
export function normalizeMac(mac: string): string | null {
  const parts = mac.trim().split(mac.includes(':') ? ':' : '-')
  if (parts.length !== 6 || !parts.every((p) => /^[0-9a-fA-F]{2}$/.test(p))) return null
  const m = parts.join(':').toLowerCase()
  if (parseInt(parts[0] ?? '1', 16) & 1 || m === '00:00:00:00:00:00') return null
  return m
}

export const deviceId = (mac: string): string => `dev-${mac.replace(/:/g, '')}`

/**
 * Домен из строки пользователя: без схемы, пути, порта, «*.» и точек по краям, в нижнем регистре. Остальное проверяет
 * контроллер (ошибка придёт с путём к полю группы).
 */
export function normalizeDomain(v: string): string {
  let d = v.trim().toLowerCase().replace(/^[a-z][a-z0-9+.-]*:\/\//, '')
  d = d.split(/[/?#]/)[0] ?? ''
  d = d.replace(/:\d+$/, '').replace(/^\*\./, '').replace(/^\.+|\.+$/g, '')
  return d
}

function uniqueDomains(list: string[]): string[] {
  return [...new Set(list.map(normalizeDomain).filter((d) => d !== ''))]
}

/** Имя для настроек: без управляющих символов, не длиннее 64 символов (check_name контроллера). */
function cleanName(n: string | undefined): string {
  const t = (n ?? '').replace(/[\u0000-\u001f\u007f-\u009f]/g, '').replace(/\s+/g, ' ').trim()
  return [...t].slice(0, 64).join('').trim()
}

const group = (id: string, name: string, destinations: Destination[]): Group => ({ id, name, destinations })

/** Профили по номеру туннеля; первый — сервер по умолчанию. */
export function sortedProfiles<T extends { tunnel?: number }>(profiles: T[]): T[] {
  return [...profiles].sort((a, b) => (a.tunnel ?? 0) - (b.tunnel ?? 0))
}
const rule = (id: string, source: Source, groupId: string, action: Action, enabled: boolean): Rule => ({
  id, source, destination: { type: 'group', id: groupId }, action, enabled,
})

/**
 * Настройки канонического вида из ответов пользователя. Профиль, `dns` и `zapret` берутся из `base` как есть.
 * Сервисы, которых нет в каталоге, отбрасываются: файла списка для них на роутере не будет.
 */
export function toConfig(base: Config, s: Simple, lan: Lan, catalog: ListCatalog, known: KnownDevice[]): Config {
  const rest: Action = s.rest === 'zapret' ? { type: 'direct_zapret' } : { type: 'direct' }
  const byId = new Map(catalog.services.map((x) => [x.id, x]))
  const services = [...new Set(s.services)].filter((id) => byId.has(id))
  // сервис и в VPN, и с обходом остаётся в VPN: категория у сервиса одна
  const zapretServices = [...new Set(s.zapretServices)].filter((id) => byId.has(id) && !services.includes(id))
  const wsServices = [...new Set(s.wsServices ?? [])].filter((id) => byId.has(id) && WS_SERVICES.includes(id) && !services.includes(id) && !zapretServices.includes(id))
  const categories: Category[] = []
  const addServices = (ids: string[], into: Destination[]) => {
    for (const id of ids) {
      const svc = byId.get(id)!
      const name = cleanName(svc.name) || id
      categories.push({ id: `svc-${id}`, name, kind: 'domain', source: SOURCE_PREFIX + svc.domains })
      into.push({ type: 'category', id: `svc-${id}` })
      if (svc.ipv4) {
        categories.push({ id: `svc-${id}-ip`, name: cleanName(`${name}: подсети`), kind: 'ip', source: SOURCE_PREFIX + svc.ipv4 })
        into.push({ type: 'category', id: `svc-${id}-ip` })
      }
    }
  }
  const profiles = sortedProfiles(base.profiles)
  const profile = profiles[0]
  const known_ = new Set(profiles.map((p) => p.id))
  /** Сервер сервиса: другой существующий профиль или null (по умолчанию). */
  const serverOf = (id: string): string | null => {
    const p = s.serviceServer?.[id]
    return p && p !== profile?.id && known_.has(p) ? p : null
  }
  /** Сервер своего домена: другой существующий профиль или null (по умолчанию). */
  const domainServerOf = (d: string): string | null => {
    const p = Object.entries(s.domainServer ?? {}).find(([k]) => normalizeDomain(k) === d)?.[1]
    return p && p !== profile?.id && known_.has(p) ? p : null
  }
  const customs = uniqueDomains(s.customDomains)
  const sites: Destination[] = []
  addServices(services.filter((id) => !serverOf(id)), sites)
  for (const d of customs.filter((x) => !domainServerOf(x))) sites.push({ type: 'domain_suffix', value: d })
  // сервисы и свои домены других серверов — по профилю в порядке номеров туннелей
  const atSites: [string, Destination[]][] = profiles.slice(1).map((p): [string, Destination[]] => {
    const into: Destination[] = []
    addServices(services.filter((id) => serverOf(id) === p.id), into)
    for (const d of customs.filter((x) => domainServerOf(x) === p.id)) into.push({ type: 'domain_suffix', value: d })
    return [p.id, into]
  }).filter(([, d]) => d.length > 0)
  const zapretSites: Destination[] = []
  addServices(zapretServices, zapretSites)
  for (const d of uniqueDomains(s.zapretDomains)) zapretSites.push({ type: 'domain_suffix', value: d })
  const wsSites: Destination[] = []
  addServices(wsServices, wsSites)
  const except: Destination[] = uniqueDomains(s.exceptions).map((value) => ({ type: 'domain_suffix', value }))

  const groups: Group[] = []
  if (sites.length) groups.push(group(SITES, 'Сайты через VPN', sites))
  for (const [pid, d] of atSites) groups.push(group(SITES_AT + pid, `Сайты через VPN (${pid})`, d))
  if (zapretSites.length) groups.push(group(ZAPRET_SITES, 'Сайты с обходом блокировок', zapretSites))
  if (wsSites.length) groups.push(group(TG_SITES, 'Telegram через WebSocket', wsSites))
  if (except.length) groups.push(group(EXCEPT, 'Исключения', except))
  groups.push(group(ALL, 'Весь интернет', ALL_NETS))

  const names = new Map<string, string>()
  for (const d of base.devices) {
    const m = normalizeMac(d.mac)
    if (m) names.set(m, cleanName(d.name))
  }
  for (const [mac, n] of Object.entries(base.device_names ?? {})) {
    const m = normalizeMac(mac)
    if (m && cleanName(n)) names.set(m, cleanName(n))
  }
  for (const k of known) {
    const m = normalizeMac(k.mac)
    const n = cleanName(k.name)
    if (m && n) names.set(m, n)
  }
  const selectedMacs = s.devices === 'all' ? [] : [...new Set(s.devices.map(normalizeMac).filter((m): m is string => m !== null))]
  // «весь интернет через VPN» — только в режиме «выбранные»; в режиме «всё» так идут все устройства
  const allMacs = s.mode === 'all' ? [] : [...new Set((s.vpnAll ?? []).map(normalizeMac).filter((m): m is string => m !== null))]
  const devices: Device[] = [...new Set([...selectedMacs, ...allMacs])]
    .map((mac) => ({ id: deviceId(mac), name: names.get(mac) || mac, mac, network: HOME }))
  const sources: [string, Source][] = s.devices === 'all' ? [['lan', { type: 'lan' }]] : selectedMacs.map((m) => [deviceId(m), { type: 'device', id: deviceId(m) }])

  const vpnTarget = s.mode === 'all' ? ALL : sites.length ? SITES : null
  const lanAll = s.mode === 'all' && s.devices === 'all'
  const needsProfile = lanAll || allMacs.length > 0 || (vpnTarget !== null && sources.length > 0)
  if (needsProfile && !profile) throw new Error('сначала настройте сервер VPN')
  const toVpn: Action = { type: 'profile', id: profile?.id ?? '' }
  const toProfile = (id: string): Action => ({ type: 'profile', id })
  const deviceTo = (mac: string): Action => {
    const p = s.deviceServer?.[mac]
    return p && p !== profile?.id && known_.has(p) ? toProfile(p) : toVpn
  }

  const rules: Rule[] = []
  for (const mac of allMacs) {
    const key = deviceId(mac)
    const src: Source = { type: 'device', id: key }
    if (except.length) rules.push(rule(`except-${key}`, src, EXCEPT, rest, s.enabled))
    if (zapretSites.length) rules.push(rule(`zapret-${key}`, src, ZAPRET_SITES, { type: 'direct_zapret' }, true))
    if (wsSites.length) rules.push(rule(`tgws-${key}`, src, TG_SITES, { type: 'tg_ws' }, s.enabled))
    rules.push(rule(`vpnall-${key}`, src, ALL, deviceTo(mac), s.enabled))
  }
  for (const [key, src] of sources) {
    if (except.length) rules.push(rule(`except-${key}`, src, EXCEPT, rest, s.enabled))
    // обход блокировок без VPN от VPN не зависит: правило включено и при выключенном VPN
    if (zapretSites.length) rules.push(rule(`zapret-${key}`, src, ZAPRET_SITES, { type: 'direct_zapret' }, true))
    // Telegram через WebSocket выключается вместе с VPN: его запасной путь — VPN
    if (wsSites.length) rules.push(rule(`tgws-${key}`, src, TG_SITES, { type: 'tg_ws' }, s.enabled))
    // VPN выключен и выбрано «не открывать»: сайты из списка блокируются (только режим «выбранные»: в режиме «всё»
    // так закрылся бы весь интернет)
    const offBlock = !s.enabled && !!s.offBlock && s.mode === 'selected'
    const vpnRule = (id: string, g: string, a: Action) => rule(id, src, g, offBlock ? { type: 'block' } : a, s.enabled || offBlock)
    for (const [pid] of atSites) rules.push(vpnRule(`vpn-${key}--${pid}`, SITES_AT + pid, toProfile(pid)))
    if (vpnTarget) rules.push(vpnRule(`vpn-${key}`, vpnTarget, toVpn))
  }
  rules.push(rule(s.enabled ? REST_ON : REST_OFF, { type: 'lan' }, ALL, rest, false))

  const home: Network = { id: HOME, name: HOME_NAME, ssid: HOME_NAME, bridge: lan.bridge, subnet: lan.subnet }
  const out: Config = {
    version: 1,
    profiles: base.profiles,
    networks: [home],
    devices,
    groups,
    categories,
    rules,
    default_action: !s.enabled ? { type: 'direct' } : lanAll ? toVpn : rest,
  }
  if (base.dns !== undefined) out.dns = base.dns
  if (base.zapret !== undefined) out.zapret = base.zapret
  if (base.schedule !== undefined) out.schedule = base.schedule
  if (base.ipv6_via_vpn) out.ipv6_via_vpn = true
  if (base.device_names && Object.keys(base.device_names).length) out.device_names = base.device_names
  if (base.panel_origins?.length) out.panel_origins = base.panel_origins
  if (base.history) out.history = base.history
  if (s.offBlock) out.vpn_off_block = true
  if (s.tgwsVia !== undefined) out.tgws = s.tgwsVia && known_.has(s.tgwsVia) ? { via: s.tgwsVia } : {}
  return out
}

/** JSON с упорядоченными ключами, без undefined и с явным `enabled` у правил: для сравнения настроек. */
function canonicalJson(c: Config): string {
  const norm = { ...c, categories: c.categories ?? [], rules: c.rules.map((r) => ({ ...r, enabled: r.enabled ?? true })) }
  const sort = (v: unknown): unknown =>
    Array.isArray(v) ? v.map(sort)
    : v !== null && typeof v === 'object' ? Object.fromEntries(Object.keys(v).sort().filter((k) => (v as Record<string, unknown>)[k] !== undefined).map((k) => [k, sort((v as Record<string, unknown>)[k])]))
    : v
  return JSON.stringify(sort(norm))
}

const notSimple = (reason: string): FromConfig => ({ canonical: false, reason })

/** Ответы пользователя из настроек канонического вида; настройки, правленные вручную, — с причиной. */
export function fromConfig(cfg: Config): FromConfig {
  const home = cfg.networks[0]
  if (cfg.networks.length !== 1 || home?.id !== HOME || !home.bridge || !home.subnet) {
    return notSimple(t('сети настроены вручную: простой вид использует одну домашнюю сеть роутера'))
  }
  const groups = new Map(cfg.groups.map((g) => [g.id, g]))
  const marker = cfg.rules.find((r) => r.id === REST_ON || r.id === REST_OFF)
  if (!marker) return notSimple(t('правила изменены вручную'))
  const action = (r: Rule | undefined) => r?.action.type
  const restFrom = action(marker)
  if (restFrom !== 'direct' && restFrom !== 'direct_zapret') return notSimple(t('правила изменены вручную'))

  /** Сервисы и домены группы сайтов; ошибка — текстом. */
  const readSites = (id: string, services: string[], domains: string[]): string | null => {
    for (const d of groups.get(id)?.destinations ?? []) {
      if (d.type === 'domain_suffix') domains.push(d.value)
      else if (d.type === 'category') {
        const m = /^svc-(.+)$/.exec(d.id)
        const cat = cfg.categories?.find((c) => c.id === d.id)
        if (!m || !cat) return t('в списке сайтов есть категория «{id}», добавленная вручную', { id: d.id })
        if (cat.kind === 'domain') services.push(m[1]!)
      } else return t('в списке сайтов есть записи, добавленные вручную')
    }
    return null
  }
  const services: string[] = []
  const customDomains: string[] = []
  const zapretServices: string[] = []
  const zapretDomains: string[] = []
  const wsServices: string[] = []
  const wsDomains: string[] = []
  const bad = readSites(SITES, services, customDomains) ?? readSites(ZAPRET_SITES, zapretServices, zapretDomains) ?? readSites(TG_SITES, wsServices, wsDomains)
  if (bad) return notSimple(bad)
  if (wsDomains.length) return notSimple(t('в списке сайтов есть записи, добавленные вручную'))
  // сервисы других серверов
  const serviceServer: Record<string, string> = {}
  const domainServer: Record<string, string> = {}
  for (const g of cfg.groups.filter((x) => x.id.startsWith(SITES_AT))) {
    const pid = g.id.slice(SITES_AT.length)
    const svc: string[] = []
    const dom: string[] = []
    const e = readSites(g.id, svc, dom)
    if (e) return notSimple(e)
    for (const id of svc) { services.push(id); serviceServer[id] = pid }
    for (const d of dom) { customDomains.push(d); domainServer[d] = pid }
  }
  const defaultId = sortedProfiles(cfg.profiles)[0]?.id
  const exceptions: string[] = []
  for (const d of groups.get(EXCEPT)?.destinations ?? []) {
    if (d.type !== 'domain_suffix') return notSimple(t('в исключениях есть записи, добавленные вручную'))
    exceptions.push(d.value)
  }

  const working = cfg.rules.filter((r) => r !== marker)
  // устройства «весь интернет через VPN»: у них есть правило vpnall-<устройство>
  const allIds = [...new Set(working.flatMap((r) => (r.id.startsWith('vpnall-') && r.source.type === 'device' ? [r.source.id] : [])))]
  const vpnAll: string[] = []
  const deviceServer: Record<string, string> = {}
  for (const id of allIds) {
    const mac = normalizeMac(cfg.devices.find((x) => x.id === id)?.mac ?? '')
    if (!mac) return notSimple(t('устройство «{id}» настроено вручную', { id }))
    vpnAll.push(mac)
    const a = working.find((r) => r.id === `vpnall-${id}`)?.action
    if (a?.type === 'profile' && a.id !== defaultId) deviceServer[mac] = a.id
  }
  const regular = working.filter((r) => !(r.source.type === 'device' && allIds.includes(r.source.id)))
  const lanRules = regular.some((r) => r.source.type === 'lan')
  const ruleDevices = [...new Set(regular.flatMap((r) => (r.source.type === 'device' ? [r.source.id] : [])))]
  const devIds = lanRules ? [] : ruleDevices.length ? ruleDevices : cfg.devices.map((d) => d.id).filter((id) => !allIds.includes(id))
  const macs: string[] = []
  for (const id of devIds) {
    const d = cfg.devices.find((x) => x.id === id)
    const mac = d && normalizeMac(d.mac)
    if (!mac) return notSimple(t('устройство «{id}» настроено вручную', { id }))
    macs.push(mac)
  }
  const mode = regular.some((r) => r.destination.type === 'group' && r.destination.id === ALL) || cfg.default_action.type === 'profile' ? 'all' : 'selected'
  const simple: Simple = {
    enabled: marker.id === REST_ON,
    mode,
    services,
    customDomains,
    zapretServices,
    zapretDomains,
    exceptions,
    rest: restFrom === 'direct_zapret' ? 'zapret' : 'direct',
    devices: lanRules || macs.length === 0 ? 'all' : macs,
  }
  if (vpnAll.length) simple.vpnAll = vpnAll
  if (Object.keys(serviceServer).length) simple.serviceServer = serviceServer
  if (Object.keys(domainServer).length) simple.domainServer = domainServer
  if (Object.keys(deviceServer).length) simple.deviceServer = deviceServer
  if (wsServices.length) simple.wsServices = wsServices
  if (cfg.tgws) simple.tgwsVia = cfg.tgws.via ?? ''
  if (cfg.vpn_off_block) simple.offBlock = true

  // проверка: из этих ответов получаются ровно те же настройки
  const catalog: ListCatalog = { source: '', commit: '', date: '', services: [] }
  for (const id of [...services, ...zapretServices, ...wsServices]) {
    const dom = cfg.categories?.find((c) => c.id === `svc-${id}`)
    const ip = cfg.categories?.find((c) => c.id === `svc-${id}-ip`)
    const path = (c: Category | undefined) => (c?.source?.startsWith(SOURCE_PREFIX) ? c.source.slice(SOURCE_PREFIX.length) : '')
    catalog.services.push({ id, name: dom?.name ?? id, group: '', domains: path(dom), ipv4: ip ? path(ip) : null })
  }
  const known = cfg.devices.map((d) => ({ mac: d.mac, name: d.name }))
  let again: Config
  try {
    again = toConfig(cfg, simple, { bridge: home.bridge, subnet: home.subnet, address: '' }, catalog, known)
  } catch {
    return notSimple(t('правила ссылаются на профиль VPN, которого нет'))
  }
  if (canonicalJson(again) !== canonicalJson(cfg)) return notSimple(t('настройки изменены вручную и отличаются от простого вида'))
  return { canonical: true, simple }
}
