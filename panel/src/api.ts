// Типы повторяют схему v1 контроллера (controller/src/model.rs, preview.rs).

/** Единственный вид VPN — TrustTunnel (официальный клиент). Профиль может быть только один. */
export type ProfileKind = 'trusttunnel'

export interface Endpoint {
  /** IP-адрес сервера; доменное имя для TLS — в `sni`. */
  server: string
  port: number
  /** Имя сервера в сертификате (TLS). Без него — адрес сервера. */
  sni?: string
  username: string
  /** HTTP/3 (QUIC) вместо HTTP/2. */
  quic: boolean
  /** Защита от DPI на стороне клиента. */
  anti_dpi: boolean
  /** Сертификат сервера (PEM) для самоподписанного сервера. */
  certificate?: string
}
export interface Profile { id: string; name: string; kind: ProfileKind; on_failure: 'block' | 'direct'; endpoint?: Endpoint }
export interface Network { id: string; name: string; ssid: string; segment?: string; subnet?: string; bridge?: string; ports?: string[] }
export interface Device { id: string; name: string; mac: string; network: string }

export type Destination =
  | { type: 'domain'; value: string }
  | { type: 'domain_suffix'; value: string }
  | { type: 'cidr'; value: string }
  | { type: 'group'; id: string }
  | { type: 'category'; id: string }

export interface Category { id: string; name: string; kind: 'domain' | 'ip'; source?: string }
export interface DnsConfig {
  /** Публичный IPv4 DNS-сервера для доменов, идущих через TrustTunnel; запросы к нему идут через туннель. По умолчанию 1.1.1.1. */
  tunnel_resolver?: string
  adblock?: { enabled: boolean; exceptions?: string[] }
}
export interface ZapretConfig { strategy: 'multisplit' | 'multidisorder'; pos?: number; tcp_ports?: number[] }
export interface ProfileSecret { password: string }

export interface Group { id: string; name: string; destinations: Destination[] }

export type Source = { type: 'device'; id: string } | { type: 'network'; id: string } | { type: 'lan' }
export type Action = { type: 'profile'; id: string } | { type: 'direct' } | { type: 'direct_zapret' } | { type: 'block' }

export interface Rule { id: string; source: Source; destination: Destination; action: Action; enabled: boolean }

export interface Config {
  version: number
  profiles: Profile[]
  networks: Network[]
  devices: Device[]
  groups: Group[]
  rules: Rule[]
  default_action: Action
  categories?: Category[]
  dns?: DnsConfig
  zapret?: ZapretConfig
}

export interface Issue { path: string; code: string; message: string }

export interface Probe { device?: string; network?: string; host: string }
export interface PreviewRequest { rule: Rule; probes: Probe[] }

export interface Decision { rule_id: string | null; exit: string }
export interface Finding { severity: 'warning' | 'info'; code: string; message: string }

export interface Preview {
  applied: false
  mode: 'add' | 'replace'
  rule: Rule
  level: number
  level_label: string
  position: number
  order: { position: number; rule_id: string; level: number; source: string; destination: string; exit: string; draft: boolean }[]
  destinations: string[]
  affected_devices: { id: string; name: string; mac: string; network: string }[]
  affects_unknown_clients: boolean
  exit: string
  on_failure: string | null
  findings: Finding[]
  match_entries: { position: number; source: string; destination: string; exit: string; on_failure: string | null }[]
  probes: { subject: string; host: string; before: Decision; after: Decision; changed: boolean }[]
}

export interface ApiError { code: string; message: string }

export interface ConfigResponse { ok: boolean; schema_version: number; revision: string | null; config: Config | null; issues: Issue[]; error?: ApiError }
export interface SaveResponse {
  ok: boolean
  mode?: 'add' | 'replace'
  previous_revision?: string
  revision?: string
  rule_id?: string
  config?: Config
  current_revision?: string
  issues: Issue[]
  error?: ApiError
}
export interface PreviewResponse { ok: boolean; preview?: Preview; issues: Issue[]; error?: ApiError }

/** Ответ API с HTTP-статусом. Сетевые сбои и не-JSON превращаются в status 0 с понятной ошибкой. */
export interface ApiResult<T> { status: number; body: T }

export interface SessionResponse {
  ok: boolean
  authenticated?: boolean
  stage?: 'password' | 'second_factor' | 'done'
  /** Включён ли второй фактор (TOTP); без него вход только паролем. */
  totp?: boolean
  csrf?: string
  expires?: number
  idle_timeout?: number
  recovery_codes_left?: number
  clock_trusted?: boolean
  methods?: string[]
  retry_after?: number
  issues: Issue[]
  error?: ApiError
}
export type SecondFactor = { totp: string } | { recovery_code: string }

const BASE: string = import.meta.env.VITE_API_BASE ?? 'cgi-bin/api'

/** CSRF-токен текущей сессии: контроллер выдаёт его после входа, панель отправляет в X-MITT-CSRF с каждым POST. */
let csrf: string | null = null
/** Вызывается, когда контроллер ответил 401 на защищённый адрес (сессия истекла, отозвана или её нет). */
let onUnauthorized: (() => void) | null = null

export function setCsrf(token: string | null): void {
  csrf = token
}
export function onAuthLost(fn: (() => void) | null): void {
  onUnauthorized = fn
}

async function call<T extends { ok: boolean; issues: Issue[]; error?: ApiError }>(path: string, init?: RequestInit): Promise<ApiResult<T>> {
  let res: Response
  const headers = new Headers(init?.headers)
  if (init?.method === 'POST' && csrf) headers.set('X-MITT-CSRF', csrf)
  try {
    // cookie сессии HttpOnly: браузер отправляет его сам только на тот же origin
    res = await fetch(`${BASE}${path}`, { ...init, headers, cache: 'no-store', credentials: 'same-origin' })
  } catch (e) {
    return { status: 0, body: { ok: false, issues: [], error: { code: 'network', message: `контроллер недоступен: ${String(e)}` } } as unknown as T }
  }
  let body: T
  try {
    body = (await res.json()) as T
  } catch {
    return { status: res.status, body: { ok: false, issues: [], error: { code: 'bad_response', message: `ответ ${res.status} не является JSON` } } as unknown as T }
  }
  if (res.status === 401 && !path.startsWith('/auth/')) {
    csrf = null
    onUnauthorized?.()
  }
  return { status: res.status, body }
}

const json = (body: unknown): RequestInit => ({ method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })

/** Клиент из аренд DHCP роутера; hostname — данные клиента LAN, показываются только как текст. */
export interface Lease { mac: string; ip: string; hostname: string; device: string | null }

export interface ManageResponse {
  ok: boolean
  mode?: string
  revision?: string
  config?: Config
  current_revision?: string
  profiles?: Record<string, boolean>
  domains?: number
  entries?: number
  queued?: boolean
  service?: unknown
  apply_pending?: boolean
  leases?: Lease[]
  issues: Issue[]
  error?: ApiError
}

/** LAN роутера из uci (`network.lan`): мост, подсеть и адрес роутера. */
export interface Lan { bridge: string; subnet: string; address: string }
export interface RouterResponse { ok: boolean; lan?: Lan; issues: Issue[]; error?: ApiError }

/** Запись каталога готовых списков (снимок itdoginfo/allow-domains в пакете). */
export interface CatalogService { id: string; name: string; group: string; domains: string; ipv4: string | null }
export interface ListCatalog { source: string; commit: string; date: string; services: CatalogService[] }
/** Итог последней проверки обновлений списков (mitt-lists.sh update); время — unix-секунды. */
export interface ListsStatus { snapshot: string; updated: number | null; checked: number; ok: boolean; errors: string[] }
export interface ListsResponse { ok: boolean; catalog?: ListCatalog; status?: ListsStatus | null; requested?: boolean; queued?: boolean; issues: Issue[]; error?: ApiError }

/** Состояние подбора стратегии Zapret (mitt-zapret-test.sh); до первого подбора — только `state: 'idle'`. */
export interface ZapretTestState {
  state: 'idle' | 'running' | 'done' | 'failed'
  pid?: number
  started?: number
  finished?: number | null
  progress?: { done: number; total: number; current: string }
  /** Сколько целей открылось без Zapret. */
  control?: { opened: number; total: number }
  best?: { id: string; opened: number } | null
  youtube?: { id: string; opened: number; total: number } | null
  applied?: boolean
  message?: string
}
export interface ZapretTestResponse { ok: boolean; test?: ZapretTestState; requested?: boolean; queued?: boolean; issues: Issue[]; error?: ApiError }

/** Ответ замены настроек целиком: при успехе — новая ревизия, настройки и заявка на применение (`queued`). */
export interface ReplaceResponse extends SaveResponse { queued?: boolean }

export const manage = {
  deleteRule: (base_revision: string, id: string) => call<ManageResponse>('/rules/delete', json({ base_revision, id })),
  moveRule: (base_revision: string, id: string, position: number) => call<ManageResponse>('/rules/move', json({ base_revision, id, position })),
  saveProfile: (base_revision: string, profile: Profile) => call<ManageResponse>('/profiles', json({ base_revision, profile })),
  deleteProfile: (base_revision: string, id: string) => call<ManageResponse>('/profiles/delete', json({ base_revision, id })),
  saveCategory: (base_revision: string, category: Category) => call<ManageResponse>('/categories', json({ base_revision, category })),
  deleteCategory: (base_revision: string, id: string) => call<ManageResponse>('/categories/delete', json({ base_revision, id })),
  categoryList: (id: string, list: string) => call<ManageResponse>('/categories/list', json({ id, list })),
  saveNetwork: (base_revision: string, network: Network) => call<ManageResponse>('/networks', json({ base_revision, network })),
  deleteNetwork: (base_revision: string, id: string) => call<ManageResponse>('/networks/delete', json({ base_revision, id })),
  saveDevice: (base_revision: string, device: Device) => call<ManageResponse>('/devices', json({ base_revision, device })),
  deleteDevice: (base_revision: string, id: string) => call<ManageResponse>('/devices/delete', json({ base_revision, id })),
  leases: () => call<ManageResponse>('/leases'),
  saveDns: (base_revision: string, dns: DnsConfig | null) => call<ManageResponse>('/dns', json({ base_revision, dns })),
  adblockList: (list: string) => call<ManageResponse>('/adblock/list', json({ list })),
  saveZapret: (base_revision: string, zapret: ZapretConfig | null) => call<ManageResponse>('/zapret', json({ base_revision, zapret })),
  secrets: () => call<ManageResponse>('/secrets'),
  // секрет только записывается: панель не получает его обратно
  setSecret: (profile_id: string, secret: ProfileSecret) => call<ManageResponse>('/secrets', json({ profile_id, secret })),
  applyRequest: () => call<ManageResponse>('/apply-request', json({})),
  status: () => call<ManageResponse>('/status'),
}

export const api = {
  config: () => call<ConfigResponse>('/config'),
  preview: (req: PreviewRequest) => call<PreviewResponse>('/preview', json(req)),
  // Браузер сам добавляет Origin и Sec-Fetch-Site; контроллер принимает запись только с origin панели, с сессией и CSRF.
  saveRule: (base_revision: string, rule: Rule) => call<SaveResponse>('/rules', json({ base_revision, rule })),
  session: () => call<SessionResponse>('/auth/session'),
  login: (password: string) => call<SessionResponse>('/auth/login', json({ password })),
  second: (factor: SecondFactor) => call<SessionResponse>('/auth/second', json(factor)),
  logout: () => call<SessionResponse>('/auth/logout', json({})),
  router: () => call<RouterResponse>('/router'),
  /** Замена настроек целиком с проверкой ревизии; контроллер сразу ставит заявку на применение. */
  replaceConfig: (base_revision: string, config: Config) => call<ReplaceResponse>('/config', json({ base_revision, config })),
  lists: () => call<ListsResponse>('/lists'),
  updateLists: () => call<ListsResponse>('/lists/update', json({})),
  zapretTest: () => call<ZapretTestResponse>('/zapret/test'),
  startZapretTest: () => call<ZapretTestResponse>('/zapret/test', json({ mode: 'quick' })),
}
