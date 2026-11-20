// Типы повторяют схему v1 контроллера (controller/src/model.rs).

/** Единственный вид VPN — TrustTunnel (официальный клиент). Профиль может быть только один. */
export type ProfileKind = 'trusttunnel'

export interface Endpoint {
  /** IP-адрес или доменное имя сервера (домен разрешает клиент TrustTunnel на роутере). */
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
export interface HostRecord { domain: string; address: string }
export type AdblockSource = 'light' | 'normal' | 'url'
export type SecureServer = 'cloudflare' | 'quad9' | 'google' | 'adguard' | 'nextdns' | 'custom'
export interface SecureDns { protocol: 'doh' | 'dot'; server: SecureServer; nextdns_id?: string; url?: string; ips?: string[] }
/** Состояние прокси DoH/DoT (mi-tt-dns), раз в 15 секунд. */
export interface DnsProxyStatus { at: number; upstream: string; queries: number; upstream_ok: number; fallback: number; failed: number; last_ok: number | null; last_error: string | null }
/** Итог последней загрузки списка рекламы службой; время — unix-секунды. */
export interface AdblockStatus { ok: boolean; checked: number; updated: number | null; domains: number | null; url: string; error: string | null }
export type ListsUpdate = '6h' | 'daily' | 'weekly' | 'manual'
export type ZapretCheck = 'off' | 'daily' | 'weekly'
export interface ScheduleConfig { lists?: ListsUpdate; zapret_check?: ZapretCheck }

export interface DnsConfig {
  /** Публичный IPv4 DNS-сервера для доменов, идущих через TrustTunnel; запросы к нему идут через туннель. По умолчанию 1.1.1.1. */
  tunnel_resolver?: string
  /** Блокировка рекламы: список HaGeZi Light (по умолчанию), Normal или своя ссылка; скачивает служба. */
  adblock?: { enabled: boolean; exceptions?: string[]; source?: AdblockSource; url?: string }
  /** Защищённый DNS (DoH/DoT) для доменов, которые не идут через VPN. */
  secure?: SecureDns
  /** Свои записи: домен вместе с поддоменами отвечает адресом (IPv4 или IPv6). */
  hosts?: HostRecord[]
}
/** Выбор стратегий Zapret (controller/src/model.rs): `auto` — круговой режим, иначе id стратегии каталога. */
export interface ZapretConfig { strategy: string; youtube: string }
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
  /** Как часто служба сама обновляет списки сайтов и перепроверяет способ Zapret. */
  schedule?: ScheduleConfig
  zapret?: ZapretConfig
}

export interface Issue { path: string; code: string; message: string }

export interface ApiError { code: string; message: string }

export interface ConfigResponse { ok: boolean; schema_version: number; revision: string | null; config: Config | null; issues: Issue[]; error?: ApiError }
export interface SaveResponse {
  ok: boolean
  previous_revision?: string
  revision?: string
  config?: Config
  current_revision?: string
  issues: Issue[]
  error?: ApiError
}

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
  adblock?: AdblockStatus | null
  dns_proxy?: DnsProxyStatus | null
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

/** Диагностика службы (mitt-diag.sh): ok — работает, warn — с оговоркой, bad — не работает, skip — не используется. */
export type DiagStatus = 'ok' | 'warn' | 'bad' | 'skip'
export interface DiagCheck { id: string; status: DiagStatus; detail: string }
/** Пробный запрос к сайту: код 0 — нет ответа; время — секунды. */
export interface DiagProbe { code: number; seconds: number | null }
export interface DiagSite { domain: string; ip: string | null; route: 'tunnel' | 'direct' | 'zapret' | 'block' | null; direct: DiagProbe | null; tunnel: DiagProbe | null }
export interface DiagResponse {
  ok: boolean; running?: boolean; started?: number | null; finished?: number | null; checks?: DiagCheck[]; site?: DiagSite | null
  logs?: { service: string[]; trusttunnel: string[]; nfqws2: string[] }; queued?: boolean; issues: Issue[]; error?: ApiError
}

/** Состояние подбора стратегии Zapret (mitt-zapret-test.sh); до первого подбора — только `state: 'idle'`. */
export interface ZapretTestState {
  state: 'idle' | 'running' | 'done' | 'failed'
  pid?: number
  started?: number
  finished?: number | null
  progress?: { done: number; total: number; current: string }
  /** Сколько целей открылось без Zapret. */
  control?: { opened: number; total: number }
  /** Лучший результат прохода «все сайты» (даже если он не применён). */
  best?: { id: string; opened: number } | null
  /** Применена ли стратегия для всех сайтов (нет в файлах до 0.3.0). */
  general?: boolean
  /** Применённая стратегия YouTube: сколько целей YouTube открылось, из скольких и сколько без обхода. */
  youtube?: { id: string; opened: number; total: number; control?: number } | null
  applied?: boolean
  message?: string
}
export interface ZapretTestResponse { ok: boolean; test?: ZapretTestState; requested?: boolean; queued?: boolean; issues: Issue[]; error?: ApiError }

/** Ответ замены настроек целиком: при успехе — новая ревизия, настройки и заявка на применение (`queued`). */
export interface ReplaceResponse extends SaveResponse { queued?: boolean }

export const manage = {
  leases: () => call<ManageResponse>('/leases'),
  secrets: () => call<ManageResponse>('/secrets'),
  // секрет только записывается: панель не получает его обратно
  setSecret: (profile_id: string, secret: ProfileSecret) => call<ManageResponse>('/secrets', json({ profile_id, secret })),
  applyRequest: () => call<ManageResponse>('/apply-request', json({})),
  status: () => call<ManageResponse>('/status'),
}

export const api = {
  config: () => call<ConfigResponse>('/config'),
  session: () => call<SessionResponse>('/auth/session'),
  login: (password: string) => call<SessionResponse>('/auth/login', json({ password })),
  second: (factor: SecondFactor) => call<SessionResponse>('/auth/second', json(factor)),
  logout: () => call<SessionResponse>('/auth/logout', json({})),
  router: () => call<RouterResponse>('/router'),
  /**
   * Замена настроек целиком с проверкой ревизии; контроллер сразу ставит заявку на применение. Браузер сам добавляет
   * Origin и Sec-Fetch-Site; контроллер принимает запись только с origin панели, с сессией и CSRF.
   */
  replaceConfig: (base_revision: string, config: Config) => call<ReplaceResponse>('/config', json({ base_revision, config })),
  lists: () => call<ListsResponse>('/lists'),
  updateLists: () => call<ListsResponse>('/lists/update', json({})),
  zapretTest: () => call<ZapretTestResponse>('/zapret/test'),
  startZapretTest: () => call<ZapretTestResponse>('/zapret/test', json({ mode: 'quick' })),
  /** Выбор способов обхода (раздел `zapret`) с проверкой ревизии. Заявку на применение контроллер здесь не ставит. */
  setZapret: (base_revision: string, zapret: ZapretConfig | null) => call<SaveResponse>('/zapret', json({ base_revision, zapret })),
  diag: () => call<DiagResponse>('/diag'),
  runDiag: (site?: string) => call<DiagResponse>('/diag', json(site ? { site } : {})),
  restartService: () => call<DiagResponse>('/service/restart', json({})),
}
