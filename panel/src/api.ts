// Типы повторяют схему v1 контроллера (controller/src/model.rs).
import { t } from './i18n'

/** Единственный вид VPN — TrustTunnel (официальный клиент). Профиль может быть только один. */
export type ProfileKind = 'trusttunnel' | 'vless' | 'hysteria2' | 'trojan' | 'shadowsocks'
/** Сводка сервера модуля sing-box (сам сервер — ссылка в секретах). */
export interface ProxyInfo { server: string; port: number; security?: string; transport?: string }

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
  /** Отпечаток TLS ClientHello, под который маскируется клиент (TrustTunnel 1.3). Без поля — chrome. */
  tls_profile?: TlsProfile
  /** Префикс client_random (hex, «префикс/маска»), если сервер пускает только по нему. */
  client_random?: string
  /** Ключ client_random (hex, сервер 1.3): client_random выводится из ключа. Задаётся что-то одно с префиксом. */
  client_random_auth_key?: string
}
export type TlsProfile = 'chrome' | 'chrome_canary' | 'safari' | 'firefox' | 'okhttp' | 'openssl' | 'boringssl'
/** Профиль TrustTunnel; backup — запасной сервер (пароль — backup_password в секретах). */
export interface Profile { id: string; name: string; kind: ProfileKind; on_failure: 'block' | 'direct'; tunnel?: number; endpoint?: Endpoint; backup?: Endpoint; prefer_fastest?: boolean; proxy?: ProxyInfo }
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
export type UpdateCheck = 'daily' | 'weekly' | 'manual'
export interface ScheduleConfig { lists?: ListsUpdate; zapret_check?: ZapretCheck; update_check?: UpdateCheck }

export interface DnsConfig {
  /** Публичный IPv4 DNS-сервера для доменов, идущих через TrustTunnel; запросы к нему идут через туннель. По умолчанию 1.1.1.1. */
  tunnel_resolver?: string
  /** DoH/DoT поверх туннеля для доменов VPN (только готовые серверы). */
  tunnel_secure?: 'doh' | 'dot'
  /** Блокировка рекламы: список HaGeZi Light (по умолчанию), Normal или своя ссылка; скачивает служба. */
  adblock?: { enabled: boolean; exceptions?: string[]; source?: AdblockSource; url?: string }
  /** Защищённый DNS (DoH/DoT) для доменов, которые не идут через VPN. */
  secure?: SecureDns
  /** Свои записи: домен вместе с поддоменами отвечает адресом (IPv4 или IPv6). */
  hosts?: HostRecord[]
  /** Профиль, через туннель которого идут DNS-вопросы (несколько серверов). */
  tunnel_profile?: string
}
/** Выбор стратегий Zapret (controller/src/model.rs): `auto` — круговой режим, иначе id стратегии каталога. */
export interface ZapretConfig { strategy: string; youtube: string }
/** Секреты профиля: поля без значения не меняются; пустая ссылка-подписка — удалить её. */
export interface ProfileSecret { password?: string; subscription_url?: string; backup_password?: string; link?: string }

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
  /** IPv6 через VPN для источников «весь интернет через VPN». */
  ipv6_via_vpn?: boolean
  /** Имена устройств от пользователя (MAC → имя): только для экрана «Устройства». */
  device_names?: Record<string, string>
  /** Дополнительные адреса панели (https://хост[:порт]), например обратный прокси. */
  panel_origins?: string[]
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
    return { status: 0, body: { ok: false, issues: [], error: { code: 'network', message: t('контроллер недоступен: {e}', { e: String(e) }) } } as unknown as T }
  }
  let body: T
  try {
    body = (await res.json()) as T
  } catch {
    return { status: res.status, body: { ok: false, issues: [], error: { code: 'bad_response', message: t('ответ {s} не является JSON', { s: res.status }) } } as unknown as T }
  }
  if (res.status === 401 && !path.startsWith('/auth/')) {
    csrf = null
    onUnauthorized?.()
  }
  return { status: res.status, body }
}

const json = (body: unknown): RequestInit => ({ method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })

/** Клиент из аренд DHCP роутера; hostname — данные клиента LAN, показываются только как текст. */
/** Что устройство объявило о себе в сети (mDNS, SSDP): имя, тип (tv, phone, tablet, computer, printer, speaker…), модель. */
export interface FoundName { name: string; kind?: string; model?: string; source: 'mdns' | 'ssdp'; seen: number }
/**
 * Устройство из аренд DHCP. hostname — имя, которое устройство сообщило при подключении; name — имя от пользователя;
 * vendor — производитель по MAC (таблица прошивки); random — случайный (приватный) MAC; link — подключение по trafficd.
 */
export interface Lease {
  mac: string; ip: string; hostname: string; device: string | null
  name?: string | null; vendor?: string | null; icon?: string | null; random?: boolean; found?: FoundName | null; link?: Record<string, string> | null
}

export interface ManageResponse {
  ok: boolean
  adblock?: AdblockStatus | null
  dns_proxy?: DnsProxyStatus | null
  dns_tunnel?: DnsProxyStatus | null
  mode?: string
  revision?: string
  config?: Config
  current_revision?: string
  profiles?: Record<string, boolean>
  /** Есть ли у профиля ссылка-подписка (значение панель не получает). */
  subscriptions?: Record<string, boolean>
  /** Сохранён ли пароль запасного сервера. */
  backups?: Record<string, boolean>
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

/** Обновление из релизов GitHub (mitt-update.sh); время — unix-секунды, ключи — отпечатки (16 знаков). */
export interface UpdateState {
  state: 'checking' | 'ready' | 'downloading' | 'installing' | 'restarting' | 'verifying' | 'done' | 'error'
  at: number
  installed: string
  latest: string
  available: string
  newer: boolean
  page: string
  published: string
  error: string | null
  /** Новая версия не заработала после перезапуска и возвращена прежняя (failed — версия, которая не заработала). */
  rolled_back?: boolean
  failed?: string
  /** Ключ пакета, если установщик отказал из-за другого ключа подписи. */
  package_key: string | null
  /** Отпечаток ключа релизов GitHub: только на него панель предлагает перейти. */
  official_key: string
}
/** Резервная копия настроек (controller/src/backup.rs): secrets — зашифрованная паролем копии часть. */
export interface BackupFile { format: 'mi-lumruri-backup'; version: number; created: number; config: unknown; lists?: Record<string, string>; secrets?: unknown }
export interface BackupExportResponse { ok: boolean; backup?: BackupFile; issues: Issue[]; error?: ApiError }
export interface BackupRestoreResponse {
  ok: boolean; revision?: string; restored?: { config: boolean; lists: number; secrets: boolean; auth: boolean }
  secrets_skipped?: boolean; warnings?: string[]; issues: Issue[]; error?: ApiError
}
/** Уведомления в Telegram (controller/src/notify.rs): токен API не отдаёт; last — итог последней отправки службой. */
export interface NotifyResponse {
  ok: boolean; configured: boolean; chat_id: string | null; events: string[]; lang: string | null
  last: { ok: boolean; at: number; sent: number; via: string; error: string | null } | null; test_pending?: boolean; issues: Issue[]; error?: ApiError
}
export interface NotifySet { telegram_token?: string; chat_id?: string; events?: string[]; lang?: string; disable?: boolean }
/** Статистика трафика (controller/src/stats.rs): байты; devices — по MAC (или IP без аренды), имя из настроек или аренды. */
/** Накопитель (GET /storage): байты; vendor/model — из sysfs, если есть. */
export interface StorageDrive { path: string; device: string; fs: string; total: number; free: number; writable: boolean; exec: boolean; vendor?: string; model?: string }
export interface StorageInfo { at: number | null; data: StorageDrive | null; usb: StorageDrive[] }
export interface StorageResponse { ok: boolean; issues: Issue[]; error?: ApiError; storage: StorageInfo }

/** Модуль (GET /modules): каталог пакета и установленная копия. */
export interface ModuleInfo {
  name: string; title: string; version: string; protocols: string[]; kinds: ProfileKind[]
  download_bytes: number; need_bytes: number; ram_bytes: number
  installed: null | { version: string; path: string; installed: number; state: 'ok' | 'missing' | 'bad' | 'unknown'; update: boolean }
  used_by: string[]
}
export interface ModulesResponse {
  ok: boolean; issues: Issue[]; error?: ApiError; modules: ModuleInfo[]; running: boolean
  op: null | { state: 'running' | 'done' | 'failed'; action: string; name: string; at: number; message: string | null }
}

export interface StatsResponse {
  ok: boolean; since: number | null; sampled: number | null; per_device: boolean
  vpn: { day: number; week: number }; wan: { day: number; week: number }
  hours: { t: number; vpn: number; wan: number }[]
  devices: { key: string; name: string | null; known: boolean; day: number; week: number }[]
  issues: Issue[]; error?: ApiError
}
/** Замер скорости и задержки (mitt-speed.sh): Мбит/с по пути или ошибка; задержка — мс до TCP-подключения. */
export type SpeedPath = { mbps: number; bytes: number } | { error: string }
export interface SpeedState { state: 'running' | 'done'; started: number; at: number; ping: { primary: number | null; backup: number | null }; direct: SpeedPath | null; tunnel: SpeedPath | null }
export interface SpeedResponse { ok: boolean; running?: boolean; speed: SpeedState | null; issues: Issue[]; error?: ApiError }
export interface UpdateResponse { ok: boolean; running?: boolean; update?: UpdateState | null; queued?: boolean; issues: Issue[]; error?: ApiError }

/** Итог обновления по подписке TrustTunnel (mitt-sub.sh); время — unix-секунды; updated — когда параметры менялись. */
export interface SubscriptionState { ok: boolean; checked: number; updated: number | null; error: string | null }
export interface SubscriptionResponse { ok: boolean; running?: boolean; subscription?: SubscriptionState | null; queued?: boolean; issues: Issue[]; error?: ApiError }

/** Ответ замены настроек целиком: при успехе — новая ревизия, настройки и заявка на применение (`queued`). */
export interface ReplaceResponse extends SaveResponse { queued?: boolean }

export const manage = {
  leases: () => call<ManageResponse>('/leases'),
  secrets: () => call<ManageResponse>('/secrets'),
  // секрет только записывается: панель не получает его обратно
  setSecret: (profile_id: string, secret: ProfileSecret) => call<ManageResponse>('/secrets', json({ profile_id, secret })),
  applyRequest: () => call<ManageResponse>('/apply-request', json({})),
  /** Имя устройства (пустое — убрать); заявку на применение не ставит. */
  setDeviceName: (base_revision: string, mac: string, name: string) => call<SaveResponse>('/device-name', json({ base_revision, mac, name })),
  /** Поиск имён, которые устройства объявляют в сети (служба, несколько секунд). */
  discover: () => call<ManageResponse>('/discover', json({})),
  /** Адреса панели целиком (заменяет список); заявку на применение не ставит. */
  setPanelOrigins: (base_revision: string, origins: string[]) => call<SaveResponse>('/panel-origins', json({ base_revision, origins })),
  notifyState: () => call<NotifyResponse>('/notify'),
  stats: () => call<StatsResponse>('/stats'),
  storage: () => call<StorageResponse>('/storage'),
  modules: () => call<ModulesResponse>('/modules'),
  installModule: (name: string, target: string) => call<ManageResponse>('/modules/install', json({ name, target })),
  removeModule: (name: string) => call<ManageResponse>('/modules/remove', json({ name })),
  speed: () => call<SpeedResponse>('/speed'),
  startSpeed: () => call<SpeedResponse>('/speed', json({})),
  setNotify: (b: NotifySet) => call<ManageResponse>('/notify', json(b)),
  testNotify: () => call<ManageResponse>('/notify/test', json({})),
  exportBackup: (secrets: boolean, passphrase?: string) => call<BackupExportResponse>('/backup/export', json({ secrets, passphrase })),
  restoreBackup: (base_revision: string, backup: BackupFile, passphrase?: string, skip_secrets = false) =>
    call<BackupRestoreResponse>('/backup/restore', json({ base_revision, backup, passphrase, skip_secrets })),
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
  update: () => call<UpdateResponse>('/update'),
  subscription: () => call<SubscriptionResponse>('/subscription'),
  updateSubscription: () => call<SubscriptionResponse>('/subscription/update', json({})),
  checkUpdate: () => call<UpdateResponse>('/update', json({ action: 'check' })),
  installUpdate: (trust_official = false) => call<UpdateResponse>('/update', json({ action: 'install', trust_official })),
}
