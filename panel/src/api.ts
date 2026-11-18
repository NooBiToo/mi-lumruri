// Типы повторяют схему v1 контроллера (controller/src/model.rs, preview.rs).

export type ProfileKind = 'trusttunnel' | 'vless' | 'hysteria2' | 'wireguard'

export interface Endpoint { server: string; port: number; sni?: string; username: string; cert_sha256?: string; quic?: boolean }
export interface Profile { id: string; name: string; kind: ProfileKind; on_failure: 'block' | 'direct'; endpoint?: Endpoint }
export interface Network { id: string; name: string; ssid: string; segment?: string; subnet?: string }
export interface Device { id: string; name: string; mac: string; network: string }

export type Destination =
  | { type: 'domain'; value: string }
  | { type: 'domain_suffix'; value: string }
  | { type: 'cidr'; value: string }
  | { type: 'group'; id: string }

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

const BASE: string = import.meta.env.VITE_API_BASE ?? 'cgi-bin/api'

async function call<T extends { ok: boolean; issues: Issue[]; error?: ApiError }>(path: string, init?: RequestInit): Promise<ApiResult<T>> {
  let res: Response
  try {
    res = await fetch(`${BASE}${path}`, { ...init, cache: 'no-store' })
  } catch (e) {
    return { status: 0, body: { ok: false, issues: [], error: { code: 'network', message: `контроллер недоступен: ${String(e)}` } } as unknown as T }
  }
  try {
    return { status: res.status, body: (await res.json()) as T }
  } catch {
    return { status: res.status, body: { ok: false, issues: [], error: { code: 'bad_response', message: `ответ ${res.status} не является JSON` } } as unknown as T }
  }
}

export const api = {
  config: () => call<ConfigResponse>('/config'),
  preview: (req: PreviewRequest) =>
    call<PreviewResponse>('/preview', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(req) }),
  // Браузер сам добавляет Origin и Sec-Fetch-Site; контроллер принимает запись только с origin панели.
  saveRule: (base_revision: string, rule: Rule) =>
    call<SaveResponse>('/rules', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ base_revision, rule }) }),
}
