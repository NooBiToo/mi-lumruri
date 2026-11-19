// Общие данные экранов после входа: настройки и ревизия, каталог списков, LAN роутера, аренды DHCP, состояние службы.
// Сохраняет любой экран одной функцией `save` (замена настроек целиком, POST /config).

import { computed, ref } from 'vue'
import { api, manage, type ApiResult, type Config, type Lan, type Lease, type ListsResponse, type ManageResponse, type ReplaceResponse } from './api'
import { knownDevices, readSimple, tunnelState } from './status'
import { HOME, toConfig, type KnownDevice, type Simple } from './simple'

export const config = ref<Config | null>(null)
export const revision = ref<string | null>(null)
export const loadError = ref<string | null>(null)
export const lists = ref<ListsResponse | null>(null)
export const lan = ref<Lan | null>(null)
export const lanError = ref<string | null>(null)
export const leases = ref<Lease[]>([])
export const service = ref<ManageResponse | null>(null)
export const hasPassword = ref(false)

export const catalog = computed(() => lists.value?.catalog ?? null)
export const simpleState = computed(() => (config.value ? readSimple(config.value) : null))
export const simple = computed<Simple | null>(() => (simpleState.value?.canonical ? simpleState.value.simple : null))
export const profile = computed(() => config.value?.profiles[0] ?? null)
export const serverReady = computed(() => !!profile.value?.endpoint)
export const tunnel = computed(() => tunnelState(service.value, config.value, simple.value))

/** Сообщение пользователю (тост); App подставляет свою реализацию. */
export const notify = { show: (_kind: 'success' | 'error' | 'info', _text: string, _detail?: string) => {} }

export function reset() {
  config.value = null
  revision.value = null
  loadError.value = null
  lists.value = null
  lan.value = null
  leases.value = []
  service.value = null
  hasPassword.value = false
}

export async function loadConfig(): Promise<boolean> {
  const r = await api.config()
  if (r.body.ok && r.body.config && r.body.revision) {
    config.value = r.body.config
    revision.value = r.body.revision
    loadError.value = null
    return true
  }
  loadError.value = r.body.error?.message ?? `контроллер ответил ${r.status}`
  return false
}

export async function loadStatus() {
  service.value = (await manage.status()).body
}

export async function loadLists() {
  const r = await api.lists()
  if (r.body.ok) lists.value = r.body
}

export async function loadLeases() {
  const r = await manage.leases()
  if (r.status === 200) leases.value = r.body.leases ?? []
}

async function loadLan() {
  const r = await api.router()
  if (r.body.ok && r.body.lan) {
    lan.value = r.body.lan
    lanError.value = null
  } else lanError.value = r.body.error?.message ?? 'сеть роутера не прочитана'
}

export async function loadSecrets() {
  const r = await manage.secrets()
  const id = profile.value?.id
  hasPassword.value = !!(id && r.body.profiles?.[id])
}

export async function loadAll(): Promise<void> {
  if (!(await loadConfig())) return
  await Promise.all([loadStatus(), loadLists(), loadLeases(), loadLan(), loadSecrets()])
}

/** LAN для простых настроек: с роутера, а если он не ответил — из уже сохранённой домашней сети. */
export function currentLan(): Lan | null {
  if (lan.value) return lan.value
  const home = config.value?.networks.find((n) => n.id === HOME)
  return home?.bridge && home.subnet ? { bridge: home.bridge, subnet: home.subnet, address: '' } : null
}

/** Почему нельзя собрать простые настройки прямо сейчас (или null, если можно). */
export function buildBlocker(): string | null {
  if (!config.value) return 'Настройки ещё не загружены.'
  if (!catalog.value) return 'Каталог сайтов ещё не загружен — подождите или обновите страницу.'
  if (!currentLan()) return `Не удалось узнать домашнюю сеть роутера${lanError.value ? ` (${lanError.value})` : ''}.`
  return null
}

/** Устройства с именами для `toConfig` без переименований: имена из настроек не меняются. */
export function knownDevicesNow(renames: Record<string, string> = {}): KnownDevice[] {
  return config.value ? knownDevices(leases.value, config.value, renames) : []
}

/** Простые настройки → полные настройки контроллера; ошибка — текстом для пользователя. */
export function build(s: Simple, known: KnownDevice[]): Config | string {
  const b = buildBlocker()
  if (b) return b
  try {
    return toConfig(config.value!, s, currentLan()!, catalog.value!, known)
  } catch (e) {
    return e instanceof Error && /сервер/.test(e.message) ? 'Сначала настройте сервер VPN на экране «Сервер».' : String(e)
  }
}

export type SaveResult = { ok: true } | { ok: false; conflict: boolean; message: string }

const SAVED = 'Сохранено, применяю на роутере'

/** Замена настроек целиком. Конфликт ревизий — перечитываем настройки и говорим об этом. */
export async function save(next: Config, done = SAVED): Promise<SaveResult> {
  if (!revision.value) return { ok: false, conflict: false, message: 'Настройки ещё не загружены.' }
  const r: ApiResult<ReplaceResponse> = await api.replaceConfig(revision.value, next)
  if (r.status === 200 && r.body.ok && r.body.config && r.body.revision) {
    config.value = r.body.config
    revision.value = r.body.revision
    if (done) notify.show('success', done)
    void loadStatus()
    return { ok: true }
  }
  if (r.status === 409 && r.body.error?.code === 'revision_conflict') {
    await loadConfig()
    const message = 'Настройки только что изменились в другом окне. Я загрузил новые — проверьте и сохраните ещё раз.'
    notify.show('error', 'Не сохранено', message)
    return { ok: false, conflict: true, message }
  }
  const details = r.body.issues.map((i) => i.message).slice(0, 3).join('; ')
  const message = `${r.body.error?.message ?? `Ошибка ${r.status}`}${details ? `: ${details}` : ''}`
  notify.show('error', 'Не сохранено', message)
  return { ok: false, conflict: false, message }
}
