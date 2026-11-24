<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import Button from 'primevue/button'
import InputText from 'primevue/inputtext'
import Message from 'primevue/message'
import Password from 'primevue/password'
import Textarea from 'primevue/textarea'
import ToggleSwitch from 'primevue/toggleswitch'
import { Check, ChevronDown, ClipboardPaste, Minus, Plus, Trash2 } from 'lucide-vue-next'
import Select from 'primevue/select'
import { api, manage, type Config, type Endpoint, type ModuleInfo, type Profile, type SubscriptionResponse, type TlsProfile } from '../api'
import { isProxyLink, parseProxyLink, PROTOCOL_LABEL } from '../proxyLink'
import { emptyProfileForm, formToProfile, formToSecret, profileToForm, type ProfileForm } from '../manage'
import { parseServer, TLS_PROFILES } from '../serverConfig'
import { build, config, freeTunnel, hasPassword, hasSubscription, knownDevicesNow, loadConfig, loadSecrets, notify, profile, profiles, save, selectedServer, simple, tunnel, withProfile } from '../store'
import { when } from '../status'
import { t } from '../i18n'
import Segmented from '../components/Segmented.vue'
import BackupServer from '../components/BackupServer.vue'
import SpeedCard from '../components/SpeedCard.vue'

const emit = defineEmits<{ navigate: [tab: 'sites' | 'modules'] }>()

const PROFILE_ID = 'tt'
/** Добавление нового сервера (форма пустая, сохранение добавляет профиль со свободным номером туннеля). */
const adding = ref(false)
function newId(): string {
  const ids = new Set(config.value?.profiles.map((p) => p.id) ?? [])
  let n = profiles.value.length + 1
  while (ids.has(`tt${n}`)) n++
  return `tt${n}`
}
const formFrom = (): ProfileForm => {
  if (profile.value && !adding.value) return profileToForm(profile.value)
  const n = profiles.value.length
  return { ...emptyProfileForm(), id: n ? newId() : PROFILE_ID, name: n ? t('Сервер {n}', { n: n + 1 }) : t('Мой сервер') }
}
const form = ref<ProfileForm>(formFrom())
const pristine = ref(JSON.stringify(form.value))
const dirty = computed(() => JSON.stringify(form.value) !== pristine.value)
function resetForm() { form.value = formFrom(); pristine.value = JSON.stringify(form.value); pasted.value = ''; parsed.value = null; error.value = null; done.value = false }
watch(profile, () => { if (!dirty.value && !adding.value) resetForm() })
const firstTime = computed(() => adding.value || !profile.value?.endpoint)
const many = computed(() => profiles.value.length > 1)
function pick(id: string) { adding.value = false; selectedServer.value = id; confirmDelete.value = false; resetForm() }
function startAdding() {
  if (config.value && freeTunnel(config.value) < 0) { notify.show('error', t('Серверов не больше 16')); return }
  adding.value = true; confirmDelete.value = false; resetForm()
}
function cancelAdding() { adding.value = false; resetForm() }
// ---- удаление сервера: его сервисы и устройства переходят на сервер по умолчанию ----
const confirmDelete = ref(false)
const omit = (m: Record<string, string> | undefined, id: string) => {
  const r = Object.fromEntries(Object.entries(m ?? {}).filter(([, v]) => v !== id))
  return Object.keys(r).length ? r : undefined
}
async function removeServer() {
  const c = config.value
  const p = profile.value
  if (!c || !p || !many.value) return
  if (!confirmDelete.value) { confirmDelete.value = true; return }
  confirmDelete.value = false
  const base: Config = { ...c, profiles: c.profiles.filter((x) => x.id !== p.id) }
  let next: Config | string = base
  if (simple.value) next = build({ ...simple.value, serviceServer: omit(simple.value.serviceServer, p.id), deviceServer: omit(simple.value.deviceServer, p.id) }, knownDevicesNow(), base)
  if (typeof next === 'string') { notify.show('error', t('Не получилось'), next); return }
  const r = await save(next, t('Сервер «{name}» удалён', { name: p.name }))
  if (r.ok) { selectedServer.value = null; resetForm() }
}
const advanced = ref(false)
const FAILURE = computed(() => [{ value: 'block' as const, label: t('Не открывать') }, { value: 'direct' as const, label: t('Открывать напрямую') }])
const tlsLabel = (id: TlsProfile): string => ({
  chrome: t('Chrome (по умолчанию)'), chrome_canary: 'Chrome Canary', safari: 'Safari', firefox: 'Firefox', okhttp: 'OkHttp (Android)',
  openssl: 'OpenSSL', boringssl: t('Без маскировки (BoringSSL)'),
} satisfies Record<TlsProfile, string>)[id]
const TLS_OPTIONS = computed(() => TLS_PROFILES.map((id) => ({ id, label: tlsLabel(id) })))

// ---- вставка конфигурации ----
const pasted = ref('')
interface Preview { rows: { label: string; value: string | null }[]; warnings: string[] }
const parsed = ref<Preview | { error: string } | null>(null)
watch(pasted, (t) => { if (!t.trim()) parsed.value = null })
function recognize() {
  const text = pasted.value
  if (!text.trim()) { parsed.value = null; return }
  // ссылка-подписка серверов sing-box (https://…, не tt://): список серверов роутер скачает после сохранения
  if (/^https:\/\/\S+$/i.test(text.trim())) {
    const f = form.value
    if (f.kind === 'trusttunnel') f.kind = 'vless'
    f.subscriptionUrl = text.trim(); f.link = ''
    parsed.value = { rows: [{ label: t('Подписка'), value: t('есть — список серверов роутер получит после сохранения') }], warnings: [] }
    return
  }
  // серверы модуля sing-box: ссылка целиком — секрет, в настройках — сводка
  if (isProxyLink(text)) {
    const x = parseProxyLink(text)
    if ('error' in x) { parsed.value = { error: x.error }; return }
    const f = form.value
    f.kind = x.kind; f.proxy = x.info; f.link = text.trim()
    if (x.name && (!profile.value || adding.value)) f.name = x.name
    parsed.value = { rows: [
      { label: t('Протокол'), value: PROTOCOL_LABEL[x.kind] },
      { label: t('Сервер'), value: `${x.info.server}:${x.info.port}` },
      ...(x.info.security ? [{ label: t('Шифрование'), value: x.info.security === 'none' ? t('нет') : x.info.security.toUpperCase() }] : []),
      ...(x.info.transport ? [{ label: t('Транспорт'), value: x.info.transport }] : []),
    ], warnings: [] }
    return
  }
  const r = parseServer(text)
  form.value.kind = 'trusttunnel'; form.value.proxy = null; form.value.link = ''
  if ('error' in r) { parsed.value = { error: r.error }; return }
  const e: Partial<Endpoint> = r.endpoint
  const f = form.value
  if (e.server !== undefined) f.server = e.server
  if (e.port !== undefined) f.port = String(e.port)
  f.sni = e.sni ?? ''
  if (e.username !== undefined) f.username = e.username
  if (e.quic !== undefined) f.quic = e.quic
  if (e.anti_dpi !== undefined) f.antiDpi = e.anti_dpi
  f.certificate = e.certificate ?? ''
  f.tlsProfile = e.tls_profile ?? 'chrome'
  f.clientRandom = e.client_random ?? ''
  f.clientRandomAuthKey = e.client_random_auth_key ?? ''
  if (r.password) f.password = r.password
  if (r.subscription) f.subscriptionUrl = r.subscription
  if (r.name && (!profile.value || adding.value)) f.name = r.name
  // необязательные параметры — только если они есть в ссылке
  const extra = [
    ...(e.tls_profile ? [{ label: t('Профиль TLS'), value: tlsLabel(e.tls_profile) }] : []),
    ...(e.client_random_auth_key ? [{ label: t('Ключ client_random'), value: t('есть') }] : e.client_random ? [{ label: t('Префикс client_random'), value: t('есть') }] : []),
  ]
  parsed.value = {
    rows: [
      { label: t('Сервер'), value: e.server ? `${e.server}${e.port ? `:${e.port}` : ''}` : null },
      { label: t('Имя сервера'), value: e.sni ?? null },
      { label: t('Логин'), value: e.username ?? null },
      { label: t('Пароль'), value: r.password ? t('есть') : null },
      { label: t('Сертификат'), value: e.certificate ? t('есть') : null },
      ...extra,
      ...(r.subscription ? [{ label: t('Подписка'), value: e.server ? t('есть') : t('есть — адрес и пароль роутер получит по ней') }] : []),
    ],
    warnings: r.warnings ?? [],
  }
}
// вставили из буфера — распознаём сразу
async function onPaste() { await nextTick(); recognize() }

// ---- сохранение ----
const saving = ref(false)
const error = ref<string | null>(null)
const done = ref(false)
/** Подписка задана сейчас или уже сохранена: адрес, логин и пароль сервер может прислать сам. */
const subscribed = computed(() => !!form.value.subscriptionUrl.trim() || hasSubscription.value)
const subscriptionOnly = computed(() => subscribed.value && !form.value.server.trim() && !form.value.username.trim())
const needPassword = computed(() => !hasPassword.value && !form.value.password && !subscribed.value)
const isProxy = computed(() => form.value.kind !== 'trusttunnel')
const protoLabel = computed(() => (form.value.kind === 'trusttunnel' ? 'TrustTunnel' : PROTOCOL_LABEL[form.value.kind]))
// ---- модуль sing-box для серверов VLESS, Hysteria2, Trojan, Shadowsocks ----
const modules = ref<ModuleInfo[] | null>(null)
async function loadModules() { try { const r = await manage.modules(); if (r.status === 200) modules.value = r.body.modules } catch { /* панель недоступна */ } }
const moduleFor = computed(() => (isProxy.value ? modules.value?.find((m) => m.kinds.includes(form.value.kind)) ?? null : null))
const moduleMissing = computed(() => isProxy.value && modules.value !== null && moduleFor.value?.installed?.state !== 'ok')
// новая ссылка в поле «Ссылка» — обновить сводку
watch(() => form.value.link, (l) => {
  if (!isProxy.value || !l.trim()) return
  const x = parseProxyLink(l)
  if (!('error' in x) && x.kind === form.value.kind) form.value.proxy = x.info
})
const blocker = computed(() => {
  const f = form.value
  if (isProxy.value) {
    if (!f.proxy && !subscribed.value) return t('Вставьте ссылку на сервер.')
    if (!f.link.trim() && !hasPassword.value && !subscribed.value) return t('Вставьте ссылку на сервер.')
    if (f.link.trim() && isProxyLink(f.link)) { const x = parseProxyLink(f.link); if ('error' in x) return x.error; if (x.kind !== f.kind) return t('Ссылка другого протокола: добавьте её отдельным сервером.') }
    return null
  }
  if (subscriptionOnly.value) return null
  if (!f.server.trim() || !f.username.trim()) return t('Укажите адрес сервера и логин — или вставьте ссылку.')
  if (needPassword.value) return t('Укажите пароль.')
  return null
})
async function submit() {
  if (blocker.value || !config.value) return
  const built = formToProfile(form.value, isProxy.value ? subscribed.value : subscriptionOnly.value)
  if (typeof built === 'string') { error.value = built; return }
  // номер туннеля, запасной сервер и выбор по задержке — от сохранённого профиля; новому — свободный номер
  const old = config.value.profiles.find((x) => x.id === built.id)
  const tunnelNo = old ? (old.tunnel ?? 0) : freeTunnel(config.value)
  if (tunnelNo < 0) { error.value = t('Серверов не больше 16'); return }
  const p: Profile = { ...built }
  if (tunnelNo) p.tunnel = tunnelNo
  if (old?.backup) p.backup = old.backup
  if (old?.prefer_fastest) p.prefer_fastest = true
  saving.value = true
  error.value = null
  try {
    const secret = formToSecret(form.value)
    const writeSecret = async (): Promise<boolean> => {
      const s = await manage.setSecret(p.id, secret!)
      if (s.status !== 200) error.value = t('Пароль не записан: {e}', { e: s.body.error?.message ?? s.status })
      return s.status === 200
    }
    // Пароль пишется до настроек: заявка на применение от POST /config уже застанет новый пароль. Но контроллер
    // принимает пароль только для профиля, который уже есть в настройках, — при первой настройке сервера пароль
    // пишется после настроек, и тогда применение запрашивается ещё раз.
    const known = config.value.profiles.some((x) => x.id === p.id)
    if (secret && known && !(await writeSecret())) return
    const r = await save(withProfile(config.value, p), secret && !known ? '' : undefined)
    if (!r.ok) { error.value = r.message; return }
    if (secret && !known) {
      if (!(await writeSecret())) return
      await manage.applyRequest()
      notify.show('success', t('Сохранено, применяю на роутере'))
    }
    // новая ссылка-подписка — сразу забрать параметры сервера
    if (secret?.subscription_url) void refreshSubscription(true)
    form.value.password = ''
    form.value.subscriptionUrl = ''
    form.value.link = ''
    pristine.value = JSON.stringify(form.value)
    pasted.value = ''
    done.value = true
    if (adding.value) { adding.value = false; selectedServer.value = p.id }
    await loadSecrets()
  } finally {
    saving.value = false
  }
}
// ---- подписка TrustTunnel ----
const sub = ref<SubscriptionResponse | null>(null)
let subTimer: number | undefined
let subWasRunning = false
async function loadSubscription() {
  clearTimeout(subTimer)
  try { sub.value = (await api.subscription()).body } catch { /* панель недоступна */ }
  if (sub.value?.running) subTimer = window.setTimeout(() => void loadSubscription(), 2000)
  // подписка обновилась — роутер мог сменить сервер: перечитать настройки
  else if (subWasRunning) void loadConfig()
  subWasRunning = !!sub.value?.running
}
/** Подписка выбранного сервера: итог обновления и список серверов (sing-box). */
const subState = computed(() => (profile.value ? sub.value?.profiles?.[profile.value.id]?.status ?? null : null))
const subEntries = computed(() => (profile.value ? sub.value?.profiles?.[profile.value.id]?.entries ?? [] : []))
const pickedName = computed(() => profile.value?.sub_pick ?? '')
async function pickEntry(name: string) {
  const id = profile.value?.id
  if (!id) return
  const r = await api.pickSubscription(id, name)
  if (r.status !== 200) { notify.show('error', t('Не получилось'), r.body.error?.message); return }
  notify.show('success', t('Сервер из подписки выбран, применяю на роутере'))
  await loadConfig()
}
async function refreshSubscription(quiet = false) {
  const r = await api.updateSubscription()
  if (r.status !== 202) { notify.show('error', t('Не получилось'), r.body.error?.message); return }
  if (!quiet) notify.show('info', t('Обновляю параметры по подписке'))
  subTimer = window.setTimeout(() => void loadSubscription(), 1500)
}
async function dropSubscription() {
  const id = profile.value?.id
  if (!id) return
  const r = await manage.setSecret(id, { subscription_url: '' })
  if (r.status !== 200) { notify.show('error', t('Не получилось'), r.body.error?.message); return }
  notify.show('success', t('Подписка удалена'))
  await loadSecrets()
}
const subText = computed(() => {
  const s = subState.value
  if (sub.value?.running) return t('Обновляю по подписке…')
  if (!s) return t('Роутер ещё не обращался к подписке')
  if (!s.ok) return t('Не получилось {when}: {e}. Действуют прежние параметры', { when: when(s.checked), e: s.error ?? t('ошибка') })
  return s.updated
    ? t('Проверено {when}, параметры менялись {changed}', { when: when(s.checked), changed: when(s.updated) })
    : t('Проверено {when}, изменений нет', { when: when(s.checked) })
})
onMounted(() => { void loadSubscription(); void loadModules() })
onBeforeUnmount(() => clearTimeout(subTimer))
const nothingSelected = computed(() => !!simple.value && simple.value.mode === 'selected' && !simple.value.services.length && !simple.value.customDomains.length)
</script>

<template>
  <section class="sect" :aria-label="t('Сервер VPN')">
    <Message v-if="done && nothingSelected" severity="success" :closable="false">
      <div class="next">
        <span>{{ t('Сервер сохранён. Теперь отметьте сайты, которые открывать через VPN.') }}</span>
        <Button :label="t('Выбрать сайты')" size="small" @click="emit('navigate', 'sites')" />
      </div>
    </Message>

    <div v-if="profiles.length" class="card servers">
      <div class="card__head">
        <div>
          <h2 class="card__title">{{ t('Серверы') }}</h2>
          <p class="card__sub">{{ many ? t('Серверы работают одновременно. На «Сайтах» и «Устройствах» можно выбрать, через какой сервер идти; остальное идёт через сервер по умолчанию.') : t('Можно добавить ещё серверы: они будут работать одновременно, а на «Сайтах» и «Устройствах» появится выбор сервера.') }}</p>
        </div>
        <Button v-if="!adding" :label="t('Добавить сервер')" size="small" severity="secondary" variant="outlined" @click="startAdding">
          <template #icon><Plus :size="16" class="p-button-icon-left" aria-hidden="true" /></template>
        </Button>
        <Button v-else :label="t('Отмена')" size="small" severity="secondary" variant="text" @click="cancelAdding" />
      </div>
      <div class="servers__list" role="group" :aria-label="t('Серверы')">
        <button v-for="(p, i) in profiles" :key="p.id" type="button" :aria-pressed="!adding && profile?.id === p.id"
          :class="['server-chip', { 'server-chip--on': !adding && profile?.id === p.id }]" @click="pick(p.id)">
          <span class="server-chip__name">{{ p.name }}</span>
          <span v-if="i === 0 && many" class="server-chip__tag">{{ t('по умолчанию') }}</span>
        </button>
        <span v-if="adding" class="server-chip server-chip--on server-chip--new">{{ t('Новый сервер') }}</span>
      </div>
      <div v-if="many && !adding" class="servers__actions">
        <Button :label="confirmDelete ? t('Точно удалить «{name}»?', { name: profile?.name ?? '' }) : t('Удалить сервер')" size="small"
          :severity="confirmDelete ? 'danger' : 'secondary'" variant="text" @click="removeServer">
          <template #icon><Trash2 :size="16" class="p-button-icon-left" aria-hidden="true" /></template>
        </Button>
        <span v-if="confirmDelete" class="hint">{{ t('Его сайты и устройства перейдут на сервер по умолчанию.') }}</span>
      </div>
    </div>

    <div class="cols">
      <div class="cols__side">
        <div class="card">
          <div>
            <h2 class="card__title">{{ firstTime ? t('Быстрая настройка') : t('Сменить сервер') }}</h2>
            <p class="card__sub">{{ t('Вставьте ссылку') }} <span class="num">tt://</span> {{ t('или файл конфигурации клиента — поля заполнятся сами') }} {{ t('Серверы VLESS, Hysteria2, Trojan и Shadowsocks — ссылкой') }} <span class="num">vless://</span>, <span class="num">hy2://</span>, <span class="num">trojan://</span>, <span class="num">ss://</span>.</p>
          </div>
          <div class="field">
            <label for="paste" class="sr-only">{{ t('Ссылка или конфигурация сервера') }}</label>
            <Textarea id="paste" v-model="pasted" rows="5" spellcheck="false" :placeholder="t('tt://?… или содержимое client.toml')" class="mono" @paste="onPaste" />
          </div>
          <Button :label="t('Распознать')" severity="secondary" variant="outlined" class="self-start" :disabled="!pasted.trim()" @click="recognize">
            <template #icon><ClipboardPaste :size="16" class="p-button-icon-left" aria-hidden="true" /></template>
          </Button>
          <Message v-if="parsed && 'error' in parsed" severity="error" :closable="false">{{ t('Не получилось прочитать: {e}.', { e: parsed.error }) }}</Message>
          <template v-else-if="parsed">
            <div class="preview" aria-live="polite">
              <p class="preview__title">{{ t('Распознано — проверьте поля и сохраните') }}</p>
              <dl class="preview__list">
                <div v-for="r in parsed.rows" :key="r.label" :class="['preview__row', { 'preview__row--none': !r.value }]">
                  <dt><Check v-if="r.value" :size="14" aria-hidden="true" /><Minus v-else :size="14" aria-hidden="true" />{{ r.label }}</dt>
                  <dd class="num">{{ r.value ?? t('нет') }}</dd>
                </div>
              </dl>
            </div>
            <Message v-for="w in parsed.warnings" :key="w" severity="warn" :closable="false">{{ t('Не поддерживается: {w}.', { w }) }}</Message>
          </template>
        </div>

        <div v-if="!firstTime" class="card conn">
          <h2 class="card__title">{{ t('Подключение') }}</h2>
          <div :class="['pill', `pill--${tunnel.tone}`, 'pill--lg']"><span class="pill__dot" aria-hidden="true" /><span class="pill__text">{{ tunnel.title }}</span></div>
          <p v-if="tunnel.detail" class="hint">{{ tunnel.detail }}</p>
        </div>
        <BackupServer v-if="!firstTime && !isProxy" />
        <SpeedCard v-if="!firstTime" />
      </div>

      <form class="card" @submit.prevent="submit">
        <h2 class="card__title">{{ t('Данные сервера') }}</h2>
        <div class="field">
          <label for="srv-name" class="field__label">{{ t('Название') }}</label>
          <InputText id="srv-name" v-model="form.name" maxlength="64" />
        </div>
        <template v-if="isProxy">
          <Message v-if="moduleMissing" severity="warn" :closable="false">
            <div class="next">
              <span>{{ moduleFor?.installed ? t('Модуль sing-box сейчас недоступен (флешка не подключена?) — сервер не работает.') : t('Для серверов {p} нужен модуль sing-box. Установите его на странице «Модули» — без него сервер сохранится, но работать не будет.', { p: protoLabel }) }}</span>
              <Button :label="t('Открыть «Модули»')" size="small" @click="emit('navigate', 'modules')" />
            </div>
          </Message>
          <dl v-if="form.proxy" class="preview__list proxy-sum">
            <div class="preview__row"><dt>{{ t('Протокол') }}</dt><dd>{{ protoLabel }}</dd></div>
            <div class="preview__row"><dt>{{ t('Сервер') }}</dt><dd class="num">{{ form.proxy.server }}:{{ form.proxy.port }}</dd></div>
            <div v-if="form.proxy.security" class="preview__row"><dt>{{ t('Шифрование') }}</dt><dd>{{ form.proxy.security === 'none' ? t('нет') : form.proxy.security.toUpperCase() }}</dd></div>
            <div v-if="form.proxy.transport" class="preview__row"><dt>{{ t('Транспорт') }}</dt><dd class="num">{{ form.proxy.transport }}</dd></div>
          </dl>
          <div class="field">
            <label for="srv-link" class="field__label">{{ t('Ссылка на сервер') }}</label>
            <Password v-model="form.link" input-id="srv-link" :feedback="false" toggle-mask fluid autocomplete="off"
              :placeholder="hasPassword ? t('Сохранена. Оставьте пустым') : 'vless://…'" />
            <span class="field__hint">{{ t('В ссылке есть ключ или пароль, поэтому она хранится только на роутере и сюда не возвращается. Вставьте новую, чтобы сменить сервер.') }}</span>
          </div>
          <div class="field">
            <label for="srv-psub" class="field__label">{{ t('Ссылка-подписка') }}</label>
            <Password v-model="form.subscriptionUrl" input-id="srv-psub" :feedback="false" toggle-mask fluid autocomplete="off"
              :placeholder="hasSubscription ? t('Сохранена. Оставьте пустым') : 'https://…'" />
            <span class="field__hint">{{ t('Подписка — список серверов от вашего провайдера VPN. Роутер забирает его по расписанию списков сайтов и по кнопке и подключается к выбранному серверу (по умолчанию — первому). Хранится только на роутере.') }}</span>
          </div>
          <template v-if="hasSubscription">
            <span :class="['adblock__state', { 'adblock__state--bad': subState && !subState.ok }]" aria-live="polite">
              <span :class="['led', subState ? (subState.ok ? 'led--ok' : 'led--warn') : 'led--idle']" aria-hidden="true" />
              <span class="meta">{{ subText }}</span>
            </span>
            <div v-if="subEntries.length" class="field">
              <label for="srv-pick" class="field__label">{{ t('Сервер из подписки') }}</label>
              <select id="srv-pick" class="tile__server self-start" :value="pickedName || subEntries.find((e) => e.server === form.proxy?.server && e.port === form.proxy?.port)?.name || ''"
                @change="pickEntry(($event.target as HTMLSelectElement).value)">
                <option v-for="e in subEntries" :key="e.name" :value="e.name">{{ e.name }} — {{ e.kind }}, {{ e.server }}:{{ e.port }}</option>
              </select>
            </div>
            <div class="sub__actions">
              <Button :label="t('Обновить по подписке')" size="small" severity="secondary" variant="outlined" :loading="!!sub?.running" :disabled="!!sub?.running" @click="refreshSubscription()" />
              <Button :label="t('Удалить подписку')" size="small" severity="secondary" variant="text" @click="dropSubscription" />
            </div>
          </template>
        </template>
        <template v-else>
        <div class="row2">
          <div class="field">
            <label for="srv-host" class="field__label">{{ t('Адрес сервера') }}</label>
            <InputText id="srv-host" v-model="form.server" placeholder="203.0.113.10" spellcheck="false" class="num" />
          </div>
          <div class="field field--port">
            <label for="srv-port" class="field__label">{{ t('Порт') }}</label>
            <InputText id="srv-port" v-model="form.port" inputmode="numeric" class="num" />
          </div>
        </div>
        <div class="field">
          <label for="srv-sni" class="field__label">{{ t('Имя сервера') }}</label>
          <InputText id="srv-sni" v-model="form.sni" placeholder="vpn.example.com" spellcheck="false" />
          <span class="field__hint">{{ t('Доменное имя из сертификата сервера. Если его нет — оставьте пустым.') }}</span>
        </div>
        <div class="row2">
          <div class="field">
            <label for="srv-user" class="field__label">{{ t('Логин') }}</label>
            <InputText id="srv-user" v-model="form.username" autocomplete="off" spellcheck="false" />
          </div>
          <div class="field">
            <label for="srv-pass" class="field__label">{{ t('Пароль') }}</label>
            <Password v-model="form.password" input-id="srv-pass" :feedback="false" toggle-mask fluid autocomplete="new-password"
              :placeholder="hasPassword ? t('Сохранён. Оставьте пустым') : ''" />
            <span class="field__hint">{{ hasPassword ? t('Пароль сохранён на роутере и сюда не возвращается. Введите новый, чтобы сменить.') : t('Хранится только на роутере') }}</span>
          </div>
        </div>

        </template>
        <div class="field">
          <span id="srv-fail-label" class="field__label">{{ t('Если сервер недоступен, сайты из списка') }}</span>
          <Segmented v-model="form.onFailure" :options="FAILURE" :label="t('Если сервер недоступен')" name="onfail" />
          <span class="field__hint">{{ form.onFailure === 'block' ? t('Рекомендуется. Сайты подождут, пока сервер снова заработает.') : t('Сайты откроются без VPN, если смогут.') }}</span>
        </div>

        <button v-if="!isProxy" type="button" class="disclose" :aria-expanded="advanced" aria-controls="srv-adv" @click="advanced = !advanced">
          <ChevronDown :size="16" :class="['disclose__icon', { 'disclose__icon--open': advanced }]" aria-hidden="true" />
          {{ t('Дополнительные параметры') }}
        </button>
        <div v-show="advanced && !isProxy" id="srv-adv" class="adv">
          <label class="setrow">
            <span class="setrow__text"><span class="setrow__title">HTTP/3</span><span class="setrow__desc">{{ t('Включайте, только если так сказано в настройках сервера') }}</span></span>
            <ToggleSwitch v-model="form.quic" input-id="srv-quic" />
          </label>
          <label class="setrow">
            <span class="setrow__text"><span class="setrow__title">{{ t('Маскировка от блокировок (anti-DPI)') }}</span><span class="setrow__desc">{{ t('Помогает, если провайдер мешает подключению к серверу.') }}</span></span>
            <ToggleSwitch v-model="form.antiDpi" input-id="srv-dpi" />
          </label>
          <div class="field">
            <label for="srv-cert" class="field__label">{{ t('Сертификат сервера') }}</label>
            <Textarea id="srv-cert" v-model="form.certificate" rows="4" spellcheck="false" class="mono" placeholder="-----BEGIN CERTIFICATE-----" />
            <span class="field__hint">{{ t('Нужен, только если сервер использует свой сертификат. Обычно приходит вместе со ссылкой.') }}</span>
          </div>
          <div class="field">
            <label for="srv-tls" class="field__label">{{ t('Профиль TLS') }}</label>
            <Select v-model="form.tlsProfile" input-id="srv-tls" :options="TLS_OPTIONS" option-label="label" option-value="id" fluid />
            <span class="field__hint">{{ t('Под какой браузер или приложение маскируется подключение. Меняйте, если так сказано в настройках сервера или провайдер мешает подключению.') }}</span>
          </div>
          <div class="row2">
            <div class="field">
              <label for="srv-cr" class="field__label">{{ t('Префикс client_random') }}</label>
              <InputText id="srv-cr" v-model="form.clientRandom" spellcheck="false" autocomplete="off" class="mono" :placeholder="t('префикс/маска')" />
            </div>
            <div class="field">
              <label for="srv-crk" class="field__label">{{ t('Ключ client_random') }}</label>
              <InputText id="srv-crk" v-model="form.clientRandomAuthKey" spellcheck="false" autocomplete="off" class="mono" />
            </div>
          </div>
          <span class="field__hint">{{ t('Нужны, только если сервер пускает подключения по client_random. Обычно приходят вместе со ссылкой; задаётся что-то одно — префикс или ключ.') }}</span>
          <div class="field">
            <label for="srv-sub" class="field__label">{{ t('Ссылка-подписка') }}</label>
            <Password v-model="form.subscriptionUrl" input-id="srv-sub" :feedback="false" toggle-mask fluid autocomplete="off"
              :placeholder="hasSubscription ? t('Сохранена. Оставьте пустым') : 'https://…'" />
            <span class="field__hint">{{ t('Подписка TrustTunnel 1.3: по ней роутер сам забирает адрес, логин, пароль и сертификат сервера — по расписанию списков сайтов и по кнопке. В ссылке есть логин и пароль, поэтому она хранится только на роутере') }}</span>
          </div>
          <template v-if="hasSubscription">
            <span :class="['adblock__state', { 'adblock__state--bad': subState && !subState.ok }]" aria-live="polite">
              <span :class="['led', subState ? (subState.ok ? 'led--ok' : 'led--warn') : 'led--idle']" aria-hidden="true" />
              <span class="meta">{{ subText }}</span>
            </span>
            <div class="sub__actions">
              <Button :label="t('Обновить по подписке')" size="small" severity="secondary" variant="outlined" :loading="!!sub?.running" :disabled="!!sub?.running" @click="refreshSubscription()" />
              <Button :label="t('Удалить подписку')" size="small" severity="secondary" variant="text" @click="dropSubscription" />
            </div>
          </template>
        </div>

        <Message v-if="error" severity="error" :closable="false">{{ error }}</Message>
        <div class="formfoot">
          <span class="formfoot__text" aria-live="polite">{{ blocker && dirty ? blocker : dirty ? t('Есть несохранённые изменения') : profile?.endpoint ? t('Всё сохранено') : t('Вставьте ссылку на сервер') }}</span>
          <Button type="submit" :label="t('Сохранить')" :loading="saving" :disabled="!dirty || !!blocker || saving" />
        </div>
      </form>
    </div>
  </section>
</template>

<style scoped>
.sub__actions { display: flex; flex-wrap: wrap; gap: 0.5rem; }
.servers__list { display: flex; flex-wrap: wrap; gap: 0.5rem; }
.server-chip { display: inline-flex; align-items: center; gap: 0.5rem; min-height: 2.5rem; padding: 0.4rem 0.9rem; border-radius: 999px;
  border: 1px solid var(--line, var(--p-content-border-color)); background: transparent; color: inherit; font: inherit; cursor: pointer; }
.server-chip:focus-visible { outline: 2px solid var(--p-primary-color); outline-offset: 2px; }
.server-chip--on { border-color: var(--p-primary-color); background: color-mix(in srgb, var(--p-primary-color) 12%, transparent); font-weight: 600; }
.server-chip--new { cursor: default; font-style: italic; }
.server-chip__tag { font-size: 0.75rem; opacity: 0.7; font-weight: 400; }
.servers__actions { display: flex; flex-wrap: wrap; align-items: center; gap: 0.5rem; }
.proxy-sum { margin: 0; }
</style>
