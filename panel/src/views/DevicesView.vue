<script setup lang="ts">
import { computed, nextTick, onMounted, ref, watch, type Component } from 'vue'
import InputText from 'primevue/inputtext'
import Button from 'primevue/button'
import { ChevronDown, HardDrive, Laptop, Lightbulb, MonitorSmartphone, Pencil, Printer, Radar, Search, Smartphone, Speaker, Tablet, Tv, Watch } from 'lucide-vue-next'
import { build, buildBlocker, config, knownDevicesNow, leases, loadConfig, loadLeases, notify, revision, save, serverReady, simple, simpleState } from '../store'
import { manage, type StatsResponse } from '../api'
import { deviceLabel, deviceRows, plural, shortVendor, type DeviceRow } from '../status'
import type { Simple } from '../simple'
import { useAutosave, type Blocker } from '../autosave'
import { avatarHue, initials } from '../ui'
import { t } from '../i18n'
import ManualBanner from './ManualBanner.vue'
import Segmented from '../components/Segmented.vue'

const emit = defineEmits<{ navigate: [tab: 'server' | 'sites'] }>()

/** all — устройства, у которых через VPN идёт весь интернет (при выборе отдельных сайтов). */
interface Draft { mode: 'all' | 'selected'; macs: string[]; all: string[] }
const toDraft = (s: Simple): Draft => ({ ...(s.devices === 'all' ? { mode: 'all' as const, macs: [] } : { mode: 'selected' as const, macs: [...s.devices] }), all: [...(s.vpnAll ?? [])] })
/** Переключатель «весь интернет» нужен, только когда через VPN идут отдельные сайты (а не «всё через VPN»). */
const sitesMode = computed(() => simple.value?.mode === 'selected')
const draft = ref<Draft | null>(simple.value ? toDraft(simple.value) : null)

const MODES = computed(() => [{ value: 'all' as const, label: t('Все устройства') }, { value: 'selected' as const, label: t('Только выбранные') }])

const rows = computed(() => (config.value && draft.value ? deviceRows(leases.value, config.value, {}, draft.value.macs) : []))
const search = ref('')
const shown = computed(() => {
  const q = search.value.trim().toLowerCase()
  return q ? rows.value.filter((d) => [deviceLabel(d), d.mac, d.ip ?? '', d.vendor ?? '', d.hostname, d.model].some((x) => x.toLowerCase().includes(q))) : rows.value
})
const online = computed(() => rows.value.filter((d) => d.online).length)
const dirty = computed(() => {
  const s = simple.value, d = draft.value
  if (!s || !d) return false
  const was = s.devices === 'all' ? [] : [...s.devices].sort()
  const now = d.mode === 'all' ? [] : [...d.macs].sort()
  const allWas = [...(s.vpnAll ?? [])].sort().join()
  return (s.devices === 'all') !== (d.mode === 'all') || was.join() !== now.join() || allWas !== [...d.all].sort().join()
})
watch(simple, (s) => { if (s && (!draft.value || !dirty.value)) draft.value = toDraft(s) })

function toggle(mac: string) {
  if (!draft.value) return
  const m = draft.value.macs
  draft.value.macs = m.includes(mac) ? m.filter((x) => x !== mac) : [...m, mac]
}
function toggleAll(mac: string) {
  if (!draft.value) return
  const a = draft.value.all
  draft.value.all = a.includes(mac) ? a.filter((x) => x !== mac) : [...a, mac]
}

// ---- переименование в строке ----
const editing = ref<string | null>(null)
const editText = ref('')
async function startRename(mac: string, name: string) {
  editing.value = mac
  editText.value = name
  await nextTick()
  document.getElementById(`rename-${mac}`)?.focus()
}
/** Имя сохраняется сразу и отдельно от выбора VPN: устройство не отмечается, маршрутизация не меняется. */
async function finishRename() {
  const mac = editing.value
  editing.value = null
  if (!mac || !revision.value) return
  const name = editText.value.trim()
  const was = rows.value.find((r) => r.mac === mac)
  if (name === (was?.named ? was.name : '') || (!name && !was?.named)) return
  const r = await manage.setDeviceName(revision.value, mac, name)
  if (r.status !== 200) { notify.show('error', t('Не сохранено'), r.body.error?.message); return }
  await loadConfig()
  notify.show('success', name ? t('Имя сохранено') : t('Имя убрано'))
}

// ---- подробности, тип устройства, поиск имён в сети ----
const open = ref<string | null>(null)
const KIND_ICON: Record<string, Component> = { tv: Tv, phone: Smartphone, tablet: Tablet, computer: Laptop, printer: Printer, speaker: Speaker, watch: Watch, smart: Lightbulb, storage: HardDrive }
const KINDS = computed<Record<string, string>>(() => ({ tv: t('телевизор или приставка'), phone: t('телефон'), tablet: t('планшет'), computer: t('компьютер'), printer: t('принтер'), speaker: t('колонка'), watch: t('часы'), smart: t('умный дом'), storage: t('сетевое хранилище') }))
const stats = ref<StatsResponse | null>(null)
const traffic = (mac: string) => stats.value?.devices.find((d) => d.key === mac)
function bytes(n: number): string {
  const units = ['byte', 'kilobyte', 'megabyte', 'gigabyte', 'terabyte'] as const
  let i = 0, v = n
  while (v >= 1000 && i < units.length - 1) { v /= 1000; i++ }
  return new Intl.NumberFormat(undefined, { style: 'unit', unit: units[i], unitDisplay: 'short', maximumFractionDigits: v < 10 && i > 0 ? 1 : 0 }).format(v)
}
/** Как сейчас идёт трафик устройства — по выбору на этом экране. */
function route(d: DeviceRow): string {
  const s = simple.value, dr = draft.value
  if (!s || !dr || !s.enabled) return t('VPN выключен — напрямую')
  if (dr.mode === 'selected' && !dr.macs.includes(d.mac) && !dr.all.includes(d.mac)) return t('Напрямую, без VPN')
  if (s.mode === 'all' || dr.all.includes(d.mac)) return t('Весь интернет через VPN')
  return t('Выбранные сайты через VPN')
}
function link(d: DeviceRow): string {
  const l = d.link
  if (!l) return ''
  const wired = l.ifname?.startsWith('eth') || l.wifi === '0' || l.wifi === 'false'
  const sig = l.signal && /^-?\d+$/.test(l.signal) && l.signal !== '0' ? t(', сигнал {s} дБм', { s: l.signal }) : ''
  return (wired ? t('кабель') : t('Wi‑Fi')) + (l.ifname ? ` (${l.ifname})` : '') + (wired ? '' : sig)
}
const scanning = ref(false)
async function discover() {
  scanning.value = true
  try {
    const r = await manage.discover()
    if (r.status !== 202) { notify.show('error', t('Не получилось'), r.body.error?.message); return }
    await new Promise((ok) => setTimeout(ok, 6000))
    await loadLeases()
    notify.show('success', t('Имена обновлены'), t('Устройства, которые объявляют себя в сети, получили имена'))
  } finally {
    scanning.value = false
  }
}

// ---- автосохранение ----
const vpnUsed = computed(() => !!simple.value && (simple.value.mode === 'all' || simple.value.services.length > 0 || simple.value.customDomains.length > 0 || !!draft.value?.all.length))
function blocker(): Blocker | null {
  if (draft.value?.mode === 'selected' && !draft.value.macs.length) return { text: t('Отметьте хотя бы одно устройство — или выберите «Все устройства».') }
  if (vpnUsed.value && !serverReady.value) return { text: t('Сначала настройте сервер VPN.'), action: { label: t('Открыть «Сервер»'), run: () => emit('navigate', 'server') } }
  const b = buildBlocker()
  return b ? { text: b } : null
}
useAutosave({
  source: [draft],
  dirty: () => dirty.value,
  blocker,
  run: async () => {
    if (!simple.value || !draft.value) return t('Настройки ещё не загружены.')
    const s: Simple = { ...simple.value, devices: draft.value.mode === 'all' ? 'all' : [...draft.value.macs] }
    if (draft.value.all.length) s.vpnAll = [...draft.value.all]
    else delete s.vpnAll
    const cfg = build(s, knownDevicesNow())
    if (typeof cfg === 'string') return cfg
    return save(cfg, '')
  },
})
onMounted(() => { void loadLeases(); void manage.stats().then((r) => { if (r.status === 200) stats.value = r.body }) })
</script>

<template>
  <section class="sect" :aria-label="t('Устройства')">
    <ManualBanner v-if="simpleState && !simpleState.canonical" :reason="simpleState.reason" />

    <template v-else-if="draft">
      <div class="card">
        <div class="card__head">
          <div>
            <h2 class="card__title">{{ t('Для каких устройств работает VPN') }}</h2>
            <p class="card__sub">{{ draft.mode === 'all'
              ? t('Рекомендуется. Настройки сайтов действуют для всех устройств дома, новые подключатся сами.')
              : t('Например, только телевизор и ноутбук. Остальные устройства открывают все сайты напрямую.') }}</p>
          </div>
          <Segmented v-model="draft.mode" :options="MODES" :label="t('Устройства')" name="devmode" />
        </div>
      </div>

      <div class="card card--flush">
        <div class="card__head card__head--pad">
          <div>
            <h2 class="card__title">{{ t('Устройства дома') }}</h2>
            <p class="card__sub">
              {{ rows.length ? t('{devices}, в сети {online}', { devices: plural(rows.length, 'устройство', 'устройства', 'устройств'), online }) : t('Пока никого') }}<template v-if="draft.mode === 'selected'"> · {{ draft.macs.length ? t('выбрано: {n}', { n: draft.macs.length }) : t('ничего не выбрано') }}</template>
            </p>
          </div>
          <Button :label="t('Найти имена в сети')" size="small" severity="secondary" variant="outlined" :loading="scanning" :disabled="scanning" @click="discover">
            <template #icon><Radar :size="16" class="p-button-icon-left" aria-hidden="true" /></template>
          </Button>
          <div v-if="rows.length > 4" class="search">
            <Search :size="16" class="search__icon" aria-hidden="true" />
            <label for="dev-search" class="sr-only">{{ t('Найти устройство') }}</label>
            <InputText id="dev-search" v-model="search" :placeholder="t('Имя, IP или MAC')" type="search" />
          </div>
        </div>
        <p v-if="!rows.length" class="muted pad">{{ t('Роутер пока не видит подключённых устройств. Подключите устройство к Wi‑Fi и обновите страницу.') }}</p>
        <ul v-else class="devs">
          <li v-for="d in shown" :key="d.mac" :class="['dev', { 'dev--on': draft.mode === 'selected' && draft.macs.includes(d.mac) }]">
            <span class="avatar" :style="{ '--h': avatarHue(d.mac) }" aria-hidden="true">
              <component :is="KIND_ICON[d.kind]" v-if="KIND_ICON[d.kind]" :size="18" />
              <template v-else-if="initials(d.name)">{{ initials(d.name) }}</template>
              <MonitorSmartphone v-else :size="18" />
            </span>
            <div class="dev__body">
              <form v-if="editing === d.mac" class="dev__rename" @submit.prevent="finishRename">
                <label :for="`rename-${d.mac}`" class="sr-only">{{ t('Новое имя') }}</label>
                <InputText :id="`rename-${d.mac}`" v-model="editText" maxlength="64" size="small" @keydown.esc="editing = null" @blur="finishRename" />
              </form>
              <span v-else class="dev__name">
                <span :class="['dev__label', { 'dev__label--guess': !d.name }]">{{ deviceLabel(d) }}</span>
                <button type="button" class="icon-btn" :aria-label="t('Переименовать {name}', { name: deviceLabel(d) })" :title="t('Переименовать')"
                  @click="startRename(d.mac, d.named ? d.name : '')"><Pencil :size="14" aria-hidden="true" /></button>
              </span>
              <span class="dev__meta">
                <span v-if="d.vendor && d.name">{{ shortVendor(d.vendor) }} · </span><span v-if="KINDS[d.kind]">{{ KINDS[d.kind] }} · </span><span class="num">{{ d.mac }}</span>
                <span v-if="d.random" class="dev__badge" :title="t('Случайный адрес Wi‑Fi: устройство скрывает настоящий MAC')">{{ t('скрытый MAC') }}</span>
              </span>
              <button type="button" class="dev__more" :aria-expanded="open === d.mac" :aria-controls="`dev-more-${d.mac}`" @click="open = open === d.mac ? null : d.mac">
                <ChevronDown :size="14" :class="['disclose__icon', { 'disclose__icon--open': open === d.mac }]" aria-hidden="true" />{{ t('Подробнее') }}
              </button>
              <dl v-if="open === d.mac" :id="`dev-more-${d.mac}`" class="dev__details">
                <dt>{{ t('Как идёт трафик') }}</dt><dd>{{ route(d) }}</dd>
                <template v-if="d.vendor"><dt>{{ t('Производитель') }}</dt><dd>{{ d.vendor }}</dd></template>
                <template v-if="d.found"><dt>{{ t('Называет себя в сети') }}</dt><dd>{{ d.found.name }}<template v-if="d.found.model"> · {{ d.found.model }}</template></dd></template>
                <template v-if="d.hostname"><dt>{{ t('Имя при подключении') }}</dt><dd>{{ d.hostname }}</dd></template>
                <template v-if="link(d)"><dt>{{ t('Подключение') }}</dt><dd>{{ link(d) }}</dd></template>
                <dt>IP</dt><dd class="num">{{ d.ip ?? '—' }}</dd>
                <dt>MAC</dt><dd class="num">{{ d.mac }}</dd>
                <template v-if="traffic(d.mac)"><dt>{{ t('Трафик') }}</dt><dd>{{ t('за сутки {d}, за неделю {w}', { d: bytes(traffic(d.mac)!.day), w: bytes(traffic(d.mac)!.week) }) }}</dd></template>
              </dl>
              <p v-if="open === d.mac && d.random" class="hint">{{ t('Это случайный адрес Wi‑Fi: телефон или ноутбук скрывает настоящий MAC и может сменить его. Чтобы имя и выбор VPN не терялись, для домашней сети отключите на устройстве «Частный адрес Wi‑Fi» (iPhone: Настройки → Wi‑Fi → (i) у сети) или «Случайный MAC» (Android: настройки сети → Конфиденциальность → MAC устройства).') }}</p>
            </div>
            <span class="dev__ip num">{{ d.ip ?? '—' }}</span>
            <span :class="['dev__state', { 'dev__state--off': !d.online }]"><span class="dot" aria-hidden="true" />{{ d.online ? t('В сети') : t('Не в сети') }}</span>
            <button v-if="draft.mode === 'selected'" type="button" role="switch" :aria-checked="draft.macs.includes(d.mac)"
              :aria-label="t('Через VPN: {name}', { name: d.name || d.mac })" class="dev__sw" @click="toggle(d.mac)">
              <span class="dev__sw-label">{{ t('Через VPN') }}</span>
              <span class="sw" aria-hidden="true"><span class="sw__knob" /></span>
            </button>
            <button v-if="sitesMode" type="button" role="switch" :aria-checked="draft.all.includes(d.mac)"
              :aria-label="t('Весь интернет через VPN: {name}', { name: d.name || d.mac })" class="dev__sw" @click="toggleAll(d.mac)">
              <span class="dev__sw-label">{{ t('Весь интернет') }}</span>
              <span class="sw" aria-hidden="true"><span class="sw__knob" /></span>
            </button>
          </li>
          <li v-if="!shown.length" class="muted pad">{{ t('Ничего не нашлось.') }}</li>
        </ul>
        <p class="hint pad">{{ t('Имя нужно только вам, чтобы узнавать устройство в списке; на VPN оно не влияет. Имена, которые устройства объявляют в сети (iPhone, телевизоры, колонки, принтеры), роутер находит сам раз в 10 минут.') }}</p>
        <p v-if="sitesMode" class="hint pad">{{ t('«Весь интернет» — у этого устройства через VPN идут все сайты, а не только выбранные. Исключения и сайты с обходом блокировок действуют и для него.') }}</p>
      </div>
    </template>
  </section>
</template>

<style scoped>
.dev__label--guess { color: var(--muted, inherit); }
.dev__badge { margin-left: 0.4rem; padding: 0 0.35rem; border-radius: 0.3rem; font-size: 0.75rem; background: var(--idle-soft, rgba(127, 127, 127, 0.15)); }
.dev__more { display: inline-flex; align-items: center; gap: 0.2rem; background: none; border: 0; padding: 0; margin-top: 0.2rem; color: var(--muted, inherit); font: inherit; font-size: 0.8125rem; cursor: pointer; }
.dev__more:focus-visible { outline: 2px solid var(--focus, currentColor); outline-offset: 2px; }
.dev__details { display: grid; grid-template-columns: auto 1fr; gap: 0.2rem 0.9rem; margin: 0.5rem 0 0.25rem; font-size: 0.875rem; }
.dev__details dt { color: var(--muted, inherit); }
.dev__details dd { margin: 0; overflow-wrap: anywhere; }
</style>
