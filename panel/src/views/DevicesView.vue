<script setup lang="ts">
import { computed, nextTick, onMounted, ref, watch } from 'vue'
import InputText from 'primevue/inputtext'
import { Pencil, Search, Smartphone } from 'lucide-vue-next'
import { build, buildBlocker, config, knownDevicesNow, leases, loadLeases, save, serverReady, simple, simpleState } from '../store'
import { deviceRows, plural } from '../status'
import { normalizeMac, type Simple } from '../simple'
import { useAutosave, type Blocker } from '../autosave'
import { avatarHue, initials } from '../ui'
import ManualBanner from './ManualBanner.vue'
import Segmented from '../components/Segmented.vue'

const emit = defineEmits<{ navigate: [tab: 'server' | 'sites'] }>()

interface Draft { mode: 'all' | 'selected'; macs: string[] }
const toDraft = (s: Simple): Draft => (s.devices === 'all' ? { mode: 'all', macs: [] } : { mode: 'selected', macs: [...s.devices] })
const draft = ref<Draft | null>(simple.value ? toDraft(simple.value) : null)
/** Переименования этого сеанса: MAC → новое имя. Без них имена из настроек не трогаем. */
const renames = ref<Record<string, string>>({})

const MODES = [{ value: 'all' as const, label: 'Все устройства' }, { value: 'selected' as const, label: 'Только выбранные' }]

const rows = computed(() => (config.value && draft.value ? deviceRows(leases.value, config.value, renames.value, draft.value.macs) : []))
const search = ref('')
const shown = computed(() => {
  const q = search.value.trim().toLowerCase()
  return q ? rows.value.filter((d) => d.name.toLowerCase().includes(q) || d.mac.includes(q) || (d.ip ?? '').includes(q)) : rows.value
})
const online = computed(() => rows.value.filter((d) => d.online).length)
const savedName = (mac: string) => config.value?.devices.find((d) => normalizeMac(d.mac) === normalizeMac(mac))?.name
// в настройках хранятся только выбранные устройства: переименование считается лишь у них
const renamed = computed(() => Object.entries(renames.value).some(([mac, n]) => draft.value?.macs.includes(mac) && n.trim() && n.trim() !== savedName(mac)))
const dirty = computed(() => {
  const s = simple.value, d = draft.value
  if (!s || !d) return false
  const was = s.devices === 'all' ? [] : [...s.devices].sort()
  const now = d.mode === 'all' ? [] : [...d.macs].sort()
  return (s.devices === 'all') !== (d.mode === 'all') || was.join() !== now.join() || (d.mode === 'selected' && renamed.value)
})
watch(simple, (s) => { if (s && (!draft.value || !dirty.value)) { draft.value = toDraft(s); renames.value = {} } })

function toggle(mac: string) {
  if (!draft.value) return
  const m = draft.value.macs
  draft.value.macs = m.includes(mac) ? m.filter((x) => x !== mac) : [...m, mac]
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
/** Переименованное устройство отмечается: имя сохраняется только у выбранных устройств, а раз его назвали — оно нужно. */
function finishRename() {
  const mac = editing.value
  if (mac && editText.value.trim()) {
    renames.value = { ...renames.value, [mac]: editText.value.trim() }
    if (draft.value && !draft.value.macs.includes(mac)) draft.value.macs = [...draft.value.macs, mac]
  }
  editing.value = null
}

// ---- автосохранение ----
const vpnUsed = computed(() => !!simple.value && (simple.value.mode === 'all' || simple.value.services.length > 0 || simple.value.customDomains.length > 0))
function blocker(): Blocker | null {
  if (draft.value?.mode === 'selected' && !draft.value.macs.length) return { text: 'Отметьте хотя бы одно устройство — или выберите «Все устройства».' }
  if (vpnUsed.value && !serverReady.value) return { text: 'Сначала настройте сервер VPN.', action: { label: 'Открыть «Сервер»', run: () => emit('navigate', 'server') } }
  const b = buildBlocker()
  return b ? { text: b } : null
}
useAutosave({
  source: [draft, renames],
  dirty: () => dirty.value,
  blocker,
  run: async () => {
    if (!simple.value || !draft.value) return 'Настройки ещё не загружены.'
    const s: Simple = { ...simple.value, devices: draft.value.mode === 'all' ? 'all' : [...draft.value.macs] }
    const cfg = build(s, knownDevicesNow(renames.value))
    if (typeof cfg === 'string') return cfg
    const r = await save(cfg, '')
    if (r.ok) renames.value = {}
    return r
  },
})
onMounted(() => void loadLeases())
</script>

<template>
  <section class="sect" aria-label="Устройства">
    <ManualBanner v-if="simpleState && !simpleState.canonical" :reason="simpleState.reason" />

    <template v-else-if="draft">
      <div class="card">
        <div class="card__head">
          <div>
            <h2 class="card__title">Для каких устройств работает VPN</h2>
            <p class="card__sub">{{ draft.mode === 'all'
              ? 'Рекомендуется. Настройки сайтов действуют для всех устройств дома, новые подключатся сами.'
              : 'Например, только телевизор и ноутбук. Остальные устройства открывают все сайты напрямую.' }}</p>
          </div>
          <Segmented v-model="draft.mode" :options="MODES" label="Устройства" name="devmode" />
        </div>
      </div>

      <div class="card card--flush">
        <div class="card__head card__head--pad">
          <div>
            <h2 class="card__title">Устройства дома</h2>
            <p class="card__sub">
              {{ rows.length ? `${plural(rows.length, 'устройство', 'устройства', 'устройств')}, в сети ${online}` : 'Пока никого' }}<template v-if="draft.mode === 'selected'"> · {{ draft.macs.length ? `выбрано: ${draft.macs.length}` : 'ничего не выбрано' }}</template>
            </p>
          </div>
          <div v-if="rows.length > 4" class="search">
            <Search :size="16" class="search__icon" aria-hidden="true" />
            <label for="dev-search" class="sr-only">Найти устройство</label>
            <InputText id="dev-search" v-model="search" placeholder="Имя, IP или MAC" type="search" />
          </div>
        </div>
        <p v-if="!rows.length" class="muted pad">Роутер пока не видит подключённых устройств. Подключите устройство к Wi‑Fi и обновите страницу.</p>
        <ul v-else class="devs">
          <li v-for="d in shown" :key="d.mac" :class="['dev', { 'dev--on': draft.mode === 'selected' && draft.macs.includes(d.mac) }]">
            <span class="avatar" :style="{ '--h': avatarHue(d.mac) }" aria-hidden="true">
              <template v-if="initials(d.name)">{{ initials(d.name) }}</template>
              <Smartphone v-else :size="18" />
            </span>
            <div class="dev__body">
              <form v-if="editing === d.mac" class="dev__rename" @submit.prevent="finishRename">
                <label :for="`rename-${d.mac}`" class="sr-only">Новое имя</label>
                <InputText :id="`rename-${d.mac}`" v-model="editText" maxlength="64" size="small" @keydown.esc="editing = null" @blur="finishRename" />
              </form>
              <span v-else class="dev__name">
                <span class="dev__label">{{ d.name || 'Устройство без имени' }}</span>
                <button v-if="draft.mode === 'selected'" type="button" class="icon-btn" :aria-label="`Переименовать ${d.name || 'устройство'}`" title="Переименовать"
                  @click="startRename(d.mac, d.name)"><Pencil :size="14" aria-hidden="true" /></button>
              </span>
              <span class="dev__meta"><span class="num">{{ d.mac }}</span></span>
            </div>
            <span class="dev__ip num">{{ d.ip ?? '—' }}</span>
            <span :class="['dev__state', { 'dev__state--off': !d.online }]"><span class="dot" aria-hidden="true" />{{ d.online ? 'В сети' : 'Не в сети' }}</span>
            <button v-if="draft.mode === 'selected'" type="button" role="switch" :aria-checked="draft.macs.includes(d.mac)"
              :aria-label="`Через VPN: ${d.name || d.mac}`" class="dev__sw" @click="toggle(d.mac)">
              <span class="dev__sw-label">Через VPN</span>
              <span class="sw" aria-hidden="true"><span class="sw__knob" /></span>
            </button>
          </li>
          <li v-if="!shown.length" class="muted pad">Ничего не нашлось.</li>
        </ul>
        <p v-if="draft.mode === 'selected'" class="hint pad">Имя нужно только вам, чтобы узнавать устройство в списке. Переименованное устройство отмечается само.</p>
      </div>
    </template>
  </section>
</template>
