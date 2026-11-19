<script setup lang="ts">
import { computed, nextTick, onMounted, ref, watch } from 'vue'
import Button from 'primevue/button'
import Checkbox from 'primevue/checkbox'
import InputText from 'primevue/inputtext'
import { build, buildBlocker, config, knownDevicesNow, leases, loadLeases, save, serverReady, simple, simpleState } from '../store'
import { deviceRows, plural } from '../status'
import { normalizeMac, type Simple } from '../simple'
import ManualBanner from './ManualBanner.vue'

const emit = defineEmits<{ navigate: [tab: 'server' | 'sites'] }>()

interface Draft { mode: 'all' | 'selected'; macs: string[] }
const toDraft = (s: Simple): Draft => (s.devices === 'all' ? { mode: 'all', macs: [] } : { mode: 'selected', macs: [...s.devices] })
const draft = ref<Draft | null>(simple.value ? toDraft(simple.value) : null)
/** Переименования этого сеанса: MAC → новое имя. Без них имена из настроек не трогаем. */
const renames = ref<Record<string, string>>({})

const rows = computed(() => (config.value && draft.value ? deviceRows(leases.value, config.value, renames.value, draft.value.macs) : []))
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

// ---- сохранение ----
const saving = ref(false)
const saveError = ref<string | null>(null)
const vpnUsed = computed(() => !!simple.value && (simple.value.mode === 'all' || simple.value.services.length > 0 || simple.value.customDomains.length > 0))
const blocker = computed(() => {
  if (!dirty.value) return null
  if (draft.value?.mode === 'selected' && !draft.value.macs.length) return 'Отметьте хотя бы одно устройство или выберите «Все устройства дома».'
  if (vpnUsed.value && !serverReady.value) return 'server'
  return buildBlocker()
})
async function submit() {
  if (!simple.value || !draft.value || blocker.value) return
  const s: Simple = { ...simple.value, devices: draft.value.mode === 'all' ? 'all' : [...draft.value.macs] }
  const cfg = build(s, knownDevicesNow(renames.value))
  if (typeof cfg === 'string') { saveError.value = cfg; return }
  saving.value = true
  saveError.value = null
  try {
    if ((await save(cfg)).ok) renames.value = {}
  } finally { saving.value = false }
}
onMounted(() => void loadLeases())
</script>

<template>
  <section class="sect" aria-labelledby="dev-title">
    <header class="sect__head">
      <h1 id="dev-title" class="sect__title">Устройства</h1>
      <p class="sect__lead">Для каких устройств дома работают настройки сайтов.</p>
    </header>

    <ManualBanner v-if="simpleState && !simpleState.canonical" :reason="simpleState.reason" />

    <template v-else-if="draft">
      <div class="choice" role="radiogroup" aria-label="Устройства">
        <label :class="['choice__opt', { 'choice__opt--on': draft.mode === 'all' }]">
          <input v-model="draft.mode" type="radio" value="all" class="choice__radio" />
          <span class="choice__text">
            <span class="choice__label">Все устройства дома</span>
            <span class="choice__note">Рекомендуется. Новые устройства тоже подключатся сами.</span>
          </span>
        </label>
        <label :class="['choice__opt', { 'choice__opt--on': draft.mode === 'selected' }]">
          <input v-model="draft.mode" type="radio" value="selected" class="choice__radio" />
          <span class="choice__text">
            <span class="choice__label">Только выбранные</span>
            <span class="choice__note">Например, только телевизор и ноутбук. Остальные устройства открывают все сайты напрямую.</span>
          </span>
        </label>
      </div>

      <div v-if="draft.mode === 'selected'" class="card">
        <div class="card__head">
          <h2 class="card__title">Устройства дома</h2>
          <span class="card__meta">{{ draft.macs.length ? `Выбрано: ${draft.macs.length}` : 'Ничего не выбрано' }}</span>
        </div>
        <p v-if="!rows.length" class="muted">Роутер пока не видит подключённых устройств. Подключите устройство к Wi‑Fi и обновите страницу.</p>
        <ul v-else class="devs">
          <li v-for="d in rows" :key="d.mac" :class="['dev', { 'dev--on': draft.macs.includes(d.mac) }]">
            <Checkbox :model-value="draft.macs.includes(d.mac)" binary :input-id="`dev-${d.mac}`" @update:model-value="toggle(d.mac)" />
            <div class="dev__body">
              <form v-if="editing === d.mac" class="dev__rename" @submit.prevent="finishRename">
                <label :for="`rename-${d.mac}`" class="sr-only">Новое имя</label>
                <InputText :id="`rename-${d.mac}`" v-model="editText" maxlength="64" size="small" @keydown.esc="editing = null" @blur="finishRename" />
              </form>
              <label v-else :for="`dev-${d.mac}`" class="dev__name">{{ d.name || 'Устройство без имени' }}</label>
              <span class="dev__meta">
                <span v-if="!d.online" class="dev__off">не в сети · </span>
                <span v-if="d.ip">{{ d.ip }} · </span><span class="num">{{ d.mac }}</span>
              </span>
            </div>
            <Button v-if="editing !== d.mac" label="Переименовать" variant="text" severity="secondary" size="small" @click="startRename(d.mac, d.name)" />
          </li>
        </ul>
        <p class="hint">Имя нужно только вам, чтобы узнавать устройство в списке. Переименованное устройство отмечается само; имя сохранится по кнопке «Сохранить».</p>
      </div>
      <p v-else-if="rows.length" class="muted">Сейчас дома {{ plural(rows.length, 'устройство', 'устройства', 'устройств') }} в сети.</p>

      <div class="savebar">
        <div class="savebar__in">
          <span class="savebar__text" aria-live="polite">
            <template v-if="blocker === 'server'">Сначала настройте сервер VPN.
              <Button label="Открыть «Сервер»" variant="link" class="inline-link" @click="emit('navigate', 'server')" /></template>
            <template v-else-if="blocker">{{ blocker }}</template>
            <template v-else-if="saveError">{{ saveError }}</template>
            <template v-else-if="dirty">Есть несохранённые изменения</template>
            <template v-else>Всё сохранено</template>
          </span>
          <Button label="Сохранить" :loading="saving" :disabled="!dirty || !!blocker || saving" @click="submit" />
        </div>
      </div>
    </template>
  </section>
</template>
