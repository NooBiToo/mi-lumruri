<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import Button from 'primevue/button'
import Message from 'primevue/message'
import { api } from '../api'
import { build, catalog, knownDevicesNow, lists, loadLists, loadStatus, notify, profile, save, serverReady, simple, simpleState, tunnel } from '../store'
import { devicesSummary, sitesSummary, when } from '../status'

const emit = defineEmits<{ navigate: [tab: 'server' | 'sites' | 'devices'] }>()

const busy = ref(false)
const error = ref<string | null>(null)
const nothingSelected = computed(() => !!simple.value && simple.value.mode === 'selected' && !simple.value.services.length && !simple.value.customDomains.length)

async function toggle() {
  const s = simple.value
  if (!s) return
  const cfg = build({ ...s, enabled: !s.enabled }, knownDevicesNow())
  if (typeof cfg === 'string') { error.value = cfg; return }
  busy.value = true
  error.value = null
  try {
    // выключенный VPN выключает и обход блокировок: правила с Zapret тоже выключаются, всё идёт напрямую
    if ((await save(cfg, '')).ok) {
      notify.show('success', s.enabled ? 'VPN выключен' : 'VPN включён, применяю на роутере',
        s.enabled ? (s.rest === 'zapret' ? 'Обход блокировок (Zapret) тоже выключен: все сайты открываются напрямую.' : 'Все сайты открываются напрямую.') : undefined)
    }
  } finally { busy.value = false }
}

// ---- списки сайтов ----
const updating = ref(false)
const listsStatus = computed(() => lists.value?.status ?? null)
const snapshot = computed(() => {
  const d = catalog.value?.date
  return d ? new Date(`${d}T00:00:00`).toLocaleDateString('ru-RU', { day: 'numeric', month: 'long', year: 'numeric' }) : null
})
let listsTimer: number | undefined
async function updateLists() {
  updating.value = true
  try {
    const r = await api.updateLists()
    if (r.status === 202) {
      notify.show('info', 'Проверяю обновления списков', 'Это займёт до минуты.')
      listsTimer = window.setTimeout(() => void loadLists().finally(() => (updating.value = false)), 20000)
    } else {
      notify.show('error', 'Не получилось', r.body.error?.message)
      updating.value = false
    }
  } catch {
    updating.value = false
  }
}
onMounted(() => { void loadStatus(); void loadLists() })
onBeforeUnmount(() => clearTimeout(listsTimer))
</script>

<template>
  <section class="sect" aria-labelledby="st-title">
    <h1 id="st-title" class="sr-only">Состояние</h1>

    <div :class="['hero', `hero--${tunnel.tone}`]">
      <span class="hero__dot" aria-hidden="true" />
      <div class="hero__text">
        <p class="hero__title">{{ tunnel.title }}</p>
        <p v-if="tunnel.detail" class="hero__detail">{{ tunnel.detail }}</p>
      </div>
      <div class="hero__act">
        <Button v-if="!serverReady" label="Настроить сервер" @click="emit('navigate', 'server')" />
        <Button v-else-if="simple && nothingSelected && simple.enabled" label="Выбрать сайты" @click="emit('navigate', 'sites')" />
        <Button v-else-if="simple" :label="simple.enabled ? 'Выключить VPN' : 'Включить VPN'" :severity="simple.enabled ? 'secondary' : undefined"
          :variant="simple.enabled ? 'outlined' : undefined" :loading="busy" @click="toggle" />
      </div>
    </div>
    <Message v-if="error" severity="error" :closable="false">{{ error }}</Message>

    <dl v-if="simple" class="summary">
      <div class="summary__row">
        <dt>Через VPN</dt>
        <dd>{{ sitesSummary(simple, catalog) }}</dd>
        <Button label="Изменить" variant="link" class="inline-link" @click="emit('navigate', 'sites')" />
      </div>
      <div class="summary__row">
        <dt>Для устройств</dt>
        <dd>{{ devicesSummary(simple) }}</dd>
        <Button label="Изменить" variant="link" class="inline-link" @click="emit('navigate', 'devices')" />
      </div>
      <div class="summary__row">
        <dt>Остальные сайты</dt>
        <dd>{{ simple.rest === 'zapret' ? 'Напрямую с обходом блокировок' : 'Напрямую' }}</dd>
        <span />
      </div>
      <div v-if="profile?.endpoint" class="summary__row">
        <dt>Сервер</dt>
        <dd>{{ profile.endpoint.sni || profile.endpoint.server }}</dd>
        <Button label="Изменить" variant="link" class="inline-link" @click="emit('navigate', 'server')" />
      </div>
    </dl>
    <Message v-else-if="simpleState && !simpleState.canonical" severity="warn" :closable="false">
      Настройки изменены вручную, поэтому здесь их не показать. Подробнее — на экране «Сайты».
    </Message>

    <div class="card card--row">
      <div>
        <h2 class="card__title">Списки сайтов</h2>
        <p class="muted">
          <template v-if="listsStatus?.updated">Обновлены {{ when(listsStatus.updated) }}.</template>
          <template v-else-if="snapshot">Списки из установки (снимок от {{ snapshot }}).</template>
          Роутер проверяет обновления сам раз в сутки.
        </p>
        <p v-if="listsStatus && !listsStatus.ok" class="warn-text">Последняя проверка {{ when(listsStatus.checked) }} не удалась — действуют прежние списки.</p>
      </div>
      <Button label="Обновить списки" severity="secondary" variant="text" :loading="updating || lists?.requested" @click="updateLists" />
    </div>
  </section>
</template>
