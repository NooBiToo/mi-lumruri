<script setup lang="ts">
// Готовые списки сайтов (itdoginfo/allow-domains): когда обновлялись, кнопка «Обновить» и частота проверки.
// «Обновить» обновляет и список блокировки рекламы (служба сбрасывает его отсрочку).
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import Button from 'primevue/button'
import { RefreshCw } from 'lucide-vue-next'
import { api, type ListsUpdate } from '../api'
import { catalog, config, lists, loadLists, notify, save } from '../store'
import { when } from '../status'
import { saveNow } from '../autosave'
import Segmented from './Segmented.vue'

const status = computed(() => lists.value?.status ?? null)
const snapshot = computed(() => {
  const d = catalog.value?.date
  return d ? new Date(`${d}T00:00:00`).toLocaleDateString('ru-RU', { day: 'numeric', month: 'long' }) : null
})
const stateText = computed(() => {
  const s = status.value
  if (s && !s.ok) return `Последняя проверка ${when(s.checked)} не удалась${s.errors.length ? `: ${s.errors[0]}` : ''}. Действуют прежние списки`
  if (s?.updated) return `Обновлены ${when(s.updated)}, проверены ${when(s.checked)}`
  return snapshot.value ? `Из установки, снимок от ${snapshot.value}${s ? `; проверены ${when(s.checked)} — новее нет` : ''}` : 'Списки ещё не загружены'
})

const updating = ref(false)
let timer: number | undefined
async function update() {
  updating.value = true
  try {
    const r = await api.updateLists()
    if (r.status === 202) {
      notify.show('info', 'Проверяю обновления списков', 'Это займёт до минуты')
      timer = window.setTimeout(() => void loadLists().finally(() => (updating.value = false)), 20000)
    } else {
      notify.show('error', 'Не получилось', r.body.error?.message)
      updating.value = false
    }
  } catch {
    updating.value = false
  }
}

const PERIODS = [
  { value: '6h' as const, label: 'Каждые 6 часов' }, { value: 'daily' as const, label: 'Раз в сутки' },
  { value: 'weekly' as const, label: 'Раз в неделю' }, { value: 'manual' as const, label: 'Вручную' },
]
const period = ref<ListsUpdate>(config.value?.schedule?.lists ?? 'daily')
watch(() => config.value?.schedule?.lists, (v) => { period.value = v ?? 'daily' })
watch(period, async (v) => {
  const c = config.value
  if (!c || (c.schedule?.lists ?? 'daily') === v) return
  const ok = await saveNow(() => save({ ...c, schedule: { ...c.schedule, lists: v } }, ''))
  if (!ok) period.value = config.value?.schedule?.lists ?? 'daily'
})

onMounted(() => void loadLists())
onBeforeUnmount(() => clearTimeout(timer))
</script>

<template>
  <div class="card">
    <div class="card__head">
      <div>
        <h2 id="lists-title" class="card__title">Списки сайтов</h2>
        <p class="card__sub">Готовые списки сервисов — <a href="https://github.com/itdoginfo/allow-domains" target="_blank" rel="noopener">itdoginfo/allow-domains</a>.
          Роутер сам проверяет новые версии; кнопка «Обновить» проверяет сразу — вместе со списком блокировки рекламы</p>
      </div>
      <Button label="Обновить" severity="secondary" variant="outlined" :loading="updating || lists?.requested" :disabled="updating || lists?.requested" @click="update">
        <template #icon><RefreshCw :size="16" class="p-button-icon-left" aria-hidden="true" /></template>
      </Button>
    </div>
    <span :class="['adblock__state', { 'adblock__state--bad': status && !status.ok }]">
      <span :class="['led', status && !status.ok ? 'led--warn' : 'led--ok']" aria-hidden="true" />
      <span class="meta">{{ stateText }}</span>
    </span>
    <div class="field">
      <span id="lists-period" class="field__label">Проверять обновления</span>
      <Segmented v-model="period" class="self-start" :options="PERIODS" label="Как часто проверять обновления списков" name="lists-update" />
    </div>
  </div>
</template>
