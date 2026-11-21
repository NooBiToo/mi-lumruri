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
import { dateTag, t } from '../i18n'
import Segmented from './Segmented.vue'

const status = computed(() => lists.value?.status ?? null)
const snapshot = computed(() => {
  const d = catalog.value?.date
  return d ? new Date(`${d}T00:00:00`).toLocaleDateString(dateTag(), { day: 'numeric', month: 'long' }) : null
})
const stateText = computed(() => {
  const s = status.value
  if (s && !s.ok) {
    return s.errors.length
      ? t('Последняя проверка {when} не удалась: {e}. Действуют прежние списки', { when: when(s.checked), e: s.errors[0]! })
      : t('Последняя проверка {when} не удалась. Действуют прежние списки', { when: when(s.checked) })
  }
  if (s?.updated) return t('Обновлены {updated}, проверены {checked}', { updated: when(s.updated), checked: when(s.checked) })
  if (!snapshot.value) return t('Списки ещё не загружены')
  return s
    ? t('Из установки, снимок от {d}; проверены {when} — новее нет', { d: snapshot.value, when: when(s.checked) })
    : t('Из установки, снимок от {d}', { d: snapshot.value })
})

const updating = ref(false)
let timer: number | undefined
async function update() {
  updating.value = true
  try {
    const r = await api.updateLists()
    if (r.status === 202) {
      notify.show('info', t('Проверяю обновления списков'), t('Это займёт до минуты'))
      timer = window.setTimeout(() => void loadLists().finally(() => (updating.value = false)), 20000)
    } else {
      notify.show('error', t('Не получилось'), r.body.error?.message)
      updating.value = false
    }
  } catch {
    updating.value = false
  }
}

const PERIODS = computed(() => [
  { value: '6h' as const, label: t('Каждые 6 часов') }, { value: 'daily' as const, label: t('Раз в сутки') },
  { value: 'weekly' as const, label: t('Раз в неделю') }, { value: 'manual' as const, label: t('Вручную') },
])
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
        <h2 id="lists-title" class="card__title">{{ t('Списки сайтов') }}</h2>
        <p class="card__sub">{{ t('Готовые списки сервисов —') }} <a href="https://github.com/itdoginfo/allow-domains" target="_blank" rel="noopener">itdoginfo/allow-domains</a>.
          {{ t('Роутер сам проверяет новые версии; кнопка «Обновить» проверяет сразу — вместе со списком блокировки рекламы') }}</p>
      </div>
      <Button :label="t('Обновить')" severity="secondary" variant="outlined" :loading="updating || lists?.requested" :disabled="updating || lists?.requested" @click="update">
        <template #icon><RefreshCw :size="16" class="p-button-icon-left" aria-hidden="true" /></template>
      </Button>
    </div>
    <span :class="['adblock__state', { 'adblock__state--bad': status && !status.ok }]">
      <span :class="['led', status && !status.ok ? 'led--warn' : 'led--ok']" aria-hidden="true" />
      <span class="meta">{{ stateText }}</span>
    </span>
    <div class="field">
      <span id="lists-period" class="field__label">{{ t('Проверять обновления') }}</span>
      <Segmented v-model="period" class="self-start" :options="PERIODS" :label="t('Как часто проверять обновления списков')" name="lists-update" />
    </div>
  </div>
</template>
