<script setup lang="ts">
// Обновление пакета из релизов GitHub: проверка, установка и перезапуск службы на роутере (mitt-update.sh).
// Во время перезапуска панель недолго недоступна — опрос переживает ошибки сети.
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import Button from 'primevue/button'
import { Download, RefreshCw } from 'lucide-vue-next'
import { api, type UpdateResponse, type UpdateState } from '../api'
import { notify, service } from '../store'
import { dateTag, t } from '../i18n'

const resp = ref<UpdateResponse | null>(null)
const u = computed<UpdateState | null>(() => resp.value?.update ?? null)
const BUSY = ['checking', 'downloading', 'installing', 'restarting']
const busy = computed(() => !!resp.value?.running || (!!u.value && BUSY.includes(u.value.state)))
const release = computed(() => (service.value?.service as { release?: string } | undefined)?.release ?? '')
const installed = computed(() => u.value?.installed || release.value || '—')
const published = computed(() => (u.value?.published ? new Date(u.value.published).toLocaleDateString(dateTag(), { day: 'numeric', month: 'long', year: 'numeric' }) : ''))
/** Другой ключ подписи, и это ключ релизов GitHub: можно перейти на релизы GitHub. */
const officialSwitch = computed(() => !!u.value?.package_key && u.value.package_key === u.value.official_key)

const step = (s: string) => ({
  checking: t('Проверяю релизы на GitHub…'), downloading: t('Скачиваю пакет…'), installing: t('Устанавливаю…'),
  restarting: t('Перезапускаю службу — панель вернётся через полминуты…'),
})[s] ?? ''
const text = computed(() => {
  const s = u.value
  if (!s) return busy.value ? step('checking') : t('Проверьте, есть ли новая версия')
  if (BUSY.includes(s.state)) return step(s.state)
  if (s.state === 'done') return t('Обновлено до {v}', { v: s.installed })
  if (s.state === 'error') {
    if (officialSwitch.value) return t('Пакеты релизов GitHub подписаны другим ключом, чем установленная сборка. Можно перейти на релизы GitHub — настройки сохранятся')
    return t('Не получилось: {e}', { e: s.error ?? t('неизвестная ошибка') })
  }
  if (s.newer) return published.value ? t('Доступна версия {v} от {d}', { v: s.latest, d: published.value }) : t('Доступна версия {v}', { v: s.latest })
  return t('Установлена последняя версия ({v})', { v: s.latest })
})
const tone = computed(() => (u.value?.state === 'error' ? 'warn' : u.value?.newer || u.value?.state === 'done' ? 'vpn' : busy.value ? 'idle' : 'ok'))

let timer: number | undefined
async function poll() {
  clearTimeout(timer)
  try {
    resp.value = await api.update().then((r) => r.body)
  } catch {
    // перезапуск службы: панель на время недоступна
  }
  if (busy.value) timer = window.setTimeout(() => void poll(), 2000)
}
async function send(kind: 'check' | 'install' | 'trust') {
  const r = kind === 'check' ? await api.checkUpdate() : await api.installUpdate(kind === 'trust')
  if (r.status !== 202) { notify.show('error', t('Не получилось'), r.body.error?.message); return }
  if (resp.value) resp.value = { ...resp.value, running: true }
  else resp.value = { ok: true, running: true, update: null, issues: [] }
  timer = window.setTimeout(() => void poll(), 1500)
}

onMounted(() => void poll())
onBeforeUnmount(() => clearTimeout(timer))
</script>

<template>
  <div class="setblock" role="group" aria-labelledby="update-title">
    <span class="setrow__text">
      <span id="update-title" class="setrow__title">{{ t('Обновление') }}</span>
      <span class="setrow__desc">{{ t('Установлена версия {v}.', { v: installed }) }} {{ t('Новые версии роутер берёт из релизов на GitHub, проверяет подпись и ставит сам; настройки сохраняются') }}
        (<a href="https://github.com/NooBiToo/mi-lumruri/releases" target="_blank" rel="noopener">GitHub</a>)</span>
    </span>
    <span :class="['adblock__state', { 'adblock__state--bad': u?.state === 'error' }]" aria-live="polite">
      <span :class="['led', `led--${tone}`]" aria-hidden="true" />
      <span class="meta">{{ text }}</span>
    </span>
    <div class="update__actions">
      <Button v-if="u?.newer && !busy && u.state !== 'done' && !officialSwitch" :label="t('Обновить до {v}', { v: u.latest })" @click="send('install')">
        <template #icon><Download :size="16" class="p-button-icon-left" aria-hidden="true" /></template>
      </Button>
      <Button v-if="officialSwitch && !busy" :label="t('Перейти на релизы GitHub и обновить')" @click="send('trust')">
        <template #icon><Download :size="16" class="p-button-icon-left" aria-hidden="true" /></template>
      </Button>
      <Button :label="t('Проверить')" severity="secondary" variant="outlined" :loading="busy" :disabled="busy" @click="send('check')">
        <template #icon><RefreshCw :size="16" class="p-button-icon-left" aria-hidden="true" /></template>
      </Button>
      <a v-if="u?.page && u.newer" :href="u.page" target="_blank" rel="noopener" class="update__notes">{{ t('Что нового') }}</a>
    </div>
    <span v-if="officialSwitch && !busy" class="field__hint">{{ t('Ключ релизов GitHub: {k}. После перехода роутер будет принимать только пакеты с этим ключом. Вернуться к своим сборкам — установкой с флагом --trust-key', { k: u?.official_key ?? '' }) }}</span>
  </div>
</template>

<style scoped>
.update__actions { display: flex; flex-wrap: wrap; align-items: center; gap: 0.5rem; }
.update__notes { font-size: 0.875rem; }
</style>
