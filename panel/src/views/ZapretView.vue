<script setup lang="ts">
// Zapret: состояние nfqws2, способ обхода (вручную или подбором), автопроверка способа по расписанию.
// Что открывать с обходом блокировок, выбирается на «Сайтах».
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import Button from 'primevue/button'
import Message from 'primevue/message'
import Select from 'primevue/select'
import { api, type ZapretCheck, type ZapretTestState } from '../api'
import { config, loadConfig, save, saveZapret, service, simple } from '../store'
import { usesZapret, when, zapretIdle, zapretProgress, zapretResult } from '../status'
import { AUTO, generalStrategies, youtubeStrategies, pickedByTest } from '../zapret'
import { saveNow, saveStatus } from '../autosave'
import { t } from '../i18n'
import Segmented from '../components/Segmented.vue'

const emit = defineEmits<{ navigate: [tab: 'sites'] }>()

// ---- состояние ----
const used = computed(() => usesZapret(simple.value))
const idle = computed(() => zapretIdle(simple.value))
const nfqwsUp = computed(() => ((service.value?.service as { engines?: Record<string, boolean> } | undefined)?.engines?.nfqws2) !== false)
const stateTone = computed(() => (!used.value || idle.value ? 'idle' : nfqwsUp.value ? 'ok' : 'bad'))
const stateText = computed(() => (!used.value ? t('Не используется') : idle.value ? t('Сейчас не нужен') : nfqwsUp.value ? t('Работает') : t('nfqws2 не запущен')))
const stateDetail = computed(() => {
  const s = simple.value
  if (!s || !used.value) return t('Обход блокировок включается на «Сайтах»: для отдельных сервисов (Zapret на плитке) или для всех остальных сайтов')
  if (idle.value) return idle.value
  const parts: string[] = []
  if (s.zapretServices.length || s.zapretDomains.length) parts.push(t('сайты с обходом блокировок'))
  if (s.rest === 'zapret' && s.enabled) parts.push(t('все остальные сайты'))
  return nfqwsUp.value ? t('Обрабатывает: {what}', { what: parts.join(t(' и ')) }) : t('Программа обхода не запущена. Откройте «Диагностику» — там видно, почему')
})

// ---- подбор способа ----
const test = ref<ZapretTestState | null>(null)
const testError = ref<string | null>(null)
let poll: number | undefined
let unmounted = false
async function readTest() {
  const r = await api.zapretTest()
  if (unmounted || !r.body.ok || !r.body.test) return
  const was = test.value?.state
  test.value = r.body.test
  const running = r.body.test.state === 'running' || r.body.requested
  if (running && poll === undefined) poll = window.setInterval(() => void readTest(), 2000)
  if (!running && poll !== undefined) { clearInterval(poll); poll = undefined }
  // подбор мог сменить способ: перечитать настройки
  if (was === 'running' && r.body.test.state !== 'running') await loadConfig()
}
async function startTest() {
  testError.value = null
  const r = await api.startZapretTest()
  if (unmounted) return
  if (r.status === 202 || r.status === 409) {
    test.value = { ...(test.value ?? {}), state: 'running', progress: undefined }
    if (poll === undefined) poll = window.setInterval(() => void readTest(), 2000)
  } else testError.value = r.body.error?.message ?? t('Ошибка {status}', { status: r.status })
}
const running = computed(() => test.value?.state === 'running')
const progress = computed(() => {
  const p = test.value?.progress
  return p && p.total ? Math.round((Math.min(p.done, p.total) / p.total) * 100) : null
})
const result = computed(() => (test.value && (test.value.state === 'done' || test.value.state === 'failed') ? zapretResult(test.value) : null))

// ---- ручной выбор способа: сохраняется сразу ----
const general = ref(config.value?.zapret?.strategy ?? AUTO)
const youtube = ref(config.value?.zapret?.youtube ?? AUTO)
watch(() => config.value?.zapret, (z) => { general.value = z?.strategy ?? AUTO; youtube.value = z?.youtube ?? AUTO })
const GENERAL_STRATEGIES = computed(generalStrategies)
const YOUTUBE_STRATEGIES = computed(youtubeStrategies)
const picked = computed(() => pickedByTest(config.value?.zapret, test.value))
const pickedWhen = computed(() => when(test.value?.finished ?? test.value?.started))
const savingZapret = ref(false)
async function chooseStrategy() {
  const z = { strategy: general.value, youtube: youtube.value }
  const cur = config.value?.zapret
  if ((cur?.strategy ?? AUTO) === z.strategy && (cur?.youtube ?? AUTO) === z.youtube) return
  savingZapret.value = true
  const ok = await saveNow(() => saveZapret(z))
  savingZapret.value = false
  if (!ok) { general.value = config.value?.zapret?.strategy ?? AUTO; youtube.value = config.value?.zapret?.youtube ?? AUTO }
}
const strategyLocked = computed(() => running.value || savingZapret.value || saveStatus.tone === 'saving')
function resetAuto() {
  general.value = AUTO
  youtube.value = AUTO
  void chooseStrategy()
}
const isAuto = computed(() => general.value === AUTO && youtube.value === AUTO)

// ---- автопроверка по расписанию ----
const CHECKS = computed(() => [{ value: 'off' as const, label: t('Выключена') }, { value: 'daily' as const, label: t('Раз в сутки') }, { value: 'weekly' as const, label: t('Раз в неделю') }])
const check = ref<ZapretCheck>(config.value?.schedule?.zapret_check ?? 'off')
watch(() => config.value?.schedule?.zapret_check, (v) => { check.value = v ?? 'off' })
watch(check, async (v) => {
  const c = config.value
  if (!c || (c.schedule?.zapret_check ?? 'off') === v) return
  const ok = await saveNow(() => save({ ...c, schedule: { ...c.schedule, zapret_check: v } }, ''))
  if (!ok) check.value = config.value?.schedule?.zapret_check ?? 'off'
})

onMounted(() => void readTest())
onBeforeUnmount(() => { unmounted = true; clearInterval(poll); poll = undefined })
</script>

<template>
  <section class="sect" aria-label="Zapret">
    <div class="card state">
      <span :class="['led', 'led--lg', `led--${stateTone}`]" aria-hidden="true" />
      <div class="state__text">
        <h2 class="state__title">{{ stateText }}</h2>
        <p class="state__detail">{{ stateDetail }}</p>
      </div>
      <Button :label="t('Что обходить')" severity="secondary" variant="outlined" class="state__act" @click="emit('navigate', 'sites')" />
    </div>

    <div class="card">
      <div class="card__head">
        <div>
          <h2 class="card__title">{{ t('Способ обхода блокировок') }}</h2>
          <p class="card__sub">{{ t('Автоматический режим перебирает готовые способы сам. Если сайты всё равно тормозят — подберите способ под ваш интернет или выберите вручную') }}</p>
        </div>
        <Button v-if="!isAuto" :label="t('Вернуть автоматический')" severity="secondary" variant="text" :disabled="strategyLocked" @click="resetAuto" />
      </div>
      <div class="pick">
        <div class="field">
          <label for="zapret-general" class="field__label">{{ t('Для всех сайтов') }}</label>
          <Select v-model="general" input-id="zapret-general" :options="GENERAL_STRATEGIES" option-label="label" option-value="id"
            :disabled="strategyLocked" scroll-height="22rem" class="pick__select" @change="chooseStrategy">
            <template #option="{ option }">
              <span class="opt"><span class="opt__label">{{ option.label }}</span><span class="opt__desc">{{ option.desc }}</span></span>
            </template>
          </Select>
          <span class="field__hint">{{ picked.general ? t('Подобран автоматически {when}. ', { when: pickedWhen }) : '' }}{{ GENERAL_STRATEGIES.find((s) => s.id === general)?.desc }}</span>
        </div>
        <div class="field">
          <label for="zapret-youtube" class="field__label">{{ t('Для YouTube') }}</label>
          <Select v-model="youtube" input-id="zapret-youtube" :options="YOUTUBE_STRATEGIES" option-label="label" option-value="id"
            :disabled="strategyLocked" scroll-height="22rem" class="pick__select" @change="chooseStrategy">
            <template #option="{ option }">
              <span class="opt"><span class="opt__label">{{ option.label }}</span><span class="opt__desc">{{ option.desc }}</span></span>
            </template>
          </Select>
          <span class="field__hint">{{ picked.youtube ? t('Подобран автоматически {when}. ', { when: pickedWhen }) : '' }}{{ YOUTUBE_STRATEGIES.find((s) => s.id === youtube)?.desc }}</span>
        </div>
      </div>
    </div>

    <div class="card">
      <div>
        <h2 class="card__title">{{ t('Подбор способа') }}</h2>
        <p class="card__sub">{{ t('Роутер сам проверит способы на YouTube, Discord и других сайтах и применит лучший — только если он лучше, чем сейчас. Займёт несколько минут, интернет при этом работает') }}</p>
      </div>
      <template v-if="used && !idle">
        <div v-if="running" class="zapret__run" aria-live="polite">
          <div class="bar" role="progressbar" :aria-label="t('Подбор способа')" :aria-valuenow="progress ?? undefined" aria-valuemin="0" aria-valuemax="100">
            <span :class="['bar__fill', { 'bar__fill--wait': progress === null }]" :style="progress !== null ? { width: `${progress}%` } : undefined" />
          </div>
          <span class="hint">{{ test && zapretProgress(test) }}</span>
        </div>
        <Button v-else :label="t('Подобрать способ')" class="self-start" @click="startTest" />
        <div v-if="result && !running" :class="['zapret__result', { 'zapret__result--bad': test?.state === 'failed' }]">
          <strong v-if="result.summary">{{ result.summary }}</strong>
          <span>{{ result.message }}</span>
          <span class="muted">{{ t('Подбор от {when}', { when: when(test?.finished ?? test?.started) }) }}</span>
        </div>
        <Message v-if="testError" severity="error" :closable="false">{{ testError }}</Message>
      </template>
      <p v-else class="hint">{{ idle ?? t('Подбирать не на чем: обход блокировок сейчас не используется') }}</p>

      <div class="zapret__check">
        <span class="setrow__text">
          <span class="setrow__title">{{ t('Автопроверка способа') }}</span>
          <span class="setrow__desc">{{ t('Роутер сам повторяет подбор по расписанию: если действующий способ перестал помогать, найдёт новый, а если новый хуже — оставит прежний') }}</span>
        </span>
        <Segmented v-model="check" :options="CHECKS" :label="t('Автопроверка способа')" name="zapret-check" />
      </div>
    </div>
  </section>
</template>
