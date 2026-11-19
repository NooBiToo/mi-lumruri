<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import Button from 'primevue/button'
import InputText from 'primevue/inputtext'
import Message from 'primevue/message'
import { Search, WandSparkles } from 'lucide-vue-next'
import { api, type ZapretTestState } from '../api'
import { build, buildBlocker, catalog, config, knownDevicesNow, loadConfig, save, scrollTarget, serverReady, simple, simpleState } from '../store'
import { strategyLabel, testedAt, when, zapretIdle, zapretProgress, zapretResult } from '../status'
import { normalizeDomain, type Simple } from '../simple'
import { useAutosave, type Blocker } from '../autosave'
import ManualBanner from './ManualBanner.vue'
import Segmented from '../components/Segmented.vue'
import ServiceLogo from '../components/ServiceLogo.vue'
import DomainChips from '../components/DomainChips.vue'

const emit = defineEmits<{ navigate: [tab: 'server' | 'devices'] }>()

// ---- черновик экрана ----
interface Draft { mode: Simple['mode']; services: string[]; custom: string[]; except: string[]; rest: Simple['rest'] }
const toDraft = (s: Simple): Draft => ({ mode: s.mode, services: [...s.services], custom: [...s.customDomains], except: [...s.exceptions], rest: s.rest })
const draft = ref<Draft | null>(simple.value ? toDraft(simple.value) : null)
/** Домены так, как их сохранит toConfig: без схемы, пути и повторов. */
const domains = (list: string[]) => [...new Set(list.map(normalizeDomain).filter(Boolean))]
const sameList = (a: string[], b: string[]) => a.length === b.length && a.every((x, i) => x === b[i])
const next = computed<Simple | null>(() => simple.value && draft.value ? {
  ...simple.value, mode: draft.value.mode, services: [...draft.value.services].sort(), customDomains: domains(draft.value.custom),
  exceptions: domains(draft.value.except), rest: draft.value.rest,
} : null)
const dirty = computed(() => {
  const a = simple.value, b = next.value
  if (!a || !b) return false
  return a.mode !== b.mode || a.rest !== b.rest || !sameList([...a.services].sort(), b.services) || !sameList(a.customDomains, b.customDomains) || !sameList(a.exceptions, b.exceptions)
})
// настройки перечитаны (сохранение, другое окно): черновик без правок следует за ними
watch(simple, (s) => { if (s && (!draft.value || !dirty.value)) draft.value = toDraft(s) })

const MODES = [{ value: 'selected' as const, label: 'Только выбранные' }, { value: 'all' as const, label: 'Всё через VPN' }]
const RESTS = [{ value: 'direct' as const, label: 'Напрямую' }, { value: 'zapret' as const, label: 'С обходом блокировок (Zapret)' }]

// ---- сервисы каталога ----
const search = ref('')
const ORDER = ['Сервисы', 'Категории', 'Россия']
/** Хостинги и CDN нужны редко и путают новичка: отдельная группа с пояснением. */
const EXPERT = 'Хостинги и CDN'
const filter = ref<string>('')
const allGroups = computed(() => {
  const all = catalog.value?.services ?? []
  return [...new Set([...ORDER.filter((g) => all.some((s) => s.group === g)), ...all.map((s) => s.group)])]
})
const groups = computed(() => {
  const q = search.value.trim().toLowerCase()
  const all = catalog.value?.services ?? []
  return allGroups.value.filter((g) => !filter.value || g === filter.value)
    .map((g) => ({ name: g, items: all.filter((s) => s.group === g && (!q || s.name.toLowerCase().includes(q) || s.id.includes(q))) }))
    .filter((g) => g.items.length)
})
const countIn = (g: string) => (catalog.value?.services ?? []).filter((s) => s.group === g && draft.value?.services.includes(s.id)).length
function toggle(id: string) {
  if (!draft.value) return
  const s = draft.value.services
  draft.value.services = s.includes(id) ? s.filter((x) => x !== id) : [...s, id]
}

// ---- автосохранение ----
const usesVpn = computed(() => !!next.value && (next.value.mode === 'all' || next.value.services.length > 0 || next.value.customDomains.length > 0))
function blocker(): Blocker | null {
  if (usesVpn.value && !serverReady.value) {
    return { text: 'Сначала настройте сервер VPN — без него сайтам некуда идти.', action: { label: 'Открыть «Сервер»', run: () => emit('navigate', 'server') } }
  }
  const b = buildBlocker()
  return b ? { text: b } : null
}
useAutosave({
  source: draft,
  dirty: () => dirty.value,
  blocker,
  run: async () => {
    if (!next.value) return 'Настройки ещё не загружены.'
    const cfg = build(next.value, knownDevicesNow())
    if (typeof cfg === 'string') return cfg
    return save(cfg, '')
  },
})

// ---- подбор стратегии Zapret ----
const test = ref<ZapretTestState | null>(null)
const testError = ref<string | null>(null)
let poll: number | undefined
let unmounted = false
async function readTest() {
  const r = await api.zapretTest()
  // экран могли закрыть, пока шёл запрос: опрос не запускаем
  if (unmounted || !r.body.ok || !r.body.test) return
  const was = test.value?.state
  test.value = r.body.test
  const running = r.body.test.state === 'running' || r.body.requested
  if (running && poll === undefined) poll = window.setInterval(() => void readTest(), 2000)
  if (!running && poll !== undefined) { clearInterval(poll); poll = undefined }
  // подбор мог сменить стратегию: перечитать настройки
  if (was === 'running' && r.body.test.state !== 'running') await loadConfig()
}
async function startTest() {
  testError.value = null
  const r = await api.startZapretTest()
  if (unmounted) return
  if (r.status === 202 || r.status === 409) {
    test.value = { ...(test.value ?? {}), state: 'running', progress: undefined }
    if (poll === undefined) poll = window.setInterval(() => void readTest(), 2000)
  } else testError.value = r.body.error?.message ?? `Ошибка ${r.status}`
}
const running = computed(() => test.value?.state === 'running')
const progress = computed(() => {
  const p = test.value?.progress
  return p && p.total ? Math.round((Math.min(p.done, p.total) / p.total) * 100) : null
})
const result = computed(() => (test.value && (test.value.state === 'done' || test.value.state === 'failed') ? zapretResult(test.value) : null))
const zapretSaved = computed(() => simple.value?.rest === 'zapret')
/** Сохранённые настройки не используют Zapret (VPN выключен или всё через VPN): кнопки подбора нет, есть объяснение. */
const idle = computed(() => zapretIdle(simple.value))
onMounted(async () => {
  void readTest()
  // переход с «Дополнительно» на подбор способа: сразу к блоку Zapret
  if (scrollTarget.value) {
    const id = scrollTarget.value
    scrollTarget.value = null
    await nextTick()
    document.getElementById(id)?.scrollIntoView({ block: 'start' })
  }
})
onBeforeUnmount(() => { unmounted = true; clearInterval(poll); poll = undefined })
</script>

<template>
  <section class="sect" aria-label="Сайты">
    <ManualBanner v-if="simpleState && !simpleState.canonical" :reason="simpleState.reason" />

    <template v-else-if="draft">
      <div class="card">
        <div class="card__head">
          <div>
            <h2 class="card__title">Что открывать через VPN</h2>
            <p class="card__sub">{{ draft.mode === 'selected'
              ? 'Рекомендуется. Через VPN идут только отмеченные сервисы и ваши сайты, остальное — как обычно.'
              : 'Весь интернет через VPN. Сайты из «Не пускать через VPN» откроются напрямую.' }}</p>
          </div>
          <Segmented v-model="draft.mode" :options="MODES" label="Что пускать через VPN" name="mode" />
        </div>
      </div>

      <div v-if="draft.mode === 'selected'" class="card">
        <div class="card__head">
          <div>
            <h2 class="card__title">Сервисы</h2>
            <p class="card__sub">{{ draft.services.length ? `Выбрано: ${draft.services.length}` : 'Ничего не выбрано' }}</p>
          </div>
          <div class="search">
            <Search :size="16" class="search__icon" aria-hidden="true" />
            <label for="svc-search" class="sr-only">Найти сервис</label>
            <InputText id="svc-search" v-model="search" placeholder="Найти сервис" type="search" />
          </div>
        </div>
        <template v-if="catalog">
          <div class="filters" role="group" aria-label="Группы сервисов">
            <button type="button" :class="['filter', { 'filter--on': !filter }]" :aria-pressed="!filter" @click="filter = ''">Все</button>
            <button v-for="g in allGroups" :key="g" type="button" :class="['filter', { 'filter--on': filter === g }]" :aria-pressed="filter === g" @click="filter = g">
              {{ g }}<span v-if="countIn(g)" class="filter__n">{{ countIn(g) }}</span>
            </button>
          </div>
          <div v-for="g in groups" :key="g.name" class="svc-group">
            <h3 v-if="!filter" class="svc-group__title">{{ g.name }}</h3>
            <p v-if="g.name === EXPERT" class="hint">Целые сети хостингов — для специалистов. Нужны, только если вы точно знаете, что сайт работает у такого хостинга и без VPN не открывается.</p>
            <div class="tiles">
              <button v-for="s in g.items" :key="s.id" type="button" role="switch" :aria-checked="draft.services.includes(s.id)"
                :class="['tile', { 'tile--on': draft.services.includes(s.id) }]" @click="toggle(s.id)">
                <ServiceLogo :id="s.id" />
                <span class="tile__name">{{ s.name }}</span>
                <span class="sw" aria-hidden="true"><span class="sw__knob" /></span>
              </button>
            </div>
          </div>
          <p v-if="!groups.length" class="muted">Ничего не нашлось. Сайт можно добавить в «Свои сайты».</p>
          <p class="hint">Списки сайтов обновляются сами раз в сутки. «Всё заблокированное в России» — большой общий список: его хватает, если не знаете, что выбрать.</p>
        </template>
        <Message v-else severity="warn" :closable="false">Каталог сайтов не загрузился. Обновите страницу.</Message>
      </div>

      <div class="grid2">
        <div v-if="draft.mode === 'selected'" class="card">
          <DomainChips id="custom" v-model="draft.custom" label="Свои сайты" placeholder="example.com"
            hint="Введите адрес и нажмите Enter. Поддомены тоже пойдут через VPN." />
        </div>
        <div class="card">
          <DomainChips id="except" v-model="draft.except" label="Не пускать через VPN" placeholder="gosuslugi.ru"
            hint="Эти сайты всегда открываются напрямую — например, банки и госуслуги." />
        </div>
      </div>

      <div id="zapret" class="card">
        <div class="card__head">
          <div>
            <h2 class="card__title">{{ draft.mode === 'selected' ? 'Остальные сайты' : 'Сайты, которые не идут через VPN' }}</h2>
            <p class="card__sub">Обход блокировок помогает, когда YouTube или Discord без VPN тормозят или не открываются.</p>
          </div>
          <Segmented v-model="draft.rest" :options="RESTS" label="Как открывать остальные сайты" name="rest" />
        </div>

        <div v-if="draft.rest === 'zapret'" class="zapret">
          <div class="zapret__line">
            <WandSparkles :size="18" class="zapret__icon" aria-hidden="true" />
            <span><span class="muted">Способ обхода:</span> {{ strategyLabel(config?.zapret, testedAt(test)) }}</span>
          </div>
          <template v-if="zapretSaved">
            <div v-if="running" class="zapret__run" aria-live="polite">
              <div class="bar" role="progressbar" aria-label="Подбор способа" :aria-valuenow="progress ?? undefined" aria-valuemin="0" aria-valuemax="100">
                <span :class="['bar__fill', { 'bar__fill--wait': progress === null }]" :style="progress !== null ? { width: `${progress}%` } : undefined" />
              </div>
              <span class="hint">{{ test && zapretProgress(test) }}. Интернет при этом работает как обычно.</span>
            </div>
            <p v-else-if="idle" class="hint">{{ idle }}</p>
            <div v-else class="zapret__row">
              <Button label="Подобрать способ" severity="secondary" variant="outlined" @click="startTest" />
              <span class="hint">Роутер сам проверит способы обхода на YouTube, Discord и других сайтах и выберет лучший. Займёт несколько минут.</span>
            </div>
            <div v-if="result && !running" :class="['zapret__result', { 'zapret__result--bad': test?.state === 'failed' }]">
              <strong v-if="result.summary">{{ result.summary }}</strong>
              <span>{{ result.message }}</span>
              <span class="muted">Подбор от {{ when(test?.finished ?? test?.started) }}</span>
            </div>
            <Message v-if="testError" severity="error" :closable="false">{{ testError }}</Message>
          </template>
          <p v-else class="hint">Обход заработает сразу после сохранения. Подобрать способ под ваш интернет можно, когда настройки сохранятся.</p>
        </div>
      </div>
    </template>
  </section>
</template>
