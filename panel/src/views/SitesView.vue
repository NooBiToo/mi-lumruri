<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import Button from 'primevue/button'
import InputText from 'primevue/inputtext'
import Message from 'primevue/message'
import Select from 'primevue/select'
import { Search, WandSparkles } from 'lucide-vue-next'
import { api, type ZapretTestState } from '../api'
import { build, buildBlocker, catalog, config, knownDevicesNow, loadConfig, save, saveZapret, scrollTarget, serverReady, simple, simpleState } from '../store'
import { usesZapret, when, zapretIdle, zapretProgress, zapretResult } from '../status'
import { normalizeDomain, serviceRoute, setServiceRoute, type ServiceRoute, type Simple } from '../simple'
import { AUTO, GENERAL_STRATEGIES, YOUTUBE_STRATEGIES, pickedByTest } from '../zapret'
import { saveNow, saveStatus, useAutosave, type Blocker } from '../autosave'
import ManualBanner from './ManualBanner.vue'
import Segmented from '../components/Segmented.vue'
import ServiceLogo from '../components/ServiceLogo.vue'
import DomainList from '../components/DomainList.vue'

const emit = defineEmits<{ navigate: [tab: 'server' | 'devices'] }>()

// ---- черновик экрана ----
interface Draft {
  mode: Simple['mode']; services: string[]; zapretServices: string[]; custom: string[]; zapret: string[]; except: string[]; rest: Simple['rest']
}
const toDraft = (s: Simple): Draft => ({
  mode: s.mode, services: [...s.services], zapretServices: [...s.zapretServices], custom: [...s.customDomains], zapret: [...s.zapretDomains],
  except: [...s.exceptions], rest: s.rest,
})
const draft = ref<Draft | null>(simple.value ? toDraft(simple.value) : null)
/** Домены так, как их сохранит toConfig: без схемы, пути и повторов. */
const domains = (list: string[]) => [...new Set(list.map(normalizeDomain).filter(Boolean))]
const sameList = (a: string[], b: string[]) => a.length === b.length && a.every((x, i) => x === b[i])
const next = computed<Simple | null>(() => simple.value && draft.value ? {
  ...simple.value, mode: draft.value.mode, services: [...draft.value.services].sort(), customDomains: domains(draft.value.custom),
  zapretServices: [...draft.value.zapretServices].sort(), zapretDomains: domains(draft.value.zapret),
  exceptions: domains(draft.value.except), rest: draft.value.rest,
} : null)
const dirty = computed(() => {
  const a = simple.value, b = next.value
  if (!a || !b) return false
  return a.mode !== b.mode || a.rest !== b.rest || !sameList([...a.services].sort(), b.services) || !sameList(a.customDomains, b.customDomains)
    || !sameList([...a.zapretServices].sort(), b.zapretServices) || !sameList(a.zapretDomains, b.zapretDomains) || !sameList(a.exceptions, b.exceptions)
})
// настройки перечитаны (сохранение, другое окно): черновик без правок следует за ними
watch(simple, (s) => { if (s && (!draft.value || !dirty.value)) draft.value = toDraft(s) })

const MODES = [{ value: 'selected' as const, label: 'Только выбранные' }, { value: 'all' as const, label: 'Всё через VPN' }]
const RESTS = [{ value: 'direct' as const, label: 'Напрямую' }, { value: 'zapret' as const, label: 'С обходом блокировок (Zapret)' }]
const ROUTES: { value: ServiceRoute; label: string; title: string }[] = [
  { value: 'vpn', label: 'VPN', title: 'через VPN' },
  { value: 'zapret', label: 'Zapret', title: 'напрямую с обходом блокировок' },
  { value: 'off', label: 'Выкл', title: 'как остальные сайты' },
]

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
const countIn = (g: string) => (catalog.value?.services ?? [])
  .filter((s) => s.group === g && (draft.value?.services.includes(s.id) || draft.value?.zapretServices.includes(s.id))).length
const routeOf = (id: string): ServiceRoute => (draft.value ? serviceRoute(draft.value, id) : 'off')
function setRoute(id: string, route: ServiceRoute) {
  if (!draft.value) return
  Object.assign(draft.value, setServiceRoute(draft.value, id, route))
}
const servicesSub = computed(() => {
  const d = draft.value
  if (!d) return ''
  const parts: string[] = []
  if (d.services.length) parts.push(`через VPN: ${d.services.length}`)
  if (d.zapretServices.length) parts.push(`с обходом блокировок: ${d.zapretServices.length}`)
  return parts.length ? `Выбрано ${parts.join(', ')}` : 'Ничего не выбрано'
})

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
/** Обход в черновике (показать выбор способа) и в сохранённых настройках (можно подбирать). */
const zapretDraft = computed(() => usesZapret(next.value))
const zapretSaved = computed(() => usesZapret(simple.value))
/** Сохранённые настройки не используют Zapret (VPN выключен или всё через VPN): кнопки подбора нет, есть объяснение. */
const idle = computed(() => zapretIdle(simple.value))

// ---- ручной выбор способа: сохраняется сразу (POST /zapret и заявка на применение) ----
const general = ref(config.value?.zapret?.strategy ?? AUTO)
const youtube = ref(config.value?.zapret?.youtube ?? AUTO)
watch(() => config.value?.zapret, (z) => { general.value = z?.strategy ?? AUTO; youtube.value = z?.youtube ?? AUTO })
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
  // не сохранилось — показываем то, что действует
  if (!ok) { general.value = config.value?.zapret?.strategy ?? AUTO; youtube.value = config.value?.zapret?.youtube ?? AUTO }
}
const strategyLocked = computed(() => running.value || savingZapret.value || saveStatus.tone === 'saving')

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
              : 'Весь интернет через VPN. Сайты из «Не пускать через VPN» и сайты с обходом блокировок откроются напрямую.' }}</p>
          </div>
          <Segmented v-model="draft.mode" :options="MODES" label="Что пускать через VPN" name="mode" />
        </div>
      </div>

      <div class="card">
        <div class="card__head">
          <div>
            <h2 class="card__title">Сервисы</h2>
            <p class="card__sub">{{ servicesSub }}</p>
          </div>
          <div class="search">
            <Search :size="16" class="search__icon" aria-hidden="true" />
            <label for="svc-search" class="sr-only">Найти сервис</label>
            <InputText id="svc-search" v-model="search" placeholder="Найти сервис" type="search" />
          </div>
        </div>
        <p class="legend">
          <span class="legend__item"><span class="legend__mark legend__mark--vpn" />VPN — через VPN</span>
          <span class="legend__item"><span class="legend__mark legend__mark--zapret" />Zapret — напрямую с обходом блокировок</span>
          <span class="legend__item"><span class="legend__mark" />Выкл — как остальные сайты</span>
        </p>
        <p v-if="draft.mode === 'all'" class="hint">Сейчас всё идёт через VPN, отметка «VPN» понадобится, только если вернуться к режиму «Только выбранные».</p>
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
              <div v-for="s in g.items" :key="s.id" :class="['tile', `tile--${routeOf(s.id)}`]">
                <ServiceLogo :id="s.id" />
                <span :id="`svc-${s.id}`" class="tile__name" :title="s.name">{{ s.name }}</span>
                <div class="route" role="radiogroup" :aria-labelledby="`svc-${s.id}`">
                  <label v-for="o in ROUTES" :key="o.value" :class="['route__opt', `route__opt--${o.value}`, { 'route__opt--on': routeOf(s.id) === o.value }]" :title="`${s.name}: ${o.title}`">
                    <input type="radio" class="route__radio" :name="`route-${s.id}`" :value="o.value" :checked="routeOf(s.id) === o.value"
                      :aria-label="`${o.label}: ${o.title}`" @change="setRoute(s.id, o.value)" />
                    <span>{{ o.label }}</span>
                  </label>
                </div>
              </div>
            </div>
          </div>
          <p v-if="!groups.length" class="muted">Ничего не нашлось. Сайт можно добавить в свои списки ниже.</p>
          <p class="hint">Списки сайтов обновляются сами раз в сутки. «Всё заблокированное в России» — большой общий список: его хватает, если не знаете, что выбрать.</p>
        </template>
        <Message v-else severity="warn" :closable="false">Каталог сайтов не загрузился. Обновите страницу.</Message>
      </div>

      <DomainList v-if="draft.mode === 'selected'" id="custom" v-model="draft.custom" title="Свои сайты через VPN" placeholder="example.com"
        sub="Сайты, которых нет среди сервисов. Поддомены тоже пойдут через VPN." empty="Пока пусто. Добавьте адрес сайта, например example.com." />
      <DomainList id="zapret-sites" v-model="draft.zapret" title="Сайты с обходом блокировок" placeholder="example.com"
        sub="Открываются напрямую, без VPN, с обходом блокировок (Zapret). Работают и при выключенном VPN."
        empty="Пока пусто. Подходит для сайтов, которые без VPN тормозят или не открываются." />
      <DomainList id="except" v-model="draft.except" title="Не пускать через VPN" placeholder="gosuslugi.ru"
        sub="Эти сайты всегда открываются напрямую — например, банки и госуслуги" empty="Пока пусто. Добавьте, например, сайт банка." />

      <div id="zapret" class="card">
        <div class="card__head">
          <div>
            <h2 class="card__title">{{ draft.mode === 'selected' ? 'Остальные сайты' : 'Сайты, которые не идут через VPN' }}</h2>
            <p class="card__sub">Обход блокировок помогает, когда YouTube или Discord без VPN тормозят или не открываются</p>
          </div>
          <Segmented v-model="draft.rest" :options="RESTS" label="Как открывать остальные сайты" name="rest" />
        </div>

        <div v-if="zapretDraft" class="zapret">
          <div class="zapret__line">
            <WandSparkles :size="18" class="zapret__icon" aria-hidden="true" />
            <h3 class="zapret__title">Способ обхода блокировок</h3>
          </div>
          <div class="pick">
            <div class="field">
              <label for="zapret-general" class="field__label">Для всех сайтов</label>
              <Select v-model="general" input-id="zapret-general" :options="GENERAL_STRATEGIES" option-label="label" option-value="id"
                :disabled="strategyLocked" scroll-height="22rem" class="pick__select" @change="chooseStrategy">
                <template #option="{ option }">
                  <span class="opt"><span class="opt__label">{{ option.label }}</span><span class="opt__desc">{{ option.desc }}</span></span>
                </template>
              </Select>
              <span class="field__hint">{{ picked.general ? `Подобран автоматически ${pickedWhen}. ` : '' }}{{ GENERAL_STRATEGIES.find((s) => s.id === general)?.desc }}</span>
            </div>
            <div class="field">
              <label for="zapret-youtube" class="field__label">Для YouTube</label>
              <Select v-model="youtube" input-id="zapret-youtube" :options="YOUTUBE_STRATEGIES" option-label="label" option-value="id"
                :disabled="strategyLocked" scroll-height="22rem" class="pick__select" @change="chooseStrategy">
                <template #option="{ option }">
                  <span class="opt"><span class="opt__label">{{ option.label }}</span><span class="opt__desc">{{ option.desc }}</span></span>
                </template>
              </Select>
              <span class="field__hint">{{ picked.youtube ? `Подобран автоматически ${pickedWhen}. ` : '' }}{{ YOUTUBE_STRATEGIES.find((s) => s.id === youtube)?.desc }}</span>
            </div>
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
