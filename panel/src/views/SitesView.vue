<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import Button from 'primevue/button'
import Checkbox from 'primevue/checkbox'
import InputText from 'primevue/inputtext'
import Message from 'primevue/message'
import Textarea from 'primevue/textarea'
import { api, type ZapretTestState } from '../api'
import { build, buildBlocker, catalog, config, knownDevicesNow, loadConfig, save, serverReady, simple, simpleState } from '../store'
import { lines, strategyLabel, when, zapretProgress, zapretResult } from '../status'
import { normalizeDomain, type Simple } from '../simple'
import ManualBanner from './ManualBanner.vue'

const emit = defineEmits<{ navigate: [tab: 'server' | 'devices'] }>()

// ---- черновик экрана ----
interface Draft { mode: Simple['mode']; services: string[]; custom: string; except: string; rest: Simple['rest'] }
const toDraft = (s: Simple): Draft => ({ mode: s.mode, services: [...s.services], custom: s.customDomains.join('\n'), except: s.exceptions.join('\n'), rest: s.rest })
const draft = ref<Draft | null>(simple.value ? toDraft(simple.value) : null)
/** Домены поля так, как их сохранит toConfig: без схемы, пути и повторов. */
const domains = (text: string) => [...new Set(lines(text).map(normalizeDomain).filter(Boolean))]
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

// ---- сервисы каталога ----
const search = ref('')
const GROUPS = ['Сервисы', 'Категории', 'Россия']
const groups = computed(() => {
  const q = search.value.trim().toLowerCase()
  const all = catalog.value?.services ?? []
  const names = [...new Set([...GROUPS.filter((g) => all.some((s) => s.group === g)), ...all.map((s) => s.group)])]
  return names.map((g) => ({ name: g, items: all.filter((s) => s.group === g && (!q || s.name.toLowerCase().includes(q) || s.id.includes(q))) }))
    .filter((g) => g.items.length)
})
function toggle(id: string) {
  if (!draft.value) return
  const s = draft.value.services
  draft.value.services = s.includes(id) ? s.filter((x) => x !== id) : [...s, id]
}

// ---- сохранение ----
const saving = ref(false)
const usesVpn = computed(() => !!next.value && (next.value.mode === 'all' || next.value.services.length > 0 || next.value.customDomains.length > 0))
const blocker = computed(() => {
  if (!dirty.value) return null
  if (usesVpn.value && !serverReady.value) return 'server'
  return buildBlocker()
})
async function submit() {
  if (!next.value || blocker.value) return
  const cfg = build(next.value, knownDevicesNow())
  if (typeof cfg === 'string') { saveError.value = cfg; return }
  saving.value = true
  saveError.value = null
  try {
    // после сохранения поля показывают домены так, как они записаны
    if ((await save(cfg)).ok && simple.value) draft.value = toDraft(simple.value)
  } finally { saving.value = false }
}
const saveError = ref<string | null>(null)

// ---- подбор стратегии Zapret ----
const test = ref<ZapretTestState | null>(null)
const testError = ref<string | null>(null)
let poll: number | undefined
async function readTest() {
  const r = await api.zapretTest()
  if (!r.body.ok || !r.body.test) return
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
  if (r.status === 202 || r.status === 409) {
    test.value = { ...(test.value ?? {}), state: 'running', progress: undefined }
    if (poll === undefined) poll = window.setInterval(() => void readTest(), 2000)
  } else testError.value = r.body.error?.message ?? `Ошибка ${r.status}`
}
const running = computed(() => test.value?.state === 'running')
const result = computed(() => (test.value && (test.value.state === 'done' || test.value.state === 'failed') ? zapretResult(test.value) : null))
const zapretSaved = computed(() => simple.value?.rest === 'zapret')
onMounted(() => void readTest())
onBeforeUnmount(() => clearInterval(poll))
</script>

<template>
  <section class="sect" aria-labelledby="sites-title">
    <header class="sect__head">
      <h1 id="sites-title" class="sect__title">Сайты</h1>
      <p class="sect__lead">Отметьте, какие сайты открывать через VPN. Остальные откроются как обычно.</p>
    </header>

    <ManualBanner v-if="simpleState && !simpleState.canonical" :reason="simpleState.reason" />

    <template v-else-if="draft">
      <div class="choice" role="radiogroup" aria-label="Что пускать через VPN">
        <label :class="['choice__opt', { 'choice__opt--on': draft.mode === 'selected' }]">
          <input v-model="draft.mode" type="radio" value="selected" class="choice__radio" />
          <span class="choice__text">
            <span class="choice__label">Только выбранные сайты через VPN</span>
            <span class="choice__note">Рекомендуется. Через VPN идут только отмеченные ниже сервисы и ваши сайты.</span>
          </span>
        </label>
        <label :class="['choice__opt', { 'choice__opt--on': draft.mode === 'all' }]">
          <input v-model="draft.mode" type="radio" value="all" class="choice__radio" />
          <span class="choice__text">
            <span class="choice__label">Всё через VPN, кроме исключений</span>
            <span class="choice__note">Весь интернет через VPN. Сайты из поля «Не пускать через VPN» откроются напрямую.</span>
          </span>
        </label>
      </div>

      <div v-if="draft.mode === 'selected'" class="card">
        <div class="card__head">
          <h2 class="card__title">Сервисы через VPN</h2>
          <span class="card__meta">{{ draft.services.length ? `Отмечено: ${draft.services.length}` : 'Ничего не отмечено' }}</span>
        </div>
        <template v-if="catalog">
          <label for="svc-search" class="sr-only">Найти сервис</label>
          <InputText id="svc-search" v-model="search" placeholder="Найти сервис" class="search" />
          <div v-for="g in groups" :key="g.name" class="svc-group">
            <h3 class="svc-group__title">{{ g.name }}</h3>
            <div class="tiles">
              <label v-for="s in g.items" :key="s.id" :class="['tile', { 'tile--on': draft.services.includes(s.id) }]">
                <Checkbox :model-value="draft.services.includes(s.id)" binary :input-id="`svc-${s.id}`" @update:model-value="toggle(s.id)" />
                <span class="tile__name">{{ s.name }}</span>
              </label>
            </div>
          </div>
          <p v-if="!groups.length" class="muted">Ничего не нашлось. Сайт можно добавить в поле «Свои сайты».</p>
          <p class="hint">Списки сайтов обновляются сами раз в сутки. «Заблокированное в России» — большой общий список: его хватает, если не знаете, что выбрать.</p>
        </template>
        <Message v-else severity="warn" :closable="false">Каталог сайтов не загрузился. Обновите страницу.</Message>

        <div class="field">
          <label for="custom" class="field__label">Свои сайты</label>
          <Textarea id="custom" v-model="draft.custom" rows="4" auto-resize placeholder="example.com" spellcheck="false" />
          <span class="field__hint">По одному в строке. Поддомены тоже пойдут через VPN.</span>
        </div>
      </div>

      <div class="card">
        <div class="field">
          <label for="except" class="field__label">Не пускать через VPN</label>
          <Textarea id="except" v-model="draft.except" rows="3" auto-resize placeholder="gosuslugi.ru" spellcheck="false" />
          <span class="field__hint">Эти сайты всегда открываются напрямую — например, банки и госуслуги. По одному в строке.</span>
        </div>
      </div>

      <div class="card" id="zapret">
        <h2 class="card__title">{{ draft.mode === 'selected' ? 'Остальные сайты' : 'Сайты, которые не идут через VPN' }}</h2>
        <div class="choice" role="radiogroup" aria-label="Как открывать остальные сайты">
          <label :class="['choice__opt', { 'choice__opt--on': draft.rest === 'direct' }]">
            <input v-model="draft.rest" type="radio" value="direct" class="choice__radio" />
            <span class="choice__text"><span class="choice__label">Напрямую</span></span>
          </label>
          <label :class="['choice__opt', { 'choice__opt--on': draft.rest === 'zapret' }]">
            <input v-model="draft.rest" type="radio" value="zapret" class="choice__radio" />
            <span class="choice__text">
              <span class="choice__label">Напрямую с обходом блокировок (Zapret)</span>
              <span class="choice__note">Помогает, когда YouTube или Discord без VPN тормозят или не открываются.</span>
            </span>
          </label>
        </div>

        <div v-if="draft.rest === 'zapret'" class="zapret">
          <p><span class="muted">Способ обхода:</span> {{ strategyLabel(config?.zapret) }}</p>
          <template v-if="zapretSaved">
            <div v-if="running" class="zapret__run" aria-live="polite">
              <span class="spinner" aria-hidden="true" />
              <span>{{ test && zapretProgress(test) }}. Интернет при этом работает как обычно.</span>
            </div>
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
          <p v-else class="hint">Сохраните, и обход заработает сразу. Подобрать способ под ваш интернет можно после сохранения.</p>
        </div>
      </div>

      <div class="savebar">
        <div class="savebar__in">
          <span class="savebar__text" aria-live="polite">
            <template v-if="blocker === 'server'">Сначала настройте сервер VPN — без него сайтам некуда идти.
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
