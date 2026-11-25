<script setup lang="ts">
import { computed, nextTick, onMounted, ref, watch } from 'vue'
import InputText from 'primevue/inputtext'
import { Search, Server, Unplug } from 'lucide-vue-next'
import { manage } from '../api'
import { build, buildBlocker, catalog, knownDevicesNow, profiles, save, scrollTarget, serverReady, simple, simpleState } from '../store'
import { usesZapret } from '../status'
import { normalizeDomain, serviceRoute, setServiceRoute, WS_SERVICES, type ServiceRoute, type Simple } from '../simple'
import { useAutosave, type Blocker } from '../autosave'
import { t } from '../i18n'
import ManualBanner from './ManualBanner.vue'
import Segmented from '../components/Segmented.vue'
import ServiceLogo from '../components/ServiceLogo.vue'
import DomainList from '../components/DomainList.vue'
import ListsCard from '../components/ListsCard.vue'

const emit = defineEmits<{ navigate: [tab: 'server' | 'devices' | 'zapret' | 'modules'] }>()

// ---- черновик экрана ----
interface Draft {
  mode: Simple['mode']; services: string[]; zapretServices: string[]; custom: string[]; zapret: string[]; except: string[]; rest: Simple['rest']
  /** Сервисы через другой сервер: id сервиса → id профиля. */
  server: Record<string, string>
  /** Сервисы через WebSocket (Telegram) и запасной путь: id профиля или '' (напрямую); undefined — не выбирался. */
  wsServices: string[]
  tgwsVia: string | undefined
}
const toDraft = (s: Simple): Draft => ({
  mode: s.mode, services: [...s.services], zapretServices: [...s.zapretServices], custom: [...s.customDomains], zapret: [...s.zapretDomains],
  except: [...s.exceptions], rest: s.rest, server: { ...(s.serviceServer ?? {}) }, wsServices: [...(s.wsServices ?? [])], tgwsVia: s.tgwsVia,
})
/** Отметки серверов только у сервисов через VPN и только для другого существующего сервера; пусто — undefined. */
function cleanServers(d: Draft): Record<string, string> | undefined {
  const def = profiles.value[0]?.id
  const ids = new Set(profiles.value.map((p) => p.id))
  const r = Object.fromEntries(Object.entries(d.server).filter(([svc, p]) => d.services.includes(svc) && p !== def && ids.has(p)).sort(([a], [b]) => a.localeCompare(b)))
  return Object.keys(r).length ? r : undefined
}
const serversJson = (m: Record<string, string> | undefined) => JSON.stringify(Object.entries(m ?? {}).sort(([a], [b]) => a.localeCompare(b)))
const draft = ref<Draft | null>(simple.value ? toDraft(simple.value) : null)
/** Домены так, как их сохранит toConfig: без схемы, пути и повторов. */
const domains = (list: string[]) => [...new Set(list.map(normalizeDomain).filter(Boolean))]
const sameList = (a: string[], b: string[]) => a.length === b.length && a.every((x, i) => x === b[i])
const next = computed<Simple | null>(() => simple.value && draft.value ? {
  ...simple.value, mode: draft.value.mode, services: [...draft.value.services].sort(), customDomains: domains(draft.value.custom),
  zapretServices: [...draft.value.zapretServices].sort(), zapretDomains: domains(draft.value.zapret),
  exceptions: domains(draft.value.except), rest: draft.value.rest, serviceServer: cleanServers(draft.value),
  wsServices: draft.value.wsServices.length ? [...draft.value.wsServices].sort() : undefined, tgwsVia: draft.value.tgwsVia,
} : null)
const dirty = computed(() => {
  const a = simple.value, b = next.value
  if (!a || !b) return false
  return a.mode !== b.mode || a.rest !== b.rest || !sameList([...a.services].sort(), b.services) || !sameList(a.customDomains, b.customDomains)
    || !sameList([...a.zapretServices].sort(), b.zapretServices) || !sameList(a.zapretDomains, b.zapretDomains) || !sameList(a.exceptions, b.exceptions)
    || serversJson(a.serviceServer) !== serversJson(b.serviceServer)
    || !sameList([...(a.wsServices ?? [])].sort(), b.wsServices ?? []) || a.tgwsVia !== b.tgwsVia
})
// ---- сервер сервиса (если серверов несколько) ----
const many = computed(() => profiles.value.length > 1)
const serverOf = (id: string): string => draft.value?.server[id] ?? profiles.value[0]?.id ?? ''
function setServer(id: string, pid: string) {
  if (!draft.value) return
  if (pid === profiles.value[0]?.id) delete draft.value.server[id]
  else draft.value.server[id] = pid
  draft.value.server = { ...draft.value.server }
}
// настройки перечитаны (сохранение, другое окно): черновик без правок следует за ними
watch(simple, (s) => { if (s && (!draft.value || !dirty.value)) draft.value = toDraft(s) })

const MODES = computed(() => [{ value: 'selected' as const, label: t('Только выбранные') }, { value: 'all' as const, label: t('Всё через VPN') }])
const RESTS = computed(() => [{ value: 'direct' as const, label: t('Напрямую') }, { value: 'zapret' as const, label: t('С обходом блокировок (Zapret)') }])
const ROUTES = computed<{ value: ServiceRoute; label: string; title: string }[]>(() => [
  { value: 'vpn', label: 'VPN', title: t('через VPN') },
  { value: 'zapret', label: 'Zapret', title: t('напрямую с обходом блокировок') },
  { value: 'ws', label: 'WS', title: t('через WebSocket Telegram, без VPN-сервера') },
  { value: 'off', label: t('Выкл'), title: t('как остальные сайты') },
])
/** Положения сервиса: «WS» — только у Telegram. */
const routesOf = (id: string) => ROUTES.value.filter((o) => o.value !== 'ws' || WS_SERVICES.includes(id))
// ---- Telegram через WebSocket: запасной путь и модуль ----
const tgwsVia = computed(() => draft.value?.tgwsVia ?? profiles.value[0]?.id ?? '')
function setTgwsVia(v: string) {
  if (draft.value) draft.value.tgwsVia = v
}
/** Модуль tgws: null — ещё неизвестно; false — не установлен или накопитель недоступен. */
const tgwsModule = ref<boolean | null>(null)
async function loadTgwsModule() {
  try {
    const r = await manage.modules()
    if (r.status === 200) tgwsModule.value = r.body.modules.some((m) => m.name === 'tgws' && m.installed?.state === 'ok')
  } catch { /* панель недоступна */ }
}

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
    .map((g) => ({ name: g, items: all.filter((s) => s.group === g && (!q || s.name.toLowerCase().includes(q) || t(s.name).toLowerCase().includes(q) || s.id.includes(q))) }))
    .filter((g) => g.items.length)
})
const countIn = (g: string) => (catalog.value?.services ?? [])
  .filter((s) => s.group === g && (draft.value?.services.includes(s.id) || draft.value?.zapretServices.includes(s.id))).length
const routeOf = (id: string): ServiceRoute => (draft.value ? serviceRoute(draft.value, id) : 'off')
function setRoute(id: string, route: ServiceRoute) {
  if (!draft.value) return
  const r = setServiceRoute(draft.value, id, route)
  Object.assign(draft.value, { services: r.services, zapretServices: r.zapretServices, wsServices: r.wsServices ?? [] })
  // первый выбор WS: запасной путь — сервер VPN по умолчанию (если сервер есть), иначе напрямую
  if (route === 'ws' && draft.value.tgwsVia === undefined) draft.value.tgwsVia = profiles.value[0]?.id ?? ''
  if (route === 'ws') void loadTgwsModule()
}
const servicesSub = computed(() => {
  const d = draft.value
  if (!d) return ''
  const parts: string[] = []
  if (d.services.length) parts.push(t('через VPN: {n}', { n: d.services.length }))
  if (d.zapretServices.length) parts.push(t('с обходом блокировок: {n}', { n: d.zapretServices.length }))
  if (d.wsServices.length) parts.push(t('через WebSocket: {n}', { n: d.wsServices.length }))
  return parts.length ? t('Выбрано {list}', { list: parts.join(', ') }) : t('Ничего не выбрано')
})

// ---- автосохранение ----
const usesVpn = computed(() => !!next.value && (next.value.mode === 'all' || next.value.services.length > 0 || next.value.customDomains.length > 0))
function blocker(): Blocker | null {
  if (usesVpn.value && !serverReady.value) {
    return { text: t('Сначала настройте сервер VPN — без него сайтам некуда идти.'), action: { label: t('Открыть «Сервер»'), run: () => emit('navigate', 'server') } }
  }
  const b = buildBlocker()
  return b ? { text: b } : null
}
useAutosave({
  source: draft,
  dirty: () => dirty.value,
  blocker,
  run: async () => {
    if (!next.value) return t('Настройки ещё не загружены.')
    const cfg = build(next.value, knownDevicesNow())
    if (typeof cfg === 'string') return cfg
    return save(cfg, '')
  },
})

/** Обход в черновике: показать ссылку на страницу Zapret. */
const zapretDraft = computed(() => usesZapret(next.value))

onMounted(async () => {
  if (draft.value?.wsServices.length) void loadTgwsModule()
  // переход с «Дополнительно» на подбор способа: сразу к блоку Zapret
  if (scrollTarget.value) {
    const id = scrollTarget.value
    scrollTarget.value = null
    await nextTick()
    document.getElementById(id)?.scrollIntoView({ block: 'start' })
  }
})
</script>

<template>
  <section class="sect" :aria-label="t('Сайты')">
    <ManualBanner v-if="simpleState && !simpleState.canonical" :reason="simpleState.reason" />

    <template v-else-if="draft">
      <div class="card">
        <div class="card__head">
          <div>
            <h2 class="card__title">{{ t('Что открывать через VPN') }}</h2>
            <p class="card__sub">{{ draft.mode === 'selected'
              ? t('Рекомендуется. Через VPN идут только отмеченные сервисы и ваши сайты, остальное — как обычно.')
              : t('Весь интернет через VPN. Сайты из «Не пускать через VPN» и сайты с обходом блокировок откроются напрямую.') }}</p>
          </div>
          <Segmented v-model="draft.mode" :options="MODES" :label="t('Что пускать через VPN')" name="mode" />
        </div>
      </div>

      <div class="card">
        <div class="card__head">
          <div>
            <h2 class="card__title">{{ t('Сервисы') }}</h2>
            <p class="card__sub">{{ servicesSub }}</p>
          </div>
          <div class="search">
            <Search :size="16" class="search__icon" aria-hidden="true" />
            <label for="svc-search" class="sr-only">{{ t('Найти сервис') }}</label>
            <InputText id="svc-search" v-model="search" :placeholder="t('Найти сервис')" type="search" />
          </div>
        </div>
        <p class="legend">
          <span class="legend__item"><span class="legend__mark legend__mark--vpn" />{{ t('VPN — через VPN') }}</span>
          <span class="legend__item"><span class="legend__mark legend__mark--zapret" />{{ t('Zapret — напрямую с обходом блокировок') }}</span>
          <span class="legend__item"><span class="legend__mark" />{{ t('Выкл — как остальные сайты') }}</span>
        </p>
        <p v-if="draft.mode === 'all'" class="hint">{{ t('Сейчас всё идёт через VPN, отметка «VPN» понадобится, только если вернуться к режиму «Только выбранные».') }}</p>
        <template v-if="catalog">
          <div class="filters" role="group" :aria-label="t('Группы сервисов')">
            <button type="button" :class="['filter', { 'filter--on': !filter }]" :aria-pressed="!filter" @click="filter = ''">{{ t('Все') }}</button>
            <button v-for="g in allGroups" :key="g" type="button" :class="['filter', { 'filter--on': filter === g }]" :aria-pressed="filter === g" @click="filter = g">
              {{ t(g) }}<span v-if="countIn(g)" class="filter__n">{{ countIn(g) }}</span>
            </button>
          </div>
          <div v-for="g in groups" :key="g.name" class="svc-group">
            <h3 v-if="!filter" class="svc-group__title">{{ t(g.name) }}</h3>
            <p v-if="g.name === EXPERT" class="hint">{{ t('Целые сети хостингов — для специалистов. Нужны, только если вы точно знаете, что сайт работает у такого хостинга и без VPN не открывается.') }}</p>
            <div class="tiles">
              <div v-for="s in g.items" :key="s.id" :class="['tile', `tile--${routeOf(s.id)}`]">
                <ServiceLogo :id="s.id" />
                <span :id="`svc-${s.id}`" class="tile__name" :title="t(s.name)">{{ t(s.name) }}</span>
                <div class="route" role="radiogroup" :aria-labelledby="`svc-${s.id}`">
                  <label v-for="o in routesOf(s.id)" :key="o.value" :class="['route__opt', `route__opt--${o.value}`, { 'route__opt--on': routeOf(s.id) === o.value }]" :title="`${t(s.name)}: ${o.title}`">
                    <input type="radio" class="route__radio" :name="`route-${s.id}`" :value="o.value" :checked="routeOf(s.id) === o.value"
                      :aria-label="`${o.label}: ${o.title}`" @change="setRoute(s.id, o.value)" />
                    <span>{{ o.label }}</span>
                  </label>
                </div>
                <template v-if="routeOf(s.id) === 'ws'">
                  <label class="tile__via tile__via--ws">
                    <span class="tile__vialabel"><Unplug :size="14" aria-hidden="true" />{{ t('Если WS не работает') }}</span>
                    <select class="tile__server tile__viasel" :value="tgwsVia" :aria-label="t('Запасной путь Telegram, если WebSocket не работает')"
                      @change="setTgwsVia(($event.target as HTMLSelectElement).value)">
                      <option v-for="p in profiles" :key="p.id" :value="p.id">{{ t('через VPN «{name}»', { name: p.name }) }}</option>
                      <option value="">{{ t('напрямую') }}</option>
                    </select>
                  </label>
                  <p v-if="tgwsModule === false" class="tile__note">
                    {{ t('Нужен модуль tgws — без него Telegram идёт запасным путём.') }}
                    <button type="button" class="link-btn" @click="emit('navigate', 'modules')">{{ t('Открыть «Модули»') }}</button>
                  </p>
                </template>
                <label v-if="many && routeOf(s.id) === 'vpn'" class="tile__via">
                  <span class="tile__vialabel"><Server :size="14" aria-hidden="true" />{{ t('Сервер VPN') }}</span>
                  <select class="tile__server tile__viasel" :value="serverOf(s.id)"
                    :aria-label="t('Сервер для «{name}»', { name: t(s.name) })" @change="setServer(s.id, ($event.target as HTMLSelectElement).value)">
                    <option v-for="p in profiles" :key="p.id" :value="p.id">{{ p.name }}</option>
                  </select>
                </label>
              </div>
            </div>
          </div>
          <p v-if="!groups.length" class="muted">{{ t('Ничего не нашлось. Сайт можно добавить в свои списки ниже.') }}</p>
          <p class="hint">{{ t('«Всё заблокированное в России» — большой общий список: его хватает, если не знаете, что выбрать.') }}</p>
        </template>
        <Message v-else severity="warn" :closable="false">{{ t('Каталог сайтов не загрузился. Обновите страницу.') }}</Message>
      </div>

      <ListsCard />

      <DomainList v-if="draft.mode === 'selected'" id="custom" v-model="draft.custom" :title="t('Свои сайты через VPN')" placeholder="example.com"
        :sub="t('Сайты, которых нет среди сервисов. Поддомены тоже пойдут через VPN.')" :empty="t('Пока пусто. Добавьте адрес сайта, например example.com.')" />
      <DomainList id="zapret-sites" v-model="draft.zapret" :title="t('Сайты с обходом блокировок')" placeholder="example.com"
        :sub="t('Открываются напрямую, без VPN, с обходом блокировок (Zapret). Работают и при выключенном VPN.')"
        :empty="t('Пока пусто. Подходит для сайтов, которые без VPN тормозят или не открываются.')" />
      <DomainList id="except" v-model="draft.except" :title="t('Не пускать через VPN')" placeholder="gosuslugi.ru"
        :sub="t('Эти сайты всегда открываются напрямую — например, банки и госуслуги')" :empty="t('Пока пусто. Добавьте, например, сайт банка.')" />

      <div id="zapret" class="card">
        <div class="card__head">
          <div>
            <h2 class="card__title">{{ draft.mode === 'selected' ? t('Остальные сайты') : t('Сайты, которые не идут через VPN') }}</h2>
            <p class="card__sub">{{ t('Обход блокировок помогает, когда YouTube или Discord без VPN тормозят или не открываются') }}</p>
          </div>
          <Segmented v-model="draft.rest" :options="RESTS" :label="t('Как открывать остальные сайты')" name="rest" />
        </div>

        <p v-if="zapretDraft" class="hint">{{ t('Способ обхода, подбор под ваш интернет и автопроверка — на странице') }}
          <button type="button" class="link-btn" @click="emit('navigate', 'zapret')">Zapret</button></p>
      </div>
    </template>
  </section>
</template>
