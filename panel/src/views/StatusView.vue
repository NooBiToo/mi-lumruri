<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import Button from 'primevue/button'
import Message from 'primevue/message'
import { ArrowRight, MonitorSmartphone, RefreshCw, Router } from 'lucide-vue-next'
import { api, type ZapretTestState } from '../api'
import { catalog, config, leases, lists, loadLeases, loadLists, loadStatus, notify, profile, serverReady, simple, simpleState, tunnel } from '../store'
import { AUTO, plural, when, zapretIdle } from '../status'
import ServiceLogo from '../components/ServiceLogo.vue'

const emit = defineEmits<{ navigate: [tab: 'server' | 'sites' | 'devices' | 'more'] }>()

const host = computed(() => profile.value?.endpoint ? (profile.value.endpoint.sni || profile.value.endpoint.server) : null)
const nothingSelected = computed(() => !!simple.value && simple.value.mode === 'selected' && !simple.value.services.length && !simple.value.customDomains.length)
const named = (ids: string[]) => ids.map((id) => ({ id, name: catalog.value?.services.find((x) => x.id === id)?.name ?? id }))
const services = computed(() => named(simple.value?.services ?? []))
const zapretServices = computed(() => named(simple.value?.zapretServices ?? []))
const MAX_DOMAINS = 6

// ---- схема маршрутов: устройства → роутер → ветки ----
const devKpi = computed(() => {
  const s = simple.value
  const online = leases.value.length
  const note = online ? `в сети ${plural(online, 'устройство', 'устройства', 'устройств')}` : 'в сети пока никого'
  if (!s) return { value: '—', note }
  return { value: s.devices === 'all' ? 'Все' : plural(s.devices.length, 'выбранное', 'выбранных', 'выбранных'), note }
})
const test = ref<ZapretTestState | null>(null)
/** Способ Zapret коротко: подпись веток, которые идут с обходом блокировок. */
const zapretWay = computed(() => (zapretAuto.value ? 'способ автоматический' : test.value?.finished ? `способ подобран ${when(test.value.finished)}` : 'способ выбран вручную'))
const zapretUsed = computed(() => !!simple.value && !zapretIdle(simple.value))
const zapretAuto = computed(() => (config.value?.zapret?.strategy ?? AUTO) === AUTO && (config.value?.zapret?.youtube ?? AUTO) === AUTO)

// ---- списки сайтов ----
const updating = ref(false)
const listsStatus = computed(() => lists.value?.status ?? null)
const snapshot = computed(() => {
  const d = catalog.value?.date
  return d ? new Date(`${d}T00:00:00`).toLocaleDateString('ru-RU', { day: 'numeric', month: 'long' }) : null
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
onMounted(async () => {
  void loadStatus()
  void loadLists()
  void loadLeases()
  const r = await api.zapretTest()
  if (r.body.ok && r.body.test) test.value = r.body.test
})
onBeforeUnmount(() => clearTimeout(listsTimer))
</script>

<template>
  <section class="sect" aria-label="Обзор">
    <!-- первый запуск: без сервера ничего не заработает -->
    <div v-if="!serverReady" class="card onboard">
      <div class="onboard__body">
        <h2 class="onboard__title">Подключите сервер</h2>
        <p class="muted">Роутер будет открывать выбранные сайты через ваш VPN-сервер TrustTunnel. Начните с ссылки на сервер — остальное займёт минуту.</p>
        <ol class="steps">
          <li class="steps__item steps__item--now"><span class="steps__n">1</span>Вставьте ссылку на сервер</li>
          <li class="steps__item"><span class="steps__n">2</span>Отметьте сайты для VPN</li>
          <li class="steps__item"><span class="steps__n">3</span>Роутер применит настройки сам</li>
        </ol>
      </div>
      <Button label="Настроить сервер" class="onboard__btn" @click="emit('navigate', 'server')">
        <template #icon><ArrowRight :size="16" class="p-button-icon-right" aria-hidden="true" /></template>
      </Button>
    </div>

    <!-- туннель: индикатор, как на корпусе роутера -->
    <div v-else :class="['card', 'state', `state--${tunnel.tone}`]">
      <span :class="['led', 'led--lg', `led--${tunnel.tone}`]" aria-hidden="true" />
      <div class="state__text">
        <h2 class="state__title">{{ tunnel.title }}</h2>
        <p v-if="tunnel.detail" class="state__detail">{{ tunnel.detail }}</p>
      </div>
      <span v-if="host" class="state__host meta" title="Сервер TrustTunnel">{{ host }}</span>
      <Button v-if="simple && nothingSelected && simple.enabled" label="Выбрать сайты" class="state__act" @click="emit('navigate', 'sites')" />
    </div>

    <Message v-if="simpleState && !simpleState.canonical" severity="warn" :closable="false">
      Настройки изменены вручную, поэтому здесь их не показать. Подробнее — на экране «Сайты».
    </Message>

    <div v-if="simple" class="card routes">
      <div class="card__head">
        <h2 id="routes-title" class="card__title">Маршруты</h2>
        <button type="button" class="link-btn" @click="emit('navigate', 'sites')">Изменить</button>
      </div>

      <div class="routes__map">
        <div class="routes__src">
          <button type="button" class="node" @click="emit('navigate', 'devices')">
            <MonitorSmartphone :size="16" class="node__icon" aria-hidden="true" />
            <span class="node__name">Устройства</span>
            <span class="meta node__meta">{{ devKpi.value.toLowerCase() }} · {{ devKpi.note }}</span>
          </button>
          <span class="routes__wire" aria-hidden="true" />
          <span class="node node--router">
            <Router :size="16" class="node__icon" aria-hidden="true" />
            <span class="node__name">Роутер</span>
          </span>
          <span class="routes__wire routes__wire--tail" aria-hidden="true" />
        </div>

        <ul class="routes__branches" aria-labelledby="routes-title">
          <!-- через VPN -->
          <li :class="['branch', 'branch--vpn', { 'branch--off': !simple.enabled }]">
            <div class="branch__head">
              <span class="branch__title"><span :class="['led', simple.enabled ? `led--${tunnel.tone === 'ok' ? 'vpn' : tunnel.tone}` : 'led--idle']" aria-hidden="true" />
                <span class="branch__name">{{ simple.mode === 'all' ? 'Весь интернет через VPN' : 'Через VPN' }}</span></span>
              <span class="meta">{{ simple.enabled ? (host ?? 'сервер не настроен') : 'VPN выключен' }}</span>
            </div>
            <p v-if="simple.mode === 'all'" class="branch__note">{{ simple.exceptions.length ? `Кроме ${plural(simple.exceptions.length, 'исключения', 'исключений', 'исключений')}` : 'Без исключений' }}</p>
            <ul v-else-if="services.length || simple.customDomains.length" class="branch__items">
              <li v-for="x in services" :key="x.id" class="branch__item"><ServiceLogo :id="x.id" size="sm" />{{ x.name }}</li>
              <li v-for="d in simple.customDomains.slice(0, MAX_DOMAINS)" :key="d" class="branch__item meta">{{ d }}</li>
              <li v-if="simple.customDomains.length > MAX_DOMAINS" class="branch__item meta">ещё {{ simple.customDomains.length - MAX_DOMAINS }}</li>
            </ul>
            <p v-else class="branch__note">Сайты не выбраны</p>
          </li>

          <!-- напрямую с обходом блокировок -->
          <li v-if="zapretServices.length || simple.zapretDomains.length" class="branch branch--zapret">
            <div class="branch__head">
              <span class="branch__title"><span class="led led--zapret" aria-hidden="true" />
                <span class="branch__name">Напрямую с обходом блокировок</span></span>
              <span class="meta">{{ zapretWay }}</span>
            </div>
            <ul class="branch__items">
              <li v-for="x in zapretServices" :key="x.id" class="branch__item"><ServiceLogo :id="x.id" size="sm" />{{ x.name }}</li>
              <li v-for="d in simple.zapretDomains.slice(0, MAX_DOMAINS)" :key="d" class="branch__item meta">{{ d }}</li>
              <li v-if="simple.zapretDomains.length > MAX_DOMAINS" class="branch__item meta">ещё {{ simple.zapretDomains.length - MAX_DOMAINS }}</li>
            </ul>
          </li>

          <!-- остальное -->
          <li v-if="simple.mode === 'selected'" :class="['branch', simple.rest === 'zapret' && zapretUsed ? 'branch--zapret' : 'branch--direct']">
            <div class="branch__head">
              <span class="branch__title"><span :class="['led', simple.rest === 'zapret' && zapretUsed ? 'led--zapret' : 'led--idle']" aria-hidden="true" />
                <span class="branch__name">Остальные сайты</span></span>
              <span class="meta">{{ simple.rest === 'zapret' ? `напрямую с обходом блокировок, ${zapretWay}` : 'напрямую' }}</span>
            </div>
          </li>
          <li v-else-if="simple.exceptions.length" class="branch branch--direct">
            <div class="branch__head">
              <span class="branch__title"><span class="led led--idle" aria-hidden="true" />
                <span class="branch__name">Исключения</span></span>
              <span class="meta">напрямую · {{ plural(simple.exceptions.length, 'сайт', 'сайта', 'сайтов') }}</span>
            </div>
          </li>
        </ul>
      </div>

      <div class="routes__foot">
        <span :class="['meta', { 'warn-text': listsStatus && !listsStatus.ok }]">
          Списки сайтов {{ listsStatus?.updated ? `обновлены ${when(listsStatus.updated)}` : snapshot ? `от ${snapshot}, из установки` : '' }}{{ listsStatus && !listsStatus.ok ? ' · проверка не удалась' : '' }}
        </span>
        <button type="button" class="link-btn" :disabled="updating || lists?.requested" @click="updateLists">
          <RefreshCw :size="14" :class="{ spin: updating || lists?.requested }" aria-hidden="true" />Обновить
        </button>
      </div>
      <p v-if="!simple.enabled" class="hint">VPN выключен: выбор сохранён и заработает, когда вы включите VPN</p>
    </div>
  </section>
</template>
