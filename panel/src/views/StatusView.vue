<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import Button from 'primevue/button'
import Message from 'primevue/message'
import ToggleSwitch from 'primevue/toggleswitch'
import { ArrowRight, ListChecks, MonitorSmartphone, RefreshCw, Route, Server, ShieldAlert, ShieldCheck, ShieldOff, Waypoints } from 'lucide-vue-next'
import { api, type ZapretTestState } from '../api'
import { catalog, config, leases, lists, loadLeases, loadLists, loadStatus, notify, profile, serverReady, simple, simpleState, tunnel } from '../store'
import { AUTO, plural, when, zapretIdle } from '../status'
import { toggleVpn, vpnBusy } from '../vpn'
import ServiceLogo from '../components/ServiceLogo.vue'

const emit = defineEmits<{ navigate: [tab: 'server' | 'sites' | 'devices' | 'more'] }>()

const heroIcon = computed(() => (tunnel.value.tone === 'ok' ? ShieldCheck : tunnel.value.tone === 'idle' ? ShieldOff : ShieldAlert))
const host = computed(() => profile.value?.endpoint ? (profile.value.endpoint.sni || profile.value.endpoint.server) : null)
const nothingSelected = computed(() => !!simple.value && simple.value.mode === 'selected' && !simple.value.services.length && !simple.value.customDomains.length)
const services = computed(() => (simple.value?.services ?? []).map((id) => ({ id, name: catalog.value?.services.find((x) => x.id === id)?.name ?? id })))

// ---- карточки-показатели ----
const vpnKpi = computed(() => {
  const s = simple.value
  if (!s) return { value: '—', note: '' }
  if (s.mode === 'all') return { value: 'Все сайты', note: s.exceptions.length ? `кроме ${plural(s.exceptions.length, 'исключения', 'исключений', 'исключений')}` : 'без исключений' }
  return {
    value: s.services.length ? plural(s.services.length, 'сервис', 'сервиса', 'сервисов') : 'Ничего',
    note: s.customDomains.length ? `+ ${plural(s.customDomains.length, 'свой сайт', 'своих сайта', 'своих сайтов')}` : s.services.length ? 'своих сайтов нет' : 'сайты не выбраны',
  }
})
const devKpi = computed(() => {
  const s = simple.value
  const online = leases.value.length
  const note = online ? `в сети ${plural(online, 'устройство', 'устройства', 'устройств')}` : 'в сети пока никого'
  if (!s) return { value: '—', note }
  return { value: s.devices === 'all' ? 'Все' : plural(s.devices.length, 'выбранное', 'выбранных', 'выбранных'), note }
})
const test = ref<ZapretTestState | null>(null)
const zapretKpi = computed(() => {
  const s = simple.value
  if (!s || s.rest !== 'zapret') return { value: 'Выключен', note: 'остальные сайты напрямую', tone: 'idle' }
  if (zapretIdle(s)) return { value: 'Не используется', note: s.enabled ? 'всё идёт через VPN' : 'VPN выключен', tone: 'idle' }
  return { value: zapretAuto.value ? 'Автоматически' : 'Подобран', note: zapretAuto.value ? 'способ выбирается сам' : test.value?.finished ? `подбор ${when(test.value.finished)}` : 'под ваш интернет', tone: 'ok' }
})
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
      <span class="onboard__icon" aria-hidden="true"><Waypoints :size="28" :stroke-width="1.75" /></span>
      <div class="onboard__body">
        <h2 class="onboard__title">Подключите сервер</h2>
        <p class="muted">Роутер будет открывать выбранные сайты через ваш VPN-сервер TrustTunnel. Начните с ссылки на сервер — остальное займёт минуту.</p>
        <ol class="steps">
          <li class="steps__item steps__item--now"><span class="steps__n">1</span>Вставьте ссылку на сервер</li>
          <li class="steps__item"><span class="steps__n">2</span>Отметьте сайты для VPN</li>
          <li class="steps__item"><span class="steps__n">3</span>Готово — роутер применит настройки</li>
        </ol>
      </div>
      <Button label="Настроить сервер" class="onboard__btn" @click="emit('navigate', 'server')">
        <template #icon><ArrowRight :size="18" class="p-button-icon-right" aria-hidden="true" /></template>
      </Button>
    </div>

    <!-- туннель -->
    <div v-else :class="['card', 'hero', `hero--${tunnel.tone}`]">
      <span class="hero__icon" aria-hidden="true"><component :is="heroIcon" :size="28" :stroke-width="1.75" /></span>
      <div class="hero__text">
        <p class="hero__kicker">Туннель</p>
        <p class="hero__title">{{ tunnel.title }}</p>
        <p v-if="tunnel.detail" class="hero__detail">{{ tunnel.detail }}</p>
        <p v-if="host" class="hero__host"><Server :size="14" aria-hidden="true" /><span class="num">{{ host }}</span></p>
      </div>
      <div class="hero__act">
        <Button v-if="simple && nothingSelected && simple.enabled" label="Выбрать сайты" @click="emit('navigate', 'sites')" />
        <label v-if="simple" class="hero__switch">
          <ToggleSwitch :model-value="simple.enabled" input-id="vpn-hero" :disabled="vpnBusy" @update:model-value="toggleVpn()" />
          <span>{{ simple.enabled ? 'VPN включён' : 'VPN выключен' }}</span>
        </label>
      </div>
    </div>

    <Message v-if="simpleState && !simpleState.canonical" severity="warn" :closable="false">
      Настройки изменены вручную, поэтому здесь их не показать. Подробнее — на экране «Сайты».
    </Message>

    <div v-if="simple" class="kpis">
      <button type="button" class="card kpi" @click="emit('navigate', 'sites')">
        <span class="kpi__head"><span class="kpi__icon kpi__icon--accent" aria-hidden="true"><Route :size="18" /></span>Через VPN</span>
        <span class="kpi__value">{{ vpnKpi.value }}</span>
        <span class="kpi__note">{{ vpnKpi.note }}</span>
      </button>
      <button type="button" class="card kpi" @click="emit('navigate', 'devices')">
        <span class="kpi__head"><span class="kpi__icon kpi__icon--accent" aria-hidden="true"><MonitorSmartphone :size="18" /></span>Устройства</span>
        <span class="kpi__value">{{ devKpi.value }}</span>
        <span class="kpi__note">{{ devKpi.note }}</span>
      </button>
      <button type="button" class="card kpi" @click="emit('navigate', 'sites')">
        <span class="kpi__head"><span :class="['kpi__icon', zapretKpi.tone === 'ok' ? 'kpi__icon--ok' : 'kpi__icon--idle']" aria-hidden="true"><ShieldCheck :size="18" /></span>Обход блокировок</span>
        <span class="kpi__value">{{ zapretKpi.value }}</span>
        <span class="kpi__note">{{ zapretKpi.note }}</span>
      </button>
      <div class="card kpi kpi--static">
        <span class="kpi__head"><span class="kpi__icon kpi__icon--accent" aria-hidden="true"><ListChecks :size="18" /></span>Списки сайтов</span>
        <span class="kpi__value">{{ listsStatus?.updated ? when(listsStatus.updated) : snapshot ? `от ${snapshot}` : '—' }}</span>
        <span class="kpi__foot">
          <span :class="['kpi__note', { 'warn-text': listsStatus && !listsStatus.ok }]">{{ listsStatus && !listsStatus.ok ? 'проверка не удалась' : listsStatus?.updated ? 'обновлены' : 'из установки' }}</span>
          <button type="button" class="link-btn" :disabled="updating || lists?.requested" @click="updateLists">
            <RefreshCw :size="14" :class="{ spin: updating || lists?.requested }" aria-hidden="true" />Обновить
          </button>
        </span>
      </div>
    </div>

    <div v-if="simple" class="card">
      <div class="card__head">
        <h2 class="card__title">Сейчас через VPN</h2>
        <button type="button" class="link-btn" @click="emit('navigate', 'sites')">Изменить<ArrowRight :size="14" aria-hidden="true" /></button>
      </div>
      <p v-if="simple.mode === 'all'" class="muted">Весь интернет идёт через VPN{{ simple.exceptions.length ? `, кроме ${plural(simple.exceptions.length, 'сайта', 'сайтов', 'сайтов')} из исключений` : '' }}.</p>
      <template v-else>
        <ul v-if="services.length || simple.customDomains.length" class="now">
          <li v-for="s in services" :key="s.id" class="now__chip"><ServiceLogo :id="s.id" size="sm" />{{ s.name }}</li>
          <li v-for="d in simple.customDomains.slice(0, 6)" :key="d" class="now__chip now__chip--domain">{{ d }}</li>
          <li v-if="simple.customDomains.length > 6" class="now__chip now__chip--more">ещё {{ simple.customDomains.length - 6 }}</li>
        </ul>
        <p v-else class="muted">Пока ничего не выбрано. Отметьте сервисы или добавьте свои сайты.</p>
      </template>
      <p v-if="!simple.enabled" class="hint">VPN выключен: выбор сохранён и заработает, когда вы включите VPN.</p>
    </div>
  </section>
</template>
