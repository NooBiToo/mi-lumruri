<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import Button from 'primevue/button'
import Message from 'primevue/message'
import { ArrowRight } from 'lucide-vue-next'
import { api, manage, type SpeedResponse, type ZapretTestState } from '../api'
import { bitrate, health, rates, useHealth } from '../health'
import HealthTiles from '../components/HealthTiles.vue'
import RouteCards, { type RouteCard, type Tone } from '../components/RouteCards.vue'
import { catalog, config, leases, lists, loadLeases, loadLists, loadStatus, notify, profile, service, serverReady, simple, simpleState, tunnel } from '../store'
import { AUTO, plural, when, zapretIdle } from '../status'
import { dateTag, t } from '../i18n'
import StatsCard from '../components/StatsCard.vue'

const emit = defineEmits<{ navigate: [tab: 'server' | 'sites' | 'devices' | 'more'] }>()

const host = computed(() => profile.value?.endpoint ? (profile.value.endpoint.sni || profile.value.endpoint.server) : null)
const nothingSelected = computed(() => !!simple.value && simple.value.mode === 'selected' && !simple.value.services.length && !simple.value.customDomains.length)
// названия из каталога списков — данные; перевод есть в словаре разделов «Сайты» (i18n/*/sites.ts)
const named = (ids: string[]) => ids.map((id) => ({ id, name: t(catalog.value?.services.find((x) => x.id === id)?.name ?? id) }))
const services = computed(() => named(simple.value?.services ?? []))
const zapretServices = computed(() => named(simple.value?.zapretServices ?? []))
// ---- маршруты: карточки веток ----
const devKpi = computed(() => {
  const s = simple.value
  const online = leases.value.length
  const note = online ? t('в сети {n}', { n: plural(online, 'устройство', 'устройства', 'устройств') }) : t('в сети пока никого')
  if (!s) return { value: '—', note }
  return { value: s.devices === 'all' ? t('Все') : plural(s.devices.length, 'выбранное', 'выбранных', 'выбранных'), note }
})
const test = ref<ZapretTestState | null>(null)
/** Способ Zapret коротко: подпись веток, которые идут с обходом блокировок. */
const zapretWay = computed(() => (zapretAuto.value ? t('способ автоматический') : test.value?.finished ? t('способ подобран {d}', { d: when(test.value.finished) }) : t('способ выбран вручную')))
const zapretUsed = computed(() => !!simple.value && !zapretIdle(simple.value))
/** nfqws2 запущен по данным службы (до первого статуса считаем, что да). */
const nfqwsUp = computed(() => ((service.value?.service as { engines?: Record<string, boolean> } | undefined)?.engines?.nfqws2) !== false)
// ---- скорость маршрутов: канал — последний замер (через VPN / напрямую), сейчас — по счётчикам TUN и WAN ----
const speedSt = ref<SpeedResponse | null>(null)
let speedTimer: number | undefined
async function loadSpeed() {
  clearTimeout(speedTimer)
  try { const r = await manage.speed(); if (r.status === 200) speedSt.value = r.body } catch { /* панель недоступна */ }
  if (speedSt.value?.running || speedSt.value?.speed?.state === 'running') speedTimer = window.setTimeout(() => void loadSpeed(), 2000)
}
async function measure() {
  const r = await manage.startSpeed()
  if (r.status !== 202) { notify.show('error', t('Не получилось'), r.body.error?.message); return }
  speedSt.value = { ...(speedSt.value ?? { ok: true, speed: null, issues: [] }), running: true }
  speedTimer = window.setTimeout(() => void loadSpeed(), 2000)
}
const stopHealth = useHealth()
onBeforeUnmount(() => { stopHealth(); clearTimeout(speedTimer) })
const tag = dateTag()
const speedRunning = computed(() => !!speedSt.value?.running || speedSt.value?.speed?.state === 'running')
const mbps = (p: unknown) => (p && typeof p === 'object' && 'mbps' in p ? bitrate((p as { mbps: number }).mbps * 1e6, tag) : p && typeof p === 'object' && 'error' in p ? t('нет связи') : null)
function speedOf(kind: 'vpn' | 'zapret' | 'direct'): Pick<RouteCard, 'cap' | 'now' | 'title'> {
  const s = speedSt.value?.speed
  const cap = speedRunning.value ? 'measuring' as const : s ? mbps(kind === 'vpn' ? s.tunnel : s.direct) : null
  const r = rates.value
  const pos = (v: number) => Math.max(0, v)
  const now = kind === 'zapret' ? 'shared' as const
    : kind === 'vpn' ? (r.vpn ? { d: bitrate(r.vpn.rx, tag), u: bitrate(r.vpn.tx, tag) } : null)
      : (r.wan ? { d: bitrate(pos(r.wan.rx - (r.vpn?.rx ?? 0)), tag), u: bitrate(pos(r.wan.tx - (r.vpn?.tx ?? 0)), tag) } : null)
  const title = s?.at ? t('Канал — замер {d} с роутера; «сейчас» — текущий трафик', { d: when(s.at) }) : t('Замера скорости ещё не было')
  return { cap, now, title }
}
const cards = computed<RouteCard[]>(() => {
  const s = simple.value
  if (!s) return []
  const out: RouteCard[] = []
  const vpnTone: Tone = !s.enabled ? 'idle' : tunnel.value.tone === 'ok' ? 'vpn' : (tunnel.value.tone as Tone)
  const all = s.mode === 'all'
  out.push({
    key: 'vpn', kind: 'vpn', tone: vpnTone, live: s.enabled && vpnTone === 'vpn',
    ...(s.enabled ? speedOf('vpn') : { cap: null, now: null, title: t('VPN выключен') }),
    name: all ? t('Весь интернет через VPN') : t('Через VPN'),
    meta: s.enabled ? (host.value ?? t('сервер не настроен')) : t('VPN выключен'),
    items: all ? [] : services.value, domains: all ? 0 : s.customDomains.length,
    note: all ? (s.exceptions.length ? t('Весь интернет, кроме {n}', { n: plural(s.exceptions.length, 'исключения', 'исключений', 'исключений') }) : t('Весь интернет без исключений'))
      : t('Сайты не выбраны'),
  })
  if (zapretServices.value.length || s.zapretDomains.length) {
    out.push({ key: 'zapret', kind: 'zapret', tone: nfqwsUp.value ? 'zapret' : 'bad', live: nfqwsUp.value, ...speedOf('zapret'),
      name: t('С обходом блокировок'), meta: zapretWay.value, items: zapretServices.value, domains: s.zapretDomains.length })
  }
  if (s.mode === 'selected') {
    // при выключенном VPN остальные сайты идут напрямую без обработки (default_action — direct)
    const z = s.enabled && s.rest === 'zapret' && zapretUsed.value
    out.push({ key: 'rest', kind: z ? 'zapret' : 'direct', tone: z ? (nfqwsUp.value ? 'zapret' : 'bad') : 'ok', live: z ? nfqwsUp.value : true, ...speedOf('direct'),
      name: z ? t('Остальные сайты') : t('Напрямую'), meta: z ? t('напрямую с обходом, {way}', { way: zapretWay.value }) : t('остальные сайты'),
      items: [], domains: 0, note: t('Всё, что не попало в списки выше') })
  } else if (s.exceptions.length) {
    out.push({ key: 'except', kind: 'direct', tone: 'ok', live: true, ...speedOf('direct'), name: t('Исключения'),
      meta: t('напрямую · {n}', { n: plural(s.exceptions.length, 'сайт', 'сайта', 'сайтов') }), items: [], domains: 0, note: t('Эти сайты идут мимо VPN') })
  }
  return out
})
const devicesNote = computed(() => `${devKpi.value.value} · ${devKpi.value.note}`)
const speedAt = computed(() => (speedSt.value?.speed?.state === 'done' ? t('замер {d}', { d: when(speedSt.value.speed.at) }) : null))
const ping = computed(() => (speedSt.value?.speed?.state === 'done' ? speedSt.value.speed.ping : null))
function uptimeText(u: number) {
  const d = Math.floor(u / 86400), hh = Math.floor((u % 86400) / 3600), m = Math.floor((u % 3600) / 60)
  return d ? t('{d} {h} ч', { d: plural(d, 'день', 'дня', 'дней'), h: hh }) : hh ? t('{h} ч {m} мин', { h: hh, m }) : t('{m} мин', { m })
}
const routerNote = computed(() => {
  const h = health.value
  if (!h) return null
  return [h.uptime != null ? t('без перезагрузки {u}', { u: uptimeText(h.uptime) }) : null,
    h.conntrack ? plural(h.conntrack.count, 'соединение', 'соединения', 'соединений') : null].filter(Boolean).join(' · ')
})
const zapretAuto = computed(() => (config.value?.zapret?.strategy ?? AUTO) === AUTO && (config.value?.zapret?.youtube ?? AUTO) === AUTO)

// ---- списки сайтов ----
const listsStatus = computed(() => lists.value?.status ?? null)
const snapshot = computed(() => {
  const d = catalog.value?.date
  return d ? new Date(`${d}T00:00:00`).toLocaleDateString(dateTag(), { day: 'numeric', month: 'long' }) : null
})
onMounted(async () => {
  void loadStatus()
  void loadLists()
  void loadLeases()
  void loadSpeed()
  const r = await api.zapretTest()
  if (r.body.ok && r.body.test) test.value = r.body.test
})
</script>

<template>
  <section class="sect" :aria-label="t('Обзор')">
    <!-- первый запуск: без сервера ничего не заработает -->
    <div v-if="!serverReady" class="card onboard">
      <div class="onboard__body">
        <h2 class="onboard__title">{{ t('Подключите сервер') }}</h2>
        <p class="muted">{{ t('Роутер будет открывать выбранные сайты через ваш VPN-сервер TrustTunnel. Начните с ссылки на сервер — остальное займёт минуту.') }}</p>
        <ol class="steps">
          <li class="steps__item steps__item--now"><span class="steps__n">1</span>{{ t('Вставьте ссылку на сервер') }}</li>
          <li class="steps__item"><span class="steps__n">2</span>{{ t('Отметьте сайты для VPN') }}</li>
          <li class="steps__item"><span class="steps__n">3</span>{{ t('Роутер применит настройки сам') }}</li>
        </ol>
      </div>
      <Button :label="t('Настроить сервер')" class="onboard__btn" @click="emit('navigate', 'server')">
        <template #icon><ArrowRight :size="16" class="p-button-icon-right" aria-hidden="true" /></template>
      </Button>
    </div>

    <!-- туннель: карточка — только когда нужно пояснение или действие; «всё работает» показывает роутер на схеме -->
    <div v-else-if="tunnel.tone !== 'ok' || (simple && nothingSelected && simple.enabled)" :class="['card', 'state', `state--${tunnel.tone}`]">
      <span :class="['led', 'led--lg', `led--${tunnel.tone}`]" aria-hidden="true" />
      <div class="state__text">
        <h2 class="state__title">{{ tunnel.title }}</h2>
        <p v-if="tunnel.detail" class="state__detail">{{ tunnel.detail }}</p>
      </div>
      <span v-if="host" class="state__host meta" :title="t('Сервер TrustTunnel')">{{ host }}</span>
      <Button v-if="simple && nothingSelected && simple.enabled" :label="t('Выбрать сайты')" class="state__act" @click="emit('navigate', 'sites')" />
    </div>

    <Message v-if="simpleState && !simpleState.canonical" severity="warn" :closable="false">
      {{ t('Настройки изменены вручную, поэтому здесь их не показать. Подробнее — на экране «Сайты».') }}
    </Message>

    <div class="ov">
      <section class="ov-sec" aria-labelledby="now-title">
        <div class="ov-head">
          <h2 id="now-title" class="ov-head__title">{{ t('Сейчас') }}</h2>
          <span v-if="routerNote" class="meta">{{ routerNote }}</span>
        </div>
        <HealthTiles :ping="ping" :host="host" />
      </section>

      <section v-if="simple" class="ov-sec" aria-labelledby="routes-title">
        <div class="ov-head">
          <div class="ov-head__lead">
            <h2 id="routes-title" class="ov-head__title">{{ t('Маршруты') }}</h2>
            <button type="button" class="link-btn ov-head__note" :title="t('Устройства')" @click="emit('navigate', 'devices')">{{ devicesNote }}</button>
          </div>
          <div class="ov-head__acts">
            <span v-if="speedAt" class="meta">{{ speedAt }}</span>
            <Button v-if="serverReady" :label="speedRunning ? t('Замеряю…') : t('Замерить скорость')" :loading="speedRunning" :disabled="speedRunning"
              severity="secondary" variant="outlined" size="small" @click="measure" />
            <button type="button" class="link-btn" @click="emit('navigate', 'sites')">{{ t('Изменить') }}</button>
          </div>
        </div>
        <RouteCards :cards="cards" @measure="measure" />
        <div class="ov-foot">
          <span :class="['meta', { 'warn-text': listsStatus && !listsStatus.ok }]">
            {{ listsStatus?.updated ? t('Списки сайтов обновлены {d}', { d: when(listsStatus.updated) }) : snapshot ? t('Списки сайтов от {d}, из установки', { d: snapshot }) : t('Списки сайтов') }}{{ listsStatus && !listsStatus.ok ? ` · ${t('проверка не удалась')}` : '' }}
          </span>
          <span v-if="!simple.enabled" class="meta">{{ t('VPN выключен: выбор сохранён и заработает, когда вы включите VPN') }}</span>
        </div>
      </section>

      <StatsCard v-if="serverReady" />
    </div>
  </section>
</template>
