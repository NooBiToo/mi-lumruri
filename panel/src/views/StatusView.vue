<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import Button from 'primevue/button'
import Message from 'primevue/message'
import { ArrowRight } from 'lucide-vue-next'
import { api, type ZapretTestState } from '../api'
import { catalog, config, leases, lists, loadLeases, loadLists, loadStatus, profile, service, serverReady, simple, simpleState, tunnel } from '../store'
import { AUTO, deviceRows, plural, when, zapretIdle } from '../status'
import { avatarHue, initials } from '../ui'
import TopoMap, { type TopoBranch, type Tone } from '../components/TopoMap.vue'

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
/** nfqws2 запущен по данным службы (до первого статуса считаем, что да). */
const nfqwsUp = computed(() => ((service.value?.service as { engines?: Record<string, boolean> } | undefined)?.engines?.nfqws2) !== false)
const cut = (ids: { id: string; name: string }[], domains: string[]) => {
  const d = domains.slice(0, MAX_DOMAINS)
  return { items: ids, domains: d, more: domains.length - d.length }
}
const branches = computed<TopoBranch[]>(() => {
  const s = simple.value
  if (!s) return []
  const out: TopoBranch[] = []
  const vpnTone: Tone = !s.enabled ? 'idle' : tunnel.value.tone === 'ok' ? 'vpn' : (tunnel.value.tone as Tone)
  out.push({
    key: 'vpn', kind: 'vpn', tone: vpnTone, live: s.enabled && vpnTone === 'vpn',
    name: s.mode === 'all' ? 'Весь интернет через VPN' : 'Через VPN',
    meta: s.enabled ? (host.value ?? 'сервер не настроен') : 'VPN выключен',
    ...(s.mode === 'all' ? cut([], []) : cut(services.value, s.customDomains)),
    note: s.mode === 'all' ? (s.exceptions.length ? `Кроме ${plural(s.exceptions.length, 'исключения', 'исключений', 'исключений')}` : 'Без исключений')
      : !services.value.length && !s.customDomains.length ? 'Сайты не выбраны' : undefined,
  })
  if (zapretServices.value.length || s.zapretDomains.length) {
    out.push({ key: 'zapret', kind: 'zapret', tone: nfqwsUp.value ? 'zapret' : 'bad', live: nfqwsUp.value,
      name: 'С обходом блокировок', meta: zapretWay.value, ...cut(zapretServices.value, s.zapretDomains) })
  }
  if (s.mode === 'selected') {
    // при выключенном VPN остальные сайты идут напрямую без обработки (default_action — direct)
    const z = s.enabled && s.rest === 'zapret' && zapretUsed.value
    out.push({ key: 'rest', kind: z ? 'zapret' : 'direct', tone: z ? (nfqwsUp.value ? 'zapret' : 'bad') : 'ok', live: z ? nfqwsUp.value : true,
      name: 'Остальные сайты', meta: z ? `напрямую с обходом, ${zapretWay.value}` : 'напрямую', ...cut([], []) })
  } else if (s.exceptions.length) {
    out.push({ key: 'except', kind: 'direct', tone: 'ok', live: true, name: 'Исключения',
      meta: `напрямую · ${plural(s.exceptions.length, 'сайт', 'сайта', 'сайтов')}`, ...cut([], []) })
  }
  return out
})
const devTopo = computed(() => {
  const rows = config.value ? deviceRows(leases.value, config.value, {}, []).filter((d) => d.online) : []
  const shown = rows.slice(0, 4)
  return {
    title: 'Устройства',
    meta: `${devKpi.value.value.toLowerCase()} · ${devKpi.value.note}`,
    avatars: shown.map((d) => ({ mac: d.mac, name: d.name, initials: initials(d.name) || '•', hue: avatarHue(d.mac) })),
    extra: rows.length - shown.length,
  }
})
const hubTopo = computed(() => ({ tone: tunnel.value.tone as Tone, meta: tunnel.value.title }))
const zapretAuto = computed(() => (config.value?.zapret?.strategy ?? AUTO) === AUTO && (config.value?.zapret?.youtube ?? AUTO) === AUTO)

// ---- списки сайтов ----
const listsStatus = computed(() => lists.value?.status ?? null)
const snapshot = computed(() => {
  const d = catalog.value?.date
  return d ? new Date(`${d}T00:00:00`).toLocaleDateString('ru-RU', { day: 'numeric', month: 'long' }) : null
})
onMounted(async () => {
  void loadStatus()
  void loadLists()
  void loadLeases()
  const r = await api.zapretTest()
  if (r.body.ok && r.body.test) test.value = r.body.test
})
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

    <!-- туннель: карточка — только когда нужно пояснение или действие; «всё работает» показывает роутер на схеме -->
    <div v-else-if="tunnel.tone !== 'ok' || (simple && nothingSelected && simple.enabled)" :class="['card', 'state', `state--${tunnel.tone}`]">
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

      <TopoMap :branches="branches" :devices="devTopo" :hub="hubTopo" @devices="emit('navigate', 'devices')" />

      <div class="routes__foot">
        <span :class="['meta', { 'warn-text': listsStatus && !listsStatus.ok }]">
          Списки сайтов {{ listsStatus?.updated ? `обновлены ${when(listsStatus.updated)}` : snapshot ? `от ${snapshot}, из установки` : '' }}{{ listsStatus && !listsStatus.ok ? ' · проверка не удалась' : '' }}
        </span>
        <button type="button" class="link-btn" @click="emit('navigate', 'sites')">Настроить</button>
      </div>
      <p v-if="!simple.enabled" class="hint">VPN выключен: выбор сохранён и заработает, когда вы включите VPN</p>
    </div>
  </section>
</template>
