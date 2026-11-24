<script setup lang="ts">
// Трафик за сутки и неделю: весь интернет (порт WAN), из него через VPN (туннель), по устройствам (штатный trafficd).
// Данные — GET /stats; служба снимает показания раз в 5 минут.
import { computed, onMounted, ref } from 'vue'
import { manage, type StatsResponse } from '../api'
import { dateTag, t } from '../i18n'
import { shortVendor } from '../status'
import Segmented from './Segmented.vue'

type Range = 'day' | 'week' | 'month' | 'quarter' | 'year'
const st = ref<StatsResponse | null>(null)
const range = ref<Range>('day')
const hist = computed(() => st.value?.history ?? null)
/** Длинные периоды — только с журналом и только те, что он покрывает. */
const RANGES = computed(() => [
  { value: 'day' as const, label: t('Сутки') }, { value: 'week' as const, label: t('Неделя') },
  ...(hist.value ? [{ value: 'month' as const, label: t('Месяц') }] : []),
  ...(hist.value && hist.value.months >= 3 ? [{ value: 'quarter' as const, label: t('3 месяца') }] : []),
  ...(hist.value && hist.value.months >= 12 ? [{ value: 'year' as const, label: t('Год') }] : []),
])
const SPAN: Record<'month' | 'quarter' | 'year', number> = { month: 30, quarter: 90, year: 365 }
const long = computed(() => range.value === 'month' || range.value === 'quarter' || range.value === 'year')
const daysIn = computed(() => {
  if (!long.value || !hist.value) return []
  const from = Date.now() / 1000 - SPAN[range.value as 'month'] * 86400
  return hist.value.days.filter((d) => d.t > from)
})

onMounted(async () => {
  const r = await manage.stats()
  if (r.status === 200) st.value = r.body
})

/** Байты по-человечески на языке панели: 1,2 ГБ / 1.2 GB. */
function bytes(n: number): string {
  const units = ['byte', 'kilobyte', 'megabyte', 'gigabyte', 'terabyte'] as const
  let i = 0
  let v = n
  while (v >= 1000 && i < units.length - 1) { v /= 1000; i++ }
  return new Intl.NumberFormat(dateTag(), { style: 'unit', unit: units[i], unitDisplay: 'short', maximumFractionDigits: v < 10 && i > 0 ? 1 : 0 }).format(v)
}

const sumDays = (f: (d: { vpn: number; wan: number }) => number) => daysIn.value.reduce((a, d) => a + f(d), 0)
const vpn = computed(() => (long.value ? sumDays((d) => d.vpn) : st.value?.vpn[range.value as 'day'] ?? 0))
const wan = computed(() => (long.value ? sumDays((d) => d.wan) : st.value?.wan[range.value as 'day'] ?? 0))
/** Имя устройства: как на «Устройствах»; без имени — производитель по MAC или сам адрес. */
const nameOf = (d: { key: string; name?: string | null; vendor?: string | null }) => d.name || (d.vendor ? t('Устройство {vendor}', { vendor: shortVendor(d.vendor) }) : d.key)
const share = computed(() => (wan.value > 0 ? Math.min(100, Math.round((vpn.value / wan.value) * 100)) : 0))
const devices = computed(() => {
  const r = range.value
  const rows = long.value
    ? (hist.value?.devices ?? []).map((d) => ({ key: d.key, label: nameOf(d), v: d[r as 'month'] }))
    : (st.value?.devices ?? []).map((d) => ({ key: d.key, label: nameOf(d), v: d[r as 'day'] }))
  return rows.filter((d) => d.v > 0).sort((a, b) => b.v - a.v).slice(0, 6)
})
const top = computed(() => Math.max(1, ...devices.value.map((d) => d.v)))
const dayPeak = computed(() => Math.max(1, ...daysIn.value.map((d) => d.wan)))
const hourOf = (s: number) => new Date(s * 1000).toLocaleTimeString(dateTag(), { hour: '2-digit', minute: '2-digit' })
const dateOf = (s: number) => new Date(s * 1000).toLocaleDateString(dateTag(), { day: 'numeric', month: 'short' })
const hours = computed(() => st.value?.hours ?? [])
const peak = computed(() => Math.max(1, ...hours.value.map((h) => h.wan)))
/** Столбиков на графике не меньше 24 (сутки по часам): первые часы после запуска не растягиваются на всю ширину. */
const slots = (n: number) => Math.max(24, n)
const note = computed(() => [t('«Весь интернет» — порт WAN роутера, туда входит и зашифрованный трафик VPN. «Через VPN» — трафик внутри туннеля'),
  hist.value ? '' : t('Динамику за месяцы покажет журнал трафика: включите его на странице «Модули».')].filter(Boolean).join('. '))
const empty = computed(() => !!st.value && !st.value.sampled)
</script>

<template>
  <section v-if="st" class="ov-sec" aria-labelledby="stats-title">
    <div class="ov-head">
      <h2 id="stats-title" class="ov-head__title">{{ t('Трафик') }}</h2>
      <Segmented v-model="range" :options="RANGES" :label="t('За какой период')" name="stats-range" />
    </div>
    <p v-if="empty" class="card stats__empty muted">{{ t('Статистика появится через несколько минут после запуска службы') }}</p>
    <div v-else class="stats">
      <div class="card stats__half">
        <div class="stats__head">
          <span class="stats__sub">{{ long ? t('По дням') : range === 'day' ? t('По часам') : t('Всего') }}</span>
          <span class="meta">{{ t('весь интернет') }} {{ bytes(wan) }}</span>
        </div>
        <svg v-if="range === 'day' && hours.length > 1" class="stats__bars" :viewBox="`${(hours.length - slots(hours.length)) * 6} 0 ${slots(hours.length) * 6} 40`" preserveAspectRatio="none" role="img"
          :aria-label="t('Трафик по часам за сутки')">
          <g v-for="(h, i) in hours" :key="h.t">
            <rect :x="i * 6" :y="40 - (h.wan / peak) * 40" width="5" :height="(h.wan / peak) * 40" class="stats__bar" />
            <rect :x="i * 6" :y="40 - (Math.min(h.vpn, h.wan) / peak) * 40" width="5" :height="(Math.min(h.vpn, h.wan) / peak) * 40" class="stats__bar stats__bar--vpn" />
          </g>
        </svg>
        <svg v-else-if="long && daysIn.length > 1" class="stats__bars" :viewBox="`${(daysIn.length - slots(daysIn.length)) * 6} 0 ${slots(daysIn.length) * 6} 40`" preserveAspectRatio="none" role="img"
          :aria-label="t('Трафик по дням с {a} по {b}', { a: dateOf(daysIn[0]!.t), b: dateOf(daysIn[daysIn.length - 1]!.t) })">
          <g v-for="(d, i) in daysIn" :key="d.t">
            <title>{{ dateOf(d.t) }}: {{ bytes(d.wan) }}, {{ t('через VPN') }} {{ bytes(d.vpn) }}</title>
            <rect :x="i * 6" :y="40 - (d.wan / dayPeak) * 40" width="5" :height="(d.wan / dayPeak) * 40" class="stats__bar" />
            <rect :x="i * 6" :y="40 - (Math.min(d.vpn, d.wan) / dayPeak) * 40" width="5" :height="(Math.min(d.vpn, d.wan) / dayPeak) * 40" class="stats__bar stats__bar--vpn" />
          </g>
        </svg>
        <div v-else class="stats__share">
          <span class="stats__big">{{ bytes(wan) }}</span>
          <span class="stats__track stats__track--lg" aria-hidden="true"><span class="stats__fill stats__fill--vpn" :style="{ width: `${share}%` }" /></span>
        </div>
        <div class="stats__axis">
          <span class="meta">{{ range === 'day' && hours.length > 1 ? hourOf(hours[0]!.t) : long && daysIn.length ? dateOf(daysIn[0]!.t) : '' }}</span>
          <span class="stats__legend">
            <span class="meta"><i class="stats__key stats__key--vpn" aria-hidden="true" />{{ t('через VPN {v}', { v: bytes(vpn) }) }}</span>
            <span class="meta"><i class="stats__key" aria-hidden="true" />{{ t('напрямую {v}', { v: bytes(Math.max(0, wan - vpn)) }) }}</span>
          </span>
          <span class="meta">{{ range === 'day' || long ? t('сейчас') : '' }}</span>
        </div>
      </div>
      <div class="card stats__half">
        <div class="stats__head">
          <span class="stats__sub">{{ t('По устройствам') }}</span>
          <span class="meta">{{ t('из них через VPN — {p}%', { p: share }) }}</span>
        </div>
        <ul v-if="devices.length" class="stats__devices">
          <li v-for="d in devices" :key="d.key" class="stats__device">
            <span class="stats__name" :title="d.key">{{ d.label }}</span>
            <span class="stats__track" aria-hidden="true"><span class="stats__fill" :style="{ width: `${(d.v / top) * 100}%` }" /></span>
            <span class="stats__val">{{ bytes(d.v) }}</span>
          </li>
        </ul>
        <p v-else-if="!st.per_device" class="hint">{{ t('По устройствам не видно: штатный учёт трафика прошивки (trafficd) не ответил') }}</p>
        <p v-else class="hint">{{ t('За этот период трафика по устройствам нет') }}</p>
      </div>
    </div>
    <p v-if="!empty" class="hint">{{ note }}</p>
  </section>
</template>

<style scoped>
.stats { display: grid; gap: 1rem; grid-template-columns: minmax(0, 1fr); }
@container ov (min-width: 760px) { .stats { grid-template-columns: repeat(2, minmax(0, 1fr)); } .stats__half { min-height: 17rem; } }
.stats__half { display: grid; grid-template-rows: auto 1fr auto; gap: 0.875rem; padding: 1.25rem; min-width: 0; }
.stats__empty { padding: 1.25rem; margin: 0; }
.stats__head { display: flex; justify-content: space-between; align-items: baseline; gap: 1rem; }
.stats__sub { font-weight: 500; }
.stats__bars { display: block; width: 100%; height: 9rem; align-self: end; }
.stats__bar { fill: var(--line-strong); }
.stats__bar--vpn { fill: var(--accent); }
.stats__share { display: flex; flex-direction: column; justify-content: center; gap: 0.75rem; }
.stats__big { font-size: 1.875rem; font-weight: 600; font-variant-numeric: tabular-nums; }
.stats__axis { display: grid; grid-template-columns: auto 1fr auto; gap: 1rem; align-items: center; }
.stats__legend { display: flex; justify-content: center; flex-wrap: wrap; gap: 0.25rem 1rem; }
.stats__key { display: inline-block; width: 0.5rem; height: 0.5rem; border-radius: 2px; margin-right: 0.375rem; background: var(--line-strong); }
.stats__key--vpn { background: var(--accent); }
.stats__devices { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; justify-content: space-between; gap: 0.5rem; }
.stats__device { display: grid; grid-template-columns: minmax(6rem, 11rem) minmax(0, 1fr) 4.5rem; align-items: center; gap: 0.875rem; font-size: 0.875rem; }
.stats__name { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.stats__track { height: 0.5rem; border-radius: 0.25rem; background: var(--idle-soft); overflow: hidden; }
.stats__track--lg { display: block; height: 0.625rem; background: var(--line-strong); }
.stats__fill { display: block; height: 100%; background: var(--accent); border-radius: 0.25rem; }
.stats__val { text-align: right; font-variant-numeric: tabular-nums; color: var(--muted); }
</style>
