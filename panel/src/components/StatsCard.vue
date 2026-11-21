<script setup lang="ts">
// Трафик за сутки и неделю: весь интернет (порт WAN), из него через VPN (туннель), по устройствам (штатный trafficd).
// Данные — GET /stats; служба снимает показания раз в 5 минут.
import { computed, onMounted, ref } from 'vue'
import { manage, type StatsResponse } from '../api'
import { dateTag, t } from '../i18n'
import Segmented from './Segmented.vue'

const st = ref<StatsResponse | null>(null)
const range = ref<'day' | 'week'>('day')
const RANGES = computed(() => [{ value: 'day' as const, label: t('Сутки') }, { value: 'week' as const, label: t('Неделя') }])

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

const vpn = computed(() => st.value?.vpn[range.value] ?? 0)
const wan = computed(() => st.value?.wan[range.value] ?? 0)
const share = computed(() => (wan.value > 0 ? Math.min(100, Math.round((vpn.value / wan.value) * 100)) : 0))
const devices = computed(() => (st.value?.devices ?? []).filter((d) => d[range.value] > 0).sort((a, b) => b[range.value] - a[range.value]).slice(0, 8))
const top = computed(() => Math.max(1, ...devices.value.map((d) => d[range.value])))
const hours = computed(() => st.value?.hours ?? [])
const peak = computed(() => Math.max(1, ...hours.value.map((h) => h.wan)))
const empty = computed(() => !!st.value && !st.value.sampled)
</script>

<template>
  <div v-if="st" class="card stats" role="group" aria-labelledby="stats-title">
    <div class="card__head">
      <h2 id="stats-title" class="card__title">{{ t('Трафик') }}</h2>
      <Segmented v-model="range" :options="RANGES" :label="t('За какой период')" name="stats-range" />
    </div>
    <p v-if="empty" class="muted">{{ t('Статистика появится через несколько минут после запуска службы') }}</p>
    <template v-else>
      <div class="stats__totals">
        <div class="stats__total">
          <span class="stats__num">{{ bytes(wan) }}</span>
          <span class="meta">{{ t('весь интернет') }}</span>
        </div>
        <div class="stats__total">
          <span class="stats__num stats__num--vpn">{{ bytes(vpn) }}</span>
          <span class="meta">{{ t('из них через VPN — {p}%', { p: share }) }}</span>
        </div>
      </div>
      <svg v-if="range === 'day' && hours.length > 1" class="stats__bars" :viewBox="`0 0 ${hours.length * 6} 40`" preserveAspectRatio="none" role="img"
        :aria-label="t('Трафик по часам за сутки')">
        <g v-for="(h, i) in hours" :key="h.t">
          <rect :x="i * 6" :y="40 - (h.wan / peak) * 40" width="5" :height="(h.wan / peak) * 40" class="stats__bar" />
          <rect :x="i * 6" :y="40 - (Math.min(h.vpn, h.wan) / peak) * 40" width="5" :height="(Math.min(h.vpn, h.wan) / peak) * 40" class="stats__bar stats__bar--vpn" />
        </g>
      </svg>
      <ul v-if="devices.length" class="stats__devices">
        <li v-for="d in devices" :key="d.key" class="stats__device">
          <span class="stats__name">{{ d.name || d.key }}</span>
          <span class="stats__track" aria-hidden="true"><span class="stats__fill" :style="{ width: `${(d[range] / top) * 100}%` }" /></span>
          <span class="meta stats__val">{{ bytes(d[range]) }}</span>
        </li>
      </ul>
      <p v-else-if="!st.per_device" class="hint">{{ t('По устройствам не видно: штатный учёт трафика прошивки (trafficd) не ответил') }}</p>
      <p class="hint">{{ t('«Весь интернет» — порт WAN роутера, туда входит и зашифрованный трафик VPN. «Через VPN» — трафик внутри туннеля') }}</p>
    </template>
  </div>
</template>

<style scoped>
.stats__totals { display: flex; flex-wrap: wrap; gap: 1.5rem; }
.stats__total { display: flex; flex-direction: column; gap: 0.15rem; }
.stats__num { font-size: 1.5rem; font-weight: 600; font-variant-numeric: tabular-nums; }
.stats__num--vpn { color: var(--vpn, #2f7d5b); }
.stats__bars { width: 100%; height: 3rem; margin-top: 0.75rem; }
.stats__bar { fill: var(--line, #c9ced6); }
.stats__bar--vpn { fill: var(--vpn, #2f7d5b); }
.stats__devices { list-style: none; margin: 0.75rem 0 0; padding: 0; display: flex; flex-direction: column; gap: 0.4rem; }
.stats__device { display: grid; grid-template-columns: minmax(6rem, 10rem) 1fr auto; align-items: center; gap: 0.6rem; }
.stats__name { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.stats__track { height: 0.4rem; border-radius: 0.2rem; background: var(--line, #e3e6ea); overflow: hidden; }
.stats__fill { display: block; height: 100%; background: var(--accent, #5b6b7d); }
.stats__val { font-variant-numeric: tabular-nums; }
</style>
