<script setup lang="ts">
// «Обзор»: состояние роутера — процессор (всего и по ядрам), память, температура по датчикам, время работы,
// соединения и текущая скорость WAN и туннелей. Опрос — общий с шапкой (health.ts).
import { computed, onBeforeUnmount } from 'vue'
import { ArrowDown, ArrowUp } from 'lucide-vue-next'
import { bitrate, health, level, memUsed, rates, useHealth } from '../health'
import { dateTag, t } from '../i18n'
import { plural } from '../status'

const stop = useHealth()
onBeforeUnmount(stop)

const h = computed(() => health.value)
const cpu = computed(() => (h.value?.cpu == null ? null : Math.round(h.value.cpu)))
function size(b: number): string {
  const mb = b / 1024 / 1024
  return mb < 1024 ? t('{n} МБ', { n: Math.round(mb) }) : t('{n} ГБ', { n: (mb / 1024).toFixed(1).replace(/\.0$/, '') })
}
const uptime = computed(() => {
  const u = h.value?.uptime
  if (u == null) return null
  const d = Math.floor(u / 86400), hh = Math.floor((u % 86400) / 3600), m = Math.floor((u % 3600) / 60)
  return d ? t('{d} {h} ч', { d: plural(d, 'день', 'дня', 'дней'), h: hh }) : hh ? t('{h} ч {m} мин', { h: hh, m }) : t('{m} мин', { m })
})
const load = computed(() => (h.value?.load.length ? h.value.load.map((x) => new Intl.NumberFormat(dateTag(), { maximumFractionDigits: 2 }).format(x)).join(' · ') : null))
const tag = dateTag()
// датчики чипа (IPQ… tsens_tz_sensorN) безымянны: «Датчик N»; много датчиков — максимум, среднее и список по запросу
const sensorName = (n: string) => { const m = /^tsens_tz_sensor(\d+)$/.exec(n); return m ? t('Датчик {n}', { n: m[1]! }) : n }
const tMax = computed(() => Math.round(Math.max(...(h.value?.temps ?? []).map((s) => s.c))))
const tAvg = computed(() => { const ts = h.value?.temps ?? []; return ts.length ? Math.round(ts.reduce((a, s) => a + s.c, 0) / ts.length) : 0 })
const sortedTemps = computed(() => [...(h.value?.temps ?? [])].sort((a, b) => b.c - a.c))
</script>

<template>
  <div class="card health" role="group" aria-labelledby="health-title">
    <h2 id="health-title" class="card__title">{{ t('Роутер') }}</h2>
    <p v-if="!h" class="muted">{{ t('Загружаю…') }}</p>
    <template v-else>
      <div class="hm">
        <div class="hm__item">
          <span class="hm__label">{{ t('Процессор') }}</span>
          <span :class="['hm__big', `hm__big--${level(cpu, 70, 90)}`]"><template v-if="cpu != null">{{ cpu }}<small>%</small></template><template v-else>—</template></span>
          <div v-if="h.cores.length > 1" class="cores" :aria-label="t('По ядрам: {list}', { list: h.cores.map((c) => `${Math.round(c)}%`).join(', ') })">
            <span v-for="(c, i) in h.cores" :key="i" class="cores__bar" :title="t('Ядро {n}: {p}%', { n: i + 1, p: Math.round(c) })">
              <span class="cores__fill" :style="{ height: `${Math.max(4, c)}%` }" />
            </span>
          </div>
          <span v-if="load" class="meta">{{ t('нагрузка {l}', { l: load }) }}</span>
        </div>
        <div class="hm__item">
          <span class="hm__label">{{ t('Память') }}</span>
          <span :class="['hm__big', `hm__big--${level(memUsed, 80, 92)}`]"><template v-if="memUsed != null">{{ memUsed }}<small>%</small></template><template v-else>—</template></span>
          <div v-if="h.mem" class="bar" role="meter" :aria-valuenow="memUsed ?? 0" aria-valuemin="0" aria-valuemax="100" :aria-label="t('Память занята на {n}%', { n: memUsed ?? 0 })">
            <span class="bar__fill" :style="{ width: `${memUsed ?? 0}%` }" />
          </div>
          <span v-if="h.mem" class="meta">{{ t('свободно {free} из {total}', { free: size(h.mem.available), total: size(h.mem.total) }) }}</span>
        </div>
      </div>

      <dl class="hl">
        <template v-if="h.temps.length && h.temps.length <= 3">
          <div v-for="s in h.temps" :key="s.name" class="hl__row">
            <dt>{{ t('Температура: {name}', { name: sensorName(s.name) }) }}</dt>
            <dd :class="`hl--${level(s.c, 75, 90)}`">{{ Math.round(s.c) }} °C</dd>
          </div>
        </template>
        <template v-else-if="h.temps.length">
          <div class="hl__row"><dt>{{ t('Температура, максимум') }}</dt><dd :class="`hl--${level(tMax, 75, 90)}`">{{ tMax }} °C</dd></div>
          <div class="hl__row"><dt>{{ t('Температура, в среднем') }}</dt><dd>{{ tAvg }} °C</dd></div>
          <details class="sensors">
            <summary class="meta">{{ t('Все датчики ({n})', { n: h.temps.length }) }}</summary>
            <div class="sensors__grid">
              <span v-for="s in sortedTemps" :key="s.name" class="sensors__item">
                <span class="meta">{{ sensorName(s.name) }}</span>
                <span :class="`hl--${level(s.c, 75, 90)}`">{{ Math.round(s.c) }} °C</span>
              </span>
            </div>
          </details>
        </template>
        <div v-if="uptime" class="hl__row"><dt>{{ t('Работает без перезагрузки') }}</dt><dd>{{ uptime }}</dd></div>
        <div v-if="h.conntrack" class="hl__row"><dt>{{ t('Соединений') }}</dt><dd>{{ h.conntrack.count }}<span v-if="h.conntrack.max" class="meta"> / {{ h.conntrack.max }}</span></dd></div>
        <div v-if="h.net.wan" class="hl__row">
          <dt>{{ t('Интернет ({dev})', { dev: h.net.wan.dev }) }}</dt>
          <dd class="rate"><ArrowDown :size="13" aria-hidden="true" />{{ bitrate(rates.wan?.rx, tag) }} <ArrowUp :size="13" aria-hidden="true" />{{ bitrate(rates.wan?.tx, tag) }}</dd>
        </div>
        <div v-if="h.net.vpn" class="hl__row">
          <dt>{{ h.net.vpn.tunnels > 1 ? t('Через VPN ({n})', { n: h.net.vpn.tunnels }) : t('Через VPN') }}</dt>
          <dd class="rate rate--vpn"><ArrowDown :size="13" aria-hidden="true" />{{ bitrate(rates.vpn?.rx, tag) }} <ArrowUp :size="13" aria-hidden="true" />{{ bitrate(rates.vpn?.tx, tag) }}</dd>
        </div>
      </dl>
    </template>
  </div>
</template>

<style scoped>
.hm { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 1rem; }
.hm__item { display: grid; gap: 0.375rem; align-content: start; }
.hm__label { font-size: 0.8125rem; color: var(--muted); }
.hm__big { font-size: 2rem; font-weight: 600; line-height: 1; font-variant-numeric: tabular-nums; }
.hm__big small { font-size: 1rem; font-weight: 500; margin-left: 0.125rem; color: var(--muted); }
.hm__big--warn { color: var(--warn-ink, var(--warn)); }
.hm__big--bad { color: var(--bad-ink, var(--bad)); }
.cores { display: flex; gap: 3px; height: 1.5rem; align-items: flex-end; }
.cores__bar { flex: 1; max-width: 0.75rem; height: 100%; display: flex; align-items: flex-end; background: var(--idle-soft); border-radius: 2px; overflow: hidden; }
.cores__fill { display: block; width: 100%; background: var(--accent); border-radius: 2px; }
.bar { height: 6px; border-radius: 3px; background: var(--idle-soft); overflow: hidden; margin: 0.5rem 0 0.125rem; }
.bar__fill { display: block; height: 100%; background: var(--accent); border-radius: 3px; }
.hl { display: grid; gap: 0.4rem; margin: 0.25rem 0 0; }
.hl__row { display: flex; justify-content: space-between; gap: 1rem; font-size: 0.875rem; }
.hl__row dt { color: var(--muted); min-width: 0; overflow-wrap: anywhere; }
.hl__row dd { margin: 0; font-variant-numeric: tabular-nums; font-weight: 500; white-space: nowrap; }
.hl--warn { color: var(--warn-ink, var(--warn)); }
.hl--bad { color: var(--bad-ink, var(--bad)); }
.sensors summary { cursor: pointer; font-size: 0.8125rem; }
.sensors summary:focus-visible { outline: 2px solid var(--focus); outline-offset: 2px; }
.sensors__grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(7.5rem, 1fr)); gap: 0.25rem 1rem; margin-top: 0.5rem; }
.sensors__item { display: flex; justify-content: space-between; gap: 0.5rem; font-size: 0.8125rem; font-variant-numeric: tabular-nums; }
.rate { display: inline-flex; align-items: center; gap: 0.2rem; }
.rate--vpn { color: var(--vpn, var(--accent)); }
</style>
