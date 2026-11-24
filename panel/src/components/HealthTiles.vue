<script setup lang="ts">
// «Обзор», раздел «Сейчас»: шесть одинаковых плиток — интернет, VPN, задержка, процессор, память, температура.
// У каждой: подпись, крупное число, полоса графика одной высоты и строка пояснения. Опрос — общий с шапкой (health.ts).
import { computed } from 'vue'
import { bitrate, bitrateParts, health, level, memUsed, rates, series } from '../health'
import { dateTag, t } from '../i18n'
import { plural } from '../status'
import Spark from './Spark.vue'

const props = defineProps<{ ping: { primary: number | null; backup: number | null } | null; host: string | null }>()

const tag = dateTag()
const h = computed(() => health.value)
const num = (v: number, d = 0) => new Intl.NumberFormat(tag, { maximumFractionDigits: d }).format(v)
const wan = computed(() => bitrateParts(rates.value.wan?.rx, tag))
const vpn = computed(() => bitrateParts(rates.value.vpn?.rx, tag))
const wanFoot = computed(() => [rates.value.wan ? `↑ ${bitrate(rates.value.wan.tx, tag)}` : null, h.value?.net.wan?.dev].filter(Boolean).join(' · ') || '—')
const vpnFoot = computed(() => {
  const n = h.value?.net.vpn?.tunnels ?? 0
  return [rates.value.vpn ? `↑ ${bitrate(rates.value.vpn.tx, tag)}` : null, n > 1 ? plural(n, 'туннель', 'туннеля', 'туннелей') : null].filter(Boolean).join(' · ') || t('туннель не поднят')
})

const cpu = computed(() => (h.value?.cpu == null ? null : Math.round(h.value.cpu)))
const cores = computed(() => h.value?.cores ?? [])
const cpuFoot = computed(() => {
  const n = cores.value.length
  const l = h.value?.load[0]
  return [n ? plural(n, 'ядро', 'ядра', 'ядер') : null, l != null ? num(l, 2) : null].filter(Boolean).join(' · ') || '—'
})
const coresTitle = computed(() => t('По ядрам: {list}', { list: cores.value.map((c) => `${Math.round(c)}%`).join(', ') }))

function size(b: number): string {
  const mb = b / 1024 / 1024
  return mb < 1024 ? t('{n} МБ', { n: Math.round(mb) }) : t('{n} ГБ', { n: num(mb / 1024, 1) })
}
const memFoot = computed(() => (h.value?.mem ? t('свободно {n}', { n: size(h.value.mem.available) }) : '—'))
const memTitle = computed(() => (h.value?.mem ? t('свободно {free} из {total}', { free: size(h.value.mem.available), total: size(h.value.mem.total) }) : ''))

// датчики чипа (IPQ… tsens_tz_sensorN) безымянны: «Датчик N»
const sensorName = (n: string) => { const m = /^tsens_tz_sensor(\d+)$/.exec(n); return m ? t('Датчик {n}', { n: m[1]! }) : n }
const temps = computed(() => h.value?.temps ?? [])
const tMax = computed(() => (temps.value.length ? Math.round(Math.max(...temps.value.map((s) => s.c))) : null))
const tAvg = computed(() => (temps.value.length ? Math.round(temps.value.reduce((a, s) => a + s.c, 0) / temps.value.length) : null))
/** Высота столбика датчика: 20 °C — пусто, 90 °C — доверху. */
const tBar = (c: number) => Math.max(8, Math.min(100, ((c - 20) / 70) * 100))
const tFoot = computed(() => (temps.value.length > 1 ? t('среднее {n} °C', { n: tAvg.value! }) : temps.value.length ? sensorName(temps.value[0]!.name) : t('датчиков нет')))

const ping = computed(() => props.ping?.primary ?? null)
const pingFoot = computed(() => (props.ping?.backup != null ? t('запасной {n} мс', { n: props.ping.backup }) : props.host ?? '—'))
</script>

<template>
  <div class="htiles">
    <section class="card htile" :aria-label="t('Интернет')">
      <span class="htile__label">{{ t('Интернет') }}</span>
      <span class="htile__big"><template v-if="wan">{{ wan.n }}<small>{{ wan.unit }}</small></template><template v-else>—</template></span>
      <Spark :values="series.wan" />
      <span class="meta htile__foot">{{ wanFoot }}</span>
    </section>

    <section class="card htile" :aria-label="t('Через VPN')">
      <span class="htile__label">{{ t('Через VPN') }}</span>
      <span class="htile__big htile__big--vpn"><template v-if="vpn">{{ vpn.n }}<small>{{ vpn.unit }}</small></template><template v-else>—</template></span>
      <Spark :values="series.vpn" tone="vpn" />
      <span class="meta htile__foot">{{ vpnFoot }}</span>
    </section>

    <section class="card htile" :aria-label="t('Задержка')">
      <span class="htile__label">{{ t('Задержка') }}</span>
      <span :class="['htile__big', `htile__big--${level(ping, 150, 400)}`]"><template v-if="ping != null">{{ ping }}<small>{{ t('мс') }}</small></template><template v-else>—</template></span>
      <span class="htile__viz htile__viz--bar"><span class="htrack"><span :class="['htrack__fill', `htrack__fill--${level(ping, 150, 400)}`]" :style="{ width: `${ping == null ? 0 : Math.min(100, ping / 5)}%` }" /></span></span>
      <span class="meta htile__foot" :title="host ?? undefined">{{ ping == null && !props.ping ? t('замера ещё не было') : pingFoot }}</span>
    </section>

    <section class="card htile" :aria-label="t('Процессор')">
      <span class="htile__label">{{ t('Процессор') }}</span>
      <span :class="['htile__big', `htile__big--${level(cpu, 70, 90)}`]"><template v-if="cpu != null">{{ cpu }}<small>%</small></template><template v-else>—</template></span>
      <span v-if="cores.length > 1" class="htile__viz htile__cols" :title="coresTitle">
        <span v-for="(c, i) in cores" :key="i" class="htile__col"><span class="htile__colfill" :style="{ height: `${Math.max(6, c)}%` }" /></span>
      </span>
      <span v-else class="htile__viz htile__viz--bar"><span class="htrack"><span :class="['htrack__fill', `htrack__fill--${level(cpu, 70, 90)}`]" :style="{ width: `${cpu ?? 0}%` }" /></span></span>
      <span class="meta htile__foot">{{ cpuFoot }}</span>
    </section>

    <section class="card htile" :aria-label="t('Память')">
      <span class="htile__label">{{ t('Память') }}</span>
      <span :class="['htile__big', `htile__big--${level(memUsed, 80, 92)}`]"><template v-if="memUsed != null">{{ memUsed }}<small>%</small></template><template v-else>—</template></span>
      <span class="htile__viz htile__viz--bar"><span class="htrack"><span :class="['htrack__fill', `htrack__fill--${level(memUsed, 80, 92)}`]" :style="{ width: `${memUsed ?? 0}%` }" /></span></span>
      <span class="meta htile__foot" :title="memTitle || undefined">{{ memFoot }}</span>
    </section>

    <section class="card htile" :aria-label="t('Температура')">
      <span class="htile__label">{{ t('Температура') }}</span>
      <span :class="['htile__big', `htile__big--${level(tMax, 75, 90)}`]"><template v-if="tMax != null">{{ tMax }}<small>°C</small></template><template v-else>—</template></span>
      <span class="htile__viz htile__cols htile__cols--thin">
        <span v-for="s in temps" :key="s.name" :class="['htile__temp', `htile__temp--${level(s.c, 75, 90)}`]" :style="{ height: `${tBar(s.c)}%` }"
          :title="`${sensorName(s.name)}: ${Math.round(s.c)} °C`" />
      </span>
      <span class="meta htile__foot">{{ tFoot }}</span>
    </section>
  </div>
</template>

<style scoped>
.htiles { display: grid; gap: 1rem; grid-template-columns: repeat(2, minmax(0, 1fr)); }
@container ov (min-width: 640px) { .htiles { grid-template-columns: repeat(3, minmax(0, 1fr)); } }
@container ov (min-width: 1040px) { .htiles { grid-template-columns: repeat(6, minmax(0, 1fr)); } }
.htile { display: grid; grid-template-rows: 1rem 2.25rem 1.75rem 1rem; row-gap: 0.625rem; padding: 1rem 1.125rem; min-width: 0; }
.htile > * { min-width: 0; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.htile__label { font-size: 0.8125rem; line-height: 1rem; color: var(--muted); }
.htile__big { font-size: 1.875rem; line-height: 2.25rem; font-weight: 600; font-variant-numeric: tabular-nums; letter-spacing: -0.01em; }
.htile__big small { font-size: 0.8125rem; font-weight: 500; color: var(--faint); margin-left: 0.2rem; letter-spacing: 0; }
.htile__big--vpn { color: var(--accent); }
.htile__big--warn { color: var(--warn-ink, var(--warn)); }
.htile__big--bad { color: var(--bad-ink, var(--bad)); }
.htile__foot { line-height: 1rem; }
.htile__viz--bar { display: flex; align-items: center; }
.htrack { flex: 1; height: 0.375rem; border-radius: 0.1875rem; background: var(--idle-soft); overflow: hidden; }
.htrack__fill { display: block; height: 100%; background: var(--accent); border-radius: 0.1875rem; }
.htrack__fill--warn { background: var(--warn); }
.htrack__fill--bad { background: var(--bad); }
.htile__cols { display: flex; gap: 0.25rem; align-items: flex-end; }
.htile__cols--thin { gap: 0.1875rem; }
.htile__col { flex: 1; height: 100%; display: flex; align-items: flex-end; background: var(--idle-soft); border-radius: 3px; overflow: hidden; }
.htile__colfill { display: block; width: 100%; background: var(--accent); border-radius: 3px; }
.htile__temp { flex: 1; min-width: 2px; border-radius: 2px; background: var(--ok); }
.htile__temp--warn { background: var(--warn); }
.htile__temp--bad { background: var(--bad); }
</style>
