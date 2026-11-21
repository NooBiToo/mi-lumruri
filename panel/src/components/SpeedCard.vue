<script setup lang="ts">
// Замер с роутера: задержка до основного и запасного серверов, скорость скачивания напрямую и через VPN.
// Замер выполняет служба (POST /speed — заявка, GET /speed — итог); скачивает до ~50 МБ.
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import Button from 'primevue/button'
import { Gauge } from 'lucide-vue-next'
import { manage, type SpeedPath, type SpeedResponse } from '../api'
import { notify, profile } from '../store'
import { dateTag, t } from '../i18n'
import { when } from '../status'

const st = ref<SpeedResponse | null>(null)
const busy = computed(() => !!st.value?.running || st.value?.speed?.state === 'running')
let timer: number | undefined

async function load() {
  const r = await manage.speed()
  if (r.status === 200) st.value = r.body
  clearTimeout(timer)
  if (busy.value) timer = window.setTimeout(() => void load(), 2000)
}
async function run() {
  const r = await manage.startSpeed()
  if (r.status !== 202) { notify.show('error', t('Не получилось'), r.body.error?.message); return }
  st.value = { ...(st.value ?? { ok: true, speed: null, issues: [] }), running: true }
  timer = window.setTimeout(() => void load(), 2000)
}
onMounted(() => void load())
onBeforeUnmount(() => clearTimeout(timer))

const num = (v: number) => new Intl.NumberFormat(dateTag(), { maximumFractionDigits: v < 10 ? 1 : 0 }).format(v)
const speedText = (p: SpeedPath | null | undefined) => (!p ? '…' : 'mbps' in p ? t('{n} Мбит/с', { n: num(p.mbps) }) : t('не получилось: {e}', { e: p.error }))
const pingText = (v: number | null | undefined) => (v == null ? t('не отвечает') : t('{n} мс', { n: v }))
const s = computed(() => st.value?.speed ?? null)
const hasBackup = computed(() => !!profile.value?.backup)
</script>

<template>
  <div class="card speed" role="group" aria-labelledby="speed-title">
    <h2 id="speed-title" class="card__title">{{ t('Скорость и задержка') }}</h2>
    <p class="hint">{{ t('Замер с самого роутера: задержка до сервера и скорость скачивания напрямую и через VPN. Скачивает до 50 МБ') }}</p>
    <dl v-if="s" class="speed__grid">
      <dt>{{ t('Задержка до основного сервера') }}</dt><dd>{{ pingText(s.ping.primary) }}</dd>
      <template v-if="hasBackup || s.ping.backup != null"><dt>{{ t('Задержка до запасного сервера') }}</dt><dd>{{ pingText(s.ping.backup) }}</dd></template>
      <dt>{{ t('Скорость напрямую') }}</dt><dd>{{ speedText(s.direct) }}</dd>
      <dt>{{ t('Скорость через VPN') }}</dt><dd :class="{ speed__vpn: s.tunnel && 'mbps' in s.tunnel }">{{ speedText(s.tunnel) }}</dd>
    </dl>
    <div class="speed__foot">
      <Button :label="busy ? t('Замеряю…') : t('Замерить')" :loading="busy" :disabled="busy" severity="secondary" variant="outlined" @click="run">
        <template #icon><Gauge :size="16" class="p-button-icon-left" aria-hidden="true" /></template>
      </Button>
      <span v-if="s && s.state === 'done'" class="meta">{{ t('Замер {d}', { d: when(s.at) }) }}</span>
    </div>
  </div>
</template>

<style scoped>
.speed__grid { display: grid; grid-template-columns: auto auto; justify-content: start; gap: 0.35rem 1.25rem; margin: 0.5rem 0; }
.speed__grid dt { color: var(--muted, inherit); }
.speed__grid dd { margin: 0; font-variant-numeric: tabular-nums; font-weight: 600; }
.speed__vpn { color: var(--vpn, #2f7d5b); }
.speed__foot { display: flex; flex-wrap: wrap; align-items: center; gap: 0.75rem; }
</style>
