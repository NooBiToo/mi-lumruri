<script setup lang="ts">
// Диагностика: проверки службы по заявке (их выполняет служба роутера), проверка одного сайта, журналы и перезапуск.
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import Button from 'primevue/button'
import InputText from 'primevue/inputtext'
import { useConfirm } from 'primevue/useconfirm'
import { Copy, RotateCw } from 'lucide-vue-next'
import { api, type DiagResponse } from '../api'
import { checkTitle, overall, overallText, reportText, siteVerdict } from '../diag'
import { normalizeDomain } from '../simple'
import { notify, loadStatus } from '../store'
import { when } from '../status'
import Segmented from '../components/Segmented.vue'

const diag = ref<DiagResponse | null>(null)
const waiting = ref(false)
const site = ref('')
const siteError = ref<string | null>(null)
const confirm = useConfirm()

const checks = computed(() => diag.value?.checks ?? [])
const shownChecks = computed(() => checks.value.filter((c) => c.status !== 'skip'))
const skipped = computed(() => checks.value.filter((c) => c.status === 'skip'))
const total = computed(() => overall(checks.value))
const verdict = computed(() => (diag.value?.site ? siteVerdict(diag.value.site) : null))
const running = computed(() => waiting.value || !!diag.value?.running)

type LogKey = 'service' | 'trusttunnel' | 'nfqws2'
const LOGS = [{ value: 'service' as const, label: 'Служба' }, { value: 'trusttunnel' as const, label: 'TrustTunnel' }, { value: 'nfqws2' as const, label: 'Zapret' }]
const log = ref<LogKey>('service')
const logLines = computed(() => diag.value?.logs?.[log.value] ?? [])

let timer: number | undefined
async function load() {
  const r = await api.diag()
  if (r.body.ok) diag.value = r.body
  return r.body
}
/** Ждём итог службы: проверка идёт в фоне, обычно 10–20 секунд (пробные запросы с таймаутом). */
function poll(since: number, left = 30) {
  clearTimeout(timer)
  timer = window.setTimeout(async () => {
    const d = await load()
    if (d.ok && !d.running && (d.finished ?? 0) >= since) { waiting.value = false; return }
    if (left > 0) poll(since, left - 1)
    else { waiting.value = false; notify.show('error', 'Проверка не закончилась', 'Служба роутера не ответила за минуту. Перезапустите службу и повторите') }
  }, 2000)
}
async function run(withSite: boolean) {
  siteError.value = null
  let s: string | undefined
  if (withSite) {
    s = normalizeDomain(site.value)
    if (!s.includes('.')) { siteError.value = 'Введите адрес сайта, например youtube.com'; return }
    site.value = s
  }
  waiting.value = true
  const since = Math.floor(Date.now() / 1000) - 5
  const r = await api.runDiag(s)
  if (r.status === 202 || r.body.error?.code === 'diag_running') { poll(since); return }
  waiting.value = false
  if (r.body.issues?.length) siteError.value = r.body.issues[0]!.message
  else notify.show('error', 'Проверка не запустилась', r.body.error?.message)
}
function restart() {
  confirm.require({
    header: 'Перезапустить службу?',
    message: 'VPN и обход блокировок прервутся на несколько секунд, затем настройки применятся заново',
    acceptLabel: 'Перезапустить', rejectLabel: 'Отмена',
    acceptProps: { severity: 'danger' }, rejectProps: { severity: 'secondary', variant: 'text' },
    accept: async () => {
      const r = await api.restartService()
      if (r.status === 202) { notify.show('info', 'Служба перезапускается', 'Через полминуты проверьте работу снова'); window.setTimeout(() => void loadStatus(), 10000) }
      else notify.show('error', 'Не получилось', r.body.error?.message)
    },
  })
}
async function copy() {
  if (!diag.value) return
  try {
    await navigator.clipboard.writeText(reportText(diag.value))
    notify.show('success', 'Отчёт скопирован', 'Вставьте его в сообщение')
  } catch {
    notify.show('error', 'Не получилось скопировать', 'Браузер не дал доступ к буферу обмена')
  }
}
onMounted(async () => {
  const d = await load()
  if (d.ok && d.running) { waiting.value = true; poll(0) }
})
onBeforeUnmount(() => clearTimeout(timer))
</script>

<template>
  <section class="sect" aria-label="Диагностика">
    <div class="card">
      <div class="card__head">
        <div>
          <h2 class="card__title">Проверка работы</h2>
          <p class="card__sub">Роутер проверит службу, туннель, маршруты, DNS и обход блокировок. Займёт до 20 секунд</p>
        </div>
        <Button :label="running ? 'Проверяю…' : 'Проверить'" :loading="running" :disabled="running" @click="run(false)" />
      </div>

      <template v-if="checks.length">
        <div :class="['diag__total', `diag__total--${total}`]">
          <span :class="['led', 'led--lg', `led--${total === 'skip' ? 'idle' : total}`]" aria-hidden="true" />
          <span class="diag__total-text">{{ overallText(checks) }}</span>
          <span class="meta">{{ when(diag?.finished) }}</span>
        </div>
        <ul class="diag__list" aria-label="Итоги проверок">
          <li v-for="c in shownChecks" :key="c.id" class="diag__row">
            <span :class="['led', `led--${c.status}`]" aria-hidden="true" />
            <span class="diag__name">{{ checkTitle(c) }}</span>
            <span :class="['diag__detail', { 'diag__detail--bad': c.status === 'bad' }]">{{ c.detail }}</span>
          </li>
        </ul>
        <p v-if="skipped.length" class="hint">Не используется: {{ skipped.map(checkTitle).join(', ').toLowerCase() }}</p>
      </template>
      <p v-else-if="!running" class="muted">Проверок ещё не было. Нажмите «Проверить»</p>
    </div>

    <div class="card">
      <div>
        <h2 class="card__title">Проверить сайт</h2>
        <p class="card__sub">Покажет, каким путём роутер отправляет сайт и отвечает ли он</p>
      </div>
      <form class="dlist__add diag__form" @submit.prevent="run(true)">
        <label for="diag-site" class="sr-only">Адрес сайта</label>
        <InputText id="diag-site" v-model="site" placeholder="youtube.com" spellcheck="false" autocomplete="off" autocapitalize="off"
          :invalid="!!siteError" aria-describedby="diag-site-note" />
        <Button type="submit" label="Проверить сайт" severity="secondary" variant="outlined" :disabled="running || !site.trim()" />
      </form>
      <span v-if="siteError" id="diag-site-note" class="field__error" aria-live="polite">{{ siteError }}</span>
      <div v-if="verdict" class="diag__row diag__site">
        <span :class="['led', `led--${verdict.status}`]" aria-hidden="true" />
        <span class="diag__name">{{ verdict.title }}</span>
        <span class="diag__detail">{{ verdict.detail }}</span>
      </div>
    </div>

    <div class="card">
      <div class="card__head">
        <div>
          <h2 class="card__title">Журналы</h2>
          <p class="card__sub">Последние записи на момент проверки. Паролей в них нет</p>
        </div>
        <div class="diag__acts">
          <Button label="Скопировать отчёт" severity="secondary" variant="outlined" :disabled="!checks.length" @click="copy">
            <template #icon><Copy :size="16" class="p-button-icon-left" aria-hidden="true" /></template>
          </Button>
        </div>
      </div>
      <Segmented v-model="log" class="self-start" :options="LOGS" label="Журнал" name="log" />
      <pre v-if="logLines.length" class="diag__log" tabindex="0" aria-label="Записи журнала">{{ logLines.join('\n') }}</pre>
      <p v-else class="muted">{{ checks.length ? 'Записей нет' : 'Журналы появятся после проверки' }}</p>
    </div>

    <div class="card setrow diag__restart">
      <span class="setrow__text">
        <span class="setrow__title">Перезапустить службу</span>
        <span class="setrow__desc">Если что-то не работает после перезагрузки роутера: заново запустит VPN, обход блокировок и применит настройки</span>
      </span>
      <Button label="Перезапустить" severity="secondary" variant="outlined" @click="restart">
        <template #icon><RotateCw :size="16" class="p-button-icon-left" aria-hidden="true" /></template>
      </Button>
    </div>
  </section>
</template>
