<script setup lang="ts">
// «Обзор», раздел «Маршруты»: карточки одной ширины и высоты — название и скорость канала по замеру,
// значки сайтов маршрута, внизу текущий трафик. Нижние строки карточек стоят на одной линии.
import { Globe } from 'lucide-vue-next'
import ServiceLogo from './ServiceLogo.vue'
import { plural } from '../status'
import { t } from '../i18n'

export type Tone = 'vpn' | 'zapret' | 'idle' | 'ok' | 'warn' | 'bad'
export interface RouteCard {
  key: string
  kind: 'vpn' | 'zapret' | 'direct'
  tone: Tone
  name: string
  meta: string
  /** Маршрут работает (выключенный VPN, остановленный обход — пунктирная рамка). */
  live: boolean
  items: { id: string; name: string }[]
  /** Своих адресов в маршруте. */
  domains: number
  /** Пояснение вместо значков: «Всё, что не попало в списки», «Сайты не выбраны»… */
  note?: string
  /** Канал по последнему замеру; 'measuring' — идёт замер; null — замера не было. */
  cap: string | 'measuring' | null
  /** Сейчас: приём и передача; 'shared' — отдельно не считается (входит в «напрямую»). */
  now: { d: string; u: string } | 'shared' | null
  title: string
}

defineProps<{ cards: RouteCard[] }>()
const emit = defineEmits<{ measure: [] }>()

/** Значков в карточке не больше двух рядов; остальное — в счётчик. */
const MAX_ICONS = 13
function more(c: RouteCard): string | null {
  const s = Math.max(0, c.items.length - MAX_ICONS)
  if (!s && !c.domains) return null
  return s ? t('ещё {n}', { n: s + c.domains }) : `+${plural(c.domains, 'адрес', 'адреса', 'адресов')}`
}
</script>

<template>
  <ul class="rcards" :aria-label="t('Маршруты')">
    <li v-for="c in cards" :key="c.key" :class="['card', 'rcard', { 'rcard--off': !c.live }]" :title="c.title">
      <div class="rcard__head">
        <span class="rcard__name"><span :class="['led', `led--${c.tone}`]" aria-hidden="true" />{{ c.name }}</span>
        <span v-if="c.cap === 'measuring'" class="rcard__cap rcard__cap--wait">{{ t('замеряю…') }}</span>
        <span v-else-if="c.cap" :class="['rcard__cap', `rcard__cap--${c.kind}`]">{{ c.cap }}</span>
        <button v-else type="button" class="link-btn rcard__measure" @click="emit('measure')">{{ t('Замерить') }}</button>
        <span class="meta rcard__meta">{{ c.meta }}</span>
        <span v-if="c.cap && c.cap !== 'measuring'" class="meta rcard__capnote">{{ t('канал') }}</span>
      </div>
      <div class="rcard__body">
        <ul v-if="c.items.length || c.domains" class="rcard__icons">
          <li v-for="x in c.items.slice(0, MAX_ICONS)" :key="x.id" :title="x.name"><ServiceLogo :id="x.id" /><span class="sr-only">{{ x.name }}</span></li>
          <li v-if="more(c)" class="rcard__more">{{ more(c) }}</li>
        </ul>
        <p v-else class="rcard__note"><span class="rcard__globe" aria-hidden="true"><Globe :size="18" /></span>{{ c.note }}</p>
      </div>
      <div class="rcard__foot">
        <span>{{ t('сейчас') }}</span>
        <span v-if="c.now === 'shared'" class="meta">{{ t('входит в «напрямую»') }}</span>
        <span v-else-if="c.now" class="rcard__now">↓ {{ c.now.d }} &nbsp;↑ {{ c.now.u }}</span>
        <span v-else class="rcard__now">—</span>
      </div>
    </li>
  </ul>
</template>

<style scoped>
.rcards { list-style: none; margin: 0; padding: 0; display: grid; gap: 1rem; grid-template-columns: repeat(auto-fit, minmax(17rem, 1fr)); }
.rcard { display: grid; grid-template-columns: minmax(0, 1fr); grid-template-rows: auto 5.25rem auto; row-gap: 1rem; padding: 1.25rem; min-width: 0; }
.rcard--off { border-style: dashed; }
.rcard__head { display: grid; grid-template-columns: minmax(0, 1fr) auto; grid-template-rows: 1.75rem 1rem; column-gap: 0.75rem; row-gap: 0.25rem; align-items: center; }
.rcard__name { display: flex; align-items: center; gap: 0.5rem; font-size: 1rem; line-height: 1.75rem; font-weight: 600; min-width: 0; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.rcard--off .rcard__name { color: var(--muted); }
.rcard__cap { font-size: 1.25rem; line-height: 1.75rem; font-weight: 600; font-variant-numeric: tabular-nums; white-space: nowrap; text-align: right; }
.rcard__cap--vpn { color: var(--accent); }
.rcard__cap--zapret { color: var(--zap-ink, var(--zap)); }
.rcard__cap--wait { font-size: 0.875rem; font-weight: 500; color: var(--muted); }
.rcard__measure { font-size: 0.875rem; justify-self: end; }
.rcard__meta { min-width: 0; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.rcard__capnote { text-align: right; }
.rcard__body { min-width: 0; overflow: hidden; }
.rcard__icons { list-style: none; margin: 0; padding: 0; display: flex; flex-wrap: wrap; gap: 0.5rem; max-height: 5.25rem; overflow: hidden; }
.rcard__icons :deep(.logo) { width: 2.375rem; height: 2.375rem; }
.rcard__more { display: grid; place-items: center; height: 2.375rem; padding: 0 0.75rem; border: 1px dashed var(--line-strong); border-radius: 10px; font-size: 0.8125rem; color: var(--muted); white-space: nowrap; }
.rcard__note { margin: 0; display: flex; align-items: center; gap: 0.75rem; font-size: 0.875rem; line-height: 1.25rem; color: var(--muted); }
.rcard__globe { flex: none; display: grid; place-items: center; width: 2.375rem; height: 2.375rem; border-radius: 10px; background: var(--idle-soft); color: var(--muted); }
.rcard__foot { display: flex; justify-content: space-between; align-items: center; gap: 0.75rem; padding-top: 0.875rem; border-top: 1px solid var(--line); font-size: 0.875rem; }
.rcard__foot > :first-child { color: var(--muted); }
.rcard__now { font-variant-numeric: tabular-nums; white-space: nowrap; }
</style>
