<script setup lang="ts">
// Серверы подписки sing-box на экране «Сервер»: список с прокруткой, как в мобильных клиентах — флаг страны,
// название, протокол и адрес, задержка с роутера; выбранный отмечен. Автовыбор — сервер с наименьшей задержкой.
import { computed, ref } from 'vue'
import Button from 'primevue/button'
import ToggleSwitch from 'primevue/toggleswitch'
import { Check, RefreshCw, Search } from 'lucide-vue-next'
import type { SubscriptionEntry } from '../api'
import { PROTOCOL_LABEL } from '../proxyLink'
import { plural } from '../status'
import { t } from '../i18n'

const props = defineProps<{ entries: SubscriptionEntry[]; current: string | null; auto: boolean; running: boolean; status: string; bad: boolean }>()
const emit = defineEmits<{ pick: [name: string]; auto: [on: boolean]; refresh: [] }>()

/** Флаг в начале названия («🇸🇪 Sweden») → код страны и название без флага: эмодзи флагов Windows не рисует. */
function split(name: string): { cc: string | null; title: string } {
  const cps = [...name]
  const ri = (c: string | undefined) => !!c && c.codePointAt(0)! >= 0x1f1e6 && c.codePointAt(0)! <= 0x1f1ff
  if (ri(cps[0]) && ri(cps[1])) {
    const cc = String.fromCharCode(cps[0]!.codePointAt(0)! - 0x1f1e6 + 65, cps[1]!.codePointAt(0)! - 0x1f1e6 + 65)
    return { cc, title: cps.slice(2).join('').trim() || name }
  }
  return { cc: null, title: name }
}
const q = ref('')
const rows = computed(() => {
  const s = q.value.trim().toLowerCase()
  return props.entries
    .filter((e) => !s || e.name.toLowerCase().includes(s) || e.server.toLowerCase().includes(s))
    .map((e) => ({ ...e, ...split(e.name), on: e.name === props.current }))
})
const meta = (e: SubscriptionEntry) => [(PROTOCOL_LABEL as Record<string, string>)[e.kind] ?? e.kind, e.security && e.security !== 'none' ? e.security.toUpperCase() : null, e.server].filter(Boolean).join(' · ')
const tone = (ms: number | null | undefined) => (ms == null ? 'none' : ms < 150 ? 'ok' : ms < 300 ? 'warn' : 'bad')
const fastest = computed(() => {
  const xs = props.entries.filter((e) => e.ping != null)
  return xs.length ? xs.reduce((a, b) => (b.ping! < a.ping! ? b : a)).name : null
})
</script>

<template>
  <section class="subs" :aria-label="t('Серверы подписки')">
    <div class="subs__head">
      <div class="subs__title">
        <h3>{{ t('Серверы подписки') }}</h3>
        <span :class="['meta', { 'warn-text': bad }]">{{ plural(entries.length, 'сервер', 'сервера', 'серверов') }} · {{ status }}</span>
      </div>
      <Button :label="t('Обновить')" size="small" severity="secondary" variant="outlined" :loading="running" :disabled="running" @click="emit('refresh')">
        <template #icon><RefreshCw :size="14" class="p-button-icon-left" aria-hidden="true" /></template>
      </Button>
    </div>

    <label class="subs__auto" for="sub-auto">
      <span class="subs__autotext">
        <span class="subs__autoname">{{ t('Автовыбор') }}</span>
        <span class="subs__autodesc">{{ t('Сервер с наименьшей задержкой. Роутер замеряет её при каждом обновлении подписки и переходит, только если другой сервер заметно быстрее.') }}</span>
      </span>
      <ToggleSwitch :model-value="auto" input-id="sub-auto" @update:model-value="(v: boolean) => emit('auto', v)" />
    </label>

    <div v-if="entries.length > 8" class="subs__search">
      <Search :size="15" aria-hidden="true" />
      <input v-model="q" type="search" :placeholder="t('Найти сервер')" :aria-label="t('Найти сервер')" />
    </div>

    <ul class="subs__list" role="radiogroup" :aria-label="t('Сервер из подписки')">
      <li v-for="e in rows" :key="e.name">
        <button type="button" role="radio" :aria-checked="e.on" :class="['srow', { 'srow--on': e.on }]" @click="!e.on && emit('pick', e.name)">
          <span :class="['srow__cc', { 'srow__cc--none': !e.cc }]" aria-hidden="true">{{ e.cc ?? e.kind.slice(0, 2).toUpperCase() }}</span>
          <span class="srow__main">
            <span class="srow__name">{{ e.title }}<span v-if="auto && e.on" class="srow__tag">{{ t('авто') }}</span></span>
            <span class="meta srow__meta">{{ meta(e) }}</span>
          </span>
          <span :class="['srow__ping', `srow__ping--${tone(e.ping)}`]" :title="e.ping == null ? (e.kind === 'hysteria2' ? t('Hysteria2 работает по UDP — задержку по TCP не замерить') : t('Не ответил или ещё не замерялся')) : e.name === fastest ? t('Самый быстрый') : undefined">
            {{ e.ping == null ? '—' : t('{n} мс', { n: e.ping }) }}
          </span>
          <span class="srow__mark" aria-hidden="true"><Check v-if="e.on" :size="16" /></span>
        </button>
      </li>
      <li v-if="!rows.length" class="subs__empty muted">{{ t('Ничего не нашлось') }}</li>
    </ul>
    <p v-if="auto" class="hint">{{ t('Выбор сервера вручную выключает автовыбор.') }}</p>
  </section>
</template>

<style scoped>
.subs { display: grid; gap: 0.75rem; padding: 1rem; border: 1px solid var(--line); border-radius: 12px; background: color-mix(in srgb, var(--surface) 60%, var(--bg)); }
.subs__head { display: flex; align-items: flex-start; justify-content: space-between; gap: 1rem; }
.subs__title { display: grid; gap: 0.25rem; min-width: 0; }
.subs__title h3 { font-size: 0.9375rem; font-weight: 600; }
.subs__auto { display: flex; align-items: center; justify-content: space-between; gap: 1rem; padding: 0.75rem 0.875rem; border-radius: 10px; background: var(--surface); border: 1px solid var(--line); cursor: pointer; }
.subs__autotext { display: grid; gap: 0.2rem; min-width: 0; }
.subs__autoname { font-weight: 500; }
.subs__autodesc { font-size: 0.8125rem; line-height: 1.35; color: var(--muted); }
.subs__search { display: flex; align-items: center; gap: 0.5rem; padding: 0 0.75rem; height: 2.375rem; border: 1px solid var(--line); border-radius: 10px; background: var(--surface); color: var(--muted); }
.subs__search:focus-within { border-color: var(--accent); }
.subs__search input { flex: 1; min-width: 0; border: 0; outline: 0; background: transparent; color: var(--ink); font: inherit; font-size: 0.875rem; }
.subs__list { list-style: none; margin: 0; padding: 0.25rem; display: grid; gap: 0.25rem; max-height: 22rem; overflow-y: auto; overscroll-behavior: contain;
  border-radius: 10px; background: var(--surface); border: 1px solid var(--line); scrollbar-width: thin; }
.subs__empty { padding: 0.75rem; }
.srow { width: 100%; display: grid; grid-template-columns: 2.25rem minmax(0, 1fr) auto 1.25rem; align-items: center; gap: 0.75rem; padding: 0.5rem 0.625rem;
  border: 1px solid transparent; border-radius: 8px; background: transparent; color: var(--ink); font: inherit; text-align: left; cursor: pointer;
  transition: background-color 0.12s var(--ease), border-color 0.12s var(--ease); }
.srow:hover { background: var(--idle-soft); }
.srow:focus-visible { outline: 2px solid var(--focus); outline-offset: -2px; }
.srow--on { background: var(--accent-soft); border-color: color-mix(in srgb, var(--accent) 45%, transparent); cursor: default; }
.srow--on:hover { background: var(--accent-soft); }
.srow__cc { display: grid; place-items: center; width: 2.25rem; height: 1.625rem; border-radius: 6px; background: var(--idle-soft); font-family: var(--mono); font-size: 0.75rem; font-weight: 600; letter-spacing: 0.02em; color: var(--muted); }
.srow--on .srow__cc { background: var(--accent); color: #fff; }
.srow__cc--none { font-weight: 500; }
.srow__main { display: grid; gap: 0.125rem; min-width: 0; }
.srow__name { display: flex; align-items: center; gap: 0.5rem; font-size: 0.9375rem; font-weight: 500; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.srow__tag { flex: none; padding: 0 0.375rem; border-radius: 4px; background: var(--accent); color: #fff; font-size: 0.6875rem; font-weight: 600; line-height: 1.1rem; }
.srow__meta { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.srow__ping { font-size: 0.8125rem; font-variant-numeric: tabular-nums; white-space: nowrap; }
.srow__ping--ok { color: var(--ok-ink, var(--ok)); }
.srow__ping--warn { color: var(--warn-ink, var(--warn)); }
.srow__ping--bad { color: var(--bad-ink, var(--bad)); }
.srow__ping--none { color: var(--faint); }
.srow__mark { display: grid; place-items: center; color: var(--accent); }
</style>
