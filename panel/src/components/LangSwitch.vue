<script setup lang="ts">
// Язык интерфейса: по умолчанию — язык браузера, выбор запоминается в этом браузере.
import { LANGS, lang, setLang, t, type Lang } from '../i18n'
import Segmented from './Segmented.vue'

defineProps<{ compact?: boolean }>()
const OPTIONS = LANGS.map((l) => ({ value: l.id, label: l.label }))
</script>

<template>
  <div v-if="compact" class="langs" role="group" :aria-label="t('Язык интерфейса')">
    <button v-for="o in OPTIONS" :key="o.value" type="button" :class="['langs__btn', { 'langs__btn--on': lang === o.value }]"
      :aria-pressed="lang === o.value" @click="setLang(o.value)">{{ o.label }}</button>
  </div>
  <Segmented v-else :model-value="lang" class="self-start" :options="OPTIONS" :label="t('Язык интерфейса')" name="lang"
    @update:model-value="(v: Lang) => setLang(v)" />
</template>

<style scoped>
.langs { display: flex; gap: 0.25rem; justify-content: center; flex-wrap: wrap; }
.langs__btn { background: none; border: 0; padding: 0.25rem 0.5rem; border-radius: 0.375rem; color: var(--muted, inherit); font: inherit; font-size: 0.8125rem; cursor: pointer; }
.langs__btn--on { color: var(--text, inherit); background: var(--surface-2, rgba(127, 127, 127, 0.15)); }
.langs__btn:focus-visible { outline: 2px solid var(--accent); outline-offset: 1px; }
</style>
