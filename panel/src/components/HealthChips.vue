<script setup lang="ts">
// Шапка: компактное состояние роутера — процессор, память, самый горячий датчик. Нажатие — «Обзор» с полной карточкой.
import { computed, onBeforeUnmount } from 'vue'
import { Cpu, MemoryStick, Thermometer } from 'lucide-vue-next'
import { health, hottest, level, memUsed, useHealth } from '../health'
import { t } from '../i18n'

const emit = defineEmits<{ open: [] }>()
const stop = useHealth()
onBeforeUnmount(stop)

const cpu = computed(() => (health.value?.cpu == null ? null : Math.round(health.value.cpu)))
const temp = computed(() => (hottest.value ? Math.round(hottest.value.c) : null))
const label = computed(() => [
  cpu.value != null ? t('процессор {n}%', { n: cpu.value }) : '',
  memUsed.value != null ? t('память {n}%', { n: memUsed.value }) : '',
  temp.value != null ? t('температура {n} °C', { n: temp.value }) : '',
].filter(Boolean).join(', '))
</script>

<template>
  <button v-if="health && (cpu != null || memUsed != null || temp != null)" type="button" class="chips" :title="t('Состояние роутера: {s}', { s: label })" :aria-label="t('Состояние роутера: {s}', { s: label })" @click="emit('open')">
    <span v-if="cpu != null" :class="['chip', `chip--${level(cpu, 70, 90)}`]"><Cpu :size="14" aria-hidden="true" /><span class="chip__v">{{ cpu }}%</span></span>
    <span v-if="memUsed != null" :class="['chip', 'chip--mem', `chip--${level(memUsed, 80, 92)}`]"><MemoryStick :size="14" aria-hidden="true" /><span class="chip__v">{{ memUsed }}%</span></span>
    <span v-if="temp != null" :class="['chip', `chip--${level(temp, 75, 90)}`]"><Thermometer :size="14" aria-hidden="true" /><span class="chip__v">{{ temp }}°</span></span>
  </button>
</template>

<style scoped>
.chips { display: inline-flex; align-items: center; gap: 0.25rem; padding: 0.25rem; border: 1px solid var(--line); border-radius: 999px; background: transparent; color: inherit; font: inherit; cursor: pointer; }
.chips:hover { border-color: var(--line-strong); }
.chips:focus-visible { outline: 2px solid var(--focus); outline-offset: 2px; }
.chip { display: inline-flex; align-items: center; gap: 0.25rem; padding: 0.125rem 0.5rem; border-radius: 999px; font-size: 0.8125rem; color: var(--muted); }
.chip__v { font-variant-numeric: tabular-nums; color: var(--ink); font-weight: 500; }
.chip--warn, .chip--warn .chip__v { color: var(--warn-ink, var(--warn)); }
.chip--bad, .chip--bad .chip__v { color: var(--bad-ink, var(--bad)); }
/* телефон: процессор и температура, память — на «Обзоре» */
@media (max-width: 640px) { .chip--mem:not(:only-child) { display: none; } }
</style>
