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
  <button v-if="health && (cpu != null || memUsed != null || temp != null)" type="button" class="hchips" :title="t('Состояние роутера: {s}', { s: label })" :aria-label="t('Состояние роутера: {s}', { s: label })" @click="emit('open')">
    <span v-if="cpu != null" :class="['hchip', `hchip--${level(cpu, 70, 90)}`]"><Cpu :size="14" aria-hidden="true" /><span class="hchip__v">{{ cpu }}%</span></span>
    <span v-if="memUsed != null" :class="['hchip', 'hchip--mem', `hchip--${level(memUsed, 80, 92)}`]"><MemoryStick :size="14" aria-hidden="true" /><span class="hchip__v">{{ memUsed }}%</span></span>
    <span v-if="temp != null" :class="['hchip', `hchip--${level(temp, 75, 90)}`]"><Thermometer :size="14" aria-hidden="true" /><span class="hchip__v">{{ temp }}°</span></span>
  </button>
</template>

<style scoped>
.hchips { display: inline-flex; align-items: center; gap: 0.75rem; box-sizing: border-box; height: 2.375rem; padding: 0 0.75rem; border: 1px solid var(--line); border-radius: 10px; background: var(--surface); color: inherit; font: inherit; cursor: pointer; }
.hchips:hover { border-color: var(--line-strong); }
.hchips:focus-visible { outline: 2px solid var(--focus); outline-offset: 2px; }
.hchip { display: inline-flex; align-items: center; gap: 0.3rem; font-size: 0.8125rem; color: var(--muted); }
.hchip__v { font-variant-numeric: tabular-nums; color: var(--ink); font-weight: 500; }
.hchip--warn, .hchip--warn .hchip__v { color: var(--warn-ink, var(--warn)); }
.hchip--bad, .hchip--bad .hchip__v { color: var(--bad-ink, var(--bad)); }
/* телефон: процессор и температура, память — на «Обзоре» */
@media (max-width: 640px) { .hchip--mem:not(:only-child) { display: none; } }
</style>
