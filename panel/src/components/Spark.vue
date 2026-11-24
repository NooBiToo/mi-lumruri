<script setup lang="ts">
// Маленький график-линия для плиток «Обзора»: значения слева направо, масштаб — по максимуму.
import { computed } from 'vue'

const props = defineProps<{ values: number[]; tone?: 'vpn' | 'muted' }>()
const path = computed(() => {
  const v = props.values
  if (v.length < 2) return 'M0,27 L100,27'
  const top = Math.max(1, ...v)
  return v.map((x, i) => `${i ? 'L' : 'M'}${((i / (v.length - 1)) * 100).toFixed(2)},${(27 - (x / top) * 25).toFixed(2)}`).join(' ')
})
</script>

<template>
  <svg class="spark" viewBox="0 0 100 28" preserveAspectRatio="none" aria-hidden="true">
    <path :d="path" :class="['spark__line', `spark__line--${tone ?? 'muted'}`, { 'spark__line--flat': values.length < 2 }]" vector-effect="non-scaling-stroke" />
  </svg>
</template>

<style scoped>
.spark { display: block; width: 100%; height: 1.75rem; overflow: visible; }
.spark__line { fill: none; stroke-width: 1.5; stroke-linejoin: round; stroke-linecap: round; }
.spark__line--muted { stroke: var(--muted); }
.spark__line--vpn { stroke: var(--accent); }
.spark__line--flat { stroke: var(--line-strong); stroke-dasharray: 3 4; }
</style>
