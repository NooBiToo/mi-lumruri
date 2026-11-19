<script setup lang="ts">
import RouteBadge from './RouteBadge.vue'
import type { RouteKind } from './route'

// Маршрут «Источник → Назначение → Действие». Стрелки видны глазу, экранному диктору — отдельная фраза.
defineProps<{ source: string; destination: string; kind: RouteKind | null; action: string }>()
</script>

<template>
  <span class="route">
    <span class="sr-only">{{ source }}, затем {{ destination }}, действие: {{ action }}</span>
    <span class="route__part" aria-hidden="true">{{ source }}</span>
    <span class="route__arrow" aria-hidden="true">→</span>
    <span class="route__part route__part--dest" aria-hidden="true">{{ destination }}</span>
    <span class="route__arrow" aria-hidden="true">→</span>
    <RouteBadge :kind="kind" :label="action" aria-hidden="true" />
  </span>
</template>
