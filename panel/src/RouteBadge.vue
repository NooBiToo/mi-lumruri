<script setup lang="ts">
import type { RouteKind } from './route'

// Плашка действия маршрута: цвет по виду действия, текст всегда есть — цвет не единственный носитель смысла.
defineProps<{ kind: RouteKind | null; label: string }>()
</script>

<template>
  <span :class="['badge', kind ? `badge--${kind}` : 'badge--none']">{{ label }}</span>
</template>
