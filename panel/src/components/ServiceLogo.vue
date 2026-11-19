<script setup lang="ts">
import { computed } from 'vue'
import { brandColor, serviceIcon, type ServiceIcon } from '../brand'

// id сервиса каталога или готовый значок (например, DNS-сервера)
const props = defineProps<{ id?: string; icon?: ServiceIcon; size?: 'sm' | 'md' }>()
const icon = computed(() => props.icon ?? serviceIcon(props.id ?? ''))
const color = computed(() => (icon.value.kind === 'brand' ? brandColor(icon.value.hex) : null))
</script>

<template>
  <span :class="['logo', `logo--${size ?? 'md'}`, { 'logo--brand': color }]" :style="color ? { '--brand': color } : undefined" aria-hidden="true">
    <svg v-if="icon.kind === 'brand'" viewBox="0 0 24 24" class="logo__svg"><path :d="icon.path" /></svg>
    <component :is="icon.icon" v-else class="logo__svg" :stroke-width="1.5" />
  </span>
</template>
