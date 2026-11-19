<script setup lang="ts" generic="T extends string">
// Переключатель «один из нескольких»: радиокнопки, оформленные сегментами. Стрелки и Tab работают как у радиогруппы.
defineProps<{ options: { value: T; label: string }[]; label: string; name: string; full?: boolean }>()
const model = defineModel<T>({ required: true })
</script>

<template>
  <div :class="['seg', { 'seg--full': full }]" role="radiogroup" :aria-label="label">
    <label v-for="o in options" :key="o.value" :class="['seg__opt', { 'seg__opt--on': model === o.value }]">
      <input v-model="model" type="radio" :name="name" :value="o.value" class="seg__radio" />
      <span>{{ o.label }}</span>
    </label>
  </div>
</template>
