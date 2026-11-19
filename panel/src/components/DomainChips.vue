<script setup lang="ts">
// Поле-метки для доменов: ввести адрес и нажать Enter (или запятую, пробел), удалить — «×» или Backspace в пустом поле.
// Вставка списка разбирается как прежнее текстовое поле: по домену в строке, через пробел или запятую.
import { ref } from 'vue'
import { X } from 'lucide-vue-next'
import { parseDomainInput } from '../ui'

const props = defineProps<{ id: string; label: string; hint: string; placeholder: string }>()
const model = defineModel<string[]>({ required: true })
const text = ref('')
const bad = ref<string[]>([])

function commit(): boolean {
  if (!text.value.trim()) { bad.value = []; return false }
  const r = parseDomainInput(text.value, model.value)
  if (r.add.length) model.value = [...model.value, ...r.add]
  bad.value = r.bad
  // неудачное остаётся в поле, чтобы его можно было поправить
  text.value = r.bad.join(' ')
  return true
}
function onKey(e: KeyboardEvent) {
  if (e.key === 'Enter' || e.key === ',' || (e.key === ' ' && text.value.trim())) {
    if (e.key !== 'Enter' || text.value.trim()) e.preventDefault()
    commit()
  } else if (e.key === 'Backspace' && !text.value && model.value.length) {
    model.value = model.value.slice(0, -1)
  }
}
function onPaste(e: ClipboardEvent) {
  const t = e.clipboardData?.getData('text') ?? ''
  if (!/[\s,;]/.test(t.trim())) return
  e.preventDefault()
  text.value = `${text.value} ${t}`
  commit()
}
function remove(d: string) {
  model.value = model.value.filter((x) => x !== d)
  document.getElementById(props.id)?.focus()
}
</script>

<template>
  <div class="chips-field">
    <label :for="id" class="field__label">{{ label }}</label>
    <div :class="['chips', { 'chips--bad': bad.length }]" @click.self="($event.currentTarget as HTMLElement).querySelector('input')?.focus()">
      <span v-for="d in model" :key="d" class="chip">
        <span class="chip__text">{{ d }}</span>
        <button type="button" class="chip__x" :aria-label="`Убрать ${d}`" @click="remove(d)"><X :size="14" aria-hidden="true" /></button>
      </span>
      <input :id="id" v-model="text" class="chips__input" :placeholder="model.length ? 'Ещё сайт' : placeholder" spellcheck="false"
        autocomplete="off" autocapitalize="off" enterkeyhint="done" :aria-invalid="bad.length > 0" :aria-describedby="`${id}-hint`"
        @keydown="onKey" @paste="onPaste" @blur="commit" />
    </div>
    <span :id="`${id}-hint`" :class="bad.length ? 'field__error' : 'field__hint'" aria-live="polite">
      {{ bad.length ? `Не похоже на адрес сайта: ${bad.join(', ')}. Пример: example.com` : hint }}
    </span>
  </div>
</template>
