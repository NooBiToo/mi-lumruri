<script setup lang="ts">
// Список сайтов отдельной карточкой: поле «Добавить» сверху, ниже — по сайту в строке с «×».
// Enter или «Добавить» добавляет всё, что похоже на адрес; вставка нескольких строк или через запятую добавляется сразу.
// Неудачное остаётся в поле и называется в подсказке; повторы не добавляются. «Очистить» — с подтверждением.
import { nextTick, ref } from 'vue'
import Button from 'primevue/button'
import InputText from 'primevue/inputtext'
import { useConfirm } from 'primevue/useconfirm'
import { Plus, X } from 'lucide-vue-next'
import { parseDomainInput } from '../ui'
import { plural } from '../status'
import { t } from '../i18n'

const props = defineProps<{ id: string; title: string; sub: string; placeholder: string; empty: string }>()
const model = defineModel<string[]>({ required: true })
const text = ref('')
const note = ref<{ bad: boolean; text: string } | null>(null)
const list = ref<HTMLElement | null>(null)
const confirm = useConfirm()

function add() {
  if (!text.value.trim()) { note.value = null; return }
  const r = parseDomainInput(text.value, model.value)
  if (r.add.length) model.value = [...model.value, ...r.add]
  // неудачное остаётся в поле, чтобы его можно было поправить
  text.value = r.bad.join(' ')
  const parts: string[] = []
  if (r.bad.length) parts.push(t('Не похоже на адрес сайта: {list}. Пример: example.com', { list: r.bad.join(', ') }))
  if (r.dup.length) parts.push(t('Уже в списке: {list}', { list: r.dup.join(', ') }))
  if (r.add.length > 1 || (r.add.length && parts.length)) parts.unshift(t('Добавлено: {n}', { n: plural(r.add.length, 'сайт', 'сайта', 'сайтов') }))
  note.value = parts.length ? { bad: r.bad.length > 0, text: parts.join('. ') } : null
  if (r.add.length) void nextTick(() => list.value?.scrollTo({ top: list.value.scrollHeight }))
}
function onPaste(e: ClipboardEvent) {
  const t = e.clipboardData?.getData('text') ?? ''
  // одна строка без разделителей — обычная вставка; список — добавляем сразу (поле в одну строку склеило бы строки)
  if (!/[\s,;]/.test(t.trim())) return
  e.preventDefault()
  text.value = `${text.value} ${t}`
  add()
}
function remove(d: string) {
  model.value = model.value.filter((x) => x !== d)
  note.value = null
}
function clear() {
  confirm.require({
    header: t('Очистить список?'),
    message: t('Из списка «{title}» будут убраны все сайты ({n}).', { title: props.title, n: model.value.length }),
    acceptLabel: t('Очистить'), rejectLabel: t('Отмена'),
    acceptProps: { severity: 'danger' }, rejectProps: { severity: 'secondary', variant: 'text' },
    accept: () => { model.value = []; note.value = null },
  })
}
</script>

<template>
  <div class="card dlist">
    <div class="dlist__head">
      <div class="dlist__titles">
        <h2 :id="`${id}-title`" class="card__title">{{ title }}<span class="count" :aria-label="plural(model.length, 'сайт', 'сайта', 'сайтов')">{{ model.length }}</span></h2>
        <p class="card__sub">{{ sub }}</p>
      </div>
      <button v-if="model.length" type="button" class="link-btn dlist__clear" @click="clear">{{ t('Очистить') }}</button>
    </div>

    <form class="dlist__add" @submit.prevent="add">
      <label :for="id" class="sr-only">{{ t('Добавить сайт в список «{title}»', { title }) }}</label>
      <InputText :id="id" v-model="text" :placeholder="placeholder" spellcheck="false" autocomplete="off" autocapitalize="off"
        enterkeyhint="done" :invalid="!!note?.bad" :aria-describedby="`${id}-note`" @paste="onPaste" />
      <Button type="submit" :label="t('Добавить')" severity="secondary" variant="outlined" :disabled="!text.trim()">
        <template #icon><Plus :size="16" class="p-button-icon-left" aria-hidden="true" /></template>
      </Button>
    </form>
    <span :id="`${id}-note`" :class="note?.bad ? 'field__error' : 'field__hint'" aria-live="polite">
      {{ note ? note.text : t('Можно вставить сразу несколько адресов: по одному в строке или через запятую') }}
    </span>

    <ul v-if="model.length" ref="list" class="dlist__items" :aria-labelledby="`${id}-title`">
      <li v-for="d in model" :key="d" class="dlist__item">
        <span class="dlist__text">{{ d }}</span>
        <button type="button" class="icon-btn" :aria-label="t('Убрать {d}', { d })" @click="remove(d)"><X :size="16" aria-hidden="true" /></button>
      </li>
    </ul>
    <p v-else class="dlist__empty">{{ empty }}</p>
  </div>
</template>
