<script setup lang="ts">
// Дополнительные адреса панели (config.panel_origins): с них можно менять настройки — например, обратный прокси на
// другом устройстве. Адрес по IP роутера и свои DNS-записи на роутер работают и без этого списка. Применяется сразу.
import { computed, ref } from 'vue'
import Button from 'primevue/button'
import InputText from 'primevue/inputtext'
import { X } from 'lucide-vue-next'
import { manage } from '../api'
import { config, loadConfig, notify, revision } from '../store'
import { t } from '../i18n'

const list = computed(() => config.value?.panel_origins ?? [])
const text = ref('')
const busy = ref(false)
const here = typeof location !== 'undefined' ? location.origin : ''
/** Как в контроллере: https://хост[:порт], без пути. Регистр и «/» в конце приводятся к виду браузера. */
const norm = (s: string) => s.trim().replace(/\/+$/, '').toLowerCase()
const valid = (s: string) => /^https:\/\/[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*(:\d{1,5})?$/.test(s)
const draft = computed(() => norm(text.value))
const error = computed(() => (!draft.value || valid(draft.value) ? null : t('Адрес — https://хост или https://хост:порт, без пути')))

async function store(next: string[], done: string) {
  if (!revision.value) return
  busy.value = true
  try {
    const r = await manage.setPanelOrigins(revision.value, next)
    if (r.status !== 200) { notify.show('error', t('Не сохранено'), r.body.error?.message ?? r.body.issues?.[0]?.message); return }
    await loadConfig()
    notify.show('success', done)
    text.value = ''
  } finally {
    busy.value = false
  }
}
const add = () => { if (draft.value && !error.value && !list.value.includes(draft.value)) void store([...list.value, draft.value], t('Адрес добавлен')) }
const remove = (o: string) => void store(list.value.filter((x) => x !== o), t('Адрес убран'))
</script>

<template>
  <div class="setblock" role="group" aria-labelledby="origins-title">
    <span class="setrow__text">
      <span id="origins-title" class="setrow__title">{{ t('Адреса панели') }}</span>
      <span class="setrow__desc">{{ t('Панель всегда открывается по IP роутера и по доменам из «Своих DNS-записей», которые указывают на роутер. Если вы открываете её через обратный прокси на другом устройстве (например, Traefik), добавьте его адрес — иначе изменения с него будут отклонены.') }}</span>
      <span class="setrow__desc">{{ t('Сейчас панель открыта по {o}', { o: here }) }}</span>
    </span>
    <ul v-if="list.length" class="origins">
      <li v-for="o in list" :key="o" class="origins__item">
        <span class="num">{{ o }}</span>
        <button type="button" class="icon-btn" :aria-label="t('Убрать {o}', { o })" :title="t('Убрать')" :disabled="busy" @click="remove(o)"><X :size="14" aria-hidden="true" /></button>
      </li>
    </ul>
    <form class="origins__add" @submit.prevent="add">
      <label for="origin-new" class="sr-only">{{ t('Новый адрес панели') }}</label>
      <InputText id="origin-new" v-model="text" placeholder="https://router.home.example.com" autocomplete="off" spellcheck="false" autocapitalize="off" :invalid="!!error" />
      <Button type="submit" :label="t('Добавить')" severity="secondary" variant="outlined" :disabled="busy || !draft || !!error || list.includes(draft)" />
    </form>
    <span v-if="error" class="field__hint field__hint--bad">{{ error }}</span>
  </div>
</template>

<style scoped>
.origins { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 0.25rem; }
.origins__item { display: flex; align-items: center; gap: 0.5rem; overflow-wrap: anywhere; }
.origins__add { display: flex; flex-wrap: wrap; gap: 0.5rem; }
.origins__add :deep(input) { min-width: 16rem; flex: 1; }
.field__hint--bad { color: var(--bad-ink); }
</style>
