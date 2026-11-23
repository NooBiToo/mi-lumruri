<script setup lang="ts">
// Свои DNS-записи отдельной карточкой: домен и адрес сверху, ниже — по записи в строке с «×».
// Запись покрывает домен вместе со всеми поддоменами (dnsmasq `address=/домен/адрес`).
import { ref } from 'vue'
import Button from 'primevue/button'
import InputText from 'primevue/inputtext'
import { Plus, X } from 'lucide-vue-next'
import type { HostRecord } from '../api'
import { parseHostRecord } from '../ui'
import { plural } from '../status'
import { t } from '../i18n'

const model = defineModel<HostRecord[]>({ required: true })
const domain = ref('')
const address = ref('')
const error = ref<string | null>(null)

function add() {
  const r = parseHostRecord(domain.value, address.value, model.value)
  if (typeof r === 'string') { error.value = r; return }
  model.value = [...model.value, r]
  domain.value = ''
  address.value = ''
  error.value = null
}
function remove(d: string) {
  model.value = model.value.filter((h) => h.domain !== d)
  error.value = null
}
</script>

<template>
  <div class="card dlist">
    <div class="dlist__head">
      <div class="dlist__titles">
        <h2 id="hosts-title" class="card__title">{{ t('Свои DNS-записи') }}<span class="count" :aria-label="plural(model.length, 'запись', 'записи', 'записей')">{{ model.length }}</span></h2>
        <p class="card__sub">{{ t('Домен и все его поддомены открываются по указанному адресу — например, домашний сервер с Traefik.') }}
          {{ t('Запись для') }} <span class="num">home.example.com</span> {{ t('подходит и для') }} <span class="num">pve.home.example.com</span>. {{ t('Изменения сохраняются сами.') }}</p>
      </div>
    </div>

    <form class="hosts__add" @submit.prevent="add">
      <span class="field">
        <label for="host-domain" class="field__label">{{ t('Домен') }}</label>
        <InputText id="host-domain" v-model="domain" placeholder="home.example.com" spellcheck="false" autocomplete="off" autocapitalize="off"
          :invalid="!!error" aria-describedby="hosts-note" />
      </span>
      <span class="field">
        <label for="host-address" class="field__label">{{ t('IP-адрес') }}</label>
        <InputText id="host-address" v-model="address" class="num" placeholder="192.168.31.10" inputmode="decimal" spellcheck="false" autocomplete="off"
          :invalid="!!error" aria-describedby="hosts-note" />
      </span>
      <Button type="submit" :label="t('Добавить')" severity="secondary" variant="outlined" :disabled="!domain.trim() || !address.trim()">
        <template #icon><Plus :size="16" class="p-button-icon-left" aria-hidden="true" /></template>
      </Button>
    </form>
    <span id="hosts-note" :class="error ? 'field__error' : 'field__hint'" aria-live="polite">
      {{ error ?? t('Работает для всех устройств, которые получают DNS от роутера') }}
    </span>

    <ul v-if="model.length" class="dlist__items" aria-labelledby="hosts-title">
      <li v-for="h in model" :key="h.domain" class="dlist__item">
        <span class="dlist__text">{{ h.domain }} <span class="hosts__arrow" aria-hidden="true">→</span><span class="sr-only">{{ t('отвечает адресом') }}</span> <span class="num">{{ h.address }}</span></span>
        <button type="button" class="icon-btn" :aria-label="t('Убрать запись {d}', { d: h.domain })" @click="remove(h.domain)"><X :size="16" aria-hidden="true" /></button>
      </li>
    </ul>
    <p v-else class="dlist__empty">{{ t('Пока пусто. Добавьте домен своего сервера и его адрес в домашней сети.') }}</p>
  </div>
</template>
