<script setup lang="ts">
// Свои DNS-записи отдельной страницей: домен со всеми поддоменами — на адрес в домашней сети. Сохраняется само.
import { computed, ref, watch } from 'vue'
import type { HostRecord } from '../api'
import { dnsToForm, formToDns } from '../manage'
import { config, save } from '../store'
import { useAutosave } from '../autosave'
import HostList from '../components/HostList.vue'

const toDraft = (): HostRecord[] => dnsToForm(config.value?.dns).hosts
const draft = ref<HostRecord[]>(toDraft())
const pristine = ref(JSON.stringify(draft.value))
const dirty = computed(() => JSON.stringify(draft.value) !== pristine.value)
watch(config, () => {
  if (!dirty.value) { draft.value = toDraft(); pristine.value = JSON.stringify(draft.value) }
})

useAutosave({
  source: draft,
  dirty: () => dirty.value,
  blocker: () => null,
  run: async () => {
    if (!config.value) return 'Настройки ещё не загружены.'
    const sent = JSON.stringify(draft.value)
    const next = { ...config.value }
    // остальные настройки DNS (сервер для VPN, реклама) — как сохранены
    const dns = formToDns({ ...dnsToForm(config.value.dns), hosts: draft.value })
    if (dns) next.dns = dns
    else delete next.dns
    const r = await save(next, '')
    if (r.ok) {
      pristine.value = sent
      if (!dirty.value) { draft.value = toDraft(); pristine.value = JSON.stringify(draft.value) }
    }
    return r
  },
})
</script>

<template>
  <section class="sect" aria-label="Свои DNS-записи">
    <HostList v-model="draft" />
  </section>
</template>
