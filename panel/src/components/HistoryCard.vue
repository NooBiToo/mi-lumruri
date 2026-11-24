<script setup lang="ts">
// «Модули» → журнал трафика: итоги по дням за 1–24 месяца на флешке или во внутренней памяти — для динамики в
// «Трафике» на «Обзоре». Запись — config.history (служба пишет файл при каждом показании статистики).
import { computed, ref, watch } from 'vue'
import Button from 'primevue/button'
import ToggleSwitch from 'primevue/toggleswitch'
import type { StorageDrive, StorageInfo } from '../api'
import { config, save } from '../store'
import { t } from '../i18n'

const props = defineProps<{ storage: StorageInfo | null }>()

const MONTHS = [1, 2, 3, 6, 12, 24]
const cur = computed(() => config.value?.history ?? null)
const on = ref(!!cur.value)
const months = ref(cur.value?.months ?? 12)
const target = ref(cur.value?.target ?? '')
watch(cur, (c) => { on.value = !!c; months.value = c?.months ?? 12; target.value = c?.target ?? target.value })

const drives = computed<StorageDrive[]>(() => [...(props.storage?.usb ?? []), ...(props.storage?.data ? [props.storage.data] : [])])
const nameOf = (d: StorageDrive) => (d === props.storage?.data ? t('Внутренняя память') : [d.vendor, d.model].filter(Boolean).join(' ') || t('USB-накопитель'))
/** Около 1,5 КБ на день (итоги и до двух десятков устройств). */
const need = computed(() => months.value * 31 * 1536)
const okDrive = (d: StorageDrive) => d.writable && d.free > need.value + 1024 * 1024
// по умолчанию — флешка
watch(drives, (ds) => { if (!target.value) target.value = ds.find((d) => okDrive(d))?.path ?? '' }, { immediate: true })
const sizeText = computed(() => (need.value < 1024 * 1024 ? t('≈ {n} КБ', { n: Math.round(need.value / 1024) }) : t('≈ {n} МБ', { n: (need.value / 1024 / 1024).toFixed(1) })))
const dirty = computed(() => (on.value ? !cur.value || cur.value.months !== months.value || cur.value.target !== target.value : !!cur.value))
const missing = computed(() => !!cur.value && !drives.value.some((d) => d.path === cur.value!.target))
const busy = ref(false)
async function apply() {
  if (!config.value) return
  busy.value = true
  try {
    const next = { ...config.value }
    if (on.value && target.value) next.history = { months: months.value, target: target.value }
    else delete next.history
    await save(next, on.value ? t('Журнал трафика включён') : t('Журнал трафика выключен'))
  } finally { busy.value = false }
}
</script>

<template>
  <div class="card" role="group" aria-labelledby="hist-title">
    <label class="setrow">
      <span class="setrow__text">
        <span id="hist-title" class="setrow__title">{{ t('Журнал трафика') }}</span>
        <span class="setrow__desc">{{ t('Хранит итоги трафика по дням — всего, через VPN и по устройствам — чтобы видеть динамику за месяцы на «Обзоре». Без журнала видны только сутки и неделя.') }}</span>
      </span>
      <ToggleSwitch v-model="on" input-id="hist-on" />
    </label>
    <template v-if="on">
      <div class="field">
        <label for="hist-months" class="field__label">{{ t('Хранить') }}</label>
        <select id="hist-months" v-model.number="months" class="tile__server self-start">
          <option v-for="m in MONTHS" :key="m" :value="m">{{ t('{n} мес.', { n: m }) }}</option>
        </select>
        <span class="field__hint">{{ t('Займёт {s}', { s: sizeText }) }}</span>
      </div>
      <fieldset class="mod__targets">
        <legend class="field__label">{{ t('Где хранить') }}</legend>
        <label v-for="d in drives" :key="d.path" :class="['mod__target', { 'mod__target--off': !okDrive(d) }]">
          <input v-model="target" type="radio" name="hist-target" :value="d.path" :disabled="!okDrive(d)" />
          <span class="mod__target-name">{{ nameOf(d) }}</span>
          <span class="meta num">{{ d.path }}</span>
        </label>
      </fieldset>
      <p v-if="missing" class="hint">{{ t('Накопитель журнала сейчас не подключён: пока его нет, дни в журнал не записываются.') }}</p>
    </template>
    <Button :label="t('Сохранить')" class="self-start" :disabled="!dirty || busy || (on && !target)" :loading="busy" @click="apply" />
  </div>
</template>

<style scoped>
.mod__targets { display: grid; gap: 0.5rem; margin: 0; padding: 0; border: 0; min-width: 0; }
.mod__target { display: flex; flex-wrap: wrap; align-items: center; gap: 0.25rem 0.625rem; padding: 0.625rem 0.75rem; border: 1px solid var(--line); border-radius: 10px; cursor: pointer; }
.mod__target:has(input:checked) { border-color: var(--accent); }
.mod__target:has(input:focus-visible) { outline: 2px solid var(--focus); outline-offset: 1px; }
.mod__target--off { opacity: 0.6; cursor: not-allowed; }
.mod__target-name { font-weight: 500; flex: 1; min-width: 8rem; overflow-wrap: anywhere; }
</style>
