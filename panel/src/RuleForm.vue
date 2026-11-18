<script setup lang="ts">
import { computed, watch } from 'vue'
import type { Config } from './api'
import { profileReady, type DraftForm, type Field } from './draft'

const form = defineModel<DraftForm>({ required: true })
const props = defineProps<{ config: Config; errors: Partial<Record<Field, string[]>>; busy: boolean }>()
const emit = defineEmits<{ submit: [] }>()

const kindLabel: Record<string, string> = { trusttunnel: 'TrustTunnel', vless: 'VLESS', hysteria2: 'Hysteria2', wireguard: 'WireGuard/AmneziaWG' }

watch(
  () => form.value.sourceType,
  (t) => {
    if (t === 'device') form.value.sourceId = props.config.devices[0]?.id ?? ''
    else if (t === 'network') form.value.sourceId = props.config.networks[0]?.id ?? ''
    else form.value.sourceId = ''
  },
)

const action = computed({
  get: () => (form.value.actionType === 'profile' ? `profile:${form.value.actionProfile}` : form.value.actionType),
  set: (v: string) => {
    if (v.startsWith('profile:')) {
      form.value.actionType = 'profile'
      form.value.actionProfile = v.slice('profile:'.length)
    } else {
      form.value.actionType = v as DraftForm['actionType']
    }
  },
})

const placeholders: Record<string, string> = { domain: 'www.example.com', domain_suffix: 'example.com', cidr: '203.0.113.0/24' }

function probeSubject(i: number) {
  const p = form.value.probes[i]
  return p ? `${p.subjectType}:${p.subjectId}` : ''
}
function setProbeSubject(i: number, v: string) {
  const p = form.value.probes[i]
  if (!p) return
  const [t, id] = v.split(':')
  p.subjectType = t === 'network' ? 'network' : 'device'
  p.subjectId = id ?? ''
}
function addProbe() {
  const d = props.config.devices[0]
  form.value.probes.push(d ? { subjectType: 'device', subjectId: d.id, host: '' } : { subjectType: 'network', subjectId: props.config.networks[0]?.id ?? '', host: '' })
}
</script>

<template>
  <form class="rule-form" novalidate @submit.prevent="emit('submit')">
    <label class="rule-form__field">
      <span class="rule-form__label">Идентификатор правила</span>
      <input v-model="form.id" name="id" autocomplete="off" spellcheck="false" :aria-invalid="!!errors.id" />
      <small v-for="m in errors.id" :key="m" class="rule-form__error">{{ m }}</small>
    </label>

    <fieldset class="rule-form__field">
      <legend class="rule-form__label">Источник</legend>
      <div class="rule-form__seg" role="radiogroup">
        <label><input v-model="form.sourceType" type="radio" value="device" name="source-type" /> Устройство</label>
        <label><input v-model="form.sourceType" type="radio" value="network" name="source-type" /> Сеть Wi‑Fi</label>
        <label><input v-model="form.sourceType" type="radio" value="lan" name="source-type" /> Вся LAN</label>
      </div>
      <select v-if="form.sourceType === 'device'" v-model="form.sourceId" name="source-id" :aria-invalid="!!errors.source">
        <option v-for="d in config.devices" :key="d.id" :value="d.id">{{ d.name }} — {{ d.mac }}</option>
      </select>
      <select v-else-if="form.sourceType === 'network'" v-model="form.sourceId" name="source-id" :aria-invalid="!!errors.source">
        <option v-for="n in config.networks" :key="n.id" :value="n.id">{{ n.name }} (SSID {{ n.ssid }})</option>
      </select>
      <small v-for="m in errors.source" :key="m" class="rule-form__error">{{ m }}</small>
    </fieldset>

    <fieldset class="rule-form__field">
      <legend class="rule-form__label">Назначение</legend>
      <select v-model="form.destType" name="dest-type">
        <option value="group">Группа</option>
        <option value="domain">Точный домен</option>
        <option value="domain_suffix">Домен с поддоменами</option>
        <option value="cidr">IPv4/IPv6-подсеть</option>
        <option v-if="config.categories?.length" value="category">Категория (геокатегория, список)</option>
      </select>
      <select v-if="form.destType === 'group'" v-model="form.destGroup" name="dest-group" :aria-invalid="!!errors.destination">
        <option v-for="g in config.groups" :key="g.id" :value="g.id">{{ g.name }} ({{ g.destinations.length }})</option>
      </select>
      <select v-else-if="form.destType === 'category'" v-model="form.destGroup" name="dest-category" :aria-invalid="!!errors.destination">
        <option v-for="c in config.categories ?? []" :key="c.id" :value="c.id">{{ c.name }} ({{ c.kind === 'domain' ? 'домены' : 'IP' }})</option>
      </select>
      <input
        v-else
        v-model="form.destValue"
        name="dest-value"
        autocomplete="off"
        spellcheck="false"
        :placeholder="placeholders[form.destType]"
        :aria-invalid="!!errors.destination"
      />
      <small v-for="m in errors.destination" :key="m" class="rule-form__error">{{ m }}</small>
    </fieldset>

    <label class="rule-form__field">
      <span class="rule-form__label">Действие</span>
      <select v-model="action" name="action" :aria-invalid="!!errors.action">
        <optgroup label="VPN-профили">
          <option v-for="p in config.profiles" :key="p.id" :value="`profile:${p.id}`">{{ p.name }} · {{ kindLabel[p.kind] }}{{ profileReady(p) ? '' : ' · не настроен' }}</option>
        </optgroup>
        <option value="direct">Прямой выход</option>
        <option value="direct_zapret">Прямой выход с Zapret</option>
        <option value="block">Блокировка</option>
      </select>
      <small v-for="m in errors.action" :key="m" class="rule-form__error">{{ m }}</small>
    </label>

    <label class="rule-form__check"><input v-model="form.enabled" type="checkbox" name="enabled" /> Правило включено</label>

    <fieldset class="rule-form__field">
      <legend class="rule-form__label">Пробные запросы</legend>
      <div v-for="(p, i) in form.probes" :key="i" class="rule-form__probe">
        <select :value="probeSubject(i)" :name="`probe-${i}-subject`" @change="setProbeSubject(i, ($event.target as HTMLSelectElement).value)">
          <optgroup label="Устройства">
            <option v-for="d in config.devices" :key="d.id" :value="`device:${d.id}`">{{ d.name }}</option>
          </optgroup>
          <optgroup label="Новый клиент сети">
            <option v-for="n in config.networks" :key="n.id" :value="`network:${n.id}`">{{ n.name }}</option>
          </optgroup>
        </select>
        <input v-model="p.host" :name="`probe-${i}-host`" placeholder="домен или IP" spellcheck="false" :aria-invalid="!!errors[`probe-${i}`]" />
        <button type="button" class="rule-form__icon" :aria-label="`Удалить пробу ${i + 1}`" @click="form.probes.splice(i, 1)">×</button>
        <small v-for="m in errors[`probe-${i}`]" :key="m" class="rule-form__error rule-form__error--wide">{{ m }}</small>
      </div>
      <button type="button" class="rule-form__link" @click="addProbe">+ добавить пробу</button>
    </fieldset>

    <button type="submit" class="rule-form__submit" :disabled="busy">{{ busy ? 'Проверяю…' : 'Проверить и показать' }}</button>
  </form>
</template>
