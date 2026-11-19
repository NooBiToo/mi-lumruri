<script setup lang="ts">
import { computed, watch } from 'vue'
import Button from 'primevue/button'
import Checkbox from 'primevue/checkbox'
import InputText from 'primevue/inputtext'
import Select from 'primevue/select'
import SelectButton from 'primevue/selectbutton'
import type { Config } from './api'
import { profileReady, toRequest, type DraftForm, type Field } from './draft'
import { destShort, routeKind, routeLabel, sourceShort, type RouteKind } from './route'
import RouteLine from './RouteLine.vue'

const form = defineModel<DraftForm>({ required: true })
const props = defineProps<{ config: Config; errors: Partial<Record<Field, string[]>>; busy: boolean }>()
const emit = defineEmits<{ submit: []; navigate: [tab: 'profiles' | 'devices'] }>()

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

const sourceTypes = [{ value: 'device', label: 'Устройство' }, { value: 'network', label: 'Сеть Wi‑Fi' }, { value: 'lan', label: 'Вся LAN' }]
const deviceOptions = computed(() => props.config.devices.map((d) => ({ value: d.id, label: d.name, mac: d.mac })))
const networkOptions = computed(() => props.config.networks.map((n) => ({ value: n.id, label: `${n.name} (SSID ${n.ssid})` })))

const destTypes = computed(() => [
  { value: 'group', label: 'Группа' },
  { value: 'domain', label: 'Домен (вместе с поддоменами)' },
  { value: 'domain_suffix', label: 'Суффикс домена (вместе с поддоменами)' },
  { value: 'cidr', label: 'IPv4/IPv6-подсеть' },
  ...(props.config.categories?.length ? [{ value: 'category', label: 'Категория (геокатегория, список)' }] : []),
])
const groupOptions = computed(() => props.config.groups.map((g) => ({ value: g.id, label: `${g.name} (${g.destinations.length})` })))
const categoryOptions = computed(() => (props.config.categories ?? []).map((c) => ({ value: c.id, label: `${c.name} (${c.kind === 'domain' ? 'домены' : 'IP'})` })))

/** Варианты действия: профили TrustTunnel, затем напрямую, с Zapret и блокировка. */
const actions = computed<{ value: string; kind: RouteKind; label: string; note: string }[]>(() => [
  ...props.config.profiles.map((p) => ({
    value: `profile:${p.id}`, kind: 'tunnel' as const, label: `Через туннель: ${p.name}`,
    note: profileReady(p) ? 'TrustTunnel' : 'TrustTunnel, сервер не настроен — правило сохранится, но не заработает',
  })),
  { value: 'direct', kind: 'direct', label: 'Напрямую', note: 'Мимо туннеля, как без правила' },
  { value: 'direct_zapret', kind: 'zapret', label: 'Напрямую с Zapret', note: 'Мимо туннеля, с обходом блокировок' },
  { value: 'block', kind: 'block', label: 'Блокировать', note: 'Соединения не устанавливаются' },
])

// доменные назначения (и группы/категории с доменами) сопоставляются через DNS роутера
const isDomainDest = computed(() => form.value.destType !== 'cidr')

const placeholders: Record<string, string> = { domain: 'www.example.com', domain_suffix: 'example.com', cidr: '203.0.113.0/24' }

/** Живой маршрут по форме: то же, что уйдёт контроллеру на проверку. */
const live = computed(() => {
  const r = toRequest(form.value).rule
  const dest = r.destination
  const empty = (dest.type === 'group' || dest.type === 'category') ? !dest.id : !dest.value
  return {
    source: sourceShort(r.source, props.config) || 'источник',
    destination: empty ? 'назначение' : destShort(dest, props.config),
    kind: routeKind(r.action),
    action: routeLabel(r.action, props.config),
  }
})

const probeOptions = computed(() => [
  { label: 'Устройства', items: props.config.devices.map((d) => ({ value: `device:${d.id}`, label: d.name })) },
  { label: 'Новый клиент сети', items: props.config.networks.map((n) => ({ value: `network:${n.id}`, label: n.name })) },
].filter((g) => g.items.length))

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
    <div :class="['rule-form__live', `bar--${live.kind}`]">
      <span class="rule-form__live-label">Маршрут</span>
      <RouteLine :source="live.source" :destination="live.destination" :kind="live.kind" :action="live.action" />
    </div>

    <div class="field">
      <label for="rule-id" class="field__label">Идентификатор правила</label>
      <InputText id="rule-id" v-model="form.id" name="id" autocomplete="off" spellcheck="false" fluid :invalid="!!errors.id"
        aria-describedby="rule-id-hint" />
      <small id="rule-id-hint" class="field__hint">Латиница, цифры, «-» и «_». Правило с тем же идентификатором будет заменено.</small>
      <small v-for="m in errors.id" :key="m" class="field__error">{{ m }}</small>
    </div>

    <fieldset class="field">
      <legend class="field__label">Источник</legend>
      <SelectButton v-model="form.sourceType" :options="sourceTypes" option-label="label" option-value="value" :allow-empty="false"
        aria-label="Вид источника" class="seg" />
      <template v-if="form.sourceType === 'device'">
        <label for="source-device" class="sr-only">Устройство</label>
        <Select v-if="deviceOptions.length" v-model="form.sourceId" input-id="source-device" name="source-id" :options="deviceOptions" option-label="label"
          option-value="value" fluid :invalid="!!errors.source">
          <template #option="{ option }"><span>{{ option.label }}</span><span class="opt-meta num">{{ option.mac }}</span></template>
        </Select>
        <p v-else class="field__hint">
          Устройств пока нет.
          <Button variant="link" label="Добавить устройство" class="inline-link" @click="emit('navigate', 'devices')" />
        </p>
      </template>
      <template v-else-if="form.sourceType === 'network'">
        <label for="source-network" class="sr-only">Сеть Wi‑Fi</label>
        <Select v-model="form.sourceId" input-id="source-network" name="source-id" :options="networkOptions" option-label="label" option-value="value"
          fluid :invalid="!!errors.source" />
      </template>
      <small v-for="m in errors.source" :key="m" class="field__error">{{ m }}</small>
    </fieldset>

    <fieldset class="field">
      <legend class="field__label">Назначение</legend>
      <label for="dest-type" class="sr-only">Вид назначения</label>
      <Select v-model="form.destType" input-id="dest-type" name="dest-type" :options="destTypes" option-label="label" option-value="value" fluid />
      <template v-if="form.destType === 'group'">
        <label for="dest-group" class="sr-only">Группа</label>
        <Select v-model="form.destGroup" input-id="dest-group" name="dest-group" :options="groupOptions" option-label="label" option-value="value" fluid
          :invalid="!!errors.destination" />
      </template>
      <template v-else-if="form.destType === 'category'">
        <label for="dest-category" class="sr-only">Категория</label>
        <Select v-model="form.destGroup" input-id="dest-category" name="dest-category" :options="categoryOptions" option-label="label" option-value="value"
          fluid :invalid="!!errors.destination" />
      </template>
      <template v-else>
        <label for="dest-value" class="sr-only">{{ form.destType === 'cidr' ? 'Подсеть' : 'Домен' }}</label>
        <InputText id="dest-value" v-model="form.destValue" class="num" name="dest-value" autocomplete="off" spellcheck="false" fluid
          :placeholder="placeholders[form.destType]" :invalid="!!errors.destination" />
      </template>
      <small v-if="isDomainDest" class="field__hint">
        Домены распознаются по DNS-запросам к роутеру: совпадают и все поддомены. Устройство со своим DoH/DoT спрашивает DNS мимо роутера и обходит правило.
      </small>
      <small v-for="m in errors.destination" :key="m" class="field__error">{{ m }}</small>
    </fieldset>

    <fieldset class="field">
      <legend class="field__label">Действие</legend>
      <div class="pick" role="radiogroup" aria-label="Действие">
        <label v-for="a in actions" :key="a.value" :class="['pick__opt', `bar--${a.kind}`, { 'pick__opt--on': action === a.value }]">
          <input v-model="action" type="radio" name="action" :value="a.value" class="pick__radio" :aria-invalid="!!errors.action" />
          <span class="pick__text">
            <span class="pick__label">{{ a.label }}</span>
            <span class="pick__note">{{ a.note }}</span>
          </span>
        </label>
      </div>
      <p v-if="!config.profiles.length" class="field__hint">
        Чтобы направить трафик в туннель, сначала добавьте сервер TrustTunnel.
        <Button variant="link" label="Перейти к профилю" class="inline-link" @click="emit('navigate', 'profiles')" />
      </p>
      <small v-for="m in errors.action" :key="m" class="field__error">{{ m }}</small>
    </fieldset>

    <div class="check">
      <Checkbox v-model="form.enabled" input-id="rule-enabled" name="enabled" binary />
      <label for="rule-enabled">Правило включено</label>
    </div>

    <fieldset class="field">
      <legend class="field__label">Пробные запросы</legend>
      <small class="field__hint">Проверка покажет, куда пойдут эти запросы сейчас и после правила.</small>
      <div v-for="(p, i) in form.probes" :key="i" class="probe">
        <label :for="`probe-${i}-subject`" class="sr-only">Кто, проба {{ i + 1 }}</label>
        <Select :model-value="probeSubject(i)" :input-id="`probe-${i}-subject`" :name="`probe-${i}-subject`" :options="probeOptions" option-label="label"
          option-value="value" option-group-label="label" option-group-children="items" fluid @update:model-value="(v: string) => setProbeSubject(i, v)" />
        <label :for="`probe-${i}-host`" class="sr-only">Куда, проба {{ i + 1 }}</label>
        <InputText :id="`probe-${i}-host`" v-model="p.host" class="num" :name="`probe-${i}-host`" placeholder="домен или IP" spellcheck="false" fluid
          :invalid="!!errors[`probe-${i}`]" />
        <Button type="button" severity="secondary" variant="text" class="probe__del" :aria-label="`Удалить пробу ${i + 1}`" @click="form.probes.splice(i, 1)">
          <svg viewBox="0 0 16 16" width="16" height="16" aria-hidden="true"><path d="M4 4l8 8M12 4l-8 8" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" /></svg>
        </Button>
        <small v-for="m in errors[`probe-${i}`]" :key="m" class="field__error probe__err">{{ m }}</small>
      </div>
      <Button type="button" variant="link" label="Добавить пробу" class="inline-link" @click="addProbe" />
    </fieldset>

    <Button type="submit" :label="busy ? 'Проверяю…' : 'Проверить правило'" :loading="busy" :disabled="busy" variant="outlined" class="rule-form__submit" />
  </form>
</template>
