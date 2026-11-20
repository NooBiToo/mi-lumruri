<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import InputText from 'primevue/inputtext'
import ToggleSwitch from 'primevue/toggleswitch'
import { ChevronDown, ChevronRight } from 'lucide-vue-next'
import type { ListsUpdate } from '../api'
import { CUSTOM_DNS, DNS_PRESETS, dnsPresetIp, dnsPresetOf, dnsToForm, formToDns, type DnsForm } from '../manage'
import { config, save } from '../store'
import { saveNow, useAutosave, type Blocker } from '../autosave'
import { dnsIcon } from '../brand'
import ServiceLogo from '../components/ServiceLogo.vue'
import Segmented from '../components/Segmented.vue'

defineProps<{ totp: boolean }>()
const emit = defineEmits<{ navigate: [tab: 'zapret' | 'hosts' | 'diag'] }>()

interface Draft { dns: DnsForm }
const toDraft = (): Draft => ({ dns: dnsToForm(config.value?.dns) })
const draft = ref<Draft>(toDraft())
const pristine = ref(JSON.stringify(draft.value))
const dirty = computed(() => JSON.stringify(draft.value) !== pristine.value)
watch(config, () => {
  if (!dirty.value) { draft.value = toDraft(); pristine.value = JSON.stringify(draft.value); custom.value = dnsPresetOf(draft.value.dns.resolver) === CUSTOM_DNS }
})

// ---- DNS: готовый сервер или свой адрес ----
/** «Свой адрес» выбран явно: пока адрес не дописан, он может совпасть с готовым или быть пустым. */
const custom = ref(dnsPresetOf(draft.value.dns.resolver) === CUSTOM_DNS)
const dnsChoice = computed(() => (custom.value ? CUSTOM_DNS : dnsPresetOf(draft.value.dns.resolver)))
const DNS_OPTIONS = [...DNS_PRESETS, { id: CUSTOM_DNS, name: 'Свой адрес', ip: '', desc: 'Любой публичный DNS-сервер (IPv4)' }]
const dnsNote = computed(() => DNS_PRESETS.find((p) => p.id === dnsChoice.value)?.note ?? null)
function chooseDns(id: string) {
  const ip = dnsPresetIp(id)
  custom.value = ip === null
  if (ip !== null) draft.value.dns.resolver = ip
}

const totpHelp = ref(false)

// ---- обновление готовых списков сайтов: сохраняется сразу ----
const LISTS_UPDATES = [
  { value: '6h' as const, label: 'Каждые 6 часов' }, { value: 'daily' as const, label: 'Раз в сутки' },
  { value: 'weekly' as const, label: 'Раз в неделю' }, { value: 'manual' as const, label: 'Вручную' },
]
const listsUpdate = ref<ListsUpdate>(config.value?.schedule?.lists ?? 'daily')
watch(() => config.value?.schedule?.lists, (v) => { listsUpdate.value = v ?? 'daily' })
watch(listsUpdate, async (v) => {
  const c = config.value
  if (!c || (c.schedule?.lists ?? 'daily') === v) return
  const ok = await saveNow(() => save({ ...c, schedule: { ...c.schedule, lists: v } }, ''))
  if (!ok) listsUpdate.value = config.value?.schedule?.lists ?? 'daily'
})

// ---- автосохранение ----
/** Адрес DNS проверяем мягко до сохранения, чтобы не отправлять недописанный «1.1». Точнее проверит контроллер. */
const resolverOk = computed(() => {
  const v = draft.value.dns.resolver.trim()
  return /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/.test(v)
})
function blocker(): Blocker | null {
  return resolverOk.value ? null : { text: 'Свой DNS-сервер — адрес IPv4, например 1.1.1.1.' }
}
useAutosave({
  source: draft,
  dirty: () => dirty.value,
  blocker,
  run: async () => {
    if (!config.value) return 'Настройки ещё не загружены.'
    const sent = JSON.stringify(draft.value)
    const next = { ...config.value }
    const dns = formToDns(draft.value.dns)
    if (dns) next.dns = dns
    else delete next.dns
    const r = await save(next, '')
    if (r.ok) {
      // сохранённое — новая точка отсчёта; правки, сделанные во время запроса, останутся несохранёнными
      pristine.value = sent
      if (!dirty.value) { draft.value = toDraft(); pristine.value = JSON.stringify(draft.value) }
    }
    return r
  },
})
</script>

<template>
  <section class="sect" aria-label="Дополнительно">
    <p class="lead">Обычно здесь ничего менять не нужно. Изменения сохраняются сами</p>

    <!-- телефон: разделы, которых нет в нижней панели -->
    <nav class="card card--flush settings more-links" aria-label="Другие разделы">
      <button type="button" class="setrow more-link" @click="emit('navigate', 'zapret')">
        <span class="setrow__text"><span class="setrow__title">Zapret</span><span class="setrow__desc">Способ обхода блокировок, подбор, автопроверка</span></span>
        <ChevronRight :size="18" class="more-link__icon" aria-hidden="true" />
      </button>
      <button type="button" class="setrow more-link" @click="emit('navigate', 'hosts')">
        <span class="setrow__text"><span class="setrow__title">Свои DNS-записи</span><span class="setrow__desc">Домашние серверы по своим именам</span></span>
        <ChevronRight :size="18" class="more-link__icon" aria-hidden="true" />
      </button>
      <button type="button" class="setrow more-link" @click="emit('navigate', 'diag')">
        <span class="setrow__text"><span class="setrow__title">Диагностика</span><span class="setrow__desc">Проверка работы, журналы, перезапуск службы</span></span>
        <ChevronRight :size="18" class="more-link__icon" aria-hidden="true" />
      </button>
    </nav>

    <div class="card card--flush settings">
      <label class="setrow">
        <span class="setrow__text">
          <span class="setrow__title">Блокировка рекламы</span>
          <span class="setrow__desc">Для всех устройств дома: рекламные сайты не открываются</span>
        </span>
        <ToggleSwitch v-model="draft.dns.adblock" input-id="adblock" />
      </label>

      <div class="setblock" role="group" aria-labelledby="dns-title">
        <span class="setrow__text">
          <span id="dns-title" class="setrow__title">DNS для сайтов через VPN</span>
          <span class="setrow__desc">Через него, внутри VPN, узнаются адреса сайтов из ваших списков. Обычно подходит Cloudflare.</span>
        </span>
        <div class="dns" role="radiogroup" aria-labelledby="dns-title">
          <label v-for="o in DNS_OPTIONS" :key="o.id" :class="['dns__opt', { 'dns__opt--on': dnsChoice === o.id }]">
            <input type="radio" name="dns" class="dns__radio" :value="o.id" :checked="dnsChoice === o.id" @change="chooseDns(o.id)" />
            <ServiceLogo :icon="dnsIcon(o.id)" />
            <span class="dns__text">
              <span class="dns__name">{{ o.name }}<span v-if="o.ip" class="dns__ip num">{{ o.ip }}</span></span>
              <span class="dns__desc">{{ o.desc }}</span>
            </span>
          </label>
        </div>
        <p v-if="dnsNote" class="dns__note">{{ dnsNote }}</p>
        <div v-if="dnsChoice === 'custom'" class="field dns__custom">
          <label for="dns" class="field__label">Адрес DNS-сервера</label>
          <InputText id="dns" v-model="draft.dns.resolver" class="num" placeholder="например, 1.0.0.1" inputmode="decimal" :invalid="!resolverOk" aria-describedby="dns-hint" />
          <span id="dns-hint" :class="resolverOk ? 'field__hint' : 'field__error'">{{ resolverOk ? 'Публичный адрес IPv4.' : 'Нужен адрес IPv4, например 1.0.0.1.' }}</span>
        </div>
      </div>

      <div class="setblock" role="group" aria-labelledby="lists-title">
        <span class="setrow__text">
          <span id="lists-title" class="setrow__title">Обновление списков сайтов</span>
          <span class="setrow__desc">Как часто роутер проверяет новые версии готовых списков (allow-domains). «Вручную» — только по кнопке «Обновить» на «Обзоре»</span>
        </span>
        <Segmented v-model="listsUpdate" class="self-start" :options="LISTS_UPDATES" label="Обновление списков сайтов" name="lists-update" />
      </div>

      <div class="setrow setrow--top">
        <span class="setrow__text">
          <span class="setrow__title">Вход в панель</span>
          <span class="setrow__desc">{{ totp ? 'По паролю и коду из приложения-аутентификатора.' : 'Только по паролю. Можно добавить второй шаг: код из приложения на телефоне (Google Authenticator и подобные).' }}</span>
          <template v-if="!totp">
            <button type="button" class="disclose" :aria-expanded="totpHelp" aria-controls="totp-help" @click="totpHelp = !totpHelp">
              <ChevronDown :size="16" :class="['disclose__icon', { 'disclose__icon--open': totpHelp }]" aria-hidden="true" />Как включить
            </button>
            <span v-show="totpHelp" id="totp-help" class="setrow__desc">Подключитесь к роутеру по SSH и выполните
              <code>sh /data/mi-trusttunnel/mitt-boot.sh auth reset-totp</code>, отсканируйте QR-код приложением, затем
              <code>sh /data/mi-trusttunnel/mitt-boot.sh auth confirm</code>. Подробнее — в инструкции, раздел «Второй фактор».</span>
          </template>
        </span>
        <span :class="['badge', totp ? 'badge--ok' : 'badge--idle']">{{ totp ? 'Пароль и код' : 'Только пароль' }}</span>
      </div>
    </div>

  </section>
</template>
