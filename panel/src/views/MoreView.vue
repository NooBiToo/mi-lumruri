<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue'
import Button from 'primevue/button'
import InputText from 'primevue/inputtext'
import ToggleSwitch from 'primevue/toggleswitch'
import { ChevronDown } from 'lucide-vue-next'
import { api, type ZapretConfig, type ZapretTestState } from '../api'
import { DEFAULT_TUNNEL_RESOLVER, dnsToForm, formToDns, type DnsForm } from '../manage'
import { AUTO, strategyLabel, testedAt } from '../status'
import { config, save, scrollTarget, simple } from '../store'
import { useAutosave, type Blocker } from '../autosave'

defineProps<{ totp: boolean }>()
const emit = defineEmits<{ navigate: [tab: 'sites'] }>()

interface Draft { dns: DnsForm; autoZapret: boolean }
const toDraft = (): Draft => ({ dns: dnsToForm(config.value?.dns), autoZapret: false })
const draft = ref<Draft>(toDraft())
const pristine = ref(JSON.stringify(draft.value))
const dirty = computed(() => JSON.stringify(draft.value) !== pristine.value)
watch(config, () => { if (!dirty.value) { draft.value = toDraft(); pristine.value = JSON.stringify(draft.value) } })

const zapret = computed(() => config.value?.zapret)
const zapretAuto = computed(() => (zapret.value?.strategy ?? AUTO) === AUTO && (zapret.value?.youtube ?? AUTO) === AUTO)
const zapretOn = computed(() => simple.value?.rest === 'zapret')
const test = ref<ZapretTestState | null>(null)
onMounted(async () => { const r = await api.zapretTest(); if (r.body.ok && r.body.test) test.value = r.body.test })
function openZapret() {
  scrollTarget.value = 'zapret'
  emit('navigate', 'sites')
}
const totpHelp = ref(false)

// ---- автосохранение ----
/** Адрес DNS проверяем мягко до сохранения, чтобы не отправлять недописанный «1.1». Точнее проверит контроллер. */
const resolverOk = computed(() => {
  const v = draft.value.dns.resolver.trim()
  return !v || /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/.test(v)
})
function blocker(): Blocker | null {
  return resolverOk.value ? null : { text: 'DNS-сервер — адрес IPv4, например 1.1.1.1.' }
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
    if (draft.value.autoZapret) next.zapret = { strategy: AUTO, youtube: AUTO } satisfies ZapretConfig
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
    <p class="lead">Обычно здесь ничего менять не нужно. Изменения сохраняются сами.</p>

    <div class="card card--flush settings">
      <label class="setrow">
        <span class="setrow__text">
          <span class="setrow__title">Блокировка рекламы</span>
          <span class="setrow__desc">Для всех устройств дома: рекламные сайты не открываются.</span>
        </span>
        <ToggleSwitch v-model="draft.dns.adblock" input-id="adblock" />
      </label>

      <div class="setrow">
        <span class="setrow__text">
          <label for="dns" class="setrow__title">DNS для сайтов через VPN</label>
          <span class="setrow__desc">Через него, внутри VPN, узнаются адреса сайтов из вашего списка. По умолчанию {{ DEFAULT_TUNNEL_RESOLVER }} (Cloudflare).</span>
          <span v-if="!resolverOk" class="field__error">Нужен адрес IPv4, например 1.1.1.1.</span>
        </span>
        <InputText id="dns" v-model="draft.dns.resolver" class="num setrow__input" :placeholder="DEFAULT_TUNNEL_RESOLVER" inputmode="decimal" :invalid="!resolverOk" />
      </div>

      <div class="setrow">
        <span class="setrow__text">
          <span class="setrow__title">Обход блокировок (Zapret)</span>
          <span class="setrow__desc">
            Способ: {{ draft.autoZapret ? strategyLabel(undefined) : strategyLabel(zapret, testedAt(test)) }}.
            <template v-if="!zapretOn">Сейчас выключен — включается на экране «Сайты».</template>
          </span>
        </span>
        <span class="setrow__actions">
          <Button v-if="!zapretAuto && !draft.autoZapret" label="Вернуть автоматический" severity="secondary" variant="text" size="small" @click="draft.autoZapret = true" />
          <Button :label="zapretOn ? 'Подобрать заново' : 'Открыть «Сайты»'" severity="secondary" variant="outlined" size="small" @click="openZapret" />
        </span>
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
