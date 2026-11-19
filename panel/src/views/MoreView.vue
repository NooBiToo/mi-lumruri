<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue'
import Button from 'primevue/button'
import InputText from 'primevue/inputtext'
import Message from 'primevue/message'
import ToggleSwitch from 'primevue/toggleswitch'
import { api, type ZapretConfig, type ZapretTestState } from '../api'
import { DEFAULT_TUNNEL_RESOLVER, dnsToForm, formToDns, type DnsForm } from '../manage'
import { AUTO, strategyLabel, testedAt } from '../status'
import { config, save, scrollTarget, simple } from '../store'

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

const saving = ref(false)
const error = ref<string | null>(null)
async function submit() {
  if (!config.value) return
  const next = { ...config.value }
  const dns = formToDns(draft.value.dns)
  if (dns) next.dns = dns
  else delete next.dns
  if (draft.value.autoZapret) next.zapret = { strategy: AUTO, youtube: AUTO } satisfies ZapretConfig
  saving.value = true
  error.value = null
  try {
    const r = await save(next)
    if (!r.ok) error.value = r.message
  } finally { saving.value = false }
}
</script>

<template>
  <section class="sect" aria-labelledby="more-title">
    <header class="sect__head">
      <h1 id="more-title" class="sect__title">Дополнительно</h1>
      <p class="sect__lead">Обычно здесь ничего менять не нужно.</p>
    </header>

    <div class="card">
      <label class="switch switch--big">
        <ToggleSwitch v-model="draft.dns.adblock" input-id="adblock" />
        <span>
          <span class="switch__label">Блокировать рекламу</span>
          <span class="switch__note">Для всех устройств дома: рекламные сайты не открываются.</span>
        </span>
      </label>
    </div>

    <div class="card">
      <div class="field">
        <label for="dns" class="field__label">DNS-сервер для сайтов через VPN</label>
        <InputText id="dns" v-model="draft.dns.resolver" class="num field__short" :placeholder="DEFAULT_TUNNEL_RESOLVER" inputmode="decimal" />
        <span class="field__hint">Через него, внутри VPN, узнаются адреса сайтов из вашего списка. По умолчанию {{ DEFAULT_TUNNEL_RESOLVER }} (Cloudflare).</span>
      </div>
    </div>

    <div class="card">
      <h2 class="card__title">Обход блокировок (Zapret)</h2>
      <p><span class="muted">Способ обхода:</span> {{ draft.autoZapret ? strategyLabel(undefined) : strategyLabel(zapret, testedAt(test)) }}</p>
      <p v-if="!zapretOn" class="hint">Сейчас выключен. Включается на экране «Сайты»: «Напрямую с обходом блокировок».</p>
      <div class="actions">
        <Button :label="zapretOn ? 'Подобрать способ заново' : 'Открыть «Сайты»'" severity="secondary" variant="outlined" @click="openZapret" />
        <Button v-if="!zapretAuto && !draft.autoZapret" label="Вернуть автоматический" severity="secondary" variant="text" @click="draft.autoZapret = true" />
      </div>
    </div>

    <div class="card">
      <h2 class="card__title">Вход в панель</h2>
      <p v-if="totp">Вход по паролю и коду из приложения-аутентификатора.</p>
      <template v-else>
        <p>Вход только по паролю.</p>
        <p class="hint">Можно добавить второй шаг: код из приложения на телефоне (Google Authenticator и подобные).</p>
        <button type="button" class="disclose" :aria-expanded="totpHelp" aria-controls="totp-help" @click="totpHelp = !totpHelp">
          {{ totpHelp ? 'Скрыть' : 'Как включить' }}
        </button>
        <p v-show="totpHelp" id="totp-help" class="hint">Подключитесь к роутеру по SSH и выполните
          <code>sh /data/mi-trusttunnel/mitt-boot.sh auth reset-totp</code>, отсканируйте QR-код приложением, затем
          <code>sh /data/mi-trusttunnel/mitt-boot.sh auth confirm</code>. Подробнее — в инструкции, раздел «Второй фактор».</p>
      </template>
    </div>

    <Message v-if="error" severity="error" :closable="false">{{ error }}</Message>

    <div class="savebar">
      <div class="savebar__in">
        <span class="savebar__text" aria-live="polite">{{ dirty ? 'Есть несохранённые изменения' : 'Всё сохранено' }}</span>
        <Button label="Сохранить" :loading="saving" :disabled="!dirty || saving" @click="submit" />
      </div>
    </div>
  </section>
</template>
