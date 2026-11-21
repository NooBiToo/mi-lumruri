<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import Button from 'primevue/button'
import InputText from 'primevue/inputtext'
import Message from 'primevue/message'
import Password from 'primevue/password'
import Textarea from 'primevue/textarea'
import ToggleSwitch from 'primevue/toggleswitch'
import { Check, ChevronDown, ClipboardPaste, Minus } from 'lucide-vue-next'
import Select from 'primevue/select'
import { api, manage, type Endpoint, type SubscriptionResponse, type TlsProfile } from '../api'
import { emptyProfileForm, formToProfile, formToSecret, profileToForm, type ProfileForm } from '../manage'
import { parseServer, TLS_PROFILES } from '../serverConfig'
import { config, hasPassword, hasSubscription, loadSecrets, notify, profile, save, simple, tunnel } from '../store'
import { when } from '../status'
import { t } from '../i18n'
import Segmented from '../components/Segmented.vue'
import BackupServer from '../components/BackupServer.vue'

const emit = defineEmits<{ navigate: [tab: 'sites'] }>()

const PROFILE_ID = 'tt'
const formFrom = (): ProfileForm => (profile.value ? profileToForm(profile.value) : { ...emptyProfileForm(), id: PROFILE_ID, name: t('Мой сервер') })
const form = ref<ProfileForm>(formFrom())
const pristine = ref(JSON.stringify(form.value))
const dirty = computed(() => JSON.stringify(form.value) !== pristine.value)
watch(profile, () => { if (!dirty.value) { form.value = formFrom(); pristine.value = JSON.stringify(form.value) } })
const firstTime = computed(() => !profile.value?.endpoint)
const advanced = ref(false)
const FAILURE = computed(() => [{ value: 'block' as const, label: t('Не открывать') }, { value: 'direct' as const, label: t('Открывать напрямую') }])
const tlsLabel = (id: TlsProfile): string => ({
  chrome: t('Chrome (по умолчанию)'), chrome_canary: 'Chrome Canary', safari: 'Safari', firefox: 'Firefox', okhttp: 'OkHttp (Android)',
  openssl: 'OpenSSL', boringssl: t('Без маскировки (BoringSSL)'),
} satisfies Record<TlsProfile, string>)[id]
const TLS_OPTIONS = computed(() => TLS_PROFILES.map((id) => ({ id, label: tlsLabel(id) })))

// ---- вставка конфигурации ----
const pasted = ref('')
interface Preview { rows: { label: string; value: string | null }[]; warnings: string[] }
const parsed = ref<Preview | { error: string } | null>(null)
watch(pasted, (t) => { if (!t.trim()) parsed.value = null })
function recognize() {
  const text = pasted.value
  if (!text.trim()) { parsed.value = null; return }
  const r = parseServer(text)
  if ('error' in r) { parsed.value = { error: r.error }; return }
  const e: Partial<Endpoint> = r.endpoint
  const f = form.value
  if (e.server !== undefined) f.server = e.server
  if (e.port !== undefined) f.port = String(e.port)
  f.sni = e.sni ?? ''
  if (e.username !== undefined) f.username = e.username
  if (e.quic !== undefined) f.quic = e.quic
  if (e.anti_dpi !== undefined) f.antiDpi = e.anti_dpi
  f.certificate = e.certificate ?? ''
  f.tlsProfile = e.tls_profile ?? 'chrome'
  f.clientRandom = e.client_random ?? ''
  f.clientRandomAuthKey = e.client_random_auth_key ?? ''
  if (r.password) f.password = r.password
  if (r.subscription) f.subscriptionUrl = r.subscription
  if (r.name && !profile.value) f.name = r.name
  // необязательные параметры — только если они есть в ссылке
  const extra = [
    ...(e.tls_profile ? [{ label: t('Профиль TLS'), value: tlsLabel(e.tls_profile) }] : []),
    ...(e.client_random_auth_key ? [{ label: t('Ключ client_random'), value: t('есть') }] : e.client_random ? [{ label: t('Префикс client_random'), value: t('есть') }] : []),
  ]
  parsed.value = {
    rows: [
      { label: t('Сервер'), value: e.server ? `${e.server}${e.port ? `:${e.port}` : ''}` : null },
      { label: t('Имя сервера'), value: e.sni ?? null },
      { label: t('Логин'), value: e.username ?? null },
      { label: t('Пароль'), value: r.password ? t('есть') : null },
      { label: t('Сертификат'), value: e.certificate ? t('есть') : null },
      ...extra,
      ...(r.subscription ? [{ label: t('Подписка'), value: e.server ? t('есть') : t('есть — адрес и пароль роутер получит по ней') }] : []),
    ],
    warnings: r.warnings ?? [],
  }
}
// вставили из буфера — распознаём сразу
async function onPaste() { await nextTick(); recognize() }

// ---- сохранение ----
const saving = ref(false)
const error = ref<string | null>(null)
const done = ref(false)
/** Подписка задана сейчас или уже сохранена: адрес, логин и пароль сервер может прислать сам. */
const subscribed = computed(() => !!form.value.subscriptionUrl.trim() || hasSubscription.value)
const subscriptionOnly = computed(() => subscribed.value && !form.value.server.trim() && !form.value.username.trim())
const needPassword = computed(() => !hasPassword.value && !form.value.password && !subscribed.value)
const blocker = computed(() => {
  const f = form.value
  if (subscriptionOnly.value) return null
  if (!f.server.trim() || !f.username.trim()) return t('Укажите адрес сервера и логин — или вставьте ссылку.')
  if (needPassword.value) return t('Укажите пароль.')
  return null
})
async function submit() {
  if (blocker.value || !config.value) return
  const p = formToProfile(form.value, subscriptionOnly.value)
  if (typeof p === 'string') { error.value = p; return }
  saving.value = true
  error.value = null
  try {
    const secret = formToSecret(form.value)
    const writeSecret = async (): Promise<boolean> => {
      const s = await manage.setSecret(p.id, secret!)
      if (s.status !== 200) error.value = t('Пароль не записан: {e}', { e: s.body.error?.message ?? s.status })
      return s.status === 200
    }
    // Пароль пишется до настроек: заявка на применение от POST /config уже застанет новый пароль. Но контроллер
    // принимает пароль только для профиля, который уже есть в настройках, — при первой настройке сервера пароль
    // пишется после настроек, и тогда применение запрашивается ещё раз.
    const known = config.value.profiles.some((x) => x.id === p.id)
    if (secret && known && !(await writeSecret())) return
    const r = await save({ ...config.value, profiles: [p, ...config.value.profiles.slice(1)] }, secret && !known ? '' : undefined)
    if (!r.ok) { error.value = r.message; return }
    if (secret && !known) {
      if (!(await writeSecret())) return
      await manage.applyRequest()
      notify.show('success', t('Сохранено, применяю на роутере'))
    }
    // новая ссылка-подписка — сразу забрать параметры сервера
    if (secret?.subscription_url) void refreshSubscription(true)
    form.value.password = ''
    form.value.subscriptionUrl = ''
    pristine.value = JSON.stringify(form.value)
    pasted.value = ''
    done.value = true
    await loadSecrets()
  } finally {
    saving.value = false
  }
}
// ---- подписка TrustTunnel ----
const sub = ref<SubscriptionResponse | null>(null)
let subTimer: number | undefined
async function loadSubscription() {
  clearTimeout(subTimer)
  try { sub.value = (await api.subscription()).body } catch { /* панель недоступна */ }
  if (sub.value?.running) subTimer = window.setTimeout(() => void loadSubscription(), 2000)
}
async function refreshSubscription(quiet = false) {
  const r = await api.updateSubscription()
  if (r.status !== 202) { notify.show('error', t('Не получилось'), r.body.error?.message); return }
  if (!quiet) notify.show('info', t('Обновляю параметры по подписке'))
  subTimer = window.setTimeout(() => void loadSubscription(), 1500)
}
async function dropSubscription() {
  const id = profile.value?.id
  if (!id) return
  const r = await manage.setSecret(id, { subscription_url: '' })
  if (r.status !== 200) { notify.show('error', t('Не получилось'), r.body.error?.message); return }
  notify.show('success', t('Подписка удалена'))
  await loadSecrets()
}
const subText = computed(() => {
  const s = sub.value?.subscription
  if (sub.value?.running) return t('Обновляю по подписке…')
  if (!s) return t('Роутер ещё не обращался к подписке')
  if (!s.ok) return t('Не получилось {when}: {e}. Действуют прежние параметры', { when: when(s.checked), e: s.error ?? t('ошибка') })
  return s.updated
    ? t('Проверено {when}, параметры менялись {changed}', { when: when(s.checked), changed: when(s.updated) })
    : t('Проверено {when}, изменений нет', { when: when(s.checked) })
})
onMounted(() => void loadSubscription())
onBeforeUnmount(() => clearTimeout(subTimer))
const nothingSelected = computed(() => !!simple.value && simple.value.mode === 'selected' && !simple.value.services.length && !simple.value.customDomains.length)
</script>

<template>
  <section class="sect" :aria-label="t('Сервер VPN')">
    <Message v-if="done && nothingSelected" severity="success" :closable="false">
      <div class="next">
        <span>{{ t('Сервер сохранён. Теперь отметьте сайты, которые открывать через VPN.') }}</span>
        <Button :label="t('Выбрать сайты')" size="small" @click="emit('navigate', 'sites')" />
      </div>
    </Message>

    <div class="cols">
      <div class="cols__side">
        <div class="card">
          <div>
            <h2 class="card__title">{{ firstTime ? t('Быстрая настройка') : t('Сменить сервер') }}</h2>
            <p class="card__sub">{{ t('Вставьте ссылку') }} <span class="num">tt://</span> {{ t('или файл конфигурации клиента — поля заполнятся сами') }}</p>
          </div>
          <div class="field">
            <label for="paste" class="sr-only">{{ t('Ссылка или конфигурация сервера') }}</label>
            <Textarea id="paste" v-model="pasted" rows="5" spellcheck="false" :placeholder="t('tt://?… или содержимое client.toml')" class="mono" @paste="onPaste" />
          </div>
          <Button :label="t('Распознать')" severity="secondary" variant="outlined" class="self-start" :disabled="!pasted.trim()" @click="recognize">
            <template #icon><ClipboardPaste :size="16" class="p-button-icon-left" aria-hidden="true" /></template>
          </Button>
          <Message v-if="parsed && 'error' in parsed" severity="error" :closable="false">{{ t('Не получилось прочитать: {e}.', { e: parsed.error }) }}</Message>
          <template v-else-if="parsed">
            <div class="preview" aria-live="polite">
              <p class="preview__title">{{ t('Распознано — проверьте поля и сохраните') }}</p>
              <dl class="preview__list">
                <div v-for="r in parsed.rows" :key="r.label" :class="['preview__row', { 'preview__row--none': !r.value }]">
                  <dt><Check v-if="r.value" :size="14" aria-hidden="true" /><Minus v-else :size="14" aria-hidden="true" />{{ r.label }}</dt>
                  <dd class="num">{{ r.value ?? t('нет') }}</dd>
                </div>
              </dl>
            </div>
            <Message v-for="w in parsed.warnings" :key="w" severity="warn" :closable="false">{{ t('Не поддерживается: {w}.', { w }) }}</Message>
          </template>
        </div>

        <div v-if="!firstTime" class="card conn">
          <h2 class="card__title">{{ t('Подключение') }}</h2>
          <div :class="['pill', `pill--${tunnel.tone}`, 'pill--lg']"><span class="pill__dot" aria-hidden="true" /><span class="pill__text">{{ tunnel.title }}</span></div>
          <p v-if="tunnel.detail" class="hint">{{ tunnel.detail }}</p>
        </div>
        <BackupServer v-if="!firstTime" />
      </div>

      <form class="card" @submit.prevent="submit">
        <h2 class="card__title">{{ t('Данные сервера') }}</h2>
        <div class="row2">
          <div class="field">
            <label for="srv-host" class="field__label">{{ t('Адрес сервера') }}</label>
            <InputText id="srv-host" v-model="form.server" placeholder="203.0.113.10" spellcheck="false" class="num" />
          </div>
          <div class="field field--port">
            <label for="srv-port" class="field__label">{{ t('Порт') }}</label>
            <InputText id="srv-port" v-model="form.port" inputmode="numeric" class="num" />
          </div>
        </div>
        <div class="field">
          <label for="srv-sni" class="field__label">{{ t('Имя сервера') }}</label>
          <InputText id="srv-sni" v-model="form.sni" placeholder="vpn.example.com" spellcheck="false" />
          <span class="field__hint">{{ t('Доменное имя из сертификата сервера. Если его нет — оставьте пустым.') }}</span>
        </div>
        <div class="row2">
          <div class="field">
            <label for="srv-user" class="field__label">{{ t('Логин') }}</label>
            <InputText id="srv-user" v-model="form.username" autocomplete="off" spellcheck="false" />
          </div>
          <div class="field">
            <label for="srv-pass" class="field__label">{{ t('Пароль') }}</label>
            <Password v-model="form.password" input-id="srv-pass" :feedback="false" toggle-mask fluid autocomplete="new-password"
              :placeholder="hasPassword ? t('Сохранён. Оставьте пустым') : ''" />
            <span class="field__hint">{{ hasPassword ? t('Пароль сохранён на роутере и сюда не возвращается. Введите новый, чтобы сменить.') : t('Хранится только на роутере') }}</span>
          </div>
        </div>

        <div class="field">
          <span id="srv-fail-label" class="field__label">{{ t('Если сервер недоступен, сайты из списка') }}</span>
          <Segmented v-model="form.onFailure" :options="FAILURE" :label="t('Если сервер недоступен')" name="onfail" />
          <span class="field__hint">{{ form.onFailure === 'block' ? t('Рекомендуется. Сайты подождут, пока сервер снова заработает.') : t('Сайты откроются без VPN, если смогут.') }}</span>
        </div>

        <button type="button" class="disclose" :aria-expanded="advanced" aria-controls="srv-adv" @click="advanced = !advanced">
          <ChevronDown :size="16" :class="['disclose__icon', { 'disclose__icon--open': advanced }]" aria-hidden="true" />
          {{ t('Дополнительные параметры') }}
        </button>
        <div v-show="advanced" id="srv-adv" class="adv">
          <label class="setrow">
            <span class="setrow__text"><span class="setrow__title">HTTP/3</span><span class="setrow__desc">{{ t('Включайте, только если так сказано в настройках сервера') }}</span></span>
            <ToggleSwitch v-model="form.quic" input-id="srv-quic" />
          </label>
          <label class="setrow">
            <span class="setrow__text"><span class="setrow__title">{{ t('Маскировка от блокировок (anti-DPI)') }}</span><span class="setrow__desc">{{ t('Помогает, если провайдер мешает подключению к серверу.') }}</span></span>
            <ToggleSwitch v-model="form.antiDpi" input-id="srv-dpi" />
          </label>
          <div class="field">
            <label for="srv-cert" class="field__label">{{ t('Сертификат сервера') }}</label>
            <Textarea id="srv-cert" v-model="form.certificate" rows="4" spellcheck="false" class="mono" placeholder="-----BEGIN CERTIFICATE-----" />
            <span class="field__hint">{{ t('Нужен, только если сервер использует свой сертификат. Обычно приходит вместе со ссылкой.') }}</span>
          </div>
          <div class="field">
            <label for="srv-tls" class="field__label">{{ t('Профиль TLS') }}</label>
            <Select v-model="form.tlsProfile" input-id="srv-tls" :options="TLS_OPTIONS" option-label="label" option-value="id" fluid />
            <span class="field__hint">{{ t('Под какой браузер или приложение маскируется подключение. Меняйте, если так сказано в настройках сервера или провайдер мешает подключению.') }}</span>
          </div>
          <div class="row2">
            <div class="field">
              <label for="srv-cr" class="field__label">{{ t('Префикс client_random') }}</label>
              <InputText id="srv-cr" v-model="form.clientRandom" spellcheck="false" autocomplete="off" class="mono" :placeholder="t('префикс/маска')" />
            </div>
            <div class="field">
              <label for="srv-crk" class="field__label">{{ t('Ключ client_random') }}</label>
              <InputText id="srv-crk" v-model="form.clientRandomAuthKey" spellcheck="false" autocomplete="off" class="mono" />
            </div>
          </div>
          <span class="field__hint">{{ t('Нужны, только если сервер пускает подключения по client_random. Обычно приходят вместе со ссылкой; задаётся что-то одно — префикс или ключ.') }}</span>
          <div class="field">
            <label for="srv-sub" class="field__label">{{ t('Ссылка-подписка') }}</label>
            <Password v-model="form.subscriptionUrl" input-id="srv-sub" :feedback="false" toggle-mask fluid autocomplete="off"
              :placeholder="hasSubscription ? t('Сохранена. Оставьте пустым') : 'https://…'" />
            <span class="field__hint">{{ t('Подписка TrustTunnel 1.3: по ней роутер сам забирает адрес, логин, пароль и сертификат сервера — по расписанию списков сайтов и по кнопке. В ссылке есть логин и пароль, поэтому она хранится только на роутере') }}</span>
          </div>
          <template v-if="hasSubscription">
            <span :class="['adblock__state', { 'adblock__state--bad': sub?.subscription && !sub.subscription.ok }]" aria-live="polite">
              <span :class="['led', sub?.subscription ? (sub.subscription.ok ? 'led--ok' : 'led--warn') : 'led--idle']" aria-hidden="true" />
              <span class="meta">{{ subText }}</span>
            </span>
            <div class="sub__actions">
              <Button :label="t('Обновить по подписке')" size="small" severity="secondary" variant="outlined" :loading="!!sub?.running" :disabled="!!sub?.running" @click="refreshSubscription()" />
              <Button :label="t('Удалить подписку')" size="small" severity="secondary" variant="text" @click="dropSubscription" />
            </div>
          </template>
        </div>

        <Message v-if="error" severity="error" :closable="false">{{ error }}</Message>
        <div class="formfoot">
          <span class="formfoot__text" aria-live="polite">{{ blocker && dirty ? blocker : dirty ? t('Есть несохранённые изменения') : profile?.endpoint ? t('Всё сохранено') : t('Вставьте ссылку на сервер') }}</span>
          <Button type="submit" :label="t('Сохранить')" :loading="saving" :disabled="!dirty || !!blocker || saving" />
        </div>
      </form>
    </div>
  </section>
</template>

<style scoped>
.sub__actions { display: flex; flex-wrap: wrap; gap: 0.5rem; }
</style>
