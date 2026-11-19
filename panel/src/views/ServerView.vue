<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import Button from 'primevue/button'
import InputText from 'primevue/inputtext'
import Message from 'primevue/message'
import Password from 'primevue/password'
import Textarea from 'primevue/textarea'
import ToggleSwitch from 'primevue/toggleswitch'
import { manage } from '../api'
import { emptyProfileForm, formToProfile, formToSecret, profileToForm, type ProfileForm } from '../manage'
import { parseServer } from '../serverConfig'
import { config, hasPassword, loadSecrets, notify, profile, save, simple } from '../store'

const emit = defineEmits<{ navigate: [tab: 'sites'] }>()

const PROFILE_ID = 'tt'
const formFrom = (): ProfileForm => (profile.value ? profileToForm(profile.value) : { ...emptyProfileForm(), id: PROFILE_ID, name: 'Мой сервер' })
const form = ref<ProfileForm>(formFrom())
const pristine = ref(JSON.stringify(form.value))
const dirty = computed(() => JSON.stringify(form.value) !== pristine.value)
watch(profile, () => { if (!dirty.value) { form.value = formFrom(); pristine.value = JSON.stringify(form.value) } })
const firstTime = computed(() => !profile.value?.endpoint)
const advanced = ref(false)

// ---- вставка конфигурации ----
const pasted = ref('')
const parsed = ref<{ ok: string; warnings: string[] } | { error: string } | null>(null)
watch(pasted, (t) => {
  if (!t.trim()) { parsed.value = null; return }
  const r = parseServer(t)
  if ('error' in r) { parsed.value = { error: r.error }; return }
  const e = r.endpoint
  const f = form.value
  if (e.server !== undefined) f.server = e.server
  if (e.port !== undefined) f.port = String(e.port)
  f.sni = e.sni ?? ''
  if (e.username !== undefined) f.username = e.username
  if (e.quic !== undefined) f.quic = e.quic
  if (e.anti_dpi !== undefined) f.antiDpi = e.anti_dpi
  f.certificate = e.certificate ?? ''
  if (r.password) f.password = r.password
  if (r.name && !profile.value) f.name = r.name
  parsed.value = { ok: `Поля заполнены: сервер ${e.sni ?? e.server}${r.password ? ', логин и пароль' : ''}${e.certificate ? ', сертификат' : ''}.`, warnings: r.warnings ?? [] }
})

// ---- сохранение ----
const saving = ref(false)
const error = ref<string | null>(null)
const done = ref(false)
const needPassword = computed(() => !hasPassword.value && !form.value.password)
const blocker = computed(() => {
  const f = form.value
  if (!f.server.trim() || !f.username.trim()) return 'Укажите адрес сервера и логин — или вставьте ссылку выше.'
  if (needPassword.value) return 'Укажите пароль.'
  return null
})
async function submit() {
  if (blocker.value || !config.value) return
  const p = formToProfile(form.value)
  if (typeof p === 'string') { error.value = p; return }
  saving.value = true
  error.value = null
  try {
    const secret = formToSecret(form.value)
    const writeSecret = async (): Promise<boolean> => {
      const s = await manage.setSecret(p.id, secret!)
      if (s.status !== 200) error.value = `Пароль не записан: ${s.body.error?.message ?? s.status}`
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
      notify.show('success', 'Сохранено, применяю на роутере')
    }
    form.value.password = ''
    pristine.value = JSON.stringify(form.value)
    pasted.value = ''
    done.value = true
    await loadSecrets()
  } finally {
    saving.value = false
  }
}
const nothingSelected = computed(() => !!simple.value && simple.value.mode === 'selected' && !simple.value.services.length && !simple.value.customDomains.length)
</script>

<template>
  <section class="sect" aria-labelledby="srv-title">
    <header class="sect__head">
      <h1 id="srv-title" class="sect__title">Сервер VPN</h1>
      <p class="sect__lead">Куда роутер подключается. Данные выдаёт ваш сервер TrustTunnel или тот, кто его настроил.</p>
    </header>

    <Message v-if="done && nothingSelected" severity="success" :closable="false">
      <div class="next">
        <span>Сервер сохранён. Теперь отметьте сайты, которые открывать через VPN.</span>
        <Button label="Выбрать сайты" size="small" @click="emit('navigate', 'sites')" />
      </div>
    </Message>

    <div class="card">
      <div class="field">
        <label for="paste" class="field__label">{{ firstTime ? 'Вставьте ссылку на сервер' : 'Сменить сервер: вставьте новую ссылку' }}</label>
        <Textarea id="paste" v-model="pasted" rows="3" auto-resize spellcheck="false" placeholder="tt://?… или содержимое файла конфигурации" class="mono" />
        <span class="field__hint">Подойдёт ссылка <span class="num">tt://</span> или файл конфигурации клиента — поля ниже заполнятся сами.</span>
      </div>
      <Message v-if="parsed && 'error' in parsed" severity="error" :closable="false">Не получилось прочитать: {{ parsed.error }}.</Message>
      <template v-else-if="parsed">
        <Message severity="success" :closable="false">{{ parsed.ok }} Проверьте и сохраните.</Message>
        <Message v-for="w in parsed.warnings" :key="w" severity="warn" :closable="false">Не поддерживается: {{ w }}.</Message>
      </template>
    </div>

    <div class="card">
      <h2 class="card__title">Данные сервера</h2>
      <div class="row2">
        <div class="field">
          <label for="srv-host" class="field__label">Адрес сервера</label>
          <InputText id="srv-host" v-model="form.server" placeholder="203.0.113.10" spellcheck="false" class="num" />
        </div>
        <div class="field field--port">
          <label for="srv-port" class="field__label">Порт</label>
          <InputText id="srv-port" v-model="form.port" inputmode="numeric" class="num" />
        </div>
      </div>
      <div class="field">
        <label for="srv-sni" class="field__label">Имя сервера</label>
        <InputText id="srv-sni" v-model="form.sni" placeholder="vpn.example.com" spellcheck="false" />
        <span class="field__hint">Доменное имя из сертификата сервера. Если его нет — оставьте пустым.</span>
      </div>
      <div class="row2">
        <div class="field">
          <label for="srv-user" class="field__label">Логин</label>
          <InputText id="srv-user" v-model="form.username" autocomplete="off" spellcheck="false" />
        </div>
        <div class="field">
          <label for="srv-pass" class="field__label">Пароль</label>
          <Password v-model="form.password" input-id="srv-pass" :feedback="false" toggle-mask fluid autocomplete="new-password"
            :placeholder="hasPassword ? 'Сохранён. Оставьте пустым' : ''" />
        </div>
      </div>

      <button type="button" class="disclose" :aria-expanded="advanced" aria-controls="srv-adv" @click="advanced = !advanced">
        {{ advanced ? 'Скрыть дополнительные параметры' : 'Дополнительные параметры' }}
      </button>
      <div v-show="advanced" id="srv-adv" class="adv">
        <label class="switch">
          <ToggleSwitch v-model="form.quic" input-id="srv-quic" />
          <span><span class="switch__label">HTTP/3</span><span class="switch__note">Включайте, только если так сказано в настройках сервера.</span></span>
        </label>
        <label class="switch">
          <ToggleSwitch v-model="form.antiDpi" input-id="srv-dpi" />
          <span><span class="switch__label">Маскировка от блокировок (anti-DPI)</span><span class="switch__note">Помогает, если провайдер мешает подключению к серверу.</span></span>
        </label>
        <div class="field">
          <label for="srv-cert" class="field__label">Сертификат сервера</label>
          <Textarea id="srv-cert" v-model="form.certificate" rows="4" spellcheck="false" class="mono" placeholder="-----BEGIN CERTIFICATE-----" />
          <span class="field__hint">Нужен, только если сервер использует свой сертификат. Обычно приходит вместе со ссылкой.</span>
        </div>
      </div>
    </div>

    <div class="card">
      <h2 class="card__title">Если сервер недоступен</h2>
      <div class="choice" role="radiogroup" aria-label="Если сервер недоступен">
        <label :class="['choice__opt', { 'choice__opt--on': form.onFailure === 'block' }]">
          <input v-model="form.onFailure" type="radio" value="block" class="choice__radio" />
          <span class="choice__text">
            <span class="choice__label">Не открывать сайты из списка</span>
            <span class="choice__note">Рекомендуется. Сайты подождут, пока сервер снова заработает.</span>
          </span>
        </label>
        <label :class="['choice__opt', { 'choice__opt--on': form.onFailure === 'direct' }]">
          <input v-model="form.onFailure" type="radio" value="direct" class="choice__radio" />
          <span class="choice__text">
            <span class="choice__label">Открывать их напрямую</span>
            <span class="choice__note">Сайты откроются без VPN, если смогут.</span>
          </span>
        </label>
      </div>
    </div>

    <Message v-if="error" severity="error" :closable="false">{{ error }}</Message>

    <div class="savebar">
      <div class="savebar__in">
        <span class="savebar__text" aria-live="polite">{{ blocker && dirty ? blocker : dirty ? 'Есть несохранённые изменения' : profile?.endpoint ? 'Всё сохранено' : 'Вставьте ссылку на сервер' }}</span>
        <Button label="Сохранить" :loading="saving" :disabled="!dirty || !!blocker || saving" @click="submit" />
      </div>
    </div>
  </section>
</template>
