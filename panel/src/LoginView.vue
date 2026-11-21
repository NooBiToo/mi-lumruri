<script setup lang="ts">
import { ref } from 'vue'
import Button from 'primevue/button'
import InputText from 'primevue/inputtext'
import Message from 'primevue/message'
import Password from 'primevue/password'
import { api, setCsrf, type SessionResponse } from './api'
import { loginMessage, nextStage, secondFactor, type LoginStage } from './auth'
import { t } from './i18n'
import LangSwitch from './components/LangSwitch.vue'

const props = defineProps<{ initialStage: LoginStage; clockTrusted: boolean }>()
const emit = defineEmits<{ done: [session: SessionResponse] }>()

const stage = ref<LoginStage>(props.initialStage)
const mode = ref<'totp' | 'recovery'>(props.clockTrusted ? 'totp' : 'recovery')
const clockTrusted = ref(props.clockTrusted)
const password = ref('')
const code = ref('')
const error = ref<string | null>(null)
const busy = ref(false)

async function submitPassword() {
  if (!password.value || busy.value) return
  busy.value = true
  error.value = null
  try {
    const r = await api.login(password.value)
    error.value = loginMessage(r)
    const next = nextStage('password', r)
    if (next === 'done') {
      password.value = ''
      setCsrf(r.body.csrf ?? null)
      emit('done', r.body)
    } else if (next === 'second_factor') {
      // пароль в памяти страницы не держим дольше необходимого
      password.value = ''
      clockTrusted.value = r.body.clock_trusted !== false
      mode.value = clockTrusted.value ? 'totp' : 'recovery'
      stage.value = 'second_factor'
    }
  } finally {
    busy.value = false
  }
}

async function submitCode() {
  const f = secondFactor(mode.value, code.value)
  if (!f) {
    error.value = mode.value === 'totp' ? t('Введите 6 цифр из приложения.') : t('Recovery-код — 16 символов (например, ABCD-EFGH-2345-6723).')
    return
  }
  if (busy.value) return
  busy.value = true
  error.value = null
  try {
    const r = await api.second(f)
    error.value = loginMessage(r)
    if (r.body.error?.code === 'clock_untrusted') {
      clockTrusted.value = false
      mode.value = 'recovery'
    }
    const next = nextStage('second_factor', r)
    code.value = ''
    if (next === 'done') {
      setCsrf(r.body.csrf ?? null)
      emit('done', r.body)
    } else if (next === 'password') {
      stage.value = 'password'
    }
  } finally {
    busy.value = false
  }
}

function switchMode() {
  mode.value = mode.value === 'totp' ? 'recovery' : 'totp'
  code.value = ''
  error.value = null
}
</script>

<template>
  <section class="gate__card login" aria-labelledby="login-title">
    <h1 id="login-title" class="login__title">{{ stage === 'password' ? t('Пароль администратора') : t('Второй шаг входа') }}</h1>

    <form v-if="stage === 'password'" class="login__form" @submit.prevent="submitPassword">
      <label for="login-password" class="field__label">{{ t('Пароль') }}</label>
      <Password v-model="password" input-id="login-password" :feedback="false" toggle-mask fluid :disabled="busy"
        :input-props="{ autocomplete: 'current-password', required: true, autofocus: true }" :invalid="!!error" />
      <Button type="submit" :label="busy ? t('Проверяю…') : t('Войти')" :loading="busy" :disabled="busy || !password" fluid />
    </form>

    <form v-else class="login__form" @submit.prevent="submitCode">
      <template v-if="mode === 'totp'">
        <label for="login-code" class="field__label">{{ t('Код из приложения-аутентификатора') }}</label>
        <InputText id="login-code" v-model="code" class="num login__code" inputmode="numeric" autocomplete="one-time-code" maxlength="7" pattern="[0-9 ]*"
          required autofocus fluid :disabled="busy" :invalid="!!error" />
      </template>
      <template v-else>
        <label for="login-recovery" class="field__label">{{ t('Одноразовый recovery-код') }}</label>
        <InputText id="login-recovery" v-model="code" class="num" autocomplete="off" autocapitalize="characters" spellcheck="false" maxlength="24"
          required autofocus fluid :disabled="busy" :invalid="!!error" />
      </template>
      <Button type="submit" :label="busy ? t('Проверяю…') : t('Подтвердить код')" :loading="busy" :disabled="busy || !code" fluid />
      <Button type="button" variant="link" class="login__alt" :disabled="busy" :label="mode === 'totp' ? t('Войти recovery-кодом') : t('Войти кодом из приложения')"
        @click="switchMode" />
      <Message v-if="!clockTrusted" severity="warn" size="small" :closable="false">{{ t('Часы роутера не синхронизированы: код из приложения сейчас не принимается.') }}</Message>
    </form>

    <div aria-live="assertive">
      <Message v-if="error" severity="error" :closable="false" class="login__error">{{ error }}</Message>
    </div>
    <p class="login__hint">{{ t('Пароль задаётся только на самом роутере командой') }} <code>mi-tt-admin auth init</code>. {{ t('Там же его можно сбросить.') }}</p>
    <LangSwitch compact />
  </section>
</template>
