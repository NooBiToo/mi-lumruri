<script setup lang="ts">
import { ref } from 'vue'
import { api, setCsrf, type SessionResponse } from './api'
import { loginMessage, nextStage, secondFactor, type LoginStage } from './auth'

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
    if (nextStage('password', r) === 'second_factor') {
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
    error.value = mode.value === 'totp' ? 'Введите 6 цифр из приложения.' : 'Recovery-код — 16 символов (например, ABCD-EFGH-2345-6723).'
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
  <section class="login" aria-labelledby="login-title">
    <h2 id="login-title">Вход в панель</h2>
    <form v-if="stage === 'password'" class="login__form" @submit.prevent="submitPassword">
      <label for="login-password">Пароль</label>
      <input id="login-password" v-model="password" type="password" autocomplete="current-password" required autofocus :disabled="busy" />
      <button type="submit" :disabled="busy || !password">{{ busy ? 'Проверяю…' : 'Далее' }}</button>
    </form>
    <form v-else class="login__form" @submit.prevent="submitCode">
      <template v-if="mode === 'totp'">
        <label for="login-code">Код из приложения-аутентификатора</label>
        <input id="login-code" v-model="code" inputmode="numeric" autocomplete="one-time-code" maxlength="7" pattern="[0-9 ]*" required autofocus :disabled="busy" />
      </template>
      <template v-else>
        <label for="login-recovery">Одноразовый recovery-код</label>
        <input id="login-recovery" v-model="code" autocomplete="off" autocapitalize="characters" spellcheck="false" maxlength="24" required autofocus :disabled="busy" />
      </template>
      <button type="submit" :disabled="busy || !code">{{ busy ? 'Проверяю…' : 'Войти' }}</button>
      <button type="button" class="login__alt" :disabled="busy" @click="switchMode">
        {{ mode === 'totp' ? 'Войти recovery-кодом' : 'Войти кодом из приложения' }}
      </button>
      <p v-if="!clockTrusted" class="login__note">Часы роутера не синхронизированы: код из приложения сейчас не принимается.</p>
    </form>
    <p v-if="error" class="login__error" role="alert">{{ error }}</p>
    <p class="login__hint">Учётные данные задаются только на самом роутере: <code>mi-tt-admin auth init</code>. Восстановление — там же.</p>
  </section>
</template>
