<script setup lang="ts">
import { onBeforeUnmount, onMounted, ref } from 'vue'
import Button from 'primevue/button'
import ConfirmDialog from 'primevue/confirmdialog'
import Message from 'primevue/message'
import Select from 'primevue/select'
import Skeleton from 'primevue/skeleton'
import Toast from 'primevue/toast'
import { useToast } from 'primevue/usetoast'
import { api, onAuthLost, setCsrf, type SessionResponse } from './api'
import type { LoginStage } from './auth'
import LoginView from './LoginView.vue'
import { config, loadAll, loadError, loadStatus, notify, reset, serverReady, tunnel } from './store'
import StatusView from './views/StatusView.vue'
import SitesView from './views/SitesView.vue'
import DevicesView from './views/DevicesView.vue'
import ServerView from './views/ServerView.vue'
import MoreView from './views/MoreView.vue'

const toast = useToast()
notify.show = (kind, text, detail) => toast.add({ severity: kind, summary: text, detail, life: kind === 'error' ? 8000 : 4000 })

/** checking — спрашиваем контроллер о сессии; login — нужен вход; ready — вошли. */
const auth = ref<'checking' | 'login' | 'ready' | 'error'>('checking')
const authError = ref<string | null>(null)
const loginStage = ref<LoginStage>('password')
const clockTrusted = ref(true)
const totpOn = ref(true)
const lost = ref(false)
const loading = ref(false)

type Tab = 'status' | 'sites' | 'devices' | 'server' | 'more'
const TABS: { value: Tab; label: string }[] = [
  { value: 'status', label: 'Состояние' },
  { value: 'sites', label: 'Сайты' },
  { value: 'devices', label: 'Устройства' },
  { value: 'server', label: 'Сервер' },
  { value: 'more', label: 'Дополнительно' },
]
const fromHash = (): Tab | null => TABS.find((t) => `#${t.value}` === location.hash)?.value ?? null
const tab = ref<Tab>(fromHash() ?? 'status')

function go(t: Tab) {
  tab.value = t
  if (location.hash !== `#${t}`) history.replaceState(null, '', `#${t}`)
  window.scrollTo({ top: 0 })
  if (t === 'status') void loadStatus()
}
const onHash = () => { const t = fromHash(); if (t) tab.value = t }

async function enter() {
  loading.value = true
  try {
    await loadAll()
  } finally {
    loading.value = false
  }
  // без сервера VPN остальное не заработает: сначала экран «Сервер»
  if (config.value && !serverReady.value) go('server')
}

async function checkSession() {
  auth.value = 'checking'
  const r = await api.session()
  if (r.status === 200 && r.body.authenticated) {
    setCsrf(r.body.csrf ?? null)
    totpOn.value = r.body.totp !== false
    auth.value = 'ready'
    await enter()
  } else if (r.status === 200) {
    loginStage.value = r.body.stage === 'second_factor' ? 'second_factor' : 'password'
    clockTrusted.value = r.body.clock_trusted !== false
    auth.value = 'login'
  } else {
    authError.value = r.body.error?.message ?? `контроллер ответил ${r.status}`
    auth.value = 'error'
  }
}

async function onLoggedIn(s: SessionResponse) {
  lost.value = false
  totpOn.value = s.totp !== false
  auth.value = 'ready'
  await enter()
}

async function logout() {
  await api.logout()
  setCsrf(null)
  reset()
  loginStage.value = 'password'
  auth.value = 'login'
}

// сессия истекла или отозвана во время работы: возвращаемся ко входу
onAuthLost(() => {
  reset()
  lost.value = true
  loginStage.value = 'password'
  auth.value = 'login'
})

// строка состояния вверху: опрос службы, пока панель открыта
let timer: number | undefined
onMounted(() => {
  void checkSession()
  addEventListener('hashchange', onHash)
  timer = window.setInterval(() => { if (auth.value === 'ready' && config.value && !document.hidden) void loadStatus() }, 10000)
})
onBeforeUnmount(() => { removeEventListener('hashchange', onHash); clearInterval(timer) })
</script>

<template>
  <Toast position="bottom-center" />
  <ConfirmDialog />

  <!-- вход и сбои до входа: узкая колонка по центру -->
  <div v-if="auth !== 'ready'" class="gate">
    <div class="gate__brand">
      <span class="gate__name">mi-trusttunnel</span>
      <span class="gate__sub">Вход в панель роутера</span>
    </div>
    <div v-if="auth === 'checking'" class="gate__card" aria-busy="true">
      <span class="sr-only">Проверяю вход</span>
      <Skeleton height="1rem" width="40%" />
      <Skeleton height="2.5rem" class="gate__skel" />
      <Skeleton height="2.5rem" />
    </div>
    <div v-else-if="auth === 'error'" class="gate__card">
      <Message severity="error" :closable="false">
        <strong>Панель недоступна.</strong> {{ authError }}. Проверьте, что роутер включён, и повторите.
      </Message>
      <Button label="Повторить" class="gate__retry" @click="checkSession()" />
    </div>
    <template v-else>
      <Message v-if="lost" severity="warn" :closable="false" class="gate__lost">Сессия завершилась. Войдите снова.</Message>
      <LoginView :initial-stage="loginStage" :clock-trusted="clockTrusted" @done="onLoggedIn" />
    </template>
  </div>

  <div v-else class="app">
    <header class="top">
      <div class="top__in">
        <div class="top__row">
          <span class="top__brand">mi-trusttunnel</span>
          <div :class="['state', `state--${tunnel.tone}`]" role="status" aria-live="polite">
            <span class="state__dot" aria-hidden="true" />
            <span class="state__title">{{ tunnel.title }}</span>
          </div>
          <Button label="Выйти" severity="secondary" variant="text" size="small" class="top__out" @click="logout" />
        </div>
        <nav class="tabs" aria-label="Разделы">
          <button v-for="t in TABS" :key="t.value" type="button" :class="['tabs__item', { 'tabs__item--on': tab === t.value }]"
            :aria-current="tab === t.value ? 'page' : undefined" @click="go(t.value)">{{ t.label }}</button>
        </nav>
        <div class="mnav">
          <label for="mnav-select" class="sr-only">Раздел</label>
          <Select input-id="mnav-select" :model-value="tab" :options="TABS" option-label="label" option-value="value" fluid
            @update:model-value="(v: Tab) => go(v)" />
        </div>
      </div>
    </header>

    <main class="page">
      <div v-if="loading || (!config && !loadError)" class="loading" aria-busy="true">
        <span class="sr-only">Читаю настройки</span>
        <Skeleton height="2rem" width="14rem" />
        <Skeleton height="6rem" />
        <Skeleton height="6rem" />
      </div>
      <section v-else-if="!config" class="sect">
        <Message severity="error" :closable="false"><strong>Настройки не загружены.</strong> {{ loadError }}.</Message>
        <Button label="Загрузить снова" class="self-start" @click="enter()" />
      </section>
      <StatusView v-else-if="tab === 'status'" @navigate="go" />
      <SitesView v-else-if="tab === 'sites'" @navigate="go" />
      <DevicesView v-else-if="tab === 'devices'" @navigate="go" />
      <ServerView v-else-if="tab === 'server'" @navigate="go" />
      <MoreView v-else :totp="totpOn" @navigate="go" />
    </main>
  </div>
</template>
