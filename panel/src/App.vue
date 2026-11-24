<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref, watch, type Component } from 'vue'
import Button from 'primevue/button'
import ConfirmDialog from 'primevue/confirmdialog'
import Message from 'primevue/message'
import Skeleton from 'primevue/skeleton'
import ToggleSwitch from 'primevue/toggleswitch'
import Toast from 'primevue/toast'
import { Activity, Check, ShieldCheck, CircleAlert, Globe, LayoutDashboard, LoaderCircle, LogOut, MonitorSmartphone, Package, Server, SlidersHorizontal, Waypoints } from 'lucide-vue-next'
import { useToast } from 'primevue/usetoast'
import { usePrimeVue } from 'primevue/config'
import { lang, t } from './i18n'
import { api, onAuthLost, setCsrf, type SessionResponse } from './api'
import type { LoginStage } from './auth'
import LoginView from './LoginView.vue'
import { broken, config, configIssues, issuesText, loadAll, loadError, loadStatus, notify, reset, serverReady, service, simple, tunnel, updateAvailable } from './store'
import { flushPending, resetSaveStatus, saveLabel, saveStatus } from './autosave'
import { toggleVpn, vpnAvailable, vpnBusy } from './vpn'
import StatusView from './views/StatusView.vue'
import SitesView from './views/SitesView.vue'
import DevicesView from './views/DevicesView.vue'
import ServerView from './views/ServerView.vue'
import MoreView from './views/MoreView.vue'
import DiagView from './views/DiagView.vue'
import ZapretView from './views/ZapretView.vue'
import ModulesView from './views/ModulesView.vue'
import HealthChips from './components/HealthChips.vue'
import ManualBanner from './views/ManualBanner.vue'

const toast = useToast()
// подписи встроенных элементов PrimeVue (диалог, пароль, списки) — на языке интерфейса
const primevue = usePrimeVue()
watch(lang, () => {
  // подписи меняются на месте: тип PrimeVueLocaleOptions требует все поля, а нужны только эти
  Object.assign(primevue.config.locale ?? {}, {
    accept: t('Да'), reject: t('Нет'), emptyMessage: t('Нет вариантов'), emptyFilterMessage: t('Ничего не найдено'),
    passwordPrompt: t('Введите пароль'), showPassword: t('Показать пароль'), hidePassword: t('Скрыть пароль'), // secret-scan: allow подписи интерфейса, не пароли
    aria: { ...primevue.config.locale?.aria, close: t('Закрыть') },
  })
}, { immediate: true })
notify.show = (kind, text, detail) => toast.add({ severity: kind, summary: text, detail, life: kind === 'error' ? 8000 : 4000 })

/** checking — спрашиваем контроллер о сессии; login — нужен вход; ready — вошли. */
const auth = ref<'checking' | 'login' | 'ready' | 'error'>('checking')
const authError = ref<string | null>(null)
const loginStage = ref<LoginStage>('password')
const clockTrusted = ref(true)
const totpOn = ref(true)
const lost = ref(false)
const loading = ref(false)

type Tab = 'status' | 'sites' | 'devices' | 'server' | 'zapret' | 'modules' | 'diag' | 'more'
/** inBar — пункт нижней панели телефона; остальные открываются со страницы «Ещё». */
const TABS = computed<{ value: Tab; label: string; short: string; icon: Component; inBar?: false }[]>(() => [
  { value: 'status', label: t('Обзор'), short: t('Обзор'), icon: LayoutDashboard },
  { value: 'sites', label: t('Сайты'), short: t('Сайты'), icon: Globe },
  { value: 'devices', label: t('Устройства'), short: t('Устройства'), icon: MonitorSmartphone },
  { value: 'server', label: t('Сервер'), short: t('Сервер'), icon: Server },
  { value: 'zapret', label: 'Zapret', short: 'Zapret', icon: ShieldCheck, inBar: false },
  { value: 'modules', label: t('Модули'), short: t('Модули'), icon: Package, inBar: false },
  { value: 'diag', label: t('Диагностика'), short: t('Проверка'), icon: Activity, inBar: false },
  { value: 'more', label: t('Настройки'), short: t('Ещё'), icon: SlidersHorizontal },
])
/** #more/<вкладка> — «Настройки»; #hosts (прежний адрес «Своих DNS-записей») — их вкладка «Сеть и DNS». */
const fromHash = (): Tab | null => {
  if (location.hash === '#hosts') { history.replaceState(null, '', '#more/dns'); return 'more' }
  if (location.hash.startsWith('#more/')) return 'more'
  return TABS.value.find((x) => `#${x.value}` === location.hash)?.value ?? null
}
const tab = ref<Tab>(fromHash() ?? 'status')
const title = computed(() => TABS.value.find((x) => x.value === tab.value)?.label ?? '')
const saveText = computed(() => saveLabel(saveStatus, !!service.value?.apply_pending))

function go(t: Tab) {
  tab.value = t
  if (location.hash !== `#${t}` && !(t === 'more' && location.hash.startsWith('#more/'))) history.replaceState(null, '', `#${t}`)
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
    authError.value = r.body.error?.message ?? t('контроллер ответил {s}', { s: r.status })
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
  await flushPending()
  await api.logout()
  setCsrf(null)
  reset()
  resetSaveStatus()
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
      <span class="gate__name">Mi Lumruri</span>
      <span class="gate__sub">{{ t('Вход в панель роутера') }}</span>
    </div>
    <div v-if="auth === 'checking'" class="gate__card" aria-busy="true">
      <span class="sr-only">{{ t('Проверяю вход') }}</span>
      <Skeleton height="1rem" width="40%" />
      <Skeleton height="2.5rem" class="gate__skel" />
      <Skeleton height="2.5rem" />
    </div>
    <div v-else-if="auth === 'error'" class="gate__card">
      <Message severity="error" :closable="false">
        <strong>{{ t('Панель недоступна.') }}</strong> {{ authError }}. {{ t('Проверьте, что роутер включён, и повторите.') }}
      </Message>
      <Button :label="t('Повторить')" class="gate__retry" @click="checkSession()" />
    </div>
    <template v-else>
      <Message v-if="lost" severity="warn" :closable="false" class="gate__lost">{{ t('Сессия завершилась. Войдите снова.') }}</Message>
      <LoginView :initial-stage="loginStage" :clock-trusted="clockTrusted" @done="onLoggedIn" />
    </template>
  </div>

  <div v-else class="app">
    <a href="#main" class="skip">{{ t('К содержимому') }}</a>
    <aside class="side" :aria-label="t('Разделы')">
      <div class="side__brand">
        <span class="side__mark" aria-hidden="true"><Waypoints :size="20" :stroke-width="1.75" /></span>
        <span class="side__name">Mi Lumruri</span>
      </div>
      <nav class="side__nav">
        <a v-for="t in TABS" :key="t.value" :href="`#${t.value}`" :class="['nav', { 'nav--on': tab === t.value }]" :title="t.label"
          :aria-current="tab === t.value ? 'page' : undefined" @click.prevent="go(t.value)">
          <component :is="t.icon" class="nav__icon" :size="18" :stroke-width="1.5" aria-hidden="true" />
          <span class="nav__label">{{ t.label }}</span>
          <span v-if="t.value === 'more' && updateAvailable" class="nav__dot" aria-hidden="true" />
        </a>
      </nav>
    </aside>

    <div class="main">
      <header class="top">
        <h1 class="top__title">{{ title }}</h1>
        <div v-show="tab !== 'status'" :class="['pill', `pill--${tunnel.tone}`]" role="status" aria-live="polite">
          <span class="pill__dot" aria-hidden="true" />
          <span class="pill__text">{{ tunnel.title }}</span>
        </div>
        <div v-if="saveStatus.tone !== 'idle'" :class="['save', `save--${saveStatus.tone}`]" aria-live="polite">
          <LoaderCircle v-if="saveStatus.tone === 'saving'" class="save__icon spin" :size="16" aria-hidden="true" />
          <Check v-else-if="saveStatus.tone === 'saved'" class="save__icon" :size="16" aria-hidden="true" />
          <CircleAlert v-else-if="saveStatus.tone === 'error' || saveStatus.tone === 'blocked'" class="save__icon" :size="16" aria-hidden="true" />
          <span v-else class="save__dot" aria-hidden="true" />
          <span class="save__text" :title="saveText">{{ saveText }}</span>
          <button v-if="saveStatus.action" type="button" class="save__act" @click="saveStatus.action.run()">{{ saveStatus.action.label }}</button>
        </div>
        <HealthChips v-if="config && tab !== 'status'" class="top__health" @open="go('status')" />
        <div class="top__end">
          <label v-if="vpnAvailable && simple" class="master" :title="simple.enabled ? t('Выключить VPN') : t('Включить VPN')">
            <span class="master__label">VPN</span>
            <ToggleSwitch :model-value="simple.enabled" input-id="vpn-master" :disabled="vpnBusy" :aria-label="simple.enabled ? t('Выключить VPN') : t('Включить VPN')"
              @update:model-value="toggleVpn()" />
          </label>
          <button type="button" class="out" :title="t('Выйти')" @click="logout"><LogOut :size="18" aria-hidden="true" /><span class="out__text">{{ t('Выйти') }}</span></button>
        </div>
      </header>

      <main id="main" class="page" tabindex="-1">
        <div v-if="loading || (!config && !loadError)" class="loading" aria-busy="true">
          <span class="sr-only">{{ t('Читаю настройки') }}</span>
          <Skeleton height="5rem" border-radius="14px" />
          <Skeleton height="16rem" border-radius="14px" />
        </div>
        <!-- настройки не разобрать (например, от другой версии): заменить простыми -->
        <section v-else-if="broken" class="sect">
          <ManualBanner broken :reason="issuesText(configIssues)" />
        </section>
        <section v-else-if="!config" class="sect">
          <Message severity="error" :closable="false"><strong>{{ t('Настройки не загружены.') }}</strong> {{ loadError }}.</Message>
          <Button :label="t('Загрузить снова')" class="self-start" @click="enter()" />
        </section>
        <StatusView v-else-if="tab === 'status'" @navigate="go" />
        <SitesView v-else-if="tab === 'sites'" @navigate="go" />
        <DevicesView v-else-if="tab === 'devices'" @navigate="go" />
        <ServerView v-else-if="tab === 'server'" @navigate="go" />
        <ZapretView v-else-if="tab === 'zapret'" @navigate="go" />
        <ModulesView v-else-if="tab === 'modules'" />
        <DiagView v-else-if="tab === 'diag'" />
        <MoreView v-else :totp="totpOn" @navigate="go" />
      </main>
    </div>

    <nav class="tabbar" :aria-label="t('Разделы')">
      <a v-for="t in TABS.filter((x) => x.inBar !== false)" :key="t.value" :href="`#${t.value}`"
        :class="['tabbar__item', { 'tabbar__item--on': tab === t.value || (t.value === 'more' && TABS.some((x) => x.value === tab && x.inBar === false)) }]"
        :aria-current="tab === t.value ? 'page' : undefined" :aria-label="t.label" @click.prevent="go(t.value)">
        <component :is="t.icon" :size="20" :stroke-width="1.5" aria-hidden="true" />
        <span>{{ t.short }}</span>
        <span v-if="t.value === 'more' && updateAvailable" class="nav__dot nav__dot--bar" aria-hidden="true" />
      </a>
    </nav>
  </div>
</template>
