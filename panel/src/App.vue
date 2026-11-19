<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue'
import Button from 'primevue/button'
import ConfirmDialog from 'primevue/confirmdialog'
import Message from 'primevue/message'
import Select from 'primevue/select'
import Skeleton from 'primevue/skeleton'
import Toast from 'primevue/toast'
import { useToast } from 'primevue/usetoast'
import { api, manage, onAuthLost, setCsrf, type ApiResult, type ConfigResponse, type ManageResponse, type PreviewResponse, type SaveResponse, type SessionResponse } from './api'
import type { LoginStage } from './auth'
import LoginView from './LoginView.vue'
import ManageView from './ManageView.vue'
import type { Config } from './api'
import { defaultForm, fieldForIssue, ruleKey, saveOutcome, toRequest, type DraftForm, type Field, type SaveOutcome } from './draft'
import { tunnelState } from './route'
import RuleForm from './RuleForm.vue'
import PreviewView from './PreviewView.vue'

const toast = useToast()

const cfg = ref<ApiResult<ConfigResponse> | null>(null)
const form = ref<DraftForm | null>(null)
const result = ref<ApiResult<PreviewResponse> | null>(null)
const busy = ref(false)
const stale = ref(false)
const checkedKey = ref<string | null>(null)
const saving = ref(false)
const saveRes = ref<ApiResult<SaveResponse> | null>(null)
const outcome = ref<SaveOutcome | null>(null)
/** checking — спрашиваем контроллер о сессии; login — нужен вход; ready — вошли. */
const auth = ref<'checking' | 'login' | 'ready' | 'error'>('checking')
const authError = ref<string | null>(null)
const loginStage = ref<LoginStage>('password')
const clockTrusted = ref(true)
const totpOn = ref(true)
const lost = ref(false)
/** Последний ответ /status: из него строится полоса состояния туннеля. */
const svc = ref<ManageResponse | null>(null)
type Tab = 'edit' | 'rules' | 'devices' | 'profiles' | 'categories' | 'dns' | 'status'
const tab = ref<Tab>('edit')
const TABS: [Tab, string][] = [['edit', 'Новое правило'], ['rules', 'Правила'], ['devices', 'Устройства и сети'], ['profiles', 'Профили'], ['categories', 'Категории'], ['dns', 'DNS, реклама, Zapret'], ['status', 'Состояние']]

const config = computed<Config | null>(() => cfg.value?.body.config ?? null)

/** Число в навигации справа от раздела: сколько правил, устройств, категорий. */
function navCount(t: Tab): number | null {
  const c = config.value
  if (!c) return null
  if (t === 'rules') return c.rules.length
  if (t === 'devices') return c.devices.length
  if (t === 'categories') return c.categories?.length ?? 0
  return null
}
const navOptions = computed(() => TABS.map(([value, label]) => {
  const n = navCount(value)
  return { value, label: n === null ? label : `${label} (${n})` }
}))

const tunnel = computed(() => tunnelState(svc.value, config.value))

function onChanged(c: Config, revision: string) {
  if (cfg.value) cfg.value = { status: 200, body: { ...cfg.value.body, ok: true, config: c, revision, issues: [] } }
}

function resetData() {
  cfg.value = null
  form.value = null
  result.value = null
  saveRes.value = null
  outcome.value = null
  checkedKey.value = null
  svc.value = null
}

async function checkSession() {
  auth.value = 'checking'
  const r = await api.session()
  if (r.status === 200 && r.body.authenticated) {
    setCsrf(r.body.csrf ?? null)
    totpOn.value = r.body.totp !== false
    auth.value = 'ready'
    await load()
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
  await load()
}

async function logout() {
  await api.logout()
  setCsrf(null)
  resetData()
  loginStage.value = 'password'
  auth.value = 'login'
}

// сессия истекла или отозвана во время работы: возвращаемся ко входу, черновик правила теряется
onAuthLost(() => {
  resetData()
  lost.value = true
  loginStage.value = 'password'
  auth.value = 'login'
})

async function loadStatus() {
  const r = await manage.status()
  svc.value = r.body
}

async function load(keepForm = false) {
  cfg.value = await api.config()
  const c = cfg.value.body.config
  if (!keepForm || !form.value) form.value = c && cfg.value.body.ok ? defaultForm(c) : null
  result.value = null
  checkedKey.value = null
  saveRes.value = null
  outcome.value = null
  if (cfg.value.body.ok) void loadStatus()
}

async function check() {
  if (!form.value) return
  busy.value = true
  try {
    const key = ruleKey(form.value)
    result.value = await api.preview(toRequest(form.value))
    stale.value = false
    checkedKey.value = result.value.status === 200 ? key : null
    saveRes.value = null
    outcome.value = null
  } finally {
    busy.value = false
  }
}

const canSave = computed(
  () => !!form.value && !!cfg.value?.body.revision && checkedKey.value !== null && checkedKey.value === ruleKey(form.value) && !saving.value,
)

async function save() {
  if (!form.value || !cfg.value?.body.revision || !canSave.value) return
  saving.value = true
  try {
    saveRes.value = await api.saveRule(cfg.value.body.revision, toRequest(form.value).rule)
    outcome.value = saveOutcome(saveRes.value)
    const b = saveRes.value.body
    if (outcome.value.kind === 'saved' && b.config && b.revision) {
      cfg.value = { status: 200, body: { ...cfg.value.body, ok: true, config: b.config, revision: b.revision, issues: [] } }
      checkedKey.value = null
      toast.add({ severity: 'success', summary: 'Правило сохранено', detail: `${outcome.value.message} Чтобы оно заработало, примените настройки в разделе «Состояние».`, life: 6000 })
    }
    if (outcome.value.kind === 'conflict') checkedKey.value = null
  } finally {
    saving.value = false
  }
}

watch(form, () => { if (result.value) stale.value = true }, { deep: true })

const errors = computed(() => {
  const out: Partial<Record<Field, string[]>> = {}
  const src = saveRes.value?.status === 422 ? saveRes.value.body.issues : result.value?.status === 422 ? result.value.body.issues : []
  for (const i of src) {
    const f = fieldForIssue(i.path)
    if (f) (out[f] ??= []).push(i.message)
  }
  return out
})

const saveHint = computed(() => {
  if (outcome.value?.kind === 'saved') return outcome.value.message
  if (outcome.value) return 'Правило не сохранено.'
  if (!result.value) return 'Сначала проверьте правило: сохранить можно только проверенное.'
  if (checkedKey.value === null) return 'Правило не прошло проверку — исправьте его и проверьте снова.'
  if (form.value && checkedKey.value !== ruleKey(form.value)) return 'Правило изменилось после проверки — проверьте его ещё раз.'
  return 'Проверка пройдена, правило можно сохранить.'
})

function go(t: Tab) {
  tab.value = t
  if (t === 'status') void loadStatus()
}

onMounted(() => checkSession())
</script>

<template>
  <Toast position="bottom-right" />
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
        <strong>Панель недоступна.</strong> {{ authError }}. Проверьте, что служба роутера запущена, и повторите.
      </Message>
      <Button label="Повторить" class="gate__retry" @click="checkSession()" />
    </div>
    <template v-else>
      <Message v-if="lost" severity="warn" :closable="false" class="gate__lost">Сессия завершилась. Войдите снова.</Message>
      <LoginView :initial-stage="loginStage" :clock-trusted="clockTrusted" @done="onLoggedIn" />
    </template>
  </div>

  <div v-else class="shell">
    <aside class="rail">
      <div class="rail__in">
      <div class="rail__brand">
        <span class="rail__name">mi-trusttunnel</span>
        <span class="rail__sub">Xiaomi BE7000</span>
      </div>
      <nav v-if="config" class="rail__nav" aria-label="Разделы">
        <button v-for="[id, label] in TABS" :key="id" type="button" :class="['rail__item', { 'rail__item--on': tab === id }]"
          :aria-current="tab === id ? 'page' : undefined" @click="go(id)">
          <span>{{ label }}</span>
          <span v-if="navCount(id) !== null" class="rail__count">{{ navCount(id) }}</span>
        </button>
      </nav>
      <p class="rail__mode" :title="totpOn ? 'Вход: пароль и второй фактор (TOTP или recovery-код)' : 'Вход только паролем. TOTP включается на роутере: mitt-boot.sh auth reset-totp, затем auth confirm'">
        {{ totpOn ? 'Вход с паролем и TOTP' : 'Вход только по паролю' }}
      </p>
      </div>
    </aside>

    <div class="main">
      <header class="strip">
        <div :class="['strip__state', `strip__state--${tunnel.tone}`]" role="status" aria-live="polite">
          <span class="strip__dot" aria-hidden="true" />
          <span class="strip__title">{{ tunnel.title }}</span>
          <span v-if="tunnel.detail" class="strip__detail">{{ tunnel.detail }}</span>
        </div>
        <div class="strip__side">
          <span v-if="cfg?.body.revision" class="strip__rev" title="Ревизия сохранённых настроек">Ревизия <span class="num">{{ cfg.body.revision.slice(0, 12) }}</span></span>
          <Button label="Выйти" severity="secondary" variant="text" size="small" @click="logout" />
        </div>
      </header>

      <div v-if="config" class="mnav">
        <label for="mnav-select" class="sr-only">Раздел</label>
        <Select input-id="mnav-select" :model-value="tab" :options="navOptions" option-label="label" option-value="value" fluid
          @update:model-value="(v: Tab) => go(v)" />
      </div>

      <main class="content">
        <div v-if="!cfg" class="loading" aria-busy="true">
          <span class="sr-only">Читаю настройки</span>
          <Skeleton height="1.75rem" width="14rem" />
          <Skeleton height="4rem" />
          <Skeleton height="4rem" />
        </div>
        <section v-else-if="!cfg.body.ok || !cfg.body.config" class="sect">
          <Message severity="error" :closable="false">
            <strong>Настройки не загружены.</strong>
            <span v-if="cfg.body.error"> {{ cfg.body.error.message }}.</span>
            <ul v-if="cfg.body.issues.length" class="issues">
              <li v-for="i in cfg.body.issues" :key="i.path + i.code"><code>{{ i.path }}</code> {{ i.message }}</li>
            </ul>
          </Message>
          <Button label="Загрузить снова" class="mt" @click="load()" />
        </section>

        <ManageView v-else-if="cfg.body.revision && tab !== 'edit'" :key="tab" :tab="tab" :config="cfg.body.config"
          :revision="cfg.body.revision" :status="svc" @changed="onChanged" @reload="load(true)" @status="(s) => (svc = s)"
          @navigate="go" />

        <section v-else-if="tab === 'edit' && form" class="sect" aria-labelledby="edit-title">
          <h1 id="edit-title" class="sect__title">Новое правило</h1>
          <p class="sect__lead">Выберите, чей трафик и куда он идёт, и решите, что с ним делать. Перед сохранением панель покажет, как изменится маршрут.</p>
          <div class="editor">
            <RuleForm v-model="form" :config="cfg.body.config" :errors="errors" :busy="busy" @submit="check" @navigate="go" />
            <div class="editor__side">
              <PreviewView :result="result" :stale="stale" />
              <div class="save">
                <Button :label="saving ? 'Сохраняю…' : 'Сохранить правило'" :loading="saving" :disabled="!canSave" @click="save" />
                <p class="save__hint" aria-live="polite">{{ saveHint }}</p>
                <Message v-if="outcome && outcome.kind !== 'saved'" severity="error" :closable="false" class="save__msg">
                  {{ outcome.message }}
                  <Button v-if="outcome.kind === 'conflict'" label="Обновить настройки" size="small" severity="secondary" class="save__reload" @click="load(true)" />
                </Message>
              </div>
            </div>
          </div>
        </section>
      </main>

      <footer class="foot">
        Чтение, проверка и сохранение доступны только после входа. Изменения принимаются только со страницы панели (Origin и CSRF-токен).
        Применяет настройки служба роутера (mi-tt-admin) по заявке из раздела «Состояние»; пароли профилей панель только записывает и не показывает.
      </footer>
    </div>
  </div>
</template>
