<script setup lang="ts">
import { computed, nextTick, ref, watch } from 'vue'
import Button from 'primevue/button'
import InputText from 'primevue/inputtext'
import Message from 'primevue/message'
import Password from 'primevue/password'
import Textarea from 'primevue/textarea'
import ToggleSwitch from 'primevue/toggleswitch'
import { Check, ChevronDown, ClipboardPaste, Minus } from 'lucide-vue-next'
import { manage, type Endpoint } from '../api'
import { emptyProfileForm, formToProfile, formToSecret, profileToForm, type ProfileForm } from '../manage'
import { parseServer } from '../serverConfig'
import { config, hasPassword, loadSecrets, notify, profile, save, simple, tunnel } from '../store'
import Segmented from '../components/Segmented.vue'

const emit = defineEmits<{ navigate: [tab: 'sites'] }>()

const PROFILE_ID = 'tt'
const formFrom = (): ProfileForm => (profile.value ? profileToForm(profile.value) : { ...emptyProfileForm(), id: PROFILE_ID, name: 'Мой сервер' })
const form = ref<ProfileForm>(formFrom())
const pristine = ref(JSON.stringify(form.value))
const dirty = computed(() => JSON.stringify(form.value) !== pristine.value)
watch(profile, () => { if (!dirty.value) { form.value = formFrom(); pristine.value = JSON.stringify(form.value) } })
const firstTime = computed(() => !profile.value?.endpoint)
const advanced = ref(false)
const FAILURE = [{ value: 'block' as const, label: 'Не открывать' }, { value: 'direct' as const, label: 'Открывать напрямую' }]

// ---- вставка конфигурации ----
const pasted = ref('')
interface Preview { rows: { label: string; value: string | null }[]; warnings: string[] }
const parsed = ref<Preview | { error: string } | null>(null)
watch(pasted, (t) => { if (!t.trim()) parsed.value = null })
function recognize() {
  const t = pasted.value
  if (!t.trim()) { parsed.value = null; return }
  const r = parseServer(t)
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
  if (r.password) f.password = r.password
  if (r.name && !profile.value) f.name = r.name
  parsed.value = {
    rows: [
      { label: 'Сервер', value: e.server ? `${e.server}${e.port ? `:${e.port}` : ''}` : null },
      { label: 'Имя сервера', value: e.sni ?? null },
      { label: 'Логин', value: e.username ?? null },
      { label: 'Пароль', value: r.password ? 'есть' : null },
      { label: 'Сертификат', value: e.certificate ? 'есть' : null },
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
const needPassword = computed(() => !hasPassword.value && !form.value.password)
const blocker = computed(() => {
  const f = form.value
  if (!f.server.trim() || !f.username.trim()) return 'Укажите адрес сервера и логин — или вставьте ссылку.'
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
  <section class="sect" aria-label="Сервер VPN">
    <Message v-if="done && nothingSelected" severity="success" :closable="false">
      <div class="next">
        <span>Сервер сохранён. Теперь отметьте сайты, которые открывать через VPN.</span>
        <Button label="Выбрать сайты" size="small" @click="emit('navigate', 'sites')" />
      </div>
    </Message>

    <div class="cols">
      <div class="cols__side">
        <div class="card">
          <div>
            <h2 class="card__title">{{ firstTime ? 'Быстрая настройка' : 'Сменить сервер' }}</h2>
            <p class="card__sub">Вставьте ссылку <span class="num">tt://</span> или файл конфигурации клиента — поля заполнятся сами</p>
          </div>
          <div class="field">
            <label for="paste" class="sr-only">Ссылка или конфигурация сервера</label>
            <Textarea id="paste" v-model="pasted" rows="5" spellcheck="false" placeholder="tt://?… или содержимое client.toml" class="mono" @paste="onPaste" />
          </div>
          <Button label="Распознать" severity="secondary" variant="outlined" class="self-start" :disabled="!pasted.trim()" @click="recognize">
            <template #icon><ClipboardPaste :size="16" class="p-button-icon-left" aria-hidden="true" /></template>
          </Button>
          <Message v-if="parsed && 'error' in parsed" severity="error" :closable="false">Не получилось прочитать: {{ parsed.error }}.</Message>
          <template v-else-if="parsed">
            <div class="preview" aria-live="polite">
              <p class="preview__title">Распознано — проверьте поля и сохраните</p>
              <dl class="preview__list">
                <div v-for="r in parsed.rows" :key="r.label" :class="['preview__row', { 'preview__row--none': !r.value }]">
                  <dt><Check v-if="r.value" :size="14" aria-hidden="true" /><Minus v-else :size="14" aria-hidden="true" />{{ r.label }}</dt>
                  <dd class="num">{{ r.value ?? 'нет' }}</dd>
                </div>
              </dl>
            </div>
            <Message v-for="w in parsed.warnings" :key="w" severity="warn" :closable="false">Не поддерживается: {{ w }}.</Message>
          </template>
        </div>

        <div v-if="!firstTime" class="card conn">
          <h2 class="card__title">Подключение</h2>
          <div :class="['pill', `pill--${tunnel.tone}`, 'pill--lg']"><span class="pill__dot" aria-hidden="true" /><span class="pill__text">{{ tunnel.title }}</span></div>
          <p v-if="tunnel.detail" class="hint">{{ tunnel.detail }}</p>
        </div>
      </div>

      <form class="card" @submit.prevent="submit">
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
            <span class="field__hint">{{ hasPassword ? 'Пароль сохранён на роутере и сюда не возвращается. Введите новый, чтобы сменить.' : 'Хранится только на роутере' }}</span>
          </div>
        </div>

        <div class="field">
          <span id="srv-fail-label" class="field__label">Если сервер недоступен, сайты из списка</span>
          <Segmented v-model="form.onFailure" :options="FAILURE" label="Если сервер недоступен" name="onfail" />
          <span class="field__hint">{{ form.onFailure === 'block' ? 'Рекомендуется. Сайты подождут, пока сервер снова заработает.' : 'Сайты откроются без VPN, если смогут.' }}</span>
        </div>

        <button type="button" class="disclose" :aria-expanded="advanced" aria-controls="srv-adv" @click="advanced = !advanced">
          <ChevronDown :size="16" :class="['disclose__icon', { 'disclose__icon--open': advanced }]" aria-hidden="true" />
          Дополнительные параметры
        </button>
        <div v-show="advanced" id="srv-adv" class="adv">
          <label class="setrow">
            <span class="setrow__text"><span class="setrow__title">HTTP/3</span><span class="setrow__desc">Включайте, только если так сказано в настройках сервера</span></span>
            <ToggleSwitch v-model="form.quic" input-id="srv-quic" />
          </label>
          <label class="setrow">
            <span class="setrow__text"><span class="setrow__title">Маскировка от блокировок (anti-DPI)</span><span class="setrow__desc">Помогает, если провайдер мешает подключению к серверу.</span></span>
            <ToggleSwitch v-model="form.antiDpi" input-id="srv-dpi" />
          </label>
          <div class="field">
            <label for="srv-cert" class="field__label">Сертификат сервера</label>
            <Textarea id="srv-cert" v-model="form.certificate" rows="4" spellcheck="false" class="mono" placeholder="-----BEGIN CERTIFICATE-----" />
            <span class="field__hint">Нужен, только если сервер использует свой сертификат. Обычно приходит вместе со ссылкой.</span>
          </div>
        </div>

        <Message v-if="error" severity="error" :closable="false">{{ error }}</Message>
        <div class="formfoot">
          <span class="formfoot__text" aria-live="polite">{{ blocker && dirty ? blocker : dirty ? 'Есть несохранённые изменения' : profile?.endpoint ? 'Всё сохранено' : 'Вставьте ссылку на сервер' }}</span>
          <Button type="submit" label="Сохранить" :loading="saving" :disabled="!dirty || !!blocker || saving" />
        </div>
      </form>
    </div>
  </section>
</template>
