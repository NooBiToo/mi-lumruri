<script setup lang="ts">
// Запасной сервер TrustTunnel: служба переключается на него, если основной не подключается дольше 2 минут, и
// возвращается, когда основной снова отвечает. Пароль хранится только на роутере (backup_password).
import { computed, ref, watch } from 'vue'
import Button from 'primevue/button'
import InputText from 'primevue/inputtext'
import Password from 'primevue/password'
import Textarea from 'primevue/textarea'
import ToggleSwitch from 'primevue/toggleswitch'
import { manage, type Endpoint } from '../api'
import { emptyProfileForm, formToProfile, profileToForm, type ProfileForm } from '../manage'
import { parseServer } from '../serverConfig'
import { config, hasBackupPassword, loadSecrets, notify, profile, save, service } from '../store'
import { t } from '../i18n'

const backup = computed<Endpoint | undefined>(() => profile.value?.backup)
const toForm = (): ProfileForm => (backup.value ? profileToForm({ id: 'b', name: 'b', kind: 'trusttunnel', on_failure: 'block', endpoint: backup.value }) : emptyProfileForm())
const open = ref(false)
const form = ref<ProfileForm>(toForm())
watch(backup, () => { if (!open.value) form.value = toForm() })
const active = computed(() => (service.value?.service as { endpoint?: string } | undefined)?.endpoint === 'backup')

const pasted = ref('')
const parseError = ref<string | null>(null)
function recognize() {
  parseError.value = null
  const r = parseServer(pasted.value)
  if ('error' in r) { parseError.value = r.error; return }
  const e = r.endpoint
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
}

const saving = ref(false)
const error = ref<string | null>(null)
const blocker = computed(() => {
  if (!profile.value?.endpoint) return t('Сначала сохраните основной сервер.')
  if (!form.value.server.trim() || !form.value.username.trim()) return t('Укажите адрес сервера и логин — или вставьте ссылку.')
  if (!form.value.password && !hasBackupPassword.value) return t('Укажите пароль.')
  return null
})
async function submit() {
  const c = config.value
  const p = profile.value
  if (!c || !p || blocker.value) return
  const built = formToProfile({ ...form.value, id: p.id, name: p.name })
  if (typeof built === 'string' || !built.endpoint) { error.value = typeof built === 'string' ? built : t('Не получилось'); return }
  saving.value = true
  error.value = null
  try {
    // пароль — до настроек: заявка на применение уже застанет его, и рендер сразу напишет client-backup.toml
    if (form.value.password) {
      const s = await manage.setSecret(p.id, { backup_password: form.value.password })
      if (s.status !== 200) { error.value = t('Пароль не записан: {e}', { e: s.body.error?.message ?? String(s.status) }); return }
    }
    const r = await save({ ...c, profiles: [{ ...p, backup: built.endpoint }, ...c.profiles.slice(1)] }, t('Запасной сервер сохранён'))
    if (!r.ok) { error.value = r.message; return }
    form.value.password = ''
    pasted.value = ''
    open.value = false
    await loadSecrets()
  } finally {
    saving.value = false
  }
}
async function remove() {
  const c = config.value
  const p = profile.value
  if (!c || !p) return
  const next = { ...p }
  delete next.backup
  const r = await save({ ...c, profiles: [next, ...c.profiles.slice(1)] }, t('Запасной сервер удалён'))
  if (!r.ok) { notify.show('error', t('Не получилось'), r.message); return }
  await manage.setSecret(p.id, { backup_password: '' })
  form.value = emptyProfileForm()
  open.value = false
  await loadSecrets()
}
</script>

<template>
  <div class="card">
    <div class="card__head">
      <div>
        <h2 class="card__title">{{ t('Запасной сервер') }}</h2>
        <p class="card__sub">{{ t('Если основной сервер не подключается дольше 2 минут, роутер переключится на запасной, а когда основной снова ответит — вернётся на него') }}</p>
      </div>
      <Button v-if="!open" :label="backup ? t('Изменить') : t('Добавить')" severity="secondary" variant="outlined" size="small" @click="open = true; form = toForm()" />
    </div>
    <p v-if="backup && !open" class="meta">
      <span class="num">{{ backup.server }}:{{ backup.port }}</span> · {{ backup.username }}
      <template v-if="active"> · <strong>{{ t('сейчас подключён запасной') }}</strong></template>
      <template v-else-if="!hasBackupPassword"> · {{ t('нет пароля — переключение не работает') }}</template>
    </p>
    <form v-if="open" class="backup" @submit.prevent="submit">
      <div class="field">
        <label for="bk-paste" class="field__label">{{ t('Ссылка или конфигурация запасного сервера') }}</label>
        <Textarea id="bk-paste" v-model="pasted" rows="3" spellcheck="false" class="mono" :placeholder="t('tt://?… или содержимое client.toml')" />
        <Button :label="t('Распознать')" severity="secondary" variant="outlined" size="small" class="self-start" :disabled="!pasted.trim()" @click="recognize" />
        <span v-if="parseError" class="field__error">{{ t('Не получилось прочитать: {e}.', { e: parseError }) }}</span>
      </div>
      <div class="row2">
        <div class="field">
          <label for="bk-host" class="field__label">{{ t('Адрес сервера') }}</label>
          <InputText id="bk-host" v-model="form.server" spellcheck="false" class="num" />
        </div>
        <div class="field field--port">
          <label for="bk-port" class="field__label">{{ t('Порт') }}</label>
          <InputText id="bk-port" v-model="form.port" inputmode="numeric" class="num" />
        </div>
      </div>
      <div class="field">
        <label for="bk-sni" class="field__label">{{ t('Имя сервера') }}</label>
        <InputText id="bk-sni" v-model="form.sni" spellcheck="false" />
      </div>
      <div class="row2">
        <div class="field">
          <label for="bk-user" class="field__label">{{ t('Логин') }}</label>
          <InputText id="bk-user" v-model="form.username" autocomplete="off" spellcheck="false" />
        </div>
        <div class="field">
          <label for="bk-pass" class="field__label">{{ t('Пароль') }}</label>
          <Password v-model="form.password" input-id="bk-pass" :feedback="false" toggle-mask fluid autocomplete="new-password"
            :placeholder="hasBackupPassword ? t('Сохранён. Оставьте пустым') : ''" />
        </div>
      </div>
      <label class="setrow">
        <span class="setrow__text"><span class="setrow__title">HTTP/3</span></span>
        <ToggleSwitch v-model="form.quic" input-id="bk-quic" />
      </label>
      <label class="setrow">
        <span class="setrow__text"><span class="setrow__title">{{ t('Маскировка от блокировок (anti-DPI)') }}</span></span>
        <ToggleSwitch v-model="form.antiDpi" input-id="bk-dpi" />
      </label>
      <span v-if="error" class="field__error">{{ error }}</span>
      <div class="backup__foot">
        <Button v-if="backup" :label="t('Удалить запасной сервер')" severity="secondary" variant="text" size="small" @click="remove" />
        <span class="backup__spacer" />
        <Button :label="t('Отмена')" severity="secondary" variant="text" size="small" @click="open = false" />
        <Button type="submit" :label="t('Сохранить')" size="small" :loading="saving" :disabled="!!blocker || saving" />
      </div>
      <span v-if="blocker" class="field__hint">{{ blocker }}</span>
    </form>
  </div>
</template>

<style scoped>
.backup { display: flex; flex-direction: column; gap: 0.75rem; }
.backup__foot { display: flex; align-items: center; gap: 0.5rem; flex-wrap: wrap; }
.backup__spacer { flex: 1; }
</style>
