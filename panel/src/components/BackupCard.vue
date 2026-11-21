<script setup lang="ts">
// Резервная копия настроек: файл JSON с настройками, правилами и своими списками. Пароли серверов и вход в панель —
// по желанию, зашифрованы паролем копии (Argon2id + ChaCha20-Poly1305 на роутере). Восстановление проверяет всё до записи.
import { computed, ref } from 'vue'
import Button from 'primevue/button'
import Password from 'primevue/password'
import ToggleSwitch from 'primevue/toggleswitch'
import { Download, Upload } from 'lucide-vue-next'
import { manage, type BackupFile } from '../api'
import { loadAll, notify, revision } from '../store'
import { t } from '../i18n'

const MIN = 8
const withSecrets = ref(false)
const exportPass = ref('')
const exporting = ref(false)
const exportReady = computed(() => !withSecrets.value || exportPass.value.length >= MIN)

async function download() {
  exporting.value = true
  try {
    const r = await manage.exportBackup(withSecrets.value, withSecrets.value ? exportPass.value : undefined)
    if (r.status !== 200 || !r.body.backup) { notify.show('error', t('Не получилось'), r.body.error?.message); return }
    const blob = new Blob([JSON.stringify(r.body.backup, null, 2) + '\n'], { type: 'application/json' })
    const a = document.createElement('a')
    a.href = URL.createObjectURL(blob)
    a.download = `mi-lumruri-backup-${new Date().toISOString().slice(0, 10)}.json`
    a.click()
    URL.revokeObjectURL(a.href)
    exportPass.value = ''
    notify.show('success', t('Копия скачана'), withSecrets.value ? t('Пароли в ней зашифрованы паролем копии') : undefined)
  } finally {
    exporting.value = false
  }
}

const file = ref<HTMLInputElement | null>(null)
const picked = ref<BackupFile | null>(null)
const pickedName = ref('')
const restorePass = ref('')
const restoring = ref(false)

async function pick(e: Event) {
  const f = (e.target as HTMLInputElement).files?.[0]
  ;(e.target as HTMLInputElement).value = ''
  if (!f) return
  try {
    const b = JSON.parse(await f.text()) as BackupFile
    if (b?.format !== 'mi-lumruri-backup') throw new Error('format')
    picked.value = b
    pickedName.value = f.name
    restorePass.value = ''
  } catch {
    notify.show('error', t('Это не копия настроек Mi Lumruri'), f.name)
  }
}

async function restore(skipSecrets = false) {
  if (!picked.value || !revision.value) return
  restoring.value = true
  try {
    const r = await manage.restoreBackup(revision.value, picked.value, skipSecrets ? undefined : restorePass.value || undefined, skipSecrets)
    if (r.status !== 200) { notify.show('error', t('Не восстановлено'), r.body.error?.message); return }
    const w = r.body.warnings ?? []
    notify.show(w.length ? 'info' : 'success', t('Настройки восстановлены и применяются'), w.length ? w.join('; ') : undefined)
    picked.value = null
    await loadAll()
  } finally {
    restoring.value = false
  }
}
const created = computed(() => (picked.value?.created ? new Date(picked.value.created * 1000).toLocaleString() : ''))
</script>

<template>
  <div class="setblock" role="group" aria-labelledby="backup-title">
    <span class="setrow__text">
      <span id="backup-title" class="setrow__title">{{ t('Резервная копия настроек') }}</span>
      <span class="setrow__desc">{{ t('Настройки, правила и свои списки — в один файл. Пригодится после сброса роутера или при переезде на другой BE7000') }}</span>
    </span>
    <label class="backup__row">
      <ToggleSwitch v-model="withSecrets" input-id="backup-secrets" />
      <span>{{ t('С паролями серверов и входом в панель') }}</span>
    </label>
    <div v-if="withSecrets" class="backup__row">
      <Password v-model="exportPass" input-id="backup-pass" :feedback="false" toggle-mask :placeholder="t('Пароль копии')" autocomplete="new-password" />
      <span class="field__hint">{{ t('Не короче {n} символов. Без него пароли из копии не восстановить', { n: MIN }) }}</span>
    </div>
    <div class="backup__actions">
      <Button :label="t('Скачать копию')" :loading="exporting" :disabled="!exportReady || exporting" @click="download">
        <template #icon><Download :size="16" class="p-button-icon-left" aria-hidden="true" /></template>
      </Button>
      <Button :label="t('Восстановить из файла…')" severity="secondary" variant="outlined" :disabled="restoring" @click="file?.click()">
        <template #icon><Upload :size="16" class="p-button-icon-left" aria-hidden="true" /></template>
      </Button>
      <input ref="file" type="file" accept="application/json,.json" class="backup__file" @change="pick" />
    </div>
    <div v-if="picked" class="backup__confirm" role="alert">
      <span>{{ t('Восстановить из «{f}» ({d})? Текущие настройки будут заменены', { f: pickedName, d: created }) }}</span>
      <template v-if="picked.secrets">
        <Password v-model="restorePass" input-id="restore-pass" :feedback="false" toggle-mask :placeholder="t('Пароль копии')" autocomplete="off" />
        <span class="field__hint">{{ t('В копии есть пароли серверов и вход в панель. Без пароля копии восстановятся только настройки') }}</span>
      </template>
      <div class="backup__actions">
        <Button :label="t('Восстановить')" :loading="restoring" :disabled="restoring || (!!picked.secrets && !restorePass)" @click="restore(false)" />
        <Button v-if="picked.secrets" :label="t('Без паролей')" severity="secondary" variant="outlined" :disabled="restoring" @click="restore(true)" />
        <Button :label="t('Отмена')" severity="secondary" variant="text" :disabled="restoring" @click="picked = null" />
      </div>
    </div>
  </div>
</template>

<style scoped>
.backup__row { display: flex; flex-wrap: wrap; align-items: center; gap: 0.5rem; }
.backup__actions { display: flex; flex-wrap: wrap; align-items: center; gap: 0.5rem; }
.backup__file { display: none; }
.backup__confirm { display: flex; flex-direction: column; gap: 0.5rem; padding: 0.75rem; border: 1px solid var(--line, currentColor); border-radius: 0.5rem; }
</style>
