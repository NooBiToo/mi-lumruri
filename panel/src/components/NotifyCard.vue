<script setup lang="ts">
// Уведомления в Telegram: токен бота и чат хранятся только на роутере (secrets.json); отправляет служба — через туннель,
// если он поднят, иначе напрямую. Проверка — заявка службе, итог приходит в GET /notify (last).
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import Button from 'primevue/button'
import InputText from 'primevue/inputtext'
import Password from 'primevue/password'
import { ChevronDown, Send } from 'lucide-vue-next'
import { manage, type NotifyResponse } from '../api'
import { notify } from '../store'
import { lang, t } from '../i18n'

const EVENTS = computed(() => [
  { id: 'tunnel', label: t('Туннель упал или снова работает') },
  { id: 'failover', label: t('Переключение на запасной сервер и обратно') },
  { id: 'update', label: t('Обновления пакета: вышла новая версия, установлена, откат') },
  { id: 'subscription', label: t('Подписка TrustTunnel: сбой или новые параметры') },
  { id: 'boot', label: t('Роутер загрузился') },
])
const DEFAULT_EVENTS = ['tunnel', 'failover', 'update', 'subscription']

const st = ref<NotifyResponse | null>(null)
const editing = ref(false)
const token = ref('')
const chat = ref('')
const events = ref<string[]>([...DEFAULT_EVENTS])
const busy = ref(false)
const help = ref(false)
const testing = ref(false)
const testResult = ref<{ ok: boolean; text: string } | null>(null)

async function load() {
  const r = await manage.notifyState()
  if (r.status !== 200) return
  st.value = r.body
  if (!editing.value) {
    chat.value = r.body.chat_id ?? ''
    events.value = r.body.configured ? [...r.body.events] : [...DEFAULT_EVENTS]
  }
}
const configured = computed(() => !!st.value?.configured)
const formReady = computed(() => (configured.value || token.value.trim().length > 0) && chat.value.trim().length > 0)

async function store(body: Parameters<typeof manage.setNotify>[0], done: string) {
  busy.value = true
  try {
    const r = await manage.setNotify(body)
    if (r.status !== 200) { notify.show('error', t('Не сохранено'), r.body.error?.message); return false }
    notify.show('success', done)
    token.value = ''
    editing.value = false
    await load()
    return true
  } finally {
    busy.value = false
  }
}
const save = () => store({ telegram_token: token.value.trim() || undefined, chat_id: chat.value.trim(), events: events.value, lang: lang.value }, t('Уведомления сохранены'))
const disable = () => store({ disable: true }, t('Уведомления выключены'))
async function toggleEvent(id: string, on: boolean) {
  events.value = on ? [...new Set([...events.value, id])] : events.value.filter((e) => e !== id)
  if (configured.value && !editing.value) await store({ chat_id: chat.value, events: events.value, lang: lang.value }, t('Уведомления сохранены'))
}

let timer: number | undefined
async function test() {
  testing.value = true
  testResult.value = null
  const before = st.value?.last?.at ?? 0
  const r = await manage.testNotify()
  if (r.status !== 202) { testing.value = false; notify.show('error', t('Не получилось'), r.body.error?.message); return }
  let n = 0
  const poll = async () => {
    await load()
    const last = st.value?.last
    if (last && last.at > before && !st.value?.test_pending) {
      testing.value = false
      testResult.value = last.ok ? { ok: true, text: t('Сообщение отправлено — проверьте Telegram') } : { ok: false, text: t('Не отправлено: {e}', { e: last.error ?? '' }) }
      return
    }
    if (++n > 20) { testing.value = false; testResult.value = { ok: false, text: t('Служба не ответила. Проверьте, что она запущена') }; return }
    timer = window.setTimeout(() => void poll(), 2000)
  }
  timer = window.setTimeout(() => void poll(), 2000)
}

onMounted(() => void load())
onBeforeUnmount(() => clearTimeout(timer))
</script>

<template>
  <div class="setblock" role="group" aria-labelledby="notify-title">
    <span class="setrow__text">
      <span id="notify-title" class="setrow__title">{{ t('Уведомления в Telegram') }}</span>
      <span class="setrow__desc">{{ t('Роутер напишет в Telegram, если туннель упадёт, сменится сервер или выйдет обновление. Сообщения идут через VPN, когда туннель работает, иначе напрямую') }}</span>
    </span>
    <span v-if="configured && !editing" class="adblock__state">
      <span class="led led--ok" aria-hidden="true" />
      <span class="meta">{{ t('Включены, чат {c}', { c: st?.chat_id ?? '' }) }}</span>
    </span>

    <template v-if="!configured || editing">
      <button type="button" class="disclose" :aria-expanded="help" aria-controls="notify-help" @click="help = !help">
        <ChevronDown :size="16" :class="['disclose__icon', { 'disclose__icon--open': help }]" aria-hidden="true" />{{ t('Как получить токен и чат') }}
      </button>
      <ol v-show="help" id="notify-help" class="setrow__desc notify__help">
        <li>{{ t('В Telegram откройте @BotFather, отправьте /newbot и скопируйте токен бота') }}</li>
        <li>{{ t('Напишите своему новому боту любое сообщение — иначе он не сможет вам писать') }}</li>
        <li>{{ t('Свой числовой id узнайте у @userinfobot. Для группы добавьте бота в неё; id группы начинается с минуса') }}</li>
      </ol>
      <label class="field" for="notify-token">
        <span class="field__label">{{ t('Токен бота') }}</span>
        <Password v-model="token" input-id="notify-token" :feedback="false" toggle-mask autocomplete="off"
          :placeholder="configured ? t('Не меняется, если оставить пустым') : '123456789:AA…'" />
      </label>
      <label class="field" for="notify-chat">
        <span class="field__label">{{ t('Чат') }}</span>
        <InputText id="notify-chat" v-model="chat" placeholder="123456789" autocomplete="off" spellcheck="false" />
      </label>
    </template>

    <fieldset class="notify__events">
      <legend class="field__label">{{ t('О чём сообщать') }}</legend>
      <label v-for="e in EVENTS" :key="e.id" class="notify__event">
        <input type="checkbox" :checked="events.includes(e.id)" :disabled="busy" @change="toggleEvent(e.id, ($event.target as HTMLInputElement).checked)" />
        <span>{{ e.label }}</span>
      </label>
    </fieldset>

    <div class="notify__actions">
      <template v-if="!configured || editing">
        <Button :label="t('Сохранить')" :loading="busy" :disabled="!formReady || busy" @click="save" />
        <Button v-if="editing" :label="t('Отмена')" severity="secondary" variant="text" @click="editing = false; token = ''" />
      </template>
      <template v-else>
        <Button :label="t('Отправить проверку')" :loading="testing" :disabled="testing" @click="test">
          <template #icon><Send :size="16" class="p-button-icon-left" aria-hidden="true" /></template>
        </Button>
        <Button :label="t('Изменить')" severity="secondary" variant="outlined" @click="editing = true" />
        <Button :label="t('Выключить')" severity="secondary" variant="text" :disabled="busy" @click="disable" />
      </template>
    </div>
    <span v-if="testResult" :class="['meta', { 'adblock__state--bad': !testResult.ok }]" aria-live="polite">{{ testResult.text }}</span>
  </div>
</template>

<style scoped>
.notify__events { border: 0; padding: 0; margin: 0; display: flex; flex-direction: column; gap: 0.35rem; }
.notify__event { display: flex; align-items: center; gap: 0.5rem; }
.notify__actions { display: flex; flex-wrap: wrap; align-items: center; gap: 0.5rem; }
.notify__help { margin: 0; padding-left: 1.25rem; }
</style>
