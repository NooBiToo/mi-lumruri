<script setup lang="ts">
// «Настройки изменены вручную»: простой экран не может их показать, предлагаем привести к простому виду.
import { ref } from 'vue'
import Button from 'primevue/button'
import Message from 'primevue/message'
import { useConfirm } from 'primevue/useconfirm'
import { build, knownDevicesNow, save } from '../store'
import { defaultSimple } from '../simple'

defineProps<{ reason: string }>()
const confirm = useConfirm()
const busy = ref(false)
const error = ref<string | null>(null)

function ask() {
  confirm.require({
    header: 'Привести к простому виду?',
    message: 'Настройки, сделанные вручную, будут заменены простыми: все устройства, сайты пока не выбраны. Сервер VPN, '
      + 'блокировка рекламы и Zapret сохранятся. Затем отметьте нужные сайты заново.',
    acceptLabel: 'Привести к простому виду', rejectLabel: 'Отмена',
    acceptProps: { severity: 'danger' }, rejectProps: { severity: 'secondary', variant: 'text' },
    accept: () => void reset(),
  })
}

async function reset() {
  const next = build(defaultSimple(), knownDevicesNow())
  if (typeof next === 'string') { error.value = next; return }
  busy.value = true
  try { await save(next) } finally { busy.value = false }
}
</script>

<template>
  <div class="manual">
    <h2 class="manual__title">Настройки изменены вручную</h2>
    <p>Их меняли не в этой панели, поэтому здесь их не показать ({{ reason }}).</p>
    <p class="muted">Пока вы ничего не меняете, роутер продолжает работать по ним.</p>
    <Message v-if="error" severity="error" :closable="false">{{ error }}</Message>
    <Button label="Привести к простому виду" severity="secondary" variant="outlined" class="self-start" :loading="busy" @click="ask" />
  </div>
</template>
