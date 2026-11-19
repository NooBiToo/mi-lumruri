<script setup lang="ts">
// «Настройки изменены вручную» или «не проходят проверку»: простой экран не может их показать, предлагаем привести
// к простому виду. `broken` — сохранённые настройки не разобрать вовсе (например, от другой версии): простые
// собираются с нуля, сервер VPN придётся вставить заново.
import { computed, ref } from 'vue'
import Button from 'primevue/button'
import Message from 'primevue/message'
import { useConfirm } from 'primevue/useconfirm'
import { build, config, configIssues, knownDevicesNow, loadAll, recoveryBase, save } from '../store'
import { defaultSimple } from '../simple'

const props = defineProps<{ reason: string; broken?: boolean }>()
const confirm = useConfirm()
const busy = ref(false)
const error = ref<string | null>(null)
const invalid = computed(() => props.broken || configIssues.value.length > 0)
const base = () => recoveryBase(props.broken ? null : config.value, configIssues.value)
const keepsServer = computed(() => !!base().profiles[0]?.endpoint)

function ask() {
  confirm.require({
    header: 'Привести к простому виду?',
    message: (invalid.value ? 'Сохранённые настройки будут заменены простыми' : 'Настройки, сделанные вручную, будут заменены простыми')
      + ': все устройства, сайты пока не выбраны. '
      + (keepsServer.value ? 'Сервер VPN сохранится. ' : 'Сервер VPN придётся вставить заново на экране «Сервер». ')
      + 'Затем отметьте нужные сайты заново.',
    acceptLabel: 'Привести к простому виду', rejectLabel: 'Отмена',
    acceptProps: { severity: 'danger' }, rejectProps: { severity: 'secondary', variant: 'text' },
    accept: () => void reset(),
  })
}

async function reset() {
  const next = build(defaultSimple(), knownDevicesNow(), base())
  if (typeof next === 'string') { error.value = next; return }
  busy.value = true
  try {
    const r = await save(next)
    if (r.ok && props.broken) await loadAll()
  } finally { busy.value = false }
}
</script>

<template>
  <div class="manual">
    <h2 class="manual__title">{{ broken ? 'Настройки на роутере не читаются' : invalid ? 'Настройки не проходят проверку' : 'Настройки изменены вручную' }}</h2>
    <p v-if="broken">Панель не может разобрать сохранённые настройки ({{ reason }}). Их можно заменить простыми.</p>
    <p v-else-if="invalid">Панель не может их показать ({{ reason }}).</p>
    <p v-else>Их меняли не в этой панели, поэтому здесь их не показать ({{ reason }}).</p>
    <p class="muted">Пока вы ничего не меняете, роутер продолжает работать по последним применённым настройкам.</p>
    <Message v-if="error" severity="error" :closable="false">{{ error }}</Message>
    <Button label="Привести к простому виду" severity="secondary" variant="outlined" class="self-start" :loading="busy" @click="ask" />
  </div>
</template>
