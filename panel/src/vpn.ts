// Общий выключатель VPN (верхняя строка и экран «Обзор»): то же, что прежняя кнопка «Выключить/Включить VPN».

import { computed, ref } from 'vue'
import { build, knownDevicesNow, notify, save, serverReady, simple } from './store'

export const vpnBusy = ref(false)
/** Выключатель доступен: сервер настроен и настройки простого вида. */
export const vpnAvailable = computed(() => serverReady.value && !!simple.value)

export async function toggleVpn(): Promise<void> {
  const s = simple.value
  if (!s || vpnBusy.value) return
  const cfg = build({ ...s, enabled: !s.enabled }, knownDevicesNow())
  if (typeof cfg === 'string') { notify.show('error', 'Не получилось', cfg); return }
  vpnBusy.value = true
  try {
    // выключенный VPN выключает и обход блокировок: правила с Zapret тоже выключаются, всё идёт напрямую
    if ((await save(cfg, '')).ok) {
      notify.show('success', s.enabled ? 'VPN выключен' : 'VPN включён, применяю на роутере',
        s.enabled ? (s.rest === 'zapret' ? 'Обход блокировок (Zapret) тоже выключен: все сайты открываются напрямую.' : 'Все сайты открываются напрямую.') : undefined)
    }
  } finally { vpnBusy.value = false }
}
