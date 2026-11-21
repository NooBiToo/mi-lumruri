// Общий выключатель VPN (верхняя строка и экран «Обзор»): то же, что прежняя кнопка «Выключить/Включить VPN».

import { computed, ref } from 'vue'
import { build, knownDevicesNow, notify, save, serverReady, simple } from './store'
import { hasZapretSites } from './status'
import { t } from './i18n'

export const vpnBusy = ref(false)
/** Выключатель доступен: сервер настроен и настройки простого вида. */
export const vpnAvailable = computed(() => serverReady.value && !!simple.value)

export async function toggleVpn(): Promise<void> {
  const s = simple.value
  if (!s || vpnBusy.value) return
  const cfg = build({ ...s, enabled: !s.enabled }, knownDevicesNow())
  if (typeof cfg === 'string') { notify.show('error', t('Не получилось'), cfg); return }
  vpnBusy.value = true
  try {
    // выключенный VPN: остальные сайты — напрямую; «сайты с обходом блокировок» по-прежнему с Zapret (simple.ts)
    if ((await save(cfg, '')).ok) {
      notify.show('success', s.enabled ? t('VPN выключен') : t('VPN включён, применяю на роутере'),
        s.enabled ? (hasZapretSites(s) ? t('Сайты открываются напрямую, сайты с обходом блокировок — по-прежнему с Zapret.')
          : s.rest === 'zapret' ? t('Обход блокировок (Zapret) тоже выключен: все сайты открываются напрямую.') : t('Все сайты открываются напрямую.')) : undefined)
    }
  } finally { vpnBusy.value = false }
}
