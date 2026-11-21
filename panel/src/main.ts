import { createApp } from 'vue'
import PrimeVue from 'primevue/config'
import ConfirmationService from 'primevue/confirmationservice'
import ToastService from 'primevue/toastservice'
import App from './App.vue'
import { MittPreset } from './theme'
import { t } from './i18n'
import './style.css'

createApp(App)
  .use(PrimeVue, {
    ripple: false,
    theme: {
      preset: MittPreset,
      // стили PrimeVue — в слое primevue: собственные правила панели (вне слоёв) всегда сильнее
      options: { darkModeSelector: 'system', cssLayer: { name: 'primevue', order: 'primevue' } },
    },
    locale: {
      accept: t('Да'), reject: t('Нет'), emptyMessage: t('Нет вариантов'), emptyFilterMessage: t('Ничего не найдено'),
      passwordPrompt: t('Введите пароль'), showPassword: t('Показать пароль'), hidePassword: t('Скрыть пароль'), // secret-scan: allow подписи интерфейса, не пароли
      aria: { close: t('Закрыть') },
    },
  })
  .use(ToastService)
  .use(ConfirmationService)
  .mount('#app')
