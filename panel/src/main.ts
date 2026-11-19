import { createApp } from 'vue'
import PrimeVue from 'primevue/config'
import ConfirmationService from 'primevue/confirmationservice'
import ToastService from 'primevue/toastservice'
import App from './App.vue'
import { MittPreset } from './theme'
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
      accept: 'Да', reject: 'Нет', emptyMessage: 'Нет вариантов', emptyFilterMessage: 'Ничего не найдено',
      passwordPrompt: 'Введите пароль', showPassword: 'Показать пароль', hidePassword: 'Скрыть пароль', // secret-scan: allow подписи интерфейса, не пароли
      aria: { close: 'Закрыть' },
    },
  })
  .use(ToastService)
  .use(ConfirmationService)
  .mount('#app')
