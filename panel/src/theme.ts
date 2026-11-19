// Тема PrimeVue: Aura с палитрой панели. Основной цвет — кобальт туннеля, поверхности — «бумага» и «чернила».
// Значения совпадают с переменными в style.css; меняйте их вместе.

import { definePreset } from '@primeuix/themes'
import type Aura from '@primeuix/themes/aura'
import base from '@primeuix/themes/aura/base'
import button from '@primeuix/themes/aura/button'
import confirmdialog from '@primeuix/themes/aura/confirmdialog'
import dialog from '@primeuix/themes/aura/dialog'
import inputtext from '@primeuix/themes/aura/inputtext'
import message from '@primeuix/themes/aura/message'
import password from '@primeuix/themes/aura/password'
import skeleton from '@primeuix/themes/aura/skeleton'
import textarea from '@primeuix/themes/aura/textarea'
import toast from '@primeuix/themes/aura/toast'
import toggleswitch from '@primeuix/themes/aura/toggleswitch'

// Полный пресет Aura тянет токены всех ~90 компонентов; собираем базу и только используемые компоненты (минус ~0,5 МБ JS).
// Добавили компонент PrimeVue в панель — добавьте сюда его токены, иначе он останется без оформления.
const AuraLite = {
  primitive: base.primitive,
  semantic: base.semantic,
  components: {
    button, confirmdialog, dialog, inputtext, message, password, skeleton, textarea, toast, toggleswitch,
  },
} as unknown as typeof Aura

const cobalt = {
  50: '#eef0fd', 100: '#dfe3fb', 200: '#c4cbf7', 300: '#a3adf2', 400: '#8b97f2', 500: '#5463df',
  600: '#3d4ed8', 700: '#3241b8', 800: '#2b3795', 900: '#283277', 950: '#1a1f48',
}

// светлая шкала: 0 — поверхность, 50 — фон страницы, 200 — линии, 500 — приглушённый текст, 900 — основной текст
const paperLight = {
  0: '#ffffff', 50: '#f4f6fa', 100: '#eceff5', 200: '#e1e5ed', 300: '#c9d0dc', 400: '#8d97a8',
  500: '#5b6577', 600: '#475062', 700: '#343c4c', 800: '#253043', 900: '#172033', 950: '#0e1422',
}
// тёмная шкала: 50 — основной текст, 300 — приглушённый, 700 — линии, 800 — поверхность, 900 — фон страницы
const paperDark = {
  0: '#ffffff', 50: '#e6eaf2', 100: '#cdd3df', 200: '#aab3c3', 300: '#9aa4b6', 400: '#6f798d',
  500: '#4f596c', 600: '#38435a', 700: '#283246', 800: '#161d2c', 900: '#0e131e', 950: '#0a0e17',
}

const ring = { width: '2px', style: 'solid', color: '{primary.color}', offset: '2px', shadow: 'none' }

export const MittPreset = definePreset(AuraLite, {
  primitive: {
    // радиус по иерархии: 4–6 — мелкие метки, 8 — поля и кнопки, 14 — карточки и окна
    borderRadius: { none: '0', xs: '2px', sm: '4px', md: '8px', lg: '10px', xl: '14px' },
  },
  semantic: {
    primary: cobalt,
    focusRing: ring,
    formField: { focusRing: { ...ring, offset: '1px' } },
    overlay: {
      select: { shadow: '0 6px 16px -6px rgba(16, 24, 40, 0.18)' },
      popover: { shadow: '0 6px 16px -6px rgba(16, 24, 40, 0.18)' },
      modal: { borderRadius: '{border.radius.xl}', shadow: '0 18px 40px -12px rgba(16, 24, 40, 0.28)' },
    },
    colorScheme: {
      light: {
        surface: paperLight,
        primary: { color: '{primary.600}', contrastColor: '#ffffff', hoverColor: '{primary.700}', activeColor: '{primary.800}' },
        highlight: { background: '{primary.50}', focusBackground: '{primary.100}', color: '{primary.800}', focusColor: '{primary.900}' },
        text: { color: '{surface.900}', hoverColor: '{surface.950}', mutedColor: '{surface.500}', hoverMutedColor: '{surface.600}' },
        formField: { color: '{surface.900}', placeholderColor: '{surface.400}', shadow: 'none', invalidBorderColor: '#b42318' },
      },
      dark: {
        surface: paperDark,
        primary: { color: '{primary.400}', contrastColor: '#0c1018', hoverColor: '{primary.300}', activeColor: '{primary.200}' },
        text: { color: '{surface.50}', hoverColor: '{surface.0}', mutedColor: '{surface.300}', hoverMutedColor: '{surface.200}' },
        content: { background: '{surface.800}', hoverBackground: '{surface.700}', borderColor: '{surface.700}' },
        formField: {
          background: '{surface.900}', borderColor: '{surface.600}', hoverBorderColor: '{surface.500}', color: '{surface.50}',
          placeholderColor: '{surface.400}', shadow: 'none', invalidBorderColor: '#f07a6e', disabledBackground: '{surface.800}',
        },
        overlay: {
          select: { background: '{surface.800}', borderColor: '{surface.700}' },
          popover: { background: '{surface.800}', borderColor: '{surface.700}' },
          modal: { background: '{surface.800}', borderColor: '{surface.700}' },
        },
        list: { option: { focusBackground: '{surface.700}' } },
      },
    },
  },
})
