// Тема PrimeVue: Aura с палитрой панели. Основной цвет — небесно-синий маршрута через VPN, поверхности — графит.
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
import select from '@primeuix/themes/aura/select'
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
    button, confirmdialog, dialog, inputtext, message, password, select, skeleton, textarea, toast, toggleswitch,
  },
} as unknown as typeof Aura

const sky = {
  50: '#eaf3fc', 100: '#d3e6f9', 200: '#a9cff4', 300: '#7cbbf7', 400: '#5aa9f5', 500: '#2b8ae6',
  600: '#0b6bcb', 700: '#0959a9', 800: '#0a4f96', 900: '#0b3f74', 950: '#08294b',
}

// светлая шкала: 0 — поверхность, 50 — фон страницы, 200 — линии, 500 — приглушённый текст, 900 — основной текст
const paperLight = {
  0: '#ffffff', 50: '#fafafa', 100: '#f4f4f5', 200: '#e7e7e9', 300: '#d4d4d8', 400: '#737373',
  500: '#525252', 600: '#404040', 700: '#333333', 800: '#262626', 900: '#171717', 950: '#0a0a0a',
}
// тёмная шкала: 50 — основной текст, 300 — приглушённый, 700 — линии, 800 — поверхность, 900 — фон страницы
const paperDark = {
  0: '#ffffff', 50: '#ededed', 100: '#d4d4d8', 200: '#b4b4b9', 300: '#a1a1a6', 400: '#85858b',
  500: '#5c5c62', 600: '#3a3a3e', 700: '#29292c', 800: '#19191b', 900: '#141415', 950: '#0f0f10',
}

const ring = { width: '2px', style: 'solid', color: '{primary.color}', offset: '2px', shadow: 'none' }

export const MittPreset = definePreset(AuraLite, {
  primitive: {
    // радиус по иерархии: 4–6 — мелкие метки, 8 — поля и кнопки, 14 — карточки и окна
    borderRadius: { none: '0', xs: '2px', sm: '4px', md: '8px', lg: '10px', xl: '14px' },
  },
  semantic: {
    primary: sky,
    focusRing: ring,
    formField: { focusRing: { ...ring, offset: '1px' } },
    overlay: {
      select: { shadow: '0 6px 16px -6px rgba(0, 0, 0, 0.18)' },
      popover: { shadow: '0 6px 16px -6px rgba(0, 0, 0, 0.18)' },
      modal: { borderRadius: '{border.radius.xl}', shadow: '0 18px 40px -12px rgba(0, 0, 0, 0.28)' },
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
        primary: { color: '{primary.400}', contrastColor: '#0f0f10', hoverColor: '{primary.300}', activeColor: '{primary.200}' },
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
