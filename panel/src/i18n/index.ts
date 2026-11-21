// Язык интерфейса: русский (исходный), английский, китайский (упрощённый). Ключ перевода — сама русская строка:
// t('Сохранить') → 'Save' / '保存'. Подстановки — {имя}: t('Доступна версия {v}', { v: '0.4.0' }).
// Словари — по разделам в i18n/en/*.ts и i18n/zh/*.ts (default export: Record<русская строка, перевод>); нет
// перевода — русская строка. Полноту словарей проверяет i18n.test.ts по исходникам (t('…') и plural(…)).
// Язык по умолчанию — по языку браузера, выбор в «Дополнительно» запоминается в браузере.
import { ref, watch } from 'vue'

export type Lang = 'ru' | 'en' | 'zh'
export const LANGS: { id: Lang; label: string }[] = [{ id: 'ru', label: 'Русский' }, { id: 'en', label: 'English' }, { id: 'zh', label: '简体中文' }]
const KEY = 'mitt.lang'

type Dict = Record<string, string>
function merge(mods: Record<string, unknown>): Dict {
  const out: Dict = {}
  for (const m of Object.values(mods)) Object.assign(out, (m as { default: Dict }).default)
  return out
}
const DICTS: Record<Exclude<Lang, 'ru'>, Dict> = {
  en: merge(import.meta.glob('./en/*.ts', { eager: true })),
  zh: merge(import.meta.glob('./zh/*.ts', { eager: true })),
}

/** Язык браузера: русский (и близкие: украинский, белорусский, казахский…), китайский, иначе английский. */
export function detectLang(langs: readonly string[] = typeof navigator !== 'undefined' ? navigator.languages ?? [navigator.language] : []): Lang {
  for (const l of langs) {
    const p = l.toLowerCase()
    if (/^(ru|uk|be|kk|ky|uz|tg|hy|az)\b/.test(p)) return 'ru'
    if (p.startsWith('zh')) return 'zh'
    if (p.startsWith('en')) return 'en'
  }
  return langs.length ? 'en' : 'ru'
}
function stored(): Lang | null {
  try {
    const v = localStorage.getItem(KEY)
    return v === 'ru' || v === 'en' || v === 'zh' ? v : null
  } catch {
    return null
  }
}

// в тестах (vitest) — всегда русский: ожидания написаны по исходным строкам; navigator есть и в Node 21+
export const lang = ref<Lang>(import.meta.env?.MODE === 'test' ? 'ru' : (stored() ?? detectLang()))
export function setLang(l: Lang) {
  lang.value = l
  try { localStorage.setItem(KEY, l) } catch { /* приватный режим */ }
}
watch(lang, (l) => { if (typeof document !== 'undefined') document.documentElement.lang = l === 'zh' ? 'zh-CN' : l }, { immediate: true })

/** Перевод русской строки; {имя} — подстановки. */
export function t(ru: string, p?: Record<string, string | number>): string {
  const s = lang.value === 'ru' ? ru : (DICTS[lang.value][ru] ?? ru)
  return p ? s.replace(/\{(\w+)\}/g, (m, k: string) => (k in p ? String(p[k]) : m)) : s
}

/** Тег для дат и чисел (toLocaleString). */
export function dateTag(): string {
  return lang.value === 'en' ? 'en-US' : lang.value === 'zh' ? 'zh-CN' : 'ru-RU'
}

/**
 * Число и слово в нужной форме: plural(5, 'сайт', 'сайта', 'сайтов') → «5 сайтов» / «5 sites» / «5 个网站».
 * Перевод — ключ «one|few|many», значение: английский «site|sites», китайский — одна форма «个网站».
 */
export function plural(n: number, one: string, few: string, many: string): string {
  if (lang.value !== 'ru') {
    const v = DICTS[lang.value][`${one}|${few}|${many}`]
    if (v !== undefined) {
      const [o, other] = v.split('|')
      return `${n} ${n === 1 || other === undefined ? o : other}`
    }
  }
  const m10 = n % 10
  const m100 = n % 100
  const w = m10 === 1 && m100 !== 11 ? one : m10 >= 2 && m10 <= 4 && (m100 < 12 || m100 > 14) ? few : many
  return `${n} ${w}`
}
