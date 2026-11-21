// Полнота переводов: каждая строка из t('…') и каждая тройка plural(…, '…', '…', '…') в исходниках панели должна быть
// в словарях en и zh. Шаблонные строки с ${…} в t() недопустимы — только подстановки {имя}.
import { describe, expect, it } from 'vitest'
import { detectLang, lang, plural, t } from './i18n'

const SOURCES = import.meta.glob(['./**/*.ts', './**/*.vue', '!./**/*.test.ts', '!./i18n/**'], { query: '?raw', import: 'default', eager: true }) as Record<string, string>
const merge = (mods: Record<string, unknown>) => Object.assign({}, ...Object.values(mods).map((m) => (m as { default: Record<string, string> }).default)) as Record<string, string>
const DICT = {
  en: merge(import.meta.glob('./i18n/en/*.ts', { eager: true })),
  zh: merge(import.meta.glob('./i18n/zh/*.ts', { eager: true })),
}

const STR = String.raw`'((?:[^'\\]|\\.)*)'`
const unq = (s: string) => s.replace(/\\'/g, "'").replace(/\\n/g, '\n')
function keys() {
  const tk = new Set<string>()
  const pk = new Set<string>()
  const bad: string[] = []
  for (const [f, src] of Object.entries(SOURCES)) {
    for (const m of src.matchAll(new RegExp(String.raw`\bt\(\s*${STR}`, 'g'))) tk.add(unq(m[1]!))
    if (/\bt\(\s*`/.test(src)) bad.push(`${f}: t(\`…\`) — используйте подстановки {имя}`)
    for (const m of src.matchAll(new RegExp(String.raw`\bplural\([^,]+,\s*${STR}\s*,\s*${STR}\s*,\s*${STR}`, 'g'))) pk.add(`${unq(m[1]!)}|${unq(m[2]!)}|${unq(m[3]!)}`)
  }
  return { tk, pk, bad }
}

describe('i18n', () => {
  it('язык браузера: ru и близкие, zh, иначе en', () => {
    expect(detectLang(['ru-RU', 'en'])).toBe('ru')
    expect(detectLang(['uk'])).toBe('ru')
    expect(detectLang(['zh-CN'])).toBe('zh')
    expect(detectLang(['de-DE', 'en-US'])).toBe('en')
    expect(detectLang(['fr'])).toBe('en')
  })
  it('подстановки и множественное число', () => {
    lang.value = 'ru'
    expect(t('Доступна версия {v}', { v: '0.4.0' })).toBe('Доступна версия 0.4.0')
    expect(plural(3, 'сайт', 'сайта', 'сайтов')).toBe('3 сайта')
    expect(plural(11, 'сайт', 'сайта', 'сайтов')).toBe('11 сайтов')
  })
  it('у каждой строки интерфейса есть английский и китайский перевод', () => {
    const { tk, pk, bad } = keys()
    expect(bad).toEqual([])
    expect(tk.size).toBeGreaterThan(0)
    const ph = (s: string) => [...s.matchAll(/\{(\w+)\}/g)].map((x) => x[1]).sort().join(',')
    for (const l of ['en', 'zh'] as const) {
      const d = DICT[l]
      expect([...tk, ...pk].filter((k) => !(k in d)), `нет перевода (${l})`).toEqual([])
      expect([...tk].filter((k) => k in d && ph(k) !== ph(d[k]!)), `подстановки не совпадают (${l})`).toEqual([])
    }
  })
})
