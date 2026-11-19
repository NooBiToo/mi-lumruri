// Мелкие помощники оформления без DOM: проверка домена для поля-меток, аватар устройства.

import { normalizeDomain } from './simple'
import { lines } from './status'

/**
 * Похоже ли значение на адрес сайта: метки из букв (в том числе кириллицы), цифр и дефисов через точку, не меньше
 * двух меток. Проверка мягкая — точные правила проверяет контроллер.
 */
export function isLikelyDomain(d: string): boolean {
  if (d.length > 253) return false
  const labels = d.split('.')
  if (labels.length < 2) return false
  return labels.every((l) => /^[\p{L}\p{N}](?:[\p{L}\p{N}-]{0,61}[\p{L}\p{N}])?$/u.test(l))
}

/**
 * Ввод поля-меток → домены: разбор как у текстового поля (`lines`), нормализация как в `toConfig` (`normalizeDomain`).
 * Повторы отбрасываются (уже добавленные — в `dup`); то, что не похоже на домен, возвращается в `bad`.
 */
export function parseDomainInput(text: string, have: string[]): { add: string[]; bad: string[]; dup: string[] } {
  const add: string[] = []
  const bad: string[] = []
  const dup: string[] = []
  for (const raw of lines(text)) {
    const d = normalizeDomain(raw)
    if (!d) continue
    if (!isLikelyDomain(d)) bad.push(raw)
    else if (have.includes(d)) { if (!dup.includes(d)) dup.push(d) }
    else if (!add.includes(d)) add.push(d)
  }
  return { add, bad, dup }
}

/** Оттенок аватара устройства (0–359) из MAC: у одного устройства всегда один цвет. */
export function avatarHue(mac: string): number {
  let h = 0
  for (const ch of mac) h = (h * 31 + ch.charCodeAt(0)) >>> 0
  return h % 360
}

/** Инициалы для аватара: первые буквы двух первых слов имени или две первые буквы; без имени — пусто. */
export function initials(name: string): string {
  const words = name.trim().split(/[\s_\-.]+/u).filter((w) => /[\p{L}\p{N}]/u.test(w))
  if (!words.length) return ''
  const first = (w: string) => [...w].find((c) => /[\p{L}\p{N}]/u.test(c)) ?? ''
  const s = words.length > 1 ? first(words[0]!) + first(words[1]!) : [...words[0]!.replace(/[^\p{L}\p{N}]/gu, '')].slice(0, 2).join('')
  return s.toUpperCase()
}
