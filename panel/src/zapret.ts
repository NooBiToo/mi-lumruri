// Готовые способы обхода блокировок (стратегии Zapret) для ручного выбора — названия и описания для людей.
// id и порядок — как в каталоге контроллера (controller/data/zapret-strategies.json): общие v1–v10, YouTube yv1–yv22.
// Описания — по приёму из аргументов стратегии, коротко и без терминов nfqws2. Каталог поменялся — поменяйте и здесь.

import type { ZapretConfig, ZapretTestState } from './api'
import { t } from './i18n'

export const AUTO = 'auto'

export interface StrategyOption { id: string; label: string; desc: string }

// списки — функциями: тексты переводятся на текущий язык при каждом показе
const generalDesc = () => [
  t('Разрез первого пакета с маскировкой'),
  t('Поддельный пакет, затем разрез'),
  t('Подмена имени сайта'),
  t('Разрез первого пакета с маскировкой, вариант 2'),
  t('Поддельный пакет и разрез с перестановкой'),
  t('Подмена имени сайта с разрезом посередине'),
  t('Серия поддельных пакетов, затем разрез'),
  t('Поддельный пакет от другого сайта'),
  t('Подмена имени сайта, вариант 2'),
  t('Поддельный пакет и простой разрез'),
]

const youtubeDesc = () => [
  t('Подмена имени сайта'),
  t('Поддельные пакеты и разрез с маскировкой'),
  t('Разрез с перестановкой'),
  t('Копия приветствия, подделка и перестановка'),
  t('Серия подделок и разрез с перестановкой'),
  t('Разрез у имени сайта'),
  t('Разрез с перестановкой и подделкой'),
  t('Копия приветствия и подмена имени сайта'),
  t('Подмена имени сайта, вариант 2'),
  t('Серия подделок и разрез с подделкой'),
  t('Серия подделок и разрез с маскировкой'),
  t('Разрез с маскировкой'),
  t('Разрез у имени сайта, вариант 2'),
  t('Разрез с длинной маскировкой'),
  t('Подделки и разрез с перестановкой'),
  t('Перестановка у имени сайта'),
  t('Перестановка тремя частями'),
  t('Подделки и разрез на части'),
  t('Разрез с перестановкой, вариант 2'),
  t('Мелкий разрез с маскировкой'),
  t('Перестановка многими частями'),
  t('Подделки и разрез с самой длинной маскировкой'),
]

export const generalStrategies = (): StrategyOption[] => [
  { id: AUTO, label: t('Автоматически (рекомендуется)'), desc: t('Роутер сам переключает способы, если сайт не открывается') },
  ...generalDesc().map((desc, i) => ({ id: `v${i + 1}`, label: t('Способ {n}', { n: i + 1 }), desc })),
]

export const youtubeStrategies = (): StrategyOption[] => [
  { id: AUTO, label: t('Автоматически'), desc: t('Роутер сам переключает способы для YouTube') },
  ...youtubeDesc().map((desc, i) => ({ id: `yv${i + 1}`, label: t('YouTube: способ {n}', { n: i + 1 }), desc })),
]

/** Название способа по id; незнакомый id (каталог новее панели) — «Другой способ», id не показываем. */
export function strategyName(kind: 'general' | 'youtube', id: string | undefined): string {
  const list = kind === 'general' ? generalStrategies() : youtubeStrategies()
  return list.find((s) => s.id === (id ?? AUTO))?.label ?? t('Другой способ')
}

/**
 * Какие из сохранённых способов поставил последний подбор (а не человек): подбор применён, и его находка совпадает с
 * сохранённой. Для всех сайтов подбор меняет способ, только если `general` не false.
 */
export function pickedByTest(z: ZapretConfig | undefined, t: ZapretTestState | null | undefined): { general: boolean; youtube: boolean } {
  const ok = !!t && t.state === 'done' && !!t.applied
  const general = ok && t!.general !== false && !!t!.best && (z?.strategy ?? AUTO) !== AUTO && t!.best.id === z?.strategy
  const youtube = ok && !!t!.youtube && (z?.youtube ?? AUTO) !== AUTO && t!.youtube.id === z?.youtube
  return { general, youtube }
}
