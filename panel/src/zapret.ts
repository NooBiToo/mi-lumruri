// Готовые способы обхода блокировок (стратегии Zapret) для ручного выбора — названия и описания для людей.
// id и порядок — как в каталоге контроллера (controller/data/zapret-strategies.json): общие v1–v10, YouTube yv1–yv22.
// Описания — по приёму из аргументов стратегии, коротко и без терминов nfqws2. Каталог поменялся — поменяйте и здесь.

import type { ZapretConfig, ZapretTestState } from './api'

export const AUTO = 'auto'

export interface StrategyOption { id: string; label: string; desc: string }

const GENERAL_DESC = [
  'Разрез первого пакета с маскировкой',
  'Поддельный пакет, затем разрез',
  'Подмена имени сайта',
  'Разрез первого пакета с маскировкой, вариант 2',
  'Поддельный пакет и разрез с перестановкой',
  'Подмена имени сайта с разрезом посередине',
  'Серия поддельных пакетов, затем разрез',
  'Поддельный пакет от другого сайта',
  'Подмена имени сайта, вариант 2',
  'Поддельный пакет и простой разрез',
]

const YOUTUBE_DESC = [
  'Подмена имени сайта',
  'Поддельные пакеты и разрез с маскировкой',
  'Разрез с перестановкой',
  'Копия приветствия, подделка и перестановка',
  'Серия подделок и разрез с перестановкой',
  'Разрез у имени сайта',
  'Разрез с перестановкой и подделкой',
  'Копия приветствия и подмена имени сайта',
  'Подмена имени сайта, вариант 2',
  'Серия подделок и разрез с подделкой',
  'Серия подделок и разрез с маскировкой',
  'Разрез с маскировкой',
  'Разрез у имени сайта, вариант 2',
  'Разрез с длинной маскировкой',
  'Подделки и разрез с перестановкой',
  'Перестановка у имени сайта',
  'Перестановка тремя частями',
  'Подделки и разрез на части',
  'Разрез с перестановкой, вариант 2',
  'Мелкий разрез с маскировкой',
  'Перестановка многими частями',
  'Подделки и разрез с самой длинной маскировкой',
]

export const GENERAL_STRATEGIES: StrategyOption[] = [
  { id: AUTO, label: 'Автоматически (рекомендуется)', desc: 'Роутер сам переключает способы, если сайт не открывается' },
  ...GENERAL_DESC.map((desc, i) => ({ id: `v${i + 1}`, label: `Способ ${i + 1}`, desc })),
]

export const YOUTUBE_STRATEGIES: StrategyOption[] = [
  { id: AUTO, label: 'Автоматически', desc: 'Роутер сам переключает способы для YouTube' },
  ...YOUTUBE_DESC.map((desc, i) => ({ id: `yv${i + 1}`, label: `YouTube: способ ${i + 1}`, desc })),
]

/** Название способа по id; незнакомый id (каталог новее панели) — «Другой способ», id не показываем. */
export function strategyName(kind: 'general' | 'youtube', id: string | undefined): string {
  const list = kind === 'general' ? GENERAL_STRATEGIES : YOUTUBE_STRATEGIES
  return list.find((s) => s.id === (id ?? AUTO))?.label ?? 'Другой способ'
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
