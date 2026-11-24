// Состояние роутера (GET /health): опрос раз в 5 секунд, пока вкладка видна; скорость WAN и туннелей — по разнице
// счётчиков байт между двумя ответами. Общий для шапки и «Обзора».

import { computed, ref } from 'vue'
import { manage, type HealthResponse } from './api'
import { t } from './i18n'

export const health = ref<HealthResponse | null>(null)
/** Скорость, бит/с: приём и передача WAN и туннелей (null — ещё нет двух снимков). */
export const rates = ref<{ wan: { rx: number; tx: number } | null; vpn: { rx: number; tx: number } | null }>({ wan: null, vpn: null })

/** Последние значения приёма WAN и туннелей, бит/с — для графиков на «Обзоре» (2 минуты при опросе раз в 5 с). */
const SERIES = 24
export const series = ref<{ wan: number[]; vpn: number[] }>({ wan: [], vpn: [] })

let prev: HealthResponse | null = null
let timer: number | undefined
let users = 0

function rate(a: { rx: number; tx: number } | null | undefined, b: { rx: number; tx: number } | null | undefined, dt: number) {
  if (!a || !b || dt <= 0 || b.rx < a.rx || b.tx < a.tx) return null
  return { rx: ((b.rx - a.rx) * 8) / dt, tx: ((b.tx - a.tx) * 8) / dt }
}

async function poll() {
  clearTimeout(timer)
  if (typeof document === 'undefined' || document.visibilityState !== 'hidden') {
    try {
      const r = await manage.health()
      if (r.status === 200) {
        const h = r.body
        if (prev) {
          const dt = (h.at_ms - prev.at_ms) / 1000
          rates.value = { wan: rate(prev.net.wan, h.net.wan, dt), vpn: rate(prev.net.vpn, h.net.vpn, dt) }
          const push = (xs: number[], v: number | undefined) => [...xs, v ?? 0].slice(-SERIES)
          series.value = { wan: push(series.value.wan, rates.value.wan?.rx), vpn: push(series.value.vpn, rates.value.vpn?.rx) }
        }
        prev = h
        health.value = h
      }
    } catch { /* панель недоступна — следующий опрос */ }
  }
  if (users > 0) timer = window.setTimeout(() => void poll(), 5000)
}

/** Подписка на опрос (шапка, «Обзор»); вернуть — отписка. */
export function useHealth(): () => void {
  users++
  if (users === 1) void poll()
  return () => { users = Math.max(0, users - 1); if (!users) clearTimeout(timer) }
}

export const memUsed = computed(() => {
  const m = health.value?.mem
  return m && m.total ? Math.round(((m.total - m.available) / m.total) * 100) : null
})
/** Самый горячий датчик. */
export const hottest = computed(() => {
  const ts = health.value?.temps ?? []
  return ts.length ? ts.reduce((a, b) => (b.c > a.c ? b : a)) : null
})
/** Тон показателя: обычный, повышенный, высокий. */
export function level(v: number | null | undefined, warn: number, bad: number): 'ok' | 'warn' | 'bad' {
  return v == null ? 'ok' : v >= bad ? 'bad' : v >= warn ? 'warn' : 'ok'
}

/** Скорость по-человечески: 12,3 Мбит/с. */
export function bitrate(bps: number | null | undefined, tag: string): string {
  const p = bitrateParts(bps, tag)
  if (!p) return '—'
  return p.i === 0 ? t('{n} кбит/с', { n: p.n }) : p.i === 1 ? t('{n} Мбит/с', { n: p.n }) : t('{n} Гбит/с', { n: p.n })
}
/** Скорость числом и единицей отдельно — для крупных цифр на плитках. */
export function bitrateParts(bps: number | null | undefined, tag: string): { n: string; unit: string; i: number } | null {
  if (bps == null) return null
  let v = bps / 1000
  let i = 0
  while (v >= 1000 && i < 2) { v /= 1000; i++ }
  const n = new Intl.NumberFormat(tag, { maximumFractionDigits: v < 10 ? 1 : 0 }).format(v)
  return { n, unit: [t('кбит/с'), t('Мбит/с'), t('Гбит/с')][i]!, i }
}
