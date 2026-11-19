// Автосохранение экранов «Сайты», «Устройства», «Дополнительно»: через ~1,5 с после последней правки черновик
// сохраняется (store.save, POST /config). Состояние одно на панель — его показывает верхняя строка.
// Нельзя сохранить (нет каталога, сети, сервера, не выбрано ни одного устройства) — показываем подсказку, а не сохраняем.
// Ошибка и конфликт ревизий (409) черновик не трогают: store перечитывает настройки, правки остаются, есть «Повторить».

import { getCurrentInstance, onBeforeUnmount, reactive, watch, type WatchSource } from 'vue'
import { loadStatus, service, type SaveResult } from './store'

export const DEBOUNCE_MS = 1500

export interface SaveAction { label: string; run: () => void }
/** Что мешает сохранить: текст подсказки и, может быть, переход туда, где это исправить. */
export interface Blocker { text: string; action?: SaveAction }

export type SaveTone = 'idle' | 'pending' | 'saving' | 'saved' | 'blocked' | 'error'
export const saveStatus = reactive<{ tone: SaveTone; text: string; action: SaveAction | null }>({ tone: 'idle', text: '', action: null })

function set(tone: SaveTone, text = '', action: SaveAction | null = null) {
  saveStatus.tone = tone
  saveStatus.text = text
  saveStatus.action = action
}

/** Текст строки сохранения: после сохранения, пока роутер применяет настройки, — «Применяю на роутере». */
export function saveLabel(s: { tone: SaveTone; text: string }, applyPending: boolean): string {
  if (s.tone === 'saved') return applyPending ? 'Применяю на роутере' : 'Сохранено'
  if (s.tone === 'saving') return 'Сохраняю…'
  if (s.tone === 'pending') return 'Есть изменения'
  return s.text
}

let pendingFlush: (() => Promise<void>) | null = null
// закрытие вкладки с несохранёнными правками: браузер переспросит
if (typeof window !== 'undefined') {
  addEventListener('beforeunload', (e) => {
    if (saveStatus.tone === 'pending' || saveStatus.tone === 'saving') e.preventDefault()
  })
}

let applyPoll: number | undefined
/** Пока роутер применяет настройки — чаще спрашиваем состояние (до ~30 с). */
function watchApply() {
  clearInterval(applyPoll)
  let left = 15
  applyPoll = window.setInterval(() => {
    if (!service.value?.apply_pending || --left <= 0) { clearInterval(applyPoll); applyPoll = undefined; return }
    void loadStatus()
  }, 2000)
}

export interface AutosaveOptions {
  /** Что отслеживать (черновик экрана, глубоко). */
  source: WatchSource | WatchSource[]
  dirty: () => boolean
  blocker: () => Blocker | null
  /** Сохранение: строка — ошибка до запроса (например, сборка настроек не удалась). */
  run: () => Promise<SaveResult | string>
  delay?: number
}

export function useAutosave(o: AutosaveOptions) {
  let timer: ReturnType<typeof setTimeout> | undefined
  let saving = false
  let again = false
  const delay = o.delay ?? DEBOUNCE_MS

  function schedule() {
    clearTimeout(timer)
    timer = undefined
    if (!o.dirty()) {
      if (saveStatus.tone === 'pending' || saveStatus.tone === 'blocked') set('idle')
      return
    }
    const b = o.blocker()
    if (b) { set('blocked', b.text, b.action ?? null); return }
    set('pending')
    timer = setTimeout(() => void flush(), delay)
    pendingFlush = flush
  }

  async function flush(): Promise<void> {
    clearTimeout(timer)
    timer = undefined
    if (pendingFlush === flush) pendingFlush = null
    if (saving) { again = true; return }
    if (!o.dirty()) return
    const b = o.blocker()
    if (b) { set('blocked', b.text, b.action ?? null); return }
    saving = true
    set('saving')
    let r: SaveResult | string
    try {
      r = await o.run()
    } catch (e) {
      r = String(e)
    } finally {
      saving = false
    }
    if (typeof r === 'string' || !r.ok) {
      const message = typeof r === 'string' ? r : r.message
      set('error', message, { label: 'Повторить', run: () => void flush() })
      again = false
      return
    }
    set('saved')
    if (service.value?.apply_pending) watchApply()
    // правки, сделанные во время сохранения, — следующим заходом
    if (again || o.dirty()) { again = false; schedule() }
  }

  // подсказка другого экрана здесь ни к чему
  if (saveStatus.tone === 'blocked' || saveStatus.tone === 'pending') set('idle')
  watch(o.source, schedule, { deep: true })
  // препятствие исчезло (загрузился каталог, настроен сервер) или появилось — пересчитать
  watch(() => o.blocker()?.text, () => { if (o.dirty() && !saving) schedule() })
  if (getCurrentInstance()) {
    onBeforeUnmount(() => {
      // ушли с экрана до срабатывания таймера — сохраняем сразу, правки не теряются
      if (timer !== undefined) void flush()
      else if (saveStatus.tone === 'blocked') set('idle')
    })
  }
  return { flush, schedule }
}

/**
 * Сохранение сразу, без черновика и задержки (выбор способа обхода): то же состояние в верхней строке, что у
 * автосохранения, и «Повторить» при ошибке. true — сохранено.
 */
export async function saveNow(run: () => Promise<SaveResult>): Promise<boolean> {
  set('saving')
  let r: SaveResult
  try {
    r = await run()
  } catch (e) {
    r = { ok: false, conflict: false, message: String(e) }
  }
  if (!r.ok) {
    set('error', r.message, { label: 'Повторить', run: () => void saveNow(run) })
    return false
  }
  set('saved')
  if (service.value?.apply_pending) watchApply()
  return true
}

/** Сохранить отложенные правки сейчас (например, перед выходом). */
export async function flushPending(): Promise<void> {
  await pendingFlush?.()
}

/** Сброс состояния (выход из панели). */
export function resetSaveStatus() {
  set('idle')
  pendingFlush = null
}
