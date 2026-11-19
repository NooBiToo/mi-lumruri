import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { nextTick, ref } from 'vue'
import { resetSaveStatus, saveLabel, saveStatus, useAutosave, type Blocker } from './autosave'
import type { SaveResult } from './store'

describe('autosave', () => {
  beforeEach(() => { vi.useFakeTimers(); resetSaveStatus() })
  afterEach(() => vi.useRealTimers())

  function setup(result: () => SaveResult | string = () => ({ ok: true })) {
    const draft = ref(0)
    const saved = ref(0)
    const blocker = ref<Blocker | null>(null)
    const run = vi.fn(async () => { const r = result(); if (typeof r !== 'string' && r.ok) saved.value = draft.value; return r })
    const a = useAutosave({ source: () => draft.value, dirty: () => draft.value !== saved.value, blocker: () => blocker.value, run })
    return { draft, saved, blocker, run, a }
  }

  it('сохраняет через 1,5 с после последней правки, одним запросом', async () => {
    const { draft, run } = setup()
    draft.value = 1
    await nextTick()
    expect(saveStatus.tone).toBe('pending')
    vi.advanceTimersByTime(1000)
    draft.value = 2
    await nextTick()
    vi.advanceTimersByTime(1000)
    expect(run).not.toHaveBeenCalled()
    await vi.advanceTimersByTimeAsync(600)
    expect(run).toHaveBeenCalledTimes(1)
    expect(saveStatus.tone).toBe('saved')
    expect(saveLabel(saveStatus, false)).toBe('Сохранено')
    expect(saveLabel(saveStatus, true)).toBe('Применяю на роутере')
  })

  it('препятствие — подсказка вместо сохранения; исчезло — сохраняет', async () => {
    const { draft, blocker, run } = setup()
    blocker.value = { text: 'Сначала настройте сервер VPN.' }
    draft.value = 1
    await nextTick()
    expect(saveStatus).toMatchObject({ tone: 'blocked', text: 'Сначала настройте сервер VPN.' })
    await vi.advanceTimersByTimeAsync(3000)
    expect(run).not.toHaveBeenCalled()
    blocker.value = null
    await nextTick()
    await vi.advanceTimersByTimeAsync(1600)
    expect(run).toHaveBeenCalledTimes(1)
  })

  it('ошибка: правки остаются, «Повторить» сохраняет снова', async () => {
    let fail = true
    const { draft, saved, run } = setup(() => (fail ? { ok: false, conflict: true, message: 'Настройки только что изменились' } : { ok: true }))
    draft.value = 5
    await nextTick()
    await vi.advanceTimersByTimeAsync(1600)
    expect(saveStatus.tone).toBe('error')
    expect(saveStatus.text).toMatch(/изменились/)
    expect(draft.value).toBe(5)
    expect(saved.value).toBe(0)
    fail = false
    saveStatus.action?.run()
    await vi.advanceTimersByTimeAsync(0)
    expect(run).toHaveBeenCalledTimes(2)
    expect(saved.value).toBe(5)
    expect(saveStatus.tone).toBe('saved')
  })
})
