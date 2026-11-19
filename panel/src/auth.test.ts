import { afterEach, describe, expect, it, vi } from 'vitest'
import { api, onAuthLost, setCsrf, type ApiResult, type SessionResponse } from './api'
import { loginMessage, nextStage, normalizeRecovery, normalizeTotp, secondFactor } from './auth'

const res = (status: number, body: Partial<SessionResponse>): ApiResult<SessionResponse> => ({ status, body: { ok: false, issues: [], ...body } })

describe('auth', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
    setCsrf(null)
    onAuthLost(null)
  })

  it('нормализует TOTP и recovery-коды', () => {
    expect(normalizeTotp(' 123 456 ')).toBe('123456')
    expect(normalizeTotp('12345')).toBeNull()
    expect(normalizeTotp('12345a')).toBeNull()
    expect(normalizeRecovery('abcd-efgh-2345-6723')).toBe('ABCDEFGH23456723')
    expect(normalizeRecovery('ABCD-EFGH-2345-6781')).toBeNull() // 8 и 1 не входят в base32
    expect(secondFactor('totp', '000111')).toEqual({ totp: '000111' })
    expect(secondFactor('recovery', 'abcd efgh 2345 6723')).toEqual({ recovery_code: 'ABCDEFGH23456723' })
  })

  it('переходы этапов и сообщения', () => {
    expect(nextStage('password', res(200, { ok: true, stage: 'second_factor' }))).toBe('second_factor')
    expect(nextStage('password', res(200, { ok: true, stage: 'done', authenticated: true, totp: false, csrf: 'x' }))).toBe('done')
    expect(nextStage('second_factor', res(200, { ok: true, csrf: 'x' }))).toBe('done')
    expect(nextStage('second_factor', res(401, { error: { code: 'login_required', message: '' } }))).toBe('password')
    expect(nextStage('second_factor', res(401, { error: { code: 'invalid_code', message: '' } }))).toBe('second_factor')
    expect(loginMessage(res(200, { ok: true }))).toBeNull()
    expect(loginMessage(res(401, { error: { code: 'code_reused', message: '' } }))).toMatch(/уже использован/)
    expect(loginMessage(res(409, { error: { code: 'clock_untrusted', message: '' } }))).toMatch(/recovery-кодом/)
    expect(loginMessage(res(429, { retry_after: 60, error: { code: 'too_many_attempts', message: '' } }))).toMatch(/60 с/)
  })

  it('POST несёт CSRF-заголовок, GET — нет; 401 на защищённом адресе сообщает о потере сессии', async () => {
    const calls: { url: string; init: RequestInit }[] = []
    vi.stubGlobal('fetch', async (url: string, init: RequestInit) => {
      calls.push({ url, init })
      const status = url.endsWith('/config') ? 401 : 200
      return new Response(JSON.stringify({ ok: status === 200, issues: [] }), { status })
    })
    const lost = vi.fn()
    onAuthLost(lost)
    setCsrf('tok')
    await api.preview({ rule: { id: 'r', source: { type: 'lan' }, destination: { type: 'domain', value: 'a.b' }, action: { type: 'direct' }, enabled: true }, probes: [] })
    await api.config()
    expect(new Headers(calls[0]!.init.headers).get('X-MITT-CSRF')).toBe('tok')
    expect(calls[0]!.init.credentials).toBe('same-origin')
    expect(new Headers(calls[1]!.init.headers).get('X-MITT-CSRF')).toBeNull()
    expect(lost).toHaveBeenCalledOnce()
    // после потери сессии токен сброшен
    await api.preview({ rule: { id: 'r', source: { type: 'lan' }, destination: { type: 'domain', value: 'a.b' }, action: { type: 'direct' }, enabled: true }, probes: [] })
    expect(new Headers(calls[2]!.init.headers).get('X-MITT-CSRF')).toBeNull()
  })

  it('401 на шагах входа не считается потерей сессии', async () => {
    vi.stubGlobal('fetch', async () => new Response(JSON.stringify({ ok: false, issues: [], error: { code: 'invalid_credentials', message: '' } }), { status: 401 }))
    const lost = vi.fn()
    onAuthLost(lost)
    const r = await api.login('x')
    expect(r.status).toBe(401)
    expect(lost).not.toHaveBeenCalled()
  })
})
