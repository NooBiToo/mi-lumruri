import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import type { Config, ListCatalog } from './api'
import { defaultSimple } from './simple'
import { build, catalog, config, lan, lists, notify, reset, revision, save } from './store'

const cfg: Config = { version: 1, profiles: [], networks: [], devices: [], groups: [], rules: [], default_action: { type: 'direct' } }
const cat: ListCatalog = { source: 's', commit: 'c', date: '2026-11-09', services: [{ id: 'youtube', name: 'YouTube', group: 'Сервисы', domains: 'Services/youtube.lst', ipv4: null }] }
const reply = (status: number, body: unknown) => new Response(JSON.stringify(body), { status })

describe('store', () => {
  const shown: [string, string, string | undefined][] = []
  beforeEach(() => {
    reset()
    config.value = cfg
    revision.value = 'rev-1'
    lists.value = { ok: true, catalog: cat, issues: [] }
    lan.value = { bridge: 'br-lan', subnet: '192.168.31.0/24', address: '192.168.31.1' }
    shown.length = 0
    notify.show = (k, t, d) => void shown.push([k, t, d])
  })
  afterEach(() => vi.unstubAllGlobals())

  it('build: без профиля VPN — понятная просьба настроить сервер; без каталога — не собирает', () => {
    expect(build({ ...defaultSimple(), services: ['youtube'] }, [])).toBe('Сначала настройте сервер VPN на экране «Сервер».')
    // без сайтов профиль не нужен
    expect(typeof build(defaultSimple(), [])).toBe('object')
    lists.value = null
    expect(catalog.value).toBeNull()
    expect(build(defaultSimple(), [])).toMatch(/Каталог сайтов ещё не загружен/)
  })

  it('save: 409 — настройки перечитаны и пользователь предупреждён', async () => {
    const calls: string[] = []
    vi.stubGlobal('fetch', async (url: string, init?: RequestInit) => {
      calls.push(`${init?.method ?? 'GET'} ${url}`)
      if (init?.method === 'POST') return reply(409, { ok: false, issues: [], error: { code: 'revision_conflict', message: 'ревизия устарела' } })
      return reply(200, { ok: true, schema_version: 1, revision: 'rev-2', config: { ...cfg, default_action: { type: 'direct_zapret' } }, issues: [] })
    })
    const r = await save(cfg)
    expect(r).toMatchObject({ ok: false, conflict: true })
    expect(calls).toEqual(['POST cgi-bin/api/config', 'GET cgi-bin/api/config'])
    expect(revision.value).toBe('rev-2')
    expect(config.value?.default_action.type).toBe('direct_zapret')
    expect(shown[0]?.[0]).toBe('error')
    expect(shown[0]?.[2]).toMatch(/изменились в другом окне/)
  })

  it('save: 422 — сообщение контроллера и причины, настройки не меняются', async () => {
    vi.stubGlobal('fetch', async () => reply(422, { ok: false, error: { code: 'config_invalid', message: 'новые настройки не прошли проверку; ничего не записано' },
      issues: [{ path: 'groups[0].destinations[0]', code: 'bad_domain', message: 'домен «a..b» записан с ошибкой' }] }))
    const r = await save(cfg)
    expect(r).toEqual({ ok: false, conflict: false, message: 'новые настройки не прошли проверку; ничего не записано: домен «a..b» записан с ошибкой' })
    expect(revision.value).toBe('rev-1')
    expect(shown).toEqual([['error', 'Не сохранено', r.ok ? '' : r.message]])
  })

  it('save: 200 — новая ревизия и тост «Сохранено, применяю на роутере»', async () => {
    vi.stubGlobal('fetch', async (_u: string, init?: RequestInit) =>
      init?.method === 'POST' ? reply(200, { ok: true, revision: 'rev-3', config: cfg, queued: true, issues: [] }) : reply(200, { ok: true, issues: [] }))
    expect(await save(cfg)).toEqual({ ok: true })
    expect(revision.value).toBe('rev-3')
    expect(shown[0]).toEqual(['success', 'Сохранено, применяю на роутере', undefined])
  })
})
