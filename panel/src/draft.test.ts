import { describe, expect, it } from 'vitest'
import type { Config } from './api'
import { defaultForm, fieldForIssue, ruleKey, sampleHost, saveOutcome, toRequest } from './draft'

const cfg: Config = {
  version: 1,
  profiles: [
    { id: 'vless-main', name: 'VLESS', kind: 'vless', on_failure: 'block' },
    { id: 'tt-home', name: 'TT', kind: 'trusttunnel', on_failure: 'block' },
  ],
  networks: [{ id: 'home', name: 'Дом', ssid: 'Home' }],
  devices: [{ id: 'tv', name: 'ТВ', mac: 'a4:77:33:10:20:30', network: 'home' }],
  groups: [{ id: 'video', name: 'Видео', destinations: [{ type: 'domain_suffix', value: 'youtube.com' }] }],
  rules: [],
  default_action: { type: 'direct' },
}

describe('draft', () => {
  it('по умолчанию выбирает TrustTunnel, первое устройство и группу', () => {
    const f = defaultForm(cfg)
    expect(f.actionProfile).toBe('tt-home')
    expect(toRequest(f)).toEqual({
      rule: { id: 'r-tv-video', source: { type: 'device', id: 'tv' }, destination: { type: 'group', id: 'video' }, action: { type: 'profile', id: 'tt-home' }, enabled: true },
      probes: [{ device: 'tv', host: 'www.youtube.com' }, { network: 'home', host: 'www.youtube.com' }],
    })
  })

  it('собирает LAN-источник, домен и действие без профиля; пустые пробы отбрасывает', () => {
    const f = { ...defaultForm(cfg), sourceType: 'lan' as const, destType: 'domain' as const, destValue: '  a.example.com ', actionType: 'block' as const }
    f.probes = [{ subjectType: 'device', subjectId: 'tv', host: ' ' }]
    expect(toRequest(f)).toEqual({
      rule: { id: 'r-tv-video', source: { type: 'lan' }, destination: { type: 'domain', value: 'a.example.com' }, action: { type: 'block' }, enabled: true },
      probes: [],
    })
  })

  it('привязывает пути ошибок контроллера к полям', () => {
    expect(fieldForIssue('rule.source.id')).toBe('source')
    expect(fieldForIssue('rule.destination.value')).toBe('destination')
    expect(fieldForIssue('rule.action')).toBe('action')
    expect(fieldForIssue('rule.id')).toBe('id')
    expect(fieldForIssue('probes[3].host')).toBe('probe-3')
    expect(fieldForIssue('config.devices[0].mac')).toBeNull()
  })

  it('подбирает пример хоста', () => {
    expect(sampleHost({ type: 'cidr', value: '203.0.113.0/24' })).toBe('203.0.113.1')
    expect(sampleHost({ type: 'cidr', value: '2001:db8::/32' })).toBe('')
    expect(sampleHost({ type: 'domain', value: 'x.org' })).toBe('x.org')
  })
})

describe('сохранение', () => {
  it('ключ правила не зависит от проб, но меняется при изменении правила', () => {
    const f = defaultForm(cfg)
    const k = ruleKey(f)
    expect(ruleKey({ ...f, probes: [] })).toBe(k)
    expect(ruleKey({ ...f, actionType: 'block' })).not.toBe(k)
  })

  it('распознаёт исходы сохранения', () => {
    expect(saveOutcome({ status: 200, body: { ok: true, mode: 'add', rule_id: 'r', revision: 'abcdef0123456789', issues: [] } })).toEqual({
      kind: 'saved',
      message: 'Правило «r» добавлено. Ревизия abcdef012345.',
    })
    expect(saveOutcome({ status: 409, body: { ok: false, issues: [], error: { code: 'revision_conflict', message: 'x' } } }).kind).toBe('conflict')
    expect(saveOutcome({ status: 409, body: { ok: false, issues: [], error: { code: 'config_invalid', message: 'x' } } }).kind).toBe('error')
    expect(saveOutcome({ status: 403, body: { ok: false, issues: [], error: { code: 'origin_forbidden', message: 'нет' } } })).toEqual({ kind: 'forbidden', message: 'нет' })
    expect(saveOutcome({ status: 422, body: { ok: false, issues: [] } }).kind).toBe('invalid')
  })
})

describe('профили (этап 7)', () => {
  it('профиль с точкой подключения готов к применению, без точки — нет', async () => {
    const { profileReady } = await import('./draft')
    expect(profileReady({ id: 'h', name: 'H', kind: 'hysteria2', on_failure: 'block', endpoint: { server: 'hy.example.com', port: 443, obfs: 'salamander' } })).toBe(true)
    expect(profileReady({ id: 't', name: 'T', kind: 'trusttunnel', on_failure: 'block' })).toBe(false)
    expect(profileReady({ id: 'v', name: 'V', kind: 'vless', on_failure: 'block' })).toBe(false)
    // этап 8: VLESS и WireGuard/AmneziaWG с точкой подключения применимы
    expect(profileReady({ id: 'v', name: 'V', kind: 'vless', on_failure: 'block', endpoint: { server: 'a.b', port: 1 } })).toBe(true)
    expect(profileReady({ id: 'w', name: 'W', kind: 'wireguard', on_failure: 'block', endpoint: { server: 'a.b', port: 51820 } })).toBe(true)
  })
  it('без TrustTunnel по умолчанию выбирается готовый профиль Hysteria2', () => {
    const c = { ...cfg, profiles: [cfg.profiles[0]!, { id: 'hy', name: 'HY', kind: 'hysteria2' as const, on_failure: 'block' as const, endpoint: { server: 'hy.example.com', port: 443 } }] }
    expect(defaultForm(c).actionProfile).toBe('hy')
  })
})
