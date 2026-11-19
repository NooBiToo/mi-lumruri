import { describe, expect, it } from 'vitest'
import type { Config, Lease, ListCatalog, ManageResponse } from './api'
import { defaultSimple, toConfig } from './simple'
import { deviceRows, knownDevices, lines, plural, readSimple, sitesSummary, strategyLabel, testedAt, tunnelState, when, zapretProgress, zapretResult } from './status'

const fresh: Config = { version: 1, profiles: [], networks: [], devices: [], groups: [], rules: [], default_action: { type: 'direct' } }
const profile = { id: 'tt', name: 'Мой сервер', kind: 'trusttunnel' as const, on_failure: 'block' as const,
  endpoint: { server: '203.0.113.10', port: 443, sni: 'vpn.example.com', username: 'alice', quic: false, anti_dpi: false } }
const catalog: ListCatalog = { source: 's', commit: 'c', date: '2026-11-09', services: [
  { id: 'youtube', name: 'YouTube', group: 'Сервисы', domains: 'Services/youtube.lst', ipv4: null },
  { id: 'telegram', name: 'Telegram', group: 'Сервисы', domains: 'Services/telegram.lst', ipv4: 'Subnets/IPv4/telegram.lst' },
  { id: 'discord', name: 'Discord', group: 'Сервисы', domains: 'Services/discord.lst', ipv4: null },
  { id: 'tiktok', name: 'TikTok', group: 'Сервисы', domains: 'Services/tiktok.lst', ipv4: null },
] }
const lan = { bridge: 'br-lan', subnet: '192.168.31.0/24', address: '192.168.31.1' }
const st = (service: unknown, extra: Partial<ManageResponse> = {}): ManageResponse => ({ ok: true, service, issues: [], ...extra })
const lease = (mac: string, hostname: string, ip = '192.168.31.20'): Lease => ({ mac, ip, hostname, device: null })

describe('status', () => {
  it('склоняет числа', () => {
    expect(plural(1, 'сайт', 'сайта', 'сайтов')).toBe('1 сайт')
    expect(plural(3, 'сайт', 'сайта', 'сайтов')).toBe('3 сайта')
    expect(plural(12, 'сайт', 'сайта', 'сайтов')).toBe('12 сайтов')
  })

  it('свежая установка — простые настройки по умолчанию, а не «изменено вручную»', () => {
    expect(readSimple(fresh)).toEqual({ canonical: true, simple: defaultSimple() })
    expect(readSimple({ ...fresh, profiles: [profile] })).toEqual({ canonical: true, simple: defaultSimple() })
    expect(readSimple({ ...fresh, networks: [{ id: 'guest', name: 'G', ssid: 'G' }] }).canonical).toBe(false)
    const cfg = toConfig({ ...fresh, profiles: [profile] }, { ...defaultSimple(), services: ['youtube'] }, lan, catalog, [])
    expect(readSimple(cfg)).toMatchObject({ canonical: true, simple: { services: ['youtube'] } })
  })

  it('состояние туннеля простыми словами', () => {
    const cfg = { ...fresh, profiles: [profile] }
    const on = { ...defaultSimple(), services: ['youtube'] }
    expect(tunnelState(st({ engines: { service: true } }), fresh, defaultSimple()).title).toBe('Сервер VPN не настроен')
    expect(tunnelState(st({ engines: { service: true, trusttunnel: true } }), cfg, { ...on, enabled: false }).title).toBe('VPN выключен')
    expect(tunnelState(st(null), cfg, on).tone).toBe('bad')
    expect(tunnelState(st({ engines: { service: true, trusttunnel: true } }, { apply_pending: true }), cfg, on).title).toBe('Применяю настройки…')
    expect(tunnelState(st({ engines: { service: true, trusttunnel: true } }), cfg, on)).toEqual({ tone: 'ok', title: 'VPN работает', detail: null })
    expect(tunnelState(st({ engines: { service: true, trusttunnel: false } }), cfg, on).tone).toBe('bad')
    const direct = { ...cfg, profiles: [{ ...profile, on_failure: 'direct' as const }] }
    expect(tunnelState(st({ engines: { service: true, trusttunnel: false } }), direct, on).tone).toBe('warn')
    expect(tunnelState(st({ engines: { service: true } }), cfg, defaultSimple()).title).toBe('VPN готов')
  })

  it('имена устройств: аренда, поверх — настройки, поверх — переименование', () => {
    const cfg = { ...fresh, devices: [{ id: 'dev-a', name: 'Телевизор', mac: 'AA:BB:CC:00:00:01', network: 'home' }] }
    const leases = [lease('aa:bb:cc:00:00:01', 'android-1234'), lease('aa:bb:cc:00:00:02', 'iPhone'), lease('aa:bb:cc:00:00:03', '')]
    expect(knownDevices(leases, cfg, {})).toEqual([{ mac: 'aa:bb:cc:00:00:01', name: 'Телевизор' }, { mac: 'aa:bb:cc:00:00:02', name: 'iPhone' }])
    expect(knownDevices(leases, cfg, { 'aa:bb:cc:00:00:01': ' ТВ в спальне ', 'aa:bb:cc:00:00:02': '  ' }))
      .toEqual([{ mac: 'aa:bb:cc:00:00:01', name: 'ТВ в спальне' }, { mac: 'aa:bb:cc:00:00:02', name: 'iPhone' }])
    // toConfig с этим списком сохраняет имя из настроек, а не из аренды
    const out = toConfig({ ...cfg, profiles: [profile] }, { ...defaultSimple(), devices: ['aa:bb:cc:00:00:01'] }, lan, catalog, knownDevices(leases, cfg, {}))
    expect(out.devices[0]?.name).toBe('Телевизор')
  })

  it('список устройств: сначала в сети, выбранные не в сети остаются', () => {
    const cfg = { ...fresh, devices: [{ id: 'dev-z', name: 'Ноутбук', mac: 'aa:bb:cc:00:00:09', network: 'home' }] }
    const rows = deviceRows([lease('aa:bb:cc:00:00:02', 'iPhone'), lease('aa:bb:cc:00:00:03', '')], cfg, {}, ['aa:bb:cc:00:00:07'])
    expect(rows.map((r) => [r.mac.slice(-2), r.name, r.online])).toEqual([['02', 'iPhone', true], ['03', '', true], ['09', 'Ноутбук', false], ['07', '', false]])
  })

  it('поля «по домену в строке» и сводка', () => {
    expect(lines(' a.com\n\nb.com, c.com ;d.com ')).toEqual(['a.com', 'b.com', 'c.com', 'd.com'])
    expect(sitesSummary({ ...defaultSimple(), services: ['youtube', 'telegram', 'discord', 'tiktok'], customDomains: ['a.com', 'b.com'] }, catalog))
      .toBe('YouTube, Telegram, Discord и ещё 1 · 2 своих сайта')
    expect(sitesSummary(defaultSimple(), catalog)).toBe('Пока ничего не выбрано')
    expect(sitesSummary({ ...defaultSimple(), mode: 'all', exceptions: ['a.ru'] }, catalog)).toBe('Все сайты, кроме 1 исключения')
  })

  it('Zapret: без id стратегий — название, прогресс и итог подбора', () => {
    expect(strategyLabel(undefined)).toBe('Автоматически (рекомендуется)')
    expect(strategyLabel({ strategy: 'auto', youtube: 'auto' })).toBe('Автоматически (рекомендуется)')
    expect(strategyLabel({ strategy: 'v4', youtube: 'auto' })).toBe('Подобран автоматически')
    const done = { state: 'done' as const, started: 1763540000, finished: 1763540200, control: { opened: 12, total: 54 }, best: { id: 'v4', opened: 47 }, applied: true,
      message: 'Применена стратегия v4: открылось 47 из 54, без Zapret — 12' }
    expect(testedAt(done)).toBe(1763540200)
    expect(strategyLabel({ strategy: 'v4', youtube: 'yv2' }, testedAt(done))).toBe(`Подобран автоматически ${when(1763540200)}`)
    expect(testedAt({ ...done, applied: false })).toBeNull()
    expect(zapretProgress({ state: 'running', progress: { done: 4, total: 11, current: 'v4' } })).toBe('Проверяю способы обхода: 5 из 11')
    expect(zapretProgress({ state: 'running', progress: { done: 0, total: 11, current: 'control' } })).toBe('Проверяю, что открывается без обхода: 1 из 11')
    expect(zapretResult(done)).toEqual({ summary: 'Открылось 47 из 54, без обхода — 12', message: 'Лучший способ применён.' })
    expect(zapretResult({ ...done, applied: false }).message).toBe('Способа лучше, чем без обхода, не нашлось — оставлен прежний.')
    const failed = zapretResult({ state: 'failed', message: 'Стратегия v4 при повторной проверке хуже, но вернуть прежнюю (v3) не удалось; действует v4' })
    expect(failed.message).not.toMatch(/[vV]\d/)
    expect(failed.message).toBe('Способ при повторной проверке хуже, но вернуть прежнюю не удалось; действует новый способ')
  })

})
