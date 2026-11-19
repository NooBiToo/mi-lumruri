import { describe, expect, it } from 'vitest'
import type { Config, ManageResponse } from './api'
import { destShort, exitKind, exitShort, plural, routeKind, routeLabel, sourceShort, tunnelState } from './route'

const cfg: Config = {
  version: 1,
  profiles: [{ id: 'tt', name: 'Дом', kind: 'trusttunnel', on_failure: 'block' }],
  networks: [{ id: 'guest', name: 'Гостевая', ssid: 'Guest' }],
  devices: [{ id: 'tv', name: 'Телевизор', mac: 'aa:bb:cc:dd:ee:ff', network: 'guest' }],
  groups: [{ id: 'video', name: 'Видео', destinations: [] }],
  rules: [],
  default_action: { type: 'direct' },
}

const st = (service: unknown): ManageResponse => ({ ok: true, service, issues: [] })

describe('маршрут', () => {
  it('подписывает источник, назначение и действие', () => {
    expect(sourceShort({ type: 'device', id: 'tv' }, cfg)).toBe('Телевизор')
    expect(sourceShort({ type: 'lan' }, cfg)).toBe('Вся LAN')
    expect(destShort({ type: 'group', id: 'video' }, cfg)).toBe('Видео')
    expect(destShort({ type: 'domain_suffix', value: 'example.com' }, cfg)).toBe('*.example.com')
    expect(routeLabel({ type: 'profile', id: 'tt' }, cfg)).toBe('Дом')
    expect(routeKind({ type: 'direct_zapret' })).toBe('zapret')
  })

  it('распознаёт выходы из ответа предпросмотра', () => {
    expect(exitKind('VPN «Дом» (TrustTunnel)')).toBe('tunnel')
    expect(exitKind('маршрут по умолчанию: прямой выход')).toBe('direct')
    expect(exitKind('прямой выход с Zapret')).toBe('zapret')
    expect(exitKind('блокировка')).toBe('block')
    expect(exitKind('что-то другое')).toBeNull()
    expect(exitShort('маршрут по умолчанию: VPN «Дом» (TrustTunnel)')).toBe('Дом')
    expect(exitShort('прямой выход с Zapret')).toBe('Напрямую с Zapret')
    expect(exitShort('блокировка')).toBe('Блокировать')
  })

  it('склоняет числа', () => {
    expect(plural(1, 'правило', 'правила', 'правил')).toBe('1 правило')
    expect(plural(3, 'правило', 'правила', 'правил')).toBe('3 правила')
    expect(plural(12, 'правило', 'правила', 'правил')).toBe('12 правил')
  })
})

describe('состояние туннеля', () => {
  it('служба не сообщала состояние', () => {
    expect(tunnelState(st(null), cfg).title).toBe('Служба не запущена')
  })
  it('туннель работает', () => {
    expect(tunnelState(st({ engines: { service: true, trusttunnel: true } }), cfg).tone).toBe('ok')
  })
  it('туннель упал, правила блокируются', () => {
    expect(tunnelState(st({ engines: { service: true, trusttunnel: false } }), cfg).title).toBe('Туннель не подключён — трафик правил блокируется')
  })
  it('туннель упал, профиль пускает напрямую', () => {
    const c = { ...cfg, profiles: [{ ...cfg.profiles[0]!, on_failure: 'direct' as const }] }
    expect(tunnelState(st({ engines: { service: true, trusttunnel: false } }), c).tone).toBe('warn')
  })
  it('без профиля — туннель не настроен', () => {
    expect(tunnelState(st({ engines: { service: true } }), { ...cfg, profiles: [] }).title).toBe('Туннель не настроен')
  })
})
