import { describe, expect, it } from 'vitest'
import type { Config, Lan, ListCatalog } from './api'
import { defaultSimple, fromConfig, serviceRoute, setServiceRoute, toConfig, type KnownDevice, type Simple } from './simple'
import validFixture from '../../fixtures/config.valid.json?raw'

const lan: Lan = { bridge: 'br-lan', subnet: '192.168.31.0/24', address: '192.168.31.1' }
const catalog: ListCatalog = {
  source: 'itdoginfo/allow-domains',
  commit: '932e11c43a9e000a24ba08129c15d99287c6e9a9',
  date: '2026-11-09',
  services: [
    { id: 'youtube', name: 'YouTube', group: 'Сервисы', domains: 'Services/youtube.lst', ipv4: null },
    { id: 'meta', name: 'Instagram и Facebook', group: 'Сервисы', domains: 'Services/meta.lst', ipv4: 'Subnets/IPv4/meta.lst' },
    { id: 'telegram', name: 'Telegram', group: 'Сервисы', domains: 'Services/telegram.lst', ipv4: 'Subnets/IPv4/telegram.lst' },
    { id: 'russia_inside', name: 'Заблокированное в России', group: 'Россия', domains: 'Russia/inside-raw.lst', ipv4: null },
  ],
}
const base: Config = {
  version: 1,
  profiles: [{
    id: 'tt', name: 'TrustTunnel', kind: 'trusttunnel', on_failure: 'block',
    endpoint: { server: '203.0.113.10', port: 443, sni: 'vpn.example.com', username: 'user', quic: false, anti_dpi: false },
  }],
  networks: [],
  devices: [],
  groups: [],
  rules: [],
  default_action: { type: 'direct' },
  dns: { tunnel_resolver: '1.1.1.1', adblock: { enabled: true } },
}
const known: KnownDevice[] = [
  { mac: 'A4-77-33-10-20-30', name: 'Телевизор' },
  { mac: '3c:22:fb:01:02:03', name: 'Телефон' },
]
const simple = (over: Partial<Simple>): Simple => ({ ...defaultSimple(), ...over })
const roundTrip = (s: Simple) => fromConfig(JSON.parse(JSON.stringify(toConfig(base, s, lan, catalog, known))) as Config)

describe('simple', () => {
  it('round_trip_selected_all_devices', () => {
    const s = simple({ services: ['youtube', 'meta'], customDomains: ['example.org'] })
    const c = toConfig(base, s, lan, catalog, known)
    expect(c.networks).toEqual([{ id: 'home', name: 'Домашняя сеть', ssid: 'Домашняя сеть', bridge: 'br-lan', subnet: '192.168.31.0/24' }])
    expect(c.devices).toEqual([])
    expect(c.categories).toEqual([
      { id: 'svc-youtube', name: 'YouTube', kind: 'domain', source: 'itdoginfo:Services/youtube.lst' },
      { id: 'svc-meta', name: 'Instagram и Facebook', kind: 'domain', source: 'itdoginfo:Services/meta.lst' },
      { id: 'svc-meta-ip', name: 'Instagram и Facebook: подсети', kind: 'ip', source: 'itdoginfo:Subnets/IPv4/meta.lst' },
    ])
    expect(c.groups.find((g) => g.id === 'vpn-sites')?.destinations).toEqual([
      { type: 'category', id: 'svc-youtube' },
      { type: 'category', id: 'svc-meta' },
      { type: 'category', id: 'svc-meta-ip' },
      { type: 'domain_suffix', value: 'example.org' },
    ])
    expect(c.groups.some((g) => g.id === 'vpn-except')).toBe(false)
    expect(c.rules.filter((r) => r.enabled)).toEqual([
      { id: 'vpn-lan', source: { type: 'lan' }, destination: { type: 'group', id: 'vpn-sites' }, action: { type: 'profile', id: 'tt' }, enabled: true },
    ])
    expect(c.default_action).toEqual({ type: 'direct' })
    expect(c.profiles).toBe(base.profiles)
    expect(c.dns).toBe(base.dns)
    expect(c.zapret).toBeUndefined()
    expect(roundTrip(s)).toEqual({ canonical: true, simple: s })
  })
  it('расписание (schedule) переносится и не мешает простому виду', () => {
    const s = simple({ services: ['youtube'] })
    const withSchedule = { ...base, schedule: { lists: '6h' as const, zapret_check: 'weekly' as const } }
    const c = toConfig(withSchedule, s, lan, catalog, known)
    expect(c.schedule).toEqual(withSchedule.schedule)
    expect(fromConfig(JSON.parse(JSON.stringify(c)) as Config)).toEqual({ canonical: true, simple: s })
  })

  it('round_trip_all_mode_with_exceptions', () => {
    const s = simple({ mode: 'all', services: ['telegram'], exceptions: ['gosuslugi.ru', 'sberbank.ru'], rest: 'zapret' })
    const c = toConfig(base, s, lan, catalog, known)
    expect(c.groups.find((g) => g.id === 'vpn-except')?.destinations).toEqual([
      { type: 'domain_suffix', value: 'gosuslugi.ru' },
      { type: 'domain_suffix', value: 'sberbank.ru' },
    ])
    const active = c.rules.filter((r) => r.enabled)
    expect(active.map((r) => [r.id, r.destination, r.action])).toEqual([
      ['except-lan', { type: 'group', id: 'vpn-except' }, { type: 'direct_zapret' }],
      ['vpn-lan', { type: 'group', id: 'vpn-all' }, { type: 'profile', id: 'tt' }],
    ])
    expect(c.default_action).toEqual({ type: 'profile', id: 'tt' })
    expect(roundTrip(s)).toEqual({ canonical: true, simple: s })
    // режим «всё через VPN» без исключений: выбор «остальных сайтов» не теряется
    const bare = simple({ mode: 'all', rest: 'zapret' })
    expect(roundTrip(bare)).toEqual({ canonical: true, simple: bare })
  })

  it('selected_devices_rules_per_device', () => {
    const s = simple({ services: ['youtube'], exceptions: ['music.youtube.com'], devices: ['a4:77:33:10:20:30', '3c:22:fb:01:02:03'] })
    const c = toConfig(base, s, lan, catalog, known)
    expect(c.devices).toEqual([
      { id: 'dev-a47733102030', name: 'Телевизор', mac: 'a4:77:33:10:20:30', network: 'home' },
      { id: 'dev-3c22fb010203', name: 'Телефон', mac: '3c:22:fb:01:02:03', network: 'home' },
    ])
    expect(c.rules.filter((r) => r.enabled).map((r) => [r.id, r.source, r.destination, r.action.type])).toEqual([
      ['except-dev-a47733102030', { type: 'device', id: 'dev-a47733102030' }, { type: 'group', id: 'vpn-except' }, 'direct'],
      ['vpn-dev-a47733102030', { type: 'device', id: 'dev-a47733102030' }, { type: 'group', id: 'vpn-sites' }, 'profile'],
      ['except-dev-3c22fb010203', { type: 'device', id: 'dev-3c22fb010203' }, { type: 'group', id: 'vpn-except' }, 'direct'],
      ['vpn-dev-3c22fb010203', { type: 'device', id: 'dev-3c22fb010203' }, { type: 'group', id: 'vpn-sites' }, 'profile'],
    ])
    expect(c.default_action).toEqual({ type: 'direct' })
    expect(roundTrip(s)).toEqual({ canonical: true, simple: s })
    // «всё через VPN» для выбранных устройств: остальная сеть идёт напрямую
    const all = { ...s, mode: 'all' as const }
    const ca = toConfig(base, all, lan, catalog, known)
    expect(ca.default_action).toEqual({ type: 'direct' })
    expect(ca.rules.filter((r) => r.enabled && r.id.startsWith('vpn-')).map((r) => r.destination)).toEqual([
      { type: 'group', id: 'vpn-all' }, { type: 'group', id: 'vpn-all' },
    ])
    expect(roundTrip(all)).toEqual({ canonical: true, simple: all })
  })

  it('selected devices survive with nothing selected yet; unknown MAC gets its own name', () => {
    const s = simple({ devices: ['02:00:00:00:00:01'] })
    const c = toConfig(base, s, lan, catalog, known)
    expect(c.devices).toEqual([{ id: 'dev-020000000001', name: '02:00:00:00:00:01', mac: '02:00:00:00:00:01', network: 'home' }])
    expect(roundTrip(s)).toEqual({ canonical: true, simple: s })
  })

  it('disable_keeps_selection', () => {
    const s = simple({ enabled: false, services: ['meta'], customDomains: ['example.org'], exceptions: ['ya.ru'], rest: 'zapret', devices: ['3c:22:fb:01:02:03'] })
    const c = toConfig(base, s, lan, catalog, known)
    expect(c.rules.length).toBeGreaterThan(0)
    expect(c.rules.every((r) => r.enabled === false)).toBe(true)
    expect(c.rules.some((r) => r.id === 'vpn-off')).toBe(true)
    expect(c.default_action).toEqual({ type: 'direct' })
    const back = roundTrip(s)
    expect(back).toEqual({ canonical: true, simple: s })
    // включение возвращает прежние галочки
    if (!back.canonical) throw new Error('ожидался простой вид')
    const on = toConfig(base, { ...back.simple, enabled: true }, lan, catalog, known)
    expect(on.rules.filter((r) => r.enabled).map((r) => r.id)).toEqual(['except-dev-3c22fb010203', 'vpn-dev-3c22fb010203'])
    expect(on.default_action).toEqual({ type: 'direct_zapret' })
    // выключено и ничего не выбрано: состояние тоже не теряется
    for (const x of [simple({ enabled: false }), simple({ enabled: false, rest: 'zapret' }), simple({ enabled: false, mode: 'all' })]) {
      expect(roundTrip(x)).toEqual({ canonical: true, simple: x })
    }
  })

  it('zapret_rest', () => {
    const c = toConfig(base, simple({ services: ['youtube'], rest: 'zapret' }), lan, catalog, known)
    expect(c.default_action).toEqual({ type: 'direct_zapret' })
    expect(c.zapret).toBeUndefined()
    const z = toConfig({ ...base, zapret: { strategy: 'v4', youtube: 'auto' } as unknown as Config['zapret'] }, simple({ rest: 'zapret' }), lan, catalog, known)
    expect(z.zapret).toEqual({ strategy: 'v4', youtube: 'auto' })
  })

  it('non_canonical_detected', () => {
    const r = fromConfig(JSON.parse(validFixture) as Config)
    expect(r.canonical).toBe(false)
    if (!r.canonical) expect(r.reason).toMatch(/сет/)
    // ручная правка простого вида тоже замечается
    const c = toConfig(base, simple({ services: ['youtube'] }), lan, catalog, known)
    c.rules.push({ id: 'my', source: { type: 'lan' }, destination: { type: 'domain_suffix', value: 'example.com' }, action: { type: 'block' }, enabled: true })
    expect(fromConfig(c).canonical).toBe(false)
  })

  it('normalizes input: domains, MACs, unknown services, device names', () => {
    const s = simple({
      services: ['youtube', 'youtube', 'gone'],
      customDomains: [' https://Example.ORG/path ', '*.foo.com', '.bar.net.', '', 'example.org'],
      devices: ['A4-77-33-10-20-30', 'a4:77:33:10:20:30', 'bad'],
    })
    const c = toConfig(base, s, lan, catalog, [{ mac: 'a4:77:33:10:20:30', name: '  ТВ\u0007 в зале  ' }])
    expect(c.categories?.map((x) => x.id)).toEqual(['svc-youtube'])
    expect(c.groups.find((g) => g.id === 'vpn-sites')?.destinations.slice(1)).toEqual([
      { type: 'domain_suffix', value: 'example.org' },
      { type: 'domain_suffix', value: 'foo.com' },
      { type: 'domain_suffix', value: 'bar.net' },
    ])
    expect(c.devices).toEqual([{ id: 'dev-a47733102030', name: 'ТВ в зале', mac: 'a4:77:33:10:20:30', network: 'home' }])
  })

  it('keeps device names from the current settings when the lease has none', () => {
    const first = toConfig(base, simple({ devices: ['a4:77:33:10:20:30'] }), lan, catalog, known)
    const again = toConfig(first, simple({ devices: ['a4:77:33:10:20:30'] }), lan, catalog, [{ mac: 'a4:77:33:10:20:30', name: '' }])
    expect(again.devices[0]?.name).toBe('Телевизор')
  })

  it('zapret_sites: группа, правила по порядку и туда-обратно', () => {
    const s = simple({ services: ['youtube'], customDomains: ['example.org'], zapretServices: ['meta'], zapretDomains: ['rutracker.org'], exceptions: ['ya.ru'] })
    const c = toConfig(base, s, lan, catalog, known)
    expect(c.categories?.map((x) => x.id)).toEqual(['svc-youtube', 'svc-meta', 'svc-meta-ip'])
    expect(c.groups.map((g) => g.id)).toEqual(['vpn-sites', 'zapret-sites', 'vpn-except', 'vpn-all'])
    expect(c.groups.find((g) => g.id === 'zapret-sites')?.destinations).toEqual([
      { type: 'category', id: 'svc-meta' },
      { type: 'category', id: 'svc-meta-ip' },
      { type: 'domain_suffix', value: 'rutracker.org' },
    ])
    // в каждом источнике: исключения, затем сайты с обходом, затем VPN
    expect(c.rules.filter((r) => r.enabled).map((r) => [r.id, r.destination, r.action])).toEqual([
      ['except-lan', { type: 'group', id: 'vpn-except' }, { type: 'direct' }],
      ['zapret-lan', { type: 'group', id: 'zapret-sites' }, { type: 'direct_zapret' }],
      ['vpn-lan', { type: 'group', id: 'vpn-sites' }, { type: 'profile', id: 'tt' }],
    ])
    expect(roundTrip(s)).toEqual({ canonical: true, simple: s })
    // только сайты с обходом, без VPN и без сервера
    const only = simple({ zapretDomains: ['rutracker.org'] })
    const none = { ...base, profiles: [] }
    expect(toConfig(none, only, lan, catalog, known).rules.filter((r) => r.enabled).map((r) => r.id)).toEqual(['zapret-lan'])
    expect(fromConfig(JSON.parse(JSON.stringify(toConfig(none, only, lan, catalog, known))) as Config)).toEqual({ canonical: true, simple: only })
    expect(roundTrip(only)).toEqual({ canonical: true, simple: only })
  })

  it('zapret_sites: «всё через VPN» не забирает их в VPN, по устройствам — у каждого своё правило', () => {
    const all = simple({ mode: 'all', zapretServices: ['youtube'], exceptions: ['gosuslugi.ru'] })
    const c = toConfig(base, all, lan, catalog, known)
    expect(c.rules.filter((r) => r.enabled).map((r) => [r.id, r.destination])).toEqual([
      ['except-lan', { type: 'group', id: 'vpn-except' }],
      ['zapret-lan', { type: 'group', id: 'zapret-sites' }],
      ['vpn-lan', { type: 'group', id: 'vpn-all' }],
    ])
    expect(c.default_action).toEqual({ type: 'profile', id: 'tt' })
    expect(roundTrip(all)).toEqual({ canonical: true, simple: all })
    const devs = simple({ services: ['telegram'], zapretDomains: ['rutracker.org'], devices: ['a4:77:33:10:20:30', '3c:22:fb:01:02:03'] })
    expect(toConfig(base, devs, lan, catalog, known).rules.filter((r) => r.enabled).map((r) => r.id)).toEqual([
      'zapret-dev-a47733102030', 'vpn-dev-a47733102030', 'zapret-dev-3c22fb010203', 'vpn-dev-3c22fb010203',
    ])
    expect(roundTrip(devs)).toEqual({ canonical: true, simple: devs })
  })

  it('zapret_sites: при выключенном VPN правила обхода остаются включёнными', () => {
    const s = simple({ enabled: false, services: ['youtube'], zapretServices: ['telegram'], zapretDomains: ['rutracker.org'], exceptions: ['ya.ru'] })
    const c = toConfig(base, s, lan, catalog, known)
    expect(c.rules.filter((r) => r.enabled).map((r) => r.id)).toEqual(['zapret-lan'])
    expect(c.rules.filter((r) => !r.enabled).map((r) => r.id)).toEqual(['except-lan', 'vpn-lan', 'vpn-off'])
    expect(c.default_action).toEqual({ type: 'direct' })
    expect(roundTrip(s)).toEqual({ canonical: true, simple: s })
  })

  it('zapret_sites: сервис не бывает и в VPN, и с обходом', () => {
    // в настройки сервис из обоих списков попадает один раз — в VPN
    const both = toConfig(base, simple({ services: ['youtube'], zapretServices: ['youtube', 'meta'] }), lan, catalog, known)
    expect(both.categories?.map((x) => x.id)).toEqual(['svc-youtube', 'svc-meta', 'svc-meta-ip'])
    expect(both.groups.find((g) => g.id === 'zapret-sites')?.destinations.map((d) => (d.type === 'category' ? d.id : ''))).toEqual(['svc-meta', 'svc-meta-ip'])
    // помощник экрана: выбор для плитки убирает сервис из другого списка
    let l = { services: ['youtube'], zapretServices: ['meta'] }
    expect(serviceRoute(l, 'youtube')).toBe('vpn')
    expect(serviceRoute(l, 'meta')).toBe('zapret')
    expect(serviceRoute(l, 'telegram')).toBe('off')
    l = setServiceRoute(l, 'youtube', 'zapret')
    expect(l).toEqual({ services: [], zapretServices: ['meta', 'youtube'] })
    l = setServiceRoute(l, 'meta', 'vpn')
    expect(l).toEqual({ services: ['meta'], zapretServices: ['youtube'] })
    l = setServiceRoute(l, 'meta', 'off')
    expect(l).toEqual({ services: [], zapretServices: ['youtube'] })
    expect(setServiceRoute(l, 'youtube', 'zapret')).toEqual(l)
  })

  it('zapret_sites: прежний канонический вид без них читается с пустыми списками; ручные правки замечаются', () => {
    const s = simple({ services: ['youtube'], exceptions: ['ya.ru'] })
    const old = JSON.parse(JSON.stringify(toConfig(base, s, lan, catalog, known))) as Config
    expect(old.groups.some((g) => g.id === 'zapret-sites')).toBe(false)
    const r = fromConfig(old)
    expect(r).toEqual({ canonical: true, simple: s })
    if (r.canonical) expect([r.simple.zapretServices, r.simple.zapretDomains]).toEqual([[], []])
    // правило обхода без группы, группа без правила, выключенное правило, чужое действие — уже не простой вид
    const z = JSON.parse(JSON.stringify(toConfig(base, simple({ zapretDomains: ['rutracker.org'] }), lan, catalog, known))) as Config
    const noRule = { ...z, rules: z.rules.filter((x) => x.id !== 'zapret-lan') }
    expect(fromConfig(noRule).canonical).toBe(false)
    const off = { ...z, rules: z.rules.map((x) => (x.id === 'zapret-lan' ? { ...x, enabled: false } : x)) }
    expect(fromConfig(off).canonical).toBe(false)
    const vpn = { ...z, rules: z.rules.map((x) => (x.id === 'zapret-lan' ? { ...x, action: { type: 'profile' as const, id: 'tt' } } : x)) }
    expect(fromConfig(vpn).canonical).toBe(false)
    const ip = { ...z, groups: z.groups.map((g) => (g.id === 'zapret-sites' ? { ...g, destinations: [...g.destinations, { type: 'cidr' as const, value: '10.0.0.0/8' }] } : g)) }
    expect(fromConfig(ip)).toMatchObject({ canonical: false, reason: expect.stringMatching(/вручную/) })
  })

  it('весь интернет через VPN для отдельного устройства: правила до источников и туда-обратно', () => {
    const tv = 'a4:77:33:10:20:30'
    const s = simple({ services: ['youtube'], exceptions: ['bank.example'], vpnAll: [tv] })
    const c = toConfig(base, s, lan, catalog, known)
    expect(c.devices.map((d) => d.mac)).toEqual([tv])
    expect(c.rules.map((r) => r.id)).toEqual(['except-dev-a47733102030', 'vpnall-dev-a47733102030', 'except-lan', 'vpn-lan', 'rest-lan'])
    expect(c.rules[1]).toMatchObject({ destination: { type: 'group', id: 'vpn-all' }, action: { type: 'profile', id: 'tt' } })
    expect(roundTrip(s)).toEqual({ canonical: true, simple: { ...s, vpnAll: [tv] } })
    // выбранные устройства и отдельное «весь интернет»
    const sel = simple({ services: ['youtube'], devices: ['3c:22:fb:01:02:03'], vpnAll: [tv] })
    expect(roundTrip(sel)).toEqual({ canonical: true, simple: sel })
    // в режиме «всё через VPN» список не нужен: так идут все
    const all = simple({ mode: 'all', vpnAll: [tv] })
    expect(toConfig(base, all, lan, catalog, known).rules.some((r) => r.id.startsWith('vpnall-'))).toBe(false)
    expect(roundTrip(all)).toEqual({ canonical: true, simple: simple({ mode: 'all' }) })
  })

  it('requires a profile only when something goes through VPN', () => {
    const none = { ...base, profiles: [] }
    expect(() => toConfig(none, simple({ services: ['youtube'] }), lan, catalog, known)).toThrow(/сервер/)
    expect(toConfig(none, simple({}), lan, catalog, known).rules.map((r) => r.id)).toEqual(['rest-lan'])
  })
  it('несколько серверов: сервисы и устройство через другой сервер, туда-обратно; сервер по умолчанию — наименьший номер туннеля', () => {
    const two: Config = { ...base, profiles: [{ ...base.profiles[0]!, id: 'hy', name: 'Второй', tunnel: 1 }, base.profiles[0]!] }
    const s = simple({ services: ['youtube', 'meta', 'telegram'], customDomains: ['example.org'], serviceServer: { youtube: 'hy' },
      devices: ['a4:77:33:10:20:30'], vpnAll: ['3c:22:fb:01:02:03'], deviceServer: { '3c:22:fb:01:02:03': 'hy' } })
    const c = toConfig(two, s, lan, catalog, known)
    expect(c.groups.find((g) => g.id === 'vpn-sites--hy')?.destinations).toEqual([{ type: 'category', id: 'svc-youtube' }])
    expect(c.groups.find((g) => g.id === 'vpn-sites')?.destinations.some((d) => d.type === 'category' && d.id === 'svc-youtube')).toBe(false)
    const ids = c.rules.map((r) => r.id)
    expect(ids.indexOf('vpn-dev-a47733102030--hy')).toBeLessThan(ids.indexOf('vpn-dev-a47733102030'))
    expect(c.rules.find((r) => r.id === 'vpn-dev-a47733102030--hy')?.action).toEqual({ type: 'profile', id: 'hy' })
    expect(c.rules.find((r) => r.id === 'vpn-dev-a47733102030')?.action).toEqual({ type: 'profile', id: 'tt' })
    expect(c.rules.find((r) => r.id === 'vpnall-dev-3c22fb010203')?.action).toEqual({ type: 'profile', id: 'hy' })
    const back = fromConfig(JSON.parse(JSON.stringify(c)) as Config)
    expect(back.canonical).toBe(true)
    if (back.canonical) {
      expect(back.simple.serviceServer).toEqual({ youtube: 'hy' })
      expect(back.simple.deviceServer).toEqual({ '3c:22:fb:01:02:03': 'hy' })
      expect([...back.simple.services].sort()).toEqual(['meta', 'telegram', 'youtube'])
    }
    // сервер удалили — его сервисы уходят на сервер по умолчанию, отметка забывается
    const one = toConfig(base, s, lan, catalog, known)
    expect(one.groups.some((g) => g.id.startsWith('vpn-sites--'))).toBe(false)
    expect(one.rules.find((r) => r.id === 'vpnall-dev-3c22fb010203')?.action).toEqual({ type: 'profile', id: 'tt' })
  })

})
