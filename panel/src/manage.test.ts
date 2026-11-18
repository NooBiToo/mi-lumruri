import { describe, expect, it } from 'vitest'
import { deviceFromLease, emptyNetworkForm, emptyProfileForm, formToNetwork, formToProfile, formToSecret, networkToForm, parseAwg, profileToForm } from './manage'
import { defaultForm, toRequest } from './draft'
import type { Config } from './api'

describe('управление профилями', () => {
  it('Hysteria2 с obfs: профиль и два секрета', () => {
    const f = { ...emptyProfileForm('hysteria2'), id: 'hy', name: 'HY', server: 'hy.example.com', sni: 'hy.example.com', obfs: true, secret1: 'p', secret2: 'o' }
    expect(formToProfile(f)).toEqual({ id: 'hy', name: 'HY', kind: 'hysteria2', on_failure: 'block', endpoint: { server: 'hy.example.com', port: 443, sni: 'hy.example.com', obfs: 'salamander' } })
    expect(formToSecret(f)).toEqual({ password: 'p', obfs_password: 'o' })
  })
  it('VLESS REALITY и TLS', () => {
    const r = { ...emptyProfileForm('vless'), id: 'v', name: 'V', server: 'v.example', sni: 'www.example.org', security: 'reality' as const, realityKey: 'K', realityShortId: 'ab' }
    expect(formToProfile(r)).toMatchObject({ endpoint: { security: 'reality', flow: 'xtls-rprx-vision', reality: { public_key: 'K', short_id: 'ab' } } })
    const id = crypto.randomUUID()
    expect(formToSecret({ ...r, secret1: id })).toEqual({ uuid: id })
  })
  it('AmneziaWG: параметры строкой и обратно', () => {
    const f = { ...emptyProfileForm('wireguard'), id: 'a', name: 'A', server: 'wg.example', publicKey: 'PK', address: '10.66.66.2/32', awg: true }
    const p = formToProfile(f)
    expect(typeof p).toBe('object')
    if (typeof p === 'object') {
      expect(p.endpoint?.awg).toEqual({ jc: 4, jmin: 40, jmax: 70, s1: 37, s2: 61, h1: 1361409513, h2: 2016328541, h3: 726101713, h4: 1919296617 })
      expect(profileToForm(p).awgText).toContain('h4=1919296617')
    }
    expect(parseAwg('jc=4 bad=1')).toMatch(/неверный/)
    expect(parseAwg('jc=4')).toMatch(/не хватает/)
    expect(formToSecret({ ...f, secret1: '' })).toBeNull()
  })
  it('правило с назначением-категорией', () => {
    const cfg: Config = { version: 1, profiles: [], networks: [{ id: 'home', name: 'H', ssid: 'H' }], devices: [{ id: 'tv', name: 'TV', mac: 'a4:77:33:10:20:30', network: 'home' }],
      groups: [], categories: [{ id: 'geo', name: 'Geo', kind: 'domain' }], rules: [], default_action: { type: 'direct' } }
    const f = { ...defaultForm(cfg), destType: 'category' as const, destGroup: 'geo', actionType: 'direct' as const }
    expect(toRequest(f).rule.destination).toEqual({ type: 'category', id: 'geo' })
  })
})

describe('сети и устройства', () => {
  it('сеть SSID: порты через пробел или запятую, туда и обратно', () => {
    const n = formToNetwork({ ...emptyNetworkForm(), id: 'iot', name: 'IoT', ssid: 'Home-IoT', ports: 'wl2, wl3', subnet: '10.10.3.0/24' })
    expect(n).toEqual({ id: 'iot', name: 'IoT', ssid: 'Home-IoT', subnet: '10.10.3.0/24', bridge: 'br-lan', ports: ['wl2', 'wl3'] })
    expect(networkToForm(n as never).ports).toBe('wl2 wl3')
    expect(typeof formToNetwork({ ...emptyNetworkForm(), id: 'x', name: 'x', ssid: 'x', bridge: '', ports: 'wl0' })).toBe('string')
    expect(typeof formToNetwork(emptyNetworkForm())).toBe('string')
  })
  it('устройство из аренды DHCP: безопасный идентификатор из имени клиента', () => {
    expect(deviceFromLease({ mac: '02:00:00:00:0e:02', ip: '10.10.1.77', hostname: 'Living-Room TV <b>', device: null }, 'home'))
      .toEqual({ id: 'living-room-tv-b', name: 'Living-Room TV <b>', mac: '02:00:00:00:0e:02', network: 'home' })
    expect(deviceFromLease({ mac: '02:00:00:00:0e:02', ip: '10.10.1.77', hostname: '', device: null }, 'home').id).toBe('dev-000e02')
  })
})
