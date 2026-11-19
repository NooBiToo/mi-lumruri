import { describe, expect, it } from 'vitest'
import { deviceFromLease, dnsDefault, dnsToForm, emptyNetworkForm, emptyProfileForm, formToDns, formToNetwork, formToProfile, formToSecret, networkToForm, profileToForm } from './manage'
import { defaultForm, toRequest } from './draft'
import type { Config } from './api'

const PEM = '-----BEGIN CERTIFICATE-----\nMIIBszCCAVmgAwIBAgIUQ\n-----END CERTIFICATE-----'

describe('профиль TrustTunnel', () => {
  it('минимальная форма: HTTP/2, без SNI и сертификата', () => {
    const f = { ...emptyProfileForm(), id: 'tt', name: 'TT', server: ' 203.0.113.10 ', username: ' alice ' }
    expect(formToProfile(f)).toEqual({
      id: 'tt', name: 'TT', kind: 'trusttunnel', on_failure: 'block',
      endpoint: { server: '203.0.113.10', port: 443, username: 'alice', quic: false, anti_dpi: false },
    })
  })
  it('туда и обратно: SNI, HTTP/3, anti-DPI, сертификат PEM, обход при отказе', () => {
    const f = {
      ...emptyProfileForm(), id: 'tt', name: 'TT', server: '203.0.113.10', port: '8443', sni: 'vpn.example.com', username: 'alice',
      quic: true, antiDpi: true, certificate: `\r\n${PEM.replace(/\n/g, '\r\n')}\r\n\r\n`, onFailure: 'direct' as const,
    }
    const p = formToProfile(f)
    expect(p).toEqual({
      id: 'tt', name: 'TT', kind: 'trusttunnel', on_failure: 'direct',
      endpoint: { server: '203.0.113.10', port: 8443, sni: 'vpn.example.com', username: 'alice', quic: true, anti_dpi: true, certificate: `${PEM}\n` },
    })
    if (typeof p !== 'object') throw new Error(p)
    const back = profileToForm(p)
    expect(back).toEqual({ ...f, certificate: `${PEM}\n`, password: '' })
    // повторное сохранение без изменений даёт тот же профиль
    expect(formToProfile(back)).toEqual(p)
  })
  it('профиль без точки подключения открывается пустой формой', () => {
    expect(profileToForm({ id: 'tt', name: 'TT', kind: 'trusttunnel', on_failure: 'block' })).toEqual({ ...emptyProfileForm(), id: 'tt', name: 'TT' })
  })
  it('неверный порт — ошибка формы, запрос не отправляется', () => {
    for (const port of ['', '0', '65536', '44.3', 'abc']) expect(typeof formToProfile({ ...emptyProfileForm(), port })).toBe('string')
  })
  it('секрет — только пароль; пустое поле — пароль не меняется', () => {
    expect(formToSecret({ ...emptyProfileForm(), password: ' p@ss ' })).toEqual({ password: ' p@ss ' }) // secret-scan: allow значение формы в тесте
    expect(formToSecret(emptyProfileForm())).toBeNull()
  })
})

describe('DNS', () => {
  it('по умолчанию — резолвер 1.1.1.1 без блокировки рекламы; сохраняется как null', () => {
    expect(dnsDefault()).toEqual({ resolver: '1.1.1.1', adblock: false, exceptions: '' })
    expect(dnsToForm(undefined)).toEqual(dnsDefault())
    expect(formToDns(dnsDefault())).toBeNull()
    expect(formToDns({ ...dnsDefault(), resolver: '  ' })).toBeNull()
  })
  it('свой резолвер и блокировка рекламы с исключениями, туда и обратно', () => {
    const d = formToDns({ resolver: ' 9.9.9.9 ', adblock: true, exceptions: 'ads.example.com\n\n  cdn.example.org ' })
    expect(d).toEqual({ tunnel_resolver: '9.9.9.9', adblock: { enabled: true, exceptions: ['ads.example.com', 'cdn.example.org'] } })
    expect(dnsToForm(d ?? undefined)).toEqual({ resolver: '9.9.9.9', adblock: true, exceptions: 'ads.example.com\ncdn.example.org' })
    expect(formToDns({ ...dnsDefault(), adblock: true })).toEqual({ adblock: { enabled: true } })
    expect(dnsToForm({ adblock: { enabled: false } })).toEqual(dnsDefault())
  })
})

describe('правила', () => {
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
