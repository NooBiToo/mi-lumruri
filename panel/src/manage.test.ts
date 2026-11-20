import { describe, expect, it } from 'vitest'
import { CUSTOM_DNS, DNS_PRESETS, dnsDefault, dnsPresetIp, dnsPresetOf, dnsToForm, emptyProfileForm, formToDns, formToProfile, formToSecret, profileToForm } from './manage'

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
    expect(dnsDefault()).toMatchObject({ resolver: '1.1.1.1', adblock: false, adblockSource: 'light', adblockUrl: '', exceptions: '', hosts: [], secure: 'off' })
    expect(dnsToForm(undefined)).toEqual(dnsDefault())
    expect(formToDns(dnsDefault())).toBeNull()
    expect(formToDns({ ...dnsDefault(), resolver: '  ' })).toBeNull()
  })
  it('свой резолвер и блокировка рекламы с исключениями, туда и обратно', () => {
    const d = formToDns({ ...dnsDefault(), resolver: ' 9.9.9.9 ', adblock: true, exceptions: 'ads.example.com\n\n  cdn.example.org ' })
    expect(d).toEqual({ tunnel_resolver: '9.9.9.9', adblock: { enabled: true, exceptions: ['ads.example.com', 'cdn.example.org'] } })
    expect(dnsToForm(d ?? undefined)).toEqual({ ...dnsDefault(), resolver: '9.9.9.9', adblock: true, exceptions: 'ads.example.com\ncdn.example.org' })
    expect(formToDns({ ...dnsDefault(), adblock: true })).toEqual({ adblock: { enabled: true } })
    expect(dnsToForm({ adblock: { enabled: false } })).toEqual(dnsDefault())
  })
  it('защищённый DNS: готовый сервер, NextDNS и свой — туда и обратно', () => {
    expect(formToDns({ ...dnsDefault(), secure: 'doh' })).toEqual({ secure: { protocol: 'doh', server: 'cloudflare' } })
    expect(formToDns({ ...dnsDefault(), secure: 'dot', secureServer: 'nextdns', nextdnsId: ' ABC123 ', secureUrl: 'лишнее' }))
      .toEqual({ secure: { protocol: 'dot', server: 'nextdns', nextdns_id: 'abc123' } })
    const c = formToDns({ ...dnsDefault(), secure: 'doh', secureServer: 'custom', secureUrl: ' https://dns.example/q ', secureIps: '203.0.113.5, 2001:db8::5' })
    expect(c).toEqual({ secure: { protocol: 'doh', server: 'custom', url: 'https://dns.example/q', ips: ['203.0.113.5', '2001:db8::5'] } })
    expect(dnsToForm(c ?? undefined)).toMatchObject({ secure: 'doh', secureServer: 'custom', secureIps: '203.0.113.5, 2001:db8::5' })
    expect(formToDns({ ...dnsDefault(), secure: 'off', secureServer: 'google' })).toBeNull()
  })
  it('список рекламы: Light не пишется, Normal и своя ссылка — туда и обратно', () => {
    expect(formToDns({ ...dnsDefault(), adblock: true, adblockSource: 'normal' })).toEqual({ adblock: { enabled: true, source: 'normal' } })
    const u = formToDns({ ...dnsDefault(), adblock: true, adblockSource: 'url', adblockUrl: ' https://example.org/ads.txt ' })
    expect(u).toEqual({ adblock: { enabled: true, source: 'url', url: 'https://example.org/ads.txt' } })
    expect(dnsToForm(u ?? undefined)).toMatchObject({ adblockSource: 'url', adblockUrl: 'https://example.org/ads.txt' })
  })
  it('свои DNS-записи, туда и обратно', () => {
    const h = formToDns({ ...dnsDefault(), hosts: [{ domain: 'home.example.com', address: '192.168.31.10' }] })
    expect(h).toEqual({ hosts: [{ domain: 'home.example.com', address: '192.168.31.10' }] })
    expect(dnsToForm(h ?? undefined).hosts).toEqual([{ domain: 'home.example.com', address: '192.168.31.10' }])
  })
  it('готовые серверы ↔ адрес: по умолчанию Cloudflare, незнакомый адрес — «Свой адрес»', () => {
    expect(DNS_PRESETS.map((p) => [p.id, p.ip])).toEqual([
      ['cloudflare', '1.1.1.1'], ['quad9', '9.9.9.9'], ['google', '8.8.8.8'], ['adguard', '94.140.14.14'], ['nextdns', '45.90.28.0'],
    ])
    for (const p of DNS_PRESETS) {
      expect(dnsPresetOf(p.ip)).toBe(p.id)
      expect(dnsPresetIp(p.id)).toBe(p.ip)
    }
    expect(dnsPresetOf(dnsToForm(undefined).resolver)).toBe('cloudflare')
    expect(dnsPresetOf('')).toBe('cloudflare')
    expect(dnsPresetOf(' 9.9.9.9 ')).toBe('quad9')
    expect(dnsPresetOf('1.0.0.1')).toBe(CUSTOM_DNS)
    expect(dnsPresetOf('9.9.9.10')).toBe(CUSTOM_DNS)
    expect(dnsPresetIp(CUSTOM_DNS)).toBeNull()
    // Cloudflare сохраняется как отсутствие раздела (по умолчанию), остальные — адресом
    expect(formToDns({ ...dnsDefault(), resolver: dnsPresetIp('cloudflare')! })).toBeNull()
    expect(formToDns({ ...dnsDefault(), resolver: dnsPresetIp('adguard')! })).toEqual({ tunnel_resolver: '94.140.14.14' })
    expect(DNS_PRESETS.find((p) => p.id === 'nextdns')?.note).toMatch(/Linked IP/)
  })
})
