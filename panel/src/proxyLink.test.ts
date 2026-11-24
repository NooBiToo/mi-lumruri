import { describe, expect, it } from 'vitest'
import { isAwgConf, isProxyLink, parseAwgConf, parseProxyLink } from './proxyLink'

describe('proxyLink', () => {
  it('vless reality, hysteria2, trojan ws, ss base64', () => {
    expect(parseProxyLink('vless://bf000d23-0752-40b4-affe-68f7707a9661@203.0.113.5:443?type=tcp&security=reality&pbk=k#%D0%94%D0%BE%D0%BC'))
      .toEqual({ kind: 'vless', info: { server: '203.0.113.5', port: 443, security: 'reality', transport: 'tcp' }, name: 'Дом' })
    expect(parseProxyLink('hy2://pw@[2001:db8::7]:8443/?sni=a')).toEqual({ kind: 'hysteria2', info: { server: '2001:db8::7', port: 8443, security: 'tls', transport: 'quic' } })
    expect(parseProxyLink('trojan://pw@t.example.com:443?type=ws')).toMatchObject({ kind: 'trojan', info: { security: 'tls', transport: 'ws' } })
    expect(parseProxyLink(`ss://${btoa('aes-256-gcm:pw@203.0.113.1:8388')}#S`)).toEqual({ kind: 'shadowsocks', info: { server: '203.0.113.1', port: 8388 }, name: 'S' })
    expect(parseProxyLink('ss://YWVzLTI1Ni1nY206cHc@h.example.com:1')).toMatchObject({ info: { server: 'h.example.com', port: 1 } })
  })
  it('errors and detection', () => {
    expect(isProxyLink('tt://?abc')).toBe(false)
    expect(isProxyLink(' VLESS://x')).toBe(true)
    expect(parseProxyLink('vless://h.example.com:443')).toHaveProperty('error')
    expect(parseProxyLink('vless://u@h.example.com')).toHaveProperty('error')
    expect(parseProxyLink('vmess://abc')).toHaveProperty('error')
  })
  it('amneziawg conf', () => {
    const c = '[Interface]\nPrivateKey = abc=\nAddress = 10.8.0.2/32\nJc = 4\n\n[Peer]\nPublicKey = def=\nEndpoint = [2001:db8::1]:51820\n'
    expect(isAwgConf(c)).toBe(true)
    expect(parseAwgConf(c)).toEqual({ kind: 'amneziawg', info: { server: '2001:db8::1', port: 51820, security: 'awg', transport: 'udp' } })
    expect(parseAwgConf(c.replace('Endpoint', 'X'))).toHaveProperty('error')
  })
})
