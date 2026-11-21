import { describe, expect, it } from 'vitest'
import { parseClientToml, parseDeepLink, parseServer } from './serverConfig'
import exportToml from './fixtures/endpoint-export.toml?raw'
import exportLink from './fixtures/endpoint-export.deeplink.txt?raw'

const PEM = `-----BEGIN CERTIFICATE-----
MIIBszCCAVmgAwIBAgIUYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXowCgYIKoZI
zj0EAwIwGjEYMBYGA1UEAwwPdnBuLmV4YW1wbGUuY29t
-----END CERTIFICATE-----`

// вид вывода `trusttunnel_endpoint vpn.toml hosts.toml -c user -a 203.0.113.10:443 --format toml`
const EXPORT = `# Сгенерировано trusttunnel_endpoint
hostname = "vpn.example.com"
addresses = ["203.0.113.10:443"]
has_ipv6 = true
username = "alice"
password = "p@ss \\"word\\"" # secret-scan: allow тестовый пример
client_random = ""
skip_verification = false
certificate = '''
${PEM}
'''
upstream_protocol = "http3"
anti_dpi = true
custom_sni = ""
`

describe('serverConfig', () => {
  it('parse_client_toml_export', () => {
    expect(parseClientToml(EXPORT)).toEqual({
      endpoint: { server: '203.0.113.10', port: 443, sni: 'vpn.example.com', username: 'alice', quic: true, anti_dpi: true, certificate: PEM },
      password: 'p@ss "word"',
    })
  })

  it('reads the [endpoint] table of a full client.toml and ignores other tables', () => {
    const full = `loglevel = "info"
vpn_mode = "general"
exclusions = []

[endpoint]
hostname = 'vpn.example.com'   # имя в сертификате
addresses = [
  "[2001:db8::1]:8443",
  "203.0.113.10:443",
]
username = "bob"
password = 'secret#1' # secret-scan: allow тестовый пример
certificate = ""
upstream_protocol = "http2"
anti_dpi = false

[listener.tun]
device_name = "tun0"
included_routes = []
`
    expect(parseClientToml(full)).toEqual({
      endpoint: { server: '2001:db8::1', port: 8443, sni: 'vpn.example.com', username: 'bob', quic: false, anti_dpi: false },
      password: 'secret#1', // secret-scan: allow тестовый пример
    })
  })

  it('takes custom_sni when hostname is absent; certificate in a multi-line basic string', () => {
    const r = parseClientToml(`addresses = ["198.51.100.7:443"]\ncustom_sni = "cdn.example.net"\nusername = "u"\ncertificate = """\n${PEM}\n"""\n`)
    expect(r).toEqual({ endpoint: { server: '198.51.100.7', port: 443, sni: 'cdn.example.net', username: 'u', certificate: PEM } })
  })

  it('parse_client_toml_garbage', () => {
    for (const t of ['', 'просто текст', '<html><body>404</body></html>', 'hostname = "a.com"\npassword = "x', '[endpoint]\nloglevel = "info"\n', 'addresses = ["203.0.113.10"]\n']) {
      const r = parseClientToml(t)
      expect(r, t).toHaveProperty('error')
      if ('error' in r) expect(r.error.length).toBeGreaterThan(0)
    }
  })

  // настоящий вывод trusttunnel_endpoint (лабораторный сервер, пароль заменён): --format toml и ссылка по умолчанию
  it('parses a real trusttunnel_endpoint export: toml and tt:// link give the same server', () => {
    const t = parseClientToml(exportToml)
    const l = parseDeepLink(exportLink)
    expect(t).toMatchObject({ endpoint: { server: '203.0.113.10', port: 443, sni: 'vpn.example.com', username: 'alice', quic: false, anti_dpi: false }, password: 'dummy-export-pass' }) // secret-scan: allow фиктивный пароль фикстуры
    if ('error' in t) throw new Error(t.error)
    expect(t.endpoint.certificate).toMatch(/^-----BEGIN CERTIFICATE-----\n[A-Za-z0-9+/=\n]+\n-----END CERTIFICATE-----$/)
    expect(t).not.toHaveProperty('warnings')
    expect(l).toEqual(t)
    expect(parseServer('  ' + exportLink)).toEqual(t)
    expect(parseServer(exportToml)).toEqual(t)
  })

  it('warns about custom_sni and skip_verification the router does not support', () => {
    const r = parseClientToml(exportToml.replace('custom_sni = ""', 'custom_sni = "cdn.example.net"').replace('skip_verification = false', 'skip_verification = true'))
    expect(r).toHaveProperty('warnings')
    if (!('error' in r)) expect(r.warnings).toHaveLength(2)
    const same = parseClientToml(exportToml.replace('custom_sni = ""', 'custom_sni = "vpn.example.com"'))
    expect(same).not.toHaveProperty('warnings')
  })

  it('rejects broken tt:// links', () => {
    for (const t of ['tt://', 'tt://?', 'tt://?!!!', exportLink.trim().slice(0, 40), 'tt://?AAEC']) {
      expect(parseDeepLink(t), t).toHaveProperty('error')
    }
  })

  it('reads http3, anti-DPI and unsupported flags from a tt:// link (DEEP_LINK.md: 0x09 = 0x02 is http3)', () => {
    const enc = new TextEncoder()
    const tlv = (tag: number, v: Uint8Array | string) => {
      const b = typeof v === 'string' ? enc.encode(v) : v
      return [tag, b.length, ...b]
    }
    const base = [...tlv(0, new Uint8Array([2])), ...tlv(1, 'vpn.example.com'), ...tlv(2, '203.0.113.10:8443'), ...tlv(5, 'bob'), ...tlv(6, 'pw')]
    const link = (b: number[]) => 'tt://?' + btoa(String.fromCharCode(...b)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
    const r = parseDeepLink(link([...base, ...tlv(9, new Uint8Array([2])), ...tlv(0x0a, new Uint8Array([1])), ...tlv(3, 'cdn.example.net'), ...tlv(7, new Uint8Array([1]))]))
    expect(r).toMatchObject({ endpoint: { server: '203.0.113.10', port: 8443, sni: 'vpn.example.com', username: 'bob', quic: true, anti_dpi: true }, password: 'pw' })
    if (!('error' in r)) expect(r.warnings).toHaveLength(2)
    expect(parseDeepLink(link([...base, ...tlv(9, new Uint8Array([1]))]))).toMatchObject({ endpoint: { quic: false, anti_dpi: false } })
    expect(parseDeepLink(link(base))).toMatchObject({ endpoint: { quic: false } })
  })

  it('reads TrustTunnel 1.3 tags: tls_profile (0x10), client_random prefix (0x0B) and auth key (0x0F)', () => {
    const enc = new TextEncoder()
    const tlv = (tag: number, v: Uint8Array | string) => {
      const b = typeof v === 'string' ? enc.encode(v) : v
      return [tag, b.length, ...b]
    }
    const base = [...tlv(1, 'vpn.example.com'), ...tlv(2, '203.0.113.10:443'), ...tlv(5, 'bob'), ...tlv(6, 'pw')]
    const link = (b: number[]) => 'tt://?' + btoa(String.fromCharCode(...b)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
    const one = (b: number) => new Uint8Array([b])
    expect(parseDeepLink(link([...base, ...tlv(0x10, one(1)), ...tlv(0x0f, '00ff')]))).toMatchObject({ endpoint: { tls_profile: 'chrome_canary', client_random_auth_key: '00ff' } })
    expect(parseDeepLink(link([...base, ...tlv(0x10, one(6)), ...tlv(0x0b, 'ab12')]))).toMatchObject({ endpoint: { tls_profile: 'boringssl', client_random: 'ab12' } })
    // chrome — по умолчанию, поле не пишется; неизвестный профиль — отказ, а не тихая потеря
    const chrome = parseDeepLink(link([...base, ...tlv(0x10, one(0))]))
    if ('error' in chrome) throw new Error(chrome.error)
    expect(chrome.endpoint).not.toHaveProperty('tls_profile')
    expect(parseDeepLink(link([...base, ...tlv(0x10, one(7))]))).toHaveProperty('error')
    // оба сразу — берём ключ, как клиент
    const both = parseDeepLink(link([...base, ...tlv(0x0b, 'ab12'), ...tlv(0x0f, '00ff')]))
    if ('error' in both) throw new Error(both.error)
    expect(both.endpoint).toMatchObject({ client_random_auth_key: '00ff' })
    expect(both.endpoint).not.toHaveProperty('client_random')
  })

  it('subscription URL (0x0E): subscription-only link is accepted, full link keeps both', () => {
    const enc = new TextEncoder()
    const tlv = (tag: number, v: string) => { const b = enc.encode(v); return [tag, b.length, ...b] }
    const link = (b: number[]) => 'tt://?' + btoa(String.fromCharCode(...b)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
    const url = 'https://alice:pw@vpn.example.com/subscription'
    expect(parseDeepLink(link([0, 1, 2, ...tlv(0x0e, url), ...tlv(0x0c, 'Acme')]))).toEqual({ endpoint: {}, subscription: url, name: 'Acme' })
    const full = parseDeepLink(link([...tlv(1, 'vpn.example.com'), ...tlv(2, '203.0.113.10:443'), ...tlv(5, 'bob'), ...tlv(6, 'pw'), ...tlv(0x0e, url)]))
    expect(full).toMatchObject({ endpoint: { server: '203.0.113.10' }, password: 'pw', subscription: url })
    expect(parseDeepLink(link([...tlv(0x0e, 'http://insecure.example.com/sub')]))).toHaveProperty('error')
    expect(parseClientToml(`hostname = "vpn.example.com"\naddresses = ["203.0.113.10:443"]\nsubscription_url = "${url}"\n`)).toMatchObject({ subscription: url })
  })

  it('reads tls_profile and client_random from client.toml; "default" is boringssl', () => {
    const t = (extra: string) => parseClientToml(`hostname = "vpn.example.com"\naddresses = ["203.0.113.10:443"]\nusername = "u"\n${extra}`)
    expect(t('tls_profile = "firefox"\nclient_random_auth_key = "00ff"\nclient_random = ""\n')).toMatchObject({ endpoint: { tls_profile: 'firefox', client_random_auth_key: '00ff' } })
    expect(t('tls_profile = "default"\nclient_random = "ab12/ffff"\n')).toMatchObject({ endpoint: { tls_profile: 'boringssl', client_random: 'ab12/ffff' } })
    expect(t('tls_profile = "netscape"\n')).toHaveProperty('error')
  })
})
