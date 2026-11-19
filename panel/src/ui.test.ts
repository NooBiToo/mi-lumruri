import { describe, expect, it } from 'vitest'
import { avatarHue, initials, isLikelyDomain, isLikelyIp, parseDomainInput, parseHostRecord } from './ui'

describe('ui', () => {
  it('isLikelyDomain: обычные, кириллические и с поддоменом — да; без точки и с мусором — нет', () => {
    expect(isLikelyDomain('example.com')).toBe(true)
    expect(isLikelyDomain('a.b-c.example.co.uk')).toBe(true)
    expect(isLikelyDomain('госуслуги.рф')).toBe(true)
    expect(isLikelyDomain('localhost')).toBe(false)
    expect(isLikelyDomain('-bad.com')).toBe(false)
    expect(isLikelyDomain('bad_.com')).toBe(false)
    expect(isLikelyDomain('a..com')).toBe(false)
  })

  it('parseDomainInput: разбор как у текстового поля, нормализация, без повторов', () => {
    expect(parseDomainInput('https://Example.com/path, *.x.org  example.com\nfoo', ['x.org'])).toEqual({ add: ['example.com'], bad: ['foo'], dup: ['x.org'] })
    expect(parseDomainInput('   ', [])).toEqual({ add: [], bad: [], dup: [] })
    expect(parseDomainInput('a.ru\nb.ru, a.ru;c', ['b.ru'])).toEqual({ add: ['a.ru'], bad: ['c'], dup: ['b.ru'] })
  })

  it('avatarHue и initials', () => {
    expect(avatarHue('aa:bb:cc:dd:ee:ff')).toBe(avatarHue('aa:bb:cc:dd:ee:ff'))
    expect(avatarHue('aa:bb:cc:dd:ee:ff')).toBeGreaterThanOrEqual(0)
    expect(avatarHue('aa:bb:cc:dd:ee:ff')).toBeLessThan(360)
    expect(initials('Ноутбук Эрлана')).toBe('НЭ')
    expect(initials('iPhone')).toBe('IP')
    expect(initials('living-room-tv')).toBe('LR')
    expect(initials('')).toBe('')
  })
  it('parseHostRecord: домен и адрес своей DNS-записи', () => {
    expect(parseHostRecord(' Home.Example.com ', ' 192.168.31.10 ', [])).toEqual({ domain: 'home.example.com', address: '192.168.31.10' })
    expect(parseHostRecord('home.example.com', '192.168.31.11', [{ domain: 'home.example.com' }])).toMatch(/уже есть/)
    expect(parseHostRecord('home', '192.168.31.10', [])).toMatch(/домен/)
    expect(parseHostRecord('home.example.com', '192.168.31', [])).toMatch(/IP-адрес/)
    expect(isLikelyIp('fd00::5')).toBe(true)
    expect(isLikelyIp('0.0.0.0')).toBe(false)
  })
})
