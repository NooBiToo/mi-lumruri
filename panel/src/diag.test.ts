import { describe, expect, it } from 'vitest'
import { overall, overallText, reportText, siteVerdict } from './diag'
import type { DiagCheck, DiagSite } from './api'

const c = (id: string, status: DiagCheck['status']): DiagCheck => ({ id, status, detail: 'подробность' })

describe('диагностика', () => {
  it('общий итог — худший из проверок, пропущенные не считаются', () => {
    expect(overall([])).toBeNull()
    expect(overall([c('service', 'ok'), c('zapret', 'skip')])).toBe('ok')
    expect(overall([c('service', 'ok'), c('dns', 'warn')])).toBe('warn')
    expect(overall([c('client', 'bad'), c('dns', 'warn')])).toBe('bad')
    expect(overallText([c('client', 'bad'), c('exit', 'bad')])).toBe('Не прошли проверки: 2')
    expect(overallText([c('service', 'ok')])).toBe('Всё работает')
  })
  it('сайт: маршрут и ответ по этому маршруту', () => {
    const s: DiagSite = { domain: 'youtube.com', ip: '142.250.1.1', route: 'tunnel', direct: { code: 0, seconds: 10 }, tunnel: { code: 200, seconds: 0.31 } }
    expect(siteVerdict(s)).toMatchObject({ status: 'ok', title: 'youtube.com — через VPN, открывается' })
    expect(siteVerdict({ ...s, route: 'direct' })).toMatchObject({ status: 'bad', title: 'youtube.com — напрямую, не отвечает' })
    expect(siteVerdict({ ...s, route: 'zapret', direct: { code: 301, seconds: 0.2 } }).detail).toMatch(/не для самого роутера/)
    expect(siteVerdict({ ...s, ip: null }).status).toBe('bad')
    expect(siteVerdict({ ...s, tunnel: null }).status).toBe('warn')
  })
  it('отчёт: итоги, сайт и журналы', () => {
    const t = reportText({ ok: true, finished: 1795085385, checks: [c('client', 'bad')], issues: [],
      logs: { service: ['строка'], trusttunnel: [], nfqws2: [] } })
    expect(t).toContain('[bad] Клиент TrustTunnel: подробность')
    expect(t).toContain('--- Служба ---\nстрока')
    expect(t).not.toContain('--- Zapret ---')
  })
})
