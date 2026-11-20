// Диагностика без DOM: названия проверок, итог по сайту и текст отчёта для копирования.

import type { DiagCheck, DiagResponse, DiagSite, DiagStatus } from './api'
import { when } from './status'

/** Проверки службы (mitt-diag.sh) по порядку и их названия в панели. */
export const CHECK_TITLES: Record<string, string> = {
  service: 'Служба роутера',
  client: 'Клиент TrustTunnel',
  exit: 'Выход в интернет через туннель',
  route: 'Маршрут в туннель',
  firewall: 'Сортировка трафика',
  dns: 'DNS роутера',
  secure: 'Защищённый DNS (DoH/DoT)',
  zapret: 'Обход блокировок (Zapret)',
  restarts: 'Стабильность программ',
}

export const checkTitle = (c: DiagCheck) => CHECK_TITLES[c.id] ?? c.id

/** Общий итог: худший из итогов проверок (пропущенные не считаются). */
export function overall(checks: DiagCheck[]): DiagStatus | null {
  if (!checks.length) return null
  for (const s of ['bad', 'warn', 'ok'] as const) if (checks.some((c) => c.status === s)) return s
  return 'skip'
}

export function overallText(checks: DiagCheck[]): string {
  const bad = checks.filter((c) => c.status === 'bad').length
  const warn = checks.filter((c) => c.status === 'warn').length
  if (bad) return bad === 1 ? 'Одна проверка не прошла' : `Не прошли проверки: ${bad}`
  if (warn) return 'Работает, но есть замечания'
  return 'Всё работает'
}

const ROUTES: Record<string, string> = { tunnel: 'через VPN', zapret: 'напрямую с обходом блокировок', direct: 'напрямую', block: 'заблокирован' }

/** Что показать по проверке сайта: маршрут и ответ сайта по этому маршруту. */
export function siteVerdict(s: DiagSite): { status: DiagStatus; title: string; detail: string } {
  if (!s.ip) return { status: 'bad', title: `${s.domain}: адрес не найден`, detail: 'DNS роутера не вернул адрес. Проверьте написание или подождите и повторите' }
  const route = s.route ?? 'direct'
  const probe = route === 'tunnel' ? s.tunnel : s.direct
  const way = ROUTES[route] ?? route
  if (route === 'block') return { status: 'warn', title: `${s.domain} — ${way}`, detail: `Адрес ${s.ip}. Так задано в настройках` }
  const how = route === 'zapret' ? '. Проверено с роутера напрямую: обход блокировок работает для устройств, а не для самого роутера' : ''
  if (!probe) return { status: 'warn', title: `${s.domain} — ${way}`, detail: `Адрес ${s.ip}. Ответ сайта не проверен: туннель не поднят${how}` }
  if (!probe.code) return { status: 'bad', title: `${s.domain} — ${way}, не отвечает`, detail: `Адрес ${s.ip}. Сайт не ответил за 10 секунд${how}` }
  const secs = probe.seconds != null ? `, ${probe.seconds.toFixed(1).replace('.', ',')} с` : ''
  return { status: 'ok', title: `${s.domain} — ${way}, открывается`, detail: `Адрес ${s.ip}. Ответ ${probe.code}${secs}${how}` }
}

/** Текст для копирования в сообщение: итоги, сайт и журналы. Секретов в журналах службы нет. */
export function reportText(d: DiagResponse): string {
  const out = [`Mi Lumruri — диагностика ${when(d.finished ?? null)}`, '']
  for (const c of d.checks ?? []) out.push(`[${c.status}] ${checkTitle(c)}: ${c.detail}`)
  if (d.site) {
    const v = siteVerdict(d.site)
    out.push('', `[${v.status}] ${v.title}. ${v.detail}`)
  }
  const logs = d.logs
  if (logs) {
    for (const [name, lines] of [['Служба', logs.service], ['TrustTunnel', logs.trusttunnel], ['Zapret', logs.nfqws2]] as const) {
      if (lines.length) out.push('', `--- ${name} ---`, ...lines)
    }
  }
  return out.join('\n')
}
