// Диагностика без DOM: названия проверок, итог по сайту и текст отчёта для копирования.

import type { DiagCheck, DiagResponse, DiagSite, DiagStatus } from './api'
import { when } from './status'
import { lang, t } from './i18n'

/** Проверки службы (mitt-diag.sh) по порядку и их названия в панели (на текущем языке — функцией). */
export const checkTitles = (): Record<string, string> => ({
  service: t('Служба роутера'),
  client: t('Клиент TrustTunnel'),
  exit: t('Выход в интернет через туннель'),
  route: t('Маршрут в туннель'),
  firewall: t('Сортировка трафика'),
  dns: t('DNS роутера'),
  secure: t('Защищённый DNS (DoH/DoT)'),
  tunnelsecure: t('Шифрованный DNS через VPN'),
  zapret: t('Обход блокировок (Zapret)'),
  restarts: t('Стабильность программ'),
  watch: t('Сторож туннеля'),
})

export const checkTitle = (c: DiagCheck) => checkTitles()[c.id] ?? c.id

/** Общий итог: худший из итогов проверок (пропущенные не считаются). */
export function overall(checks: DiagCheck[]): DiagStatus | null {
  if (!checks.length) return null
  for (const s of ['bad', 'warn', 'ok'] as const) if (checks.some((c) => c.status === s)) return s
  return 'skip'
}

export function overallText(checks: DiagCheck[]): string {
  const bad = checks.filter((c) => c.status === 'bad').length
  const warn = checks.filter((c) => c.status === 'warn').length
  if (bad) return bad === 1 ? t('Одна проверка не прошла') : t('Не прошли проверки: {n}', { n: bad })
  if (warn) return t('Работает, но есть замечания')
  return t('Всё работает')
}

const routes = (): Record<string, string> => ({ tunnel: t('через VPN'), zapret: t('напрямую с обходом блокировок'), direct: t('напрямую'), block: t('заблокирован') })

/** Что показать по проверке сайта: маршрут и ответ сайта по этому маршруту. */
export function siteVerdict(s: DiagSite): { status: DiagStatus; title: string; detail: string } {
  const domain = s.domain
  if (!s.ip) return { status: 'bad', title: t('{domain}: адрес не найден', { domain }), detail: t('DNS роутера не вернул адрес. Проверьте написание или подождите и повторите') }
  const ip = s.ip
  const route = s.route ?? 'direct'
  const probe = route === 'tunnel' ? s.tunnel : s.direct
  const way = routes()[route] ?? route
  if (route === 'block') return { status: 'warn', title: t('{domain} — {way}', { domain, way }), detail: t('Адрес {ip}. Так задано в настройках', { ip }) }
  const how = route === 'zapret' ? t('. Проверено с роутера напрямую: обход блокировок работает для устройств, а не для самого роутера') : ''
  if (!probe) return { status: 'warn', title: t('{domain} — {way}', { domain, way }), detail: t('Адрес {ip}. Ответ сайта не проверен: туннель не поднят{how}', { ip, how }) }
  if (!probe.code) return { status: 'bad', title: t('{domain} — {way}, не отвечает', { domain, way }), detail: t('Адрес {ip}. Сайт не ответил за 10 секунд{how}', { ip, how }) }
  const num = probe.seconds?.toFixed(1)
  const secs = num != null ? t(', {s} с', { s: lang.value === 'ru' ? num.replace('.', ',') : num }) : ''
  return { status: 'ok', title: t('{domain} — {way}, открывается', { domain, way }), detail: t('Адрес {ip}. Ответ {code}{secs}{how}', { ip, code: probe.code, secs, how }) }
}

/** Текст для копирования в сообщение: итоги, сайт и журналы. Секретов в журналах службы нет. */
export function reportText(d: DiagResponse): string {
  const out = [t('Mi Lumruri — диагностика {when}', { when: when(d.finished ?? null) }), '']
  for (const c of d.checks ?? []) out.push(`[${c.status}] ${checkTitle(c)}: ${c.detail}`)
  if (d.site) {
    const v = siteVerdict(d.site)
    out.push('', `[${v.status}] ${v.title}. ${v.detail}`)
  }
  const logs = d.logs
  if (logs) {
    for (const [name, lines] of [[t('Служба'), logs.service], ['TrustTunnel', logs.trusttunnel], ['Zapret', logs.nfqws2]] as const) {
      if (lines.length) out.push('', `--- ${name} ---`, ...lines)
    }
  }
  return out.join('\n')
}
