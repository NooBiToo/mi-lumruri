// Логика экрана входа без DOM: разбор ответов контроллера и подготовка второго фактора.

import type { ApiResult, SecondFactor, SessionResponse } from './api'
import { t } from './i18n'

export type LoginStage = 'password' | 'second_factor'

/** Код из приложения: только 6 цифр (пробелы, которые вставляют некоторые приложения, отбрасываются). */
export function normalizeTotp(raw: string): string | null {
  const s = raw.replace(/\s+/g, '')
  return /^\d{6}$/.test(s) ? s : null
}

/** Recovery-код: 16 символов base32, дефисы и регистр не важны. */
export function normalizeRecovery(raw: string): string | null {
  const s = raw.replace(/[^0-9a-z]/gi, '').toUpperCase()
  return /^[A-Z2-7]{16}$/.test(s) ? s : null
}

export function secondFactor(mode: 'totp' | 'recovery', raw: string): SecondFactor | null {
  if (mode === 'totp') {
    const c = normalizeTotp(raw)
    return c ? { totp: c } : null
  }
  const c = normalizeRecovery(raw)
  return c ? { recovery_code: c } : null
}

/** Сообщение для пользователя по ответу контроллера; null — успех. */
export function loginMessage(r: ApiResult<SessionResponse>): string | null {
  if (r.status === 200 && r.body.ok) return null
  const code = r.body.error?.code
  switch (code) {
    case 'invalid_credentials':
      return t('Неверный пароль.')
    case 'invalid_code':
      return t('Код не подошёл.')
    case 'code_reused':
      return t('Этот код уже использован. Дождитесь следующего кода в приложении.')
    case 'clock_untrusted':
      return t('Часы роутера ещё не синхронизированы, поэтому код из приложения не принимается. Войдите recovery-кодом или подождите синхронизации времени.')
    case 'login_required':
      return t('Время на ввод кода истекло. Введите пароль ещё раз.')
    case 'too_many_attempts':
      return t('Слишком много неудачных попыток. Повторите через {s} с.', { s: r.body.retry_after ?? 30 })
    case 'auth_not_configured':
      return t('Вход не настроен. На роутере выполните mi-tt-admin auth init и auth confirm.')
    case 'https_required':
      return t('Вход возможен только по HTTPS.')
    case 'origin_forbidden':
    case 'origin_required':
    case 'cross_site':
    case 'write_disabled':
      return t('Запрос отклонён: страница открыта не с адреса панели.')
    default:
      return r.body.error?.message ?? t('Ошибка {s}.', { s: r.status })
  }
}

/** Куда перейти после ответа на шаге входа. */
export function nextStage(current: LoginStage, r: ApiResult<SessionResponse>): LoginStage | 'done' {
  // вход только паролем (TOTP не включён): контроллер сразу выдаёт полную сессию
  if (r.status === 200 && r.body.ok) return current === 'password' && !r.body.authenticated ? 'second_factor' : 'done'
  if (current === 'second_factor' && r.body.error?.code === 'login_required') return 'password'
  return current
}
