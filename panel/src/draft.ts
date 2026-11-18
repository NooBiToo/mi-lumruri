// Состояние формы правила и его преобразование в запрос предпросмотра. Проверку выполняет контроллер;
// здесь только сборка JSON и привязка ошибок контроллера к полям формы.

import type { ApiResult, Config, Destination, PreviewRequest, Probe, Rule, SaveResponse } from './api'

export type SourceType = 'device' | 'network' | 'lan'
export type DestType = Destination['type']
export type ActionType = 'profile' | 'direct' | 'direct_zapret' | 'block'

export interface ProbeForm { subjectType: 'device' | 'network'; subjectId: string; host: string }

export interface DraftForm {
  id: string
  sourceType: SourceType
  sourceId: string
  destType: DestType
  destGroup: string
  destValue: string
  actionType: ActionType
  actionProfile: string
  enabled: boolean
  probes: ProbeForm[]
}

export type Field = 'id' | 'source' | 'destination' | 'action' | `probe-${number}`

export function toRequest(f: DraftForm): PreviewRequest {
  const source: Rule['source'] = f.sourceType === 'lan' ? { type: 'lan' } : { type: f.sourceType, id: f.sourceId }
  const destination: Destination = f.destType === 'group' ? { type: 'group', id: f.destGroup } : { type: f.destType, value: f.destValue.trim() }
  const action: Rule['action'] = f.actionType === 'profile' ? { type: 'profile', id: f.actionProfile } : { type: f.actionType }
  const probes: Probe[] = f.probes
    .filter((p) => p.host.trim() !== '')
    .map((p) => (p.subjectType === 'device' ? { device: p.subjectId, host: p.host.trim() } : { network: p.subjectId, host: p.host.trim() }))
  return { rule: { id: f.id.trim(), source, destination, action, enabled: f.enabled }, probes }
}

/** Путь ошибки контроллера (`rule.source.id`, `probes[2].host`) → поле формы. */
export function fieldForIssue(path: string): Field | null {
  const m = /^probes\[(\d+)\]/.exec(path)
  if (m) return `probe-${Number(m[1])}`
  if (path === 'rule.id') return 'id'
  for (const f of ['source', 'destination', 'action'] as const) {
    if (path === `rule.${f}` || path.startsWith(`rule.${f}.`)) return f
  }
  return null
}

/** Пример хоста для пробы: домен как есть, суффикс с www., для подсети — первый адрес. */
export function sampleHost(d: Destination | undefined): string {
  if (!d) return ''
  switch (d.type) {
    case 'domain':
      return d.value
    case 'domain_suffix':
      return `www.${d.value}`
    case 'cidr': {
      const [addr] = d.value.split('/')
      if (addr && /^\d+\.\d+\.\d+\.\d+$/.test(addr)) {
        const parts = addr.split('.').map(Number)
        parts[3] = (parts[3] ?? 0) + 1
        return parts.join('.')
      }
      return ''
    }
    case 'group':
      return ''
  }
}

/** Черновик по умолчанию — сценарий TrustTunnel для первого устройства и первой группы. */
export function defaultForm(cfg: Config): DraftForm {
  const tt = cfg.profiles.find((p) => p.kind === 'trusttunnel') ?? cfg.profiles[0]
  const dev = cfg.devices[0]
  const group = cfg.groups[0]
  const host = sampleHost(group?.destinations[0])
  const probes: ProbeForm[] = [
    ...cfg.devices.map((d) => ({ subjectType: 'device' as const, subjectId: d.id, host })),
    ...cfg.networks.map((n) => ({ subjectType: 'network' as const, subjectId: n.id, host })),
  ]
  return {
    id: dev ? `r-${dev.id}-${group?.id ?? 'dst'}` : 'r-new',
    sourceType: dev ? 'device' : 'lan',
    sourceId: dev?.id ?? '',
    destType: group ? 'group' : 'domain_suffix',
    destGroup: group?.id ?? '',
    destValue: '',
    actionType: tt ? 'profile' : 'direct',
    actionProfile: tt?.id ?? '',
    enabled: true,
    probes,
  }
}

/** Ключ правила: сохранять можно ровно то, что прошло проверку (пробы на ключ не влияют). */
export function ruleKey(f: DraftForm): string {
  return JSON.stringify(toRequest(f).rule)
}

export type SaveOutcome = { kind: 'saved' | 'conflict' | 'invalid' | 'forbidden' | 'error'; message: string }

export function saveOutcome(r: ApiResult<SaveResponse>): SaveOutcome {
  const b = r.body
  if (r.status === 200 && b.ok) {
    const what = b.mode === 'replace' ? 'заменено' : 'добавлено'
    return { kind: 'saved', message: `Правило «${b.rule_id}» ${what}. Ревизия ${b.revision?.slice(0, 12)}.` }
  }
  if (r.status === 409 && b.error?.code === 'revision_conflict') {
    return { kind: 'conflict', message: 'Настройки изменились после загрузки панели. Обновите их и проверьте правило ещё раз.' }
  }
  if (r.status === 422) return { kind: 'invalid', message: b.error?.message ?? 'правило не прошло проверку' }
  if (r.status === 403) return { kind: 'forbidden', message: b.error?.message ?? 'запись запрещена' }
  return { kind: 'error', message: b.error?.message ?? `ошибка ${r.status}` }
}
