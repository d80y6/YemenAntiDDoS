import type { UserRow } from '../users/data'

export type AuditRow = { id: number; user_id: number | null; entity_type: string; entity_id: string;
  action: string; diff: unknown; delivery_version: number | null; created_at: string }
export type AuditFilters = { entity_type?: string; user_id?: string; from?: string; to?: string }
export const entityTypes = ['action_precondition', 'active_action', 'bgp_connector', 'bgp_orphan_dismiss',
  'bgp_orphan_force_withdraw', 'bgp_orphan_undismiss', 'flow_listener', 'flow_source', 'node', 'response',
  'response_action', 'shell_connector', 'threshold', 'threshold_template', 'threshold_template_rule',
  'user', 'watch_prefix', 'webhook_connector', 'xdrop_connector']
export const actions = ['create', 'update', 'delete', 'force_remove', 'force_withdraw', 'dismiss', 'undismiss']
export const entityLabel = (value: string, t: (key: string) => string) => entityTypes.includes(value)
  ? t('audit.entity.' + value) : value
export const actionLabel = (value: string, t: (key: string) => string) => actions.includes(value)
  ? t('audit.op.' + value) : value
// null is an absent condition; NaN is a supplied but invalid condition.
export function auditTime(raw = ''): number | null {
  if (!raw.trim()) return null
  const match = /^(\d{4})-(\d{1,2})-(\d{1,2})(?:[ T](\d{1,2}):(\d{2})(?::(\d{2}))?)?$/.exec(raw.trim())
  if (!match) return NaN
  const [y, m, d, h, min, sec] = match.slice(1).map(v => Number(v ?? 0)) as number[]
  const date = new Date(y!, m! - 1, d!, h!, min!, sec!)
  if (date.getFullYear() !== y || date.getMonth() !== m! - 1 || date.getDate() !== d
    || date.getHours() !== h || date.getMinutes() !== min || date.getSeconds() !== sec) return NaN
  return date.getTime()
}
export function auditQuery(filters: AuditFilters, page: number) {
  const q = new URLSearchParams()
  if (filters.entity_type) q.set('entity_type', filters.entity_type)
  if (filters.user_id) q.set('user_id', filters.user_id)
  for (const key of ['from', 'to'] as const) {
    const time = auditTime(filters[key])
    if (time !== null && Number.isFinite(time)) q.set(key, new Date(time).toISOString())
  }
  q.set('limit', '51')
  q.set('offset', String((page - 1) * 50))
  return '/api/audit-log?' + q.toString()
}
export const diffPreview = (diff: unknown) => diff === null ? '-' : JSON.stringify(diff).slice(0, 100)
export const userLabel = (id: number | null, users: UserRow[]) => id === null ? '—'
  : users.find(u => u.id === id)?.username ?? `#${id}`
export const actionTone = (action: string) => action === 'create' ? 'ok' : action === 'update' ? 'warn'
  : action === 'delete' ? 'crit' : 'neutral'
