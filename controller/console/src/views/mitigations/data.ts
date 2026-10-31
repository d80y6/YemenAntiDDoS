import { ApiError } from '../../api/client'
import { isSyntheticRuleId } from '../../api/xdropRules'
import type { Row } from '../attacks/data'
export type { Row } from '../attacks/data'
export type Translate = (key: string, values?: Record<string, any>) => string
export function statusLabel(status: string, t: Translate) {
  const keys: Record<string, string> = { active: 'mitigations.active', delayed: 'mitigations.delayed',
    failed: 'attacks.failed', pending: 'attacks.statusPending' }
  return keys[status] ? t(keys[status]) : status
}
export const attached = (row: Row): Row[] => (row.attached_attacks ?? []).filter((a: Row) => !a.detached_at)
export function attackLinks(row: Row) {
  const items: Row[] = row.attached_attacks ?? []
  return { ids: items.length ? attached(row).map(a => a.attack_id) : row.attack_id > 0 ? [row.attack_id] : [],
    detached: items.filter(a => a.detached_at).length }
}
export function bgpConfirmation(row: Row, t: Translate) {
  const n = attached(row).length
  return { title: t('mitigations.withdrawTitle', { prefix: row.prefix }),
    description: t('mitigations.' + (n > 1 ? 'withdrawShared' : row.status === 'delayed'
      ? 'withdrawDelayed' : n === 1 ? 'withdrawSingle' : 'withdrawNeutral'), { n }) }
}
export function xdropConfirmation(row: Row, n: number, t: Translate) {
  return isSyntheticRuleId(row.external_rule_id)
    ? { title: t('mitigations.closeFailedTitle'), description: t('mitigations.closeFailedDescription'),
      label: t('mitigations.closeFailed') }
    : { title: t('attacks.forceUnblock'), description: t('attacks.'
      + (n > 0 ? 'confirmReleaseShared' : 'confirmReleaseLast'), { n }), label: t('attacks.release') }
}
export function matchSummary(row: Row, t: Translate) {
  return [row.protocol, row.src_port ? t('mitigations.srcPort', { n: row.src_port }) : '',
    row.dst_port ? t('mitigations.dstPort', { n: row.dst_port }) : '',
    row.tcp_flags ? t('mitigations.flags', { flags: row.tcp_flags }) : '',
    row.rate_limit ? t('mitigations.rate', { n: row.rate_limit }) : ''].filter(Boolean).join(' · ') || '—'
}
export const actionLabel = (row: Row, t: Translate) => !row.action ? '—'
  : ['drop', 'rate_limit'].includes(row.action) ? t('mitigations.' + row.action) : row.action
export const businessKey = (row: Row, kind: string) => JSON.stringify(kind === 'bgp'
  ? [row.external_rule_id, row.connector_id]
  : [row.attack_id, row.action_id, row.connector_id, row.external_rule_id])
export const connector = (row: Row, connectors: Row[]) => row.connector_name
  || connectors.find(c => c.id === row.connector_id)?.name || '#' + row.connector_id
export const disabledConnector = (row: Row, connectors: Row[]) =>
  connectors.some(c => c.id === row.connector_id && c.enabled === false)
export const timelineRows = (logs: Row[] | null, row: Row) => (logs ?? [])
  .filter(log => !log.action_id || !row.action_id || log.action_id === row.action_id)
export function deliveryResult(value?: Row, error?: unknown) {
  if (error) return { kind: error instanceof ApiError && error.timeout ? 'timeout' : 'failed',
    message: error instanceof Error ? error.message : String(error), nodes: [] as Row[] }
  const body = value ?? {}
  const kind = body.found === false ? 'notFound'
    : body.error && !['rule_id', 'nodes', 'found'].some(k => Object.hasOwn(body, k)) ? 'unavailable'
      : Object.hasOwn(body, 'nodes') ? body.nodes?.length ? 'nodes' : 'none' : 'failed'
  return { kind, message: '', nodes: (body.nodes ?? []) as Row[] }
}
