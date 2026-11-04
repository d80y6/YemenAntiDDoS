export type Row = Record<string, any>
export type Phase = 'on_detected' | 'on_expired'
export type Condition = { attribute: string; operator: string; value: string }
export type Connector = { id: number; name: string; enabled: boolean; vendor?: string; flowspec_enabled?: boolean }
export interface Form {
  id: number | null
  action_type: string
  connector_id: number | null
  priority: number
  run_mode: string
  period_seconds: number
  execution: string
  xdrop_action: string
  xdrop_fields: string[]
  xdrop_rate_limit: number
  target_node_ids: number[]
  shell_extra_args: string
  bgp_route_map: string
  bgp_withdraw_delay_minutes: number
  unblock_delay_minutes: number
  enabled: boolean
  preconditionsLoaded: boolean
  preconditions: Condition[]
}
export function defaults(): Form {
  return { id: null, action_type: 'webhook', connector_id: null, priority: 5, run_mode: 'once',
    period_seconds: 60, execution: 'automatic', xdrop_action: 'filter_l4', xdrop_fields: ['dst_ip'],
    xdrop_rate_limit: 100000, target_node_ids: [], shell_extra_args: '', bgp_route_map: '',
    bgp_withdraw_delay_minutes: 0, unblock_delay_minutes: 0, enabled: true,
    preconditionsLoaded: true, preconditions: [] }
}
export const conditions = (rows: Row[] | null): Condition[] => (rows ?? [])
  .map(({ attribute, operator, value }) => ({ attribute, operator, value }))
export function fill(row: Row, loaded: boolean, rows: Row[] | null): Form {
  return { id: row.id, action_type: row.action_type || 'webhook', connector_id: row.connector_id,
    priority: row.priority || 5, run_mode: row.run_mode || 'once', period_seconds: row.period_seconds || 60,
    execution: row.execution || 'automatic', xdrop_action: row.xdrop_action || 'filter_l4',
    xdrop_fields: row.xdrop_fields || ['dst_ip'], xdrop_rate_limit: row.xdrop_rate_limit || 100000,
    target_node_ids: row.target_node_ids || [], shell_extra_args: row.shell_extra_args || '',
    bgp_route_map: row.bgp_route_map || '', bgp_withdraw_delay_minutes: row.bgp_withdraw_delay_minutes || 0,
    unblock_delay_minutes: row.unblock_delay_minutes || 0, enabled: row.enabled !== false,
    preconditionsLoaded: loaded, preconditions: conditions(rows) }
}
export const matching = (f: Form) => ['filter_l4', 'rate_limit'].includes(f.xdrop_action)
export function validate(f: Form): { key: string; row?: number } | undefined {
  if (f.action_type === 'xdrop' && matching(f)) {
    if (!f.xdrop_fields.length) return { key: 'responses.filterFieldsRequired' }
    if (f.xdrop_action === 'rate_limit' && !(f.xdrop_rate_limit > 0)) return { key: 'responses.rateLimitRequired' }
  }
  const index = f.preconditions.findIndex(c => [c.attribute, c.operator, c.value]
    .some(v => v == null || !String(v).trim()))
  if (index >= 0) return { key: 'responses.conditionIncomplete', row: index + 1 }
}
export function payload(f: Form, phase: Phase): Row {
  const p: Row = { action_type: f.action_type, connector_id: f.action_type === 'xdrop' ? null : f.connector_id,
    priority: f.priority, run_mode: f.run_mode, execution: f.execution, enabled: f.enabled,
    period_seconds: f.run_mode === 'periodic' ? f.period_seconds : null, trigger_phase: phase }
  if (f.action_type === 'xdrop') {
    p.xdrop_action = f.xdrop_action
    p.xdrop_fields = [...f.xdrop_fields]
    p.xdrop_rate_limit = f.xdrop_action === 'rate_limit' ? f.xdrop_rate_limit : null
    p.target_node_ids = f.target_node_ids.length ? [...f.target_node_ids] : null
    if (matching(f)) {
      const cp: Row = {}
      const map: Record<string, string> = { dst_ip: '{dst_ip}', src_ip: '{src_ip}',
        dst_port: '{dominant_dst_port}', src_port: '{dominant_src_port}', protocol: '{decoder}' }
      for (const key of Object.keys(map)) if (f.xdrop_fields.includes(key)) cp[key] = map[key]
      cp.action = f.xdrop_action === 'rate_limit' ? 'rate_limit' : 'drop'
      if (f.xdrop_action === 'rate_limit') cp.rate_limit = f.xdrop_rate_limit
      cp.comment = 'attack #{attack_id} {decoder}'
      p.xdrop_custom_payload = cp
    }
    if (phase === 'on_detected') p.unblock_delay_minutes = matching(f) ? f.unblock_delay_minutes || 0 : 0
  }
  if (f.action_type === 'shell') p.shell_extra_args = f.shell_extra_args || ''
  if (f.action_type === 'bgp') {
    p.bgp_route_map = f.bgp_route_map || ''
    if (phase === 'on_detected') p.bgp_withdraw_delay_minutes = f.bgp_withdraw_delay_minutes || 0
  }
  return p
}
export type Send = (path: string, method: string, body?: Row) => Promise<any>
export async function conditionsChanged(f: Form, send: Send): Promise<boolean> {
  if (!f.preconditionsLoaded) return false
  if (f.id === null) return f.preconditions.length > 0
  try {
    const current: Condition[] = await send(`/api/actions/${f.id}/preconditions`, 'GET') ?? []
    return current.length !== f.preconditions.length || current.some((c, i) =>
      ['attribute', 'operator', 'value'].some(key => c[key as keyof Condition]
        !== f.preconditions[i]![key as keyof Condition]))
  } catch { return true }
}
export type SaveResult = { ok: true; created: boolean } | {
  ok: false; step: number; reason: string; suffix: string
}
// No component lifecycle signal: once issued, the complete persistence sequence survives navigation.
export async function saveAction(f: Form, phase: Phase, responseID: number, send: Send): Promise<SaveResult> {
  const changed = await conditionsChanged(f, send)
  const p = payload(f, phase), rows = conditions(f.preconditions), created = f.id === null
  let step = 1
  try {
    const first = changed ? { ...p, enabled: false } : p
    if (f.id !== null) await send(`/api/actions/${f.id}`, 'PUT', first)
    else {
      const result = await send(`/api/responses/${responseID}/actions`, 'POST', first)
      f.id = result.id
    }
    if (changed) {
      step = 2
      await send(`/api/actions/${f.id}/preconditions`, 'PUT', { preconditions: rows })
      if (p.enabled) {
        step = 3
        await send(`/api/actions/${f.id}`, 'PUT', { ...p, enabled: true })
      }
    }
    return { ok: true, created }
  } catch (e) {
    const reason = e instanceof Error ? e.message : String(e ?? '')
    const suffix = step === 2 ? 'responses.actionSavedDisabled'
      : step === 3 ? 'responses.reenableUnconfirmed' : ''
    return { ok: false, step, reason, suffix }
  }
}
const order: Record<string, number> = { xdrop: 0, shell: 1, webhook: 2 }
export function phaseRows(rows: Row[], phase: Phase): Row[] {
  return rows.filter(a => a.trigger_phase === phase && (phase !== 'on_expired' || !a.auto_generated))
    .sort((a, b) => (order[a.action_type] ?? 9) - (order[b.action_type] ?? 9)
      || (a.priority || 0) - (b.priority || 0))
    .map((a, i, all) => ({ ...a, divider: i > 0 && all[i - 1]!.action_type !== a.action_type }))
}
export function connectorName(a: Row, nodes: Connector[], failed: boolean, all: string) {
  if (a.action_type !== 'xdrop') return a.connector_name || '—'
  if (failed) return a.connector_name
  const ids: number[] = a.target_node_ids ?? []
  if (!ids.length) return all
  const name = nodes.find(n => n.id === ids[0])?.name || '#' + ids[0]
  return name + (ids.length > 1 ? ' +' + (ids.length - 1) : '')
}
export const paired = (a: Row) => a.trigger_phase === 'on_detected' && ['xdrop', 'bgp'].includes(a.action_type)
export const attributes = ['cidr', 'decoder', 'attack_type', 'severity', 'pps', 'bps', 'node', 'domain',
  'dominant_src_port', 'dominant_src_port_pct', 'dominant_dst_port', 'dominant_dst_port_pct', 'unique_src_ips']
export const operators = ['eq', 'neq', 'gt', 'gte', 'lt', 'lte', 'in', 'not_in']
export function exampleKey(attribute: string, operator: string) {
  const group = ['pps', 'bps'].includes(attribute) ? 'rate'
    : ['dominant_src_port', 'dominant_dst_port'].includes(attribute) ? 'port'
    : ['dominant_src_port_pct', 'dominant_dst_port_pct'].includes(attribute) ? 'percent' : attribute
  return attributes.includes(attribute)
    ? `responses.example_${group}_${['in', 'not_in'].includes(operator) ? 'many' : 'one'}` : 'responses.value'
}
