export const SYNTHETIC_RULE_PREFIX = 'failed-create-'
export function isSyntheticRuleId(id: unknown) {
  return typeof id === 'string' && id.startsWith(SYNTHETIC_RULE_PREFIX)
}
export interface Holder { attack_id: number; action_id: number; external_rule_id: string; status?: string }
export function otherHolders(rows: Holder[] | null, row: Holder) {
  if (!row?.external_rule_id || isSyntheticRuleId(row.external_rule_id)) return 0
  const self = JSON.stringify([row.attack_id, row.action_id]), holders = new Set<string>()
  for (const other of rows || []) {
    if (other.external_rule_id !== row.external_rule_id || isSyntheticRuleId(other.external_rule_id)) continue
    if (!['active', 'delayed', 'failed'].includes(other.status ?? '')) continue
    const key = JSON.stringify([other.attack_id, other.action_id])
    if (key === self) continue
    holders.add(key)
  }
  return holders.size
}

export function deliveryStateType(state: string): 'ok' | 'warn' | 'crit' | 'neutral' {
  if (state === 'confirmed') return 'ok'
  if (state === 'pending' || state === 'overloaded') return 'warn'
  if (state === 'rejected' || state === 'offline') return 'crit'
  return 'neutral'
}
