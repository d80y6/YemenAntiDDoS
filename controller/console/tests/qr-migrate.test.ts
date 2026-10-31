import { expect, it } from 'vitest'
import { mountQE, writes, body, choose } from './qe-harness'
import { otherHolders } from '../src/api/xdropRules'

it('RuleNull existing response changed to default sends exact singleton null PUT', async () => {
  const { w } = await mountQE('/thresholds/7')
  const row = w.findAll('tbody tr').find(r => r.text().includes('出向'))!
  await choose('响应', 'Observe', row.element)
  expect(body()).toEqual({ response_id: 1 })
  expect(row.get('[role=combobox]').text()).toContain('Observe')
  await choose('响应', '—（使用默认）', row.element)
  const last = writes().at(-1)!
  expect(last[0]).toBe('/api/threshold-rules/103')
  expect(last[1]?.method).toBe('PUT')
  expect(body()).toEqual({ response_id: null })
})

// Retired web/tests/xdropRules.test.mjs U2: holders are keyed by attack + action
// (backend xdropClaimRef), not by connector.
const RID = 'rule-6f1c'
const holder = (attack_id: number, action_id: number, connector_id: number, status: string) =>
  ({ attack_id, action_id, connector_id, external_rule_id: RID, status }) as any
it('U2 this holder duplicated across connectors counts zero', () => {
  const self = holder(1, 10, 1, 'active')
  expect(otherHolders([self, holder(1, 10, 2, 'active'), holder(1, 10, 3, 'failed')], self)).toBe(0)
})
it('U2 one other holder duplicated across connectors counts once', () => {
  const self = holder(1, 10, 1, 'active')
  expect(otherHolders([self, holder(2, 10, 1, 'active'), holder(2, 10, 2, 'delayed')], self)).toBe(1)
  expect(otherHolders([self, holder(2, 10, 1, 'active'), holder(2, 10, 2, 'active'), holder(3, 10, 2, 'active')],
    self)).toBe(2)
})
