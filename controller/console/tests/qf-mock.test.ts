import { expect, it } from 'vitest'
import { mockReply, mockSession } from '../mock/data'
it('G-mock preceding response list reads unchanged and detail fixture complete', () => {
  expect(mockReply('/api/responses', 'normal', 0).body).toEqual([
    { id: 1, name: 'Observe', description: 'Webhook notification', enabled: true, action_count: 1,
      bound_template_count: 1, created_at: '1969-12-31T00:00:00.000Z' },
    { id: 2, name: 'Edge defense', description: 'XDrop action', enabled: false, action_count: 1,
      bound_template_count: 0, created_at: '1969-12-31T00:00:00.000Z' },
    { id: 3, name: 'IDC-C defense', description: 'Response action suite', enabled: true, action_count: 8,
      bound_template_count: 0, created_at: '1969-12-31T00:00:00.000Z' },
  ])
  const r = mockReply('/api/responses/3').body
  expect(r.actions).toHaveLength(8)
  expect(r.actions.find((a: any) => a.id === 15)).toMatchObject({ connector_id: null,
    target_node_ids: [1, 2], connector_name: 'Edge XDrop (+1)', paired_with: 16, preconditions: null })
  expect(r.actions.find((a: any) => a.id === 16).auto_generated).toBe(true)
  expect(r.actions.find((a: any) => a.id === 17).target_node_ids).toEqual([])
})
it('G-mock response/action writes, pairing and counts match handler shape', () => {
  const mock = mockSession('qf')
  expect(mock('/api/responses', 'POST', { name: 'New', description: 'D' }))
    .toEqual({ status: 201, body: { id: 4 } })
  expect(mock('/api/responses/4', 'PUT', { name: 'Edited', description: 'D2', enabled: false }))
    .toEqual({ status: 200, body: { ok: true } })
  const created = mock('/api/responses/4/actions', 'POST', { action_type: 'bgp', connector_id: 1,
    priority: 5, run_mode: 'once', execution: 'automatic', enabled: false, trigger_phase: 'on_detected',
    period_seconds: null, bgp_route_map: 'RTBH', bgp_withdraw_delay_minutes: 0 })
  expect(created).toEqual({ status: 201, body: { id: 100 } })
  expect(mock('/api/responses/4').body.actions.map((a: any) => [a.id, a.trigger_phase, a.enabled]))
    .toEqual([[100, 'on_detected', false], [101, 'on_expired', false]])
  expect(mock('/api/responses').body.find((r: any) => r.id === 4).action_count).toBe(2)
  expect(mock('/api/actions/100', 'DELETE').status).toBe(200)
  expect(mock('/api/responses/4').body.actions).toEqual([])
  expect(mock('/api/responses/4', 'DELETE').status).toBe(200)
  expect(mock('/api/responses/4').status).toBe(404)
})
it.each([
  [{ action_type: 'shell', connector_id: null }, 'shell action requires connector_id'],
  [{ action_type: 'bgp', connector_id: 1, bgp_route_map: '' }, 'bgp action (on_detected) requires bgp_route_map'],
  [{ action_type: 'bgp', connector_id: 1, bgp_route_map: 'bad name' },
    "bgp_route_map may only contain letters, digits, '_', '-', '.'"],
  [{ action_type: 'shell', connector_id: 1, shell_extra_args: '{typo}' },
    'shell_extra_args contains unknown template variable {typo}'],
])('G-mock action 400 original %j', (more, error) => {
  expect(mockSession('qf')('/api/responses/3/actions', 'POST', { trigger_phase: 'on_detected',
    run_mode: 'once', priority: 5, execution: 'automatic', enabled: true, ...more }))
    .toEqual({ status: 400, body: { error } })
})
it('G-mock type changes original, threshold reference conflict, conditions validation original', () => {
  const mock = mockSession('qf')
  expect(mock('/api/actions/11', 'PUT', { action_type: 'shell' })).toEqual({ status: 400,
    body: { error: 'cannot change action_type via PUT — delete this action and create a new one instead' } })
  expect(mock('/api/responses/2', 'DELETE')).toEqual({ status: 409,
    body: { error: 'response in use by threshold rule id=107' } })
  expect(mock('/api/actions/15/preconditions', 'PUT', { preconditions: [
    { attribute: 'severity', operator: 'eq', value: 'critical,high' },
  ] })).toEqual({ status: 400, body: { error: 'invalid precondition value for severity: "critical,high"' } })
})
it.each(['qf-condition-fail', 'qf-second-fail', 'qf-third-fail', 'qf-first-fail', 'qf-reread-fail', 'qf-empty'])(
  'G-mock named apparatus mode %s', mode => {
    const mock = mockSession(mode)
    const read = mock('/api/actions/15/preconditions')
    if (mode === 'qf-condition-fail') expect(read.status).toBe(500)
    if (mode === 'qf-reread-fail') expect(mock('/api/actions/15/preconditions').status).toBe(500)
    if (mode === 'qf-empty') expect(mock('/api/responses').body).toBeNull()
    if (mode === 'qf-second-fail') expect(mock('/api/actions/15/preconditions', 'PUT', { preconditions: [] })
      .status).toBe(500)
    if (mode === 'qf-first-fail') expect(mock('/api/actions/11', 'PUT', {}).status).toBe(500)
    if (mode === 'qf-third-fail') expect(mock('/api/actions/11', 'PUT', { action_type: 'webhook', enabled: true })
      .body.error).toBe('sync paired action: rollback incomplete: parent row')
  },
)
