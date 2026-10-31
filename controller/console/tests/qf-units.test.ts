import { describe, expect, it, vi } from 'vitest'
import { conditionsChanged, connectorName, defaults, exampleKey, fill, paired, payload, phaseRows,
  saveAction, validate } from '../src/views/responses/data'
import type { Condition, Form, Phase, Send } from '../src/views/responses/data'
import zh from '../src/i18n/zh'
import en from '../src/i18n/en'
import { mockSession } from '../mock/data'
const one = { attribute: 'severity', operator: 'eq', value: 'critical' }
const form = (more: Partial<Form> = {}) => ({ ...defaults(), ...more })
const base = { action_type: 'webhook', connector_id: 1, priority: 5, run_mode: 'once', execution: 'automatic',
  enabled: true, period_seconds: null, trigger_phase: 'on_detected' }
describe('G-units payload literal contracts', () => {
  it.each(['on_detected', 'on_expired'] as Phase[])('webhook and shell exact payload %s W9 W10', phase => {
    const f = Object.assign(form({ connector_id: 1 }), { trigger_phase: 'wrong' })
    expect(payload(f, phase)).toEqual({ ...base, trigger_phase: phase })
    f.action_type = 'shell'
    expect(payload(f, phase)).toEqual({ ...base, action_type: 'shell', trigger_phase: phase, shell_extra_args: '' })
    f.shell_extra_args = '--attack 7'; f.run_mode = 'periodic'
    expect(payload(f, phase)).toEqual({ ...base, action_type: 'shell', trigger_phase: phase,
      run_mode: 'periodic', period_seconds: 60, shell_extra_args: '--attack 7' })
  })
  it.each(['on_detected', 'on_expired'] as Phase[])('bgp zero delay always sent only in detected %s W11', phase => {
    expect(payload(form({ connector_id: 1, action_type: 'bgp' }), phase)).toEqual({ ...base, action_type: 'bgp',
      trigger_phase: phase, bgp_route_map: '', ...(phase === 'on_detected' ? { bgp_withdraw_delay_minutes: 0 } : {}) })
  })
  it.each(['on_detected', 'on_expired'] as Phase[])('xdrop filter five mappings no source %s W13 W14 W15', phase => {
    const p = payload(form({ action_type: 'xdrop', connector_id: 99,
      xdrop_fields: ['dst_ip', 'src_ip', 'dst_port', 'src_port', 'protocol'] }), phase)
    expect(p).toEqual({ ...base, action_type: 'xdrop', connector_id: null, trigger_phase: phase,
      xdrop_action: 'filter_l4', xdrop_fields: ['dst_ip', 'src_ip', 'dst_port', 'src_port', 'protocol'],
      xdrop_rate_limit: null, target_node_ids: null, xdrop_custom_payload: { dst_ip: '{dst_ip}', src_ip: '{src_ip}',
        dst_port: '{dominant_dst_port}', src_port: '{dominant_src_port}', protocol: '{decoder}',
        action: 'drop', comment: 'attack #{attack_id} {decoder}' },
      ...(phase === 'on_detected' ? { unblock_delay_minutes: 0 } : {}) })
  })
  it.each(['on_detected', 'on_expired'] as Phase[])('rate and unblock exact keys %s W12', phase => {
    const f = form({ action_type: 'xdrop', xdrop_action: 'rate_limit', target_node_ids: [2],
      unblock_delay_minutes: 17 })
    expect(payload(f, phase)).toEqual({ ...base, action_type: 'xdrop', connector_id: null, trigger_phase: phase,
      xdrop_action: 'rate_limit', xdrop_fields: ['dst_ip'], xdrop_rate_limit: 100000, target_node_ids: [2],
      xdrop_custom_payload: { dst_ip: '{dst_ip}', action: 'rate_limit', rate_limit: 100000,
        comment: 'attack #{attack_id} {decoder}' }, ...(phase === 'on_detected' ? { unblock_delay_minutes: 17 } : {}) })
    f.xdrop_action = 'unblock'
    expect(payload(f, phase)).toEqual({ ...base, action_type: 'xdrop', connector_id: null, trigger_phase: phase,
      xdrop_action: 'unblock', xdrop_fields: ['dst_ip'], xdrop_rate_limit: null, target_node_ids: [2],
      ...(phase === 'on_detected' ? { unblock_delay_minutes: 0 } : {}) })
  })
  it('fill legacy eleven defaults and structured conditions only W16', () => {
    expect(fill({ id: 7, action_type: 'shell', priority: 0, run_mode: '', xdrop_fields: null, enabled: false,
      connector_id: 2, preconditions: { legacy: true } }, true, [{ ...one, id: 9, action_id: 7 }])).toEqual({
      id: 7, action_type: 'shell', connector_id: 2, priority: 5, run_mode: 'once', period_seconds: 60,
      execution: 'automatic', xdrop_action: 'filter_l4', xdrop_fields: ['dst_ip'], xdrop_rate_limit: 100000,
      target_node_ids: [], shell_extra_args: '', bgp_route_map: '', bgp_withdraw_delay_minutes: 0,
      unblock_delay_minutes: 0, enabled: false, preconditionsLoaded: true, preconditions: [one],
    })
  })
  it('validation precedence then trim and 1-based row W17', () => {
    const f = form({ action_type: 'xdrop', xdrop_action: 'rate_limit', xdrop_fields: [], xdrop_rate_limit: 0,
      preconditions: [{ attribute: '', operator: 'eq', value: '' }] })
    expect(validate(f)).toEqual({ key: 'responses.filterFieldsRequired' })
    f.xdrop_fields = ['dst_ip']
    expect(validate(f)).toEqual({ key: 'responses.rateLimitRequired' })
    f.xdrop_rate_limit = 1; f.preconditions = [one, { ...one, value: '  ' }]
    expect(validate(f)).toEqual({ key: 'responses.conditionIncomplete', row: 2 })
    f.preconditions[1]!.value = 'high'
    expect(validate(f)).toBeUndefined()
  })
})
describe('G-units conditionsChanged and persistence sequence', () => {
  it.each([
    [null, true, [], [], false], [null, true, [one], [], true], [7, false, [one], [], false],
    [7, true, [one], [one], false],
    [7, true, [one], [{ ...one, value: 'high' }], true],
    [7, true, [one], [], true], [7, true, [], [one], true],
  ])('conditionsChanged %j W2', async (id, loaded, rows, current, expected) => {
    const send = vi.fn().mockResolvedValue(current)
    expect(await conditionsChanged(form({ id: id as number | null, preconditionsLoaded: loaded as boolean,
      preconditions: rows as Condition[] }), send)).toBe(expected)
    expect(send.mock.calls.length).toBe(id === null || !loaded ? 0 : 1)
  })
  it('reread failure counts changed W3', async () => {
    expect(await conditionsChanged(form({ id: 7 }), async () => { throw Error('read failed') })).toBe(true)
  })
  it('save-time reread sees database changes after open W2', async () => {
    const f = fill({ id: 7 }, true, [one])
    const send = vi.fn().mockResolvedValue([{ ...one, value: 'high' }])
    expect(await conditionsChanged(f, send)).toBe(true)
    expect(send).toHaveBeenCalledWith('/api/actions/7/preconditions', 'GET')
  })
  function recorder(fail = 0, current: Condition[] = []) {
    const writes: any[] = [], all: any[] = []
    const send: Send = async (path, method, body) => {
      all.push([path, method, body])
      if (method === 'GET') return current
      writes.push([path, method, body])
      if (writes.length === fail) throw Error(fail === 3 ? 'sync: rollback incomplete: parent row' : 'write rejected')
      return { id: 44 }
    }
    return { send, writes, all }
  }
  it('unchanged one write; changed enabled three writes with disabled first W1', async () => {
    const unchanged = recorder(0, [one])
    expect(await saveAction(form({ id: 7, preconditions: [one] }), 'on_detected', 3, unchanged.send))
      .toEqual({ ok: true, created: false })
    expect(unchanged.writes).toHaveLength(1)
    const r = recorder()
    expect(await saveAction(form({ connector_id: 1, preconditions: [one] }), 'on_detected', 3, r.send))
      .toEqual({ ok: true, created: true })
    expect(r.writes).toEqual([
      ['/api/responses/3/actions', 'POST', { ...base, enabled: false }],
      ['/api/actions/44/preconditions', 'PUT', { preconditions: [one] }],
      ['/api/actions/44', 'PUT', { ...base, enabled: true }],
    ])
  })
  it('changed disabled action two writes W4', async () => {
    const r = recorder()
    await saveAction(form({ preconditions: [one], enabled: false }), 'on_detected', 3, r.send)
    expect(r.writes).toHaveLength(2)
    expect(r.writes[0][2].enabled).toBe(false)
  })
  it.each([1, 2, 3])('failure step %s returns exact reason/suffix W6', async step => {
    const r = recorder(step), f = form({ preconditions: [one] })
    expect(await saveAction(f, 'on_detected', 3, r.send)).toEqual({ ok: false, step,
      reason: step === 3 ? 'sync: rollback incomplete: parent row' : 'write rejected',
      suffix: step === 2 ? 'responses.actionSavedDisabled' : step === 3 ? 'responses.reenableUnconfirmed' : '' })
    expect(f.enabled).toBe(true)
    expect(f.id).toBe(step === 1 ? null : 44)
  })
  it('identity preserved after second-step failure and retry is PUT same id W5', async () => {
    const f = form({ preconditions: [one] }), r = recorder(2)
    await saveAction(f, 'on_detected', 3, r.send)
    expect(f.id).toBe(44)
    const retry = recorder()
    await saveAction(f, 'on_detected', 3, retry.send)
    expect(retry.writes.map(w => [w[0], w[1]]))
      .toEqual([['/api/actions/44', 'PUT'], ['/api/actions/44/preconditions', 'PUT'], ['/api/actions/44', 'PUT']])
  })
})
it('G-units sort, group and phase child filter W22 W23', () => {
  const rows = [{ id: 1, action_type: 'bgp', priority: 1 }, { id: 2, action_type: 'webhook' },
    { id: 3, action_type: 'xdrop', priority: 9 }, { id: 4, action_type: 'xdrop', priority: 2 },
    { id: 5, action_type: 'shell' }].map(a => ({ ...a, trigger_phase: 'on_detected' }))
  expect(phaseRows(rows, 'on_detected').map(a => [a.id, a.divider]))
    .toEqual([[4, false], [3, false], [5, true], [2, true], [1, true]])
  expect(phaseRows([{ id: 6, trigger_phase: 'on_expired', auto_generated: true },
    { id: 7, trigger_phase: 'on_expired' }], 'on_expired').map(a => a.id)).toEqual([7])
})
it('G-units connector localization and failure fallback W24', () => {
  const nodes = [{ id: 1, name: 'Edge A', enabled: true }]
  expect(connectorName({ action_type: 'webhook', connector_name: 'Hook' }, nodes, false, '全部节点')).toBe('Hook')
  expect(connectorName({ action_type: 'shell', connector_name: '' }, [], false, '全部节点')).toBe('—')
  expect(connectorName({ action_type: 'xdrop', target_node_ids: [] }, nodes, false, '全部节点')).toBe('全部节点')
  expect(connectorName({ action_type: 'xdrop', target_node_ids: [1, 9] }, nodes, false, '全部节点')).toBe('Edge A +1')
  expect(connectorName({ action_type: 'xdrop', target_node_ids: [7] }, nodes, false, '全部节点')).toBe('#7')
  expect(connectorName({ action_type: 'xdrop', connector_name: '(all)' }, nodes, true, '全部节点')).toBe('(all)')
  expect(paired({ action_type: 'webhook', trigger_phase: 'on_detected' })).toBe(false)
})
const examples = [
  ['cidr', '32', '32,24'], ['decoder', 'udp', 'udp,tcp'], ['attack_type', 'syn_flood', 'syn_flood,udp_flood'],
  ['severity', 'critical', 'critical,high'], ['pps', '100000', '100000,200000'], ['bps', '100000', '100000,200000'],
  ['node', 'node-a', 'node-a,node-b'], ['domain', 'internal_ip', 'internal_ip,subnet'],
  ['dominant_src_port', '53', '53,123'], ['dominant_src_port_pct', '80', '80,90'],
  ['dominant_dst_port', '53', '53,123'], ['dominant_dst_port_pct', '80', '80,90'], 
  ['unique_src_ips', '1000', '1000,5000'],
]
it.each(examples)('G-units operator-aware examples and Go-valid combinations %s W34', (attribute, one, many) => {
  const mock = mockSession('qf')
  for (const [operator, literal] of [['eq', one], ['in', many], ['not_in', many]]) {
    const key = exampleKey(attribute!, operator!) as string
    for (const d of [zh, en]) {
      const shown = (d.responses as any)[key.replace('responses.', '')]
      expect(shown).toBe(literal)
      if (!(attribute === 'node' && operator === 'not_in')) {
        expect(mock('/api/actions/15/preconditions', 'PUT', { preconditions: [{ attribute, operator, value: shown }] })
          .status).toBe(200)
      }
    }
  }
  expect(exampleKey('', 'eq')).toBe('responses.value')
})
it('G-units failed XDrop connector read preserves empty backend name exactly', () => {
  expect(connectorName({ action_type: 'xdrop', connector_name: '' }, [], true, '全部节点')).toBe('')
})
