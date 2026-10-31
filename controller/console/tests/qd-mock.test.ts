import { it, expect } from 'vitest'
import { mockReply } from '../mock/data'
const now = Date.parse('2026-10-28T12:00:00.000Z')
it('Go fixture FlowListener uses exact store fields and validates node_id', () => {
  expect(mockReply('/api/flow-listeners?node_id=edge-a', 'qd', now).body).toEqual([
    { id: 1, node_id: 'edge-a', listen_address: '0.0.0.0:6343', protocol_mode: 'sflow', enabled: true,
      description: 'Flow input', created_at: '2026-10-27T12:00:00.000Z' },
  ])
  expect(mockReply('/api/flow-listeners', 'qd', now)).toMatchObject({ status: 400,
    body: { error: 'node_id is required' } })
})
it('Go fixture status nine conditional branches have values possible in their handlers', () => {
  const s = mockReply('/api/nodes/edge-a/status', 'qd', now).body
  expect(Object.keys(s).sort()).toEqual(['capture', 'config_status', 'connected_at',
    'delivery_version_applied', 'delivery_version_current', 'drift', 'flow_metrics', 'id', 'interfaces',
    'last_ack_at', 'last_stats_at', 'listener_statuses', 'mode', 'online', 'source_statuses',
    'stats_age_seconds', 'uptime_seconds'])
  expect(s.flow_metrics).toEqual({ decode_errors: 0, unknown_exporter: 0, template_misses: 0,
    updated_at: '2026-10-28T11:59:55.000Z' })
  expect(s.source_statuses).toEqual([{ device_ip: '192.0.2.1', active: true, last_seen_at: 1793188795,
    records_received: 100 }])
  expect(s.listener_statuses).toEqual([{ listen_addr: '0.0.0.0:6343', protocol_mode: 'sflow', records_decoded: 100,
    decode_errors: 0, unknown_exporter: 0, template_misses: 0, source_count: 1 }])
})
it('Go fixture timeline includes all mandatory ActionExecutionLog fields and BGP action type', () => {
  const logs = mockReply('/api/active-actions/timeline?attack_id=1&action_id=5&connector_id=1'
    + '&external_rule_id=192.0.2.16%2F28%7Cdefense', 'qd', now).body.logs
  for (const log of logs) expect(Object.keys(log).sort()).toEqual(['action_id', 'action_type', 'attack_id',
    'connector_id', 'connector_name', 'duration_ms', 'error_message', 'executed_at', 'external_rule_id', 'id',
    'request_body', 'response_body', 'response_name', 'status', 'status_code', 'trigger_phase'])
  expect(logs[0].action_type).toBe('bgp')
  expect(logs[1]).toMatchObject({ action_type: 'manual_override', trigger_phase: 'manual_override',
    status: 'failed', error_message: 'upstream busy' })
})
it('r1 B5 W41 synthetic rule retains the destination populated before request-body parsing', () => {
  const entry = mockReply('/api/active-actions/xdrop', 'qd', now).body[2]
  expect(entry).toMatchObject({ external_rule_id: 'failed-create-5',
    attack_dst_ip: '198.51.100.7/32', dst_ip: '198.51.100.7/32' })
})
it('r1 B5 orphan fixtures have zero attack and action identities', () => {
  const orphans = mockReply('/api/active-actions/bgp', 'qd', now).body.filter((entry: any) => entry.is_orphan)
  expect(orphans.map((entry: any) => [entry.announcement_id, entry.attack_id, entry.action_id]))
    .toEqual([[8, 0, 0], [9, 0, 0]])
})
it('r1 B5 connector views include all permanent fields with masked API keys', () => {
  expect(mockReply('/api/settings/xdrop-connectors', 'qd', now).body).toEqual([
    { id: 1, name: 'Edge XDrop', enabled: true, api_url: 'http://mock-xdrop.invalid', api_key: '***abcd',
      timeout_ms: 10000, created_at: '2026-10-27T12:00:00.000Z', updated_at: '2026-10-28T11:59:55.000Z' },
    { id: 2, name: 'Disabled XDrop', enabled: false, api_url: 'http://mock-disabled.invalid', api_key: '***',
      timeout_ms: 10000, created_at: '2026-10-27T12:00:00.000Z', updated_at: '2026-10-28T11:59:55.000Z' },
  ])
})
it('r1 B5 connector empty modes return an empty JSON array', () => {
  for (const mode of ['null', 'qd-empty', 'qd-connectors-empty']) {
    expect(mockReply('/api/settings/xdrop-connectors', mode, now).body).toEqual([])
  }
})
it('r1 B5 ordinary fixtures omit zero-valued optional fields; explicit tolerant sample keeps them', () => {
  const entries = mockReply('/api/active-actions/xdrop', 'qd', now).body
  expect(entries[4]).not.toHaveProperty('src_port')
  expect(entries[5]).not.toHaveProperty('protocol')
  expect(entries[5]).not.toHaveProperty('src_port')
  expect(entries[5]).not.toHaveProperty('dst_port')
  const tolerant = mockReply('/api/active-actions/xdrop', 'qd-tolerant-zero', now).body[5]
  expect(tolerant).toMatchObject({ protocol: '', src_port: 0, dst_port: 0, rate_limit: 1000 })
})
