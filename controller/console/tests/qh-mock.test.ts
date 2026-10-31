import { expect, it } from 'vitest'
import { mockReply, mockSession, qdReply } from '../mock/data'
it.each(['normal', 'attacks', 'null', 'qd-empty', 'qd-slash', 'qd-delete-error'])(
  'G-fl legacy listener read unchanged %s', mode => {
    for (const node of ['flow-b', 'edge-a', 'a/b', '']) {
      const path = '/api/flow-listeners?node_id=' + encodeURIComponent(node)
      expect(mockReply(path, mode, 0)).toEqual(qdReply(path, mode, 0))
      expect(mockSession(mode, 0)(path)).toEqual(qdReply(path, mode, 0))
    }
  })
it('G-fl qh modes alone add flow-d; no new default node', () => {
  expect(mockReply('/api/nodes').body.map((n: any) => n.id)).toEqual(['edge-a', 'flow-b', 'edge-c'])
  expect(mockReply('/api/nodes', 'qh').body.map((n: any) => n.id)).toEqual(['edge-a', 'flow-b', 'edge-c', 'flow-d'])
})
it.each([
  [{ node_id: '', listen_address: '', protocol_mode: 'bad' }, 'node_id is required'],
  [{ node_id: 'flow-b', listen_address: '' }, 'listen_address is required'],
  [{ node_id: 'flow-b', listen_address: '2055' }, 'listen_address must be :port or host:port format'],
  [{ node_id: 'flow-b', listen_address: ':0' }, 'listen_address port must be 1-65535'],
  [{ node_id: 'flow-b', listen_address: ':65536' }, 'listen_address port must be 1-65535'],
  [{ node_id: 'flow-b', listen_address: ':2056', protocol_mode: 'bad' }, "protocol_mode must be 'auto', 'sflow', 'netflow', or 'ipfix'"],
  [{ node_id: 'missing', listen_address: ':2056' }, 'node_id not found: missing'],
  [{ node_id: 'edge-a', listen_address: ':2056' }, 'node edge-a is mode=xdp, flow listeners require mode=flow'],
])('G-fl mock Listener validation order %j', (body, error) => {
  expect(mockSession('qh')('/api/flow-listeners', 'POST', body)).toEqual({ status: 400, body: { error } })
})
it.each([
  [{ name: '', device_ip: '', sample_mode: 'bad' }, 'name is required'],
  [{ name: 'router', device_ip: '' }, 'device_ip is required'],
  [{ name: 'router', device_ip: '192.0.2.1/32' }, 'device_ip must be a valid IPv4 or IPv6 address'],
  [{ name: 'router', device_ip: '192.0.2.01' }, 'device_ip must be a valid IPv4 or IPv6 address'],
  [{ name: 'router', device_ip: '192.0.2.1', sample_mode: 'bad' }, "sample_mode must be 'auto', 'force', or 'none'"],
  [{ name: 'router', device_ip: '192.0.2.1', sample_mode: 'force', sample_rate: 0 }, "sample_rate must be > 0 when sample_mode is 'force'"],
  [{ name: 'router', device_ip: '192.0.2.1', listener_id: 999 }, 'listener_id not found'],
])('G-fl mock source validation order %j', (body, error) => {
  expect(mockSession('qh')('/api/flow-sources', 'POST', body)).toEqual({ status: 400, body: { error } })
})
it('G-fl source query failures and not-found raw strings', () => {
  const mock = mockSession('qh')
  for (const id of ['', 'abc']) expect(mock('/api/flow-sources?listener_id=' + id))
    .toEqual({ status: 400, body: { error: 'listener_id is required' } })
  expect(mock('/api/flow-sources?listener_id=999')).toEqual({ status: 200, body: [] })
  expect(mock('/api/flow-sources/999')).toEqual({ status: 404, body: { error: 'flow source not found' } })
  expect(mock('/api/flow-listeners/999')).toEqual({ status: 404, body: { error: 'flow listener not found' } })
})
it.each([-2147483649, 2147483648])('G-fl B3 mock int32 overflow %s does not allocate or alter a row', rate => {
  const session = mockSession('qh')
  const body = { listener_id: 1, name: 'Boundary', device_ip: '192.0.2.9', sample_mode: 'auto',
    sample_rate: rate, description: 'raw' }
  const write = (path: string, method: string, value: object) => session(path, method, value)
  expect(write('/api/flow-sources', 'POST', body)).toEqual({ status: 500, body: { error: 'database error' } })
  const before = session('/api/flow-sources/2')
  expect(write('/api/flow-sources/2', 'PUT', { ...body, enabled: true }))
    .toEqual({ status: 500, body: { error: 'database error' } })
  expect(session('/api/flow-sources/2')).toEqual(before)
  expect(write('/api/flow-sources', 'POST', { ...body, sample_rate: 1000 }))
    .toEqual({ status: 201, body: { id: 4 } })
})
