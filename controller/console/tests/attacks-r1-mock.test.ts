import { beforeEach, afterEach, describe, it, expect, vi } from 'vitest'
import { mockReply, mockSession } from '../mock/data'
beforeEach(() => { vi.useFakeTimers(); vi.stubEnv('XSIGHT_API', ''); vi.stubEnv('XSIGHT_MOCK_CASE', '') })
afterEach(() => vi.unstubAllEnvs())
async function middleware(path: string) {
  let handler: any
  const serverModule = '../mock/server'
  const plugin: any = (await import(serverModule)).mockPlugin()
  plugin.configureServer({ middlewares: { use: (fn: any) => { handler = fn } } })
  const res = { statusCode: 0, setHeader: vi.fn(), end: vi.fn() }
  await handler({ method: 'GET', url: path }, res, vi.fn())
  return res
}
describe('r1 mock handler parity', () => {
  it('R1-08 W42 default middleware responds to attack 2 samples without a delay', async () => {
    const res = await middleware('/api/attacks/2/sensor-logs')
    expect(res.end).toHaveBeenCalledTimes(1); expect(res.statusCode).toBe(200)
  })
  it('R1-08 W42 explicit loading middleware alone owns the sample loading delay', async () => {
    vi.stubEnv('XSIGHT_MOCK_CASE', 'loading')
    const res = await middleware('/api/attacks/2/sensor-logs')
    expect(res.end).toHaveBeenCalledTimes(0)
    await vi.advanceTimersByTimeAsync(20000); expect(res.end).toHaveBeenCalledTimes(1)
  })
  it.each([
    ['5s', '2026-10-28T11:59:53Z', '2026-10-28T12:00:03Z',
      ['2026-10-28T11:59:55.000Z', '2026-10-28T12:00:00.000Z']],
    ['5min', '2026-10-28T11:52:01Z', '2026-10-28T12:07:02Z',
      ['2026-10-28T11:55:00.000Z', '2026-10-28T12:00:00.000Z', '2026-10-28T12:05:00.000Z']],
  ])('R1-10 fixed %s bucket boundaries stay within requested range', (resolution, from, to, expected) => {
    const query = new URLSearchParams({ from, to, resolution, direction: 'sends' })
    const result = mockReply('/api/stats/timeseries?' + query)
    expect(result.body.map((p: any) => p.time)).toEqual(expected)
  })
  it.each([
    { attack_id: '1' }, { attack_id: 0 }, { action_id: 11.5 }, { action_id: 0 },
    { connector_id: '1' }, { connector_id: 0 }, { external_rule_id: 123 }, { external_rule_id: '' },
  ])('R1-10 force-remove Go binding rejects %j', change => {
    const result = mockSession()('/api/active-actions/force-remove', 'POST', {
      attack_id: 1, action_id: 11, connector_id: 1, external_rule_id: 'shared-rule', ...change,
    })
    expect(result.status).toBe(400)
  })
  it.each([
    ['direction=invalid', "direction must be 'receives' or 'sends'"],
    ['ended_after=bad', 'invalid ended_after'], ['ended_after=', 'invalid ended_after'],
    ['dst_ip=198.51..7', 'invalid dst_ip'], ['dst_ip=', 'invalid dst_ip'],
  ])('R1-10 invalid list query %s returns original handler error', (query, error) => {
    expect(mockReply('/api/attacks?' + query)).toEqual({ status: 400, body: { error } })
  })
})
