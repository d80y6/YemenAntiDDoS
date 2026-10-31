import { beforeEach, expect, it } from 'vitest'
import { calls, clock, mountPage, params } from './attacks-harness'
beforeEach(clock)
it.each(['active', 'expired', 'all'])('K6 %s main request and counts', async status => {
  const { w } = await mountPage('/attacks?status=' + status)
  const requests = calls('/api/attacks')
  expect(requests).toHaveLength(3)
  expect(params(requests[0]).get('limit')).toBe('50')
  expect(params(requests[0]).get('sort')).toBe(status === 'active' ? 'peak_pps' : null)
  for (const call of requests.slice(1)) {
    expect(params(call).get('limit')).toBe('1')
    expect(params(call).has('sort')).toBe(false)
  }
  if (status === 'active') {
    expect(w.findAll('tbody tr').map(r => Number(r.get('td a').text().slice(1))))
      .toEqual([7, 6, 5, 4, 3, 2, 1])
  }
  if (status === 'all') {
    expect(w.findAll('.pager button').map(b => b.text()).filter(t => /^\d+$/.test(t)))
      .toEqual(['1', '2'])
  }
})
it('K6 empty active probe falls back to all without sort', async () => {
  await mountPage('/attacks', 'null')
  const requests = calls('/api/attacks')
  expect(params(requests[0]).get('sort')).toBe('peak_pps')
  expect(params(requests[1]).get('limit')).toBe('50')
  expect(params(requests[1]).has('status')).toBe(false)
  expect(params(requests[1]).has('sort')).toBe(false)
  expect(requests.filter(c => params(c).get('limit') === '1')
    .every(c => !params(c).has('sort'))).toBe(true)
})
