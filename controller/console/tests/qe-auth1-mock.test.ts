import { it, expect } from 'vitest'
import { middlewareProbe } from './qe-fixtures.mjs'
const prefix = { prefix: '198.51.100.0/24', name: 'New', ip_group: '', parent_id: null,
  threshold_template_id: null }
const rule = { prefix_id: 1, domain: 'internal_ip', direction: 'receives', decoder: 'tcp_syn', unit: 'pps',
  comparison: 'over', value: 500, inheritable: true }
const config = { enabled: true, deviation_min: 50, deviation_max: 150, stable_weeks: 6,
  min_pps: 2000, min_bps: 16000, ewma_alpha: 0.25 }
it.each(['POST', 'PUT'])('auth1 B2-1 prefix %s nonexistent parent is 400 before commit', async method => {
  const invoke = await middlewareProbe()
  expect(await invoke(method, '/api/prefixes' + (method === 'PUT' ? '/1' : ''), { ...prefix, parent_id: 999 }))
    .toEqual({ status: 400, body: { error: 'parent_id not found' } })
  const rows = (await invoke('GET', '/api/prefixes', {})).body!
  expect(rows).toHaveLength(8)
  expect(rows.find((r: any) => r.id === 1).name).toBe('Transit')
})
it.each(['999', false, {}, []])('auth1 B2-2 prefix PUT ignores nonnumeric nonnull ids %j', async value => {
  const invoke = await middlewareProbe()
  expect(await invoke('PUT', '/api/prefixes/4', { parent_id: value, threshold_template_id: value }))
    .toEqual({ status: 200, body: { ok: true } })
  expect((await invoke('GET', '/api/prefixes', {})).body!.find((p: any) => p.id === 4))
    .toMatchObject({ parent_id: 1, threshold_template_id: 7 })
})
it('auth1 B2-2 prefix PUT numeric ids and explicit null still change the stored values', async () => {
  const invoke = await middlewareProbe()
  await invoke('PUT', '/api/prefixes/4', { parent_id: null, threshold_template_id: null })
  expect((await invoke('GET', '/api/prefixes', {})).body!.find((p: any) => p.id === 4))
    .toMatchObject({ parent_id: null, threshold_template_id: null })
  await invoke('PUT', '/api/prefixes/4', { parent_id: 2, threshold_template_id: 8 })
  expect((await invoke('GET', '/api/prefixes', {})).body!.find((p: any) => p.id === 4))
    .toMatchObject({ parent_id: 2, threshold_template_id: 8 })
})
const invalidRules = [
  [{ unit: 'other', comparison: 'bad', domain: 'bad', value: -1 }, 'unit must be one of: pps, bps, pct; got "other"'],
  [{ comparison: 'between', domain: 'bad' }, 'comparison must be one of: over, under; got "between"'],
  [{ domain: 'host', value: -1 }, 'domain must be one of: internal_ip, subnet; got "host"'],
  [{ value: -1, decoder: 'unknown' }, 'value must be between 0 and 9223372036854775807, got -1'],
  [{ decoder: 'unknown', direction: 'east' },
    'decoder must be one of: ip, bad_fragment, esp, fragment, gre, icmp, igmp, invalid, ip_other, tcp,'
    + ' tcp_ack, tcp_fin, tcp_rst, tcp_syn, udp; got "unknown"'],
  [{ direction: 'east' }, "direction must be 'receives' or 'sends', got \"east\""],
  [{ unit: 'pct', decoder: 'ip', value: 101 }, 'percentage thresholds are not meaningful for decoder=ip (always 100%);'
    + ' use a specific decoder like tcp, udp, icmp'],
  [{ unit: 'pct', value: 0 }, 'percentage threshold value must be between 1 and 100, got 0'],
  [{ unit: 'pct', value: 101 }, 'percentage threshold value must be between 1 and 100, got 101'],
] as const
for (const [method, path] of [['POST', '/api/threshold-templates/7/rules'], ['POST', '/api/thresholds'],
  ['PUT', '/api/threshold-rules/101']]) {
  it.each(invalidRules)('auth1 B2-3 validateThreshold order ' + method + ' ' + path + ' %j', async (change, error) => {
    const invoke = await middlewareProbe()
    expect(await invoke(method, path, { ...rule, ...change })).toEqual({ status: 400, body: { error } })
  })
}
it.each([[101, 7, null], [107, null, 1]])('auth1 B2-4 rule %s PUT ownership immutable',
  async (id, templateID, prefixID) => {
  const invoke = await middlewareProbe()
  expect(await invoke('PUT', '/api/threshold-rules/' + id, { template_id: 8, prefix_id: 9, value: 123 }))
    .toEqual({ status: 200, body: { ok: true } })
  expect((await invoke('GET', '/api/thresholds', {})).body!.find((r: any) => r.id === id))
    .toMatchObject({ id, template_id: templateID, prefix_id: prefixID, value: 123 })
})
it.each([
  [{ deviation_min: -1, stable_weeks: 0, ewma_alpha: 2 }, 'deviation values must be non-negative'],
  [{ deviation_max: -1 }, 'deviation values must be non-negative'],
  [{ deviation_min: 151, ewma_alpha: 2 }, 'deviation_min must be <= deviation_max'],
  [{ stable_weeks: 0, ewma_alpha: 2 }, 'stable_weeks must be >= 1'],
  [{ ewma_alpha: 0, min_pps: -1 }, 'ewma_alpha must be between 0 and 1 (exclusive)'],
  [{ ewma_alpha: 1 }, 'ewma_alpha must be between 0 and 1 (exclusive)'],
  [{ min_pps: -1, min_bps: -1 }, 'min_pps must be >= 0'],
  [{ min_bps: -1 }, 'min_bps must be >= 0'],
])('auth1 B2-5 dynamic config validation order %j', async (change, error) => {
  const invoke = await middlewareProbe()
  expect(await invoke('PUT', '/api/dynamic-detection/config', { ...config, ...change }))
    .toEqual({ status: 400, body: { error } })
  expect(await invoke('GET', '/api/dynamic-detection/config', {})).toEqual({ status: 200, body: config })
})
it.each(['POST', 'PUT'])('auth1 B2-6 global prefix %s rejects blocking template default', async method => {
  const invoke = await middlewareProbe()
  expect(await invoke('PUT', '/api/threshold-templates/9', { response_id: 2 }))
    .toEqual({ status: 200, body: { ok: true } })
  expect(await invoke(method, '/api/prefixes' + (method === 'PUT' ? '/8' : ''), {
    ...prefix, prefix: '0.0.0.0/0', threshold_template_id: 9 }))
    .toEqual({ status: 400,
      body: { error: 'Global prefix (0.0.0.0/0) cannot use responses containing xDrop/BGP actions' } })
  expect((await invoke('GET', '/api/prefixes', {})).body!.find((p: any) => p.id === 8).threshold_template_id).toBe(8)
})
it('auth1 B2-6 template default uses the same global error and null clears the default', async () => {
  const invoke = await middlewareProbe()
  expect(await invoke('PUT', '/api/threshold-templates/8', { response_id: 2 }))
    .toEqual({ status: 400,
      body: { error: 'Global prefix (0.0.0.0/0) cannot use responses containing xDrop/BGP actions' } })
  expect(await invoke('PUT', '/api/threshold-templates/8', { response_id: null }))
    .toEqual({ status: 200, body: { ok: true } })
})
it.each(['/api/threshold-templates', '/api/threshold-templates/7/duplicate'])(
  'auth1 B2-7 W37 duplicate name is 409 already exists %s', async path => {
    const invoke = await middlewareProbe()
    expect(await invoke('POST', path, { name: 'Transit defaults', description: 'Rejected' }))
      .toEqual({ status: 409, body: { error: 'already exists' } })
    expect((await invoke('GET', '/api/threshold-templates', {})).body).toHaveLength(3)
  })
it('auth1 B3 profile thresholds are hand-calculated from expected traffic and sample weeks', async () => {
  const invoke = await middlewareProbe()
  const rows = (await invoke('GET', '/api/dynamic-detection/status', {})).body!.prefixes
  expect(rows.map((r: any) => [r.prefix, r.thresh_pps, r.thresh_bps, r.sample_weeks])).toEqual([
    ['2001:db8::/48', 0, 0, 0], ['10.2.0.0/16', 400, 4000, 3], ['10.1.0.0/16', 150, 1500, 6],
  ])
  expect(rows[1]).toMatchObject({ current_pps: 100, thresh_pps: 400,
    current_bps: 20000, thresh_bps: 4000, status: 'exceeded' })
})
