import { it, expect } from 'vitest'
import { mountQE, clickText, domClick, dialog, body, writes, textInput, calls } from './qe-harness'
import { response } from './helpers'
import { state } from '../src/state'
it.each([['pct', 80, 102], ['pps', 1200, 103]])(
  'auth1 B1 W36 selected unit %s preserves value %s through real drawer and PUT', async (unit, value, id) => {
    const { w } = await mountQE('/thresholds/7', (path, _init, result) => {
      if (path.startsWith('/api/threshold-templates/7')) return response(200, { ...result.body,
        rules: result.body.rules.map((rule: any) => rule.id === 103 ? { ...rule, value: 1200 } : rule) })
    })
    const row = w.findAll('tbody tr').find(r => r.text().includes(unit === 'pct' ? 'pct' : '出向'))!
    await clickText(row, '编辑')
    const field = dialog().querySelector<HTMLInputElement>('input[aria-label="阈值"]')!
    expect(field.value).toBe(String(value))
    await domClick(String(unit))
    expect(field.value).toBe(String(value))
    field.focus(); field.blur()
    await domClick('保存')
    expect(body().value).toBe(value)
    expect(writes().at(-1)?.[0]).toBe('/api/threshold-rules/' + id)
    expect(writes().at(-1)?.[1]?.method).toBe('PUT')
  })
it('auth1 A1 W38 parent candidates exclude only self and retain every other prefix', async () => {
  const { w } = await mountQE('/prefixes')
  await clickText(w.findAll('tbody tr').find(r => r.text().includes('10.1.0.0/16'))!, '编辑')
  const parent = dialog().querySelector<HTMLButtonElement>('[aria-label^="父级前缀:"]')!
  parent.click()
  const { flushPromises } = await import('@vue/test-utils')
  await flushPromises()
  expect([...dialog().querySelectorAll('[role=option]')].map(o => o.textContent?.trim())).toEqual([
    '— 无 —', '0.0.0.0/0 (Global)', '10.1.1.0/24 (Transit child)', '10.2.0.0/16 (Services)',
    '10.3.0.0/16 (Outbound)', '192.0.2.0/24 (Office)', '2001:db8::/48 (IPv6)', '203.0.113.0/24 (Unbound)',
  ])
})
it('auth1 A2 W39 write refresh clears stale template and baseline silently', async () => {
  let failAux = false
  const { w } = await mountQE('/prefixes', path => failAux
    && (path.startsWith('/api/threshold-templates') || path.startsWith('/api/baseline'))
    ? response(503, { error: 'auxiliary failed' }) : undefined)
  const transit = w.findAll('tbody tr').find(r => r.text().includes('10.1.0.0/16'))!
  expect(transit.findAll('td')[5]!.text()).toBe('Transit defaults')
  expect(transit.findAll('td')[6]!.text()).toContain('P95 150')
  await clickText(transit, '编辑')
  await textInput('名称', 'Auth1 prefix')
  failAux = true
  await domClick('保存')
  const row = w.findAll('tbody tr').find(r => r.text().includes('10.1.0.0/16'))!
  expect(row.text()).toContain('Auth1 prefix')
  expect(row.findAll('td')[5]!.text()).toBe('—')
  expect(row.findAll('td')[6]!.text()).toBe('—')
  expect(w.find('[role=alert]').exists()).toBe(false)
  expect(w.text()).not.toContain('auxiliary failed')
  expect(calls('/api/threshold-templates')).toHaveLength(2)
  expect(calls('/api/baseline')).toHaveLength(2)
})
it.each([['zh', '启用动态检测'], ['en', 'Enable Dynamic Detection']])(
  'auth1 P3-4 visible configuration label %s', async (locale, label) => {
    state.locale = locale as 'zh' | 'en'
    const { w } = await mountQE('/baseline')
    expect(w.get('.config').text()).toContain(label)
  })
