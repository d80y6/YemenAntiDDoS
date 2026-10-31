import { describe, expect, it, vi } from 'vitest'
import { flushPromises } from '@vue/test-utils'
import { saveSession } from '../src/state'
import { deferred, response } from './helpers'
import { clickText, dialog, mountQE } from './qe-harness'
const paths = () => vi.mocked(fetch).mock.calls.map(([p]) => String(p))
const auditPaths = () => paths().filter(p => p.startsWith('/api/audit-log'))
const settle = async () => { await flushPromises(); await flushPromises() }
async function dropdown(label: string) {
  const button = [...document.querySelectorAll<HTMLButtonElement>('button')]
    .find(b => b.getAttribute('aria-label')?.startsWith(label + ':'))!
  expect(button, label).toBeTruthy()
  button.click()
  await settle()
}
async function select(text: string) {
  const button = [...document.querySelectorAll<HTMLButtonElement>('[role=option]')]
    .find(b => b.textContent?.trim() === text)!
  expect(button, text).toBeTruthy()
  button.click()
  await settle()
}
async function search(value: string, enter = false) {
  const input = document.querySelector<HTMLInputElement>('[role=combobox]')!
  input.value = value
  input.dispatchEvent(new Event('input', { bubbles: true }))
  await settle()
  if (enter) input.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true }))
  await settle()
}
async function time(label: string, value: string) {
  const control = [...document.querySelectorAll('label')].find(l => l.textContent === label)!
  const input = document.getElementById(control.htmlFor) as HTMLInputElement
  expect(input).toBeTruthy()
  input.value = value
  input.dispatchEvent(new Event('input', { bubbles: true }))
  input.dispatchEvent(new Event('blur'))
  await settle()
  return input
}
const first = (w: any) => w.get('tbody tr').findAll('td')[0].text()
describe('G-au queries and rows', () => {
  it('mount requests, 50 rows, next and previous V14 V25', async () => {
    const { w } = await mountQE('/audit', undefined, true, 'qi')
    expect(paths()).toEqual(['/api/users', '/api/audit-log?limit=51&offset=0'])
    expect(w.findAll('thead th').map(h => h.text()))
      .toEqual(['ID', '用户', '实体类型', '实体 ID', '操作', '配置版本', '创建时间', '变更内容'])
    expect(w.findAll('tbody tr')).toHaveLength(50)
    expect(first(w)).toBe('59')
    expect(w.text()).toContain('第 1 页')
    await clickText(w, '下一页')
    expect(auditPaths().at(-1)).toBe('/api/audit-log?limit=51&offset=50')
    expect(first(w)).toBe('9')
    expect(w.findAll('tbody tr')).toHaveLength(9)
    expect(w.text()).toContain('第 2 页')
    expect(w.findAll('button').find(b => b.text() === '下一页')!.attributes('disabled')).toBeDefined()
    await clickText(w, '上一页')
    expect(first(w)).toBe('59')
    expect(w.text()).toContain('第 1 页')
  })
  it('literal null, unknown user, action pills, full time, long preview and details', async () => {
    const at = new Date(2026, 9, 27, 8, 9, 10).toISOString()
    const { w } = await mountQE('/audit', p => p.startsWith('/api/audit-log') ? response(200, [
      { id: 70, user_id: null, entity_type: 'user', entity_id: '1', action: 'create',
        delivery_version: null, diff: null, created_at: at },
      { id: 71, user_id: 7, entity_type: 'node', entity_id: 'flow-b', action: 'delete',
        delivery_version: 12, diff: { text: 'x'.repeat(140) }, created_at: at },
      { id: 72, user_id: 2, entity_type: 'user', entity_id: '2', action: 'update',
        delivery_version: 13, diff: {}, created_at: at },
    ]) : undefined, true, 'qi')
    const rows = w.findAll('tbody tr')
    expect(rows[0]!.findAll('td').map(c => c.text()))
      .toEqual(['70', '—', '用户', '1', '创建', '', '2026-10-27 08:09:10', '-'])
    expect(rows[0]!.get('.pill').classes()).toContain('ok')
    expect(rows[1]!.get('.pill').classes()).toContain('crit')
    expect(rows[2]!.get('.pill').classes()).toContain('warn')
    expect(rows[1]!.findAll('td')[1]!.text()).toBe('#7')
    expect(rows[1]!.findAll('td')[1]!.classes()).toContain('sub')
    expect(rows[1]!.get('.au-diff').text()).toBe('{"text":"' + 'x'.repeat(91))
    expect(rows[2]!.findAll('td')[1]!.text()).toBe('noc-01')
    await rows[1]!.trigger('click')
    expect(dialog().querySelector('h2')?.textContent).toBe('审计条目 · 节点 flow-b')
    expect([...dialog().querySelectorAll('dt')].map(d => d.textContent))
      .toEqual(['ID', '用户', '实体类型', '实体 ID', '操作', '配置版本', '创建时间'])
    expect(dialog().querySelector('pre')?.textContent?.trim()).toBe('{\n  "text": "' + 'x'.repeat(140) + '"\n}')
  })
  it('null detail version and diff', async () => {
    const { w } = await mountQE('/audit', undefined, true, 'qi')
    await w.findAll('tbody tr')[5]!.trigger('click')
    expect(dialog().querySelector('pre')?.textContent?.trim()).toBe('-')
    expect([...dialog().querySelectorAll('dd')].map(d => d.textContent)).toContain('—')
  })
  it('loading disables both pagination buttons', async () => {
    const pending = deferred<Response>()
    const { w } = await mountQE('/audit', p => p.startsWith('/api/audit-log') ? pending.promise : undefined, true, 'qi')
    expect(w.get('.au-pager').text()).toContain('加载中…')
    expect(w.get('.au-pager').findAll('button').every(b => b.attributes('disabled') !== undefined)).toBe(true)
    pending.resolve(response(200, []))
    await settle()
    expect(w.get('section').attributes('aria-busy')).toBe('false')
  })
  it.each([200, 500])('stale request ignored including loading and errors status=%s V13', async status => {
    const old = deferred<Response>()
    const { w } = await mountQE('/audit', p => p === '/api/audit-log?limit=51&offset=0' ? old.promise : undefined,
      true, 'qi')
    await dropdown('实体类型')
    await select('用户')
    expect(first(w)).toBe('53')
    const signal = vi.mocked(fetch).mock.calls[1]![1]!.signal!
    expect(signal.aborted).toBe(true)
    old.resolve(response(status, status === 200 ? [{ id: 999, entity_type: 'stale', user_id: null,
      entity_id: '99', action: 'delete', delivery_version: null, diff: null, created_at: '2026-10-27T00:00:00Z' }]
      : { error: 'stale error' }))
    await settle()
    expect(first(w)).toBe('53')
    expect(w.text()).not.toContain('stale')
    expect(w.get('section').attributes('aria-busy')).toBe('false')
  })
  it.each(['qi-audit-fail', 'qi-audit-empty'])('first response %s', async mode => {
    const { w } = await mountQE('/audit', undefined, true, mode)
    expect(w.get('tbody').text()).toBe(mode === 'qi-audit-fail' ? '查询失败 audit unavailable' : '暂无数据')
  })
  it('page failure retains page, rows and next state V15', async () => {
    const { w } = await mountQE('/audit', undefined, true, 'qi-audit-page-fail')
    await clickText(w, '下一页')
    expect(w.get('[role=alert]').text()).toBe('查询失败 audit unavailable （仍显示第 1 页的旧结果）')
    expect(w.findAll('tbody tr')).toHaveLength(50)
    expect(first(w)).toBe('59')
    expect(w.get('.au-pager').text()).toContain('第 1 页')
    expect(w.findAll('button').find(b => b.text() === '下一页')!.attributes('disabled')).toBeUndefined()
  })
  it('filter failure clears former page and resets page one', async () => {
    const h = await mountQE('/audit', undefined, true, 'qi')
    await clickText(h.w, '下一页')
    h.intercept(p => p.startsWith('/api/audit-log') ? response(500, { error: 'filter failed' }) : undefined)
    await dropdown('实体类型')
    await select('节点')
    expect(h.w.get('tbody').text()).toBe('查询失败 filter failed')
    expect(h.w.get('.au-pager').text()).toContain('第 1 页')
    expect(h.w.text()).not.toContain('仍显示')
  })
})
describe('G-au filters and roles', () => {
  it('fixed type, free text enter and blur, all types clear with literal query', async () => {
    await mountQE('/audit', undefined, true, 'qi')
    await dropdown('实体类型')
    expect(document.querySelectorAll('[role=option]')).toHaveLength(20)
    await select('前缀')
    expect(auditPaths().at(-1)).toBe('/api/audit-log?entity_type=watch_prefix&limit=51&offset=0')
    await dropdown('实体类型')
    await search('new/type &', true)
    expect(auditPaths().at(-1)).toBe('/api/audit-log?entity_type=new%2Ftype+%26&limit=51&offset=0')
    await dropdown('实体类型')
    await search('future_kind')
    document.querySelector<HTMLInputElement>('[role=combobox]')!.dispatchEvent(new Event('blur'))
    await settle()
    expect(auditPaths().at(-1)).toBe('/api/audit-log?entity_type=future_kind&limit=51&offset=0')
    await dropdown('实体类型')
    await search('')
    await select('全部类型')
    expect(auditPaths().at(-1)).toBe('/api/audit-log?limit=51&offset=0')
  })
  it('user search, selection and clear', async () => {
    await mountQE('/audit', undefined, true, 'qi')
    await dropdown('用户')
    await search('noc')
    expect(document.querySelectorAll('[role=option]')).toHaveLength(1)
    await select('noc-01')
    expect(auditPaths().at(-1)).toBe('/api/audit-log?user_id=2&limit=51&offset=0')
    await dropdown('用户')
    await search('')
    await select('全部用户')
    expect(auditPaths().at(-1)).toBe('/api/audit-log?limit=51&offset=0')
  })
  it('valid time ISO, invalid omission and clear V18', async () => {
    const { w } = await mountQE('/audit', undefined, true, 'qi')
    await time('开始时间', '2026-10-27 08:00')
    expect(auditPaths().at(-1)).toBe('/api/audit-log?from='
      + encodeURIComponent(new Date(2026, 9, 27, 8).toISOString()) + '&limit=51&offset=0')
    const input = await time('开始时间', '2026-02-31')
    expect(input.getAttribute('aria-invalid')).toBe('true')
    expect(w.text()).toContain('格式不对，这个条件没有生效；例：2026-10-27 08:00')
    expect(auditPaths().at(-1)).toBe('/api/audit-log?limit=51&offset=0')
    await w.get('[aria-label="清空开始时间"]').trigger('click')
    expect(input.value).toBe('')
    expect(input.getAttribute('aria-invalid')).toBe('false')
    expect(w.find('[aria-label="清空开始时间"]').exists()).toBe(false)
  })
  it('inverted range invalidates pending request and sends none V16', async () => {
    const late = deferred<Response>()
    const h = await mountQE('/audit', undefined, true, 'qi')
    await time('开始时间', '2026-10-27 12:00')
    h.intercept(p => p.startsWith('/api/audit-log') ? late.promise : undefined)
    await time('结束时间', '2026-10-27 13:00')
    const count = auditPaths().length
    await time('结束时间', '2026-10-27 08:00')
    expect(auditPaths()).toHaveLength(count)
    expect(h.w.get('tbody').text()).toBe('开始时间不能晚于结束时间')
    expect(h.w.findAll('input[aria-invalid="true"]')).toHaveLength(2)
    late.resolve(response(200, []))
    await settle()
    expect(h.w.get('tbody').text()).toBe('开始时间不能晚于结束时间')
    expect(h.w.get('section').attributes('aria-busy')).toBe('false')
  })
  it('users failure permits audit and falls back to ids', async () => {
    const { w } = await mountQE('/audit', undefined, true, 'qi-users-fail')
    expect(w.findAll('tbody tr')[1]!.findAll('td')[1]!.text()).toBe('#2')
    await dropdown('用户')
    expect([...document.querySelectorAll('[role=option]')].map(b => b.textContent?.trim())).toEqual(['全部用户'])
  })
  it('viewer has same read page and can open detail', async () => {
    const { w } = await mountQE('/audit', undefined, false, 'qi')
    saveSession('development-viewer', { id: 3, username: 'audit-ro', role: 'viewer' })
    await settle()
    expect(w.findAll('thead th')).toHaveLength(8)
    await clickText(w, '下一页')
    expect(first(w)).toBe('9')
    await w.get('tbody tr').trigger('click')
    expect(dialog().textContent).toContain('审计条目')
  })
})
