import { it, expect, vi } from 'vitest'
import { flushPromises } from '@vue/test-utils'
import { sourceText } from './r1-files.mjs'
import { parse, compileStyle } from '@vue/compiler-sfc'
import { mountQD, calls, clock, tick, clickText, dialog, domClick } from './qd-harness'
import { response, render } from './helpers'
import { checkContract } from '../scripts/contract-check.mjs'
import { bgpConfirmation } from '../src/views/mitigations/data'
import Status from '../src/views/mitigations/Status.vue'
import { i18n } from '../src/i18n'
import { notifications } from '../src/notifications'
import zh from '../src/i18n/zh'
import en from '../src/i18n/en'

it('r1 B1 W39 BGP unnamed connector stays in its own namespace in list and drawer', async () => {
  const { w } = await mountQD('/mitigations', 'qd', (path, _init, reply) => {
    if (path !== '/api/active-actions/bgp') return
    const entries = reply.body.map((entry: any, index: number) => index === 0
      ? { ...entry, connector_name: '', connector_id: 1 } : entry)
    return response(200, entries)
  })
  const entry = w.get('[data-testid=bgp] tr.link')
  expect(entry.findAll('td')[2]!.text()).toBe('#1')
  await entry.get('td').trigger('click'); await flushPromises()
  expect(dialog().querySelectorAll('.kv > dd')[2]!.textContent?.trim()).toBe('#1')
  expect(dialog().textContent).not.toContain('Edge XDrop')
})
it('r1 B2 W40 release submission rechecks newly disabled connector and keeps raw failure', async () => {
  clock()
  const { w, intercept } = await mountQD()
  await w.get('[data-testid=xdrop] tr.link button').trigger('click'); await flushPromises()
  intercept((path, _init, reply) => path === '/api/settings/xdrop-connectors'
    ? response(200, reply.body.map((entry: any) => ({ ...entry, enabled: false }))) : undefined)
  await tick(5000)
  expect(w.get('[data-testid=xdrop] tr.link button').attributes('disabled')).toBeDefined()
  await clickText(w.get('[role=alertdialog]'), '释放')
  expect(calls('/api/active-actions/force-remove')).toHaveLength(0)
  expect(w.get('[role=alertdialog]').get('[role=alert]').text()).toBe('连接器已停用，强制解除会被拒绝')
  expect(notifications.at(-1)).toMatchObject({ tone: 'crit', message: '连接器已停用，强制解除会被拒绝' })
})
it('r1 B2 failed connector lookup still permits an open release confirmation', async () => {
  clock()
  const { w, intercept } = await mountQD()
  await w.get('[data-testid=xdrop] tr.link button').trigger('click'); await flushPromises()
  intercept(path => path === '/api/settings/xdrop-connectors' ? response(503, { error: 'lookup failed' }) : undefined)
  await tick(5000)
  await clickText(w.get('[role=alertdialog]'), '释放')
  expect(calls('/api/active-actions/force-remove')).toHaveLength(1)
  expect(w.find('[role=alertdialog]').exists()).toBe(false)
})
const endpoint = '/api/nodes/{node}/status'
const captureEntries = [
  { endpoint, path: 'capture', conditional: 'getNodeStatus: len(GetCapture) > 0' },
  { endpoint, path: 'capture[].interface' }, { endpoint, path: 'capture[].upstream_sample_rate' },
]
it('r1 A1 W34 conditional array absent on real sample covers parent and both descendants', async () => {
  const report = await checkContract(captureEntries, async () => ({ id: 'fresh-node' }), { node: 'fresh-node' })
  expect(report.passed).toBe(true)
  expect(report.results.map((entry: any) => [entry.state, entry.conditionalAbsent])).toEqual([
    ['hit-absent', true], ['hit-absent', true], ['hit-absent', true],
  ])
})
it('r1 A1 present conditional array continues to reject a misspelled child', async () => {
  const report = await checkContract(captureEntries, async () => ({
    capture: [{ interfac: 'eth1', upstream_sample_rate: 300 }],
  }), { node: 'fresh-node' })
  expect(report.passed).toBe(false)
  expect(report.results.map((entry: any) => [entry.state, entry.conditionalAbsent])).toEqual([
    ['hit', false], ['missing', false], ['hit', false],
  ])
})
it('r1 A1 strict mock rejects absent conditional array with the named reason on all paths', async () => {
  const report = await checkContract(captureEntries, async () => ({}), { node: 'fresh-node', mock: true })
  expect(report.passed).toBe(false)
  expect(report.results.map((entry: any) => entry.detail)).toEqual([
    'mock conditional-absent is forbidden', 'mock conditional-absent is forbidden',
    'mock conditional-absent is forbidden',
  ])
})
it('r1 A2 W35 shared confirmation takes priority over delayed withdrawal for 3 attached attacks', () => {
  const row = { prefix: '192.0.2.0/24', status: 'delayed', attached_attacks: [
    { attack_id: 1 }, { attack_id: 2, detached_at: null }, { attack_id: 3 },
    { attack_id: 4, detached_at: '2026-10-28T11:00:00Z' },
  ] }
  expect(bgpConfirmation(row, i18n.global.t as any)).toEqual({ title: '强制撤回 192.0.2.0/24？',
    description: '这条宣告还挂着 3 个攻击，会一起解除关联并撤回。' })
})
it('r1 A3 W36 updated timestamp advances only on a fully successful round', async () => {
  clock(); vi.setSystemTime(new Date('2026-10-28T12:00:00'))
  const { w, intercept } = await mountQD()
  const timestamp = () => w.get('.page-head > .sub').text()
  expect(timestamp()).toBe('更新于 12:00:00')
  intercept(path => path === '/api/active-actions/xdrop' ? response(503, { error: 'rules unavailable' }) : undefined)
  await tick(5000)
  expect(timestamp()).toBe('更新于 12:00:00')
  intercept(); await tick(5000)
  expect(timestamp()).toBe('更新于 12:00:10')
})
it('r1 A4 W37 connector fetch failure clears cached disabled state and name without alert', async () => {
  clock()
  const { w, intercept } = await mountQD('/mitigations', 'qd', (path, _init, reply) =>
    path === '/api/active-actions/xdrop' ? response(200, reply.body.map((entry: any) =>
      entry.connector_id === 2 ? { ...entry, connector_name: '' } : entry)) : undefined)
  const entry = () => w.findAll('[data-testid=xdrop] tr.link')[3]!
  expect(entry().get('button').attributes('disabled')).toBeDefined()
  expect(entry().findAll('td')[4]!.text()).toContain('Disabled XDrop')
  expect(entry().get('.pill').text()).toBe('已停用')
  intercept((path, _init, reply) => path === '/api/settings/xdrop-connectors'
    ? response(503, { error: 'connector table unavailable' }) : path === '/api/active-actions/xdrop'
      ? response(200, reply.body.map((item: any) => item.connector_id === 2 ? { ...item, connector_name: '' } : item))
      : undefined)
  await tick(5000)
  expect(entry().get('button').attributes('disabled')).toBeUndefined()
  expect(entry().find('.pill').exists()).toBe(false)
  expect(entry().findAll('td')[4]!.text()).toBe('#2')
  expect(w.findAll('[role=alert]')).toHaveLength(0)
})
it('r1 A5 W38 delete note is the exact sealed Chinese sentence', () => {
  expect(zh.nodes.deleteNote).toBe('删除后，该节点需要重新添加才能接入；它的 Flow 监听器和来源会一并删除，已入库的流量数据保留。')
})
it('r1 A5 delete note is the exact sealed English sentence', () => {
  expect(en.nodes.deleteNote).toBe('After deletion the node must be added again before it can connect; '
    + 'its Flow listeners and sources are deleted too. Stored traffic data is kept.')
})
it.each(['active', 'delayed'])('r1 A6 status %s owns its 4px duration spacing', status => {
  const w = render(Status, { props: { row: { status, created_at: '2026-10-28T12:00:00Z',
    scheduled_for: '2026-10-28T12:02:00Z' }, kind: 'bgp', now: Date.parse('2026-10-28T12:01:00Z') },
  attachTo: document.body })
  const { descriptor } = parse(sourceText('src/views/mitigations/Status.vue'))
  const element = w.get('small').element as HTMLElement
  const scope = [...element.attributes].find(attr => attr.name.startsWith('data-v-'))?.name || 'data-v-r1-status'
  const style = document.createElement('style')
  style.textContent = compileStyle({ source: descriptor.styles.map(s => s.content).join('\n'),
    id: scope, scoped: true, filename: 'Status.vue' }).code
  document.head.append(style)
  try { expect(getComputedStyle(element).marginLeft).toBe('4px') } finally { style.remove() }
})
it('r1 A6 timeline visibly separates success from the duration marker', async () => {
  const { w } = await mountQD()
  await w.get('[data-testid=bgp] tr.link td').trigger('click'); await flushPromises()
  expect(dialog().querySelector('.tl li')!.textContent).toContain('成功 · 12 ms')
  await domClick('✕')
})
