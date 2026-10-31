import { expect, it, vi } from 'vitest'
import { flushPromises } from '@vue/test-utils'
import { mountQE, clickText, domClick, dialog, textInput, input, clock, tick, writes, body } from './qe-harness'
import { response } from './helpers'
import { notifications } from '../src/notifications'
import { kinds } from '../src/views/connectors/data'
import type { Kind } from '../src/views/connectors/data'
import * as client from '../src/api/client'
import { bgpRoutes, testConnector } from '../src/views/connectors/probe'
const calls = () => vi.mocked(fetch).mock.calls.map(([path]) => String(path))
const panel = (w: any, kind: Kind) => w.get(`[data-kind="${kind}"]`)
const first = (w: any, kind: Kind) => panel(w, kind).get('tr.cn-row')
const mount = (path = '/connectors', change?: any, admin = true, mode = 'qg') => mountQE(path, change, admin, mode)
async function add(w: any, kind: Kind) { await clickText(panel(w, kind), '＋添加') }
async function required(kind: Kind) {
  await textInput('名称', 'New connector')
  if (kind === 'xdrop') {
    await textInput('API 地址', 'https://xdrop.example.com/api/v1')
    await input('API 密钥', 'synthetic-key')
  }
  if (kind === 'webhook') await textInput('URL', 'https://hooks.example.net/notify')
  if (kind === 'shell') await textInput('命令', '/bin/true')
}
it('G-cn five parallel GETs, no polling at 60 seconds; counts and all column headings', async () => {
  clock()
  const { w } = await mount()
  expect(calls().sort()).toEqual(['/api/webhooks', ...kinds.map(k => `/api/settings/${k}-connectors`)].sort())
  await tick(60000)
  expect(calls()).toHaveLength(5)
  expect(w.get('.cn-page > .seg').text()).toBe('全部 8BGP 2XDrop 2Webhook 2Shell 2')
  const heads = {
    bgp: ['ID', '名称', 'BGP ASN', 'vtysh 路径', '状态', '操作'],
    xdrop: ['ID', '名称', 'API 地址', 'API 密钥', '超时（ms）', '状态', '操作'],
    webhook: ['ID', '名称', 'URL', '方法', '全局', '状态', '操作'],
    shell: ['ID', '名称', '命令', '默认参数', '状态', '操作'],
  }
  for (const kind of kinds) {
    const th = panel(w, kind).findAll('th').map((n: any) => n.element.childNodes[0]?.textContent?.trim())
    expect(th).toEqual(heads[kind])
    expect(panel(w, kind).findAll('tr.cn-disabled')).toHaveLength(1)
  }
  expect(panel(w, 'xdrop').text()).toContain('***abcd')
  expect(panel(w, 'xdrop').get('[role=note]').text()).toContain('igmp')
})
it('G-cn route selection /connectors/xdrop and segment push W22', async () => {
  const { w, router } = await mount('/connectors/xdrop')
  expect(w.findAll('.cn-panel').map(p => p.attributes('data-kind'))).toEqual(['xdrop'])
  await clickText(w.get('.cn-page > .seg'), 'Shell 2')
  expect(router.currentRoute.value.path).toBe('/connectors/shell')
  expect(w.findAll('.cn-panel').map(p => p.attributes('data-kind'))).toEqual(['shell'])
})
it('G-cn one class failure retains all other classes and retry W19', async () => {
  const { w, intercept } = await mount('/connectors', undefined, true, 'qg-fail')
  expect(panel(w, 'shell').get('[role=alert]').text()).toContain('shell list unavailable')
  expect(w.get('.cn-page > .seg').text()).toContain('Webhook 2Shell')
  expect(w.get('.cn-page > .seg').text()).not.toContain('Shell 2')
  for (const kind of ['bgp', 'xdrop', 'webhook'] as const) expect(panel(w, kind).findAll('.cn-row')).toHaveLength(2)
  intercept((path: string) => path === '/api/settings/shell-connectors' ? response(200, []) : undefined)
  await clickText(panel(w, 'shell'), '重试')
  expect(panel(w, 'shell').text()).toContain('暂无数据')
  expect(panel(w, 'shell').find('[role=alert]').exists()).toBe(false)
})
it('G-cn qg-empty null lists and legacy empty W20', async () => {
  const { w } = await mount('/connectors', undefined, true, 'qg-empty')
  expect(w.findAll('.cn-panel').every(p => p.text().includes('暂无数据'))).toBe(true)
  await clickText(w.get('.cn-legacy'), '展开')
  expect(w.get('.cn-legacy').text()).toContain('暂无数据')
  expect(w.findAll('tr.cn-row')).toHaveLength(0)
})
it('G-cn legacy collapsed initially, read-only, event pills, raw error and retry W21', async () => {
  const { w, intercept } = await mount('/connectors/webhook')
  const legacy = w.get('.cn-legacy')
  expect(legacy.find('table').exists()).toBe(false)
  expect(legacy.get('button').attributes('aria-expanded')).toBe('false')
  await clickText(legacy, '展开')
  expect(legacy.get('[role=note]').text()).toContain('推送不再读取这些条目。')
  expect(legacy.findAll('tbody .pill').map(p => p.text())).toEqual([
    'attack_start', 'attack_update', 'attack_end', '已启用', 'attack_start', 'attack_end', '已停用',
  ])
  expect(legacy.findAll('button')).toHaveLength(1)
  expect(legacy.text()).not.toMatch(/Authorization|Headers|添加|测试|删除旧/)
  intercept(() => undefined)
})
it('G-cn legacy load failure stays local and retry requests only legacy', async () => {
  const { w } = await mount('/connectors', undefined, true, 'qg-legacy-fail')
  await clickText(w.get('.cn-legacy'), '展开')
  expect(w.get('.cn-legacy [role=alert]').text()).toContain('legacy webhook list unavailable')
  const before = calls().length
  await clickText(w.get('.cn-legacy'), '重试')
  expect(calls().slice(before)).toEqual(['/api/webhooks'])
  expect(w.findAll('tr.cn-row')).toHaveLength(8)
})
it.each(kinds)('G-cn %s preselected new type, enabled policy, preserve name on switch W28', async kind => {
  const { w } = await mount()
  await add(w, kind)
  expect(dialog().querySelector('[aria-pressed=true]')?.textContent?.trim()).toBe(
    ({ bgp: 'BGP', xdrop: 'XDrop', webhook: 'Webhook', shell: 'Shell' })[kind])
  const enabled = [...dialog().querySelectorAll('[role=switch]')].filter(e => e.getAttribute('aria-label') === '已启用')
  expect(enabled.length).toBe(kind === 'bgp' ? 1 : 0)
  if (kind !== 'bgp') expect(dialog().textContent).toContain('新建后默认启用，可在编辑里停用')
  await textInput('名称', 'Keep me')
  await domClick(kind === 'bgp' ? 'Shell' : 'BGP')
  expect((dialog().querySelector('input') as HTMLInputElement).value).toBe('Keep me')
  expect(dialog().textContent).not.toContain('pass_stdin')
  expect(dialog().textContent).not.toContain('address_family')
})
it.each(kinds)('G-cn %s edit fills row without a detail GET and saves exact class reload W23', async kind => {
  const { w } = await mount()
  const before = calls().length
  await first(w, kind).trigger('click')
  expect(calls()).toHaveLength(before)
  expect(dialog().textContent).toContain('编辑连接器')
  expect(dialog().querySelectorAll('[role=group]')).toHaveLength(0)
  await textInput('名称', 'Renamed')
  await domClick('保存')
  expect(document.querySelector('[role=dialog]')).toBeNull()
  expect(calls().slice(before)).toEqual([`/api/settings/${kind}-connectors/1`, `/api/settings/${kind}-connectors`])
  expect(body().name).toBe('Renamed')
  expect(notifications.at(-1)?.message).toBe('已更新')
})
it('G-cn XDrop changed URL warns and blocks save without key W2', async () => {
  const { w } = await mount('/connectors/xdrop')
  await first(w, 'xdrop').trigger('click')
  expect(dialog().querySelector('[data-key-hint]')?.textContent).toContain('当前密钥 ***abcd。')
  await textInput('API 地址', 'http://192.0.2.10/api/v1')
  expect(dialog().querySelector('[data-key-hint]')?.classList.contains('warn')).toBe(true)
  await domClick('保存')
  expect(writes()).toHaveLength(0)
  expect(dialog().querySelector('[role=alert]')?.textContent).toBe('已改 API 地址，必须重新填写密钥。')
  await input('API 密钥', 'new-key')
  await domClick('保存')
  expect(body().api_key).toBe('new-key')
})
it('G-cn Webhook masked JSON refill and blank clear W6', async () => {
  const { w } = await mount('/connectors/webhook')
  await first(w, 'webhook').trigger('click')
  expect(dialog().querySelector('textarea')?.value).toBe('{\n  "Authorization": "******"\n}')
  expect(dialog().textContent).toContain('清空整个框 = 删除全部 Header。')
  await textInput('Headers', '')
  await domClick('保存')
  expect(body().headers).toEqual({})
})
it.each(['xdrop', 'webhook', 'shell'] as const)(
  'G-cn %s XNumber blur rounds and clamps decimals/zero/upper bound W9', async kind => {
    const { w } = await mount()
    for (const [typed, want] of [['1.5', 2], ['0', 1], ['99999', kind === 'webhook' ? 10000 : 30000]] as const) {
      await first(w, kind).trigger('click')
      await input('超时（ms）', typed)
      await domClick('保存')
      expect(body().timeout_ms).toBe(want)
    }
  },
)
it.each(kinds)('G-cn %s create closes and only reloads that list', async kind => {
  const { w } = await mount()
  await add(w, kind)
  await required(kind)
  const before = calls().length
  await domClick('保存')
  expect(document.querySelector('[role=dialog]')).toBeNull()
  expect(calls().slice(before)).toEqual([`/api/settings/${kind}-connectors`, `/api/settings/${kind}-connectors`])
  expect(notifications.at(-1)?.message).toBe('已创建')
  expect(panel(w, kind).text()).toContain('New connector')
})
it.each(kinds)('G-cn %s save 400 preserves form with crit original and notification', async kind => {
  const { w } = await mount('/connectors', (path: string, init: RequestInit) =>
    init.method === 'POST' ? response(400, { error: 'write rejected original' }) : undefined)
  await add(w, kind)
  await required(kind)
  await domClick('保存')
  expect(dialog().querySelector('[role=alert]')?.textContent).toBe('write rejected original')
  expect(dialog().querySelector('[role=alert]')?.classList.contains('crit')).toBe(true)
  expect((dialog().querySelector('input') as HTMLInputElement).value).toBe('New connector')
  expect(notifications.at(-1)).toMatchObject({ tone: 'crit', message: 'write rejected original' })
})
it.each([
  [409, 'connector in use by 2 action(s)', '仍有响应动作在用这个连接器，相关记录在响应页。'],
  [409, 'xDrop connector still has active rules', '仍有生效中的规则或宣告，相关记录在缓解页。'],
  [409, 'connector still has 2 announcements in FRR-relevant states', '仍有生效中的规则或宣告，相关记录在缓解页。'],
  [409, 'other conflict', ''], [500, 'delete rejected', ''],
] as const)('G-cn delete %s %s retains confirm and raw text W17', async (status, error, hint) => {
  const { w } = await mount('/connectors/bgp', (_: string, init: RequestInit) =>
    init.method === 'DELETE' ? response(status, { error }) : undefined)
  await clickText(first(w, 'bgp'), '删除')
  await clickText(w.get('[role=alertdialog]'), '删除')
  const confirm = w.get('[role=alertdialog]')
  expect(confirm.text()).toContain(status === 409 ? '不能删除「Edge BGP」。' : '删除失败')
  expect(confirm.text()).toContain(hint)
  expect(confirm.get('[role=alert]').text()).toBe(error)
  expect(notifications.at(-1)?.message).toBe(error)
})
it.each(kinds)('G-cn %s delete new row notifies and reloads only class', async kind => {
  const { w } = await mount()
  await add(w, kind)
  await required(kind)
  await domClick('保存')
  const row = panel(w, kind).get('[data-row="3"]')
  await clickText(row, '删除')
  const before = calls().length
  await clickText(w.get('[role=alertdialog]'), '删除')
  expect(panel(w, kind).find('[data-row="3"]').exists()).toBe(false)
  expect(w.find('[role=alertdialog]').exists()).toBe(false)
  expect(calls().slice(before)).toEqual([`/api/settings/${kind}-connectors/3`, `/api/settings/${kind}-connectors`])
  expect(notifications.at(-1)?.message).toBe('已删除')
})
it.each(['bgp', 'xdrop', 'webhook'] as const)(
  'G-cn %s testing pending disables button and success inline', async kind => {
  let resolve!: (value: Response) => void
  const { w } = await mount('/connectors', (_: string, init: RequestInit, result: any) =>
    init.method === 'POST' ? new Promise<Response>(r => { resolve = r }) : undefined)
  await clickText(first(w, kind), '测试')
  expect(panel(w, kind).get('button:disabled').text()).toBe('测试中…')
  resolve(response(200, kind === 'bgp' ? { ok: true, output: 'BGP mock output' }
    : kind === 'xdrop' ? { success: true, name: 'fixture-machine' } : { success: true, status_code: 204 }))
  await flushPromises()
  expect(panel(w, kind).get('.cn-result').text()).toContain({ bgp: 'BGP 连接正常',
    xdrop: '连接成功，凭证：fixture-machine', webhook: 'Webhook 测试成功（HTTP 204）' }[kind])
  expect(notifications).toHaveLength(0)
  await clickText(panel(w, kind).get('.cn-result'), '✕')
  expect(panel(w, kind).find('.cn-result').exists()).toBe(false)
})
it.each(['bgp', 'xdrop', 'webhook'] as const)('G-cn %s fixture failure original inline W15', async kind => {
  const { w } = await mount('/connectors', undefined, true, 'qg-test-fail')
  await clickText(first(w, kind), '测试')
  expect(panel(w, kind).get('.cn-result').text()).toContain({ bgp: 'vtysh failed: mock unavailable',
    xdrop: 'health check failed: mock unavailable', webhook: 'HTTP 503' }[kind])
  expect(notifications).toHaveLength(0)
})
it('G-cn probe exports exact paths and explicit request timeout 45000 W13', async () => {
  const spy = vi.spyOn(client, 'request').mockResolvedValue({ output: '' })
  for (const kind of ['bgp', 'xdrop', 'webhook'] as const) await testConnector(kind, 7)
  await bgpRoutes(7)
  expect(spy.mock.calls).toEqual([
    ['/api/settings/bgp-connectors/7/test', { method: 'POST', timeout: 45000 }],
    ['/api/settings/xdrop-connectors/7/test', { method: 'POST', timeout: 45000 }],
    ['/api/settings/webhook-connectors/7/test', { method: 'POST', timeout: 45000 }],
    ['/api/settings/bgp-connectors/7/routes', { timeout: 45000 }],
  ])
})
it('G-cn routes success drawer, then failure clears old bar and stays closed', async () => {
  const { w, intercept } = await mount('/connectors/bgp')
  await clickText(first(w, 'bgp'), '路由表')
  expect(dialog().textContent).toContain('BGP 路由表 · Edge BGP')
  expect(dialog().querySelector('pre')?.textContent).toContain('192.0.2.0/24')
  expect(dialog().textContent).toContain('show ip bgp ipv6 unicast')
  await domClick('✕')
  intercept((path: string) => path.endsWith('/routes') ? response(502, { error: 'routes failed original' }) : undefined)
  await clickText(first(w, 'bgp'), '路由表')
  expect(document.querySelector('[role=dialog]')).toBeNull()
  expect(w.get('.cn-route-error').text()).toContain('获取路由表失败')
  expect(w.get('.cn-route-error').text()).toContain('routes failed original')
  intercept((path: string) => path.endsWith('/routes') ? response(200, { output: '' }) : undefined)
  await clickText(first(w, 'bgp'), '路由表')
  expect(w.find('.cn-route-error').exists()).toBe(false)
  expect(dialog().querySelector('pre')?.textContent).toBe('暂无数据')
})
it.each(kinds)('G-cn viewer %s no write/test, disabled view form and BGP routes allowed W18', async kind => {
  const { w } = await mount('/connectors', undefined, false)
  expect(w.findAll('button').some(b => ['＋添加', '测试', '删除'].includes(b.text()))).toBe(false)
  await first(w, kind).trigger('click')
  expect(dialog().textContent).toContain('查看连接器')
  expect([...dialog().querySelectorAll<HTMLInputElement>('input,textarea,[role=switch],[role=combobox]')]
    .every(e => e.disabled)).toBe(true)
  expect([...dialog().querySelectorAll('button')].some(b => b.textContent?.trim() === '保存')).toBe(false)
  await domClick('✕')
  if (kind === 'bgp') {
    await clickText(first(w, kind), '路由表')
    expect(dialog().textContent).toContain('BGP 路由表')
  }
})
it.each([true, false])('G-cn save pending all disabled, leaving page retains result %s W29', async success => {
  let resolve!: (value: Response) => void
  const { w, router } = await mount('/connectors/bgp', (_: string, init: RequestInit) =>
    init.method === 'PUT' ? new Promise<Response>(r => { resolve = r }) : undefined)
  await first(w, 'bgp').trigger('click')
  await domClick('保存')
  expect(dialog().getAttribute('aria-busy')).toBe('true')
  expect([...dialog().querySelectorAll<HTMLInputElement>('input,textarea,button')].every(e => e.disabled)).toBe(true)
  await router.push('/flow')
  await flushPromises()
  resolve(response(success ? 200 : 400, success ? { ok: true } : { error: 'late failure original' }))
  await flushPromises()
  expect(notifications.at(-1)?.message).toBe(success ? '已更新' : 'late failure original')
  expect(w.text()).toContain(success ? '已更新' : 'late failure original')
})

it('G-cn visible global and enabled labels identify working Webhook switches W31', async () => {
  const { w } = await mount('/connectors/webhook')
  await first(w, 'webhook').trigger('click')
  for (const [text, before, after] of [['全局', 'false', 'true'], ['已启用', 'true', 'false']]) {
    const label = [...dialog().querySelectorAll('label.field')]
      .find(e => e.querySelector('span')?.childNodes[0]?.textContent?.trim() === text)
    expect(label, `visible label ${text}`).toBeDefined()
    const span = label!.querySelector('span')!
    expect(span.closest('[hidden],[aria-hidden=true]')).toBeNull()
    expect(getComputedStyle(span).display).not.toBe('none')
    expect(getComputedStyle(span).visibility).not.toBe('hidden')
    const control = label!.querySelector<HTMLButtonElement>('[role=switch]')!
    expect(control.getAttribute('aria-checked')).toBe(before)
    control.click()
    await flushPromises()
    expect(control.getAttribute('aria-checked')).toBe(after)
  }
  await domClick('保存')
  expect(body()).toMatchObject({ global: true, enabled: false })
})
it('G-cn Webhook transport fixture uses Go safe error wording A3', async () => {
  const { w } = await mount('/connectors/webhook', undefined, true, 'qg-test-fail')
  await clickText(panel(w, 'webhook').findAll('.cn-row')[1], '测试')
  expect(w.get('.cn-result').text()).toContain('connection refused')
})

it.each([
  ['全局', 'false', 'true', { global: true, enabled: true }],
  ['已启用', 'true', 'false', { global: false, enabled: false }],
] as const)('G-cn clicking visible %s label changes saved body W31 supplement', async (text, before, after, saved) => {
  const { w } = await mount('/connectors/webhook')
  await first(w, 'webhook').trigger('click')
  const label = [...dialog().querySelectorAll<HTMLLabelElement>('label.field')]
    .find(e => e.querySelector('span')?.childNodes[0]?.textContent?.trim() === text)!
  const span = label.querySelector('span')!
  const control = label.querySelector<HTMLButtonElement>('[role=switch]')!
  expect(control.id).not.toBe('')
  expect(document.querySelectorAll(`[id="${control.id}"]`)).toHaveLength(1)
  expect(control.getAttribute('aria-checked')).toBe(before)
  span.click()
  await flushPromises()
  expect.soft(control.getAttribute('aria-checked')).toBe(after)
  expect.soft(label.htmlFor).toBe(control.id)
  expect.soft(label.control).toBe(control)
  await domClick('保存')
  expect(body()).toMatchObject(saved)
})
