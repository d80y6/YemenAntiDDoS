import { it, expect, vi } from 'vitest'
import { flushPromises } from '@vue/test-utils'
import { mountQD, calls, clock, tick, params, clickText, dialog, domClick } from './qd-harness'
import { response, deferred } from './helpers'
import { state } from '../src/state'
import { notifications } from '../src/notifications'
const block = (w: any, id: string) => w.get('[data-testid=' + id + ']')
const row = (w: any, id: string, n: number) => block(w, id).findAll('tbody > tr')[n]
it('W5 W12 W27 four GETs per 5s, dismissed count while collapsed, local clock, unmount zero', async () => {
  clock()
  const { w } = await mountQD()
  expect(vi.mocked(fetch)).toHaveBeenCalledTimes(4)
  expect(w.text()).toContain('发现 2 条孤立 BGP 路由')
  expect(w.text()).toContain('BGP 宣告'); expect(w.text()).toContain('XDrop 规则')
  expect(w.text()).toContain('已忽略的孤立路由 2')
  expect(block(w, 'bgp').text()).toContain('2:05')
  await tick(1000); expect(block(w, 'bgp').text()).toContain('2:04')
  await tick(4000); expect(vi.mocked(fetch)).toHaveBeenCalledTimes(8)
  expect(calls('/api/settings/xdrop-connectors')).toHaveLength(2)
  w.unmount(); const count = vi.mocked(fetch).mock.calls.length
  await tick(30000); expect(vi.mocked(fetch)).toHaveBeenCalledTimes(count)
})
it('W29 datasets fail independently keep rows and clear errors; first error retries', async () => {
  clock()
  const { w, intercept } = await mountQD()
  intercept(p => p === '/api/active-actions/xdrop' ? response(503, { error: 'xdrop 503 raw' }) : undefined)
  await tick(5000)
  expect(block(w, 'xdrop').get('[role=alert]').text()).toContain('xdrop 503 raw')
  expect(block(w, 'xdrop').text()).toContain('shared-rule')
  expect(block(w, 'bgp').find('[role=alert]').exists()).toBe(false)
  intercept(); await tick(5000)
  expect(block(w, 'xdrop').find('[role=alert]').exists()).toBe(false)
  w.unmount()
  const first = await mountQD('/mitigations', 'qd', p => p === '/api/active-actions/bgp'
    ? response(503, { error: 'bgp first raw' }) : undefined)
  expect(block(first.w, 'bgp').get('[role=alert]').text()).toContain('bgp first raw')
  expect(block(first.w, 'bgp').findAll('button').some((b: any) => b.text() === '重试')).toBe(true)
})
it('W17 null datasets show empty states, no orphan; dismissed [] empty', async () => {
  const { w } = await mountQD('/mitigations', 'null')
  expect(w.find('[data-testid=orphans]').exists()).toBe(false)
  expect(block(w, 'bgp').text()).toContain('暂无数据'); expect(block(w, 'xdrop').text()).toContain('暂无数据')
  await clickText(w, '已忽略的孤立路由 0 ▾')
  expect(w.text()).toContain('无已忽略的孤立路由')
})
it('W1 W2 W4 BGP all states force entry, exact shared count and four body keys; failed no tooltip', async () => {
  clock(); const { w } = await mountQD()
  const list = block(w, 'bgp').findAll('tbody > tr')
  expect(list).toHaveLength(6)
  list.forEach((r: any) => expect(r.find('button').text()).toBe('强制撤回'))
  expect(list[0].findAll('a')).toHaveLength(3)
  expect(list[0].text()).toContain('+2 已脱离'); expect(block(w, 'bgp').text()).not.toContain('已结束')
  expect(list[0].text()).toContain('10m')
  expect(list[4].find('.dot').attributes('title')).toBeUndefined()
  await list[0].find('button').trigger('click'); await flushPromises()
  expect(w.get('[role=alertdialog]').text()).toContain('这条宣告还挂着 3 个攻击')
  await clickText(w.get('[role=alertdialog]'), '撤回')
  const c = calls('/api/active-actions/force-remove')[0]!
  expect(JSON.parse(String(c[1]?.body))).toEqual({ attack_id: 1, action_id: 5, connector_id: 1,
    external_rule_id: '192.0.2.16/28|defense' })
  expect(notifications.at(-1)).toMatchObject({ message: '已强制移除', tone: 'ok' })
})
it.each(['withdraw', 'dismiss', 'undismiss'])('W3 orphan %s exact URL body and immediate refresh', async op => {
  const { w } = await mountQD()
  if (op === 'undismiss') await clickText(w, '已忽略的孤立路由 2 ▾')
  const source = op === 'undismiss' ? block(w, 'bgp') : block(w, 'orphans')
  await clickText(source, op === 'withdraw' ? '强制撤回' : op === 'dismiss' ? '忽略' : '重新提示')
  await clickText(w.get('[role=alertdialog]'), op === 'withdraw' ? '撤回' : op === 'dismiss' ? '忽略' : '重新提示')
  const path = '/api/active-actions/bgp/orphan-' + (op === 'withdraw' ? 'force-withdraw' : op)
  expect(calls(path)).toHaveLength(1)
  expect(JSON.parse(String(calls(path)[0]![1]?.body))).toEqual({ announcement_id: op === 'undismiss' ? 20 : 8 })
  expect(calls('/api/active-actions/bgp')).toHaveLength(2)
})
it('dismissed six columns methods and detected_at', async () => {
  const { w } = await mountQD(); await clickText(w, '已忽略的孤立路由 2 ▾')
  expect(block(w, 'bgp').findAll('table')[1].findAll('th')).toHaveLength(6)
  expect(w.text()).toContain('升级时自动忽略'); expect(w.text()).toContain('手动忽略')
  expect(block(w, 'bgp').findAll('table')[1].find('tbody tr').text()).toMatch(/\d\d-\d\d \d\d:\d\d/)
})
it('W11 W12 disabled connector refresh re-enables; synthetic labels and specialized closeout', async () => {
  clock(); const { w, intercept } = await mountQD()
  const disabled = row(w, 'xdrop', 3).get('button')
  expect(disabled.attributes('disabled')).toBeDefined()
  expect(disabled.attributes('title')).toBe('连接器已停用，强制解除会被拒绝')
  intercept((p, _i, r) => p === '/api/settings/xdrop-connectors'
    ? response(200, r.body.map((c: any) => ({ ...c, enabled: true }))) : undefined)
  await tick(5000); expect(row(w, 'xdrop', 3).get('button').attributes('disabled')).toBeUndefined()
  expect(row(w, 'xdrop', 2).text()).toContain('— 创建失败')
  expect(row(w, 'xdrop', 2).text()).not.toContain('failed-create-5')
  expect(row(w, 'xdrop', 0).text()).toContain('共用')
  expect(row(w, 'xdrop', 2).findAll('td')[3].text()).toBe('—')
  await row(w, 'xdrop', 2).get('button').trigger('click'); await flushPromises()
  expect(w.get('[role=alertdialog]').text()).toContain('收尾这条创建失败的记录？')
  await clickText(w.get('[role=alertdialog]'), '收尾')
  expect(notifications.at(-1)).toMatchObject({ message: '已收尾创建失败的记录', tone: 'ok' })
})
it('W15 drawer follows latest status, retains missing row, attack link closes and navigates', async () => {
  clock(); const { w, router, intercept } = await mountQD()
  await row(w, 'bgp', 0).trigger('click'); await flushPromises()
  expect(dialog().textContent).toContain('挂载中'); expect(dialog().textContent).toContain('已脱离')
  expect(dialog().querySelectorAll('button').length).toBe(2)
  intercept((p, _i, r) => p === '/api/active-actions/bgp' ? response(200,
    r.body.map((a: any) => ({ ...a, status: 'delayed', scheduled_for: '2026-10-28T12:02:05Z' }))) : undefined)
  await tick(5000); expect(dialog().querySelectorAll('.kv > dd')[3]?.textContent).toContain('延迟撤回')
  intercept(p => p === '/api/active-actions/bgp' ? response(200, []) : undefined)
  await tick(5000); expect(dialog().textContent).toContain('已不在活跃列表')
  expect(dialog().textContent).toContain('192.0.2.16/28')
  ;(dialog().querySelector('a') as HTMLElement).click(); await flushPromises()
  expect(router.currentRoute.value.path).toBe('/attacks/1'); expect(document.querySelector('[role=dialog]')).toBeNull()
})
it('W5 W10 delivery once across six polls, refresh and timeline four parameters filtering red error', async () => {
  clock(); const { w } = await mountQD()
  await row(w, 'xdrop', 0).trigger('click'); await flushPromises()
  expect(calls('/api/active-actions/xdrop/delivery')).toHaveLength(1)
  const q = params(calls('/api/active-actions/timeline')[0])
  expect(Object.fromEntries(q)).toEqual({ attack_id: '1', action_id: '11', connector_id: '1',
    external_rule_id: 'shared-rule' })
  expect(dialog().textContent).not.toContain('OTHER ACTION')
  expect(dialog().querySelector('.tl .crit')?.textContent).toBe('失败')
  expect(dialog().querySelector('.tl .mono.crit')?.textContent?.trim()).toBe('upstream busy')
  expect(dialog().querySelector('[title="E_TABLE_FULL · rule table full"]')).not.toBeNull()
  await tick(30000); expect(calls('/api/active-actions/xdrop/delivery')).toHaveLength(1)
  await domClick('刷新'); expect(calls('/api/active-actions/xdrop/delivery')).toHaveLength(2)
})
it.each([
  ['qd-notfound', 'XDrop 上不存在'], ['qd-unavailable', '连接器不可用'], ['qd-delivery-empty', '无节点'],
  ['qd-delivery-null', '无节点'], ['qd-delivery-bad', '查询失败'], ['qd-delivery-error', 'HTTP 409 epoch mismatch'],
  ['qd', '已确认'],
])('W7 delivery branch %s', async (mode, expected) => {
  const { w } = await mountQD('/mitigations', mode)
  await row(w, 'xdrop', 0).trigger('click'); await flushPromises()
  expect(dialog().textContent).toContain(expected)
  expect(calls('/api/active-actions/xdrop/delivery')[0]![1]?.signal).toBeDefined()
})
it('W8 delivery timeout recognized', async () => {
  clock(); const { w } = await mountQD('/mitigations', 'qd', (p, init) => p.includes('/delivery?')
    ? new Promise((_resolve, reject) => init.signal?.addEventListener('abort', () => reject(new DOMException('',
      'AbortError')))) : undefined)
  await row(w, 'xdrop', 0).trigger('click'); await flushPromises(); await tick(30000)
  expect(dialog().textContent).toContain('查询超时')
})
it('W6 stale refresh cannot finish a reopened same-rule refresh even when abort ignored', async () => {
  clock(); const { w, intercept } = await mountQD()
  await row(w, 'xdrop', 0).trigger('click'); await flushPromises()
  const old = deferred<Response>(), fresh = deferred<Response>()
  intercept(p => p.includes('/delivery?') ? old.promise : undefined)
  await domClick('刷新'); await domClick('✕')
  intercept(); await row(w, 'xdrop', 0).trigger('click'); await flushPromises()
  intercept(p => p.includes('/delivery?') ? fresh.promise : undefined)
  await domClick('刷新')
  old.resolve(response(200, { nodes: [{ name: 'OLD', state: 'confirmed' }] })); await flushPromises()
  expect(dialog().textContent).toContain('加载中…'); expect(dialog().textContent).not.toContain('OLD')
  fresh.resolve(response(200, { nodes: [{ name: 'NEW', state: 'confirmed' }] })); await flushPromises()
  expect(dialog().textContent).toContain('NEW'); expect(dialog().textContent).not.toContain('加载中…')
})
it('W9 synthetic zero delivery; attack zero zero timeline, null logs and errors', async () => {
  const { w, intercept } = await mountQD()
  await row(w, 'xdrop', 2).trigger('click'); await flushPromises()
  expect(calls('/api/active-actions/xdrop/delivery')).toHaveLength(0)
  expect(dialog().textContent).toContain('不查询下发状态')
  expect(dialog().textContent).not.toContain('failed-create-5')
  await domClick('✕'); const count = calls('/api/active-actions/timeline').length
  await row(w, 'bgp', 4).trigger('click'); await flushPromises()
  expect(calls('/api/active-actions/timeline')).toHaveLength(count)
  expect(dialog().textContent).toContain('暂无执行日志')
  await domClick('✕'); intercept(p => p.includes('/timeline?') ? response(200, { logs: null }) : undefined)
  await row(w, 'bgp', 0).trigger('click'); await flushPromises()
  expect(dialog().textContent).toContain('暂无执行日志')
  await domClick('✕'); intercept(p => p.includes('/timeline?') ? response(503, { error: 'timeline raw' }) : undefined)
  await row(w, 'bgp', 0).trigger('click'); await flushPromises()
  expect(dialog().textContent).toContain('timeline raw')
})
it('W16 viewer hides every write entrance, drawer and delivery refresh remain', async () => {
  const { w } = await mountQD('/mitigations', 'qd', undefined, false)
  expect(w.findAll('button').map(b => b.text())).not.toEqual(expect.arrayContaining(['强制撤回']))
  expect(block(w, 'orphans').findAll('button')).toHaveLength(0)
  expect(block(w, 'bgp').findAll('tbody button')).toHaveLength(0)
  expect(block(w, 'xdrop').findAll('tbody button')).toHaveLength(0)
  await clickText(w, '已忽略的孤立路由 2 ▾')
  expect(block(w, 'bgp').findAll('tbody button')).toHaveLength(0)
  await row(w, 'xdrop', 0).trigger('click'); await flushPromises()
  await domClick('刷新'); expect(calls('/api/active-actions/xdrop/delivery')).toHaveLength(2)
})
it('W23 English legacy labels visible', async () => {
  state.locale = 'en'
  const { w } = await mountQD(); await clickText(w, 'View dismissed orphans (2) ▾')
  for (const label of ['Active Mitigations', 'BGP Routing', 'Force Withdraw', 'orphan', 'dismissed orphans',
    'Dismissed on upgrade', 'Un-dismiss']) expect(w.text()).toContain(label)
})
const operations = ['withdraw', 'dismiss', 'undismiss', 'bgp', 'xdrop']
for (const op of operations) for (const outcome of ['success', 'error', ...(['withdraw', 'bgp', 'xdrop'].includes(op)
  ? ['warning'] : [])]) it('W28 ' + op + ' route-unmounted ' + outcome + ' global notification', async () => {
  const pending = deferred<Response>()
  const { w, router } = await mountQD('/mitigations', 'qd', (_p, init) => init.method === 'POST'
    ? pending.promise : undefined)
  if (op === 'undismiss') await clickText(w, '已忽略的孤立路由 2 ▾')
  if (op === 'bgp' || op === 'xdrop') await row(w, op, 0).find('button').trigger('click')
  else await clickText(block(w, op === 'undismiss' ? 'bgp' : 'orphans'), op === 'withdraw' ? '强制撤回'
    : op === 'dismiss' ? '忽略' : '重新提示')
  await flushPromises()
  await clickText(w.get('[role=alertdialog]'), op === 'xdrop' ? '释放'
    : op === 'withdraw' || op === 'bgp' ? '撤回' : op === 'dismiss' ? '忽略' : '重新提示')
  await router.push('/other'); await flushPromises(); expect(w.find('[data-testid=bgp]').exists()).toBe(false)
  pending.resolve(response(outcome === 'error' ? 500 : 200, outcome === 'error' ? { error: 'raw failed' }
    : outcome === 'warning' ? { warning: 'exact backend warning' } : { ok: true }))
  await flushPromises()
  expect(notifications.at(-1)?.tone).toBe(outcome === 'error' ? 'crit' : outcome === 'warning' ? 'warn' : 'ok')
  if (outcome !== 'success') expect(notifications.at(-1)?.message)
    .toBe(outcome === 'error' ? 'raw failed' : 'exact backend warning')
})
it.each(['bgp', 'withdraw', 'xdrop'])('failure %s keeps confirmation and raw error', async op => {
  const { w } = await mountQD('/mitigations', 'qd', (_p, init) => init.method === 'POST'
    ? response(op === 'withdraw' ? 400 : 500, { error: 'raw failure' }) : undefined)
  if (op === 'withdraw') await clickText(block(w, 'orphans'), '强制撤回')
  else await row(w, op, 0).get('button').trigger('click')
  await flushPromises(); await clickText(w.get('[role=alertdialog]'), op === 'xdrop' ? '释放' : '撤回')
  expect(w.get('[role=alertdialog]').text()).toContain('raw failure')
  expect(notifications.at(-1)).toMatchObject({ tone: 'crit', message: 'raw failure' })
})
it('W8 W14 XDrop force timeout is warn and keeps confirm', async () => {
  clock(); const { w } = await mountQD('/mitigations', 'qd', (_p, init) => init.method === 'POST'
    ? new Promise((_resolve, reject) => init.signal?.addEventListener('abort', () => reject(new DOMException('',
      'AbortError')))) : undefined)
  await row(w, 'xdrop', 0).get('button').trigger('click'); await flushPromises()
  await clickText(w.get('[role=alertdialog]'), '释放'); await tick(30000)
  expect(notifications.at(-1)).toMatchObject({ tone: 'warn', message: '请求超时，后台可能仍在处理。' })
  expect(w.get('[role=alertdialog]').text()).toContain('请求超时，后台可能仍在处理。')
})
it('unknown delivery state retains its original spelling', async () => {
  const { w } = await mountQD('/mitigations', 'qd', p => p.includes('/delivery?')
    ? response(200, { rule_id: 'r', nodes: [{ name: 'n1', state: 'bogus' }] }) : undefined)
  await row(w, 'xdrop', 0).trigger('click'); await flushPromises()
  expect(dialog().querySelector('.delivery-table')?.textContent).toContain('bogus')
  expect(dialog().querySelector('.delivery-table')?.textContent).not.toContain('Bogus')
})
it('XDrop shared and last-holder confirmations use their distinct messages', async () => {
  const { w } = await mountQD()
  await row(w, 'xdrop', 0).get('button').trigger('click'); await flushPromises()
  expect(w.get('[role=alertdialog]').text()).toContain('本 xSight 还有 1 个其他持有方，规则保留。')
  await clickText(w.get('[role=alertdialog]'), '取消')
  await row(w, 'xdrop', 5).get('button').trigger('click'); await flushPromises()
  expect(w.get('[role=alertdialog]').text()).toContain('其他系统可能仍持有该规则。')
})
it('write completion starts fresh GETs during an old round and invalidates its late response', async () => {
  clock(); let requests = 0
  const old = deferred<Response>()
  const { w } = await mountQD('/mitigations', 'qd', p => p === '/api/active-actions/bgp'
    && ++requests === 2 ? old.promise : undefined)
  await tick(5000); expect(calls('/api/active-actions/bgp')).toHaveLength(2)
  await row(w, 'bgp', 0).get('button').trigger('click'); await flushPromises()
  await clickText(w.get('[role=alertdialog]'), '撤回')
  expect(calls('/api/active-actions/bgp')).toHaveLength(3)
  old.resolve(response(200, null)); await flushPromises()
  expect(block(w, 'bgp').findAll('tbody > tr.link')).toHaveLength(6)
})

it('W27 dismissed count is present while the section remains collapsed', async () => {
  const { w } = await mountQD()
  expect(w.get('[aria-expanded]').attributes('aria-expanded')).toBe('false')
  expect(w.get('[aria-expanded]').text()).toBe('已忽略的孤立路由 2 ▾')
})
