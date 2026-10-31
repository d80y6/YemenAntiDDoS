import { expect, it, vi } from 'vitest'
import { flushPromises } from '@vue/test-utils'
import { mountQE, clickText, domClick, dialog, input, writes, calls } from './qe-harness'
import { deferred, response } from './helpers'
import { notifications } from '../src/notifications'
import { defaults } from '../src/views/responses/data'
import ActionEditor from '../src/views/responses/ActionEditor.vue'
async function choose(label: string, option: string) {
  const button = [...document.querySelectorAll<HTMLButtonElement>('[role=combobox]')]
    .find(b => b.getAttribute('aria-label') === label || b.getAttribute('aria-label')?.startsWith(label + ':'))
  if (!button) throw Error('combobox not found: ' + label)
  button.click()
  await flushPromises()
  const item = [...document.querySelectorAll<HTMLButtonElement>('[role=option]')]
    .find(b => b.textContent?.trim() === option)
  if (!item) throw Error('option not found: ' + option)
  item.click()
  await flushPromises()
}
const mount = (mode = 'qf', admin = true) => mountQE('/responses/3', undefined, admin, mode)
async function add(w: any, phase = 'on_detected') {
  await clickText(w.find(`[data-phase=${phase}]`), '+ 添加动作')
}
async function edit(w: any, id = 15, viewing = false) {
  await clickText(w.find(`[data-action="${id}"]`), viewing ? '查看' : '编辑')
}
async function condition() {
  await domClick('+ 添加条件')
  await choose('属性', '严重度')
  await input('值', 'critical')
}
async function newWebhook(w: any) {
  await add(w)
  await choose('连接器', 'Alert hook')
  await condition()
}
it('G-ed new defaults, phase heading and readonly before GET resolves', async () => {
  const { w, intercept } = await mount()
  await add(w)
  expect(w.findComponent(ActionEditor).props('form')).toEqual(defaults())
  expect(dialog().textContent).toContain('攻击检测时')
  await domClick('取消')
  const gate = deferred<Response>()
  intercept(p => p === '/api/actions/15/preconditions' ? gate.promise : undefined)
  await edit(w)
  expect(document.querySelector('[role=dialog]')).toBeNull()
  gate.resolve(response(200, [{ id: 99, attribute: 'severity', operator: 'eq', value: 'high' }]))
  await flushPromises()
  expect(dialog().querySelector<HTMLInputElement>('[aria-label=值]')!.value).toBe('high')
})
it('G-ed interleaved opens last-click identity phase and conditions B wins W19', async () => {
  const { w, intercept } = await mount()
  const gate = deferred<Response>()
  intercept(p => p === '/api/actions/15/preconditions' ? gate.promise : p === '/api/actions/18/preconditions'
    ? response(200, [{ attribute: 'severity', operator: 'eq', value: 'critical' }]) : undefined)
  await edit(w, 15)
  await edit(w, 18)
  expect(w.findComponent(ActionEditor).props('form').id).toBe(18)
  gate.resolve(response(200, [{ attribute: 'decoder', operator: 'eq', value: 'udp' }]))
  await flushPromises()
  expect(w.findComponent(ActionEditor).props('form').id).toBe(18)
  expect(w.findComponent(ActionEditor).props('phase')).toBe('on_expired')
  expect(dialog().querySelector<HTMLInputElement>('[aria-label=值]')!.value).toBe('critical')
})
it('G-ed failed condition GET read-only both warnings and no condition writes W18', async () => {
  const { w } = await mount('qf-condition-fail')
  await edit(w)
  expect(dialog().textContent).toContain('前置条件加载失败，本次条件只读。')
  expect(dialog().textContent).toContain('条件加载失败，本次保存不会修改条件。')
  expect([...dialog().querySelectorAll('button')].some(b => b.textContent?.includes('添加条件'))).toBe(false)
  expect(w.findComponent(ActionEditor).props('form').preconditionsLoaded).toBe(false)
  await domClick('保存')
  expect(writes()).toHaveLength(1)
  expect(writes()[0]![0]).toBe('/api/actions/15')
})
it('G-ed failed condition GET with existing rows disables each condition control W18', async () => {
  const { w } = await mount()
  await edit(w)
  const editor = w.findComponent(ActionEditor)
  editor.props('form').preconditionsLoaded = false
  await flushPromises()
  expect([...dialog().querySelectorAll('.rs-condition button,.rs-condition input')]
    .every(e => e.matches(':disabled'))).toBe(true)
})
it('G-ed on_expired exactly two types and once run-mode W20', async () => {
  const { w } = await mount()
  await add(w, 'on_expired')
  const editor = w.findComponent(ActionEditor)
  const boxes = editor.findAllComponents({ name: 'XListbox' })
  const type = boxes.find(c => c.props('label') === '动作类型')!
  const run = boxes.find(c => c.props('label') === '运行模式')!
  expect(type.props('options').map((o: any) => o.value)).toEqual(['webhook', 'shell'])
  expect(run.props('options').map((o: any) => o.value)).toEqual(['once'])
})
it('G-ed editing type disabled, disabled connector listed, manual and periodic explanatory text W21', async () => {
  const { w } = await mount()
  await edit(w, 12)
  expect(dialog().querySelector<HTMLButtonElement>('[aria-label^="动作类型:"]')!.disabled).toBe(true)
  expect(dialog().textContent).toContain('要换类型请删除后重建。')
  expect(dialog().textContent).toContain('手动动作不会执行（尚无手动触发）。')
  await choose('连接器', 'Disabled shell（已停用）')
  await choose('运行模式', '周期')
  expect(dialog().textContent).toContain('随攻击更新执行，约每 5 分钟一次。')
  expect(dialog().querySelector('[aria-label="周期（秒）"]')).toBeNull()
})
it.each(['filter_l4', 'rate_limit', 'unblock'])(
  'G-ed xdrop %s field visibility and target enabled hint', async kind => {
  const { w } = await mount()
  await add(w)
  await choose('动作类型', 'xDrop')
  await choose('xDrop 动作', { filter_l4: 'Filter L4', rate_limit: 'Rate Limit', unblock: 'Unblock' }[kind]!)
  expect(dialog().querySelector('[aria-label="规则保持（分钟）"]') !== null).toBe(kind !== 'unblock')
  expect(dialog().querySelector('[aria-label="限速 (PPS)"]') !== null).toBe(kind === 'rate_limit')
  expect(dialog().querySelector('[role=checkbox][aria-label="目的 IP"]') !== null).toBe(kind !== 'unblock')
  expect(dialog().textContent).toContain('留空 = 全部已启用的 XDrop 连接器')
  expect(dialog().textContent).toContain('Disabled XDrop（已停用）')
  expect(dialog().querySelector('[aria-label^="连接器:"]')).toBeNull()
})
it('G-ed type changes clear connector and shell/bgp conditional fields', async () => {
  const { w } = await mount()
  await add(w)
  await choose('连接器', 'Alert hook')
  await choose('动作类型', 'Shell')
  expect(w.findComponent(ActionEditor).props('form').connector_id).toBeNull()
  expect(dialog().querySelector<HTMLInputElement>('.mono')?.placeholder).toBe('--attack {attack_id}')
  await choose('动作类型', 'BGP')
  expect(dialog().querySelector<HTMLInputElement>('[placeholder=RTBH]')).not.toBeNull()
  expect(dialog().querySelector('[aria-label="路由保持（分钟）"]')).not.toBeNull()
  w.findComponent(ActionEditor).props('form').action_type = 'bgp'
  await flushPromises()
})
it('G-ed three-write save only one final notice closes refreshes W1 W8', async () => {
  const { w } = await mount()
  await newWebhook(w)
  await domClick('保存')
  expect(writes().map(([p, init]) => [p, init?.method, JSON.parse(String(init?.body))])).toEqual([
    ['/api/responses/3/actions', 'POST', { action_type: 'webhook', connector_id: 1, priority: 5,
      run_mode: 'once', execution: 'automatic', enabled: false, period_seconds: null, trigger_phase: 'on_detected' }],
    ['/api/actions/100/preconditions', 'PUT', { preconditions: [
      { attribute: 'severity', operator: 'eq', value: 'critical' }] }],
    ['/api/actions/100', 'PUT', { action_type: 'webhook', connector_id: 1, priority: 5,
      run_mode: 'once', execution: 'automatic', enabled: true, period_seconds: null, trigger_phase: 'on_detected' }],
  ])
  expect(notifications.map(n => n.message)).toEqual(['动作已创建'])
  expect(document.querySelector('[role=dialog]')).toBeNull()
  expect(calls('/api/responses/3')).toHaveLength(2)
})
it.each([1, 2, 3])('G-ed step %s failure precise suffix refresh keeps form W6 W7', async step => {
  const { w, intercept } = await mount()
  let count = 0
  intercept((p, init) => init.method && init.method !== 'GET' && ++count === step
    ? response(500, { error: step === 3 ? 'sync: rollback incomplete: parent row' : 'storage rejected' }) : undefined)
  await newWebhook(w)
  await domClick('保存')
  const expected = step === 1 ? 'storage rejected' : step === 2 ? 'storage rejected 动作已以停用状态保存。'
    : 'sync: rollback incomplete: parent row 条件已保存；重新启用未确认，请看动作表里的启用状态。'
  expect(notifications.map(n => n.message)).toEqual([expected])
  expect(dialog().querySelector('[role=alert]')?.textContent).toBe(expected)
  expect(calls('/api/responses/3')).toHaveLength(2)
  expect(w.findComponent(ActionEditor).props('form').enabled).toBe(true)
  expect(dialog().querySelector<HTMLInputElement>('[aria-label=值]')!.value).toBe('critical')
})
it('G-ed new second-step failure retry PUT same id, no second POST W5', async () => {
  const { w, intercept } = await mount()
  intercept((p, init) => p.endsWith('/preconditions') && init.method === 'PUT'
    ? response(500, { error: 'conditions rejected' }) : undefined)
  await newWebhook(w); await domClick('保存')
  expect(w.findComponent(ActionEditor).props('form').id).toBe(100)
  expect(dialog().querySelector<HTMLButtonElement>('[aria-label^="动作类型:"]')!.disabled).toBe(true)
  intercept()
  await domClick('保存')
  expect(writes().filter(([, i]) => i?.method === 'POST')).toHaveLength(1)
  expect(writes().slice(2).map(([p, i]) => [p, i?.method])).toEqual([
    ['/api/actions/100', 'PUT'], ['/api/actions/100/preconditions', 'PUT'], ['/api/actions/100', 'PUT'],
  ])
})
it.each([false, true])(
  'G-ed leaving during first write keeps subsequent steps and final notice failed=%s W28', async fail => {
  const { w, router, intercept } = await mount()
  const gate = deferred<Response>()
  intercept((p, init) => p === '/api/responses/3/actions' && init.method === 'POST' ? gate.promise
    : fail && p === '/api/actions/100' && init.method === 'PUT'
      ? response(500, { error: 'sync: rollback incomplete: parent row' }) : undefined)
  await newWebhook(w)
  const editor = w.findComponent(ActionEditor)
  await domClick('保存')
  expect(dialog().getAttribute('aria-busy')).toBe('true')
  expect([...dialog().querySelectorAll('button,input')].every(e => e.matches(':disabled'))).toBe(true)
  dialog().dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true }))
  document.querySelector<HTMLElement>('.scrim')!.click()
  await flushPromises()
  expect(document.querySelector('[role=dialog]')).not.toBeNull()
  expect(writes()).toHaveLength(1)
  await router.push('/responses'); await flushPromises()
  expect(editor.exists()).toBe(false)
  gate.resolve(response(201, { id: 100 }))
  await flushPromises()
  expect(writes().map(([p]) => p)).toEqual([
    '/api/responses/3/actions', '/api/actions/100/preconditions', '/api/actions/100'])
  expect(notifications).toHaveLength(1)
  expect(notifications[0]!.message).toBe(fail
    ? 'sync: rollback incomplete: parent row 条件已保存；重新启用未确认，请看动作表里的启用状态。' : '动作已创建')
})
it('G-ed structured GET conditions win legacy JSONB, unknown attribute roundtrips all three keys W31', async () => {
  const { w } = await mount()
  await edit(w)
  expect(w.findComponent(ActionEditor).props('form').preconditions).toEqual([
    { attribute: 'decoder', operator: 'eq', value: 'udp' }, { attribute: 'peak_pps', operator: 'gte', value: '100000' },
  ])
  expect(dialog().textContent).toContain('peak_pps')
  const fields = dialog().querySelectorAll<HTMLInputElement>('[aria-label=值]')
  fields[1]!.value = '200000'; fields[1]!.dispatchEvent(new Event('input', { bubbles: true }))
  await domClick('保存')
  expect(JSON.parse(String(writes()[1]![1]!.body))).toEqual({ preconditions: [
    { attribute: 'decoder', operator: 'eq', value: 'udp' }, { attribute: 'peak_pps', operator: 'gte', value: '200000' },
  ] })
})
it('G-ed viewer every form control disabled no save add/remove W32', async () => {
  const { w } = await mount('qf', false)
  await edit(w, 15, true)
  expect(dialog().textContent).toContain('查看动作')
  expect([...dialog().querySelectorAll('fieldset button,fieldset input')].every(e => e.matches(':disabled'))).toBe(true)
  expect([...dialog().querySelectorAll('button')].some(b => ['保存', '+ 添加条件', '✕'].includes(b.textContent!.trim())
    && b.getAttribute('aria-label') !== '关闭')).toBe(false)
  expect(writes()).toHaveLength(0)
})
it.each([[15, '规则保持（分钟）', 'unblock_delay_minutes'], [13, '路由保持（分钟）', 'bgp_withdraw_delay_minutes']])(
  'G-ed integer holds and priority decimal blur %s W33', async (id, label, key) => {
    const { w } = await mount()
    await edit(w, Number(id))
    await input(String(label), '1.5'); await input('优先级', '1.5')
    await domClick('保存')
    const sent = JSON.parse(String(writes()[0]![1]!.body))
    expect(sent[key]).toBe(2)
    expect(sent.priority).toBe(2)
  },
)
it('G-ed rate decimal blur sent integer in both payload positions', async () => {
  const { w } = await mount()
  await edit(w, 17)
  await input('限速 (PPS)', '1.5')
  await domClick('保存')
  const sent = JSON.parse(String(writes()[0]![1]!.body))
  expect(sent.xdrop_rate_limit).toBe(2)
  expect(sent.xdrop_custom_payload.rate_limit).toBe(2)
})
it('G-ed severity default equals shown placeholder accepted by Go-shaped mock W34', async () => {
  const { w } = await mount()
  await add(w); await choose('连接器', 'Alert hook'); await domClick('+ 添加条件')
  await choose('属性', '严重度')
  const field = dialog().querySelector<HTMLInputElement>('[aria-label=值]')!
  expect(field.placeholder).toBe('critical')
  await input('值', field.placeholder); await domClick('保存')
  expect(notifications.map(n => n.message)).toEqual(['动作已创建'])
})
it.each([
  [15, '优先级', '11', 'priority', 10], [15, '优先级', '-1', 'priority', 1],
  [15, '规则保持（分钟）', '1441', 'unblock_delay_minutes', 1440],
  [13, '路由保持（分钟）', '-1', 'bgp_withdraw_delay_minutes', 0],
  [17, '限速 (PPS)', '100000001', 'xdrop_rate_limit', 100000000],
])('G-ed number bounds and clear restore previous %s %s', async (id, label, draft, key, expected) => {
  const { w } = await mount()
  await edit(w, Number(id))
  await input(String(label), String(draft))
  await input(String(label), '')
  await domClick('保存')
  expect(JSON.parse(String(writes()[0]![1]!.body))[key]).toBe(expected)
})
it('G-ed validation warn in footer and zero writes', async () => {
  const { w } = await mount()
  await add(w); await choose('动作类型', 'xDrop')
  const check = dialog().querySelector<HTMLButtonElement>('[aria-label="目的 IP"]')!
  check.click(); await flushPromises()
  await domClick('保存')
  expect(dialog().querySelector('[role=alert]')?.textContent).toBe('请至少选择一个匹配字段')
  expect(writes()).toHaveLength(0)
})
