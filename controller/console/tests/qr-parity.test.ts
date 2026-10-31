import { expect, it, vi } from 'vitest'
import { flushPromises } from '@vue/test-utils'
import { nextTick } from 'vue'
import { render, response, deferred } from './helpers'
import { mountPage } from './attacks-harness'
import { mountQE, clickText, domClick, dialog, body } from './qe-harness'
import { pointer } from './pointer'
import { state } from '../src/state'
import { notifications } from '../src/notifications'
import XTip from '../src/components/XTip.vue'
import XChart from '../src/components/chart/XChart.vue'
import Status from '../src/views/mitigations/Status.vue'
import Detail from '../src/views/mitigations/Detail.vue'
import ActionDrawer from '../src/views/attacks/ActionDrawer.vue'
import AttackMitigations from '../src/views/attacks/Mitigations.vue'
import { fullDateTime } from '../src/format'

const linkStub = { RouterLink: { template: '<a><slot /></a>' } }
const action = (status: string) => ({ id: 101, attack_id: 1, action_id: 5, connector_id: 1,
  action_type: 'bgp', status, trigger_phase: 'attack_start', executed_at: '2026-10-28T01:02:03Z',
  duration_ms: 0, connector_name: 'fixture', bgp_role: 'triggered' })
async function mitigation(row: any, logs: any[] = [], nodes: any[] = [], kind = 'bgp') {
  vi.stubGlobal('fetch', vi.fn(async (path: string) => response(200,
    path.includes('/delivery?') ? { found: true, nodes } : { logs })))
  const w = render(Detail, { props: { modelValue: true, row, kind, now: Date.now(), connectors: [],
    holders: 0, missing: false }, global: { stubs: linkStub }, attachTo: document.body })
  await flushPromises()
  return w
}

it.each([
  ['zh', '只筛选本图；卡片与 Top 表不按前缀筛选'],
  ['en', 'Filters this chart only; the cards and the Top table are not filtered by prefix'],
] as const)('F1 prefix explanation is exact in %s and cards/Top ignore prefix', async (locale, text) => {
  state.locale = locale
  const { w } = await mountQE('/traffic?prefix=192.0.2.0/24', undefined, true, 'normal')
  expect(w.findComponent(XTip).props('text')).toBe(text)
  expect(w.findComponent(XTip).text()).toContain(text)
  const urls = vi.mocked(fetch).mock.calls.map(([raw]) => new URL(String(raw), 'http://localhost'))
  const overviews = urls.filter(u => u.pathname === '/api/stats/overview')
  expect(overviews.length).toBeGreaterThan(0)
  for (const url of overviews) expect(url.searchParams.has('prefix')).toBe(false)
  expect(urls.find(u => u.pathname === '/api/stats/summary')?.search).toBe('')
})
it.each([
  ['both nodes', 'both', ['A'], [], ['A', 'B'], ['A', 'B']],
  ['missing both row', 'both', ['A'], ['B'], undefined, ['A']],
  ['both empty nodes', 'both', ['A'], ['B'], [], []],
  ['outgoing fallback', 'both', [], ['B'], undefined, ['B']],
  ['incoming only', 'receives', ['A'], ['B'], ['A', 'B'], ['A']],
] as const)('F2 %s preserves merged nodes and the current-side fallback', async (_name, direction, inc, out,
  both, expected) => {
  const nodes = (ids: readonly string[]) => ids.map(id => ({ id, mode: 'flow' }))
  const { w } = await mountQE('/traffic?direction=' + direction, (path, _init, result) => {
    if (!path.startsWith('/api/stats/overview?')) return
    const side = new URL(path, 'http://localhost').searchParams.get('direction')
    const ids = side === 'both' ? both : side === 'sends' ? out : inc
    const rows = ids === undefined || side !== 'both' && !ids.length ? [] : [{ prefix: '192.0.2.0/24',
      pps: 100, bps: 800, nodes: nodes(ids) }]
    return response(200, { ...result.body, top_prefixes: rows })
  }, true, 'normal')
  expect(w.get('tbody tr').findAll('.brief .pill').map(p => p.text()))
    .toEqual(expected.map(id => id + ' · FLOW'))
})
it.each([[71.4, 0], [126.2, 1]])('F3 drag ending at %s emits %s updates for one/two points', async (end, count) => {
  const w = render(XChart, { props: { points: [0, 1000, 2000].map(time => ({ time, values: { tcp: 1 } })),
    selected: ['tcp'], slots: { tcp: 1 }, bounds: [0, 10000], zoomable: true } })
  await pointer(w.get('svg').element, 'pointerdown', 44)
  await pointer(w.get('svg').element, 'pointerup', end!)
  expect(w.emitted('update:window') ?? []).toHaveLength(count!)
})

it.each([
  ['zh', ['生效中', '延迟撤回', '失败', '待执行']],
  ['en', ['Active', 'Delayed withdrawal', 'Failed', 'Pending']],
] as const)('F4 mitigation Status and attack summary hover map all states in %s', async (locale, labels) => {
  state.locale = locale
  for (const [index, status] of ['active', 'delayed', 'failed', 'pending', 'unknown'].entries()) {
    const expected = labels[index] ?? 'unknown'
    const statusView = render(Status, { props: { row: { status }, kind: 'bgp', now: Date.now() } })
    expect(statusView.text()).toContain(expected)
    statusView.unmount()
    const { w } = await mountPage('/attacks', 'attacks', (path, _init, result) => {
      if (!path.startsWith('/api/attacks/mitigation-brief')) return
      for (const value of Object.values(result.body) as any[]) {
        for (const row of [...(value.bgp ?? []), ...(value.xdrop_rules ?? [])]) row.status = status
      }
      return response(200, result.body)
    })
    const tips = w.findAll('[title]').map(e => e.attributes('title'))
    expect(tips.some(text => text?.includes(' · ' + expected))).toBe(true)
    w.unmount()
  }
})
it.each([['zh', '解码器'], ['en', 'Decoder']] as const)(
  'F4 AttackDetail detection label translates in %s; decoder identifier stays tcp', async (locale, label) => {
    state.locale = locale
    const { w } = await mountPage('/attacks/1', 'attacks', (path, _init, result) => {
      if (path.split('?')[0] !== '/api/attacks/1') return
      result.body.attack.decoder_family = 'tcp'
      return response(200, result.body)
    })
    const dt = w.findAll('.detection-kv dt').find(d => d.text() === label)!
    expect(dt.exists()).toBe(true)
    expect(dt.element.nextElementSibling?.textContent).toBe('tcp')
  },
)
it.each([['zh', '源端口:123', '目的端口:456'], ['en', 'src:123', 'dst:456']] as const)(
  'F4 attack mitigation port labels translate in %s', (locale, src, dst) => {
    state.locale = locale
    const row = { id: 1, attack_id: 1, action_id: 5, connector_id: 1, external_rule_id: 'r1', status: 'active' }
    const w = render(AttackMitigations, { props: { data: { xdrop_rules: [row] },
      holders: [{ ...row, dst_ip: '192.0.2.1', protocol: 'tcp', src_port: 123, dst_port: 456 }],
      responseId: 1, now: Date.now() }, global: { stubs: linkStub } })
    expect(w.text()).toContain(src)
    expect(w.text()).toContain(dst)
  },
)
it.each([
  ['zh', 'triggered', '触发'], ['zh', 'attached_shared', '附加'],
  ['en', 'triggered', 'triggered'], ['en', 'attached_shared', 'attached'],
] as const)('F4 ActionDrawer BGP role %s/%s uses the log-table label', async (locale, role, expected) => {
  state.locale = locale
  render(ActionDrawer, { props: { modelValue: true, row: { ...action('success'), bgp_role: role } },
    attachTo: document.body })
  await flushPromises()
  expect(dialog().textContent).toContain(expected)
})
async function statusSurface(surface: string, status: string, expected: string) {
  if (surface === 'log') {
    const { w } = await mountPage('/attacks/1', 'attacks', (path, _init, result) => path.split('?')[0]!
      .endsWith('mitigation-summary')
      ? response(200, { ...result.body, executions: [action(status)] }) : undefined)
    expect(w.get('.action-log tbody tr').findAll('td')[4]!.text()).toBe(expected)
  } else if (surface === 'drawer') {
    render(ActionDrawer, { props: { modelValue: true, row: action(status) }, attachTo: document.body })
    await flushPromises()
    expect(dialog().querySelectorAll('dd')[1]?.textContent).toBe(expected)
  } else {
    await mitigation({ ...action(status), prefix: '192.0.2.0/24' }, [action(status)])
    expect(dialog().querySelector('.tl li > span.sub')?.textContent?.trim()).toBe(expected)
  }
}
it.each(['log', 'drawer', 'timeline'])('F4 running translates on %s in both languages', async surface => {
  await statusSurface(surface, 'running', '执行中')
  state.locale = 'en'
  await nextTick()
  expect(document.body.textContent).toContain('Running')
})
it.each(['log', 'drawer', 'timeline'])('F5 pending means awaiting execution on %s', async surface => {
  await statusSurface(surface, 'pending', '待执行')
  expect(document.body.textContent).not.toContain('实时状态暂未取到')
})
it('F5 missing live status retains the original pending explanation', async () => {
  const { w } = await mountPage('/attacks', 'attacks', path => path.split('?')[0] === '/api/attacks/active'
    ? response(200, { attacks: [], timers: {}, active_count: 0, returned: 0 }) : undefined)
  expect(w.findAll('[title]').map(e => e.attributes('title')))
    .toContain('实时状态暂未取到（可能刚结束）')
})
it.each([['zh', '触发阶段'], ['en', 'trigger_phase']] as const)(
  'F4 timeline trigger phase hover translates in %s', async (locale, expected) => {
    state.locale = locale
    await mitigation({ ...action('success'), prefix: '192.0.2.0/24' }, [action('success')])
    expect(dialog().querySelector('.tl .pill')?.getAttribute('title')).toBe(expected + ' attack_start')
  },
)
it('F4 Flow list, listener option, source heading/list/options translate without changing values', async () => {
  const { w } = await mountQE('/flow/flow-b', (path, _init, result) => {
    if (path.startsWith('/api/flow-listeners')) {
      if (Array.isArray(result.body)) result.body[0].protocol_mode = 'auto'
      else if (result.body.listener) result.body.listener.protocol_mode = 'auto'
      return response(200, result.body)
    }
  }, true, 'qh')
  expect(w.get('.fl-row').findAll('td')[2]!.text()).toBe('自动')
  await w.get('.fl-row').trigger('click')
  await flushPromises()
  expect(dialog().querySelector('[aria-label="协议模式"]')?.textContent).toContain('自动')
  await domClick('取消')
  await clickText(w.get('.fl-row'), '数据源 3')
  expect(dialog().querySelector('p.sub.mono')?.textContent).toContain('自动')
  expect([...dialog().querySelectorAll('tbody tr .pill')].map(e => e.textContent?.trim()))
    .toEqual(expect.arrayContaining(['自动', '强制', '无']))
  await domClick('添加数据源')
  expect(dialog().querySelector('[aria-label="采样模式"]')?.textContent?.trim()).toBe('自动强制无')
  await domClick('强制')
  state.locale = 'en'
  await nextTick()
  expect(dialog().querySelector('[aria-label="Sample mode"]')?.textContent?.trim()).toBe('AutoForceNone')
  expect(dialog().querySelector('[aria-pressed="true"]')?.textContent?.trim()).toBe('Force')
})
it('F4 threshold detail direction/comparison, delete description, edit options and rules list translate', async () => {
  const { w, router } = await mountQE('/thresholds/7')
  const row = w.get('tbody tr')
  expect(row.findAll('td')[1]!.text()).toBe('入向')
  expect(row.findAll('td')[2]!.text()).toBe('超过')
  expect(w.findAll('tbody tr').some(r => r.text().includes('出向'))).toBe(true)
  await clickText(row, '删除')
  expect(w.get('[role=alertdialog]').text()).toContain('ip bps 超过 800K')
  await clickText(w.get('[role=alertdialog]'), '取消')
  await clickText(row, '编辑')
  expect(dialog().querySelector('[aria-label="比较"]')?.textContent?.trim()).toBe('超过低于')
  await domClick('低于')
  await domClick('保存')
  expect(body().comparison).toBe('under')
  state.locale = 'en'
  await nextTick()
  expect(w.get('tbody tr').findAll('td')[2]!.text()).toBe('Under')
  await router.push('/thresholds/rules')
  await flushPromises()
  expect(w.get('tbody tr').findAll('td')[4]!.text()).toBe('Over')
})
it('F6 detached association displays full year, date and time', async () => {
  const detached = '2025-03-04T01:02:03Z'
  await mitigation({ prefix: '192.0.2.0/24', status: 'active',
    attached_attacks: [{ attack_id: 1, detached_at: detached }] })
  expect(dialog().querySelector('.attachment .sub')?.textContent).toContain(fullDateTime(detached))
  expect(dialog().querySelector('.attachment .sub')?.textContent).toContain('2025-03-04')
})
it.each([0, 10, null, undefined])('F7 association delay %s preserves zero and omits null/missing', async delay => {
  await mitigation({ prefix: '192.0.2.0/24', status: 'active',
    attached_attacks: [{ attack_id: 1, delay_minutes: delay }] })
  expect(dialog().querySelector('.attachment')?.textContent?.includes('延迟')).toBe(delay != null)
  if (delay != null) expect(dialog().querySelector('.attachment')?.textContent).toContain(String(delay))
})
it.each([0, 10, null, undefined])('F7 attack mitigation delay %s preserves zero and omits null/missing', delay => {
  const w = render(AttackMitigations, { props: { data: { bgp_announcements: [{ detached_at: null,
    attack_delay_minutes: delay, announcement: { id: 1, prefix: '192.0.2.0/24', status: 'active' } }] },
    holders: [], responseId: 1, now: Date.now() }, global: { stubs: linkStub } })
  expect(w.text().includes('结束后延迟')).toBe(delay != null)
  if (delay != null) expect(w.text()).toContain(`结束后延迟 ${delay} 分撤回`)
})
it('F9 error-only node puts the error on visible status and has no empty error span', async () => {
  await mitigation({ ...action('active'), external_rule_id: 'r1' }, [],
    [{ name: 'fixture', state: 'failed', code: '', error: 'x' }], 'xdrop')
  const status = dialog().querySelector('.delivery-table [title="x"]')!
  expect(status.textContent?.trim()).not.toBe('')
  expect(dialog().querySelector('.delivery-table .sub.mono')).toBeNull()
})
it.each(['bgp', 'xdrop', 'webhook'] as const)(
  'F11 %s late success/failure has one identical global result; mounted results stay inline', async kind => {
    for (const outcome of ['success', 'business failure', 'HTTP failure'] as const) {
      const text = outcome === 'success' ? { bgp: 'BGP 连接正常\nprobe output',
        xdrop: '连接成功，凭证：fixture-machine', webhook: 'Webhook 测试成功（HTTP 204）' }[kind]
        : { bgp: '测试失败', xdrop: '连接测试失败', webhook: 'Webhook 测试失败' }[kind] + '\nbackend original'
      const reply = () => response(outcome === 'HTTP failure' ? 500 : 200, outcome === 'success'
        ? kind === 'bgp' ? { ok: true, output: 'probe output' }
          : { success: true, name: 'fixture-machine', status_code: 204 }
        : { success: false, ok: false, error: 'backend original' })
      for (const leave of [false, true]) {
        notifications.splice(0)
        const pending = deferred<Response>()
        const { w } = await mountQE('/connectors/' + kind,
          (_path, init) => init.method === 'POST' ? pending.promise : undefined, true, 'qg')
        await clickText(w.get('.cn-row'), '测试')
        if (leave) w.unmount()
        pending.resolve(reply())
        await flushPromises()
        expect(notifications).toHaveLength(leave ? 1 : 0)
        if (leave) expect(notifications[0]).toMatchObject({ message: text,
          tone: outcome === 'success' ? 'ok' : 'crit', raw: outcome !== 'success' })
        else {
          for (const part of text.split('\n')) expect(w.get('.cn-result').text()).toContain(part)
          w.unmount()
        }
      }
    }
  },
)
it.each([[0, 10000], [-1, 10000], [2500, 2500]])(
  'F12 XDrop timeout %s displays effective %s', async (input, expected) => {
  const { w } = await mountQE('/connectors/xdrop', (path, _init, result) => {
    if (path !== '/api/settings/xdrop-connectors') return
    result.body[0].timeout_ms = input
    return response(200, result.body)
  }, true, 'qg')
  expect(w.get('.cn-row').findAll('td')[4]!.text()).toBe(String(expected))
  },
)
