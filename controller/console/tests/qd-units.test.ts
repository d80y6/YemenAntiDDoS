import { it, expect, vi } from 'vitest'
import { i18n } from '../src/i18n'
import { ApiError } from '../src/api/client'
import { deliveryStateType } from '../src/api/xdropRules'
import { actionLabel, attackLinks, bgpConfirmation, businessKey, deliveryResult, matchSummary,
  timelineRows, xdropConfirmation } from '../src/views/mitigations/data'
import { captureText, configCell, generateKey, nodeReadings, snippet, validNodeId } from '../src/views/nodes/data'
import XSpark from '../src/components/chart/XSpark.vue'
import { render } from './helpers'
const t = i18n.global.t as any
it('W4 W32 BGP confirmation four branches count only 3 attached, forbid attack lifecycle assertions', () => {
  const shared = { prefix: 'X', attached_attacks: [{}, { detached_at: null }, {},
    { detached_at: 't' }, { detached_at: 't' }] }
  const results = [bgpConfirmation(shared, t), bgpConfirmation({ attached_attacks: [{}], status: 'delayed' }, t),
    bgpConfirmation({ attached_attacks: [{}], status: 'active' }, t),
    bgpConfirmation({ attack_id: 7, attached_attacks: [{ detached_at: 't' }], status: 'failed' }, t)]
  results.forEach(r => expect(r.title + r.description).not.toMatch(/进行中|仍在进行|已结束/))
  expect(results[0]).toEqual({ title: '强制撤回 X？', description: '这条宣告还挂着 3 个攻击，会一起解除关联并撤回。' })
  expect(results[1].description).toBe('立即从 FRR 撤回，不再等延迟。')
  expect(results[2].description).toBe('这条宣告还有 1 个未脱离的攻击挂载，会解除关联并立即尝试从 FRR 撤回。')
  expect(results[3].description).toBe('立即尝试从 FRR 撤回这条宣告。')
})
it('attack links split live detached and fallback', () => {
  expect(attackLinks({ attached_attacks: [{ attack_id: 1 }, { attack_id: 2, detached_at: null },
    { attack_id: 3 }, { attack_id: 4, detached_at: 't' }, { attack_id: 5, detached_at: 't' }] }))
    .toEqual({ ids: [1, 2, 3], detached: 2 })
  expect(attackLinks({ attack_id: 7 })).toEqual({ ids: [7], detached: 0 })
  expect(attackLinks({ attack_id: 0 })).toEqual({ ids: [], detached: 0 })
})
it('W13 XDrop confirmations synthetic shared last', () => {
  expect(xdropConfirmation({ external_rule_id: 'failed-create-5' }, 9, t)).toEqual({
    title: '收尾这条创建失败的记录？',
    description: '创建结果未知。收尾只保证关闭 xSight 里的记录，XDrop 上可能仍有对应规则，请到 XDrop 核对。', label: '收尾' })
  expect(xdropConfirmation({}, 1, t).description).toBe('释放本攻击这个动作的持有？本 xSight 还有 1 个其他持有方，规则保留。')
  expect(xdropConfirmation({}, 0, t).description).toBe('释放本攻击这个动作的持有？其他系统可能仍持有该规则。')
})
it.each([
  [{ protocol: 'udp', src_port: 53 }, 'udp · 源端口 53'],
  [{ protocol: 'tcp', dst_port: 443, tcp_flags: 'SYN' }, 'tcp · 目的端口 443 · 标志 SYN'],
  [{ rate_limit: 1000 }, '限速 1000'], [{}, '—'],
])('match summary %j', (row, expected) => { expect(matchSummary(row, t)).toBe(expected) })
it('missing action is unknown', () => { expect(actionLabel({}, t)).toBe('—') })
it.each([
  ['confirmed', 'ok'], ['pending', 'warn'], ['overloaded', 'warn'], ['rejected', 'crit'],
  ['offline', 'crit'], ['disabled', 'neutral'], ['incompatible', 'neutral'], ['bogus', 'neutral'],
])('delivery state %s %s', (state, tone) => expect(deliveryStateType(state)).toBe(tone))
it.each([
  [{ found: false }, 'notFound'], [{ error: 'xdrop connector not found' }, 'unavailable'],
  [{ rule_id: 'r', nodes: [] }, 'none'], [{ rule_id: 'r', nodes: null }, 'none'],
  [{ rule_id: 'r', nodes: [{ name: 'n1', state: 'confirmed' }] }, 'nodes'], [{}, 'failed'],
])('delivery classification %j', (body, kind) => expect(deliveryResult(body).kind).toBe(kind))
it('W8 delivery exception classification keeps backend message', () => {
  expect(deliveryResult(undefined, new ApiError(0, 'timeout', true)).kind).toBe('timeout')
  expect(deliveryResult(undefined, new ApiError(502, 'HTTP 409 …'))).toEqual({
    kind: 'failed', message: 'HTTP 409 …', nodes: [] })
})
it('business keys distinguish every identity member', () => {
  const row = { attack_id: 1, action_id: 5, connector_id: 1, external_rule_id: 'r' }
  expect(businessKey(row, 'bgp')).not.toBe(businessKey({ ...row, connector_id: 2 }, 'bgp'))
  for (const key of Object.keys(row)) expect(businessKey(row, 'xdrop'))
    .not.toBe(businessKey({ ...row, [key]: 'different' }, 'xdrop'))
})
it('W10 timeline filters another action and keeps legacy missing', () => {
  expect(timelineRows([{ action_id: 5 }, { action_id: 6 }, {}], { action_id: 5 })).toEqual([{ action_id: 5 }, {}])
})
it('W18 crypto produces exact 64 lowercase hex characters without Math.random', () => {
  const spy = vi.spyOn(Math, 'random'), random = vi.spyOn(crypto, 'getRandomValues')
    .mockImplementation((a: any) => { a.fill(0xab); return a })
  const key = generateKey()
  expect(spy).not.toHaveBeenCalled()
  expect(key).toBe('abababababababababababababababababababababababababababababababab')
  expect(random).toHaveBeenCalledTimes(1)
  random.mockRestore(); spy.mockRestore()
})
it('W22 snippet mode and YAML escaping', () => {
  for (const mode of ['xdp', 'flow']) expect(snippet('', '', mode, t)).not.toMatch(/interfaces:|mirror|erspan/i)
  expect(snippet('', '', 'xdp', t)).toContain('node_id: "edge-03"')
  expect(snippet('', '', 'xdp', t)).toContain('config.example.yaml')
  expect(snippet('', '', 'flow', t).split('\n')[0]).toBe('mode: flow')
  expect(snippet('a"b\\c', '', 'xdp', t).split('\n')[0]).toBe('node_id: "a\\"b\\\\c"')
})
it.each([['edge/03', false], ['.', false], ['..', false], ['edge-03', true], ['edge.03', true],
  ['a..b', true], ['边缘 3', true]])('W33 node ID %s', (id, expected) => expect(validNodeId(id)).toBe(expected))
it('W21 config status takes precedence over versions and offline hint', () => {
  const row = { delivery_version_current: 7, delivery_version_applied: 4, online: true }
  expect(configCell({ ...row, config_status: 'synced' }, t)).toEqual({ tone: 'ok', text: '已同步',
    tip: '已应用配置版本 4' })
  expect(configCell({ ...row, config_status: 'failed' }, t)).toEqual({ tone: 'crit', text: '失败',
    tip: '节点拒收或应用失败，版本 7' })
  expect(configCell({ ...row, config_status: 'pending' }, t).text).toBe('待下发 · 落后 3')
  expect(configCell({ ...row, online: false }, t).tip).toBe('已应用 4，最新 7；节点离线，上线后自动下发')
})
it('capture three rates interfaces and absent; readings join by ID', () => {
  expect(captureText({ capture: [{ interface: 'eth1', upstream_sample_rate: 1 },
    { interface: 'eth2', upstream_sample_rate: 0 }, { interface: 'eth3', upstream_sample_rate: 300 }] }, t))
    .toBe('eth1 · 不采样\neth2 · 不采样\neth3 · 1:300 采样')
  expect(captureText({ interfaces: ['eth1', 'eth2'] }, t)).toBe('eth1, eth2')
  expect(captureText({}, t)).toBe('—')
  expect(nodeReadings([{ id: 'n' }, { id: 'm' }], [{ id: 'n', pps: 7 }])).toEqual([
    { id: 'n', reading: { id: 'n', pps: 7 } }, { id: 'm', reading: undefined }])
})
it('W24 XSpark default and custom viewBox plus applied SVG sizes', () => {
  const w = render(XSpark, { props: { values: [1, 2] } })
  expect(w.attributes('viewBox')).toBe('0 0 120 32')
  expect(w.element.style.width).toBe('120px'); expect(w.element.style.height).toBe('32px')
  const large = render(XSpark, { props: { values: [1], width: 400, height: 56 } })
  expect(large.attributes('viewBox')).toBe('0 0 400 56')
  expect(large.element.style.width).toBe('400px'); expect(large.element.style.height).toBe('56px')
})
