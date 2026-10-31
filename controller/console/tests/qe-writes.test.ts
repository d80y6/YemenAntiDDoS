import { it, expect } from 'vitest'
import { flushPromises } from '@vue/test-utils'
import { mountQE, clickText, domClick, choose, textInput, input, writes } from './qe-harness'
import { deferred, response } from './helpers'
import { notifications } from '../src/notifications'
const cases = [
  ['prefix-create', '/prefixes', '前缀已创建'],
  ['prefix-update', '/prefixes', '前缀已更新'],
  ['prefix-delete', '/prefixes', '已删除'],
  ['template-create', '/thresholds', '模板已创建'],
  ['template-rename', '/thresholds/7', '已更新'],
  ['template-copy', '/thresholds', '已复制'],
  ['template-delete', '/thresholds', '已删除'],
  ['default-response', '/thresholds/7', '默认响应已更新'],
  ['rule-response', '/thresholds/7', '规则响应已更新'],
  ['rule-create', '/thresholds/7', '规则已添加'],
  ['rule-update', '/thresholds/7', '已更新'],
  ['rule-delete', '/thresholds/7', '已删除'],
  ['flat-create', '/thresholds/rules', '阈值已创建'],
  ['flat-delete', '/thresholds/rules', '已删除'],
  ['config-save', '/baseline', '已保存'],
]
it.each(cases.flatMap(row => [true, false].map(ok => [...row, ok] as const)))(
  'G-write all15 %s leaves %s result %s success=%s', async (operation, path, message, ok) => {
    const pending = deferred<Response>()
    let result: any
    const { w, router } = await mountQE(path as string, (_p, i, r) => {
      if (i.method && i.method !== 'GET') { result = r; return pending.promise }
    })
    const row = () => w.get('tbody tr')
    if (operation === 'prefix-create') {
      await clickText(w, '添加前缀'); await textInput('前缀 (CIDR)', '198.51.100.0/24'); await domClick('创建')
    } else if (operation === 'prefix-update') {
      await clickText(row(), '编辑'); await domClick('保存')
    } else if (operation === 'template-create') {
      await clickText(w, '创建'); await textInput('名称', 'Created'); await domClick('创建')
    } else if (operation === 'template-rename') {
      await clickText(w, '编辑名称'); await domClick('保存')
    } else if (operation === 'template-copy') {
      await clickText(row(), '复制'); await clickText(w.get('.inline'), '复制')
    } else if (operation === 'default-response') await choose('默认响应', '无')
    else if (operation === 'rule-response') await choose('响应', 'Observe', row().element)
    else if (operation === 'rule-create' || operation === 'flat-create') {
      await clickText(w, operation === 'rule-create' ? '+ 添加规则' : '添加规则')
      if (operation === 'flat-create') await input('前缀 ID', '2')
      await domClick('创建')
    } else if (operation === 'rule-update') {
      await clickText(row(), '编辑'); await domClick('保存')
    } else if (operation === 'config-save') await clickText(w.get('.config'), '保存')
    else {
      const target = operation === 'template-delete'
        ? w.findAll('tbody tr').find(r => r.text().includes('Unused'))! : row()
      await clickText(target, '删除'); await clickText(w.get('[role=alertdialog]'), '删除')
    }
    expect(writes()).toHaveLength(1)
    await router.push('/about'); await flushPromises()
    pending.resolve(ok ? response(result.status, result.body) : response(400, { error: 'write rejected verbatim' }))
    await flushPromises()
    expect(notifications.at(-1)).toMatchObject({ message: ok ? message : 'write rejected verbatim',
      tone: ok ? 'ok' : 'crit' })
    expect(w.text()).toContain(ok ? message : 'write rejected verbatim')
  })
