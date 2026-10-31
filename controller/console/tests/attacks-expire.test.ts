import { describe, it, expect, beforeEach } from 'vitest'
import { flushPromises } from '@vue/test-utils'
import { mountPage, clock, calls } from './attacks-harness'
import { response, deferred } from './helpers'
import { notifications } from '../src/notifications'
beforeEach(clock)
async function confirmation(url: string, id = 1) {
  const context = await mountPage(url)
  const { w } = context
  const label = url.includes('?') ? '结束' : '结束攻击'
  const button = w.findAll('button').find(b => b.text() === label && (label !== '结束'
    || b.element.closest('tr')?.textContent?.includes('#' + id)))!
  await button.trigger('click')
  return context
}
describe.each(['/attacks?status=active', '/attacks/1'])('G-expire %s', url => {
  it.each([['', '/api/attacks/1/expire', '已按全局设置请求压制'],
    ['0', '/api/attacks/1/expire?hold_seconds=0', '本次未请求压制'],
    ['600', '/api/attacks/1/expire?hold_seconds=600', '已请求最长压制 600 秒']])(
    'W4 hold=%s exact request and result', async (raw, expected, message) => {
      const { w } = await confirmation(url)
      await w.get('[role=alertdialog] input').setValue(raw)
      await w.get('[role=alertdialog] .danger').trigger('click'); await flushPromises()
      expect(calls('/api/attacks/1/expire')[0]![0]).toBe(expected)
      expect(notifications.at(-1)).toMatchObject({ tone: 'ok', message: '攻击 #1 已结束，' + message })
      expect(w.find('[role=alertdialog]').exists()).toBe(false)
    })
  it.each(['86401', '-1', '01', '1.5'])('invalid hold=%s makes zero writes and stays open', async raw => {
    const { w } = await confirmation(url)
    await w.get('[role=alertdialog] input').setValue(raw)
    await w.get('[role=alertdialog] .danger').trigger('click'); await flushPromises()
    expect(calls('/api/attacks/1/expire')).toHaveLength(0)
    expect(w.get('[role=alertdialog]').text()).toContain('请输入 0–86400 的整数，或留空')
  })
  it('W5 method=db warns and 409 shows original error inline with confirmation open', async () => {
    const { w, intercept } = await confirmation(url)
    intercept(path => path.startsWith('/api/attacks/1/expire') ? response(200, { method: 'db', ok: true }) : undefined)
    await w.get('[role=alertdialog] .danger').trigger('click'); await flushPromises()
    expect(notifications.at(-1)).toMatchObject({ tone: 'warn',
      message: '攻击 #1 已结束，但未压制：该攻击不在实时检测中（例如 controller 重启后）' })
    w.unmount()
    const second = await confirmation(url)
    second.intercept(path => path.startsWith('/api/attacks/1/expire')
      ? response(409, { error: 'attack already expired' }) : undefined)
    await second.w.get('[role=alertdialog] .danger').trigger('click'); await flushPromises()
    expect(second.w.get('[role=alertdialog]').text()).toContain('attack already expired')
    expect(notifications.at(-1)).toMatchObject({ tone: 'crit', message: 'attack already expired' })
  })
  it('write result still appears after initiating route unmounts', async () => {
    const pending = deferred<Response>(), { w, router, intercept } = await confirmation(url)
    intercept(path => path.startsWith('/api/attacks/1/expire') ? pending.promise : undefined)
    await w.get('[role=alertdialog] .danger').trigger('click')
    await router.push('/elsewhere'); await flushPromises()
    pending.resolve(response(200, { method: 'tracker', ok: true })); await flushPromises()
    expect(w.text()).toContain('攻击 #1 已结束，已按全局设置请求压制')
  })
})
