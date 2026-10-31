import { expect, it } from 'vitest'
import { flushPromises } from '@vue/test-utils'
import { mountQE, calls } from './qe-harness'
import { response } from './helpers'
import { i18n } from '../src/i18n'
import { actions, entityTypes, entityLabel, actionLabel } from '../src/views/audit/data'
const query = () => new URL(String(calls('/api/audit-log').at(-1)![0]), 'http://localhost').searchParams
it.each(['zh', 'en'] as const)('K4 complete entity and action labels in %s with unknown fallback', locale => {
  const t = (key: string) => i18n.global.t(key, {}, { locale })
  expect(entityTypes).toHaveLength(19)
  expect(actions).toHaveLength(7)
  for (const [values, label, group] of [[entityTypes, entityLabel, 'entity'], [actions, actionLabel, 'op']] as const) {
    for (const value of values) {
      expect(i18n.global.te('audit.' + group + '.' + value, locale)).toBe(true)
      expect(label(value, t).trim().length).toBeGreaterThan(0)
    }
  }
  expect(entityLabel('webhook', t)).toBe('webhook')
  expect(actionLabel('future_op', t)).toBe('future_op')
})
it('K4 selected option sends raw entity value', async () => {
  await mountQE('/audit', undefined, true, 'qi')
  document.querySelector<HTMLButtonElement>('button[aria-label^="实体类型:"]')!.click()
  await flushPromises()
  const option = [...document.querySelectorAll<HTMLButtonElement>('[role=option]')]
    .find(button => button.textContent?.trim() === '前缀')!
  option.click()
  await flushPromises()
  expect(query().get('entity_type')).toBe('watch_prefix')
})
it.each([
  ['watch_prefix', 'Enter', 'watch_prefix'], ['前缀', 'blur', 'watch_prefix'],
  ['Prefix', 'blur', 'watch_prefix'], ['前', 'Enter', '前'],
])('K4 free text %s with %s sends %s', async (value, event, expected) => {
  await mountQE('/audit', undefined, true, 'qi')
  document.querySelector<HTMLButtonElement>('button[aria-label^="实体类型:"]')!.click()
  await flushPromises()
  const input = document.querySelector<HTMLInputElement>('input[role=combobox]')!
  input.value = value
  input.dispatchEvent(new Event('input', { bubbles: true }))
  await flushPromises()
  input.dispatchEvent(event === 'blur' ? new Event('blur')
    : new KeyboardEvent('keydown', { key: 'Enter', bubbles: true }))
  await flushPromises()
  expect(query().get('entity_type')).toBe(expected)
})
it('K4 raw titles, raw action tones and unknown row text', async () => {
  const entries = [...actions, 'future_op'].map((action, i) => ({ id: i + 1, user_id: null,
    entity_type: i === 7 ? 'webhook' : 'user', entity_id: '1', action,
    diff: null, delivery_version: null, created_at: '2026-10-31T00:00:00Z' }))
  const { w } = await mountQE('/audit', path => path.startsWith('/api/audit-log')
    ? response(200, entries) : undefined, true, 'qi')
  const rows = w.findAll('tbody tr')
  const tones = ['ok', 'warn', 'crit', 'neutral', 'neutral', 'neutral', 'neutral', 'neutral']
  rows.forEach((row, i) => {
    expect(row.findAll('td')[2]!.attributes('title')).toBe(entries[i]!.entity_type)
    expect(row.get('.pill').attributes('title')).toBe(entries[i]!.action)
    expect(row.get('.pill').classes()).toContain(tones[i])
  })
  expect(rows[7]!.findAll('td')[2]!.text()).toBe('webhook')
  expect(rows[7]!.get('.pill').text()).toBe('future_op')
})
