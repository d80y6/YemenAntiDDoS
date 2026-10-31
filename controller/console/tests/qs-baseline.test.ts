import { expect, it } from 'vitest'
import { slotLabel } from '../src/views/baseline/data'
import { i18n } from '../src/i18n'
const days = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
const chinese = ['周一', '周二', '周三', '周四', '周五', '周六', '周日']
const slots = days.flatMap((day, d) => Array.from({ length: 24 }, (_, hour) => [false, true].map(latest => {
  const time = String(hour).padStart(2, '0') + ':00 UTC'
  return [day + ' ' + time + (latest ? ' (latest)' : ''),
    chinese[d] + ' ' + time + (latest ? '（最近有数据）' : '')]
})).flat())
it.each(slots)('K3 slot %s', (raw, expected) => {
  expect(slotLabel(raw!, key => i18n.global.t(key, {}, { locale: 'zh' }))).toBe(expected)
  expect(slotLabel(raw!, key => i18n.global.t(key, {}, { locale: 'en' }))).toBe(raw)
})
it.each(['slot_200', 'Funday 01:00 UTC', ''])('K3 unknown slot %s is unchanged', raw => {
  for (const locale of ['zh', 'en'] as const) {
    expect(slotLabel(raw, key => i18n.global.t(key, {}, { locale }))).toBe(raw)
  }
})
