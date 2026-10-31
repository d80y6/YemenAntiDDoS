import { expect, it } from 'vitest'
import { mountQE, clock } from './qe-harness'
import XListbox from '../src/components/XListbox.vue'
import DecoderPicker from '../src/components/chart/DecoderPicker.vue'
import { render } from './helpers'
import { state } from '../src/state'
it('K5 traffic node labels preserve IDs, modes and offline entries', async () => {
  clock()
  const { w } = await mountQE('/traffic', undefined, true, 'normal')
  expect(w.findAllComponents(XListbox)[0]!.props('options').slice(1)).toEqual([
    { value: 'edge-a', label: 'edge-a · XDP' },
    { value: 'flow-b', label: 'flow-b · FLOW（离线）' },
    { value: 'edge-c', label: 'edge-c · XDP' },
  ])
})
it.each([['zh', '解码器'], ['en', 'Decoders']] as const)('K7 decoder label %s', (locale, label) => {
  state.locale = locale
  expect(render(DecoderPicker).get('.decoder-picker > button').text()).toBe(label)
})
it.each([[false, '查看'], [true, '编辑']] as const)('K7 template link admin=%s', async (admin, label) => {
  const { w } = await mountQE('/thresholds', undefined, admin)
  const links = w.findAll('tbody tr a')
  expect(links.length).toBeGreaterThan(0)
  links.forEach(link => {
    expect(link.text()).toBe(label)
    expect(link.attributes('href')).toBe('/thresholds/' + link.element.closest('tr')!.querySelector('td')!.textContent)
  })
})
