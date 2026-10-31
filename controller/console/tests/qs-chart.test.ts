import { expect, it } from 'vitest'
import { nextTick, defineComponent, h } from 'vue'
import { render } from './helpers'
import { pointer } from './pointer'
import XChart from '../src/components/chart/XChart.vue'
const point = (time: number) => ({ time, values: { tcp: time / 1000 + 1 } })
const props = () => ({ points: [point(10000), point(0), point(5000)], bounds: [0, 10000] as [number, number],
  selected: ['tcp'], slots: { tcp: 1 } })
async function key(w: any, value: string) {
  const event = new KeyboardEvent('keydown', { key: value, bubbles: true, cancelable: true })
  w.get('svg').element.dispatchEvent(event)
  await nextTick()
  return event.defaultPrevented
}
function readout(w: any, value: number, cx: string) {
  expect(w.get('.chart-tip').text()).toContain(`tcp: ${value} pps`)
  expect(w.get('.hover-mark').attributes('cx')).toBe(cx)
  expect(w.get('.sr-only[role=status]').text())
    .toBe(w.findAll('.chart-tip > div').map((d: any) => d.text()).join(' '))
}
it('K1 focus, sorted navigation, initial arrows, clear and instance hints', async () => {
  const host = render(defineComponent({ setup: () => () => [h(XChart, props()),
    h(XChart, { ...props(), zoomable: true })] }), { attachTo: document.body })
  const [w, second] = host.findAllComponents(XChart) as [any, any]
  expect(w.get('svg').attributes('tabindex')).toBe('0')
  const id = w.get('svg').attributes('aria-describedby')
  expect(w.get('#' + id).text()).toContain('Home / End')
  expect(second.get('svg').attributes('aria-describedby')).not.toBe(id)
  expect(second.findAll('.sr-only')[0]!.text()).toContain('Enter')
  expect(w.get('svg').attributes('aria-label')).toBe('趋势图')
  for (const first of ['ArrowLeft', 'ArrowRight']) {
    expect(await key(w, first)).toBe(true); readout(w, 11, '592')
    expect(await key(w, 'Escape')).toBe(true)
    expect(w.find('.chart-tip').exists()).toBe(false)
  }
  expect(await key(w, 'Home')).toBe(true); readout(w, 1, '44')
  await key(w, 'ArrowRight'); readout(w, 6, '318')
  await key(w, 'ArrowLeft'); readout(w, 1, '44')
  await key(w, 'ArrowRight'); await key(w, 'ArrowRight'); readout(w, 11, '592')
  await key(w, 'Home'); await key(w, 'End'); readout(w, 11, '592')
  await w.get('svg').trigger('blur')
  expect(w.find('.chart-tip').exists()).toBe(false)
  expect(w.get('.sr-only[role=status]').text()).toBe('')
})
it.each([{ points: [] }, { error: 'failed' }, { loading: true }, { selected: [] }])(
  'K1 non-chart state %j has no focus or keyboard status', override => {
    const w = render(XChart, { props: { ...props(), ...override } })
    expect(w.find('svg').exists()).toBe(false)
    expect(w.find('[tabindex]').exists()).toBe(false)
    expect(w.findAll('.sr-only')).toHaveLength(0)
  },
)
it('K1 pointer hover never writes the status', async () => {
  const w = render(XChart, { props: props() })
  await pointer(w.get('svg').element, 'pointermove', 318)
  expect(w.get('.chart-tip').text()).toContain('tcp: 6 pps')
  expect(w.get('.sr-only[role=status]').text()).toBe('')
  await key(w, 'Home')
  const spoken = w.get('.sr-only[role=status]').text()
  await pointer(w.get('svg').element, 'pointermove', 592)
  expect(w.get('.sr-only[role=status]').text()).toBe(spoken)
})
it('K1 Enter selection shares two-point minimum, shows a band and cancels on blur or Escape', async () => {
  const w = render(XChart, { props: { ...props(), zoomable: true }, attachTo: document.body })
  await key(w, 'Enter')
  expect(w.findAll('rect.band')).toHaveLength(0)
  await key(w, 'Home'); await key(w, 'Enter')
  expect(w.findAll('rect.band')).toHaveLength(1)
  await key(w, 'Enter')
  expect(w.emitted('update:window')).toBeUndefined()
  await key(w, 'Enter'); await key(w, 'ArrowRight'); await key(w, 'Enter')
  expect(w.emitted('update:window')).toEqual([[[0, 5000]]])
  expect(w.findAll('rect.band')).toHaveLength(0)
  await key(w, 'Enter'); await key(w, 'End'); await key(w, 'Escape')
  expect(w.findAll('rect.band')).toHaveLength(0)
  expect(w.find('.chart-tip').exists()).toBe(true)
  await key(w, 'Enter'); await w.get('svg').trigger('blur')
  expect(w.findAll('rect.band')).toHaveLength(0)
  await key(w, 'Home'); await key(w, 'Enter')
  expect(w.emitted('update:window')).toHaveLength(1)
})
it('K1 read-only Enter never emits; pointer drag survives blur and toolbar remains three buttons', async () => {
  const w = render(XChart, { props: props() })
  await key(w, 'Home'); await key(w, 'Enter'); await key(w, 'End'); await key(w, 'Enter')
  expect(w.emitted('update:window')).toBeUndefined()
  await w.setProps({ zoomable: true, window: [0, 10000] })
  expect(w.findAll('button')).toHaveLength(3)
  await pointer(w.get('svg').element, 'pointerdown', 44)
  await w.get('svg').trigger('blur')
  await pointer(w.get('svg').element, 'pointerup', 318)
  expect(w.emitted('update:window')).toEqual([[[0, 5000]]])
})
