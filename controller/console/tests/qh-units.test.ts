import { expect, it } from 'vitest'
import { connectionTime, listenerBody, listenerForm, listenerRecords, listenerValidation, records,
  runtimeIP, sourceActive, sourceBody, sourceForm, sourceValidation } from '../src/views/flow/data'
import type { FlowStatus, Listener, Source } from '../src/views/flow/data'
const listener: Listener = { id: 7, node_id: 'flow-b', listen_address: ':2055', protocol_mode: 'ipfix',
  description: ' d ', enabled: false }
const source: Source = { id: 9, listener_id: 7, name: 'router', device_ip: '192.0.2.1/32', sample_mode: 'auto',
  sample_rate: 0, description: ' x ', enabled: false }
it('G-units listener new excludes enabled; edit four keys excludes node_id W1 W2', () => {
  const form = { ...listenerForm('flow-b', listener), listen_address: ' :6343 ' }
  expect(listenerBody(form)).toEqual({ node_id: 'flow-b', listen_address: ':6343',
    protocol_mode: 'ipfix', description: ' d ' })
  expect(listenerBody(form, listener)).toEqual({ listen_address: ':6343', protocol_mode: 'ipfix',
    description: ' d ', enabled: false })
})
it('G-units source new/edit six keys, trim only form, non-force rate W3 W5', () => {
  const form = { ...sourceForm(source), name: ' router ', device_ip: ' 192.0.2.1 ', sample_rate: 0 }
  expect(sourceBody(form, 7)).toEqual({ listener_id: 7, name: 'router', device_ip: '192.0.2.1',
    sample_mode: 'auto', sample_rate: 0, description: ' x ' })
  expect(sourceBody(form, 7, source)).toEqual({ name: 'router', device_ip: '192.0.2.1',
    sample_mode: 'auto', sample_rate: 0, description: ' x ', enabled: false })
  expect(sourceBody({ ...form, sample_mode: 'none', sample_rate: 27 }, 7, source).sample_rate).toBe(27)
})
it('G-units refill strips both prefixes and restores rate zero to 1000 W3 W6', () => {
  expect(sourceForm(source)).toEqual({ name: 'router', device_ip: '192.0.2.1', sample_mode: 'auto',
    sample_rate: 1000, description: ' x ', enabled: false })
  expect(sourceForm({ ...source, device_ip: '2001:db8::1/128' }).device_ip).toBe('2001:db8::1')
  expect(sourceForm()).toEqual({ name: '', device_ip: '', sample_mode: 'auto', sample_rate: 1000,
    description: '', enabled: true })
  expect(listenerForm('new')).toEqual({ node_id: 'new', listen_address: '', protocol_mode: 'auto',
    description: '', enabled: true })
})
it('G-units new CIDR is preserved for backend 400', () => {
  expect(sourceBody({ ...sourceForm(), name: 'router', device_ip: ' 192.0.2.1/32 ' }, 7).device_ip)
    .toBe('192.0.2.1/32')
})
it('G-units toggle retains listener original text and complete four keys W4 W30', () => {
  const row = { ...listener, listen_address: ' :2055' }
  expect(listenerBody({ ...listenerForm('ignored'), toggle: true, enabled: true }, row))
    .toEqual({ listen_address: ' :2055', protocol_mode: 'ipfix', description: ' d ', enabled: true })
})
it.each([' ', ' router '])('G-units toggle source original text %j, zero and six keys W4 W28 W30', name => {
  const row = { ...source, name }
  expect(sourceBody({ ...sourceForm(), toggle: true, enabled: true }, 999, row))
    .toEqual({ name, device_ip: '192.0.2.1', sample_mode: 'auto', sample_rate: 0,
      description: ' x ', enabled: true })
  expect(sourceBody({ ...sourceForm(), toggle: true }, 7, { ...row, device_ip: '2001:db8::1/128' }).device_ip)
    .toBe('2001:db8::1')
})
it('G-units required validation order; no approximate address validation', () => {
  expect(listenerValidation({ ...listenerForm('b'), listen_address: ' ' })).toBe('flow.needAddress')
  expect(listenerValidation({ ...listenerForm('b'), listen_address: '16343' })).toBe('')
  expect(sourceValidation(sourceForm())).toBe('flow.needName')
  expect(sourceValidation({ ...sourceForm(), name: 'router', device_ip: ' ' })).toBe('flow.needIP')
  expect(sourceValidation({ ...sourceForm(), name: 'router', device_ip: 'invalid' })).toBe('')
})
it.each([
  ['192.0.2.1/32', '192.0.2.1'], ['2001:db8::1/128', '2001:db8::1'],
  ['::ffff:192.0.2.1/128', '192.0.2.1'], ['::FFFF:192.0.2.1', '192.0.2.1'],
  ['::192.0.2.1/128', '::c000:201'], ['2001:db8::c000:201/128', '2001:db8::c000:201'],
  ['::0.0.0.2/128', '::2'], ['::1.0.0.0/128', '::100:0'], ['::0.0.0.0/128', '::'],
])('G-units runtime source %s -> %s W7 W26 W31', (ip, reported) => {
  expect(runtimeIP(ip)).toBe(reported)
  expect(sourceActive({ ...source, device_ip: ip }, { online: true,
    source_statuses: [{ device_ip: reported, active: true }] })).toBe(true)
})
it('G-units runtime exact address matching and unknown/false distinction W7', () => {
  const status: FlowStatus = { online: true, listener_statuses: [
    { listen_addr: '0.0.0.0:2055', records_decoded: 55 }, { listen_addr: ':2055', records_decoded: 99 },
  ], source_statuses: [{ device_ip: '192.0.2.10', active: true }, { device_ip: '192.0.2.1', active: false }] }
  expect(listenerRecords(listener, status)).toBe(99)
  expect(listenerRecords({ ...listener, listen_address: ':205' }, status)).toBeUndefined()
  expect(listenerRecords(listener, { online: false,
    listener_statuses: [{ listen_addr: '0.0.0.0:2055', records_decoded: 55 }] })).toBeUndefined()
  expect(sourceActive(source, status)).toBe(false)
  expect(sourceActive(source, { online: true,
    source_statuses: [{ device_ip: '192.0.2.10', active: true }] })).toBeUndefined()
})
it.each([[undefined, '—'], [999, '999'], [1000, '1.0K'], [18432117, '18.4M']] as const)(
  'G-units record abbreviation %s -> %s', (input, expected) => expect(records(input)).toBe(expected))
it.each([[59, '59s'], [61, '1m'], [10800, '3h 0m'], [274320, '3d 4h 12m']] as const)(
  'G-units connection duration %s -> %s', (input, expected) => expect(connectionTime(input)).toBe(expected))
