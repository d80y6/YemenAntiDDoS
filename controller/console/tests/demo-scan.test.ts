import { expect, it } from 'vitest'
// @ts-expect-error Node built-ins run in Vitest; production tsconfig excludes Node globals.
import { resolve } from 'node:path'
import { literals, scanSources, scanData, scanValue } from '../demo/scan.mjs'

it('G2 data and source literals are safe across all backend GET routes', () => {
  expect(scanData()).toEqual({ endpoints: 50, failures: [] })
  expect(scanSources(resolve('demo'))).toEqual([])
})
it.each([
  '10.0.0.1', '172.16.5.5', '2400:cb00::1', 'https://evil.test/', '{"password":"hunter2"}',
  '[2400:cb00::1]:443', '::ffff:10.0.0.1', '10.0.0.1/24', 'Bearer sample-value',
  'https://reader:value@hooks.example.com/', '203.0.113.0/16',
])('G2 rejects %s', value => { expect(scanValue(value).length).toBeGreaterThan(0) })
it.each([
  '1.4.0', 'margin:1.2px; opacity:0.4', '12345678901234567890', '1.2.3.4.5',
  '203.0.113.10', '203.0.113.0/26', '[2001:db8::1]:443', '2001:db8:100::/48',
  'https://hooks.example.com/events', '{"Authorization":"******","token":"demo-session"}',
])('G2 accepts %s', value => { expect(scanValue(value)).toEqual([]) })
it('G2 recognizes compressed IPv6, CIDR, brackets and embedded IPv4 with full boundaries', () => {
  expect(literals('[2400:cb00::1]:443 2001:db8::/32 ::ffff:10.0.0.1'))
    .toEqual(expect.arrayContaining(['2400:cb00::1', '2001:db8::/32', '::ffff:10.0.0.1']))
  expect(literals('1.2.3.4.5 1.4.0 12345678')).toEqual([])
  expect(scanValue('0.0.0.0')).not.toEqual([])
  expect(scanValue({ listen_address: '0.0.0.0:6343' })).toEqual([])
})
