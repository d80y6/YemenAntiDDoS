import { it, expect, vi } from 'vitest'
import { flushPromises } from '@vue/test-utils'
import { nextTick } from 'vue'
import { render, response } from './helpers'
import { state } from '../src/state'
import { i18n } from '../src/i18n'
import Inline from '../src/views/inline/Inline.vue'
import L7 from '../src/views/l7/L7.vue'

const now = new Date().toISOString()
const postureFixture = {
  'edge-a': {
    xdp_mode: 'inline', inline_enabled: true, filter_rules: 3, validated_clients: 2,
    syn_cookies_replied: 10, syn_cookies_validated: 8, syn_cookies_dropped: 1,
    emergency_drops: 4, burst_alerts: 7, redirect_ok: 99, redirect_err: 2,
    af_xdp_active: true, af_xdp_rx: 1234, af_xdp_umem_drops: 0,
    cpu_pins: [2, 3], cpu_util: [12.4, 3.6], cleanpipe_egress: 'eth1',
    updated_at: now,
  },
}
const recentEvent = {
  node_id: 'edge-a', type: 'l7_tls_anomaly', dst_ip: '198.51.100.9', at: now,
  detail: { handshakes: 900, missing_sni: 100 },
}
const l7Summary = {
  enabled: true, generated_at: now, window_minutes: 15, bucket_seconds: 60,
  totals: { l7_tls_anomaly: 1 }, rates_per_second: { l7_tls_anomaly: 0.1 },
  series: [{ at: now, http: 1, tls: 0, slowloris: 0 }],
  targets: [], sources: [], nodes: [], ja3: [], ja4: [], user_agents: [],
  recent: [recentEvent], dropped: 0,
}

function stubFetch() {
  vi.stubGlobal('fetch', vi.fn(async (raw: any) => {
    const path = String(raw)
    if (path.startsWith('/api/nodes/posture')) return response(200, postureFixture)
    if (path.startsWith('/api/inline/mitigations')) return response(200,
      { enabled: true, active: 1, pushes: 3, push_errors: 0, mitigations: null })
    if (path.startsWith('/api/l7/summary')) return response(200, l7Summary)
    if (path.startsWith('/api/l7/events')) return response(200, { events: [recentEvent] })
    return response(200, {})
  }))
  state.token = 'development'
  state.user = { id: 1, username: 'demo', role: 'admin' }
}

it('posture renders burst alerts, redirect rate and per-core CPU utilisation', async () => {
  stubFetch()
  const w = render(Inline, { attachTo: document.body })
  await flushPromises()

  const row = w.findAll('tbody tr').find(r => r.text().includes('edge-a'))
  expect(row, 'posture row for edge-a').toBeTruthy()
  const text = row!.text()
  expect(text).toContain(i18n.global.t('inline.alerts', { n: '7' }))
  expect(text).toContain(i18n.global.t('inline.redirect', { ok: '99', err: '2' }))
  expect(text).toContain('12% 4%')
  w.unmount()
})

it('L7 chart measures its width via ResizeObserver and renders type pills', async () => {
  stubFetch()
  vi.stubGlobal('ResizeObserver', class {
    private cb: (entries: unknown[]) => void
    constructor(cb: (entries: unknown[]) => void) { this.cb = cb }
    observe() { this.cb([{ contentRect: { width: 640 } }]) }
    disconnect() {}
  })
  const w = render(L7, { attachTo: document.body })
  await flushPromises()
  await nextTick()

  const svg = w.find('.chart-svg')
  expect(svg.exists()).toBe(true)
  expect(svg.attributes('width')).toBe('640')
  expect(w.find('span.pill').exists(),
    'XPill must be imported so recent-event types render as pills').toBe(true)
  w.unmount()
})
