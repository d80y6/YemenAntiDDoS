<script setup lang="ts">
import { ref, shallowRef, onMounted, onUnmounted, computed, type ShallowRef, type ComputedRef } from 'vue'
import { useI18n } from 'vue-i18n'
import { request } from '../../api/client'
import { usePoll } from '../../composables/usePoll'
import { thousands, fullDateTime, dateTime } from '../../format'
import XKpi from '../../components/XKpi.vue'
import XTip from '../../components/XTip.vue'
import XEmpty from '../../components/XEmpty.vue'

const { t } = useI18n()

interface L7Event {
  node_id: string
  type: 'l7_http_flood' | 'l7_tls_anomaly' | 'l7_slowloris'
  dst_ip: string
  at: string
  interface?: string
  detail: {
    requests?: number; methods?: string[]; paths?: string[]
    handshakes?: number; snis?: string[]; missing_sni?: number
    connections?: number; unique_sources?: number; sample_sources?: string[]
    window_seconds?: number; alert_threshold?: number
  }
}

interface L7Summary {
  enabled: boolean
  generated_at: string
  window_minutes: number
  bucket_seconds: number
  totals: Record<string, number>
  rates_per_second: Record<string, number>
  series: { at: string; http: number; tls: number; slowloris: number }[]
  targets: { dst_ip: string; http: number; tls: number; slowloris: number; total: number; last_at: string }[]
  sources: { label: string; count: number }[]
  nodes: { label: string; count: number }[]
  recent: L7Event[]
  dropped: number
}

const summary: ShallowRef<L7Summary> = shallowRef({
  enabled: false, generated_at: '', window_minutes: 15, bucket_seconds: 60,
  totals: {}, rates_per_second: {}, series: [], targets: [], sources: [], nodes: [], recent: [], dropped: 0
})
const events = shallowRef<L7Event[]>([])
const loading = ref(true)
const error = ref<string>()

const windowMinutes = ref(15)
const abortCtrl = new AbortController()

function fetchSummary() {
  request<L7Summary>(`/api/l7/summary?window_minutes=${windowMinutes.value}`, { signal: abortCtrl.signal })
    .then(r => { summary.value = r; error.value = '' })
    .catch(e => { if (!abortCtrl.signal.aborted) error.value = e instanceof Error ? e.message : String(e) })
    .finally(() => { loading.value = false })
}

function fetchEvents() {
  request<{ events: L7Event[]; buffered: number; total_dropped: number }>(
    `/api/l7/events?limit=100`, { signal: abortCtrl.signal })
    .then(r => { events.value = r.events })
    .catch(e => { if (!abortCtrl.signal.aborted) console.warn('l7 events fetch', e) })
}

usePoll(
  async () => { await fetchSummary(); await fetchEvents() },
  5000,
  () => {}, () => {}
)

onUnmounted(() => { abortCtrl.abort() })

function setWindow(m: number) { windowMinutes.value = m; fetchSummary() }

const totals: ComputedRef<Record<string, number>> = computed(() => summary.value.totals ?? {})
const rates: ComputedRef<Record<string, number>> = computed(() => summary.value.rates_per_second ?? {})
const series: ComputedRef<L7Summary['series']> = computed(() => summary.value.series ?? [])
const targets: ComputedRef<L7Summary['targets']> = computed(() => summary.value.targets ?? [])
const sources: ComputedRef<L7Summary['sources']> = computed(() => summary.value.sources ?? [])
const nodes: ComputedRef<L7Summary['nodes']> = computed(() => summary.value.nodes ?? [])
const recent: ComputedRef<L7Event[]> = computed(() => summary.value.recent ?? [])
const dropped: ComputedRef<number> = computed(() => summary.value.dropped ?? 0)

function typeLabel(evType: string) {
  if (evType === 'l7_http_flood') return t('l7.type.http')
  if (evType === 'l7_tls_anomaly') return t('l7.type.tls')
  if (evType === 'l7_slowloris') return t('l7.type.slowloris')
  return evType
}
function typeTone(evType: string) {
  if (evType === 'l7_http_flood') return 'http'
  if (evType === 'l7_tls_anomaly') return 'tls'
  return 'slowloris'
}

function formatDetail(d: L7Event['detail']) {
  if (d.requests !== undefined) {
    const parts = [`${d.requests} req`]
    if (d.methods?.length) parts.push(d.methods.slice(0, 3).join(', ') + (d.methods.length > 3 ? ` +${d.methods.length - 3}` : ''))
    if (d.paths?.length) parts.push(d.paths.slice(0, 3).join(', ') + (d.paths.length > 3 ? ` +${d.paths.length - 3}` : ''))
    return parts.join(' · ')
  }
  if (d.connections !== undefined) {
    return `${d.connections} conns · ${d.unique_sources ?? 0} srcs`
  }
  if (d.handshakes !== undefined) {
    const parts = [`${d.handshakes} hs`]
    if (d.missing_sni) parts.push(t('l7.detail.missingSni', { n: d.missing_sni }))
    if (d.snis?.length) parts.push(d.snis.slice(0, 3).join(', ') + (d.snis.length > 3 ? ` +${d.snis.length - 3}` : ''))
    return parts.join(' · ')
  }
  return '—'
}

const chartWidth = ref(0), chartHeight = 200
const hover = ref<number | null>(null)

const maxVal = computed(() => {
  const s = series.value
  if (!s.length) return 1
  let m = 0
  for (const p of s) m = Math.max(m, p.http + p.tls + p.slowloris)
  return m || 1
})
const stepVal = computed(() => {
  const m = maxVal.value
  const step = Math.pow(10, Math.floor(Math.log10(m / 4)))
  const n = Math.ceil(m / step)
  return step * Math.ceil(n / 4)
})
const ceiling = computed(() => maxVal.value === 0 ? 1 : stepVal.value * 4)

function x(time: number) {
  if (!chartWidth.value) return 44
  const sp = series.value
  if (!sp.length) return 44
  const first = Date.parse(sp[0].at)
  const last = Date.parse(sp[sp.length - 1].at)
  if (!isFinite(first) || !isFinite(last) || last <= first) return 44
  return 44 + (time - first) / (last - first) * (chartWidth.value - 52)
}
function y(val: number) { return chartHeight - 20 - val / ceiling.value * (chartHeight - 28) }
function xLabel(time: number) { return new Date(time).toLocaleTimeString([], { hour12: false, hour: '2-digit', minute: '2-digit' }) }

function barRects(p: { at: string; http: number; tls: number; slowloris: number }, idx: number) {
  const ts = Date.parse(p.at)
  if (!isFinite(ts)) return []
  const w = series.value.length > 1 ? Math.max(10, (chartWidth.value - 52) / series.value.length * 0.7) : 30
  const x0 = x(ts) - w / 2
  const rects = []
  let base = chartHeight - 20
  for (const { val, cls, label } of [
    { val: p.slowloris, cls: 'slowloris', label: t('l7.chart.slowloris') },
    { val: p.tls, cls: 'tls', label: t('l7.chart.tls') },
    { val: p.http, cls: 'http', label: t('l7.chart.http') }
  ]) {
    if (val > 0) {
      const h = val / ceiling.value * (chartHeight - 28)
      const y0 = base - h
      rects.push({ x: x0, y: y0, w, h, cls, label: `${label}: ${val}` })
      base = y0
    }
  }
  return rects
}

function move(e: MouseEvent) {
  const host = (e.currentTarget as HTMLElement)
  const box = host.getBoundingClientRect()
  const px = Math.max(44, Math.min(chartWidth.value - 8, e.clientX - box.left))
  const sp = series.value
  if (!sp.length) return
  const first = Date.parse(sp[0].at)
  const last = Date.parse(sp[sp.length - 1].at)
  if (!isFinite(first) || !isFinite(last) || last <= first) return
  hover.value = first + (px - 44) / (chartWidth.value - 52) * (last - first)
}

function start(e: MouseEvent) {
  if (e.button !== 0) return
  move(e)
}

function showTarget(t: { dst_ip: string }) {
  console.log('target selected', t.dst_ip)
}

const seriesColor = (p: { http: number; tls: number; slowloris: number }) => {
  if (p.http >= p.tls && p.http >= p.slowloris) return 'var(--l7-http)'
  if (p.tls >= p.slowloris) return 'var(--l7-tls)'
  return 'var(--l7-slowloris)'
}

const LIMIT_3 = (arr?: string[]) => arr ? (arr.length > 3 ? arr.slice(0, 3).join(', ') + ` +${arr.length - 3}` : arr.join(', ')) : '—'
</script>
<template>
  <div class="page l7-page">
    <div class="page-head">
      <h1>{{ t('l7.title') }}
        <span class="sub" v-if="summary.generated_at">
          {{ t('l7.subtitle', { time: fullDateTime(summary.generated_at).slice(11) }) }}</span>
      </h1>
      <div class="window-selector">
        <label>{{ t('l7.window') }}</label>
        <select v-model.number="windowMinutes" @change="setWindow(windowMinutes)">
          <option :value="5">{{ t('l7.window.5') }}</option>
          <option :value="15">{{ t('l7.window.15') }}</option>
          <option :value="60">{{ t('l7.window.60') }}</option>
        </select>
      </div>
    </div>

    <p v-if="loading" class="sub">{{ t('l7.loading') }}</p>
    <p v-else-if="error" class="crit mono" role="alert">{{ error }}</p>

    <section v-else-if="!summary.enabled" class="panel disabled">
      <h2>{{ t('l7.disabledTitle') }}</h2>
      <p>{{ t('l7.disabledDesc') }}</p>
    </section>

    <template v-else>
      <section class="panel kpis">
        <XKpi :label="t('l7.kpi.http')" :value="thousands(totals['l7_http_flood'] ?? 0)" :sub="t('l7.perSecond', { n: (rates['l7_http_flood'] ?? 0).toFixed(1) })" />
        <XKpi :label="t('l7.kpi.slowloris')" :value="thousands(totals['l7_slowloris'] ?? 0)" :sub="t('l7.perSecond', { n: (rates['l7_slowloris'] ?? 0).toFixed(1) })" />
        <XKpi :label="t('l7.kpi.tls')" :value="thousands(totals['l7_tls_anomaly'] ?? 0)" :sub="t('l7.perSecond', { n: (rates['l7_tls_anomaly'] ?? 0).toFixed(1) })" />
        <XKpi :label="t('l7.kpi.targets')" :value="thousands(targets.length)" />
      </section>

      <section class="panel chart-panel">
        <div class="panel-head"><h2>{{ t('l7.chart.title') }}</h2>
          <div class="legend" role="img" :aria-label="t('l7.chart.legend')">
            <span class="swatch http" :title="t('l7.chart.http')"></span>{{ t('l7.chart.http') }}
            <span class="swatch tls" :title="t('l7.chart.tls')"></span>{{ t('l7.chart.tls') }}
            <span class="swatch slowloris" :title="t('l7.chart.slowloris')"></span>{{ t('l7.chart.slowloris') }}
          </div></div>
        <div class="chart-wrap" ref="chartHost" @mousemove="move" @mouseleave="hover = null" @mousedown="start">
          <svg :width="chartWidth" :height="chartHeight" class="chart-svg">
            <rect x="44" y="0" :width="chartWidth - 52" :height="chartHeight - 20" fill="none" />
            <g v-for="(p, idx) in series" :key="idx">
              <g v-for="r in barRects(p, idx)" :key="r.x + '_' + r.y">
                <rect :x="r.x" :y="r.y" :width="r.w" :height="r.h" :class="['bar', r.cls]" :title="r.label" />
              </g>
            </g>
            <g class="y-axis">
              <line x1="44" y1="0" x2="44" :y2="chartHeight - 20" stroke="var(--line)" />
              <g v-for="i in 4" :key="i">
                <line x1="44" :y1="y(i * stepVal)" x2="40" :y2="y(i * stepVal)" stroke="var(--line)" />
                <text x="38" :y="y(i * stepVal) + 4" text-anchor="end" font-size="11" fill="var(--text-muted)">{{ thousands(i * stepVal) }}</text>
              </g>
            </g>
            <g class="x-axis">
              <line x1="44" :y1="chartHeight - 20" :x2="chartWidth - 8" y2="chartHeight - 20" stroke="var(--line)" />
              <g v-for="(p, idx) in series" :key="idx">
                <text :x="x(Date.parse(p.at))" :y="chartHeight - 4" text-anchor="middle" font-size="11" fill="var(--text-muted)" :transform="idx % 3 !== 0 ? 'scale(0.001,1)' : ''">{{ xLabel(Date.parse(p.at)) }}</text>
              </g>
            </g>
            <rect v-if="hover !== null" :x="x(hover)" y="0" width="1" :height="chartHeight - 20" fill="var(--text-muted)" opacity="0.3" />
          </svg>
          <div v-if="hover !== null" class="chart-hint">
            <div class="time">{{ fullDateTime(new Date(hover).toISOString()).slice(11) }}</div>
            <template v-for="p in series" :key="p.at">
              <div v-if="Math.abs(Date.parse(p.at) - hover) < 31000" class="series" :style="{ color: seriesColor(p) }">
                {{ t('l7.chart.http') }}: {{ thousands(p.http) }} · {{ t('l7.chart.tls') }}: {{ thousands(p.tls) }} · {{ t('l7.chart.slowloris') }}: {{ thousands(p.slowloris) }}
              </div>
            </template>
          </div>
        </div>
        <p v-if="dropped" class="sub dropped">{{ t('l7.dropped', { n: thousands(dropped) }) }}</p>
      </section>

      <section class="panel">
        <div class="panel-head"><h2>{{ t('l7.targets.title') }}</h2></div>
        <div class="tbl-wrap">
          <table><thead><tr>
            <th>{{ t('l7.col.target') }}</th><th>{{ t('l7.col.http') }}</th><th>{{ t('l7.col.tls') }}</th>
            <th>{{ t('l7.col.slowloris') }}</th><th>{{ t('l7.col.total') }}</th><th>{{ t('l7.col.lastSeen') }}</th>
          </tr></thead><tbody>
            <tr v-for="t in targets" :key="t.dst_ip" class="link" @click="showTarget(t)">
              <td class="mono strong">{{ t.dst_ip }}</td>
              <td class="num">{{ thousands(t.http) }}</td><td class="num">{{ thousands(t.tls) }}</td>
              <td class="num">{{ thousands(t.slowloris) }}</td>
              <td class="num strong">{{ thousands(t.total) }}</td>
              <td class="sub">{{ dateTime(t.last_at).slice(6) }}</td>
            </tr>
          </tbody></table>
          <XEmpty v-if="!targets.length" :label="t('l7.empty')" />
        </div>
      </section>

      <section class="panel">
        <div class="panel-head"><h2>{{ t('l7.sources.title') }}</h2></div>
        <ul class="kv-list">
          <li v-for="s in sources" :key="s.label">{{ s.label }} <span class="num">{{ thousands(s.count) }}</span></li>
        </ul>
        <XEmpty v-if="!sources.length" :label="t('l7.empty')" />
      </section>

      <section class="panel">
        <div class="panel-head"><h2>{{ t('l7.nodes.title') }}</h2></div>
        <ul class="kv-list">
          <li v-for="n in nodes" :key="n.label">{{ n.label }} <span class="num">{{ thousands(n.count) }}</span></li>
        </ul>
        <XEmpty v-if="!nodes.length" :label="t('l7.empty')" />
      </section>

      <section class="panel">
        <div class="panel-head"><h2>{{ t('l7.recent.title') }}</h2></div>
        <div class="tbl-wrap">
          <table><thead><tr>
            <th>{{ t('l7.col.time') }}</th><th>{{ t('l7.col.node') }}</th><th>{{ t('l7.col.type') }}</th>
            <th>{{ t('l7.col.detail') }}</th>
          </tr></thead><tbody>
            <tr v-for="e in recent" :key="e.at + e.node_id + e.dst_ip">
              <td class="sub">{{ dateTime(e.at).slice(11) }}</td>
              <td>{{ e.node_id }}</td>
              <td><XPill :tone="typeTone(e.type)">{{ typeLabel(e.type) }}</XPill></td>
              <td class="mono">{{ formatDetail(e.detail) }}</td>
            </tr>
          </tbody></table>
          <XEmpty v-if="!recent.length" :label="t('l7.empty')" />
        </div>
      </section>
    </template>
  </div>
</template>
<style scoped>
.page-head { display: flex; justify-content: space-between; align-items: center; gap: 12px; margin-bottom: 16px; }
.window-selector select { margin-left: 8px; padding: 4px 8px; border: 1px solid var(--line); border-radius: 4px; background: var(--bg); color: var(--text); }
.kpis { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 12px; }
.chart-panel { position: relative; }
.chart-wrap { position: relative; min-height: 220px; }
.chart-svg { width: 100%; height: 200px; }
.bar { rx: 2; transition: opacity 0.1s; }
.bar.http { fill: var(--l7-http); }
.bar.tls { fill: var(--l7-tls); }
.bar.slowloris { fill: var(--l7-slowloris); }
.legend { display: flex; gap: 16px; font-size: 12px; align-items: center; }
.swatch { display: inline-block; width: 12px; height: 12px; border-radius: 2px; margin-right: 6px; }
.swatch.http { background: var(--l7-http); }
.swatch.tls { background: var(--l7-tls); }
.swatch.slowloris { background: var(--l7-slowloris); }
.chart-hint { position: absolute; top: 8px; left: 48px; background: var(--bg-elev); border: 1px solid var(--line); border-radius: 4px; padding: 6px 10px; font-size: 12px; pointer-events: none; z-index: 10; }
.dropped { margin-top: 8px; color: var(--text-muted); }
.panel { margin-top: 16px; }
.tbl-wrap { overflow-x: auto; }
table { width: 100%; border-collapse: collapse; }
th, td { padding: 8px 10px; text-align: left; border-bottom: 1px solid var(--line); }
th { font-weight: 600; font-size: 12px; color: var(--text-muted); background: var(--bg); position: sticky; top: 0; }
.num { text-align: right; font-variant-numeric: tabular-nums; }
.mono { font-family: var(--font-num); }
.strong { font-weight: 600; }
.link:hover td { background: var(--bg-elev); }
.kv-list { list-style: none; padding: 0; margin: 0; display: grid; grid-template-columns: repeat(auto-fill, minmax(240px, 1fr)); gap: 8px; }
.kv-list li { display: flex; justify-content: space-between; padding: 6px 10px; background: var(--bg-elev); border-radius: 4px; border: 1px solid var(--line); }
.disabled { padding: 20px; text-align: center; color: var(--text-muted); }
.disabled h2 { margin-bottom: 8px; color: var(--text); }
</style>