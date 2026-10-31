<script setup lang="ts">
import { computed, reactive, ref } from 'vue'
import { useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'
import XKpi from '../../components/XKpi.vue'
import XTable from '../../components/XTable.vue'
import XEmpty from '../../components/XEmpty.vue'
import XSeg from '../../components/XSeg.vue'
import XPill from '../../components/XPill.vue'
import XChart from '../../components/chart/XChart.vue'
import DecoderPicker from '../../components/chart/DecoderPicker.vue'
import { selection, initSelection } from '../../components/chart/selection'
import { pps, bps, thousands, duration } from '../../format'
import { useData, grain, held, attackRate } from './data'
import { normalize, type Attack } from '../../api/data'
import '../../styles/pages.css'
const { t } = useI18n(), router = useRouter()
initSelection()
const filters = reactive({ range: '15m', node: '', prefix: '', direction: 'receives', limit: '5' })
const d = useData(filters, true)
const fast = computed(() => d.fast.data.value), history = computed(() => d.history.data.value)
const ranges = ['15m', '1h', '6h', '24h'].map(value => ({ value, label: value }))
const rows = computed(() => [...(fast.value.active.attacks ?? []), ...history.value.expired]
  .filter((a, i, all) => all.findIndex(b => b.id === a.id) === i))
const columns = computed(() => ['dst_ip', 'attack_type', 'pps', 'mitigation', 'status']
  .map(key => ({ key, label: t('data.' + key) })))
const nodeColumns = computed(() => ['id', 'mode', 'online', 'pps', 'bps', 'config', 'heartbeat']
  .map(key => ({ key, label: t('data.' + key) })))
const topColumns = computed(() => ['prefix', 'name', 'pps', 'bps', 'share']
  .map(key => ({ key, label: t('data.' + key), heat: key === 'share' })))
const top = computed(() => (fast.value.incoming.top_prefixes ?? []).map(p => ({ ...p,
  name: d.prefixes.data.value.find(n => n.prefix === p.prefix)?.name || '—',
  share: fast.value.incoming.total_pps ? p.pps / fast.value.incoming.total_pps * 100 : 0,
})))
const nodeRows = computed(() => d.nodes.data.value.map(n => ({ ...n,
  ...Object.fromEntries(['pps', 'bps'].map(key => [key,
    fast.value.incoming.nodes?.find(v => v.id === n.id)?.[key as 'pps' | 'bps']])),
})))
const actionTip = (kind: 'bgp' | 'xdrop') => {
  const rows = held(fast.value[kind], kind === 'xdrop')
  return t('data.actionCounts', { active: rows.filter(a => a.status === 'active').length,
    delayed: rows.filter(a => a.status === 'delayed').length })
    + (kind === 'xdrop' ? ' · ' + t('data.ruleRecords') : '')
}
const brief = (row: Record<string, unknown>) => row.ended_at ? history.value.brief[String(row.id)]
  : fast.value.brief[String(row.id)]
const peak = (row: Record<string, unknown>) => `${t('data.peak')}: ${pps(Number(row.peak_pps))} pps / ${
  row.peak_bps ? bps(Number(row.peak_bps)) : '—'}`
const time = (stamp: string | number) => new Date(stamp).toLocaleTimeString([], { hour12: false })
const rate = (row: Record<string, unknown>) => attackRate(row as Attack, fast.value.active)
const defaults = ['pps', 'attacks', 'bps', 'top']
const layout = reactive({ order: [...defaults], ratio: 55 })
try {
  const stored = JSON.parse(localStorage.getItem('xs-ov-layout') || 'null')
  if (stored && stored.order?.length === 4 && new Set(stored.order).size === 4
    && stored.order.every((v: string) => defaults.includes(v))) layout.order = stored.order
  if (stored && Number.isFinite(stored.ratio)) layout.ratio = Math.max(30, Math.min(78, stored.ratio))
} catch { /* Retain default layout. */ }
const grid = ref<HTMLElement>(), dragging = ref('')
function persist() { localStorage.setItem('xs-ov-layout', JSON.stringify(layout)) }
function drop(target: string) {
  const a = layout.order.indexOf(dragging.value), b = layout.order.indexOf(target)
  if (a >= 0 && b >= 0) [layout.order[a], layout.order[b]] = [layout.order[b]!, layout.order[a]!]
  dragging.value = ''; persist()
}
function ratio(value: number) { layout.ratio = Math.max(30, Math.min(78, value)); persist() }
function resize(event: PointerEvent) {
  if (!(event.buttons & 1)) return
  const box = grid.value!.getBoundingClientRect()
  ratio((event.clientX - box.left) / box.width * 100)
}
</script>
<template>
  <section class="page">
    <header class="page-head"><h1>{{ t('nav.overview') }}</h1>
      <div class="toolbar">
        <span v-if="d.updated.value" class="sub">{{ t('data.updated', { time: time(d.updated.value) }) }}</span>
        <button class="text-button" @click="layout.order = [...defaults]; layout.ratio = 55; persist()">
          {{ t('data.resetLayout') }}</button></div>
    </header>
    <XEmpty v-if="d.fast.error.value" :error="d.fast.error.value" />
    <div class="kpis">
      <XKpi :label="t('data.receives')" :value="pps(fast.incoming.total_pps)" tone="in"
        :secondary="bps(fast.incoming.total_bps)"
        :title="thousands(fast.incoming.total_pps) + ' pps / ' + thousands(fast.incoming.total_bps) + ' bps'" />
      <XKpi :label="t('nav.attacks')" :value="fast.summary.active_attacks" tone="atk"
        :title="(fast.active.attacks ?? []).map(a => a.dst_ip + ' · ' + a.attack_type).join('\n')" />
      <XKpi :label="t('nav.nodes')" :value="`${fast.summary.online_nodes} / ${fast.summary.total_nodes}`"
        :title="d.nodes.data.value.filter(n => !n.online).map(n => n.description || n.id).join('\n')" />
      <XKpi label="BGP" :value="held(fast.bgp).length" :title="actionTip('bgp')" />
      <XKpi label="XDrop" :value="held(fast.xdrop, true).length" :title="actionTip('xdrop')" />
    </div>
    <div class="toolbar"><XSeg v-model="filters.range" :options="ranges" :label="t('data.range')" /></div>
    <div ref="grid" class="overview-grid" :style="{ '--ratio': layout.ratio + '%' }">
      <article v-for="panel in layout.order" :key="panel" class="panel" @dragover.prevent @drop.prevent="drop(panel)">
        <div class="panel-head">
          <h2 draggable="true" @dragstart="dragging = panel" @dragend="dragging = ''">
            ⠿ {{ t('data.panel_' + panel) }}</h2>
          <DecoderPicker v-if="panel === 'pps'" />
          <RouterLink v-if="panel === 'attacks'" to="/attacks">{{ t('data.viewAll') }}</RouterLink>
        </div>
        <template v-if="panel === 'pps' || panel === 'bps'">
          <XChart :points="normalize(d.curves.data.value.incoming, panel)" :selected="selection.keys"
            :slots="selection.slots" :metric="panel" :bands="d.bands.value" :bounds="d.curves.data.value.bounds"
            :grain="grain(filters.range)" :loading="d.curves.loading.value" :error="d.curves.error.value" />
          <XEmpty v-if="d.history.error.value" :error="d.history.error.value" />
          <p v-if="history.bandCapped" class="sub">{{ t('data.bandCap') }}</p>
        </template>
        <template v-else-if="panel === 'attacks'">
          <XEmpty v-if="d.history.error.value" :error="d.history.error.value" />
          <XTable :rows="rows" :columns="columns" row-key="id" clickable :loading="d.fast.loading.value"
            @row="router.push('/attacks/' + $event.id)">
            <template #dst_ip="{ value }">{{ value === '0.0.0.0/0' ? t('data.global') : value }}</template>
            <template #pps="{ row }"><span class="num" :title="peak(row)">{{ rate(row) === undefined
              ? '—' : pps(rate(row)!) }}</span></template>
            <template #mitigation="{ row }"><span class="brief">
              <XPill v-if="brief(row)?.bgp?.length" :label="'BGP ' + brief(row)!.bgp!.length" tone="ok">
                {{ 'BGP ' + brief(row)!.bgp!.length }}</XPill>
              <XPill v-if="brief(row)?.xdrop_rules?.length"
                :label="'XDrop ' + brief(row)!.xdrop_rules!.length" tone="warn">
                {{ 'XDrop ' + brief(row)!.xdrop_rules!.length }}</XPill>
              <span v-if="!brief(row)?.bgp?.length && !brief(row)?.xdrop_rules?.length">—</span>
            </span></template>
            <template #status="{ row }"><span :title="String(row.ended_at || row.started_at)">{{ row.ended_at
              ? t('data.ended', { time: time(String(row.ended_at)).slice(0, 5) })
              : duration((d.updated.value - Date.parse(String(row.started_at))) / 1000) }}</span></template>
            <template #empty><XEmpty>{{ t('data.noAttacks') }}</XEmpty></template>
          </XTable>
          <p v-if="history.tableCapped" class="sub">{{ t('data.tableCap') }}</p>
        </template>
        <XTable v-else :rows="top" :columns="topColumns" row-key="prefix">
          <template #pps="{ value }">{{ pps(Number(value)) }}</template>
          <template #bps="{ value }">{{ bps(Number(value)) }}</template>
          <template #share="{ value }">{{ Number(value).toFixed(1) }}%</template>
          <template #empty><XEmpty>{{ t('data.noTop') }}</XEmpty></template>
        </XTable>
      </article>
      <div class="overview-gutter" role="separator" aria-orientation="vertical" tabindex="0"
        :aria-label="t('data.resize')" :aria-valuenow="layout.ratio" aria-valuemin="30" aria-valuemax="78"
        @pointerdown="($event.currentTarget as HTMLElement).setPointerCapture($event.pointerId); resize($event)"
        @pointermove="resize" @keydown.left.prevent="ratio(layout.ratio - 2)"
        @keydown.right.prevent="ratio(layout.ratio + 2)" />
    </div>
    <article class="panel"><h2>{{ t('nav.nodes') }}</h2>
      <XTable :rows="nodeRows" :columns="nodeColumns" row-key="id" :error="d.nodes.error.value">
        <template #id="{ row }"><RouterLink to="/nodes">{{ row.description || row.id }}</RouterLink></template>
        <template #online="{ value }">{{ t(value ? 'data.online' : 'data.offline') }}</template>
        <template #pps="{ value }">{{ value === undefined ? '—' : pps(Number(value)) }}</template>
        <template #bps="{ value }">{{ value === undefined ? '—' : bps(Number(value)) }}</template>
        <template #config="{ row }"><span :title="`${row.delivery_version_applied} / ${row.delivery_version_current}`">
          {{ Number(row.delivery_version_current) <= Number(row.delivery_version_applied) ? t('data.synced')
            : t('data.behind', { n: Number(row.delivery_version_current) - Number(row.delivery_version_applied) }) }}
        </span></template>
        <template #heartbeat="{ row }">{{ row.last_stats_at ? t('data.secondsAgo', {
          n: Math.max(0, Math.floor((d.updated.value - Date.parse(String(row.last_stats_at))) / 1000)),
        }) : '—' }}</template>
        <template #empty><XEmpty>{{ t('data.noNodes') }}</XEmpty></template>
      </XTable>
    </article>
  </section>
</template>
