<script setup lang="ts">
import { computed, reactive, ref, toRef, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'
import XKpi from '../../components/XKpi.vue'
import XTable from '../../components/XTable.vue'
import XEmpty from '../../components/XEmpty.vue'
import XListbox from '../../components/XListbox.vue'
import XSeg from '../../components/XSeg.vue'
import XTip from '../../components/XTip.vue'
import XPill from '../../components/XPill.vue'
import XChart from '../../components/chart/XChart.vue'
import DecoderPicker from '../../components/chart/DecoderPicker.vue'
import { selection, initSelection, choose } from '../../components/chart/selection'
import { maximum } from '../../components/chart/math'
import { DECODERS } from '../../config/decoders'
import { normalize } from '../../api/data'
import { useData, grain, useZoom } from '../overview/data'
import { topRows, topValue, sortTop } from './top'
import { pps, bps } from '../../format'
import '../../styles/pages.css'
const { t } = useI18n(), route = useRoute(), router = useRouter()
initSelection()
const filters = reactive({ direction: 'receives', node: '', prefix: '', range: '1h', metric: 'pps', limit: '20' })
function restore() {
  for (const [key, choices] of Object.entries({ direction: ['receives', 'sends', 'both'],
    range: ['1h', '6h', '24h'], metric: ['pps', 'bps'], limit: ['10', '20', '50', '100'] })) {
    const value = route.query[key]
    const fallback = { direction: 'receives', range: '1h', metric: 'pps', limit: '20' }[key]!
    filters[key as 'range'] = typeof value === 'string' && choices.includes(value) ? value : fallback
  }
  filters.node = typeof route.query.node === 'string' ? route.query.node : ''
  filters.prefix = typeof route.query.prefix === 'string' ? route.query.prefix : ''
  if (typeof route.query.decoders === 'string' && route.query.decoders) {
    let count = 0
    const keys = [...new Set(route.query.decoders.split(','))].filter(k => DECODERS.some(d => d.key === k)
      && (k === 'total' || ++count <= 3))
    choose(keys.length ? keys : ['tcp', 'udp'])
  }
}
restore()
watch(() => route.query, restore)
watch(() => [JSON.stringify(filters), selection.keys.join(',')], () => {
  const query = { ...route.query, ...filters, decoders: selection.keys.join(',') }
  if (!selection.keys.length) delete (query as Partial<typeof query>).decoders
  if (Object.keys({ ...route.query, ...query }).some(k => route.query[k] !== query[k as keyof typeof query])) {
    void router.replace({ query })
  }
})
const d = useData(filters), window = useZoom(toRef(filters, 'range'))
const fast = computed(() => d.fast.data.value)
const incoming = computed(() => normalize(d.curves.data.value.incoming, filters.metric))
const outgoing = computed(() => normalize(d.curves.data.value.outgoing, filters.metric))
const sharedMax = computed(() => Math.max(maximum(incoming.value.filter(p => !window.value
  || p.time >= window.value[0] && p.time <= window.value[1]), selection.keys),
maximum(outgoing.value.filter(p => !window.value
  || p.time >= window.value[0] && p.time <= window.value[1]), selection.keys)))
const options = (values: string[], group = 'data') => values.map(value => ({ value, label: t(group + '.' + value) }))
const nodeOptions = computed(() => [{ value: '', label: t('data.allNodes') }, ...d.nodes.data.value.map(n => ({
  value: n.id, label: `${n.id} · ${n.mode === 'flow' ? 'FLOW' : 'XDP'}` + (n.online ? '' : t('data.offlineSuffix')),
}))])
const prefixOptions = computed(() => [{ value: '', label: t('data.allPrefixes') }, ...d.prefixes.data.value.map(p => ({
  value: p.prefix, label: p.prefix + (p.name ? ' · ' + p.name : ''),
}))])
const sortKey = ref('in:pps'), sortDirection = ref<'ascending' | 'descending'>('descending')
const sides = computed(() => filters.direction === 'both'
  ? ['in', 'out'] : [filters.direction === 'sends' ? 'out' : 'in'])
const columns = computed(() => [{ key: 'prefix', label: t('data.prefix') }, { key: 'name', label: t('data.name') },
  ...sides.value.flatMap(side => ['pps', 'bps', 'tcp', 'udp', 'icmp'].map(field => ({
    key: side + ':' + field, label: (filters.direction === 'both' ? t('data.' + side) + ' ' : '')
      + field.toUpperCase() + (['tcp', 'udp', 'icmp'].includes(field) ? ' ' + filters.metric : ''), sortable: true,
  }))), { key: 'nodes', label: t('nav.nodes') }, { key: 'share', label: t('data.share') }])
const rows = computed(() => sortTop(topRows(filters.direction === 'sends' ? { ...fast.value.incoming, top_prefixes: [] }
  : fast.value.incoming,
filters.direction === 'receives' ? { ...fast.value.outgoing, top_prefixes: [] } : fast.value.outgoing),
sortKey.value, filters.metric, sortDirection.value))
watch(() => filters.direction, () => { sortKey.value = (filters.direction === 'sends' ? 'out' : 'in') + ':pps' })
const source = (row: Record<string, unknown>, side: string) => row[side === 'out' ? 'outgoing' : 'incoming'] as
  typeof fast.value.incoming.top_prefixes extends (infer P)[] | null ? P | undefined : never
const nodes = (row: Record<string, unknown>) => filters.direction === 'both'
  ? fast.value.both.top_prefixes?.find(p => p.prefix === row.prefix)?.nodes
    || (source(row, 'in') || source(row, 'out'))?.nodes || []
  : source(row, sides.value[0]!)?.nodes ?? []
const share = (row: Record<string, unknown>, side: string) => {
  const total = side === 'out' ? fast.value.outgoing.total_pps : fast.value.incoming.total_pps
  const value = source(row, side)?.pps
  return value === undefined ? '—' : (total ? value / total * 100 : 0).toFixed(1) + '%'
}
const activePrefixes = computed(() => filters.direction === 'both'
  ? `${t('data.in')} ${fast.value.incoming.active_prefixes} / ${t('data.out')} ${fast.value.outgoing.active_prefixes}`
  : String((filters.direction === 'sends' ? fast.value.outgoing : fast.value.incoming).active_prefixes))
const activeNodes = computed(() => (filters.direction === 'both' ? fast.value.both
  : filters.direction === 'sends' ? fast.value.outgoing : fast.value.incoming).node_count)
</script>
<template>
  <section class="page">
    <header class="page-head"><h1>{{ t('nav.traffic') }}</h1><span v-if="d.updated.value" class="sub">
      {{ t('data.updated', { time: new Date(d.updated.value).toLocaleTimeString([], { hour12: false }) }) }}
    </span></header>
    <div class="toolbar traffic-filters">
      <XSeg v-model="filters.direction" :options="options(['receives', 'sends', 'both'])"
        :label="t('data.direction')" />
      <XListbox v-model="filters.node" :options="nodeOptions" :label="t('nav.nodes')" />
      <XListbox v-model="filters.prefix" :options="prefixOptions" mode="search" :label="t('data.prefix')" />
      <XTip :text="t('traffic.prefixFilterTip')" />
      <XSeg v-model="filters.range" :options="['1h', '6h', '24h'].map(v => ({ value: v, label: v }))"
        :label="t('data.range')" />
      <XSeg v-model="filters.metric" :options="['pps', 'bps'].map(v => ({ value: v, label: v.toUpperCase() }))"
        :label="t('data.metric')" />
    </div>
    <XEmpty v-if="d.fast.error.value || d.nodes.error.value || d.prefixes.error.value"
      :error="d.fast.error.value || d.nodes.error.value || d.prefixes.error.value" />
    <div class="kpis traffic-kpis">
      <XKpi :label="t('data.receives')" :value="pps(fast.incoming.total_pps)"
        :secondary="bps(fast.incoming.total_bps)" />
      <XKpi :label="t('data.sends')" :value="pps(fast.outgoing.total_pps)" :secondary="bps(fast.outgoing.total_bps)" />
      <XKpi :label="t('nav.nodes')" :value="`${fast.summary.online_nodes} / ${fast.summary.total_nodes}`"
        :secondary="t('data.activeNodes', { n: activeNodes })" />
      <XKpi :label="t('data.activePrefixes')" :value="activePrefixes" />
    </div>
    <article class="panel"><div class="panel-head"><h2>{{ t('chart.trend') }}</h2><DecoderPicker /></div>
      <div class="trend-stack">
        <div v-for="side in sides" :key="side"><h2 v-if="sides.length === 2">{{ t('data.' + side) }}</h2>
          <XChart v-model:window="window" :points="side === 'out' ? outgoing : incoming" :selected="selection.keys"
            :slots="selection.slots" :metric="filters.metric" :bands="d.bands.value" :outbound="side === 'out'"
            :bounds="d.curves.data.value.bounds" :grain="grain(filters.range)" :shared-max="sharedMax" zoomable
            :loading="d.curves.loading.value" :error="d.curves.error.value" />
        </div>
      </div>
      <XEmpty v-if="d.history.error.value" :error="d.history.error.value" />
      <p v-if="d.history.data.value.bandCapped" class="sub">{{ t('data.bandCap') }}</p>
    </article>
    <article class="panel"><div class="panel-head"><h2>{{ t('data.top') }}</h2>
      <XSeg v-model="filters.limit" :options="['10', '20', '50', '100'].map(v => ({ value: v, label: v }))"
        :label="t('data.topCount')" /></div>
      <XTable :rows="rows" :columns="columns" row-key="prefix" clickable :sort-key="sortKey"
        :sort-direction="sortDirection" :loading="d.fast.loading.value"
        @sort="(key, direction) => { sortKey = key; sortDirection = direction }"
        @row="filters.prefix = String($event.prefix)">
        <template #prefix="{ value }"><span class="mono">{{ value }}</span></template>
        <template #name="{ row }">{{ d.prefixes.data.value.find(p => p.prefix === row.prefix)?.name || '—' }}</template>
        <template v-for="column in columns.filter(c => c.key.includes(':'))" :key="column.key" #[column.key]="{ row }">
          <span class="num">{{ topValue(row as any, column.key, filters.metric) === undefined ? '—'
            : (column.key.endsWith(':bps') || !column.key.endsWith(':pps') && filters.metric === 'bps' ? bps : pps)(
              topValue(row as any, column.key, filters.metric)!) }}</span>
        </template>
        <template #nodes="{ row }"><span class="brief"><XPill v-for="node in nodes(row)" :key="node.id"
          :tone="node.mode === 'flow' ? 'warn' : 'neutral'" :label="node.id + ' · ' + node.mode.toUpperCase()">
          {{ node.id }} · {{ node.mode.toUpperCase() }}</XPill>
        </span></template>
        <template #share="{ row }">{{ sides.map(side => share(row, side)).join(' / ') }}</template>
        <template #empty><XEmpty>{{ t('data.noTop') }}</XEmpty></template>
      </XTable>
    </article>
  </section>
</template>
