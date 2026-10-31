<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, shallowRef } from 'vue'
import { useI18n } from 'vue-i18n'
import { rounds } from '../mitigations/poll'
import { settle, minStamp, type Stamp } from '../mitigations/split'
import { api } from '../../api/data'
import { bps, pps, fullDateTime, relativeTime } from '../../format'
import { isAdmin } from '../../auth'
import XTip from '../../components/XTip.vue'
import XEmpty from '../../components/XEmpty.vue'
import type { Row } from '../mitigations/data'
import { nodeReadings } from './data'
import ConfigCell from './ConfigCell.vue'
import Detail from './Detail.vue'
import AddNode from './AddNode.vue'
const { t } = useI18n()
const nodes = shallowRef<Row[]>([]), readings = shallowRef<Row[]>([]), error = ref(''), updated = ref(0)
const loaded = ref([false, false]), now = ref(Date.now()), adding = ref(false), open = ref(false), missing = ref(false)
const stamps: Stamp[] = Array.from({ length: 2 }, () => ({ lastOk: null, failing: false }))
const selected = shallowRef<Row>(), rows = computed(() => nodeReadings(nodes.value, readings.value))
const lifetime = new AbortController()
let timer: ReturnType<typeof setInterval>
function stamp(i: number, result: PromiseSettledResult<unknown>) {
  loaded.value[i] = true
  stamps[i]!.failing = result.status === 'rejected'
  if (result.status === 'fulfilled') stamps[i]!.lastOk = Date.now()
  updated.value = minStamp(stamps, updated.value)
}
const nodePoll = rounds(() => settle(api<Row[] | null>('nodes', {}, lifetime.signal)), 5000, n => {
  if (n.status === 'fulfilled') { nodes.value = n.value ?? []; error.value = '' }
  else error.value = n.reason?.message || String(n.reason)
  stamp(0, n)
  if (selected.value) {
    const next = nodes.value.find(n => n.id === selected.value!.id)
    missing.value = !next
    if (next) selected.value = next
  }
})
const overviewPoll = rounds(() => settle(api<Row>('stats/overview', { direction: 'receives' }, lifetime.signal)),
  5000, o => {
    if (o.status === 'fulfilled') readings.value = o.value?.nodes ?? []
    stamp(1, o)
  })
const poll = { refresh: () => Promise.all([nodePoll.refresh(), overviewPoll.refresh()]) }
onMounted(() => { timer = setInterval(() => { now.value = Date.now() }, 1000) })
onUnmounted(() => { clearInterval(timer); lifetime.abort() })
function show(row: Row) { selected.value = row; open.value = true; missing.value = false }
</script>
<template>
  <div class="page nodes-page"><div class="page-head"><h1>{{ t('nav.nodes') }} <span class="sub num count">
    {{ t('nodes.onlineCount', { on: nodes.filter(n => n.online).length, total: nodes.length }) }}</span></h1>
    <div class="toolbar"><span v-if="updated" class="sub">{{ t('data.updated', {
      time: fullDateTime(new Date(updated).toISOString()).slice(11) }) }}</span>
      <button v-if="isAdmin()" class="btn primary sm" @click="adding = true">{{ t('nodes.addNode') }}</button>
    </div></div>
    <p v-if="error" class="crit mono" role="alert">{{ error }}
      <button class="btn sm" @click="poll.refresh">{{ t('attacks.retry') }}</button></p>
    <div class="tbl-wrap"><table><thead><tr><th>{{ t('nav.nodes') }}</th><th>{{ t('nodes.mode') }}</th>
      <th>{{ t('nodes.status') }}</th><th>{{ t('nodes.pps') }}</th><th>{{ t('nodes.bps') }}</th>
      <th>{{ t('nodes.config') }}<XTip :text="t('nodes.configTip')" wide /></th>
      <th>{{ t('nodes.lastAck') }}<XTip :text="t('nodes.lastAckTip')" /></th><th /></tr></thead><tbody>
      <tr v-for="row in rows" :key="row.id" class="link" tabindex="0"
        @click="($event.target as Element).closest('a,button') || show(row)" @keydown.enter.self="show(row)">
        <td><strong class="mono">{{ row.id }}</strong><div class="sub">{{ row.description }}</div></td>
        <td>{{ row.mode === 'flow' ? 'Flow' : 'XDP' }}</td><td><span class="dot"
          :class="row.online ? 'ok' : 'neutral'" /> {{ t(row.online ? 'data.online' : 'data.offline') }}
          <small v-if="row.last_stats_at" class="sub num">{{ relativeTime(row.last_stats_at, now) }}</small></td>
        <td class="num">{{ row.reading ? pps(row.reading.pps) : '—' }}</td>
        <td class="num">{{ row.reading ? bps(row.reading.bps) : '—' }}</td>
        <td><ConfigCell :row="row" /></td><td class="num sub">{{ row.last_ack_at
          ? fullDateTime(row.last_ack_at) : '—' }}</td>
        <td><RouterLink v-if="row.mode === 'flow'" :to="'/flow/' + encodeURIComponent(row.id)">
          {{ t('nodes.flowLink') }}</RouterLink></td>
      </tr></tbody></table><XEmpty v-if="!rows.length" :loading="!loaded[0]">{{ t('nodes.empty') }}</XEmpty></div>
    <Detail v-if="selected" :key="selected.id" v-model="open" :row="selected" :now="now" :missing="missing"
      :reading="readings.find(r => r.id === selected!.id)" @deleted="poll.refresh" />
    <AddNode v-model="adding" @saved="poll.refresh" />
  </div>
</template>
<style scoped>
table { width: 100%; }
td { overflow-wrap: anywhere; }
.count { font-size: 12px; font-weight: 500; }
@media (max-width: 700px) { table { min-width: 980px; } }
</style>
