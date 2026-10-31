<script setup lang="ts">
import { computed, ref, shallowRef, watch, onUnmounted } from 'vue'
import { useRoute } from 'vue-router'
import { useI18n } from 'vue-i18n'
import { api, normalize, type Attack, type Timer, type RawPoint } from '../../api/data'
import { request, ApiError } from '../../api/client'
import { otherHolders } from '../../api/xdropRules'
import { DECODERS } from '../../config/decoders'
import { usePoll } from '../../composables/usePoll'
import { isAdmin } from '../../auth'
import { notify } from '../../notifications'
import { dateTime, fullDateTime, duration, pps, bps, thousands } from '../../format'
import type { Point, Window } from '../../components/chart/math'
import XChart from '../../components/chart/XChart.vue'
import XKpi from '../../components/XKpi.vue'
import XTip from '../../components/XTip.vue'
import XTabs from '../../components/XTabs.vue'
import XPill from '../../components/XPill.vue'
import XConfirm from '../../components/XConfirm.vue'
import XEmpty from '../../components/XEmpty.vue'
import TargetCell from './TargetCell.vue'
import ExpireConfirm from './ExpireConfirm.vue'
import ActionDrawer from './ActionDrawer.vue'
import Mitigations from './Mitigations.vue'
import Samples from './Samples.vue'
import { target, threshold, curveRequest, mergeTail, countdown, statusInfo, canForceRemoveRow,
  forceBody, activeMitigations, actionKey, phaseKey, type Row } from './data'
const route = useRoute(), { t, te } = useI18n()
const id = computed(() => /^[1-9]\d*$/.test(String(route.params.id)) && Number.isSafeInteger(+route.params.id!)
  ? Number(route.params.id) : 0)
const attack = shallowRef<Attack | null>(null), timer = shallowRef<Timer>(), current = ref<Row>()
const summary = shallowRef<Row>({}), holders = shallowRef<Row[]>([]), error = ref(''), summaryError = ref('')
const notFound = ref(false), loading = ref(true), now = ref(Date.now()), tab = ref('log')
const points = shallowRef<Point[]>([]), bounds = ref<Window>([0, 1]), grain = ref(5000), capped = ref(false)
const chartError = ref(''), chartLoading = ref(true), tailError = ref('')
const sample = shallowRef<Row | null>(null), sampleLoading = ref(false), sampleError = ref('')
const busy = ref(false), expire = ref(false), selected = shallowRef<Row | null>(null), drawer = ref(false)
const force = ref<number | null>(null)
let lifetime = new AbortController(), generation = 0, refreshSequence = 0, sampleSequence = 0
let sampleLoaded = false, curveLoaded = false, curveComplete = false, curveEnded = false, curveAt = 0
let summaryLoaded = false, summarySequence = 0, curveAttempted = false, endObserved = false
const loadedMetric = ref('')
let pollContext: { attackId: number; seq: number; signal: AbortSignal } | undefined
const label = (key: string) => te('attacks.' + key) ? t('attacks.' + key) : key
const executions = computed<Row[]>(() => summary.value.executions ?? [])
const th = computed(() => attack.value ? threshold(attack.value, timer.value)
  : { metric: 'pps', line: undefined, pct: undefined })
const metricPending = computed(() => !!loadedMetric.value && loadedMetric.value !== th.value.metric)
const global = computed(() => !!attack.value && target(attack.value.dst_ip).kind === 'global')
const selectedDecoders = computed(() => {
  const key = attack.value?.decoder_family
  return key && key !== 'ip' && DECODERS.some(d => d.key === key) && key !== 'total' ? ['total', key] : ['total']
})
const state = computed(() => attack.value ? statusInfo(attack.value, { attacks: [attack.value],
  timers: timer.value ? { [id.value]: timer.value } : {}, active_count: 1, returned: 1 }) : null)
const stateText = computed(() => attack.value?.ended_at ? t('data.ended',
  { time: dateTime(attack.value.ended_at).slice(6, 11) }) : state.value ? label(state.value.key === 'breaching'
    ? 'breachingNow' : state.value.key).replace('{time}', countdown(state.value.seconds)) : '')
async function loadSummary(attackId: number, signal: AbortSignal) {
  const data = await api<Row>(`attacks/${attackId}/mitigation-summary`, {}, signal)
  signal.throwIfAborted()
  let xdrop: Row[] | undefined
  if (data.xdrop_rules?.length || data.executions?.some((e: Row) => e.action_type === 'xdrop')) {
    try { xdrop = (await api<Row[] | null>('active-actions/xdrop', {}, signal)) ?? [] }
    catch { signal.throwIfAborted() }
  }
  return { data, xdrop }
}
const poll = usePoll(async () => {
  const attackId = id.value, seq = generation, signal = lifetime.signal, stamp = Date.now()
  const result: Row = { attackId, seq, stamp }
  pollContext = { attackId, seq, signal }
  if (!attackId || notFound.value) return result
  let a = attack.value, activeTimer = timer.value
  if (!a || !a.ended_at) {
    try {
      const detail = await api<{ attack: Attack; timer?: Timer; current?: Row }>(`attacks/${attackId}`, {}, signal)
      a = detail.attack; activeTimer = detail.timer; result.detail = detail
    } catch (e) { result.failure = e; return result }
  }
  signal.throwIfAborted()
  if (!summaryLoaded || !attack.value?.ended_at || activeMitigations(summary.value)) {
    result.summarySeq = ++summarySequence
    try { result.summary = await loadSummary(attackId, signal) }
    catch (e) { result.summaryFailure = e instanceof Error ? e.message : String(e) }
  }
  signal.throwIfAborted()
  const firstEnded = !!a?.ended_at && !curveEnded
  const newEnd = !!a?.ended_at && !endObserved
  if (a && (!curveAttempted || newEnd || stamp - curveAt >= 10000 && (!a.ended_at || !curveComplete))) {
    const metric = threshold(a, activeTimer).metric
    const metricChanged = curveLoaded && loadedMetric.value !== metric
    const plan = curveRequest(a, stamp, points.value, grain.value, firstEnded, metricChanged)
    result.curveMetric = metric
    result.plan = plan; result.curveAttempt = true
    try {
      result.curve = normalize(await api<RawPoint[] | null>(plan.path, plan.params, signal),
        threshold(a, activeTimer).metric)
    } catch (e) { result.curveFailure = e instanceof Error ? e.message : String(e) }
  }
  return result
}, 5000, result => {
  if (result.attackId !== id.value || result.seq !== generation) {
    queueMicrotask(() => void poll.refresh()); return
  }
  now.value = result.stamp
  if (!id.value) { notFound.value = true; loading.value = false; return }
  if (result.failure) {
    notFound.value = result.failure instanceof ApiError && result.failure.status === 404
    error.value = result.failure.message; loading.value = false; return
  }
  error.value = ''
  if (result.detail) {
    attack.value = result.detail.attack; timer.value = result.detail.timer; current.value = result.detail.current
    loading.value = false
    if (result.detail.attack.ended_at) endObserved = true
  }
  if (result.summary && result.summarySeq === summarySequence) {
    summaryLoaded = true
    summary.value = result.summary.data; summaryError.value = ''
    if (result.summary.xdrop !== undefined) holders.value = result.summary.xdrop
  }
  if (result.summaryFailure && result.summarySeq === summarySequence) summaryError.value = result.summaryFailure
  if (result.curveAttempt) {
    curveAt = result.stamp; curveAttempted = true; bounds.value = result.plan.bounds
    capped.value = result.plan.capped; chartLoading.value = false
    if (result.curveFailure) {
      if (!curveLoaded) chartError.value = result.curveFailure
      else tailError.value = result.curveFailure
    } else {
      if (result.plan.whole) {
        grain.value = result.plan.grain
        loadedMetric.value = result.curveMetric
      }
      points.value = mergeTail(result.plan.whole ? [] : points.value, result.curve, result.plan.from,
        result.plan.bounds[0])
      curveLoaded = true; curveEnded = !!attack.value?.ended_at
      curveComplete = curveEnded && result.plan.to >= result.plan.bounds[1]
      chartError.value = tailError.value = ''
    }
  }
  if (tab.value === 'flow' && !sampleLoaded && !sampleLoading.value) void loadSamples()
}, reason => {
  if (pollContext?.signal.aborted && pollContext.seq !== generation && !lifetime.signal.aborted) {
    queueMicrotask(() => void poll.refresh())
  } else {
    error.value = reason instanceof Error ? reason.message : String(reason)
    loading.value = false
  }
})
async function refreshLogs() {
  const attackId = id.value, seq = generation, refresh = ++refreshSequence, signal = lifetime.signal
  const requestSeq = ++summarySequence
  busy.value = true
  try {
    const result = await loadSummary(attackId, signal)
    if (attackId !== id.value || seq !== generation || refresh !== refreshSequence
      || requestSeq !== summarySequence) return
    summary.value = result.data; summaryError.value = ''; summaryLoaded = true
    if (result.xdrop !== undefined) holders.value = result.xdrop
  } catch (e) {
    if (attackId === id.value && seq === generation && refresh === refreshSequence && requestSeq === summarySequence) {
      summaryError.value = e instanceof Error ? e.message : String(e)
    }
  } finally {
    if (attackId === id.value && seq === generation && refresh === refreshSequence) busy.value = false
  }
}
async function loadSamples(refresh = false) {
  if (!attack.value || global.value || sampleLoading.value || sampleLoaded && !refresh) return
  const attackId = id.value, seq = generation, refreshId = ++sampleSequence, signal = lifetime.signal
  sampleLoading.value = true
  try {
    const result = await api<Row>(`attacks/${attackId}/sensor-logs`, {}, signal)
    if (attackId !== id.value || seq !== generation || refreshId !== sampleSequence) return
    sample.value = { ...result, flows: result.flows ?? [] }; sampleError.value = ''; sampleLoaded = true
  } catch (e) {
    if (attackId !== id.value || seq !== generation || refreshId !== sampleSequence) return
    sampleError.value = e instanceof Error ? e.message : String(e); sampleLoaded = true
    notify(sampleError.value, 'crit', true)
  } finally {
    if (attackId === id.value && seq === generation && refreshId === sampleSequence) sampleLoading.value = false
  }
}
function restoreTab() { tab.value = route.query.tab === 'flow' ? 'flow' : 'log' }
restoreTab()
watch(() => route.query.tab, restoreTab)
watch(tab, value => { if (value === 'flow') void loadSamples() })
watch(id, () => {
  lifetime.abort(); lifetime = new AbortController(); generation++; refreshSequence++; sampleSequence++
  attack.value = null; timer.value = undefined; current.value = undefined; summary.value = {}; holders.value = []
  error.value = summaryError.value = chartError.value = tailError.value = sampleError.value = ''
  notFound.value = false; loading.value = chartLoading.value = true; points.value = []; bounds.value = [0, 1]
  sample.value = null; sampleLoaded = curveLoaded = curveComplete = curveEnded = false; curveAt = 0
  summaryLoaded = curveAttempted = endObserved = false; summarySequence++; loadedMetric.value = ''
  sampleLoading.value = busy.value = false; expire.value = drawer.value = false
  selected.value = null; force.value = null
  void poll.refresh()
})
onUnmounted(() => { lifetime.abort(); generation++; refreshSequence++; sampleSequence++; summarySequence++ })
function perAttackForceRemoveTitle(row: Row) {
  if (row.action_type === 'xdrop') {
    const n = otherHolders(holders.value as any, { ...row, attack_id: Number(route.params.id) } as any)
    return n > 0 ? t('attacks.confirmReleaseShared', { n }) : t('attacks.confirmReleaseLast')
  }
  const refcount = row.announcement_refcount || 0
  if (refcount > 1) return t('attacks.confirmDetachFromShared', { remaining: refcount - 1 })
  return t('attacks.confirmForceWithdraw')
}
async function forceRemoveActionRow(row: Row) {
  try {
    const resp = await request<{ warning?: string }>('/api/active-actions/force-remove', {
      method: 'POST', body: JSON.stringify(forceBody(Number(route.params.id), row)),
    })
    if (resp?.warning) notify(resp.warning, 'warn', true)
    else notify(t(row.action_type === 'xdrop' ? 'attacks.holdReleased' : 'attacks.forceRemoved'))
    void refreshLogs()
  } catch (e) {
    const timeout = row.action_type === 'xdrop' && e instanceof ApiError && e.timeout
    const message = timeout ? t('mitigations.forceTimeout')
      : e instanceof Error && e.message ? e.message : t('mitigations.forceFailed')
    notify(message, timeout ? 'warn' : 'crit', !timeout)
    throw new Error(message)
  }
}
function viewActionRow(event: Event, row: Row) {
  if (!(event.target as Element).closest('button,a,input,[role=alertdialog]')) viewActionDetail(row)
}
function viewActionDetail(row: Row) { selected.value = row; drawer.value = true }
const columns = computed(() => ['time', 'action', 'connector', 'triggerPhase', 'status', 'bgpRole',
  'http', 'durationMs', 'operation'].map(key => ({ key, label: key === 'http' ? 'HTTP'
  : key === 'status' ? t('data.status') : t('attacks.' + key) })))
</script>
<template>
  <section class="page attack-detail">
    <div class="crumb"><RouterLink to="/attacks">{{ t('nav.attacks') }}</RouterLink> / #{{ route.params.id }}</div>
    <XEmpty v-if="notFound || !id">{{ t('attacks.notFound') }} <RouterLink to="/attacks">
      {{ t('attacks.backList') }}</RouterLink></XEmpty>
    <XEmpty v-else-if="loading" loading />
    <div v-else-if="error && !attack" class="empty" role="alert">{{ error }}
      <button class="btn" @click="poll.refresh">{{ t('attacks.retry') }}</button></div>
    <template v-else-if="attack">
      <header class="page-head"><div><h1><TargetCell :value="attack.dst_ip" /></h1><div class="meta">
        <span :title="attack.attack_type + ' · ' + attack.decoder_family">{{ attack.decoder_family === 'ip'
          ? t('attacks.ipTotal') : attack.decoder_family }}</span>
        <XPill :tone="['critical', 'high'].includes(attack.severity) ? 'crit' : 'neutral'">
          {{ label(attack.severity) }}</XPill>
        <span :title="attack.ended_at ? fullDateTime(attack.ended_at)
          : label(state?.tip || '')">{{ state?.key === 'falling'
          ? t('attacks.falling', { time: countdown(state.seconds) }) : stateText }}</span>
        <XPill v-if="attack.direction === 'sends'" :title="t('attacks.outboundTip')">{{ t('data.sends') }}</XPill>
      </div></div><div><button v-if="!attack.ended_at && isAdmin()" class="btn sm crit-line"
        @click="expire = true">{{ t('attacks.endAttack') }}</button>
        <ExpireConfirm v-model="expire" :attack="attack" @done="poll.refresh" /></div></header>
      <div v-if="error" class="detail-warning crit" role="alert">{{ error }}
        <button class="btn sm" @click="poll.refresh">{{ t('attacks.retry') }}</button></div>
      <div class="kpis attack-kpis">
        <XKpi v-if="!attack.ended_at" :label="t('attacks.current')"
          :value="current ? pps(current.pps) + ' pps' : '—'"
          :secondary="current ? bps(current.bps) : '—'" tone="drop" />
        <XKpi v-else :label="t('attacks.end')" :value="fullDateTime(attack.ended_at).slice(11)"
          :secondary="fullDateTime(attack.ended_at).slice(0, 10)" />
        <XKpi :label="t('attacks.peak')" :value="attack.peak_pps ? pps(attack.peak_pps) + ' pps' : '—'"
          :secondary="attack.peak_bps ? bps(attack.peak_bps) : '—'"
          :title="(attack.peak_pps ? thousands(attack.peak_pps) : '—') + ' pps · '
            + (attack.peak_bps ? thousands(attack.peak_bps) : '—') + ' bps'" />
        <XKpi :label="t('attacks.start')" :value="fullDateTime(attack.started_at).slice(11)"
          :secondary="fullDateTime(attack.started_at).slice(0, 10)" />
        <XKpi :label="t('attacks.elapsed')" :value="duration(((attack.ended_at
          ? Date.parse(attack.ended_at) : now) - Date.parse(attack.started_at)) / 1000)" />
        <div class="kpi"><div class="k">{{ t('attacks.confidence') }}
          <XTip :text="t('attacks.confidenceTip')" /></div>
          <div class="v num">{{ Math.round(attack.confidence * 100) }}%</div>
        </div>
      </div>
      <article class="panel"><div class="panel-head"><h2>{{ t('attacks.targetTraffic', { metric: th.metric }) }}</h2>
        <span v-if="capped" class="sub">{{ t(target(attack.dst_ip).kind === 'single'
          ? 'attacks.capIP' : 'attacks.capPrefix') }}</span></div>
        <p v-if="tailError" class="crit sub" role="alert">{{ tailError }}</p>
        <XChart :points="points" :selected="selectedDecoders" :slots="{ [attack.decoder_family]: 0 }"
          :metric="th.metric" :threshold="th.line" :bounds="bounds" :grain="grain"
          :loading="chartLoading || metricPending"
          :error="chartError" :bands="[{ start: Date.parse(attack.started_at), end: attack.ended_at
            ? Date.parse(attack.ended_at) : null, target: attack.dst_ip, type: attack.attack_type }]" />
        <p v-if="!chartLoading && !chartError && !points.length" class="sub">
          {{ t(target(attack.dst_ip).kind === 'single'
          ? 'attacks.noIPData' : 'common.empty') }}</p>
        <p class="sub">{{ th.pct !== undefined ? t('attacks.percentThreshold', { value: th.pct })
          : th.line === undefined ? t('attacks.noThreshold') : '' }}</p>
      </article>
      <article class="panel"><h2>{{ t('attacks.detection') }}</h2><dl class="kv detection-kv">
        <dt>{{ t('attacks.attackType') }}</dt><dd>{{ attack.attack_type }}</dd>
        <dt>{{ t('attacks.decoder') }}</dt><dd>{{ attack.decoder_family }}</dd><dt>{{ t('data.direction') }}</dt>
        <dd>{{ t('data.' + attack.direction) }}</dd><dt>{{ t('attacks.peakPps') }}</dt>
        <dd>{{ attack.peak_pps ? thousands(attack.peak_pps) : '—' }}</dd><dt>{{ t('attacks.peakBps') }}</dt>
        <dd>{{ attack.peak_bps ? thousands(attack.peak_bps) : '—' }}</dd><dt>{{ t('attacks.triggerRule') }}</dt>
        <dd>{{ attack.template_name || '' }} <span class="mono">{{ attack.rule_summary || '' }}</span>
          <span v-if="!attack.template_name && !attack.rule_summary">—</span></dd>
        <dt>{{ t('attacks.response') }}</dt><dd>{{ executions.find(r => r.response_name)?.response_name
          || (attack.response_id ? t('attacks.bound', { id: attack.response_id }) : t('attacks.unbound')) }}</dd>
        <dt>{{ t('attacks.nodeSources') }}</dt><dd>{{ attack.node_sources?.join('、') || '—' }}</dd>
        <dt>{{ t('attacks.reasonCodes') }}</dt><dd><XPill v-for="reason in attack.reason_codes ?? []" :key="reason">
          {{ reason }}</XPill><span v-if="!attack.reason_codes?.length">—</span></dd></dl></article>
      <p v-if="summaryError" class="crit" role="alert">{{ summaryError }}</p>
      <Mitigations :data="summary" :holders="holders" :response-id="attack.response_id" :now="now" />
      <article class="panel"><div class="refresh-row"><button v-if="tab !== 'flow' || !global" class="btn sm"
        :disabled="busy || sampleLoading" @click="tab === 'flow' ? loadSamples(true) : refreshLogs()">
        {{ t(busy || sampleLoading ? 'attacks.refreshing' : 'attacks.refresh') }}</button></div>
        <XTabs v-model="tab" query :label="t('nav.attacks')" :tabs="[{ value: 'log',
          label: t('attacks.logTab', { n: executions.length }) }, { value: 'flow', label: t('attacks.samples') }]">
          <template #log><div class="tbl-wrap action-log"><table><thead><tr>
            <th v-for="column in columns" :key="column.key">{{ column.label }}</th>
          </tr></thead><tbody>
            <template v-for="row in executions" :key="row.id"><tr class="link" tabindex="0"
              @click="viewActionRow($event, row)" @keydown.enter.self="viewActionRow($event, row)">
              <td :title="fullDateTime(row.executed_at)">{{ dateTime(row.executed_at) }}</td>
              <td>{{ label(actionKey(row)) }}</td><td>{{ row.connector_name || '—' }}</td>
              <td>{{ label(phaseKey(row.trigger_phase)) }}</td><td><XPill :tone="row.status === 'success' ? 'ok'
                : row.status === 'failed' ? 'crit' : 'neutral'"
                :title="[row.skip_reason, row.error_message].filter(Boolean).join(' · ')">
                {{ row.status === 'pending' ? t('attacks.statusPending') : label(row.status) }}</XPill></td>
              <td><XPill v-if="['triggered', 'attached_shared'].includes(row.bgp_role)"
                :tone="row.bgp_role === 'triggered' ? 'crit' : 'neutral'"
                :title="t(row.bgp_role === 'triggered' ? 'attacks.roleTriggeredTip' : 'attacks.roleAttachedTip')">
                {{ t(row.bgp_role === 'triggered' ? 'attacks.bgpRoleTriggered' : 'attacks.bgpRoleAttached') }}</XPill>
                <span v-else>—</span></td>
              <td>{{ row.status_code ?? '—' }}</td><td>{{ ['skipped', 'scheduled'].includes(row.status)
                ? '—' : row.duration_ms + ' ms' }}</td>
              <td><button class="text-button" @click="viewActionDetail(row)">{{ t('attacks.detailsArrow') }}</button>
                <button v-if="isAdmin() && canForceRemoveRow(row, attack)" class="btn sm crit-line"
                  @click="force = row.id">{{ t('attacks.forceRemove') }}</button></td>
            </tr><tr v-if="force === row.id" class="confirmation-row"><td colspan="9">
              <XConfirm :model-value="force === row.id" :title="perAttackForceRemoveTitle(row)" description=""
                tone="danger" :confirm-label="t(row.action_type === 'xdrop' ? 'attacks.release' : 'attacks.withdraw')"
                :action="() => forceRemoveActionRow(row)"
                @update:model-value="force = $event ? row.id : null" />
            </td></tr></template>
          </tbody></table><p v-if="!executions.length" class="empty" role="status">{{ t('common.empty') }}</p>
          </div></template>
          <template #flow>
            <Samples :global="global" :loading="sampleLoading" :error="sampleError" :data="sample" />
          </template>
        </XTabs>
      </article>
      <ActionDrawer v-model="drawer" :row="selected" />
    </template>
  </section>
</template>
<style scoped>
.crumb { display: flex; gap: 8px; color: var(--muted); margin-bottom: 12px; }
.meta { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
.attack-kpis { grid-template-columns: repeat(5, minmax(0, 1fr)); }
@media (min-width: 641px) { .attack-kpis :deep(.tip-text) { left: auto; right: 0; } }
.action-log table { min-width: 1060px; }
.action-log th, .action-log td { white-space: nowrap; }
.refresh-row { display: flex; justify-content: flex-end; margin-bottom: 8px; }
:deep(.confirm) { max-width: calc(100vw - 48px); width: 680px; white-space: normal; }
.confirmation-row td { cursor: default; }
@media (max-width: 640px) { .attack-kpis { grid-template-columns: repeat(2, minmax(0, 1fr)); } }
</style>
