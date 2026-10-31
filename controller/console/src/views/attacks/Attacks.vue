<script setup lang="ts">
import { computed, reactive, ref, shallowRef, watch, onUnmounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'
import { api, briefs, type Attack, type Active, type Brief } from '../../api/data'
import { usePoll } from '../../composables/usePoll'
import { isAdmin } from '../../auth'
import { dateTime, fullDateTime, duration, pps, bps } from '../../format'
import XSeg from '../../components/XSeg.vue'
import XPager from '../../components/XPager.vue'
import XPill from '../../components/XPill.vue'
import XEmpty from '../../components/XEmpty.vue'
import TargetCell from './TargetCell.vue'
import { statusLabel } from '../mitigations/data'
import ExpireConfirm from './ExpireConfirm.vue'
import { validTarget, listParams, statusInfo, countdown, PAGE, type Filters } from './data'
const { t, te } = useI18n(), route = useRoute(), router = useRouter()
const filters = reactive<Filters>({ status: '', dir: 'all', win: '24h', q: '', page: 1 })
const raw = ref(''), rows = shallowRef<Attack[]>([]), total = ref(0), loading = ref(true), error = ref('')
const counts = ref<Record<string, number | null>>({ active: null, expired: null, all: null })
const active = shallowRef<Active>(), activeError = ref(''), brief = ref<Record<string, Brief>>({})
const updated = ref(0), now = ref(Date.now()), confirm = ref<number | null>(null)
const lifetime = new AbortController(), statuses = ['active', 'expired', 'all']
let restoring = false, restoredKey = '', writtenURL = ''
let debounce: ReturnType<typeof setTimeout> | undefined
const key = () => JSON.stringify(filters)
const invalid = computed(() => !!raw.value.trim() && !validTarget(raw.value))
function restore() {
  restoring = true
  const q = route.query
  filters.status = typeof q.status === 'string' && statuses.includes(q.status) ? q.status : ''
  filters.dir = typeof q.dir === 'string' && ['all', 'receives', 'sends'].includes(q.dir) ? q.dir : 'all'
  filters.win = typeof q.win === 'string' && ['24h', '7d', '30d'].includes(q.win) ? q.win : '24h'
  raw.value = typeof q.q === 'string' ? q.q : ''; filters.q = raw.value.trim()
  filters.page = typeof q.page === 'string' && /^[1-9]\d*$/.test(q.page) && Number.isSafeInteger(+q.page) ? +q.page : 1
  restoredKey = key(); restoring = false
}
restore()
function writeURL() {
  const q = { status: filters.status, dir: filters.dir, win: filters.win, q: filters.q, page: String(filters.page) }
  if (Object.entries(q).some(([k, v]) => route.query[k] !== v)) {
    writtenURL = router.resolve({ query: q }).fullPath
    void router.replace({ query: q })
  }
}
function commitSearch() {
  clearTimeout(debounce)
  if (invalid.value) return
  if (filters.q !== raw.value.trim()) { filters.q = raw.value.trim(); filters.page = 1 }
}
watch(raw, () => { clearTimeout(debounce); debounce = setTimeout(commitSearch, 400) })
const poll = usePoll(async () => {
  const snapshot = key(), stamp = Date.now(), f = { ...filters }, signal = lifetime.signal
  if (invalid.value) return { snapshot, idle: true }
  try {
    let status = f.status || 'active'
    let list = await api<{ attacks: Attack[] | null; total: number }>('attacks', listParams(f, status, stamp), signal)
    if (!f.status && !list.total) {
      status = 'all'; list = await api('attacks', listParams(f, status, stamp), signal)
    }
    const data = list.attacks ?? [], c: Record<string, number | null> = { [status]: list.total }
    await Promise.all(statuses.filter(s => s !== status).map(async s => {
      try { c[s] = (await api<{ total: number }>('attacks', listParams(f, s, stamp, true), signal)).total }
      catch { c[s] = null }
    }))
    let live: Active | undefined, liveError = ''
    if (data.some(a => !a.ended_at)) {
      try { live = await api<Active>('attacks/active', { limit: 1000 }, signal) }
      catch (e) { liveError = e instanceof Error ? e.message : String(e) }
    }
    const mitigation = await briefs(data.map(a => a.id), signal)
    return { snapshot, stamp, status, list, data, c, live, liveError, mitigation }
  } catch (e) { return { snapshot, failure: e instanceof Error ? e.message : String(e) } }
}, 5000, result => {
  if (result.snapshot !== key()) { queueMicrotask(() => void poll.refresh()); return }
  if ('idle' in result) return
  now.value = Date.now()
  loading.value = false
  if ('failure' in result) { error.value = result.failure!; return }
  rows.value = result.data!; total.value = result.list!.total; counts.value = result.c!
  if (result.live) active.value = result.live
  activeError.value = result.liveError!; brief.value = result.mitigation!; error.value = ''
  updated.value = Date.now()
  if (!filters.status) { filters.status = result.status!; writeURL() }
  const last = Math.max(1, Math.ceil(total.value / PAGE))
  if (filters.page > last) filters.page = last
})
watch(() => route.query, () => {
  const previous = key(), ownWrite = route.fullPath === writtenURL
  writtenURL = ''; restore()
  if (!ownWrite || key() !== previous) void poll.refresh()
})
watch(() => [filters.status, filters.dir, filters.win], () => {
  if (!restoring) filters.page = 1
}, { flush: 'sync' })
watch(key, value => {
  if (!restoring && value !== restoredKey) { writeURL(); void poll.refresh() }
})
onUnmounted(() => { lifetime.abort(); clearTimeout(debounce) })
const info = (a: Attack) => statusInfo(a, active.value, activeError.value)
function stateText(a: Attack) {
  const s = info(a)
  return a.ended_at ? t('data.ended', { time: dateTime(a.ended_at).slice(6, 11) }) : s.key === 'missing' ? '—'
    : t('attacks.' + (s.key === 'breaching' ? 'breachingNow' : s.key), { time: countdown(s.seconds) })
}
const stateTitle = (a: Attack) => a.ended_at ? fullDateTime(a.ended_at) : info(a).tip
  ? t('attacks.' + info(a).tip) === 'attacks.' + info(a).tip ? info(a).tip : t('attacks.' + info(a).tip) : ''
function open(event: Event, id: number) {
  if (!(event.target as Element).closest('button,a,input,[role=alertdialog]')) void router.push('/attacks/' + id)
}
const briefStatus = (status: string, type: string) => te('attacks.' + type + '_' + status)
  ? t('attacks.' + type + '_' + status, { time: '' }) : te('attacks.' + status) ? t('attacks.' + status) : status
const briefTitle = (row: any, xdrop: boolean) => xdrop
  ? row.external_rule_id + ' · ' + statusLabel(row.status, t) + (row.scheduled_for
    ? ' · ' + countdown((Date.parse(row.scheduled_for) - now.value) / 1000) : '')
  : row.prefix + ' · ' + row.route_map + ' · ' + statusLabel(row.status, t)
</script>
<template>
  <section class="page attacks-page">
    <header class="page-head"><h1>{{ t('nav.attacks') }}</h1><span v-if="updated" class="sub">
      {{ t('data.updated', { time: fullDateTime(new Date(updated).toISOString()).slice(11) }) }}</span></header>
    <p v-if="error" role="alert" class="crit">{{ error }}</p>
    <div class="toolbar filters"><div class="chips">
      <button v-for="s in statuses" :key="s" class="chip" :aria-pressed="filters.status === s"
        @click="filters.status = s">{{ t('attacks.' + (s === 'active' ? 'ongoing' : s === 'all' ? 'allStatuses' : s)) }}
        <span class="num">{{ counts[s] ?? '—' }}</span></button></div>
      <XSeg v-model="filters.dir" :label="t('data.direction')" :options="['all', 'receives', 'sends'].map(value =>
        ({ value, label: t(value === 'all' ? 'attacks.allDirections' : 'data.' + value) }))" />
      <XSeg v-if="filters.status === 'expired'" v-model="filters.win" :label="t('data.range')"
        :options="['24h', '7d', '30d'].map(value => ({ value, label: value }))" />
      <input v-model="raw" class="search" type="search" :aria-label="t('attacks.targetSearch')"
        :placeholder="t('attacks.searchPlaceholder')" :aria-invalid="invalid"
        aria-describedby="target-hint target-error"
        @keydown.enter="commitSearch" @blur="commitSearch" />
    </div>
    <p id="target-error" v-if="invalid" class="crit" role="alert">{{ t('attacks.searchInvalid') }}</p>
    <p id="target-hint" class="sub">{{ t('attacks.searchHint') }}</p>
    <XEmpty v-if="loading" loading />
    <div v-else class="tbl-wrap"><table class="attack-table"><thead><tr>
      <th>ID</th><th>{{ t('data.dst_ip') }}</th><th>{{ t('data.attack_type') }}</th>
      <th>{{ t('attacks.severity') }}</th><th>{{ t('attacks.peakPps') }}</th><th>{{ t('attacks.peakBps') }}</th>
      <th>{{ t('data.mitigation') }}</th><th>{{ t('attacks.triggerRule') }}</th><th>{{ t('attacks.start') }}</th>
      <th>{{ t('attacks.elapsed') }}</th><th>{{ t('data.status') }}</th><th>{{ t('attacks.operation') }}</th>
    </tr></thead><tbody>
      <template v-for="a in rows" :key="a.id"><tr :class="a.ended_at ? 'atk-ended' : 'atk-live'" tabindex="0"
        @click="open($event, a.id)" @keydown.enter.self="open($event, a.id)">
        <td><RouterLink :to="'/attacks/' + a.id">#{{ a.id }}</RouterLink></td>
        <td><TargetCell :value="a.dst_ip" :direction="a.direction" /></td>
        <td :title="a.attack_type + ' · ' + a.decoder_family">{{ a.decoder_family === 'ip'
          ? t('attacks.ipTotal') : a.decoder_family }}</td>
        <td><XPill :tone="['critical', 'high'].includes(a.severity) ? 'crit'
          : a.severity === 'medium' ? 'warn' : 'neutral'">
          {{ t('attacks.' + a.severity) }}</XPill></td>
        <td class="num" :class="{ 'c-drop': !a.ended_at }">{{ a.peak_pps ? pps(a.peak_pps) : '—' }}</td>
        <td class="num muted">{{ a.peak_bps ? bps(a.peak_bps) : '—' }}</td>
        <td><span class="brief"><XPill v-for="(r, i) in brief[a.id]?.xdrop_rules ?? []" :key="'x' + i"
          :title="briefTitle(r, true)">XDrop · {{ briefStatus(r.status, 'xdrop') }}</XPill>
          <XPill v-for="(r, i) in brief[a.id]?.bgp ?? []" :key="'b' + i"
            :title="briefTitle(r, false)">BGP · {{ briefStatus(r.status, 'bgp') }}</XPill>
          <span v-if="!brief[a.id]?.xdrop_rules?.length && !brief[a.id]?.bgp?.length">—</span></span></td>
        <td class="rule" :title="[a.template_name, a.rule_summary].filter(Boolean).join(' · ')">
          {{ a.template_name }} <span class="mono muted">{{ a.rule_summary }}</span>
          <span v-if="!a.template_name && !a.rule_summary">—</span></td>
        <td class="num" :title="fullDateTime(a.started_at)">{{ dateTime(a.started_at) }}</td>
        <td class="num">{{ duration(((a.ended_at ? Date.parse(a.ended_at) : now)
          - Date.parse(a.started_at)) / 1000) }}</td>
        <td :title="stateTitle(a)">{{ stateText(a) }}</td>
        <td><button v-if="!a.ended_at && isAdmin()" class="btn sm crit-line"
          @click="confirm = a.id">{{ t('attacks.endAction') }}</button>
        </td>
      </tr><tr v-if="confirm === a.id" class="confirmation-row"><td colspan="12">
        <ExpireConfirm :model-value="confirm === a.id" :attack="a"
          @update:model-value="confirm = $event ? a.id : null" @done="poll.refresh" />
      </td></tr></template>
    </tbody></table><XEmpty v-if="!rows.length">{{ t('attacks.noMatches') }}</XEmpty></div>
    <XPager v-model="filters.page" :total="total" :page-size="PAGE" :busy="loading" />
  </section>
</template>
<style scoped>
.filters { flex-wrap: wrap; margin-bottom: 8px; }
.chips { display: flex; gap: 6px; }
.chip { display: inline-flex; gap: 6px; padding: 6px 10px; border: 1px solid var(--line);
  border-radius: 999px; background: var(--panel); color: var(--muted); font: inherit; cursor: pointer;
  white-space: nowrap; }
.chip[aria-pressed="true"] { color: var(--drop); background: var(--drop-soft); border-color: var(--drop); }
.filters :deep(.seg) { flex-shrink: 0; }
.attack-table { min-width: 1320px; }
.attack-table tr { cursor: pointer; }
.atk-live td:first-child { border-left: 3px solid var(--drop); }
.atk-ended { color: var(--muted); }
.rule { max-width: 210px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.c-drop { color: var(--drop); }
.brief { display: inline-flex; gap: 4px; flex-wrap: wrap; }
.search { min-width: 230px; flex: 1; }
:deep(.confirm) { max-width: calc(100vw - 48px); width: 680px; white-space: normal; }
.confirmation-row td { cursor: default; }
@media (max-width: 640px) { .chips { width: 100%; } .search { min-width: 0; width: 100%; } }

@media (min-width: 1100px) {
  .attack-table { min-width: 0; width: 100%; table-layout: fixed; font-size: 11px; }
  .attack-table th, .attack-table td { padding: 7px 6px; white-space: nowrap;
    overflow: hidden; text-overflow: ellipsis; }
  .attack-table th:nth-child(1) { width: 4%; }
  .attack-table th:nth-child(2) { width: 14%; }
  .attack-table th:nth-child(3), .attack-table th:nth-child(4), .attack-table th:nth-child(12) { width: 5%; }
  .attack-table th:nth-child(5) { width: 6%; }
  .attack-table th:nth-child(6) { width: 8%; }
  .attack-table th:nth-child(7), .attack-table th:nth-child(9) { width: 11%; }
  .attack-table th:nth-child(8), .attack-table th:nth-child(11) { width: 12%; }
  .attack-table th:nth-child(10) { width: 7%; }
  .attack-table :deep(.target-cell) { max-width: 100%; }
  .attack-table :deep(.target-cell .mono) { overflow: hidden; text-overflow: ellipsis; }
  .attack-table .brief { max-width: 100%; }
  .attack-table :deep(.pill) { max-width: 100%; overflow: hidden; text-overflow: ellipsis; }
  .filters :deep(.seg button) { white-space: nowrap; }
}
</style>
