<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, shallowRef } from 'vue'
import { useI18n } from 'vue-i18n'
import { rounds } from './poll'
import { settle, minStamp, type Stamp } from './split'
import { request } from '../../api/client'
import { ApiError } from '../../api/client'
import { isSyntheticRuleId, otherHolders } from '../../api/xdropRules'
import { dateTime, fullDateTime } from '../../format'
import { isAdmin } from '../../auth'
import { notify } from '../../notifications'
import { forceBody, target } from '../attacks/data'
import { actionLabel, attackLinks, bgpConfirmation, businessKey, connector, disabledConnector,
  matchSummary, xdropConfirmation, type Row } from './data'
import XConfirm from '../../components/XConfirm.vue'
import XTip from '../../components/XTip.vue'
import XEmpty from '../../components/XEmpty.vue'
import Detail from './Detail.vue'
import Status from './Status.vue'
import RuleId from './RuleId.vue'
import Flowspec from './Flowspec.vue'
import XTabs from '../../components/XTabs.vue'
const { t } = useI18n()
const rows = shallowRef<Row[]>([]), dismissed = shallowRef<Row[]>([]), xdrop = shallowRef<Row[]>([])
const connectors = shallowRef<Row[]>([]), errors = ref(['', '', '']), updated = ref(0)
const loaded = ref([false, false, false, false])
const stamps: Stamp[] = Array.from({ length: 4 }, () => ({ lastOk: null, failing: false }))
const expanded = ref(false), now = ref(Date.now()), drawerOpen = ref(false), kind = ref('bgp'), tab = ref('bgp')
const tabs = [
  { value: 'bgp', label: t('mitigations.bgpTitle') },
  { value: 'flowspec', label: t('flowspec.title') },
  { value: 'xdrop', label: t('mitigations.xdropTitle') },
]
const selected = shallowRef<Row>(), missing = ref(false)
const bgp = computed(() => rows.value.filter(r => !r.is_orphan))
const orphans = computed(() => rows.value.filter(r => r.is_orphan))
const lifetime = new AbortController()
let timer: ReturnType<typeof setInterval>
const paths = ['bgp', 'bgp/dismissed-orphans', 'xdrop'].map(p => '/api/active-actions/' + p)
  .concat('/api/settings/xdrop-connectors')
const sets = [rows, dismissed, xdrop, connectors]
const polls = paths.map((p, i) => rounds(() => settle(request<Row[] | null>(p,
  { signal: lifetime.signal })), 5000, r => {
  loaded.value[i] = true
  if (r.status === 'fulfilled') { sets[i]!.value = r.value ?? []; if (i < 3) errors.value[i] = '' }
  else if (i < 3) errors.value[i] = r.reason?.message || String(r.reason)
  else connectors.value = []
  stamps[i]!.failing = r.status === 'rejected'
  if (r.status === 'fulfilled') stamps[i]!.lastOk = Date.now()
  updated.value = minStamp(stamps, updated.value)
  if (selected.value && i === (kind.value === 'bgp' ? 0 : 2)) {
    const latest = (kind.value === 'bgp' ? rows.value : xdrop.value)
      .find(r => businessKey(r, kind.value) === businessKey(selected.value!, kind.value))
    missing.value = !latest
    if (latest) selected.value = latest
  }
}))
const poll = { refresh: () => Promise.all(polls.map(p => p.refresh())) }
onMounted(() => { timer = setInterval(() => { now.value = Date.now() }, 1000) })
onUnmounted(() => { clearInterval(timer); lifetime.abort() })
function open(row: Row, type: string) {
  selected.value = row; kind.value = type; missing.value = false; drawerOpen.value = true
}
const confirm = shallowRef<{ row: Row; op: string; title: string; description: string; label: string }>()
const confirming = ref(false)
function ask(row: Row, op: string) {
  const text = op === 'bgp' ? { ...bgpConfirmation(row, t), label: t('attacks.withdraw') }
    : op === 'xdrop' ? xdropConfirmation(row, otherHolders(xdrop.value as any, row as any), t)
      : { title: t('mitigations.' + ({ withdraw: 'orphanWithdraw', dismiss: 'dismissTitle',
        undismiss: 'undismissTitle' }[op]!), { prefix: row.prefix }),
      description: op === 'withdraw' ? '' : t('mitigations.'
        + (op === 'dismiss' ? 'dismissDescription' : 'undismissDescription')),
      label: t(op === 'withdraw' ? 'attacks.withdraw' : 'mitigations.' + op) }
  confirm.value = { row, op, ...text }; confirming.value = true
}
async function execute() {
  const { row, op } = confirm.value!
  const generic = op === 'bgp' || op === 'xdrop'
  const path = generic ? '/api/active-actions/force-remove' : '/api/active-actions/bgp/orphan-'
    + ({ withdraw: 'force-withdraw', dismiss: 'dismiss', undismiss: 'undismiss' }[op])
  try {
    if (op === 'xdrop' && !loaded.value[3]) throw new Error(t('common.loading'))
    if (op === 'xdrop' && disabledConnector(row, connectors.value)) {
      throw new Error(t('mitigations.disabledForceTip'))
    }
    const result = await request<Row>(path, { method: 'POST', body: JSON.stringify(generic
      ? forceBody(row.attack_id, row) : { announcement_id: row.announcement_id }) })
    const key = op === 'dismiss' ? 'mitigations.dismissed' : op === 'undismiss' ? 'mitigations.undismissed'
      : op === 'xdrop' ? isSyntheticRuleId(row.external_rule_id) ? 'mitigations.closedFailed'
        : 'attacks.holdReleased' : 'attacks.forceRemoved'
    notify(result.warning || t(key), result.warning ? 'warn' : 'ok')
    await poll.refresh()
  } catch (e) {
    const timeout = op === 'xdrop' && e instanceof ApiError && e.timeout
    const message = timeout ? t('mitigations.forceTimeout') : e instanceof Error && e.message
      ? e.message : t('mitigations.forceFailed')
    notify(message, timeout ? 'warn' : 'crit')
    throw new Error(message)
  }
}
const holderCount = (row: Row) => otherHolders(xdrop.value as any, row as any)
const showConfirm = (row: Row, op: string) => confirming.value && confirm.value?.op === op
  && (['bgp', 'xdrop'].includes(op) ? businessKey(confirm.value.row, op) === businessKey(row, op)
    : confirm.value.row.announcement_id === row.announcement_id)
const headers = (keys: string[]) => keys.map(k => t('mitigations.' + k))
</script>
<template>
  <div class="page mitigations-page">
    <div class="page-head"><h1>{{ t('nav.mitigations') }}</h1><span v-if="updated" class="sub">
      {{ t('data.updated', { time: fullDateTime(new Date(updated).toISOString()).slice(11) }) }}</span></div>
    <XTabs v-model="tab" :tabs="tabs" label="Mitigations" query />
    <section v-if="orphans.length && tab === 'bgp'" class="orphan confirm" data-testid="orphans">
      <strong>{{ t('mitigations.orphanBannerTitle', { count: orphans.length }) }}</strong>
      <p class="sub">{{ t('mitigations.orphanBannerDesc') }}</p>
      <div class="tbl-wrap"><table><tbody><template v-for="row in orphans" :key="row.announcement_id">
        <tr><td class="mono strong">{{ row.prefix }}</td>
          <td class="mono">{{ row.route_map }}</td>
          <td>{{ connector(row, []) }}</td><td class="sub" :title="fullDateTime(row.created_at)">
            {{ t('mitigations.detected', { time: dateTime(row.created_at).slice(6, 11) }) }}</td>
          <td v-if="isAdmin()" class="ops"><button class="btn sm" @click="ask(row, 'withdraw')">
            {{ t('attacks.forceWithdraw') }}</button><button class="btn sm ghost" @click="ask(row, 'dismiss')">
            {{ t('mitigations.dismiss') }}</button></td></tr>
        <tr v-if="showConfirm(row, 'withdraw') || showConfirm(row, 'dismiss')"><td colspan="5">
          <XConfirm v-model="confirming" :title="confirm!.title" :description="confirm!.description"
            :confirm-label="confirm!.label" tone="danger" :action="execute" /></td></tr>
      </template></tbody></table></div>
    </section>
    <template v-if="tab === 'bgp'"><section class="panel" data-testid="bgp"><div class="panel-head"><h2>{{ t('mitigations.bgpTitle') }}
      <span class="sub num">{{ bgp.length }}</span></h2>
      <button class="btn sm ghost" :aria-expanded="expanded" @click="expanded = !expanded">
        {{ t('mitigations.viewDismissedOrphans', { count: dismissed.length }) }}
        {{ expanded ? '▴' : '▾' }}</button></div>
      <p v-if="errors[0]" class="crit mono" role="alert">{{ errors[0] }}
        <button class="btn sm" @click="poll.refresh">{{ t('attacks.retry') }}</button></p>
      <div class="tbl-wrap"><table><thead><tr><th v-for="h in headers(
        ['prefix', 'routeMap', 'connector', 'attack', 'announcedAt', 'status', 'operation'])" :key="h">{{ h }}</th>
      </tr></thead><tbody><template v-for="row in bgp" :key="businessKey(row, 'bgp')">
        <tr class="link" tabindex="0" @click="($event.target as Element).closest('button,a,[role=alertdialog]')
          || open(row, 'bgp')" @keydown.enter.self="open(row, 'bgp')">
          <td class="mono strong">{{ row.prefix }}</td><td class="mono">{{ row.route_map }}</td>
          <td>{{ connector(row, []) }}</td><td><RouterLink v-for="id in attackLinks(row).ids" :key="id"
            :to="'/attacks/' + id">#{{ id }} </RouterLink>
            <span v-if="attackLinks(row).detached" class="sub" :title="t('mitigations.detachedTip')">
              {{ t('mitigations.detachedCount', { n: attackLinks(row).detached }) }}</span>
            <span v-if="!attackLinks(row).ids.length && !attackLinks(row).detached">—</span></td>
          <td class="sub num" :title="fullDateTime(row.created_at)">{{ dateTime(row.created_at).slice(6) }}</td>
          <td><Status :row="row" :now="now" kind="bgp" /></td><td>
            <button v-if="isAdmin()" class="btn sm" @click="ask(row, 'bgp')">{{ t('attacks.forceWithdraw') }}</button>
          </td></tr>
        <tr v-if="showConfirm(row, 'bgp')"><td colspan="7"><XConfirm v-model="confirming"
          :title="confirm!.title" :description="confirm!.description" :confirm-label="confirm!.label"
          tone="danger" :action="execute" /></td></tr>
      </template></tbody></table><XEmpty v-if="!bgp.length" :loading="!loaded[0]" /></div>
      <p v-if="errors[1]" class="crit mono" role="alert">{{ errors[1] }}
        <button class="btn sm" @click="poll.refresh">{{ t('attacks.retry') }}</button></p>
      <template v-if="expanded"><h3 class="subh">{{ t('mitigations.dismissedTitle') }}
        <span class="sub">{{ t('mitigations.dismissedNote') }}</span></h3>
        <div class="tbl-wrap sub-tbl"><table><thead><tr><th v-for="h in headers(
          ['prefix', 'routeMap', 'connector', 'method', 'detectedAt', 'operation'])" :key="h">{{ h }}</th></tr></thead>
          <tbody><template v-for="row in dismissed" :key="row.announcement_id"><tr>
            <td class="mono">{{ row.prefix }}</td><td class="mono">{{ row.route_map }}</td>
            <td>{{ connector(row, []) }}</td><td>{{ t(row.status === 'dismissed_on_upgrade'
              ? 'mitigations.dismissedOnUpgrade' : 'mitigations.dismissedManual') }}</td>
            <td class="sub num" :title="fullDateTime(row.detected_at)">{{ dateTime(row.detected_at).slice(0, 11) }}</td>
            <td><button v-if="isAdmin()" class="btn sm ghost" :title="t('mitigations.undismissTip')"
              @click="ask(row, 'undismiss')">{{ t('mitigations.undismiss') }}</button></td></tr>
            <tr v-if="showConfirm(row, 'undismiss')"><td colspan="6"><XConfirm v-model="confirming"
              :title="confirm!.title" :description="confirm!.description" :confirm-label="confirm!.label"
              :action="execute" /></td></tr>
          </template></tbody></table><p v-if="!dismissed.length" class="empty">
            {{ t(loaded[1] ? 'mitigations.noDismissedOrphans' : 'common.loading') }}</p></div>
      </template>
    </section>
  </template>
  <template v-if="tab === 'flowspec'"><Flowspec :now="now" :admin="isAdmin()" /></template>
  <template v-if="tab === 'xdrop'">
    <section class="panel" data-testid="xdrop"><div class="panel-head"><h2>{{ t('mitigations.xdropTitle') }}
      <span class="sub num">{{ xdrop.length }}</span></h2><XTip :text="t('mitigations.xdropTip')" wide /></div>
      <p v-if="errors[2]" class="crit mono" role="alert">{{ errors[2] }}
        <button class="btn sm" @click="poll.refresh">{{ t('attacks.retry') }}</button></p>
      <div class="tbl-wrap"><table><thead><tr><th v-for="h in headers(
        ['rule', 'target', 'match', 'action', 'connector', 'attack', 'createdAt', 'status', 'operation'])" :key="h">
        {{ h }}</th></tr></thead><tbody><template v-for="row in xdrop" :key="businessKey(row, 'xdrop')">
        <tr class="link" tabindex="0" @click="($event.target as Element).closest('button,a,[role=alertdialog]')
          || open(row, 'xdrop')" @keydown.enter.self="open(row, 'xdrop')">
          <td><RuleId :row="row" :holders="holderCount(row)" /></td>
          <td class="mono">{{ target(row.dst_ip || '').text || '—' }}</td><td>{{ matchSummary(row, t) }}</td>
          <td>{{ actionLabel(row, t) }}</td><td>{{ connector(row, connectors) }}
            <span v-if="disabledConnector(row, connectors)" class="pill"
              :title="t('mitigations.connectorDisabledTip')">{{ t('mitigations.connectorDisabled') }}</span></td>
          <td><RouterLink :to="'/attacks/' + row.attack_id">#{{ row.attack_id }}</RouterLink></td>
          <td class="sub num" :title="fullDateTime(row.created_at)">{{ dateTime(row.created_at).slice(6) }}</td>
          <td><Status :row="row" :now="now" kind="xdrop" /></td><td><button v-if="isAdmin()" class="btn sm"
            :disabled="!loaded[3] || disabledConnector(row, connectors)"
            :title="disabledConnector(row, connectors) ? t('mitigations.disabledForceTip') : undefined"
            @click="ask(row, 'xdrop')">{{ t('attacks.forceUnblock') }}</button></td></tr>
        <tr v-if="showConfirm(row, 'xdrop')"><td colspan="9"><XConfirm v-model="confirming"
          :title="confirm!.title" :description="confirm!.description" :confirm-label="confirm!.label"
          :action="execute" /></td></tr>
      </template></tbody></table><XEmpty v-if="!xdrop.length" :loading="!loaded[2]" /></div>
    </section>
  </template>
  <Detail v-if="selected" :key="kind + businessKey(selected, kind)" v-model="drawerOpen"
      :row="selected" :kind="kind" :now="now" :missing="missing"
      :connectors="connectors" :holders="holderCount(selected)" />
  </div>
</template>
<style scoped>
.panel { margin-top: 14px; }
.panel-head { display: flex; justify-content: space-between; align-items: center; gap: 8px; }
.orphan { position: static; padding: 10px 12px 4px; }
.orphan p { margin: 2px 0 6px; }
table { width: 100%; }
td { overflow-wrap: anywhere; }
.ops { display: flex; gap: 6px; }
.subh { font-size: 12.5px; font-weight: 500; display: flex; flex-wrap: wrap; gap: 10px; margin: 14px 0 0; }
.sub-tbl { margin-top: 6px; border-top: 1px solid var(--line); }
.strong { font-weight: 600; }
td small { margin-left: 4px; }
td a + a, td a + .sub { margin-left: 4px; }
@media (max-width: 700px) { table { min-width: 920px; } .panel-head { flex-wrap: wrap; } }
</style>
