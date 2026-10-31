<script setup lang="ts">
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import XDrawer from '../../components/XDrawer.vue'
import XTip from '../../components/XTip.vue'
import { api } from '../../api/data'
import { deliveryStateType, isSyntheticRuleId } from '../../api/xdropRules'
import { dateTime, fullDateTime } from '../../format'
import { actionKey, phaseKey, target } from '../attacks/data'
import { actionLabel, businessKey, connector, deliveryResult, disabledConnector, matchSummary, timelineRows,
  type Row } from './data'
import { lookup } from './lookup'
import Status from './Status.vue'
import RuleId from './RuleId.vue'
import { request } from '../../api/client'
const props = defineProps<{ modelValue: boolean; row: Row; kind: string; now: number; connectors: Row[];
  holders: number; missing: boolean }>()
const emit = defineEmits<{ 'update:modelValue': [value: boolean] }>()
const { t, te } = useI18n()
const open = computed({ get: () => props.modelValue, set: value => emit('update:modelValue', value) })
const identity = () => props.modelValue ? businessKey(props.row, props.kind) : ''
const synthetic = computed(() => isSyntheticRuleId(props.row.external_rule_id))
const delivery = lookup(() => identity() && props.kind === 'xdrop' && !synthetic.value ? identity() : '', signal => {
  const q = new URLSearchParams({ connector_id: String(props.row.connector_id), rule_id: props.row.external_rule_id })
  return request<Row>('/api/active-actions/xdrop/delivery?' + q, { signal, allow: [404] })
})
const result = computed(() => deliveryResult(delivery.data.value, delivery.error.value))
const timeline = lookup(() => identity() && props.row.attack_id > 0 ? identity() : '', signal =>
  api<{ logs: Row[] | null }>('active-actions/timeline', { attack_id: props.row.attack_id,
    action_id: props.row.action_id || 0, connector_id: props.row.connector_id || 0,
    external_rule_id: props.row.external_rule_id }, signal))
const logs = computed(() => timelineRows(timeline.data.value?.logs ?? null, props.row))
const label = (group: string, value: string) => te(group + value) ? t(group + value) : value
function stateLabel(state: string) {
  const key = 'mitigations.deliveryState' + state[0]?.toUpperCase() + state.slice(1)
  return te(key) ? t(key) : state
}
</script>
<template>
  <XDrawer v-model="open" :width="460" :title="t(kind === 'bgp' ? 'mitigations.bgpDrawer'
    : 'mitigations.xdropDrawer', { id: kind === 'bgp' ? row.prefix : synthetic ? '—' : row.external_rule_id })">
    <p v-if="missing" class="sub">{{ t('mitigations.noLongerActive') }}</p>
    <dl class="kv">
      <template v-if="kind === 'bgp'">
        <dt>{{ t('mitigations.prefix') }}</dt><dd class="mono">{{ row.prefix }}</dd>
        <dt>{{ t('mitigations.routeMap') }}</dt><dd class="mono">{{ row.route_map }}</dd>
      </template>
      <template v-else>
        <dt>{{ t('mitigations.ruleId') }}</dt><dd><RuleId :row="row" :holders="0" /></dd>
        <dt>{{ t('mitigations.target') }}</dt><dd class="mono">{{ target(row.dst_ip || '').text || '—' }}</dd>
        <dt>{{ t('mitigations.match') }}</dt><dd>{{ matchSummary(row, t) }}</dd>
        <dt>{{ t('mitigations.tcpFlags') }}</dt><dd class="mono">{{ row.tcp_flags || '—' }}</dd>
        <dt>{{ t('mitigations.action') }}</dt><dd>{{ actionLabel(row, t) }}</dd>
      </template>
      <dt>{{ t('mitigations.connector') }}</dt><dd>{{ connector(row, kind === 'xdrop' ? connectors : []) }}
        <span v-if="kind === 'xdrop' && disabledConnector(row, connectors)" class="pill"
          :title="t('mitigations.connectorDisabledTip')">{{ t('mitigations.connectorDisabled') }}</span>
      </dd>
      <dt>{{ t('mitigations.status') }}</dt><dd><Status :row="row" :now="now" :kind="kind" /></dd>
      <template v-if="kind === 'bgp'">
        <dt>{{ t('mitigations.attackTarget') }}</dt><dd class="mono">{{ row.attack_dst_ip || '—' }}</dd>
        <template v-if="row.attached_attacks?.length">
          <dt>{{ t('mitigations.attachedAttacks', { n: row.attached_attacks.length }) }}
            <XTip :text="t('mitigations.attachedTip')" wide /></dt>
          <dd><div v-for="a in row.attached_attacks" :key="a.attack_id" class="attachment">
            <RouterLink :to="'/attacks/' + a.attack_id" @click="open = false">#{{ a.attack_id }}</RouterLink>
            <span v-if="a.decoder" class="pill mono">{{ a.decoder }}</span>
            <span v-if="a.response_name" class="pill">{{ a.response_name }}</span>
            <span v-if="a.delay_minutes != null" class="pill">
              {{ t('mitigations.delay', { n: a.delay_minutes }) }}</span>
            <span v-if="a.detached_at" class="sub">{{ t('mitigations.detached', {
              time: fullDateTime(a.detached_at) }) }}</span>
            <span v-else class="pill ok">{{ t('mitigations.attachedCurrent') }}</span>
          </div></dd>
        </template>
      </template>
      <template v-else>
        <dt>{{ t('mitigations.attack') }}</dt><dd><RouterLink :to="'/attacks/' + row.attack_id"
          @click="open = false">#{{ row.attack_id }}</RouterLink></dd>
        <template v-if="holders > 0"><dt>{{ t('mitigations.otherHolders', { n: holders }) }}</dt><dd /></template>
      </template>
    </dl>
    <template v-if="kind === 'xdrop'">
      <p v-if="synthetic" class="note">{{ t('mitigations.syntheticDelivery') }}</p>
      <template v-else>
        <div class="dh"><h3>{{ t('mitigations.delivery') }}<XTip :text="t('mitigations.deliveryTip')" wide /></h3>
          <button class="btn sm ghost" :disabled="delivery.loading.value" @click="delivery.refresh">
            {{ t('mitigations.deliveryRefresh') }}</button></div>
        <p v-if="delivery.loading.value" class="sub" role="status">{{ t('common.loading') }}</p>
        <table v-else-if="result.kind === 'nodes'" class="delivery-table"><tbody>
          <tr v-for="n in result.nodes" :key="n.name"><td class="mono">{{ n.name }}</td><td>
            <span :class="['dot', deliveryStateType(n.state)]" />
            <span :title="n.code || n.error ? n.error : undefined">{{ stateLabel(n.state) }}</span>
            <span v-if="n.code" class="sub mono" :title="[n.code, n.error].filter(Boolean).join(' · ')">
              {{ n.code }}</span>
          </td></tr>
        </tbody></table>
        <p v-else class="empty" :class="result.kind === 'failed' ? 'crit' : 'sub'">
          {{ t('mitigations.delivery' + result.kind[0]!.toUpperCase() + result.kind.slice(1)) }}
          <span v-if="result.message" class="sub mono" :title="result.message">{{ result.message }}</span>
        </p>
      </template>
    </template>
    <h3 class="sub">{{ t('mitigations.timeline') }}</h3>
    <p v-if="timeline.loading.value" class="sub">{{ t('common.loading') }}</p>
    <p v-else-if="timeline.error.value" class="crit mono" role="alert">{{ String(
      timeline.error.value instanceof Error ? timeline.error.value.message : timeline.error.value) }}</p>
    <p v-else-if="!logs.length" class="empty">{{ t('mitigations.noTimeline') }}</p>
    <ol v-else class="tl"><li v-for="(log, i) in logs" :key="i"
      :class="{ override: log.trigger_phase === 'manual_override' }">
      <time class="sub num" :title="fullDateTime(log.executed_at)">{{ dateTime(log.executed_at).slice(6) }}</time>
      {{ label('attacks.', actionKey(log)) }}
      <span class="pill" :class="{ warn: log.trigger_phase === 'manual_override' }"
        :title="t('mitigations.triggerPhaseLabel') + ' ' + log.trigger_phase">
        {{ label('attacks.', phaseKey(log.trigger_phase)) }}</span>
      <span :class="log.status === 'failed' ? 'crit' : 'sub'">{{ log.status === 'pending'
        ? t('attacks.statusPending') : label('attacks.', log.status) }}</span>
      <span v-if="log.duration_ms > 0" class="sub num">{{ ' · ' + log.duration_ms + ' ms' }}</span>
      <div v-if="log.error_message" class="mono" :class="log.status === 'failed' ? 'crit' : 'sub'">
        {{ log.error_message }}</div>
    </li></ol>
  </XDrawer>
</template>
<style scoped>
.kv { grid-template-columns: 112px minmax(0, 1fr); }
.attachment { display: flex; flex-wrap: wrap; align-items: center; gap: 4px; margin-bottom: 8px; }
.dh, .dh h3 { display: flex; align-items: center; justify-content: space-between; gap: 4px; }
.dh { margin-top: 18px; }
h3 { font-size: 13px; font-weight: 500; }
.delivery-table { width: 100%; }
.delivery-table td { padding: 4px 0; }
.tl { padding-left: 12px; border-left: 2px solid var(--line); list-style: none; }
.tl li { position: relative; margin: 0 0 10px; }
.tl li::before { content: ''; position: absolute; left: -17px; top: 6px; width: 8px; height: 8px;
  border: 2px solid var(--muted); border-radius: 50%; background: var(--panel); }
.tl li.override::before { border-color: var(--warn); }
.tl .mono { word-break: break-all; }
</style>
