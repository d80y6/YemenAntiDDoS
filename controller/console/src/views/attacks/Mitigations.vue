<script setup lang="ts">
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import XPill from '../../components/XPill.vue'
import { otherHolders, isSyntheticRuleId } from '../../api/xdropRules'
import { connectorName, countdown, delaySeconds, type Row } from './data'
const props = defineProps<{ data: Row; holders: Row[]; responseId: number | null; now: number }>()
const { t, te } = useI18n()
const xdrop = computed<Row[]>(() => props.data.xdrop_rules ?? [])
const bgp = computed<Row[]>(() => props.data.bgp_announcements ?? [])
const executions = computed<Row[]>(() => props.data.executions ?? [])
function content(row: Row) {
  const match = props.holders.find(r => ['attack_id', 'action_id', 'connector_id', 'external_rule_id']
    .every(k => r[k] === row[k]))
  return match ? [match.dst_ip, match.protocol, match.src_port ? t('attacks.matchSrcPort') + ':' + match.src_port : '',
    match.dst_port ? t('attacks.matchDstPort') + ':' + match.dst_port : ''].filter(Boolean).join(' · ') || '—' : '—'
}
function status(row: Row, type: string) {
  const key = 'attacks.' + type + '_' + row.status
  return te(key) ? t(key, { time: countdown(delaySeconds(row, props.now)) }) : row.status === 'failed'
    ? t('attacks.failed') : row.status
}
</script>
<template>
  <article class="panel mitigation-panel"><div class="panel-head"><h2>{{ t('data.mitigation') }}</h2>
    <span class="sub">{{ t('attacks.actionSummary', { n: data.summary?.total_evaluated ?? 0,
      a: data.summary?.success ?? 0, b: data.summary?.failed ?? 0, c: data.summary?.skipped ?? 0 }) }}</span></div>
    <div v-if="xdrop.length || bgp.length" class="tbl-wrap"><table><thead><tr>
      <th>{{ t('attacks.ruleAnnouncement') }}</th><th>{{ t('attacks.content') }}</th>
      <th>{{ t('attacks.connector') }}</th><th>{{ t('data.status') }}</th>
    </tr></thead><tbody>
      <tr v-for="r in xdrop" :key="'x' + r.id"><td class="mono">{{ r.external_rule_id }}
        <XPill v-if="isSyntheticRuleId(r.external_rule_id)" tone="crit">{{ t('attacks.deliveryFailed') }}</XPill></td>
        <td>{{ content(r) }}</td><td>{{ connectorName(executions, r, 'xdrop') }}</td><td>{{ status(r, 'xdrop') }}
          <XPill v-if="otherHolders(holders as any, r as any)" :title="t('attacks.heldTip',
            { n: otherHolders(holders as any, r as any) })">{{ t('attacks.held',
              { n: otherHolders(holders as any, r as any) }) }}</XPill></td></tr>
      <tr v-for="b in bgp" :key="'b' + b.announcement.id"><td class="mono">{{ b.announcement.prefix }}</td>
        <td>{{ t('attacks.bgpContent', { name: b.announcement.route_map }) }}
          <span v-if="b.detached_at === null && b.attack_delay_minutes != null" class="sub"> ·
            {{ t('attacks.afterDelay', { n: b.attack_delay_minutes }) }}</span></td>
        <td>{{ connectorName(executions, b.announcement, 'bgp') }}</td>
        <td>{{ status(b.announcement, 'bgp') }} <XPill>{{ t('attacks.references',
          { n: b.announcement.refcount }) }}</XPill></td></tr>
    </tbody></table></div>
    <p v-else class="empty">{{ t(responseId ? 'attacks.noMitigations' : 'attacks.noBoundMitigations') }}</p>
    <p><RouterLink to="/mitigations">{{ t('attacks.mitigationLink') }}</RouterLink></p>
  </article>
</template>
<style scoped>
table { min-width: 760px; }
th, td { white-space: nowrap; }
</style>
