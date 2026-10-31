<script setup lang="ts">
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import { duration } from '../../format'
import { countdown, type Row } from '../attacks/data'
import { isSyntheticRuleId } from '../../api/xdropRules'
import { statusLabel } from './data'
const props = defineProps<{ row: Row; now: number; kind: string }>()
const { t } = useI18n()
const tones: Record<string, string> = { active: 'ok', delayed: 'warn', failed: 'crit' }
const tone = computed(() => tones[props.row.status] ?? 'neutral')
const tip = computed(() => props.row.status === 'delayed' ? t('mitigations.delayedTip')
  : props.row.status === 'failed' && props.kind === 'xdrop' ? isSyntheticRuleId(props.row.external_rule_id)
    ? t('mitigations.createFailedTip', { id: props.row.external_rule_id })
    : t('mitigations.failedRetryTip') : undefined)
</script>
<template>
  <span :class="['dot', tone]" :title="tip" /> <span :title="tip">{{ statusLabel(row.status, t) }}</span>
  <small v-if="row.status === 'active'" class="sub num">
    {{ duration((now - Date.parse(row.created_at)) / 1000) }}</small>
  <small v-if="row.status === 'delayed' && row.scheduled_for" class="warn num">
    {{ countdown((Date.parse(row.scheduled_for) - now) / 1000) }}
  </small>
</template>

<style scoped>
small { margin-left: 4px; }
</style>
