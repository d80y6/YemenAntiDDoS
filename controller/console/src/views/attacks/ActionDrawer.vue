<script setup lang="ts">
import { ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import XDrawer from '../../components/XDrawer.vue'
import XSeg from '../../components/XSeg.vue'
import { fullDateTime } from '../../format'
import { formattedJSON, actionKey, phaseKey, type Row } from './data'
const props = defineProps<{ modelValue: boolean; row: Row | null }>()
const emit = defineEmits<{ 'update:modelValue': [value: boolean] }>()
const { t, te } = useI18n(), mode = ref('formatted')
watch(() => [props.modelValue, props.row], () => { if (props.modelValue) mode.value = 'formatted' })
const label = (key: string) => te('attacks.' + key) ? t('attacks.' + key) : key
</script>
<template>
  <XDrawer :model-value="modelValue" :title="row ? label(actionKey(row)) + ' · ' + row.connector_name : ''"
    :width="460"
    @update:model-value="emit('update:modelValue', $event)">
    <template v-if="row"><dl class="kv">
      <dt>{{ t('attacks.triggerPhase') }}</dt><dd>{{ label(phaseKey(row.trigger_phase)) }}</dd>
      <dt>{{ t('data.status') }}</dt><dd>{{ row.status === 'pending'
        ? t('attacks.statusPending') : label(row.status) }}</dd>
      <dt>{{ t('attacks.time') }}</dt><dd>{{ fullDateTime(row.executed_at) }}</dd>
      <dt>HTTP</dt><dd>{{ row.status_code ?? '—' }}</dd>
      <dt>{{ t('attacks.durationMs') }}</dt><dd>{{ ['skipped', 'scheduled'].includes(row.status)
        ? '—' : row.duration_ms + ' ms' }}</dd>
      <template v-if="row.bgp_role"><dt>{{ t('attacks.bgpRole') }}</dt><dd>{{
        ['triggered', 'attached_shared'].includes(row.bgp_role)
          ? t(row.bgp_role === 'triggered' ? 'attacks.bgpRoleTriggered' : 'attacks.bgpRoleAttached')
          : row.bgp_role }}</dd></template>
      <dt>{{ t(row.status === 'failed' ? 'attacks.errorMessage' : 'attacks.logNote') }}</dt>
      <dd>{{ row.error_message || '—' }}</dd>
      <template v-if="row.skip_reason"><dt>{{ t('attacks.logSkipReason') }}</dt><dd>{{ row.skip_reason }}</dd>
      </template>
      <template v-if="row.detail"><dt>{{ t('attacks.logDetail') }}</dt><dd>{{ row.detail }}</dd></template>
    </dl>
    <h3>{{ t('attacks.responseBody') }}</h3>
    <XSeg v-model="mode" :label="t('attacks.responseBody')" :options="['formatted', 'raw'].map(value =>
      ({ value, label: t('attacks.' + value) }))" />
    <pre>{{ mode === 'formatted' ? formattedJSON(row.response_body) : row.response_body || '—' }}</pre></template>
  </XDrawer>
</template>
<style scoped>
pre { white-space: pre-wrap; overflow-wrap: anywhere; font: 11px var(--font-num); }
</style>
