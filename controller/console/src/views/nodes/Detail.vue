<script setup lang="ts">
import { computed, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import XDrawer from '../../components/XDrawer.vue'
import XConfirm from '../../components/XConfirm.vue'
import XSpark from '../../components/chart/XSpark.vue'
import { api } from '../../api/data'
import { request } from '../../api/client'
import { bps, pps, fullDateTime, relativeTime } from '../../format'
import { isAdmin } from '../../auth'
import { notify } from '../../notifications'
import { lookup } from '../mitigations/lookup'
import type { Row } from '../mitigations/data'
import { captureText } from './data'
import ConfigCell from './ConfigCell.vue'
const props = defineProps<{ modelValue: boolean; row: Row; now: number; missing: boolean; reading?: Row }>()
const emit = defineEmits<{ 'update:modelValue': [value: boolean]; deleted: [] }>()
const { t } = useI18n()
const open = computed({ get: () => props.modelValue, set: value => emit('update:modelValue', value) })
const identity = () => props.modelValue ? props.row.id : ''
const capture = lookup(() => identity() && props.row.mode !== 'flow' ? identity() : '', signal =>
  request<Row>('/api/nodes/' + encodeURIComponent(props.row.id) + '/status', { signal, allow: [404] }))
const flow = lookup(() => identity() && props.row.mode === 'flow' ? identity() : '', signal =>
  api<Row[] | null>('flow-listeners', { node_id: props.row.id }, signal))
const traffic = lookup(() => identity() && props.row.online ? identity() : '', signal =>
  api<Row[] | null>('stats/total-timeseries', { node_id: props.row.id, direction: 'receives', resolution: '5s',
    from: new Date(Date.now() - 900000).toISOString() }, signal))
const confirmation = ref(false)
async function remove() {
  try {
    await request('/api/nodes/' + encodeURIComponent(props.row.id), { method: 'DELETE' })
    notify(t('nodes.deleted')); open.value = false; emit('deleted')
  } catch (e) { notify(e instanceof Error ? e.message : String(e), 'crit'); throw e }
}
const message = (error: unknown) => error instanceof Error ? error.message : String(error)
</script>
<template>
  <XDrawer v-model="open" :width="460" :title="row.id">
    <p v-if="missing" class="sub">{{ t('nodes.notListed') }}</p>
    <dl class="kv">
      <dt>{{ t('nodes.description') }}</dt><dd>{{ row.description || '—' }}</dd>
      <dt>{{ t('nodes.mode') }}</dt><dd>{{ row.mode === 'flow' ? 'Flow' : 'XDP' }}</dd>
      <dt>{{ t('nodes.status') }}</dt><dd><span class="dot" :class="row.online ? 'ok' : 'neutral'" />
        {{ t(row.online ? 'data.online' : 'data.offline') }}<span v-if="row.last_stats_at" class="sub">
          {{ t('nodes.heartbeat', { time: relativeTime(row.last_stats_at, now) }) }}</span></dd>
      <dt>{{ t('nodes.config') }}</dt><dd><ConfigCell :row="row" /><span class="sub num">
        {{ t('nodes.versions', { a: row.delivery_version_applied, c: row.delivery_version_current }) }}</span></dd>
      <dt>{{ t('nodes.lastAck') }}</dt>
      <dd class="num">{{ row.last_ack_at ? fullDateTime(row.last_ack_at) : '—' }}</dd>
      <template v-if="row.mode !== 'flow'"><dt>{{ t('nodes.capture') }}</dt><dd class="mono capture">
        <span v-if="capture.error.value" role="alert">{{ message(capture.error.value) }}</span>
        <span v-else>{{ captureText(capture.data.value, t) }}</span></dd></template>
      <template v-else><dt>Flow</dt><dd><span v-if="flow.error.value" role="alert">
        {{ message(flow.error.value) }}</span>
        <span v-else>{{ t('nodes.flowCount', { n: flow.data.value?.length || 0 }) }}
        </span> <RouterLink :to="'/flow/' + encodeURIComponent(row.id)">
          {{ t('nodes.flowLink') }}</RouterLink></dd>
      </template>
      <dt>{{ t('nodes.registered') }}</dt><dd class="num">{{ fullDateTime(row.created_at) }}</dd>
    </dl>
    <div class="dh"><h3>{{ t('nodes.traffic') }}</h3><span v-if="reading" class="num">
      {{ pps(reading.pps) }} pps · {{ bps(reading.bps) }}</span></div>
    <p v-if="!row.online" class="empty">{{ t('nodes.offlineRecent') }}</p>
    <p v-else-if="traffic.loading.value" class="sub">{{ t('common.loading') }}</p>
    <p v-else-if="traffic.error.value" class="crit mono" role="alert">{{ message(traffic.error.value) }}</p>
    <XSpark v-else-if="traffic.data.value?.length" :values="traffic.data.value.map(p => p.pps)"
      :width="400" :height="56" :aria-label="t('nodes.trafficLabel')" />
    <p v-else class="empty">{{ t('nodes.noRecent') }}</p>
    <div v-if="isAdmin()" class="danger-zone"><strong>{{ t('nodes.deleteNode') }}</strong>
      <p class="sub">{{ t('nodes.deleteNote') }}</p>
      <button class="btn crit-line" @click="confirmation = true">{{ t('nodes.deleteButton') }}</button>
      <XConfirm v-model="confirmation" :title="t('nodes.deleteTitle', { id: row.id })" description=""
        :confirm-label="t('nodes.delete')" tone="danger" :action="remove" />
    </div>
  </XDrawer>
</template>
<style scoped>
.kv { grid-template-columns: 100px minmax(0, 1fr); }
.capture { white-space: pre-line; }
.dh { display: flex; justify-content: space-between; align-items: center; gap: 6px; margin-top: 18px; }
h3 { font-size: 13px; font-weight: 500; }
.danger-zone { margin-top: 18px; padding-top: 12px; border-top: 1px solid var(--line); }
.danger-zone p { margin: 4px 0 8px; }
</style>
