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
interface CertInfo {
  subject?: string; issuer?: string; serial_number?: string
  not_before?: string; not_after?: string
  dns_names?: string[]; uris?: string[]; fingerprint_sha256?: string; is_ca?: boolean
}
interface TlsState {
  node_id: string
  enabled: boolean
  warnings: string[]
  server?: { cert: CertInfo; min_version: string; days_remaining: number; not_after: string }
  node?: { present: boolean; mtls?: boolean; verified?: boolean; identity?: string
    days_remaining?: number; seen_at?: string; cert?: CertInfo }
}
const tls = lookup(() => props.modelValue ? props.row.id : '', signal =>
  request<TlsState>('/api/nodes/' + encodeURIComponent(props.row.id) + '/tls', { signal }))
const expiry = (days?: number) => days === undefined ? '—'
  : t(days < 0 ? 'nodes.tls.expired' : 'nodes.tls.days', { n: days })
const expiryTone = (days?: number) => days === undefined ? '' : days < 0 ? 'crit' : days <= 30 ? 'warn' : 'ok'
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
    <div class="dh"><h3>{{ t('nodes.tls.title') }}</h3>
      <span v-if="tls.data.value && !tls.data.value.enabled" class="sub">{{ t('nodes.tls.plaintext') }}</span></div>
    <p v-if="tls.loading.value" class="sub">{{ t('common.loading') }}</p>
    <p v-else-if="tls.error.value" class="crit mono" role="alert">{{ message(tls.error.value) }}</p>
    <template v-else-if="tls.data.value">
      <p v-if="!tls.data.value.enabled" class="sub">{{ t('nodes.tls.disabledDesc') }}</p>
      <template v-else>
        <ul v-if="tls.data.value.warnings.length" class="warns">
          <li v-for="w in tls.data.value.warnings" :key="w" class="crit">
            {{ t('nodes.tls.warn.' + w) }}</li>
        </ul>
        <dl class="kv">
          <dt>{{ t('nodes.tls.server') }}</dt>
          <dd><span class="pill ok">TLS</span>
            <span class="sub">{{ t('nodes.tls.minVersion', { v: tls.data.value.server?.min_version || '—' }) }}</span>
            <span class="sub" :class="expiryTone(tls.data.value.server?.days_remaining)">
              {{ t('nodes.tls.expires', { when: tls.data.value.server?.not_after
                ? fullDateTime(tls.data.value.server.not_after) : '—',
                left: expiry(tls.data.value.server?.days_remaining) }) }}</span></dd>
          <dt>{{ t('nodes.tls.issuer') }}</dt>
          <dd class="mono">{{ tls.data.value.server?.cert.issuer || '—' }}</dd>
          <dt>{{ t('nodes.tls.fingerprint') }}</dt>
          <dd class="mono fp">{{ tls.data.value.server?.cert.fingerprint_sha256 || '—' }}</dd>
          <dt>{{ t('nodes.tls.node') }}</dt>
          <dd v-if="!tls.data.value.node?.present" class="sub">{{ t('nodes.tls.noCert') }}</dd>
          <dd v-else><span class="pill" :class="tls.data.value.node.verified ? 'ok' : 'warn'">
            {{ t(tls.data.value.node.verified ? 'nodes.tls.verified' : 'nodes.tls.unverified') }}</span>
            <span class="sub" :class="expiryTone(tls.data.value.node.days_remaining)">
              {{ expiry(tls.data.value.node.days_remaining) }}</span></dd>
          <template v-if="tls.data.value.node?.present">
            <dt>{{ t('nodes.tls.subject') }}</dt>
            <dd class="mono">{{ tls.data.value.node.cert?.subject || '—' }}</dd>
            <dt>{{ t('nodes.tls.identity') }}</dt>
            <dd class="mono">{{ tls.data.value.node.identity || '—' }}</dd>
            <dt>{{ t('nodes.tls.sans') }}</dt>
            <dd class="mono sans">{{ [...(tls.data.value.node.cert?.uris || []),
              ...(tls.data.value.node.cert?.dns_names || [])].join(', ') || '—' }}</dd>
            <dt>{{ t('nodes.tls.seen') }}</dt>
            <dd class="num">{{ tls.data.value.node.seen_at
              ? fullDateTime(tls.data.value.node.seen_at) : '—' }}</dd>
          </template>
        </dl>
      </template>
    </template>
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
.fp, .sans { overflow-wrap: anywhere; font-size: 11.5px; }
.warns { list-style: none; padding: 0; margin: 0 0 6px; }
.warns li { font-size: 12px; }
.dh { display: flex; justify-content: space-between; align-items: center; gap: 6px; margin-top: 18px; }
h3 { font-size: 13px; font-weight: 500; }
.danger-zone { margin-top: 18px; padding-top: 12px; border-top: 1px solid var(--line); }
.danger-zone p { margin: 4px 0 8px; }
</style>
