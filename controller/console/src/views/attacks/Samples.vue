<script setup lang="ts">
import { computed, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import XTable from '../../components/XTable.vue'
import XEmpty from '../../components/XEmpty.vue'
import { dateTime, fullDateTime, thousands, bytes1024 } from '../../format'
import { aggregateTop, protoName, formatTCPFlags, type Row } from './data'
const props = defineProps<{ global: boolean; loading: boolean; error: string; data: Row | null }>()
const { t } = useI18n(), sort = ref('packets'), direction = ref<'ascending' | 'descending'>('descending')
const flows = computed<Row[]>(() => props.data?.flows ?? [])
const rows = computed(() => [...flows.value].sort((a, b) => (a[sort.value] - b[sort.value])
  * (direction.value === 'ascending' ? 1 : -1)))
const columns = computed(() => ['time', 'protocol', 'source', 'destination', 'tcpFlags', 'packets', 'bytes']
  .map(key => ({ key, label: t('attacks.' + key), sortable: ['packets', 'bytes'].includes(key) })))
</script>
<template>
  <div class="samples">
    <p class="empty" role="status" v-if="global">{{ t('attacks.globalNoFlowDetail') }}</p>
    <XEmpty v-else-if="loading" loading />
    <p class="empty" role="alert" v-else-if="error">{{ t('attacks.samplesFailed') }}</p>
    <p class="empty" role="status" v-else-if="data?.expired">{{ t('attacks.flowDataExpired') }}</p>
    <p class="empty" role="status" v-else-if="!flows.length">{{ t('attacks.noFlowData') }}</p>
    <template v-else>
      <div class="sample-tops"><article v-for="[field, title] in [['src_ip', 'topSrcIps'],
        ['src_port', 'topSrcPorts'], ['dst_port', 'topDstPorts']]" :key="field">
        <h3>{{ t('attacks.' + title) }}</h3><table><thead><tr><th>{{ t('attacks.' + title) }}</th>
          <th>{{ t('attacks.flowPercent') }}</th></tr></thead><tbody>
          <tr v-for="r in aggregateTop(flows, field!)" :key="r.key"><td class="mono">{{ r.key }}</td>
            <td class="num">{{ r.pct }}%</td></tr></tbody></table>
      </article></div>
      <p class="sub">{{ t('attacks.samplesNote') }}</p>
      <p v-if="data?.window === 'last_1h'" class="sub">{{ t('attacks.lastHour') }}</p>
      <XTable :rows="rows" :columns="columns" :sort-key="sort" :sort-direction="direction"
        @sort="(key, value) => { sort = key; direction = value }">
        <template #time="{ value }">
          <span :title="fullDateTime(String(value))">{{ dateTime(String(value)) }}</span>
        </template>
        <template #protocol="{ row }">{{ protoName(row.protocol as number) }}</template>
        <template #source="{ row }"><span class="mono">{{ row.src_ip }}:{{ row.src_port }}</span></template>
        <template #destination="{ row }"><span class="mono">{{ row.dst_ip }}:{{ row.dst_port }}</span></template>
        <template #tcpFlags="{ row }">{{ formatTCPFlags(row.tcp_flags as number, row.protocol as number) }}</template>
        <template #packets="{ value }">{{ thousands(value as number) }}</template>
        <template #bytes="{ value }">{{ bytes1024(value as number) }}</template>
      </XTable>
    </template>
  </div>
</template>
<style scoped>
:deep(.tbl-wrap table) { min-width: 800px; }
.sample-tops { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 16px; }
@media (max-width: 640px) { .sample-tops { grid-template-columns: minmax(0, 1fr); } }
</style>
