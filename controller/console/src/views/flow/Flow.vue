<script setup lang="ts">
import { computed, onMounted, onUnmounted, reactive, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'
import { request } from '../../api/client'
import { isAdmin } from '../../auth'
import { notifyWrite } from '../../notifications'
import XListbox from '../../components/XListbox.vue'
import XKpi from '../../components/XKpi.vue'
import XPill from '../../components/XPill.vue'
import XSwitch from '../../components/XSwitch.vue'
import XConfirm from '../../components/XConfirm.vue'
import ListenerDrawer from './ListenerDrawer.vue'
import SourceDrawer from './SourceDrawer.vue'
import { connectionTime, deleteListener, listenerRecords, rawError, records, saveListener } from './data'
import type { Detail, FlowNode, FlowStatus, Listener } from './data'
import './flow.css'
const { t } = useI18n()
const router = useRouter(), route = useRoute()
const nodes = ref<FlowNode[]>([]), nodesError = ref(''), nodesLoading = ref(true)
const node = computed(() => String(route.params.node ?? ''))
const selected = computed(() => nodes.value.find(n => n.id === node.value))
const options = computed(() => nodes.value.map(n => ({ value: n.id,
  label: `${n.id} · ${t(n.online ? 'flow.online' : 'flow.offline')}` })))
const status = ref<FlowStatus>(), statusError = ref(''), updatedAt = ref('')
const listeners = ref<Listener[]>([]), listError = ref(''), listLoading = ref(false)
const details = reactive<Record<number, { sources?: Detail['sources']; error: string }>>({})
const listenerOpen = ref(false), editing = ref<Listener>()
const sourceId = ref<number>(), sourceOpen = ref(false), confirm = ref<number>()
const sourceListener = computed(() => listeners.value.find(l => l.id === sourceId.value))
const busy = reactive<Record<number, boolean>>({})
let alive = true, generation = 0, listGeneration = 0, statusSequence = 0
let controller = new AbortController()
const nodeController = new AbortController()
let timer: ReturnType<typeof setInterval> | undefined
const valid = (seq: number) => alive && seq === generation
function stop() {
  generation++
  controller.abort()
  if (timer !== undefined) clearInterval(timer)
  timer = undefined
}
async function loadNodes() {
  nodesLoading.value = true
  nodesError.value = ''
  try {
    const result = await request<FlowNode[] | null>('/api/nodes', { signal: nodeController.signal })
    if (alive) nodes.value = (result ?? []).filter(n => n.mode === 'flow')
  } catch (error) { if (alive) nodesError.value = rawError(error) }
  finally { if (alive) nodesLoading.value = false }
}
async function loadStatus(seq: number, id: string, signal: AbortSignal) {
  const requestSequence = ++statusSequence
  try {
    const value = await request<FlowStatus>(`/api/nodes/${encodeURIComponent(id)}/status`, { signal })
    if (!valid(seq) || requestSequence !== statusSequence) return
    status.value = value
    statusError.value = ''
    updatedAt.value = new Date().toLocaleTimeString('en-GB', { hour12: false })
  } catch (error) {
    if (valid(seq) && requestSequence === statusSequence) statusError.value = rawError(error)
  }
}
async function loadDetail(row: Listener, seq = generation, listSeq = listGeneration) {
  const state = details[row.id] ?? (details[row.id] = { error: '' })
  state.error = ''
  try {
    const result = await request<Detail>(`/api/flow-listeners/${row.id}`, { signal: controller.signal })
    if (valid(seq) && listSeq === listGeneration) state.sources = result.sources ?? []
  } catch (error) {
    if (valid(seq) && listSeq === listGeneration) { state.sources = undefined; state.error = rawError(error) }
  }
}
async function loadListeners() {
  const seq = generation, listSeq = ++listGeneration, id = node.value
  listLoading.value = true
  listError.value = ''
  try {
    const rows = await request<Listener[]>(`/api/flow-listeners?node_id=${encodeURIComponent(id)}`,
      { signal: controller.signal })
    if (!valid(seq) || listSeq !== listGeneration) return
    listeners.value = rows ?? []
    for (const key of Object.keys(details)) delete details[Number(key)]
    await Promise.all(listeners.value.map(row => loadDetail(row, seq, listSeq)))
  } catch (error) { if (valid(seq) && listSeq === listGeneration) listError.value = rawError(error) }
  finally { if (valid(seq) && listSeq === listGeneration) listLoading.value = false }
}
watch([node, nodes, nodesLoading], () => {
  stop()
  controller = new AbortController()
  listenerOpen.value = false
  sourceOpen.value = false
  confirm.value = undefined
  status.value = undefined
  statusError.value = ''
  updatedAt.value = ''
  listeners.value = []
  for (const key of Object.keys(details)) delete details[Number(key)]
  if (nodesLoading.value || nodesError.value) return
  if (!node.value && nodes.value.length) {
    void router.replace('/flow/' + encodeURIComponent(nodes.value[0]!.id))
    return
  }
  if (!selected.value) return
  const seq = generation, id = node.value, signal = controller.signal
  void loadStatus(seq, id, signal)
  void loadListeners()
  timer = setInterval(() => { void loadStatus(seq, id, signal) }, 10000)
})
onMounted(loadNodes)
onUnmounted(() => { alive = false; stop(); nodeController.abort() })
function openListener(row?: Listener, event?: MouseEvent) {
  if (event && (event.target as HTMLElement).closest('button,label,a,[role=alertdialog]')) return
  editing.value = row
  listenerOpen.value = true
}
function openSources(row: Listener) { sourceId.value = row.id; sourceOpen.value = true }
async function toggle(row: Listener, enabled: boolean) {
  if (!isAdmin() || busy[row.id]) return
  const before = row.enabled, seq = generation
  row.enabled = enabled
  busy[row.id] = true
  try {
    await notifyWrite(saveListener({ ...row, enabled, toggle: true }, row), t('flow.updated'))
    if (valid(seq)) await loadListeners()
  } catch { row.enabled = before }
  finally { busy[row.id] = false }
}
async function remove(row: Listener) {
  const seq = generation
  await notifyWrite(deleteListener(row.id), t('flow.deleted'))
  if (valid(seq)) await loadListeners()
}
const metrics = [['decode_errors', 'decodeErrors'], ['unknown_exporter', 'unknownExporter'],
  ['template_misses', 'templateMisses']] as const
</script>
<template>
  <div class="page fl-page">
    <div class="crumb"><RouterLink to="/nodes">{{ t('flow.nodes') }}</RouterLink><span>/</span>
      <span class="mono">{{ node }}</span></div>
    <div class="page-head">
      <div class="fl-title"><h1>{{ t('flow.title') }}</h1>
        <XListbox v-if="nodes.length" :model-value="node" :options="options" :label="t('flow.node')"
          @update:model-value="router.push('/flow/' + encodeURIComponent($event))" /></div>
      <div v-if="selected" class="toolbar"><span v-if="updatedAt" class="sub">
        {{ t('flow.updatedAt', { time: updatedAt }) }}</span>
        <button v-if="isAdmin()" class="btn primary" @click="openListener()">{{ t('flow.addListener') }}</button>
      </div>
    </div>
    <div v-if="nodesError" class="empty-page" role="alert">{{ nodesError }}
      <button class="btn" @click="loadNodes">{{ t('flow.retry') }}</button></div>
    <div v-else-if="!nodesLoading && !selected" class="empty-page">
      <p>{{ node ? t('flow.notFlow', { id: node }) : t('flow.noFlow') }}</p>
      <RouterLink v-if="nodes.length" :to="'/flow/' + encodeURIComponent(nodes[0]!.id)">
        {{ t('flow.firstFlow') }}</RouterLink>
      <RouterLink v-else to="/nodes">{{ t('flow.nodes') }}</RouterLink>
    </div>
    <template v-else-if="selected">
      <section v-if="status" class="fl-health" :aria-label="t('flow.health')">
        <div class="kpis fl-kpis">
          <XKpi class="fl-status" :label="t('flow.status')" :value="t(status.online ? 'flow.online' : 'flow.offline')"
            :tone="status.online ? 'ok' : 'crit'"
            :secondary="status.uptime_seconds !== undefined
              ? t('flow.uptime', { duration: connectionTime(status.uptime_seconds) }) : undefined" />
          <template v-if="status.flow_metrics">
            <XKpi v-for="[key, label] in metrics" :key="key" :label="t('flow.' + label)"
              :value="status.flow_metrics[key]" :tone="!status.online ? 'fl-muted'
                : status.flow_metrics[key] > 0 ? 'warn' : undefined" />
          </template>
        </div>
        <p v-if="!status.online && status.flow_metrics" class="sub fl-stale">{{ t('flow.stale') }}</p>
      </section>
      <p v-if="statusError" class="sub fl-status-error" role="alert">{{ statusError }}</p>
      <section class="panel fl-panel" :aria-busy="listLoading">
        <div class="panel-head"><h2>{{ t('flow.listeners') }}
          <span class="num sub">{{ listeners.length }}</span></h2></div>
        <p v-if="listError" role="alert">{{ listError }} <button class="btn" @click="loadListeners">
          {{ t('flow.retry') }}</button></p>
        <div v-else class="tbl-wrap">
          <table class="fl-table"><thead><tr>
            <th v-for="key in ['id', 'address', 'protocol', 'description', 'records', 'enabled', 'actions']" :key="key">
              {{ t('flow.' + key) }}</th>
          </tr></thead><tbody>
            <template v-for="row in listeners" :key="row.id">
              <tr class="fl-row" :class="{ 'fl-disabled': !row.enabled }" @click="openListener(row, $event)">
                <td class="num sub">{{ row.id }}</td><td class="mono fl-link">{{ row.listen_address }}</td>
                <td><XPill class="mono">{{ row.protocol_mode === 'auto'
                  ? t('flow.modeAuto') : row.protocol_mode }}</XPill></td><td>{{ row.description }}</td>
                <td class="num" :title="String(listenerRecords(row, status) ?? '')">
                  {{ records(listenerRecords(row, status)) }}</td>
                <td><template v-if="isAdmin()">
                  <XSwitch :id="'fl-enabled-' + row.id" :model-value="row.enabled" :disabled="busy[row.id]"
                    :label="t('flow.enableListener', { address: row.listen_address })"
                    @update:model-value="toggle(row, $event)" /></template>
                  <span v-else>{{ t(row.enabled ? 'flow.yes' : 'flow.no') }}</span></td>
                <td><div class="toolbar"><button class="btn sm" @click="openSources(row)">
                  {{ t('flow.sourcesCount', { count: details[row.id]?.sources?.length ?? '—' }) }}</button>
                  <button v-if="isAdmin()" class="btn sm danger" @click="confirm = row.id">
                    {{ t('flow.delete') }}</button>
                </div></td>
              </tr>
              <tr v-if="confirm === row.id && isAdmin()"><td colspan="7">
                <XConfirm :model-value="true" :title="t('flow.deleteListener', { address: row.listen_address })"
                  :description="details[row.id]?.sources === undefined ? t('flow.cascadeUnknown')
                    : t('flow.cascadeKnown', { count: details[row.id]!.sources!.length })"
                  :action="() => remove(row)" :confirm-label="t('flow.delete')" tone="danger"
                  @update:model-value="confirm = undefined" /></td></tr>
            </template>
            <tr v-if="!listLoading && !listeners.length"><td colspan="7" class="empty">{{ t('flow.empty') }}</td></tr>
          </tbody></table>
        </div>
      </section>
    </template>
    <ListenerDrawer :key="node" v-model="listenerOpen" :node="node" :row="editing" @saved="loadListeners" />
    <SourceDrawer v-if="sourceListener" v-model="sourceOpen" :listener="sourceListener" :node="node"
      :sources="details[sourceListener.id]?.sources" :error="details[sourceListener.id]?.error ?? ''" :status="status"
      @retry="loadDetail(sourceListener)" @saved="loadListeners" />
  </div>
</template>
