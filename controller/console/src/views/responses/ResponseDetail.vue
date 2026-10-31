<script setup lang="ts">
import { computed, onUnmounted, reactive, ref, watch } from 'vue'
import { useRoute } from 'vue-router'
import { useI18n } from 'vue-i18n'
import { ApiError, request } from '../../api/client'
import { isAdmin } from '../../auth'
import { notifyWrite } from '../../notifications'
import XSwitch from '../../components/XSwitch.vue'
import XConfirm from '../../components/XConfirm.vue'
import XEmpty from '../../components/XEmpty.vue'
import XTip from '../../components/XTip.vue'
import ActionEditor from './ActionEditor.vue'
import { connectorName, defaults, fill, paired, phaseRows } from './data'
import type { Connector, Form, Phase, Row } from './data'
const { t } = useI18n(), route = useRoute()
const detail = ref<Row>(), error = ref(''), missing = ref(false), loaded = ref(false), saving = ref(false)
const basic = reactive({ name: '', description: '', enabled: true })
const basicError = ref(''), connectors = ref<Record<string, Connector[]>>({}), xdropFailed = ref(false)
const editing = ref(false), form = ref<Form>(defaults()), phase = ref<Phase>('on_detected'), confirmID = ref<number>()
let generation = 0, opening = 0, alive = true, controller = new AbortController()
let readSequence = 0
const phases: Phase[] = ['on_detected', 'on_expired']
const rid = computed(() => Number(route.params.id))
function accept(data: Row, initialize = false) {
  detail.value = data
  if (initialize) Object.assign(basic, { name: data.response.name, description: data.response.description,
    enabled: data.response.enabled !== false })
}
async function load() {
  const seq = generation, read = ++readSequence
  error.value = ''; missing.value = false
  try {
    const data = await request<Row>(`/api/responses/${encodeURIComponent(String(route.params.id))}`,
      { signal: controller.signal })
    if (alive && seq === generation && read === readSequence) accept(data, !detail.value)
  } catch (e) {
    if (alive && seq === generation && read === readSequence) {
      missing.value = e instanceof ApiError && e.status === 404
      error.value = e instanceof Error ? e.message : String(e)
    }
  } finally { if (alive && seq === generation && read === readSequence) loaded.value = true }
}
watch(() => route.params.id, () => {
  generation++; opening++; controller.abort(); controller = new AbortController()
  detail.value = undefined; loaded.value = false; editing.value = false; confirmID.value = undefined
  basicError.value = ''; connectors.value = {}; xdropFailed.value = false
  const seq = generation
  void load()
  for (const kind of ['webhook', 'shell', 'bgp', 'xdrop']) {
    void request<Connector[] | null>(`/api/settings/${kind}-connectors`, { signal: controller.signal })
      .then(data => { if (alive && seq === generation) connectors.value[kind] = data ?? [] })
      .catch(() => {
        if (alive && seq === generation) { connectors.value[kind] = []; if (kind === 'xdrop') xdropFailed.value = true }
      })
  }
}, { immediate: true })
onUnmounted(() => { alive = false; generation++; opening++; controller.abort() })
async function update() {
  if (saving.value || !basic.name.trim() || !isAdmin()) return
  saving.value = true; basicError.value = ''
  const id = rid.value, seq = generation, body = { ...basic, name: basic.name.trim() }
  try {
    await notifyWrite(request(`/api/responses/${id}`, { method: 'PUT', body: JSON.stringify(body) }),
      t('responses.updated'))
    if (alive && seq === generation) { detail.value!.response = { ...detail.value!.response, ...body }; await load() }
  } catch (e) { if (alive && seq === generation) basicError.value = e instanceof Error ? e.message : String(e) }
  finally { saving.value = false }
}
async function open(action?: Row, nextPhase: Phase = 'on_detected') {
  const seq = ++opening
  if (!action) { form.value = defaults(); phase.value = nextPhase; editing.value = true; return }
  let rows: Row[] | null = [], success = false
  try {
    rows = await request<Row[] | null>(`/api/actions/${action.id}/preconditions`, { signal: controller.signal })
    success = true
  } catch { /* The editor must remain available with read-only conditions. */ }
  if (!alive || seq !== opening) return
  form.value = fill(action, success, rows); phase.value = action.trigger_phase; editing.value = true
}
async function remove(action: Row) {
  const seq = generation
  await notifyWrite(request(`/api/actions/${action.id}`, { method: 'DELETE' }), t('responses.deleted'))
  if (alive && seq === generation) await load()
}
const rows = (p: Phase) => phaseRows(detail.value?.actions ?? [], p)
const phaseTitle = (p: Phase) => t(p === 'on_detected' ? 'responses.onDetected' : 'responses.onExpired')
const runLabel = (value: string) => value === '' ? '""'
  : ['once', 'periodic', 'retry_until_success'].includes(value) ? t('responses.' + value) : value
const executionLabel = (value: string) => !value || value === 'automatic' ? t('responses.automatic')
  : value === 'manual' ? t('responses.manual') : value
async function refreshActions(id: number) {
  if (!alive || id !== rid.value) return
  const seq = generation, read = ++readSequence
  try {
    const data = await request<Row>(`/api/responses/${id}`, { signal: controller.signal })
    if (alive && seq === generation && read === readSequence && detail.value) detail.value.actions = data.actions ?? []
  } catch { /* Preserve the write result and the editor form. */ }
}
</script>
<template>
  <div class="page rs-detail"><nav class="crumb"><RouterLink to="/responses">{{ t('nav.responses') }}</RouterLink>
    / #{{ route.params.id }}</nav>
    <RouterLink v-if="missing" to="/responses">{{ t('responses.missing') }}</RouterLink>
    <p v-else-if="error" class="crit mono" role="alert">{{ error }}
      <button class="btn sm" @click="load">{{ t('responses.retry') }}</button></p>
    <template v-if="detail && !missing"><div class="page-head"><h1>{{ detail.response.name }}</h1>
      <span class="pill" :class="{ ok: detail.response.enabled !== false }">
        {{ t(detail.response.enabled !== false ? 'responses.enabled' : 'responses.disabled') }}</span></div>
      <section class="panel"><div class="panel-head"><h2>{{ t('responses.basic') }}</h2></div>
        <div class="rs-basic"><label class="field"><span>{{ t('responses.name') }}</span>
          <input v-model="basic.name" :disabled="!isAdmin() || saving"></label>
          <label class="field"><span>{{ t('responses.description') }}</span>
            <input v-model="basic.description" :disabled="!isAdmin() || saving"></label>
          <label class="field"><span>{{ t('responses.enabled') }}</span>
            <XSwitch v-model="basic.enabled" :label="t('responses.enabled')" :disabled="!isAdmin() || saving" /></label>
          <button v-if="isAdmin()" class="btn primary" :disabled="saving || !basic.name.trim()" @click="update">
            {{ t('responses.save') }}</button></div>
        <p v-if="basicError" role="alert" class="crit mono">{{ basicError }}</p></section>
      <section v-for="p in phases" :key="p" class="panel rs-phase" :data-phase="p">
        <div class="panel-head"><h2>{{ phaseTitle(p) }}
          <XTip v-if="p === 'on_expired'" :text="t('responses.expiredHint')" wide /></h2>
          <button v-if="isAdmin()" class="btn sm primary" @click="open(undefined, p)">
            + {{ t('responses.addAction') }}</button></div>
        <div class="tbl-wrap"><table><thead><tr><th>{{ t('responses.priority') }}</th>
          <th>{{ t('responses.actionType') }}</th><th>{{ t('responses.connector') }}</th>
          <th>{{ t('responses.runMode') }}</th><th>{{ t('responses.execution') }}</th>
          <th>{{ t('responses.enabled') }}</th><th>{{ t('responses.operations') }}</th></tr></thead><tbody>
          <template v-for="a in rows(p)" :key="a.id"><tr :class="{ 'rs-divider': a.divider }" :data-action="a.id">
            <td class="num">{{ a.priority }}</td><td><span class="mono">{{ a.action_type }}</span>
              <span v-if="a.action_type !== 'webhook'" class="rs-first pill">{{ t('responses.firstMatch') }}
                <XTip :text="t('responses.firstMatchHint')" wide /></span></td>
            <td class="mono">{{ connectorName(a, connectors.xdrop ?? [], xdropFailed, t('responses.allNodes')) }}</td>
            <td :class="{ mono: !['once', 'periodic', 'retry_until_success'].includes(a.run_mode) }">
              {{ runLabel(a.run_mode) }}<XTip v-if="a.run_mode === ''" :text="t('responses.legacyRun')" /></td>
            <td>{{ executionLabel(a.execution) }}</td><td><span class="pill" :class="{ ok: a.enabled !== false }">
              {{ t(a.enabled !== false ? 'responses.yes' : 'responses.no') }}</span></td>
            <td><div class="actions"><button class="btn sm ghost" @click="open(a)">
              {{ t(isAdmin() ? 'responses.edit' : 'responses.view') }}</button>
              <button v-if="isAdmin()" class="btn sm ghost" @click="confirmID = a.id">
                {{ t('responses.delete') }}</button></div></td></tr>
          <tr v-if="confirmID === a.id"><td colspan="7"><XConfirm :model-value="true"
            :title="t('responses.deleteAction')" :description="paired(a) ? t('responses.pairDelete') : ''"
            :action="() => remove(a)" :confirm-label="t('responses.delete')" tone="danger"
            @update:model-value="confirmID = undefined" /></td></tr></template></tbody></table>
          <XEmpty v-if="!rows(p).length" /></div></section>
      <ActionEditor v-if="editing" v-model="editing" :form="form" :phase="phase"
        :responseID="rid" :connectors="connectors" :viewing="!isAdmin()" @refresh="refreshActions" />
    </template><XEmpty v-else-if="!loaded" loading />
  </div>
</template>
<style scoped>
.crumb { display: flex; gap: 8px; margin-bottom: 14px; color: var(--muted); font-size: 12px; }
.rs-basic { display: flex; align-items: end; gap: 18px; flex-wrap: wrap; padding: 18px; }
.rs-basic .field:first-child { width: 200px; }
.rs-basic .field:nth-child(2) { width: 300px; max-width: 100%; }
.rs-detail table { width: 100%; }
.rs-divider td { border-top: 2px solid var(--line); }
.rs-first { margin-left: 8px; font-size: 10px; white-space: nowrap; }
.rs-detail .actions { white-space: nowrap; }
.rs-phase { margin-top: 20px; }
@media (max-width: 600px) {
  .rs-basic .field { width: 100% !important; }
  .rs-detail .panel-head { align-items: start; gap: 8px; }
}
@media (max-width: 600px) {
  .rs-detail :deep(.tip-text) {
    position: fixed; left: 16px; top: 30%; width: calc(100vw - 48px);
  }
}
</style>
