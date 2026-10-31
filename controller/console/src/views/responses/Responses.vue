<script setup lang="ts">
import { nextTick, onMounted, onUnmounted, ref, watch } from 'vue'
import { useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'
import { request } from '../../api/client'
import { isAdmin } from '../../auth'
import { notifyWrite } from '../../notifications'
import { fullDateTime } from '../../format'
import XDrawer from '../../components/XDrawer.vue'
import XConfirm from '../../components/XConfirm.vue'
import XEmpty from '../../components/XEmpty.vue'
import XTip from '../../components/XTip.vue'
import type { Row } from './data'
const { t } = useI18n(), router = useRouter()
const rows = ref<Row[]>([]), error = ref(''), loaded = ref(false), adding = ref(false)
const name = ref(''), description = ref(''), addError = ref(''), busy = ref(false), confirmID = ref<number>()
const nameInput = ref<HTMLInputElement>()
let alive = true
const controller = new AbortController()
onUnmounted(() => { alive = false; controller.abort() })
async function load() {
  try {
    const data = await request<Row[] | null>('/api/responses', { signal: controller.signal })
    if (alive) { rows.value = data ?? []; error.value = '' }
  } catch (e) { if (alive) error.value = e instanceof Error ? e.message : String(e) }
  finally { if (alive) loaded.value = true }
}
onMounted(load)
watch(adding, async value => {
  if (!value) return
  name.value = ''; description.value = ''; addError.value = ''
  await nextTick()
  await nextTick()
  nameInput.value?.focus()
})
async function create() {
  if (busy.value || !name.value.trim() || !isAdmin()) return
  busy.value = true
  try {
    await notifyWrite(request('/api/responses', { method: 'POST', body: JSON.stringify({
      name: name.value.trim(), description: description.value,
    }) }), t('responses.created'))
    adding.value = false
    await load()
  } catch (e) { addError.value = e instanceof Error ? e.message : String(e) }
  finally { busy.value = false }
}
async function remove(row: Row) {
  await notifyWrite(request(`/api/responses/${row.id}`, { method: 'DELETE' }), t('responses.deleted'))
  await load()
}
function open(row: Row, event: MouseEvent) {
  if (!(event.target as HTMLElement).closest('button,a,[role=alertdialog]')) void router.push(`/responses/${row.id}`)
}
</script>
<template>
  <div class="page rs-list"><div class="page-head"><h1>{{ t('nav.responses') }}</h1>
    <button v-if="isAdmin()" class="btn sm primary" @click="adding = true">{{ t('responses.addResponse') }}</button>
  </div>
    <p v-if="error" class="crit mono" role="alert">{{ error }}
      <button class="btn sm" @click="load">{{ t('responses.retry') }}</button></p>
    <section class="panel"><div class="tbl-wrap"><table><thead><tr><th>ID</th><th>{{ t('responses.name') }}</th>
      <th>{{ t('responses.description') }}</th><th class="r">{{ t('responses.actionCount') }}
        <XTip :text="t('responses.countHint')" /></th><th class="r">{{ t('responses.boundTemplates') }}</th>
      <th>{{ t('responses.enabled') }}</th><th>{{ t('responses.createdAt') }}</th>
      <th>{{ t('responses.operations') }}</th></tr></thead><tbody>
      <template v-for="row in rows" :key="row.id"><tr class="link" @click="open(row, $event)">
        <td class="num sub">{{ row.id }}</td>
        <td><RouterLink :to="`/responses/${row.id}`"><strong>{{ row.name }}</strong>
        </RouterLink></td><td class="sub">{{ row.description }}</td><td class="r num">{{ row.action_count }}</td>
        <td class="r num">{{ row.bound_template_count }}</td>
        <td><span class="pill" :class="{ ok: row.enabled !== false }">
          {{ t(row.enabled !== false ? 'responses.yes' : 'responses.no') }}</span></td>
        <td class="num sub nw">{{ fullDateTime(row.created_at) }}</td>
        <td><div v-if="isAdmin()" class="actions">
          <button class="btn sm ghost" @click="router.push(`/responses/${row.id}`)">{{ t('responses.edit') }}</button>
          <button class="btn sm ghost" @click="confirmID = row.id">{{ t('responses.delete') }}</button></div></td>
      </tr><tr v-if="confirmID === row.id"><td colspan="8"><XConfirm :model-value="true"
        :title="t('responses.deleteResponse', { name: row.name })" description="" :action="() => remove(row)"
        :confirm-label="t('responses.delete')" tone="danger" @update:model-value="confirmID = undefined" /></td></tr>
      </template></tbody></table><XEmpty v-if="!rows.length" :loading="!loaded" /></div></section>
    <XDrawer v-model="adding" :title="t('responses.addResponse')" :width="460" :busy="busy">
      <div class="form"><p v-if="addError" class="crit mono" role="alert">{{ addError }}</p>
        <label class="field"><span>{{ t('responses.name') }}</span><input ref="nameInput" v-model="name"
          :placeholder="t('responses.nameExample')" autocomplete="off" :disabled="busy"></label>
        <label class="field"><span>{{ t('responses.description') }}</span>
          <textarea v-model="description" rows="3" :disabled="busy" /></label></div>
      <template #footer><small class="sub rs-create-hint">{{ t('responses.createHint') }}</small><div class="toolbar">
        <button class="btn" :disabled="busy" @click="adding = false">{{ t('common.cancel') }}</button>
        <button class="btn primary" :disabled="busy || !name.trim()" @click="create">
          {{ t('responses.create') }}</button>
      </div></template></XDrawer>
  </div>
</template>
<style scoped>
.rs-create-hint { flex: 1; min-width: 0; }
.rs-list table { width: 100%; }
.rs-list .actions { white-space: nowrap; }
@media (max-width: 600px) {
  .rs-list :deep(.tip-text) {
    position: fixed; left: 16px; top: 30%; width: calc(100vw - 48px);
  }
}
</style>
