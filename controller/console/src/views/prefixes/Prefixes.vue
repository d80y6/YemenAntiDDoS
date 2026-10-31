<script setup lang="ts">
import { computed, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { isAdmin } from '../../auth'
import XConfirm from '../../components/XConfirm.vue'
import XDrawer from '../../components/XDrawer.vue'
import XListbox from '../../components/XListbox.vue'
import XSwitch from '../../components/XSwitch.vue'
import XTip from '../thresholds/Tip.vue'
import XEmpty from '../../components/XEmpty.vue'
import { reads, write } from '../thresholds/reads'
import type { Row } from '../thresholds/data'
import { prefixForm, prefixBody, prefixBaseline } from './data'
import '../thresholds/detection.css'
const { t } = useI18n()
const { data, error, loaded, refresh } = reads(() => ({ rows: 'prefixes', templates: 'threshold-templates',
  baselines: 'baseline' }), 'rows')
const rows = computed<Row[]>(() => data.value.rows ?? [])
const open = ref(false), selected = ref<Row>(), form = ref(prefixForm()), confirm = ref<number>()
const busy = ref(false), saveError = ref('')
const parents = computed(() => [{ value: '', label: t('prefixes.none') }, ...rows.value
  .filter(p => p.id !== selected.value?.id).map(p => ({ value: String(p.id), label: `${p.prefix} (${p.name})` }))])
const templates = computed(() => [{ value: '', label: t('prefixes.none') }, ...(data.value.templates ?? [])
  .map((p: Row) => ({ value: String(p.id), label: p.name }))])
const parent = (id: number) => rows.value.find(p => p.id === id)
const parentTitle = (id: number) => parent(id) ? `${parent(id)!.prefix} (${parent(id)!.name})` : ''
const baseline = (row: Row) => prefixBaseline(row, data.value.baselines ?? [])
const templateName = (row: Row) => (data.value.templates ?? [])
  .find((p: Row) => p.id === row.threshold_template_id)?.name
function show(row?: Row) {
  if (!isAdmin()) return
  selected.value = row
  form.value = prefixForm(row)
  saveError.value = ''
  confirm.value = undefined
  open.value = true
}
async function save() {
  busy.value = true
  saveError.value = ''
  try {
    await write('prefixes' + (selected.value ? '/' + selected.value.id : ''), selected.value ? 'PUT' : 'POST',
      prefixBody(form.value, !!selected.value), t(selected.value ? 'prefixes.prefixUpdated' : 'prefixes.created'))
    open.value = false
    await refresh()
  } catch (e) { saveError.value = (e as Error).message }
  finally { busy.value = false }
}
async function remove(row: Row) {
  await write('prefixes/' + row.id, 'DELETE', undefined, t('prefixes.deleted'))
  await refresh()
}
</script>
<template>
  <div class="page detection prefixes-page" :data-editing="!!selected">
    <div class="page-head"><h1>{{ t('nav.prefixes') }} <span class="sub num count">{{ rows.length }}</span></h1>
      <button v-if="isAdmin()" class="btn primary sm" @click="show()">{{ t('prefixes.add') }}</button></div>
    <p v-if="error" class="crit mono" role="alert">{{ error }}
      <button class="btn sm" @click="refresh">{{ t('prefixes.retry') }}</button></p>
    <div class="tbl-wrap"><table><thead><tr>
      <th>ID</th><th>{{ t('prefixes.prefix') }}</th><th>{{ t('prefixes.name') }}</th>
      <th>{{ t('prefixes.ipGroup') }}</th><th>{{ t('prefixes.parent') }}</th><th>{{ t('prefixes.template') }}</th>
      <th>{{ t('prefixes.baseline') }}</th><th>{{ t('prefixes.status') }}</th><th>{{ t('prefixes.actions') }}</th>
    </tr></thead><tbody><template v-for="row in rows" :key="row.id">
      <tr :class="{ 'disabled-row': !row.enabled, link: isAdmin() }" :tabindex="isAdmin() ? 0 : undefined"
        @click="($event.target as Element).closest('button,a,[role=alertdialog]') || show(row)"
        @keydown.enter.self="show(row)">
        <td class="num sub">{{ row.id }}</td><td class="mono cidr"><strong>{{ row.prefix }}</strong></td>
        <td>{{ row.name }}</td><td class="mono">{{ row.ip_group }}</td>
        <td class="num"><span :title="parentTitle(row.parent_id)">{{ row.parent_id }}</span>
          <XTip v-if="parent(row.parent_id)" :text="parentTitle(row.parent_id)" /></td>
        <td :class="{ sub: !templateName(row) }">{{ templateName(row) ?? '—' }}</td>
        <td class="num"><span :class="{ sub: !baseline(row).next }">{{ baseline(row).text }}</span>
          <XTip v-if="baseline(row).tip" :text="t(baseline(row).tip!)" wide />
          <div v-if="baseline(row).next" class="sub">{{ baseline(row).next }}</div></td>
        <td><span class="pill" :class="row.enabled ? 'ok' : 'neutral'">
          {{ t(row.enabled ? 'prefixes.enabled' : 'prefixes.disabled') }}</span></td>
        <td><div v-if="isAdmin()" class="actions">
          <button class="btn sm ghost" @click="show(row)">{{ t('prefixes.editAction') }}</button>
          <button class="btn sm ghost" @click="confirm = row.id">{{ t('prefixes.delete') }}</button></div></td>
      </tr><tr v-if="confirm === row.id"><td colspan="9">
        <XConfirm :model-value="true" :title="t('prefixes.deleteTitle', { prefix: row.prefix })"
          :description="t('prefixes.deleteConsequences')" :action="() => remove(row)" tone="danger"
          :confirm-label="t('prefixes.delete')" @update:model-value="confirm = undefined" />
      </td></tr></template></tbody></table><XEmpty v-if="!rows.length" :loading="!loaded" /></div>
    <XDrawer v-model="open" :width="460" :busy="busy"
      :title="selected ? t('prefixes.edit', { prefix: selected.prefix }) : t('prefixes.add')">
      <div class="form dt-form">
        <label class="field"><span>{{ t('prefixes.prefix') }}</span><input v-model="form.prefix" class="mono"
          :disabled="!!selected" placeholder="198.51.100.0/24" autocomplete="off"></label>
        <label class="field"><span>{{ t('prefixes.name') }}</span><input v-model="form.name"></label>
        <label class="field"><span>{{ t('prefixes.ipGroup') }}</span><input v-model="form.ip_group"></label>
        <div class="field"><span>{{ t('prefixes.parent') }}</span>
          <XListbox v-model="form.parent_id" :label="t('prefixes.parent')" :options="parents"
            :mode="rows.length >= 20 ? 'search' : 'select'" /></div>
        <div class="field"><span>{{ t('prefixes.template') }}</span>
          <XListbox v-model="form.threshold_template_id" :label="t('prefixes.template')" :options="templates" /></div>
        <div v-if="selected" class="field"><span>{{ t('prefixes.status') }}</span>
          <XSwitch v-model="form.enabled" :label="t(form.enabled ? 'prefixes.enabled' : 'prefixes.disabled')" /></div>
      </div><p v-if="saveError" class="crit mono" role="alert">{{ saveError }}</p>
      <template #footer><button class="btn" :disabled="busy" @click="open = false">{{ t('common.cancel') }}</button>
        <button class="btn primary" :disabled="busy || (!selected && !form.prefix.trim())" @click="save">
          {{ t(selected ? 'prefixes.save' : 'prefixes.create') }}</button></template>
    </XDrawer>
  </div>
</template>
<style>
body:has(.prefixes-page[data-editing='true']) .drawer-head h2 { font-family: var(--font-num); }
</style>
