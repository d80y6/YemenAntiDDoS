<script setup lang="ts">
import { computed, nextTick, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { useRouter } from 'vue-router'
import { isAdmin } from '../../auth'
import XConfirm from '../../components/XConfirm.vue'
import XEmpty from '../../components/XEmpty.vue'
import Heading from './Heading.vue'
import TemplateDrawer from './TemplateDrawer.vue'
import { reads, write } from './reads'
import type { Row } from './data'
import './detection.css'
const { t } = useI18n()
const router = useRouter()
const { data, error, errors, loaded, refresh } = reads(() => ({ rows: 'threshold-templates', rules: 'thresholds',
  responses: 'responses' }), 'rows')
const rows = computed<Row[]>(() => data.value.rows ?? [])
const adding = ref(false), inline = ref<{ id: number; kind: string }>(), copyName = ref('')
const copyError = ref(''), busy = ref(false)
async function show(row: Row, kind: string) {
  inline.value = { id: row.id, kind }
  copyError.value = ''
  copyName.value = t('templates.copyDefault', { name: row.name })
  if (kind === 'copy') {
    await nextTick()
    const input = document.querySelector<HTMLInputElement>('.templates-page .inline input')
    input?.focus()
    input?.select()
  }
}
async function duplicate(row: Row) {
  if (!copyName.value.trim() || busy.value) return
  busy.value = true
  try {
    await write(`threshold-templates/${row.id}/duplicate`, 'POST',
      { name: copyName.value.trim() }, t('templates.copied'))
    inline.value = undefined
    await refresh()
  } catch (e) { copyError.value = (e as Error).message }
  finally { busy.value = false }
}
async function remove(row: Row) {
  await write('threshold-templates/' + row.id, 'DELETE', undefined, t('prefixes.deleted'))
  await refresh()
}
</script>
<template>
  <div class="page detection templates-page">
    <Heading view="templates" :count="loaded && !errors.rules ? (data.rules ?? []).length : undefined">
      <button v-if="isAdmin()" class="btn primary sm" @click="adding = true">{{ t('prefixes.create') }}</button>
    </Heading><p v-if="error" class="crit mono" role="alert">{{ error }}
      <button class="btn sm" @click="refresh">{{ t('prefixes.retry') }}</button></p>
    <div class="tbl-wrap"><table><thead><tr><th>ID</th><th>{{ t('prefixes.name') }}</th>
      <th>{{ t('prefixes.description') }}</th><th class="r">{{ t('templates.rules') }}</th>
      <th class="r">{{ t('templates.prefixes') }}</th><th>{{ t('prefixes.actions') }}</th></tr></thead><tbody>
      <template v-for="row in rows" :key="row.id"><tr class="link" tabindex="0"
        @click="($event.target as Element).closest('button,a,input') || router.push('/thresholds/' + row.id)"
        @keydown.enter.self="router.push('/thresholds/' + row.id)">
        <td class="num sub">{{ row.id }}</td><td><strong>{{ row.name }}</strong></td>
        <td class="sub">{{ row.description }}</td><td class="r num">{{ row.rule_count }}</td>
        <td class="r num">{{ row.prefix_count }}</td><td><div class="actions">
          <RouterLink :to="'/thresholds/' + row.id" class="btn sm ghost">
            {{ t(isAdmin() ? 'prefixes.editAction' : 'responses.view') }}</RouterLink>
          <button v-if="isAdmin()" class="btn sm ghost" @click="show(row, 'copy')">{{ t('templates.copy') }}</button>
          <button v-if="isAdmin()" class="btn sm ghost" @click="show(row, row.prefix_count > 0 ? 'used' : 'delete')">
            {{ t('prefixes.delete') }}</button></div></td></tr>
        <tr v-if="inline?.id === row.id"><td colspan="6">
          <div v-if="inline?.kind === 'copy'" class="inline" @keydown.esc="inline = undefined">
            <label>{{ t('templates.copyName') }} <input v-model="copyName" :disabled="busy"></label>
            <button class="btn sm" :disabled="busy" @click="inline = undefined">{{ t('common.cancel') }}</button>
            <button class="btn primary sm" :disabled="busy || !copyName.trim()" @click="duplicate(row)">
              {{ t('templates.copy') }}</button><p class="sub">{{ t('templates.copyHint') }}</p>
            <p v-if="copyError" role="alert" class="crit mono">{{ copyError }}</p></div>
          <div v-else-if="inline?.kind === 'used'" class="inline" role="status">
            {{ t('templates.inUse', { n: row.prefix_count }) }}
            <button class="btn sm" @click="inline = undefined">{{ t('templates.ack') }}</button></div>
          <XConfirm v-else :model-value="true" :title="t('templates.deleteTitle', { name: row.name })"
            :description="row.rule_count ? t('templates.deleteConsequences', { n: row.rule_count }) : ''"
            :action="() => remove(row)" tone="danger" :confirm-label="t('prefixes.delete')"
            @update:model-value="inline = undefined" />
        </td></tr></template></tbody></table><XEmpty v-if="!rows.length" :loading="!loaded" /></div>
    <TemplateDrawer v-model="adding" @saved="refresh" />
  </div>
</template>
