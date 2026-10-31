<script setup lang="ts">
import { computed, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { isAdmin } from '../../auth'
import XConfirm from '../../components/XConfirm.vue'
import XEmpty from '../../components/XEmpty.vue'
import XTip from './Tip.vue'
import Heading from './Heading.vue'
import RuleDrawer from './RuleDrawer.vue'
import { reads, write } from './reads'
import type { Row } from './data'
import './detection.css'
const { t } = useI18n()
const { data, error, loaded, refresh } = reads(() => ({ rows: 'thresholds', prefixes: 'prefixes',
  responses: 'responses' }), 'rows')
const rows = computed<Row[]>(() => data.value.rows ?? [])
const adding = ref(false), confirm = ref<number>()
const prefixTitle = (id: number) => (data.value.prefixes ?? []).find((p: Row) => p.id === id)?.prefix
const responseTitle = (id: number) => (data.value.responses ?? []).find((r: Row) => r.id === id)?.name
async function remove(row: Row) {
  await write('thresholds/' + row.id, 'DELETE', undefined, t('prefixes.deleted'))
  await refresh()
}
</script>
<template>
  <div class="page detection all-rules"><Heading view="rules" :count="rows.length">
    <button v-if="isAdmin()" class="btn primary sm" @click="adding = true">{{ t('thresholds.addRule') }}</button>
  </Heading><p v-if="error" class="crit mono" role="alert">{{ error }}
    <button class="btn sm" @click="refresh">{{ t('prefixes.retry') }}</button></p>
    <div class="tbl-wrap"><table><thead><tr><th>{{ t('thresholds.prefixID') }}
      <XTip :text="t('thresholds.templateRow')" wide /></th><th>{{ t('thresholds.domain') }}</th>
      <th>{{ t('thresholds.decoder') }}</th><th>{{ t('thresholds.unit') }}</th><th>{{ t('thresholds.comparison') }}</th>
      <th>{{ t('thresholds.value') }}</th><th>{{ t('thresholds.inheritable') }}</th>
      <th>{{ t('thresholds.response') }}</th>
      <th>{{ t('prefixes.actions') }}</th></tr></thead><tbody><template v-for="row in rows" :key="row.id"><tr>
        <td class="num" :title="prefixTitle(row.prefix_id)">{{ row.prefix_id }}</td>
        <td class="mono">{{ row.domain }}</td><td class="mono">{{ row.decoder }}</td>
        <td class="mono">{{ row.unit }}</td>
        <td class="mono">{{ t('thresholds.' + row.comparison) }}</td><td class="r num">{{ row.value }}</td>
        <td :class="row.inheritable ? 'ok' : 'sub'">{{ row.inheritable ? '✓' : '✗' }}</td>
        <td class="num" :title="responseTitle(row.response_id)">{{ row.response_id ?? '—' }}</td>
        <td><button v-if="isAdmin()" class="btn sm ghost" @click="confirm = row.id">
          {{ t('prefixes.delete') }}</button></td>
      </tr><tr v-if="confirm === row.id"><td colspan="9"><XConfirm :model-value="true"
        :title="t('thresholds.deleteFlat')" description="" :action="() => remove(row)" tone="danger"
        :confirm-label="t('prefixes.delete')" @update:model-value="confirm = undefined" /></td></tr>
      </template></tbody></table><XEmpty v-if="!rows.length" :loading="!loaded" /></div>
    <RuleDrawer v-model="adding" :prefixes="data.prefixes ?? []" @saved="refresh" />
  </div>
</template>
