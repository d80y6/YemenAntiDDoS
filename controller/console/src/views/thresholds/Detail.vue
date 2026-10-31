<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { useRoute } from 'vue-router'
import { useI18n } from 'vue-i18n'
import { isAdmin } from '../../auth'
import { dtRate } from '../../format'
import XEmpty from '../../components/XEmpty.vue'
import XTip from './Tip.vue'
import XConfirm from '../../components/XConfirm.vue'
import TemplateDrawer from './TemplateDrawer.vue'
import RuleDrawer from './RuleDrawer.vue'
import ResponseSelect from './ResponseSelect.vue'
import { reads, write } from './reads'
import { globalTemplate, recommendation, type Row } from './data'
import './detection.css'
const { t } = useI18n()
const route = useRoute()
const { data, error, failure, loaded, refresh } = reads(() => ({ detail: 'threshold-templates/' + route.params.id,
  responses: 'responses', baselines: 'baseline' }), 'detail')
const detail = computed(() => data.value.detail ?? {})
const template = computed<Row>(() => detail.value.template ?? {})
const rules = computed<Row[]>(() => detail.value.rules ?? [])
const users = computed<Row[]>(() => detail.value.prefixes_using ?? [])
const more = ref(false), renaming = ref(false), ruleOpen = ref(false), selected = ref<Row>()
const confirm = ref<number>(), rowErrors = ref<Record<number, string>>({})
const recommend = (row: Row) => recommendation(row, users.value, data.value.baselines ?? [])
const reload = () => refresh(['detail', 'baselines'])
watch(() => route.params.id, () => {
  more.value = false
  rowErrors.value = {}
  ruleOpen.value = false
  renaming.value = false
  selected.value = undefined
  confirm.value = undefined
})
function edit(row?: Row) { selected.value = row; ruleOpen.value = true }
async function remove(row: Row) {
  await write('threshold-rules/' + row.id, 'DELETE', undefined, t('prefixes.deleted'))
  await reload()
}
</script>
<template>
  <div class="page detection template-detail">
    <nav class="crumb"><RouterLink to="/thresholds">{{ t('nav.thresholds') }}</RouterLink> / {{ template.name }}</nav>
    <RouterLink v-if="failure?.status === 404" to="/thresholds">{{ t('templates.missing') }}</RouterLink>
    <p v-else-if="error" class="crit mono" role="alert">{{ error }}
      <button class="btn sm" @click="refresh">{{ t('prefixes.retry') }}</button></p>
    <template v-else-if="template.id">
      <div class="page-head"><div><h1>{{ template.name }}</h1><span class="sub">{{ template.description }}</span></div>
        <button v-if="isAdmin()" class="btn sm" @click="renaming = true">{{ t('templates.editName') }}</button></div>
      <section class="panel"><div class="meta"><span class="sub">{{ t('thresholds.defaultResponse') }}</span>
        <ResponseSelect :key="template.id" :row="template" :responses="data.responses ?? []" @saved="reload" /></div>
        <div v-if="users.length" class="meta"><span class="sub">{{ t('templates.users', { n: users.length }) }}</span>
          <span v-for="p in more ? users : users.slice(0, 5)" :key="p.id" class="pill mono">{{ p.prefix }}</span>
          <button v-if="users.length > 5" class="btn sm ghost" @click="more = !more">
            {{ more ? t('templates.less') : t('templates.more', { n: users.length - 5 }) }}</button></div></section>
      <section class="panel"><div class="panel-head"><h2>{{ t('templates.ruleCount', { n: rules.length }) }}</h2>
        <button v-if="isAdmin()" class="btn sm primary" @click="edit()">+ {{ t('thresholds.addRule') }}</button></div>
        <div class="tbl-wrap"><table><thead><tr><th>{{ t('thresholds.domain') }}</th>
          <th>{{ t('thresholds.direction') }}</th><th>{{ t('thresholds.comparison') }}</th>
          <th class="r">{{ t('thresholds.value') }}</th><th>{{ t('thresholds.decoder') }}</th>
          <th>{{ t('thresholds.unit') }}</th><th>{{ t('thresholds.inheritable') }}</th>
          <th>{{ t('thresholds.response') }}</th><th>{{ t('thresholds.recommend') }}</th>
          <th>{{ t('prefixes.actions') }}</th></tr></thead><tbody>
          <template v-for="row in rules" :key="row.id"><tr>
            <td class="mono">{{ row.domain }}</td><td class="mono">{{ t('thresholds.' + row.direction) }}</td>
            <td class="mono">{{ t('thresholds.' + row.comparison) }}</td><td class="r num">{{ dtRate(row.value) }}</td>
            <td class="mono">{{ row.decoder }}</td><td class="mono">{{ row.unit }}</td>
            <td :class="row.inheritable ? 'ok' : 'sub'">{{ row.inheritable ? '✓' : '✗' }}</td>
            <td><ResponseSelect :row="row" :responses="data.responses ?? []" rule @saved="reload"
              @error="rowErrors[row.id] = $event" /></td>
            <td class="num sub">{{ recommend(row).key ? t(recommend(row).key!) : recommend(row).text }}
              <XTip v-if="recommend(row).tip" :text="t(recommend(row).tip!)" direction="up-right" wide /></td>
            <td><div v-if="isAdmin()" class="actions">
              <button class="btn sm ghost" @click="edit(row)">{{ t('prefixes.editAction') }}</button>
              <button class="btn sm ghost" @click="confirm = row.id">{{ t('prefixes.delete') }}</button></div></td>
          </tr><tr v-if="rowErrors[row.id]"><td colspan="10" class="crit mono" role="alert">
            {{ rowErrors[row.id] }}</td></tr><tr v-if="confirm === row.id"><td colspan="10">
            <XConfirm :model-value="true" :title="t('thresholds.deleteRule')"
              :description="`${row.decoder} ${row.unit} ${t('thresholds.' + row.comparison)} ${dtRate(row.value)}`"
              :action="() => remove(row)" tone="danger" :confirm-label="t('prefixes.delete')"
              @update:model-value="confirm = undefined" /></td></tr></template>
          </tbody></table><XEmpty v-if="!rules.length" /></div></section>
      <TemplateDrawer v-model="renaming" :row="template" @saved="reload" />
      <RuleDrawer v-model="ruleOpen" :template="template" :row="selected"
        :global="globalTemplate(users)" @saved="reload" />
    </template><XEmpty v-else-if="!loaded" loading />
  </div>
</template>
