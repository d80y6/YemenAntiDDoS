<script setup lang="ts">
import { computed, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { isAdmin } from '../../auth'
import { request } from '../../api/client'
import { notify } from '../../notifications'
import XDrawer from '../../components/XDrawer.vue'
import XListbox from '../../components/XListbox.vue'
import XNumber from '../../components/XNumber.vue'
import XCheck from '../../components/XCheck.vue'
import XSwitch from '../../components/XSwitch.vue'
import XTip from '../../components/XTip.vue'
import { attributes, operators, exampleKey, matching, saveAction, validate } from './data'
import type { Form, Connector, Phase, Send } from './data'
const props = defineProps<{
  modelValue: boolean; form: Form; phase: Phase; responseID: number
  connectors: Record<string, Connector[]>; viewing?: boolean
}>()
const emit = defineEmits<{ 'update:modelValue': [value: boolean]; refresh: [responseID: number] }>()
const { t } = useI18n()
const saving = ref(false), error = ref(''), warning = ref('')
const disabled = computed(() => saving.value || props.viewing || !isAdmin())
const readOnly = computed(() => disabled.value || !props.form.preconditionsLoaded)
const title = computed(() => t(props.viewing ? 'responses.viewAction'
  : props.form.id === null ? 'responses.addAction' : 'responses.editAction'))
const options = (values: string[], prefix = '') =>
  values.map(value => ({ value, label: t('responses.' + prefix + value) }))
const types = computed(() => options(props.phase === 'on_expired'
  ? ['webhook', 'shell'] : ['webhook', 'xdrop', 'shell', 'bgp'], 'type_'))
const connectorOptions = computed(() => [{ value: '', label: t('responses.selectConnector') },
  ...(props.connectors[props.form.action_type] ?? []).map(c => ({ value: String(c.id),
    label: c.name + (c.enabled === false ? t('responses.disabledConnector') : '') }))])
function toggle(key: 'xdrop_fields' | 'target_node_ids', value: any, selected: boolean) {
  const values: any[] = props.form[key]
  ;(props.form[key] as any[]) = selected ? [...values, value] : values.filter(v => v !== value)
}
const send: Send = (path, method, body) => request(path, {
  method, body: body === undefined ? undefined : JSON.stringify(body),
})
async function save() {
  if (disabled.value) return
  error.value = ''
  warning.value = ''
  const invalid = validate(props.form)
  if (invalid) { warning.value = t(invalid.key, { row: invalid.row }); return }
  saving.value = true
  const rid = props.responseID, phase = props.phase, form = props.form
  const result = await saveAction(form, phase, rid, send)
  emit('refresh', rid)
  if (result.ok) {
    notify(t(result.created ? 'responses.actionCreated' : 'responses.actionUpdated'))
    emit('update:modelValue', false)
  } else {
    error.value = (result.reason || t('common.failed')) + (result.suffix ? ' ' + t(result.suffix) : '')
    notify(error.value, 'crit')
  }
  saving.value = false
}
</script>
<template>
  <XDrawer :model-value="modelValue" :title="title" :width="600" :busy="saving"
    @update:model-value="emit('update:modelValue', $event)">
    <p class="sub">{{ t(phase === 'on_detected' ? 'responses.onDetected' : 'responses.onExpired') }}</p>
    <p v-if="!form.preconditionsLoaded" class="confirm warn" role="alert">{{ t('responses.conditionsFailed') }}</p>
    <fieldset class="rs-form" :disabled="disabled">
      <label class="field"><span>{{ t('responses.actionType') }}</span>
        <XListbox :model-value="form.action_type" :options="types" :label="t('responses.actionType')"
          :disabled="disabled || form.id !== null"
          @update:model-value="form.action_type = $event; form.connector_id = null" />
        <small v-if="form.id !== null" class="sub">{{ t('responses.typeLocked') }}</small></label>
      <label v-if="form.action_type !== 'xdrop'" class="field"><span>{{ t('responses.connector') }}</span>
        <XListbox :model-value="String(form.connector_id ?? '')" :options="connectorOptions"
          :label="t('responses.connector')" :disabled="disabled"
          @update:model-value="form.connector_id = $event ? Number($event) : null" /></label>
      <div class="rs-grid"><label class="field"><span>{{ t('responses.priority') }}</span>
        <XNumber v-model="form.priority" :label="t('responses.priority')" :min="1" :max="10" :digits="0"
          :disabled="disabled" /></label>
        <label class="field"><span>{{ t('responses.runMode') }}</span>
          <XListbox v-model="form.run_mode" :label="t('responses.runMode')" :disabled="disabled"
            :options="options(phase === 'on_expired' ? ['once'] : ['once', 'periodic', 'retry_until_success'])" />
        </label></div>
      <small v-if="form.run_mode === 'periodic'" class="sub">{{ t('responses.periodicExplanation') }}</small>
      <label class="field"><span>{{ t('responses.execution') }}</span>
        <XListbox v-model="form.execution" :options="options(['automatic', 'manual'])"
          :label="t('responses.execution')" :disabled="disabled" /></label>
      <small v-if="form.execution === 'manual'" class="sub">{{ t('responses.manualHint') }}</small>
      <template v-if="form.action_type === 'xdrop'">
        <div class="field"><span>{{ t('responses.xdropAction') }}
          <XTip :text="t('responses.xdropDecoderScope') + '：' + t('responses.xdropDecoderScopeBody')" wide /></span>
          <XListbox v-model="form.xdrop_action" :options="options(['filter_l4', 'rate_limit', 'unblock'])"
            :label="t('responses.xdropAction')" :disabled="disabled" /></div>
        <div v-if="matching(form)" class="field"><span>{{ t('responses.filterFields') }}
          <XTip :text="t('responses.filterFieldsHint')" wide /></span><div class="rs-checks">
          <span v-for="field in ['dst_ip', 'src_ip', 'dst_port', 'src_port', 'protocol']" :key="field">
            <XCheck :model-value="form.xdrop_fields.includes(field)" :label="t('responses.field_' + field)"
              :disabled="disabled" @update:model-value="toggle('xdrop_fields', field, $event)" />
            <XTip v-if="field === 'protocol'" :text="t('responses.protocolPinnedTip')" wide /></span></div></div>
        <label v-if="form.xdrop_action === 'rate_limit'" class="field"><span>{{ t('responses.rateLimitPPS') }}</span>
          <div class="toolbar"><XNumber v-model="form.xdrop_rate_limit" :label="t('responses.rateLimitPPS')"
            :min="1" :max="100000000" :digits="0" :disabled="disabled" /><span class="sub">pps</span></div></label>
        <div class="field"><span>{{ t('responses.targetNodes') }}</span><div class="rs-checks mono">
          <XCheck v-for="node in connectors.xdrop ?? []" :key="node.id"
            :model-value="form.target_node_ids.includes(node.id)" :disabled="disabled"
            :label="node.name + (node.enabled === false ? t('responses.disabledConnector') : '')"
            @update:model-value="toggle('target_node_ids', node.id, $event)" /></div>
          <small class="sub">{{ t('responses.targetEnabledHint') }}</small></div>
        <div v-if="phase === 'on_detected' && matching(form)" class="field"><span>{{ t('responses.unblockDelay') }}
          <XTip :text="t('responses.unblockDelayHint')" wide /></span>
          <XNumber v-model="form.unblock_delay_minutes" :label="t('responses.unblockDelay')"
            :min="0" :max="1440" :digits="0" :disabled="disabled" /></div>
      </template>
      <template v-if="form.action_type === 'bgp' && phase === 'on_detected'">
        <label class="field"><span>{{ t('responses.routeMap') }}</span>
          <input v-model="form.bgp_route_map" class="mono" :placeholder="t('responses.routeExample')"></label>
        <label class="field"><span>{{ t('responses.withdrawDelay') }}</span>
          <XNumber v-model="form.bgp_withdraw_delay_minutes" :label="t('responses.withdrawDelay')"
            :min="0" :max="1440" :digits="0" :disabled="disabled" />
          <small class="sub">{{ t('responses.withdrawDelayHint') }}</small></label>
      </template>
      <label v-if="form.action_type === 'shell'" class="field"><span>{{ t('responses.shellExtraArgs') }}</span>
        <input v-model="form.shell_extra_args" class="mono" :placeholder="t('responses.argsExample')"></label>
      <label class="field"><span>{{ t('responses.enabled') }}</span>
        <XSwitch v-model="form.enabled" :label="t('responses.enabled')" :disabled="disabled" /></label>
      <div class="field"><span>{{ t('responses.preconditions') }}</span>
        <div v-for="(condition, i) in form.preconditions" :key="i" class="rs-condition">
          <XListbox v-model="condition.attribute" :options="options(attributes, 'attr_')"
            :label="t('responses.attribute')" :disabled="readOnly" />
          <XListbox v-model="condition.operator" :options="options(operators, 'op_')"
            :label="t('responses.operator')" :disabled="readOnly" />
          <input v-model="condition.value" :aria-label="t('responses.value')"
            :placeholder="t(exampleKey(condition.attribute, condition.operator))" :disabled="readOnly">
          <button v-if="!readOnly" class="btn ghost" type="button" :aria-label="t('responses.removeCondition')"
            @click="form.preconditions.splice(i, 1)">✕</button>
        </div>
        <button v-if="!readOnly" class="btn sm ghost rs-add" type="button"
          @click="form.preconditions.push({ attribute: '', operator: 'eq', value: '' })">
          + {{ t('responses.addCondition') }}</button>
        <small v-if="!form.preconditionsLoaded" class="sub">{{ t('responses.conditionsReadOnly') }}</small>
      </div>
    </fieldset>
    <template #footer><div class="rs-foot"><span v-if="saving" class="sub">{{ t('responses.saving') }}</span>
      <span v-else-if="error" class="crit mono" role="alert">{{ error }}</span>
      <span v-else-if="warning" class="warn" role="alert">{{ warning }}</span>
      <small v-else-if="form.id === null && phase === 'on_detected' && ['xdrop', 'bgp'].includes(form.action_type)"
        class="sub">{{ t('responses.autoPairHint') }}</small></div>
      <div class="toolbar"><button class="btn" :disabled="saving" @click="emit('update:modelValue', false)">
        {{ t('common.cancel') }}</button><button v-if="!viewing && isAdmin()" class="btn primary" :disabled="saving"
        @click="save">{{ t('responses.save') }}</button></div></template>
  </XDrawer>
</template>
<style scoped>
.rs-form { border: 0; padding: 0; margin: 20px 0 0; display: grid; gap: 16px; min-width: 0; }
.rs-grid { display: grid; grid-template-columns: 1fr 2fr; gap: 14px; }
.rs-checks { display: flex; flex-wrap: wrap; gap: 10px 18px; }
.rs-checks :deep(.tip-text) { left: auto; right: 0; }
.rs-condition { display: grid; grid-template-columns: 150px 90px minmax(0, 1fr) 30px; gap: 8px; }
.rs-condition input { min-width: 0; width: 100%; }
.rs-condition :deep(.listbox-button) { min-width: 0; width: 100%; overflow: hidden; }
.rs-add { justify-self: start; }
:global(.drawer:has(.rs-form)) { max-width: 100%; }
.rs-foot { flex: 1; min-width: 0; overflow-wrap: anywhere; }
@media (max-width: 600px) {
  .rs-form :deep(.tip-text) {
    position: fixed; left: 16px; right: auto; top: 30%; width: calc(100vw - 48px);
  }
  .rs-condition { grid-template-columns: minmax(0, 1fr) 85px 30px; }
  .rs-condition input { grid-column: 1 / 3; grid-row: 2; }
  .rs-condition > button:last-child:not([role=combobox]) { grid-column: 3; grid-row: 1 / 3; }
}
</style>
