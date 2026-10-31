<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import XDrawer from '../../components/XDrawer.vue'
import XSeg from '../../components/XSeg.vue'
import XNumber from '../../components/XNumber.vue'
import XSwitch from '../../components/XSwitch.vue'
import XListbox from '../../components/XListbox.vue'
import { ruleForm, ruleBody, flatBody, options, decoderOptions, pctError, zeroHint, changeUnit, type Row } from './data'
import { write } from './reads'
const props = defineProps<{ modelValue: boolean; template?: Row; row?: Row; global?: boolean; prefixes?: Row[] }>()
const emit = defineEmits<{ 'update:modelValue': [value: boolean]; saved: [] }>()
const { t } = useI18n()
const form = ref<Row>({ ...ruleForm(), prefix_id: 1 }), error = ref(''), busy = ref(false)
const flat = computed(() => !props.template)
watch(() => props.modelValue, open => {
  if (open) { form.value = { ...ruleForm(props.global, props.row), prefix_id: 1 }; error.value = '' }
})
async function save() {
  error.value = pctError(form.value, t('thresholds.pctWarning'))
  if (error.value) return
  busy.value = true
  try {
    const path = flat.value ? 'thresholds' : props.row ? 'threshold-rules/' + props.row.id
      : `threshold-templates/${props.template!.id}/rules`
    await write(path, props.row ? 'PUT' : 'POST', flat.value ? flatBody(form.value) : ruleBody(form.value),
      t(flat.value ? 'thresholds.created' : props.row ? 'prefixes.updated' : 'thresholds.ruleAdded'))
    emit('update:modelValue', false)
    emit('saved')
  } catch (e) { error.value = (e as Error).message }
  finally { busy.value = false }
}
</script>
<template>
  <XDrawer :model-value="modelValue" :width="460" :busy="busy" :title="flat ? t('thresholds.addRule') :
    t(row ? 'thresholds.ruleTitleEdit' : 'thresholds.ruleTitleAdd', { name: template!.name })"
    @update:model-value="emit('update:modelValue', $event)">
    <div class="form dt-form">
      <div v-if="flat" class="field"><span>{{ t('thresholds.prefixID') }}</span>
        <XNumber v-model="form.prefix_id" :label="t('thresholds.prefixID')" :min="1" :digits="0" />
        <small class="sub mono">{{ prefixes?.find(p => p.id === form.prefix_id)?.prefix
          ?? t('thresholds.missingPrefix') }}</small></div>
      <div class="field"><span>{{ t('thresholds.domain') }}</span><XSeg v-model="form.domain"
        :label="t('thresholds.domain')" :options="options(global ? ['subnet'] : ['internal_ip', 'subnet'])" /></div>
      <p v-if="global" class="warn">{{ t('thresholds.globalSubnetOnly') }}</p>
      <div v-if="!flat" class="field"><span>{{ t('thresholds.direction') }}</span>
        <XSeg v-model="form.direction" :label="t('thresholds.direction')" :options="[
          { value: 'receives', label: t('thresholds.receives') },
          { value: 'sends', label: t('thresholds.sends') }]" /></div>
      <div class="field dt-decoder-field"><span>{{ t('thresholds.decoder') }}</span><XListbox v-model="form.decoder"
        :options="decoderOptions" :label="t('thresholds.decoder')" /></div>
      <div class="field"><span>{{ t('thresholds.unit') }}</span><XSeg :model-value="form.unit"
        :options="options(flat ? ['pps', 'bps'] : ['pps', 'bps', 'pct'])" :label="t('thresholds.unit')"
        @update:model-value="changeUnit(form, $event)" /></div>
      <div class="field"><span>{{ t('thresholds.comparison') }}</span><XSeg v-model="form.comparison"
        :options="['over', 'under'].map(value => ({ value, label: t('thresholds.' + value) }))"
        :label="t('thresholds.comparison')" /></div>
      <div class="field"><span>{{ t('thresholds.value') }}</span><XNumber v-model="form.value"
        :label="t('thresholds.value')" :min="form.unit === 'pct' ? 1 : 0"
        :max="form.unit === 'pct' ? 100 : undefined" :digits="0" />
        <small v-if="form.unit === 'pct'" class="sub">{{ t('thresholds.pctRange') }}</small>
        <small v-if="!flat && zeroHint(form)" class="sub">{{ t('thresholds.zero') }}</small></div>
      <div class="field"><span>{{ t('thresholds.inheritable') }}</span>
        <XSwitch v-model="form.inheritable" :label="t('thresholds.inheritable')" /></div>
    </div><p v-if="error" class="crit mono" role="alert">{{ error }}</p>
    <template #footer><button class="btn" :disabled="busy" @click="emit('update:modelValue', false)">
      {{ t('common.cancel') }}</button><button class="btn primary" :disabled="busy" @click="save">
        {{ t(row ? 'prefixes.save' : 'prefixes.create') }}</button></template>
  </XDrawer>
</template>
