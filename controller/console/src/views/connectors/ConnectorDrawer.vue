<script setup lang="ts">
import { computed, nextTick, ref, useId, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { isAdmin } from '../../auth'
import { notifyWrite } from '../../notifications'
import XDrawer from '../../components/XDrawer.vue'
import XSeg from '../../components/XSeg.vue'
import XNumber from '../../components/XNumber.vue'
import XPassword from '../../components/XPassword.vue'
import XListbox from '../../components/XListbox.vue'
import XSwitch from '../../components/XSwitch.vue'
import XTip from '../../components/XTip.vue'
import { saveConnector, methods, connectorCheck, fillForm, kinds, kindName, normalizeURL, timeoutMax } from './data'
import type { ConnectorRow, Kind, XDropRow } from './data'
const props = defineProps<{ modelValue: boolean; kind: Kind; row?: ConnectorRow }>()
const emit = defineEmits<{ 'update:modelValue': [value: boolean]; saved: [kind: Kind] }>()
const { t } = useI18n()
const globalId = useId()
const enabledId = useId()
const kind = ref<Kind>(props.kind)
const form = ref(fillForm(kind.value))
const busy = ref(false)
const message = ref('')
const tone = ref('warn')
const nameInput = ref<HTMLInputElement>()
const disabled = computed(() => busy.value || !isAdmin())
const changedURL = computed(() => props.row && kind.value === 'xdrop'
  && normalizeURL(form.value.api_url) !== (props.row as XDropRow).api_url)
const options = computed(() => kinds.map(value => ({ value, label: kindName[value], disabled: disabled.value })))
const title = computed(() => t('connectors.' + (!isAdmin() ? 'view' : props.row ? 'edit' : 'create')))
watch(() => props.modelValue, async open => {
  if (!open) return
  kind.value = props.kind
  form.value = fillForm(props.kind, props.row)
  message.value = ''
  await nextTick()
  await nextTick()
  nameInput.value?.focus()
}, { immediate: true })
function changeKind(value: string) {
  const name = form.value.name
  kind.value = value as Kind
  form.value = fillForm(kind.value)
  form.value.name = name
  message.value = ''
}
async function save() {
  if (disabled.value) return
  const check = connectorCheck(kind.value, form.value, props.row)
  if (check) {
    message.value = t('connectors.' + check.key, check.args ?? {})
    tone.value = 'warn'
    return
  }
  busy.value = true
  message.value = ''
  const savedKind = kind.value
  try {
    await notifyWrite(saveConnector(savedKind, form.value, props.row),
      t('connectors.' + (props.row ? 'updated' : 'created')))
    emit('update:modelValue', false)
    emit('saved', savedKind)
  } catch (error) {
    message.value = error instanceof Error ? error.message : String(error)
    tone.value = 'crit'
  } finally { busy.value = false }
}
</script>
<template>
  <XDrawer :model-value="modelValue" :title="title" :width="600" :busy="busy"
    @update:model-value="emit('update:modelValue', $event)">
    <p class="sub cn-kind">{{ kindName[kind] }}</p>
    <div class="form cn-form">
      <XSeg v-if="!row" :model-value="kind" :options="options" :label="t('connectors.type')"
        @update:model-value="changeKind" />
      <label class="field"><span>{{ t('connectors.name') }}</span>
        <input ref="nameInput" v-model="form.name" :disabled="disabled" autocomplete="off"
          :placeholder="t('connectors.nameExample')"></label>
      <template v-if="kind === 'bgp'">
        <label class="field"><span>{{ t('connectors.asn') }}</span>
          <XNumber v-model="form.bgp_asn" :label="t('connectors.asn')" :min="1" :max="4294967295"
            :digits="0" :disabled="disabled" /></label>
        <label class="field"><span>{{ t('connectors.vtysh') }}</span>
          <input v-model="form.vtysh_path" class="mono" autocomplete="off" :disabled="disabled"
            placeholder="/usr/bin/vtysh"></label>
        <label class="field"><span>{{ t('connectors.description') }}</span>
          <textarea v-model="form.description" rows="2" :disabled="disabled" /></label>
      </template>
      <template v-if="kind === 'xdrop'">
        <label class="field"><span>{{ t('connectors.apiURL') }}</span>
          <input v-model="form.api_url" class="mono" autocomplete="off" :disabled="disabled"
            placeholder="https://xdrop.example.com:8000/api/v1">
          <small class="sub">{{ t('connectors.apiUrlHint') }}</small></label>
        <div class="field"><span>{{ t('connectors.apiKey') }}</span>
          <XPassword v-model="form.api_key" :label="t('connectors.apiKey')" autocomplete="off" :disabled="disabled" />
          <small class="sub">{{ t('connectors.apiKeyTip') }}</small>
          <small v-if="row" :class="changedURL ? 'warn' : 'sub'" data-key-hint>
            {{ t('connectors.' + (changedURL ? 'keyCurrentChanged' : 'keyCurrent'),
              { key: (row as XDropRow).api_key }) }}
          </small></div>
      </template>
      <template v-if="kind === 'webhook'">
        <label class="field"><span>{{ t('connectors.url') }}</span>
          <input v-model="form.url" class="mono" autocomplete="off" :disabled="disabled"
            placeholder="https://hooks.example.net/notify"></label>
        <div class="field"><span>{{ t('connectors.method') }}</span>
          <XListbox v-model="form.method" :label="t('connectors.method')" :disabled="disabled"
            :options="methods.map(value => ({ value, label: value }))" /></div>
        <label class="field"><span>{{ t('connectors.headers') }}</span>
          <textarea v-model="form.headers" class="mono" rows="4" :disabled="disabled"
            placeholder='{"Authorization": "Bearer <token>"}' />
          <small v-if="row" class="sub">{{ t('connectors.headersHint') }}</small></label>
      </template>
      <template v-if="kind === 'shell'">
        <label class="field"><span>{{ t('connectors.command') }}</span>
          <input v-model="form.command" class="mono" autocomplete="off" :disabled="disabled"
            placeholder="/usr/local/bin/script.sh">
          <small class="sub">{{ t('connectors.commandHint') }}</small></label>
        <label class="field"><span>{{ t('connectors.defaultArgs') }}</span>
          <input v-model="form.default_args" class="mono" autocomplete="off" :disabled="disabled"
            placeholder="--attack {attack_id} --ip {dst_ip}"></label>
      </template>
      <label v-if="kind !== 'bgp'" class="field"><span>{{ t('connectors.timeout') }}</span>
        <XNumber v-model="form.timeout_ms" :label="t('connectors.timeout')" :min="1" :max="timeoutMax(kind)"
          :digits="0" :disabled="disabled" />
        <small class="sub">{{ t('connectors.' + kind + 'TimeoutTip') }}</small></label>
      <label v-if="kind === 'webhook'" class="field" :for="globalId">
        <span>{{ t('connectors.global') }} <XTip :text="t('connectors.globalTip')" wide /></span>
        <XSwitch :id="globalId" v-model="form.global" :label="t('connectors.global')" :disabled="disabled" /></label>
      <label class="field" :for="row || kind === 'bgp' ? enabledId : undefined">
        <span>{{ t('connectors.enabled') }}</span>
        <XSwitch v-if="row || kind === 'bgp'" :id="enabledId" v-model="form.enabled" :label="t('connectors.enabled')"
          :disabled="disabled" />
        <small v-else class="sub">{{ t('connectors.autoEnabled') }}</small></label>
      <small v-if="kind === 'xdrop'" class="sub">{{ t('connectors.xdropFallback') }}</small>
    </div>
    <template #footer>
      <p v-if="message" class="cn-message" :class="tone" role="alert">{{ message }}</p>
      <div class="toolbar">
        <button class="btn" :disabled="busy" @click="emit('update:modelValue', false)">{{ t('common.cancel') }}</button>
        <button v-if="isAdmin()" class="btn primary" :disabled="busy" @click="save">
          {{ t('connectors.' + (busy ? 'saving' : 'save')) }}</button>
      </div>
    </template>
  </XDrawer>
</template>
<style scoped>
.cn-kind { margin-top: 0; }
.cn-form small { line-height: 1.6; }
.cn-message { flex: 1; margin: 0; overflow-wrap: anywhere; }
</style>
