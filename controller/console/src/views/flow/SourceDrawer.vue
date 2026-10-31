<script setup lang="ts">
import { computed, onUnmounted, reactive, ref, useId, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { isAdmin } from '../../auth'
import { notifyWrite } from '../../notifications'
import XDrawer from '../../components/XDrawer.vue'
import XSeg from '../../components/XSeg.vue'
import XNumber from '../../components/XNumber.vue'
import XSwitch from '../../components/XSwitch.vue'
import XPill from '../../components/XPill.vue'
import XConfirm from '../../components/XConfirm.vue'
import { deleteSource, rawError, saveSource, sourceActive, sourceForm, sourceValidation, withoutPrefix } from './data'
import type { FlowStatus, Listener, Source } from './data'
const props = defineProps<{ modelValue: boolean; listener: Listener; node: string; sources?: Source[];
  error: string; status?: FlowStatus }>()
const emit = defineEmits<{ 'update:modelValue': [value: boolean]; saved: []; retry: [] }>()
const { t } = useI18n()
const id = useId(), view = ref<'list' | 'new' | 'edit'>('list'), editing = ref<Source>()
const form = reactive(sourceForm()), busy = ref(false), message = ref(''), tone = ref('crit')
const toggling = reactive<Record<number, boolean>>({}), confirm = ref<number>()
let alive = true
onUnmounted(() => { alive = false })
const disabled = computed(() => busy.value || !isAdmin())
const title = computed(() => view.value === 'list'
  ? t('flow.sourcesTitle', { address: props.listener.listen_address })
  : editing.value ? t(isAdmin() ? 'flow.editSource' : 'flow.viewSource', { name: editing.value.name })
    : t('flow.addSource'))
const modes = computed(() => [
  ['auto', t('flow.modeAuto')], ['force', t('flow.modeForce')], ['none', t('flow.modeNone')],
]
  .map(([value, label]) => ({ value: value!, label: label!, disabled: disabled.value })))
watch(() => props.modelValue, open => { if (open) back() })
function back() { view.value = 'list'; message.value = ''; confirm.value = undefined }
function open(row?: Source, event?: MouseEvent) {
  if (event && (event.target as HTMLElement).closest('button,label,a,[role=alertdialog]')) return
  editing.value = row
  Object.assign(form, sourceForm(row))
  view.value = row ? 'edit' : 'new'
  message.value = ''
  confirm.value = undefined
}
async function save() {
  if (disabled.value) return
  const invalid = sourceValidation(form)
  if (invalid) { message.value = t(invalid); tone.value = 'warn'; return }
  busy.value = true
  message.value = ''
  try {
    await notifyWrite(saveSource(form, props.listener.id, editing.value),
      t(editing.value ? 'flow.updated' : 'flow.sourceCreated'))
    if (alive) { back(); emit('saved') }
  } catch (error) { message.value = rawError(error); tone.value = 'crit' }
  finally { busy.value = false }
}
async function toggle(row: Source, enabled: boolean) {
  if (!isAdmin() || toggling[row.id]) return
  const before = row.enabled
  row.enabled = enabled
  toggling[row.id] = true
  try {
    await notifyWrite(saveSource({ ...row, enabled, toggle: true }, props.listener.id, row), t('flow.updated'))
    if (alive) emit('saved')
  } catch { row.enabled = before }
  finally { toggling[row.id] = false }
}
async function remove(row: Source) {
  await notifyWrite(deleteSource(row.id), t('flow.deleted'))
  if (alive) emit('saved')
}
</script>
<template>
  <XDrawer :model-value="modelValue" :title="title" :width="780" :busy="busy"
    @update:model-value="emit('update:modelValue', $event)">
    <div class="fl-sources">
      <template v-if="view === 'list'">
        <p class="sub mono">{{ node }} · {{ listener.protocol_mode === 'auto'
          ? t('flow.modeAuto') : listener.protocol_mode }}</p>
        <div class="fl-bar"><span class="sub">{{ t('flow.sourceRefresh') }}</span>
          <button v-if="isAdmin()" class="btn primary" @click="open()">{{ t('flow.addSource') }}</button></div>
        <p v-if="error" role="alert">{{ error }} <button class="btn" @click="emit('retry')">
          {{ t('flow.retry') }}</button></p>
        <div v-else class="tbl-wrap">
          <table class="fl-source-table"><thead><tr>
            <th v-for="key in ['name', 'deviceIP', 'status', 'sampleMode', 'sampleRate', 'description', 'enabled']"
              :key="key">{{ t('flow.' + key) }}</th>
            <th v-if="isAdmin()">{{ t('flow.delete') }}</th>
          </tr></thead><tbody>
            <template v-for="row in sources" :key="row.id">
              <tr class="fl-source-row" :class="{ 'fl-disabled': !row.enabled }" @click="open(row, $event)">
                <td class="fl-link">{{ row.name }}</td><td class="mono">{{ withoutPrefix(row.device_ip) }}</td>
                <td><span v-if="sourceActive(row, status) === undefined" class="sub">—</span>
                  <span v-else class="fl-source-status"><i class="dot" :class="{ ok: sourceActive(row, status) }" />
                    {{ t(sourceActive(row, status) ? 'flow.online' : 'flow.offline') }}</span></td>
                <td><XPill class="mono">{{ ({ auto: t('flow.modeAuto'), force: t('flow.modeForce'),
                  none: t('flow.modeNone') } as Record<string, string>)[row.sample_mode]
                  ?? row.sample_mode }}</XPill></td>
                <td class="num">{{ row.sample_rate }}</td>
                <td>{{ row.description }}</td>
                <td><template v-if="isAdmin()">
                  <XSwitch :id="id + '-enabled-' + row.id" :model-value="row.enabled" :disabled="toggling[row.id]"
                    :label="t('flow.enableSource', { name: row.name })" @update:model-value="toggle(row, $event)" />
                  </template><span v-else>{{ t(row.enabled ? 'flow.yes' : 'flow.no') }}</span></td>
                <td v-if="isAdmin()"><button class="btn sm danger" @click="confirm = row.id">
                  {{ t('flow.delete') }}</button></td>
              </tr>
              <tr v-if="confirm === row.id && isAdmin()"><td colspan="8">
                <XConfirm :model-value="true" :title="t('flow.deleteSource', { name: row.name })" description=""
                  :action="() => remove(row)" :confirm-label="t('flow.delete')" tone="danger"
                  @update:model-value="confirm = undefined" /></td></tr>
            </template>
            <tr v-if="sources && !sources.length"><td :colspan="isAdmin() ? 8 : 7" class="empty">
              {{ t('flow.empty') }}</td></tr>
          </tbody></table>
        </div>
      </template>
      <template v-else>
        <button class="btn ghost fl-back" :disabled="busy" @click="back">{{ t('flow.sourcesBack') }}</button>
        <div class="form fl-form">
          <label class="field" :for="id + '-name'"><span>{{ t('flow.name') }}</span>
            <input :id="id + '-name'" v-model="form.name" :disabled="disabled" autocomplete="off">
            <small class="sub">{{ t('flow.nameHint') }}</small></label>
          <label class="field" :for="id + '-ip'"><span>{{ t('flow.deviceIP') }}</span>
            <input :id="id + '-ip'" v-model="form.device_ip" class="mono" placeholder="192.0.2.1"
              :disabled="disabled" autocomplete="off"><small class="sub">{{ t('flow.ipHint') }}</small></label>
          <div class="field"><span :id="id + '-mode'">{{ t('flow.sampleMode') }}</span>
            <XSeg v-model="form.sample_mode" :options="modes" :label="t('flow.sampleMode')"
              :aria-labelledby="id + '-mode'" /></div>
          <label v-if="form.sample_mode === 'force'" class="field" :for="id + '-rate'">
            <span>{{ t('flow.sampleRate') }}</span>
            <XNumber :id="id + '-rate'" v-model="form.sample_rate" :label="t('flow.sampleRate')"
              :min="1" :digits="0" :disabled="disabled" />
            <small class="sub">{{ t('flow.rateHint') }}</small></label>
          <label class="field" :for="id + '-description'"><span>{{ t('flow.description') }}</span>
            <input :id="id + '-description'" v-model="form.description" :disabled="disabled" autocomplete="off"></label>
        </div>
      </template>
    </div>
    <template v-if="view !== 'list'" #footer>
      <div class="fl-footer">
        <small class="sub">{{ editing ? t('flow.sourceEditNote', { address: listener.listen_address })
          : t('flow.sourceNewNote') }}</small>
        <p v-if="message" :class="tone" role="alert">{{ message }}</p>
        <div class="toolbar"><button class="btn" :disabled="busy" @click="back">{{ t('flow.cancel') }}</button>
          <button v-if="isAdmin()" class="btn primary" :disabled="busy" @click="save">
            {{ t(busy ? 'flow.saving' : 'flow.save') }}</button></div>
      </div>
    </template>
  </XDrawer>
</template>
