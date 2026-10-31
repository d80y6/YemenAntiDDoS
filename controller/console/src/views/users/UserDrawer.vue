<script setup lang="ts">
import { computed, reactive, ref, useId, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import XDrawer from '../../components/XDrawer.vue'
import XPassword from '../../components/XPassword.vue'
import XListbox from '../../components/XListbox.vue'
import XSwitch from '../../components/XSwitch.vue'
import { adminGuard, isSelf, rawError, userForm, userValidation } from './data'
import type { UserForm, UserRow } from './data'
const props = defineProps<{ modelValue: boolean; row?: UserRow; users: UserRow[]; writable: boolean;
  busy: boolean; save: (form: UserForm, row?: UserRow) => Promise<boolean> }>()
const emit = defineEmits<{ 'update:modelValue': [value: boolean] }>()
const { t } = useI18n()
const id = useId(), form = reactive(userForm())
const message = ref(''), tone = ref('crit')
const last = computed(() => props.row && !!adminGuard(props.users, props.row, 'delete'))
const options = computed(() => {
  const roles = ['admin', 'operator', 'viewer'].map(value => ({ value, label: t('users.option_' + value),
    disabled: !!last.value && value !== 'admin' }))
  if (props.row && !roles.some(r => r.value === props.row!.role)) roles.push({ value: props.row.role,
    label: `${props.row.role} · ${t('users.readonly')}`, disabled: false })
  return roles
})
watch(() => props.modelValue, value => {
  if (value) { Object.assign(form, userForm(props.row)); message.value = '' }
})
async function submit() {
  if (!props.writable || props.busy) return
  const invalid = userValidation(form, props.row) || (props.row ? adminGuard(props.users, props.row, form) : '')
  if (invalid) { message.value = t(invalid); tone.value = 'warn'; return }
  message.value = ''
  try {
    if (await props.save({ ...form }, props.row)) emit('update:modelValue', false)
  } catch (error) { message.value = rawError(error); tone.value = 'crit' }
}
defineExpose({ form, submit })
</script>
<template>
  <XDrawer :model-value="modelValue" :width="460" :busy="busy"
    :title="row ? t('users.edit', { name: row.username }) : t('users.add')"
    @update:model-value="emit('update:modelValue', $event)">
    <div class="form us-form">
      <label class="field" :for="id + '-username'"><span>{{ t('users.username') }}</span>
        <input :id="id + '-username'" v-model="form.username" class="mono" :readonly="!!row" :disabled="busy"
          autocomplete="off"></label>
      <label v-if="!row" class="field" :for="id + '-password'"><span>{{ t('users.password') }}</span>
        <XPassword :id="id + '-password'" v-model="form.password" :label="t('users.password')"
          :disabled="busy" autocomplete="new-password" /></label>
      <div class="field"><span>{{ t('users.role') }}</span>
        <XListbox v-model="form.role" :options="options" :label="t('users.role')" :disabled="busy" /></div>
      <template v-if="row">
        <div class="field"><label :for="id + '-enabled'">{{ t('users.status') }}</label>
          <div class="us-switch"><XSwitch :id="id + '-enabled'" v-model="form.enabled" :label="t('users.status')"
            :disabled="busy || !!last" /><span class="sub">
              {{ t(form.enabled ? 'users.enabled' : 'users.disabled') }}</span></div></div>
        <label class="field" :for="id + '-password'"><span>{{ t('users.newPassword') }}</span>
          <XPassword :id="id + '-password'" v-model="form.password" :label="t('users.newPassword')"
            :disabled="busy" autocomplete="new-password" />
          <small class="sub">{{ t('users.passwordHint') }}</small></label>
        <p v-if="last" class="sub">{{ t('users.lastEdit') }}</p>
        <p class="us-note"><template v-if="isSelf(row)"><strong>{{ t('users.selfHeading') }}</strong>
          {{ t('users.selfNote') }}</template>
          <i18n-t v-else keypath="users.otherNote" tag="span"><template #name>
            <strong>{{ row.username }}</strong></template></i18n-t></p>
      </template>
      <p v-else class="sub">{{ t('users.newNote') }}</p>
    </div>
    <template #footer><div class="us-footer">
      <p v-if="message" :class="tone" role="alert">{{ message }}</p>
      <div class="toolbar"><button class="btn" :disabled="busy" @click="emit('update:modelValue', false)">
        {{ t('common.cancel') }}</button>
        <button class="btn primary" :disabled="!writable || busy" @click="submit">
          {{ t(row ? 'users.save' : 'users.create') }}</button></div>
    </div></template>
  </XDrawer>
</template>
