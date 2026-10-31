<script setup lang="ts">
import { ref, useId, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import XConfirm from '../../components/XConfirm.vue'
import { request } from '../../api/client'
import type { Attack } from '../../api/data'
import { notify } from '../../notifications'
import { target, holdInputValid, expireURL, expireResult } from './data'
const props = defineProps<{ modelValue: boolean; attack: Attack }>()
const emit = defineEmits<{ 'update:modelValue': [value: boolean]; done: [] }>()
const { t } = useI18n(), raw = ref(''), id = useId()
watch(() => props.modelValue, open => { if (open) raw.value = '' })
async function expire() {
  if (!holdInputValid(raw.value)) throw new Error(t('attacks.expireHoldInvalid'))
  const hold = raw.value, attackId = props.attack.id
  try {
    const result = await request<{ method: string }>(expireURL(attackId, hold), { method: 'POST' })
    const message = expireResult(attackId, hold, result.method)
    notify(t('attacks.' + message.key, message.values), message.tone, false)
    emit('done')
  } catch (error) {
    notify(error instanceof Error ? error.message : String(error), 'crit', true)
    throw error
  }
}
</script>
<template>
  <XConfirm :model-value="modelValue" tone="danger" :confirm-label="t('attacks.endAction')"
    :title="t('attacks.expireConfirm', { id: attack.id,
      target: target(attack.dst_ip).kind === 'global' ? t('attacks.global') : target(attack.dst_ip).text })"
    :description="t('attacks.expireDescription')" :action="expire"
    @update:model-value="emit('update:modelValue', $event)">
    <label :for="id">{{ t('attacks.holdSeconds') }}</label>
    <input :id="id" v-model="raw" type="text" inputmode="numeric" :placeholder="t('attacks.holdPlaceholder')"
      :aria-describedby="id + '-hint'" />
    <p :id="id + '-hint'" class="sub">{{ t('attacks.holdHint') }}</p>
  </XConfirm>
</template>
