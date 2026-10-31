<script setup lang="ts">
import { ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'

const props = withDefaults(defineProps<{
  modelValue: number
  label: string
  min?: number
  max?: number
  digits?: number
  validateOnly?: boolean
  disabled?: boolean
}>(), { min: -Infinity, max: Infinity })
const emit = defineEmits<{ 'update:modelValue': [value: number]; valid: [valid: boolean] }>()
const { t } = useI18n()
const draft = ref(String(props.modelValue))
const previous = ref(props.modelValue)
const invalid = ref(false)

watch(() => props.modelValue, value => {
  draft.value = String(value)
  if (Number.isFinite(value) && value >= props.min && value <= props.max) previous.value = value
})

function commit() {
  const raw = draft.value.trim()
  const number = Number(raw)
  const valid = !!raw && Number.isFinite(number)
  const inRange = valid && number >= props.min && number <= props.max
  if (props.validateOnly) {
    invalid.value = !inRange
    emit('valid', inRange)
    if (inRange) {
      previous.value = number
      emit('update:modelValue', number)
    }
    return
  }
  let value = valid ? Math.min(props.max, Math.max(props.min, number)) : previous.value
  if (props.digits !== undefined) value = Math.min(props.max, Math.max(props.min, Number(value.toFixed(props.digits))))
  previous.value = value
  draft.value = String(value)
  invalid.value = false
  emit('update:modelValue', value)
  emit('valid', true)
}
</script>

<template>
  <input
    v-model="draft"
    type="text"
    inputmode="decimal"
    :aria-label="label"
    :aria-invalid="invalid"
    :title="invalid ? t('common.invalidNumber') : undefined"
    :disabled="disabled"
    @blur="commit"
    @keydown.enter="commit"
  >
</template>
