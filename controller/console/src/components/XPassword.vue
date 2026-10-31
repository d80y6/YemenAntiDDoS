<script setup lang="ts">
import { nextTick, ref } from 'vue'
import { useI18n } from 'vue-i18n'

defineProps<{
  modelValue: string
  label: string
  id?: string
  disabled?: boolean
  autocomplete?: string
}>()
const emit = defineEmits<{ 'update:modelValue': [value: string] }>()
const { t } = useI18n()
const visible = ref(false)
const input = ref<HTMLInputElement>()

async function toggle() {
  const start = input.value?.selectionStart
  visible.value = !visible.value
  await nextTick()
  input.value?.focus()
  if (start !== undefined && start !== null) input.value?.setSelectionRange(start, start)
}
</script>

<template>
  <span class="keyrow">
    <input
      v-if="visible"
      :id="id"
      ref="input"
      type="text"
      :value="modelValue"
      :aria-label="label"
      :autocomplete="autocomplete"
      :disabled="disabled"
      @input="emit('update:modelValue', ($event.target as HTMLInputElement).value)"
    >
    <input
      v-else
      :id="id"
      ref="input"
      type="password"
      :value="modelValue"
      :aria-label="label"
      :autocomplete="autocomplete"
      :disabled="disabled"
      @input="emit('update:modelValue', ($event.target as HTMLInputElement).value)"
    >
    <button
      type="button"
      class="btn ghost"
      :aria-label="t(visible ? 'common.hidePassword' : 'common.showPassword')"
      :aria-pressed="visible"
      :disabled="disabled"
      @click="toggle"
    >
      <svg viewBox="0 0 24 24" aria-hidden="true">
        <path d="M2 12s4-7 10-7 10 7 10 7-4 7-10 7S2 12 2 12z"/>
        <circle cx="12" cy="12" r="3"/>
      </svg>
    </button>
  </span>
</template>
