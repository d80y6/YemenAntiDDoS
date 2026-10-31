<script setup lang="ts">
import { nextTick, ref } from 'vue'

const props = defineProps<{
  modelValue: string
  options: { value: string; label: string; disabled?: boolean }[]
  label: string
}>()
const emit = defineEmits<{ 'update:modelValue': [value: string] }>()
const root = ref<HTMLElement>()

async function key(event: KeyboardEvent, value: string) {
  if (!['ArrowLeft', 'ArrowRight'].includes(event.key)) return
  event.preventDefault()
  const enabled = props.options.filter(o => !o.disabled)
  const index = enabled.findIndex(o => o.value === value)
  const option = enabled[(index + (event.key === 'ArrowRight' ? 1 : -1) + enabled.length) % enabled.length]
  if (!option) return
  emit('update:modelValue', option.value)
  await nextTick()
  const indexAll = props.options.indexOf(option)
  root.value?.querySelectorAll('button')[indexAll]?.focus()
}
</script>

<template>
  <div ref="root" class="seg" role="group" :aria-label="label">
    <button
      v-for="option in options"
      :key="option.value"
      type="button"
      :aria-pressed="option.value === modelValue"
      :disabled="option.disabled"
      @click="emit('update:modelValue', option.value)"
      @keydown="key($event, option.value)"
    >
      {{ option.label }}
    </button>
  </div>
</template>
