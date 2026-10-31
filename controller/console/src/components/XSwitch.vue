<script setup lang="ts">
defineProps<{ modelValue: boolean; label: string; disabled?: boolean }>()
const emit = defineEmits<{ 'update:modelValue': [value: boolean] }>()
</script>

<template>
  <button
    type="button"
    class="switch"
    role="switch"
    :aria-checked="modelValue"
    :aria-label="label"
    :disabled="disabled"
    @click="emit('update:modelValue', !modelValue)"
    @keydown.space.prevent="emit('update:modelValue', !modelValue)"
  >
    <span aria-hidden="true">{{ modelValue ? '✓' : '' }}</span>
  </button>
</template>
