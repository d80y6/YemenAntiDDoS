<script setup lang="ts">
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'

const props = withDefaults(defineProps<{
  modelValue: number
  pageSize?: number
  total?: number
  hasNext?: boolean
  busy?: boolean
}>(), { pageSize: 20 })
const emit = defineEmits<{ 'update:modelValue': [value: number] }>()
const { t } = useI18n()
const pages = computed(() => Math.max(1, Math.ceil((props.total || 0) / props.pageSize)))
const visible = computed(() => Array.from(
  { length: Math.min(7, pages.value) },
  (_, i) => Math.max(1, Math.min(props.modelValue - 3, pages.value - 6)) + i,
))
</script>

<template>
  <div class="pager">
    <button
      type="button"
      class="btn sm"
      :disabled="busy || modelValue <= 1"
      @click="emit('update:modelValue', modelValue - 1)"
    >
      {{ t('common.previous') }}
    </button>
    <template v-if="total !== undefined">
      <button
        v-for="page in visible"
        :key="page"
        type="button"
        class="btn sm"
        :aria-current="page === modelValue ? 'page' : undefined"
        :disabled="busy"
        @click="emit('update:modelValue', page)"
      >
        {{ page }}
      </button>
      <span class="muted">{{ t('common.total', { n: total }) }}</span>
    </template>
    <button
      type="button"
      class="btn sm"
      :disabled="busy || (total !== undefined ? modelValue >= pages : !hasNext)"
      @click="emit('update:modelValue', modelValue + 1)"
    >
      {{ t('common.next') }}
    </button>
  </div>
</template>
