<script setup lang="ts">
import { nextTick, ref, useId } from 'vue'
import { useRoute, useRouter } from 'vue-router'

const props = defineProps<{
  modelValue: string
  tabs: { value: string; label: string }[]
  label: string
  query?: boolean
}>()
const emit = defineEmits<{ 'update:modelValue': [value: string] }>()
const id = useId()
const root = ref<HTMLElement>()
const route = useRoute()
const router = useRouter()
const current = () => props.query
  && typeof route?.query.tab === 'string'
  && props.tabs.some(t => t.value === route.query.tab)
  ? route.query.tab
  : props.modelValue

function select(value: string) {
  emit('update:modelValue', value)
  if (props.query) void router.replace({ query: { ...route.query, tab: value } })
}

async function key(event: KeyboardEvent, index: number) {
  if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return
  event.preventDefault()
  const next = event.key === 'Home'
    ? 0
    : event.key === 'End'
      ? props.tabs.length - 1
      : (index + (event.key === 'ArrowRight' ? 1 : -1) + props.tabs.length) % props.tabs.length
  const tab = props.tabs[next]
  if (tab) select(tab.value)
  await nextTick()
  root.value?.querySelectorAll<HTMLElement>('[role=tab]')[next]?.focus()
}
</script>

<template>
  <div>
    <div ref="root" class="tabs" role="tablist" :aria-label="label">
      <button
        v-for="(tab, index) in tabs"
        :id="`${id}-tab-${index}`"
        :key="tab.value"
        type="button"
        role="tab"
        :aria-selected="current() === tab.value"
        :aria-controls="`${id}-panel-${index}`"
        :tabindex="current() === tab.value ? 0 : -1"
        @click="select(tab.value)"
        @keydown="key($event, index)"
      >
        {{ tab.label }}
      </button>
    </div>
    <section
      v-for="(tab, index) in tabs"
      :id="`${id}-panel-${index}`"
      :key="tab.value"
      role="tabpanel"
      :aria-labelledby="`${id}-tab-${index}`"
      :hidden="current() !== tab.value"
      tabindex="0"
    >
      <slot :name="tab.value" :tab="tab.value" />
    </section>
  </div>
</template>
