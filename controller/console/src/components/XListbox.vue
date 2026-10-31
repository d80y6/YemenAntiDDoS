<script setup lang="ts">
import { computed, nextTick, onMounted, onUnmounted, ref, useId } from 'vue'
import { useI18n } from 'vue-i18n'
import { placePopup } from './popup'

export interface Option {
  value: string
  label: string
  disabled?: boolean
}

const props = withDefaults(defineProps<{
  modelValue: string
  options: Option[]
  label: string
  mode?: 'select' | 'search' | 'free'
  disabled?: boolean
}>(), { mode: 'select' })
const emit = defineEmits<{ 'update:modelValue': [value: string] }>()
const { t } = useI18n()
const id = useId()
const open = ref(false)
const query = ref('')
const active = ref(-1)
const anchor = ref<HTMLElement>()
const popup = ref<HTMLElement>()
const input = ref<HTMLInputElement>()
const position = ref<ReturnType<typeof placePopup>>()
const shown = computed(() => props.options.filter(
  o => props.mode === 'select' || o.label.toLowerCase().includes(query.value.toLowerCase()),
))
const label = computed(() => props.options.find(o => o.value === props.modelValue)?.label || props.modelValue)

function move(direction: number, edge = false) {
  const enabled = shown.value
    .map((o, i) => ({ o, i }))
    .filter(({ o }) => !o.disabled)
    .map(({ i }) => i)
  if (!enabled.length) {
    active.value = -1
    return
  }
  if (edge) active.value = direction > 0 ? enabled[0]! : enabled[enabled.length - 1]!
  else {
    const index = enabled.indexOf(active.value)
    active.value = enabled[(index + direction + enabled.length) % enabled.length]!
  }
}

function relocate() {
  if (anchor.value) position.value = placePopup(
    anchor.value.getBoundingClientRect(),
    { width: innerWidth, height: innerHeight },
    popup.value ? Math.min(240, popup.value.scrollHeight + 2) : 240,
  )
}

async function show() {
  if (props.disabled) return
  query.value = ''
  open.value = true
  relocate()
  active.value = shown.value.findIndex(o => o.value === props.modelValue && !o.disabled)
  if (active.value < 0) move(1, true)
  await nextTick()
  relocate()
  input.value?.focus()
}

function close(focus = false) {
  open.value = false
  if (focus) anchor.value?.focus()
}

function select(index: number) {
  const option = shown.value[index]
  if (!option || option.disabled) return
  emit('update:modelValue', option.value)
  close(true)
}

function key(event: KeyboardEvent) {
  if (!['ArrowDown', 'ArrowUp', 'Home', 'End', 'Enter', 'Escape'].includes(event.key)) return
  event.preventDefault()
  if (open.value || event.key !== 'Escape') event.stopPropagation()
  if (event.key === 'Escape') {
    close(true)
    return
  }
  if (!open.value) {
    void show()
    return
  }
  if (event.key === 'Enter') {
    if (props.mode === 'free' && query.value && !shown.value.some(o => o.label === query.value)) {
      emit('update:modelValue', query.value)
      close(true)
    } else select(active.value)
  } else move(
    event.key === 'ArrowUp' || event.key === 'End' ? -1 : 1,
    event.key === 'Home' || event.key === 'End',
  )
}

function outside(event: Event) {
  if (!anchor.value?.contains(event.target as Node) && !popup.value?.contains(event.target as Node)) blur()
}

function blur() {
  if (!open.value) return
  if (props.mode === 'free' && query.value) emit('update:modelValue', query.value)
  close()
}

onMounted(() => {
  document.addEventListener('pointerdown', outside)
  window.addEventListener('resize', relocate)
  window.addEventListener('scroll', relocate, true)
})
onUnmounted(() => {
  document.removeEventListener('pointerdown', outside)
  window.removeEventListener('resize', relocate)
  window.removeEventListener('scroll', relocate, true)
})
</script>

<template>
  <button
    ref="anchor"
    type="button"
    class="btn listbox-button"
    :role="mode === 'select' ? 'combobox' : undefined"
    :disabled="disabled"
    :aria-label="label ? `${props.label}: ${label}` : props.label"
    aria-haspopup="listbox"
    :aria-expanded="open"
    :aria-controls="id"
    :aria-activedescendant="open && active >= 0 ? `${id}-${active}` : undefined"
    @click="open ? close() : show()"
    @keydown="key"
  >
    {{ label || props.label }} <span aria-hidden="true">⌄</span>
  </button>
  <Teleport :to="anchor?.closest('[role=dialog]') || 'body'">
    <div v-if="open" ref="popup" class="mpop" :style="position" @keydown="key">
      <input
        v-if="mode !== 'select'"
        ref="input"
        v-model="query"
        role="combobox"
        :aria-label="t('common.search')"
        :aria-expanded="open"
        :aria-controls="id"
        aria-autocomplete="list"
        :aria-activedescendant="active >= 0 ? `${id}-${active}` : undefined"
        @input="move(1, true)"
        @keydown.tab="blur"
        @blur="blur"
      >
      <div :id="id" role="listbox" :aria-label="props.label">
        <button
          v-for="(option, index) in shown"
          :id="`${id}-${index}`"
          :key="option.value"
          type="button"
          role="option"
          tabindex="-1"
          :aria-selected="option.value === modelValue"
          :aria-disabled="!!option.disabled"
          :disabled="option.disabled"
          :class="{ active: active === index }"
          @pointerdown.prevent
          @click="select(index)"
        >
          {{ option.label }}
        </button>
        <p v-if="!shown.length" class="muted">{{ t('common.noMatch') }}</p>
      </div>
    </div>
  </Teleport>
</template>
