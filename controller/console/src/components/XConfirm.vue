<script setup lang="ts">
import { nextTick, onMounted, onUnmounted, ref, useId, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { activeConfirm, drawerCount } from './overlay'

const props = defineProps<{
  modelValue: boolean
  title: string
  description: string
  action: () => Promise<unknown>
  confirmLabel?: string
  tone?: 'danger'
}>()
const emit = defineEmits<{ 'update:modelValue': [value: boolean] }>()
const { t } = useI18n()
const id = useId()
const root = ref<HTMLElement>()
const first = ref<HTMLElement>()
const error = ref('')
const busy = ref(false)

function close() {
  if (!busy.value) emit('update:modelValue', false)
}

watch(() => props.modelValue, async open => {
  if (open) {
    activeConfirm.value = id
    error.value = ''
    await nextTick()
    first.value?.focus()
  } else if (activeConfirm.value === id) activeConfirm.value = null
}, { immediate: true })
watch(activeConfirm, value => {
  if (props.modelValue && value !== id) close()
})

async function execute() {
  if (busy.value) return
  busy.value = true
  error.value = ''
  try {
    await props.action()
    busy.value = false
    close()
  } catch (e) {
    error.value = e instanceof Error ? e.message : String(e)
  } finally {
    busy.value = false
  }
}

function outside(event: Event) {
  if (props.modelValue && !drawerCount.value && !root.value?.contains(event.target as Node)) close()
}

function key(event: KeyboardEvent) {
  if (event.key === 'Escape' && !drawerCount.value) close()
}

onMounted(() => {
  document.addEventListener('pointerdown', outside)
  document.addEventListener('keydown', key)
})
onUnmounted(() => {
  document.removeEventListener('pointerdown', outside)
  document.removeEventListener('keydown', key)
  if (activeConfirm.value === id) activeConfirm.value = null
})
</script>

<template>
  <div
    v-if="modelValue && activeConfirm === id"
    ref="root"
    class="confirm"
    role="alertdialog"
    :aria-labelledby="`${id}-title`"
    :aria-describedby="`${id}-description`"
    :aria-busy="busy"
  >
    <strong :id="`${id}-title`">{{ title }}</strong>
    <p :id="`${id}-description`">{{ description }}</p>
    <slot />
    <p v-if="error" class="crit mono" role="alert">{{ error }}</p>
    <div class="toolbar">
      <button ref="first" type="button" class="btn" :class="tone === 'danger' ? 'danger' : 'primary'"
        :disabled="busy" @click="execute">
        {{ confirmLabel ?? t('common.confirm') }}
      </button>
      <button type="button" class="btn" :disabled="busy" @click="close">{{ t('common.cancel') }}</button>
    </div>
  </div>
</template>
