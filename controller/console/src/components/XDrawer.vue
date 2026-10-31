<script setup lang="ts">
import { nextTick, onUnmounted, ref, useId, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { drawerCount } from './overlay'

const props = withDefaults(defineProps<{
  modelValue: boolean
  title: string
  width?: 'default' | 460 | 600 | 680 | 780
  busy?: boolean
}>(), { width: 'default' })
const emit = defineEmits<{ 'update:modelValue': [value: boolean] }>()
const { t } = useI18n()
const id = useId()
const dialog = ref<HTMLElement>()
const closeButton = ref<HTMLButtonElement>()
let opener: HTMLElement | null = null
let counted = false

function close() {
  if (!props.busy) emit('update:modelValue', false)
}

function restoreFocus() {
  opener?.focus()
}

function isWithinHiddenTree(el: HTMLElement) {
  if (el.closest('[hidden],[inert]')) return true
  for (let current: HTMLElement | null = el; current; current = current.parentElement) {
    if (getComputedStyle(current).display === 'none') return true
  }
  return false
}

function canFocus(el: HTMLElement) {
  return !el.hidden && !el.matches(':disabled') && el.tabIndex >= 0 && !isWithinHiddenTree(el)
}

function key(event: KeyboardEvent) {
  if (event.key === 'Escape') {
    event.stopPropagation()
    close()
  }
  if (event.key !== 'Tab') return
  const items = [...(dialog.value?.querySelectorAll<HTMLElement>(
    'button:not(:disabled),a[href],input:not(:disabled),textarea:not(:disabled),[tabindex="0"]',
  ) || [])].filter(canFocus)
  if (!items.length) {
    event.preventDefault()
    dialog.value?.focus()
    return
  }
  const first = items[0]
  const last = items[items.length - 1]
  if (document.activeElement === dialog.value) {
    event.preventDefault()
    const target = event.shiftKey ? last : first
    target?.focus()
    return
  }
  if (event.shiftKey && (document.activeElement === first || !dialog.value?.contains(document.activeElement))) {
    event.preventDefault()
    last?.focus()
  } else if (!event.shiftKey && (document.activeElement === last || !dialog.value?.contains(document.activeElement))) {
    event.preventDefault()
    first?.focus()
  }
}

watch(() => props.modelValue, async open => {
  if (open) {
    opener = document.activeElement as HTMLElement
    drawerCount.value++
    counted = true
    await nextTick()
    if (closeButton.value && canFocus(closeButton.value)) closeButton.value.focus()
    else dialog.value?.focus()
  } else {
    if (counted) drawerCount.value--
    counted = false
    await nextTick()
    restoreFocus()
  }
}, { immediate: true })
onUnmounted(() => {
  if (counted) {
    drawerCount.value--
    restoreFocus()
  }
})
</script>

<template>
  <Teleport to="body">
    <div v-if="modelValue" class="scrim" @click.self="close">
      <aside
        ref="dialog"
        class="drawer"
        :style="{ width: width === 'default' ? undefined : `${width}px` }"
        role="dialog"
        aria-modal="true"
        tabindex="-1"
        :aria-labelledby="id"
        :aria-busy="!!busy"
        @keydown="key"
      >
        <header class="drawer-head">
          <h2 :id="id">{{ title }}</h2>
          <button
            ref="closeButton"
            type="button"
            class="btn ghost"
            :aria-label="t('common.close')"
            :disabled="busy"
            @click="close"
          >✕</button>
        </header>
        <div class="drawer-body">
          <slot />
        </div>
        <footer v-if="$slots.footer" class="drawer-foot">
          <slot name="footer" />
        </footer>
      </aside>
    </div>
  </Teleport>
</template>
