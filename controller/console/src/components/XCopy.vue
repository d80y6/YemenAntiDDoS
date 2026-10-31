<script setup lang="ts">
import { onUnmounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'

const props = defineProps<{ text: string }>()
const { t } = useI18n()
const result = ref('')
let timer: ReturnType<typeof setTimeout> | undefined

async function copy() {
  try {
    await navigator.clipboard.writeText(props.text)
    result.value = 'common.copied'
  } catch {
    result.value = 'common.copyFailed'
  }
  clearTimeout(timer)
  timer = setTimeout(() => result.value = '', 1500)
}

onUnmounted(() => clearTimeout(timer))
</script>

<template>
  <button type="button" class="btn sm" @click="copy">{{ t(result || 'common.copy') }}</button>
  <span v-if="result" role="status" class="sr-only">{{ t(result) }}</span>
</template>
