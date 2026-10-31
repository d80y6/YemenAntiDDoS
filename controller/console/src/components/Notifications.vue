<script setup lang="ts">
import { notifications } from '../notifications'
</script>

<template>
  <div class="toasts">
    <div
      v-for="notice in notifications"
      :key="notice.id"
      role="status"
      class="toast"
      :class="[notice.tone, { mono: notice.raw }]"
    >
      {{ notice.message }}
    </div>
  </div>
</template>
