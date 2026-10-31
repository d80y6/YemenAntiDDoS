<script setup lang="ts">
import Shell from './components/Shell.vue'
import Notifications from './components/Notifications.vue'
</script>

<template>
  <RouterView v-if="$route.path === '/login'" />
  <Shell v-else>
    <RouterView />
  </Shell>
  <Notifications />
</template>
