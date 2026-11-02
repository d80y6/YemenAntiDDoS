<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { PROJECT_URL } from '../project'
import XEmpty from '../components/XEmpty.vue'

const { t } = useI18n()
const version = __XS_VERSION__
const licenses = ref<{ name: string; version: string; license: string; licenseText: string }[]>([])
const error = ref('')
const loading = ref(true)

onMounted(async () => {
  try {
    const response = await fetch('/third-party.json')
    if (!response.ok) throw new Error(`HTTP ${response.status}`)
    licenses.value = await response.json()
  } catch (e) {
    error.value = e instanceof Error ? e.message : String(e)
  } finally {
    loading.value = false
  }
})
</script>

<template>
  <div class="page">
    <h1>{{ t('pages.about') }}</h1>
    <section class="panel">
      <h2>YEMENANTIDDOS</h2>
      <dl class="kv">
        <dt>{{ t('pages.version') }}</dt>
        <dd class="mono">{{ version }}</dd>
        <dt>{{ t('pages.project') }}</dt>
        <dd>
          <a :href="PROJECT_URL" target="_blank" rel="noopener noreferrer">{{ PROJECT_URL }}</a>
        </dd>
      </dl>
    </section>
    <section class="panel">
      <h2>{{ t('pages.licenses') }}</h2>
      <XEmpty v-if="loading || error" :loading="loading" :error="error" />
      <details v-for="entry in licenses" :key="entry.name" class="license">
        <summary>
          <strong>{{ entry.name }}</strong> <span class="mono">{{ entry.version }} · {{ entry.license }}</span>
        </summary>
        <pre class="raw">{{ entry.licenseText }}</pre>
      </details>
    </section>
  </div>
</template>
