<script setup lang="ts">
// /__dev/components -- development-only route sentinel.
import { computed, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import XListbox from '../components/XListbox.vue'
import XDrawer from '../components/XDrawer.vue'
import XConfirm from '../components/XConfirm.vue'
import XTip from '../components/XTip.vue'
import XSwitch from '../components/XSwitch.vue'
import XCheck from '../components/XCheck.vue'
import XSeg from '../components/XSeg.vue'
import XTabs from '../components/XTabs.vue'
import XNumber from '../components/XNumber.vue'
import XPassword from '../components/XPassword.vue'
import XCopy from '../components/XCopy.vue'
import XBadge from '../components/XBadge.vue'
import XPill from '../components/XPill.vue'
import XDot from '../components/XDot.vue'
import XKpi from '../components/XKpi.vue'
import XEmpty from '../components/XEmpty.vue'
import XTable from '../components/XTable.vue'
import XPager from '../components/XPager.vue'
import { notify } from '../notifications'

const { t } = useI18n()
const choice = ref('a')
const enabled = ref(true)
const checked = ref(false)
const number = ref(5)
const password = ref('')
const drawer = ref(false)
const confirm = ref(false)
const tab = ref('a')
const page = ref(1)
const sortKey = ref('name')
const direction = ref<'ascending' | 'descending'>('ascending')
const options = computed(() => [
  { value: 'a', label: t('dev.first') },
  { value: 'b', label: t('dev.disabled'), disabled: true },
  { value: 'c', label: t('dev.last') },
])
const tabs = computed(() => options.value.filter(o => !o.disabled))
const columns = computed(() => [
  { key: 'name', label: t('dev.name'), sortable: true },
  { key: 'value', label: t('dev.value'), sortable: true, heat: true },
])
const rows = computed(() => [
  { name: t('dev.first'), value: 65 },
  { name: t('dev.last'), value: 35 },
].sort((a, b) => (sortKey.value === 'name'
  ? a.name.localeCompare(b.name)
  : a.value - b.value) * (direction.value === 'ascending' ? 1 : -1)))

async function action() {
  notify(t('common.success'))
}
</script>

<template>
  <div class="page">
    <h1>{{ t('dev.title') }}</h1>
    <section class="panel">
      <h2>{{ t('dev.controls') }}</h2>
      <div class="demo-grid">
        <XListbox
          v-for="mode in (['select', 'search', 'free'] as const)"
          :key="mode"
          v-model="choice"
          :options="options"
          :label="t('dev.choice')"
          :mode="mode"
        />
        <XSwitch v-model="enabled" :label="t('dev.switch')" />
        <XCheck v-model="checked" :label="t('dev.check')" />
        <XSeg v-model="choice" :options="tabs" :label="t('dev.choice')" />
        <label>
          {{ t('dev.number') }}<XNumber v-model="number" :label="t('dev.number')" :min="0" :max="10" :digits="0" />
        </label>
        <label>
          {{ t('dev.validate') }}<XNumber
            v-model="number"
            :label="t('dev.validate')"
            :min="0"
            :max="10"
            validate-only
          />
        </label>
        <XPassword v-model="password" :label="t('login.password')" />
        <XCopy text="YEMENANTIDDOS" />
      </div>
    </section>
    <section class="panel">
      <h2>{{ t('dev.overlays') }}</h2>
      <div class="toolbar">
        <button type="button" class="btn" @click="drawer = true">{{ t('dev.openDrawer') }}</button>
        <button type="button" class="btn" @click="confirm = true">{{ t('dev.delete') }}</button>
        <XTip :text="t('dev.tip')" />
        <XTip :text="t('dev.tip')" direction="up-right" wide />
        <button type="button" class="btn" @click="notify(t('common.success'))">{{ t('dev.write') }}</button>
      </div>
      <XConfirm
        v-model="confirm"
        :title="t('dev.delete')"
        :description="t('dev.description')"
        :action="action"
      />
    </section>
    <section class="panel">
      <XTabs v-model="tab" :tabs="tabs" :label="t('dev.tabs')" query>
        <template #a>{{ t('dev.panel') }} A</template>
        <template #c>{{ t('dev.panel') }} C</template>
      </XTabs>
    </section>
    <section class="panel">
      <h2>{{ t('dev.table') }}</h2>
      <XTable
        :rows="rows"
        :columns="columns"
        :sort-key="sortKey"
        :sort-direction="direction"
        clickable
        @sort="(key, dir) => {
          sortKey = key;
          direction = dir
        }"
      />
      <XPager v-model="page" :total="48" />
    </section>
    <section class="panel">
      <h2>{{ t('dev.indicators') }}</h2>
      <div class="toolbar">
        <XBadge tone="crit">3</XBadge>
        <XPill tone="ok">{{ t('common.success') }}</XPill>
        <XDot tone="warn" :label="t('common.failed')" />
      </div>
      <div class="kpis">
        <XKpi :label="t('dev.metric')" value="1.42M" secondary="9.62 Gbps" />
      </div>
      <XEmpty />
      <XEmpty error="HTTP 503" />
    </section>
    <XDrawer v-model="drawer" :title="t('dev.drawer')" :width="600">
      <XNumber v-model="number" :label="t('dev.number')" :min="0" :max="10" />
      <div style="height: 75vh" />
      <XListbox v-model="choice" :options="options" :label="t('dev.choice')" mode="search" />
      <button type="button" class="btn" @click="drawer = false">{{ t('common.close') }}</button>
    </XDrawer>
  </div>
</template>
