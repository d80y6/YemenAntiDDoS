<script setup lang="ts">
import XEmpty from './XEmpty.vue'

export interface Column {
  key: string
  label: string
  sortable?: boolean
  heat?: boolean
}

const props = defineProps<{
  rows: Record<string, unknown>[]
  columns: Column[]
  rowKey?: string
  sortKey?: string
  sortDirection?: 'ascending' | 'descending'
  loading?: boolean
  error?: string
  clickable?: boolean
}>()
const emit = defineEmits<{
  sort: [key: string, direction: 'ascending' | 'descending']
  row: [row: Record<string, unknown>]
}>()

function sort(column: Column) {
  if (column.sortable) emit(
    'sort',
    column.key,
    props.sortKey === column.key && props.sortDirection === 'ascending' ? 'descending' : 'ascending',
  )
}

function row(event: Event, value: Record<string, unknown>) {
  if (
    props.clickable
    && !(event.target as Element).closest('button,a,input,[role=alertdialog],[role=checkbox],[role=switch]')
  ) emit('row', value)
}

function heat(value: unknown) {
  return `${Math.max(0, Math.min(100, Number(value) || 0))}%`
}
</script>

<template>
  <div class="tbl-wrap">
    <table>
      <thead>
        <tr>
          <th
            v-for="column in columns"
            :key="column.key"
            :aria-sort="column.sortable ? (sortKey === column.key ? sortDirection : 'none') : undefined"
            :tabindex="column.sortable ? 0 : undefined"
            :class="{ sortable: column.sortable }"
            @click="sort(column)"
            @keydown.enter.prevent="sort(column)"
            @keydown.space.prevent="sort(column)"
          >
            {{ column.label }}
          </th>
        </tr>
      </thead>
      <tbody v-if="!loading && !error && rows.length">
        <tr
          v-for="(value, index) in rows"
          :key="String(rowKey ? value[rowKey] : index)"
          :class="{ link: clickable }"
          :tabindex="clickable ? 0 : undefined"
          @click="row($event, value)"
          @keydown.enter.self="row($event, value)"
        >
          <td
            v-for="column in columns"
            :key="column.key"
            :class="{ heat: column.heat }"
            :style="column.heat ? { '--w': heat(value[column.key]) } : undefined"
          >
            <slot :name="column.key" :row="value" :value="value[column.key]">{{ value[column.key] }}</slot>
          </td>
        </tr>
      </tbody>
    </table>
    <slot v-if="loading" name="loading">
      <XEmpty loading />
    </slot>
    <slot v-else-if="error" name="error" :error="error">
      <XEmpty :error="error" />
    </slot>
    <slot v-else-if="!rows.length" name="empty">
      <XEmpty />
    </slot>
  </div>
</template>
