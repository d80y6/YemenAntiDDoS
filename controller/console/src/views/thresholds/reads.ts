import { onMounted, onUnmounted, ref, shallowRef, watch } from 'vue'
import { api } from '../../api/data'
import { request } from '../../api/client'
import { notifyWrite } from '../../notifications'
import type { Row } from './data'
export function reads(paths: () => Record<string, string>, primary: string) {
  const data = shallowRef<Row>({}), error = ref(''), failure = shallowRef<any>(), loaded = ref(false)
  const errors = ref<Row>({})
  let generation = 0, alive = true, controller: AbortController | undefined
  async function refresh(keys?: unknown) {
    if (!alive) return
    const seq = ++generation
    controller?.abort()
    controller = new AbortController()
    const entries = Object.entries(paths()).filter(([key]) => !Array.isArray(keys) || keys.includes(key))
    const results = await Promise.allSettled(entries.map(([, path]) => api<any>(path, {}, controller!.signal)))
    if (!alive || seq !== generation) return
    const next = { ...data.value }
    results.forEach((result, index) => {
      const key = entries[index]![0]
      if (result.status === 'fulfilled') {
        errors.value[key] = ''
        next[key] = result.value ?? []
        if (key === primary) { error.value = ''; failure.value = undefined }
      } else {
        errors.value[key] = result.reason.message
        if (key === primary) { failure.value = result.reason; error.value = result.reason.message }
        else next[key] = []
      }
    })
    data.value = next
    loaded.value = true
  }
  watch(() => JSON.stringify(paths()), () => {
    data.value = {}
    loaded.value = false
    void refresh()
  })
  onMounted(refresh)
  onUnmounted(() => { alive = false; generation++; controller?.abort() })
  return { data, error, errors, failure, loaded, refresh }
}
export const write = (path: string, method: string, body: unknown, success: string) => notifyWrite(
  request('/api/' + path, { method, ...(body === undefined ? {} : { body: JSON.stringify(body) }) }), success,
)
