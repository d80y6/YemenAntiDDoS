import { onUnmounted, ref, shallowRef, watch } from 'vue'
// A key includes identity and visibility. Each invocation also owns a sequence number.
export function lookup<T>(key: () => string, fetcher: (signal: AbortSignal) => Promise<T>) {
  const data = shallowRef<T>(), error = shallowRef<unknown>(), loading = ref(false)
  let sequence = 0, controller: AbortController | undefined, alive = true
  function invalidate() { sequence++; controller?.abort(); loading.value = false }
  async function refresh() {
    invalidate()
    const identity = key(), seq = sequence
    if (!identity || !alive) return
    controller = new AbortController()
    loading.value = true
    error.value = undefined
    data.value = undefined
    const current = () => alive && seq === sequence && !!key() && key() === identity
    try {
      const value = await fetcher(controller.signal)
      if (current()) data.value = value
    } catch (e) { if (current()) error.value = e }
    finally { if (current()) loading.value = false }
  }
  watch(key, () => { void refresh() }, { immediate: true, flush: 'sync' })
  onUnmounted(() => { alive = false; invalidate() })
  return { data, error, loading, refresh }
}
