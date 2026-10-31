import { onMounted, onUnmounted } from 'vue'
// Normal rounds run after completion; a successful write starts a fresh generation immediately.
export function rounds<T>(fetcher: () => Promise<T>, ms: number, accept: (value: T) => void) {
  let alive = false, generation = 0, timer: ReturnType<typeof setTimeout> | undefined
  function clear() { clearTimeout(timer); timer = undefined }
  async function refresh() {
    clear()
    if (!alive || document.hidden) return
    const sequence = ++generation
    try {
      const result = await fetcher()
      if (alive && !document.hidden && sequence === generation) accept(result)
    } finally {
      if (alive && !document.hidden && sequence === generation) timer = setTimeout(refresh, ms)
    }
  }
  function visibility() {
    generation++
    clear()
    if (!document.hidden) void refresh()
  }
  onMounted(() => {
    alive = true
    document.addEventListener('visibilitychange', visibility)
    void refresh()
  })
  onUnmounted(() => {
    alive = false
    generation++
    clear()
    document.removeEventListener('visibilitychange', visibility)
  })
  return { refresh }
}
