import { onMounted, onUnmounted } from 'vue'

// Results are applied here, after lifecycle/visibility generation checks.
export function usePoll<T>(
  fn: () => Promise<T>,
  ms: number,
  accept: (value: T) => void = () => {},
  reject: (error: unknown) => void = () => {},
) {
  let alive = false
  let inFlight = false
  let generation = 0
  let timer: ReturnType<typeof setTimeout> | undefined
  const clear = () => {
    if (timer !== undefined) clearTimeout(timer)
    timer = undefined
  }
  async function run() {
    clear()
    if (!alive || document.hidden || inFlight) return
    inFlight = true
    const seq = generation
    try {
      const value = await fn()
      if (alive && !document.hidden && seq === generation) accept(value)
    } catch (error) {
      if (alive && !document.hidden && seq === generation) reject(error)
    } finally {
      inFlight = false
      if (alive && !document.hidden) {
        if (seq !== generation) void run()
        else timer = setTimeout(run, ms)
      }
    }
  }
  function visibility() {
    generation++
    clear()
    if (!document.hidden) void run()
  }
  onMounted(() => {
    alive = true
    document.addEventListener('visibilitychange', visibility)
    void run()
  })
  onUnmounted(() => {
    alive = false
    generation++
    clear()
    document.removeEventListener('visibilitychange', visibility)
  })
  return { refresh: run }
}
