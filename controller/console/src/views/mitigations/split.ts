export type Stamp = { lastOk: number | null; failing: boolean }
export function settle<T>(promise: Promise<T>): Promise<PromiseSettledResult<T>> {
  return promise.then(value => ({ status: 'fulfilled', value }), reason => ({ status: 'rejected', reason }))
}
export function minStamp(stamps: Stamp[], previous: number) {
  return stamps.some(s => s.failing || s.lastOk === null) ? previous : Math.min(...stamps.map(s => s.lastOk!))
}
