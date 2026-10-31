import { request } from '../../api/client'
import type { ProbeReply, TestKind } from './data'

export function testConnector(kind: TestKind, id: number) {
  return request<ProbeReply>(`/api/settings/${kind}-connectors/${id}/test`, { method: 'POST', timeout: 45000 })
}
export function bgpRoutes(id: number) {
  return request<{ output: string }>(`/api/settings/bgp-connectors/${id}/routes`, { timeout: 45000 })
}
