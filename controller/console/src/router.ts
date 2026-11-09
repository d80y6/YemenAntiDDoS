import { createRouter, createWebHistory, type RouterHistory, type RouteRecordRaw } from 'vue-router'
import { state } from './state'
import Login from './views/Login.vue'
import Placeholder from './views/Placeholder.vue'
import About from './views/About.vue'
import NotFound from './views/NotFound.vue'

export const businessPaths = [
  '/overview',
  '/traffic',
  '/attacks',
  '/attacks/:id',
  '/mitigations',
  '/l7',
  '/inline',
  '/nodes',
  '/prefixes',
  '/thresholds',
  '/thresholds/rules',
  '/thresholds/:id',
  '/baseline',
  '/flow',
  '/flow/:node',
  '/responses',
  '/responses/:id',
  '/connectors',
  '/connectors/:kind(bgp|xdrop|webhook|shell)',
  '/users',
  '/audit',
]

export const legacyRoutes: RouteRecordRaw[] = [
  { path: '/traffic-overview', redirect: '/traffic' },
  { path: '/templates', redirect: '/thresholds' },
  { path: '/dynamic-detection', redirect: '/baseline' },
  { path: '/webhooks', redirect: '/connectors/webhook' },
  ...['bgp', 'xdrop', 'webhook', 'shell'].map(kind => ({
    path: `/settings/${kind}-connectors`,
    redirect: `/connectors/${kind}`,
  })),
  { path: '/nodes/:id/flow', redirect: to => `/flow/${encodeURIComponent(String(to.params.id))}` },
]

export function makeRouter(history: RouterHistory = createWebHistory()) {
  const routes: RouteRecordRaw[] = [
    { path: '/', redirect: '/overview' },
    ...businessPaths.map(path => ({ path, component: path === '/overview'
      ? () => import('./views/overview/Overview.vue')
      : path === '/traffic' ? () => import('./views/traffic/Traffic.vue')
      : path === '/attacks' ? () => import('./views/attacks/Attacks.vue')
      : path === '/attacks/:id' ? () => import('./views/attacks/AttackDetail.vue')
      : path === '/mitigations' ? () => import('./views/mitigations/Mitigations.vue')
      : path === '/nodes' ? () => import('./views/nodes/Nodes.vue')
      : path === '/l7' ? () => import('./views/l7/L7.vue')
      : path === '/inline' ? () => import('./views/inline/Inline.vue')
      : path === '/prefixes' ? () => import('./views/prefixes/Prefixes.vue')
      : path === '/thresholds' ? () => import('./views/thresholds/Templates.vue')
      : path === '/thresholds/rules' ? () => import('./views/thresholds/Rules.vue')
      : path === '/thresholds/:id' ? () => import('./views/thresholds/Detail.vue')
      : path === '/responses' ? () => import('./views/responses/Responses.vue')
      : path === '/responses/:id' ? () => import('./views/responses/ResponseDetail.vue')
      : path === '/connectors' || path.startsWith('/connectors/:kind')
        ? () => import('./views/connectors/Connectors.vue')
      : path === '/flow' || path === '/flow/:node' ? () => import('./views/flow/Flow.vue')
      : path === '/users' ? () => import('./views/users/Users.vue')
      : path === '/audit' ? () => import('./views/audit/Audit.vue')
      : path === '/baseline' ? () => import('./views/baseline/Baseline.vue') : Placeholder })),
    ...legacyRoutes,
    { path: '/about', component: About },
    { path: '/login', component: Login },
  ]
  if (import.meta.env.DEV) routes.push({
    path: '/__dev/components',
    component: () => import('./dev/Components.vue'),
  })
  routes.push({ path: '/:pathMatch(.*)*', component: NotFound })
  const router = createRouter({ history, routes })
  router.beforeEach(to => {
    if (!state.token && to.path !== '/login') return {
      path: '/login',
      query: { next: to.fullPath },
      replace: true,
    }
    if (state.token && to.path === '/login') return { path: '/overview', replace: true }
  })
  return router
}
