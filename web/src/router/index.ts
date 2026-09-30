// Copyright (C) 2026 James Hickman
//
// SPDX-License-Identifier: AGPL-3.0-or-later

import { createRouter, createWebHistory, type RouteRecordRaw } from 'vue-router'
import {
  SYSTEM_OBSERVER,
  SYSTEM_OWNER,
  SYSTEM_SECURITY,
  useSession,
  wireUnauthenticated,
} from '@/stores/session'

const routes: RouteRecordRaw[] = [
  { path: '/login', name: 'login', component: () => import('@/views/LoginView.vue'),
    meta: { anonymous: true } },
  { path: '/', name: 'dashboard', component: () => import('@/views/DashboardView.vue'),
    meta: { role: SYSTEM_OBSERVER } },
  { path: '/tenants', name: 'tenants', component: () => import('@/views/TenantsView.vue'),
    meta: { role: SYSTEM_OBSERVER } },
  { path: '/tenants/:id', name: 'tenant', component: () => import('@/views/TenantDetailView.vue'),
    meta: { role: SYSTEM_OBSERVER } },
  { path: '/jobs', name: 'jobs', component: () => import('@/views/JobsView.vue'),
    meta: { role: SYSTEM_OBSERVER } },
  { path: '/security', name: 'security', component: () => import('@/views/SecurityView.vue'),
    meta: { role: SYSTEM_SECURITY } },
  { path: '/queue', name: 'queue', component: () => import('@/views/QueueView.vue'),
    meta: { role: SYSTEM_SECURITY } },
  { path: '/redactions', name: 'redactions', component: () => import('@/views/RedactionsView.vue'),
    meta: { role: SYSTEM_SECURITY } },
  { path: '/administrators', name: 'administrators',
    component: () => import('@/views/AdministratorsView.vue'), meta: { role: SYSTEM_OWNER } },
  { path: '/denied', name: 'denied', component: () => import('@/views/DeniedView.vue'),
    meta: { role: null } },
  { path: '/:pathMatch(.*)*', redirect: '/' },
]

export const router = createRouter({ history: createWebHistory(), routes })

/** The guard.
 *
 * Its whole job is to be UNABLE to loop, because one of these locked up
 * production before: a guard that redirects on a condition it does not clear will
 * bounce forever, and a single-hop test cannot see it.
 *
 * Three rules make that structural rather than careful:
 *
 *   1. /login is `anonymous` and is never redirected AWAY from by a missing
 *      session — so the "no session" branch always terminates.
 *   2. /denied requires only a session (`role: null`), so the "wrong role" branch
 *      terminates too. Sending someone role-less to a page that needs a role is
 *      the classic version of this bug.
 *   3. The session refresh happens ONCE per navigation and its failure lands on
 *      /login, never on a retry of the route that failed.
 *
 * The router owns navigation for the same reason: the axios interceptor clears the
 * token and calls back, and never touches window.location, so one stale request
 * cannot become a reload loop.
 */
let refreshed = false

router.beforeEach(async (to) => {
  const s = useSession()

  if (to.meta.anonymous) return true

  if (!s.isSignedIn) {
    // `next` so the user lands where they were going. Not applied when already
    // heading to the root, to keep the URL clean.
    return { name: 'login', query: to.fullPath !== '/' ? { next: to.fullPath } : {} }
  }

  // A token restored from storage carries no roles until whoami answers, and the
  // role check below would otherwise refuse every route on the first navigation
  // after a reload.
  if (!refreshed && s.roles.length === 0) {
    refreshed = true
    const ok = await s.refresh()
    if (!ok) return { name: 'login' }
  }

  const required = to.meta.role as string | null | undefined
  if (required && !s.has(required)) return { name: 'denied' }

  return true
})

wireUnauthenticated(() => {
  refreshed = false
  // Only move if there is somewhere to move to. Pushing /login while already on
  // it is the loop.
  if (router.currentRoute.value.name !== 'login') {
    void router.push({ name: 'login' })
  }
})
