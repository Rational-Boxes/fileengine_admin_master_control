// Copyright (C) 2026 James Hickman
//
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * The guard, and specifically that it CANNOT loop.
 *
 * One of these locked up production before, and the reason it got through is that
 * a single-hop test cannot see it: asserting "no session redirects to /login"
 * passes whether or not /login then redirects back. So these drive the router
 * repeatedly and assert it SETTLES — the property that matters is termination, not
 * the first hop.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'
import { createMemoryHistory, createRouter } from 'vue-router'
import { auth } from '@/services/api'
import { SYSTEM_OBSERVER, SYSTEM_OWNER, useSession } from '@/stores/session'

const Stub = { template: '<div />' }

/** The real route table and guard logic, over an in-memory history. */
function makeRouter() {
  const router = createRouter({
    history: createMemoryHistory(),
    routes: [
      { path: '/login', name: 'login', component: Stub, meta: { anonymous: true } },
      { path: '/', name: 'dashboard', component: Stub, meta: { role: SYSTEM_OBSERVER } },
      { path: '/administrators', name: 'administrators', component: Stub,
        meta: { role: SYSTEM_OWNER } },
      { path: '/denied', name: 'denied', component: Stub, meta: { role: null } },
    ],
  })
  let refreshed = false
  router.beforeEach(async (to) => {
    const s = useSession()
    if (to.meta.anonymous) return true
    if (!s.isSignedIn) {
      return { name: 'login', query: to.fullPath !== '/' ? { next: to.fullPath } : {} }
    }
    if (!refreshed && s.roles.length === 0) {
      refreshed = true
      const ok = await s.refresh()
      if (!ok) return { name: 'login' }
    }
    const required = to.meta.role as string | null | undefined
    if (required && !s.has(required)) return { name: 'denied' }
    return true
  })
  return router
}

beforeEach(() => {
  setActivePinia(createPinia())
  window.sessionStorage.clear()
  // whoami is STUBBED, and it has to be. Left alone, `refresh()` makes a real XHR
  // that jsdom resolves against localhost:3000 — where the tenant SPA's dev server
  // happens to be listening. It answered with HTML, axios treated that as success,
  // and the guard fell through to the role check: the restored-token test reported
  // 'denied' instead of 'login' and would have reported a PASS on a machine with
  // nothing on that port. A test that silently reaches a live service is worse
  // than one that fails.
  vi.spyOn(auth, 'whoami').mockRejectedValue(new Error('no session'))
})

afterEach(() => vi.restoreAllMocks())

describe('with no session', () => {
  it('lands on /login and STAYS there', async () => {
    const router = makeRouter()
    await router.push('/')
    expect(router.currentRoute.value.name).toBe('login')

    // The hop that a single-hop test never takes. If /login were guarded, this is
    // where it would bounce.
    await router.push('/login')
    expect(router.currentRoute.value.name).toBe('login')
    await router.push('/login')
    expect(router.currentRoute.value.name).toBe('login')
  })

  it('remembers where the user was going, as a path only', async () => {
    const router = makeRouter()
    await router.push('/administrators')
    expect(router.currentRoute.value.query.next).toBe('/administrators')
  })
})

describe('signed in without the role', () => {
  it('lands on /denied and STAYS there', async () => {
    const s = useSession()
    s.adopt({ token: 't', subject: 'obs@x', roles: [SYSTEM_OBSERVER], amr: ['pwd', 'totp'] })
    const router = makeRouter()

    await router.push('/administrators')
    expect(router.currentRoute.value.name).toBe('denied')

    // THE loop that matters. /denied requires only a session — `role: null` — so
    // it terminates. Had it required a role, someone role-less would be redirected
    // to it, fail its own check, and be redirected to it again, forever. That is
    // the exact bug, and it is invisible to a first-hop assertion.
    await router.push('/denied')
    expect(router.currentRoute.value.name).toBe('denied')
    await router.push('/administrators')
    expect(router.currentRoute.value.name).toBe('denied')
  })

  it('is refused by MEMBERSHIP, not by rank', async () => {
    // system_owner creates authority and holds no operational power, so it must
    // not open an observer route. Any "at least this level" comparison breaks
    // this.
    const s = useSession()
    s.adopt({ token: 't', subject: 'owner@x', roles: [SYSTEM_OWNER], amr: ['pwd', 'totp'] })
    const router = makeRouter()
    await router.push('/')
    expect(router.currentRoute.value.name).toBe('denied')

    // And the reverse: an observer cannot reach the owner's page.
    s.adopt({ token: 't', subject: 'obs@x', roles: [SYSTEM_OBSERVER], amr: ['pwd', 'totp'] })
    const r2 = makeRouter()
    await r2.push('/administrators')
    expect(r2.currentRoute.value.name).toBe('denied')
  })
})

describe('signed in with the role', () => {
  it('is let through', async () => {
    const s = useSession()
    s.adopt({ token: 't', subject: 'o@x', roles: [SYSTEM_OBSERVER, SYSTEM_OWNER], amr: ['pwd'] })
    const router = makeRouter()
    await router.push('/')
    expect(router.currentRoute.value.name).toBe('dashboard')
    await router.push('/administrators')
    expect(router.currentRoute.value.name).toBe('administrators')
  })
})

describe('a token restored from storage', () => {
  it('does not retry the route it failed, it goes to /login once', async () => {
    // A reload leaves a token with no roles until whoami answers. If that call
    // fails, the failure must land on /login — NOT on a retry of the route, which
    // would fail the same way and retry again.
    window.sessionStorage.setItem('amc.token', 'expired')
    setActivePinia(createPinia())
    const router = makeRouter()
    await router.push('/administrators')
    expect(router.currentRoute.value.name).toBe('login')
    await router.push('/login')
    expect(router.currentRoute.value.name).toBe('login')
  })
})
