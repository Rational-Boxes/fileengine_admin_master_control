// Copyright (C) 2026 James Hickman
//
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * The client, and the one thing it exists to get right.
 *
 * `POST /v1/auth/token` answers 401 WITH A CHALLENGE — that is the protocol at
 * this tier, not an expired session. The tenant SPA's client redirects to /login
 * on any 401, and copying that here would fire during login itself: the challenge
 * is discarded, the page returns to the login it is already on, and the form looks
 * broken while never advancing. These tests pin the exemption.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import MockAdapter from 'axios-mock-adapter'
import { apiError, createClient, onUnauthenticated, session } from './client'

describe('the session token', () => {
  beforeEach(() => window.sessionStorage.clear())

  it('lives in sessionStorage, so it dies with the tab', () => {
    session.set('abc')
    expect(window.sessionStorage.getItem('amc.token')).toBe('abc')
    // The deliberate difference from the tenant SPA: a token to the console that
    // reads every tenant's audit should not survive a reboot on a shared machine.
    expect(window.localStorage.getItem('amc.token')).toBeNull()
  })

  it('survives a storage that throws rather than crashing the app', () => {
    const spy = vi.spyOn(window.sessionStorage, 'getItem').mockImplementation(() => {
      throw new Error('blocked in a private window')
    })
    expect(session.get()).toBeNull()
    spy.mockRestore()
  })
})

describe('a 401 during login is not an expired session', () => {
  beforeEach(() => {
    window.sessionStorage.clear()
    onUnauthenticated.handler = null
  })

  it('does not clear the session or signal a sign-out', async () => {
    session.set('a-valid-token')
    const signedOut = vi.fn()
    onUnauthenticated.handler = signedOut
    const client = createClient()
    const mock = new MockAdapter(client)
    mock.onPost('/v1/auth/token').reply(401, { status: 'verify', challenge_token: 'c' })

    await expect(client.post('/v1/auth/token', {})).rejects.toBeTruthy()

    expect(signedOut).not.toHaveBeenCalled()
    expect(session.get()).toBe('a-valid-token')
  })

  it('exempts every mfa route too', async () => {
    const signedOut = vi.fn()
    onUnauthenticated.handler = signedOut
    const client = createClient()
    const mock = new MockAdapter(client)
    for (const url of [
      '/v1/auth/mfa/verify',
      '/v1/auth/mfa/enroll/begin',
      '/v1/auth/mfa/enroll/complete',
    ]) {
      mock.onPost(url).reply(401, { detail: 'that code did not match' })
      await expect(client.post(url, {})).rejects.toBeTruthy()
    }
    // A wrong TOTP code must leave the challenge usable for the next attempt.
    expect(signedOut).not.toHaveBeenCalled()
  })

  it('DOES sign out on a 401 from a real route', async () => {
    session.set('stale')
    const signedOut = vi.fn()
    onUnauthenticated.handler = signedOut
    const client = createClient()
    const mock = new MockAdapter(client)
    mock.onGet('/v1/whoami').reply(401, { detail: 'unauthorized' })

    await expect(client.get('/v1/whoami')).rejects.toBeTruthy()
    expect(signedOut).toHaveBeenCalledOnce()
    expect(session.get()).toBeNull()
  })

  it('never navigates by itself', async () => {
    // The router owns navigation. An interceptor calling location.assign is how
    // one stale request becomes a reload loop.
    const client = createClient()
    const mock = new MockAdapter(client)
    mock.onGet('/v1/whoami').reply(401, {})
    const before = window.location.href
    await expect(client.get('/v1/whoami')).rejects.toBeTruthy()
    expect(window.location.href).toBe(before)
  })
})

describe('the bearer', () => {
  beforeEach(() => window.sessionStorage.clear())

  it('is attached to ordinary requests', async () => {
    session.set('tok')
    const client = createClient()
    const mock = new MockAdapter(client)
    mock.onGet('/v1/tenants').reply((cfg) => [200, { seen: cfg.headers?.Authorization }])
    const r = await client.get('/v1/tenants')
    expect(r.data.seen).toBe('Bearer tok')
  })

  it('is NOT attached to the login, which takes a challenge in its body', async () => {
    // A stale bearer on the login request is not wrong exactly, but sending a
    // dead credential where none is wanted invites a 401 that means nothing.
    session.set('stale')
    const client = createClient()
    const mock = new MockAdapter(client)
    mock.onPost('/v1/auth/token').reply((cfg) => [200, { seen: cfg.headers?.Authorization ?? null }])
    const r = await client.post('/v1/auth/token', {})
    expect(r.data.seen).toBeNull()
  })
})

describe('error messages', () => {
  it('shows the server’s own words', async () => {
    // These refusals are written to be read — "would consume the domain's rate
    // limit, which is shared by every tenant" is the actual API response, and
    // replacing it with "Request failed" throws away the only explanation the
    // user gets.
    const client = createClient()
    const mock = new MockAdapter(client)
    const detail =
      'tenant acme is requested, not verified — the DNS gate has not passed and ' +
      'has not been overridden.'
    mock.onPost('/v1/tenants/acme/provision').reply(409, { detail })
    try {
      await client.post('/v1/tenants/acme/provision')
      expect.unreachable()
    } catch (e) {
      expect(apiError(e)).toBe(detail)
    }
  })

  it('does not print a pydantic error object at a human', async () => {
    const client = createClient()
    const mock = new MockAdapter(client)
    mock.onPost('/v1/tenants').reply(422, { detail: [{ msg: 'a base domain is required' }] })
    try {
      await client.post('/v1/tenants')
      expect.unreachable()
    } catch (e) {
      expect(apiError(e)).toBe('a base domain is required')
    }
  })
})
