// Copyright (C) 2026 James Hickman
//
// SPDX-License-Identifier: AGPL-3.0-or-later

import axios, { type AxiosInstance } from 'axios'

/** Where the session lives.
 *
 * sessionStorage, NOT localStorage, and not by accident. This is the console that
 * reads every tenant's audit and grants deployment authority; a token that
 * outlives the tab — surviving a reboot on a shared or unattended machine — is a
 * worse trade here than asking for a TOTP code again. The tenant SPA makes the
 * other choice for the other reason: people live in it all day.
 *
 * Every accessor is wrapped, because storage throws in a private window and in
 * some embedded webviews rather than returning null.
 */
export const session = {
  key: 'amc.token',
  get(): string | null {
    try {
      return window.sessionStorage.getItem(this.key)
    } catch {
      return null
    }
  },
  set(token: string): void {
    try {
      window.sessionStorage.setItem(this.key, token)
    } catch {
      /* a session that cannot be stored still works for this page */
    }
  },
  clear(): void {
    try {
      window.sessionStorage.removeItem(this.key)
    } catch {
      /* nothing to do */
    }
  },
}

/** Routes where a 401 is part of the PROTOCOL rather than an expired session.
 *
 * This is the trap this client exists to avoid. `POST /v1/auth/token` answers 401
 * with a challenge — that is the design, not a failure: a correct password never
 * returns a session at this tier. The tenant SPA's client redirects to /login on
 * any 401, and the same rule here would fire on the login request itself and send
 * the page back to the login it was already on, discarding the challenge each
 * time. The result is a form that looks broken and never advances.
 *
 * So these paths are exempt: their 401s are returned to the caller, which knows
 * what they mean.
 */
const AUTH_ROUTES = ['/v1/auth/token', '/v1/auth/mfa/']

function isAuthRoute(url: string | undefined): boolean {
  return !!url && AUTH_ROUTES.some((p) => url.startsWith(p))
}

export const onUnauthenticated: { handler: (() => void) | null } = { handler: null }

export function createClient(): AxiosInstance {
  const client = axios.create({ baseURL: '' })

  client.interceptors.request.use((config) => {
    const token = session.get()
    if (token && !isAuthRoute(config.url)) {
      config.headers.Authorization = `Bearer ${token}`
    }
    return config
  })

  client.interceptors.response.use(
    (r) => r,
    (error) => {
      const status = error.response?.status
      if (status === 401 && !isAuthRoute(error.config?.url)) {
        // A real expiry on a real session. Clear it and let the app decide where
        // to go — the router owns navigation, so this never calls
        // window.location.assign: doing that from here is what turns one stale
        // request into a reload loop.
        session.clear()
        onUnauthenticated.handler?.()
      }
      return Promise.reject(error)
    },
  )

  return client
}

export const http = createClient()

/** The message worth showing a human.
 *
 * FastAPI puts it in `detail`, and this tier's refusals are written to be read —
 * "the DNS gate has not passed and has not been overridden … would consume the
 * domain's rate limit, which is shared by every tenant" is the actual API
 * response. Replacing that with "Request failed" throws away the only
 * explanation the user is going to get.
 */
export function apiError(e: unknown): string {
  if (axios.isAxiosError(e)) {
    const detail = e.response?.data?.detail
    if (typeof detail === 'string' && detail) return detail
    if (Array.isArray(detail) && detail.length) {
      // pydantic validation errors
      const first = detail[0]
      if (first?.msg) return String(first.msg)
    }
    if (e.response?.status === 503) return 'A service this console depends on is unavailable.'
    if (e.response?.status) return `Request failed (${e.response.status}).`
    return 'The console could not be reached.'
  }
  return e instanceof Error ? e.message : String(e)
}
