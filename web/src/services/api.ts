// Copyright (C) 2026 James Hickman
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// One module per concern would be six files that each wrap two calls. The API is
// small and flat; this stays flat with it.

import { http } from './client'

// ── the door ───────────────────────────────────────────────────────────────

/** What a correct password buys: a challenge, and which kind. */
export type LoginStep = 'verify' | 'enroll'

export interface Challenge {
  status: LoginStep
  challenge_token: string
  methods: string[]
  expires_in: number
  detail?: string
}

export interface Session {
  token: string
  subject: string
  roles: string[]
  amr: string[]
  can_grant?: boolean
  status?: string
  recovery_codes?: string[]
}

export const auth = {
  /** Step one. Resolves to a Challenge on 401 — which is the normal path. */
  async password(subject: string, password: string): Promise<Challenge | Session> {
    try {
      const r = await http.post<Session>('/v1/auth/token', { subject, password })
      // Only reachable when the requirement has been switched off
      // (AMC_REQUIRE_MFA=false). Kept rather than treated as impossible, because
      // it is a supported configuration and the console should work in it.
      return r.data
    } catch (e: any) {
      const body = e?.response?.data
      if (e?.response?.status === 401 && body?.challenge_token) {
        return body as Challenge
      }
      throw e
    }
  },

  async verify(challenge_token: string, code: string, method = 'totp'): Promise<Session> {
    const r = await http.post<Session>('/v1/auth/mfa/verify', { challenge_token, code, method })
    return r.data
  },

  async enrollBegin(challenge_token: string) {
    const r = await http.post<{
      status: string
      otpauth_uri: string
      secret: string
      issuer: string
      account: string
      challenge_token: string
    }>('/v1/auth/mfa/enroll/begin', { challenge_token })
    return r.data
  },

  async enrollComplete(challenge_token: string, code: string): Promise<Session> {
    const r = await http.post<Session>('/v1/auth/mfa/enroll/complete', { challenge_token, code })
    return r.data
  },

  async whoami() {
    const r = await http.get<{ subject: string; roles: string[]; amr: string[]; can_grant: boolean }>(
      '/v1/whoami',
    )
    return r.data
  },
}

// ── tenants (§3.4a) ────────────────────────────────────────────────────────

export interface DnsCheck {
  hostname: string
  ok: boolean
  resolved: string[]
  expected: string
  detail: string
}

export interface TenantView {
  tenant_id: string
  /** The human-readable name, for billing and high-level operations.
   *
   * Falls back to `tenant_id` server-side so there is always something to print —
   * but it is NEVER an identifier. Anything that looks a tenant up uses
   * `tenant_id`, which is immutable because it reaches a hostname, a Postgres
   * schema, an LDAP DN and a file path.
   */
  display_name: string
  has_display_name: boolean
  schema_name: string
  /** The REGISTRY's lifecycle state — the same value the doors compare against. */
  state: string
  /** Whether a login is admitted, which is `state === 'live'` and nothing else. */
  admits_logins: boolean
  /** THE SERVER'S JUDGEMENT on the DNS gate. Never recomputed here. */
  may_provision: boolean
  gate_cleared: boolean
  /** False for every tenant that predates this console — the normal case. */
  requested_here: boolean
  created_at: string
  state_since: string
  state_by: string
  state_note: string
  base_domain: string
  address: string
  initial_admin: string
  requested_by: string
  hostnames: string[]
  records: { name: string; type: string; value: string; zone_line: string }[]
  dns?: { ok: boolean; authoritative: boolean; blocking_reason: string; checks: DnsCheck[] }
  override?: { by: string; reason: string }
  failure?: { step: string; detail: string; retry_safe: boolean }
  job_id?: string
}

export const tenants = {
  async list() {
    const r = await http.get<{ tenants: TenantView[] }>('/v1/tenants')
    return r.data.tenants
  },
  async get(id: string) {
    const r = await http.get<TenantView>(`/v1/tenants/${encodeURIComponent(id)}`)
    return r.data
  },
  async request(body: {
    tenant_id: string
    base_domain: string
    address: string
    initial_admin: string
    display_name?: string
  }) {
    const r = await http.post<TenantView>('/v1/tenants', body)
    return r.data
  },
  /** Rename the LABEL. Never the identifier. */
  async setDisplayName(id: string, display_name: string) {
    const r = await http.put<TenantView>(
      `/v1/tenants/${encodeURIComponent(id)}/display-name`, { display_name })
    return r.data
  },
  async dnsCheck(id: string) {
    const r = await http.post<TenantView>(`/v1/tenants/${encodeURIComponent(id)}/dns-check`)
    return r.data
  },
  async dnsOverride(id: string, reason: string) {
    const r = await http.post<TenantView>(`/v1/tenants/${encodeURIComponent(id)}/dns-override`, {
      reason,
    })
    return r.data
  },
  async provision(id: string) {
    const r = await http.post<{ job: Record<string, unknown>; tenant: TenantView }>(
      `/v1/tenants/${encodeURIComponent(id)}/provision`,
    )
    return r.data
  },
  async jobs() {
    const r = await http.get<{ jobs: Record<string, any>[] }>('/v1/provisioning-jobs')
    return r.data.jobs
  },
}

// ── administrators (§6.3) ──────────────────────────────────────────────────

export const administrators = {
  async list() {
    const r = await http.get<Record<string, any>>('/v1/administrators')
    return r.data
  },
  async history(subject: string) {
    const r = await http.get<Record<string, any>>(
      `/v1/administrators/${encodeURIComponent(subject)}/history`,
    )
    return r.data
  },
  async roles() {
    const r = await http.get<Record<string, any>>('/v1/roles')
    return r.data
  },
  async grant(subject: string, role: string, reason: string) {
    const r = await http.post('/v1/grants', { subject, role, reason })
    return r.data
  },
  async revoke(subject: string, role: string, reason: string) {
    const r = await http.post('/v1/revocations', { subject, role, reason })
    return r.data
  },
}

// ── the cross-tenant security view (§3.4) ──────────────────────────────────

export const security = {
  async incidents(params: Record<string, string | number> = {}) {
    const r = await http.get<Record<string, any>>('/v1/security/incidents', { params })
    return r.data
  },
  async campaigns() {
    const r = await http.get<Record<string, any>>('/v1/security/campaigns')
    return r.data
  },
  async queue(params: Record<string, string | number> = {}) {
    const r = await http.get<Record<string, any>>('/v1/security/queue', { params })
    return r.data
  },
  async backlog() {
    const r = await http.get<Record<string, any>>('/v1/security/backlog')
    return r.data
  },
  async item(id: number | string) {
    const r = await http.get<Record<string, any>>(`/v1/security/queue/${id}`)
    return r.data
  },
  /** One move along the procedure. No `actor` — the server takes it from the token. */
  async transition(body: {
    incident_id: number
    state: string
    reason?: string
    counterparty?: string
    evidence?: string
  }) {
    const r = await http.post('/v1/security/queue/transition', body)
    return r.data
  },
}

export const redactions = {
  async register() {
    const r = await http.get<Record<string, any>>('/v1/redactions')
    return r.data
  },
}
