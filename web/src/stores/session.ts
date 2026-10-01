// Copyright (C) 2026 James Hickman
//
// SPDX-License-Identifier: AGPL-3.0-or-later

import { defineStore } from 'pinia'
import { auth, type Challenge, type Session } from '@/services/api'
import { onUnauthenticated, session as store } from '@/services/client'

// The deployment roles. Additive, unordered, and NONE implies another —
// system_owner creates authority and holds no operational power of its own. So
// every check is a membership test; there is no rank to compare.
export const SYSTEM_OBSERVER = 'system_observer'
export const SYSTEM_TENANTS = 'system_tenants'
export const SYSTEM_SECURITY = 'system_security'
export const SYSTEM_BILLING = 'system_billing'
export const SYSTEM_OWNER = 'system_owner'

interface State {
  token: string | null
  subject: string
  roles: string[]
  amr: string[]
  /** The pre-session challenge. IN MEMORY ONLY — deliberately never stored.
   *
   * It is a credential that stands between a correct password and a session. Put
   * it in sessionStorage and it outlives the tab that earned it and becomes a
   * second thing worth stealing, for no benefit: it expires in ten minutes and
   * the only thing to do with it is finish the login that is already on screen.
   */
  challenge: Challenge | null
  /** Shown exactly once, after enrolment, and never persisted. */
  recoveryCodes: string[]
}

export const useSession = defineStore('session', {
  state: (): State => ({
    token: store.get(),
    subject: '',
    roles: [],
    amr: [],
    challenge: null,
    recoveryCodes: [],
  }),

  getters: {
    isSignedIn: (s) => !!s.token,
    /** Whether a role is held. Not "at least" — see the note above. */
    has: (s) => (role: string) => s.roles.includes(role),
  },

  actions: {
    /** Step one. Returns what the door wants next. */
    async signIn(subject: string, password: string): Promise<'verify' | 'enroll' | 'done'> {
      const r = await auth.password(subject, password)
      if ('challenge_token' in r) {
        this.challenge = r as Challenge
        return (r as Challenge).status
      }
      // Only when the requirement is switched off.
      this.adopt(r as Session)
      return 'done'
    },

    async verify(code: string, method = 'totp') {
      if (!this.challenge) throw new Error('there is no challenge to complete')
      this.adopt(await auth.verify(this.challenge.challenge_token, code, method))
    },

    async enrollBegin() {
      if (!this.challenge) throw new Error('there is no challenge to complete')
      const begun = await auth.enrollBegin(this.challenge.challenge_token)
      // The server hands the challenge back rather than issuing a fresh one, so
      // the ten-minute window does not extend for as long as someone keeps
      // pressing. Carry whatever it returned.
      this.challenge = { ...this.challenge, challenge_token: begun.challenge_token }
      return begun
    },

    async enrollComplete(code: string) {
      if (!this.challenge) throw new Error('there is no challenge to complete')
      const s = await auth.enrollComplete(this.challenge.challenge_token, code)
      this.adopt(s)
      // Returned once by the API and held only in memory. If this page is closed
      // before they are written down they are gone, which is why the view makes
      // acknowledging them a deliberate step rather than a dismissable toast.
      this.recoveryCodes = s.recovery_codes ?? []
    },

    adopt(s: Session) {
      this.token = s.token
      this.subject = s.subject
      this.roles = s.roles ?? []
      this.amr = s.amr ?? []
      this.challenge = null
      store.set(s.token)
    },

    /** Re-read identity for a token restored from storage on a reload. */
    async refresh(): Promise<boolean> {
      if (!this.token) return false
      try {
        const me = await auth.whoami()
        this.subject = me.subject
        this.roles = me.roles ?? []
        this.amr = me.amr ?? []
        return true
      } catch {
        // Expired, revoked, or the console restarted with a new signing secret.
        this.signOut()
        return false
      }
    },

    abandonChallenge() {
      this.challenge = null
    },

    acknowledgeRecoveryCodes() {
      this.recoveryCodes = []
    },

    signOut() {
      this.token = null
      this.subject = ''
      this.roles = []
      this.amr = []
      this.challenge = null
      this.recoveryCodes = []
      store.clear()
    },
  },
})

/** Let an expiry mid-session reach the store without the client importing it. */
export function wireUnauthenticated(onSignedOut: () => void) {
  onUnauthenticated.handler = () => {
    const s = useSession()
    s.signOut()
    onSignedOut()
  }
}
