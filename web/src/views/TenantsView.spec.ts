// Copyright (C) 2026 James Hickman
//
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * The Provision button, which is the only control in this UI whose mistake is
 * expensive beyond the page.
 *
 * Failed certificate issuance consumes a rate limit shared by EVERY tenant on the
 * domain, so a button that can be pressed early can exhaust issuance for the whole
 * deployment. The rule that keeps it safe is that the UI renders the server's
 * `may_provision` and never re-derives it: a local
 * `state === 'verified' || override` looks identical, is a second implementation,
 * and when the two disagree the button is enabled and the server is right.
 *
 * So the test that matters gives the component a row where a plausible local
 * computation says yes and the server says NO.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { mount } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import TenantsView from './TenantsView.vue'
import { tenants, type TenantView } from '@/services/api'
import { SYSTEM_OBSERVER, SYSTEM_TENANTS, useSession } from '@/stores/session'

function row(over: Partial<TenantView> = {}): TenantView {
  return {
    tenant_id: 'acme',
    state: 'verified',
    base_domain: 'example.com',
    address: '203.0.113.10',
    initial_admin: 'a@acme.test',
    requested_by: 'ten@x',
    requested_at: '2026-09-29T00:00:00+00:00',
    hostnames: ['acme.example.com', 'acme-drive.example.com'],
    records: [],
    may_provision: true,
    ...over,
  }
}

const stubs = { RouterLink: { template: '<a><slot /></a>' } }

async function view(rows: TenantView[], roles = [SYSTEM_OBSERVER, SYSTEM_TENANTS]) {
  setActivePinia(createPinia())
  useSession().adopt({ token: 't', subject: 'ten@x', roles, amr: ['pwd', 'totp'] })
  vi.spyOn(tenants, 'list').mockResolvedValue(rows)
  const w = mount(TenantsView, { global: { stubs } })
  await vi.waitFor(() => expect(w.text()).not.toContain('Loading'))
  return w
}

function provisionButton(w: ReturnType<typeof mount>) {
  return w
    .findAll('button')
    .find((b) => b.text() === 'Provision')
}

beforeEach(() => vi.restoreAllMocks())

describe('the provision button', () => {
  it('is enabled when the SERVER says the gate passed', async () => {
    const w = await view([row({ may_provision: true })])
    expect(provisionButton(w)!.attributes('disabled')).toBeUndefined()
  })

  it('is disabled when the server says it did not', async () => {
    const w = await view([row({ state: 'awaiting_dns', may_provision: false })])
    expect(provisionButton(w)!.attributes('disabled')).toBeDefined()
  })

  it('OBEYS the server even when the row looks provisionable locally', async () => {
    // THE test. `state: 'verified'` with an override recorded is exactly what a
    // hand-rolled check would call ready; the server says no. Any local
    // re-derivation makes this button live, and a press then burns issuance for
    // every tenant on the domain.
    const w = await view([
      row({ state: 'verified', override: { by: 'someone', reason: 'sure' }, may_provision: false }),
    ])
    expect(provisionButton(w)!.attributes('disabled')).toBeDefined()
  })

  it('and stays disabled for a state the UI has never heard of', async () => {
    // A lifecycle state added server-side later must not become provisionable by
    // default here. Reading may_provision gives that for free; a local allow-list
    // of states would not.
    const w = await view([row({ state: 'quarantined', may_provision: false })])
    expect(provisionButton(w)!.attributes('disabled')).toBeDefined()
  })
})

describe('waiting is not failing', () => {
  it('shows awaiting_dns as a warning, never as an error', async () => {
    // Records that have not propagated are not a fault, and colouring them red
    // sends someone looking for a problem that does not exist.
    const w = await view([row({ state: 'awaiting_dns', may_provision: false })])
    const pill = w.findAll('.pill').find((p) => p.text().includes('awaiting'))
    expect(pill!.classes()).toContain('warn')
    expect(pill!.classes()).not.toContain('bad')
  })

  it('shows failed as an error', async () => {
    const w = await view([row({ state: 'failed', may_provision: false })])
    const pill = w.findAll('.pill').find((p) => p.text().includes('failed'))
    expect(pill!.classes()).toContain('bad')
  })
})

describe('authority', () => {
  it('hides the action column from an observer who cannot act', async () => {
    const w = await view([row()], [SYSTEM_OBSERVER])
    expect(provisionButton(w)).toBeUndefined()
    // Hiding is a courtesy; the server gates it regardless. The point of the test
    // is that a read-only administrator is not shown controls that will 403.
    expect(w.text()).not.toContain('Request a tenant')
  })

  it('shows them to system_tenants', async () => {
    const w = await view([row()], [SYSTEM_OBSERVER, SYSTEM_TENANTS])
    expect(provisionButton(w)).toBeDefined()
  })
})

describe('the blocking reason is shown, not summarised', () => {
  it('renders the per-hostname detail the server sent', async () => {
    // "resolves to 198.51.100.4, expected 203.0.113.10" and "no record" need
    // opposite responses: only one of them improves by waiting.
    const w = await view([
      row({
        state: 'awaiting_dns',
        may_provision: false,
        dns: {
          ok: false,
          authoritative: true,
          blocking_reason:
            'DNS not ready for: acme.example.com (resolves to 198.51.100.4, expected 203.0.113.10)',
          checks: [],
        },
      }),
    ])
    expect(w.text()).toContain('resolves to 198.51.100.4')
    expect(w.text()).toContain('expected 203.0.113.10')
  })
})
