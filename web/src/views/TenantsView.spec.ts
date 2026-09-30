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
    display_name: 'Acme Corporation',
    has_display_name: true,
    schema_name: 'tenant_acme',
    state: 'awaiting_dns',
    admits_logins: false,
    gate_cleared: true,
    requested_here: true,
    created_at: '',
    state_since: '',
    state_by: '',
    state_note: '',
    base_domain: 'example.com',
    address: '203.0.113.10',
    initial_admin: 'a@acme.test',
    requested_by: 'ten@x',
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

  it('uses the REGISTRY vocabulary, not an invented one', async () => {
    // `verified` and `failed` were this console's own states and are gone: the
    // registry is the single source and the doors compare against its values.
    const w = await view([row({ state: 'suspended', admits_logins: false, may_provision: false })])
    const pill = w.findAll('.pill').find((p) => p.text().includes('suspended'))
    expect(pill!.classes()).toContain('warn')
  })

  it('reports logins from admits_logins, which only live sets', async () => {
    const live = await view([row({ state: 'live', admits_logins: true, may_provision: false })])
    expect(live.text()).toContain('admitted')
    const susp = await view([row({ state: 'suspended', admits_logins: false, may_provision: false })])
    expect(susp.text()).toContain('refused')
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


describe('the human-readable name', () => {
  it('is what the row leads with, while the id stays visible', async () => {
    // The label is what a human recognises; the id is what every other system uses.
    // Hiding the id would make the page useless for the operations it exists for.
    const w = await view([row({ display_name: 'Acme Corporation', has_display_name: true })])
    expect(w.text()).toContain('Acme Corporation')
    expect(w.text()).toContain('acme')
  })

  it('falls back to the id when unset, without pretending it is a name', async () => {
    const w = await view([row({ display_name: 'acme', has_display_name: false })])
    expect(w.text()).toContain('acme')
  })
})

describe('tenants that predate this console', () => {
  it('are listed, and are not offered a DNS check they cannot pass', async () => {
    // THE regression this file now guards: the page listed only tenants requested
    // here, so a deployment with seventy live ones showed nothing. And a tenant with
    // no recorded base domain has nothing to check its DNS against.
    const w = await view([
      row({
        tenant_id: 'default', display_name: 'default', has_display_name: false,
        state: 'live', admits_logins: true, may_provision: false,
        requested_here: false, base_domain: '', address: '', records: [],
      }),
    ])
    expect(w.text()).toContain('default')
    expect(w.findAll('button').some((b) => b.text() === 'Check DNS')).toBe(false)
    // But it CAN be given a human-readable name, which is the main reason to reach
    // for this page on an established estate.
    expect(w.findAll('button').some((b) => b.text() === 'Name')).toBe(true)
  })
})
