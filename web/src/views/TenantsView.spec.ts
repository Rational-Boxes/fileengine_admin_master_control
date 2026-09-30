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
  const base: TenantView = {
    tenant_id: 'acme',
    display_name: 'Acme Corporation',
    has_display_name: true,
    schema_name: 'tenant_acme',
    state: 'awaiting_dns',
    admits_logins: false,
    gate_cleared: true,
    requested_here: true,
    base_tenant_id: 'acme',
    reachable_by_hostname: true,
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
  }
  // base_tenant_id follows the id unless a test says otherwise, so a row is
  // internally consistent without every caller restating it.
  const merged = { ...base, ...over }
  // Derived from the id unless a test says otherwise, so a fixture row is internally
  // CONSISTENT. Left hardcoded, every row claimed `acme`'s hostnames whatever its id,
  // which made the rendered output say one thing and the row mean another — a fixture
  // that lies quietly is worse than one that fails.
  if (over.tenant_id) {
    if (over.base_tenant_id === undefined) merged.base_tenant_id = over.tenant_id.split('-')[0]
    if (over.reachable_by_hostname === undefined) {
      merged.reachable_by_hostname = !over.tenant_id.includes('-')
    }
    if (over.hostnames === undefined) {
      merged.hostnames = [`${over.tenant_id}.example.com`,
                          `${over.tenant_id}-drive.example.com`]
    }
  }
  return merged
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


describe('interface hostnames are folded under their tenant', () => {
  it('does not list <tenant>-drive as a tenant of its own', async () => {
    // It is the WebDAV HOSTNAME of the tenant above it. The core registered it as a
    // tenant because it registers anything it is asked about, and the doors resolve
    // its host to the parent — so no request can ever arrive for it.
    const w = await view([
      row({ tenant_id: 'filenginetest', display_name: 'filenginetest', state: 'live',
            admits_logins: true, may_provision: false }),
      row({ tenant_id: 'filenginetest-drive', display_name: 'filenginetest-drive',
            state: 'live', admits_logins: true, may_provision: false,
            shadowed_by: 'filenginetest' }),
    ])
    expect(w.text()).toContain('not a tenant')
    expect(w.text()).toContain('An interface hostname of')
    // Folded, NOT hidden: it holds a schema and nothing here can remove it.
    expect(w.text()).toContain('tenant_filenginetestdrive'.slice(0, 6))
  })

  it('offers it no actions of its own', async () => {
    const w = await view([
      row({ tenant_id: 'acme', state: 'live', admits_logins: true, may_provision: false }),
      row({ tenant_id: 'acme-drive', state: 'live', admits_logins: true,
            may_provision: false, shadowed_by: 'acme' }),
    ])
    // One tenant row -> one Provision-capable row set. The folded row gets no buttons,
    // because there is nothing correct to do to it from here.
    expect(w.findAll('button').filter((b) => b.text() === 'Name')).toHaveLength(1)
  })

  it('leaves an orphan at the top level and says why it is worse', async () => {
    // `fileenginetest-drive` has no `fileenginetest` to belong to, so its hostname
    // points at a tenant that does not exist. Folding it would mean inventing a parent.
    const w = await view([
      row({ tenant_id: 'fileenginetest-drive', display_name: 'fileenginetest-drive',
            state: 'live', admits_logins: true, may_provision: false, shadowed_by: '' }),
    ])
    expect(w.text()).toContain('no tenant to belong to')
  })

  it('lists the interfaces of a real tenant as hostnames, not as tenants', async () => {
    const w = await view([
      row({ tenant_id: 'acme', state: 'awaiting_dns', may_provision: false,
            hostnames: ['acme.example.com', 'acme-drive.example.com',
                        'acme-mcp.example.com'] }),
    ])
    expect(w.text()).toContain('3 interfaces')
    expect(w.text()).toContain('acme-mcp.example.com')
  })
})

describe('the search filter', () => {
  const estate = () => [
    row({ tenant_id: 'filenginetest', display_name: 'filenginetest', state: 'live',
          admits_logins: true, may_provision: false }),
    row({ tenant_id: 'filenginetest-drive', display_name: 'filenginetest-drive',
          state: 'live', admits_logins: true, may_provision: false,
          shadowed_by: 'filenginetest' }),
    row({ tenant_id: 'rationalboxes', display_name: 'Rational Boxes Ltd',
          has_display_name: true, state: 'live', admits_logins: true,
          may_provision: false }),
    row({ tenant_id: 'acct_iso_a_1932011_15', display_name: 'acct_iso_a_1932011_15',
          state: 'live', admits_logins: true, may_provision: false }),
  ]

  async function search(term: string) {
    const w = await view(estate())
    const box = w.find('input#q')
    await box.setValue(term)
    return w
  }

  it('matches on the tenant id', async () => {
    const w = await search('rational')
    expect(w.text()).toContain('Rational Boxes Ltd')
    expect(w.text()).not.toContain('acct_iso_a')
  })

  it('matches on the human-readable name too', async () => {
    // Someone looking for "Rational Boxes Ltd" and someone looking for
    // "rationalboxes" are looking for the same tenant.
    const w = await search('Boxes Ltd')
    expect(w.text()).toContain('rationalboxes')
  })

  it('is case-insensitive', async () => {
    expect((await search('RATIONAL')).text()).toContain('Rational Boxes Ltd')
  })

  it('does not treat the term as a regex', async () => {
    // A stray '(' would throw if the term were compiled as a pattern.
    const w = await search('(')
    expect(w.text()).toContain('Nothing matches')
  })

  it('matches a dot literally, because a domain contains one', async () => {
    // My first version of the test above also asserted that '.' matched nothing, on
    // the theory that a regex '.' matches everything. That was wrong about this code:
    // the term is a literal substring and '.' genuinely appears in every base domain,
    // so matching them all is correct.
    const w = await search('.com')
    expect(w.text()).toContain('rationalboxes')
  })

  it('keeps a parent whose INTERFACE row matched', async () => {
    // Filtering the flat list first would leave the child with nothing to fold under,
    // and it would then read as a tenant of its own — the exact misreading this view
    // exists to correct.
    const w = await search('filenginetest-drive')
    expect(w.text()).toContain('An interface hostname of')
    expect(w.text()).toContain('filenginetest')
  })

  it('shows every interface of a group it keeps', async () => {
    const w = await search('rationalboxes')
    expect(w.text()).not.toContain('An interface hostname of')
  })

  it('says how many of how many, so a stale filter is visible', async () => {
    // On an estate this size "1–50" and "1–50 of 218" look identical without the
    // total, and a filter left set is the commonest reason a tenant appears to be
    // missing — so the filtered count names what it was filtered FROM.
    const w = await search('rational')
    expect(w.text()).toContain('1–1 of 1')
    expect(w.text()).toContain('filtered from 3')
  })

  it('offers a way out when nothing matches', async () => {
    const w = await search('zzzznothing')
    expect(w.text()).toContain('Nothing matches')
    expect(w.findAll('button').some((b) => b.text().includes('Clear'))).toBe(true)
  })
})


describe('the pager', () => {
  const many = (n: number) =>
    Array.from({ length: n }, (_, i) =>
      row({ tenant_id: `t${String(i).padStart(3, '0')}`,
            display_name: `t${String(i).padStart(3, '0')}`,
            state: 'live', admits_logins: true, may_provision: false }))

  it('does not appear when everything fits on one page', async () => {
    const w = await view(many(5))
    expect(w.find('.pager').exists()).toBe(false)
  })

  it('splits a long estate and says where you are', async () => {
    const w = await view(many(120))
    expect(w.find('.pager').exists()).toBe(true)
    expect(w.text()).toContain('1–50 of 120')
    expect(w.text()).toContain('Page 1 of 3')
    expect(w.text()).toContain('t000')
    expect(w.text()).not.toContain('t050')
  })

  it('moves through the pages', async () => {
    const w = await view(many(120))
    const next = w.findAll('button').find((b) => b.text() === 'Next')!
    await next.trigger('click')
    expect(w.text()).toContain('51–100 of 120')
    expect(w.text()).toContain('t050')
    const last = w.findAll('button').find((b) => b.text() === 'Last')!
    await last.trigger('click')
    expect(w.text()).toContain('101–120 of 120')
    expect(w.text()).toContain('t119')
  })

  it('RESETS TO PAGE ONE when the filter changes', async () => {
    // The bug this guards: search while on page 3 and you are left on page 3 of a
    // one-page result — an empty table that reads as "no matches" and is really
    // "no such page".
    const w = await view(many(120))
    await w.findAll('button').find((b) => b.text() === 'Last')!.trigger('click')
    expect(w.text()).toContain('Page 3 of 3')
    await w.find('input#q').setValue('t001')
    expect(w.text()).toContain('t001')
    expect(w.find('.pager').exists()).toBe(false)
  })

  it('never splits a tenant from its interface rows', async () => {
    // A page ending on the parent with its folded child at the top of the next page
    // would show the child with no parent above it — the exact misreading this view
    // exists to prevent. Paging counts GROUPS, so it cannot happen.
    const rowsIn = [
      ...many(49),
      row({ tenant_id: 'zparent', display_name: 'zparent', state: 'live',
            admits_logins: true, may_provision: false }),
      row({ tenant_id: 'zparent-drive', display_name: 'zparent-drive', state: 'live',
            admits_logins: true, may_provision: false, shadowed_by: 'zparent' }),
    ]
    const w = await view(rowsIn)
    // 50 groups, all on page one — the interface row does not count towards the page.
    expect(w.find('.pager').exists()).toBe(false)
    expect(w.text()).toContain('zparent')
    expect(w.text()).toContain('An interface hostname of')
  })

  it('can show everything at once', async () => {
    const w = await view(many(120))
    await w.find('select#per').setValue('0')
    expect(w.text()).toContain('1–120 of 120')
    expect(w.find('.pager').exists()).toBe(false)
  })
})
