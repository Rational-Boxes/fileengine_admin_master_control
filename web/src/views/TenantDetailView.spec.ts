// Copyright (C) 2026 James Hickman <james@rationalboxes.com>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

// Suspend / resume from the status, where the state is shown (§3.4b's reversible
// phase). Choosing a different status never acts by itself: it opens a panel that
// asks for a reason and — to suspend — the tenant id typed.
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'

vi.mock('vue-router', () => ({ useRoute: () => ({ params: { id: 'acme' } }) }))

import TenantDetailView from './TenantDetailView.vue'
import { tenants, type TenantView } from '@/services/api'
import { SYSTEM_OBSERVER, SYSTEM_TENANTS, useSession } from '@/stores/session'

function tenant(over: Partial<TenantView> = {}): TenantView {
  return {
    tenant_id: 'acme', display_name: 'Acme', has_display_name: true,
    schema_name: 'tenant_acme', state: 'live', admits_logins: true, gate_cleared: true,
    requested_here: false, base_tenant_id: 'acme', reachable_by_hostname: true,
    created_at: '', state_since: '', state_by: '', state_note: '',
    base_domain: 'example.com', address: '203.0.113.10', initial_admin: '',
    requested_by: '', hostnames: [], records: [], may_provision: false,
    ...over,
  } as TenantView
}

const stubs = { RouterLink: { template: '<a><slot /></a>' } }

async function view(t: TenantView, roles = [SYSTEM_OBSERVER, SYSTEM_TENANTS]) {
  setActivePinia(createPinia())
  useSession().adopt({ token: 't', subject: 'ten@x', roles, amr: ['pwd', 'totp'] })
  vi.spyOn(tenants, 'get').mockResolvedValue(t)
  const w = mount(TenantDetailView, { global: { stubs } })
  await flushPromises()
  return w
}

beforeEach(() => {
  vi.restoreAllMocks()
})

describe('the status control', () => {
  it('is a dropdown for system_tenants on a live tenant', async () => {
    const w = await view(tenant())
    const sel = w.find('select[aria-label="Tenant status"]')
    expect(sel.exists()).toBe(true)
    expect(sel.findAll('option').map((o) => o.element.value)).toEqual(['live', 'suspended'])
  })

  it('is a plain status for an observer', async () => {
    const w = await view(tenant(), [SYSTEM_OBSERVER])
    expect(w.find('select[aria-label="Tenant status"]').exists()).toBe(false)
    expect(w.text()).toContain('live')
  })

  it('is a plain status in a state this operation does not move', async () => {
    const w = await view(tenant({ state: 'provisioning', admits_logins: false }))
    expect(w.find('select[aria-label="Tenant status"]').exists()).toBe(false)
  })

  it('choosing suspended does nothing until confirmed', async () => {
    const set = vi.spyOn(tenants, 'setState')
    const w = await view(tenant())
    await w.find('select[aria-label="Tenant status"]').setValue('suspended')
    expect(set).not.toHaveBeenCalled()
    expect(w.text()).toContain('Suspend acme')
  })

  it('suspends only with a reason and the id typed', async () => {
    const set = vi.spyOn(tenants, 'setState')
      .mockResolvedValue(tenant({ state: 'suspended', admits_logins: false }))
    const w = await view(tenant())
    await w.find('select[aria-label="Tenant status"]').setValue('suspended')
    const go = () => w.find('button[data-test="apply-state"]')
    expect(go().attributes('disabled')).toBeDefined()
    await w.find('textarea[data-test="state-reason"]').setValue('unpaid invoice')
    expect(go().attributes('disabled')).toBeDefined()
    await w.find('input[data-test="state-confirm"]').setValue('other')
    expect(go().attributes('disabled')).toBeDefined()
    await w.find('input[data-test="state-confirm"]').setValue('acme')
    expect(go().attributes('disabled')).toBeUndefined()
    await go().trigger('click')
    await flushPromises()
    expect(set).toHaveBeenCalledWith('acme', 'suspended', 'unpaid invoice', 'acme')
    expect(w.text()).toContain('logins refused')
  })

  it('resumes with a reason and no typed id', async () => {
    const set = vi.spyOn(tenants, 'setState')
      .mockResolvedValue(tenant({ state: 'live', admits_logins: true }))
    const w = await view(tenant({ state: 'suspended', admits_logins: false }))
    await w.find('select[aria-label="Tenant status"]').setValue('live')
    expect(w.find('input[data-test="state-confirm"]').exists()).toBe(false)
    await w.find('textarea[data-test="state-reason"]').setValue('invoice paid')
    await w.find('button[data-test="apply-state"]').trigger('click')
    await flushPromises()
    expect(set).toHaveBeenCalledWith('acme', 'live', 'invoice paid', '')
  })

  it('cancel puts the dropdown back', async () => {
    const w = await view(tenant())
    const sel = w.find('select[aria-label="Tenant status"]')
    await sel.setValue('suspended')
    await w.find('button[data-test="cancel-state"]').trigger('click')
    expect((sel.element as HTMLSelectElement).value).toBe('live')
    expect(w.text()).not.toContain('Suspend acme')
  })
})
