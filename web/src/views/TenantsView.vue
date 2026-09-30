<!--
  Copyright (C) 2026 James Hickman
  SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { RouterLink } from 'vue-router'
import { apiError } from '@/services/client'
import { tenants, type TenantView } from '@/services/api'
import { SYSTEM_TENANTS, useSession } from '@/stores/session'

const s = useSession()
const rows = ref<TenantView[]>([])
const error = ref('')
const loading = ref(true)
const creating = ref(false)
const busy = ref('')

const form = ref({ tenant_id: '', base_domain: '', address: '', initial_admin: '' })

const mayAct = computed(() => s.has(SYSTEM_TENANTS))

onMounted(refresh)

async function refresh() {
  error.value = ''
  try {
    rows.value = await tenants.list()
  } catch (e) {
    error.value = apiError(e)
  } finally {
    loading.value = false
  }
}

async function act(id: string, fn: () => Promise<TenantView | unknown>) {
  busy.value = id
  error.value = ''
  try {
    await fn()
    await refresh()
  } catch (e) {
    error.value = apiError(e)
    // Refresh anyway: a refusal usually means the server's state is not what this
    // page thought, and leaving the stale row on screen invites the same press
    // again.
    await refresh()
  } finally {
    busy.value = ''
  }
}

async function create() {
  busy.value = 'new'
  error.value = ''
  try {
    await tenants.request({
      tenant_id: form.value.tenant_id.trim(),
      base_domain: form.value.base_domain.trim(),
      address: form.value.address.trim(),
      initial_admin: form.value.initial_admin.trim(),
    })
    form.value = { tenant_id: '', base_domain: '', address: '', initial_admin: '' }
    creating.value = false
    await refresh()
  } catch (e) {
    error.value = apiError(e)
  } finally {
    busy.value = ''
  }
}

async function override(t: TenantView) {
  // A prompt, and not a nicety: the server requires a reason and refuses an empty
  // one, so there is no path here that skips the gate without recording why.
  const reason = window.prompt(
    `Override the DNS check for ${t.tenant_id}?\n\n` +
      'This is the one action that can exhaust certificate issuance for EVERY ' +
      'tenant on this domain, so it is recorded against your name.\n\n' +
      'Why are you sure DNS is ready?',
  )
  if (!reason) return
  await act(t.tenant_id, () => tenants.dnsOverride(t.tenant_id, reason))
}

function stateClass(state: string) {
  if (state === 'live') return 'ok'
  if (state === 'failed') return 'bad'
  // `awaiting_dns` and `requested` are WAITING, not broken. Colouring them red
  // would report a tenant whose records simply have not propagated as an error.
  if (state === 'awaiting_dns' || state === 'requested') return 'warn'
  return ''
}
</script>

<template>
  <div>
    <div class="head">
      <div>
        <h1>Tenants</h1>
        <p class="sub">
          Requested here, provisioned by a runner. This console holds no DNS
          credential and runs no playbook — it records what was asked and hands the
          runner a job.
        </p>
      </div>
      <button v-if="mayAct" class="btn" @click="creating = !creating">
        {{ creating ? 'Cancel' : 'Request a tenant' }}
      </button>
    </div>

    <div v-if="error" class="notice bad">{{ error }}</div>

    <form v-if="creating" class="card new" @submit.prevent="create">
      <h2>New tenant</h2>
      <div class="pair">
        <div class="field">
          <label for="tid">Tenant id</label>
          <input id="tid" v-model="form.tenant_id" placeholder="acme" autofocus />
          <p class="hint">
            Lower-case letters, digits and hyphens. It becomes a hostname, a
            Postgres schema and an LDAP entry, so it is validated strictly and
            cannot be changed afterwards.
          </p>
        </div>
        <div class="field">
          <label for="dom">Base domain</label>
          <input id="dom" v-model="form.base_domain" placeholder="example.com" />
        </div>
      </div>
      <div class="pair">
        <div class="field">
          <label for="addr">Address the hostnames must point at</label>
          <input id="addr" v-model="form.address" placeholder="203.0.113.10" />
        </div>
        <div class="field">
          <label for="admin">First administrator</label>
          <input id="admin" v-model="form.initial_admin" placeholder="admin@acme.example" />
          <p class="hint">A tenant with no administrator is a tenant nobody can manage.</p>
        </div>
      </div>
      <button class="btn" type="submit" :disabled="busy === 'new'">
        {{ busy === 'new' ? 'Requesting…' : 'Request' }}
      </button>
    </form>

    <p v-if="loading" class="empty">Loading…</p>
    <p v-else-if="!rows.length" class="empty">No tenant requests on record.</p>

    <table v-else class="card">
      <thead>
        <tr>
          <th>Tenant</th>
          <th>State</th>
          <th>DNS</th>
          <th>Requested by</th>
          <th v-if="mayAct" class="actions">Actions</th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="t in rows" :key="t.tenant_id">
          <td>
            <RouterLink :to="`/tenants/${t.tenant_id}`" class="tid">{{ t.tenant_id }}</RouterLink>
            <div class="muted small">{{ t.base_domain }} → {{ t.address }}</div>
          </td>
          <td>
            <span class="pill" :class="stateClass(t.state)">{{ t.state.replace('_', ' ') }}</span>
            <div v-if="t.override" class="muted small ovr">
              overridden by {{ t.override.by }}
            </div>
          </td>
          <td class="dns">
            <template v-if="t.dns">
              <span v-if="t.dns.ok" class="pill ok">verified</span>
              <div v-else class="muted small">{{ t.dns.blocking_reason }}</div>
            </template>
            <span v-else class="muted small">not checked</span>
          </td>
          <td class="muted small">{{ t.requested_by }}</td>
          <td v-if="mayAct" class="actions">
            <div class="row">
              <button class="btn secondary sm" :disabled="busy === t.tenant_id"
                      @click="act(t.tenant_id, () => tenants.dnsCheck(t.tenant_id))">
                Check DNS
              </button>
              <button class="btn secondary sm" :disabled="busy === t.tenant_id || t.state === 'live'"
                      @click="override(t)">
                Override
              </button>
              <!--
                THE GATE. `:disabled` is bound to `t.may_provision` — the SERVER'S
                judgement, carried in the response — and never to a condition
                computed here. A local `state === 'verified' || override` looks
                identical and is a second implementation of the rule that protects
                a rate limit shared by every tenant on the domain; when the two
                disagree the button is enabled and the server is right.

                Disabling it is a courtesy, not the control: the server claims the
                request with one conditional UPDATE, so a double-click or a stale
                page cannot queue two runs.
              -->
              <button class="btn sm" :disabled="busy === t.tenant_id || !t.may_provision"
                      :title="t.may_provision
                        ? 'Hand a provisioning job to the runner'
                        : 'The DNS gate has not passed and has not been overridden'"
                      @click="act(t.tenant_id, () => tenants.provision(t.tenant_id))">
                Provision
              </button>
            </div>
          </td>
        </tr>
      </tbody>
    </table>
  </div>
</template>

<style scoped>
.head {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: 1rem;
}
.new {
  margin-bottom: 1.25rem;
}
.pair {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
  gap: 0 1rem;
}
.hint {
  color: var(--muted);
  font-size: 0.75rem;
  margin: 0.3rem 0 0;
  line-height: 1.45;
}
.small {
  font-size: 0.78rem;
}
.ovr {
  margin-top: 0.25rem;
}
.tid {
  color: var(--primary);
  text-decoration: none;
  font-weight: 500;
}
.tid:hover {
  text-decoration: underline;
}
.dns {
  max-width: 34ch;
  line-height: 1.45;
}
.actions {
  white-space: nowrap;
}
.btn.sm {
  padding: 0.3rem 0.6rem;
  font-size: 0.82rem;
}
</style>
