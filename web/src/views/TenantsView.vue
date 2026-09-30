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

const form = ref({ tenant_id: '', base_domain: '', address: '', initial_admin: '',
                   display_name: '' })

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
      display_name: form.value.display_name.trim(),
    })
    form.value = { tenant_id: '', base_domain: '', address: '', initial_admin: '',
                   display_name: '' }
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

async function rename(t: TenantView) {
  // The LABEL only. tenant_id reaches a hostname, a Postgres schema, an LDAP DN and
  // a file path, so it is immutable — an organisation renaming itself must not move
  // its data. The prompt says so, because "rename" invites the other expectation.
  const name = window.prompt(
    `Human-readable name for ${t.tenant_id}.\n\n` +
      'Used for billing and high-level operations. The tenant id itself does not ' +
      'change — nothing is keyed on this.',
    t.has_display_name ? t.display_name : '',
  )
  if (name === null) return
  await act(t.tenant_id, () => tenants.setDisplayName(t.tenant_id, name))
}

function stateClass(state: string) {
  // The REGISTRY's vocabulary, which is the one the doors compare against.
  if (state === 'live') return 'ok'
  if (state === 'decommissioned') return 'bad'
  // `awaiting_dns` and `requested` are WAITING, not broken: records that have not
  // propagated are not a fault, and red would send someone looking for a problem
  // that does not exist. `suspended` and `decommissioning` are deliberate acts, so
  // they are flagged without being errors either.
  if (state === 'awaiting_dns' || state === 'requested' || state === 'suspended'
      || state === 'decommissioning' || state === 'provisioning') return 'warn'
  return ''
}
</script>

<template>
  <div>
    <div class="head">
      <div>
        <h1>Tenants</h1>
        <p class="sub">
          Every tenant in the registry — the core's <span class="mono">public.tenants</span>,
          the same rows the doors read. Most predate this console and simply have no
          creation details recorded here; that is normal. New ones are requested here
          and provisioned by a runner, which holds the credentials this console does not.
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
          <label for="dname">Name (optional)</label>
          <input id="dname" v-model="form.display_name" placeholder="Acme Corporation Ltd" />
          <p class="hint">
            What a human calls them, for billing and high-level operations. Free text,
            changeable later, and never used to look anything up.
          </p>
        </div>
      </div>
      <div class="pair">
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
          <th>Logins</th>
          <th>DNS</th>
          <th v-if="mayAct" class="actions">Actions</th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="t in rows" :key="t.tenant_id">
          <td>
            <RouterLink :to="`/tenants/${t.tenant_id}`" class="tid">
              {{ t.display_name }}
            </RouterLink>
            <!-- The IDENTIFIER, always shown, in mono, even when a label exists. The
                 label is what a human recognises and the id is what everything else
                 uses; hiding the id would make the page unusable for the operations
                 it exists for. -->
            <div class="muted small mono">{{ t.tenant_id }}</div>
            <div v-if="t.base_domain" class="muted small">
              {{ t.base_domain }} → {{ t.address }}
            </div>
          </td>
          <td>
            <span class="pill" :class="stateClass(t.state)">{{ t.state.replace('_', ' ') }}</span>
            <div v-if="t.override" class="muted small ovr">
              overridden by {{ t.override.by }}
            </div>
          </td>
          <td>
            <!-- Derived from the registry state, not guessed: only `live` admits. -->
            <span class="pill" :class="t.admits_logins ? 'ok' : ''">
              {{ t.admits_logins ? 'admitted' : 'refused' }}
            </span>
          </td>
          <td class="dns">
            <template v-if="t.dns">
              <span v-if="t.dns.ok" class="pill ok">verified</span>
              <div v-else class="muted small">{{ t.dns.blocking_reason }}</div>
            </template>
            <span v-else class="muted small">not checked</span>
          </td>
          <td v-if="mayAct" class="actions">
            <div class="row">
              <button class="btn secondary sm" :disabled="busy === t.tenant_id"
                      @click="rename(t)">
                Name
              </button>
              <!-- Only offered where there is something to check against. A tenant
                   that predates this console has no recorded domain, and the server
                   says so with a 409 rather than reporting a DNS failure. -->
              <button v-if="t.base_domain" class="btn secondary sm"
                      :disabled="busy === t.tenant_id"
                      @click="act(t.tenant_id, () => tenants.dnsCheck(t.tenant_id))">
                Check DNS
              </button>
              <button v-if="!t.admits_logins && t.base_domain" class="btn secondary sm"
                      :disabled="busy === t.tenant_id" @click="override(t)">
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
              <button v-if="!t.admits_logins" class="btn sm"
                      :disabled="busy === t.tenant_id || !t.may_provision"
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
