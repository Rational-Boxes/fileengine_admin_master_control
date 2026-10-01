<!--
  Copyright (C) 2026 James Hickman
  SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue'
import { RouterLink } from 'vue-router'
import { apiError } from '@/services/client'
import { tenants, type TenantView } from '@/services/api'
import { SYSTEM_OBSERVER, SYSTEM_TENANTS, useSession } from '@/stores/session'

const s = useSession()
const rows = ref<TenantView[]>([])
const error = ref('')
const loading = ref(true)
// Whether the LAST load failed. Distinct from an empty result: a failed request
// leaves `rows` empty too, and the empty-registry message then sends an operator
// to debug a database connection that is fine (production, 2026-10-01).
const loadFailed = ref(false)
const creating = ref(false)
const busy = ref('')

const form = ref({ tenant_id: '', base_domain: '', address: '', initial_admin: '',
                   display_name: '' })

const query = ref('')
const stateFilter = ref('')
const pageSize = ref(50)
const page = ref(1)

// RESET TO PAGE ONE WHENEVER THE FILTER CHANGES. Without this, typing a search while
// on page 5 leaves you on page 5 of a one-page result — an empty table that looks
// like "no matches" and is really "no such page". The same applies to changing the
// page size, which can shrink the number of pages under your feet.
watch([query, stateFilter, pageSize], () => {
  page.value = 1
})

/** Plain substring matching, not a regex.
 *
 * `String.includes` on a lower-cased needle: a tenant id or a company name typed into
 * a box is not a pattern, and treating it as one would make a stray `(` throw and a
 * `.` match everything. Matches the IDENTIFIER and the LABEL both, because someone
 * looking for "Rational Boxes Ltd" and someone looking for "rationalboxes" are both
 * looking for the same tenant.
 */
function matches(t: TenantView): boolean {
  if (stateFilter.value && t.state !== stateFilter.value) return false
  const q = query.value.trim().toLowerCase()
  if (!q) return true
  return (
    t.tenant_id.toLowerCase().includes(q) ||
    t.display_name.toLowerCase().includes(q) ||
    t.base_domain.toLowerCase().includes(q)
  )
}

/** The states actually present, so the filter offers nothing that returns zero rows. */
const statesPresent = computed(() =>
  [...new Set(rows.value.map((t) => t.state))].sort(),
)

const mayAct = computed(() => s.has(SYSTEM_TENANTS))
// Running a check is an OBSERVER act on the server (POST /tenants/{id}/verify), so
// it is offered on that role — not on mayAct, which would hide it from the people
// the API already lets press it.
const mayCheck = computed(() => s.has(SYSTEM_OBSERVER))

/** Tenants, with interface-shaped rows FOLDED UNDER the tenant they belong to.
 *
 * `filenginetest-drive` is not a tenant. It is the WebDAV HOSTNAME of tenant
 * `filenginetest`, which the core registered as a tenant because it auto-registers
 * anything it is asked about — so browsing to that host created one. The doors split
 * the leading DNS label on '-' and keep the first segment, so no request can ever
 * arrive for it: the row and its schema are real, but the tenant is not.
 *
 * Folded rather than hidden. An unreachable schema that may hold data is exactly what
 * this console exists to surface, and there is no button here that could remove it —
 * decommissioning is a later phase behind its own re-authentication.
 *
 * The suffix is not a fixed list. The bridge treats everything after the first hyphen
 * as an interface (`acme-staging` resolves to `acme` too), and each interface is a
 * real subdomain with its own A record and its own certificate — which is why the set
 * is configured server-side and this view only groups what it is told.
 */
/** Every tenant, grouped, before any filter. The denominator in "showing X of Y". */
const allGroups = computed(() => {
  const byId = new Map(rows.value.map((t) => [t.tenant_id, t]))
  const children = new Map<string, TenantView[]>()
  const top: TenantView[] = []
  for (const t of rows.value) {
    if (!t.reachable_by_hostname && byId.has(t.base_tenant_id)) {
      const list = children.get(t.base_tenant_id) ?? []
      list.push(t)
      children.set(t.base_tenant_id, list)
    } else {
      top.push(t)
    }
  }
  return top.map((t) => ({ tenant: t, folded: children.get(t.tenant_id) ?? [] }))
})

/** The interface subdomains of one tenant, each with its own DNS verdict.
 *
 * Folded under the tenant's main subdomain because that is what they are — one tenant
 * served on several hostnames, `<tenant>` and `<tenant>-<interface>`, all resolving
 * back to the same tenant.
 *
 * But each is a SEPARATE SUBDOMAIN needing its own A record and its own certificate,
 * so each carries its own verdict rather than inheriting the tenant's. A single
 * "DNS: not ready" on the parent hides which hostname is missing, and the causes need
 * opposite responses: "no record" improves by waiting, a wrong address never does.
 */
function interfacesOf(t: TenantView) {
  const dns = new Map((t.dns?.checks ?? []).map((c) => [c.hostname, c]))
  const tls = new Map((t.tls?.checks ?? []).map((c) => [c.hostname, c]))
  return t.hostnames.map((host, i) => ({
    host,
    // The label after the hyphen, or "tenant" for the bare host. Derived from the
    // hostname rather than from a list of known suffixes, because the estate's rule is
    // a split: anything after the first hyphen is an interface.
    role: i === 0 ? 'tenant' : host.split('.')[0].split('-').slice(1).join('-'),
    check: dns.get(host) ?? null,
    cert: tls.get(host) ?? null,
  }))
}

/** How to colour a certificate state.
 *
 * `expiring` is AMBER, not green and not red: it is serving and the thing that should
 * have renewed it has already missed several chances. Green would hide a fault that has
 * a deadline; red would say the site is down when it is not. `absent` is neutral,
 * because before provisioning it is simply the truth.
 */
function certClass(state: string) {
  if (state === 'valid') return 'ok'
  if (state === 'expiring' || state === 'untrusted') return 'warn'
  if (state === 'expired' || state === 'wrong_host') return 'bad'
  return ''
}

function certLabel(c: { state: string; days_remaining: number | null }) {
  if (c.state === 'valid' && c.days_remaining !== null) return `${c.days_remaining}d`
  if (c.state === 'expiring' && c.days_remaining !== null) return `${c.days_remaining}d left`
  return c.state.replace(/_/g, ' ')
}

/** The filtered view.
 *
 * FILTERED AFTER GROUPING, and a group is kept when the parent OR any of its interface
 * rows match. Filtering the flat list first would strip a parent whose child matched
 * and leave that child with nothing to fold under — so searching "filenginetest-drive"
 * would either show it as a top-level tenant, which is the misreading this whole view
 * exists to correct, or drop it entirely.
 *
 * Once a group is kept, ALL of its interfaces are shown: hiding one for not matching
 * the text would misreport how many hostnames a tenant has.
 */
const grouped = computed(() =>
  allGroups.value.filter((g) => matches(g.tenant) || g.folded.some(matches)),
)

/** Pagination over the GROUPS, not the rows.
 *
 * A page boundary must never fall between a tenant and its interface rows — a page
 * ending on `filenginetest` with `filenginetest-drive` at the top of the next one
 * would show the folded row with no parent above it, which is exactly the reading this
 * view exists to prevent. Counting groups makes that impossible rather than unlikely.
 *
 * 0 means "all": with 218 tenants a single page is slow to scan but sometimes it is
 * what you want, and the choice costs nothing.
 */
const pageCount = computed(() =>
  pageSize.value === 0 ? 1 : Math.max(1, Math.ceil(grouped.value.length / pageSize.value)),
)

const paged = computed(() => {
  if (pageSize.value === 0) return grouped.value
  // Clamped rather than trusted: a stale `page` after a filter change would otherwise
  // slice past the end and render nothing.
  const current = Math.min(page.value, pageCount.value)
  const from = (current - 1) * pageSize.value
  return grouped.value.slice(from, from + pageSize.value)
})

const firstShown = computed(() =>
  grouped.value.length === 0 ? 0
    : pageSize.value === 0 ? 1
      : (Math.min(page.value, pageCount.value) - 1) * pageSize.value + 1,
)
const lastShown = computed(() => firstShown.value + paged.value.length - 1)

/** Unreachable rows with no tenant to fold under — a worse case, and a different one.
 *
 * `fileenginetest-drive` (note the spelling) has no `fileenginetest` to belong to, so
 * its hostname points at a tenant that does not exist. Left at the top level, because
 * folding it somewhere would be inventing a parent.
 */
const orphans = computed(() =>
  rows.value.filter((t) => !t.reachable_by_hostname && !t.shadowed_by),
)

onMounted(refresh)

async function refresh() {
  error.value = ''
  try {
    rows.value = await tenants.list()
    loadFailed.value = false
  } catch (e) {
    error.value = apiError(e)
    loadFailed.value = true
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

    <!-- ABOVE the v-if/v-else chain below, and that placement is load-bearing.
         Sitting between `<p v-if="loading">` and `<table v-else>`, this `v-if` STOLE
         the `v-else`: Vue pairs v-else with its immediately preceding conditional, so
         the table rendered only when there were no orphans — and with one orphan in
         the registry the whole list vanished while every filter and count still said
         it was there. Nothing catches that at build time. -->
    <p v-if="orphans.length" class="notice warn">
      {{ orphans.length }} registry row{{ orphans.length === 1 ? '' : 's' }}
      {{ orphans.length === 1 ? 'has' : 'have' }} an interface-shaped id with no tenant
      to belong to — their hostnames resolve to a tenant that does not exist, so nothing
      can reach them. They hold a schema and cannot be removed from here.
    </p>

    <!-- EVERY ONE OF THESE STATES ITS OWN CONDITION. No `v-else` anywhere in this
         group, deliberately: `v-else` binds to whatever conditional immediately
         precedes it, so inserting any sibling in the middle silently re-parents it. I
         did that twice — once with the orphan notice and once with the filter row —
         and the second time the table rendered only when the list was EMPTY, while
         every count above it still reported the tenants correctly. Nothing catches it
         at build time, and it reads as "no tenants" rather than as a broken template.

         Spelling the conditions out costs a few repeated clauses and makes the group
         insertion-proof. -->
    <p v-if="loading" class="empty">Loading…</p>
    <p v-if="!loading && loadFailed && !rows.length" class="empty">
      The tenant list could not be loaded<template v-if="error"> — {{ error }}</template>.
      This is not an empty registry; try again, or sign in again if your session has
      expired.
    </p>
    <p v-if="!loading && !loadFailed && !rows.length" class="empty">
      No tenants in the registry. If the estate is not empty, check that
      AMC_CORE_PG_* points at the core's database.
    </p>
    <p v-if="!loading && rows.length && !grouped.length" class="empty">
      Nothing matches. <button class="link" @click="query = ''; stateFilter = ''">Clear
      the filter</button> to see all {{ rows.length }}.
    </p>

    <div v-if="!loading && rows.length" class="row filters">
      <div class="field grow">
        <label for="q">Search</label>
        <input id="q" v-model="query" type="search"
               placeholder="tenant id, name, or domain" />
      </div>
      <div class="field">
        <label for="st">State</label>
        <select id="st" v-model="stateFilter">
          <option value="">any</option>
          <option v-for="st in statesPresent" :key="st" :value="st">
            {{ st.replace(/_/g, ' ') }}
          </option>
        </select>
      </div>
      <!-- The count is part of the filter, not decoration: on an estate of this size
           "showing 3" and "showing 218" look identical without it, and a filter left
           set is the commonest reason a tenant appears to be missing. -->
      <div class="field">
        <label for="per">Per page</label>
        <select id="per" v-model.number="pageSize">
          <option :value="25">25</option>
          <option :value="50">50</option>
          <option :value="100">100</option>
          <option :value="0">all</option>
        </select>
      </div>
      <!-- The count is part of the filter, not decoration: on an estate of this size
           "showing 3" and "showing 218" look identical without it, and a filter left
           set is the commonest reason a tenant appears to be missing. -->
      <p class="count muted">
        {{ grouped.length ? `${firstShown}–${lastShown} of ${grouped.length}` : '0' }}
        <template v-if="grouped.length !== allGroups.length">
          (filtered from {{ allGroups.length }})
        </template>
        <button v-if="query || stateFilter" class="link"
                @click="query = ''; stateFilter = ''">clear</button>
      </p>
    </div>

    <table v-if="!loading && grouped.length" class="card">
      <thead>
        <tr>
          <th>Tenant</th>
          <th>State</th>
          <th>Logins</th>
          <th>DNS</th>
          <th>Certificate</th>
          <th v-if="mayAct" class="actions">Actions</th>
        </tr>
      </thead>
      <tbody>
        <template v-for="g in paged" :key="g.tenant.tenant_id">
          <tr>
            <td>
              <RouterLink :to="`/tenants/${g.tenant.tenant_id}`" class="tid">
                {{ g.tenant.display_name }}
              </RouterLink>
              <!-- The IDENTIFIER, always shown, even when a label exists: the label is
                   what a human recognises and the id is what every other system uses. -->
              <div class="muted small mono">{{ g.tenant.tenant_id }}</div>
              <div v-if="g.tenant.base_domain" class="muted small">
                {{ g.tenant.base_domain }} → {{ g.tenant.address }}
              </div>
            </td>
            <td>
              <span class="pill" :class="stateClass(g.tenant.state)">
                {{ g.tenant.state.replace(/_/g, ' ') }}
              </span>
              <div v-if="g.tenant.override" class="muted small ovr">
                overridden by {{ g.tenant.override.by }}
              </div>
            </td>
            <td>
              <span class="pill" :class="g.tenant.admits_logins ? 'ok' : ''">
                {{ g.tenant.admits_logins ? 'admitted' : 'refused' }}
              </span>
            </td>
            <td class="dns">
              <template v-if="g.tenant.dns">
                <span v-if="g.tenant.dns.ok" class="pill ok">verified</span>
                <div v-else class="muted small">{{ g.tenant.dns.blocking_reason }}</div>
              </template>
              <span v-else class="muted small">not checked</span>
            </td>
            <td class="dns">
              <template v-if="g.tenant.tls">
                <span class="pill" :class="g.tenant.tls.ok ? 'ok'
                  : g.tenant.tls.serving ? 'warn' : 'bad'">
                  {{ g.tenant.tls.ok ? 'valid'
                    : g.tenant.tls.serving ? 'renewal overdue' : 'not serving' }}
                </span>
                <!-- A tenant is as renewed as its LEAST renewed subdomain. -->
                <div v-if="g.tenant.tls.soonest_expiry_days !== null" class="muted small">
                  soonest expiry {{ g.tenant.tls.soonest_expiry_days }}d
                </div>
              </template>
              <span v-else class="muted small">not checked</span>
            </td>
            <td v-if="mayAct" class="actions">
              <div class="row">
                <button class="btn secondary sm" :disabled="busy === g.tenant.tenant_id"
                        @click="rename(g.tenant)">
                  Name
                </button>
                <!-- One operation for both halves: does each subdomain resolve, and is
                     each serving a trusted certificate that covers it. The separate
                     DNS-only check stays because it is the gate's input and it is what
                     gets pressed repeatedly while waiting for propagation. -->
                <button v-if="g.tenant.base_domain" class="btn secondary sm"
                        :disabled="busy === g.tenant.tenant_id"
                        title="Check DNS and certificates on every subdomain"
                        @click="act(g.tenant.tenant_id, () => tenants.verify(g.tenant.tenant_id))">
                  Verify
                </button>
                <button v-if="g.tenant.base_domain && !g.tenant.admits_logins"
                        class="btn secondary sm" :disabled="busy === g.tenant.tenant_id"
                        title="DNS only — the input to the provisioning gate"
                        @click="act(g.tenant.tenant_id, () => tenants.dnsCheck(g.tenant.tenant_id))">
                  DNS
                </button>
                <button v-if="!g.tenant.admits_logins && g.tenant.base_domain"
                        class="btn secondary sm" :disabled="busy === g.tenant.tenant_id"
                        @click="override(g.tenant)">
                  Override
                </button>
                <!--
                  THE GATE. `:disabled` is bound to `may_provision` — the SERVER'S
                  judgement, carried in the response — and never to a condition computed
                  here. A local `state === 'awaiting_dns' && gate_cleared` looks
                  identical and is a second implementation of the rule protecting a
                  certificate rate limit shared by every tenant on the domain; when the
                  two disagree the button is enabled and the server is right.

                  Disabling it is a courtesy, not the control: the server claims the
                  registry row with one conditional UPDATE, so a double click or a stale
                  page cannot queue two runs.
                -->
                <button v-if="!g.tenant.admits_logins" class="btn sm"
                        :disabled="busy === g.tenant.tenant_id || !g.tenant.may_provision"
                        :title="g.tenant.may_provision
                          ? 'Hand a provisioning job to the runner'
                          : 'The DNS gate has not passed and has not been overridden'"
                        @click="act(g.tenant.tenant_id, () => tenants.provision(g.tenant.tenant_id))">
                  Provision
                </button>
              </div>
            </td>
          </tr>
          <!-- The tenant's own subdomains, folded under it. One tenant, several
               hostnames — and each needs its own A record and its own certificate, so
               each shows its own verdict rather than inheriting the tenant's. -->
          <tr v-for="iface in interfacesOf(g.tenant)" :key="iface.host" class="iface">
            <td>
              <span class="tree" aria-hidden="true">└</span>
              <span class="mono">{{ iface.host }}</span>
              <span class="pill role">{{ iface.role }}</span>
            </td>
            <td colspan="2" class="muted small">
              its own record and certificate
            </td>
            <td class="dns">
              <template v-if="iface.check">
                <span class="pill" :class="iface.check.ok ? 'ok' : 'bad'">
                  {{ iface.check.ok ? 'ok' : 'no' }}
                </span>
                <!-- The per-hostname detail: "no record" improves by waiting, a wrong
                     address never does, and a non-authoritative answer means nothing is
                     wrong with the zone at all. -->
                <div v-if="iface.check.detail" class="muted small">
                  {{ iface.check.detail }}
                </div>
              </template>
              <!-- "not checked" is where an administrator looks, so it is where the
                   check is run: the tenant's verify, DNS and TLS on every subdomain. -->
              <button v-else-if="mayCheck" class="linkbtn small"
                      :disabled="busy === g.tenant.tenant_id"
                      title="Check DNS and certificates on every subdomain of this tenant"
                      @click="act(g.tenant.tenant_id, () => tenants.verify(g.tenant.tenant_id))">
                {{ busy === g.tenant.tenant_id ? 'checking…' : 'not checked' }}
              </button>
              <span v-else class="muted small">not checked</span>
            </td>
            <td class="dns">
              <template v-if="iface.cert">
                <span class="pill" :class="certClass(iface.cert.state)">
                  {{ certLabel(iface.cert) }}
                </span>
                <div v-if="iface.cert.detail" class="muted small">
                  {{ iface.cert.detail }}
                </div>
                <div v-else-if="iface.cert.issuer" class="muted small">
                  {{ iface.cert.issuer }}
                </div>
              </template>
              <button v-else-if="mayCheck" class="linkbtn small"
                      :disabled="busy === g.tenant.tenant_id"
                      title="Check DNS and certificates on every subdomain of this tenant"
                      @click="act(g.tenant.tenant_id, () => tenants.verify(g.tenant.tenant_id))">
                {{ busy === g.tenant.tenant_id ? 'checking…' : 'not checked' }}
              </button>
              <span v-else class="muted small">not checked</span>
            </td>
            <td v-if="mayAct"></td>
          </tr>

          <!-- Folded: registry rows that are an INTERFACE HOSTNAME of the tenant above,
               registered as tenants of their own. No request can arrive for them; the
               schema is real and there is nothing here that can remove it. -->
          <tr v-for="c in g.folded" :key="c.tenant_id" class="folded">
            <td colspan="5">
              <span class="mono">{{ c.tenant_id }}</span>
              <span class="pill warn">not a tenant</span>
              <div class="muted small">
                An interface hostname of <span class="mono">{{ g.tenant.tenant_id }}</span>,
                registered as a tenant because the core registers any tenant it is asked
                about. Nothing can reach it — the doors resolve
                <span class="mono">{{ c.tenant_id }}.&lt;domain&gt;</span> to
                <span class="mono">{{ g.tenant.tenant_id }}</span> — but it holds the
                schema <span class="mono">{{ c.schema_name }}</span>.
              </div>
            </td>
            <td v-if="mayAct"></td>
          </tr>
        </template>
      </tbody>
    </table>

    <nav v-if="pageCount > 1" class="pager">
      <button class="btn secondary sm" :disabled="page <= 1" @click="page = 1">First</button>
      <button class="btn secondary sm" :disabled="page <= 1" @click="page -= 1">
        Previous
      </button>
      <span class="muted">Page {{ Math.min(page, pageCount) }} of {{ pageCount }}</span>
      <button class="btn secondary sm" :disabled="page >= pageCount" @click="page += 1">
        Next
      </button>
      <button class="btn secondary sm" :disabled="page >= pageCount"
              @click="page = pageCount">
        Last
      </button>
    </nav>
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
tr.iface td {
  padding-top: 0.3rem;
  padding-bottom: 0.3rem;
  border-bottom: none;
}
tr.iface td:first-child {
  padding-left: 1.5rem;
}
.tree {
  color: var(--muted);
  margin-right: 0.4rem;
}
.pill.role {
  margin-left: 0.5rem;
  font-size: 0.7rem;
}
.filters {
  align-items: flex-end;
  margin-bottom: 1rem;
}
.filters .field {
  margin-bottom: 0;
  width: 180px;
}
.filters .field.grow {
  flex: 1;
  min-width: 220px;
}
.count {
  font-size: 0.8rem;
  margin: 0 0 0.35rem;
  white-space: nowrap;
}
.count .link {
  margin-left: 0.4rem;
}
.pager {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  margin-top: 1rem;
  font-size: 0.85rem;
  flex-wrap: wrap;
}
tr.folded td {
  padding-top: 0.35rem;
  padding-bottom: 0.6rem;
  padding-left: 1.75rem;
  border-bottom: 1px solid var(--border);
  background: var(--bg);
}
tr.folded .pill {
  margin-left: 0.5rem;
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
/* A status that is also its own action: reads as the muted label it replaces,
   and shows it can be pressed. */
.linkbtn {
  background: none;
  border: 0;
  padding: 0;
  font: inherit;
  color: var(--muted);
  text-decoration: underline dotted;
  text-underline-offset: 3px;
  cursor: pointer;
}
.linkbtn:hover:not(:disabled),
.linkbtn:focus-visible { color: var(--primary); text-decoration-style: solid; }
.linkbtn:disabled { cursor: progress; opacity: 0.7; }
.btn.sm {
  padding: 0.3rem 0.6rem;
  font-size: 0.82rem;
}
</style>
