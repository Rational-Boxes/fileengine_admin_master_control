<!--
  Copyright (C) 2026 James Hickman
  SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { apiError } from '@/services/client'
import { administrators } from '@/services/api'
import { useSession } from '@/stores/session'

const s = useSession()
const data = ref<Record<string, any> | null>(null)
const roles = ref<string[]>([])
const error = ref('')
const loading = ref(true)
const busy = ref('')
const history = ref<{ subject: string; label: string; rows: Record<string, any>[] } | null>(null)

const grant = ref({ subject: '', role: '', reason: '' })

onMounted(load)

async function load() {
  error.value = ''
  try {
    data.value = await administrators.list()
    const r = await administrators.roles()
    roles.value = r.grantable ?? r.roles ?? []
  } catch (e) {
    error.value = apiError(e)
  } finally {
    loading.value = false
  }
}

async function submitGrant() {
  busy.value = 'grant'
  error.value = ''
  try {
    await administrators.grant(grant.value.subject.trim(), grant.value.role, grant.value.reason)
    grant.value = { subject: '', role: '', reason: '' }
    await load()
  } catch (e) {
    error.value = apiError(e)
  } finally {
    busy.value = ''
  }
}

/** How a person is named on screen: their address. The ledger and the API speak in
 *  the directory's canonical uid, which for some accounts is not the address. */
function label(a: { subject: string; email?: string }) {
  return a.email || a.subject
}

async function revoke(subject: string, role: string, who: string = subject) {
  const reason = window.prompt(`Revoke ${role} from ${who}. Why?`)
  if (reason === null) return
  busy.value = subject + role
  error.value = ''
  try {
    await administrators.revoke(subject, role, reason)
    await load()
  } catch (e) {
    error.value = apiError(e)
  } finally {
    busy.value = ''
  }
}

async function showHistory(subject: string, who: string = subject) {
  try {
    const h = await administrators.history(subject)
    history.value = { subject, label: who, rows: h.grants ?? h.history ?? [] }
  } catch (e) {
    error.value = apiError(e)
  }
}
</script>

<template>
  <div>
    <h1>Administrators</h1>
    <p class="sub">
      The directory decides who holds what; this is the attributed record of grants
      made here. The two can disagree — someone with directory access can add a
      member without going through this console, which is legitimate, and drift is
      shown rather than hidden.
    </p>

    <div v-if="error" class="notice bad">{{ error }}</div>
    <p v-if="loading" class="empty">Loading…</p>

    <template v-else-if="data">
      <div v-if="(data.drift ?? []).length" class="notice warn">
        <strong>Directory and ledger disagree.</strong>
        <ul>
          <li v-for="d in data.drift" :key="String(d)">{{ d }}</li>
        </ul>
      </div>

      <section class="card">
        <h2>Grant a role</h2>
        <!-- system_owner is the only role that creates authority, and it does NOT
             imply the operational ones — so this is a list to pick from, never a
             level to raise someone to. -->
        <form class="row form" @submit.prevent="submitGrant">
          <div class="field">
            <label for="sub">Administrator</label>
            <input id="sub" v-model="grant.subject" placeholder="them@example.com" />
          </div>
          <div class="field">
            <label for="role">Role</label>
            <select id="role" v-model="grant.role">
              <option value="" disabled>choose…</option>
              <option v-for="r in roles" :key="r" :value="r">{{ r }}</option>
            </select>
          </div>
          <div class="field grow">
            <label for="why">Reason</label>
            <input id="why" v-model="grant.reason" placeholder="why they need it" />
          </div>
          <button class="btn" type="submit"
                  :disabled="busy === 'grant' || !grant.subject || !grant.role">
            Grant
          </button>
        </form>
        <p v-if="!s.has('system_owner')" class="hint">
          Granting requires system_owner — and holding it does not imply the
          operational roles.
        </p>
      </section>

      <section class="card">
        <h2>Current</h2>
        <table>
          <thead>
            <tr>
              <th>Administrator</th>
              <th>Roles</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="a in data.administrators ?? []" :key="a.subject">
              <td>
                <div>{{ label(a) }}</div>
                <div v-if="a.email && a.email !== a.subject" class="muted small mono">
                  uid {{ a.subject }}
                </div>
                <button class="link small" @click="showHistory(a.subject, label(a))">history</button>
              </td>
              <td>
                <div class="row">
                  <span v-for="r in a.roles" :key="r" class="pill role">
                    {{ r }}
                    <button class="x" :disabled="busy === a.subject + r"
                            :title="`Revoke ${r}`" @click="revoke(a.subject, r, label(a))">×</button>
                  </span>
                  <span v-if="!a.roles?.length" class="muted small">none</span>
                </div>
              </td>
              <td></td>
            </tr>
          </tbody>
        </table>
      </section>

      <section v-if="history" class="card">
        <h2>{{ history.label }} — every grant and revocation</h2>
        <p class="hint">Append-only. A revocation is a new entry, not a deletion.</p>
        <table>
          <tbody>
            <tr v-for="(g, i) in history.rows" :key="i">
              <td class="muted small nowrap">{{ g.at ?? g.granted_at ?? '' }}</td>
              <td><span class="pill">{{ g.action ?? (g.revoked ? 'revoke' : 'grant') }}</span></td>
              <td class="mono">{{ g.role }}</td>
              <td class="muted small">
                by {{ g.granted_by ?? g.by ?? '—' }}
                <div v-if="g.reason">“{{ g.reason }}”</div>
              </td>
            </tr>
          </tbody>
        </table>
        <button class="btn secondary" @click="history = null">Close</button>
      </section>
    </template>
  </div>
</template>

<style scoped>
section.card {
  margin-bottom: 1rem;
}
.form {
  align-items: flex-end;
}
.form .field {
  margin-bottom: 0;
  width: 220px;
}
.form .field.grow {
  flex: 1;
  min-width: 200px;
}
.hint {
  color: var(--muted);
  font-size: 0.8rem;
  margin: 0.6rem 0 0;
}
.small {
  font-size: 0.78rem;
}
.nowrap {
  white-space: nowrap;
}
.pill.role {
  display: inline-flex;
  align-items: center;
  gap: 0.35rem;
}
.x {
  background: none;
  border: none;
  color: var(--muted);
  padding: 0;
  font-size: 1rem;
  line-height: 1;
}
.x:hover {
  color: var(--danger);
}
</style>
