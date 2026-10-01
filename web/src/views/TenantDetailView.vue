<!--
  Copyright (C) 2026 James Hickman
  SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { useRoute } from 'vue-router'
import { apiError } from '@/services/client'
import { tenants, type TenantView } from '@/services/api'

const route = useRoute()
const t = ref<TenantView | null>(null)
const error = ref('')
const loading = ref(true)
const copied = ref(false)

onMounted(async () => {
  try {
    t.value = await tenants.get(String(route.params.id))
  } catch (e) {
    error.value = apiError(e)
  } finally {
    loading.value = false
  }
})

function copyZone() {
  const lines = (t.value?.records ?? []).map((r) => r.zone_line).join('\n')
  void navigator.clipboard?.writeText(lines)
  copied.value = true
  window.setTimeout(() => (copied.value = false), 1800)
}
</script>

<template>
  <div>
    <p v-if="loading" class="empty">Loading…</p>
    <div v-else-if="error" class="notice bad">{{ error }}</div>

    <template v-else-if="t">
      <h1>{{ t.display_name }}</h1>
      <p class="sub">
        <!-- The identifier, always visible. The heading is the label a human
             recognises; this is what every other system uses, and it cannot change. -->
        <span class="mono">{{ t.tenant_id }}</span>
        · schema <span class="mono">{{ t.schema_name }}</span>
        <template v-if="t.requested_here"> · requested by {{ t.requested_by }}</template>
        <template v-else>
          · created before this console, so it has no creation details here
        </template>
      </p>

      <div class="grid two">
        <section v-if="t.records.length" class="card">
          <h2>DNS records to create</h2>
          <p class="hint">
            Create these wherever this domain is managed. This console never
            touches DNS — there is no DNS credential here because there is no DNS
            operation.
          </p>
          <pre class="zone mono">{{ t.records.map((r) => r.zone_line).join('\n') }}</pre>
          <button class="btn secondary" @click="copyZone">
            {{ copied ? 'Copied' : 'Copy zone lines' }}
          </button>
        </section>

        <section class="card">
          <h2>Gate</h2>
          <p class="row">
            <span class="pill">{{ t.state.replace(/_/g, ' ') }}</span>
            <span class="pill" :class="t.admits_logins ? 'ok' : ''">
              logins {{ t.admits_logins ? 'admitted' : 'refused' }}
            </span>
            <span v-if="!t.admits_logins" class="pill"
                  :class="t.may_provision ? 'ok' : 'warn'">
              {{ t.may_provision ? 'may provision' : 'gate closed' }}
            </span>
          </p>
          <p v-if="t.state_by" class="muted small">
            moved to {{ t.state.replace(/_/g, ' ') }} by {{ t.state_by }}
            <template v-if="t.state_since"> · {{ t.state_since }}</template>
            <template v-if="t.state_note"> — “{{ t.state_note }}”</template>
          </p>
          <template v-if="t.dns">
            <table class="checks">
              <tbody>
                <tr v-for="c in t.dns.checks" :key="c.hostname">
                  <td>
                    <span class="pill" :class="c.ok ? 'ok' : 'bad'">{{ c.ok ? 'ok' : 'no' }}</span>
                  </td>
                  <td>
                    <div class="mono">{{ c.hostname }}</div>
                    <!-- Each hostname's own detail, because the causes need
                         opposite responses: "no record" improves by waiting, a
                         wrong address never does, and a non-authoritative answer
                         means nothing is wrong with the zone at all. -->
                    <div v-if="c.detail" class="muted small">{{ c.detail }}</div>
                  </td>
                </tr>
              </tbody>
            </table>
            <p v-if="!t.dns.authoritative" class="notice warn">
              The answer was not authoritative, so it is not what a certificate
              authority would see. This console refuses to treat it as proof; if
              you know the zone is ready, use the recorded override.
            </p>
          </template>
          <p v-else class="muted small">DNS has not been checked yet.</p>

          <div v-if="t.override" class="notice warn">
            <strong>Gate overridden</strong> by {{ t.override.by }} — “{{ t.override.reason }}”
          </div>
        </section>
      </div>

      <section v-if="t.failure" class="card">
        <h2>Last failure</h2>
        <p><strong>{{ t.failure.step }}</strong></p>
        <p class="muted">{{ t.failure.detail }}</p>
        <p class="pill" :class="t.failure.retry_safe ? 'ok' : 'bad'">
          {{ t.failure.retry_safe ? 'safe to retry' : 'not safe to retry' }}
        </p>
      </section>

      <section class="card">
        <h2>Details</h2>
        <dl>
          <dt v-if="t.hostnames.length">Hostnames</dt>
          <dd v-if="t.hostnames.length" class="mono">{{ t.hostnames.join(', ') }}</dd>
          <dt v-if="t.address">Address</dt>
          <dd v-if="t.address" class="mono">{{ t.address }}</dd>
          <dt v-if="t.initial_admin">First administrator</dt>
          <dd v-if="t.initial_admin">{{ t.initial_admin }}</dd>
          <dt>Schema</dt>
          <dd class="mono">{{ t.schema_name }}</dd>
          <dt v-if="t.created_at">Created</dt>
          <dd v-if="t.created_at">{{ t.created_at }}</dd>
          <dt v-if="t.job_id">Provisioning job</dt>
          <dd v-if="t.job_id" class="mono">{{ t.job_id }}</dd>
        </dl>
      </section>
    </template>
  </div>
</template>

<style scoped>
.grid.two {
  grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
  margin-bottom: 1rem;
}
.grid.two > section,
section.card {
  margin-bottom: 1rem;
}
.hint {
  color: var(--muted);
  font-size: 0.8rem;
  line-height: 1.5;
  margin: 0 0 0.75rem;
}
.zone {
  background: var(--bg);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 0.7rem;
  overflow-x: auto;
  margin: 0 0 0.75rem;
  font-size: 0.8rem;
  line-height: 1.6;
}
.checks td {
  border: none;
  padding: 0.35rem 0.5rem 0.35rem 0;
}
.small {
  font-size: 0.78rem;
}
.row {
  margin: 0 0 0.5rem;
}
dl {
  display: grid;
  grid-template-columns: max-content 1fr;
  gap: 0.4rem 1rem;
  margin: 0;
  font-size: 0.9rem;
}
dt {
  color: var(--muted);
}
dd {
  margin: 0;
}
</style>
