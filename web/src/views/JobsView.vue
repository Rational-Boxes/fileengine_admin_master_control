<!--
  Copyright (C) 2026 James Hickman
  SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { apiError } from '@/services/client'
import { tenants } from '@/services/api'

const jobs = ref<Record<string, any>[]>([])
const error = ref('')
const loading = ref(true)

onMounted(async () => {
  try {
    jobs.value = await tenants.jobs()
  } catch (e) {
    error.value = apiError(e)
  } finally {
    loading.value = false
  }
})

const queued = computed(() => jobs.value.filter((j) => j.state === 'queued').length)

function cls(state: string) {
  if (state === 'done') return 'ok'
  if (state === 'failed') return 'bad'
  if (state === 'queued') return 'warn'
  return ''
}
</script>

<template>
  <div>
    <h1>Provisioning</h1>
    <p class="sub">
      The queue a runner claims from. This console writes the job and stops there —
      the runner holds the vault password and the inventory, which is why neither is
      reachable from here.
    </p>

    <div v-if="error" class="notice bad">{{ error }}</div>
    <!-- Worth stating rather than leaving as an unexplained backlog: a job sitting
         in `queued` usually means no runner is running, not that provisioning
         failed. -->
    <div v-else-if="queued" class="notice warn">
      {{ queued }} job{{ queued === 1 ? '' : 's' }} waiting to be claimed. If this does not
      fall, check that a runner is running — a queued job is not a failed one.
    </div>

    <p v-if="loading" class="empty">Loading…</p>
    <p v-else-if="!jobs.length" class="empty">No provisioning jobs have been requested.</p>

    <table v-else class="card">
      <thead>
        <tr>
          <th>Job</th>
          <th>Tenant</th>
          <th>State</th>
          <th>Requested by</th>
          <th>Gate</th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="j in jobs" :key="j.job_id">
          <td class="mono">{{ j.job_id }}</td>
          <td class="mono">{{ j.tenant_id }}</td>
          <td>
            <span class="pill" :class="cls(j.state)">{{ j.state }}</span>
            <div v-if="j.claimed_by" class="muted small">by {{ j.claimed_by }}</div>
            <div v-if="j.detail" class="muted small">{{ j.detail }}</div>
          </td>
          <td class="muted small">{{ j.requested_by }}</td>
          <td>
            <span v-if="j.dns_verified" class="pill ok">verified</span>
            <template v-else-if="j.dns_overridden_by">
              <span class="pill warn">overridden</span>
              <!-- The reason, not just the actor. Who pressed it is in the audit
                   trail either way; what they believed about the zone is the only
                   thing that explains the decision afterwards. -->
              <div class="muted small">
                {{ j.dns_overridden_by }} — “{{ j.dns_override_reason }}”
              </div>
            </template>
          </td>
        </tr>
      </tbody>
    </table>
  </div>
</template>

<style scoped>
.small {
  font-size: 0.78rem;
}
</style>
