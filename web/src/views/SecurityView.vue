<!--
  Copyright (C) 2026 James Hickman
  SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import BaseChart from '@/components/BaseChart.vue'
import { apiError } from '@/services/client'
import { security } from '@/services/api'

const incidents = ref<Record<string, any>[]>([])
const campaigns = ref<Record<string, any>[]>([])
const aggregated = ref<Record<string, any>[]>([])
const error = ref('')
const campaignError = ref('')
const loading = ref(true)
const minSeverity = ref('')

onMounted(load)

async function load() {
  loading.value = true
  error.value = ''
  campaignError.value = ''
  try {
    const params: Record<string, string | number> = { limit: 200 }
    if (minSeverity.value) params.min_severity = minSeverity.value
    const d = await security.incidents(params)
    incidents.value = d.incidents ?? []
    aggregated.value = d.aggregated ?? []
  } catch (e) {
    error.value = apiError(e)
  }
  try {
    campaigns.value = (await security.campaigns()).campaigns ?? []
  } catch (e) {
    campaignError.value = apiError(e)
  }
  loading.value = false
}

/** Incidents per tenant — the view that exists ONLY here.
 *
 * A tenant administrator can see their own tenant's incidents. Nobody inside a
 * tenant can see that the same thing is happening in eleven others, which is the
 * capability this tier adds and the reason a per-tenant breakdown is the first
 * chart rather than a total.
 */
const byTenantOption = computed(() => {
  const counts = new Map<string, number>()
  for (const i of incidents.value) {
    const key = i.tenant || '(deployment-wide)'
    counts.set(key, (counts.get(key) ?? 0) + 1)
  }
  const sorted = [...counts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 14)
  return {
    // Horizontal: tenant ids are long and a rotated axis label is unreadable.
    xAxis: { type: 'value', minInterval: 1 },
    yAxis: { type: 'category', data: sorted.map(([k]) => k).reverse(), axisLabel: { fontSize: 11 } },
    tooltip: { trigger: 'axis' },
    grid: { left: 8, right: 24 },
    series: [{ type: 'bar', barMaxWidth: 18, data: sorted.map(([, n]) => n).reverse() }],
  }
})

function sevClass(sev: string) {
  if (sev === 'critical') return 'bad'
  if (sev === 'serious') return 'warn'
  return ''
}
</script>

<template>
  <div>
    <h1>Security</h1>
    <p class="sub">
      Every tenant at once. A tenant administrator sees their own incidents; only
      this view can see that the same thing is happening in eleven others.
    </p>

    <div class="row filters">
      <div class="field inline">
        <label for="sev">Minimum severity</label>
        <select id="sev" v-model="minSeverity" @change="load">
          <option value="">any</option>
          <option value="notable">notable</option>
          <option value="serious">serious</option>
          <option value="critical">critical</option>
        </select>
      </div>
      <button class="btn secondary" @click="load">Refresh</button>
    </div>

    <!-- 503 is not "quiet". An unreachable ledger must not render as zero
         incidents, which is the single most misleading thing this page could do. -->
    <div v-if="error" class="notice bad">{{ error }}</div>

    <p v-if="loading" class="empty">Loading…</p>

    <template v-else-if="!error">
      <section class="grid two">
        <div class="card">
          <h2>Incidents by tenant</h2>
          <BaseChart v-if="incidents.length" :option="byTenantOption" height="300px" />
          <p v-else class="empty">No incidents recorded.</p>
        </div>
        <div class="card">
          <h2>Campaigns</h2>
          <p class="hint">
            One source acting against several tenants. No single tenant could have
            seen this.
          </p>
          <p v-if="campaignError" class="notice bad">{{ campaignError }}</p>
          <p v-else-if="!campaigns.length" class="empty">No cross-tenant campaigns.</p>
          <table v-else>
            <tbody>
              <tr v-for="c in campaigns" :key="String(c.id ?? c.group_key)">
                <td>
                  <div class="mono">{{ c.group_key }}</div>
                  <div class="muted small">{{ c.description }}</div>
                </td>
                <td>
                  <span class="pill" :class="sevClass(c.severity)">{{ c.severity }}</span>
                  <div v-if="c.distinct_values?.length" class="muted small">
                    {{ c.distinct_values.length }} tenants
                  </div>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      <section class="card">
        <h2>Incidents</h2>
        <p v-if="!incidents.length" class="empty">No incidents recorded.</p>
        <table v-else>
          <thead>
            <tr>
              <th>When</th>
              <th>Tenant</th>
              <th>Rule</th>
              <th>Severity</th>
              <th>Matches</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="i in incidents" :key="i.id">
              <td class="muted small nowrap">{{ String(i.ts).replace('T', ' ').slice(0, 19) }}</td>
              <td>
                <span v-if="i.tenant" class="mono">{{ i.tenant }}</span>
                <span v-else class="pill">deployment</span>
              </td>
              <td>
                <div class="mono">{{ i.rule_id }}</div>
                <div class="muted small">{{ i.description }}</div>
                <div v-if="i.group_key" class="muted small">
                  {{ i.group_by }}: <span class="mono">{{ i.group_key }}</span>
                </div>
              </td>
              <td><span class="pill" :class="sevClass(i.severity)">{{ i.severity }}</span></td>
              <td>{{ i.match_count }}</td>
              <td><span class="pill">{{ i.status }}</span></td>
            </tr>
          </tbody>
        </table>
      </section>
    </template>
  </div>
</template>

<style scoped>
.filters {
  margin-bottom: 1rem;
  align-items: flex-end;
}
.field.inline {
  margin-bottom: 0;
  width: 200px;
}
.grid.two {
  grid-template-columns: repeat(auto-fit, minmax(340px, 1fr));
  margin-bottom: 1rem;
}
.hint {
  color: var(--muted);
  font-size: 0.8rem;
  margin: 0 0 0.75rem;
  line-height: 1.5;
}
.small {
  font-size: 0.78rem;
}
.nowrap {
  white-space: nowrap;
}
</style>
