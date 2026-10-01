<!--
  Copyright (C) 2026 James Hickman
  SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { RouterLink } from 'vue-router'
import BaseChart from '@/components/BaseChart.vue'
import { apiError } from '@/services/client'
import { security, tenants, type TenantView } from '@/services/api'
import { SYSTEM_SECURITY, useSession } from '@/stores/session'

const s = useSession()
const tenantRows = ref<TenantView[]>([])
const jobs = ref<Record<string, any>[]>([])
const incidents = ref<Record<string, any>[]>([])
const backlog = ref<Record<string, any>[]>([])

/** Per-panel errors, NOT one page-level error.
 *
 * The panels read different services, and this tier's whole discipline is that an
 * unanswerable question is not an empty answer. One shared error banner would
 * either hide a working half of the page or, worse, leave a chart rendering zero
 * while the thing it counts is simply unreachable — which reads as "no incidents".
 */
const errors = ref<Record<string, string>>({})
const loading = ref(true)

onMounted(async () => {
  await Promise.all([
    load('tenants', async () => (tenantRows.value = await tenants.list())),
    load('jobs', async () => (jobs.value = await tenants.jobs())),
    ...(s.has(SYSTEM_SECURITY)
      ? [
          load('incidents', async () => {
            incidents.value = (await security.incidents({ limit: 200 })).incidents ?? []
          }),
          load('backlog', async () => {
            backlog.value = (await security.backlog()).backlog ?? []
          }),
        ]
      : []),
  ])
  loading.value = false
})

async function load(key: string, fn: () => Promise<unknown>) {
  try {
    await fn()
  } catch (e) {
    errors.value[key] = apiError(e)
  }
}

// ── tenant lifecycle ───────────────────────────────────────────────────────

const LIFECYCLE = ['requested', 'awaiting_dns', 'verified', 'provisioning', 'live', 'failed']

const byState = computed(() => {
  const counts: Record<string, number> = {}
  for (const st of LIFECYCLE) counts[st] = 0
  for (const t of tenantRows.value) counts[t.state] = (counts[t.state] ?? 0) + 1
  return counts
})

/** The stalled ones. This is what §3.2 exists to surface.
 *
 * `awaiting_dns` is the honest headline: it is not a failure and must not be
 * coloured as one, but a tenant sitting there is a tenant nobody has finished, and
 * before this console existed it was tracked in somebody's terminal scrollback.
 */
const waiting = computed(() =>
  tenantRows.value.filter((t) => t.state === 'awaiting_dns' || t.state === 'requested'),
)
const readyToProvision = computed(() => tenantRows.value.filter((t) => t.may_provision))
const queuedJobs = computed(() => jobs.value.filter((j) => j.state === 'queued'))

const lifecycleOption = computed(() => ({
  xAxis: { type: 'category', data: LIFECYCLE.map(label) },
  yAxis: { type: 'value', minInterval: 1 },
  tooltip: { trigger: 'axis' },
  series: [
    {
      type: 'bar',
      barMaxWidth: 46,
      data: LIFECYCLE.map((st) => ({
        value: byState.value[st],
        // Coloured by MEANING, not by position in a palette: waiting states are
        // amber, live is green, failed is red. A gradient across the lifecycle
        // would imply progress is good and `failed` is merely further along.
        itemStyle: { color: stateColour(st) },
      })),
    },
  ],
}))

function stateColour(st: string): string {
  const v = (n: string) => getComputedStyle(document.documentElement).getPropertyValue(n).trim()
  if (st === 'live') return v('--success')
  if (st === 'failed') return v('--danger')
  if (st === 'awaiting_dns' || st === 'requested') return v('--warning')
  return v('--primary')
}

function label(st: string) {
  return st.replace(/_/g, ' ')
}

// ── security, when this administrator may see it ───────────────────────────

const SEVERITIES = ['critical', 'serious', 'notable', 'minor']

const severityOption = computed(() => {
  const counts: Record<string, number> = {}
  for (const sev of SEVERITIES) counts[sev] = 0
  for (const i of incidents.value) {
    if (counts[i.severity] !== undefined) counts[i.severity] += 1
    else counts[i.severity] = 1
  }
  const v = (n: string) => getComputedStyle(document.documentElement).getPropertyValue(n).trim()
  const colours: Record<string, string> = {
    critical: v('--danger'),
    serious: v('--warning'),
    notable: v('--primary'),
    minor: v('--muted'),
  }
  return {
    tooltip: { trigger: 'item' },
    legend: { bottom: 0 },
    series: [
      {
        type: 'pie',
        radius: ['46%', '68%'],
        center: ['50%', '44%'],
        label: { show: false },
        data: Object.entries(counts)
          .filter(([, n]) => n > 0)
          .map(([sev, n]) => ({
            name: sev,
            value: n,
            itemStyle: { color: colours[sev] ?? v('--muted') },
          })),
      },
    ],
  }
})

/** Incidents per day, from the ledger rows the view already has.
 *
 * Every day in the range is present even when it has no incidents. Charting only
 * the days that appear compresses a quiet week into a straight line and makes a
 * spike look like the normal rate.
 */
const overTimeOption = computed(() => {
  const byDay = new Map<string, number>()
  for (const i of incidents.value) {
    const day = String(i.ts ?? '').slice(0, 10)
    if (day) byDay.set(day, (byDay.get(day) ?? 0) + 1)
  }
  const days = [...byDay.keys()].sort()
  const filled: string[] = []
  if (days.length) {
    const cursor = new Date(days[0] + 'T00:00:00Z')
    const last = new Date(days[days.length - 1] + 'T00:00:00Z')
    while (cursor <= last) {
      filled.push(cursor.toISOString().slice(0, 10))
      cursor.setUTCDate(cursor.getUTCDate() + 1)
    }
  }
  return {
    xAxis: { type: 'category', data: filled, boundaryGap: false },
    yAxis: { type: 'value', minInterval: 1 },
    tooltip: { trigger: 'axis' },
    series: [
      {
        type: 'line',
        smooth: false,
        showSymbol: filled.length < 40,
        areaStyle: { opacity: 0.12 },
        data: filled.map((d) => byDay.get(d) ?? 0),
      },
    ],
  }
})

const oldestUnacknowledged = computed(() => {
  const open = backlog.value.filter((b) => b.state === 'raised')
  return open.length ? open[0] : null
})
</script>

<template>
  <div>
    <h1>Deployment</h1>
    <p class="sub">
      What is outstanding across the whole estate. Nothing here acts on anything —
      every figure is a link to the place where it can be dealt with.
    </p>

    <div v-if="loading" class="empty">Loading…</div>

    <template v-else>
      <!-- the numbers that mean something needs a person -->
      <section class="tiles">
        <RouterLink class="tile card" to="/tenants">
          <span class="n">{{ waiting.length }}</span>
          <span class="l">Awaiting DNS</span>
          <span class="h">Not a failure — but unfinished</span>
        </RouterLink>
        <RouterLink class="tile card" to="/tenants">
          <span class="n" :class="{ good: readyToProvision.length > 0 }">
            {{ readyToProvision.length }}
          </span>
          <span class="l">Ready to provision</span>
          <span class="h">DNS verified or overridden</span>
        </RouterLink>
        <RouterLink class="tile card" to="/jobs">
          <span class="n">{{ queuedJobs.length }}</span>
          <span class="l">Jobs queued</span>
          <span class="h">Waiting for a runner to claim</span>
        </RouterLink>
        <RouterLink v-if="s.has(SYSTEM_SECURITY)" class="tile card" to="/queue">
          <span class="n" :class="{ bad: oldestUnacknowledged }">
            {{ backlog.filter((b) => b.state === 'raised').length }}
          </span>
          <span class="l">Unacknowledged</span>
          <span class="h">Incidents nobody has picked up</span>
        </RouterLink>
      </section>

      <div v-if="errors.tenants" class="notice bad">Tenants: {{ errors.tenants }}</div>
      <div v-if="errors.jobs" class="notice bad">Provisioning queue: {{ errors.jobs }}</div>

      <section class="charts">
        <div class="card">
          <h2>Tenants by lifecycle state</h2>
          <BaseChart v-if="tenantRows.length" :option="lifecycleOption" />
          <p v-else class="empty">No tenant requests on record.</p>
        </div>

        <template v-if="s.has(SYSTEM_SECURITY)">
          <div class="card">
            <h2>Incidents by severity</h2>
            <!-- An unreachable ledger is NOT an empty chart. A zero here would
                 read as "the estate is quiet", which is the opposite of what a
                 503 means. -->
            <p v-if="errors.incidents" class="notice bad">{{ errors.incidents }}</p>
            <BaseChart v-else-if="incidents.length" :option="severityOption" />
            <p v-else class="empty">No incidents recorded.</p>
          </div>
          <div class="card wide">
            <h2>Incidents over time</h2>
            <p v-if="errors.incidents" class="notice bad">{{ errors.incidents }}</p>
            <BaseChart v-else-if="incidents.length" :option="overTimeOption" />
            <p v-else class="empty">No incidents recorded.</p>
          </div>
        </template>
      </section>
    </template>
  </div>
</template>

<style scoped>
.tiles {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(190px, 1fr));
  gap: 1rem;
  margin-bottom: 1rem;
}
.tile {
  display: flex;
  flex-direction: column;
  gap: 0.1rem;
  text-decoration: none;
  color: inherit;
}
.tile:hover {
  border-color: var(--primary);
}
.n {
  font-size: 1.9rem;
  font-weight: 600;
  line-height: 1.1;
}
.n.good {
  color: var(--success);
}
.n.bad {
  color: var(--danger);
}
.l {
  font-size: 0.9rem;
}
.h {
  font-size: 0.75rem;
  color: var(--muted);
}
.charts {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
  gap: 1rem;
}
.charts .wide {
  grid-column: 1 / -1;
}
</style>
