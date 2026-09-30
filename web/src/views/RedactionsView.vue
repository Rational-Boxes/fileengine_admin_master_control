<!--
  Copyright (C) 2026 James Hickman
  SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { apiError } from '@/services/client'
import { redactions } from '@/services/api'

const data = ref<Record<string, any> | null>(null)
const error = ref('')
const loading = ref(true)

onMounted(async () => {
  try {
    data.value = await redactions.register()
  } catch (e) {
    error.value = apiError(e)
  } finally {
    loading.value = false
  }
})

const BUCKETS = [
  ['outstanding', 'Outstanding', 'Requested, not yet carried out.'],
  ['approved_not_completed', 'Approved, not completed', 'Decided and still pending.'],
  ['completed', 'Completed', 'Carried out.'],
] as const
</script>

<template>
  <div>
    <h1>Redactions</h1>
    <!--
      The rule, stated on the page it governs, because the temptation to add a
      filename column is permanent and the reason not to is not obvious from the
      data: a redaction exists because content may hold identifiable information,
      and a filename is content. The record keeps a UUID so the historical activity
      trail stays intact and readable without reintroducing what was redacted.
    -->
    <p class="sub">
      Files are named by UUID only. A filename is content, and content is what a
      redaction is for — the activity record stays intact without it.
    </p>

    <div v-if="error" class="notice bad">{{ error }}</div>
    <p v-if="loading" class="empty">Loading…</p>

    <template v-else-if="data">
      <div class="tiles">
        <div v-for="[key, label] in BUCKETS" :key="key" class="tile card">
          <span class="n">{{ data.counts?.[key] ?? 0 }}</span>
          <span class="l">{{ label }}</span>
        </div>
      </div>

      <section v-for="[key, label, hint] in BUCKETS" :key="key" class="card">
        <h2>{{ label }}</h2>
        <p class="hint">{{ hint }}</p>
        <p v-if="!(data[key] ?? []).length" class="empty">Nothing in this state.</p>
        <table v-else>
          <thead>
            <tr>
              <th>File</th>
              <th>Tenant</th>
              <th>Requested</th>
              <th>State</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="item in data[key]" :key="item.file_uid">
              <td>
                <div class="mono">{{ item.file_uid }}</div>
                <!-- The server sends a placeholder rather than a name; rendered as
                     given, never substituted for something friendlier. -->
                <div class="muted small">{{ item.display_name }}</div>
              </td>
              <td class="mono">{{ item.tenant ?? '—' }}</td>
              <td class="muted small">{{ item.requested_at ?? '—' }}</td>
              <td><span class="pill">{{ item.state ?? '—' }}</span></td>
            </tr>
          </tbody>
        </table>
      </section>
    </template>
  </div>
</template>

<style scoped>
.tiles {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  gap: 1rem;
  margin-bottom: 1rem;
}
.tile {
  display: flex;
  flex-direction: column;
}
.n {
  font-size: 1.9rem;
  font-weight: 600;
  line-height: 1.1;
}
.l {
  font-size: 0.85rem;
  color: var(--muted);
}
section.card {
  margin-bottom: 1rem;
}
.hint {
  color: var(--muted);
  font-size: 0.8rem;
  margin: 0 0 0.75rem;
}
.small {
  font-size: 0.78rem;
}
</style>
