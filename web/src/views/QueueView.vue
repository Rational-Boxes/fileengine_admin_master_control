<!--
  Copyright (C) 2026 James Hickman
  SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { apiError } from '@/services/client'
import { security } from '@/services/api'

/** The procedure, in order. Each state may only move to what follows it.
 *
 * Rendered from this list rather than offering every state as a dropdown: the
 * order is the point of the queue — it is what distinguishes a procedure from a
 * list of labels — and the server enforces it, so showing the impossible moves
 * would only produce 409s.
 */
const ORDER = ['raised', 'acknowledged', 'customer_confirmed', 'approved', 'completed']

const rows = ref<Record<string, any>[]>([])
const error = ref('')
const loading = ref(true)
const busy = ref<number | null>(null)

onMounted(load)

async function load() {
  error.value = ''
  try {
    rows.value = (await security.backlog()).backlog ?? []
  } catch (e) {
    error.value = apiError(e)
  } finally {
    loading.value = false
  }
}

function nextState(state: string): string | null {
  const i = ORDER.indexOf(state)
  return i >= 0 && i < ORDER.length - 1 ? ORDER[i + 1] : null
}

async function move(row: Record<string, any>, state: string) {
  const reason = window.prompt(
    `Move incident ${row.incident_id} to “${state.replace(/_/g, ' ')}”.\n\n` +
      'This is recorded against your name as a decision. Why?',
  )
  if (reason === null) return
  busy.value = row.incident_id
  error.value = ''
  try {
    // No actor field. The server takes it from the token — this is the table that
    // exists to answer "who approved this", and a body-supplied name would make it
    // worthless exactly when it matters.
    await security.transition({ incident_id: row.incident_id, state, reason })
    await load()
  } catch (e) {
    error.value = apiError(e)
  } finally {
    busy.value = null
  }
}

async function decline(row: Record<string, any>) {
  const reason = window.prompt(
    `Decline incident ${row.incident_id}.\n\n` +
      'Recorded as a decision NOT to act, with a reason — the point is that the ' +
      'record shows a refusal rather than silence.',
  )
  if (reason === null) return
  busy.value = row.incident_id
  try {
    await security.transition({ incident_id: row.incident_id, state: 'declined', reason })
    await load()
  } catch (e) {
    error.value = apiError(e)
  } finally {
    busy.value = null
  }
}

const unacknowledged = computed(() => rows.value.filter((r) => r.state === 'raised'))

function cls(state: string) {
  if (state === 'completed') return 'ok'
  if (state === 'declined') return 'bad'
  if (state === 'raised') return 'warn'
  return ''
}
</script>

<template>
  <div>
    <h1>Acknowledgements</h1>
    <p class="sub">
      Incidents waiting on a person, in the order the procedure requires. Nothing
      here executes anything — an approval is a recorded decision, carried out
      elsewhere behind its own human step.
    </p>

    <div v-if="error" class="notice bad">{{ error }}</div>
    <div v-else-if="unacknowledged.length" class="notice warn">
      {{ unacknowledged.length }} incident{{ unacknowledged.length === 1 ? '' : 's' }}
      nobody has acknowledged yet.
    </div>

    <p v-if="loading" class="empty">Loading…</p>
    <p v-else-if="!rows.length" class="empty">Nothing is waiting on a person.</p>

    <table v-else class="card">
      <thead>
        <tr>
          <th>Incident</th>
          <th>Tenant</th>
          <th>State</th>
          <th>Last moved by</th>
          <th class="actions">Next</th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="r in rows" :key="r.incident_id">
          <td>
            <div class="mono">#{{ r.incident_id }}</div>
            <div class="muted small">{{ r.description ?? r.rule_id }}</div>
          </td>
          <td>
            <span v-if="r.tenant" class="mono">{{ r.tenant }}</span>
            <span v-else class="pill">deployment</span>
          </td>
          <td>
            <span class="pill" :class="cls(r.state)">{{ String(r.state).replace(/_/g, ' ') }}</span>
          </td>
          <td class="muted small">
            {{ r.actor || '—' }}
            <div v-if="r.reason">“{{ r.reason }}”</div>
          </td>
          <td class="actions">
            <div class="row">
              <button v-if="nextState(r.state)" class="btn sm" :disabled="busy === r.incident_id"
                      @click="move(r, nextState(r.state)!)">
                {{ nextState(r.state)!.replace(/_/g, ' ') }}
              </button>
              <span v-else class="muted small">—</span>
              <button v-if="r.state !== 'completed' && r.state !== 'declined'"
                      class="btn secondary sm" :disabled="busy === r.incident_id"
                      @click="decline(r)">
                Decline
              </button>
            </div>
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
.actions {
  white-space: nowrap;
}
.btn.sm {
  padding: 0.3rem 0.6rem;
  font-size: 0.82rem;
}
</style>
