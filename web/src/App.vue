<!--
  Copyright (C) 2026 James Hickman
  SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script setup lang="ts">
import { computed } from 'vue'
import { RouterLink, RouterView, useRouter } from 'vue-router'
import { useSession } from '@/stores/session'
import { SYSTEM_OBSERVER, SYSTEM_OWNER, SYSTEM_SECURITY, SYSTEM_TENANTS } from '@/stores/session'

const s = useSession()
const router = useRouter()

/** The navigation, filtered by role.
 *
 * COSMETIC, and worth saying so: hiding a link is not access control. The server
 * gates every route on its own role and this list only spares someone a 403 they
 * cannot act on. The roles are additive and NONE of them implies another —
 * system_owner grants authority and holds no operational power — so this is a
 * membership test per item, never a rank comparison.
 */
const nav = computed(() =>
  [
    { to: '/', label: 'Dashboard', role: SYSTEM_OBSERVER },
    { to: '/tenants', label: 'Tenants', role: SYSTEM_OBSERVER },
    { to: '/jobs', label: 'Provisioning', role: SYSTEM_OBSERVER },
    { to: '/security', label: 'Security', role: SYSTEM_SECURITY },
    { to: '/queue', label: 'Acknowledgements', role: SYSTEM_SECURITY },
    { to: '/redactions', label: 'Redactions', role: SYSTEM_SECURITY },
    { to: '/administrators', label: 'Administrators', role: SYSTEM_OWNER },
  ].filter((i) => s.has(i.role)),
)

async function signOut() {
  s.signOut()
  await router.push('/login')
}
</script>

<template>
  <div class="shell">
    <header v-if="s.isSignedIn" class="bar">
      <div class="brand">
        <span class="mark">FileEngine</span>
        <!-- Named on every page. Someone with this open is outside the tenant
             model looking at the whole estate, and a chrome that looked like the
             tenant app would invite them to forget that. -->
        <span class="tier">Deployment Administration</span>
      </div>
      <nav>
        <RouterLink v-for="i in nav" :key="i.to" :to="i.to">{{ i.label }}</RouterLink>
      </nav>
      <div class="who">
        <span class="subject">{{ s.subject }}</span>
        <span class="roles">{{ s.roles.join(' · ') || 'no role' }}</span>
        <button class="link" @click="signOut">Sign out</button>
      </div>
    </header>
    <main :class="{ plain: !s.isSignedIn }">
      <RouterView />
    </main>
  </div>
</template>

<style>
/* The main application's tokens, by the same NAMES so components stay portable
   between the two apps — but inverted: here the dark values are the default and
   light is the override. This console is looked at in a terminal-shaped context,
   and a cross-tenant audit view that flashes white on load is worse than one that
   does not.

   Mechanism matches the tenant SPA: `data-theme` on <html>. */
:root {
  --fg: #e6e8eb;
  --muted: #98a2b3;
  --border: #2b313b;
  --bg: #14171c;
  --card: #1c212a;
  --primary: #3b82f6;
  --primary-hover: #60a5fa;
  --danger: #f87171;
  --success: #4ade80;
  /* Not in the tenant app's set: this tier has states that are neither good nor
     bad but WAITING, and colouring those as success or danger would misreport
     them. `awaiting_dns` is not a failure. */
  --warning: #fbbf24;
  --font-sans: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
}

:root[data-theme='light'] {
  --fg: #1f2933;
  --muted: #6b7280;
  --border: #e5e7eb;
  --bg: #f7f8fa;
  --card: #ffffff;
  --primary: #2563eb;
  --primary-hover: #1d4ed8;
  --danger: #dc2626;
  --success: #15803d;
  --warning: #b45309;
}

* {
  box-sizing: border-box;
}

body {
  margin: 0;
  font-family: var(--font-sans);
  color: var(--fg);
  background: var(--bg);
}

#app {
  font-family: var(--font-sans);
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
  color: var(--fg);
  background: var(--bg);
  min-height: 100vh;
}

button {
  font: inherit;
  cursor: pointer;
  color: inherit;
}

/* ── shared primitives ──────────────────────────────────────────────────── */

.card {
  background: var(--card);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 1rem 1.25rem;
}

h1 {
  font-size: 1.35rem;
  margin: 0 0 0.25rem;
}
h2 {
  font-size: 1.05rem;
  margin: 0 0 0.75rem;
}
.sub {
  color: var(--muted);
  margin: 0 0 1.5rem;
  font-size: 0.9rem;
  max-width: 62ch;
  line-height: 1.5;
}

.btn {
  background: var(--primary);
  color: #fff;
  border: 1px solid transparent;
  border-radius: 6px;
  padding: 0.5rem 0.9rem;
  font-weight: 500;
}
.btn:hover:not(:disabled) {
  background: var(--primary-hover);
}
.btn:disabled {
  opacity: 0.45;
  cursor: not-allowed;
}
.btn.secondary {
  background: transparent;
  border-color: var(--border);
  color: var(--fg);
}
.btn.secondary:hover:not(:disabled) {
  border-color: var(--primary);
  background: transparent;
}
.btn.danger {
  background: var(--danger);
  color: #14171c;
}
.link {
  background: none;
  border: none;
  color: var(--primary);
  padding: 0;
  text-decoration: underline;
}

input,
select,
textarea {
  font: inherit;
  color: var(--fg);
  background: var(--bg);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 0.5rem 0.6rem;
  width: 100%;
}
input:focus,
textarea:focus,
select:focus {
  outline: 2px solid var(--primary);
  outline-offset: -1px;
}
label {
  display: block;
  font-size: 0.82rem;
  color: var(--muted);
  margin-bottom: 0.3rem;
}
.field {
  margin-bottom: 0.9rem;
}

table {
  width: 100%;
  border-collapse: collapse;
  font-size: 0.9rem;
}
th {
  text-align: left;
  color: var(--muted);
  font-weight: 500;
  font-size: 0.8rem;
  text-transform: uppercase;
  letter-spacing: 0.03em;
  padding: 0.5rem 0.6rem;
  border-bottom: 1px solid var(--border);
}
td {
  padding: 0.6rem;
  border-bottom: 1px solid var(--border);
  vertical-align: top;
}
tr:last-child td {
  border-bottom: none;
}

.pill {
  display: inline-block;
  font-size: 0.75rem;
  padding: 0.15rem 0.5rem;
  border-radius: 999px;
  border: 1px solid var(--border);
  color: var(--muted);
  white-space: nowrap;
}
.pill.ok {
  color: var(--success);
  border-color: var(--success);
}
.pill.warn {
  color: var(--warning);
  border-color: var(--warning);
}
.pill.bad {
  color: var(--danger);
  border-color: var(--danger);
}

.notice {
  border: 1px solid var(--border);
  border-left: 3px solid var(--muted);
  border-radius: 4px;
  padding: 0.7rem 0.9rem;
  font-size: 0.88rem;
  line-height: 1.5;
  margin-bottom: 1rem;
  background: var(--card);
}
.notice.bad {
  border-left-color: var(--danger);
}
.notice.warn {
  border-left-color: var(--warning);
}
.notice.ok {
  border-left-color: var(--success);
}

.muted {
  color: var(--muted);
}
.empty {
  color: var(--muted);
  padding: 1.5rem 0;
  font-size: 0.9rem;
}
.mono {
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: 0.85em;
}
.row {
  display: flex;
  gap: 0.6rem;
  align-items: center;
  flex-wrap: wrap;
}
.grid {
  display: grid;
  gap: 1rem;
}
</style>

<style scoped>
.bar {
  display: flex;
  align-items: center;
  gap: 1.5rem;
  padding: 0 1.5rem;
  height: 56px;
  border-bottom: 1px solid var(--border);
  background: var(--card);
  flex-wrap: wrap;
}
.brand {
  display: flex;
  flex-direction: column;
  line-height: 1.15;
}
.mark {
  font-weight: 600;
}
.tier {
  font-size: 0.72rem;
  color: var(--muted);
}
nav {
  display: flex;
  gap: 0.35rem;
  flex: 1;
  flex-wrap: wrap;
}
nav a {
  color: var(--muted);
  text-decoration: none;
  padding: 0.35rem 0.6rem;
  border-radius: 6px;
  font-size: 0.9rem;
}
nav a:hover {
  color: var(--fg);
}
nav a.router-link-exact-active {
  color: var(--fg);
  background: var(--bg);
}
.who {
  display: flex;
  flex-direction: column;
  align-items: flex-end;
  font-size: 0.78rem;
  line-height: 1.3;
}
.subject {
  color: var(--fg);
}
.roles {
  color: var(--muted);
}
main {
  padding: 1.5rem;
  max-width: 1200px;
}
main.plain {
  display: grid;
  place-items: center;
  min-height: 100vh;
  padding: 1.5rem;
  max-width: none;
}
</style>
