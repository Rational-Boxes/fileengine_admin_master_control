<!--
  Copyright (C) 2026 James Hickman
  SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script setup lang="ts">
import { useSession } from '@/stores/session'
const s = useSession()
</script>

<template>
  <!--
    A terminal page, and that is its job. The guard sends anyone lacking a role
    here, so this route must require only a session — sending a role-less
    administrator to a page that needs a role is how a guard loops forever.
  -->
  <div class="card box">
    <h1>Not your authority</h1>
    <p class="sub">
      You are signed in as <span class="mono">{{ s.subject }}</span>, holding
      <span class="mono">{{ s.roles.join(', ') || 'no deployment role' }}</span>.
      That page needs a role you do not have.
    </p>
    <p class="sub">
      The deployment roles are additive and none implies another — system_owner
      grants authority and holds no operational power of its own, so being an owner
      does not open the operational pages. Another owner can grant what you need,
      and it will be recorded.
    </p>
    <RouterLink to="/" class="btn secondary">Back to the dashboard</RouterLink>
  </div>
</template>

<style scoped>
.box {
  max-width: 560px;
}
.btn {
  display: inline-block;
  text-decoration: none;
}
</style>
