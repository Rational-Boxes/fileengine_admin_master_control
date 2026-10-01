// Copyright (C) 2026 James Hickman
//
// SPDX-License-Identifier: AGPL-3.0-or-later

import { createApp } from 'vue'
import { createPinia } from 'pinia'
import App from './App.vue'
import { router } from './router'

// Dark by default, and set before the app mounts so there is no light flash on a
// cross-tenant audit view. A stored preference wins; `light` is the only value
// that changes anything, so an unreadable/absent value falls back to dark.
try {
  const pref = window.localStorage.getItem('amc.theme')
  document.documentElement.dataset.theme = pref === 'light' ? 'light' : 'dark'
} catch {
  document.documentElement.dataset.theme = 'dark'
}

createApp(App).use(createPinia()).use(router).mount('#app')
