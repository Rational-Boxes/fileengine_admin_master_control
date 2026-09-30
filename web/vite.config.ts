// Copyright (C) 2026 James Hickman
//
// SPDX-License-Identifier: AGPL-3.0-or-later

import { fileURLToPath } from 'node:url'
import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

// The console's API. In dev this is proxied rather than called cross-origin, for
// the same reason the tenant SPA proxies the bridge: same-origin means no CORS
// and no preflight on every authenticated request.
//
// In PRODUCTION the built bundle is served by the FastAPI app itself (see
// app.py), so `/v1` is genuinely same-origin and this proxy is a dev-only
// convenience. That matters for the ngrok case: the account allows ONE agent
// session, so the console and its UI have to share a single endpoint.
const API = process.env.AMC_DEV_API ?? 'http://localhost:8103'

export default defineConfig({
  plugins: [vue()],
  resolve: {
    alias: { '@': fileURLToPath(new URL('./src', import.meta.url)) },
  },
  // Not 3000: that is the tenant SPA's port, and running both at once is the
  // normal case when working on the estate.
  server: {
    port: 3100,
    host: true,
    proxy: {
      '/v1': { target: API, changeOrigin: true },
    },
  },
  build: {
    // Emitted where app.py looks for it. Nothing serves it unless it exists.
    outDir: 'dist',
    emptyOutDir: true,
  },
  test: {
    environment: 'jsdom',
    include: ['src/**/*.spec.ts'],
  },
})
