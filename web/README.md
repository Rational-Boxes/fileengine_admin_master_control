# admin_master_control — console UI

Vue 3 + Vite + Pinia, for the deployment administration console. **Not** the tenant
SPA: a different trust tier, outside the tenant model.

```bash
npm install
npm run dev          # :3100, proxying /v1 to localhost:8103
npm run build        # dist/, which the FastAPI app then serves itself
npm run test:run
npm run type-check
```

## Why the bundle is served by FastAPI

Same origin. The alternative is CORS on the console that reads every tenant's
audit, a preflight on every call, and an allow-list to keep correct. It also makes
the dev tunnel work at all — the ngrok account allows one agent session, so the API
and the UI have to share a single endpoint.

## Conventions

The colour tokens are the main application's, by the same names so components stay
portable — but **dark is the default** here (`:root` carries the dark values,
`[data-theme='light']` overrides), toggled the same way, via `data-theme` on
`<html>`.

Charts are ECharts via `vue-echarts`, imported from `echarts/core` with explicit
registration rather than the convenience bundle, which pulls in about a megabyte for
the four chart types in use. `BaseChart` reads the **live CSS variables** so one
theme definition governs both the DOM and the canvas.

## Three things not to "simplify"

**The 401 exemption in `services/client.ts`.** `POST /v1/auth/token` answers 401
*with a challenge* — that is the protocol, not an expired session. A blanket
401 → redirect (as the tenant SPA has, correctly, for its own API) fires during
login and discards the challenge on every attempt.

**`may_provision` comes from the server.** Never re-derive it. A local
`state === 'verified' || override` looks identical and is a second implementation
of the rule protecting a certificate rate limit shared by every tenant on the
domain; when they disagree the button is live and the server is right.

**`/denied` requires only a session.** Sending a role-less administrator to a page
that needs a role is how a guard loops forever, and a single-hop test cannot see it
— `router/guard.spec.ts` drives it repeatedly and asserts it settles.

## Testing note

jsdom **silently ignores `<script type="module">`**, which is what Vite emits, so it
cannot smoke-test a built bundle — an attempt to do so reported "no script errors on
boot" while executing nothing. Component tests mount real components under vitest;
to check the built bundle actually boots, use a real browser:

```bash
chromium-browser --headless --virtual-time-budget=6000 --dump-dom http://localhost:8103/
```
