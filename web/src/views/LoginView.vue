<!--
  Copyright (C) 2026 James Hickman
  SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script setup lang="ts">
import { nextTick, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import QRCode from 'qrcode'
import { apiError } from '@/services/client'
import { useSession } from '@/stores/session'

const s = useSession()
const router = useRouter()
const route = useRoute()

type Step = 'password' | 'verify' | 'enroll' | 'codes'
const step = ref<Step>('password')
const subject = ref('')
const password = ref('')
const code = ref('')
const method = ref('totp')
const busy = ref(false)
const error = ref('')
const qr = ref('')
const secret = ref('')
const acknowledged = ref(false)

const codeField = ref<HTMLInputElement | null>(null)

async function focusCode() {
  await nextTick()
  codeField.value?.focus()
}

async function submitPassword() {
  busy.value = true
  error.value = ''
  try {
    const next = await s.signIn(subject.value.trim(), password.value)
    // The password is not kept once it has been spent. There is nothing further
    // to do with it and a reactive ref holding it costs nothing to clear.
    password.value = ''
    if (next === 'done') return void router.push(redirect())
    if (next === 'enroll') {
      step.value = 'enroll'
      await beginEnrolment()
      return
    }
    method.value = s.challenge?.methods?.includes('totp') ? 'totp' : (s.challenge?.methods?.[0] ?? 'totp')
    step.value = 'verify'
    await focusCode()
  } catch (e) {
    error.value = apiError(e)
  } finally {
    busy.value = false
  }
}

async function beginEnrolment() {
  busy.value = true
  error.value = ''
  try {
    const begun = await s.enrollBegin()
    secret.value = begun.secret
    // Rendered locally from the otpauth URI. It is NOT sent to an image service:
    // that URI contains the TOTP secret, and handing it to a third party to draw
    // a picture would disclose the factor being enrolled.
    qr.value = await QRCode.toDataURL(begun.otpauth_uri, {
      width: 208,
      margin: 1,
      color: { dark: '#e6e8eb', light: '#1c212a' },
    })
    await focusCode()
  } catch (e) {
    error.value = apiError(e)
  } finally {
    busy.value = false
  }
}

async function submitCode() {
  busy.value = true
  error.value = ''
  try {
    if (step.value === 'enroll') {
      await s.enrollComplete(code.value.trim())
      code.value = ''
      if (s.recoveryCodes.length) {
        // Deliberately NOT straight to the console. These are shown once and
        // nowhere else, and landing on a dashboard would bury them.
        step.value = 'codes'
        return
      }
      return void router.push(redirect())
    }
    await s.verify(code.value.trim(), method.value)
    code.value = ''
    await router.push(redirect())
  } catch (e) {
    error.value = apiError(e)
    code.value = ''
    await focusCode()
  } finally {
    busy.value = false
  }
}

function redirect(): string {
  const next = route.query.next
  // Only ever an in-app path. An absolute URL here would make the login form an
  // open redirect, and this is the one form in the estate worth phishing.
  if (typeof next === 'string' && next.startsWith('/') && !next.startsWith('//')) return next
  return '/'
}

function startOver() {
  s.abandonChallenge()
  step.value = 'password'
  code.value = ''
  error.value = ''
  qr.value = ''
}

async function finishCodes() {
  s.acknowledgeRecoveryCodes()
  await router.push(redirect())
}

function copyCodes(codes: string[]) {
  void navigator.clipboard?.writeText(codes.join('\n'))
}
</script>

<template>
  <div class="box card">
    <header>
      <h1>Deployment Administration</h1>
      <p class="sub">
        This console is outside the tenant model. It reads every tenant's audit and
        grants deployment authority.
      </p>
    </header>

    <div v-if="error" class="notice bad">{{ error }}</div>

    <!-- step 1 ─────────────────────────────────────────────────────────── -->
    <form v-if="step === 'password'" @submit.prevent="submitPassword">
      <div class="field">
        <label for="subject">Administrator</label>
        <input id="subject" v-model="subject" autocomplete="username" autofocus
               placeholder="you@example.com" />
      </div>
      <div class="field">
        <label for="password">Password</label>
        <input id="password" v-model="password" type="password" autocomplete="current-password" />
      </div>
      <button class="btn" type="submit" :disabled="busy || !subject || !password">
        {{ busy ? 'Checking…' : 'Continue' }}
      </button>
      <p class="hint">A second factor is required at this tier.</p>
    </form>

    <!-- step 2a: prove an existing factor ──────────────────────────────── -->
    <form v-else-if="step === 'verify'" @submit.prevent="submitCode">
      <p class="hint top">
        Signing in as <span class="mono">{{ subject }}</span>.
      </p>
      <div class="field">
        <label for="code">
          {{ method === 'recovery' ? 'Recovery code' : 'Code from your authenticator' }}
        </label>
        <input id="code" ref="codeField" v-model="code" inputmode="text"
               autocomplete="one-time-code" :placeholder="method === 'recovery' ? '' : '000000'" />
      </div>
      <div v-if="(s.challenge?.methods?.length ?? 0) > 1" class="field">
        <label for="method">Method</label>
        <select id="method" v-model="method">
          <option v-for="m in s.challenge?.methods" :key="m" :value="m">
            {{ m === 'totp' ? 'Authenticator app' : m === 'recovery' ? 'Recovery code' : m }}
          </option>
        </select>
      </div>
      <div class="row">
        <button class="btn" type="submit" :disabled="busy || !code">
          {{ busy ? 'Verifying…' : 'Sign in' }}
        </button>
        <button class="link" type="button" @click="startOver">Start over</button>
      </div>
    </form>

    <!-- step 2b: first login, no factor yet ────────────────────────────── -->
    <form v-else-if="step === 'enroll'" @submit.prevent="submitCode">
      <div class="notice">
        <strong>Set up two-factor authentication.</strong>
        This is required before your first session — there is nothing to skip to.
      </div>
      <div class="enrol">
        <img v-if="qr" :src="qr" alt="Scan this with your authenticator app" width="208"
             height="208" />
        <div>
          <p class="hint">Scan with your authenticator app, or enter the key by hand:</p>
          <p class="mono key">{{ secret }}</p>
          <p class="hint">Then enter the six-digit code it shows.</p>
        </div>
      </div>
      <div class="field">
        <label for="ecode">Code</label>
        <input id="ecode" ref="codeField" v-model="code" inputmode="numeric"
               autocomplete="one-time-code" placeholder="000000" />
      </div>
      <div class="row">
        <button class="btn" type="submit" :disabled="busy || !code">
          {{ busy ? 'Confirming…' : 'Confirm and sign in' }}
        </button>
        <button class="link" type="button" @click="startOver">Start over</button>
      </div>
    </form>

    <!-- step 3: the codes, once ────────────────────────────────────────── -->
    <div v-else-if="step === 'codes'">
      <div class="notice warn">
        <strong>Save your recovery codes now.</strong>
        They are shown once and cannot be retrieved. Losing your only factor on
        this console means nobody can grant authority to anybody — including you.
      </div>
      <ul class="codes mono">
        <li v-for="c in s.recoveryCodes" :key="c">{{ c }}</li>
      </ul>
      <div class="row">
        <button class="btn secondary" type="button" @click="copyCodes(s.recoveryCodes)">
          Copy all
        </button>
      </div>
      <label class="ack">
        <input type="checkbox" v-model="acknowledged" />
        I have saved these somewhere I can reach without this console.
      </label>
      <button class="btn" type="button" :disabled="!acknowledged" @click="finishCodes">
        Continue
      </button>
    </div>
  </div>
</template>

<style scoped>
.box {
  width: 100%;
  max-width: 440px;
}
header {
  margin-bottom: 1.25rem;
}
.sub {
  margin-bottom: 0;
}
.hint {
  color: var(--muted);
  font-size: 0.82rem;
  margin: 0.75rem 0 0;
  line-height: 1.5;
}
.hint.top {
  margin: 0 0 1rem;
}
.enrol {
  display: flex;
  gap: 1rem;
  align-items: flex-start;
  margin-bottom: 1rem;
}
.enrol img {
  border-radius: 6px;
  flex: none;
}
.key {
  word-break: break-all;
  background: var(--bg);
  border: 1px solid var(--border);
  border-radius: 4px;
  padding: 0.4rem 0.5rem;
  margin: 0.4rem 0;
}
.codes {
  list-style: none;
  padding: 0.75rem;
  margin: 0 0 1rem;
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 0.3rem 1rem;
  background: var(--bg);
  border: 1px solid var(--border);
  border-radius: 6px;
}
.ack {
  display: flex;
  gap: 0.5rem;
  align-items: flex-start;
  color: var(--fg);
  font-size: 0.85rem;
  margin: 1rem 0;
  line-height: 1.45;
}
.ack input {
  width: auto;
  margin-top: 0.15rem;
}
</style>
