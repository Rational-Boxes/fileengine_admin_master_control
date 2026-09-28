# Proposal: the System Administration application

**Status:** Proposal — for review. Nothing implemented, nothing scheduled.
**One of two proposed applications** — see
[`PROPOSED_ADMIN_APPLICATIONS.md`](PROPOSED_ADMIN_APPLICATIONS.md) for why the
pair must be two and not one, and for the handoff between them.
**Companion:** [`DEPLOYMENT_MANAGEMENT_INTERFACE.md`](DEPLOYMENT_MANAGEMENT_INTERFACE.md)
scopes *whether* this should exist and what belongs in it. This proposes *what it
is*. Where they disagree, the scoping wins — it holds the reasoning.
**Depends on:** three prerequisites that must land first (§7). None is large;
all three are defects or gaps that exist today independently of this.

---

## 1. What it is, in one paragraph

A small, separate web application at the deployment tier — above every tenant —
whose purpose is to let a system administrator **see the whole platform and make
the decisions the platform cannot make for itself**. It observes; it holds
queues of things awaiting a human; it records what was decided and by whom. It
does not provision, deploy, restore, or destroy. Those remain Ansible and the
CLI, which are better at them.

It is the answer to a specific absence: every administrative surface that exists
today is scoped to one tenant, and every system-wide operation is a command that
starts and finishes, so nothing in the estate can express *"this is outstanding
and nobody has looked at it"*.

---

## 2. Why a separate application

The cheaper option is to add views to the existing frontend. It should be
rejected, for one reason that outranks the cost:

**The tenant SPA is a per-tenant surface, and this is deliberately a
cross-tenant one.** Putting them in the same application puts a boundary the
platform enforces at every door inside a single codebase, a single session, and
a single set of route guards — where a mistake is a rendering bug rather than a
refused request. That boundary has already been crossed once in this platform
(the 1.9.17 defect), and the architecture's answer is that **each door alone
enforces membership**. A door that is meant to see every tenant should not share
a runtime with one that must see exactly one.

Secondary, and still sufficient on its own: it needs a different authentication
tier (§6), a different audit posture, a different release cadence, and a
substantially smaller attack surface than a full document SPA.

---

## 3. What it does

Four areas. The first is most of the value and the least of the risk.

### 3.1 See the platform

Read-only, cross-tenant. The questions an operator currently answers over SSH:

- **Tenants** — which exist, when created, storage consumed, user count, last
  activity, which hostnames resolve to them.
- **Security** — incidents from the rules engine across every tenant, their
  severity, what fired them, which are unacknowledged (§3.2).
- **Integrity** — accountability chain verification status, audit drain health,
  the last successful backup and whether it verified, offsite mirror lag.
- **Credentials** — service credentials and their expiry; which services have
  which capabilities.
- **Services** — the `/healthz` `/readyz` of every component in one place.

### 3.2 Hold what is waiting on a human

The capability nothing else has. Items arrive from
`audit_service`'s rules engine with `audience` including `deployment`
(`audit_service/design_documents/PROPOSAL_deployment_admin_signal.md`), and
carry a state: `raised → acknowledged → decided → completed`.

Two properties make it a procedure rather than a list:

- **A backlog is visible and alertable.** The count of `raised` items older than
  N hours is the one number that more email cannot satisfy.
- **Decisions record who and when, and record refusals too.** `erasure_ack`
  already models this — `complied = false` recorded rather than silence — and is
  the shape to copy.

### 3.3 Approve redactions

The motivating case. A redaction is raised here, the administrator confirms it
with the end customer, and only then is it approved — after which the cloud-B
redaction application (`scripts/Ansible/docs/PROPOSAL_offsite_redaction.md`)
carries it out, still behind its own human step.

This application **produces an approved request; it does not execute one.** The
separation is the entire security argument of the redaction design and must not
be collapsed here for convenience.

`customer_confirmed` records that a named administrator *asserted* the
confirmation happened. The confirmation itself occurs on a call or in writing,
outside any system, and the UI must not phrase it as though the platform
verified it.

### 3.3.1 What a redaction item must carry

The administrator has to **hold a conversation with a customer** about a
specific deletion. A queue row of opaque uids does not support that, and the
constraint is that it must be made to support it *without resurrecting what the
erasure destroyed*.

What the item carries, and where each part comes from:

| | |
|---|---|
| Tenant, and its administrative contact | LDAP — this is who gets called |
| `erasure_id`, `initiated_at`, actor, reason | the `erasure` row, which retains all of it deliberately |
| `file_uid` | the erasure row; the identifier survives, which is the point |
| **The file's name — only if `name_retained` is true** | see below |
| Whether the payload was ever mirrored offsite | the redaction tool's verification step answers this; the queue can only say "expected" |

**`name_retained = false` means the name was redacted too, and this application
must show its absence rather than find it somewhere else.** The audit log
deliberately stores no `target_name` — "a filename is party data, and this log is
immutable and long-lived" — so there is no second copy to fall back on, and
building one would undo a compliance property the architecture provides for free.
The correct display is *"name redacted with the payload"*, and the conversation
with the customer proceeds from the erasure's reason and timestamp instead.

A reporting surface that quietly made redacted names visible again to the tier
with the most reach would be the worst possible place for that leak.

### 3.3.2 Reporting on redactions

Beyond the queue: a **register** of every redaction, its state, and how long it
has been in it — because the obligation this serves is one the organisation has
undertaken, and "we performed it" is a claim that has to be evidenced later.

- outstanding items by age, which is the number that matters;
- completed ones with the receipt from the redaction tool (§ the pair overview,
  §B — the return path that is not yet designed);
- and, honestly presented, the ones where the loop was never closed.

### 3.4 Report and alert on serious security rules

Breach detection today is effectively per-tenant: incidents are recorded against
a tenant, and whether anyone looks is that tenant's business. That is right for
a tenant's own brute-force lockout and wrong for anything that spans tenants or
that a tenant cannot act on.

Two distinct capabilities, and the second is the one that does not exist at all:

**Aggregation** — every incident from every tenant in one severity-ranked view,
with what fired it, the group key, the count, and whether it has been
acknowledged. Straightforward; it reads what `audit_service` already records.

**Cross-tenant detection** — the capability that only exists at this tier.
Rule windows are keyed per tenant (`wkey = (tenant, rule.id, key)`), so a source
address hitting ten tenants four times each produces **no incident anywhere**:
each tenant is below threshold, so there is nothing for aggregation to find. That
needs a global rule scope in `audit_service`
(`PROPOSAL_deployment_admin_signal.md` §3.5), not a view here — this application
is where the result is seen and acted on, but the detection has to happen where
the events are.

**Intervention.** Seeing a campaign is only useful if the tier that sees it can
act. Per §4 this application executes nothing destructive, so its actions are:
acknowledge, annotate, escalate to the tenant's administrator, and — the one
real lever — **request a credential revocation or an account disable**, which
the CLI or `ldap_manager` carries out. The gap between deciding and acting
remains deliberate even here, and the argument for it is stronger rather than
weaker under pressure.

### 3.4a Tenant setup and management

The deployment tier's most frequent operation, and today a manual sequence:
`tenant.yml`, then DNS, then confirming the vhost and the certificate, then the
MCP host allow-list. In scope here — **requested in this application, executed
by a runner** (§5.3).

What the application owns:

- **The request**, with its inputs validated (§5.3.1) — tenant id, the initial
  administrator, the hostnames.
- **The state**, which is the point: `requested → provisioning → awaiting DNS →
  verifying → live`, or `failed` with which step and why. A tenant part-way
  through creation is exactly the *outstanding* thing §3.2 exists for, and it is
  currently tracked in somebody's terminal scrollback.
- **The outstanding manual steps**, shown rather than assumed. If DNS is not
  ours, the application says so, shows the record to create, and polls until it
  resolves — instead of reporting success at four fifths.
- **Day-to-day management** afterwards: seats, quota, the tenant's own
  administrators, and whether its backup last verified.

What it does **not** own: the credentials, the execution, or the decision to
destroy. Decommissioning a tenant is destructive and belongs with §3.5's phase-4
work, behind the same re-authentication.

### 3.5 The tenant-admin exclusions

Full account deletion, per-user 2FA teardown — the highest-tier tasks the tenant
admin app deliberately excludes. These are destructive, they need an audit trail
more than they need a command, and they arrive **last** (§8), after the trail
exists.

---

## 4. What it must never do

Hard boundaries, not guidelines. Each exists because the alternative makes this
application the most valuable target in the estate.

- **No cloud credentials.** Not DNS, not Spaces, not AWS. A web application
  holding the credential that can destroy things is that credential one exploit
  from being used.
- **It executes nothing destructive.** It records a decision; a playbook, the
  CLI, or the cloud-B application acts. The gap between *approved* and *done* is
  deliberate.
- **No deploys, no restores.** RESTORE.md already argues a restore should be a
  decision rather than a tag someone can pass by accident; the same is true of a
  button.
- **No content.** It never reads file payloads, never renders a document, never
  proxies a download. It deals in identifiers, counts and states. This is also
  what keeps it out of scope for the content-PII rules the audit log follows.
- **No tenant impersonation.** No "log in as this tenant's admin". If a system
  administrator needs tenant access they are granted it explicitly, in the
  tenant, and it is visible there.

---

## 5. Shape

Conventional for this platform, deliberately — a new component should not also
be a new set of habits.

| | |
|---|---|
| **Repo** | `system_admin`, sibling of `share_service` / `folder_actions` |
| **Backend** | Python + FastAPI; reused `fileengine` gRPC client; `FILEENGINE_*` shared config with `SYSADMIN_*` private keys |
| **Frontend** | its own small SPA, not part of the tenant frontend (§2) |
| **Ports** | API `:8103`, monitoring `:8104` — the next free pair after `share_service` (`:8101`/`:8102`). Monitoring binds **loopback-only**, per the platform convention for unauthenticated `/healthz` `/readyz` `/poolz` `/metrics` |
| **Hostname** | `system.<base>` — a plain vhost like `docs.<base>` and `ldap-admin.<base>`, *not* a `<tenant>.<base>` pattern, so it cannot be reached by a tenant-shaped hostname |
| **Storage** | its own database for queue state and decisions. Nothing else writes there, and it writes nowhere else (§5.1) |

### 5.1 What it reads: one queue, one ledger

**Every signal already converges on one place.** Every service publishes to the
same audit stream, and `audit_service` consumes it. That convergence is the
design, and it is what makes a deployment-tier console cheap: it does not need
an integration per service, it needs to watch the point everything already flows
through.

So the primary source is that stream — with one correction the platform has
already made for itself, and which this application must inherit rather than
rediscover.

**Observe the queue; read the ledger.** `puller.py` states the rule plainly:
*"Pull, not push. The Redis stream is a fine transport and an unacceptable
system of record — it is trimmed, sampled and fail-open — so the guarantee path
is a cursor read over the core's transactional outbox."* The stream is `XADD`ed
with `MAXLEN ~`, so it forgets; the durable accountability records
`audit_service` writes to Postgres do not.

A console that read the stream directly would inherit all three failures the
puller exists to avoid: history lost with a node, no way to rebuild from zero,
and a backlog bounded by an outbox that drops oldest under pressure. An
administrator's view of "what happened last month" cannot be built on something
that trims.

The stream still matters — for **latency**. New incidents should appear without
waiting for a poll. The same push/pull split applies here as everywhere else in
this platform: the stream tells the console something arrived; the ledger is
what it displays.

### 5.2 What is not in the queue

The queue carries **events**. It does not carry **state**, and reconstructing
state from a trimmed stream is the mistake "monitor the queue" invites.

| Needed | Not an event — comes from |
|---|---|
| Which tenants exist, their users and roles | LDAP, and `ldap_manager`'s admin API |
| Storage consumed per tenant | the core, as a read-only service principal |
| Service credential expiry | the core's credential store |
| Component health | each service's `/healthz` `/readyz` |
| Chain verification and drain health | `audit_service`'s own state — it is *about* the queue rather than in it |

Five small integrations, none of them a data path, against one primary source
that carries everything event-shaped: signals, incidents, redactions, breaches.
The one write this application makes is its own queue state (§3.2) — and that
asymmetry, reads everywhere and writes in one place, is what keeps §4's
boundaries checkable rather than aspirational.

### 5.3 The runner, and why it is not this application

Driving Ansible from a web process would put the vault password, the DNS API key
and the cloud credentials inside a browser-facing application — the highest
concentration of authority in the estate, behind a session. §4 forbids it, and
tenant creation does not need it.

Instead: the application writes a **job**; a small runner on the host claims it,
executes the playbook, and reports state back. The runner holds the credentials;
the application holds none and knows only that it asked. The same request /
execute split the redaction design uses, for the same reason.

#### 5.3.1 What running a playbook from a UI actually risks

Naming these because they are not obvious from "run the playbook", and each has
a cheap answer:

| Risk | Answer |
|---|---|
| **Injection through the tenant id.** It becomes a Postgres schema name, an LDAP OU, a hostname and a container label. A crafted value reaches four interpreters. | Validate against a strict pattern at the boundary — `^[a-z][a-z0-9-]{1,30}$` — and pass parameters via `--extra-vars` as JSON, never by string interpolation into a command. |
| **Concurrency.** Two overlapping plays against the same inventory is not a supported state, and `deploy.sh --service X` has already shown that a targeted run can ship different variables from a full one. | One runner, one job at a time, a lock the application cannot bypass. Queued, not parallel. |
| **Duration.** A playbook is minutes; an HTTP request is not. | It is a job with state (§3.4a), not a request that blocks. This is the queue again. |
| **Output is not safe to stream.** Playbook output carries vault-decrypted values, passwords and connection strings. | The runner returns a *status and a step*, not a transcript. Full output stays on the host, readable by someone with host access — which is the audience for it. |
| **Partial failure.** A half-created tenant is worse than none: an LDAP OU with no schema, or a vhost with no certificate. | The playbook is already idempotent, so the answer is to re-run rather than to unwind. The state must therefore distinguish *failed, safe to retry* from *failed, needs a human* — and default to the latter. |
| **Certificate rate limits.** Let's Encrypt allows a limited number of certificates per domain per week. A create button that can be clicked repeatedly, or a retry loop, can exhaust that for **every** tenant, not just the one being created. | Retries are rate-limited by the application and a failed certificate step does not auto-retry. This is the one failure here with blast radius beyond the tenant involved. |

#### 5.3.2 The runner is a deployment component, not part of this repository

It runs on the host, holds secrets, and executes Ansible — it belongs with
`scripts/Ansible` and the deployment's own trust boundary, not inside a
browser-facing application. This proposal specifies the contract between them
(a job, a state, a result) and nothing about how the runner is built.

## 6. Authentication

**LDAP roles outside every tenant's scope**, per the decision recorded in the
scoping document §6. They divide by **responsibility rather than seniority** —
`system_observer` (read-only, the baseline), `system_tenants`, `system_security`,
`system_billing`, and `system_owner` which grants the others — and they are
additive and unordered, so a large deployment can give each administrator one
area while a small one gives one person all of them.

Two consequences for this application specifically: a route is authorised by a
**named role rather than by a tier**, so there is no ordering to get wrong and
no implicit inheritance; and every action records **which role authorised it**,
because a person holding three roles who approves a redaction did so as
`system_security`, and that distinction is what makes the decision auditable a
year later.

Requirements specific to this application:

- **MFA is mandatory**, not policy-dependent. Every tenant's 2FA policy is the
  tenant's to set; this tier's is not negotiable.
- **A distinct token audience.** A token minted here must be rejected by every
  tenant door, and a tenant token must be rejected here. Not "should not be
  accepted" — structurally a different audience, so acceptance is impossible
  rather than unimplemented.
- **`system_owner` re-authenticates for destructive actions**, rather than
  holding the capability for a session.
- **Every action is audited at `scope = Global`** with the acting administrator
  named. An administrator tier that is not itself audited is the one place in
  the platform where nobody is watched.

---

## 7. Prerequisites

Three things must land before this is built. All three are defects or gaps that
exist today regardless of whether it is ever built, which is why they are
prerequisites rather than scope.

1. **Deployment roles must be invisible to tenant-scoped role resolution.**
   `LDAPAuthenticator::extractRolesFromGroups` walks a list of fallback search
   bases that includes the directory root, breaking at the first that returns.
   A group placed outside tenant scope therefore sits inside the path a tenant
   login already walks, and whether it is reached is search ordering rather than
   a boundary — the same shape as the 1.9.17 defect. Tenant-context resolution
   must refuse `system_*` names outright, whichever base returned them. **Nothing
   here is safe until this is done.**
2. **Deployment roles must be stripped at every tenant door**, as
   `share_service` already strips admin roles before delegating. Defence in
   depth for (1), because placement is configuration and configuration drifts.
3. **A global rule scope** in `audit_service`
   (`PROPOSAL_deployment_admin_signal.md` §3.5). Without it §3.4's cross-tenant
   detection has nothing to display: windows are keyed per tenant, so a campaign
   spread thinly across tenants produces no incident for this application to
   show. Aggregation alone would make the console look like it was watching
   while the attack it was built for stayed invisible.
4. **A real `AdminNotifier`** in `audit_service`. Today `notify_admins_mandatory`
   is a stub that logs *"MANDATORY admin email for serious incident"* and sends
   nothing, and `main()` wires a real store with no notifier. Until it is
   implemented, this application's queue would be the *only* path to an
   administrator, with no notification to say an item had arrived.

---

## 8. Phasing

1. **Read-only** (§3.1). No writes, no decisions, no destructive capability —
   so the security review in §9 has a much smaller surface, and it delivers the
   daily pain point on its own. Worth building even if nothing else follows.
2. **Acknowledgement** (§3.2). Queue state, backlog metric, the notifier from
   §7.3 pointing at it.
3. **Approval** (§3.3). Redaction confirm/approve. Still executes nothing.
4. **The destructive exclusions** (§3.5), and `system_owner` role granting —
   the single most dangerous capability proposed here, since it is the one that
   can create its own authority. It deserves its own review, and there is a
   reasonable argument that it should stay in provisioning permanently rather
   than arriving in a UI at all (§10-Q2).

---

## 9. Security review points

For the review §2 and §4 argue this needs, before it is reachable:

1. A tenant token is rejected here, and a `system_*` token is rejected at every
   tenant door — both asserted, both directions.
2. A `system_*` role never appears in a tenant-context role resolution (§7.1),
   tested against a directory that actually contains one.
3. No route returns file content, a filename, or anything the audit log would
   redact.
4. The application holds no credential that can delete from any bucket, and none
   that can write to another service's database.
5. Every state transition in the queue is audited at `scope = Global` with the
   acting administrator, and a refusal is recorded as explicitly as an approval.
6. `system_owner` actions require re-authentication, and the session cannot be
   extended to avoid it.
7. The monitoring port is loopback-only and the API host is not a
   `<tenant>.<base>` pattern.

---

## 10. Open questions

**Q1 — Does the tenant list come from LDAP or the core?** Both know about
tenants and neither is obviously authoritative. Worth settling before §3.1 is
built, because the answer decides whether a tenant that exists in one and not the
other is visible as a discrepancy or invisible as an absence — and that
discrepancy is exactly the kind of thing this application should surface.

**Q2 — Should `system_owner` role granting live here at all?** It is the one
capability that can create authority, and provisioning already does it. Keeping
it in Ansible means a role grant is a reviewed commit rather than a click. The
counter-argument is that an emergency grant at 3am through a playbook is worse
than one through a UI with MFA and an audit trail. Not obvious either way.

**Q3 — What happens when `audit_service` is down?** §5.1 makes it the primary
source. A deployment-tier console that goes blind exactly when something is
wrong is the wrong failure mode, and the queue state at least should survive in
this application's own database rather than being a view over another service's.

**Q4 — Is there a tier below `system_observer`?** Support staff who need to see
whether a tenant is healthy without seeing security incidents. Possibly, and
possibly that is what `system_observer` already is with incidents removed.
