# Proposal: platform observability — metrics, reports and the status dashboard

**Status:** Proposal — for review. Nothing implemented, nothing scheduled.
**Part of:** the System Administration application
([`PROPOSAL_system_administration_application.md`](PROPOSAL_system_administration_application.md)),
§3.1 *See the platform*. The derivation mechanism and its three traps are in
[`../../audit_service/design_documents/PROPOSAL_deployment_admin_signal.md`](../../audit_service/design_documents/PROPOSAL_deployment_admin_signal.md)
§3.8; this is the catalogue and the presentation.

---

## 1. What these are for

Not "a dashboard". Every metric below exists to serve a decision a deployment
administrator actually makes, and one that cannot be made today without SSH:

- *When do I need more disk, and which tenant is driving it?*
- *Is the platform silently not doing something it reports as done?*
- *Is this tenant actually using what they are paying for?*
- *Where is it bad, as users experience it rather than as processes report it?*
- *What obligations are outstanding?*

Metrics that serve no decision are cost with a graph attached. Each section
below names its decision first.

---

## 2. What the stream already carries

Every event has: `tenant`, `category` (access | mutate | permission | user |
auth | admin), `action`, `outcome` (ok | denied | error), `actor`,
`actor_roles`, `target_type`, `target_uid`, `source_iface` (grpc | rest | webdav
| mcp), `source_addr`, `request_id`, `ts`, and a free-form JSON `detail`.

That is enough for most of §4 immediately. Two gaps, named in §5.

**`action` is free-form text from the emitter**, unlike category and outcome
which are enumerated in `codes.py`. A typo, or a new service, silently creates a
new time series forever. **The metrics consumer must map actions through an
allowlist and bucket the remainder as `other`** — and a rising `other` is itself
worth watching, because it means something started emitting a vocabulary nobody
registered.

### 2.1 The hard part is interpretation, not aggregation

The data is there and it is **sprawling** — eleven services, each emitting its
own action vocabulary, into one stream. The aggregation is trivial (§7.4a). The
risk is a query that runs, returns a number, and is confidently wrong.

Four ways that happens here, all of them properties of the architecture rather
than defects:

**1. One user action produces events at several layers.** A download is seen by
the door that served it and by the core that read the bytes. An upload is seen by
the door, the core, and then again as the conversion pipeline writes renditions —
which are more core writes. Summing bytes or counting operations across layers
inflates a customer's usage by a factor nobody can explain, and the inflation is
not constant: it varies with how much derived work a file happens to trigger.

**2. Much of the traffic is the platform working on itself.** Renditions,
indexing, reconcile sweeps and culls are all real operations by real principals —
the `svc-*` accounts in `ou=services` and the workers' own identities. They are
not customer activity. Billing a tenant for the platform's own indexing is
indefensible, and counting it as "active usage" makes a dormant tenant look busy.

**3. Delegation makes `actor` mean something different depending on the
emitter.** This is deliberate and documented: a share redemption calls the core
**as the link's creator**, so the core's own events attribute the read to a
person who was not there. `audit_service` is the only place that records the
external party (`share:<link_uid>|<verified_email>`). Any metric keyed on `actor`
without knowing which layer emitted it therefore mis-attributes every delegated
operation — silently, and in a way that looks like a real user being busy.

**4. `action` is a per-service vocabulary with no registry.** Whether the core's
`read_version` and a door's download are the same fact is currently a matter of
opinion held separately by whoever writes each query.

### 2.2 The answer is a taxonomy, not better queries

Interpretation should be settled **once, as reviewed data**, not re-derived by
each query, dashboard and billing run.

An **event taxonomy registry** declaring, for each `(service, action)` pair:

| Field | Answers |
|---|---|
| `origin` | `user` \| `machinery` — is this a customer doing something, or the platform working on itself? |
| `authoritative_for` | which facts, if any, this event is the **single** counting point for — bytes egressed, operations, storage delta |
| `attribution` | whose activity it is: the event's `actor`, or the door's external party, or nobody |
| `contributes_to` | the metrics and billing dimensions it feeds |

Three rules fall out of it, and they are the ones that make the numbers
defensible:

- **Exactly one authoritative emitter per fact.** Bytes egressed are counted at
  the door that served them, never also at the core. The second layer's events
  remain in the ledger — they are the audit record — and are simply not a
  counting point.
- **`origin = machinery` is excluded by default**, and included only where
  deliberately chosen (renditions *do* consume disk, so storage counts them; they
  are not *operations* a customer performed).
- **Attribution follows the taxonomy, not the field.** A delegated read is
  attributed to the external party or to nobody, never to the creator whose
  identity the core saw.

### 2.3 Why this makes the numbers defensible

The registry is **versioned data**, which gives three things nothing else does.

- **It goes in the statement.** §7.4's reproducibility already requires recording
  the code version and the sequence bounds; the taxonomy version belongs beside
  them. "Why did last quarter's invoice use a different method?" then has an
  answer.
- **It is testable.** Assert that every `(service, action)` seen in the last N
  days is registered — which closes the loop on §2's `other` bucket: a rising
  `other` is not merely a cardinality nuisance, it is **an unregistered fact
  silently absent from every report and every invoice**.
- **It makes the interpretation reviewable.** The question "should a rendition
  write count as a customer operation?" is a decision someone can disagree with
  in a pull request, rather than an accident buried in a `WHERE` clause.

**None of this is optional for billing**, and it is nearly as important for the
reports: a dashboard that counts the platform's own indexing as tenant activity
will be believed, and will make every adoption metric in §4.3 wrong in the
direction that looks good.

---

## 3. The metric class this platform most needs: conservation checks

Before the catalogue, the framing that should shape it.

This platform's characteristic failure is not the crash. It is **the operation
that reports success while doing nothing**, and its history is a list of them:
`S3Storage::delete_file` was a hard-coded refusal, so erasure destroyed rows and
left every object in the bucket while reporting success; `mc mirror` exited 0
having copied nothing, with `--json` reporting success per object; the CLI exited
0 whether an operation succeeded or was refused; `notify_admins_mandatory` logs
that a mandatory admin email was sent and sends none; superseded `metamodel`
renditions have never been pruned because the format was absent from one
allowlist.

None of those is detectable from a process metric. All of them are detectable
from **two independent counts that must agree**. So the most valuable class of
metric here is not a rate or a gauge — it is a **conservation check**, and a
dashboard for this platform should lead with them.

| Check | Should agree | Divergence means |
|---|---|---|
| Objects in the content bucket ↔ versions rows | after accounting for known orphans | culled-but-not-reclaimed, erased-but-surviving, or a mirror that is not mirroring |
| Files whose type bears text ↔ documents with extracted text | exactly | indexing silently stopped for a MIME class |
| Files ↔ files with a current-version rendition set | by policy | a converter is failing for a format, invisibly |
| Events emitted by services ↔ events drained into the ledger | exactly | the audit path is lossy, which is the one thing it must never be |
| Erasures initiated ↔ erasures completed everywhere | exactly | the offsite loop is not being closed (see the redaction procedure's §B) |
| Credentials issued ↔ credentials in use | roughly | a service is running on a credential nobody tracks |

Each is cheap, each has caught a real defect in this codebase already, and each
answers a question no single counter can.

---

## 4. Catalogue

### 4.1 Capacity and cost

*Decision: when do I provision, and who is driving the bill?*

| Metric | Granularity | Note |
|---|---|---|
| Stored bytes: **source / versions / renditions, separately** | tenant, total | Renditions are derived and can exceed the source — the media work showed a published video set at 720p + 480p + Opus + poster roughly doubling a video folder. Lumping them hides the thing you can act on. |
| Growth rate (bytes/day) and projected time-to-threshold | tenant, total | The forecast is the decision; the gauge is not. |
| Object count vs versions rows | total | §3, and it is also the orphan-cruft number. |
| Egress: downloads, share redemptions, WebDAV | tenant | The bill nobody predicts. Share links make this user-triggerable. |
| Cold reads (served from the object store rather than cache) | tenant | Rising cold-read rate is the cache losing its working set — a cost and latency signal before it is a complaint. |
| Conversion CPU-seconds | tenant, format | CSAI is the expensive service; per-format shows which corpus costs what. |

### 4.2 Silent-failure detection

*Decision: is the platform doing what it says?* §3's conservation checks, plus:

| Metric | Note |
|---|---|
| Conversion outcome rate by format | `converted / unsupported / skipped / error`. A format quietly moving to `unsupported` is a regression nobody reports. |
| Index lag: files created ↔ files indexed, by age | A growing tail is the reconcile sweep not keeping up or not running. |
| Rendition coverage by format | The "no previews" complaint, findable before it is made. |
| Event drain lag, per consumer group | Both the audit consumer and the rules consumer. A lagging rules consumer means detection is behind, which is worse than it sounds. |
| Reconcile sweep: examined / repaired / failed | Zero repaired for a week is either healthy or not running, and the two look identical without this. |
| Worker liveness by service | The ingest worker not running produces no error — only an absence of previews. |

### 4.3 Adoption and engagement

*Decision: is this tenant getting value, and which surfaces matter?*

| Metric | Granularity |
|---|---|
| Active users — daily, weekly, monthly | tenant |
| Seats provisioned vs seats active | tenant — the churn signal, and the upsell one |
| Operations per active user | tenant |
| Surface mix: web / WebDAV / MCP / share / integration | tenant, total — where to invest |
| Feature usage: search, chat, comments, reviews, share links, editing sessions, comparisons | tenant |
| Time to first file after tenant creation | tenant — onboarding health, and it is a single number |
| Dormancy: tenants with no activity in N days | total |

### 4.4 Reliability as users experience it

*Decision: where is it actually bad?*

| Metric | Note |
|---|---|
| Error rate by action and by `source_iface` | The door matters: WebDAV failing while the SPA is fine is a different problem. |
| Denial rate, excluding attack traffic | A rising denial rate among legitimate users is usually a misconfigured ACL, not an intrusion. |
| Upload and download failure rate, by size band | Large-file failures hide inside an overall rate that looks fine. |
| Operation latency, p50/p95 | **Needs §5.** |
| Auth failure rate for known principals | Distinct from §3.6's fan-out: this is *our users struggling*, not someone probing. |

### 4.5 Obligation and risk

*Decision: what is outstanding, and what is exposed?*

| Metric | Note |
|---|---|
| Erasures pending offsite confirmation, by age | The redaction loop. Age is the number that matters. |
| Unacknowledged deployment signals, by age | The one number more email cannot satisfy. |
| Live share links, and worst-case egress | `archive_bytes × max_uses` summed — the exposure a tenant has created. |
| Open external share links by access mode | Once media share lands, `open` mode is the one to watch. |
| Service credentials within N days of expiry | An expiry outage is entirely preventable and entirely silent until it happens. |
| Tenants whose backup last verified more than N hours ago | Verified, not taken. |

---

## 5. What the events do not yet carry

Two things §4 needs that are not in the envelope today. Both are small and both
should be decided before dashboards are built on data that is not there.

1. **Duration.** No latency metric is possible without it. Adding `duration_ms`
   to the envelope is a one-field change at the emitters, and the alternative —
   pairing start/end events by `request_id` — doubles event volume to compute
   something the emitter already knows.
2. **Size.** Bytes moved per operation. `detail` is free-form JSON so a service
   *can* put it there, but deriving a metric from free-form detail is fragile in
   exactly the way §2's `action` warning describes. A small set of **typed
   optional numeric fields** (`duration_ms`, `bytes`) is better than a detail
   convention nobody can enforce.

Until then: §4.4's latency row and the byte-based rows in §4.1 are the ones to
defer, and they should be marked as such on the dashboard rather than quietly
showing zeros.

---

## 6. The real-time status dashboard

A **different thing** from the reports above, and conflating them is how both
get worse. Reports answer "what has been happening"; the status dashboard
answers **"is it healthy right now"**, in about five seconds, for someone who has
just been paged or who checks it each morning.

### 6.1 What is on it

One screen, no scrolling, roughly in this order:

1. **Stream health.** Drain lag per consumer group, and events/sec in and out.
   First, because everything else on this page is derived from it — if this is
   behind, the rest of the page is a photograph of the past.
2. **Conservation checks** (§3), as a row of pass/diverged indicators with the
   magnitude of any divergence. The platform's characteristic failure gets the
   most prominent place it can honestly have.
3. **Outstanding decisions.** Unacknowledged signals and pending redactions, by
   age. The only actionable items on the page.
4. **Active incidents** by severity, including any cross-tenant fan-out.
5. **Services** up / degraded / down, with the degraded reason.
6. **Capacity headroom** — disk, and the shortest projected time-to-threshold
   across tenants.
7. **Right now** — operations/sec, error rate, active tenants, active users.

### 6.2 It must degrade honestly

The most important property, and the one most dashboards get wrong.

**A stale dashboard must look stale, not healthy.** If the metrics consumer is
behind, or a source is unreachable, every affected panel shows its as-of time and
greys out — it does not show the last good value as though it were current. This
platform has a documented history of surfaces that reported something other than
what they measured, and a frozen status page showing green is the purest form of
that failure.

Concretely: every panel carries an as-of timestamp; a panel older than its
refresh interval is visibly stale; and the page states the *worst* staleness at
the top rather than letting a fresh panel imply the page is fresh.

### 6.3 It is not the alerting path

The dashboard is for when someone is already looking. Anything that needs a
human who is *not* looking goes through the alerting path and the notifier — a
dashboard nobody has open at 3am has raised nothing. The corollary: **no metric
should exist only on the dashboard if its absence would matter overnight.**

### 6.4 Presentation discipline

- **Tenant-labelled series are a cross-tenant disclosure.** Correct at this tier,
  and they must never reach a tenant-facing view or a shared monitoring system
  where tenant admins have accounts.
- **No actor, uid, filename or address in any label** (§3.8's traps).
- **Rates and ratios over raw counts** wherever the decision is comparative — a
  tenant with 10× the users will always top a raw-count table, which makes the
  table useless for spotting the anomalous one.
- **Every panel links to the ledger query behind it**, so "why is that number
  odd" is one click rather than an SSH session. The number is the aggregate; the
  answer is always in the record.

---

## 7. Metering and billing

For a hosted service the same activity can feed billing, and a metered plan
offered alongside a flat one. The data is the same; **the pipeline must not be.**

### 7.1 Billing reads the ledger, never the metrics

§3.8 of the signal proposal states that metrics are lossy, resampled and briefly
retained, and that nothing compliance-bearing may be answered from a series. **An
invoice is compliance-bearing.** A customer will dispute one, and the answer has
to be reproducible months later.

So metering derives from the **durable accountability records** — the same
hash-chained ledger `audit_service` writes, which is complete, ordered,
idempotent on `event_id`, and replayable from zero. The Redis stream is
explicitly "a fine transport and an unacceptable system of record"; billing is
the clearest case of something that must not be built on it.

This also disposes of the most common billing defect before it can happen.
Delivery is at-least-once, so a stream-derived meter **double-counts on
redelivery** — silently, and in the direction that bills the customer twice. The
ledger deduplicates on `event_id` already; a meter that reads it inherits that
for free.

### 7.2 Storage is a running total, reconciled by a snapshot

Bytes in and out for a period are a windowed sum, counted at the one
authoritative layer the taxonomy names (§2.2). Storage is different in shape —
"bytes held" is a level, not a flow — but it is still derivable, and **as a
running total rather than as a series of measurements.**

Every operation that changes the level emits a signed delta: a version written
(+), a version culled (−), a file erased (−), a rendition written (+), a
rendition pruned (−). The level at any instant is the sum of deltas before it.

**This works because the source is the ledger, not the stream.** The Redis stream
trims, so a running total over *it* would be unrecoverable after the first
trim — which is what an earlier draft of this section argued, before concluding
too quickly that snapshots were therefore required. The accountability records do
not trim: they are complete, ordered and replayable from zero, so a total
accumulated over them is exact and can be rebuilt at any time by replaying.

It is also **better for billing than sampling**. Byte-hours from a running total
is exact — the sum of each level multiplied by the time it held — because the
level changes at known instants. Byte-hours from periodic samples is a
trapezoidal approximation whose error depends on the sampling interval, and a
customer who uploads and deletes a terabyte between two samples is billed for
nothing.

**What it requires**, and it is the one prerequisite: every byte-changing
operation must emit its signed delta. That is §5's `bytes` field applied to
mutations rather than only to transfers, and it must include the operations
nobody thinks of as writes — culls, erasures and rendition pruning all reduce
stored bytes and all currently report counts rather than sizes.

#### The snapshot does not go away; its job changes

A running total drifts. A missed event, or an operation that changes bytes
without emitting a delta, moves the total away from reality **silently and
cumulatively** — which is precisely this platform's characteristic failure
(§3).

So a periodic measurement of actual stored bytes remains, not as the billing
input but as the **conservation check** on it:

> running total ↔ measured bytes in the object store

Their divergence is a monitored metric, and a growing divergence means a
byte-changing operation is not emitting. That is the §3 pattern applied to the
largest line on an invoice, and it is the difference between a number that is
exact and a number that is merely precise.

Split the same way §4.1 does — source, versions, renditions — because a customer
billed for storage will ask why it exceeds the files they uploaded, and "your
published video renditions" is an answer where "storage" is not.

### 7.3 What is meterable

| Dimension | Source | Unit | Note |
|---|---|---|---|
| Storage | §7.2 snapshot | GB-hours | split source / versions / renditions |
| Egress | ledger | GB | downloads, share redemptions, WebDAV; the one a customer can drive without noticing |
| Operations | ledger | count | by category; the "API calls" line |
| Conversion | ledger + `duration_ms` (§5) | CPU-seconds | needs the field §5 asks for |
| AI usage | CSAI | tokens / embeddings | this one has a real per-call cost to a provider, so it is the strongest metered candidate |
| Seats | state sample | user-months | provisioned or active — a commercial decision, not a technical one |

### 7.4 The disciplines a meter needs and a dashboard does not

1. **Closed periods and immutable statements.** A billing run for a period reads
   the ledger up to a fixed point, produces a statement, and stores it. It does
   not recompute on demand. If re-running an old period can produce a different
   number, the difference is unexplainable to a customer and the statement was
   never a statement.
2. **Reproducible.** Same input, same code version, same answer. Which means the
   code version is part of the statement.
3. **Itemised to the day, and never to the filename.** A dispute needs "which
   days drove this", and the ledger supports it. It must not be itemised by file
   name: the audit log deliberately holds no `target_name`, and an invoice is
   exactly the wrong place to become the system that does.
4. **Fail closed toward not billing.** If a period's inputs are incomplete — a
   drain gap, a missing storage sample — **do not estimate**. Bill what is
   provable and record the gap. Over-billing is a trust event in a way that
   under-billing is not, and an estimate that nobody can reproduce is the worst
   of both.
5. **Round in the customer's favour.** Cheap, and it removes an entire class of
   argument.

### 7.4a The calculation, and the two ways a trivial one goes wrong

For everything event-shaped the calculation really is trivial — a grouped
aggregate over a window:

```sql
SELECT tenant, category, count(*), sum(bytes), sum(duration_ms)
  FROM accountability_record
 WHERE seq >= :period_start_seq AND seq < :period_end_seq
 GROUP BY tenant, category;
```

The detail is already in the ledger, which is the point. Two things about that
query are load-bearing, and both are the sort of thing that looks like a detail
until an invoice is disputed.

**1. The window is half-open, and bounded by SEQUENCE rather than by clock.**

`[start, end)` so an event on a boundary is billed exactly once — a closed-closed
window double-bills every boundary, which is the classic version of this bug and
is invisible until someone reconciles two consecutive invoices.

More importantly, the bound is the ledger's **sequence**, not `ts`. `ts` is an
emit time, and a record that arrives late with an earlier `ts` would silently
change a period that had already been closed and invoiced. The accountability
chain is ordered and gap-free, so closing a period means **recording the
sequence bounds in the statement** and re-deriving from exactly those. That makes
the run reproducible by construction and immune to late arrivals, which §7.4's
immutability requires and which a `ts BETWEEN` query cannot provide.

Wall-clock still appears — a customer's period is a calendar month in a stated
timezone — but it is used *once*, to pick the sequence bounds at close time, and
never again.

**2. Storage is a level, so its window arithmetic differs.**

Everything above is a `SUM` of flows within the window. Storage is a level, so a
period needs the level **entering** the window as well as the deltas inside it:

```
opening_level = Σ delta WHERE seq < period_start_seq
byte_hours    = Σ over each level change in the period of (level × duration held)
```

The opening level is a sum over all history, which is why §7.2's running total is
maintained rather than recomputed per invoice — and why the closing level of one
period must be recorded as the opening level of the next, so a period is
verifiable against its neighbours rather than against a replay of everything.

Same window semantics, different arithmetic. Worth stating plainly because "it is
all just events" is true of the flows and subtly different for the one line
customers ask about most.

### 7.5 Erasure and billing do not conflict, but the boundary must be explicit

A file erased under a subject-access request has its payload and version rows
destroyed. Its *historical usage* remains in the ledger, because the fact of the
activity is retained even when the content is not — and that is correct: last
month's storage was genuinely consumed and cannot be un-consumed.

Two rules follow:

- **An invoice may state that storage was used; it may not state what was
  stored.** The uid-only discipline gives this automatically, and after erasure a
  join to the name finds nothing — "compliance as a property of the
  architecture" rather than a redaction step someone must remember.
- **Erasure must not silently alter a closed statement.** Statements are
  immutable (§7.4.1); if an erasure would change a period's numbers, the period
  was not closed when it should have been.

### 7.6 Meter everyone, bill some

Collection should not be gated on the plan. A flat-rate customer whose usage is
metered anyway can be *shown* what a metered plan would have cost them — which
is how the option gets offered with evidence rather than with a sales pitch —
and a customer moving between plans has history rather than a discontinuity.

The cost of metering a flat-rate tenant is one row a day and some counters. The
cost of not doing it is having no answer the first time someone asks.

---

## 8. Open questions

**Q1 — Where do metrics live?** Prometheus is already in the estate and is the
obvious answer for rates and gauges. It is a poor fit for the conservation checks
in §3, which are comparisons between two systems' counts and are better computed
on a schedule and stored as results with history. Possibly both, and the split is
worth deciding rather than defaulting.

**Q2 — Retention.** Reports want months; the status dashboard wants minutes.
Prometheus retention is usually weeks. A rollup strategy is needed before §4.1's
growth projections are meaningful, since a forecast needs more history than the
default retention keeps.

**Q3 — Does any of this belong to tenants too?** Much of §4.3 and §4.4 would be
valuable in the tenant admin app, scoped to that tenant. Building it twice would
be a mistake; building the aggregation once with a tenant filter and two
audiences is the better shape, and it changes where this work should live.

**Q4 — Should `duration_ms` and `bytes` be added now?** (§5.) Metering makes
this sharper: without `bytes` the egress line of an invoice is unavailable, and
without `duration_ms` the conversion line is. They are cheap at
the emitters and expensive to retrofit into a year of history. If the answer is
yes, it wants to land before the storage-pipeline work rather than after, since
that work is already touching every emitter's neighbourhood.

**Q5 — Is the billing meter part of this application, or its own?** It reads the
same ledger and serves a different audience with different retention,
reproducibility and correctness requirements (§7.4). The administration
application is the natural place to *view* statements and the wrong place to
*compute* them, on the same reasoning that keeps it from executing anything
destructive: a console that can alter what a customer is billed is a console
whose compromise is a financial event.

**Q6 — Which unit does a customer actually understand?** GB-hours is correct and
is not how anyone thinks. The billable unit is a product decision that constrains
the engineering — peak GB, average GB, or GB-hours are three different
collections — and it should be settled before §7.2's snapshot cadence is chosen.
