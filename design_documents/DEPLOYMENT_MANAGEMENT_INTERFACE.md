# Scoping: a deployment management interface

**Status:** Scoping — for discussion. Nothing implemented, nothing scheduled.
**Tier:** the deployment itself — above any tenant. Distinct from the tenant
admin app (`TenantAdminView`, `AdminOpsView`, `AdminSharesView`) and from
`ldap-admin.<base>`, both of which are tenant-scoped.

---

## 1. What the operator has today

Every system-wide administrative operation is a playbook or a CLI invocation.

| Surface | Covers |
|---|---|
| **Ansible** (13 playbooks) | `site`, `bootstrap`, `app_plane`, `data_plane`, `ingress`, `ops`, `preflight` — provisioning and deploys; `tenant` — tenant creation; `service_accounts`; `predeploy_capture`, `snapshot`, `backup_fetch` — recovery points; `erasure_patch` |
| **`fileengine_cli`** | `service-token issue\|rotate\|prune\|revoke\|list`, `service capabilities\|grant\|revoke-cap`, `bootstrap enrol`, storage usage |
| **`ldap_manager`** | `admin_users`, `admin_roles`, `admin_oauth`, `admin_templates`, `service_cred`, `twofa` — a real admin API, but **per tenant** |
| **frontend** | three admin views, all **per tenant** |

This is not a deficient arrangement. Provisioning belongs in Ansible: it is
idempotent, reviewable, version-controlled, and it runs the same way from a
laptop and from CI. **A UI that re-implements a playbook is worse than the
playbook** — less reviewable, less testable, and holding credentials a web
application should not hold.

So the question is not "what should be moved into a UI". It is "what does the
operator currently not have, in any surface".

---

## 2. What is actually missing

Three things, and none of them is a wrapper around a playbook.

### 2.1 Queues with a human decision in them

`predeploy_capture`, `snapshot`, `tenant` — all of these are *commands*. They
start, they finish, they are done. Nothing in the estate models a thing that is
**outstanding**: raised, waiting on a person, and still waiting tomorrow.

Two requirements now depend on exactly that:

- **Redaction approval** — raised by the deployment, confirmed with the end
  customer by a human, then executed
  (`scripts/Ansible/docs/PROPOSAL_offsite_redaction.md`).
- **Deployment-tier security signals** — acknowledged, not merely sent
  (`audit_service/design_documents/PROPOSAL_deployment_admin_signal.md`).

A command cannot express "nobody has looked at this for three days". That is the
gap a UI is genuinely the right shape for, and it is the only one that cannot be
closed by writing another playbook.

### 2.2 Visibility across tenants

Every existing admin surface is scoped to one tenant, deliberately. The
deployment operator's questions are not: *which tenants exist and what state are
they in; where is storage going; which security incidents fired this week,
anywhere; which service credentials are near expiry; is the audit drain healthy;
did last night's backup verify.*

Answering those today means SSH and a shell. That is fine at three tenants and
not at thirty.

### 2.3 State that survives between operations

An acknowledgement, a decision and its reason, who confirmed what and when. A
playbook run leaves a log; it does not leave a record anyone can query next
month.

---

## 3. The test for what belongs in it

> **Does it have a human decision or a waiting state in it?**
>
> Yes → the interface. No → it stays a playbook or a CLI command, and the
> interface at most *shows* that it ran.

Applied:

| Operation | Where |
|---|---|
| Approve a redaction; acknowledge a security incident | **Interface** — decision |
| Review tenant state, storage, incidents, credential expiry | **Interface** — observation |
| Provision or decommission a tenant | **Requested in the interface, executed by the runner** (§3.1). Decommissioning is destructive and lands with the §5 phase-4 work, not with creation. |
| Deploy, take a snapshot, restore | **Playbook.** A restore should be a decision, not a button — RESTORE.md already says why |
| Issue or rotate a service credential | **CLI**, shown by the interface |
| Full account deletion, per-user 2FA teardown | **Interface** — the tasks the tenant-admin app deliberately excludes, and they need an audit trail more than they need a command |

### 3.1 Tenant lifecycle is in scope — the application requests, a runner executes

*(Revised. An earlier version of this section argued tenant creation should stay
a playbook the interface merely observes. That was too strong, and the reasoning
behind it survives in a better shape.)*

Tenant setup is the deployment tier's most frequent operation and today it is a
manual sequence: run `tenant.yml`, arrange DNS, confirm the vhost and the
certificate, check the MCP host allow-list. Automating it is real value and the
interface is the right place to drive it from.

**What was right in the original objection** is that a web application must not
hold the credentials that do it. `tenant.yml`'s own header says five things must
happen "and only four of them are ours" — DNS is outside Ansible — and a UI
holding a DNS API key, a vault password and cloud credentials is the highest
concentration of authority in the estate sitting behind a browser session.

**So the split is the same one the redaction design uses:** the application
records the *intent* and a **runner** executes it (§5.3 of the application
proposal). The runner holds the vault password; the application holds none and
knows only that it asked.

**And DNS stays with the human entirely.** The administrator updates the zone
wherever the domain is managed; the application shows the records to create,
verifies they have propagated, and only then allows the playbook to be invoked.
There is no DNS credential to hold because there is no DNS operation to perform
— which disposes of the original objection rather than mitigating it. The gap between *requested*
and *done* is the same gap §4 keeps everywhere else, and it is what stops a
browser session being a route to the deployment's secrets.

That also makes tenant creation fit §2.1 rather than contradict it: a tenant
that is requested, provisioning, awaiting DNS, or live is precisely a thing that
is **outstanding**, which is the capability nothing else in the estate has.

---

## 4. The constraint that shapes everything else

**This is the highest-value target in the estate.** It is, by construction, the
first door that reads across the tenant boundary on purpose.

That boundary has already been breached once: a local HS256 shortcut combined
with a flattened LDAP role search let a member of one tenant administer another
(fixed and deployed as 1.9.17). The architecture's answer is that the core is
trusted-upstream and read-by-default, so **each door alone enforces membership** —
which means a door built to see every tenant cannot inherit a single assumption
from the doors that see one.

Consequences that are not negotiable:

- **Its own security review**, before it is reachable, not after.
- **No cloud credentials.** Not DNS, not Spaces, not AWS. The redaction proposal
  makes the same call for its cloud-B component and for the same reason: a web
  application holding the credential that can destroy things is the credential
  being one exploit away from destroying them.
- **It executes nothing destructive itself.** It records decisions; the playbook
  or the operator executes. The gap between "approved" and "done" is a feature.
- **MFA, and an identity that is not a tenant role** (§6).

---

## 5. Suggested phasing

1. **Read-only.** Tenants, storage, incidents, credential expiry, drain and
   backup health. No writes at all, so §4's review has a much smaller surface to
   consider, and it is immediately useful — §2.2 is the daily pain.
2. **Acknowledgement.** The deployment-admin signal queue: raised → acknowledged,
   with who and when. Still no destructive capability.
3. **Approval.** Redaction confirm/approve, and whatever else has accumulated a
   decision step by then.
4. **The excluded tenant-admin tasks** — full account deletion, 2FA teardown —
   which are destructive and should arrive last, after the audit trail they need
   already exists.

Phase 1 is worth building on its own even if 2–4 never happen.

---

## 6. The administrator identity — decided

**LDAP roles, defined outside any tenant's scope, and more than one of them.**
Role membership is already request-borne from LDAP groups — the core's
`user_roles` is effectively always empty — so this needs no new mechanism, only
a placement and a discipline.

### 6.1 Responsibilities, not a ladder

*(Revised. An earlier version proposed four roles that read as levels —
observer, operator, security, owner. That was the wrong shape: deployment work
divides by **responsibility**, not by seniority, and a large deployment has
several administrators each holding one area.)*

One all-powerful account is wrong for the same reason `tenant_admin` is not one
permission. But so is a ladder: a billing administrator does not need tenant
provisioning, and a security administrator does not need to alter invoices.

**Four orthogonal roles, plus one that can grant them:**

| Role | Holds |
|---|---|
| `system_observer` | Read-only across everything. The baseline, and what most people actually need — most deployment work is looking. |
| `system_tenants` | Tenant setup, lifecycle and day-to-day management: request provisioning, seats, quota, the tenant's own administrators. |
| `system_security` | Monitoring and security: incidents, cross-tenant detection, acknowledgements, redaction approval, credential revocation. |
| `system_billing` | Metering, statements, plan changes. |
| `system_owner` | Grants the four above. The only role that can create authority. |

**They are additive and unordered.** Holding `system_billing` grants nothing in
tenants or security. A person may hold several; on a small deployment one person
holds all of them, and the model does not get in the way. The point is that on a
large one it *can* be divided, and that dividing it requires no redesign.

#### Why separation here is worth the extra roles

- **Redaction approval and tenant provisioning are different jobs.** The
  redaction design assumes an administrator separate from whoever holds droplet
  root; separating security from tenant operations is the same argument one
  level up.
- **Billing is a financial-fraud surface.** Someone who can alter what a
  customer is billed is a distinct risk from someone who can read usage, so
  *viewing* metering (`system_observer`) and *changing* a plan or reissuing a
  statement (`system_billing`) are deliberately different grants. Statements are
  immutable regardless, which limits what the role can do even when held.
- **Least privilege has somewhere to land.** Without these, every deployment-tier
  task needs the one role that does everything, and it gets handed out.

#### What the audit record must carry

Every action records **which role authorised it**, not only who performed it. A
person holding three roles who approves a redaction did so as `system_security`,
and a year later that is the difference between an auditable decision and a name
with unclear standing.

### 6.2 Two invariants, and a live risk to the first

- **A deployment role must be invisible to tenant-scoped role resolution.**
- **A deployment role must be stripped at every tenant door**, the way
  `share_service` already strips admin roles before delegating — defence in
  depth, because placement is configuration and configuration drifts.

The first is not currently safe by construction, and this must be fixed before
any such group exists.

**RESOLVED 2026-09-29** — `fix/tenant-roles-scoped-to-tenant-ous` in both
bridges. The description below is kept because it is what the work was scoped
against, with one correction: **it was worse than stated.**

`LDAPAuthenticator::extractRolesFromGroups`
(`http_bridge/src/ldap_authenticator.cpp:~700`) resolved a user's groups by
trying a **list of fallback search bases**, and that list included the directory
root (`ldap_domain_`) along with `ou=groups`, `ou=Group`, `ou=Roles`, `ou=role`,
`ou=tenants` and `ou=users` beneath it.

This section said it "breaks at the first base that returns successfully", which
would make the outcome depend on search ordering. Reading the loop, it did not
break — the comment in the code says *"Continue to other bases to collect all
possible roles"* and it did exactly that, **unioning every base**. So the
directory root was not *sometimes* reached depending on ordering; it was
**always** reached. Every `groupOfNames` anywhere in the directory naming the
user became a role of theirs in tenant context.

Two further findings from the same reading, neither of which was known when this
was written:

- `tenant_base_` **defaulted to the directory root** when unset
  (`tenant_base.empty() ? ldap_domain : tenant_base`), so a deployment that
  simply did not configure it searched the whole directory without anyone
  choosing that. Production does set it; the default was a trap waiting for the
  next deployment.
- The empty-roles fallback searched a hard-coded `ou=default,ou=tenants,…`
  regardless of who was logging in, so a user in another tenant with no roles of
  their own fell back into `default`'s groups.

It is the same shape as the defect fixed in 1.9.17, where a flattened role search
let a member of one tenant administer another. Reintroducing it through directory
*layout* rather than through code would be no better.

**What was done.** Tenant-context role collection now searches exactly one base
— the tenant subtree — and `SUBTREE` scope covers every `ou=<tenant>` beneath
it, which is what the widening list was reaching for by accident. An unset base,
or one equal to the directory root, is **refused** rather than widened. The
policy lives in `http_bridge/include/tenant_role_policy.h` (shared verbatim with
`webdav_bridge`) so it is header-only and testable offline: it could not be
asserted on before, because it lived inside a function that needs a live LDAP
connection to call. 14 tests pin it.

**Therefore, before a deployment role is defined:** tenant-context role
resolution must refuse names in the deployment namespace outright, regardless of
which base returned them. A shared prefix (`system_*`) makes that one rule rather
than a list that drifts as roles are added — which is the practical argument for
the namespace, beyond tidiness.

**Done, and kept as a SECOND layer rather than a replacement for the scoping.**
Both are needed: scoping the search depends on directory *layout*, and layout is
configuration. A `system_*` group moved into a tenant OU by mistake, or a tenant
OU created above one, puts it back inside a base the bridge is entitled to
search — and the name filter is what catches it then. Every exit from
`extractRolesFromGroups` passes through the filter, including the DN-parsing
fallbacks; it was made a single choke point rather than a guard repeated at each
acceptance site, because there were already two identical sites and a third
would have been missed. The prefix match agrees with
`admin_master_control/src/admin_master_control/roles.py`, deliberately.

### 6.3 Where the first one comes from

No tenant admin may create a deployment role or grant membership of one.
`system_owner` grants the others; the first `system_owner` comes from
provisioning, the way a tenant's first administrator already does in
`tenant.yml`. A `system_owner` granting themselves another role is legitimate
and must be **recorded as a grant**, not silently effective — otherwise the
separation above is a convention rather than a control. Accounts live outside every tenant OU, alongside `ou=services`.

---

## 7. Open questions

**Q1 — A new application, or part of an existing one?** Bolting it onto the
frontend puts a cross-tenant surface inside the per-tenant SPA, which is the
exact adjacency §4 says to avoid. A separate application on its own hostname is
the safer shape and the more expensive one.

**Q2 — What does it read?** Every service has its own per-tenant schema. A
cross-tenant view either queries many databases or consumes something that
already aggregates. `audit_service` is the only component with a whole-platform
view today, which makes it the natural backend for §2.2 — and makes its tenant
scoping the thing to examine first.

**Q3 — Does it need to exist before the redaction work?** The redaction proposal
assumes a queue this interface would provide. If redaction is wanted sooner, the
queue could ship as an API with no UI and be adopted later — which is what
`PROPOSAL_deployment_admin_signal.md` §5 already suggests.
