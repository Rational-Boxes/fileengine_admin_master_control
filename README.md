# admin_master_control

> ⚠️ **Scaffold only.** The specification is complete and under review; no
> capability is implemented. `/readyz` is red until the deployment meets the
> conditions in §7 of the proposal, which is deliberate.

FileEngine's **deployment-tier** administration application — the tier above
every tenant. It exists to let a system administrator see the whole platform and
make the decisions the platform cannot make for itself.

Read [`design_documents/PROPOSAL_system_administration_application.md`](design_documents/PROPOSAL_system_administration_application.md)
first; [`DEPLOYMENT_MANAGEMENT_INTERFACE.md`](design_documents/DEPLOYMENT_MANAGEMENT_INTERFACE.md)
holds the scoping and the administrator role tier, and
[`PROPOSAL_platform_observability.md`](design_documents/PROPOSAL_platform_observability.md)
the metrics, reports and metering.

## The two sentences that govern every change here

1. **This is the first door that reads across the tenant boundary on purpose**,
   so it inherits nothing from the doors that read one tenant. That boundary has
   been crossed once before in this platform; a mistake here is not a rendering
   bug.
2. **It observes and records decisions.** It executes nothing destructive, holds
   no cloud credential, never reads file content, and never impersonates a
   tenant. The gap between *approved* and *done* is the design.

## Where it sits

| | |
|---|---|
| Ports | API `:8103`, monitoring `:8104` — **loopback-only**, per the platform rule for unauthenticated `/healthz` `/readyz` `/metrics` |
| Hostname | `system.<base>` — a plain vhost like `docs.<base>`, never a `<tenant>.<base>` pattern |
| Reads | the audit **ledger** for content and the stream for latency; LDAP, `ldap_manager` and service health for the state the queue cannot carry |
| Writes | its own queue state. Nothing else, anywhere |
| Auth | `system_*` LDAP roles defined outside every tenant OU, MFA mandatory, a token audience distinct from every tenant door |

## Prerequisites, which are not this repo's work

§7 of the proposal. Three of the four are defects that exist today regardless of
whether this is ever built, and the first is **blocking**:

1. `LDAPAuthenticator::extractRolesFromGroups` falls back through search bases
   including the directory root, so a `system_*` group would sit inside the path
   a tenant login already walks. Tenant-context resolution must refuse the
   prefix outright **before the first such role is created**.
2. Deployment roles must be stripped at every tenant door.
3. A global rule scope in `audit_service`, without which cross-tenant detection
   has nothing to show.
4. A real `AdminNotifier` — today it logs a mandatory admin email and sends none.

## Develop

```bash
pip install -e ".[dev]"
cp .env.example .env            # fill in; /readyz tells you what is missing
pytest src/tests -q
admin-master-control            # API :8103, monitoring :8104
```

## Status

Scaffold: config, the two listeners, readiness, and the metrics module shared
verbatim across the estate. No routers are mounted, and a test asserts that —
an application at this tier with no routes is safe, and one with speculative
routes is not.

## License

Copyright (C) 2026 James Hickman <james@rationalboxes.com>

Licensed under the **GNU Affero General Public License, version 3 (or later)** —
see [LICENSE](LICENSE).
