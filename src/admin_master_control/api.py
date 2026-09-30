# Copyright (C) 2026 James Hickman
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""Phase 1: the read-only surface, and the door in front of it.

PROPOSAL_system_administration_application.md §8.1 — "No writes, no decisions,
no destructive capability, so the security review in §9 has a much smaller
surface, and it delivers the daily pain point on its own."

Taken literally. Every route here is a GET except the login, nothing mutates
anything outside this application's own ledger, and the routes that would
mutate are absent rather than stubbed: a route that exists and returns 501 is a
route somebody will wire up.

The grant endpoints are the one exception to "read-only", and they are here
rather than in phase 4 because the ledger is this application's OWN store and
granting is what `system_owner` exists to do. They execute nothing outside it.
"""
from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, Body, Depends, HTTPException, Request, status
from pydantic import BaseModel

from .administrators import AdministratorRegistry, summarise
from .auth import (
    AuthError,
    DeploymentDirectory,
    Principal,
    login as do_login,
    make_require,
    mint_token,
    reconcile,
)
from .config import Config
from .redactions import ErasureSource, register as redaction_register
from .tenants import (
    Resolver,
    StaticResolver,
    TenantError,
    TenantRequest,
    override as dns_override,
    provisioning_job,
    records_for,
    verify as dns_verify,
)
from .incidents import (
    IncidentSource,
    LedgerUnavailable,
    TransitionRefused,
    aggregated,
    campaigns,
)
from .roles import (
    ALL_ROLES,
    GRANTABLE_ROLES,
    SYSTEM_OBSERVER,
    SYSTEM_OWNER,
    SYSTEM_SECURITY,
    SYSTEM_TENANTS,
    RoleError,
)

log = logging.getLogger("admin_master_control.api")


class LoginRequest(BaseModel):
    subject: str
    password: str
    second_factor: Optional[str] = None


class TenantRequestBody(BaseModel):
    tenant_id: str
    base_domain: str
    address: str
    initial_admin: str


class OverrideBody(BaseModel):
    reason: str


class GrantRequest(BaseModel):
    subject: str
    role: str
    reason: str = ""


class TransitionRequest(BaseModel):
    """One move along the procedure.

    There is no `actor` field, deliberately. The acting administrator is the
    authenticated caller; accepting one from the body would record who the caller
    SAID they were, and this is the table that exists to answer "who approved
    this".
    """

    incident_id: int
    state: str
    reason: str = ""
    counterparty: str = ""
    evidence: str = ""


def build_router(config: Config, registry: AdministratorRegistry,
                 directory: DeploymentDirectory,
                 incidents: IncidentSource | None = None,
                 erasures: ErasureSource | None = None,
                 resolver: Resolver | None = None,
                 tenant_requests: dict | None = None,
                 jobs: list | None = None) -> APIRouter:
    r = APIRouter(prefix="/v1")
    require = make_require(config)

    # ── the door ───────────────────────────────────────────────────────────

    @r.post("/auth/token")
    def issue_token(body: LoginRequest):
        """Authenticate and mint a session for this tier.

        The audience is distinct, so what comes back is useless at every tenant
        door — and a tenant token is useless here, which is the half that
        matters.
        """
        try:
            principal = do_login(config, directory, body.subject, body.password,
                                 second_factor=body.second_factor)
        except AuthError as e:
            log.info("login refused for %s: %s", body.subject, e.reason)
            raise HTTPException(status_code=e.status_code, detail="unauthorized") from e

        if config.require_mfa and not principal.has_second_factor:
            # Refuse to MINT a session that the gate would then refuse on every
            # request. Issuing one would be a login that "succeeds" and then
            # 403s everything, which reads as a broken service rather than as a
            # missing second factor.
            log.info("login refused for %s: second factor required", body.subject)
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                                detail="second factor required")

        return {
            "token": mint_token(config, principal),
            "subject": principal.subject,
            "roles": sorted(principal.roles),
            "amr": list(principal.amr),
        }

    @r.get("/whoami")
    def whoami(principal: Principal = Depends(require(SYSTEM_OBSERVER))):
        """Who the caller is and what they may do.

        Gated on `system_observer` rather than being open to any authenticated
        principal, because `system_observer` IS the baseline — §6.1 calls it
        "the baseline, and what most people actually need". A holder of only
        `system_billing` legitimately cannot read this, and that is the model
        working rather than an oversight.
        """
        return {
            "subject": principal.subject,
            "roles": sorted(principal.roles),
            "amr": list(principal.amr),
            "can_grant": SYSTEM_OWNER in principal.roles,
        }

    # ── who holds authority ────────────────────────────────────────────────

    @r.get("/administrators")
    def administrators(principal: Principal = Depends(require(SYSTEM_OBSERVER))):
        """Current holders, and the drift between the directory and the ledger.

        The drift is returned WITH the list rather than behind a separate call,
        because a console that shows holders without showing that the two
        stores disagree is showing a number somebody will trust.
        """
        current = [{"subject": s, "roles": rs} for s, rs in summarise(registry)]
        dir_roles = {s: directory.roles_of(s)
                     for s in (registry.subjects() | {a["subject"] for a in current})}
        led_roles = {s: registry.roles_of(s) for s in registry.subjects()}
        return {
            "administrators": current,
            "drift": reconcile(dir_roles, led_roles),
        }

    @r.get("/administrators/{subject}/history")
    def history(subject: str,
                principal: Principal = Depends(require(SYSTEM_OBSERVER))):
        """Every grant and revocation for one administrator, oldest first.

        This is the answer to "who could have approved this, and since when",
        which §6.3 exists to make answerable. Revocations are entries, so the
        history of a role somebody no longer holds is still here.
        """
        entries = registry.history(subject)
        if not entries:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")
        return {
            "subject": subject,
            "roles_now": sorted(registry.roles_of(subject)),
            "history": [
                {"role": g.role, "granted_by": g.granted_by, "revoked": g.revoked,
                 "reason": g.reason, "at": g.at.isoformat()}
                for g in entries
            ],
        }

    @r.get("/roles")
    def roles(principal: Principal = Depends(require(SYSTEM_OBSERVER))):
        """The namespace, so a console does not hard-code it."""
        return {
            "roles": list(ALL_ROLES),
            "grantable": list(GRANTABLE_ROLES),
            "granting_role": SYSTEM_OWNER,
            "note": "additive and unordered; system_owner grants the others and "
                    "holds none of them implicitly",
        }

    # ── the only writes, and they touch this application's ledger alone ────

    @r.post("/grants", status_code=status.HTTP_201_CREATED)
    def grant(body: GrantRequest,
              principal: Principal = Depends(require(SYSTEM_OWNER))):
        """Record a grant. Requires `system_owner` — the only role that creates
        authority (§6.1).

        The authorising role is taken from the gate that allowed the call, not
        recomputed, so the record cannot claim a role the caller did not hold.
        """
        authorised_as = principal.authorising(SYSTEM_OWNER)
        try:
            # The DIRECTORY-verified roles, from the gate that just allowed
            # this call — not the ledger's own view, which may not yet record a
            # grant for an owner the directory already honours.
            g = registry.grant(body.subject, body.role, by=principal.subject,
                               reason=body.reason, authority=principal.roles)
        except RoleError as e:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e)) from e
        log.info("grant %s to %s by %s (as %s)", g.role, g.subject, g.granted_by, authorised_as)
        return {"subject": g.subject, "role": g.role, "granted_by": g.granted_by,
                "authorised_as": authorised_as, "at": g.at.isoformat()}

    @r.post("/revocations", status_code=status.HTTP_201_CREATED)
    def revoke(body: GrantRequest,
               principal: Principal = Depends(require(SYSTEM_OWNER))):
        """Record a revocation. Appends; never edits."""
        authorised_as = principal.authorising(SYSTEM_OWNER)
        try:
            g = registry.revoke(body.subject, body.role, by=principal.subject,
                                reason=body.reason, authority=principal.roles)
        except RoleError as e:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e)) from e
        log.info("revoke %s from %s by %s (as %s)", g.role, g.subject, g.granted_by, authorised_as)
        return {"subject": g.subject, "role": g.role, "revoked_by": g.granted_by,
                "authorised_as": authorised_as, "at": g.at.isoformat()}

    # ── the cross-tenant security view (§3.4) ──────────────────────────────
    #
    # Gated on system_security rather than system_observer. §6.1 gives
    # system_security "incidents, cross-tenant detection, acknowledgements" as
    # its own area, and an incident naming a source address and the tenants it
    # touched is more than a read-only baseline should see.

    def _ledger():
        if incidents is None:
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                                detail="no audit ledger configured")
        return incidents

    @r.get("/security/incidents")
    def security_incidents(limit: int = 100, min_severity: str | None = None,
                           status_filter: str | None = None,
                           principal: Principal = Depends(require(SYSTEM_SECURITY))):
        """Every incident from every tenant, severity-ranked (§3.4 aggregation)."""
        try:
            return aggregated(_ledger(), limit=max(1, min(limit, 500)),
                              min_severity=min_severity, status=status_filter)
        except ValueError as e:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e)) from e
        except LedgerUnavailable as e:
            # 503, never an empty list. "No incidents" and "I could not ask" look
            # identical in a console and mean opposite things, and an empty
            # security view is the most reassuring thing a screen can show.
            log.error("security view unavailable: %s", e)
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                                detail="audit ledger unavailable") from e

    @r.get("/security/campaigns")
    def security_campaigns(limit: int = 100,
                           principal: Principal = Depends(require(SYSTEM_SECURITY))):
        """The cross-tenant detections — what no tenant could have seen (§3.4).

        These are the `scope=global` incidents: produced by windows that dropped
        the tenant, so each is a count no single tenant's view contains. This is
        the only view in which the campaign exists at all.
        """
        try:
            return campaigns(_ledger(), limit=max(1, min(limit, 500)))
        except LedgerUnavailable as e:
            log.error("campaign view unavailable: %s", e)
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                                detail="audit ledger unavailable") from e

    # ── the queue of things waiting on a human (§3.2 / §4) ─────────────────

    @r.get("/security/queue")
    def security_queue(state: str | None = None, limit: int = 100,
                       principal: Principal = Depends(require(SYSTEM_SECURITY))):
        """Items waiting, with their state and the legal next moves.

        Returning `next_states` per item is what keeps a console from
        hard-coding the procedure and drifting from it.
        """
        try:
            return _ledger().queue(state=state, limit=max(1, min(limit, 500)))
        except LedgerUnavailable as e:
            log.error("queue unavailable: %s", e)
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                                detail="audit ledger unavailable") from e

    @r.get("/security/backlog")
    def security_backlog(older_than_hours: float = 0.0,
                         principal: Principal = Depends(require(SYSTEM_SECURITY))):
        """How much is waiting, and for how long.

        §4: "A queue whose backlog is invisible is a log." `unacknowledged` with
        `older_than_hours` set is the one number worth alerting on, and the one
        that cannot be satisfied by sending more email.
        """
        try:
            return _ledger().backlog(older_than_hours=older_than_hours)
        except LedgerUnavailable as e:
            log.error("backlog unavailable: %s", e)
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                                detail="audit ledger unavailable") from e

    @r.get("/security/queue/{incident_id}")
    def security_item(incident_id: int,
                      principal: Principal = Depends(require(SYSTEM_SECURITY))):
        """One item's full transition history, refusals included."""
        try:
            return _ledger().item_history(incident_id)
        except LedgerUnavailable as e:
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                                detail="audit ledger unavailable") from e

    @r.post("/security/queue/transition", status_code=status.HTTP_201_CREATED)
    def security_transition(body: TransitionRequest,
                            principal: Principal = Depends(require(SYSTEM_SECURITY))):
        """Move one item along.

        THIS APPLICATION PRODUCES AN APPROVED REQUEST; IT DOES NOT EXECUTE ONE
        (§3.3, §4 of the proposal's "what it must never do"). Approving a
        redaction records a decision — the cloud-B application carries it out,
        behind its own human step. That separation is the entire security
        argument of the redaction design and is not collapsed here.

        The actor is the authenticated caller, and the authorising role is
        recorded from the gate that allowed the call.
        """
        authorised_as = principal.authorising(SYSTEM_SECURITY)
        try:
            out = _ledger().transition(
                incident_id=body.incident_id, state=body.state, actor=principal.subject,
                reason=body.reason, counterparty=body.counterparty, evidence=body.evidence)
        except TransitionRefused as e:
            # 409, not 503: "you cannot approve something nobody acknowledged" is
            # a correct answer, and presenting it as an outage would teach an
            # administrator to retry rather than to read it.
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e)) from e
        except LedgerUnavailable as e:
            log.error("transition failed: %s", e)
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                                detail="audit ledger unavailable") from e
        log.info("incident %s -> %s by %s (as %s)", body.incident_id, body.state,
                 principal.subject, authorised_as)
        return {**out, "actor": principal.subject, "authorised_as": authorised_as}

    # ── the redaction register (§3.3.2) ────────────────────────────────────

    @r.get("/redactions")
    def redactions(principal: Principal = Depends(require(SYSTEM_SECURITY))):
        """Every redaction, its state, and how long it has been in it.

        THE FILE IS NAMED BY UUID AND NOTHING ELSE unless its name survived the
        erasure. The redaction concern is potential PII in CONTENT — a filename
        is content ("Acme_Corp_Contract_J_Smith.pdf") — while the principals who
        acted are kept, because "who" was never the concern and an erasure with
        no attributable actor is unauditable.

        Where a name was redacted there is no second copy anywhere, and this
        surface does not go looking for one: it shows the absence. §3.3.1 — "A
        reporting surface that quietly made redacted names visible again to the
        tier with the most reach would be the worst possible place for that leak."
        """
        if erasures is None:
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                                detail="no erasure source configured")
        states: dict = {}
        if incidents is not None:
            # States come from the acknowledgement queue, keyed by erasure_id.
            try:
                for item in (incidents.queue(limit=500).get("items") or []):
                    key = item.get("group_key")
                    if key:
                        states[key] = {"state": item.get("state"),
                                       "evidence": item.get("evidence") or "",
                                       "reason": item.get("reason") or ""}
            except LedgerUnavailable as e:
                # The register is still worth showing without states — it is the
                # evidence of an obligation — but it must say the states are
                # missing rather than implying everything is unlooked-at.
                log.error("redaction states unavailable: %s", e)
                raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                                    detail="queue state unavailable") from e
        return redaction_register(erasures, states)

    # ── tenant setup and management (§3.4a) ────────────────────────────────
    #
    # THIS APPLICATION NEVER TOUCHES DNS AND NEVER RUNS ANSIBLE. DNS is managed
    # wherever the domain is, by a human — so there is no DNS credential here
    # because there is no DNS operation. And the playbook is executed by a runner
    # on the host that holds the vault password; these routes write a JOB (§5.3).

    _requests: dict = tenant_requests if tenant_requests is not None else {}
    _jobs: list = jobs if jobs is not None else []
    _resolver: Resolver = resolver if resolver is not None else StaticResolver(answers={})

    @r.post("/tenants", status_code=status.HTTP_201_CREATED)
    def request_tenant(body: TenantRequestBody,
                       principal: Principal = Depends(require(SYSTEM_TENANTS))):
        """Request a tenant, and return exactly the DNS records to create.

        Step 1 of §3.4a. The response is meant for pasting into a zone file — the
        administrator then updates the zone wherever the domain is managed, and
        the gate below is what decides when provisioning may run.
        """
        principal.authorising(SYSTEM_TENANTS)
        if body.tenant_id in _requests:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                                detail=f"{body.tenant_id} is already requested")
        try:
            req = TenantRequest(tenant_id=body.tenant_id, base_domain=body.base_domain,
                                address=body.address, initial_admin=body.initial_admin,
                                requested_by=principal.subject)
        except TenantError as e:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e)) from e
        _requests[req.tenant_id] = req
        log.info("tenant %s requested by %s", req.tenant_id, principal.subject)
        return req.for_display()

    @r.get("/tenants")
    def list_requests(principal: Principal = Depends(require(SYSTEM_OBSERVER))):
        """Every in-flight request and its state.

        Readable by the observer baseline: a tenant part-way through creation is
        the outstanding thing §3.2 exists for, and knowing one is stuck needs no
        authority to change it.
        """
        return {"tenants": [t.for_display() for t in _requests.values()]}

    @r.get("/tenants/{tenant_id}")
    def get_request(tenant_id: str,
                    principal: Principal = Depends(require(SYSTEM_OBSERVER))):
        req = _requests.get(tenant_id)
        if req is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")
        return req.for_display()

    @r.post("/tenants/{tenant_id}/dns-check")
    def check(tenant_id: str,
              principal: Principal = Depends(require(SYSTEM_TENANTS))):
        """Run the DNS gate.

        Asks the zone's authoritative nameservers, compares the ADDRESS rather
        than merely that something resolves, and checks EVERY hostname. Each of
        those is a way a green tick can be wrong, and a wrong green tick here
        burns certificate issuance for the whole domain.
        """
        req = _requests.get(tenant_id)
        if req is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")
        dns_verify(req, _resolver)
        return req.for_display()

    @r.post("/tenants/{tenant_id}/dns-override")
    def do_override(tenant_id: str, body: OverrideBody,
                    principal: Principal = Depends(require(SYSTEM_TENANTS))):
        """Force past the DNS gate, recorded.

        There are legitimate reasons the check fails on a correct setup —
        split-horizon DNS, a CDN in front, a zone the administrator does not
        control but has been told is ready. This is the one path to provisioning
        that can exhaust certificate issuance for every tenant on the domain,
        which is why it takes a reason and keeps a name attached rather than
        being a retry button.
        """
        authorised_as = principal.authorising(SYSTEM_TENANTS)
        req = _requests.get(tenant_id)
        if req is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")
        try:
            dns_override(req, by=principal.subject, reason=body.reason)
        except TenantError as e:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e)) from e
        log.warning("tenant %s DNS gate overridden by %s (as %s): %s",
                    tenant_id, principal.subject, authorised_as, body.reason)
        return req.for_display()

    @r.post("/tenants/{tenant_id}/provision", status_code=status.HTTP_202_ACCEPTED)
    def provision(tenant_id: str,
                  principal: Principal = Depends(require(SYSTEM_TENANTS))):
        """Write the provisioning job for the runner to claim.

        202, not 200: this application has ASKED. A playbook is minutes and an
        HTTP request is not, so the work is a job with state, and the runner —
        which holds the credentials this application deliberately does not —
        claims it, executes one at a time, and reports back.
        """
        authorised_as = principal.authorising(SYSTEM_TENANTS)
        req = _requests.get(tenant_id)
        if req is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")
        try:
            job = provisioning_job(req, requested_by=principal.subject)
        except TenantError as e:
            # 409, not 400: the request is well-formed, the SEQUENCE is wrong. The
            # gate has not passed and has not been overridden.
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e)) from e
        job["authorised_as"] = authorised_as
        _jobs.append(job)
        req.state = "provisioning"
        req.job_id = f"job-{len(_jobs)}"
        job["job_id"] = req.job_id
        log.info("tenant %s provisioning job written by %s", tenant_id, principal.subject)
        return {"job": job, "tenant": req.for_display()}

    @r.get("/tenants/{tenant_id}/records")
    def dns_records(tenant_id: str,
                    principal: Principal = Depends(require(SYSTEM_OBSERVER))):
        """The records to create, on their own, for pasting into a zone."""
        req = _requests.get(tenant_id)
        if req is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")
        return {"tenant_id": tenant_id,
                "records": [{"name": rec.name, "type": rec.type, "value": rec.value,
                             "zone_line": rec.as_zone_line()} for rec in req.records]}

    return r
