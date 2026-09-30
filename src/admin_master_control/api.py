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
from dataclasses import replace
from typing import Optional

from fastapi import APIRouter, Body, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from .administrators import AdministratorRegistry, summarise
from .auth import (
    CHALLENGE_ENROLL,
    CHALLENGE_VERIFY,
    AuthError,
    DeploymentDirectory,
    Principal,
    login as do_login,
    make_require,
    mint_challenge,
    mint_token,
    reconcile,
    verify_challenge,
)
from .config import Config
from .mfa import (
    ADMITTED,
    ENROLLMENT_REQUIRED,
    VERIFY_REQUIRED,
    FactorStore,
    MfaGate,
)
from .redactions import ErasureSource, register as redaction_register
from .tenant_store import (
    InMemoryTenantStore,
    StoreUnavailable,
    TenantExists,
    TenantStore,
)
from .tenants import (
    LIVE,
    PROVISIONING,
    VERIFIED,
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
    # NO `second_factor`. It was a self-asserted string: checked against a set of
    # factor NAMES and folded into the signed amr without a code being verified,
    # so {"second_factor":"totp"} bought a fully MFA-marked token. Removed rather
    # than deprecated — a field that still parses is a hole still reachable.


class ChallengeBody(BaseModel):
    """The pre-session token from /auth/token, plus a code where one is due."""

    challenge_token: str


class VerifyBody(ChallengeBody):
    code: str
    method: str = "totp"


class EnrollCompleteBody(ChallengeBody):
    code: str


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
                 tenants: TenantStore | None = None,
                 factors: FactorStore | None = None) -> APIRouter:
    r = APIRouter(prefix="/v1")
    require = make_require(config)
    gate = MfaGate(config, factors)

    def _challenge(token: str, expect: str) -> Principal:
        """Verify a challenge for one specific purpose, or 401.

        `expect` is not optional. An enrollment challenge must not complete a
        verification, nor the reverse — otherwise someone already enrolled could
        take the enrollment path after a password-only login and overwrite their
        factor with one they chose.
        """
        try:
            return verify_challenge(config, token, expect)
        except AuthError as e:
            log.info("challenge refused: %s", e.reason)
            raise HTTPException(status_code=e.status_code, detail=e.reason) from e

    def _session(principal: Principal, amr: tuple[str, ...]) -> dict:
        """The real session, and the ONLY place one is minted after a factor."""
        proven = Principal(subject=principal.subject, roles=principal.roles, amr=amr)
        return {
            "token": mint_token(config, proven),
            "subject": proven.subject,
            "roles": sorted(proven.roles),
            "amr": list(proven.amr),
            "can_grant": SYSTEM_OWNER in proven.roles,
        }

    # ── the door ───────────────────────────────────────────────────────────

    @r.post("/auth/token")
    def issue_token(body: LoginRequest):
        """Step one: the password. NOT, by itself, a session.

        The audience is distinct, so what eventually comes back is useless at
        every tenant door — and a tenant token is useless here, which is the half
        that matters.

        While a second factor is required this returns a CHALLENGE, not a token:
        either `verify` for an administrator who has a factor, or `enroll` for one
        who does not. There is no third branch in which a correct password alone
        yields a session, which is what `AMC_REQUIRE_MFA=true` now actually means.
        """
        try:
            principal = do_login(config, directory, body.subject, body.password)
        except AuthError as e:
            log.info("login refused for %s: %s", body.subject, e.reason)
            raise HTTPException(status_code=e.status_code, detail="unauthorized") from e

        try:
            step = gate.next_step(principal.subject)
        except AuthError as e:
            # Required-but-unenforceable, or an unreachable store. FAILS CLOSED,
            # and says which, because "your code was wrong" would send an
            # administrator to re-scan a QR that is fine.
            log.error("login refused for %s: %s", body.subject, e.reason)
            raise HTTPException(status_code=e.status_code, detail=e.reason) from e

        if step == ENROLLMENT_REQUIRED:
            # First login with no factor. §6 requires one, so they get an
            # enrollment-only challenge and nothing else — not a session with a
            # reminder attached. 401, because they are not yet authenticated: the
            # password is one of two things they owe.
            log.info("%s must enrol a second factor before a session is issued",
                     principal.subject)
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"status": ENROLLMENT_REQUIRED,
                         "challenge_token": mint_challenge(config, principal,
                                                           CHALLENGE_ENROLL),
                         "methods": list(gate.methods()),
                         "expires_in": config.mfa_challenge_ttl_s,
                         "detail": "a second factor is required at this tier; "
                                   "enrol one to continue"})

        if step == VERIFY_REQUIRED:
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"status": VERIFY_REQUIRED,
                         "challenge_token": mint_challenge(config, principal,
                                                           CHALLENGE_VERIFY),
                         "methods": list(gate.methods()),
                         "expires_in": config.mfa_challenge_ttl_s,
                         "detail": "second factor required"})

        # ADMITTED — the explicit opt-out (AMC_REQUIRE_MFA=false). Logged by the
        # gate on every use, and reported by /readyz, because a deployment should
        # not be able to run this way quietly.
        assert step == ADMITTED

        return _session(principal, ("pwd",))

    # ── the second factor: enrol, then prove (§6) ──────────────────────────
    #
    # These three are the ONLY routes reachable with a challenge token, and they
    # are reachable with nothing else. The separation is structural rather than
    # conditional: a challenge carries a different `aud`, PyJWT is given the
    # audience to validate, so a challenge presented to any other route fails
    # signature-and-claim validation together. There is no branch anywhere that
    # accepts a challenge as a session.

    @r.post("/auth/mfa/enroll/begin")
    def enroll_begin(body: ChallengeBody):
        """Start enrollment for an administrator who has no factor.

        The secret is returned ONCE, to the holder of a challenge proving they
        just supplied the right password. Nothing is enabled yet: `enroll-begin`
        stores a PENDING secret, and a pending enrollment is not a factor — which
        is why `next_step` reads `enabled` rather than `pending` and an
        abandoned enrollment leaves the account still owing one.
        """
        principal = _challenge(body.challenge_token, CHALLENGE_ENROLL)
        try:
            begun = gate.enroll_begin(principal.subject)
        except AuthError as e:
            raise HTTPException(status_code=e.status_code, detail=e.reason) from e
        log.info("second-factor enrolment begun for %s", principal.subject)
        # The challenge is returned so the client can complete without re-posting
        # the password. Same token, same short expiry — not a fresh one, or the
        # window would extend for as long as someone kept calling begin.
        return {"status": "enrolment_started",
                "otpauth_uri": begun.get("otpauth_uri", ""),
                "secret": begun.get("secret", ""),
                "issuer": begun.get("issuer", ""),
                "account": begun.get("account", principal.subject),
                "challenge_token": body.challenge_token}

    @r.post("/auth/mfa/enroll/complete")
    def enroll_complete(body: EnrollCompleteBody):
        """Confirm enrollment with a generated code, and only then issue a session.

        The recovery codes are returned HERE and nowhere else, once. They matter
        more at this tier than anywhere: losing the only factor on the console
        that grants all authority is the stranded state /readyz reports, and no
        other administrator can necessarily fix it.
        """
        principal = _challenge(body.challenge_token, CHALLENGE_ENROLL)
        try:
            done = gate.enroll_complete(principal.subject, body.code)
        except AuthError as e:
            raise HTTPException(status_code=e.status_code, detail=e.reason) from e
        if not done.get("ok"):
            # Not a session, and not a new challenge either: the one they hold is
            # still valid until it expires.
            log.info("second-factor enrolment failed for %s: wrong code", principal.subject)
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                detail="that code did not match; try the next one")
        log.info("second-factor enrolment completed for %s", principal.subject)
        out = _session(principal, ("pwd", "totp"))
        out["recovery_codes"] = list(done.get("recovery_codes") or [])
        out["status"] = "enrolled"
        return out

    @r.post("/auth/mfa/verify")
    def mfa_verify(body: VerifyBody):
        """Prove an existing factor, and get the session.

        The method is checked against this tier's allowlist rather than the
        tenant-wide cap, so `email` cannot be reached by naming it — see
        Config.mfa_methods for why it is excluded here and not elsewhere.
        """
        principal = _challenge(body.challenge_token, CHALLENGE_VERIFY)
        try:
            ok = gate.verify(principal.subject, body.method, body.code)
        except AuthError as e:
            raise HTTPException(status_code=e.status_code, detail=e.reason) from e
        if not ok:
            log.info("second factor refused for %s (%s)", principal.subject, body.method)
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                detail="that code did not match")
        method = body.method.strip().lower()
        log.info("second factor accepted for %s (%s)", principal.subject, method)
        return _session(principal, ("pwd", method))

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

    _store: TenantStore = tenants if tenants is not None else InMemoryTenantStore()
    _resolver: Resolver = resolver if resolver is not None else StaticResolver(answers={})

    def _must_get(tenant_id: str) -> TenantRequest:
        try:
            req = _store.get(tenant_id)
        except StoreUnavailable as e:
            # 503, not 404. "No such tenant" and "could not ask" need different
            # responses, and reporting the first sends someone looking for a
            # tenant that is fine.
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                                detail=str(e.args[0])) from e
        if req is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")
        return req

    @r.post("/tenants", status_code=status.HTTP_201_CREATED)
    def request_tenant(body: TenantRequestBody,
                       principal: Principal = Depends(require(SYSTEM_TENANTS))):
        """Request a tenant, and return exactly the DNS records to create.

        Step 1 of §3.4a. The response is meant for pasting into a zone file — the
        administrator then updates the zone wherever the domain is managed, and
        the gate below is what decides when provisioning may run.
        """
        principal.authorising(SYSTEM_TENANTS)
        try:
            req = TenantRequest(tenant_id=body.tenant_id, base_domain=body.base_domain,
                                address=body.address, initial_admin=body.initial_admin,
                                requested_by=principal.subject)
        except TenantError as e:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e)) from e
        try:
            # No prior existence check. The unique primary key decides, because a
            # SELECT then an INSERT is two statements and a race: two
            # administrators requesting the same id simultaneously both pass a
            # check-then-insert, and only the constraint is authoritative.
            _store.create(req)
        except TenantExists as e:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e)) from e
        except StoreUnavailable as e:
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                                detail=str(e.args[0])) from e
        log.info("tenant %s requested by %s", req.tenant_id, principal.subject)
        return req.for_display()

    @r.get("/tenants")
    def list_requests(principal: Principal = Depends(require(SYSTEM_OBSERVER))):
        """Every in-flight request and its state.

        Readable by the observer baseline: a tenant part-way through creation is
        the outstanding thing §3.2 exists for, and knowing one is stuck needs no
        authority to change it.
        """
        try:
            return {"tenants": [t.for_display() for t in _store.list()]}
        except StoreUnavailable as e:
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                                detail=str(e.args[0])) from e

    @r.get("/tenants/{tenant_id}")
    def get_request(tenant_id: str,
                    principal: Principal = Depends(require(SYSTEM_OBSERVER))):
        return _must_get(tenant_id).for_display()

    @r.post("/tenants/{tenant_id}/dns-check")
    def check(tenant_id: str,
              principal: Principal = Depends(require(SYSTEM_TENANTS))):
        """Run the DNS gate.

        Asks the zone's authoritative nameservers, compares the ADDRESS rather
        than merely that something resolves, and checks EVERY hostname. Each of
        those is a way a green tick can be wrong, and a wrong green tick here
        burns certificate issuance for the whole domain.
        """
        req = _must_get(tenant_id)
        dns_verify(req, _resolver)
        _store.save(req)
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
        req = _must_get(tenant_id)
        try:
            dns_override(req, by=principal.subject, reason=body.reason)
        except TenantError as e:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e)) from e
        _store.save(req)
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
        before = _must_get(tenant_id)            # 404 before anything else

        # CLAIM FIRST. One conditional UPDATE moves verified -> provisioning, so
        # two administrators pressing this at the same moment cannot both queue a
        # run. Reading the state and then writing it lets both through — each sees
        # `verified`, each passes may_provision — and two runs mean two certificate
        # issuance attempts against a rate limit SHARED BY EVERY TENANT on the
        # domain. That is the exact failure the DNS gate exists to prevent, so the
        # gate has to be held by the database rather than by arrival order.
        claimed = _store.claim_for_provisioning(tenant_id)
        if claimed is None:
            # Refused — and WHICH refusal matters. Building the job first and
            # letting its guard produce the message told the second presser "the
            # DNS gate has not passed" about a tenant whose gate had passed and
            # whose run was already underway, which sends them to re-check DNS
            # that is fine.
            now = _must_get(tenant_id)
            # The discriminator is whether the tenant is already PAST the gate,
            # not what this request happened to read. An earlier version asked
            # `before.may_provision`, which is False on a straightforward second
            # press — the second caller reads `provisioning`, having never seen
            # `verified` — so it fell into the gate branch and produced the wrong
            # message for the commonest case there is.
            if now.state in (PROVISIONING, LIVE) or before.may_provision:
                # It has passed the gate and been started. Nothing is wrong, and
                # nothing more should happen.
                detail = (f"tenant {tenant_id} is already {now.state} — another "
                          f"administrator started it a moment ago. No second run "
                          f"has been queued.")
            else:
                # It never passed the gate. Reuse the gate's own words, which name
                # what the refusal protects.
                try:
                    provisioning_job(now, requested_by=principal.subject)
                    detail = f"tenant {tenant_id} is {now.state}, not verified"
                except TenantError as e:
                    detail = str(e)
            # 409, not 400: the request is well-formed, the SEQUENCE is wrong.
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=detail)

        # The claim succeeded, so this request WAS verified. `claimed` now reads
        # `provisioning`, and provisioning_job rightly refuses that state — its
        # guard protects direct callers and is not relaxed here. So the job is
        # built from a request in the state that was claimed: the pre-claim read
        # when it agrees, otherwise the claimed row with that state restored (which
        # happens only if someone verified it between the read and the claim).
        source = before if before.may_provision else replace(claimed, state=VERIFIED)
        try:
            job = provisioning_job(source, requested_by=principal.subject)
        except TenantError as e:  # pragma: no cover - the claim already proved this
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e)) from e

        job["authorised_as"] = authorised_as
        job["job_id"] = _store.record_job(tenant_id, job)
        log.info("tenant %s provisioning job %s written by %s",
                 tenant_id, job["job_id"], principal.subject)
        return {"job": job, "tenant": _must_get(tenant_id).for_display()}

    @r.get("/provisioning-jobs")
    def provisioning_jobs(principal: Principal = Depends(require(SYSTEM_OBSERVER))):
        """The queue the runner reads, and its state.

        Deliberately NOT mounted at /tenants/jobs: that would collide with
        /tenants/{tenant_id} and be resolved by declaration order, so a tenant
        legitimately called `jobs` would shadow it or be shadowed. A separate top
        level path has no ordering to get wrong.

        Observer-readable. A job stuck in `queued` because no runner is running is
        exactly the outstanding thing §3.2 exists to surface, and noticing it needs
        no authority to change it.
        """
        try:
            return {"jobs": _store.jobs()}
        except StoreUnavailable as e:
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                                detail=str(e.args[0])) from e

    @r.get("/tenants/{tenant_id}/records")
    def dns_records(tenant_id: str,
                    principal: Principal = Depends(require(SYSTEM_OBSERVER))):
        """The records to create, on their own, for pasting into a zone."""
        req = _must_get(tenant_id)
        return {"tenant_id": tenant_id,
                "records": [{"name": rec.name, "type": rec.type, "value": rec.value,
                             "zone_line": rec.as_zone_line()} for rec in req.records]}

    return r
