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
from .job_store import InMemoryJobStore, JobStore, StoreUnavailable
from .registry import (
    CLAIMABLE,
    LIVE,
    PROVISIONING,
    RegistryRefused,
    RegistryUnavailable,
    StaticTenantRegistry,
    TenantRegistry,
    schema_name_for,
)
from .tls import SystemTlsProbe, TlsProbe, check_tls
from .tenants import (
    Resolver,
    StaticResolver,
    TenantError,
    check_dns,
    hostnames_for,
    provisioning_job,
    records_for,
    validate_tenant_id,
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
    #: The name a human uses. Optional, free text, and NEVER an identifier.
    display_name: str = ""


class DisplayNameBody(BaseModel):
    display_name: str


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
                 # NOT `registry`: that is the AdministratorRegistry above. Two
                 # different registries in one signature is exactly the sort of
                 # near-name that reads fine and binds the wrong object.
                 tenant_registry: TenantRegistry | None = None,
                 jobs: JobStore | None = None,
                 tls_probe: TlsProbe | None = None,
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

    _registry: TenantRegistry = (tenant_registry if tenant_registry is not None
                                 else StaticTenantRegistry())
    _jobs: JobStore = jobs if jobs is not None else InMemoryJobStore()
    _resolver: Resolver = resolver if resolver is not None else StaticResolver(answers={})

    _interfaces = config.interface_list()
    _tls: TlsProbe = tls_probe if tls_probe is not None else SystemTlsProbe()

    def _hostnames_of(t) -> list:
        """Every subdomain this tenant is served on, or none when unknown.

        A tenant that predates this console has no recorded base domain, and one with a
        hyphenated id is not reachable as itself — deriving hostnames for either would be
        inventing names to then report as broken.
        """
        if not t.base_domain or not t.reachable_by_hostname:
            return []
        return hostnames_for(t.tenant_id, t.base_domain, _interfaces)

    def _run_dns(t):
        verdict = check_dns(t.tenant_id, t.base_domain, t.address, _resolver, _interfaces)
        return {"ok": verdict.ok, "authoritative": verdict.authoritative,
                "blocking_reason": verdict.blocking_reason,
                "checks": [{"hostname": c.hostname, "ok": c.ok,
                            "resolved": list(c.resolved), "expected": c.expected,
                            "detail": c.detail} for c in verdict.checks]}

    def _needs_hostnames(t):
        """Refuse a check there is nothing to check, and say which it is."""
        if not t.base_domain or not t.address:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"{t.tenant_id} has no recorded base domain or address — it was "
                       f"not requested through this console, so there is nothing to "
                       f"check its DNS or certificates against.")
        if not t.reachable_by_hostname:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"{t.tenant_id} is an interface hostname of "
                       f"{t.base_tenant_id}, not a tenant — the doors resolve its host "
                       f"to {t.base_tenant_id}, so it has no subdomains of its own to "
                       f"check.")

    def _records_of(t) -> list:
        """The zone lines, derived rather than stored.

        A tenant that predates this console has no base domain recorded, so there is
        nothing to derive — an empty list, not a guess.
        """
        if not t.base_domain or not t.address:
            return []
        return [{"name": rec.name, "type": rec.type, "value": rec.value,
                 "zone_line": rec.as_zone_line()}
                for rec in records_for(t.tenant_id, t.base_domain, t.address, _interfaces)]

    def _with_records(t) -> dict:
        out = t.for_display()
        out["hostnames"] = _hostnames_of(t)
        out["records"] = _records_of(t)
        return out

    def _must_get(tenant_id: str):
        try:
            t = _registry.get(tenant_id)
        except RegistryUnavailable as e:
            # 503, not 404. "No such tenant" and "could not ask" need different
            # responses, and reporting the first sends someone looking for a tenant
            # that is fine.
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                                detail=str(e)) from e
        if t is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")
        return t

    @r.post("/tenants", status_code=status.HTTP_201_CREATED)
    def request_tenant(body: TenantRequestBody,
                       principal: Principal = Depends(require(SYSTEM_TENANTS))):
        """Request a tenant, and return exactly the DNS records to create.

        Writes a row to the REGISTRY in state `requested` — the same table the doors
        read and provisioning updates. There is no separate request table: the
        registry already models `requested → awaiting_dns → provisioning → live`, so
        a second one would be the same facts twice with two writers.
        """
        principal.authorising(SYSTEM_TENANTS)
        try:
            tenant_id = validate_tenant_id(body.tenant_id)
            if not body.base_domain:
                raise TenantError("a base domain is required")
            if not body.address:
                raise TenantError("the address the hostnames must point at is required")
            if not body.initial_admin:
                # A tenant with no administrator is a tenant nobody can manage, and
                # the platform's own tenant.yml takes one for the same reason.
                raise TenantError("a first administrator is required")
        except TenantError as e:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e)) from e
        try:
            # No prior existence check: a SELECT then an INSERT is two statements and
            # a race, and only the registry's unique index is authoritative.
            t = _registry.request(tenant_id=tenant_id, base_domain=body.base_domain,
                                  address=body.address, initial_admin=body.initial_admin,
                                  requested_by=principal.subject,
                                  display_name=body.display_name.strip())
        except RegistryRefused as e:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e)) from e
        except RegistryUnavailable as e:
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                                detail=str(e)) from e
        log.info("tenant %s requested by %s", tenant_id, principal.subject)
        return _with_records(t)

    @r.get("/tenants")
    def list_tenants(principal: Principal = Depends(require(SYSTEM_OBSERVER))):
        """EVERY tenant in the registry, not only the ones requested here.

        Built from the registry outward. Building it from this console's own request
        rows outward is what made this page show nothing on a deployment with seventy
        live tenants — they predate the console, so they have no request of ours, and
        that is the normal case rather than a gap.
        """
        try:
            rows = _registry.list()
        except RegistryUnavailable as e:
            # NOT an empty list, which would report an estate with no tenants.
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                                detail=str(e)) from e

        # Which ids actually exist, so an unreachable row can say whether its
        # hostname goes to a real tenant or to nothing at all. The two cases need
        # different responses: `filenginetest-drive` is shadowed by a live tenant and
        # is harmless clutter, while `fileenginetest-drive` — a typo nobody owns —
        # points its traffic at a tenant that does not exist.
        present = {t.tenant_id for t in rows}
        out = []
        for t in rows:
            shown = _with_records(t)
            if not t.reachable_by_hostname:
                shown["shadowed_by"] = t.base_tenant_id if t.base_tenant_id in present else ""
            out.append(shown)
        try:
            return {"tenants": out}
        except RegistryUnavailable as e:
            # NOT an empty list, which would report an estate with no tenants.
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                                detail=str(e)) from e

    @r.get("/tenants/{tenant_id}")
    def get_tenant(tenant_id: str,
                   principal: Principal = Depends(require(SYSTEM_OBSERVER))):
        return _with_records(_must_get(tenant_id))

    @r.put("/tenants/{tenant_id}/display-name")
    def set_display_name(tenant_id: str, body: DisplayNameBody,
                         principal: Principal = Depends(require(SYSTEM_TENANTS))):
        """Set the human-readable name, for billing and high-level operations.

        This renames the LABEL and never the identifier. `tenant_id` reaches a
        hostname, a Postgres schema, an LDAP DN and a file path, so it is immutable;
        an organisation renaming itself must not move its data. Allowed in any
        lifecycle state, including decommissioned, so a billing history stays readable.
        """
        principal.authorising(SYSTEM_TENANTS)
        _must_get(tenant_id)
        name = body.display_name.strip()
        if len(name) > 200:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                                detail="that name is too long (200 characters)")
        try:
            t = _registry.set_display_name(tenant_id, name)
        except RegistryUnavailable as e:
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                                detail=str(e)) from e
        log.info("tenant %s display name set by %s", tenant_id, principal.subject)
        return _with_records(t)

    @r.post("/tenants/{tenant_id}/dns-check")
    def check(tenant_id: str,
              principal: Principal = Depends(require(SYSTEM_TENANTS))):
        """Run the DNS gate — every subdomain, primary and service alike.

        Asks the zone's authoritative nameservers, compares the ADDRESS rather than
        merely that something resolves, and checks EVERY hostname. Each of those is a way
        a green tick can be wrong, and a wrong green tick here burns certificate issuance
        for the whole domain.

        DNS only, and fast: this is the input to the provisioning gate, and it is the one
        that gets pressed repeatedly while waiting for propagation. `verify` below does
        this and the certificates together.
        """
        t = _must_get(tenant_id)
        _needs_hostnames(t)
        dns = _run_dns(t)
        try:
            t = _registry.record_dns(tenant_id, dns)
        except RegistryUnavailable as e:
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                                detail=str(e)) from e
        log.info("tenant %s DNS check: %s", tenant_id,
                 "passed" if dns["ok"] else dns["blocking_reason"])
        return _with_records(t)

    @r.post("/tenants/{tenant_id}/verify")
    def verify(tenant_id: str,
               principal: Principal = Depends(require(SYSTEM_OBSERVER))):
        """Is this tenant actually live? DNS **and** TLS, on every subdomain.

        The two halves answer different questions and a tenant needs both to work:

          * DNS — does each name resolve, authoritatively, to the right address.
          * TLS — is each name serving a trusted certificate that covers it, and for
            how much longer.

        Every subdomain separately, because every one has its own record and its own
        certificate. A tenant whose primary host is fine and whose `-drive` host expired
        is one whose WebDAV stopped while its web interface kept serving, and a single
        verdict cannot say that.

        Gated on the OBSERVER baseline, not system_tenants: this is a read. It resolves
        names and opens TLS connections and changes nothing about the tenant — and
        noticing that a certificate expires in nine days should not require the authority
        to provision.

        THE CERTIFICATE RESULT DOES NOT FEED THE PROVISIONING GATE. No certificate exists
        before provisioning, so requiring one would make the gate unpassable; `absent` is
        the expected answer for a tenant being created and is not reported as a fault.
        """
        t = _must_get(tenant_id)
        _needs_hostnames(t)
        hosts = _hostnames_of(t)

        dns = _run_dns(t)
        tls = check_tls(hosts, _tls).as_dict()
        try:
            _registry.record_dns(tenant_id, dns)
            t = _registry.record_tls(tenant_id, tls)
        except RegistryUnavailable as e:
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                                detail=str(e)) from e
        log.info("tenant %s verify: dns=%s tls=%s", tenant_id,
                 "ok" if dns["ok"] else "not ready",
                 "ok" if tls["ok"] else (tls["blocking_reason"] or "not ready"))
        return _with_records(t)

    @r.post("/tenants/{tenant_id}/dns-override")
    def do_override(tenant_id: str, body: OverrideBody,
                    principal: Principal = Depends(require(SYSTEM_TENANTS))):
        """Force past the DNS gate, recorded.

        There are legitimate reasons the check fails on a correct setup —
        split-horizon DNS, a CDN in front, a zone the administrator does not control
        but has been told is ready. This is the one path to provisioning that can
        exhaust certificate issuance for every tenant on the domain, which is why it
        takes a reason and keeps a name attached rather than being a retry button.
        """
        authorised_as = principal.authorising(SYSTEM_TENANTS)
        t = _must_get(tenant_id)
        reason = body.reason.strip()
        if not reason:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="an override needs a reason: it is the one path to provisioning "
                       "that can exhaust certificate issuance for the whole deployment")
        if t.state not in CLAIMABLE:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"{tenant_id} is {t.state} — the DNS gate only applies before "
                       f"provisioning")
        try:
            t = _registry.record_override(tenant_id, principal.subject, reason)
        except RegistryUnavailable as e:
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                                detail=str(e)) from e
        log.warning("tenant %s DNS gate overridden by %s (as %s): %s",
                    tenant_id, principal.subject, authorised_as, reason)
        return _with_records(t)

    @r.post("/tenants/{tenant_id}/provision", status_code=status.HTTP_202_ACCEPTED)
    def provision(tenant_id: str,
                  principal: Principal = Depends(require(SYSTEM_TENANTS))):
        """Claim the request and write the job for the runner.

        202, not 200: this application has ASKED. A playbook is minutes and an HTTP
        request is not, so the work is a job with state, and the runner — which holds
        the credentials this application deliberately does not — claims it.
        """
        authorised_as = principal.authorising(SYSTEM_TENANTS)
        before = _must_get(tenant_id)          # 404 before anything else

        # CLAIM FIRST, in the REGISTRY. One conditional UPDATE moves a gated request
        # to `provisioning`, so two administrators pressing this at the same moment
        # cannot both queue a run — and two runs mean two certificate issuance
        # attempts against a rate limit SHARED BY EVERY TENANT on the domain. The
        # gate is held by the database rather than by arrival order.
        try:
            claimed = _registry.claim_for_provisioning(tenant_id, principal.subject)
        except RegistryUnavailable as e:
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                                detail=str(e)) from e
        if claimed is None:
            # WHICH refusal matters. An earlier version let the job builder produce
            # this message, which told the second presser "the DNS gate has not
            # passed" about a tenant whose gate HAD passed and whose run was already
            # underway — sending them to re-check DNS that was fine.
            now = _must_get(tenant_id)
            if now.state == PROVISIONING:
                # The race, or a double click. Distinguished from "in service"
                # because they are different situations: a tenant live since June
                # being told "another administrator started it a moment ago" is
                # simply false, and reads as a race that did not happen.
                detail = (f"tenant {tenant_id} is already being provisioned — another "
                          f"administrator started it a moment ago. No second run has "
                          f"been queued.")
            elif now.state not in CLAIMABLE:
                detail = (f"tenant {tenant_id} is {now.state} and cannot be "
                          f"provisioned again. Provisioning applies to a tenant being "
                          f"created, not one already in service.")
            else:
                detail = (f"tenant {tenant_id} is {now.state} and the DNS gate has not "
                          f"passed and has not been overridden. Provisioning now would "
                          f"fail at the certificate step and consume the domain's rate "
                          f"limit, which is shared by every tenant.")
            # 409, not 400: the request is well-formed, the SEQUENCE is wrong.
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=detail)

        job = provisioning_job(
            tenant_id=claimed.tenant_id, base_domain=claimed.base_domain,
            address=claimed.address, initial_admin=claimed.initial_admin,
            hostnames=hostnames_for(claimed.tenant_id, claimed.base_domain, _interfaces)
            if claimed.base_domain else [],
            requested_by=principal.subject,
            dns_verified=bool((before.dns or {}).get("ok")),
            override_by=claimed.override_by, override_reason=claimed.override_reason)
        job["authorised_as"] = authorised_as
        try:
            job["job_id"] = _jobs.record(tenant_id, job)
            _registry.attach_job(tenant_id, job["job_id"])
        except (StoreUnavailable, RegistryUnavailable) as e:
            # The claim already moved the registry to `provisioning`. Say so rather
            # than implying nothing happened: the tenant is not reachable in that
            # state, and an operator needs to know it needs picking up by hand.
            log.error("tenant %s was claimed but its job could not be written: %s",
                      tenant_id, e)
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=f"{tenant_id} has been moved to provisioning but the job could "
                       f"not be queued: {e}") from e
        log.info("tenant %s provisioning job %s written by %s",
                 tenant_id, job["job_id"], principal.subject)
        return {"job": job, "tenant": _with_records(_must_get(tenant_id))}

    @r.get("/tenants/{tenant_id}/records")
    def dns_records(tenant_id: str,
                    principal: Principal = Depends(require(SYSTEM_OBSERVER))):
        """The records to create, on their own, for pasting into a zone."""
        t = _must_get(tenant_id)
        return {"tenant_id": tenant_id, "records": _records_of(t)}

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
            return {"jobs": _jobs.jobs()}
        except StoreUnavailable as e:
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                                detail=str(e.args[0])) from e

    return r
