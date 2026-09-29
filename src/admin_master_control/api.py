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
from .incidents import (
    IncidentSource,
    LedgerUnavailable,
    aggregated,
    campaigns,
)
from .roles import (
    ALL_ROLES,
    GRANTABLE_ROLES,
    SYSTEM_OBSERVER,
    SYSTEM_OWNER,
    SYSTEM_SECURITY,
    RoleError,
)

log = logging.getLogger("admin_master_control.api")


class LoginRequest(BaseModel):
    subject: str
    password: str
    second_factor: Optional[str] = None


class GrantRequest(BaseModel):
    subject: str
    role: str
    reason: str = ""


def build_router(config: Config, registry: AdministratorRegistry,
                 directory: DeploymentDirectory,
                 incidents: IncidentSource | None = None) -> APIRouter:
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

    return r
