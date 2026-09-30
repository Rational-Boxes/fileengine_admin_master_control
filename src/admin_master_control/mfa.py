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

"""The second factor, verified rather than claimed (§6).

`AMC_REQUIRE_MFA` used to mean the caller had SAID they used one. `login()` took
`second_factor` as a string, checked it against a set of factor NAMES, and
appended it to `amr` — so anyone holding a directory password could send
`{"second_factor":"totp"}` and receive a fully MFA-marked token, on the console
that reads every tenant's audit and grants deployment authority.

This module makes the claim checkable. It does NOT implement TOTP: `ldap_manager`
already owns `user_2fa` and exposes internal-secret-guarded endpoints for exactly
this case — `/internal/2fa/enroll-begin` is documented as "grace enrollment for a
mandated-but-unenrolled user during login: the door drives TOTP setup on their
behalf". A second implementation of TOTP here would be a second place for the
secret to live and a second answer to "is this administrator enrolled".

The store is keyed by **uid alone and shared across tenants**, so an
administrator who enrolled through a tenant already has a factor this tier can
verify. One enrollment, not one per door.

TWO THINGS THIS TIER DOES DIFFERENTLY, and the second is a trap:

  * The requirement is UNCONDITIONAL. ldap_manager's `/internal/2fa/required`
    answers from a TENANT policy (`tenant_2fa_policy`, `TOTP_REQUIRED_TENANTS`),
    and deployment roles live outside every tenant OU, so no tenant's policy
    applies. This gate never asks whether a factor is required; it requires one.

  * Method resolution is "deployment cap ∩ that tenant's policy", and the
    endpoints are tenant-addressed. Passing a REAL tenant would let its
    administrator disable TOTP and thereby block enrollment for this console — a
    tenant-scoped setting denying the highest-trust tier its second factor. So an
    EMPTY tenant is passed, which resolves to the deployment cap.

    Not an invented sentinel like `__deployment__`, which was the first attempt:
    the core AUTO-REGISTERS any tenant it is asked about, with the default state
    `live`, so in this estate a plausible-looking name is a tenant waiting to be
    created. See Config.mfa_tenant_context.

Everything here FAILS CLOSED. An unreachable store refuses the login rather than
admitting one, for the reason §3.4c gives about the tenant gate: "allow on error"
is how the check stops being a check.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Optional, Protocol

from fastapi import status

from .auth import AuthError
from .config import Config

log = logging.getLogger("admin_master_control.mfa")

#: What a factor can be at this tier. `email` is deliberately absent — see
#: Config.mfa_methods.
TOTP = "totp"
RECOVERY = "recovery"


class MfaUnavailable(AuthError):
    """The factor store could not be ASKED.

    503, and distinct from "the code was wrong", for the same reason
    DirectoryUnavailable is distinct from "holds no deployment role": telling an
    administrator their code was rejected when the store was unreachable sends
    them to re-scan a QR that is fine.
    """

    def __init__(self, reason: str):
        super().__init__(reason, status_code=status.HTTP_503_SERVICE_UNAVAILABLE)


@dataclass(frozen=True)
class FactorStatus:
    """Whether this administrator has a factor, and whether one is half-set-up.

    `pending` matters: enrollment that has begun but not completed leaves a
    secret stored and 2FA NOT enabled. Treating that as enrolled would admit a
    session against a secret nobody has confirmed they can generate codes from.
    """

    enabled: bool = False
    pending: bool = False
    recovery_remaining: int = 0


class FactorStore(Protocol):
    """Reads and writes second factors. Injectable so the gate is testable."""

    def status(self, uid: str) -> FactorStatus: ...
    def verify(self, uid: str, method: str, code: str) -> bool: ...
    def enroll_begin(self, uid: str) -> dict: ...
    def enroll_complete(self, uid: str, code: str) -> dict: ...


@dataclass
class LdapManagerFactors:
    """ldap_manager's `/internal/2fa/*` endpoints.

    Guarded by `X-Internal-Auth`; it answers 404 when its own
    MFA_INTERNAL_SECRET is unset and 403 on a mismatch. Both are treated as
    MfaUnavailable rather than as a failed factor — they are deployment faults,
    not the administrator's.
    """

    url: str
    internal_secret: str
    tenant_context: str = ""
    timeout_s: float = 5.0

    def _post(self, path: str, body: dict) -> dict:
        import httpx

        try:
            r = httpx.post(f"{self.url.rstrip('/')}{path}", json=body,
                           headers={"X-Internal-Auth": self.internal_secret},
                           timeout=self.timeout_s)
        except Exception as e:  # noqa: BLE001 — any transport failure is a refusal
            log.warning("2FA store unreachable calling %s: %s", path, e)
            raise MfaUnavailable(f"the second-factor store could not be reached: {e}") from e
        if r.status_code in (403, 404):
            # The internal API is not enabled, or our secret does not match. This
            # is the misconfiguration that would otherwise look like "nobody is
            # enrolled" and hand out sessions.
            log.error("2FA store refused the internal call to %s (%d) — check that "
                      "AMC_MFA_INTERNAL_SECRET matches ldap_manager's "
                      "MFA_INTERNAL_SECRET", path, r.status_code)
            raise MfaUnavailable("the second-factor store refused this service's credential")
        if r.status_code == 429:
            raise AuthError("too many attempts; wait and try again",
                            status_code=status.HTTP_429_TOO_MANY_REQUESTS)
        if r.status_code >= 400:
            log.warning("2FA store returned %d for %s", r.status_code, path)
            raise MfaUnavailable(f"the second-factor store returned {r.status_code}")
        try:
            return r.json()
        except Exception as e:  # noqa: BLE001
            raise MfaUnavailable("the second-factor store returned an unreadable body") from e

    def _who(self, uid: str) -> dict:
        return {"uid": uid, "tenant": self.tenant_context}

    def status(self, uid: str) -> FactorStatus:
        # `/internal/2fa/required` reports `enabled` (per-user enrollment) next to
        # the tenant mandate. Only `enabled` is read: the mandate is a tenant
        # policy and this tier's requirement is not a tenant's to set.
        d = self._post("/internal/2fa/required", self._who(uid))
        return FactorStatus(enabled=bool(d.get("enabled")))

    def verify(self, uid: str, method: str, code: str) -> bool:
        d = self._post("/internal/2fa/verify",
                       {"uid": uid, "tenant": self.tenant_context,
                        "method": method, "code": code})
        return bool(d.get("ok"))

    def enroll_begin(self, uid: str) -> dict:
        d = self._post("/internal/2fa/enroll-begin", self._who(uid))
        return {"secret": d.get("secret", ""),
                "otpauth_uri": d.get("otpauth_uri", ""),
                "issuer": d.get("issuer", ""),
                "account": d.get("account", uid)}

    def enroll_complete(self, uid: str, code: str) -> dict:
        d = self._post("/internal/2fa/enroll-complete",
                       {"uid": uid, "tenant": self.tenant_context, "code": code})
        return {"ok": bool(d.get("ok")), "recovery_codes": list(d.get("recovery_codes") or [])}


@dataclass
class StaticFactors:
    """An in-memory factor store. Real, for the tests and for development.

    Enrolls nobody by default, so a deployment that wires this by accident
    refuses every login rather than admitting every one.
    """

    enrolled: dict[str, str] = field(default_factory=dict)      # uid -> code it accepts
    pending: dict[str, str] = field(default_factory=dict)
    recovery: dict[str, list[str]] = field(default_factory=dict)
    unavailable: bool = False
    calls: list[tuple[str, str]] = field(default_factory=list)

    def _guard(self, what: str, uid: str) -> None:
        self.calls.append((what, uid))
        if self.unavailable:
            raise MfaUnavailable("the second-factor store could not be reached")

    def status(self, uid: str) -> FactorStatus:
        self._guard("status", uid)
        return FactorStatus(enabled=uid in self.enrolled, pending=uid in self.pending,
                            recovery_remaining=len(self.recovery.get(uid, [])))

    def verify(self, uid: str, method: str, code: str) -> bool:
        self._guard("verify", uid)
        if method == RECOVERY:
            codes = self.recovery.get(uid, [])
            if code in codes:
                codes.remove(code)      # one-time, as the real store's consume is
                return True
            return False
        return self.enrolled.get(uid) == code

    def enroll_begin(self, uid: str) -> dict:
        self._guard("enroll_begin", uid)
        self.pending[uid] = "424242"
        return {"secret": "STATICSECRET", "otpauth_uri": f"otpauth://totp/{uid}",
                "issuer": "FileEngine", "account": uid}

    def enroll_complete(self, uid: str, code: str) -> dict:
        self._guard("enroll_complete", uid)
        want = self.pending.get(uid)
        if want is None:
            raise AuthError("no pending enrolment", status_code=status.HTTP_409_CONFLICT)
        if code != want:
            return {"ok": False, "recovery_codes": []}
        del self.pending[uid]
        self.enrolled[uid] = want
        self.recovery[uid] = ["rec-1", "rec-2"]
        return {"ok": True, "recovery_codes": list(self.recovery[uid])}


def from_config(config: Config) -> Optional[FactorStore]:
    """The live store when configured, otherwise None.

    None is NOT "MFA off" — `MfaGate` refuses on it while the requirement stands.
    The distinction is the one the tenant-state gate needed: a door with no way
    to ask must refuse, or the check is decorative on exactly the deployment that
    forgot to wire it.
    """
    if not config.mfa_is_enforceable():
        return None
    return LdapManagerFactors(url=config.mfa_url,
                              internal_secret=config.mfa_internal_secret,
                              tenant_context=config.mfa_tenant_context)


# ── the gate ───────────────────────────────────────────────────────────────


#: What a login needs next.
ADMITTED = "admitted"            # no factor required (opted out) — session now
VERIFY_REQUIRED = "verify"       # enrolled: prove it
ENROLLMENT_REQUIRED = "enroll"   # no factor: set one up before anything else


@dataclass
class MfaGate:
    """Decides what a correct password entitles someone to.

    Three outcomes, and the middle one is the whole point of the rewrite: a
    correct password alone never yields a session while the requirement stands.
    """

    config: Config
    store: Optional[FactorStore] = None

    def methods(self) -> tuple[str, ...]:
        return self.config.mfa_method_list()

    def next_step(self, uid: str) -> str:
        if not self.config.require_mfa:
            # The explicit opt-out. Logged on every use rather than silently
            # honoured, because this is the console it is being switched off for.
            log.warning("AMC_REQUIRE_MFA is false — admitting %s on a password "
                        "alone at the deployment tier", uid)
            return ADMITTED
        if self.store is None:
            # Required but unenforceable. REFUSES: the alternative is a
            # requirement that evaporates on the deployment that misconfigured it.
            log.error("a second factor is required but no store is configured "
                      "(AMC_MFA_URL / AMC_MFA_INTERNAL_SECRET) — refusing %s", uid)
            raise MfaUnavailable("a second factor is required but cannot be checked; "
                                 "access is refused until it can")
        st = self.store.status(uid)
        # `pending` is NOT enrolled. A begun-but-unconfirmed enrollment has a
        # secret stored and 2FA disabled; treating it as done would admit a
        # session against a secret nobody has proved they can generate codes from.
        return VERIFY_REQUIRED if st.enabled else ENROLLMENT_REQUIRED

    def verify(self, uid: str, method: str, code: str) -> bool:
        if self.store is None:
            raise MfaUnavailable("a second factor cannot be checked")
        m = (method or "").strip().lower()
        if m not in self.methods():
            # An allowlist, so a method this tier has deliberately excluded
            # cannot be reached by naming it. `email` is the one that matters.
            raise AuthError(f"{m or 'that'} is not a permitted second factor at this tier",
                            status_code=status.HTTP_400_BAD_REQUEST)
        if not code:
            raise AuthError("no code supplied", status_code=status.HTTP_400_BAD_REQUEST)
        return self.store.verify(uid, m, code)

    def enroll_begin(self, uid: str) -> dict:
        if self.store is None:
            raise MfaUnavailable("a second factor cannot be enrolled")
        if TOTP not in self.methods():
            raise AuthError("TOTP is not permitted at this tier",
                            status_code=status.HTTP_400_BAD_REQUEST)
        return self.store.enroll_begin(uid)

    def enroll_complete(self, uid: str, code: str) -> dict:
        if self.store is None:
            raise MfaUnavailable("a second factor cannot be enrolled")
        if not code:
            raise AuthError("no code supplied", status_code=status.HTTP_400_BAD_REQUEST)
        return self.store.enroll_complete(uid, code)
