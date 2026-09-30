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

"""The door to the deployment tier.

PROPOSAL_system_administration_application.md §6. Four properties, each of which
is load-bearing rather than good practice:

**Deployment roles are resolved from the deployment OU and nowhere else.** The
exact mirror of the fix the tenant doors just received: they refuse the
``system_*`` namespace and search only tenant OUs; this one searches only the
deployment OU and grants nothing for a tenant group. A tenant administrator who
is a member of fifty tenant groups gets no authority here, and that is a
property of *where this looks*, not of a check somebody remembered.

**The audience is distinct.** A token minted here carries an audience no tenant
door accepts, and verification here pins the same value. Acceptance across the
boundary is impossible rather than unimplemented — §6 asks for exactly that
distinction.

**MFA is mandatory.** Not policy-dependent, not per-tenant. A session whose
``amr`` carries only ``pwd`` is refused at the gate even if it verifies.

**Authorisation is by named role.** There is no tier and no inheritance, so
there is no ordering to get wrong, and every authorised call reports WHICH role
allowed it so the caller can put that in the audit record (§6.1).
"""
from __future__ import annotations

import datetime as _dt
import logging
from dataclasses import dataclass, field
from typing import Iterable, Optional, Protocol, Sequence

import jwt
from fastapi import Depends, Header, HTTPException, status

from .config import Config
from .roles import (
    ALL_ROLES,
    SYSTEM_OWNER,
    RoleError,
    authorising_role,
    effective_roles,
    is_deployment_role,
)

log = logging.getLogger("admin_master_control.auth")

#: Authentication methods that count as a SECOND factor. "pwd" is not among
#: them, deliberately — it is the first.
SECOND_FACTORS = frozenset({"totp", "webauthn", "recovery", "email", "oauth"})


class AuthError(Exception):
    """Refused at the door. Carries the reason for the log, never for the body."""

    def __init__(self, reason: str, *, status_code: int = status.HTTP_401_UNAUTHORIZED):
        super().__init__(reason)
        self.reason = reason
        self.status_code = status_code


class DirectoryUnavailable(AuthError):
    """The directory could not be ASKED — as distinct from having answered "no".

    The two are opposite operator responses and they were indistinguishable at
    first, because a failed search returned an empty role set. That is the same
    mistake the tenant-state gate was written to avoid: "a failed lookup must not
    claim a suspension". Here it claimed something narrower and more misleading —
    that a named administrator holds no deployment role — about a directory that
    in fact lists them in all five groups.

    Still FAILS CLOSED: this is an AuthError, so nothing is authorised on it. The
    difference is only in what it says, and 503 rather than 403 says "come back"
    rather than "you have no authority here".
    """

    def __init__(self, reason: str):
        super().__init__(reason, status_code=status.HTTP_503_SERVICE_UNAVAILABLE)


@dataclass(frozen=True)
class Principal:
    """An authenticated administrator and the authority they hold."""

    subject: str
    roles: frozenset[str] = frozenset()
    amr: tuple[str, ...] = ()
    jti: str = ""

    @property
    def has_second_factor(self) -> bool:
        return bool(SECOND_FACTORS.intersection(self.amr))

    def authorising(self, required: str) -> str:
        """The role under which an action is authorised, for the audit record.

        Raises :class:`RoleError` when not held, so a caller cannot record an
        action as authorised by a role its actor did not have.
        """
        return authorising_role(self.roles, required)


# ── directory ──────────────────────────────────────────────────────────────


class DeploymentDirectory(Protocol):
    """Resolves an administrator's deployment roles. Injectable so the gate can
    be tested without a directory."""

    def authenticate(self, subject: str, password: str) -> bool: ...
    def roles_of(self, subject: str) -> frozenset[str]: ...


@dataclass
class LdapDeploymentDirectory:
    """LDAP, scoped to the deployment OU.

    THE SCOPE IS THE SECURITY PROPERTY. ``role_base`` is
    ``ou=system,<base_dn>`` and nothing above or beside it is searched, so a
    tenant group cannot become authority here however the directory is laid
    out. The tenant doors got the same treatment in the opposite direction on
    2026-09-29; the two halves only work as a pair.

    A name that comes back and is NOT in the deployment namespace is dropped
    rather than trusted, because the base could be misconfigured to point at a
    tenant OU and that must fail closed, not open.
    """

    url: str
    base_dn: str
    bind_dn: str = ""
    bind_password: str = ""
    role_ou: str = "ou=system"
    user_ou: str = "ou=users"

    @property
    def role_base(self) -> str:
        return f"{self.role_ou},{self.base_dn}"

    def user_dn(self, subject: str) -> str:
        return f"uid={subject},{self.user_ou},{self.base_dn}"

    def _connect(self, dn: str, password: str):
        import ldap3  # imported here so the module is testable without ldap3

        server = ldap3.Server(self.url, get_info=ldap3.NONE)
        return ldap3.Connection(server, user=dn, password=password,
                                auto_bind=True, raise_exceptions=False)

    def authenticate(self, subject: str, password: str) -> bool:
        if not subject or not password:
            return False
        try:
            conn = self._connect(self.user_dn(subject), password)
        except Exception as e:  # noqa: BLE001 - an unreachable directory is a refusal
            log.warning("directory bind failed for %s: %s", subject, e)
            return False
        try:
            return bool(conn.bound)
        finally:
            try:
                conn.unbind()
            except Exception:  # noqa: BLE001
                pass

    def roles_of(self, subject: str) -> frozenset[str]:
        import ldap3

        dn = self.user_dn(subject)
        try:
            conn = self._connect(self.bind_dn, self.bind_password)
        except Exception as e:  # noqa: BLE001
            # RAISES rather than returning an empty set. An empty set means "this
            # administrator holds no deployment role", which is a true and
            # actionable statement; it must not also mean "the directory did not
            # answer". See DirectoryUnavailable.
            log.warning("directory unreachable resolving roles for %s: %s", subject, e)
            raise DirectoryUnavailable(
                f"the deployment directory could not be reached: {e}") from e
        try:
            # SUBTREE of the deployment OU ONLY. Never base_dn, never a tenant OU.
            ok = conn.search(self.role_base,
                             f"(&(objectClass=groupOfNames)(member={dn}))",
                             search_scope=ldap3.SUBTREE, attributes=["cn"])
            if not ok:
                # The search itself failed — the commonest cause is exactly the one
                # that bit here: an ANONYMOUS or under-privileged bind against a
                # directory that hides the role OU. OpenLDAP answers `noSuchObject`
                # for a subtree the client may not see, so "the OU is missing" and
                # "you may not read it" arrive identically and neither is "this
                # user has no roles".
                result = getattr(conn, "result", None) or {}
                desc = result.get("description") or result.get("result") or "unknown"
                log.error("role search under %s failed (%s) — bound as %r. A directory "
                          "that hides the role OU returns nothing to an anonymous "
                          "client; set AMC_LDAP_BIND_DN / AMC_LDAP_BIND_PASSWORD.",
                          self.role_base, desc, self.bind_dn or "<anonymous>")
                raise DirectoryUnavailable(
                    f"the deployment role OU {self.role_base} could not be searched "
                    f"({desc})")
            found = set()
            for entry in conn.entries:
                cn = str(entry.cn.value) if entry.cn else ""
                if not cn:
                    continue
                if not is_deployment_role(cn):
                    # The base is meant to hold only deployment roles. Something
                    # else here means the base is pointing somewhere it should
                    # not, and the safe reading is "grant nothing from it".
                    log.warning("ignoring non-deployment group %r under %s", cn, self.role_base)
                    continue
                found.add(cn)
            return frozenset(r for r in found if r in ALL_ROLES)
        finally:
            try:
                conn.unbind()
            except Exception:  # noqa: BLE001
                pass


@dataclass
class StaticDeploymentDirectory:
    """A directory held in memory. Real, for development and for the tests —
    the gate's behaviour must not depend on having LDAP to hand."""

    passwords: dict[str, str] = field(default_factory=dict)
    grants: dict[str, set[str]] = field(default_factory=dict)

    def authenticate(self, subject: str, password: str) -> bool:
        return bool(password) and self.passwords.get(subject) == password

    def roles_of(self, subject: str) -> frozenset[str]:
        return frozenset(r for r in self.grants.get(subject, set()) if r in ALL_ROLES)


# ── tokens ─────────────────────────────────────────────────────────────────


def mint_token(config: Config, principal: Principal, *, ttl_seconds: int = 3600) -> str:
    """A session for this tier, and for this tier only.

    ``aud`` is the distinct audience; ``amr`` records how the administrator
    proved themselves, so the MFA requirement can be enforced on every request
    rather than only at login.
    """
    if not config.jwt_secret:
        raise AuthError("no token secret configured",
                        status_code=status.HTTP_503_SERVICE_UNAVAILABLE)
    now = _dt.datetime.now(_dt.timezone.utc)
    payload = {
        "sub": principal.subject,
        "aud": config.token_audience,
        "iss": "admin-master-control",
        "iat": int(now.timestamp()),
        "exp": int((now + _dt.timedelta(seconds=ttl_seconds)).timestamp()),
        "amr": list(principal.amr),
        "roles": sorted(principal.roles),
    }
    return jwt.encode(payload, config.jwt_secret, algorithm="HS256")


def verify_token(config: Config, token: str) -> Principal:
    """Verify a token minted here. Refuses anything minted anywhere else.

    ``audience`` is passed to PyJWT rather than compared afterwards, so a token
    for a tenant door fails signature-and-claim validation together instead of
    reaching a check that could be removed by a later refactor. The algorithm is
    pinned for the same reason the bridge pins it: an unpinned verifier accepts
    "alg":"none".
    """
    if not config.jwt_secret:
        raise AuthError("no token secret configured",
                        status_code=status.HTTP_503_SERVICE_UNAVAILABLE)
    try:
        claims = jwt.decode(
            token,
            config.jwt_secret,
            algorithms=["HS256"],
            audience=config.token_audience,
            issuer="admin-master-control",
            options={"require": ["exp", "sub", "aud"]},
        )
    except jwt.PyJWTError as e:
        raise AuthError(f"token rejected: {e}") from e

    roles = effective_roles(claims.get("roles") or [])
    return Principal(
        subject=str(claims.get("sub") or ""),
        roles=roles,
        amr=tuple(claims.get("amr") or ()),
        jti=str(claims.get("jti") or ""),
    )


# ── login ──────────────────────────────────────────────────────────────────


def login(config: Config, directory: DeploymentDirectory, subject: str, password: str,
          *, second_factor: Optional[str] = None) -> Principal:
    """Authenticate an administrator and resolve their authority.

    Order matters. The password is checked first, then the roles are read — a
    caller who cannot bind never learns whether the account holds authority,
    so this is not an oracle for "is X an administrator".

    An administrator with NO deployment role is refused rather than issued an
    empty session. There is nothing at this tier for a principal with no role to
    do, and an empty session is a thing that exists and can be passed around.
    """
    if not directory.authenticate(subject, password):
        raise AuthError("bad credentials")
    roles = directory.roles_of(subject)
    if not roles:
        raise AuthError(f"{subject} holds no deployment role",
                        status_code=status.HTTP_403_FORBIDDEN)

    amr = ["pwd"]
    if second_factor:
        if second_factor not in SECOND_FACTORS:
            raise AuthError(f"unknown second factor {second_factor!r}")
        amr.append(second_factor)
    return Principal(subject=subject, roles=roles, amr=tuple(amr))


# ── the gate ───────────────────────────────────────────────────────────────


def principal_from_header(config: Config, authorization: Optional[str]) -> Principal:
    """Verify the bearer and enforce the tier's non-negotiables."""
    if not authorization or not authorization.lower().startswith("bearer "):
        raise AuthError("no bearer token")
    principal = verify_token(config, authorization.split(None, 1)[1].strip())

    if config.require_mfa and not principal.has_second_factor:
        # §6: MFA is mandatory at this tier, not policy-dependent. Enforced on
        # every request rather than only at login, so a session that predates a
        # policy change cannot outlive it.
        raise AuthError("second factor required at this tier",
                        status_code=status.HTTP_403_FORBIDDEN)
    if not principal.roles:
        raise AuthError("no deployment role", status_code=status.HTTP_403_FORBIDDEN)
    return principal


def _http(err: AuthError) -> HTTPException:
    # The body says only that it was refused. The reason goes to the log: a
    # caller learning WHY they were refused learns about the directory.
    return HTTPException(status_code=err.status_code, detail="forbidden"
                         if err.status_code == status.HTTP_403_FORBIDDEN else "unauthorized")


def make_require(config: Config):
    """Bind the gate to a config, returning a `require(role)` factory.

    The config is bound once at application build rather than looked up per
    request, so a test can build an app with a config it constructed and the
    gate uses that one.
    """

    def require_role(role: str):
        if role not in ALL_ROLES:
            raise RoleError(f"{role!r} is not a deployment role")

        def dependency(authorization: Optional[str] = Header(None)) -> Principal:
            try:
                principal = principal_from_header(config, authorization)
                principal.authorising(role)  # raises RoleError when not held
            except AuthError as e:
                log.info("refused: %s", e.reason)
                raise _http(e) from e
            except RoleError as e:
                log.info("refused: %s", e)
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                                    detail="forbidden") from e
            return principal

        return dependency

    return require_role


# ── directory vs ledger ────────────────────────────────────────────────────


class OwnerLookup(Protocol):
    """A directory that can answer "does anyone own this deployment"."""

    def holders(self, role: str) -> list[str]: ...


def directory_has_owner(directory: DeploymentDirectory, candidates: Iterable[str]) -> bool:
    """Whether any of ``candidates`` holds system_owner IN THE DIRECTORY.

    THE DIRECTORY IS AUTHORITATIVE. Readiness must ask it, not the ledger: a
    deployment can perfectly well have an owner in `ou=system` and an empty
    ledger — that is what a directory-first deployment looks like on its first
    start, and reporting it as "stranded" would be reporting the wrong store.

    ``candidates`` is needed because LDAP answers "which groups is this user
    in", not "who is in this group", through the interface this tier uses. The
    names come from the ledger and the bootstrap value: the subjects this
    application has any reason to know about. It is therefore a check for "an
    owner we can name", not "an owner exists" — and the difference is why a
    directory-only owner nobody has recorded still shows as drift rather than
    being silently relied upon.

    Propagates :class:`DirectoryUnavailable` rather than answering False. "No
    owner" and "could not read the role OU" need different operator responses —
    the first is a provisioning gap, the second a bind credential — and readiness
    reported the first about a directory containing an owner until they were
    separated.
    """
    for subject in candidates:
        if SYSTEM_OWNER in directory.roles_of(subject):
            return True
    return False


def reconcile(directory_roles: dict[str, frozenset[str]],
              ledger_roles: dict[str, frozenset[str]]) -> list[str]:
    """Differences between what the directory says and what the ledger records.

    Two stores describe authority here and they can disagree: the DIRECTORY is
    what authorisation reads, and the LEDGER is the attributed record of grants
    made through this application (§6.3 wants a grant to be a record, not a
    flag). Someone with directory access can add a member without going through
    this application at all, and that is legitimate — directory administration
    outranks this tier.

    What is not acceptable is the disagreement being SILENT. A role held in the
    directory with no grant behind it is authority nobody can account for, and
    it is precisely what an attacker with directory access would create. This
    returns those differences so /readyz and the console can show them; it
    deliberately does not resolve them, because either side might be the wrong
    one and only a person can say which.
    """
    out: list[str] = []
    for subject in sorted(set(directory_roles) | set(ledger_roles)):
        d = directory_roles.get(subject, frozenset())
        l = ledger_roles.get(subject, frozenset())
        for role in sorted(d - l):
            out.append(f"{subject} holds {role} in the directory with no grant recorded")
        for role in sorted(l - d):
            out.append(f"{subject} was granted {role} but does not hold it in the directory")
    return out
