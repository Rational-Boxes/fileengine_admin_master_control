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

"""Who holds deployment authority, and the record of how they got it.

DEPLOYMENT_MANAGEMENT_INTERFACE.md §6.1 and §6.3. The shape here follows from
one sentence in §6.3: a grant "must be recorded as a grant, not silently
effective — otherwise the separation above is a convention rather than a
control". So membership is not a column somebody edits. It is the **fold of an
append-only ledger of grants and revocations**, and the current holders are
derived from it rather than stored beside it.

That costs a little on read and buys the only thing that matters at this tier:
the question "who could have approved this, and since when" has an answer that
nobody had to remember to write down.

WHERE ADMINISTRATORS LIVE. §6.3 places these accounts outside every tenant OU,
alongside ou=services. That was blocked until 2026-09-29 by the §6.2
prerequisite — tenant-context role resolution walked a search path that
included the directory root — and it is now done in both bridges, so `ou=system`
exists and is what :mod:`auth` resolves authority from.

WHICH MEANS THERE ARE TWO STORES, AND THEY ARE NOT THE SAME THING.

  * The DIRECTORY IS AUTHORITATIVE — decided 2026-09-29. A session's roles come
    from `ou=system`, adding a member there confers authority immediately with
    no entry here, and readiness asks the directory whether anyone owns this
    deployment. Directory administration outranks this application; pretending
    otherwise would only mean this application disagreed with the system that
    actually decides.

    So nothing here is a permission check that the outside world must pass. The
    ledger's own `can_grant` guard remains only for direct programmatic use —
    the API passes the directory-verified roles instead (see `authority`
    below).
  * This LEDGER is the attributed record of grants made THROUGH this
    application, and the seed for the first owner. It answers "who could have
    approved this, and since when" — which a directory, holding only the
    present, cannot.

They can legitimately disagree, and the disagreement must never be silent:
:func:`auth.reconcile` names it and `/v1/administrators` returns it beside the
list, because a role held in the directory with no grant behind it is authority
nobody can account for — and is exactly what someone with directory access
would create.
"""
from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass, field
from typing import Iterable, Optional, Protocol

from .roles import (
    ALL_ROLES,
    GRANTABLE_ROLES,
    SYSTEM_OWNER,
    RoleError,
    can_grant,
    validate_role,
)

#: The actor recorded for grants that come from provisioning rather than from a
#: person. §6.3: "the first `system_owner` comes from provisioning, the way a
#: tenant's first administrator already does in tenant.yml." It is not a
#: principal, cannot authenticate, and exists so the first row in the ledger has
#: an honest author instead of naming someone who did not act.
PROVISIONING = "provisioning"


def _now() -> _dt.datetime:
    return _dt.datetime.now(_dt.timezone.utc)


@dataclass(frozen=True)
class Grant:
    """One entry in the ledger. Immutable by construction: a revocation is a new
    entry, never an edit, so history cannot be rewritten into agreement with the
    present."""

    subject: str
    role: str
    granted_by: str
    reason: str = ""
    at: _dt.datetime = field(default_factory=_now)
    revoked: bool = False

    def __post_init__(self) -> None:
        if not self.subject:
            raise RoleError("a grant needs a subject")
        if not self.granted_by:
            raise RoleError("a grant needs an actor; use PROVISIONING for the first one")
        validate_role(self.role)


class GrantStore(Protocol):
    """Append and read. Deliberately no update and no delete."""

    def append(self, grant: Grant) -> None: ...
    def all(self) -> list[Grant]: ...


class InMemoryGrantStore:
    """The default store. Real, not a stub — it is the whole ledger for a
    development instance, and it is what the tests exercise."""

    def __init__(self) -> None:
        self._entries: list[Grant] = []

    def append(self, grant: Grant) -> None:
        self._entries.append(grant)

    def all(self) -> list[Grant]:
        return list(self._entries)


class AdministratorRegistry:
    """Deployment authority, derived from the ledger."""

    def __init__(self, store: Optional[GrantStore] = None) -> None:
        self.store = store if store is not None else InMemoryGrantStore()

    # ── reading ────────────────────────────────────────────────────────────

    def roles_of(self, subject: str) -> frozenset[str]:
        """The roles ``subject`` holds now, folded from the ledger in order.

        A later entry wins over an earlier one for the same (subject, role),
        which is what makes revoke-then-regrant work without special cases.
        """
        held: dict[str, bool] = {}
        for g in self.store.all():
            if g.subject == subject:
                held[g.role] = not g.revoked
        return frozenset(r for r, live in held.items() if live)

    def holders(self, role: str) -> list[str]:
        """Everyone holding ``role`` now, sorted."""
        validate_role(role)
        return sorted(
            s for s in self.subjects() if role in self.roles_of(s)
        )

    def subjects(self) -> set[str]:
        """Everyone who has ever appeared in the ledger, held or not."""
        return {g.subject for g in self.store.all()}

    def history(self, subject: Optional[str] = None) -> list[Grant]:
        """The ledger, optionally for one subject, oldest first."""
        entries = self.store.all()
        if subject is not None:
            entries = [g for g in entries if g.subject == subject]
        return entries

    def is_administrator(self, subject: str) -> bool:
        return bool(self.roles_of(subject))

    # ── writing ────────────────────────────────────────────────────────────

    def grant(self, subject: str, role: str, *, by: str, reason: str = "",
              authority: Optional[Iterable[str]] = None) -> Grant:
        """Grant ``role`` to ``subject``, as ``by``.

        Refuses unless the actor holds `system_owner` (§6.1: "the only role that
        can create authority"), with one exception: :data:`PROVISIONING`, which
        is how the first owner exists at all and is checked separately in
        :func:`bootstrap_owner` rather than being a general escape hatch.

        A self-grant is allowed and recorded like any other — §6.3 says exactly
        that. It is not a loophole: an owner can already grant the same role to
        anyone, so forbidding the self case would buy nothing and would only
        push the same act through a second account.

        ``authority`` NAMES WHERE THE ACTOR'S ROLES CAME FROM, and exists
        because there are two stores. The API gate authorises from the
        DIRECTORY — that is what the session's roles are resolved from — while
        this ledger knows only about grants recorded here. The two can
        legitimately disagree: an owner added in the directory has authority
        before any grant of theirs is recorded, which is exactly the bootstrap
        case. Passing the directory-verified roles keeps one source of truth per
        call instead of silently checking a second one and refusing for a reason
        the caller cannot see.

        Omitted, it falls back to this ledger's own view, which keeps the
        control meaningful for direct programmatic use and for the tests.
        """
        validate_role(role)
        actor_roles = self.roles_of(by) if authority is None else frozenset(authority)
        if by != PROVISIONING and not can_grant(actor_roles):
            raise RoleError(
                f"{by!r} cannot grant {role!r}: only {SYSTEM_OWNER} creates authority"
            )
        if role == SYSTEM_OWNER and by == PROVISIONING and self.holders(SYSTEM_OWNER):
            # Provisioning mints the FIRST owner. After that, owners come from
            # owners, so a re-run of provisioning cannot quietly add one.
            raise RoleError(
                "an owner already exists; further owners are granted by an owner, "
                "not by provisioning"
            )
        g = Grant(subject=subject, role=role, granted_by=by, reason=reason)
        self.store.append(g)
        return g

    def revoke(self, subject: str, role: str, *, by: str, reason: str = "",
               authority: Optional[Iterable[str]] = None) -> Grant:
        """Revoke ``role`` from ``subject``. Appends; never edits.

        The last owner cannot be revoked. A deployment with no owner has no way
        to create authority again short of re-provisioning, and discovering that
        during an incident is the wrong time.
        """
        validate_role(role)
        actor_roles = self.roles_of(by) if authority is None else frozenset(authority)
        if not can_grant(actor_roles):
            raise RoleError(f"{by!r} cannot revoke {role!r}: only {SYSTEM_OWNER} creates authority")
        if role == SYSTEM_OWNER and self.holders(SYSTEM_OWNER) == [subject]:
            raise RoleError(
                "refusing to revoke the last system_owner — the deployment would "
                "have no way to grant authority again"
            )
        g = Grant(subject=subject, role=role, granted_by=by, reason=reason, revoked=True)
        self.store.append(g)
        return g


def bootstrap_owner(
    registry: AdministratorRegistry,
    subject: str,
    *,
    with_all_roles: bool = True,
    reason: str = "first deployment administrator, from provisioning",
) -> list[Grant]:
    """Create the first ``system_owner``, idempotently.

    ``with_all_roles`` also grants the four operational roles. That is what
    makes this account the *ultimate* administrator rather than merely the one
    who can hand out authority — and it matters because `system_owner` does not
    imply the others (see :func:`roles.effective_roles`). Without it the first
    administrator can grant every power and exercise none, which on a
    single-operator deployment is a puzzle rather than a control.

    Each of those four is written as its own ledger entry attributed to
    :data:`PROVISIONING`, so "this account can approve redactions" is a dated
    record with an author, exactly as §6.3 requires — not a special case in the
    authorisation code that a reader would have to know about.

    Idempotent because it runs at startup: a restart must not append a second
    identical grant, and must not fail either.
    """
    if not subject:
        raise RoleError("bootstrap needs a subject")

    existing_owners = registry.holders(SYSTEM_OWNER)
    if existing_owners and subject not in existing_owners:
        # Someone else already owns this deployment. Refusing is right: silently
        # adding a second owner from a configuration file is how a bootstrap
        # value becomes a back door.
        raise RoleError(
            f"cannot bootstrap {subject!r}: {', '.join(existing_owners)} already "
            f"holds {SYSTEM_OWNER}. Grant it from an existing owner instead."
        )

    wanted = [SYSTEM_OWNER] + (list(GRANTABLE_ROLES) if with_all_roles else [])
    held = registry.roles_of(subject)
    made: list[Grant] = []
    for role in wanted:
        if role in held:
            continue
        made.append(registry.grant(subject, role, by=PROVISIONING, reason=reason))
    return made


def summarise(registry: AdministratorRegistry) -> list[tuple[str, list[str]]]:
    """(subject, roles) for every current administrator, sorted. For /readyz,
    a console, and the startup log — the answer to "who holds authority here"
    should never require a query somebody has to compose."""
    out = []
    for s in sorted(registry.subjects()):
        roles = sorted(registry.roles_of(s))
        if roles:
            out.append((s, roles))
    return out
