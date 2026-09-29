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

"""The deployment-role namespace and the rules that govern it.

DEPLOYMENT_MANAGEMENT_INTERFACE.md §6.1–6.3. Pure: no I/O, no configuration
read at import, so the rules can be tested without a deployment underneath them
and reused by anything that needs to recognise one of these names.
"""
from __future__ import annotations

from typing import Iterable, Sequence

#: The prefix that makes "refuse these in tenant context" ONE rule rather than a
#: list that drifts as roles are added (§6.2). Every deployment role must carry
#: it; that is what `is_deployment_role` relies on, and why a role added later
#: without it would be invisible to the very check that contains it.
ROLE_PREFIX = "system_"

# ── The five names ─────────────────────────────────────────────────────────

#: Read-only across everything. The baseline, and what most deployment work
#: actually needs.
SYSTEM_OBSERVER = "system_observer"
#: Tenant setup, lifecycle, seats, quota, a tenant's own administrators.
SYSTEM_TENANTS = "system_tenants"
#: Incidents, cross-tenant detection, acknowledgements, redaction approval,
#: credential revocation.
SYSTEM_SECURITY = "system_security"
#: Metering, statements, plan changes.
SYSTEM_BILLING = "system_billing"
#: Grants the four above. The only role that can create authority.
SYSTEM_OWNER = "system_owner"

#: The four that `system_owner` can grant. Ordered for stable display.
GRANTABLE_ROLES: tuple[str, ...] = (
    SYSTEM_OBSERVER,
    SYSTEM_TENANTS,
    SYSTEM_SECURITY,
    SYSTEM_BILLING,
)

#: Every deployment role, including the one that grants.
ALL_ROLES: tuple[str, ...] = GRANTABLE_ROLES + (SYSTEM_OWNER,)


class RoleError(ValueError):
    """A role name or a grant that the namespace refuses."""


# ── Recognition ────────────────────────────────────────────────────────────


def is_deployment_role(name: str, prefix: str = ROLE_PREFIX) -> bool:
    """True for any name in the deployment namespace.

    Matches on the PREFIX, not on membership of :data:`ALL_ROLES`, and that is
    deliberate. The check exists so a tenant-scoped login can refuse these
    outright; a role added to the directory tomorrow and to this file next week
    must be refused for the whole of that gap, not welcomed because the list had
    not caught up. The prefix is the boundary; the list is only what this
    application knows how to use.
    """
    return bool(name) and name.startswith(prefix)


def strip_deployment_roles(roles: Iterable[str], prefix: str = ROLE_PREFIX) -> list[str]:
    """Everything in ``roles`` that is NOT a deployment role.

    Defence in depth for a tenant door (§6.2), the way share_service already
    strips admin roles before delegating. Placement in the directory is
    configuration, and configuration drifts; this does not depend on placement.

    It is NOT a substitute for the resolver fix §6.2 requires. A door that calls
    this is protected; the core is protected only when tenant-context resolution
    refuses these names regardless of which search base returned them.
    """
    return [r for r in roles if not is_deployment_role(r, prefix)]


def validate_role(name: str) -> str:
    """Return ``name`` if it is a known deployment role, else raise."""
    if name not in ALL_ROLES:
        raise RoleError(
            f"{name!r} is not a deployment role; expected one of {', '.join(ALL_ROLES)}"
        )
    return name


# ── Authority ──────────────────────────────────────────────────────────────


def effective_roles(held: Iterable[str]) -> frozenset[str]:
    """The roles a holder actually has. **Returns what was passed, expanded by
    nothing.**

    This function exists to be the place where somebody would, reasonably and
    wrongly, make `system_owner` imply the other four. It must not. §6.1: the
    roles are "additive and unordered", and §6.3: an owner granting themselves
    another role "is legitimate and must be recorded as a grant, not silently
    effective — otherwise the separation above is a convention rather than a
    control".

    An owner who has not been granted `system_security` cannot approve a
    redaction. They can grant it to themselves in one call, and that grant is
    then a record with a timestamp and an actor. The inconvenience is the
    feature: it is the difference between an auditable decision and a name with
    unclear standing.
    """
    return frozenset(r for r in held if r in ALL_ROLES)


def can_grant(held: Iterable[str]) -> bool:
    """Only ``system_owner`` can create authority (§6.1)."""
    return SYSTEM_OWNER in effective_roles(held)


def authorises(held: Iterable[str], required: str) -> bool:
    """Whether ``held`` satisfies ``required``.

    Plain membership, for the reason in :func:`effective_roles`. `system_owner`
    does not satisfy `system_security`; it satisfies `system_owner`.
    """
    validate_role(required)
    return required in effective_roles(held)


def authorising_role(held: Iterable[str], required: str) -> str:
    """The role under which an action is authorised, for the audit record.

    §6.1: "Every action records WHICH ROLE authorised it, not only who performed
    it. A person holding three roles who approves a redaction did so as
    `system_security`, and a year later that is the difference between an
    auditable decision and a name with unclear standing."

    Raises :class:`RoleError` when the holder does not have it, so a caller
    cannot record an action as authorised by a role its actor did not hold.
    """
    if not authorises(held, required):
        raise RoleError(
            f"not authorised: {required!r} required, holder has "
            f"{', '.join(sorted(effective_roles(held))) or '(none)'}"
        )
    return required


def describe(held: Sequence[str]) -> str:
    """A stable, human-readable summary for logs and the audit record."""
    eff = sorted(effective_roles(held))
    return ", ".join(eff) if eff else "(no deployment roles)"
