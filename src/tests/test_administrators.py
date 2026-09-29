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

"""The deployment role model and the grant ledger.

The tests that matter here are the ones pinning rules a later change would
reasonably and wrongly "simplify":

  * `system_owner` does NOT imply the other four (§6.1). Making it imply them
    is the obvious convenience and it turns the separation into a convention.
  * a grant is a LEDGER ENTRY, not a flag. §6.3 requires an owner's self-grant
    to be recorded rather than silently effective, and that is only true if
    membership is derived from entries.
  * the deployment namespace is recognised by PREFIX, not by the known-role
    list, so a role added to the directory before it is added to this code is
    still refused in tenant context.
"""
from __future__ import annotations

import pytest

from admin_master_control.administrators import (
    PROVISIONING,
    AdministratorRegistry,
    Grant,
    bootstrap_owner,
    summarise,
)
from admin_master_control.roles import (
    ALL_ROLES,
    GRANTABLE_ROLES,
    SYSTEM_BILLING,
    SYSTEM_OBSERVER,
    SYSTEM_OWNER,
    SYSTEM_SECURITY,
    SYSTEM_TENANTS,
    RoleError,
    authorises,
    authorising_role,
    can_grant,
    effective_roles,
    is_deployment_role,
    strip_deployment_roles,
)

JAMES = "james@rationalboxes.com"


# ── the namespace ──────────────────────────────────────────────────────────


def test_the_five_roles_are_the_namespace():
    assert set(ALL_ROLES) == {
        SYSTEM_OBSERVER, SYSTEM_TENANTS, SYSTEM_SECURITY, SYSTEM_BILLING, SYSTEM_OWNER,
    }
    assert SYSTEM_OWNER not in GRANTABLE_ROLES, "owner is minted by provisioning, not granted as one of the four"


def test_a_deployment_role_is_recognised_by_prefix_not_by_the_list():
    # The gap this covers: a role that exists in the directory before it exists
    # in this file. Recognising by membership of ALL_ROLES would WELCOME it in
    # tenant context for exactly as long as the list lagged.
    assert is_deployment_role("system_something_added_later")
    assert is_deployment_role(SYSTEM_SECURITY)
    assert not is_deployment_role("administrators")
    assert not is_deployment_role("")


def test_tenant_roles_survive_stripping_and_deployment_roles_do_not():
    mixed = ["users", "contributors", SYSTEM_SECURITY, "system_future", "erasure_admins"]
    assert strip_deployment_roles(mixed) == ["users", "contributors", "erasure_admins"]


# ── the rule most likely to be "simplified" away ───────────────────────────


def test_owner_does_not_imply_the_operational_roles():
    held = [SYSTEM_OWNER]
    assert can_grant(held), "owner creates authority"
    for role in GRANTABLE_ROLES:
        assert not authorises(held, role), (
            f"{SYSTEM_OWNER} must not silently confer {role} — §6.3 requires the "
            f"grant to be recorded, and an implied role is recorded nowhere"
        )


def test_effective_roles_expands_nothing():
    assert effective_roles([SYSTEM_OWNER]) == frozenset({SYSTEM_OWNER})
    assert effective_roles(["not_a_role", SYSTEM_BILLING]) == frozenset({SYSTEM_BILLING})


def test_the_authorising_role_is_named_and_must_be_held():
    held = [SYSTEM_OWNER, SYSTEM_SECURITY]
    assert authorising_role(held, SYSTEM_SECURITY) == SYSTEM_SECURITY
    # Holding three roles does not let an action be recorded under a fourth.
    with pytest.raises(RoleError):
        authorising_role(held, SYSTEM_BILLING)


# ── the ledger ─────────────────────────────────────────────────────────────


def test_membership_is_derived_from_entries_not_stored():
    r = AdministratorRegistry()
    bootstrap_owner(r, JAMES, with_all_roles=False)
    assert r.roles_of(JAMES) == frozenset({SYSTEM_OWNER})
    r.grant("ops@rationalboxes.com", SYSTEM_OBSERVER, by=JAMES, reason="on call")
    assert r.holders(SYSTEM_OBSERVER) == ["ops@rationalboxes.com"]
    # Two entries, both still present after the fact.
    assert len(r.history()) == 2


def test_only_an_owner_can_grant():
    r = AdministratorRegistry()
    bootstrap_owner(r, JAMES)
    r.grant("sec@rationalboxes.com", SYSTEM_SECURITY, by=JAMES)
    with pytest.raises(RoleError):
        # Holding system_security does not let you hand it on.
        r.grant("someone@rationalboxes.com", SYSTEM_SECURITY, by="sec@rationalboxes.com")


def test_a_self_grant_is_allowed_and_recorded():
    # §6.3 says exactly this: legitimate, and recorded rather than implied.
    r = AdministratorRegistry()
    bootstrap_owner(r, JAMES, with_all_roles=False)
    assert not authorises(r.roles_of(JAMES), SYSTEM_BILLING)
    g = r.grant(JAMES, SYSTEM_BILLING, by=JAMES, reason="single-operator deployment")
    assert authorises(r.roles_of(JAMES), SYSTEM_BILLING)
    assert g.granted_by == JAMES and g.reason == "single-operator deployment"
    assert any(e.role == SYSTEM_BILLING and not e.revoked for e in r.history(JAMES))


def test_revocation_is_an_entry_and_history_survives_it():
    r = AdministratorRegistry()
    bootstrap_owner(r, JAMES)
    r.grant("temp@rationalboxes.com", SYSTEM_TENANTS, by=JAMES)
    r.revoke("temp@rationalboxes.com", SYSTEM_TENANTS, by=JAMES, reason="contract ended")
    assert r.roles_of("temp@rationalboxes.com") == frozenset()
    hist = r.history("temp@rationalboxes.com")
    assert len(hist) == 2, "the grant is still in the ledger after the revocation"
    assert hist[0].revoked is False and hist[1].revoked is True


def test_a_revoked_role_can_be_granted_again():
    r = AdministratorRegistry()
    bootstrap_owner(r, JAMES)
    sub = "temp@rationalboxes.com"
    r.grant(sub, SYSTEM_TENANTS, by=JAMES)
    r.revoke(sub, SYSTEM_TENANTS, by=JAMES)
    r.grant(sub, SYSTEM_TENANTS, by=JAMES, reason="came back")
    assert SYSTEM_TENANTS in r.roles_of(sub)
    assert len(r.history(sub)) == 3


def test_the_last_owner_cannot_be_revoked():
    r = AdministratorRegistry()
    bootstrap_owner(r, JAMES)
    with pytest.raises(RoleError, match="last system_owner"):
        r.revoke(JAMES, SYSTEM_OWNER, by=JAMES)
    # With a second owner it is allowed.
    r.grant("second@rationalboxes.com", SYSTEM_OWNER, by=JAMES)
    r.revoke(JAMES, SYSTEM_OWNER, by="second@rationalboxes.com")
    assert r.holders(SYSTEM_OWNER) == ["second@rationalboxes.com"]


def test_a_grant_needs_an_actor_and_a_real_role():
    with pytest.raises(RoleError):
        Grant(subject=JAMES, role=SYSTEM_OWNER, granted_by="")
    with pytest.raises(RoleError):
        Grant(subject=JAMES, role="system_invented", granted_by=PROVISIONING)


# ── bootstrap ──────────────────────────────────────────────────────────────


def test_bootstrap_makes_james_the_ultimate_administrator():
    r = AdministratorRegistry()
    made = bootstrap_owner(r, JAMES)
    assert r.roles_of(JAMES) == frozenset(ALL_ROLES), (
        "the first administrator holds every role, because owner implies none of them"
    )
    assert len(made) == len(ALL_ROLES)
    # Every one of them is an attributed entry, not a special case in the code.
    assert all(g.granted_by == PROVISIONING for g in made)
    assert all(g.at is not None for g in made)


def test_bootstrap_can_withhold_the_operational_roles():
    r = AdministratorRegistry()
    bootstrap_owner(r, JAMES, with_all_roles=False)
    assert r.roles_of(JAMES) == frozenset({SYSTEM_OWNER})


def test_bootstrap_is_idempotent_across_restarts():
    r = AdministratorRegistry()
    bootstrap_owner(r, JAMES)
    before = len(r.history())
    again = bootstrap_owner(r, JAMES)
    assert again == [], "a restart must not append a second identical grant"
    assert len(r.history()) == before


def test_bootstrap_refuses_to_add_a_second_owner():
    # Otherwise the configuration value is a back door needing only file access.
    r = AdministratorRegistry()
    bootstrap_owner(r, JAMES)
    with pytest.raises(RoleError, match="already"):
        bootstrap_owner(r, "someone.else@rationalboxes.com")
    assert r.holders(SYSTEM_OWNER) == [JAMES]


def test_provisioning_cannot_mint_a_second_owner_directly():
    r = AdministratorRegistry()
    bootstrap_owner(r, JAMES, with_all_roles=False)
    with pytest.raises(RoleError, match="owner already exists"):
        r.grant("other@rationalboxes.com", SYSTEM_OWNER, by=PROVISIONING)


def test_bootstrap_completes_a_partial_grant_set():
    # A crash between entries must not leave the owner permanently short.
    r = AdministratorRegistry()
    bootstrap_owner(r, JAMES, with_all_roles=False)
    made = bootstrap_owner(r, JAMES, with_all_roles=True)
    assert {g.role for g in made} == set(GRANTABLE_ROLES)
    assert r.roles_of(JAMES) == frozenset(ALL_ROLES)


def test_summarise_lists_current_holders_only():
    r = AdministratorRegistry()
    bootstrap_owner(r, JAMES, with_all_roles=False)
    r.grant("gone@rationalboxes.com", SYSTEM_OBSERVER, by=JAMES)
    r.revoke("gone@rationalboxes.com", SYSTEM_OBSERVER, by=JAMES)
    assert summarise(r) == [(JAMES, [SYSTEM_OWNER])]
