# Copyright (C) 2026 James Hickman <james@rationalboxes.com>
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
"""Administrators are SHOWN by email and RECORDED by canonical uid.

Production 2026-10-01: the owner is uid=james, mail=james@rationalboxes.com. The
list identified them as "james". And the grant form, which invites an address,
wrote whatever was typed into the ledger — so a grant to the owner's address
would have recorded authority for a second, phantom identity that no login
resolves to.
"""
from __future__ import annotations

from fastapi.testclient import TestClient

from . import _harness
from admin_master_control.administrators import AdministratorRegistry, bootstrap_owner
from admin_master_control.app import build_app
from admin_master_control.auth import StaticDeploymentDirectory
from admin_master_control.config import Config
from admin_master_control.roles import ALL_ROLES, SYSTEM_BILLING

OWNER, OWNER_MAIL = "james", "james@rationalboxes.com"
ALICE, ALICE_MAIL = "alice", "alice@rationalboxes.com"


def _cfg() -> Config:
    c = Config()
    c.jwt_secret = "x" * 48
    c.bootstrap_owner = ""
    return c


def _client():
    d = StaticDeploymentDirectory(
        passwords={OWNER: "pw", ALICE: "pw"},
        grants={OWNER: set(ALL_ROLES)},
        emails={OWNER_MAIL: OWNER, ALICE_MAIL: ALICE},
    )
    reg = AdministratorRegistry()
    bootstrap_owner(reg, OWNER)
    c = TestClient(build_app(_cfg(), reg, d, None, None, None, _harness.factors(OWNER)))
    return c, reg, d


def test_the_list_identifies_administrators_by_email():
    c, _, _ = _client()
    h = _harness.headers(c, OWNER_MAIL)
    r = c.get("/v1/administrators", headers=h)
    assert r.status_code == 200, r.text
    (row,) = r.json()["administrators"]
    assert row["subject"] == OWNER
    assert row["email"] == OWNER_MAIL


def test_a_grant_by_email_is_recorded_against_the_canonical_uid():
    c, reg, d = _client()
    h = _harness.headers(c, OWNER_MAIL)
    r = c.post("/v1/grants", headers=h,
               json={"subject": ALICE_MAIL, "role": SYSTEM_BILLING, "reason": "billing"})
    assert r.status_code == 201, r.text
    assert SYSTEM_BILLING in reg.roles_of(ALICE)
    assert ALICE_MAIL not in reg.subjects()


def test_a_grant_to_an_address_with_no_account_is_refused_not_recorded():
    c, reg, _ = _client()
    h = _harness.headers(c, OWNER_MAIL)
    r = c.post("/v1/grants", headers=h,
               json={"subject": "nobody@rationalboxes.com", "role": SYSTEM_BILLING,
                     "reason": "x"})
    assert r.status_code in (404, 422), r.text
    assert "nobody@rationalboxes.com" not in reg.subjects()
