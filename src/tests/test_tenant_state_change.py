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
"""Suspend and resume — §3.4b's first phase, the reversible one.

Only `live` admits a user; the doors read the state from the core's registry, the
same row this console writes. Suspend is `live -> suspended`, resume the reverse,
and NOTHING else moves through this operation: provisioning has its own claimed,
gated path, and decommissioning is destructive and not built here.

Discipline (§3.4b): `system_tenants` only; a reason always, because the row's
state_note is what an operator reads afterwards; and suspension asks for the
tenant id TYPED, because the realistic failure is the right operation on the
wrong tenant. Resume needs no typed id — undoing a lock-out should not be hard.
"""
from __future__ import annotations

from admin_master_control.registry import (
    LIVE, REQUESTED, SUSPENDED, DECOMMISSIONED, StaticTenantRegistry, Tenant,
)

from .test_registry import TEN, _client, _hdr


def _reg(*rows):
    return StaticTenantRegistry().seed(*rows)


def _t(tid="acme", state=LIVE):
    return Tenant(tenant_id=tid, schema_name=f"tenant_{tid}", state=state)


# ── the registry ────────────────────────────────────────────────────────────


def test_live_to_suspended_records_who_when_and_why():
    r = _reg(_t())
    t = r.set_state("acme", SUSPENDED, by="ten@x", note="unpaid invoice")
    assert t.state == SUSPENDED and not t.admits_logins
    assert t.state_by == "ten@x" and t.state_note == "unpaid invoice" and t.state_since


def test_suspended_to_live_resumes():
    r = _reg(_t(state=SUSPENDED))
    assert r.set_state("acme", LIVE, by="ten@x", note="paid").admits_logins


def test_no_other_transition_moves_through_this_operation():
    for start, to in ((REQUESTED, SUSPENDED), (SUSPENDED, SUSPENDED), (LIVE, LIVE),
                      (LIVE, DECOMMISSIONED), (DECOMMISSIONED, LIVE)):
        r = _reg(_t(state=start))
        assert r.set_state("acme", to, by="ten@x", note="n") is None, (start, to)
        assert r.get("acme").state == start


# ── the API ─────────────────────────────────────────────────────────────────


def _post(c, h, tid="acme", **body):
    return c.post(f"/v1/tenants/{tid}/state", headers=h, json=body)


def test_suspend_with_reason_and_the_id_typed():
    c, reg = _client(_reg(_t()))
    r = _post(c, _hdr(c), state=SUSPENDED, reason="unpaid invoice", confirm="acme")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["state"] == SUSPENDED and body["admits_logins"] is False
    assert body["state_by"] == TEN and body["state_note"] == "unpaid invoice"
    assert reg.get("acme").state == SUSPENDED


def test_suspend_refuses_without_the_id_typed_or_with_the_wrong_one():
    c, reg = _client(_reg(_t(), _t("other")))
    h = _hdr(c)
    for confirm in (None, "", "other", "ACME "):
        body = {"state": SUSPENDED, "reason": "x"}
        if confirm is not None:
            body["confirm"] = confirm
        r = _post(c, h, **body)
        assert r.status_code == 400, (confirm, r.text)
    assert reg.get("acme").state == LIVE


def test_a_reason_is_always_required():
    c, reg = _client(_reg(_t(), _t("b", state=SUSPENDED)))
    h = _hdr(c)
    assert _post(c, h, state=SUSPENDED, reason="   ", confirm="acme").status_code in (400, 422)
    assert _post(c, h, "b", state=LIVE).status_code in (400, 422)
    assert reg.get("acme").state == LIVE and reg.get("b").state == SUSPENDED


def test_resume_needs_a_reason_but_no_typed_id():
    c, reg = _client(_reg(_t(state=SUSPENDED)))
    r = _post(c, _hdr(c), state=LIVE, reason="invoice paid")
    assert r.status_code == 200, r.text
    assert reg.get("acme").state == LIVE


def test_an_observer_cannot_change_state():
    c, reg = _client(_reg(_t()))
    r = _post(c, _hdr(c, "obs@x"), state=SUSPENDED, reason="x", confirm="acme")
    assert r.status_code == 403
    assert reg.get("acme").state == LIVE


def test_a_transition_the_lifecycle_does_not_allow_is_409():
    c, reg = _client(_reg(_t(state=REQUESTED)))
    r = _post(c, _hdr(c), state=SUSPENDED, reason="x", confirm="acme")
    assert r.status_code == 409, r.text
    assert reg.get("acme").state == REQUESTED


def test_only_live_and_suspended_can_be_asked_for():
    c, reg = _client(_reg(_t()))
    r = _post(c, _hdr(c), state=DECOMMISSIONED, reason="x", confirm="acme")
    assert r.status_code in (400, 422)
    assert reg.get("acme").state == LIVE


def test_an_unknown_tenant_is_404():
    c, _ = _client(_reg(_t()))
    r = _post(c, _hdr(c), "ghost", state=SUSPENDED, reason="x", confirm="ghost")
    assert r.status_code == 404
