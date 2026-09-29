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

"""The console's half of the acknowledgement procedure (§3.2 / §3.3 / §4).

The tests weighted heaviest are the ones that would let the procedure quietly
become a list: that the actor comes from the token and not the body, that the
order is enforced end to end, that a refusal is 409 rather than an outage, and
that approving records a decision without executing anything.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from admin_master_control.administrators import AdministratorRegistry, bootstrap_owner
from admin_master_control.app import build_app
from admin_master_control.auth import StaticDeploymentDirectory
from admin_master_control.config import Config
from admin_master_control.incidents import LedgerUnavailable, StaticQueue
from admin_master_control.roles import SYSTEM_OBSERVER, SYSTEM_SECURITY

SEC = "sec@rationalboxes.com"
OBS = "obs@rationalboxes.com"


def _row(iid=1, **over):
    r = {"id": iid, "ts": "2026-09-29T12:00:00+00:00", "tenant": None,
         "rule_id": "auth_fanout", "group_by": "source_addr", "group_key": "203.0.113.7",
         "severity": "serious", "match_count": 30, "scope": "global",
         "audience": "deployment", "description": "one source probing many tenants",
         "status": "open", "distinct_values": ["a", "b", "c"]}
    r.update(over)
    return r


def _cfg() -> Config:
    c = Config()
    c.jwt_secret = "deployment-tier-secret"
    c.token_audience = "fileengine-system-admin"
    c.require_mfa = True
    c.monitor_host = "127.0.0.1"
    c.audit_url = "http://audit:8097"
    c.bootstrap_owner = ""
    return c


def _client(rows=None, source=None):
    d = StaticDeploymentDirectory()
    for who, roles in ((SEC, {SYSTEM_SECURITY}), (OBS, {SYSTEM_OBSERVER})):
        d.passwords[who] = "pw"
        d.grants[who] = roles
    reg = AdministratorRegistry()
    bootstrap_owner(reg, "james@rationalboxes.com")
    src = source if source is not None else StaticQueue(rows if rows is not None else [_row()])
    return TestClient(build_app(_cfg(), reg, d, src)), src


def _hdr(client, who=SEC):
    r = client.post("/v1/auth/token",
                    json={"subject": who, "password": "pw", "second_factor": "totp"})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['token']}"}


def _move(client, hdr, iid, state, **body):
    return client.post("/v1/security/queue/transition",
                       json={"incident_id": iid, "state": state, **body}, headers=hdr)


# ── the actor is not self-reported ─────────────────────────────────────────


def test_the_actor_comes_from_the_token_not_the_body():
    # THE ASSERTION THAT MATTERS MOST. This is the table that exists to answer
    # "who approved this"; an actor taken from the body records who the caller
    # said they were.
    client, src = _client()
    hdr = _hdr(client)
    r = _move(client, hdr, 1, "acknowledged", actor="somebody.else@example.com")
    assert r.status_code == 201
    assert r.json()["actor"] == SEC
    assert src.transitions[1][-1]["actor"] == SEC


def test_the_authorising_role_is_recorded():
    # §6.1: every action records WHICH role authorised it.
    client, _ = _client()
    r = _move(client, _hdr(client), 1, "acknowledged")
    assert r.json()["authorised_as"] == SYSTEM_SECURITY


# ── the order is enforced end to end ───────────────────────────────────────


def test_an_item_cannot_be_approved_without_being_acknowledged():
    client, _ = _client()
    r = _move(client, _hdr(client), 1, "approved")
    assert r.status_code == 409
    assert "raised -> approved" in r.json()["detail"]


def test_a_redaction_cannot_be_approved_before_the_customer_is_confirmed():
    # §3.3, the motivating case: confirm with the customer, and only then approve.
    client, _ = _client()
    hdr = _hdr(client)
    assert _move(client, hdr, 1, "acknowledged").status_code == 201
    r = _move(client, hdr, 1, "approved")
    assert r.status_code == 409


def test_the_full_procedure_runs_through():
    client, src = _client()
    hdr = _hdr(client)
    assert _move(client, hdr, 1, "acknowledged").status_code == 201
    assert _move(client, hdr, 1, "customer_confirmed",
                 counterparty="Ops at Acme").status_code == 201
    assert _move(client, hdr, 1, "approved", reason="confirmed by phone").status_code == 201
    assert _move(client, hdr, 1, "completed",
                 evidence="redaction-run-01").status_code == 201
    hist = client.get("/v1/security/queue/1", headers=hdr).json()
    assert [h["state"] for h in hist["history"]] == \
        ["acknowledged", "customer_confirmed", "approved", "completed"]
    assert hist["state"] == "completed"


def test_a_refusal_is_a_conflict_not_an_outage():
    # "You cannot do that yet" is a correct answer. Presenting it as 503 teaches
    # an administrator to retry rather than to read it.
    client, _ = _client()
    r = _move(client, _hdr(client), 1, "completed")
    assert r.status_code == 409


def test_a_customer_confirmation_needs_a_named_counterparty():
    # §4: it records an ASSERTION, and an assertion with nobody named is a
    # checkbox.
    client, _ = _client()
    hdr = _hdr(client)
    _move(client, hdr, 1, "acknowledged")
    assert _move(client, hdr, 1, "customer_confirmed").status_code == 409


def test_a_decline_needs_a_reason():
    client, _ = _client()
    hdr = _hdr(client)
    _move(client, hdr, 1, "acknowledged")
    assert _move(client, hdr, 1, "declined").status_code == 409
    assert _move(client, hdr, 1, "declined", reason="corporate NAT egress").status_code == 201


def test_a_refusal_is_recorded_not_left_as_silence():
    # erasure_ack's property: complied=false is a row. A declined item must be
    # distinguishable from one nobody looked at.
    client, src = _client()
    hdr = _hdr(client)
    _move(client, hdr, 1, "acknowledged")
    _move(client, hdr, 1, "declined", reason="uptime probe")
    hist = client.get("/v1/security/queue/1", headers=hdr).json()
    assert hist["state"] == "declined"
    assert hist["history"][-1]["reason"] == "uptime probe"


# ── the backlog is the number that matters ─────────────────────────────────


def test_the_backlog_counts_what_nobody_has_looked_at():
    client, _ = _client([_row(1), _row(2), _row(3)])
    b = client.get("/v1/security/backlog", headers=_hdr(client)).json()
    assert b["unacknowledged"] == 3 and b["needs_a_human"] == 3


def test_acknowledging_reduces_the_unacknowledged_count():
    client, _ = _client([_row(1), _row(2)])
    hdr = _hdr(client)
    _move(client, hdr, 1, "acknowledged")
    b = client.get("/v1/security/backlog", headers=hdr).json()
    assert b["unacknowledged"] == 1
    # Still needs a human — acknowledged is not done.
    assert b["needs_a_human"] == 2


def test_an_approved_item_still_needs_a_human():
    # It has to be carried out elsewhere. Counting it as finished would hide the
    # items waiting on the cloud-B redaction step.
    client, _ = _client()
    hdr = _hdr(client)
    for state, extra in (("acknowledged", {}), ("customer_confirmed", {"counterparty": "Ops"}),
                         ("approved", {})):
        assert _move(client, hdr, 1, state, **extra).status_code == 201
    assert client.get("/v1/security/backlog", headers=hdr).json()["needs_a_human"] == 1


def test_a_declined_item_stops_needing_anyone():
    client, _ = _client()
    hdr = _hdr(client)
    _move(client, hdr, 1, "acknowledged")
    _move(client, hdr, 1, "declined", reason="NAT")
    assert client.get("/v1/security/backlog", headers=hdr).json()["needs_a_human"] == 0


# ── the queue listing ──────────────────────────────────────────────────────


def test_items_carry_the_legal_next_moves():
    # So a console does not hard-code the procedure and drift from it.
    client, _ = _client()
    hdr = _hdr(client)
    item = client.get("/v1/security/queue", headers=hdr).json()["items"][0]
    assert item["next_states"] == ["acknowledged"]
    _move(client, hdr, 1, "acknowledged")
    item = client.get("/v1/security/queue", headers=hdr).json()["items"][0]
    assert set(item["next_states"]) == {"customer_confirmed", "declined"}


def test_the_queue_can_be_filtered_by_state():
    client, _ = _client([_row(1), _row(2)])
    hdr = _hdr(client)
    _move(client, hdr, 2, "acknowledged")
    raised = client.get("/v1/security/queue?state=raised", headers=hdr).json()["items"]
    assert [i["id"] for i in raised] == [1]


# ── who may act ────────────────────────────────────────────────────────────


def test_an_observer_cannot_move_the_queue():
    # §6.1 gives acknowledgement to system_security. A read-only baseline that
    # could approve a redaction would make the separation decorative.
    client, _ = _client()
    hdr = _hdr(client, OBS)
    assert _move(client, hdr, 1, "acknowledged").status_code == 403
    assert client.get("/v1/security/queue", headers=hdr).status_code == 403
    assert client.get("/v1/security/backlog", headers=hdr).status_code == 403


def test_no_token_cannot_move_the_queue():
    client, _ = _client()
    assert client.post("/v1/security/queue/transition",
                       json={"incident_id": 1, "state": "acknowledged"}).status_code == 401


# ── the ledger being down is not a refusal ─────────────────────────────────


def test_an_unreachable_ledger_is_503_on_the_queue():
    class Down:
        def fetch(self, **_f):
            raise LedgerUnavailable("down")

        def queue(self, **_f):
            raise LedgerUnavailable("down")

        def backlog(self, **_f):
            raise LedgerUnavailable("down")

        def item_history(self, _i):
            raise LedgerUnavailable("down")

        def transition(self, **_b):
            raise LedgerUnavailable("down")

    client, _ = _client(source=Down())
    hdr = _hdr(client)
    assert client.get("/v1/security/queue", headers=hdr).status_code == 503
    assert client.get("/v1/security/backlog", headers=hdr).status_code == 503
    assert _move(client, hdr, 1, "acknowledged").status_code == 503


def test_the_double_matches_audit_services_transition_table():
    # The double duplicates the state graph instead of importing it, so that a
    # widening in audit_service cannot silently make these tests pass. This is
    # the pin that makes the duplication safe.
    #
    # SKIPS rather than fails when the sibling repo is not importable: this
    # suite must not require a checkout next door to run. The skip is the one
    # place a cross-repo assumption is allowed to be absent, and it is visible
    # in the output rather than silent.
    TRANSITIONS = pytest.importorskip(
        "audit_service.queue",
        reason="audit_service not on the path; run with "
               "PYTHONPATH=../audit_service/src to pin the state graph").TRANSITIONS

    assert {k: tuple(v) for k, v in StaticQueue.MOVES.items()} == \
        {k: tuple(v) for k, v in TRANSITIONS.items()}
