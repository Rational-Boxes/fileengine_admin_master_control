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

"""Redaction items and the register (§3.3.1, §3.3.2).

WHERE THE LINE IS, because it is not where people assume. The concern is
potential PII in CONTENT, never the identity of the principals who acted — so
uids, roles, actions and timestamps are kept, and the file is named by UUID.

A FILENAME IS CONTENT. That is the part most likely to be got wrong, because a
name looks like metadata and reads like a label while
`invoice_for_Jane_Doe.pdf` carries exactly what the redaction was for. The
heaviest tests here are the ones that prove there is no path by which a redacted
name comes back.
"""
from __future__ import annotations

import datetime as _dt

import pytest
from fastapi.testclient import TestClient

from admin_master_control.administrators import AdministratorRegistry, bootstrap_owner
from admin_master_control.app import build_app
from admin_master_control.auth import StaticDeploymentDirectory
from admin_master_control.config import Config
from admin_master_control.incidents import StaticQueue
from admin_master_control.redactions import (
    NAME_REDACTED,
    OFFSITE_EXPECTED,
    RedactionError,
    RedactionItem,
    StaticErasures,
    register,
)
from admin_master_control.roles import SYSTEM_OBSERVER, SYSTEM_SECURITY

SEC = "sec@rationalboxes.com"
OBS = "obs@rationalboxes.com"
UID = "3cbdbc15-60a6-4d6f-b6c4-062f85279242"


def _item(**over) -> RedactionItem:
    kw = dict(erasure_id="er-1", file_uid=UID, tenant="acme",
              initiated_at="2026-09-20T10:00:00+00:00",
              actor="james@rationalboxes.com", reason="customer request",
              tenant_contact="ops@acme.example")
    kw.update(over)
    return RedactionItem(**kw)


# ── a redacted name has no second copy, and this must not become one ───────


def test_an_item_whose_name_was_redacted_shows_its_absence():
    item = _item(name_retained=False)
    assert item.display_name == NAME_REDACTED
    assert "file_name" not in item.for_display()


def test_supplying_a_name_for_a_redacted_item_raises_rather_than_being_ignored():
    # THE ASSERTION THAT MATTERS MOST. Silently dropping the argument would let
    # the caller believe the name had been stored and the next reader believe its
    # absence meant something else. §3.3.1: a reporting surface that quietly made
    # redacted names visible again to the tier with the most reach would be the
    # worst possible place for that leak.
    with pytest.raises(RedactionError, match="no second copy"):
        _item(name_retained=False, file_name="Acme_Corp_Contract_J_Smith.pdf")


def test_a_retained_name_is_shown_because_it_survived():
    # The other half: where the name was NOT redacted, hiding it would make the
    # administrator's conversation with the customer harder for no benefit.
    item = _item(name_retained=True, file_name="public_price_list.pdf")
    assert item.display_name == "public_price_list.pdf"
    assert item.for_display()["file_name"] == "public_price_list.pdf"


def test_the_display_payload_omits_the_name_rather_than_nulling_it():
    # A null invites a client to fill it in from somewhere, and there is nowhere.
    d = _item(name_retained=False).for_display()
    assert "file_name" not in d
    assert d["display_name"] == NAME_REDACTED


def test_no_field_anywhere_carries_a_path_or_content():
    d = _item(name_retained=False).for_display()
    assert set(d) == {
        "erasure_id", "file_uid", "tenant", "tenant_contact", "initiated_at",
        "actor", "reason", "name_retained", "display_name", "offsite",
        "activity_query",
    }, "a new field here needs deciding whether it is content"


# ── what IS kept, because "who" was never the concern ─────────────────────


def test_the_principal_who_acted_is_kept():
    # An erasure with no attributable actor is unauditable. Redaction destroys
    # content, not accountability.
    item = _item(name_retained=False)
    assert item.actor == "james@rationalboxes.com"
    assert item.for_display()["actor"] == "james@rationalboxes.com"


def test_the_uuid_survives_and_points_at_the_history():
    # The identifier is what remains, and it is what ties the item to the file's
    # historical activity record — readable without ever knowing the name.
    d = _item(name_retained=False).for_display()
    assert d["file_uid"] == UID
    assert d["activity_query"] == {"target_uid": UID, "tenant": "acme"}


def test_the_reason_and_timestamp_are_kept_for_the_conversation():
    # §3.3.1: with the name gone, "the conversation with the customer proceeds
    # from the erasure's reason and timestamp instead".
    d = _item(name_retained=False).for_display()
    assert d["reason"] == "customer request"
    assert d["initiated_at"] == "2026-09-20T10:00:00+00:00"
    assert d["tenant_contact"] == "ops@acme.example"


def test_an_item_needs_its_uid():
    with pytest.raises(RedactionError, match="file_uid"):
        _item(file_uid="")


def test_the_offsite_state_is_only_ever_a_claim():
    # §3.3.1: "the queue can only say 'expected'" — the redaction tool's
    # verification step is what actually answers it, on cloud B.
    assert _item().offsite == OFFSITE_EXPECTED
    with pytest.raises(RedactionError):
        _item(offsite="definitely_gone")


# ── the register (§3.3.2) ──────────────────────────────────────────────────


def _now():
    return _dt.datetime(2026, 9, 30, 10, 0, tzinfo=_dt.timezone.utc)


def test_outstanding_items_are_ordered_oldest_first():
    src = StaticErasures([
        _item(erasure_id="new", initiated_at="2026-09-30T09:00:00+00:00"),
        _item(erasure_id="old", initiated_at="2026-09-01T09:00:00+00:00"),
    ])
    out = register(src, {}, now=_now())["outstanding"]
    assert [r["erasure_id"] for r in out] == ["old", "new"]
    assert out[0]["age_hours"] > out[1]["age_hours"]


def test_the_oldest_outstanding_age_is_reported():
    # §3.3.2 calls outstanding-by-age "the number that matters".
    src = StaticErasures([_item(initiated_at="2026-09-29T10:00:00+00:00")])
    counts = register(src, {}, now=_now())["counts"]
    assert counts["oldest_outstanding_hours"] == pytest.approx(24.0, abs=0.1)


def test_approved_but_never_completed_is_its_own_bucket():
    # THE HONEST BUCKET. §3.3.2 asks for "the ones where the loop was never
    # closed" — the items an organisation would most like to forget and exactly
    # the ones it must be able to produce. Folding them into "outstanding" would
    # make them look like nobody had got to them yet.
    src = StaticErasures([_item(erasure_id="er-1")])
    reg = register(src, {"er-1": {"state": "approved"}}, now=_now())
    assert reg["counts"]["approved_not_completed"] == 1
    assert reg["counts"]["outstanding"] == 0
    assert reg["approved_not_completed"][0]["erasure_id"] == "er-1"


def test_a_completed_item_without_a_receipt_is_counted_separately():
    # Performed as far as anyone can tell, and not evidenced. §3.3.2 wants the
    # loop honestly presented, not made to look closed.
    src = StaticErasures([_item(erasure_id="a"), _item(erasure_id="b")])
    reg = register(src, {"a": {"state": "completed", "evidence": "run-01"},
                         "b": {"state": "completed"}}, now=_now())
    assert reg["counts"]["completed"] == 2
    assert reg["counts"]["completed_without_evidence"] == 1
    by_id = {r["erasure_id"]: r for r in reg["completed"]}
    assert by_id["a"]["evidenced"] is True and by_id["a"]["evidence"] == "run-01"
    assert by_id["b"]["evidenced"] is False


def test_a_declined_item_is_finished_but_records_why():
    src = StaticErasures([_item(erasure_id="er-1")])
    reg = register(src, {"er-1": {"state": "declined", "reason": "not our data"}},
                   now=_now())
    assert reg["counts"]["outstanding"] == 0
    assert reg["completed"][0]["reason_declined"] == "not our data"


def test_an_item_with_no_queue_entry_is_outstanding():
    src = StaticErasures([_item()])
    assert register(src, {}, now=_now())["counts"]["outstanding"] == 1


def test_the_register_never_shows_a_redacted_name():
    # End to end, through the register rather than the item.
    src = StaticErasures([_item(name_retained=False)])
    reg = register(src, {}, now=_now())
    blob = repr(reg)
    assert NAME_REDACTED in blob
    assert ".pdf" not in blob and ".docx" not in blob


# ── through the API ────────────────────────────────────────────────────────


def _client(items=None):
    d = StaticDeploymentDirectory()
    for who, roles in ((SEC, {SYSTEM_SECURITY}), (OBS, {SYSTEM_OBSERVER})):
        d.passwords[who] = "pw"
        d.grants[who] = roles
    reg = AdministratorRegistry()
    bootstrap_owner(reg, "james@rationalboxes.com")
    c = Config()
    c.jwt_secret = "deployment-tier-secret"
    c.token_audience = "fileengine-system-admin"
    c.require_mfa = True
    c.monitor_host = "127.0.0.1"
    c.audit_url = "http://audit:8097"
    c.bootstrap_owner = ""
    return TestClient(build_app(c, reg, d, StaticQueue([]),
                                StaticErasures(items or [])))


def _hdr(client, who=SEC):
    r = client.post("/v1/auth/token",
                    json={"subject": who, "password": "pw", "second_factor": "totp"})
    return {"Authorization": f"Bearer {r.json()['token']}"}


def test_the_register_route_returns_the_buckets():
    client = _client([_item()])
    body = client.get("/v1/redactions", headers=_hdr(client)).json()
    assert body["counts"]["outstanding"] == 1
    assert body["outstanding"][0]["file_uid"] == UID
    assert body["outstanding"][0]["display_name"] == NAME_REDACTED


def test_the_register_needs_system_security():
    client = _client([_item()])
    assert client.get("/v1/redactions", headers=_hdr(client, OBS)).status_code == 403


def test_the_register_needs_a_token():
    assert _client([_item()]).get("/v1/redactions").status_code == 401


def test_an_empty_register_is_empty_not_broken():
    # No live erasure source exists yet, so the default is an EMPTY source. An
    # empty register is honest — there are no items it can see — where a 503
    # would say the feature is broken.
    client = _client([])
    r = client.get("/v1/redactions", headers=_hdr(client))
    assert r.status_code == 200 and r.json()["counts"]["outstanding"] == 0
