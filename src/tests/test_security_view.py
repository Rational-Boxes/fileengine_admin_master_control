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

"""The cross-tenant security view (§3.4).

Two capabilities, and the tests are weighted accordingly: aggregation is
straightforward and gets the ordering and counting assertions, while
cross-tenant detection gets the one that matters — that the campaign visible
here produced no incident in any tenant, which is the whole reason this tier
exists.

The failure mode guarded hardest is an EMPTY view. "No incidents" and "I could
not ask" look identical on a screen and mean opposite things, and an empty
security page is the most reassuring thing a console can show.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from . import _harness
from admin_master_control.administrators import AdministratorRegistry, bootstrap_owner
from admin_master_control.app import build_app
from admin_master_control.auth import StaticDeploymentDirectory
from admin_master_control.config import Config
from admin_master_control.incidents import (
    SEVERITY_RANK,
    LedgerUnavailable,
    StaticIncidents,
    aggregated,
    campaigns,
    from_config,
)
from admin_master_control.roles import (
    SYSTEM_OBSERVER,
    SYSTEM_OWNER,
    SYSTEM_SECURITY,
)

SEC = "sec@rationalboxes.com"
OBS = "obs@rationalboxes.com"


def _row(**over):
    r = {"id": 1, "ts": "2026-09-29T12:00:00+00:00", "tenant": "acme",
         "rule_id": "auth_fail", "group_by": "source_addr", "group_key": "203.0.113.7",
         "actor": None, "severity": "warn", "response": "flag", "match_count": 5,
         "window_s": 300, "action_taken": "flagged", "dry_run": False,
         "description": "auth failures", "status": "open",
         "scope": "tenant", "audience": "tenant", "distinct_values": []}
    r.update(over)
    return r


def _cfg(**over) -> Config:
    c = Config()
    c.jwt_secret = "deployment-tier-secret"
    c.token_audience = "fileengine-system-admin"
    c.require_mfa = True
    c.monitor_host = "127.0.0.1"
    c.audit_url = "http://audit:8097"
    # A second factor is required (the default), so it must also be CHECKABLE.
    # Readiness reports "required but no store configured" otherwise, which is the
    # point: enforcement that cannot reach its source refuses every login.
    c.mfa_url = "http://ldap-manager:8093"
    c.mfa_internal_secret = "internal-shared-secret"
    c.bootstrap_owner = ""
    for k, v in over.items():
        setattr(c, k, v)
    return c


def _client(rows=None, source=None):
    d = StaticDeploymentDirectory()
    d.passwords[SEC] = "pw"
    d.grants[SEC] = {SYSTEM_SECURITY}
    d.passwords[OBS] = "pw"
    d.grants[OBS] = {SYSTEM_OBSERVER}
    reg = AdministratorRegistry()
    bootstrap_owner(reg, "james@rationalboxes.com")
    src = source if source is not None else StaticIncidents(rows or [])
    return TestClient(build_app(_cfg(), reg, d, src, None, None,
                                _harness.factors(SEC, OBS)))


def _tok(client, who=SEC):
    return _harness.headers(client, who)


# ── the capability that exists nowhere else ────────────────────────────────


def test_a_campaign_no_tenant_could_have_seen():
    # The §3.4 case. A global incident: 40 events from one source across ten
    # tenants, four each — below every tenant's own threshold, so no tenant has
    # an incident and aggregation of tenant incidents finds nothing.
    tenants = [f"tenant{i}" for i in range(10)]
    rows = [_row(id=99, tenant=None, scope="global", audience="deployment",
                 severity="serious", rule_id="auth_fail_global", match_count=40,
                 distinct_values=tenants)]
    client = _client(rows)
    body = client.get("/v1/security/campaigns", headers=_tok(client)).json()
    assert len(body["campaigns"]) == 1
    c = body["campaigns"][0]
    assert c["fanout"] == 10
    assert c["touched_tenants"] == tenants
    assert body["widest_fanout"] == 10
    # The number alone does not carry the point; the view says why.
    assert "below each tenant's own threshold" in c["why_invisible_per_tenant"]


def test_campaigns_excludes_tenant_scoped_incidents():
    # A tenant's own brute-force lockout is not a campaign, and mixing it in
    # would bury the signal this view exists for.
    rows = [_row(scope="tenant", severity="critical"),
            _row(id=2, tenant=None, scope="global", audience="deployment",
                 severity="warn", distinct_values=["a", "b", "c"])]
    client = _client(rows)
    body = client.get("/v1/security/campaigns", headers=_tok(client)).json()
    assert [c["id"] for c in body["campaigns"]] == [2]


def test_a_campaign_belongs_to_no_tenant():
    rows = [_row(id=7, tenant=None, scope="global", audience="deployment",
                 distinct_values=["a", "b"])]
    client = _client(rows)
    body = client.get("/v1/security/campaigns", headers=_tok(client)).json()
    assert body["campaigns"][0]["tenant"] is None


# ── aggregation ────────────────────────────────────────────────────────────


def test_aggregation_spans_every_tenant():
    rows = [_row(id=1, tenant="acme"), _row(id=2, tenant="beta"), _row(id=3, tenant="gamma")]
    client = _client(rows)
    body = client.get("/v1/security/incidents", headers=_tok(client)).json()
    assert body["tenants_affected"] == ["acme", "beta", "gamma"]
    assert body["counts"]["total"] == 3


def test_aggregation_ranks_worst_first():
    # A page of a hundred ordered only by time can be entirely `info` while a
    # `critical` sits on page two — the shape of a console somebody stops
    # trusting.
    rows = [_row(id=1, severity="info"), _row(id=2, severity="critical"),
            _row(id=3, severity="warn"), _row(id=4, severity="serious")]
    client = _client(rows)
    body = client.get("/v1/security/incidents", headers=_tok(client)).json()
    assert [i["severity"] for i in body["incidents"]] == \
        ["critical", "serious", "warn", "info"]


def test_aggregation_counts_by_severity():
    rows = [_row(id=1, severity="critical"), _row(id=2, severity="critical"),
            _row(id=3, severity="info")]
    client = _client(rows)
    counts = client.get("/v1/security/incidents", headers=_tok(client)).json()["counts"]
    assert counts["critical"] == 2 and counts["info"] == 1 and counts["total"] == 3


def test_min_severity_filters():
    rows = [_row(id=1, severity="info"), _row(id=2, severity="serious")]
    client = _client(rows)
    body = client.get("/v1/security/incidents?min_severity=serious",
                      headers=_tok(client)).json()
    assert [i["id"] for i in body["incidents"]] == [2]


def test_a_bad_min_severity_is_a_client_error_not_a_crash():
    client = _client([_row()])
    r = client.get("/v1/security/incidents?min_severity=catastrophic",
                   headers=_tok(client))
    assert r.status_code == 400


def test_the_severity_order_matches_audit_services():
    # The two lists drifting apart would silently reorder this console. Pinned
    # against the values audit_service ranks by.
    assert SEVERITY_RANK == {"critical": 0, "serious": 1, "warn": 2, "info": 3}


# ── an empty view must never be a failed fetch ─────────────────────────────


def test_an_unreachable_ledger_is_503_not_an_empty_page():
    class Down:
        def fetch(self, **_f):
            raise LedgerUnavailable("connection refused")

    client = _client(source=Down())
    r = client.get("/v1/security/incidents", headers=_tok(client))
    assert r.status_code == 503
    assert r.json()["detail"] == "audit ledger unavailable"


def test_an_unreachable_ledger_also_fails_the_campaign_view():
    class Down:
        def fetch(self, **_f):
            raise LedgerUnavailable("connection refused")

    client = _client(source=Down())
    assert client.get("/v1/security/campaigns", headers=_tok(client)).status_code == 503


def test_a_genuinely_quiet_platform_is_200_and_empty():
    # The other side of the same coin: nothing wrong must look different from
    # nothing asked.
    client = _client([])
    r = client.get("/v1/security/incidents", headers=_tok(client))
    assert r.status_code == 200
    assert r.json()["incidents"] == [] and r.json()["counts"]["total"] == 0


def test_an_unconfigured_ledger_refuses_rather_than_showing_nothing():
    class Cfg:
        audit_url = ""
        audit_token = ""

    src = from_config(Cfg())
    with pytest.raises(LedgerUnavailable):
        src.fetch()


# ── who may look ───────────────────────────────────────────────────────────


def test_the_security_view_needs_system_security_not_the_observer_baseline():
    # §6.1 gives system_security "incidents, cross-tenant detection" as its own
    # area. An incident naming a source address and the tenants it touched is
    # more than a read-only baseline should see.
    client = _client([_row()])
    hdr = _tok(client, OBS)
    assert client.get("/v1/security/incidents", headers=hdr).status_code == 403
    assert client.get("/v1/security/campaigns", headers=hdr).status_code == 403


def test_an_observer_can_still_read_the_observer_routes():
    client = _client([_row()])
    assert client.get("/v1/whoami", headers=_tok(client, OBS)).status_code == 200


def test_the_security_view_needs_a_token_at_all():
    client = _client([_row()])
    assert client.get("/v1/security/incidents").status_code == 401


# ── the source's own filtering ─────────────────────────────────────────────


def test_the_static_source_honours_the_filters_it_is_given():
    # Used by every test above, so its own filtering has to be right or the
    # assertions are measuring the double rather than the view.
    src = StaticIncidents([_row(id=1, scope="tenant", severity="info"),
                           _row(id=2, scope="global", severity="critical")])
    assert [r["id"] for r in src.fetch(scope="global")] == [2]
    assert [r["id"] for r in src.fetch(min_severity="serious")] == [2]
    assert len(src.fetch(limit=1)) == 1


def test_aggregated_and_campaigns_are_callable_without_http():
    src = StaticIncidents([_row(id=1, scope="global", tenant=None,
                                distinct_values=["a", "b"])])
    assert aggregated(src)["counts"]["total"] == 1
    assert campaigns(src)["widest_fanout"] == 2
