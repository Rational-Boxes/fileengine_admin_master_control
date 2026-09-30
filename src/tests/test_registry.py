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

"""The tenant registry — the ONE tenants table — and the gate that lives in it.

This replaces test_tenant_store.py. That file tested a second tenant table in this
application's own database; the table is gone, because `public.tenants` in the core
already modelled the same lifecycle and the core is a mandatory dependency. The
failure it avoided was silent: the doors admit or refuse on the registry's state, so
a console reading its own copy would have shown `live` for a suspended tenant.

Two properties carry the weight here:

  * `test_the_list_shows_tenants_this_console_never_created` — the one that would
    have caught the empty page. Most tenants predate this console and have no
    request of ours, so a list built from our own rows outward shows nothing on a
    deployment with seventy live tenants.

  * `test_two_simultaneous_claims_queue_one_run` — the gate. Failed certificate
    issuance consumes a rate limit shared by EVERY tenant on the domain, so the
    claim has to be one statement rather than a read followed by a write.

Live Postgres tests are marked and skip without AMC_TEST_CORE_PG_DSN.
"""
from __future__ import annotations

import os

import pytest

from admin_master_control import registry as reg
from admin_master_control.registry import (
    AWAITING_DNS,
    CLAIMABLE,
    LIVE,
    PROVISIONING,
    REQUESTED,
    SUSPENDED,
    PostgresTenantRegistry,
    RegistryRefused,
    RegistryUnavailable,
    StaticTenantRegistry,
    Tenant,
    schema_name_for,
)

TEN = "ten@rationalboxes.com"
BASE = "rationalboxes.com"
ADDR = "203.0.113.10"


def _requested(r: StaticTenantRegistry, tid="acme") -> Tenant:
    return r.request(tenant_id=tid, base_domain=BASE, address=ADDR,
                     initial_admin="admin@acme.test", requested_by=TEN)


def _passing_dns() -> dict:
    return {"ok": True, "authoritative": True, "blocking_reason": "", "checks": []}


def _failing_dns() -> dict:
    return {"ok": False, "authoritative": True,
            "blocking_reason": "DNS not ready for: acme-drive.rationalboxes.com (no record)",
            "checks": []}


# ── there is only one tenants table ────────────────────────────────────────


def test_the_list_shows_tenants_this_console_never_created():
    """THE test for the bug that started this.

    The console listed its OWN request rows, so a deployment with seventy live
    tenants showed an empty page — they predate the console and have no request of
    ours. That is the normal case, not a gap, which is why the list is built from the
    registry outward.
    """
    r = StaticTenantRegistry().seed(
        Tenant(tenant_id="default", schema_name="tenant_default", state=LIVE),
        Tenant(tenant_id="someco", schema_name="tenant_someco", state=LIVE),
    )
    ids = [t.tenant_id for t in r.list()]
    assert ids == ["default", "someco"]
    # And none of them claims to have been requested here.
    assert all(not t.for_display()["requested_here"] for t in r.list())


def test_a_tenant_requested_here_is_marked_as_such():
    r = StaticTenantRegistry()
    _requested(r)
    assert r.get("acme").for_display()["requested_here"] is True


def test_the_state_comes_from_the_registry_not_a_local_copy():
    # A suspended tenant must READ as suspended. With a private table this is where
    # the console and the doors would disagree, and the console would look healthy.
    r = StaticTenantRegistry().seed(
        Tenant(tenant_id="acme", schema_name="tenant_acme", state=SUSPENDED))
    t = r.get("acme")
    assert t.state == SUSPENDED
    assert not t.admits_logins
    assert not t.may_provision


def test_only_live_admits_logins():
    for state in (REQUESTED, AWAITING_DNS, PROVISIONING, SUSPENDED,
                  "decommissioning", "decommissioned"):
        assert not Tenant(tenant_id="a", schema_name="s", state=state).admits_logins
    assert Tenant(tenant_id="a", schema_name="s", state=LIVE).admits_logins


def test_the_admit_rule_matches_the_doors_policy_header():
    """Parse the C++ doors' header and compare.

    This console renders "reachable" from its own copy of the rule, and a second copy
    that nobody checks is how two copies drift — the console would then tell an
    operator a tenant was reachable when the doors refused it.
    """
    import pathlib
    import re

    header = (pathlib.Path(__file__).resolve().parents[3]
              / "http_bridge" / "include" / "tenant_state_policy.h")
    if not header.exists():
        pytest.skip("http_bridge not checked out beside this repo")
    text = header.read_text()
    cpp_states = set(re.findall(r'constexpr const char\* k\w+ = "([a-z_]+)";', text))
    assert cpp_states == set(reg.REGISTRY_STATES), (
        f"state vocabularies differ: C++ has {sorted(cpp_states - set(reg.REGISTRY_STATES))} "
        f"extra, this console has {sorted(set(reg.REGISTRY_STATES) - cpp_states)} extra")
    body = text[text.index("inline bool admits("):]
    body = body[:body.index("}")]
    assert "state == kLive" in body
    assert reg.ADMITS == "live"


# ── the schema name is the core's rule, not a new one ──────────────────────


def test_the_schema_name_is_derived_the_way_the_core_derives_it():
    # Database::get_schema_prefix is "tenant_" + id with everything that is not
    # alphanumeric or underscore removed. A different rule here would write a registry
    # row pointing at a schema that never appears.
    assert schema_name_for("acme") == "tenant_acme"
    assert schema_name_for("filenginetest-drive") == "tenant_filenginetestdrive"
    assert schema_name_for("a-b-c") == "tenant_abc"


def test_the_schema_name_is_truncated_like_the_core_truncates_it():
    assert len(schema_name_for("x" * 100)) == 63


# ── the human-readable name is a LABEL, never an identifier ────────────────


def test_a_tenant_can_be_given_a_human_name():
    r = StaticTenantRegistry()
    _requested(r)
    t = r.set_display_name("acme", "Acme Corporation Ltd")
    assert t.display_name == "Acme Corporation Ltd"
    assert t.for_display()["display_name"] == "Acme Corporation Ltd"
    assert t.for_display()["has_display_name"] is True


def test_the_display_name_falls_back_to_the_id_but_stays_a_separate_key():
    # A caller always has something to print, but the identifier and the label never
    # merge: code that needs the id must not end up with a label because a name
    # happened to be set.
    r = StaticTenantRegistry().seed(
        Tenant(tenant_id="default", schema_name="tenant_default", state=LIVE))
    shown = r.get("default").for_display()
    assert shown["display_name"] == "default"
    assert shown["has_display_name"] is False
    assert shown["tenant_id"] == "default"


def test_renaming_the_label_never_touches_the_identifier():
    # tenant_id reaches a hostname, a Postgres schema, an LDAP DN and a file path. An
    # organisation renaming itself must not move its data.
    r = StaticTenantRegistry()
    _requested(r)
    before = r.get("acme")
    after = r.set_display_name("acme", "Something Else Entirely")
    assert after.tenant_id == before.tenant_id == "acme"
    assert after.schema_name == before.schema_name


def test_a_live_tenant_can_still_be_renamed():
    # Organisations rename themselves while in service, and a decommissioned tenant's
    # name should stay readable in a billing history.
    for state in (LIVE, SUSPENDED, "decommissioned"):
        r = StaticTenantRegistry().seed(
            Tenant(tenant_id="acme", schema_name="tenant_acme", state=state))
        assert r.set_display_name("acme", "Renamed").display_name == "Renamed"


def test_the_display_name_is_not_unique():
    # Uniqueness would make it an identifier by the back door, and the id already is
    # one. Two tenants may legitimately carry the same label.
    r = StaticTenantRegistry()
    _requested(r, "acme")
    _requested(r, "acme2")
    r.set_display_name("acme", "Acme")
    r.set_display_name("acme2", "Acme")
    assert [t.display_name for t in r.list()] == ["Acme", "Acme"]


# ── the gate ───────────────────────────────────────────────────────────────


def test_a_request_is_not_claimable_until_the_gate_clears():
    r = StaticTenantRegistry()
    _requested(r)
    assert not r.get("acme").gate_cleared
    assert r.claim_for_provisioning("acme", TEN) is None


def test_a_passing_dns_check_clears_the_gate():
    r = StaticTenantRegistry()
    _requested(r)
    t = r.record_dns("acme", _passing_dns())
    assert t.state == AWAITING_DNS
    assert t.gate_cleared and t.may_provision


def test_a_failing_dns_check_does_not():
    r = StaticTenantRegistry()
    _requested(r)
    t = r.record_dns("acme", _failing_dns())
    assert not t.gate_cleared
    assert r.claim_for_provisioning("acme", TEN) is None


def test_a_recheck_can_close_the_gate_again():
    # DNS regresses: a record edited, a zone reloaded, a TTL expiring onto a stale
    # value. The gate is a reading, not an achievement.
    r = StaticTenantRegistry()
    _requested(r)
    r.record_dns("acme", _passing_dns())
    assert r.get("acme").may_provision
    r.record_dns("acme", _failing_dns())
    assert not r.get("acme").may_provision


def test_an_override_clears_the_gate():
    r = StaticTenantRegistry()
    _requested(r)
    t = r.record_override("acme", TEN, "customer-managed zone")
    assert t.gate_cleared and t.may_provision
    assert t.override_by == TEN


def test_an_override_is_always_visible():
    r = StaticTenantRegistry()
    _requested(r)
    r.record_override("acme", TEN, "split-horizon DNS")
    assert r.get("acme").for_display()["override"] == {
        "by": TEN, "reason": "split-horizon DNS"}


def test_the_gate_predicate_matches_the_sql_that_enforces_it():
    """`Tenant.gate_cleared` mirrors the WHERE clause in claim_for_provisioning.

    Two expressions of one rule, so they are compared here over the matrix that
    matters rather than trusted to stay in step. The SQL is authoritative — it runs
    inside the UPDATE — and this property is what the UI renders.
    """
    assert "override_by <> ''" in reg._GATE
    assert "(dns->>'ok') = 'true'" in reg._GATE
    cases = [
        ({}, "", False),
        ({"ok": False}, "", False),
        ({"ok": True}, "", True),
        ({}, "someone", True),
        ({"ok": False}, "someone", True),
    ]
    for dns, override_by, expected in cases:
        t = Tenant(tenant_id="a", schema_name="s", state=REQUESTED,
                   dns=dns or None, override_by=override_by)
        assert t.gate_cleared is expected, (dns, override_by)


def test_a_dns_check_on_a_live_tenant_does_not_drag_it_out_of_service():
    # Running a check against a live tenant is a legitimate diagnostic. The doors
    # read this column, so moving it to awaiting_dns would cut off every user.
    r = StaticTenantRegistry().seed(
        Tenant(tenant_id="acme", schema_name="tenant_acme", state=LIVE))
    t = r.record_dns("acme", _failing_dns())
    assert t.state == LIVE
    assert t.admits_logins


def test_an_override_is_refused_once_provisioning_has_started():
    r = StaticTenantRegistry().seed(
        Tenant(tenant_id="acme", schema_name="tenant_acme", state=LIVE))
    assert r.record_override("acme", TEN, "because") is None


# ── the claim: one run, however many presses ───────────────────────────────


def test_two_simultaneous_claims_queue_one_run():
    """THE gate test.

    Two administrators press Provision. Both would read a cleared gate; only one may
    claim. Two runs mean two certificate issuance attempts against a rate limit
    SHARED BY EVERY TENANT on the domain.
    """
    r = StaticTenantRegistry()
    _requested(r)
    r.record_dns("acme", _passing_dns())
    assert r.claim_for_provisioning("acme", TEN) is not None
    assert r.claim_for_provisioning("acme", TEN) is None


def test_the_claim_moves_the_state_and_records_who():
    r = StaticTenantRegistry()
    _requested(r)
    r.record_override("acme", TEN, "sure")
    claimed = r.claim_for_provisioning("acme", TEN)
    assert claimed.state == PROVISIONING
    assert claimed.state_by == TEN


@pytest.mark.parametrize("state", [PROVISIONING, LIVE, SUSPENDED, "decommissioned"])
def test_a_tenant_past_the_gate_cannot_be_claimed_again(state):
    r = StaticTenantRegistry().seed(
        Tenant(tenant_id="acme", schema_name="tenant_acme", state=state,
               override_by=TEN, override_reason="cleared"))
    assert r.claim_for_provisioning("acme", TEN) is None


def test_claiming_something_that_does_not_exist_is_none_not_an_error():
    assert StaticTenantRegistry().claim_for_provisioning("nosuch", TEN) is None


def test_a_duplicate_request_is_refused_by_the_registry():
    r = StaticTenantRegistry()
    _requested(r)
    with pytest.raises(RegistryRefused):
        _requested(r)


# ── unavailable is not empty ───────────────────────────────────────────────


def test_an_unreachable_registry_raises_rather_than_reporting_no_tenants():
    r = StaticTenantRegistry(unavailable=True)
    with pytest.raises(RegistryUnavailable):
        r.list()
    with pytest.raises(RegistryUnavailable):
        r.get("acme")


def test_no_core_configured_is_empty_and_loud(caplog):
    from admin_master_control.config import Config

    c = Config()
    c.core_pg_user = ""
    with caplog.at_level("WARNING"):
        got = reg.from_config(c)
    assert isinstance(got, StaticTenantRegistry)
    assert any("NO tenants will be listed" in x.message for x in caplog.records)


def test_a_configured_but_unreachable_core_does_not_become_an_empty_registry(caplog):
    # Falling back would show an empty estate, which reads as "there are no tenants"
    # on the console whose job is to know how many there are.
    from admin_master_control.config import Config

    c = Config()
    c.core_pg_user, c.core_pg_host, c.core_pg_port = "u", "127.0.0.1", 1
    c.core_pg_database = "nope"
    with caplog.at_level("ERROR"):
        got = reg.from_config(c)
    assert isinstance(got, PostgresTenantRegistry)
    assert any("unusable" in x.message for x in caplog.records)


def test_the_dsn_is_separate_from_this_applications_own_database():
    # AMC_PG_* is this console's database (its queue and decisions); AMC_CORE_PG_* is
    # the core's. Pointing one at the other would put console tables in the core's
    # schema or look for tenants in a database that has none.
    from admin_master_control.config import Config
    from admin_master_control import job_store

    c = Config()
    c.pg_host, c.pg_database, c.pg_user = "own", "admin_master_control", "u"
    c.core_pg_host, c.core_pg_database, c.core_pg_user = "core", "fileengine", "u"
    assert "dbname=admin_master_control" in job_store.dsn_for(c)
    assert "dbname=fileengine" in reg.dsn_for(c)


# ── live Postgres ──────────────────────────────────────────────────────────

live = pytest.mark.skipif(
    not os.environ.get("AMC_TEST_CORE_PG_DSN"),
    reason="set AMC_TEST_CORE_PG_DSN to run the live registry tests")


@pytest.fixture()
def pg():
    """A live registry with the console's columns, cleaned of THIS TEST'S rows only.

    It does NOT truncate. The earlier job-store fixture did, and pointed at the dev
    database it deleted the console's real in-flight requests — noticed only because a
    later check reported three where there had been four. This table belongs to the
    core and holds every real tenant, so a truncating fixture here would delete the
    estate. Only ids under a reserved prefix are removed.
    """
    dsn = os.environ["AMC_TEST_CORE_PG_DSN"]
    r = PostgresTenantRegistry(dsn=dsn)
    r.ensure_schema()
    with r._connect() as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM public.tenants WHERE tenant_id LIKE 'zztest-%'")
        conn.commit()
    return r


@live
def test_live_adding_the_columns_is_idempotent(pg):
    pg.ensure_schema()
    pg.ensure_schema()


@live
def test_live_the_real_estate_is_listed(pg):
    # The actual point: tenants nobody requested through this console.
    ids = [t.tenant_id for t in pg.list()]
    assert "default" in ids, "the registry should contain the deployment's own tenants"
    assert len(ids) > 1


@live
def test_live_request_and_claim(pg):
    t = pg.request(tenant_id="zztest-a", base_domain=BASE, address=ADDR,
                   initial_admin="a@b.c", requested_by=TEN, display_name="ZZ Test A")
    assert t.state == REQUESTED
    assert t.schema_name == "tenant_zztesta"
    assert t.display_name == "ZZ Test A"

    assert pg.claim_for_provisioning("zztest-a", TEN) is None, "the gate is not cleared"
    pg.record_dns("zztest-a", _failing_dns())
    assert pg.claim_for_provisioning("zztest-a", TEN) is None
    pg.record_dns("zztest-a", _passing_dns())
    claimed = pg.claim_for_provisioning("zztest-a", TEN)
    assert claimed is not None and claimed.state == PROVISIONING
    assert pg.claim_for_provisioning("zztest-a", TEN) is None, "only once"


@live
def test_live_duplicate_is_the_constraint(pg):
    pg.request(tenant_id="zztest-b", base_domain=BASE, address=ADDR,
               initial_admin="a@b.c", requested_by=TEN)
    with pytest.raises(RegistryRefused):
        pg.request(tenant_id="zztest-b", base_domain=BASE, address=ADDR,
                   initial_admin="a@b.c", requested_by=TEN)


@live
def test_live_concurrent_claims_admit_exactly_one(pg):
    """Eight real connections racing one row. Only the database can show this."""
    pg.request(tenant_id="zztest-c", base_domain=BASE, address=ADDR,
               initial_admin="a@b.c", requested_by=TEN)
    pg.record_dns("zztest-c", _passing_dns())

    import threading
    won: list = []

    def claim():
        r = PostgresTenantRegistry(dsn=os.environ["AMC_TEST_CORE_PG_DSN"])
        if r.claim_for_provisioning("zztest-c", TEN) is not None:
            won.append(1)

    ts = [threading.Thread(target=claim) for _ in range(8)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    assert sum(won) == 1, f"{sum(won)} claims succeeded; exactly one must"


@live
def test_live_the_display_name_round_trips(pg):
    pg.request(tenant_id="zztest-d", base_domain=BASE, address=ADDR,
               initial_admin="a@b.c", requested_by=TEN)
    pg.set_display_name("zztest-d", "Ácme Ltd — Oﬀice")
    assert pg.get("zztest-d").display_name == "Ácme Ltd — Oﬀice"


@live
def test_live_the_console_columns_do_not_break_the_cores_insert(pg):
    """Every added column is defaulted, so the core's own INSERT still works.

    A NOT NULL column without a default would take the file service down — a console
    feature breaking the thing it administers.
    """
    with pg._connect() as conn:
        with conn.cursor() as cur:
            # Exactly the shape the core uses: id + schema only.
            cur.execute("INSERT INTO public.tenants (tenant_id, schema_name) "
                        "VALUES ('zztest-core', 'tenant_zztestcore')")
        conn.commit()
    t = pg.get("zztest-core")
    assert t is not None
    assert t.state == LIVE, "the core's default state"
    assert t.display_name == "" and t.base_domain == ""


# ── through the API ────────────────────────────────────────────────────────


def _cfg():
    from admin_master_control.config import Config

    c = Config()
    c.jwt_secret = "deployment-tier-secret"
    c.token_audience = "fileengine-system-admin"
    c.require_mfa = True
    c.monitor_host = "127.0.0.1"
    c.audit_url = "http://audit:8097"
    c.mfa_url = "http://ldap-manager:8093"
    c.mfa_internal_secret = "internal-shared-secret"
    c.bootstrap_owner = ""
    return c


def _client(registry=None, resolver=None):
    from fastapi.testclient import TestClient

    from . import _harness
    from admin_master_control.administrators import AdministratorRegistry, bootstrap_owner
    from admin_master_control.app import build_app
    from admin_master_control.auth import StaticDeploymentDirectory
    from admin_master_control.roles import SYSTEM_OBSERVER, SYSTEM_TENANTS
    from admin_master_control.tenants import StaticResolver, hostnames_for

    d = StaticDeploymentDirectory()
    for who, roles in ((TEN, {SYSTEM_TENANTS, SYSTEM_OBSERVER}),
                       ("obs@x", {SYSTEM_OBSERVER})):
        d.passwords[who] = "pw"
        d.grants[who] = roles
    admins = AdministratorRegistry()
    bootstrap_owner(admins, "james@rationalboxes.com")
    reg_ = registry if registry is not None else StaticTenantRegistry()
    res = resolver if resolver is not None else StaticResolver(
        answers={h: (ADDR,) for h in hostnames_for("acme", BASE)})
    app = build_app(_cfg(), admins, d, None, None, res,
                    _harness.factors(TEN, "obs@x"), reg_, None)
    return TestClient(app), reg_


def _hdr(client, who=TEN):
    from . import _harness

    return _harness.headers(client, who)


def test_the_api_lists_tenants_it_never_created():
    # The bug, at the level the user saw it: an empty page on a populated estate.
    r = StaticTenantRegistry().seed(
        Tenant(tenant_id="default", schema_name="tenant_default", state=LIVE),
        Tenant(tenant_id="someco", schema_name="tenant_someco", state=SUSPENDED),
    )
    c, _ = _client(registry=r)
    body = c.get("/v1/tenants", headers=_hdr(c)).json()
    assert [t["tenant_id"] for t in body["tenants"]] == ["default", "someco"]
    assert body["tenants"][0]["admits_logins"] is True
    assert body["tenants"][1]["admits_logins"] is False


def test_the_api_reports_an_unreachable_registry_rather_than_an_empty_estate():
    c, _ = _client(registry=StaticTenantRegistry(unavailable=True))
    assert c.get("/v1/tenants", headers=_hdr(c)).status_code == 503


def test_requesting_a_tenant_writes_to_the_registry():
    c, r = _client()
    resp = c.post("/v1/tenants", headers=_hdr(c), json={
        "tenant_id": "acme", "base_domain": BASE, "address": ADDR,
        "initial_admin": "a@acme.test", "display_name": "Acme Corporation"})
    assert resp.status_code == 201
    assert resp.json()["state"] == REQUESTED
    assert resp.json()["display_name"] == "Acme Corporation"
    # In the REGISTRY, not beside it.
    assert r.get("acme").state == REQUESTED


def test_the_records_to_paste_come_back_with_the_request():
    c, _ = _client()
    body = c.post("/v1/tenants", headers=_hdr(c), json={
        "tenant_id": "acme", "base_domain": BASE, "address": ADDR,
        "initial_admin": "a@acme.test"}).json()
    assert [rec["name"] for rec in body["records"]] == [
        f"acme.{BASE}", f"acme-drive.{BASE}"]


def test_the_display_name_can_be_set_afterwards():
    c, r = _client()
    c.post("/v1/tenants", headers=_hdr(c), json={
        "tenant_id": "acme", "base_domain": BASE, "address": ADDR,
        "initial_admin": "a@acme.test"})
    resp = c.put("/v1/tenants/acme/display-name", headers=_hdr(c),
                 json={"display_name": "Acme Corporation Ltd"})
    assert resp.status_code == 200
    assert resp.json()["display_name"] == "Acme Corporation Ltd"
    assert r.get("acme").tenant_id == "acme", "the identifier must not move"


def test_a_pre_existing_tenant_can_be_given_a_name():
    # The main reason this route exists: seventy tenants predate the console and none
    # of them has a human-readable name yet.
    r = StaticTenantRegistry().seed(
        Tenant(tenant_id="default", schema_name="tenant_default", state=LIVE))
    c, _ = _client(registry=r)
    assert c.put("/v1/tenants/default/display-name", headers=_hdr(c),
                 json={"display_name": "House Account"}).status_code == 200
    assert r.get("default").display_name == "House Account"


def test_setting_a_name_needs_system_tenants():
    r = StaticTenantRegistry().seed(
        Tenant(tenant_id="default", schema_name="tenant_default", state=LIVE))
    c, _ = _client(registry=r)
    assert c.put("/v1/tenants/default/display-name", headers=_hdr(c, "obs@x"),
                 json={"display_name": "Nope"}).status_code == 403


def test_a_dns_check_on_a_tenant_that_predates_the_console_says_so():
    # It has no recorded base domain, so there is nothing to check against. Said
    # plainly rather than reported as a DNS failure, which would send someone to look
    # at a zone that is fine.
    r = StaticTenantRegistry().seed(
        Tenant(tenant_id="default", schema_name="tenant_default", state=LIVE))
    c, _ = _client(registry=r)
    resp = c.post("/v1/tenants/default/dns-check", headers=_hdr(c))
    assert resp.status_code == 409
    assert "not requested through this console" in resp.json()["detail"]


def test_the_double_press_queues_one_run_through_the_api():
    c, r = _client()
    c.post("/v1/tenants", headers=_hdr(c), json={
        "tenant_id": "acme", "base_domain": BASE, "address": ADDR,
        "initial_admin": "a@acme.test"})
    assert c.post("/v1/tenants/acme/dns-check", headers=_hdr(c)).json()["may_provision"]
    first = c.post("/v1/tenants/acme/provision", headers=_hdr(c))
    second = c.post("/v1/tenants/acme/provision", headers=_hdr(c))
    assert first.status_code == 202
    assert second.status_code == 409
    detail = second.json()["detail"].lower()
    # THIS one is the race, and says so.
    assert "another administrator" in detail and "a moment ago" in detail
    assert "dns gate has not passed" not in detail
    jobs = c.get("/v1/provisioning-jobs", headers=_hdr(c)).json()["jobs"]
    assert len(jobs) == 1


def test_provisioning_is_refused_with_the_reason_that_names_what_it_protects():
    c, _ = _client()
    c.post("/v1/tenants", headers=_hdr(c), json={
        "tenant_id": "acme", "base_domain": BASE, "address": ADDR,
        "initial_admin": "a@acme.test"})
    resp = c.post("/v1/tenants/acme/provision", headers=_hdr(c))
    assert resp.status_code == 409
    assert "rate limit" in resp.json()["detail"]


def test_a_live_tenant_cannot_be_provisioned_again():
    r = StaticTenantRegistry().seed(
        Tenant(tenant_id="default", schema_name="tenant_default", state=LIVE,
               override_by=TEN, override_reason="x"))
    c, _ = _client(registry=r)
    resp = c.post("/v1/tenants/default/provision", headers=_hdr(c))
    assert resp.status_code == 409
    detail = resp.json()["detail"]
    assert "already in service" in detail
    # NOT the race message. A tenant live since June being told "another
    # administrator started it a moment ago" is simply false, and reads as a race
    # that did not happen.
    assert "a moment ago" not in detail
