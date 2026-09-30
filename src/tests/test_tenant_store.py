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

"""Persisting tenant requests, and the race that persistence is really for.

Surviving a restart is the easy half and the less important one. The weight here
is on `claim_for_provisioning`, because a dict could not make the provisioning
gate safe no matter how carefully the gate was written:

    Two administrators press Provision at the same moment. Both read
    `state == "verified"`, both pass `may_provision`, both queue a job. Two
    playbook runs, two certificate issuance attempts — against a rate limit
    SHARED BY EVERY TENANT on the domain.

That is the exact failure the DNS gate exists to prevent, arrived at by a route
that never skipped the gate. `test_two_simultaneous_provisions_queue_one_job` is
the assertion that matters in this file.

The live Postgres tests are marked `live` and skip without a database.
"""
from __future__ import annotations

import os

import pytest
from fastapi.testclient import TestClient

from . import _harness
from admin_master_control.administrators import AdministratorRegistry, bootstrap_owner
from admin_master_control.app import build_app
from admin_master_control.auth import StaticDeploymentDirectory
from admin_master_control.config import Config
from admin_master_control.roles import SYSTEM_OBSERVER, SYSTEM_TENANTS
from admin_master_control.tenant_store import (
    InMemoryTenantStore,
    PostgresTenantStore,
    StoreUnavailable,
    TenantExists,
    dsn_for,
    verdict_from_json,
    verdict_to_json,
)
from admin_master_control.tenants import (
    AWAITING_DNS,
    LIVE,
    PROVISIONING,
    REQUESTED,
    VERIFIED,
    DnsVerdict,
    HostCheck,
    StaticResolver,
    TenantRequest,
    hostnames_for,
    override as dns_override,
    verify as dns_verify,
)

TEN = "ten@rationalboxes.com"
OBS = "obs@rationalboxes.com"
BASE = "rationalboxes.com"
ADDR = "203.0.113.10"


def _req(tenant_id="acme", **over) -> TenantRequest:
    kw = {"tenant_id": tenant_id, "base_domain": BASE, "address": ADDR,
          "initial_admin": "admin@acme.test", "requested_by": TEN}
    kw.update(over)
    return TenantRequest(**kw)


def _ready(tenant_id="acme") -> StaticResolver:
    return StaticResolver(answers={h: (ADDR,) for h in hostnames_for(tenant_id, BASE)})


# ── the claim: one job, however many presses ───────────────────────────────


def test_a_verified_request_can_be_claimed_once():
    store = InMemoryTenantStore()
    store.create(_req(state=VERIFIED))
    assert store.claim_for_provisioning("acme") is not None
    assert store.claim_for_provisioning("acme") is None, (
        "a second claim must not succeed — it would queue a second playbook run")


def test_the_claim_moves_the_state_in_the_same_breath():
    store = InMemoryTenantStore()
    store.create(_req(state=VERIFIED))
    store.claim_for_provisioning("acme")
    assert store.get("acme").state == PROVISIONING


@pytest.mark.parametrize("state", [REQUESTED, AWAITING_DNS, PROVISIONING, LIVE])
def test_an_unverified_request_cannot_be_claimed(state):
    # The gate, enforced by the store rather than only by the route. A caller that
    # forgot to check may_provision still cannot start a run.
    store = InMemoryTenantStore()
    store.create(_req(state=state))
    assert store.claim_for_provisioning("acme") is None


def test_claiming_something_that_does_not_exist_is_none_not_an_error():
    assert InMemoryTenantStore().claim_for_provisioning("nosuch") is None


# ── the same property, through the API ─────────────────────────────────────


def _cfg() -> Config:
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


def _client(store=None, resolver=None):
    d = StaticDeploymentDirectory()
    for who, roles in ((TEN, {SYSTEM_TENANTS}), (OBS, {SYSTEM_OBSERVER})):
        d.passwords[who] = "pw"
        d.grants[who] = roles
    reg = AdministratorRegistry()
    bootstrap_owner(reg, "james@rationalboxes.com")
    store = store if store is not None else InMemoryTenantStore()
    app = build_app(_cfg(), reg, d, None, None,
                    resolver if resolver is not None else _ready(),
                    _harness.factors(TEN, OBS), store)
    return TestClient(app), store


def _body(tenant_id="acme"):
    return {"tenant_id": tenant_id, "base_domain": BASE, "address": ADDR,
            "initial_admin": "admin@acme.test"}


def test_two_simultaneous_provisions_queue_one_job():
    """THE test in this file.

    Not a threading test — the race does not need concurrency to demonstrate,
    because the bug was that the state was read and then written. Two sequential
    presses model it exactly: with a dict, the first set `state = "provisioning"`
    only AFTER building the job, so the second press read the state the first had
    not yet written.
    """
    c, store = _client()
    h = _harness.headers(c, TEN)
    c.post("/v1/tenants", json=_body(), headers=h)
    c.post("/v1/tenants/acme/dns-check", headers=h)

    first = c.post("/v1/tenants/acme/provision", headers=h)
    second = c.post("/v1/tenants/acme/provision", headers=h)

    assert first.status_code == 202
    assert second.status_code == 409, "the second press must not start a second run"
    # And it says the RIGHT thing. Letting provisioning_job's guard produce this
    # message told the second presser "the DNS gate has not passed" about a tenant
    # whose gate HAD passed and whose run was already underway — sending them to
    # re-check DNS that was fine.
    detail = second.json()["detail"].lower()
    assert "another administrator" in detail
    assert "dns gate has not passed" not in detail
    assert len(store.jobs()) == 1, (
        "two jobs means two certificate issuance attempts against a rate limit "
        "shared by every tenant on the domain")


def test_the_second_press_is_told_the_current_state_not_just_refused():
    c, _ = _client()
    h = _harness.headers(c, TEN)
    c.post("/v1/tenants", json=_body(), headers=h)
    c.post("/v1/tenants/acme/dns-check", headers=h)
    c.post("/v1/tenants/acme/provision", headers=h)
    detail = c.post("/v1/tenants/acme/provision", headers=h).json()["detail"]
    assert PROVISIONING in detail


def test_a_duplicate_request_is_refused_by_the_store_not_a_prior_check():
    # A SELECT then an INSERT is two statements and a race. The route no longer
    # looks first; it inserts and handles the constraint.
    c, store = _client()
    h = _harness.headers(c, TEN)
    assert c.post("/v1/tenants", json=_body(), headers=h).status_code == 201
    assert c.post("/v1/tenants", json=_body(), headers=h).status_code == 409
    with pytest.raises(TenantExists):
        store.create(_req())


# ── it is actually written down ────────────────────────────────────────────


def test_a_request_survives_a_new_app_on_the_same_store():
    # The restart, modelled: a second app over the same store sees the request.
    # It used to be a dict on app.state, so a tenant half-created — exactly the
    # outstanding thing §3.2 exists to surface — vanished on restart.
    store = InMemoryTenantStore()
    c1, _ = _client(store=store)
    c1.post("/v1/tenants", json=_body(), headers=_harness.headers(c1, TEN))

    c2, _ = _client(store=store)
    got = c2.get("/v1/tenants/acme", headers=_harness.headers(c2, OBS))
    assert got.status_code == 200
    assert got.json()["requested_by"] == TEN


def test_the_dns_verdict_is_written_down_too():
    # Not just the state: the blocking reason is what an administrator comes back
    # for, and recomputing it on read would need the resolver again.
    store = InMemoryTenantStore()
    c, _ = _client(store=store, resolver=StaticResolver(answers={}))
    h = _harness.headers(c, TEN)
    c.post("/v1/tenants", json=_body(), headers=h)
    c.post("/v1/tenants/acme/dns-check", headers=h)

    c2, _ = _client(store=store)
    shown = c2.get("/v1/tenants/acme", headers=_harness.headers(c2, OBS)).json()
    assert shown["state"] == AWAITING_DNS
    assert "acme-drive" in shown["dns"]["blocking_reason"]


def test_an_override_is_written_down():
    store = InMemoryTenantStore()
    c, _ = _client(store=store, resolver=StaticResolver(answers={}))
    h = _harness.headers(c, TEN)
    c.post("/v1/tenants", json=_body(), headers=h)
    c.post("/v1/tenants/acme/dns-override", json={"reason": "customer zone"}, headers=h)

    c2, _ = _client(store=store)
    shown = c2.get("/v1/tenants/acme", headers=_harness.headers(c2, OBS)).json()
    assert shown["override"] == {"by": TEN, "reason": "customer zone"}
    assert shown["may_provision"]


def test_the_job_is_readable_after_the_fact():
    c, _ = _client()
    h = _harness.headers(c, TEN)
    c.post("/v1/tenants", json=_body(), headers=h)
    c.post("/v1/tenants/acme/dns-check", headers=h)
    c.post("/v1/tenants/acme/provision", headers=h)
    jobs = c.get("/v1/provisioning-jobs", headers=_harness.headers(c, OBS)).json()["jobs"]
    assert len(jobs) == 1
    assert jobs[0]["state"] == "queued"
    assert jobs[0]["extra_vars"]["tenant_id"] == "acme"
    assert jobs[0]["job_id"]


def test_the_queue_is_observer_readable_but_not_writable():
    # A job stuck in `queued` because no runner is running is the §3.2 case.
    c, _ = _client()
    assert c.get("/v1/provisioning-jobs",
                 headers=_harness.headers(c, OBS)).status_code == 200
    assert c.post("/v1/provisioning-jobs",
                  headers=_harness.headers(c, TEN)).status_code == 405


# ── the verdict round-trips ────────────────────────────────────────────────


def test_a_verdict_survives_json():
    v = DnsVerdict(ok=False, authoritative=False, detail="one or more not ready",
                   checks=(HostCheck(hostname="acme.example.com", resolved=("1.2.3.4",),
                                     expected=ADDR, ok=False,
                                     detail="resolves to 1.2.3.4, expected " + ADDR),
                           HostCheck(hostname="acme-drive.example.com", resolved=(),
                                     expected=ADDR, ok=False, detail="no record")))
    back = verdict_from_json(verdict_to_json(v))
    assert back == v
    # And the property the UI depends on, which is derived rather than stored.
    assert "1.2.3.4" in back.blocking_reason and "no record" in back.blocking_reason


def test_no_verdict_round_trips_as_no_verdict():
    # None means "not checked yet", which must not become a verdict of ok=False —
    # that would read as "DNS has failed" on a request nobody has checked.
    assert verdict_to_json(None) is None
    assert verdict_from_json(None) is None
    assert verdict_from_json({}) is None


def test_a_passing_verdict_round_trips():
    req = _req()
    dns_verify(req, _ready())
    back = verdict_from_json(verdict_to_json(req.dns))
    assert back.ok and back.authoritative and back.blocking_reason == ""


# ── reading a row back is not re-validating it ─────────────────────────────


def test_a_stored_request_loads_even_if_the_rules_later_tighten():
    # `__post_init__` validates an id arriving from OUTSIDE, which is right at the
    # entry point and wrong on the way back out of the store. If RESERVED_IDS
    # grows, a request already recorded must still load — otherwise the validator
    # hides the very tenant it wants attention drawn to, and nobody can see or
    # cancel it.
    from admin_master_control.tenant_store import _row_to_request

    row = ("login", REQUESTED, BASE, ADDR, "a@b.c", TEN, "2026-09-29T00:00:00+00:00",
           None, "", "", "", "", False, "")
    got = _row_to_request(row)
    assert got.tenant_id == "login"
    assert got.state == REQUESTED


def test_loading_does_not_invent_a_verdict():
    from admin_master_control.tenant_store import _row_to_request

    row = ("acme", REQUESTED, BASE, ADDR, "a@b.c", TEN, "2026-09-29T00:00:00+00:00",
           None, "", "", "", "", False, "")
    assert _row_to_request(row).dns is None


# ── unavailable is not empty ───────────────────────────────────────────────


class _Down:
    def ensure_schema(self): return None
    def get(self, tenant_id): raise StoreUnavailable("the tenant store is down")
    def list(self): raise StoreUnavailable("the tenant store is down")
    def create(self, request): raise StoreUnavailable("the tenant store is down")
    def save(self, request): raise StoreUnavailable("the tenant store is down")
    def claim_for_provisioning(self, tenant_id): raise StoreUnavailable("down")
    def record_job(self, tenant_id, job): raise StoreUnavailable("down")
    def jobs(self, *, limit=100): raise StoreUnavailable("the tenant store is down")


def test_an_unreachable_store_is_503_not_404():
    # "No such tenant" would send someone looking for a tenant that is fine.
    c, _ = _client(store=_Down())
    h = _harness.headers(c, TEN)
    assert c.get("/v1/tenants/acme", headers=_harness.headers(c, OBS)).status_code == 503
    assert c.post("/v1/tenants", json=_body(), headers=h).status_code == 503


def test_an_unreachable_store_is_503_not_an_empty_list():
    # An empty list reads as "no tenants are being created", which is a statement
    # about the estate rather than about this application's database.
    c, _ = _client(store=_Down())
    r = c.get("/v1/tenants", headers=_harness.headers(c, OBS))
    assert r.status_code == 503
    r = c.get("/v1/provisioning-jobs", headers=_harness.headers(c, OBS))
    assert r.status_code == 503


# ── configuration ──────────────────────────────────────────────────────────


def test_the_dsn_omits_credentials_it_does_not_have():
    c = Config()
    c.pg_host, c.pg_port, c.pg_database = "db", 5432, "amc"
    c.pg_user, c.pg_password = "", ""
    assert dsn_for(c) == "host=db port=5432 dbname=amc"


def test_the_dsn_carries_them_when_it_does():
    c = Config()
    c.pg_host, c.pg_port, c.pg_database = "db", 5434, "amc"
    c.pg_user, c.pg_password = "u", "p"
    assert "user=u" in dsn_for(c) and "password=p" in dsn_for(c)


def test_no_database_configured_falls_back_loudly(caplog):
    from admin_master_control.tenant_store import from_config

    c = Config()
    c.pg_user = ""
    with caplog.at_level("WARNING"):
        store = from_config(c)
    assert isinstance(store, InMemoryTenantStore)
    assert any("IN MEMORY" in r.message for r in caplog.records), (
        "a store that loses in-flight requests on restart should say so")


def test_a_configured_but_unreachable_store_does_not_silently_become_memory(caplog):
    # Falling back would accept requests that look fine and then vanish. Worse
    # than reporting that the database is down.
    from admin_master_control.tenant_store import from_config

    c = Config()
    c.pg_user, c.pg_host, c.pg_port = "u", "127.0.0.1", 1      # nothing listens
    c.pg_database = "amc"
    with caplog.at_level("ERROR"):
        store = from_config(c)
    assert isinstance(store, PostgresTenantStore)
    assert any("unreachable" in r.message for r in caplog.records)


# ── live Postgres ──────────────────────────────────────────────────────────

live = pytest.mark.skipif(not os.environ.get("AMC_TEST_PG_DSN"),
                          reason="set AMC_TEST_PG_DSN to run the live store tests")


@pytest.fixture()
def pg():
    store = PostgresTenantStore(dsn=os.environ["AMC_TEST_PG_DSN"])
    store.ensure_schema()
    with store._connect() as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM provisioning_job")
            cur.execute("DELETE FROM tenant_request")
        conn.commit()
    return store


@live
def test_live_schema_is_idempotent(pg):
    # Called on every start. Running it twice must be a no-op, not a
    # duplicate-object error.
    pg.ensure_schema()
    pg.ensure_schema()


@live
def test_live_round_trip(pg):
    req = _req()
    dns_verify(req, _ready())
    pg.create(req)
    pg.save(req)
    got = pg.get("acme")
    assert got.tenant_id == "acme"
    assert got.state == VERIFIED
    assert got.dns is not None and got.dns.ok
    assert got.requested_by == TEN
    assert [r.name for r in got.records] == hostnames_for("acme", BASE)


@live
def test_live_duplicate_is_the_constraint(pg):
    pg.create(_req())
    with pytest.raises(TenantExists):
        pg.create(_req())


@live
def test_live_claim_is_atomic(pg):
    req = _req()
    dns_verify(req, _ready())
    pg.create(req)
    pg.save(req)
    assert pg.claim_for_provisioning("acme") is not None
    assert pg.claim_for_provisioning("acme") is None
    assert pg.get("acme").state == PROVISIONING


@live
def test_live_claim_refuses_an_unverified_request(pg):
    pg.create(_req())            # state=requested
    assert pg.claim_for_provisioning("acme") is None
    assert pg.get("acme").state == REQUESTED


@live
def test_live_concurrent_claims_admit_exactly_one(pg):
    """Two real connections, both racing the same row.

    The in-memory double cannot demonstrate this; only the database can, and this
    is the property the whole design rests on.
    """
    req = _req()
    dns_verify(req, _ready())
    pg.create(req)
    pg.save(req)

    import threading
    won: list = []

    def claim():
        s = PostgresTenantStore(dsn=os.environ["AMC_TEST_PG_DSN"])
        if s.claim_for_provisioning("acme") is not None:
            won.append(1)

    ts = [threading.Thread(target=claim) for _ in range(8)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    assert sum(won) == 1, f"{sum(won)} claims succeeded; exactly one must"


@live
def test_live_override_and_job_persist(pg):
    req = _req()
    dns_override(req, by=TEN, reason="customer-managed zone")
    pg.create(req)
    pg.save(req)
    claimed = pg.claim_for_provisioning("acme")
    assert claimed is not None
    assert claimed.override_reason == "customer-managed zone"
    job_id = pg.record_job("acme", {"playbook": "playbooks/tenant.yml",
                                    "requested_by": TEN,
                                    "extra_vars": {"tenant_id": "acme"}})
    assert job_id.startswith("job-")
    assert pg.get("acme").job_id == job_id
    jobs = pg.jobs()
    assert len(jobs) == 1 and jobs[0]["state"] == "queued"
    assert jobs[0]["extra_vars"]["tenant_id"] == "acme"


@live
def test_live_a_job_needs_a_tenant_that_exists(pg):
    # The foreign key. A job for a tenant nobody requested is a run nobody asked
    # for, and the runner would execute it.
    import psycopg

    with pytest.raises(psycopg.errors.ForeignKeyViolation):
        pg.record_job("nosuch", {"requested_by": TEN})


@live
def test_live_listing_is_newest_first(pg):
    for i, tid in enumerate(("aaa", "bbb", "ccc")):
        r = _req(tid)
        r.requested_at = f"2026-09-2{i}T00:00:00+00:00"
        pg.create(r)
    assert [r.tenant_id for r in pg.list()] == ["ccc", "bbb", "aaa"]
