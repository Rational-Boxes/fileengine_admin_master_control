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

"""Tenant setup (§3.4a), and the DNS gate that stands in front of it.

The weight of this file is on ONE failure, because its blast radius is not
confined to the tenant being created (§5.3):

    "Run the playbook before DNS has propagated and the certificate step fails —
    and failed issuance consumes the domain's rate limit, which is SHARED BY
    EVERY TENANT. A create button that can be pressed early is a button that can
    exhaust certificate issuance for the whole deployment."

So the tests that matter most are not "creating a tenant works". They are the
ways a check can say yes when the certificate authority would say no: a
non-authoritative answer, a name pointing at the wrong host, a second hostname
nobody looked at. Each of those reads as success and issues nothing.

The other axis is §5.3's boundary — requested here, executed by a runner. The
job is asserted to be structured data with no credentials in it, and
`test_readiness.py` asserts structurally that this package cannot run anything.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from admin_master_control import tenants as t
from admin_master_control.administrators import AdministratorRegistry, bootstrap_owner
from admin_master_control.app import build_app
from admin_master_control.auth import StaticDeploymentDirectory
from admin_master_control.config import Config
from admin_master_control.roles import (
    SYSTEM_OBSERVER,
    SYSTEM_SECURITY,
    SYSTEM_TENANTS,
)

TEN = "ten@rationalboxes.com"
OBS = "obs@rationalboxes.com"
SEC = "sec@rationalboxes.com"

BASE = "rationalboxes.com"
ADDR = "203.0.113.10"


def _ready(tenant_id="acme", base=BASE, address=ADDR, **kw) -> t.StaticResolver:
    """A resolver on which the gate SHOULD pass: every hostname, right address."""
    return t.StaticResolver(
        answers={h: (address,) for h in t.hostnames_for(tenant_id, base)}, **kw)


def _req(tenant_id="acme", **over) -> t.TenantRequest:
    kw = {"tenant_id": tenant_id, "base_domain": BASE, "address": ADDR,
          "initial_admin": "admin@acme.test", "requested_by": TEN}
    kw.update(over)
    return t.TenantRequest(**kw)


# ── the tenant id reaches four interpreters (§5.3.1) ───────────────────────


def test_a_tenant_id_is_a_narrow_shape():
    for good in ("acme", "acme-corp", "a1", "x" * 31):
        assert t.validate_tenant_id(good) == good


@pytest.mark.parametrize("bad", [
    "",
    "A",                    # the id becomes a Postgres schema and an LDAP ou
    "1acme",                # must start with a letter
    "-acme",
    "acme_corp",            # underscore is not valid in a hostname label
    "acme.corp",            # would create a second DNS label
    "x" * 32,               # hostname label limit
    "acme corp",
    "acme;rm -rf /",
    "acme'--",
    "../acme",
    "acme$(id)",
    "acme\nwww",
])
def test_an_id_that_could_mean_something_elsewhere_is_refused(bad):
    # §5.3.1: the id reaches a hostname, a Postgres schema name, an LDAP DN and a
    # file path. Validating once, narrowly, at the entry point is the only place
    # it can be done for all four — the alternative is escaping it correctly in
    # four dialects, four times.
    with pytest.raises(t.TenantError):
        t.validate_tenant_id(bad)


@pytest.mark.parametrize("reserved", sorted(t.RESERVED_IDS))
def test_a_reserved_id_is_refused(reserved):
    # `login.rationalboxes.com` and `www.rationalboxes.com` already exist. A
    # tenant claiming one would have the playbook write a vhost that shadows the
    # deployment's own — and the failure would arrive as "the login page is gone".
    with pytest.raises(t.TenantError):
        t.validate_tenant_id(reserved)


# ── the records to create ──────────────────────────────────────────────────


def test_both_hostnames_are_named():
    # The webdav door gets its own name, so there are TWO certificates. A check
    # that looked at one would pass and the run would stop on the second.
    assert t.hostnames_for("acme", BASE) == ["acme.rationalboxes.com",
                                             "acme-drive.rationalboxes.com"]


def test_the_records_are_pasteable():
    recs = t.records_for("acme", BASE, ADDR)
    assert [r.name for r in recs] == ["acme.rationalboxes.com",
                                      "acme-drive.rationalboxes.com"]
    assert all(r.type == "A" and r.value == ADDR for r in recs)
    # Fully-qualified with the trailing dot and an explicit TTL: pasted into a
    # zone without the dot, `acme.rationalboxes.com` would be read as relative to
    # the origin and become acme.rationalboxes.com.rationalboxes.com.
    assert recs[0].as_zone_line().split() == [
        "acme.rationalboxes.com.", "300", "IN", "A", ADDR]


def test_an_ipv6_address_gets_a_quad_a_record():
    recs = t.records_for("acme", BASE, "2001:db8::10")
    assert all(r.type == "AAAA" for r in recs)


# ── the gate: three ways a naive check says yes ────────────────────────────


def test_the_gate_passes_when_dns_is_actually_ready():
    assert t.check_dns("acme", BASE, ADDR, _ready()).ok


def test_a_non_authoritative_answer_does_not_pass():
    # The reason this is not pedantry: a cached NXDOMAIN blocks a record that has
    # in fact propagated, and a local override or a search-domain quirk shows a
    # success the world does not see. Neither is what the CA will resolve.
    v = t.check_dns("acme", BASE, ADDR, _ready(authoritative=False))
    assert not v.ok
    assert not v.authoritative
    assert "authoritative" in v.blocking_reason


def test_a_name_pointing_at_the_wrong_host_does_not_pass():
    # "A name pointing at the previous host resolves perfectly and issues
    # nothing." The check compares the ADDRESS, not merely that something
    # answered.
    v = t.check_dns("acme", BASE, ADDR,
                    t.StaticResolver(answers={h: ("198.51.100.4",)
                                              for h in t.hostnames_for("acme", BASE)}))
    assert not v.ok
    assert "198.51.100.4" in v.blocking_reason and ADDR in v.blocking_reason


def test_a_missing_drive_hostname_does_not_pass():
    # The asymmetric case, and the likeliest one in practice: an administrator
    # creates the obvious record and not the second.
    v = t.check_dns("acme", BASE, ADDR,
                    t.StaticResolver(answers={"acme.rationalboxes.com": (ADDR,)}))
    assert not v.ok
    assert "acme-drive.rationalboxes.com" in v.blocking_reason
    assert [c.ok for c in v.checks] == [True, False]


def test_every_hostname_is_reported_not_just_the_first_failure():
    # An administrator fixing DNS needs the whole list, or they will make one
    # round trip per record and each round trip is a propagation wait.
    v = t.check_dns("acme", BASE, ADDR, t.StaticResolver(answers={}))
    assert len(v.checks) == 2
    assert all(c.detail for c in v.checks)


def test_a_resolver_error_does_not_pass():
    v = t.check_dns("acme", BASE, ADDR, t.StaticResolver(answers={}, error="SERVFAIL"))
    assert not v.ok
    assert "SERVFAIL" in v.blocking_reason


def test_the_local_resolver_reports_itself_as_not_authoritative():
    # Deliberate, and the most important line in the module: the stdlib resolver
    # cannot tell an authoritative answer from a cached one or from /etc/hosts.
    # Rather than pretend, it says so — which means the gate never passes on its
    # word, and an administrator who is sure must use the recorded override. The
    # alternative is a green tick backed by nothing.
    addrs, authoritative, detail = t.SystemResolver().addresses("localhost")
    assert authoritative is False
    assert detail


# ── the gate BLOCKS provisioning, which is the whole point ─────────────────


@pytest.mark.parametrize("state", [t.REQUESTED, t.AWAITING_DNS, t.PROVISIONING,
                                   t.LIVE, t.FAILED])
def test_provisioning_is_refused_unless_the_gate_passed(state):
    # THE test in this file. Everything above only matters because of this.
    req = _req(state=state)
    with pytest.raises(t.TenantError) as e:
        t.provisioning_job(req, requested_by=TEN)
    assert "rate limit" in str(e.value), "the refusal should say what it protects"


def test_a_verified_request_may_provision():
    req = _req()
    t.verify(req, _ready())
    assert req.state == t.VERIFIED and req.may_provision


def test_a_failed_check_leaves_the_request_waiting_not_verified():
    req = _req()
    t.verify(req, t.StaticResolver(answers={}))
    assert req.state == t.AWAITING_DNS
    assert not req.may_provision


def test_a_recheck_can_take_a_request_back_out_of_verified():
    # DNS can regress — a record edited, a zone reloaded, a TTL expiring onto a
    # stale value. Verified is a reading, not an achievement.
    req = _req()
    t.verify(req, _ready())
    assert req.may_provision
    t.verify(req, t.StaticResolver(answers={}))
    assert not req.may_provision


# ── the override: the one path that can burn the shared limit ──────────────


def test_an_override_needs_a_reason_and_an_actor():
    with pytest.raises(t.TenantError):
        t.override(_req(), by=TEN, reason="")
    with pytest.raises(t.TenantError):
        t.override(_req(), by="", reason="split-horizon DNS, verified by hand")


def test_an_override_unblocks_provisioning():
    req = _req()
    t.override(req, by=TEN, reason="CDN in front; apex verified out of band")
    assert req.may_provision
    assert t.provisioning_job(req, requested_by=TEN)["extra_vars"]["tenant_id"] == "acme"


def test_an_override_is_always_visible():
    # Never a quiet flag. If provisioning later fails at the certificate step and
    # consumes issuance for the domain, the record of who decided to skip the
    # check and why is the only way to understand it.
    req = _req()
    t.override(req, by=TEN, reason="zone is managed by the customer")
    shown = req.for_display()
    assert shown["override"] == {"by": TEN,
                                 "reason": "zone is managed by the customer"}


def test_an_override_survives_into_the_job():
    req = _req()
    t.override(req, by=TEN, reason="customer-managed zone")
    job = t.provisioning_job(req, requested_by=TEN)
    assert job["dns_overridden_by"] == TEN
    # The REASON, not just the actor. If this run burns the domain's issuance
    # limit, who pressed it is in the audit trail either way; what they believed
    # about the zone is the only thing that explains the decision.
    assert job["dns_override_reason"] == "customer-managed zone"
    assert job["dns_verified"] is False, "an override is not a verification"


def test_a_live_tenant_cannot_be_overridden_back_into_provisioning():
    with pytest.raises(t.TenantError):
        t.override(_req(state=t.LIVE), by=TEN, reason="because")


# ── the job is data for a runner, and carries no credentials (§5.3) ────────


def test_the_job_passes_parameters_as_structured_data():
    req = _req()
    t.verify(req, _ready())
    job = t.provisioning_job(req, requested_by=TEN)
    assert job["extra_vars"]["tenant_id"] == "acme"
    assert isinstance(job["extra_vars"], dict), "not a command line"
    assert "command" not in job and "argv" not in job and "shell" not in job


def test_the_job_carries_no_credential():
    req = _req()
    t.verify(req, _ready())
    blob = str(t.provisioning_job(req, requested_by=TEN)).lower()
    for secret in ("password", "vault", "secret", "token", "api_key", "private_key"):
        assert secret not in blob, f"the job should not carry {secret}"


def test_the_job_names_who_asked():
    req = _req()
    t.verify(req, _ready())
    assert t.provisioning_job(req, requested_by=TEN)["requested_by"] == TEN
    with pytest.raises(t.TenantError):
        t.provisioning_job(req, requested_by="")


# ── through the API ────────────────────────────────────────────────────────


def _cfg() -> Config:
    c = Config()
    c.jwt_secret = "deployment-tier-secret"
    c.token_audience = "fileengine-system-admin"
    c.require_mfa = True
    c.monitor_host = "127.0.0.1"
    c.audit_url = "http://audit:8097"
    c.bootstrap_owner = ""
    return c


def _client(resolver=None):
    d = StaticDeploymentDirectory()
    for who, roles in ((TEN, {SYSTEM_TENANTS}), (OBS, {SYSTEM_OBSERVER}),
                       (SEC, {SYSTEM_SECURITY})):
        d.passwords[who] = "pw"
        d.grants[who] = roles
    reg = AdministratorRegistry()
    bootstrap_owner(reg, "james@rationalboxes.com")
    return TestClient(build_app(_cfg(), reg, d, None, None,
                                resolver if resolver is not None else _ready()))


def _hdr(client, who=TEN):
    r = client.post("/v1/auth/token",
                    json={"subject": who, "password": "pw", "second_factor": "totp"})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['token']}"}


def _body(tenant_id="acme"):
    return {"tenant_id": tenant_id, "base_domain": BASE, "address": ADDR,
            "initial_admin": "admin@acme.test"}


def test_requesting_a_tenant_returns_the_records_to_create():
    c = _client()
    r = c.post("/v1/tenants", json=_body(), headers=_hdr(c))
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["state"] == t.REQUESTED
    assert not body["may_provision"]
    assert [rec["name"] for rec in body["records"]] == [
        "acme.rationalboxes.com", "acme-drive.rationalboxes.com"]
    assert all(rec["zone_line"] for rec in body["records"])


def test_the_api_refuses_to_provision_before_the_check():
    c = _client()
    h = _hdr(c)
    c.post("/v1/tenants", json=_body(), headers=h)
    r = c.post("/v1/tenants/acme/provision", headers=h)
    # 409, not 400: the request is well-formed, the SEQUENCE is wrong.
    assert r.status_code == 409
    assert "rate limit" in r.json()["detail"]


def test_the_api_provisions_after_a_passing_check():
    c = _client()
    h = _hdr(c)
    c.post("/v1/tenants", json=_body(), headers=h)
    assert c.post("/v1/tenants/acme/dns-check", headers=h).json()["may_provision"]
    r = c.post("/v1/tenants/acme/provision", headers=h)
    assert r.status_code == 202, "the work is REQUESTED, not done"
    assert r.json()["tenant"]["state"] == t.PROVISIONING
    assert r.json()["job"]["extra_vars"]["tenant_id"] == "acme"


def test_a_failing_check_through_the_api_still_blocks():
    c = _client(resolver=t.StaticResolver(answers={"acme.rationalboxes.com": (ADDR,)}))
    h = _hdr(c)
    c.post("/v1/tenants", json=_body(), headers=h)
    checked = c.post("/v1/tenants/acme/dns-check", headers=h).json()
    assert not checked["may_provision"]
    assert "acme-drive" in checked["dns"]["blocking_reason"]
    assert c.post("/v1/tenants/acme/provision", headers=h).status_code == 409


def test_the_override_route_requires_a_reason():
    c = _client(resolver=t.StaticResolver(answers={}))
    h = _hdr(c)
    c.post("/v1/tenants", json=_body(), headers=h)
    assert c.post("/v1/tenants/acme/dns-override", json={"reason": ""},
                  headers=h).status_code == 400
    r = c.post("/v1/tenants/acme/dns-override",
               json={"reason": "customer-managed zone, verified by hand"}, headers=h)
    assert r.status_code == 200
    assert r.json()["may_provision"]
    assert r.json()["override"]["by"] == TEN


def test_the_override_actor_comes_from_the_token_not_the_body():
    # There is no field for it, and that is the assertion: an override is
    # attributable to whoever authenticated, and a body-supplied name would make
    # the record worthless exactly when it matters.
    c = _client(resolver=t.StaticResolver(answers={}))
    h = _hdr(c)
    c.post("/v1/tenants", json=_body(), headers=h)
    r = c.post("/v1/tenants/acme/dns-override",
               json={"reason": "r", "by": "someone-else@example.com"}, headers=h)
    assert r.status_code == 200
    assert r.json()["override"]["by"] == TEN


def test_an_invalid_id_is_refused_at_the_route():
    c = _client()
    r = c.post("/v1/tenants", json=_body("Acme Corp"), headers=_hdr(c))
    assert r.status_code == 400


def test_a_duplicate_request_is_refused():
    c = _client()
    h = _hdr(c)
    assert c.post("/v1/tenants", json=_body(), headers=h).status_code == 201
    assert c.post("/v1/tenants", json=_body(), headers=h).status_code == 409


# ── authority ──────────────────────────────────────────────────────────────


@pytest.mark.parametrize("method,path,body", [
    ("post", "/v1/tenants", _body()),
    ("post", "/v1/tenants/acme/dns-check", None),
    ("post", "/v1/tenants/acme/dns-override", {"reason": "r"}),
    ("post", "/v1/tenants/acme/provision", None),
])
def test_only_system_tenants_may_change_anything(method, path, body):
    # system_security reads the whole estate and may not create a tenant;
    # system_tenants creates tenants and may not read the security view. The
    # roles are additive and unordered, and neither implies the other.
    c = _client()
    for who in (OBS, SEC):
        r = getattr(c, method)(path, json=body, headers=_hdr(c, who))
        assert r.status_code == 403, f"{who} should not reach {path}"


def test_the_observer_baseline_can_watch_but_not_act():
    # A tenant stuck part-way through creation is exactly the outstanding thing
    # §3.2 exists to surface, and noticing it needs no authority to change it.
    c = _client()
    c.post("/v1/tenants", json=_body(), headers=_hdr(c, TEN))
    h = _hdr(c, OBS)
    assert c.get("/v1/tenants", headers=h).status_code == 200
    assert c.get("/v1/tenants/acme", headers=h).json()["tenant_id"] == "acme"
    assert c.get("/v1/tenants/acme/records", headers=h).status_code == 200
    assert c.post("/v1/tenants/acme/dns-check", headers=h).status_code == 403


def test_an_unauthenticated_caller_reaches_nothing():
    c = _client()
    assert c.get("/v1/tenants").status_code in (401, 403)
    assert c.post("/v1/tenants", json=_body()).status_code in (401, 403)


def test_an_unknown_tenant_is_404_not_500():
    c = _client()
    h = _hdr(c)
    assert c.post("/v1/tenants/nosuch/dns-check", headers=h).status_code == 404
    assert c.get("/v1/tenants/nosuch", headers=_hdr(c, OBS)).status_code == 404
