# Copyright (C) 2026 James Hickman
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Readiness refuses to serve a cross-tenant console on an unsafe configuration.

These assert the §7 prerequisites that are checkable from inside the process.
They are the first tests deliberately: everything this application will later do
is more dangerous than what it does today, and the conditions under which it may
run should be settled before any of it exists.
"""
from fastapi.testclient import TestClient

from admin_master_control.administrators import AdministratorRegistry, bootstrap_owner
from admin_master_control.app import build_monitoring
from admin_master_control.auth import StaticDeploymentDirectory
from admin_master_control.config import Config


def _cfg(**over) -> Config:
    c = Config()
    c.jwt_secret = "test-secret"
    c.token_audience = "fileengine-system-admin"
    c.require_mfa = True
    c.monitor_host = "127.0.0.1"
    c.audit_url = "http://audit:8090"
    # A second factor is required (the default), so it must also be CHECKABLE.
    # Readiness reports "required but no store configured" otherwise, which is the
    # point: enforcement that cannot reach its source refuses every login.
    c.mfa_url = "http://ldap-manager:8093"
    c.mfa_internal_secret = "internal-shared-secret"
    for k, v in over.items():
        setattr(c, k, v)
    return c


OWNER = "james@rationalboxes.com"


def _owned() -> AdministratorRegistry:
    """A ledger recording the owner. NOT what readiness asks any more."""
    r = AdministratorRegistry()
    bootstrap_owner(r, OWNER)
    return r


def _owned_directory() -> StaticDeploymentDirectory:
    """A directory in which someone actually owns the deployment.

    Readiness asks THIS, not the ledger — the directory is authoritative. A
    ledger naming an owner the directory does not honour is drift, not
    readiness, which is why the two fixtures are separate rather than one
    helper that seeds both.
    """
    d = StaticDeploymentDirectory()
    d.passwords[OWNER] = "pw"
    d.grants[OWNER] = {"system_owner"}
    return d


def test_ready_when_configured():
    r = TestClient(build_monitoring(_cfg(), _owned(), _owned_directory())).get("/readyz")
    assert r.status_code == 200 and r.json()["status"] == "ready"


def test_not_ready_without_an_owner_in_the_directory():
    # system_owner is the only role that creates authority, so a deployment
    # without one cannot grant anything to anybody. That is not a degraded
    # console, it is a stranded one, and the only way out is the directory.
    r = TestClient(build_monitoring(_cfg(), AdministratorRegistry(),
                                    StaticDeploymentDirectory())).get("/readyz")
    assert r.status_code == 503
    assert any("system_owner" in p for p in r.json()["problems"])


def test_the_owner_condition_is_reported_alongside_the_others():
    # A deployment can be unsafe for several reasons at once and should be told
    # all of them, not the first one somebody checked.
    r = TestClient(build_monitoring(_cfg(jwt_secret=""), AdministratorRegistry(),
                                    StaticDeploymentDirectory())).get("/readyz")
    problems = r.json()["problems"]
    assert any("token secret" in p for p in problems)
    assert any("system_owner" in p for p in problems)


def test_healthz_does_not_imply_ready():
    # A liveness probe answering does not mean it is safe to serve; the two are
    # separate questions and conflating them is how an unsafe deployment looks
    # healthy.
    c = _cfg(jwt_secret="")
    mon = TestClient(build_monitoring(c, _owned(), _owned_directory()))
    assert mon.get("/healthz").status_code == 200
    assert mon.get("/readyz").status_code == 503


def test_mfa_is_not_optional_at_this_tier():
    r = TestClient(build_monitoring(_cfg(require_mfa=False), _owned(), _owned_directory())).get("/readyz")
    assert r.status_code == 503
    assert any("MFA" in p for p in r.json()["problems"])


def test_distinct_audience_is_required():
    # Without one, a tenant token could be accepted by a cross-tenant console.
    r = TestClient(build_monitoring(_cfg(token_audience=""), _owned(), _owned_directory())).get("/readyz")
    assert r.status_code == 503
    assert any("audience" in p for p in r.json()["problems"])


def test_monitoring_must_be_loopback():
    r = TestClient(build_monitoring(_cfg(monitor_host="0.0.0.0"), _owned(), _owned_directory())).get("/readyz")
    assert r.status_code == 503
    assert any("loopback" in p for p in r.json()["problems"])


def test_problems_are_reported_together():
    # A deployment with three faults should learn all three, not discover them
    # one redeploy at a time.
    c = _cfg(jwt_secret="", require_mfa=False, monitor_host="0.0.0.0")
    r = TestClient(build_monitoring(c, _owned(), _owned_directory())).get("/readyz")
    assert r.status_code == 503 and len(r.json()["problems"]) >= 3


def _served(app):
    """(METHOD, path) for everything the app actually serves.

    Read from the OpenAPI schema rather than walking ``app.routes``: this
    FastAPI version keeps an included router as an opaque object rather than
    flattening its routes, so walking the list finds nothing and the assertion
    passes vacuously. The schema is what is served.
    """
    spec = app.openapi()
    return {(m.upper(), path)
            for path, ops in spec.get("paths", {}).items()
            for m in ops}


def test_only_phase_one_routes_are_mounted():
    # This replaced "no routes are mounted yet", which was right while nothing
    # was built and is the wrong assertion now that phase 1 is. The property
    # worth keeping is the same one: a route arriving without its security
    # review should be a FAILING TEST rather than a quiet addition.
    #
    # The list is exhaustive and must be edited deliberately. Phase 2-4 routes
    # (queue, decisions, exclusions, decommissioning) appearing here without
    # their review will fail this.
    from admin_master_control.app import build_app
    assert _served(build_app(_cfg(), _owned())) == {
        ("POST", "/v1/auth/token"),
        # §6, the second factor. Three routes, and they are the ONLY ones a
        # challenge token reaches — a challenge carries a different audience, so
        # it is structurally not a session.
        ("POST", "/v1/auth/mfa/enroll/begin"),
        ("POST", "/v1/auth/mfa/enroll/complete"),
        ("POST", "/v1/auth/mfa/verify"),
        ("GET", "/v1/whoami"),
        ("GET", "/v1/administrators"),
        ("GET", "/v1/administrators/{subject}/history"),
        ("GET", "/v1/roles"),
        ("POST", "/v1/grants"),
        ("POST", "/v1/revocations"),
        # §3.4, the cross-tenant security view. Read-only, gated on
        # system_security rather than the observer baseline.
        ("GET", "/v1/security/incidents"),
        ("GET", "/v1/security/campaigns"),
        # §3.2 / §4, the queue of things waiting on a human. The transition POST
        # writes to audit_service's queue and executes nothing.
        ("GET", "/v1/security/queue"),
        ("GET", "/v1/security/backlog"),
        ("GET", "/v1/security/queue/{incident_id}"),
        ("POST", "/v1/security/queue/transition"),
        # §3.3.2, the redaction register. Read-only, and names the file by uuid.
        ("GET", "/v1/redactions"),
        # §3.4a, tenant setup. The three POSTs beyond the request are the DNS
        # gate, the recorded override of it, and the job hand-off — reviewed
        # below, because they are the first routes in this application whose
        # effect leaves it.
        ("POST", "/v1/tenants"),
        ("GET", "/v1/tenants"),
        ("GET", "/v1/tenants/{tenant_id}"),
        ("GET", "/v1/tenants/{tenant_id}/records"),
        ("POST", "/v1/tenants/{tenant_id}/dns-check"),
        ("POST", "/v1/tenants/{tenant_id}/dns-override"),
        ("POST", "/v1/tenants/{tenant_id}/provision"),
        # The queue the runner reads. A top-level path rather than /tenants/jobs,
        # which would collide with /tenants/{tenant_id} and be resolved by
        # declaration order.
        ("GET", "/v1/provisioning-jobs"),
    }


def test_every_write_is_a_record_or_a_request_never_an_execution():
    # This was `test_phase_one_writes_nothing_outside_its_own_ledger`, and the
    # rename is the honest part: with §3.4a that assertion is no longer TRUE.
    # `/v1/tenants/{id}/provision` writes a job that a runner will execute, and
    # a playbook run reaches a real DNS zone, a real certificate authority and a
    # real database. Widening the old list and keeping its name would have left a
    # test claiming a property the application had stopped having.
    #
    # The property that survives — and the one §5.3 actually asks for — is that
    # every write here is a RECORD of a decision or a REQUEST for work, never the
    # work. This application holds no vault password, no DNS credential and no
    # Ansible inventory, so there is nothing it could execute even if a route
    # tried.
    from admin_master_control.app import build_app
    writes = {path for method, path in _served(build_app(_cfg(), _owned()))
              if method in {"POST", "PUT", "PATCH", "DELETE"}}
    assert writes == {
        "/v1/auth/token",
        # The second factor. These write to ldap_manager's `user_2fa` — an
        # enrolment, which is a record of a credential this administrator now
        # holds, not an action taken on the estate.
        "/v1/auth/mfa/enroll/begin",
        "/v1/auth/mfa/enroll/complete",
        "/v1/auth/mfa/verify",
        # Records, in this application's own append-only ledger.
        "/v1/grants",
        "/v1/revocations",
        # Records a DECISION in audit_service's queue. Executes nothing: an
        # approved redaction is carried out by the cloud-B application, behind
        # its own human step.
        "/v1/security/queue/transition",
        # Records a request and the state of its DNS gate. No effect outside this
        # application: the administrator creates the records by hand, wherever
        # the domain is managed.
        "/v1/tenants",
        "/v1/tenants/{tenant_id}/dns-check",
        "/v1/tenants/{tenant_id}/dns-override",
        # REQUESTS work. The one route whose effect leaves this application, and
        # it leaves as a queued job for a runner that holds the credentials this
        # application deliberately does not.
        "/v1/tenants/{tenant_id}/provision",
    }


def test_nothing_here_can_destroy_a_tenant():
    # §8.1's "no destructive capability", kept as its own assertion now that
    # tenant routes exist. §3.4b decommissioning is phase 4 and behind
    # re-authentication; until it is reviewed, no DELETE may exist at all, and
    # no route may spell suspension or decommissioning.
    from admin_master_control.app import build_app
    served = _served(build_app(_cfg(), _owned()))
    assert not [p for m, p in served if m == "DELETE"], "no DELETE has been reviewed"
    for _, path in served:
        for forbidden in ("decommission", "suspend", "destroy", "purge"):
            assert forbidden not in path, f"{path} needs its own §3.4b review"


def test_no_route_can_execute_a_playbook_because_nothing_here_can():
    # The structural half of the claim above: grep the package for the tools that
    # would be needed to run the work rather than request it. A route that tried
    # would have to import one of these, and this fails before it can be written.
    import pathlib

    import admin_master_control
    pkg = pathlib.Path(admin_master_control.__file__).parent
    for src in pkg.rglob("*.py"):
        text = src.read_text()
        for tool in ("ansible-playbook", "subprocess", "os.system", "pexpect",
                     "vault_password", "certbot"):
            assert tool not in text, (
                f"{src.name} references {tool!r}: provisioning is REQUESTED here "
                f"and executed by the runner (§5.3)")
