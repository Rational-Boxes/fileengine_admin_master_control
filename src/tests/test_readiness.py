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
        ("GET", "/v1/whoami"),
        ("GET", "/v1/administrators"),
        ("GET", "/v1/administrators/{subject}/history"),
        ("GET", "/v1/roles"),
        ("POST", "/v1/grants"),
        ("POST", "/v1/revocations"),
    }


def test_phase_one_writes_nothing_outside_its_own_ledger():
    # §8.1: "No writes, no decisions, no destructive capability." The two POSTs
    # beyond the login touch this application's own grant ledger and nothing
    # else. Anything reaching a tenant, a bucket or a playbook belongs to a
    # later phase and a separate review.
    from admin_master_control.app import build_app
    writes = {path for method, path in _served(build_app(_cfg(), _owned()))
              if method in {"POST", "PUT", "PATCH", "DELETE"}}
    assert writes == {"/v1/auth/token", "/v1/grants", "/v1/revocations"}
