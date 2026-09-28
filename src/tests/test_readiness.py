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

from admin_master_control.app import build_monitoring
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


def test_ready_when_configured():
    r = TestClient(build_monitoring(_cfg())).get("/readyz")
    assert r.status_code == 200 and r.json()["status"] == "ready"


def test_healthz_does_not_imply_ready():
    # A liveness probe answering does not mean it is safe to serve; the two are
    # separate questions and conflating them is how an unsafe deployment looks
    # healthy.
    c = _cfg(jwt_secret="")
    mon = TestClient(build_monitoring(c))
    assert mon.get("/healthz").status_code == 200
    assert mon.get("/readyz").status_code == 503


def test_mfa_is_not_optional_at_this_tier():
    r = TestClient(build_monitoring(_cfg(require_mfa=False))).get("/readyz")
    assert r.status_code == 503
    assert any("MFA" in p for p in r.json()["problems"])


def test_distinct_audience_is_required():
    # Without one, a tenant token could be accepted by a cross-tenant console.
    r = TestClient(build_monitoring(_cfg(token_audience=""))).get("/readyz")
    assert r.status_code == 503
    assert any("audience" in p for p in r.json()["problems"])


def test_monitoring_must_be_loopback():
    r = TestClient(build_monitoring(_cfg(monitor_host="0.0.0.0"))).get("/readyz")
    assert r.status_code == 503
    assert any("loopback" in p for p in r.json()["problems"])


def test_problems_are_reported_together():
    # A deployment with three faults should learn all three, not discover them
    # one redeploy at a time.
    c = _cfg(jwt_secret="", require_mfa=False, monitor_host="0.0.0.0")
    r = TestClient(build_monitoring(c)).get("/readyz")
    assert r.status_code == 503 and len(r.json()["problems"]) >= 3


def test_no_routes_are_mounted_yet():
    # The application mounts nothing until a phase is built. Asserted so that a
    # route arriving without its security review is a failing test rather than a
    # quiet addition.
    from admin_master_control.app import build_app
    paths = {r.path for r in build_app(_cfg()).routes}
    assert not any(p.startswith("/v1") or p.startswith("/admin") for p in paths)
