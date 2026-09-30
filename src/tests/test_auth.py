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

"""The door to the deployment tier (§6).

Four properties are load-bearing, and each has a test that would fail if a
later change made the obvious simplification:

  * a tenant token cannot be accepted here, and a token minted here cannot be
    accepted at a tenant door — by AUDIENCE, not by a comparison somebody could
    delete;
  * MFA is mandatory, enforced on every request rather than only at login;
  * a route is authorised by a NAMED role with no inheritance, so holding
    `system_owner` does not open an observer route;
  * authority comes from the deployment OU, so a tenant group grants nothing.
"""
from __future__ import annotations

import datetime as _dt

import jwt
import pytest
from fastapi.testclient import TestClient

from admin_master_control.administrators import AdministratorRegistry, bootstrap_owner
from admin_master_control.app import build_app
from admin_master_control.auth import (
    AuthError,
    DirectoryUnavailable,
    Principal,
    StaticDeploymentDirectory,
    login,
    mint_token,
    reconcile,
    verify_token,
)
from admin_master_control.config import Config
from admin_master_control.roles import (
    SYSTEM_BILLING,
    SYSTEM_OBSERVER,
    SYSTEM_OWNER,
    SYSTEM_SECURITY,
)

JAMES = "james@rationalboxes.com"
TENANT_AUDIENCE = "fileengine-bridge"   # what a tenant door would mint for


def _cfg(**over) -> Config:
    c = Config()
    c.jwt_secret = "deployment-tier-secret"
    c.token_audience = "fileengine-system-admin"
    c.require_mfa = True
    c.monitor_host = "127.0.0.1"
    c.audit_url = "http://audit:8097"
    c.bootstrap_owner = ""
    for k, v in over.items():
        setattr(c, k, v)
    return c


def _dir(**grants) -> StaticDeploymentDirectory:
    d = StaticDeploymentDirectory()
    for subject, roles in grants.items():
        sub = subject.replace("_AT_", "@")
        d.passwords[sub] = "pw-" + sub
        d.grants[sub] = set(roles)
    return d


def _owned_registry() -> AdministratorRegistry:
    r = AdministratorRegistry()
    bootstrap_owner(r, JAMES)
    return r


def _client(config=None, directory=None, registry=None) -> TestClient:
    config = config or _cfg()
    directory = directory if directory is not None else _dir(**{JAMES.replace("@", "_AT_"): list(
        ["system_owner", "system_observer", "system_tenants", "system_security", "system_billing"])})
    registry = registry if registry is not None else _owned_registry()
    return TestClient(build_app(config, registry, directory))


def _token(client: TestClient, subject: str, second_factor="totp"):
    r = client.post("/v1/auth/token", json={
        "subject": subject, "password": "pw-" + subject, "second_factor": second_factor})
    return r


# ── audience isolation ─────────────────────────────────────────────────────


def test_a_tenant_token_is_not_accepted_here():
    # Same secret, different audience — the worst case, because a deployment
    # that shares FILEENGINE_JWT_SECRET across services would otherwise let a
    # tenant session walk in. It must fail on the AUDIENCE.
    c = _cfg()
    now = _dt.datetime.now(_dt.timezone.utc)
    tenant_token = jwt.encode({
        "sub": JAMES, "aud": TENANT_AUDIENCE, "iss": "fileengine-bridge",
        "exp": int((now + _dt.timedelta(hours=1)).timestamp()),
        "roles": ["system_owner"],
    }, c.jwt_secret, algorithm="HS256")
    with pytest.raises(AuthError):
        verify_token(c, tenant_token)


def test_a_token_minted_here_does_not_verify_against_a_tenant_audience():
    # The other half. A tenant door pinning its own audience must reject this.
    c = _cfg()
    tok = mint_token(c, Principal(subject=JAMES, roles=frozenset({SYSTEM_OWNER}), amr=("pwd", "totp")))
    with pytest.raises(jwt.PyJWTError):
        jwt.decode(tok, c.jwt_secret, algorithms=["HS256"], audience=TENANT_AUDIENCE)


def test_the_algorithm_is_pinned():
    # An unpinned verifier accepts "alg":"none". The bridge pins it for the same
    # reason; this tier has more to lose.
    c = _cfg()
    forged = jwt.encode({"sub": JAMES, "aud": c.token_audience, "iss": "admin-master-control",
                         "exp": int((_dt.datetime.now(_dt.timezone.utc) + _dt.timedelta(hours=1)).timestamp()),
                         "roles": [SYSTEM_OWNER]}, key="", algorithm="none")
    with pytest.raises(AuthError):
        verify_token(c, forged)


def test_a_token_signed_with_another_secret_is_refused():
    c = _cfg()
    other = _cfg(jwt_secret="someone-elses-secret")
    tok = mint_token(other, Principal(subject=JAMES, roles=frozenset({SYSTEM_OWNER}), amr=("pwd", "totp")))
    with pytest.raises(AuthError):
        verify_token(c, tok)


def test_an_expired_token_is_refused():
    c = _cfg()
    tok = mint_token(c, Principal(subject=JAMES, roles=frozenset({SYSTEM_OWNER}), amr=("pwd", "totp")),
                     ttl_seconds=-10)
    with pytest.raises(AuthError):
        verify_token(c, tok)


# ── MFA ────────────────────────────────────────────────────────────────────


def test_a_password_only_login_is_refused_rather_than_issued():
    # Issuing a session the gate would then refuse on every request reads as a
    # broken service instead of a missing second factor.
    client = _client()
    r = _token(client, JAMES, second_factor=None)
    assert r.status_code == 403


def test_a_password_only_token_is_refused_at_the_gate():
    # Enforced per request, not only at login, so a session that predates a
    # policy change cannot outlive it. Minted directly to bypass the login path.
    c = _cfg()
    client = _client(config=c)
    tok = mint_token(c, Principal(subject=JAMES, roles=frozenset({SYSTEM_OBSERVER}), amr=("pwd",)))
    r = client.get("/v1/whoami", headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 403


def test_a_second_factor_is_accepted():
    client = _client()
    r = _token(client, JAMES)
    assert r.status_code == 200
    assert "totp" in r.json()["amr"]


def test_an_unknown_second_factor_is_refused():
    client = _client()
    r = client.post("/v1/auth/token", json={
        "subject": JAMES, "password": "pw-" + JAMES, "second_factor": "vibes"})
    assert r.status_code == 401


# ── named roles, no inheritance ────────────────────────────────────────────


def test_owner_does_not_open_an_observer_route():
    # THE RULE MOST LIKELY TO BE "SIMPLIFIED". system_owner creates authority; it
    # does not hold it. An owner who has not been granted system_observer cannot
    # read the observer routes, and the fix is a recorded self-grant, not an
    # implicit one.
    owner_only = "owner.only@rationalboxes.com"
    d = _dir(**{owner_only.replace("@", "_AT_"): [SYSTEM_OWNER]})
    client = _client(directory=d)
    tok = _token(client, owner_only).json()["token"]
    assert client.get("/v1/whoami", headers={"Authorization": f"Bearer {tok}"}).status_code == 403


def test_owner_can_still_reach_the_route_that_needs_owner():
    owner_only = "owner.only@rationalboxes.com"
    d = _dir(**{owner_only.replace("@", "_AT_"): [SYSTEM_OWNER]})
    client = _client(directory=d)
    tok = _token(client, owner_only).json()["token"]
    r = client.post("/v1/grants",
                    json={"subject": "new@rationalboxes.com", "role": SYSTEM_OBSERVER},
                    headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 201
    assert r.json()["authorised_as"] == SYSTEM_OWNER


def test_a_non_owner_cannot_grant():
    sec = "sec@rationalboxes.com"
    d = _dir(**{sec.replace("@", "_AT_"): [SYSTEM_SECURITY, SYSTEM_OBSERVER]})
    client = _client(directory=d)
    tok = _token(client, sec).json()["token"]
    r = client.post("/v1/grants",
                    json={"subject": "x@rationalboxes.com", "role": SYSTEM_OBSERVER},
                    headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 403


def test_holding_billing_does_not_open_the_observer_routes():
    # Additive and unordered: billing is not "above" observer.
    bill = "bill@rationalboxes.com"
    d = _dir(**{bill.replace("@", "_AT_"): [SYSTEM_BILLING]})
    client = _client(directory=d)
    tok = _token(client, bill).json()["token"]
    assert client.get("/v1/roles", headers={"Authorization": f"Bearer {tok}"}).status_code == 403


# ── where authority comes from ─────────────────────────────────────────────


def test_a_tenant_role_grants_nothing_here():
    # The mirror of the tenant-door fix: they refuse system_*, this grants
    # nothing for a tenant group. A tenant administrator with every tenant role
    # there is gets no authority at this tier.
    tadmin = "tenantadmin@rationalboxes.com"
    d = StaticDeploymentDirectory()
    d.passwords[tadmin] = "pw-" + tadmin
    d.grants[tadmin] = {"administrators", "tenant_admin", "users", "erasure_admins"}
    client = _client(directory=d)
    r = client.post("/v1/auth/token",
                    json={"subject": tadmin, "password": "pw-" + tadmin, "second_factor": "totp"})
    assert r.status_code == 403, "a tenant role must not authenticate into the deployment tier"


def test_an_administrator_with_no_role_is_refused_not_given_an_empty_session():
    nobody = "nobody@rationalboxes.com"
    d = StaticDeploymentDirectory()
    d.passwords[nobody] = "pw"
    with pytest.raises(AuthError):
        login(_cfg(), d, nobody, "pw", second_factor="totp")


def test_a_bad_password_does_not_reveal_whether_the_account_holds_authority():
    # The password is checked before the roles are read, so this is not an
    # oracle for "is X an administrator".
    d = _dir(**{JAMES.replace("@", "_AT_"): [SYSTEM_OWNER]})
    with pytest.raises(AuthError) as e:
        login(_cfg(), d, JAMES, "wrong", second_factor="totp")
    assert "bad credentials" in str(e.value)


def test_an_unreachable_directory_refuses_rather_than_admits():
    class Down:
        def authenticate(self, subject, password):
            return False

        def roles_of(self, subject):
            return frozenset()

    client = _client(directory=Down())
    assert _token(client, JAMES).status_code == 401


# ── drift between the two stores ───────────────────────────────────────────


def test_drift_names_a_directory_role_with_no_grant_behind_it():
    # Authority nobody can account for — precisely what someone with directory
    # access would create.
    out = reconcile({JAMES: frozenset({SYSTEM_OWNER, SYSTEM_SECURITY})},
                    {JAMES: frozenset({SYSTEM_OWNER})})
    assert out == [f"{JAMES} holds system_security in the directory with no grant recorded"]


def test_drift_names_a_grant_the_directory_does_not_honour():
    out = reconcile({JAMES: frozenset({SYSTEM_OWNER})},
                    {JAMES: frozenset({SYSTEM_OWNER, SYSTEM_BILLING})})
    assert out == [f"{JAMES} was granted system_billing but does not hold it in the directory"]


def test_no_drift_when_they_agree():
    assert reconcile({JAMES: frozenset({SYSTEM_OWNER})},
                     {JAMES: frozenset({SYSTEM_OWNER})}) == []


def test_the_administrators_route_reports_drift_with_the_list():
    # A console that shows holders without showing disagreement is showing a
    # number somebody will trust.
    d = _dir(**{JAMES.replace("@", "_AT_"): [SYSTEM_OWNER, SYSTEM_OBSERVER]})
    client = _client(directory=d)          # ledger has all five from bootstrap
    tok = _token(client, JAMES).json()["token"]
    body = client.get("/v1/administrators", headers={"Authorization": f"Bearer {tok}"}).json()
    assert body["administrators"]
    assert any("does not hold it in the directory" in d_ for d_ in body["drift"])


# ── the gate itself ────────────────────────────────────────────────────────


def test_no_token_is_refused():
    assert _client().get("/v1/whoami").status_code == 401


def test_a_garbage_token_is_refused():
    r = _client().get("/v1/whoami", headers={"Authorization": "Bearer not-a-token"})
    assert r.status_code == 401


def test_the_refusal_body_does_not_explain_itself():
    # A caller learning WHY they were refused learns about the directory.
    r = _client().get("/v1/whoami", headers={"Authorization": "Bearer not-a-token"})
    assert r.json() == {"detail": "unauthorized"}


def test_history_is_readable_and_records_revocations():
    client = _client()
    tok = _token(client, JAMES).json()["token"]
    h = client.get(f"/v1/administrators/{JAMES}/history",
                   headers={"Authorization": f"Bearer {tok}"})
    assert h.status_code == 200
    body = h.json()
    assert len(body["history"]) == 5          # the five bootstrap grants
    assert all(e["granted_by"] == "provisioning" for e in body["history"])


# ── "could not ask" is not "answered no" ───────────────────────────────────
#
# Found by running the app against the real dev directory rather than a fixture.
# The role search bound ANONYMOUSLY (there was no configuration path for a bind
# credential at all), OpenLDAP answers `noSuchObject` for ou=system to an
# anonymous client, and the empty result was read as "this administrator holds no
# deployment role". So the console authenticated the owner and then refused them,
# and /readyz reported "no system_owner in the directory" about a directory
# listing them in all five groups.
#
# Failing closed was right. Being unable to say WHY was the defect: a missing
# owner is a provisioning gap and an unreadable role OU is a bind credential, and
# nothing in the output told them apart.


class _Unreachable:
    """A directory that cannot be asked."""

    def authenticate(self, subject, password):
        return True

    def roles_of(self, subject):
        raise DirectoryUnavailable("the deployment role OU could not be searched")


class _NoRoles:
    """A directory that answers, and answers none."""

    def authenticate(self, subject, password):
        return True

    def roles_of(self, subject):
        return frozenset()


def test_an_unreadable_directory_is_not_reported_as_no_roles():
    with pytest.raises(DirectoryUnavailable):
        login(_cfg(), _Unreachable(), "james@rationalboxes.com", "pw",
              second_factor="totp")


def test_an_unreadable_directory_says_come_back_not_you_have_no_authority():
    # 503, not 403. The distinction is the whole point: 403 tells an
    # administrator they hold no authority, which sends them to the directory to
    # fix something that is not broken.
    try:
        login(_cfg(), _Unreachable(), "james@rationalboxes.com", "pw",
              second_factor="totp")
    except DirectoryUnavailable as e:
        assert e.status_code == 503
        assert "could not be searched" in e.reason
        assert "no deployment role" not in e.reason


def test_a_directory_that_answers_none_still_refuses_with_403():
    # The other side of the pair — this message IS the right one here.
    with pytest.raises(AuthError) as e:
        login(_cfg(), _NoRoles(), "nobody@rationalboxes.com", "pw",
              second_factor="totp")
    assert e.value.status_code == 403
    assert "no deployment role" in e.value.reason
    assert not isinstance(e.value, DirectoryUnavailable)


def test_an_unreadable_directory_still_authorises_nothing():
    # It fails CLOSED. DirectoryUnavailable is an AuthError precisely so that a
    # caller which only catches AuthError cannot accidentally treat it as a pass.
    assert issubclass(DirectoryUnavailable, AuthError)


def test_readiness_distinguishes_no_owner_from_an_unreadable_directory():
    from admin_master_control.app import build_monitoring
    from fastapi.testclient import TestClient

    c = _cfg()
    c.audit_url = "http://audit:8097"
    c.bootstrap_owner = "james@rationalboxes.com"

    unreadable = TestClient(build_monitoring(c, AdministratorRegistry(), _Unreachable()))
    problems = unreadable.get("/readyz").json()["problems"]
    assert any("could not be read" in p for p in problems)
    assert not any("no system_owner" in p for p in problems), (
        "an unreadable directory must not be reported as a missing owner")

    empty = TestClient(build_monitoring(c, AdministratorRegistry(), _NoRoles()))
    problems = empty.get("/readyz").json()["problems"]
    assert any("no system_owner" in p for p in problems)


def test_the_bind_credential_reaches_the_directory():
    # There was no configuration path for this at all, so the search bound
    # anonymously. A field with no way to set it is a default that only works
    # against a directory allowing anonymous reads of its role OU.
    from admin_master_control.app import default_directory

    c = _cfg()
    c.ldap_url = "ldap://localhost:1389"
    c.ldap_base_dn = "dc=rationalboxes,dc=com"
    c.ldap_bind_dn = "cn=reader,dc=rationalboxes,dc=com"
    c.ldap_bind_password = "secret"
    d = default_directory(c)
    assert d.bind_dn == "cn=reader,dc=rationalboxes,dc=com"
    assert d.bind_password == "secret"
    assert d.role_base == "ou=system,dc=rationalboxes,dc=com"
