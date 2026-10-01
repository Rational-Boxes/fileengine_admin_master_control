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

from . import _harness
from admin_master_control.administrators import AdministratorRegistry, bootstrap_owner
from admin_master_control.app import build_app
from admin_master_control.auth import (
    CHALLENGE_VERIFY,
    AuthError,
    DirectoryUnavailable,
    Principal,
    mint_challenge,
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
    # A second factor is required (the default), so it must also be CHECKABLE.
    # Readiness reports "required but no store configured" otherwise, which is the
    # point: enforcement that cannot reach its source refuses every login.
    c.mfa_url = "http://ldap-manager:8093"
    c.mfa_internal_secret = "internal-shared-secret"
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


def _client(config=None, directory=None, registry=None, factors=None) -> TestClient:
    config = config or _cfg()
    directory = directory if directory is not None else _dir(**{JAMES.replace("@", "_AT_"): list(
        ["system_owner", "system_observer", "system_tenants", "system_security", "system_billing"])})
    registry = registry if registry is not None else _owned_registry()
    # An explicit factor store, always. Left to default it would build the LIVE
    # ldap_manager client from _cfg()'s url and every login would make a real HTTP
    # call that times out — which is how this suite went from 3 seconds to 37.
    factors = factors if factors is not None else _harness.factors(JAMES)
    return TestClient(build_app(config, registry, directory, None, None, None, factors))


def _password_only(client: TestClient, subject: str):
    """Step one alone. Never a session while a factor is required."""
    return client.post("/v1/auth/token",
                       json={"subject": subject, "password": "pw-" + subject})


def _session(client: TestClient, subject: str) -> dict:
    """The full two-step login."""
    return _harness.login(client, subject, "pw-" + subject)


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


# ── MFA: verified, not claimed (§6) ────────────────────────────────────────
#
# `AMC_REQUIRE_MFA` used to mean the caller had SAID they used a factor.
# `second_factor` was a string, checked against a set of factor NAMES and folded
# into the signed amr, so {"second_factor":"totp"} bought a fully MFA-marked
# token on the console that reads every tenant's audit. These tests are what
# stops that coming back — the first one is the whole point of the change.


def test_a_correct_password_alone_never_returns_a_session():
    # THE test. Not "a password-only login is refused" — refused is not enough,
    # because the old code refused only when the caller declined to CLAIM a
    # factor. What matters is that no response to a password contains a token.
    client = _client()
    r = _password_only(client, JAMES)
    assert r.status_code == 401
    body = r.json()
    assert "token" not in body, "a password alone must not yield a session"
    assert body["status"] == "verify"
    assert body["challenge_token"]


def test_a_claimed_factor_is_not_a_factor():
    # The exact hole, asserted closed. The field no longer exists, so a caller
    # sending it gets the challenge like anybody else rather than a token.
    client = _client()
    r = client.post("/v1/auth/token", json={
        "subject": JAMES, "password": "pw-" + JAMES, "second_factor": "totp"})
    assert r.status_code == 401
    assert "token" not in r.json()


def test_a_challenge_token_is_not_a_session():
    # Structural, not conditional: a challenge carries a different `aud` and
    # PyJWT is given the audience to validate, so it cannot be spent as a session
    # on any route however the gate is later refactored.
    client = _client()
    challenge = _password_only(client, JAMES).json()["challenge_token"]
    r = client.get("/v1/whoami", headers={"Authorization": f"Bearer {challenge}"})
    assert r.status_code in (401, 403)
    with pytest.raises(AuthError):
        verify_token(_cfg(), challenge)


def test_the_right_code_completes_the_login():
    client = _client()
    body = _session(client, JAMES)
    assert "totp" in body["amr"]
    assert client.get("/v1/whoami",
                      headers={"Authorization": f"Bearer {body['token']}"}).status_code == 200


def test_the_wrong_code_does_not():
    client = _client()
    challenge = _password_only(client, JAMES).json()["challenge_token"]
    r = client.post("/v1/auth/mfa/verify",
                    json={"challenge_token": challenge, "code": "000000", "method": "totp"})
    assert r.status_code == 401
    assert "token" not in r.json()


def test_a_method_this_tier_excludes_cannot_be_reached_by_naming_it():
    # `email` is permitted elsewhere in the platform and deliberately not here:
    # it is the weakest path and this is the highest-trust console. An allowlist
    # rather than a denylist, so it cannot be reached by asking for it.
    client = _client()
    challenge = _password_only(client, JAMES).json()["challenge_token"]
    r = client.post("/v1/auth/mfa/verify",
                    json={"challenge_token": challenge, "code": "123456", "method": "email"})
    assert r.status_code == 400
    assert "email" in r.json()["detail"]


def test_a_password_only_token_is_refused_at_the_gate():
    # Enforced per request, not only at login, so a session that predates a
    # policy change cannot outlive it. Minted directly to bypass the login path.
    c = _cfg()
    client = _client(config=c)
    tok = mint_token(c, Principal(subject=JAMES, roles=frozenset({SYSTEM_OBSERVER}), amr=("pwd",)))
    r = client.get("/v1/whoami", headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 403


# ── enrolment is forced on first login ─────────────────────────────────────


def test_an_administrator_with_no_factor_must_enrol_before_anything_else():
    # "If 2FA is not disabled require setup on first login." Not admitted and
    # nagged — admitted to NOTHING until they finish. Otherwise "required" means
    # "required of whoever already has one", which is nobody on a new deployment.
    client = _client(factors=_harness.factors())      # enrols nobody
    r = _password_only(client, JAMES)
    assert r.status_code == 401
    assert r.json()["status"] == "enroll"
    assert "token" not in r.json()


def test_enrolment_yields_a_session_and_recovery_codes():
    client = _client(factors=_harness.factors())
    body = _session(client, JAMES)
    assert body["status"] == "enrolled"
    assert "totp" in body["amr"]
    # Returned once, here and nowhere else. They matter more at this tier than
    # anywhere: losing the only factor on the console that grants all authority is
    # the stranded state /readyz reports.
    assert body["recovery_codes"]
    assert client.get("/v1/whoami",
                      headers={"Authorization": f"Bearer {body['token']}"}).status_code == 200


def test_beginning_enrolment_does_not_by_itself_admit_anyone():
    # enroll-begin stores a PENDING secret and enables nothing. A pending
    # enrolment is not a factor, so abandoning it must leave the account still
    # owing one rather than half-admitted.
    store = _harness.factors()
    client = _client(factors=store)
    challenge = _password_only(client, JAMES).json()["challenge_token"]
    begun = client.post("/v1/auth/mfa/enroll/begin", json={"challenge_token": challenge})
    assert begun.status_code == 200
    assert "token" not in begun.json()
    assert begun.json()["otpauth_uri"]
    assert not store.status(JAMES).enabled
    # And a fresh password login still asks for enrolment, not verification.
    assert _password_only(client, JAMES).json()["status"] == "enroll"


def test_an_enrolment_challenge_cannot_complete_a_verification():
    # Nor the reverse. Someone already enrolled must not be able to take the
    # enrolment path after a password-only login and overwrite their factor with
    # one they chose.
    client = _client()                                 # JAMES IS enrolled
    challenge = _password_only(client, JAMES).json()["challenge_token"]
    r = client.post("/v1/auth/mfa/enroll/begin", json={"challenge_token": challenge})
    assert r.status_code == 401
    assert "not for enroll" in r.json()["detail"]


def test_a_verification_challenge_cannot_be_used_to_enrol():
    client = _client(factors=_harness.factors())       # JAMES is NOT enrolled
    challenge = _password_only(client, JAMES).json()["challenge_token"]
    r = client.post("/v1/auth/mfa/verify",
                    json={"challenge_token": challenge, "code": _harness.CODE})
    assert r.status_code == 401
    assert "not for verify" in r.json()["detail"]


def test_an_expired_challenge_is_refused():
    c = _cfg()
    c.mfa_challenge_ttl_s = -10
    client = _client(config=c)
    challenge = _password_only(client, JAMES).json()["challenge_token"]
    r = client.post("/v1/auth/mfa/verify",
                    json={"challenge_token": challenge, "code": _harness.CODE})
    assert r.status_code == 401
    assert "expired" in r.json()["detail"]


def test_a_forged_challenge_is_refused():
    client = _client()
    other = _cfg(jwt_secret="someone-elses-secret")
    forged = mint_challenge(other, Principal(subject=JAMES, roles=frozenset({SYSTEM_OWNER})),
                            CHALLENGE_VERIFY)
    r = client.post("/v1/auth/mfa/verify",
                    json={"challenge_token": forged, "code": _harness.CODE})
    assert r.status_code == 401


# ── fails closed ───────────────────────────────────────────────────────────


def test_an_unreachable_factor_store_refuses_rather_than_admitting():
    # "Allow on error" is how a requirement stops being one. 503 and no token.
    client = _client(factors=_harness.factors(JAMES, unavailable=True))
    r = _password_only(client, JAMES)
    assert r.status_code == 503
    assert "token" not in r.json()


def test_a_required_factor_with_no_store_configured_refuses_every_login():
    # The decorative-check trap: a deployment that believes it is enforcing and
    # has nothing to enforce against. It must refuse, not wave everyone through.
    c = _cfg()
    c.mfa_url = ""
    c.mfa_internal_secret = ""
    client = TestClient(build_app(c, _owned_registry(), _dir(**{
        JAMES.replace("@", "_AT_"): ["system_owner"]})))
    r = _password_only(client, JAMES)
    assert r.status_code == 503
    assert "cannot be checked" in r.json()["detail"]


def test_readiness_reports_required_but_unenforceable_separately_from_disabled():
    from admin_master_control.app import build_monitoring

    c = _cfg()
    c.bootstrap_owner = JAMES
    c.mfa_url = ""
    c.mfa_internal_secret = ""
    d = _dir(**{JAMES.replace("@", "_AT_"): ["system_owner"]})
    problems = TestClient(build_monitoring(c, _owned_registry(), d)).get("/readyz").json()["problems"]
    assert any("no store is configured" in p for p in problems)
    assert not any("MFA disabled" in p for p in problems), (
        "it is not disabled — it is required and unenforceable, which is worse")


# ── the opt-out is explicit ────────────────────────────────────────────────


def test_disabling_the_requirement_admits_on_a_password_alone():
    # The configuration option, working. Default ON; this is the way out.
    c = _cfg()
    c.require_mfa = False
    client = _client(config=c, factors=_harness.factors())
    r = _password_only(client, JAMES)
    assert r.status_code == 200
    assert r.json()["token"]
    assert r.json()["amr"] == ["pwd"]


def test_the_requirement_is_on_by_default():
    # Opt-out, not opt-in: a Config built from an empty environment requires a
    # factor. The console should not need configuring to be safe.
    assert Config().require_mfa is True


def test_disabling_it_is_reported_by_readiness():
    from admin_master_control.app import build_monitoring

    c = _cfg()
    c.require_mfa = False
    c.bootstrap_owner = JAMES
    d = _dir(**{JAMES.replace("@", "_AT_"): ["system_owner"]})
    problems = TestClient(build_monitoring(c, _owned_registry(), d)).get("/readyz").json()["problems"]
    assert any("MFA disabled" in p for p in problems)


# ── named roles, no inheritance ────────────────────────────────────────────


def test_owner_does_not_open_an_observer_route():
    # THE RULE MOST LIKELY TO BE "SIMPLIFIED". system_owner creates authority; it
    # does not hold it. An owner who has not been granted system_observer cannot
    # read the observer routes, and the fix is a recorded self-grant, not an
    # implicit one.
    owner_only = "owner.only@rationalboxes.com"
    d = _dir(**{owner_only.replace("@", "_AT_"): [SYSTEM_OWNER]})
    client = _client(directory=d)
    tok = _session(client, owner_only)["token"]
    assert client.get("/v1/whoami", headers={"Authorization": f"Bearer {tok}"}).status_code == 403


def test_owner_can_still_reach_the_route_that_needs_owner():
    owner_only = "owner.only@rationalboxes.com"
    # The grantee has an ACCOUNT: a grant to an address no account answers to is
    # refused (404) rather than recorded for an identity no login resolves to.
    d = _dir(**{owner_only.replace("@", "_AT_"): [SYSTEM_OWNER],
                "new_AT_rationalboxes.com": []})
    client = _client(directory=d)
    tok = _session(client, owner_only)["token"]
    r = client.post("/v1/grants",
                    json={"subject": "new@rationalboxes.com", "role": SYSTEM_OBSERVER},
                    headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 201
    assert r.json()["authorised_as"] == SYSTEM_OWNER


def test_a_non_owner_cannot_grant():
    sec = "sec@rationalboxes.com"
    d = _dir(**{sec.replace("@", "_AT_"): [SYSTEM_SECURITY, SYSTEM_OBSERVER]})
    client = _client(directory=d)
    tok = _session(client, sec)["token"]
    r = client.post("/v1/grants",
                    json={"subject": "x@rationalboxes.com", "role": SYSTEM_OBSERVER},
                    headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 403


def test_holding_billing_does_not_open_the_observer_routes():
    # Additive and unordered: billing is not "above" observer.
    bill = "bill@rationalboxes.com"
    d = _dir(**{bill.replace("@", "_AT_"): [SYSTEM_BILLING]})
    client = _client(directory=d)
    tok = _session(client, bill)["token"]
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
                    json={"subject": tadmin, "password": "pw-" + tadmin})
    assert r.status_code == 403, "a tenant role must not authenticate into the deployment tier"


def test_an_administrator_with_no_role_is_refused_not_given_an_empty_session():
    nobody = "nobody@rationalboxes.com"
    d = StaticDeploymentDirectory()
    d.passwords[nobody] = "pw"
    with pytest.raises(AuthError):
        login(_cfg(), d, nobody, "pw")


def test_a_bad_password_does_not_reveal_whether_the_account_holds_authority():
    # The password is checked before the roles are read, so this is not an
    # oracle for "is X an administrator".
    d = _dir(**{JAMES.replace("@", "_AT_"): [SYSTEM_OWNER]})
    with pytest.raises(AuthError) as e:
        login(_cfg(), d, JAMES, "wrong")
    assert "bad credentials" in str(e.value)


def test_an_unreachable_directory_refuses_rather_than_admits():
    class Down:
        def authenticate(self, subject, password):
            return False

        def roles_of(self, subject):
            return frozenset()

    client = _client(directory=Down())
    assert _password_only(client, JAMES).status_code == 401


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
    tok = _session(client, JAMES)["token"]
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
    tok = _session(client, JAMES)["token"]
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
        login(_cfg(), _Unreachable(), "james@rationalboxes.com", "pw")


def test_an_unreadable_directory_says_come_back_not_you_have_no_authority():
    # 503, not 403. The distinction is the whole point: 403 tells an
    # administrator they hold no authority, which sends them to the directory to
    # fix something that is not broken.
    try:
        login(_cfg(), _Unreachable(), "james@rationalboxes.com", "pw")
    except DirectoryUnavailable as e:
        assert e.status_code == 503
        assert "could not be searched" in e.reason
        assert "no deployment role" not in e.reason


def test_a_directory_that_answers_none_still_refuses_with_403():
    # The other side of the pair — this message IS the right one here.
    with pytest.raises(AuthError) as e:
        login(_cfg(), _NoRoles(), "nobody@rationalboxes.com", "pw")
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
    # A second factor is required (the default), so it must also be CHECKABLE.
    # Readiness reports "required but no store configured" otherwise, which is the
    # point: enforcement that cannot reach its source refuses every login.
    c.mfa_url = "http://ldap-manager:8093"
    c.mfa_internal_secret = "internal-shared-secret"
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
