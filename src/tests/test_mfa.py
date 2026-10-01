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

"""The factor gate and the client that reads the factor store (§6).

`test_auth.py` covers the login flow through the API. This covers the two pieces
underneath it: what a correct password entitles someone to (`MfaGate`), and what
happens when the store answers badly (`LdapManagerFactors`).

The weight is on the refusals. A second factor that can be skipped is not one,
and every way of skipping it here is a way that looked like an ordinary error
path: an unreachable store, a store that 403s because the internal secret does
not match, a requirement with nothing configured to check it against.
"""
from __future__ import annotations

import pytest

from admin_master_control import mfa
from admin_master_control.auth import AuthError
from admin_master_control.config import Config
from admin_master_control.mfa import (
    ADMITTED,
    ENROLLMENT_REQUIRED,
    VERIFY_REQUIRED,
    LdapManagerFactors,
    MfaGate,
    MfaUnavailable,
    StaticFactors,
)

WHO = "james@rationalboxes.com"


def _cfg(**over) -> Config:
    c = Config()
    c.jwt_secret = "test-secret"
    c.mfa_url = "http://ldap-manager:8093"
    c.mfa_internal_secret = "shared"
    for k, v in over.items():
        setattr(c, k, v)
    return c


# ── what a password entitles you to ────────────────────────────────────────


def test_an_enrolled_administrator_must_prove_it():
    g = MfaGate(_cfg(), StaticFactors(enrolled={WHO: "424242"}))
    assert g.next_step(WHO) == VERIFY_REQUIRED


def test_an_unenrolled_administrator_must_enrol():
    # "If 2FA is not disabled require setup on first login."
    assert MfaGate(_cfg(), StaticFactors()).next_step(WHO) == ENROLLMENT_REQUIRED


def test_a_pending_enrolment_is_not_a_factor():
    # enroll-begin stores a secret and enables nothing. Treating pending as
    # enrolled would admit a session against a secret nobody has proved they can
    # generate codes from — and would let an abandoned enrolment become a way in.
    store = StaticFactors()
    store.enroll_begin(WHO)
    assert store.status(WHO).pending
    assert not store.status(WHO).enabled
    assert MfaGate(_cfg(), store).next_step(WHO) == ENROLLMENT_REQUIRED


def test_the_opt_out_admits_on_a_password_alone():
    g = MfaGate(_cfg(require_mfa=False), StaticFactors())
    assert g.next_step(WHO) == ADMITTED


def test_the_opt_out_does_not_need_a_store():
    # Turning it off should not require configuring the thing being turned off.
    assert MfaGate(_cfg(require_mfa=False), None).next_step(WHO) == ADMITTED


# ── fails closed, every way ────────────────────────────────────────────────


def test_a_requirement_with_no_store_refuses():
    # The decorative-check trap, and the one §3.4c named for the tenant gate: a
    # check is worth nothing on exactly the deployment that forgot to wire it.
    with pytest.raises(MfaUnavailable):
        MfaGate(_cfg(), None).next_step(WHO)


def test_an_unreachable_store_refuses():
    with pytest.raises(MfaUnavailable):
        MfaGate(_cfg(), StaticFactors(unavailable=True)).next_step(WHO)


def test_an_unreachable_store_says_so_rather_than_blaming_the_code():
    # Telling an administrator their code was wrong when the store was unreachable
    # sends them to re-scan a QR that is fine — the same distinction
    # DirectoryUnavailable exists for.
    try:
        MfaGate(_cfg(), StaticFactors(unavailable=True)).next_step(WHO)
    except MfaUnavailable as e:
        assert e.status_code == 503
        assert "could not be reached" in e.reason
        assert "did not match" not in e.reason


def test_unavailability_is_an_autherror_so_nothing_treats_it_as_a_pass():
    assert issubclass(MfaUnavailable, AuthError)


def test_verify_refuses_without_a_store():
    with pytest.raises(MfaUnavailable):
        MfaGate(_cfg(), None).verify(WHO, "totp", "424242")


# ── the method allowlist ───────────────────────────────────────────────────


def test_the_default_methods_exclude_email():
    # Deliberate: email is the weakest path on offer and this is the console that
    # reads every tenant's audit. It is permitted elsewhere in the platform.
    assert Config().mfa_method_list() == ("totp", "recovery")


def test_recovery_is_kept_on_purpose():
    # Losing the only factor here means nobody can grant authority to anybody —
    # the stranded state /readyz reports, which no other administrator can fix.
    assert mfa.RECOVERY in Config().mfa_method_list()


def test_a_method_outside_the_allowlist_is_refused():
    g = MfaGate(_cfg(), StaticFactors(enrolled={WHO: "424242"}))
    for bad in ("email", "oauth", "webauthn", "", "TOTP-ish"):
        with pytest.raises(AuthError) as e:
            g.verify(WHO, bad, "424242")
        assert e.value.status_code == 400


def test_a_permitted_method_is_case_insensitive():
    g = MfaGate(_cfg(), StaticFactors(enrolled={WHO: "424242"}))
    assert g.verify(WHO, "TOTP", "424242")


def test_the_allowlist_is_configurable_but_narrow_by_default():
    g = MfaGate(_cfg(mfa_methods="totp"), StaticFactors(enrolled={WHO: "1"}))
    with pytest.raises(AuthError):
        g.verify(WHO, "recovery", "rec-1")


def test_a_recovery_code_is_one_time():
    store = StaticFactors(enrolled={WHO: "424242"}, recovery={WHO: ["rec-1"]})
    g = MfaGate(_cfg(), store)
    assert g.verify(WHO, "recovery", "rec-1")
    assert not g.verify(WHO, "recovery", "rec-1"), "a recovery code must not be reusable"


def test_an_empty_code_is_refused_before_the_store_is_asked():
    store = StaticFactors(enrolled={WHO: "424242"})
    with pytest.raises(AuthError):
        MfaGate(_cfg(), store).verify(WHO, "totp", "")
    assert not [c for c in store.calls if c[0] == "verify"]


# ── enrolment ──────────────────────────────────────────────────────────────


def test_enrolment_returns_something_scannable():
    begun = MfaGate(_cfg(), StaticFactors()).enroll_begin(WHO)
    assert begun["otpauth_uri"]
    assert begun["secret"]


def test_enrolment_completes_only_with_the_right_code():
    store = StaticFactors()
    g = MfaGate(_cfg(), store)
    g.enroll_begin(WHO)
    assert not g.enroll_complete(WHO, "000000")["ok"]
    assert not store.status(WHO).enabled
    done = g.enroll_complete(WHO, "424242")
    assert done["ok"] and done["recovery_codes"]
    assert store.status(WHO).enabled


def test_enrolment_is_refused_when_totp_is_not_permitted():
    with pytest.raises(AuthError):
        MfaGate(_cfg(mfa_methods="recovery"), StaticFactors()).enroll_begin(WHO)


# ── the store's own configuration ──────────────────────────────────────────


def test_both_halves_are_needed_to_enforce():
    # A URL with no secret gets 403 from every endpoint; a secret with no URL has
    # nothing to call. Either alone is a deployment that believes it is enforcing.
    assert _cfg().mfa_is_enforceable()
    assert not _cfg(mfa_url="").mfa_is_enforceable()
    assert not _cfg(mfa_internal_secret="").mfa_is_enforceable()


def test_from_config_returns_nothing_rather_than_a_broken_client():
    assert mfa.from_config(_cfg(mfa_url="")) is None
    assert isinstance(mfa.from_config(_cfg()), LdapManagerFactors)


def test_the_tenant_context_is_empty_not_an_invented_name():
    """No made-up sentinel, because THE CORE PROVISIONS ANY TENANT IT IS ASKED ABOUT.

    This was `__deployment__`, reasoning that a tenant with no policy row inherits
    the full method cap. That much is true; what it missed is that
    `Database::create_tenant_schema` inserts into `public.tenants` with the default
    state `live`, so in an estate that provisions on first reference a
    plausible-looking name is a tenant waiting to be created — and it would then
    read as LIVE in the registry this console displays.

    An empty string cannot be taken for a tenant id by anything downstream.
    """
    assert Config().mfa_tenant_context == ""


def test_the_context_could_not_be_a_tenant_even_if_someone_tried():
    from admin_master_control.tenants import TenantError, validate_tenant_id

    with pytest.raises(TenantError):
        validate_tenant_id(Config().mfa_tenant_context)


# ── the HTTP client's error handling ───────────────────────────────────────


class _Resp:
    def __init__(self, status_code, body=None, bad_json=False):
        self.status_code = status_code
        self._body = body if body is not None else {}
        self._bad = bad_json

    def json(self):
        if self._bad:
            raise ValueError("not json")
        return self._body


def _client(monkeypatch, resp=None, raises=None):
    store = LdapManagerFactors(url="http://ldap-manager:8093", internal_secret="shared",
                               tenant_context="")
    sent = {}

    def fake_post(url, json=None, headers=None, timeout=None):
        sent["url"] = url
        sent["json"] = json
        sent["headers"] = headers
        if raises:
            raise raises
        return resp

    import httpx
    monkeypatch.setattr(httpx, "post", fake_post)
    return store, sent


def test_a_403_is_a_misconfiguration_not_a_failed_factor(monkeypatch):
    # ldap_manager 403s when the internal secret does not match and 404s when its
    # internal API is disabled. Read as "not enrolled", either would hand out
    # sessions on the deployment that got the secret wrong.
    for code in (403, 404):
        store, _ = _client(monkeypatch, _Resp(code))
        with pytest.raises(MfaUnavailable):
            store.status(WHO)


def test_a_transport_failure_is_unavailability(monkeypatch):
    store, _ = _client(monkeypatch, raises=OSError("connection refused"))
    with pytest.raises(MfaUnavailable):
        store.verify(WHO, "totp", "424242")


def test_a_rate_limit_is_passed_through_as_itself(monkeypatch):
    # ldap_manager rate-limits verify per ip and per uid. 429 is not a refusal of
    # the factor and not an outage; saying so lets a client back off.
    store, _ = _client(monkeypatch, _Resp(429))
    with pytest.raises(AuthError) as e:
        store.verify(WHO, "totp", "424242")
    assert e.value.status_code == 429
    assert not isinstance(e.value, MfaUnavailable)


def test_an_unreadable_body_is_unavailability(monkeypatch):
    store, _ = _client(monkeypatch, _Resp(200, bad_json=True))
    with pytest.raises(MfaUnavailable):
        store.status(WHO)


def test_a_missing_ok_field_is_not_a_pass(monkeypatch):
    # `{}` must not read as success. The store returns {"ok": bool}; anything else
    # is a no.
    store, _ = _client(monkeypatch, _Resp(200, {}))
    assert store.verify(WHO, "totp", "424242") is False


def test_the_internal_secret_is_sent_in_the_header(monkeypatch):
    store, sent = _client(monkeypatch, _Resp(200, {"enabled": True}))
    store.status(WHO)
    assert sent["headers"]["X-Internal-Auth"] == "shared"
    assert sent["json"]["tenant"] == ""
    assert sent["url"].endswith("/internal/2fa/required")


def test_only_the_per_user_enrolment_is_read_not_the_tenant_mandate(monkeypatch):
    # /internal/2fa/required reports the TENANT mandate alongside per-user
    # enrolment. This tier's requirement is unconditional and not a tenant's to
    # set, so a tenant saying "not required" must not make it optional here.
    store, _ = _client(monkeypatch, _Resp(200, {"enabled": True, "required": False,
                                               "tenant_requires": False}))
    assert store.status(WHO).enabled is True
