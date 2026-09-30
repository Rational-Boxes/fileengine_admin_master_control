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

"""Certificate validation, per subdomain.

DNS answers "will issuance work". This answers "did it, and does it still" — and the
second question is the one that goes unasked, because issuance happens once and renewal
happens forever. A renewal that quietly stops working is invisible until a browser
refuses the site.

The weight is on the failures that LOOK like success from the server's side:

  * a certificate served for the wrong name (the apex cert on the `-drive` host, or the
    reverse proxy's default vhost) — the handshake works, the browser refuses;
  * a certificate with twelve days left — working now, and the thing that should have
    renewed it has already missed several chances;
  * `absent` before provisioning, which is EXPECTED and must not read as a fault.

Nothing here opens a socket. `StaticTlsProbe` is injected, because a test that quietly
connected would pass or fail on whatever happened to be listening.
"""
from __future__ import annotations

import datetime as _dt

import pytest

from admin_master_control import tls as m
from admin_master_control.tls import (
    ABSENT,
    EXPIRED,
    EXPIRING,
    UNREACHABLE,
    UNTRUSTED,
    VALID,
    WRONG_HOST,
    CertCheck,
    StaticTlsProbe,
    check_tls,
    covers_hostname,
)

HOSTS = ["acme.example.com", "acme-drive.example.com"]


def _cert(host, state=VALID, days=80, **over):
    kw = dict(hostname=host, state=state, days_remaining=days,
              covers=(host,), issuer="Let's Encrypt")
    kw.update(over)
    return CertCheck(**kw)


# ── wildcard and exact coverage ────────────────────────────────────────────


def test_an_exact_name_covers_the_host():
    assert covers_hostname(("acme.example.com",), "acme.example.com")


def test_coverage_is_case_and_trailing_dot_insensitive():
    assert covers_hostname(("ACME.Example.COM.",), "acme.example.com")


def test_a_wildcard_covers_one_label_only():
    # `*.example.com` covers acme.example.com and acme-drive.example.com — both are a
    # single label — but NOT a.b.example.com, and not the apex.
    names = ("*.example.com",)
    assert covers_hostname(names, "acme.example.com")
    assert covers_hostname(names, "acme-drive.example.com")
    assert not covers_hostname(names, "a.b.example.com")
    assert not covers_hostname(names, "example.com")


def test_coverage_is_not_a_substring_test():
    # The generous direction is the dangerous one: reporting a certificate as covering a
    # host it does not is the single error this check exists to catch.
    assert not covers_hostname(("notacme.example.com",), "acme.example.com")
    assert not covers_hostname(("acme.example.com.evil.test",), "acme.example.com")
    assert not covers_hostname(("example.com",), "acme.example.com")


def test_a_name_list_with_nothing_relevant_does_not_cover():
    assert not covers_hostname((), "acme.example.com")
    assert not covers_hostname(("www.example.com", "example.com"), "acme.example.com")


# ── what counts as ok ─────────────────────────────────────────────────────


def test_a_valid_certificate_is_ok():
    assert _cert("a", VALID, 80).ok


def test_an_EXPIRING_certificate_is_serving_but_NOT_ok():
    """The distinction that makes this check worth having.

    Twelve days left means the certificate works and the thing that should have renewed
    it has already failed several times. Calling that ok is how it stays unnoticed until
    it is not — so `ok` is false and `serving` is true, and the UI can say "working, and
    broken".
    """
    c = _cert("a", EXPIRING, 12)
    assert c.serving
    assert not c.ok


@pytest.mark.parametrize("state", [EXPIRED, WRONG_HOST, UNTRUSTED, ABSENT, UNREACHABLE])
def test_everything_else_is_neither(state):
    c = _cert("a", state, None)
    assert not c.ok
    assert not c.serving


# ── the verdict over several subdomains ───────────────────────────────────


def test_every_subdomain_is_checked_separately():
    v = check_tls(HOSTS, StaticTlsProbe(answers={
        HOSTS[0]: _cert(HOSTS[0], VALID, 80),
        HOSTS[1]: _cert(HOSTS[1], EXPIRED, -3, detail="expired 3 day(s) ago"),
    }))
    assert len(v.checks) == 2
    assert not v.ok
    # THE case this exists for: the web interface keeps serving while WebDAV stops, and
    # one verdict on the tenant cannot say that.
    assert v.checks[0].ok
    assert not v.checks[1].serving


def test_the_blocking_reason_names_the_host_and_the_cause():
    # Listing only the hostnames reads as one problem for every cause, and these need
    # opposite responses: `absent` before provisioning is expected, `wrong_host` means a
    # certificate exists and is the wrong one, `expiring` means renewal is broken and
    # there is still time.
    v = check_tls(HOSTS, StaticTlsProbe(answers={
        HOSTS[0]: _cert(HOSTS[0], VALID, 80),
        HOSTS[1]: _cert(HOSTS[1], WRONG_HOST, 80,
                        detail="the certificate served is for acme.example.com, "
                               "not acme-drive.example.com"),
    }))
    assert "acme-drive.example.com" in v.blocking_reason
    assert "not acme-drive.example.com" in v.blocking_reason
    assert "acme.example.com (" not in v.blocking_reason, "the passing host is not listed"


def test_the_soonest_expiry_is_what_gets_reported():
    # A tenant is as renewed as its least renewed subdomain.
    v = check_tls(HOSTS, StaticTlsProbe(answers={
        HOSTS[0]: _cert(HOSTS[0], VALID, 80),
        HOSTS[1]: _cert(HOSTS[1], EXPIRING, 9),
    }))
    assert v.soonest_expiry == 9


def test_an_unchecked_verdict_is_not_ok():
    # An empty verdict must not read as "all fine" — `all()` over nothing is True, which
    # is exactly the trap.
    assert not m.TlsVerdict().ok
    assert not m.TlsVerdict().serving


def test_a_probe_with_nothing_configured_reports_absent():
    # The pre-provisioning state, and the safe default for a probe that has not been
    # told otherwise.
    v = check_tls(HOSTS, StaticTlsProbe())
    assert all(c.state == ABSENT for c in v.checks)
    assert not v.ok


def test_absent_is_distinguished_from_unreachable():
    # "Nothing is serving here yet" and "I could not find out" need different responses,
    # and the second must not be reported as the first on a live tenant.
    v = check_tls(["a"], StaticTlsProbe(answers={"a": _cert("a", UNREACHABLE, None,
                                                            detail="timed out")}))
    assert v.checks[0].state == UNREACHABLE
    assert "timed out" in v.blocking_reason


# ── the wire form ─────────────────────────────────────────────────────────


def test_the_verdict_serialises_what_the_ui_needs():
    v = check_tls(HOSTS, StaticTlsProbe(answers={
        HOSTS[0]: _cert(HOSTS[0], VALID, 80, not_after="2027-01-01T00:00:00+00:00"),
        HOSTS[1]: _cert(HOSTS[1], EXPIRING, 9),
    }))
    d = v.as_dict()
    assert d["ok"] is False
    assert d["soonest_expiry_days"] == 9
    assert d["checked_at"]
    assert [c["hostname"] for c in d["checks"]] == HOSTS
    assert d["checks"][0]["not_after"] == "2027-01-01T00:00:00+00:00"
    assert d["checks"][1]["days_remaining"] == 9


# ── parsing what a server actually sends ──────────────────────────────────


def test_not_after_parses_openssl_format():
    when = m._parse_not_after("Jan  1 00:00:00 2027 GMT")
    assert when is not None and when.year == 2027
    assert when.tzinfo is _dt.timezone.utc


def test_an_unparseable_not_after_is_none_rather_than_a_guess():
    # A date this build cannot read must not become "expires today" or "expires never".
    assert m._parse_not_after("") is None
    assert m._parse_not_after("whenever") is None


def test_names_come_from_the_sans_and_fall_back_to_the_cn():
    both = {"subjectAltName": (("DNS", "a.example.com"), ("DNS", "b.example.com")),
            "subject": ((("commonName", "a.example.com"),),)}
    assert m._names_from(both) == ("a.example.com", "b.example.com")
    cn_only = {"subject": ((("commonName", "old.example.com"),),)}
    assert m._names_from(cn_only) == ("old.example.com",)


def test_the_expiring_threshold_leaves_room_to_notice():
    # Let's Encrypt renews at 30 days, so a certificate under this has had chances and
    # missed them — which is the signal, rather than "it is going to expire eventually".
    assert m.EXPIRING_SOON_DAYS < 30


# ── what the transport failure actually means ─────────────────────────────


def test_a_refused_port_is_absent_but_a_reset_is_unreachable(monkeypatch):
    """A connection reset is NOT "nothing is serving".

    Refused means the port is closed — genuinely nothing there, which before provisioning
    is the expected answer. A RESET means something answered and hung up: a load balancer
    with no backend, a rate limiter, or a host dropping unknown SNI. Reporting that as
    `absent` says the subdomain is empty when it is not.

    Measured against a real host: probing it twice in quick succession returned `expired`
    and then a reset, which is exactly why the two must not share a state.
    """
    import socket as s

    probe = m.SystemTlsProbe(timeout_s=0.1)

    def refuse(*a, **k):
        raise ConnectionRefusedError(111, "Connection refused")

    monkeypatch.setattr(s, "create_connection", refuse)
    assert probe.probe("a.example.com").state == ABSENT

    def reset(*a, **k):
        raise ConnectionResetError(104, "Connection reset by peer")

    monkeypatch.setattr(s, "create_connection", reset)
    got = probe.probe("a.example.com")
    assert got.state == UNREACHABLE
    assert "reset" in got.detail
    assert "nothing" not in got.detail


def test_a_timeout_is_unreachable_not_absent(monkeypatch):
    import socket as s

    probe = m.SystemTlsProbe(timeout_s=0.1)
    monkeypatch.setattr(s, "create_connection",
                        lambda *a, **k: (_ for _ in ()).throw(TimeoutError()))
    got = probe.probe("a.example.com")
    assert got.state == UNREACHABLE
    assert "timed out" in got.detail


def test_a_name_that_does_not_resolve_says_so_rather_than_blaming_the_certificate(monkeypatch):
    # That is the DNS check's business. Saying "no certificate" would send someone to a
    # certificate authority about a missing A record.
    import socket as s

    probe = m.SystemTlsProbe(timeout_s=0.1)
    monkeypatch.setattr(s, "create_connection",
                        lambda *a, **k: (_ for _ in ()).throw(s.gaierror(-2, "Name or service not known")))
    got = probe.probe("nope.example.invalid")
    assert got.state == ABSENT
    assert "does not resolve" in got.detail
