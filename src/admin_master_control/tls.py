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

"""Certificate validation, per hostname, for the primary and every service subdomain.

The DNS gate answers "will issuance work". This answers "did it, and does it still" —
and they are different questions asked at different times:

  * BEFORE provisioning, no certificate exists. `absent` is the expected answer and is
    NOT a failure. Reporting it as one would make every new tenant look broken.
  * AFTER provisioning, a missing or expired certificate is the failure that nobody
    notices. Issuance happens once, renewal happens forever, and a renewal that stops
    working is silent until a browser refuses the site. This is the check that makes
    that visible, which is why it reports DAYS REMAINING rather than a boolean.

EVERY SUBDOMAIN IS CHECKED SEPARATELY, because every one has its own certificate. A
tenant whose primary host is fine and whose `-drive` host expired is a tenant whose
WebDAV stopped working while its web interface kept serving — and a single verdict on
the tenant cannot say that.

THE CERTIFICATE IS FETCHED WITHOUT HOSTNAME VERIFICATION, AND THEN JUDGED HERE. That is
deliberate and it is the same reasoning as the DNS check comparing the address rather
than merely that something resolved: a verifying handshake fails with "wrong host" and
throws the certificate away, so it cannot tell you the certificate served was for
`www.example.com`, or was the reverse proxy's default vhost, or covers the apex but not
`-drive`. Those are the interesting failures — they look like success from the server's
side — and naming them is the difference between "TLS failed" and "you have the apex
certificate on both hosts".

Trust is then established by a SEPARATE verifying handshake, so "expired",
"untrusted" and "wrong hostname" stay distinguishable instead of collapsing into one
refusal.
"""
from __future__ import annotations

import datetime as _dt
import logging
import socket
import ssl
from dataclasses import dataclass, field
from typing import Optional, Protocol

log = logging.getLogger("admin_master_control.tls")

#: Per-hostname outcomes.
VALID = "valid"              # trusted, covers the host, comfortably in date
EXPIRING = "expiring"        # trusted and covers the host, but renewal is overdue
EXPIRED = "expired"          # past notAfter — the site is already refusing
WRONG_HOST = "wrong_host"    # a certificate is served, but not for this name
UNTRUSTED = "untrusted"      # covers the host, chain does not verify (self-signed, staging)
ABSENT = "absent"            # nothing is listening, or it is not speaking TLS
UNREACHABLE = "unreachable"  # could not be determined — NOT the same as absent

#: Let's Encrypt renews at 30 days. Under this, renewal has had chances and missed them,
#: which is the signal worth surfacing — a certificate with 40 days left is being
#: managed, one with 12 is not.
EXPIRING_SOON_DAYS = 21

#: Short. A hostname whose DNS is wrong will not answer, and this runs once per
#: subdomain, so a generous timeout turns a check of six hosts into a minute of waiting.
CONNECT_TIMEOUT_S = 5.0


@dataclass(frozen=True)
class CertCheck:
    """One hostname's certificate."""

    hostname: str
    state: str = UNREACHABLE
    detail: str = ""
    #: Whatever the server actually served, even when it is the wrong certificate —
    #: that is the fact worth reporting.
    subject: str = ""
    issuer: str = ""
    covers: tuple[str, ...] = ()
    not_after: str = ""
    days_remaining: Optional[int] = None

    @property
    def ok(self) -> bool:
        """Serving now, and will keep serving. `expiring` is NOT ok.

        A certificate with twelve days left is working and is also a fault: the thing
        that was supposed to renew it has already failed several times. Calling that ok
        is how it stays unnoticed until it is not.
        """
        return self.state == VALID

    @property
    def serving(self) -> bool:
        """Working RIGHT NOW, whatever happens next. For "is the site up"."""
        return self.state in (VALID, EXPIRING)

    def as_dict(self) -> dict:
        return {"hostname": self.hostname, "state": self.state, "ok": self.ok,
                "serving": self.serving, "detail": self.detail, "subject": self.subject,
                "issuer": self.issuer, "covers": list(self.covers),
                "not_after": self.not_after, "days_remaining": self.days_remaining}


@dataclass(frozen=True)
class TlsVerdict:
    checks: tuple[CertCheck, ...] = ()

    @property
    def ok(self) -> bool:
        return bool(self.checks) and all(c.ok for c in self.checks)

    @property
    def serving(self) -> bool:
        return bool(self.checks) and all(c.serving for c in self.checks)

    @property
    def soonest_expiry(self) -> Optional[int]:
        days = [c.days_remaining for c in self.checks if c.days_remaining is not None]
        return min(days) if days else None

    @property
    def blocking_reason(self) -> str:
        """Why, per hostname, INCLUDING each detail.

        The same reasoning as the DNS verdict: listing only the hostnames reads as one
        problem for every cause, and these causes need opposite responses. "absent"
        before provisioning is expected; "wrong_host" means a certificate exists and is
        the wrong one; "expiring" means renewal is broken and there is still time.
        """
        if self.ok:
            return ""
        bad = [f"{c.hostname} ({c.detail or c.state})" for c in self.checks if not c.ok]
        return f"certificates not in order for: {'; '.join(bad)}" if bad else ""

    def as_dict(self) -> dict:
        return {"ok": self.ok, "serving": self.serving,
                "soonest_expiry_days": self.soonest_expiry,
                "blocking_reason": self.blocking_reason,
                "checked_at": _dt.datetime.now(_dt.timezone.utc).isoformat(),
                "checks": [c.as_dict() for c in self.checks]}


class TlsProbe(Protocol):
    """Fetches one hostname's certificate. Injectable so the logic is testable offline."""

    def probe(self, hostname: str, port: int = 443) -> CertCheck: ...


def _names_from(cert: dict) -> tuple[str, ...]:
    """Every name the certificate claims: the SANs, plus the CN for old certificates.

    SANs are what matters — CN has been advisory for years and browsers ignore it — but a
    certificate with only a CN still exists in the wild and reporting nothing for it
    would be less useful than reporting what it says.
    """
    names = [v for k, v in cert.get("subjectAltName", ()) if k.lower() == "dns"]
    for rdn in cert.get("subject", ()):
        for k, v in rdn:
            if k == "commonName" and v not in names:
                names.append(v)
    return tuple(names)


def covers_hostname(names: tuple[str, ...], hostname: str) -> bool:
    """Whether any name covers this host, including a single-level wildcard.

    Implemented rather than delegated because the certificate is fetched WITHOUT
    verification (see the module docstring), so ssl's own matching is not in play.

    A wildcard matches exactly one label: `*.example.com` covers `acme.example.com` and
    does NOT cover `a.b.example.com` or the apex `example.com`. Getting that wrong in the
    generous direction would report a certificate as covering a host it does not, which
    is the one error this check exists to catch.
    """
    host = hostname.lower().rstrip(".")
    for raw in names:
        name = raw.lower().rstrip(".")
        if name == host:
            return True
        if name.startswith("*."):
            suffix = name[1:]            # ".example.com"
            if host.endswith(suffix) and "." not in host[: -len(suffix)]:
                return True
    return False


@dataclass
class SystemTlsProbe:
    """A real TLS connection, over the system trust store."""

    timeout_s: float = CONNECT_TIMEOUT_S

    def probe(self, hostname: str, port: int = 443) -> CertCheck:
        # 1. Fetch the certificate WITHOUT verifying, so a wrong-host or untrusted
        #    certificate can still be described rather than merely refused.
        unverified = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        unverified.check_hostname = False
        unverified.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((hostname, port), timeout=self.timeout_s) as sock:
                with unverified.wrap_socket(sock, server_hostname=hostname) as tls:
                    der = tls.getpeercert(binary_form=True)
                    cert = tls.getpeercert()
        except (socket.gaierror, socket.herror) as e:
            # The name does not resolve. That is the DNS check's business, and saying so
            # here rather than "no certificate" avoids sending someone to look at a
            # certificate authority about a missing A record.
            return CertCheck(hostname=hostname, state=ABSENT,
                             detail=f"does not resolve ({e})")
        except ConnectionRefusedError as e:
            # Refused means the port is closed: genuinely nothing serving, which before
            # provisioning is the expected answer.
            return CertCheck(hostname=hostname, state=ABSENT,
                             detail=f"nothing listening on port {port} ({e})")
        except (TimeoutError, socket.timeout):
            return CertCheck(hostname=hostname, state=UNREACHABLE,
                             detail=f"timed out after {self.timeout_s:g}s")
        except ConnectionResetError as e:
            # SOMETHING ANSWERED AND HUNG UP. Not `absent`, which would say nothing is
            # serving — a load balancer with no backend, a rate limiter, or a host that
            # drops unknown SNI all reset, and the honest answer is that this could not be
            # determined rather than that the subdomain is empty.
            #
            # Measured: probing the same host twice in quick succession returned `expired`
            # and then a reset, which is precisely why the two must not share a state.
            return CertCheck(hostname=hostname, state=UNREACHABLE,
                             detail=f"connection reset — something answered on port "
                                    f"{port} and closed it ({e})")
        except OSError as e:
            # Network unreachable, no route, and the rest. Not a statement about whether
            # a certificate exists.
            return CertCheck(hostname=hostname, state=UNREACHABLE,
                             detail=f"could not connect to port {port} ({e})")
        except ssl.SSLError as e:
            return CertCheck(hostname=hostname, state=ABSENT,
                             detail=f"not speaking TLS ({e})")
        except Exception as e:  # noqa: BLE001
            return CertCheck(hostname=hostname, state=UNREACHABLE, detail=str(e))

        # `getpeercert()` returns {} on an unverified connection in some builds, so fall
        # back to decoding the DER rather than reporting a certificate with no fields.
        if not cert and der:
            cert = _decode_der(der)

        names = _names_from(cert)
        subject = _first(cert.get("subject", ()), "commonName")
        issuer = _first(cert.get("issuer", ()), "organizationName") \
            or _first(cert.get("issuer", ()), "commonName")
        not_after_raw = cert.get("notAfter", "")
        expires = _parse_not_after(not_after_raw)
        days = None if expires is None else (expires - _now()).days

        if not covers_hostname(names, hostname):
            return CertCheck(hostname=hostname, state=WRONG_HOST, subject=subject,
                             issuer=issuer, covers=names, not_after=_iso(expires),
                             days_remaining=days,
                             detail=f"the certificate served is for "
                                    f"{', '.join(names) or 'an unknown name'}, "
                                    f"not {hostname}")
        if days is not None and days < 0:
            return CertCheck(hostname=hostname, state=EXPIRED, subject=subject,
                             issuer=issuer, covers=names, not_after=_iso(expires),
                             days_remaining=days,
                             detail=f"expired {abs(days)} day(s) ago")

        # 2. Trust, as its own question, so "untrusted" does not masquerade as
        #    "expired" or "wrong host".
        verified, why = self._verifies(hostname, port)
        if not verified:
            return CertCheck(hostname=hostname, state=UNTRUSTED, subject=subject,
                             issuer=issuer, covers=names, not_after=_iso(expires),
                             days_remaining=days,
                             detail=f"covers this host but the chain does not "
                                    f"verify ({why})")

        if days is not None and days <= EXPIRING_SOON_DAYS:
            return CertCheck(hostname=hostname, state=EXPIRING, subject=subject,
                             issuer=issuer, covers=names, not_after=_iso(expires),
                             days_remaining=days,
                             detail=f"{days} day(s) left — renewal is overdue")
        return CertCheck(hostname=hostname, state=VALID, subject=subject, issuer=issuer,
                         covers=names, not_after=_iso(expires), days_remaining=days)

    def _verifies(self, hostname: str, port: int) -> tuple[bool, str]:
        ctx = ssl.create_default_context()
        try:
            with socket.create_connection((hostname, port), timeout=self.timeout_s) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname):
                    return True, ""
        except ssl.SSLCertVerificationError as e:
            return False, e.verify_message or str(e)
        except Exception as e:  # noqa: BLE001
            return False, str(e)


def _decode_der(der: bytes) -> dict:
    """Last resort when getpeercert() is empty on an unverified socket."""
    try:
        import tempfile

        with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=True) as f:
            f.write(ssl.DER_cert_to_PEM_cert(der))
            f.flush()
            return ssl._ssl._test_decode_cert(f.name)  # type: ignore[attr-defined]
    except Exception:  # noqa: BLE001
        return {}


def _first(rdns, key: str) -> str:
    for rdn in rdns or ():
        for k, v in rdn:
            if k == key:
                return str(v)
    return ""


def _parse_not_after(raw: str) -> Optional[_dt.datetime]:
    if not raw:
        return None
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b %d %H:%M:%S %Y"):
        try:
            return _dt.datetime.strptime(raw, fmt).replace(tzinfo=_dt.timezone.utc)
        except ValueError:
            continue
    log.warning("could not parse notAfter %r", raw)
    return None


def _now() -> _dt.datetime:
    return _dt.datetime.now(_dt.timezone.utc)


def _iso(when: Optional[_dt.datetime]) -> str:
    return when.isoformat() if when else ""


@dataclass
class StaticTlsProbe:
    """Canned answers. Real, for the tests — no network, no clock skew."""

    answers: dict = field(default_factory=dict)
    default: Optional[CertCheck] = None

    def probe(self, hostname: str, port: int = 443) -> CertCheck:
        got = self.answers.get(hostname)
        if got is not None:
            return got
        if self.default is not None:
            return CertCheck(hostname=hostname, state=self.default.state,
                             detail=self.default.detail, subject=self.default.subject,
                             issuer=self.default.issuer, covers=self.default.covers,
                             not_after=self.default.not_after,
                             days_remaining=self.default.days_remaining)
        # Nothing configured means nothing is serving — the pre-provisioning state, and
        # the safe default for a probe that has not been told otherwise.
        return CertCheck(hostname=hostname, state=ABSENT, detail="no certificate served")


def check_tls(hostnames: list[str], probe: TlsProbe) -> TlsVerdict:
    """Every hostname, one verdict each. Primary and service subdomains alike."""
    return TlsVerdict(checks=tuple(probe.probe(h) for h in hostnames))
