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

"""Requesting a tenant, and the gate in front of provisioning (§3.4a, §5.3).

**This application never touches DNS, and never runs Ansible.** DNS is managed
wherever the domain is, by a human — so there is no DNS credential to hold
because there is no DNS operation to perform. And the playbook is executed by a
runner on the host that holds the vault password; this application writes a JOB
and knows only that it asked (§5.3). Driving Ansible from a browser-facing
process would put the highest concentration of authority in the estate behind a
session.

THE DNS CHECK IS A GATE, NOT A STATUS INDICATOR, and that is the whole reason
this module is more than a form. `tenant.yml` provisions an nginx vhost and a
Let's Encrypt certificate per hostname, and issuance validates that the name
resolves here and answers on port 80. Run the playbook before DNS has propagated
and the certificate step fails — **and failed issuance consumes the domain's rate
limit, which is shared by every tenant.**

    A create button that can be pressed early is a button that can exhaust
    certificate issuance for the whole deployment, not just for the tenant being
    created.

So the check blocks the run, it asks the zone's AUTHORITATIVE nameservers rather
than a local resolver, it compares the ADDRESS rather than merely that something
resolves, and it checks EVERY hostname the tenant needs. Each of those is a way
a cheerful green tick can be wrong.

The override exists because the check can fail on a correct setup — split-horizon
DNS, a CDN in front, a zone the administrator does not control. It requires
`system_tenants`, it records who and why, and it is the one path to provisioning
that can burn the rate limit. That is why it is a deliberate act with a name
attached rather than a retry button.
"""
from __future__ import annotations

import datetime as _dt
import logging
import re
import socket
from dataclasses import dataclass, field
from typing import Optional, Protocol

log = logging.getLogger("admin_master_control.tenants")

#: §5.3.1. The tenant id becomes a Postgres schema name, an LDAP OU, a hostname
#: and a container label — a crafted value reaches four interpreters. Validated
#: at the boundary, and parameters are passed to Ansible as JSON via
#: --extra-vars, never interpolated into a command line.
TENANT_ID = re.compile(r"^[a-z][a-z0-9-]{1,30}$")

#: Names that must never become a tenant, because the platform already uses them
#: as hostnames. A tenant called `login` would shadow the sign-in origin.
RESERVED_IDS = frozenset({
    "login", "www", "api", "mcp", "admin", "docs", "cms", "dav", "drive",
    "default",   # exists on every deployment
})

# ── states (§3.4a) ─────────────────────────────────────────────────────────
#
# requested → awaiting_dns → verified → provisioning → live
#                                                    └→ failed
#
# DNS comes BEFORE provisioning rather than during it. The proposal records that
# an earlier draft had it the other way round, and the rate-limit argument above
# is why the order matters.
REQUESTED = "requested"
AWAITING_DNS = "awaiting_dns"
VERIFIED = "verified"
PROVISIONING = "provisioning"
LIVE = "live"
FAILED = "failed"

REQUEST_STATES = (REQUESTED, AWAITING_DNS, VERIFIED, PROVISIONING, LIVE, FAILED)

#: Only these may be handed to the runner.
READY_TO_PROVISION = (VERIFIED,)


class TenantError(ValueError):
    """A request the platform will not accept."""


def validate_tenant_id(tenant_id: str) -> str:
    """§5.3.1's strict pattern, applied at the boundary."""
    if not tenant_id:
        raise TenantError("a tenant id is required")
    if not TENANT_ID.match(tenant_id):
        raise TenantError(
            f"{tenant_id!r} is not a valid tenant id: lower-case letters, digits "
            f"and hyphens, starting with a letter, 2-31 characters. It becomes a "
            f"schema name, an LDAP OU, a hostname and a container label.")
    if tenant_id in RESERVED_IDS:
        raise TenantError(f"{tenant_id!r} is reserved by the platform")
    return tenant_id


def hostnames_for(tenant_id: str, base_domain: str) -> list[str]:
    """Every hostname the tenant needs, which is what the DNS check must cover.

    A missing `<tenant>-drive` "fails later and less legibly" (§3.4a) — the
    playbook gets through the first certificate and stops on the second, by which
    point the run is half done.
    """
    validate_tenant_id(tenant_id)
    if not base_domain:
        raise TenantError("a base domain is required")
    return [f"{tenant_id}.{base_domain}", f"{tenant_id}-drive.{base_domain}"]


@dataclass(frozen=True)
class DnsRecord:
    """One record for the administrator to paste into the zone."""

    name: str
    type: str
    value: str

    def as_zone_line(self) -> str:
        return f"{self.name}.\t300\tIN\t{self.type}\t{self.value}"


def records_for(tenant_id: str, base_domain: str, address: str) -> list[DnsRecord]:
    """Exactly the records to create, in a form meant for pasting (§3.4a step 1)."""
    if not address:
        raise TenantError("the address these records must point at is required")
    rtype = "AAAA" if ":" in address else "A"
    return [DnsRecord(name=h, type=rtype, value=address)
            for h in hostnames_for(tenant_id, base_domain)]


# ── the DNS gate ───────────────────────────────────────────────────────────


@dataclass(frozen=True)
class HostCheck:
    hostname: str
    resolved: tuple[str, ...] = ()
    expected: str = ""
    ok: bool = False
    detail: str = ""


@dataclass(frozen=True)
class DnsVerdict:
    ok: bool
    checks: tuple[HostCheck, ...] = ()
    authoritative: bool = False
    detail: str = ""

    @property
    def blocking_reason(self) -> str:
        """Why the gate did not pass, per hostname, INCLUDING each detail.

        An earlier version listed only the hostnames, which reads as "wait
        longer" for every cause. The causes need opposite responses and only one
        of them improves on its own:

          * "no record" — the administrator has not created it yet, or it is
            still propagating. Waiting is the right move.
          * "resolves to 198.51.100.4, expected 203.0.113.10" — the name points
            at the old host. Waiting will never fix this, and someone watching a
            hostname-only message will wait anyway.
          * "answer was not authoritative" — nothing is wrong with the zone; this
            deployment cannot see it from here, and the override exists for it.

        A message that cannot distinguish those turns the third case into an hour
        of waiting and the second into a support call.
        """
        if self.ok:
            return ""
        bad = [f"{c.hostname} ({c.detail})" if c.detail else c.hostname
               for c in self.checks if not c.ok]
        if bad:
            return f"DNS not ready for: {'; '.join(bad)}"
        return self.detail or "DNS check did not pass"


class Resolver(Protocol):
    """Answers "what does the AUTHORITATIVE nameserver say for this name".

    Injectable because the gate must be testable without DNS, and because the
    real implementation needs the zone's nameservers rather than the local
    resolver — see :class:`SystemResolver` for why that distinction is the whole
    point.
    """

    def addresses(self, hostname: str) -> tuple[tuple[str, ...], bool, str]: ...


@dataclass
class SystemResolver:
    """The LOCAL resolver. Deliberately reports itself as non-authoritative.

    §3.4a: "Query the zone's authoritative nameservers, not the local resolver. A
    cached NXDOMAIN blocks a record that has in fact propagated; a local override
    or a search-domain quirk shows a success the world does not see."

    So this exists as a fallback and says so: `authoritative=False` travels with
    the answer, and :func:`check_dns` refuses to pass a non-authoritative answer
    as a gate. Getting a real one needs a DNS library that can query NS records
    directly (dnspython); until that is a dependency, the honest behaviour is to
    make the administrator use the recorded override rather than to let a local
    lookup masquerade as proof.
    """

    def addresses(self, hostname: str) -> tuple[tuple[str, ...], bool, str]:
        try:
            infos = socket.getaddrinfo(hostname, None)
        except socket.gaierror as e:
            return (), False, f"does not resolve locally ({e.strerror or e})"
        addrs = tuple(sorted({i[4][0] for i in infos}))
        return addrs, False, "answered by the local resolver, which is not authoritative"


@dataclass
class StaticResolver:
    """A resolver with known answers. Real, for development and the tests."""

    answers: dict = field(default_factory=dict)
    authoritative: bool = True
    error: Optional[str] = None

    def addresses(self, hostname: str) -> tuple[tuple[str, ...], bool, str]:
        if self.error:
            return (), self.authoritative, self.error
        got = self.answers.get(hostname)
        if got is None:
            return (), self.authoritative, "no record"
        return tuple(got), self.authoritative, ""


def check_dns(tenant_id: str, base_domain: str, address: str,
              resolver: Resolver) -> DnsVerdict:
    """The gate. Passes only on an authoritative answer matching the address for
    EVERY hostname.

    Three ways this says no that a naive check would say yes to:

      * the answer came from a non-authoritative source — it may be a local
        override or a stale cache, and neither is what the CA will see;
      * the name resolves but to the wrong address — "a name pointing at the
        previous host resolves perfectly and issues nothing";
      * one hostname is missing — the run would get through the first
        certificate and stop on the second.
    """
    checks: list[HostCheck] = []
    all_authoritative = True
    for host in hostnames_for(tenant_id, base_domain):
        addrs, authoritative, detail = resolver.addresses(host)
        all_authoritative = all_authoritative and authoritative
        matches = address in addrs
        ok = bool(addrs) and matches and authoritative
        if not addrs:
            why = detail or "no record"
        elif not matches:
            why = f"resolves to {', '.join(addrs)}, expected {address}"
        elif not authoritative:
            why = detail or "answer was not authoritative"
        else:
            why = ""
        checks.append(HostCheck(hostname=host, resolved=addrs, expected=address,
                                ok=ok, detail=why))

    ok = all(c.ok for c in checks)
    return DnsVerdict(ok=ok, checks=tuple(checks), authoritative=all_authoritative,
                      detail="" if ok else "one or more hostnames are not ready")


# ── the request, and its state ─────────────────────────────────────────────


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat()


@dataclass
class TenantRequest:
    """A tenant part-way through creation — "exactly the outstanding thing §3.2
    exists for, and today it is tracked in somebody's terminal scrollback"."""

    tenant_id: str
    base_domain: str
    address: str
    initial_admin: str
    requested_by: str
    state: str = REQUESTED
    requested_at: str = field(default_factory=_now)
    dns: Optional[DnsVerdict] = None
    #: Set only by an explicit, attributed override.
    override_by: str = ""
    override_reason: str = ""
    #: The runner's last word.
    failed_step: str = ""
    failure_detail: str = ""
    retry_safe: bool = False
    job_id: str = ""

    def __post_init__(self) -> None:
        validate_tenant_id(self.tenant_id)
        if not self.base_domain:
            raise TenantError("a base domain is required")
        if not self.address:
            raise TenantError("the address the hostnames must point at is required")
        if not self.initial_admin:
            # A tenant with no administrator is a tenant nobody can manage, and
            # the platform's own tenant.yml takes one for the same reason.
            raise TenantError("an initial administrator is required")
        if not self.requested_by:
            raise TenantError("a request needs an actor")

    @property
    def hostnames(self) -> list[str]:
        return hostnames_for(self.tenant_id, self.base_domain)

    @property
    def records(self) -> list[DnsRecord]:
        return records_for(self.tenant_id, self.base_domain, self.address)

    @property
    def may_provision(self) -> bool:
        """Whether the runner may be handed this request.

        `verified` only. An override moves the state to `verified` and records
        who did it, so there is ONE gate rather than a gate plus a bypass that
        callers have to remember to check.
        """
        return self.state in READY_TO_PROVISION

    def for_display(self) -> dict:
        out = {
            "tenant_id": self.tenant_id,
            "state": self.state,
            "base_domain": self.base_domain,
            "address": self.address,
            "initial_admin": self.initial_admin,
            "requested_by": self.requested_by,
            "requested_at": self.requested_at,
            "hostnames": self.hostnames,
            "records": [{"name": r.name, "type": r.type, "value": r.value,
                         "zone_line": r.as_zone_line()} for r in self.records],
            "may_provision": self.may_provision,
        }
        if self.dns is not None:
            out["dns"] = {
                "ok": self.dns.ok,
                "authoritative": self.dns.authoritative,
                "blocking_reason": self.dns.blocking_reason,
                "checks": [{"hostname": c.hostname, "ok": c.ok,
                            "resolved": list(c.resolved), "expected": c.expected,
                            "detail": c.detail} for c in self.dns.checks],
            }
        if self.override_by:
            # Always visible. The override is the one path that can burn the
            # shared rate limit, so it is never a quiet flag.
            out["override"] = {"by": self.override_by, "reason": self.override_reason}
        if self.state == FAILED:
            out["failure"] = {"step": self.failed_step, "detail": self.failure_detail,
                              "retry_safe": self.retry_safe}
        if self.job_id:
            out["job_id"] = self.job_id
        return out


def verify(request: TenantRequest, resolver: Resolver) -> TenantRequest:
    """Run the DNS gate and move the state accordingly."""
    verdict = check_dns(request.tenant_id, request.base_domain, request.address, resolver)
    request.dns = verdict
    request.state = VERIFIED if verdict.ok else AWAITING_DNS
    log.info("tenant %s DNS check: %s", request.tenant_id,
             "passed" if verdict.ok else verdict.blocking_reason)
    return request


def override(request: TenantRequest, *, by: str, reason: str) -> TenantRequest:
    """Force past the DNS gate, with a name attached.

    Requires a reason as well as an actor, because this is the one path to
    provisioning that can consume certificate issuance for every tenant on the
    domain. A retry button would not need a reason; this is not a retry.
    """
    if not by:
        raise TenantError("an override needs an actor")
    if not reason:
        raise TenantError(
            "an override needs a reason: it is the one path to provisioning that "
            "can exhaust certificate issuance for the whole deployment")
    if request.state == LIVE:
        raise TenantError("this tenant is already live")
    request.override_by = by
    request.override_reason = reason
    request.state = VERIFIED
    log.warning("tenant %s DNS gate OVERRIDDEN by %s: %s",
                request.tenant_id, by, reason)
    return request


# ── the job handed to the runner (§5.3) ────────────────────────────────────


def provisioning_job(request: TenantRequest, *, requested_by: str) -> dict:
    """What this application writes for the runner to claim.

    Parameters as STRUCTURED DATA, never a command line. §5.3.1: the tenant id
    reaches four interpreters, so it goes to Ansible as JSON via --extra-vars and
    is never interpolated into a shell string. This function returns the data; it
    does not build a command, and nothing here knows how the runner invokes
    anything.

    No credentials. The runner holds the vault password; this application holds
    none and knows only that it asked.
    """
    if not request.may_provision:
        raise TenantError(
            f"tenant {request.tenant_id} is {request.state}, not verified — the DNS "
            f"gate has not passed and has not been overridden. Provisioning now "
            f"would fail at the certificate step and consume the domain's rate "
            f"limit, which is shared by every tenant.")
    if not requested_by:
        raise TenantError("a provisioning job needs an actor")
    return {
        "playbook": "playbooks/tenant.yml",
        # Ansible reads these as --extra-vars JSON. No shell, no interpolation.
        "extra_vars": {
            "tenant_id": request.tenant_id,
            "tenant_admin": request.initial_admin,
            "tenant_hostnames": request.hostnames,
        },
        "requested_by": requested_by,
        "requested_at": _now(),
        "tenant_id": request.tenant_id,
        # Carried so the runner's record shows the gate was passed rather than
        # bypassed, and if it was bypassed, BY WHOM AND WHY.
        #
        # The reason was missing here at first while the actor was present, which
        # got the emphasis backwards. If this run fails at the certificate step
        # and consumes issuance for every tenant on the domain, the question is
        # not who pressed it — that is in the audit trail either way — but what
        # they believed was true about the zone. That is the only field that
        # explains the decision to someone reading it afterwards.
        "dns_verified": bool(request.dns and request.dns.ok),
        "dns_overridden_by": request.override_by,
        "dns_override_reason": request.override_reason,
    }
