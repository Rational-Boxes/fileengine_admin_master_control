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
from admin_master_control import tenants as t

TEN = "ten@rationalboxes.com"
OBS = "obs@rationalboxes.com"
SEC = "sec@rationalboxes.com"

BASE = "rationalboxes.com"
ADDR = "203.0.113.10"


def _ready(tenant_id="acme", base=BASE, address=ADDR, **kw) -> t.StaticResolver:
    """A resolver on which the gate SHOULD pass: every hostname, right address."""
    return t.StaticResolver(
        answers={h: (address,) for h in t.hostnames_for(tenant_id, base)}, **kw)



# ── the tenant id reaches four interpreters (§5.3.1) ───────────────────────


def test_a_tenant_id_is_a_narrow_shape():
    for good in ("acme", "acmecorp", "a1", "x" * 31):
        assert t.validate_tenant_id(good) == good


@pytest.mark.parametrize("bad", [
    "",
    "A",                    # the id becomes a Postgres schema and an LDAP ou
    "1acme",                # must start with a letter
    "-acme",
    "acme_corp",            # underscore is not valid in a hostname label
    # A HYPHEN is refused, and this is the one on the list that is a reachability
    # bug rather than a syntax one. The doors split the leading DNS label on '-' and
    # keep the first segment (`<tenant>-<interface>`, e.g. `acme-drive` for WebDAV),
    # so `acme-corp` can never be reached as itself — and `acme-corp.example.com`
    # would serve tenant `acme`, handing its users somebody else's data.
    #
    # This test asserted acme-corp was VALID until 2026-09-30. The registry still
    # holds rows like `filenginetest-drive` created before the rule was enforced,
    # because the core auto-registers any tenant it is asked about.
    "acme-corp",
    "acme-drive",
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


# ── the job handed to the runner (§5.3) ────────────────────────────────────
#
# The gate itself is now the registry's conditional UPDATE, so the tests that used to
# live here — "provisioning is refused unless the gate passed", the override, the
# double press — moved to test_registry.py where the gate actually is. What remains
# here is the pure part: validation, derivation, the DNS check and the job payload.


def _job(**over):
    kw = dict(tenant_id="acme", base_domain=BASE, address=ADDR,
              initial_admin="admin@acme.test",
              hostnames=t.hostnames_for("acme", BASE), requested_by=TEN,
              dns_verified=True)
    kw.update(over)
    return t.provisioning_job(**kw)


def test_the_job_passes_parameters_as_structured_data():
    job = _job()
    assert job["extra_vars"]["tenant_id"] == "acme"
    assert isinstance(job["extra_vars"], dict), "not a command line"
    assert "command" not in job and "argv" not in job and "shell" not in job


def test_the_job_carries_no_credential():
    blob = str(_job()).lower()
    for secret in ("password", "vault", "secret", "token", "api_key", "private_key"):
        assert secret not in blob, f"the job should not carry {secret}"


def test_the_job_names_who_asked():
    assert _job()["requested_by"] == TEN
    with pytest.raises(t.TenantError):
        _job(requested_by="")


def test_the_job_carries_the_override_reason_not_just_the_actor():
    # The reason was missing at first while the actor was present, which got the
    # emphasis backwards. If this run burns the domain's issuance limit, who pressed
    # it is in the audit trail either way; what they believed about the zone is the
    # only thing that explains the decision.
    job = _job(dns_verified=False, override_by=TEN, override_reason="customer-managed zone")
    assert job["dns_overridden_by"] == TEN
    assert job["dns_override_reason"] == "customer-managed zone"
    assert job["dns_verified"] is False, "an override is not a verification"


def test_the_job_no_longer_second_guesses_the_gate():
    """It used to refuse unless a request object said `verified`.

    That was a check on a value the process had read earlier, so two callers could
    both pass it. The gate is now the registry's conditional UPDATE — which either
    claims the row or does not — and this function is only reached once that has
    succeeded. A second opinion here could only ever disagree with the one that
    counts.
    """
    # No state argument exists to be wrong about.
    assert "state" not in _job()
    assert _job(dns_verified=False)["extra_vars"]["tenant_id"] == "acme"


# ── what the doors would resolve an id to ──────────────────────────────────


def test_the_base_id_is_what_the_doors_resolve_to():
    # The bridge splits the leading label on '-' and keeps the first segment. The
    # suffix is NOT a fixed list — its own comment gives `acme-staging` as well as
    # `acme-drive` — so this is a split, not a lookup.
    assert t.base_tenant_id("acme") == "acme"
    assert t.base_tenant_id("acme-drive") == "acme"
    assert t.base_tenant_id("acme-staging") == "acme"
    assert t.base_tenant_id("acme-a-b") == "acme"


def test_a_hyphenated_id_is_not_reachable_as_itself():
    assert t.reachable_by_hostname("acme")
    assert not t.reachable_by_hostname("acme-drive")
    assert not t.reachable_by_hostname("filenginetest-drive")
    assert not t.reachable_by_hostname("")


def test_every_id_this_console_will_now_create_is_reachable():
    # The validator and the reachability rule have to agree, or the console creates
    # tenants nobody can reach. Asserted as a property rather than by example.
    for good in ("acme", "acmecorp", "a1", "x" * 31):
        assert t.reachable_by_hostname(t.validate_tenant_id(good))


# ── the interfaces: each is its own subdomain, DNS and certificate ─────────
#
# `<tenant>-drive` is not a naming flourish — it is a separate hostname that needs its
# own A record and its own certificate. That is why the set is configured rather than
# hardcoded: adding one adds a record the zone must carry and a certificate the
# playbook must obtain, and a hostname the gate does not know about is one the run
# still tries to certify, failing on it after the earlier certificates have already
# spent issuance from a limit shared by every tenant on the domain.


def test_the_default_interfaces_are_the_tenant_host_and_webdav():
    assert t.DEFAULT_INTERFACES == ("", "drive")
    assert t.hostnames_for("acme", BASE) == [f"acme.{BASE}", f"acme-drive.{BASE}"]


def test_the_tenant_own_host_is_always_included():
    # A tenant that resolves only on -drive is not reachable, so the bare host is not
    # optional however the list is configured.
    assert t.interface_suffixes("drive")[0] == ""
    assert t.interface_suffixes("mcp,docs")[0] == ""
    assert t.interface_suffixes("")[0] == ""


def test_adding_an_interface_adds_a_hostname_a_record_and_a_check():
    ifaces = t.interface_suffixes("drive,mcp,docs")
    assert t.hostnames_for("acme", BASE, ifaces) == [
        f"acme.{BASE}", f"acme-drive.{BASE}", f"acme-mcp.{BASE}", f"acme-docs.{BASE}"]
    # A record for each, because each needs its own certificate.
    assert [r.name for r in t.records_for("acme", BASE, ADDR, ifaces)] == \
        t.hostnames_for("acme", BASE, ifaces)
    # And the gate covers every one of them.
    v = t.check_dns("acme", BASE, ADDR, t.StaticResolver(answers={}), ifaces)
    assert len(v.checks) == 4


def test_a_new_interface_is_blocking_until_its_record_exists():
    # The point of threading the list through the gate: an interface nobody has created
    # a record for must STOP provisioning, not be discovered at the certificate step.
    ifaces = t.interface_suffixes("drive,mcp")
    ready_three = t.StaticResolver(
        answers={h: (ADDR,) for h in t.hostnames_for("acme", BASE, ifaces)[:2]})
    v = t.check_dns("acme", BASE, ADDR, ready_three, ifaces)
    assert not v.ok
    assert f"acme-mcp.{BASE}" in v.blocking_reason


def test_the_suffix_list_is_forgiving_of_how_it_is_written():
    for spelling in ("drive", " drive ", "-drive", "DRIVE", "drive,drive"):
        assert t.interface_suffixes(spelling) == ("", "drive"), spelling


def test_an_interface_suffix_is_not_a_tenant():
    # `acme-drive` is a hostname of tenant `acme`. It is not a tenant, and the
    # validator now refuses it — which is what stops the console creating the very
    # rows the registry already holds from before the rule existed.
    with pytest.raises(t.TenantError):
        t.validate_tenant_id("acme-drive")
    assert t.base_tenant_id("acme-drive") == "acme"
