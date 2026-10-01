# Copyright (C) 2026 James Hickman <james@rationalboxes.com>
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
"""The DNS gate's real resolver: ask the ZONE'S nameservers, accept only AA answers.

Production 2026-10-01: only SystemResolver existed, which honestly reports every
answer as non-authoritative, so every hostname of every tenant showed a red "no"
with "answered by the local resolver" — for names that resolved perfectly. The
gate was right to refuse a local answer; what was missing was the authoritative one.
"""
from __future__ import annotations

import os

import dns.flags
import dns.message
import dns.rcode
import dns.rrset
import pytest

from admin_master_control.tenants import AuthoritativeResolver, check_dns

ZONE = "example.com."
NS = {"ns1.example.net.": "192.0.2.1", "ns2.example.net.": "192.0.2.2"}


def _reply(qname, *, aa=True, rcode=dns.rcode.NOERROR, a=(), cname=None):
    q = dns.message.make_query(qname, "A")
    r = dns.message.make_response(q)
    if aa:
        r.flags |= dns.flags.AA
    r.set_rcode(rcode)
    if cname:
        r.answer.append(dns.rrset.from_text(qname, 300, "IN", "CNAME", cname))
    if a:
        r.answer.append(dns.rrset.from_text(cname or qname, 300, "IN", "A", *a))
    return r


def _resolver(answers, *, fail=()):
    """answers: {(ns_ip, qname): reply}; fail: ns ips that time out."""
    sent = []

    def query(msg, ip):
        sent.append((ip, msg.question[0].name.to_text(), bool(msg.flags & dns.flags.RD)))
        if ip in fail:
            raise dns.exception.Timeout()
        return answers[(ip, msg.question[0].name.to_text())]

    r = AuthoritativeResolver(zone_for=lambda h: ZONE,
                              nameservers_of=lambda z: list(NS.items()),
                              query=query)
    return r, sent


def test_an_authoritative_answer_is_authoritative():
    r, sent = _resolver({("192.0.2.1", "acme.example.com."): _reply("acme.example.com.", a=["203.0.113.10"])})
    addrs, auth, detail = r.addresses("acme.example.com")
    assert addrs == ("203.0.113.10",) and auth is True and detail == ""
    # Recursion is OFF: we are asking the zone, not a resolver.
    assert sent[0][2] is False


def test_a_reply_without_the_aa_flag_is_not_trusted():
    r, _ = _resolver({("192.0.2.1", "acme.example.com."): _reply("acme.example.com.", aa=False, a=["203.0.113.10"]),
                      ("192.0.2.2", "acme.example.com."): _reply("acme.example.com.", aa=False, a=["203.0.113.10"])})
    addrs, auth, detail = r.addresses("acme.example.com")
    assert auth is False and "authoritative" in detail


def test_an_authoritative_nxdomain_is_no_record_the_waiting_case():
    r, _ = _resolver({("192.0.2.1", "acme-drive.example.com."): _reply("acme-drive.example.com.", rcode=dns.rcode.NXDOMAIN)})
    addrs, auth, detail = r.addresses("acme-drive.example.com")
    assert addrs == () and auth is True and detail == "no record"


def test_a_dead_nameserver_falls_through_to_the_next():
    r, sent = _resolver({("192.0.2.2", "acme.example.com."): _reply("acme.example.com.", a=["203.0.113.10"])},
                        fail={"192.0.2.1"})
    addrs, auth, _ = r.addresses("acme.example.com")
    assert addrs == ("203.0.113.10",) and auth is True
    assert [s[0] for s in sent] == ["192.0.2.1", "192.0.2.2"]


def test_no_nameserver_answering_is_said_plainly_and_not_authoritative():
    r, _ = _resolver({}, fail=set(NS.values()))
    addrs, auth, detail = r.addresses("acme.example.com")
    assert addrs == () and auth is False and "no authoritative nameserver answered" in detail


def test_a_cname_is_followed_to_its_addresses():
    r, _ = _resolver({("192.0.2.1", "acme.example.com."):
                      _reply("acme.example.com.", cname="edge.example.com.", a=["203.0.113.10"])})
    addrs, auth, _ = r.addresses("acme.example.com")
    assert addrs == ("203.0.113.10",) and auth is True


def test_the_gate_passes_on_authoritative_matching_answers():
    ans = {("192.0.2.1", f"{h}.example.com."): _reply(f"{h}.example.com.", a=["203.0.113.10"])
           for h in ("acme", "acme-drive")}
    r, _ = _resolver(ans)
    v = check_dns("acme", "example.com", "203.0.113.10", r, ("", "drive"))
    assert v.ok and v.authoritative


@pytest.mark.skipif(not os.environ.get("AMC_LIVE_DNS"), reason="set AMC_LIVE_DNS=1 to query real DNS")
def test_live_against_the_production_zone():
    addrs, auth, detail = AuthoritativeResolver().addresses("rationalboxes-drive.proximafilevault.com")
    assert auth is True, detail
    assert "134.199.137.132" in addrs
