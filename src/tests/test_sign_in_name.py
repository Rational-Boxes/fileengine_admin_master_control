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
"""Signing in by uid OR email, resolved to ONE canonical account.

Found in production on 2026-10-01: the owner's directory entry is
`uid=james` with `mail=james@rationalboxes.com`, and the console built the bind
DN straight from whatever was typed. Signing in with the address the owner
actually uses bound `uid=james@rationalboxes.com,...`, which does not exist, and
answered a bare 401 before the second factor was ever reached.

The rule the rest of the platform already follows (a filter that matches uid OR
mail) applies here too — with one addition this tier needs: everything after the
lookup uses the CANONICAL uid. The grant ledger, the role search, the 2FA store
(keyed by uid) and the token's subject must all name the same account however it
was typed, or one person becomes two principals with different authority.
"""
from __future__ import annotations

import pytest

from admin_master_control.auth import (
    AuthError,
    DirectoryUnavailable,
    LdapDeploymentDirectory,
    StaticDeploymentDirectory,
    login,
)
from admin_master_control.config import Config
from admin_master_control.roles import ALL_ROLES

BASE = "dc=rationalboxes,dc=com"
JAMES_DN = f"uid=james,ou=users,{BASE}"


def _cfg() -> Config:
    c = Config()
    c.jwt_secret = "x" * 48
    return c


def _static() -> StaticDeploymentDirectory:
    return StaticDeploymentDirectory(
        passwords={"james": "pw"},
        grants={"james": set(ALL_ROLES)},
        emails={"james@rationalboxes.com": "james"},
    )


# ── the login contract ──────────────────────────────────────────────────────


def test_signing_in_with_the_email_resolves_to_the_canonical_uid():
    p = login(_cfg(), _static(), "james@rationalboxes.com", "pw")
    assert p.subject == "james"
    assert p.roles == frozenset(ALL_ROLES)


def test_signing_in_with_the_uid_still_works():
    assert login(_cfg(), _static(), "james", "pw").subject == "james"


def test_the_email_is_matched_without_regard_to_case():
    # Addresses are case-insensitive in practice, and so is LDAP's mail match.
    assert login(_cfg(), _static(), "James@RationalBoxes.com", "pw").subject == "james"


def test_an_unknown_name_is_bad_credentials_not_a_different_message():
    # Same 401 and the same words as a wrong password: the login endpoint must not
    # become an oracle for "is this address an account here".
    with pytest.raises(AuthError) as unknown:
        login(_cfg(), _static(), "nobody@rationalboxes.com", "pw")
    with pytest.raises(AuthError) as wrong:
        login(_cfg(), _static(), "james@rationalboxes.com", "not-it")
    assert unknown.value.status_code == wrong.value.status_code == 401
    assert unknown.value.reason == wrong.value.reason


def test_a_directory_without_resolution_keeps_the_old_behaviour():
    class _Plain:
        def authenticate(self, subject, password):
            return subject == "james" and password == "pw"

        def roles_of(self, subject):
            return frozenset(ALL_ROLES)

    assert login(_cfg(), _Plain(), "james", "pw").subject == "james"


# ── LDAP: what is actually sent to the directory ────────────────────────────


class _Entry:
    def __init__(self, uid, dn):
        self.entry_dn = dn
        self.uid = type("A", (), {"value": uid})()
        self.cn = type("A", (), {"value": None})()


class _Conn:
    def __init__(self, log, dn, entries_for, result=0):
        self.log, self.dn = log, dn
        self.entries_for = entries_for
        self.bound = True
        self.entries = []
        self.result = {"result": result, "description": "success" if result == 0 else "noSuchObject"}

    def search(self, base, flt, search_scope=None, attributes=None):
        self.log.append(("search", self.dn, base, flt))
        self.entries = list(self.entries_for(base, flt))
        # ldap3's real rule: True only when entries came back, EVEN ON SUCCESS.
        return bool(self.entries) and self.result["result"] == 0

    def unbind(self):
        pass


def _ldap(monkeypatch, *, users, groups=(), passwords=None, user_search_result=0):
    """An LdapDeploymentDirectory over an in-memory tree, recording every call."""
    passwords = passwords or {}
    log: list = []
    d = LdapDeploymentDirectory(url="ldap://x", base_dn=BASE,
                                bind_dn="cn=svc", bind_password="svc")

    def entries_for(base, flt):
        if base == f"ou=users,{BASE}":
            if user_search_result != 0:
                return []
            return [_Entry(uid, dn) for uid, mail, dn in users
                    if f"(uid={_esc(uid)})" in flt or f"(mail={_esc(mail)})" in flt]
        if base == f"ou=system,{BASE}":
            return [type("G", (), {"cn": type("A", (), {"value": cn})()})()
                    for cn, member in groups if f"(member={member})" in flt]
        return []

    def connect(dn, password):
        log.append(("bind", dn))
        if dn == "cn=svc":
            return _Conn(log, dn, entries_for,
                         result=user_search_result)
        c = _Conn(log, dn, entries_for)
        c.bound = passwords.get(dn) == password
        return c

    monkeypatch.setattr(d, "_connect", connect)
    return d, log


def _esc(v):
    from ldap3.utils.conv import escape_filter_chars
    return escape_filter_chars(v)


USERS = [("james", "james@rationalboxes.com", JAMES_DN)]


def test_ldap_binds_as_the_dn_the_search_found_not_one_built_from_input(monkeypatch):
    d, log = _ldap(monkeypatch, users=USERS, passwords={JAMES_DN: "pw"},
                   groups=[("system_owner", JAMES_DN)])
    p = login(_cfg(), d, "james@rationalboxes.com", "pw")
    assert p.subject == "james"
    assert ("bind", JAMES_DN) in log
    assert ("bind", f"uid=james@rationalboxes.com,ou=users,{BASE}") not in log


def test_ldap_roles_are_read_for_the_resolved_account(monkeypatch):
    d, _ = _ldap(monkeypatch, users=USERS, passwords={JAMES_DN: "pw"},
                 groups=[(r, JAMES_DN) for r in ALL_ROLES])
    assert login(_cfg(), d, "james@rationalboxes.com", "pw").roles == frozenset(ALL_ROLES)


def test_ldap_filter_metacharacters_are_escaped(monkeypatch):
    d, log = _ldap(monkeypatch, users=USERS, passwords={JAMES_DN: "pw"})
    with pytest.raises(AuthError):
        login(_cfg(), d, "*)(uid=*", "pw")
    searches = [f for kind, *rest in log if kind == "search" for f in [rest[-1]]]
    assert searches and all("(uid=*)" not in f for f in searches)
    assert any("\\2a" in f for f in searches)


def test_ldap_an_ambiguous_name_is_refused(monkeypatch):
    # Two accounts answering to one sign-in name is a directory defect; choosing
    # either would be guessing which person is signing in.
    twin = ("james2", "james@rationalboxes.com", f"uid=james2,ou=users,{BASE}")
    d, _ = _ldap(monkeypatch, users=USERS + [twin], passwords={JAMES_DN: "pw"})
    with pytest.raises(AuthError) as e:
        login(_cfg(), d, "james@rationalboxes.com", "pw")
    assert e.value.status_code == 401


def test_ldap_an_unreadable_user_ou_is_unavailable_not_unknown(monkeypatch):
    d, _ = _ldap(monkeypatch, users=USERS, passwords={JAMES_DN: "pw"},
                 user_search_result=32)
    with pytest.raises(DirectoryUnavailable):
        login(_cfg(), d, "james@rationalboxes.com", "pw")


def test_ldap_an_account_with_no_role_is_403_not_503(monkeypatch):
    # ldap3 returns False from search() for "no entries" even when the search
    # SUCCEEDED. roles_of used to read that as "could not search" and answer 503,
    # telling a plain non-administrator to come back later.
    d, _ = _ldap(monkeypatch, users=USERS, passwords={JAMES_DN: "pw"}, groups=[])
    with pytest.raises(AuthError) as e:
        login(_cfg(), d, "james@rationalboxes.com", "pw")
    assert e.value.status_code == 403
    assert not isinstance(e.value, DirectoryUnavailable)
