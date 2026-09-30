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

"""Signing in, for tests of everything that happens after it.

Every suite needs a bearer token and none of them is about how one is obtained,
so the two-step login lives here once. Before the second factor was verified,
each suite posted `{"second_factor": "totp"}` and got a token straight back; that
field is gone, and 64 tests failed when it went — which is the evidence the old
path is unreachable rather than merely discouraged.

`headers()` walks the real flow: password, then the code. It deliberately does
NOT bypass the gate by minting a token directly, because a fixture that skips the
door is a fixture that would keep passing if the door broke.
"""
from __future__ import annotations

from admin_master_control.mfa import StaticFactors

#: The code `StaticFactors` accepts. Not a secret and not a real TOTP — the TOTP
#: arithmetic is ldap_manager's and is tested there.
CODE = "424242"


def factors(*enrolled: str, code: str = CODE, unavailable: bool = False) -> StaticFactors:
    """A factor store in which the named subjects are already enrolled.

    Anyone NOT named has no factor, so they get the enrollment challenge — which
    is the first-login path, and worth being the default rather than a special
    case a test has to opt into.
    """
    return StaticFactors(enrolled={uid: code for uid in enrolled}, unavailable=unavailable)


def login(client, subject: str, password: str = "pw", *, code: str = CODE) -> dict:
    """The whole flow, returning the session body.

    Asserts the shape as it goes, so a suite that uses this gets the door's
    contract checked for free: the password alone must yield 401 with a challenge,
    never a token.
    """
    first = client.post("/v1/auth/token",
                        json={"subject": subject, "password": password})
    if first.status_code == 200:
        # The opt-out (AMC_REQUIRE_MFA=false). A session straight away.
        return first.json()
    assert first.status_code == 401, first.text
    body = first.json()
    assert "token" not in body, "a password alone must never return a session token"
    challenge = body["challenge_token"]

    if body["status"] == "enroll":
        begun = client.post("/v1/auth/mfa/enroll/begin",
                            json={"challenge_token": challenge})
        assert begun.status_code == 200, begun.text
        challenge = begun.json()["challenge_token"]
        done = client.post("/v1/auth/mfa/enroll/complete",
                           json={"challenge_token": challenge, "code": CODE})
        assert done.status_code == 200, done.text
        return done.json()

    assert body["status"] == "verify", body
    r = client.post("/v1/auth/mfa/verify",
                    json={"challenge_token": challenge, "code": code, "method": "totp"})
    assert r.status_code == 200, r.text
    return r.json()


def headers(client, subject: str, password: str = "pw", *, code: str = CODE) -> dict:
    return {"Authorization": f"Bearer {login(client, subject, password, code=code)['token']}"}
