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

"""Redaction items, and the register of them (§3.3.1, §3.3.2).

WHERE THE REDACTION LINE IS DRAWN, because it is not where people assume.

The risk is **potential PII in content**, never the identity of the principals
who acted. So an item keeps the uids, the roles, the actions and the timestamps —
that is the audit value and destroying it would serve nobody — and it refers to
the file by **UUID alone**. A redacted file keeps its identifier and its whole
historical activity record; what is gone is the payload and, if it was redacted
too, the name.

**A filename is content.** That is the part most likely to be got wrong, because
a name looks like metadata and reads like a label. `invoice_for_Jane_Doe.pdf`
carries exactly what the redaction was for. The audit log therefore stores no
`target_name` at all — deliberately, as "a filename is party data, and this log
is immutable and long-lived" — which means:

    WHEN A NAME WAS REDACTED THERE IS NO SECOND COPY TO FALL BACK ON,
    AND THIS MODULE MUST NOT GO LOOKING FOR ONE.

§3.3.1 is blunt about the consequence: "A reporting surface that quietly made
redacted names visible again to the tier with the most reach would be the worst
possible place for that leak." So :class:`RedactionItem` cannot be constructed
with a name when ``name_retained`` is false — it raises rather than dropping the
argument, because silently ignoring it would let a caller believe it had been
stored and let the next reader believe its absence meant something else.

The conversation with the customer then proceeds from the erasure's reason and
timestamp, which is what §3.3.1 says to do.
"""
from __future__ import annotations

import datetime as _dt
import logging
from dataclasses import dataclass, field
from typing import Optional, Protocol

log = logging.getLogger("admin_master_control.redactions")

#: What the display says in place of a redacted name. One string, in one place,
#: so a console cannot invent a friendlier one that implies the name is merely
#: missing rather than destroyed.
NAME_REDACTED = "name redacted with the payload"

#: Whether the payload reached the offsite copy. The queue can only ever say
#: "expected" — §3.3.1 — because the redaction tool's verification step is what
#: actually answers it, and that runs on cloud B behind its own human step.
OFFSITE_EXPECTED = "expected"
OFFSITE_CONFIRMED = "confirmed"
OFFSITE_ABSENT = "confirmed-absent"
OFFSITE_UNKNOWN = "unknown"
OFFSITE_STATES = (OFFSITE_EXPECTED, OFFSITE_CONFIRMED, OFFSITE_ABSENT, OFFSITE_UNKNOWN)


class RedactionError(ValueError):
    """An item that would misrepresent what survived the erasure."""


@dataclass(frozen=True)
class RedactionItem:
    """One redaction awaiting, or having had, a human decision.

    Every field is either an identifier, a timestamp, a principal or a reason.
    There is deliberately no field for content, no path, and no name unless the
    name survived the erasure.
    """

    erasure_id: str
    file_uid: str
    tenant: str
    initiated_at: str
    #: The principal who initiated the erasure. KEPT: "who" is not the redaction
    #: concern, and an erasure with no attributable actor is unauditable.
    actor: str
    reason: str = ""
    #: False means the name was redacted with the payload. There is then no
    #: name, anywhere, and this application must show its absence.
    name_retained: bool = False
    #: Only ever set when name_retained is true.
    file_name: Optional[str] = None
    tenant_contact: str = ""
    offsite: str = OFFSITE_EXPECTED

    def __post_init__(self) -> None:
        if not self.erasure_id:
            raise RedactionError("a redaction item needs its erasure_id")
        if not self.file_uid:
            # The uid is the whole point: it is what survives and what ties the
            # item to the file's historical activity.
            raise RedactionError("a redaction item needs the file_uid")
        if not self.tenant:
            raise RedactionError("a redaction item needs its tenant")
        if self.offsite not in OFFSITE_STATES:
            raise RedactionError(f"bad offsite state: {self.offsite!r}")
        if not self.name_retained and self.file_name:
            # RAISES rather than dropping it. Silently ignoring the argument
            # would let the caller believe the name had been stored and the next
            # reader believe its absence meant something else.
            raise RedactionError(
                "file_name was supplied for an item whose name was redacted. "
                "There is no second copy of a redacted name and this must not "
                "become one — pass name_retained=True only when the name "
                "genuinely survived the erasure.")

    @property
    def display_name(self) -> str:
        """What a console shows. Never a guess, never a lookup."""
        if self.name_retained and self.file_name:
            return self.file_name
        return NAME_REDACTED

    def for_display(self) -> dict:
        """The item as a console should render it.

        `file_name` is absent from the payload entirely when the name was
        redacted, rather than present-and-null: a null invites a client to fill
        it in from somewhere, and there is nowhere.
        """
        out = {
            "erasure_id": self.erasure_id,
            "file_uid": self.file_uid,
            "tenant": self.tenant,
            "tenant_contact": self.tenant_contact,
            "initiated_at": self.initiated_at,
            "actor": self.actor,
            "reason": self.reason,
            "name_retained": self.name_retained,
            "display_name": self.display_name,
            "offsite": self.offsite,
            # The point of keeping the uid: the file's history is still there to
            # be read, and this is how a console gets to it without ever needing
            # the name.
            "activity_query": {"target_uid": self.file_uid, "tenant": self.tenant},
        }
        if self.name_retained and self.file_name:
            out["file_name"] = self.file_name
        return out


class ErasureSource(Protocol):
    """Where redaction items come from.

    NOT WIRED TO A LIVE SOURCE YET. §3.3.1 says the fields come from the core's
    `erasure` row (which retains the id, timestamp, actor and reason
    deliberately) plus LDAP for the tenant's administrative contact. Reading
    them means a cursor over the core's erasure table or an audit_service
    endpoint over it, and neither exists — so this protocol is the seam, and
    :class:`StaticErasures` is what the tests and a development instance use.
    """

    def items(self) -> list[RedactionItem]: ...


@dataclass
class StaticErasures:
    rows: list = field(default_factory=list)

    def items(self) -> list[RedactionItem]:
        return list(self.rows)


# ── the register (§3.3.2) ──────────────────────────────────────────────────


def _age_hours(iso: str, now: Optional[_dt.datetime] = None) -> float:
    try:
        then = _dt.datetime.fromisoformat(iso.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return 0.0
    if then.tzinfo is None:
        then = then.replace(tzinfo=_dt.timezone.utc)
    now = now or _dt.datetime.now(_dt.timezone.utc)
    return max(0.0, (now - then).total_seconds() / 3600.0)


def register(source: ErasureSource, states: dict, *,
            now: Optional[_dt.datetime] = None) -> dict:
    """Every redaction, its state, and how long it has been in it.

    §3.3.2: "the obligation this serves is one the organisation has undertaken,
    and 'we performed it' is a claim that has to be evidenced later."

    ``states`` maps erasure_id -> {"state": ..., "evidence": ...} from the
    acknowledgement queue. Items with no entry are outstanding and unlooked-at,
    which is the number that matters.

    THE THIRD BUCKET IS THE HONEST ONE. §3.3.2 asks for "the ones where the loop
    was never closed" — approved and then never completed. Those are the items an
    organisation would most like to forget and exactly the ones it must be able
    to produce, so they are counted separately rather than folded into
    "outstanding".
    """
    outstanding, completed, unclosed = [], [], []
    for item in source.items():
        st = states.get(item.erasure_id) or {}
        state = st.get("state") or "raised"
        row = {**item.for_display(), "state": state,
               "age_hours": round(_age_hours(item.initiated_at, now), 2)}
        if state == "completed":
            # The receipt from the redaction tool. §3.3.2 wants it shown; the
            # return path itself is not yet designed, so an absent receipt is
            # reported rather than assumed.
            row["evidence"] = st.get("evidence") or ""
            row["evidenced"] = bool(st.get("evidence"))
            completed.append(row)
        elif state == "approved":
            unclosed.append(row)
        elif state == "declined":
            row["reason_declined"] = st.get("reason") or ""
            completed.append(row)          # finished, though not performed
        else:
            outstanding.append(row)

    outstanding.sort(key=lambda r: r["age_hours"], reverse=True)
    unclosed.sort(key=lambda r: r["age_hours"], reverse=True)
    return {
        "outstanding": outstanding,
        "approved_not_completed": unclosed,
        "completed": completed,
        "counts": {
            "outstanding": len(outstanding),
            "approved_not_completed": len(unclosed),
            "completed": len(completed),
            # The one number §3.3.2 calls "the number that matters".
            "oldest_outstanding_hours": (outstanding[0]["age_hours"] if outstanding else 0.0),
            # Completed but with no receipt: performed as far as anyone can tell,
            # and not evidenced. Surfaced because §3.3.2 asks for the loop to be
            # honestly presented, not for it to look closed.
            "completed_without_evidence": sum(
                1 for r in completed if r.get("state") == "completed" and not r.get("evidenced")),
        },
    }
