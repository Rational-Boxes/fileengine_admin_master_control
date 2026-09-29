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

"""Reading the security ledger, and the two views built on it.

PROPOSAL_system_administration_application.md §3.4, which names two distinct
capabilities and is explicit that the second is the one that does not exist
anywhere else:

  * **Aggregation** — every incident from every tenant in one severity-ranked
    view. Straightforward; it reads what audit_service already records.
  * **Cross-tenant detection** — the campaign that produces no incident in any
    tenant because each tenant is below threshold. The detection has to happen
    where the events are (audit_service §3.5/§3.6, built 2026-09-29); this is
    where the result is seen.

**The ledger, not the stream.** §5.1 is emphatic and the platform has already
made this mistake once elsewhere: the Redis stream is `XADD`ed with `MAXLEN ~`,
so it forgets, and a console built on it loses history with a node and cannot
rebuild from zero. So this reads audit_service's durable store through its API —
never its schema, and never the stream.

**Through the API, with the deployment tier's own credential.** Not a
`system_admin` token: that role is the core's ACL bypass and reads every file in
every tenant, which is far more than this needs. audit_service grants the global
audit read to `system_observer`/`system_security` instead.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Iterable, Optional, Protocol

log = logging.getLogger("admin_master_control.incidents")

#: Worst first. Mirrors audit_service's ordering; the two drifting apart would
#: silently reorder this console, so a test pins them together.
SEVERITY_RANK = {"critical": 0, "serious": 1, "warn": 2, "info": 3}


class LedgerUnavailable(Exception):
    """The ledger could not be read.

    Raised rather than returning an empty list, because "no incidents" and "I
    could not ask" look identical in a console and mean opposite things. An
    empty security view is the most reassuring thing a screen can show, and it
    must never be what a failed fetch looks like.
    """


class TransitionRefused(Exception):
    """The procedure does not allow that move.

    Distinct from :class:`LedgerUnavailable` on purpose: "you cannot approve
    something nobody acknowledged" is a correct answer, and presenting it as an
    outage would teach an administrator to retry rather than to read it.
    """


def _detail(r) -> str:
    try:
        return str(r.json().get("detail") or r.text)
    except Exception:  # noqa: BLE001
        return r.text[:200]


class IncidentSource(Protocol):
    def fetch(self, **filters) -> list[dict]: ...


@dataclass
class AuditServiceIncidents:
    """audit_service's `/v1/security/incidents`, read over HTTP."""

    base_url: str
    token: str = ""
    timeout_s: float = 10.0

    def _call(self, method: str, path: str, *, params=None, json=None) -> dict:
        import httpx

        headers = {"Authorization": f"Bearer {self.token}"} if self.token else {}
        url = self.base_url.rstrip("/") + path
        try:
            r = httpx.request(method, url, params=params, json=json, headers=headers,
                              timeout=self.timeout_s)
        except Exception as e:  # noqa: BLE001
            raise LedgerUnavailable(f"audit ledger unreachable: {e}") from e
        if r.status_code == 403:
            raise LedgerUnavailable(
                "audit ledger refused this credential — the deployment read role "
                "must be granted in audit_service (AUDIT_DEPLOYMENT_READ_ROLES)")
        if r.status_code == 409:
            # The procedure refused the move. Surfaced as its own type so the
            # route can answer 409 rather than flattening it into "unavailable",
            # which would read as an outage instead of "you cannot do that yet".
            raise TransitionRefused(_detail(r))
        if r.status_code >= 400:
            raise LedgerUnavailable(f"audit ledger returned {r.status_code}: {_detail(r)}")
        try:
            return dict(r.json())
        except Exception as e:  # noqa: BLE001
            raise LedgerUnavailable(f"audit ledger returned unreadable JSON: {e}") from e

    def fetch(self, **filters) -> list[dict]:
        params = {k: v for k, v in filters.items() if v is not None}
        return list(self._call("GET", "/v1/security/incidents",
                               params=params).get("incidents") or [])

    def queue(self, **filters) -> dict:
        params = {k: v for k, v in filters.items() if v is not None}
        return self._call("GET", "/v1/security/queue", params=params)

    def backlog(self, **filters) -> dict:
        params = {k: v for k, v in filters.items() if v is not None}
        return self._call("GET", "/v1/security/queue/backlog", params=params)

    def item_history(self, incident_id: int) -> dict:
        return self._call("GET", f"/v1/security/incidents/{incident_id}/history")

    def transition(self, **body) -> dict:
        return self._call("POST", "/v1/security/queue/transition", json=body)


@dataclass
class StaticIncidents:
    """A ledger held in memory. Real, for development and the tests — a view
    whose behaviour can only be checked against a live audit_service is a view
    nobody checks."""

    rows: list = field(default_factory=list)

    def fetch(self, **filters) -> list[dict]:
        out = list(self.rows)
        for key in ("tenant", "status", "audience", "scope"):
            want = filters.get(key)
            if want is not None:
                out = [r for r in out if r.get(key) == want]
        ms = filters.get("min_severity")
        if ms is not None:
            if ms not in SEVERITY_RANK:
                raise ValueError(f"bad min_severity: {ms!r}")
            out = [r for r in out if SEVERITY_RANK.get(r.get("severity"), 9) <= SEVERITY_RANK[ms]]
        if filters.get("order") == "severity":
            out.sort(key=lambda r: (SEVERITY_RANK.get(r.get("severity"), 9),
                                    _neg_ts(r.get("ts"))))
        limit = filters.get("limit")
        return out[: int(limit)] if limit else out


@dataclass
class StaticQueue(StaticIncidents):
    """StaticIncidents plus the queue, for testing the console without
    audit_service. Holds the same append-only discipline so the tests exercise
    the procedure rather than a permissive double."""

    transitions: dict = field(default_factory=dict)   # incident_id -> [entries]

    #: Mirrors audit_service.queue.TRANSITIONS. Duplicated in a DOUBLE rather
    #: than imported, deliberately: importing it would make these tests pass
    #: whatever audit_service allowed, including a future widening nobody
    #: reviewed. A test pins the two together instead.
    MOVES = {
        "raised": ("acknowledged",),
        "acknowledged": ("customer_confirmed", "declined"),
        "customer_confirmed": ("approved", "declined"),
        "approved": ("completed",),
        "declined": (),
        "completed": (),
    }
    OPEN = ("raised", "acknowledged", "customer_confirmed", "approved")

    def state_of(self, incident_id: int) -> str:
        entries = self.transitions.get(incident_id) or []
        return entries[-1]["state"] if entries else "raised"

    def queue(self, **filters) -> dict:
        want = filters.get("state")
        out = []
        for r in self.rows:
            if r.get("audience") != filters.get("audience", "deployment"):
                continue
            st = self.state_of(r["id"])
            if want is not None and st != want:
                continue
            out.append({**r, "state": st, "next_states": list(self.MOVES.get(st, ()))})
        return {"items": out, "states": list(self.MOVES)}

    def backlog(self, **filters) -> dict:
        counts = {s: 0 for s in self.MOVES}
        for r in self.rows:
            if r.get("audience") != filters.get("audience", "deployment"):
                continue
            counts[self.state_of(r["id"])] += 1
        return {"counts": counts,
                "unacknowledged": counts["raised"],
                "needs_a_human": sum(counts[s] for s in self.OPEN),
                "open": sum(counts[s] for s in self.OPEN)}

    def item_history(self, incident_id: int) -> dict:
        return {"incident_id": incident_id, "state": self.state_of(incident_id),
                "history": list(self.transitions.get(incident_id) or [])}

    def transition(self, **body) -> dict:
        iid = int(body["incident_id"])
        to = str(body.get("state") or "")
        frm = self.state_of(iid)
        if to not in self.MOVES:
            raise TransitionRefused(f"unknown state: {to!r}")
        if to not in self.MOVES.get(frm, ()):
            raise TransitionRefused(f"cannot go {frm} -> {to}")
        if to == "customer_confirmed" and not body.get("counterparty"):
            raise TransitionRefused("customer_confirmed needs the counterparty")
        if to == "declined" and not body.get("reason"):
            raise TransitionRefused("a decline needs a reason")
        if to == "completed" and not body.get("evidence"):
            raise TransitionRefused("completed needs a pointer to the evidence")
        entry = {"state": to, "actor": body.get("actor", ""),
                 "reason": body.get("reason", ""),
                 "counterparty": body.get("counterparty", ""),
                 "evidence": body.get("evidence", "")}
        self.transitions.setdefault(iid, []).append(entry)
        return {"incident_id": iid, "from_state": frm, "state": to}


def _neg_ts(ts) -> str:
    """Sort key that puts newer first among equal severities, without parsing."""
    return "" if ts is None else "".join(chr(0x10FFFD - ord(c)) if ord(c) < 0x10FFFD else c
                                        for c in str(ts))


# ── the two views ──────────────────────────────────────────────────────────


def aggregated(source: IncidentSource, *, limit: int = 100,
               min_severity: Optional[str] = None,
               status: Optional[str] = None) -> dict:
    """Every incident from every tenant, severity-ranked (§3.4 aggregation).

    Ranked rather than time-ordered on purpose: a page of a hundred ordered only
    by time can be entirely `info` while a `critical` sits on page two, which is
    the shape of a console somebody stops trusting.
    """
    rows = source.fetch(limit=limit, min_severity=min_severity, status=status,
                        order="severity")
    return {
        "incidents": rows,
        "counts": _counts(rows),
        "tenants_affected": sorted({r["tenant"] for r in rows if r.get("tenant")}),
    }


def campaigns(source: IncidentSource, *, limit: int = 100) -> dict:
    """The cross-tenant detections — what no tenant could have seen (§3.4).

    `scope=global`, which is the whole point: these incidents were produced by
    windows that dropped the tenant, so each one is a count no single tenant's
    view contains. A deployment administrator reading this is seeing the only
    view in which the campaign exists.
    """
    rows = source.fetch(limit=limit, scope="global", order="severity")
    out = []
    for r in rows:
        touched = list(r.get("distinct_values") or [])
        out.append({
            **r,
            "touched_tenants": touched,
            "fanout": len(touched),
            # Said plainly, because the number on its own does not carry the
            # point: this is why the tenants saw nothing.
            "why_invisible_per_tenant": (
                f"{r.get('match_count')} events from {r.get('group_by')}="
                f"{r.get('group_key')} spread across "
                f"{len(touched) or 'several'} tenants in {r.get('window_s')}s — "
                f"below each tenant's own threshold"),
        })
    return {
        "campaigns": out,
        "counts": _counts(rows),
        "widest_fanout": max((c["fanout"] for c in out), default=0),
    }


def _counts(rows: Iterable[dict]) -> dict:
    counts = {s: 0 for s in SEVERITY_RANK}
    for r in rows:
        sev = r.get("severity")
        if sev in counts:
            counts[sev] += 1
    counts["total"] = sum(counts[s] for s in SEVERITY_RANK)
    return counts


def from_config(cfg) -> IncidentSource:
    """Build the source, or one that refuses honestly.

    With no audit URL configured this returns a source that RAISES rather than
    one that returns nothing: /readyz already reports the missing URL, and a
    security view that renders an empty, reassuring page because it was never
    wired up is the worst available failure.
    """
    url = getattr(cfg, "audit_url", "") or ""
    if not url:
        log.warning("no audit ledger configured — the security view will refuse, "
                    "not show an empty page")

        class Unconfigured:
            def fetch(self, **_f):
                raise LedgerUnavailable("no audit ledger configured (AMC_AUDIT_URL)")

        return Unconfigured()
    return AuditServiceIncidents(base_url=url, token=getattr(cfg, "audit_token", "") or "")
