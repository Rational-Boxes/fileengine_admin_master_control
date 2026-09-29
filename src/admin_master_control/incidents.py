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


class IncidentSource(Protocol):
    def fetch(self, **filters) -> list[dict]: ...


@dataclass
class AuditServiceIncidents:
    """audit_service's `/v1/security/incidents`, read over HTTP."""

    base_url: str
    token: str = ""
    timeout_s: float = 10.0

    def fetch(self, **filters) -> list[dict]:
        import httpx

        params = {k: v for k, v in filters.items() if v is not None}
        headers = {"Authorization": f"Bearer {self.token}"} if self.token else {}
        url = self.base_url.rstrip("/") + "/v1/security/incidents"
        try:
            r = httpx.get(url, params=params, headers=headers, timeout=self.timeout_s)
        except Exception as e:  # noqa: BLE001
            raise LedgerUnavailable(f"audit ledger unreachable: {e}") from e
        if r.status_code == 403:
            raise LedgerUnavailable(
                "audit ledger refused this credential — the deployment read role "
                "must be granted in audit_service (AUDIT_DEPLOYMENT_READ_ROLES)")
        if r.status_code >= 400:
            raise LedgerUnavailable(f"audit ledger returned {r.status_code}")
        try:
            return list(r.json().get("incidents") or [])
        except Exception as e:  # noqa: BLE001
            raise LedgerUnavailable(f"audit ledger returned unreadable JSON: {e}") from e


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
