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

"""Where tenant requests live, and what that buys beyond surviving a restart.

They were a dict on `app.state`, which lost every in-flight request on restart —
"exactly the outstanding thing §3.2 exists for, and today it is tracked in
somebody's terminal scrollback" was true of this application's own memory.

BUT DURABILITY IS THE SMALLER HALF. The dict could not make the provisioning gate
safe, and the database can:

    Two administrators press Provision at the same moment. Both read
    `state == "verified"`, both pass `may_provision`, and both append a job. Two
    playbook runs, two certificate issuance attempts — against a rate limit
    SHARED BY EVERY TENANT on the domain. That is the precise failure the whole
    DNS gate exists to prevent, and a read-then-write over a dict cannot prevent
    it however carefully the gate is written.

So `claim_for_provisioning` is a single conditional UPDATE: the state moves from
`verified` to `provisioning` in one statement, and the caller writes a job only if
it changed a row. The second press changes nothing and is told so. The gate is
enforced by the database rather than by the order two requests happen to arrive
in — which is the only way a check on shared state is ever actually enforced.

The other reason this is a table rather than a queue in memory: §5.3's boundary is
"requested here, executed by a runner", and a runner in another process needs
somewhere to look. `provisioning_job` is that place, shaped so a claim is safe
(`FOR UPDATE SKIP LOCKED`) rather than assuming one runner.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Optional, Protocol

from .config import Config
from .tenants import (
    PROVISIONING,
    READY_TO_PROVISION,
    DnsVerdict,
    HostCheck,
    TenantError,
    TenantRequest,
)

log = logging.getLogger("admin_master_control.tenant_store")


class TenantExists(TenantError):
    """That id is already requested. Raised by the STORE, not checked before it.

    A `SELECT` then an `INSERT` is two statements and a race; the unique primary
    key is one. Two administrators requesting `acme` simultaneously both pass a
    prior existence check, and only the constraint is authoritative.
    """


class StoreUnavailable(TenantError):
    """The store could not be reached.

    Distinct from "no such tenant" for the reason that keeps recurring here: an
    empty answer and an unanswerable question need different responses, and
    reporting the first when the second happened sends someone looking for a
    tenant that is fine.
    """


# ── serialising the DNS verdict ────────────────────────────────────────────
#
# Stored as JSONB rather than flattened into columns. It is a READING, not
# state — a nested per-hostname result that is displayed and never queried by
# its parts, and the checks list grows if a tenant ever gets a third hostname.


def verdict_to_json(v: Optional[DnsVerdict]) -> Optional[dict]:
    if v is None:
        return None
    return {"ok": v.ok, "authoritative": v.authoritative, "detail": v.detail,
            "checks": [{"hostname": c.hostname, "resolved": list(c.resolved),
                        "expected": c.expected, "ok": c.ok, "detail": c.detail}
                       for c in v.checks]}


def verdict_from_json(d: Optional[dict]) -> Optional[DnsVerdict]:
    if not d:
        return None
    return DnsVerdict(
        ok=bool(d.get("ok")),
        authoritative=bool(d.get("authoritative")),
        detail=str(d.get("detail") or ""),
        checks=tuple(HostCheck(hostname=str(c.get("hostname") or ""),
                               resolved=tuple(c.get("resolved") or ()),
                               expected=str(c.get("expected") or ""),
                               ok=bool(c.get("ok")),
                               detail=str(c.get("detail") or ""))
                     for c in (d.get("checks") or ())))


class TenantStore(Protocol):
    """Reads and writes tenant requests. Injectable so the routes are testable."""

    def ensure_schema(self) -> None: ...
    def get(self, tenant_id: str) -> Optional[TenantRequest]: ...
    def list(self) -> list[TenantRequest]: ...
    def create(self, request: TenantRequest) -> TenantRequest: ...
    def save(self, request: TenantRequest) -> None: ...
    def claim_for_provisioning(self, tenant_id: str) -> Optional[TenantRequest]: ...
    def record_job(self, tenant_id: str, job: dict) -> str: ...
    def jobs(self, *, limit: int = 100) -> list[dict]: ...


# ── the schema ─────────────────────────────────────────────────────────────

_TENANT_DDL = """
CREATE TABLE IF NOT EXISTS tenant_request (
    -- The id is the primary key, not a surrogate: it IS the identity, it is
    -- validated narrowly at entry (§5.3.1), and the uniqueness is the thing that
    -- makes a duplicate request a constraint violation rather than a race.
    tenant_id       text PRIMARY KEY,
    state           text NOT NULL,
    base_domain     text NOT NULL,
    address         text NOT NULL,
    initial_admin   text NOT NULL,
    requested_by    text NOT NULL,
    requested_at    text NOT NULL,
    dns             jsonb,
    override_by     text NOT NULL DEFAULT '',
    override_reason text NOT NULL DEFAULT '',
    failed_step     text NOT NULL DEFAULT '',
    failure_detail  text NOT NULL DEFAULT '',
    retry_safe      boolean NOT NULL DEFAULT false,
    job_id          text NOT NULL DEFAULT '',
    updated_at      timestamptz NOT NULL DEFAULT now()
)
"""

_JOB_DDL = """
CREATE TABLE IF NOT EXISTS provisioning_job (
    id           bigserial PRIMARY KEY,
    tenant_id    text NOT NULL REFERENCES tenant_request(tenant_id),
    -- The whole job as this application wrote it: structured parameters for
    -- --extra-vars, never a command line (§5.3.1). Kept verbatim so the record of
    -- what was ASKED survives any later change to how it is built.
    payload      jsonb NOT NULL,
    requested_by text NOT NULL,
    requested_at timestamptz NOT NULL DEFAULT now(),
    -- queued -> claimed -> done | failed. The runner owns every transition after
    -- queued; this application only ever writes the first.
    state        text NOT NULL DEFAULT 'queued',
    claimed_by   text NOT NULL DEFAULT '',
    claimed_at   timestamptz,
    finished_at  timestamptz,
    detail       text NOT NULL DEFAULT ''
)
"""

_MIGRATIONS = (
    # Migrations run AFTER the CREATEs and each is separately conditional, because
    # `CREATE TABLE IF NOT EXISTS` is a no-op on an existing table — so a column
    # added here never appears on a database that already has the table unless it
    # is added by its own ALTER. An index on a column added in the same block as
    # the CREATE runs before that column exists on an upgrade and fails; this bit
    # once already, and a fresh database would have passed.
    "ALTER TABLE tenant_request ADD COLUMN IF NOT EXISTS updated_at timestamptz "
    "NOT NULL DEFAULT now()",
    "ALTER TABLE provisioning_job ADD COLUMN IF NOT EXISTS detail text NOT NULL DEFAULT ''",
    # Listing is by recency and the table is small, but a request stuck in
    # `awaiting_dns` is the thing §3.2 wants surfaced, so state is worth an index.
    "CREATE INDEX IF NOT EXISTS tenant_request_state_idx ON tenant_request (state)",
    "CREATE INDEX IF NOT EXISTS provisioning_job_state_idx ON provisioning_job (state, id)",
)

#: Any stable 64-bit number; it only has to be the same in every process. The
#: platform learned this the hard way: idempotent DDL is not concurrency-safe DDL,
#: and two backends running CREATE/ALTER ... IF NOT EXISTS concurrently race —
#: the loser gets a duplicate-object error rather than a no-op.
_DDL_LOCK = 0x7E9A_47C1

_COLS = ("tenant_id", "state", "base_domain", "address", "initial_admin",
         "requested_by", "requested_at", "dns", "override_by", "override_reason",
         "failed_step", "failure_detail", "retry_safe", "job_id")


def _row_to_request(row) -> TenantRequest:
    """Rebuild a request from a row, BYPASSING __post_init__'s validation.

    Deliberate. `__post_init__` validates an id being accepted from outside, which
    is right at the entry point and wrong here: a row that is already stored must
    load even if the rules have since tightened. Refusing to read it back would
    turn a stricter RESERVED_IDS list into a request nobody can see or cancel —
    the validator would be hiding the very tenant it wants attention drawn to.
    """
    req = TenantRequest.__new__(TenantRequest)
    (req.tenant_id, req.state, req.base_domain, req.address, req.initial_admin,
     req.requested_by, req.requested_at, dns, req.override_by, req.override_reason,
     req.failed_step, req.failure_detail, req.retry_safe, req.job_id) = row
    req.dns = verdict_from_json(dns if isinstance(dns, dict) else
                               (json.loads(dns) if dns else None))
    return req


@dataclass
class PostgresTenantStore:
    """The real store. Its own database — not another service's schema (§5.1)."""

    dsn: str
    _pool: object = None

    def _connect(self):
        import psycopg

        try:
            return psycopg.connect(self.dsn, autocommit=False)
        except Exception as e:  # noqa: BLE001
            log.warning("tenant store unreachable: %s", e)
            raise StoreUnavailable(f"the tenant store could not be reached: {e}") from e

    def ensure_schema(self) -> None:
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT pg_advisory_xact_lock(%s)", (_DDL_LOCK,))
                cur.execute(_TENANT_DDL)
                cur.execute(_JOB_DDL)
                for stmt in _MIGRATIONS:
                    cur.execute(stmt)
            conn.commit()
        log.info("tenant store schema ready")

    def get(self, tenant_id: str) -> Optional[TenantRequest]:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(f"SELECT {', '.join(_COLS)} FROM tenant_request "
                        f"WHERE tenant_id = %s", (tenant_id,))
            row = cur.fetchone()
        return _row_to_request(row) if row else None

    def list(self) -> list[TenantRequest]:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(f"SELECT {', '.join(_COLS)} FROM tenant_request "
                        f"ORDER BY requested_at DESC")
            rows = cur.fetchall()
        return [_row_to_request(r) for r in rows]

    def create(self, request: TenantRequest) -> TenantRequest:
        import psycopg

        with self._connect() as conn:
            try:
                with conn.cursor() as cur:
                    cur.execute(
                        "INSERT INTO tenant_request (tenant_id, state, base_domain, "
                        "address, initial_admin, requested_by, requested_at, dns) "
                        "VALUES (%s,%s,%s,%s,%s,%s,%s,%s)",
                        (request.tenant_id, request.state, request.base_domain,
                         request.address, request.initial_admin, request.requested_by,
                         request.requested_at,
                         json.dumps(verdict_to_json(request.dns))
                         if request.dns else None))
                conn.commit()
            except psycopg.errors.UniqueViolation as e:
                conn.rollback()
                # The CONSTRAINT decides, not a prior SELECT. Two administrators
                # requesting the same id simultaneously both pass a check-then-insert.
                raise TenantExists(f"{request.tenant_id} is already requested") from e
        return request

    def save(self, request: TenantRequest) -> None:
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE tenant_request SET state=%s, dns=%s, override_by=%s, "
                    "override_reason=%s, failed_step=%s, failure_detail=%s, "
                    "retry_safe=%s, job_id=%s, updated_at=now() WHERE tenant_id=%s",
                    (request.state,
                     json.dumps(verdict_to_json(request.dns)) if request.dns else None,
                     request.override_by, request.override_reason, request.failed_step,
                     request.failure_detail, request.retry_safe, request.job_id,
                     request.tenant_id))
            conn.commit()

    def claim_for_provisioning(self, tenant_id: str) -> Optional[TenantRequest]:
        """Move verified -> provisioning ATOMICALLY, or return None.

        One statement, so the gate is enforced by the database rather than by
        which of two simultaneous requests read the row first. None means the
        state was not `verified` — already provisioning, still awaiting DNS, or
        gone — and the caller must NOT write a job.

        This is the difference persistence actually makes. Two administrators
        pressing Provide at the same moment would each have read `verified` from a
        dict, each passed `may_provision`, and each queued a run: two certificate
        issuance attempts against a limit shared by every tenant on the domain.
        """
        placeholders = ", ".join(["%s"] * len(READY_TO_PROVISION))
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    f"UPDATE tenant_request SET state=%s, updated_at=now() "
                    f"WHERE tenant_id=%s AND state IN ({placeholders}) "
                    f"RETURNING {', '.join(_COLS)}",
                    (PROVISIONING, tenant_id, *READY_TO_PROVISION))
                row = cur.fetchone()
            conn.commit()
        return _row_to_request(row) if row else None

    def record_job(self, tenant_id: str, job: dict) -> str:
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO provisioning_job (tenant_id, payload, requested_by) "
                    "VALUES (%s, %s, %s) RETURNING id",
                    (tenant_id, json.dumps(job), str(job.get("requested_by") or "")))
                job_id = f"job-{cur.fetchone()[0]}"
                cur.execute("UPDATE tenant_request SET job_id=%s, updated_at=now() "
                            "WHERE tenant_id=%s", (job_id, tenant_id))
            conn.commit()
        return job_id

    def jobs(self, *, limit: int = 100) -> list[dict]:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute("SELECT id, tenant_id, payload, requested_by, state, "
                        "claimed_by, detail FROM provisioning_job "
                        "ORDER BY id DESC LIMIT %s", (limit,))
            rows = cur.fetchall()
        out = []
        for jid, tid, payload, by, st, claimed_by, detail in rows:
            p = payload if isinstance(payload, dict) else json.loads(payload)
            p.update({"job_id": f"job-{jid}", "tenant_id": tid, "requested_by": by,
                      "state": st, "claimed_by": claimed_by, "detail": detail})
            out.append(p)
        return out


@dataclass
class InMemoryTenantStore:
    """A store held in memory. Real, for the tests and for a dev run with no database.

    Matches the Postgres semantics that MATTER rather than being a loose double:
    `create` refuses a duplicate, and `claim_for_provisioning` returns the request
    only on the first call. A double that admitted two claims would let the
    concurrency test pass against the thing it is meant to catch.
    """

    requests: dict = field(default_factory=dict)
    job_rows: list = field(default_factory=list)

    def ensure_schema(self) -> None:
        return None

    def get(self, tenant_id: str) -> Optional[TenantRequest]:
        return self.requests.get(tenant_id)

    def list(self) -> list[TenantRequest]:
        return sorted(self.requests.values(), key=lambda r: r.requested_at, reverse=True)

    def create(self, request: TenantRequest) -> TenantRequest:
        if request.tenant_id in self.requests:
            raise TenantExists(f"{request.tenant_id} is already requested")
        self.requests[request.tenant_id] = request
        return request

    def save(self, request: TenantRequest) -> None:
        self.requests[request.tenant_id] = request

    def claim_for_provisioning(self, tenant_id: str) -> Optional[TenantRequest]:
        req = self.requests.get(tenant_id)
        if req is None or req.state not in READY_TO_PROVISION:
            return None
        req.state = PROVISIONING
        return req

    def record_job(self, tenant_id: str, job: dict) -> str:
        job_id = f"job-{len(self.job_rows) + 1}"
        row = dict(job)
        row.update({"job_id": job_id, "tenant_id": tenant_id, "state": "queued"})
        self.job_rows.append(row)
        req = self.requests.get(tenant_id)
        if req is not None:
            req.job_id = job_id
        return job_id

    def jobs(self, *, limit: int = 100) -> list[dict]:
        return list(reversed(self.job_rows))[:limit]


def dsn_for(config: Config) -> str:
    parts = [f"host={config.pg_host}", f"port={config.pg_port}",
             f"dbname={config.pg_database}"]
    if config.pg_user:
        parts.append(f"user={config.pg_user}")
    if config.pg_password:
        parts.append(f"password={config.pg_password}")
    return " ".join(parts)


def from_config(config: Config) -> TenantStore:
    """Postgres when a user is configured, memory otherwise.

    The fallback is LOUD. An in-memory store loses every in-flight request on
    restart, and a tenant half-created is exactly what §3.2 exists to surface —
    so a deployment that has not configured a database should be told, not
    quietly given a dict that works until it is restarted.
    """
    if not config.pg_user:
        log.warning("no database configured (AMC_PG_USER) — tenant requests are held "
                    "IN MEMORY and will be lost on restart")
        return InMemoryTenantStore()
    store = PostgresTenantStore(dsn=dsn_for(config))
    try:
        store.ensure_schema()
    except StoreUnavailable as e:
        # Does NOT fall back to memory. A console that silently degrades to a
        # store it will lose is worse than one that reports the database is down:
        # the requests would be accepted, look fine, and vanish.
        log.error("the tenant store is configured but unreachable: %s", e.args[0])
    return store
