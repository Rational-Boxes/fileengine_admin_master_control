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

"""The provisioning job queue. NOT a tenant table — there is only one of those.

This module used to own `tenant_request`: a second table keyed by tenant_id, in this
application's own database, carrying a `state` column whose values overlapped the
registry's by four names. It is gone.

`public.tenants` in the core database already modelled
`requested → awaiting_dns → provisioning → live`, so it was built to hold a tenant
from the moment one is asked for, and the core is a mandatory dependency — so the
second table bought nothing and risked a great deal. The risk was silent: the DOORS
admit or refuse on the registry's state, so a console showing its own copy would
report `live` for a tenant the registry had suspended. The page whose job is to tell
an operator what is happening would have been the page that was wrong, and it would
have looked healthy. See registry.py.

What remains here genuinely belongs to this application. §5.3's boundary is
"requested in this console, executed by a runner", and a runner in another process
needs somewhere to look. A job row records what was ASKED — structured parameters
for `--extra-vars`, never a command line — and the runner owns every state after
`queued`. The table is shaped so a claim is safe with `FOR UPDATE SKIP LOCKED`
rather than assuming there is only ever one runner.

The job's own tenant_id is NOT a foreign key to anything here, because the tenant it
names lives in another database. That is a real cost of the split and worth stating:
the registry can no longer refuse a job for a tenant that does not exist. The route
reads the registry first and the claim has to succeed before a job is written, so the
check happens — it is just no longer the database doing it.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Optional, Protocol

from .config import Config

log = logging.getLogger("admin_master_control.job_store")


class StoreUnavailable(RuntimeError):
    """The job store could not be reached.

    Distinct from "no jobs": an empty queue and an unanswerable question need
    different responses, and reporting the first when the second happened makes a
    backlog look like calm.
    """


#: The runner's vocabulary for a job, after `queued`.
QUEUED, CLAIMED, DONE, FAILED = "queued", "claimed", "done", "failed"
FINISHED = (DONE, FAILED)


class JobStore(Protocol):
    def ensure_schema(self) -> None: ...
    def record(self, tenant_id: str, job: dict) -> str: ...
    def jobs(self, *, limit: int = 100) -> list[dict]: ...
    def claim_next(self, runner: str) -> Optional[dict]: ...
    def finish(self, job_id: str, *, state: str, detail: str) -> bool: ...


def _job_number(job_id: str) -> int:
    """`job-12` -> 12. The id is shown to people as `job-N`; the row key is N."""
    if not job_id.startswith("job-") or not job_id[4:].isdigit():
        raise ValueError(f"not a job id: {job_id!r}")
    return int(job_id[4:])


_JOB_DDL = """
CREATE TABLE IF NOT EXISTS provisioning_job (
    id           bigserial PRIMARY KEY,
    -- No foreign key: the tenant lives in the core's database, not this one. The
    -- route checks it by claiming the registry row first.
    tenant_id    text NOT NULL,
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
    # AFTER the CREATE, and each separately conditional: `CREATE TABLE IF NOT
    # EXISTS` is a no-op on an existing table, so a column added inside that block
    # never lands on an upgrade, and an index over it runs before the column exists.
    # That bit once already, and a fresh database would have passed.
    "ALTER TABLE provisioning_job ADD COLUMN IF NOT EXISTS detail text NOT NULL DEFAULT ''",
    "CREATE INDEX IF NOT EXISTS provisioning_job_state_idx ON provisioning_job (state, id)",
    "CREATE INDEX IF NOT EXISTS provisioning_job_tenant_idx ON provisioning_job (tenant_id)",
)

#: Any stable 64-bit number, the same in every process. Idempotent DDL is not
#: concurrency-safe DDL: two backends running CREATE/ALTER ... IF NOT EXISTS
#: concurrently race, and the loser gets a duplicate-object error, not a no-op.
_DDL_LOCK = 0x7E9A_47C1


@dataclass
class PostgresJobStore:
    """The queue, in this application's OWN database (§5.1)."""

    dsn: str

    def _connect(self):
        import psycopg

        try:
            return psycopg.connect(self.dsn, autocommit=False)
        except Exception as e:  # noqa: BLE001
            log.warning("job store unreachable: %s", e)
            raise StoreUnavailable(f"the provisioning queue could not be reached: {e}") from e

    def ensure_schema(self) -> None:
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT pg_advisory_xact_lock(%s)", (_DDL_LOCK,))
                cur.execute(_JOB_DDL)
                for stmt in _MIGRATIONS:
                    cur.execute(stmt)
            conn.commit()
        log.info("provisioning queue schema ready")

    def record(self, tenant_id: str, job: dict) -> str:
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO provisioning_job (tenant_id, payload, requested_by) "
                    "VALUES (%s, %s, %s) RETURNING id",
                    (tenant_id, json.dumps(job), str(job.get("requested_by") or "")))
                job_id = f"job-{cur.fetchone()[0]}"
            conn.commit()
        return job_id

    def jobs(self, *, limit: int = 100) -> list[dict]:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute("SELECT id, tenant_id, payload, requested_by, state, "
                        "claimed_by, detail, claimed_at, finished_at FROM provisioning_job "
                        "ORDER BY id DESC LIMIT %s", (limit,))
            rows = cur.fetchall()
        return [_out(r) for r in rows]

    def claim_next(self, runner: str) -> Optional[dict]:
        """Take the oldest queued job, or None. Safe with several runners.

        `FOR UPDATE SKIP LOCKED` inside the sub-select: a second runner polling at
        the same moment skips the row the first has locked rather than waiting for
        it and then claiming it too.
        """
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE provisioning_job SET state = %s, claimed_by = %s, "
                    "claimed_at = now() WHERE id = (SELECT id FROM provisioning_job "
                    "WHERE state = %s ORDER BY id FOR UPDATE SKIP LOCKED LIMIT 1) "
                    "RETURNING id, tenant_id, payload, requested_by, state, claimed_by, "
                    "detail, claimed_at, finished_at",
                    (CLAIMED, runner, QUEUED))
                row = cur.fetchone()
            conn.commit()
        return _out(row) if row else None

    def finish(self, job_id: str, *, state: str, detail: str) -> bool:
        """`claimed` -> `done` | `failed`. False if the job was not claimed."""
        if state not in FINISHED:
            raise ValueError(f"a job finishes as one of {FINISHED}, not {state!r}")
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute("UPDATE provisioning_job SET state = %s, detail = %s, "
                            "finished_at = now() WHERE id = %s AND state = %s",
                            (state, detail, _job_number(job_id), CLAIMED))
                changed = cur.rowcount == 1
            conn.commit()
        return changed


def _out(r) -> dict:
    jid, tid, payload, by, st, claimed_by, detail, claimed_at, finished_at = r
    p = payload if isinstance(payload, dict) else json.loads(payload)
    p.update({"job_id": f"job-{jid}", "tenant_id": tid, "requested_by": by,
              "state": st, "claimed_by": claimed_by, "detail": detail,
              "claimed_at": str(claimed_at or ""), "finished_at": str(finished_at or "")})
    return p


@dataclass
class InMemoryJobStore:
    """The queue in memory. Real, for tests and for a dev run with no database."""

    rows: list = field(default_factory=list)

    def ensure_schema(self) -> None:
        return None

    def record(self, tenant_id: str, job: dict) -> str:
        job_id = f"job-{len(self.rows) + 1}"
        row = dict(job)
        row.update({"job_id": job_id, "tenant_id": tenant_id, "state": "queued"})
        self.rows.append(row)
        return job_id

    def jobs(self, *, limit: int = 100) -> list[dict]:
        return list(reversed(self.rows))[:limit]

    def claim_next(self, runner: str) -> Optional[dict]:
        for row in self.rows:
            if row["state"] == QUEUED:
                row.update({"state": CLAIMED, "claimed_by": runner})
                return dict(row)
        return None

    def finish(self, job_id: str, *, state: str, detail: str) -> bool:
        if state not in FINISHED:
            raise ValueError(f"a job finishes as one of {FINISHED}, not {state!r}")
        for row in self.rows:
            if row["job_id"] == job_id and row["state"] == CLAIMED:
                row.update({"state": state, "detail": detail})
                return True
        return False


def dsn_for(config: Config) -> str:
    parts = [f"host={config.pg_host}", f"port={config.pg_port}",
             f"dbname={config.pg_database}"]
    if config.pg_user:
        parts.append(f"user={config.pg_user}")
    if config.pg_password:
        parts.append(f"password={config.pg_password}")
    return " ".join(parts)


def from_config(config: Config) -> JobStore:
    """Postgres when configured, memory otherwise — LOUDLY.

    An in-memory queue loses queued jobs on restart, and a job nobody ran is exactly
    what §3.2 exists to surface, so a deployment without a database configured
    should be told rather than quietly given a list that works until it restarts.
    """
    if not config.pg_user:
        log.warning("no database configured (AMC_PG_USER) — provisioning jobs are held "
                    "IN MEMORY and will be lost on restart")
        return InMemoryJobStore()
    store = PostgresJobStore(dsn=dsn_for(config))
    try:
        store.ensure_schema()
    except StoreUnavailable as e:
        # No fallback to memory: accepting jobs that look queued and then vanish is
        # worse than reporting that the database is down.
        log.error("the provisioning queue is configured but unreachable: %s", e)
    return store
