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

"""The tenant registry: `public.tenants` in the core database, and the ONLY one.

This console had its own `tenant_request` table. It is gone, and that is the point
of this module. The registry already models `requested → awaiting_dns →
provisioning → live`, so it was built to hold a tenant from the moment it is asked
for; a second table keyed by tenant_id was a duplicate of the same facts in a
different database, with four state names in common and two separate writers.

The failure that makes this worth doing is silent and specific. The doors admit or
refuse on the REGISTRY's state. A console reading its own copy would show `live`
for a tenant the registry had suspended — so the page whose job is to tell an
operator what is happening would be the page that is wrong, and it would look
perfectly healthy. The core is a mandatory dependency, so the second table bought
nothing for that risk.

WHAT THIS MODULE ADDS TO THE TABLE, rather than beside it: the creation request has
fields the registry had no column for (the base domain, the address the hostnames
must point at, the first administrator, the DNS verdict, the override, the job).
They are ADDED to `public.tenants`, additively and with defaults, so the core's own
inserts are unaffected.

THE GATE IS A DERIVED PREDICATE, not a stored flag:

    override_by <> '' OR (dns->>'ok') = 'true'

A `gate_cleared` boolean would be a cached summary of two columns it could
disagree with. Evaluating it inside the same UPDATE that performs the claim means
there is nothing to keep in step — and the claim stays one statement, so two
administrators pressing Provision cannot both queue a run against a certificate
rate limit shared by every tenant on the domain.

There is deliberately NO `verified` and no `failed` state. `verified` was this
console's own invention and is what the derived predicate replaces. A failed
provisioning leaves the state at `provisioning` with the failure columns filled:
the registry's vocabulary has no `failed`, and since only `live` admits a login,
leaving it there is both truthful and safe.
"""
from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from typing import Optional, Protocol

from .config import Config

log = logging.getLogger("admin_master_control.registry")

#: The lifecycle, exactly as the core writes it and the doors compare it.
REQUESTED = "requested"
AWAITING_DNS = "awaiting_dns"
PROVISIONING = "provisioning"
LIVE = "live"
SUSPENDED = "suspended"
DECOMMISSIONING = "decommissioning"
DECOMMISSIONED = "decommissioned"

REGISTRY_STATES = (REQUESTED, AWAITING_DNS, PROVISIONING, LIVE,
                   SUSPENDED, DECOMMISSIONING, DECOMMISSIONED)

#: The states a request may be claimed for provisioning FROM.
#:
#: A LIST, not a tuple, because it is passed to psycopg as an `= ANY(%s)` parameter.
#: `state IN %s` with a tuple is psycopg2 idiom and psycopg3 does not expand it — it
#: fails with `syntax error at or near "$4"`. The in-memory double happily passed
#: every test that exercised it; only the live Postgres run found this.
CLAIMABLE = [REQUESTED, AWAITING_DNS]

#: The one state that admits a login. Mirrored from the doors' policy header for
#: DISPLAY only, and asserted against that header by a test — a second copy of a
#: security rule that nobody checks is how two copies drift.
ADMITS = LIVE


class RegistryUnavailable(RuntimeError):
    """The registry could not be reached.

    Distinct from "no tenants", which is the whole point: an empty list would
    report an estate with no tenants, and this reports a console that could not ask.
    """


class RegistryRefused(ValueError):
    """A write the registry would not accept (a duplicate, or a bad id)."""


def schema_name_for(tenant_id: str) -> str:
    """The schema the core will use, derived the SAME way the core derives it.

    `Database::get_schema_prefix` is "tenant_" + the id, with every character that
    is not alphanumeric or an underscore removed, truncated to 63 — which is why
    `filenginetest-drive` is stored as `tenant_filenginetestdrive`.

    The column is NOT NULL and a requested tenant has no schema yet, so a value has
    to be written at request time. Computing it by the core's rule rather than
    inventing one keeps the row consistent with what provisioning will create; a
    different rule here would produce a registry row pointing at a schema that never
    appears.
    """
    cleaned = re.sub(r"[^0-9a-zA-Z_]", "", f"tenant_{tenant_id}")
    return cleaned[:63]


@dataclass(frozen=True)
class Tenant:
    """One registry row — the authoritative record that a tenant exists."""

    tenant_id: str
    schema_name: str
    state: str
    #: Free text for humans. NEVER an identifier — see _ADDED.
    display_name: str = ""
    created_at: str = ""
    state_since: str = ""
    state_by: str = ""
    state_note: str = ""
    base_domain: str = ""
    address: str = ""
    initial_admin: str = ""
    requested_by: str = ""
    dns: Optional[dict] = None
    override_by: str = ""
    override_reason: str = ""
    job_id: str = ""
    failed_step: str = ""
    failure_detail: str = ""
    retry_safe: bool = False

    @property
    def admits_logins(self) -> bool:
        return self.state == ADMITS

    @property
    def gate_cleared(self) -> bool:
        """The same predicate the claim uses, for display.

        Kept in ONE place conceptually: this mirrors the SQL in
        `claim_for_provisioning`, and a test asserts the two agree over a matrix of
        rows. The UI renders this rather than deciding for itself.
        """
        return bool(self.override_by) or bool((self.dns or {}).get("ok"))

    @property
    def may_provision(self) -> bool:
        return self.state in CLAIMABLE and self.gate_cleared

    def for_display(self) -> dict:
        out = {
            "tenant_id": self.tenant_id,
            # Falls back to the id so a caller always has something to print, but the
            # two stay SEPARATE keys: a client that needs the identifier must not end
            # up with a label because a name happened to be set.
            "display_name": self.display_name or self.tenant_id,
            "has_display_name": bool(self.display_name),
            "schema_name": self.schema_name,
            "state": self.state,
            "admits_logins": self.admits_logins,
            "may_provision": self.may_provision,
            "gate_cleared": self.gate_cleared,
            "created_at": self.created_at,
            "state_since": self.state_since,
            "state_by": self.state_by,
            "state_note": self.state_note,
            "base_domain": self.base_domain,
            "address": self.address,
            "initial_admin": self.initial_admin,
            "requested_by": self.requested_by,
            # True when this console has the creation details — most tenants predate
            # it and simply do not, which is not a gap.
            "requested_here": bool(self.requested_by),
        }
        if self.dns:
            out["dns"] = self.dns
        if self.override_by:
            out["override"] = {"by": self.override_by, "reason": self.override_reason}
        if self.job_id:
            out["job_id"] = self.job_id
        if self.failed_step or self.failure_detail:
            out["failure"] = {"step": self.failed_step, "detail": self.failure_detail,
                              "retry_safe": self.retry_safe}
        return out


class TenantRegistry(Protocol):
    def ensure_schema(self) -> None: ...
    def list(self) -> list[Tenant]: ...
    def get(self, tenant_id: str) -> Optional[Tenant]: ...
    def request(self, *, tenant_id: str, base_domain: str, address: str,
                initial_admin: str, requested_by: str,
                display_name: str = "") -> Tenant: ...
    def set_display_name(self, tenant_id: str, name: str) -> Optional[Tenant]: ...
    def record_dns(self, tenant_id: str, verdict: dict) -> Optional[Tenant]: ...
    def record_override(self, tenant_id: str, by: str, reason: str) -> Optional[Tenant]: ...
    def claim_for_provisioning(self, tenant_id: str, by: str) -> Optional[Tenant]: ...
    def attach_job(self, tenant_id: str, job_id: str) -> None: ...


# ── the columns this console adds ──────────────────────────────────────────
#
# ADDITIVE AND DEFAULTED, every one. The core inserts into this table too, and a
# NOT NULL column without a default would break its insert — a console feature
# taking the file service down with it.

_ADDED = (
    # The name a HUMAN uses for this tenant — "Acme Corporation Ltd" — for billing
    # and high-level operations. A different kind of thing from `tenant_id`, and the
    # difference is the reason it is a separate column rather than a rename:
    #
    #   * `tenant_id` is the IDENTIFIER. It reaches a hostname, a Postgres schema
    #     name, an LDAP DN and a file path, which is why it is validated to a narrow
    #     charset and is IMMUTABLE. Changing it would mean changing all four.
    #   * `display_name` is a LABEL. Free text, mutable, set through this console,
    #     and never used to look anything up — an organisation renaming itself must
    #     not move its data.
    #
    # Not unique, deliberately: uniqueness would make it an identifier by the back
    # door, and the id already is one. It may be empty, which is the normal state for
    # every tenant created before this console existed.
    ("display_name", "text NOT NULL DEFAULT ''"),
    ("base_domain", "text NOT NULL DEFAULT ''"),
    ("address", "text NOT NULL DEFAULT ''"),
    ("initial_admin", "text NOT NULL DEFAULT ''"),
    ("requested_by", "text NOT NULL DEFAULT ''"),
    # The DNS verdict: a nested per-hostname reading, displayed whole and never
    # queried by its parts, except for `ok` in the gate predicate.
    ("dns", "jsonb"),
    ("override_by", "text NOT NULL DEFAULT ''"),
    ("override_reason", "text NOT NULL DEFAULT ''"),
    ("job_id", "text NOT NULL DEFAULT ''"),
    ("failed_step", "text NOT NULL DEFAULT ''"),
    ("failure_detail", "text NOT NULL DEFAULT ''"),
    ("retry_safe", "boolean NOT NULL DEFAULT false"),
)

#: Any stable 64-bit number, the same in every process. Idempotent DDL is not
#: concurrency-safe DDL: two backends running ALTER ... IF NOT EXISTS concurrently
#: race, and the loser gets a duplicate-object error rather than a no-op.
_DDL_LOCK = 0x7E9A_47C2

_COLS = ("tenant_id, schema_name, state, display_name, created_at, state_since, "
         "state_by, state_note, base_domain, address, initial_admin, requested_by, "
         "dns, override_by, override_reason, job_id, failed_step, failure_detail, "
         "retry_safe")

#: The gate, in SQL. Mirrored by Tenant.gate_cleared, and a test asserts they agree.
_GATE = "(override_by <> '' OR (dns->>'ok') = 'true')"


def _row(r) -> Tenant:
    dns = r[12]
    if isinstance(dns, str):
        dns = json.loads(dns)
    return Tenant(
        tenant_id=str(r[0]), schema_name=str(r[1] or ""), state=str(r[2] or ""),
        display_name=str(r[3] or ""), created_at=str(r[4] or ""),
        state_since=str(r[5] or ""), state_by=str(r[6] or ""),
        state_note=str(r[7] or ""), base_domain=str(r[8] or ""),
        address=str(r[9] or ""), initial_admin=str(r[10] or ""),
        requested_by=str(r[11] or ""), dns=dns,
        override_by=str(r[13] or ""), override_reason=str(r[14] or ""),
        job_id=str(r[15] or ""), failed_step=str(r[16] or ""),
        failure_detail=str(r[17] or ""), retry_safe=bool(r[18]),
    )


@dataclass
class PostgresTenantRegistry:
    """`public.tenants` in the core database."""

    dsn: str

    def _connect(self):
        import psycopg

        try:
            return psycopg.connect(self.dsn, autocommit=False)
        except Exception as e:  # noqa: BLE001
            log.warning("tenant registry unreachable: %s", e)
            raise RegistryUnavailable(f"the tenant registry could not be read: {e}") from e

    def ensure_schema(self) -> None:
        """Add this console's columns. Never creates the table.

        If `public.tenants` does not exist, the core has not started against this
        database and creating it here would put a half-formed registry in front of
        the service that owns it. Reported, not fixed.
        """
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT pg_advisory_xact_lock(%s)", (_DDL_LOCK,))
                cur.execute("SELECT to_regclass('public.tenants') IS NOT NULL")
                if not cur.fetchone()[0]:
                    conn.rollback()
                    log.error("public.tenants does not exist in the core database — "
                              "the core owns that table and has not created it here")
                    raise RegistryUnavailable("the core's tenant registry does not exist")
                for name, decl in _ADDED:
                    cur.execute(f"ALTER TABLE public.tenants "
                                f"ADD COLUMN IF NOT EXISTS {name} {decl}")
            conn.commit()
        log.info("tenant registry ready (public.tenants, +%d console columns)", len(_ADDED))

    def list(self) -> list[Tenant]:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(f"SELECT {_COLS} FROM public.tenants ORDER BY tenant_id")
            return [_row(r) for r in cur.fetchall()]

    def get(self, tenant_id: str) -> Optional[Tenant]:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(f"SELECT {_COLS} FROM public.tenants WHERE tenant_id = %s",
                        (tenant_id,))
            r = cur.fetchone()
        return _row(r) if r else None

    def request(self, *, tenant_id: str, base_domain: str, address: str,
                initial_admin: str, requested_by: str, display_name: str = "") -> Tenant:
        import psycopg

        with self._connect() as conn:
            try:
                with conn.cursor() as cur:
                    cur.execute(
                        f"INSERT INTO public.tenants (tenant_id, schema_name, state, "
                        f"state_since, state_by, display_name, base_domain, address, "
                        f"initial_admin, requested_by) "
                        f"VALUES (%s,%s,%s,now(),%s,%s,%s,%s,%s,%s) "
                        f"RETURNING {_COLS}",
                        (tenant_id, schema_name_for(tenant_id), REQUESTED, requested_by,
                         display_name, base_domain, address, initial_admin, requested_by))
                    row = cur.fetchone()
                conn.commit()
            except psycopg.errors.UniqueViolation as e:
                conn.rollback()
                # The CONSTRAINT decides, not a prior SELECT: two administrators
                # requesting the same id simultaneously both pass a check-then-insert,
                # and the unique index is the only authority.
                raise RegistryRefused(f"{tenant_id} already exists") from e
        return _row(row)

    def set_display_name(self, tenant_id: str, name: str) -> Optional[Tenant]:
        """Rename the LABEL. Never the identifier.

        Allowed in ANY lifecycle state, including `live` and `decommissioned` — an
        organisation renames itself while in service, and a decommissioned tenant's
        row survives so its name should stay readable in a billing history. Nothing
        keyed on the tenant moves, because nothing is keyed on this.
        """
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(f"UPDATE public.tenants SET display_name = %s, "
                            f"updated_at = now() WHERE tenant_id = %s RETURNING {_COLS}",
                            (name, tenant_id))
                row = cur.fetchone()
            conn.commit()
        return _row(row) if row else None

    def record_dns(self, tenant_id: str, verdict: dict) -> Optional[Tenant]:
        """Store the verdict and move to awaiting_dns, or leave a live tenant alone.

        The state is only touched while the tenant is still pre-provisioning. Running
        a DNS check against a LIVE tenant is a legitimate diagnostic, and it must not
        drag it back out of service — the doors read this column.
        """
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    f"UPDATE public.tenants SET dns = %s, updated_at = now(), "
                    f"state = CASE WHEN state = ANY(%s) THEN %s ELSE state END, "
                    f"state_since = CASE WHEN state = ANY(%s) THEN now() "
                    f"ELSE state_since END "
                    f"WHERE tenant_id = %s RETURNING {_COLS}",
                    (json.dumps(verdict), CLAIMABLE, AWAITING_DNS, CLAIMABLE, tenant_id))
                row = cur.fetchone()
            conn.commit()
        return _row(row) if row else None

    def record_override(self, tenant_id: str, by: str, reason: str) -> Optional[Tenant]:
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    f"UPDATE public.tenants SET override_by = %s, override_reason = %s, "
                    f"updated_at = now() WHERE tenant_id = %s AND state = ANY(%s) "
                    f"RETURNING {_COLS}",
                    (by, reason, tenant_id, CLAIMABLE))
                row = cur.fetchone()
            conn.commit()
        return _row(row) if row else None

    def claim_for_provisioning(self, tenant_id: str, by: str) -> Optional[Tenant]:
        """Move a gated request to `provisioning`, ATOMICALLY, or return None.

        One statement, so the gate is held by the database rather than by which of
        two simultaneous requests read the row first. The predicate is evaluated
        here — not read, compared and written back — which is what makes a double
        press unable to queue two certificate issuance attempts against a limit
        shared by every tenant on the domain.
        """
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    f"UPDATE public.tenants SET state = %s, state_since = now(), "
                    f"state_by = %s, updated_at = now() "
                    f"WHERE tenant_id = %s AND state = ANY(%s) AND {_GATE} "
                    f"RETURNING {_COLS}",
                    (PROVISIONING, by, tenant_id, CLAIMABLE))
                row = cur.fetchone()
            conn.commit()
        return _row(row) if row else None

    def attach_job(self, tenant_id: str, job_id: str) -> None:
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute("UPDATE public.tenants SET job_id = %s, updated_at = now() "
                            "WHERE tenant_id = %s", (job_id, tenant_id))
            conn.commit()


@dataclass
class StaticTenantRegistry:
    """An in-memory registry. Real, for the tests.

    Matches the Postgres semantics that MATTER rather than being a loose double:
    `request` refuses a duplicate, `claim_for_provisioning` succeeds only once and
    only through the gate, and `record_dns` leaves a live tenant's state alone. A
    double that admitted two claims would let the concurrency test pass against the
    very thing it exists to catch.
    """

    rows: dict = None            # type: ignore[assignment]
    unavailable: bool = False

    def __post_init__(self) -> None:
        if self.rows is None:
            self.rows = {}

    def _guard(self) -> None:
        if self.unavailable:
            raise RegistryUnavailable("the tenant registry could not be read")

    def seed(self, *tenants: Tenant) -> "StaticTenantRegistry":
        for t in tenants:
            self.rows[t.tenant_id] = t
        return self

    def ensure_schema(self) -> None:
        self._guard()

    def list(self) -> list[Tenant]:
        self._guard()
        return sorted(self.rows.values(), key=lambda t: t.tenant_id)

    def get(self, tenant_id: str) -> Optional[Tenant]:
        self._guard()
        return self.rows.get(tenant_id)

    def request(self, *, tenant_id: str, base_domain: str, address: str,
                initial_admin: str, requested_by: str, display_name: str = "") -> Tenant:
        self._guard()
        if tenant_id in self.rows:
            raise RegistryRefused(f"{tenant_id} already exists")
        t = Tenant(tenant_id=tenant_id, schema_name=schema_name_for(tenant_id),
                   state=REQUESTED, display_name=display_name, base_domain=base_domain,
                   address=address, initial_admin=initial_admin,
                   requested_by=requested_by, state_by=requested_by)
        self.rows[tenant_id] = t
        return t

    def set_display_name(self, tenant_id: str, name: str) -> Optional[Tenant]:
        self._guard()
        if tenant_id not in self.rows:
            return None
        return self._replace(tenant_id, display_name=name)

    def _replace(self, tenant_id: str, **over) -> Optional[Tenant]:
        import dataclasses

        t = self.rows.get(tenant_id)
        if t is None:
            return None
        t = dataclasses.replace(t, **over)
        self.rows[tenant_id] = t
        return t

    def record_dns(self, tenant_id: str, verdict: dict) -> Optional[Tenant]:
        self._guard()
        t = self.rows.get(tenant_id)
        if t is None:
            return None
        state = AWAITING_DNS if t.state in CLAIMABLE else t.state
        return self._replace(tenant_id, dns=verdict, state=state)

    def record_override(self, tenant_id: str, by: str, reason: str) -> Optional[Tenant]:
        self._guard()
        t = self.rows.get(tenant_id)
        if t is None or t.state not in CLAIMABLE:
            return None
        return self._replace(tenant_id, override_by=by, override_reason=reason)

    def claim_for_provisioning(self, tenant_id: str, by: str) -> Optional[Tenant]:
        self._guard()
        t = self.rows.get(tenant_id)
        if t is None or t.state not in CLAIMABLE or not t.gate_cleared:
            return None
        return self._replace(tenant_id, state=PROVISIONING, state_by=by)

    def attach_job(self, tenant_id: str, job_id: str) -> None:
        self._guard()
        self._replace(tenant_id, job_id=job_id)


def dsn_for(config: Config) -> str:
    parts = [f"host={config.core_pg_host}", f"port={config.core_pg_port}",
             f"dbname={config.core_pg_database}"]
    if config.core_pg_user:
        parts.append(f"user={config.core_pg_user}")
    if config.core_pg_password:
        parts.append(f"password={config.core_pg_password}")
    return " ".join(parts)


def from_config(config: Config) -> TenantRegistry:
    """The live registry when configured, an empty in-memory one otherwise.

    The fallback is LOUD. The core is a mandatory dependency, so a console without
    it configured will show no tenants at all — and an administrator seeing an empty
    list needs to know whether that is the estate or the configuration.
    """
    if not config.core_pg_user:
        log.warning("no core database configured (AMC_CORE_PG_USER) — the tenant "
                    "registry cannot be reached and NO tenants will be listed")
        return StaticTenantRegistry()
    registry = PostgresTenantRegistry(dsn=dsn_for(config))
    try:
        registry.ensure_schema()
    except RegistryUnavailable as e:
        # Does NOT fall back to an empty registry: a console that silently shows no
        # tenants because its database is down is worse than one that reports it.
        log.error("the tenant registry is configured but unusable: %s", e)
    return registry
