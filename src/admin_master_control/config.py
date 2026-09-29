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

"""Environment-driven configuration.

Platform convention: FILEENGINE_* for values shared across services, AMC_* for
this one's own. Nothing here is read at import time; Config() reads the
environment and get_config() loads ./.env at startup, so tests construct Config
directly.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field


def _env(key: str, default: str = "") -> str:
    v = os.environ.get(key)
    return v if v is not None and v != "" else default


def _int(key: str, default: int) -> int:
    try:
        return int(_env(key, str(default)))
    except ValueError:
        return default


def _bool(key: str, default: bool = False) -> bool:
    return _env(key, "true" if default else "false").lower() in ("1", "true", "yes")


@dataclass
class Config:
    # ── Listeners ──────────────────────────────────────────────────────────
    # :8103/:8104 — the next free pair after share_service (:8101/:8102).
    host: str = field(default_factory=lambda: _env("AMC_HOST", "0.0.0.0"))
    port: int = field(default_factory=lambda: _int("AMC_PORT", 8103))
    # Monitoring binds LOOPBACK-ONLY, per the platform rule for unauthenticated
    # /healthz /readyz /poolz /metrics. Not a default to be overridden casually.
    monitor_host: str = field(default_factory=lambda: _env("AMC_MONITOR_HOST", "127.0.0.1"))
    monitor_port: int = field(default_factory=lambda: _int("AMC_MONITOR_PORT", 8104))

    # ── Its own store: queue state and decisions, and nothing else ─────────
    pg_host: str = field(default_factory=lambda: _env("AMC_PG_HOST", _env("FILEENGINE_PG_HOST", "localhost")))
    pg_port: int = field(default_factory=lambda: _int("AMC_PG_PORT", _int("FILEENGINE_PG_PORT", 5432)))
    pg_database: str = field(default_factory=lambda: _env("AMC_PG_DATABASE", "admin_master_control"))
    pg_user: str = field(default_factory=lambda: _env("AMC_PG_USER", _env("FILEENGINE_PG_USER", "")))
    pg_password: str = field(default_factory=lambda: _env("AMC_PG_PASSWORD", _env("FILEENGINE_PG_PASSWORD", "")))

    # ── What it reads, through APIs rather than through schemas (§5.1) ─────
    audit_url: str = field(default_factory=lambda: _env("AMC_AUDIT_URL", ""))
    ldap_manager_url: str = field(default_factory=lambda: _env("AMC_LDAP_MANAGER_URL", ""))
    # The audit stream, for LATENCY only. The ledger is what is displayed: the
    # stream is XADDed with MAXLEN ~ and forgets, so a console built on it would
    # lose history with a node (§5.1).
    redis_url: str = field(default_factory=lambda: _env("AMC_REDIS_URL", _env("FILEENGINE_REDIS_URL", "")))

    # ── Authentication (§6) ────────────────────────────────────────────────
    ldap_url: str = field(default_factory=lambda: _env("FILEENGINE_LDAP_URL", ""))
    ldap_base_dn: str = field(default_factory=lambda: _env("FILEENGINE_LDAP_BASE_DN", ""))
    # Deployment roles live OUTSIDE every tenant OU. The shared prefix is what
    # makes "refuse these in tenant context" one rule rather than a list that
    # drifts as roles are added — see DEPLOYMENT_MANAGEMENT_INTERFACE.md §6.2.
    role_prefix: str = field(default_factory=lambda: _env("AMC_ROLE_PREFIX", "system_"))
    # A DISTINCT audience from every tenant door, so a tenant token cannot be
    # accepted here and one minted here cannot be accepted there. Structural,
    # not a check someone remembered to write.
    token_audience: str = field(default_factory=lambda: _env("AMC_TOKEN_AUDIENCE", "fileengine-system-admin"))
    jwt_secret: str = field(default_factory=lambda: _env("AMC_JWT_SECRET", ""))
    # MFA is mandatory at this tier, not policy-dependent. Off is a development
    # convenience and /readyz reports it, so a deployment cannot run this way
    # without the fact being visible.
    require_mfa: bool = field(default_factory=lambda: _bool("AMC_REQUIRE_MFA", True))

    # ── The first administrator (§6.3) ─────────────────────────────────────
    # The first system_owner comes from provisioning, the way a tenant's first
    # administrator does in tenant.yml. Empty means "no owner yet", which
    # /readyz reports: a deployment-tier console with nobody able to grant
    # authority is not ready, it is stranded.
    #
    # It is applied ONCE. If someone else already holds system_owner, startup
    # refuses rather than adding a second — otherwise this value is a back door
    # that only needs edit access to a file.
    bootstrap_owner: str = field(default_factory=lambda: _env("AMC_BOOTSTRAP_OWNER", ""))
    # Whether that first owner also receives the four operational roles.
    # system_owner does NOT imply them (§6.1), so without this the first
    # administrator can grant every power and exercise none.
    bootstrap_owner_all_roles: bool = field(
        default_factory=lambda: _bool("AMC_BOOTSTRAP_OWNER_ALL_ROLES", True))

    def monitoring_is_public(self) -> bool:
        """True when the monitoring listener is bound off-loopback — which the
        platform's convention forbids. /readyz reports it rather than refusing:
        a misbinding should be loud and diagnosable, not a silent refusal to
        start that someone works around."""
        return self.monitor_host not in ("127.0.0.1", "localhost", "::1")


def get_config() -> Config:
    """Config with ./.env loaded first. Entrypoints use this; tests use Config()."""
    load_dotenv()
    return Config()


def load_dotenv(path: str = ".env") -> None:
    if not os.path.exists(path):
        return
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))
