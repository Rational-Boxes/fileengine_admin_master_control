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

    # ── The tenant registry, read-only (§3.4b) ─────────────────────────────
    #
    # `public.tenants` in the CORE's global schema is the one list of tenants and
    # the one lifecycle state — provisioning writes it and the doors read it to
    # decide whether a login is admitted. This console reads the same rows so that
    # what an administrator sees is what the doors enforce.
    #
    # A separate DSN from AMC_PG_* on purpose: that is this application's OWN
    # database (its queue, its decisions, its tenant requests) and this is another
    # service's. Defaults to the platform-wide FILEENGINE_PG_* so a normal
    # deployment configures it once.
    #
    # The connection is opened read-only, so a stray write fails at the database.
    core_pg_host: str = field(default_factory=lambda: _env(
        "AMC_CORE_PG_HOST", _env("FILEENGINE_PG_HOST", "localhost")))
    core_pg_port: int = field(default_factory=lambda: _int(
        "AMC_CORE_PG_PORT", _int("FILEENGINE_PG_PORT", 5432)))
    core_pg_database: str = field(default_factory=lambda: _env(
        "AMC_CORE_PG_DATABASE", _env("FILEENGINE_PG_DATABASE", "fileengine")))
    core_pg_user: str = field(default_factory=lambda: _env(
        "AMC_CORE_PG_USER", _env("FILEENGINE_PG_USER", "")))
    core_pg_password: str = field(default_factory=lambda: _env(
        "AMC_CORE_PG_PASSWORD", _env("FILEENGINE_PG_PASSWORD", "")))

    # ── What it reads, through APIs rather than through schemas (§5.1) ─────
    audit_url: str = field(default_factory=lambda: _env("AMC_AUDIT_URL", ""))
    # The credential this application reads the ledger with. NOT a system_admin
    # token: that role is the core's ACL bypass and reads every file in every
    # tenant. audit_service grants the global audit read to the deployment roles
    # instead (AUDIT_DEPLOYMENT_READ_ROLES).
    audit_token: str = field(default_factory=lambda: _env("AMC_AUDIT_TOKEN", ""))
    ldap_manager_url: str = field(default_factory=lambda: _env("AMC_LDAP_MANAGER_URL", ""))
    # The audit stream, for LATENCY only. The ledger is what is displayed: the
    # stream is XADDed with MAXLEN ~ and forgets, so a console built on it would
    # lose history with a node (§5.1).
    redis_url: str = field(default_factory=lambda: _env("AMC_REDIS_URL", _env("FILEENGINE_REDIS_URL", "")))

    # ── Authentication (§6) ────────────────────────────────────────────────
    ldap_url: str = field(default_factory=lambda: _env("FILEENGINE_LDAP_URL", ""))
    ldap_base_dn: str = field(default_factory=lambda: _env("FILEENGINE_LDAP_BASE_DN", ""))
    # The credential this application READS THE ROLE OU WITH. Distinct from the
    # administrator's own bind, which authenticates them: resolving "which
    # deployment roles does this subject hold" is a search, and a directory that
    # hides ou=system from anonymous clients — which is every sensibly configured
    # one — returns nothing to an unbound search.
    #
    # There was no way to set this at first, so the search bound anonymously. The
    # dev directory answers "No such object" for ou=system to an anonymous client,
    # so every lookup came back empty, which is indistinguishable from "this
    # administrator holds no deployment role". The result was a console that
    # authenticated the owner correctly and then refused them, and a /readyz that
    # reported "no system_owner in the directory" about a directory containing
    # one. Failing closed was right; being unable to say why was not.
    #
    # A read-only account is sufficient and correct — this application never
    # writes to the directory. Grants are recorded in its own ledger, and
    # directory membership is changed by directory administration.
    ldap_bind_dn: str = field(default_factory=lambda: _env(
        "AMC_LDAP_BIND_DN", _env("FILEENGINE_LDAP_BIND_DN", "")))
    ldap_bind_password: str = field(default_factory=lambda: _env(
        "AMC_LDAP_BIND_PASSWORD", _env("FILEENGINE_LDAP_BIND_PASSWORD", "")))
    # Deployment roles live OUTSIDE every tenant OU. The shared prefix is what
    # makes "refuse these in tenant context" one rule rather than a list that
    # drifts as roles are added — see DEPLOYMENT_MANAGEMENT_INTERFACE.md §6.2.
    role_prefix: str = field(default_factory=lambda: _env("AMC_ROLE_PREFIX", "system_"))
    # The OU holding the deployment role groups, and the one holding accounts.
    # Configurable because directory layout is a deployment's choice — but the
    # role OU must never be a tenant OU or the directory root: this tier reads
    # authority from it, and widening it is the mirror of the defect the tenant
    # doors were just fixed for.
    ldap_role_ou: str = field(default_factory=lambda: _env("AMC_LDAP_ROLE_OU", "ou=system"))
    ldap_user_ou: str = field(default_factory=lambda: _env("AMC_LDAP_USER_OU", "ou=users"))
    # A DISTINCT audience from every tenant door, so a tenant token cannot be
    # accepted here and one minted here cannot be accepted there. Structural,
    # not a check someone remembered to write.
    token_audience: str = field(default_factory=lambda: _env("AMC_TOKEN_AUDIENCE", "fileengine-system-admin"))
    jwt_secret: str = field(default_factory=lambda: _env("AMC_JWT_SECRET", ""))
    # ── the second factor (§6) ─────────────────────────────────────────────
    #
    # DEFAULT ON, and the only way out is to say so: `AMC_REQUIRE_MFA=false` is an
    # explicit opt-out, /readyz reports it, and startup logs it. A deployment
    # cannot run this way without the fact being visible.
    #
    # `require_mfa` means a factor is VERIFIED. It used to mean the caller had
    # CLAIMED one, which made it decorative: `second_factor` was a self-asserted
    # string checked against a set of factor NAMES, so anyone holding a directory
    # password could send {"second_factor":"totp"} and receive a fully MFA-marked
    # token.
    #
    # It also implies FORCED ENROLLMENT on first login. An administrator with no
    # factor is not admitted and then nagged; they get an enrollment-only session
    # and nothing else until they finish. Otherwise "required" means "required of
    # whoever already happens to have one" — nobody, on a new deployment.
    require_mfa: bool = field(default_factory=lambda: _bool("AMC_REQUIRE_MFA", True))

    # Where the factor actually lives. ldap_manager owns `user_2fa`, keyed by uid
    # ALONE and shared across tenants, so an administrator who enrolled through a
    # tenant already has a factor this tier can verify — one enrollment, not one
    # per door. Unset while require_mfa is true is a MISCONFIGURATION, not a
    # silent pass: /readyz reports it and the gate refuses, because enforcement
    # that cannot reach its source must not wave everyone through.
    mfa_url: str = field(default_factory=lambda: _env(
        "AMC_MFA_URL", _env("AMC_LDAP_MANAGER_URL", "")))
    # Guards ldap_manager's /internal/2fa/* endpoints, sent as X-Internal-Auth.
    # Shared with its MFA_INTERNAL_SECRET: it serves 404 when that is unset and
    # 403 on a mismatch.
    mfa_internal_secret: str = field(default_factory=lambda: _env(
        "AMC_MFA_INTERNAL_SECRET", _env("MFA_INTERNAL_SECRET", "")))

    # The methods permitted AT THIS TIER — narrower than the deployment cap on
    # purpose. `email` is left out: it is the weakest path on offer and this is
    # the console that reads every tenant's audit and grants deployment
    # authority. `recovery` is kept, because losing the only factor here means
    # nobody can grant authority to anybody — the stranded state /readyz reports.
    mfa_methods: str = field(default_factory=lambda: _env("AMC_MFA_METHODS", "totp,recovery"))

    # ldap_manager's internal 2FA endpoints are tenant-addressed and resolve
    # permitted methods as "deployment cap ∩ that tenant's policy". Deployment roles
    # live outside every tenant OU, so no tenant's policy should govern them — and
    # passing a REAL tenant would let its administrator disable TOTP and thereby
    # block enrollment for this console.
    #
    # EMPTY, not a made-up name. This was `__deployment__`, on the reasoning that a
    # tenant with no policy row inherits the full cap — which is true, and misses
    # that THE CORE AUTO-REGISTERS ANY TENANT IT IS ASKED ABOUT:
    # Database::create_tenant_schema inserts into public.tenants with the default
    # state `live`. In an estate that provisions on first reference there is no such
    # thing as an inert sentinel tenant string — a plausible-looking name is a tenant
    # waiting to be created, and it would then appear in the registry as LIVE, in the
    # very list this console displays.
    #
    # An empty string cannot be taken for a tenant id by anything downstream, and it
    # resolves to the same deployment method cap — measured against the running
    # ldap_manager, which returns identical `methods` for both.
    mfa_tenant_context: str = field(default_factory=lambda: _env(
        "AMC_MFA_TENANT_CONTEXT", ""))

    # How long the pre-session challenge lives — the window between a correct
    # password and a proven factor, so: short.
    mfa_challenge_ttl_s: int = field(default_factory=lambda: _int("AMC_MFA_CHALLENGE_TTL_S", 600))

    # FastAPI's /docs, /redoc and /openapi.json. OFF at this tier, and the
    # default is the decision.
    #
    # They are UNAUTHENTICATED, and they sit on the public listener — unlike
    # /healthz /readyz /poolz /metrics, which are on the loopback-only monitoring
    # port precisely because they are unauthenticated. Leaving them on published
    # the complete route inventory and request schemas of the cross-tenant console
    # to anyone who found the URL: 24 paths, measured over the dev tunnel on
    # 2026-09-29, including every /v1/security and /v1/administrators route.
    #
    # Not a vulnerability by itself — knowing a route exists is not reaching it —
    # but it is a free map of the most sensitive surface in the estate, and it
    # contradicts the rule the rest of this application follows. /readyz reports
    # it when it is on, the same way it reports MFA being disabled.
    serve_api_docs: bool = field(default_factory=lambda: _bool("AMC_SERVE_API_DOCS", False))

    # The interfaces every tenant is served on, as hostname suffixes, comma
    # separated. The tenant's own host is always included whether listed or not.
    #
    # EACH IS A SEPARATE SUBDOMAIN with its own A record and its own certificate, so
    # this list decides what the DNS gate requires and what the zone must carry.
    # Adding one here is the whole change: every tenant's record set and every DNS
    # check follow it. Getting it wrong in the other direction is expensive — a
    # hostname the gate does not know about is one the playbook still tries to
    # certify, and it fails on that certificate after the earlier ones have already
    # spent issuance from a limit shared by every tenant on the domain.
    #
    # `drive` is WebDAV, which needs its own host because its verbs cannot sit behind
    # a path prefix. MCP and the document server are path-routable today; when either
    # needs a host of its own, it goes here.
    tenant_interfaces: str = field(default_factory=lambda: _env("AMC_TENANT_INTERFACES", "drive"))

    def interface_list(self) -> tuple[str, ...]:
        from .tenants import interface_suffixes

        return interface_suffixes(self.tenant_interfaces)

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

    def mfa_method_list(self) -> tuple[str, ...]:
        seen: set[str] = set()
        out: list[str] = []
        for m in self.mfa_methods.split(","):
            m = m.strip().lower()
            if m and m not in seen:
                seen.add(m)
                out.append(m)
        return tuple(out)

    def mfa_is_enforceable(self) -> bool:
        """Whether the requirement can be checked against anything at all.

        Both halves are needed: a URL with no internal secret gets 403 from every
        endpoint, and a secret with no URL has nothing to call. Separating
        "enforced" from "enforceable" is what stops this becoming the mistake the
        tenant-state gate was written to avoid — a check that is decorative on
        exactly the deployment that forgot to wire it.
        """
        return bool(self.mfa_url and self.mfa_internal_secret)

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
