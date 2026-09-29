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

"""The app: two listeners, and the readiness that decides whether this tier is
safe to serve at all.

Two listeners, per platform convention: the API on :8103, and monitoring on
:8104 bound loopback-only because /healthz /readyz /poolz /metrics are
unauthenticated.
"""
from __future__ import annotations

import logging
import threading

from fastapi import FastAPI
from fastapi.responses import JSONResponse

from . import metrics as _fe_metrics
from . import __version__
from .administrators import AdministratorRegistry, bootstrap_owner, summarise
from .api import build_router
from .auth import (
    DeploymentDirectory,
    LdapDeploymentDirectory,
    StaticDeploymentDirectory,
    directory_has_owner,
)
from .config import Config, get_config
from .roles import RoleError

log = logging.getLogger("admin_master_control.app")


def default_directory(config: Config) -> DeploymentDirectory:
    """LDAP when configured, an empty static directory otherwise.

    The fallback authenticates NOBODY rather than everybody. A deployment with
    no directory configured should refuse every login, not run open — and
    /readyz says which piece is missing.
    """
    if config.ldap_url and config.ldap_base_dn:
        return LdapDeploymentDirectory(url=config.ldap_url, base_dn=config.ldap_base_dn,
                                       role_ou=config.ldap_role_ou,
                                       user_ou=config.ldap_user_ou)
    log.warning("no directory configured — every login will be refused")
    return StaticDeploymentDirectory()


def build_app(config: Config,
              registry: AdministratorRegistry | None = None,
              directory: DeploymentDirectory | None = None) -> FastAPI:
    """The API. Pure: takes its config, reads no environment, loads no dotenv —
    so a test can construct one without a deployment underneath it.

    ``registry`` and ``directory`` are injectable for the same reason: the tests
    need a ledger with a known history and a directory with known members, and a
    startup that reaches for a global would make that impossible without LDAP
    and a database.
    """
    app = FastAPI(title="FileEngine System Administration", version=__version__)
    app.state.config = config
    app.state.registry = registry if registry is not None else AdministratorRegistry()
    app.state.directory = directory if directory is not None else default_directory(config)
    apply_bootstrap(config, app.state.registry)

    # PHASE 1 (§8.1): read-only, plus the door in front of it and the grant
    # endpoints, which touch this application's own ledger and nothing else.
    #
    # The later phases land here as they are built:
    #   phase 2  queue        — acknowledgement
    #   phase 3  decisions    — redaction approval
    #   phase 4  exclusions   — the destructive tenant-admin tasks
    # They are absent rather than stubbed. A route that exists and returns 501
    # is a route somebody will wire up.
    app.include_router(build_router(config, app.state.registry, app.state.directory))
    return app


def apply_bootstrap(config: Config, registry: AdministratorRegistry) -> list:
    """Apply ``AMC_BOOTSTRAP_OWNER``, if set, and say what it did.

    Idempotent, because it runs on every start. A refusal is LOGGED rather than
    raised: the deployment already has an owner and is therefore working, and
    taking the console down because a stale configuration value names somebody
    else would be an outage caused by a file nobody has read in a year. /readyz
    is where a deployment with NO owner gets reported, and that is the condition
    that actually needs attention.
    """
    if not config.bootstrap_owner:
        return []
    try:
        made = bootstrap_owner(
            registry,
            config.bootstrap_owner,
            with_all_roles=config.bootstrap_owner_all_roles,
        )
    except RoleError as e:
        log.warning("bootstrap owner not applied: %s", e)
        return []
    for g in made:
        log.info("granted %s to %s (by %s)", g.role, g.subject, g.granted_by)
    return made


def build_monitoring(config: Config,
                     registry: AdministratorRegistry | None = None,
                     directory: DeploymentDirectory | None = None) -> FastAPI:
    """The unauthenticated monitoring listener. Loopback-only."""
    mon = FastAPI(title="admin_master_control monitoring", version=__version__)
    registry = registry if registry is not None else AdministratorRegistry()
    directory = directory if directory is not None else default_directory(config)

    @mon.get("/healthz", include_in_schema=False)
    def healthz():
        return {"status": "ok", "service": "admin_master_control", "version": __version__}

    @mon.get("/readyz", include_in_schema=False)
    def readyz():
        """Readiness is a statement about whether it is SAFE to serve, not only
        about whether dependencies answer.

        The prerequisites in §7 of the proposal are conditions of this tier
        existing safely at all, and two of them are checkable from here. A
        deployment that has not met them should not quietly serve a
        cross-tenant console: it should be red, and say which one."""
        problems = []

        if not config.jwt_secret:
            problems.append("no token secret configured")
        if not config.token_audience:
            # Without a distinct audience a tenant token could be accepted here.
            problems.append("no distinct token audience — a tenant token could be accepted")
        if not config.require_mfa:
            problems.append("MFA disabled — mandatory at this tier (§6)")
        if config.monitoring_is_public():
            problems.append(f"monitoring bound off-loopback ({config.monitor_host})")
        if not config.audit_url:
            problems.append("no audit ledger configured — nothing to display (§5.1)")
        # THE DIRECTORY IS AUTHORITATIVE, so this asks it — not the ledger.
        # A deployment can have an owner in ou=system and an empty ledger, which
        # is what a directory-first deployment looks like on its first start;
        # asking the ledger would report that as stranded and be wrong about
        # which store decides.
        known = set(registry.subjects())
        if config.bootstrap_owner:
            known.add(config.bootstrap_owner)
        if not directory_has_owner(directory, known):
            # system_owner is the only role that creates authority, so a
            # deployment without one cannot grant anything to anybody. It is not
            # degraded, it is stranded, and the only way out is the directory.
            problems.append("no system_owner in the directory — nobody can grant authority (§6.3)")

        if problems:
            return JSONResponse({"status": "not-ready", "problems": problems}, status_code=503)
        return {"status": "ready"}

    _fe_metrics.install(mon, "admin_master_control", [], {"version": __version__})
    return mon


def create_app() -> FastAPI:
    """The .env-loading factory, for `uvicorn ...:create_app --factory`."""
    return build_app(get_config())


def main() -> None:  # pragma: no cover - process entrypoint
    import uvicorn

    logging.basicConfig(level=logging.INFO)
    config = get_config()

    registry = AdministratorRegistry()
    app = build_app(config, registry)
    for subject, roles in summarise(registry):
        log.info("administrator %s: %s", subject, ", ".join(roles))

    mon = build_monitoring(config, registry, app.state.directory)
    t = threading.Thread(
        target=lambda: uvicorn.run(mon, host=config.monitor_host, port=config.monitor_port,
                                   log_level="warning"),
        daemon=True)
    t.start()
    log.info("monitoring on %s:%d", config.monitor_host, config.monitor_port)

    uvicorn.run(app, host=config.host, port=config.port)
