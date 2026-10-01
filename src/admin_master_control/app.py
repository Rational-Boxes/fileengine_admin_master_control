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
import pathlib
import threading

from fastapi import FastAPI, HTTPException, status
from fastapi.responses import JSONResponse

from . import metrics as _fe_metrics
from . import __version__
from .administrators import AdministratorRegistry, bootstrap_owner, summarise
from .api import build_router
from .incidents import IncidentSource, from_config as incidents_from_config
from .mfa import FactorStore, from_config as factors_from_config
from .redactions import ErasureSource, StaticErasures
from .job_store import JobStore, from_config as job_store_from_config
from .tls import SystemTlsProbe
from .registry import TenantRegistry, from_config as registry_from_config
from .tenants import Resolver, SystemResolver
from .auth import (
    DeploymentDirectory,
    DirectoryUnavailable,
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
                                       bind_dn=config.ldap_bind_dn,
                                       bind_password=config.ldap_bind_password,
                                       role_ou=config.ldap_role_ou,
                                       user_ou=config.ldap_user_ou)
    log.warning("no directory configured — every login will be refused")
    return StaticDeploymentDirectory()


def build_app(config: Config,
              registry: AdministratorRegistry | None = None,
              directory: DeploymentDirectory | None = None,
              incidents: IncidentSource | None = None,
              erasures: ErasureSource | None = None,
              resolver: Resolver | None = None,
              factors: FactorStore | None = None,
              # NOT `registry`: that parameter is the AdministratorRegistry.
              tenant_registry: TenantRegistry | None = None,
              jobs: JobStore | None = None,
              tls_probe=None) -> FastAPI:
    """The API. Pure: takes its config, reads no environment, loads no dotenv —
    so a test can construct one without a deployment underneath it.

    ``registry`` and ``directory`` are injectable for the same reason: the tests
    need a ledger with a known history and a directory with known members, and a
    startup that reaches for a global would make that impossible without LDAP
    and a database.
    """
    app = FastAPI(
        title="FileEngine System Administration",
        version=__version__,
        # None removes the ROUTE. app.openapi() still works, so the tests that
        # assert the served surface are unaffected — they read the schema through
        # the method, not over HTTP.
        docs_url="/docs" if config.serve_api_docs else None,
        redoc_url="/redoc" if config.serve_api_docs else None,
        openapi_url="/openapi.json" if config.serve_api_docs else None,
    )
    if config.serve_api_docs:
        log.warning("AMC_SERVE_API_DOCS is on — /docs and /openapi.json are "
                    "UNAUTHENTICATED on the public listener and publish this "
                    "console's whole route inventory")
    app.state.config = config
    app.state.registry = registry if registry is not None else AdministratorRegistry()
    app.state.directory = directory if directory is not None else default_directory(config)
    app.state.incidents = incidents if incidents is not None else incidents_from_config(config)
    # No live erasure source exists yet — §3.3.1's fields come from the core's
    # `erasure` table plus LDAP, and neither read is built. An EMPTY source, not
    # None: the route then reports an empty register rather than 503, which is
    # honest (there are no items it can see) where a 503 would say the feature is
    # broken.
    app.state.erasures = erasures if erasures is not None else StaticErasures()
    # The LOCAL resolver, which reports itself as non-authoritative — so the DNS
    # gate will not pass on its word and an administrator must use the recorded
    # override. That is deliberate: a local lookup masquerading as proof is how a
    # premature run burns the domain's certificate rate limit.
    app.state.resolver = resolver if resolver is not None else SystemResolver()
    # THE TENANT REGISTRY IS THE CORE'S TABLE. This console reads and writes
    # `public.tenants` rather than keeping a second one: it already modelled
    # requested -> awaiting_dns -> provisioning -> live, the doors compare against
    # it, and a private copy would let this console report `live` for a tenant the
    # registry had suspended. See registry.py.
    app.state.tenant_registry = (tenant_registry if tenant_registry is not None
                                 else registry_from_config(config))
    # The provisioning queue IS this application's own — the runner needs somewhere
    # to look, and §5.3 puts that boundary here.
    app.state.jobs = jobs if jobs is not None else job_store_from_config(config)
    # The certificate prober. Real TLS connections, so it is injectable — the tests must
    # not open sockets, and a test that quietly did would pass or fail on whatever
    # happened to be listening.
    app.state.tls_probe = tls_probe if tls_probe is not None else SystemTlsProbe()
    # The second-factor store. None when unconfigured, which is NOT "MFA off":
    # MfaGate refuses every login while the requirement stands, because a
    # requirement that evaporates on the deployment that misconfigured it is not a
    # requirement. AMC_REQUIRE_MFA=false is the only way out, and it is explicit.
    app.state.factors = factors if factors is not None else factors_from_config(config)
    if config.require_mfa and app.state.factors is None:
        log.error("a second factor is REQUIRED but no store is configured — set "
                  "AMC_MFA_URL and AMC_MFA_INTERNAL_SECRET, or opt out explicitly "
                  "with AMC_REQUIRE_MFA=false. Every login will be refused.")
    elif not config.require_mfa:
        log.warning("AMC_REQUIRE_MFA is false — this deployment admits the "
                    "cross-tenant console on a password alone")
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
    # BY KEYWORD, all of them. This call passed ten positional arguments and a new
    # parameter inserted into the middle of the signature silently swapped `factors`
    # with `tls_probe` — which surfaced as `'SystemTlsProbe' object has no attribute
    # 'status'` from inside the MFA gate, sixty-six tests away from the cause.
    app.include_router(build_router(
        config,
        registry=app.state.registry,
        directory=app.state.directory,
        incidents=app.state.incidents,
        erasures=app.state.erasures,
        resolver=app.state.resolver,
        tenant_registry=app.state.tenant_registry,
        jobs=app.state.jobs,
        factors=app.state.factors,
        tls_probe=app.state.tls_probe,
    ))
    mount_web(app)
    return app


#: The built console UI, relative to the repository root. Vite writes it here.
WEB_DIST = pathlib.Path(__file__).resolve().parents[2] / "web" / "dist"

#: First path segment values the SPA fallback refuses. See mount_web.
_NOT_SPA = frozenset({
    "healthz", "readyz", "poolz", "metrics",
    "docs", "redoc", "openapi.json",
})


def mount_web(app: FastAPI) -> None:
    """Serve the built Vue console from this same app, if it has been built.

    SAME ORIGIN, deliberately. The UI could be served by Vite or any static host,
    but then every authenticated request is cross-origin: CORS on the console that
    reads every tenant's audit, a preflight on each call, and an allow-list to keep
    correct. Serving the bundle here means the browser's origin and the API's are
    the same and none of that exists.

    It also makes the dev tunnel work. The ngrok account allows ONE agent session,
    so the console and its UI have to share a single endpoint; two origins would
    need two.

    MOUNTED LAST, after the API router, so nothing here can shadow /v1. That
    ordering is the whole safety property of this function: a catch-all mounted
    first would answer API paths with index.html, and a 404 from the API would
    arrive at the browser as a 200 containing HTML — which fetch() then fails to
    parse, reporting a JSON error for what was really a missing route.

    Absent dist is not an error. The console is a useful API without a UI, and a
    deployment that has not run `npm run build` should not fail to start.
    """
    #: Paths the SPA must NOT answer, beyond /v1.
    #:
    #: Found over the tunnel: `GET /readyz` returned 200 with index.html, because
    #: it is not a /v1 path and the fallback took it. The monitoring endpoints live
    #: on the loopback-only listener and are deliberately unreachable from outside
    #: — but an external health check pointed here would have read that 200 as
    #: "ready" without the service having been asked anything. A false healthy is
    #: worse than an unreachable probe, because nobody investigates it.
    #:
    #: The docs paths are here for the adjacent reason: with AMC_SERVE_API_DOCS off
    #: the routes are gone, and a client fetching /openapi.json would otherwise get
    #: HTML with a 200 and fail on parsing it rather than on the 404 that is true.
    #:
    #: (The production reverse proxy blocks the monitoring paths too. This is the
    #: same rule applied where the SPA could otherwise answer for them.)
    if not WEB_DIST.is_dir():
        log.info("no built UI at %s — serving the API only "
                 "(cd web && npm install && npm run build)", WEB_DIST)
        return

    from fastapi.responses import FileResponse
    from fastapi.staticfiles import StaticFiles

    index = WEB_DIST / "index.html"
    assets = WEB_DIST / "assets"
    if assets.is_dir():
        app.mount("/assets", StaticFiles(directory=assets), name="assets")

    @app.get("/{path:path}", include_in_schema=False)
    def spa(path: str):
        """The history-mode fallback.

        Vue Router uses real paths (/tenants/acme), so a reload has to return the
        app rather than 404. But ONLY for paths the API does not own: /v1 is
        answered above by the router — this handler is registered after it, so it
        never sees those — and it is refused here as well rather than relying on
        that, because a catch-all that could answer an API path would turn a
        genuine 404 into an HTML 200 and the error would surface as a JSON parse
        failure in the browser instead.
        """
        if path.startswith("v1/") or path.split("/")[0] in _NOT_SPA:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")
        # A real file, if it is one (favicon, manifest); otherwise the app.
        candidate = (WEB_DIST / path).resolve()
        if path and candidate.is_file() and candidate.is_relative_to(WEB_DIST.resolve()):
            return FileResponse(candidate)
        return FileResponse(index)

    log.info("serving the console UI from %s", WEB_DIST)
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
        elif not config.mfa_is_enforceable():
            # Required, and nothing to check it against. Reported separately from
            # "disabled" because the deployment believes it is enforcing: this is
            # the state in which the requirement is decorative, and it is exactly
            # the trap the tenant-state gate was written to avoid.
            problems.append("a second factor is required but no store is configured "
                            "(AMC_MFA_URL / AMC_MFA_INTERNAL_SECRET) — every login "
                            "will be refused")
        if config.monitoring_is_public():
            problems.append(f"monitoring bound off-loopback ({config.monitor_host})")
        if config.serve_api_docs:
            # Same class as the line above: an unauthenticated surface where this
            # deployment's convention says there should not be one.
            problems.append("API docs are served (AMC_SERVE_API_DOCS) — /docs and "
                            "/openapi.json are unauthenticated on the public listener")
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
        try:
            has_owner = directory_has_owner(directory, known)
        except DirectoryUnavailable as e:
            # NOT "no owner". The directory could not be asked, and the two need
            # opposite responses: a missing owner is a provisioning gap, while an
            # unreadable role OU is a bind credential. This reported the former
            # about a directory containing an owner in all five groups, because
            # the role search bound anonymously and OpenLDAP hides ou=system from
            # an anonymous client.
            problems.append(f"the deployment directory could not be read: {e.reason}")
        else:
            if not has_owner:
                # system_owner is the only role that creates authority, so a
                # deployment without one cannot grant anything to anybody. It is
                # not degraded, it is stranded, and the only way out is the
                # directory.
                problems.append(
                    "no system_owner in the directory — nobody can grant authority (§6.3)")

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
