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
from .config import Config, get_config

log = logging.getLogger("admin_master_control.app")


def build_app(config: Config) -> FastAPI:
    """The API. Pure: takes its config, reads no environment, loads no dotenv —
    so a test can construct one without a deployment underneath it."""
    app = FastAPI(title="FileEngine System Administration", version=__version__)
    app.state.config = config

    # Routers land here as the phases in §8 of the proposal are built:
    #   phase 1  observe      — read-only, cross-tenant
    #   phase 2  queue        — acknowledgement
    #   phase 3  decisions    — redaction approval
    #   phase 4  exclusions   — the destructive tenant-admin tasks
    # Nothing is mounted yet, deliberately: an application at this tier with no
    # routes is safe, and one with speculative routes is not.
    return app


def build_monitoring(config: Config) -> FastAPI:
    """The unauthenticated monitoring listener. Loopback-only."""
    mon = FastAPI(title="admin_master_control monitoring", version=__version__)

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

    mon = build_monitoring(config)
    t = threading.Thread(
        target=lambda: uvicorn.run(mon, host=config.monitor_host, port=config.monitor_port,
                                   log_level="warning"),
        daemon=True)
    t.start()
    log.info("monitoring on %s:%d", config.monitor_host, config.monitor_port)

    uvicorn.run(build_app(config), host=config.host, port=config.port)
