# admin_master_control image.
#
#   podman build -f admin_master_control/Containerfile -t admin-master-control ..
#   podman run --rm -p 8103:8103 --env-file admin_master_control/.env admin-master-control
#
# Built with the PARENT directory as context for consistency with the other
# services, though this one currently reuses no sibling package — and that is
# worth preserving. Every package added here is reach this application gains,
# and §4 of the proposal is a list of things it must not be able to do.

# The console UI. Built here rather than copied from a developer's web/dist, so
# the image carries the UI of the commit it was built from and nothing older.
FROM docker.io/library/node:20-slim AS web
WORKDIR /web
COPY admin_master_control/web/package.json admin_master_control/web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY admin_master_control/web/ ./
RUN rm -rf dist && npm run build

FROM python:3.12-slim

WORKDIR /app

COPY admin_master_control/pyproject.toml admin_master_control/README.md /app/admin_master_control/
COPY admin_master_control/src/ /app/admin_master_control/src/

# EDITABLE, deliberately. app.WEB_DIST is resolved relative to the package
# source (src/admin_master_control -> ../../web/dist). A regular install puts
# the package in site-packages, where that path points at nothing, and the
# console starts as an API with no UI — logged at INFO and otherwise silent.
RUN pip install --no-cache-dir -e /app/admin_master_control
COPY --from=web /web/dist/ /app/admin_master_control/web/dist/

# The API only. Monitoring binds loopback INSIDE the container and is reached
# through an exec or a sidecar, never published.
EXPOSE 8103
CMD ["admin-master-control"]
