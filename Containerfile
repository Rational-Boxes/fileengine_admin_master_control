# admin_master_control image.
#
#   podman build -f admin_master_control/Containerfile -t admin-master-control ..
#   podman run --rm -p 8103:8103 --env-file admin_master_control/.env admin-master-control
#
# Built with the PARENT directory as context for consistency with the other
# services, though this one currently reuses no sibling package — and that is
# worth preserving. Every package added here is reach this application gains,
# and §4 of the proposal is a list of things it must not be able to do.
FROM python:3.12-slim

WORKDIR /app

COPY admin_master_control/pyproject.toml admin_master_control/README.md /app/admin_master_control/
COPY admin_master_control/src/ /app/admin_master_control/src/

RUN pip install --no-cache-dir /app/admin_master_control

# The API only. Monitoring binds loopback INSIDE the container and is reached
# through an exec or a sidecar, never published.
EXPOSE 8103
CMD ["admin-master-control"]
