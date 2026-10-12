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

"""Claim a provisioning job, run its play on this host, write back what happened.

One job at a time, and one runner at a time per host (a lock file), because two
overlapping plays against the same host are not a supported state. The claim is
also safe across hosts (`FOR UPDATE SKIP LOCKED`), but there is only ever meant to
be the one.

What it guarantees, each answering a §5.3.1 risk:

* **Only an allow-listed playbook runs.** The job names one; the runner refuses
  anything outside ALLOWED_PLAYBOOKS. The database row is not trusted to choose
  what executes.
* **No shell, no interpolation.** The command is an argv list; the job's
  parameters are validated again here and handed to Ansible as a 0600 JSON file
  (`-e @file`), never spliced into a string.
* **A status and a step, not a transcript.** The full output stays on this host
  under the log directory, 0600; the console gets whether it worked, which task
  failed, and that task's own message.
* **No automatic retry.** A failure is recorded and stays recorded until a person
  re-queues it from the console. The play's certificate step spends issuance from a
  limit shared by every tenant on the domain.
* **It only finishes what it was given.** Success promotes the tenant to `live` only
  if the tenant is still in `provisioning` under THIS job's id.
"""
from __future__ import annotations

import argparse
import fcntl
import json
import logging
import os
import re
import shlex
import signal
import socket
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from typing import Callable, Optional

from admin_master_control import job_store as job_store_mod
from admin_master_control import registry as registry_mod
from admin_master_control.config import Config
from admin_master_control.job_store import (DONE, FAILED, JobStore, StoreUnavailable)
from admin_master_control.registry import (PROVISIONING, RegistryUnavailable,
                                           TenantRegistry)
from admin_master_control.tenants import TenantError, validate_tenant_id

log = logging.getLogger("admin_master_control_runner")

#: The only plays a job may name. Adding one is a code change, reviewed here.
ALLOWED_PLAYBOOKS = frozenset({"playbooks/tenant.yml"})

_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_DETAIL_MAX = 600


def _env(key: str, default: str) -> str:
    return os.environ.get(key, "") or default


@dataclass
class RunnerConfig:
    # The deployment tree ON THIS HOST (scripts/Ansible, installed by roles/amc_runner).
    ansible_dir: str = field(default_factory=lambda: _env(
        "AMC_RUNNER_ANSIBLE_DIR", "/opt/fileengine/provisioner/Ansible"))
    # deploy.sh is used rather than ansible-playbook directly so the secrets, vault
    # password and collections are handled exactly as they are from a workstation.
    command: str = field(default_factory=lambda: _env(
        "AMC_RUNNER_COMMAND", "./deploy.sh --no-capture"))
    # Local connection: the play is built for SSH to the droplet; on the droplet
    # itself it runs against localhost. Extra vars beat the inventory's
    # ansible_host, which deploy.sh would otherwise set from the secrets file.
    extra_args: str = field(default_factory=lambda: _env(
        "AMC_RUNNER_EXTRA_ARGS", "-e ansible_connection=local -e ansible_host=127.0.0.1"))
    log_dir: str = field(default_factory=lambda: _env(
        "AMC_RUNNER_LOG_DIR", "/var/log/fileengine-provisioner"))
    lock_path: str = field(default_factory=lambda: _env(
        "AMC_RUNNER_LOCK", "/run/fileengine-provisioner.lock"))
    runner_id: str = field(default_factory=lambda: _env(
        "AMC_RUNNER_ID", f"runner@{socket.gethostname()}"))
    poll_s: int = field(default_factory=lambda: int(_env("AMC_RUNNER_POLL_S", "15")))
    timeout_s: int = field(default_factory=lambda: int(_env("AMC_RUNNER_TIMEOUT_S", "3600")))


class JobRefused(ValueError):
    """The job cannot be run as given. Recorded as a failure, never executed."""


# ── what to run ───────────────────────────────────────────────────────────


def play_vars(job: dict, display_name: str = "") -> dict:
    """The play's variables from the job, validated again here.

    The console validated them when it wrote the job; this does it again because the
    runner is the one about to hand them to four interpreters, and the row could have
    been written by anything with access to the database.
    """
    playbook = str(job.get("playbook") or "")
    if playbook not in ALLOWED_PLAYBOOKS:
        raise JobRefused(f"playbook {playbook!r} is not one this runner will run")
    ev = job.get("extra_vars") or {}
    tenant_id = str(ev.get("tenant_id") or job.get("tenant_id") or "")
    if tenant_id != job.get("tenant_id"):
        raise JobRefused("the job's tenant and its parameters disagree")
    try:
        validate_tenant_id(tenant_id)
    except TenantError as e:
        raise JobRefused(str(e)) from e
    admin = str(ev.get("tenant_admin") or "")
    if not _EMAIL.match(admin):
        raise JobRefused(f"the initial administrator {admin!r} is not an email address")
    out = {"tenant": tenant_id, "tenant_admin_email": admin}
    if display_name:
        out["tenant_display_name"] = display_name
    return out


def argv_for(cfg: RunnerConfig, playbook: str, vars_path: str) -> list[str]:
    if playbook not in ALLOWED_PLAYBOOKS:       # belt and braces: never reached otherwise
        raise JobRefused(f"playbook {playbook!r} is not one this runner will run")
    return (shlex.split(cfg.command) + [playbook] + shlex.split(cfg.extra_args)
            + ["-e", f"@{vars_path}"])


# ── what happened ─────────────────────────────────────────────────────────


@dataclass
class Outcome:
    ok: bool
    step: str = ""
    detail: str = ""
    retry_safe: bool = False
    welcome_to: str = ""


_TASK = re.compile(r"^TASK \[(?P<name>.*)\] \*")
_FATAL = re.compile(r"^(?:fatal|failed): \[[^\]]+\]")
_CHANGED = re.compile(r"^changed: \[")
_MSG = re.compile(r'"msg": "(?P<msg>(?:[^"\\]|\\.)*)"')
_RECAP = re.compile(r"\bfailed=(\d+)\b.*\bunreachable=(\d+)|\bunreachable=(\d+)\b.*\bfailed=(\d+)")
_WELCOME = re.compile(r"Welcome mail sent to (?P<to>\S+)")


def summarise(rc: int, output: str) -> Outcome:
    """Read an ansible run's output down to a status, a step and a message.

    `retry_safe` is true only when the run failed BEFORE it changed anything —
    typically a pre-flight assertion such as a hostname that does not resolve yet.
    Anything later has touched the host, and whether to try again is a decision for
    whoever has read why.
    """
    lines = output.splitlines()
    task = ""
    changed_before_failure = False
    for i, line in enumerate(lines):
        m = _TASK.match(line)
        if m:
            task = m.group("name")
            continue
        if _CHANGED.match(line):
            changed_before_failure = True
            continue
        if _FATAL.match(line) or line.startswith("fatal: "):
            # The message is on this line or within the next few (multi-line JSON).
            window = "\n".join(lines[i:i + 12])
            mm = _MSG.search(window)
            msg = mm.group("msg") if mm else line
            try:
                msg = json.loads(f'"{msg}"')
            except ValueError:
                pass
            return Outcome(ok=False, step=task or "unknown step", detail=msg[:_DETAIL_MAX],
                           retry_safe=not changed_before_failure)
    welcome = _WELCOME.search(output)
    if rc == 0:
        return Outcome(ok=True, welcome_to=welcome.group("to").rstrip(".") if welcome else "")
    tail = next((l for l in reversed(lines) if l.strip()), f"exit status {rc}")
    return Outcome(ok=False, step=task or "before the play started", detail=tail[:_DETAIL_MAX],
                   retry_safe=not changed_before_failure)


# ── running it ────────────────────────────────────────────────────────────


Executor = Callable[[list, str, str, int], tuple]


def run_play(argv: list, cwd: str, log_path: str, timeout_s: int) -> tuple:
    """Run the play, teeing its output to a 0600 log on this host. (rc, output)."""
    fd = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as logf:
        # Blocking stdio: Ansible refuses a non-blocking stdin/stdout. A regular file
        # and /dev/null are both blocking.
        proc = subprocess.run(argv, cwd=cwd, stdin=subprocess.DEVNULL, stdout=logf,
                              stderr=subprocess.STDOUT, timeout=timeout_s, check=False)
    with open(log_path, encoding="utf-8", errors="replace") as f:
        return proc.returncode, f.read()


def _write_vars(cfg: RunnerConfig, job_id: str, values: dict) -> str:
    fd, path = tempfile.mkstemp(prefix=f"{job_id}-", suffix=".json", dir=cfg.log_dir)
    with os.fdopen(fd, "w") as f:          # mkstemp creates it 0600
        json.dump(values, f)
    return path


def process_one(cfg: RunnerConfig, jobs: JobStore, registry: TenantRegistry,
                execute: Executor = run_play) -> Optional[str]:
    """Claim and run ONE job. Returns its id, or None when the queue is empty."""
    job = jobs.claim_next(cfg.runner_id)
    if job is None:
        return None
    job_id, tenant_id = job["job_id"], str(job.get("tenant_id") or "")
    by = cfg.runner_id
    log.info("claimed %s for tenant %s", job_id, tenant_id)

    def fail(step: str, detail: str, *, retry_safe: bool = False, touch_registry: bool = True):
        log.warning("%s failed at %s: %s", job_id, step, detail)
        if touch_registry:
            try:
                registry.record_provisioning_failure(tenant_id, job_id, step=step,
                                                     detail=detail, retry_safe=retry_safe)
            except RegistryUnavailable as e:
                log.error("could not record the failure of %s on %s: %s", job_id, tenant_id, e)
        jobs.finish(job_id, state=FAILED, detail=f"{step}: {detail}"[:_DETAIL_MAX])
        return job_id

    tenant = registry.get(tenant_id)
    # A job is only run for the tenant it was written for, while that tenant is
    # still waiting on it. A stale row (the tenant moved, or was re-queued under a
    # newer job) is closed without touching the registry, which belongs to the
    # newer state.
    if tenant is None:
        return fail("runner", f"tenant {tenant_id!r} is not in the registry",
                    touch_registry=False)
    if tenant.state != PROVISIONING or tenant.job_id != job_id:
        return fail("runner", f"stale job: tenant is {tenant.state} under "
                              f"{tenant.job_id or 'no job'}, not provisioning under {job_id}",
                    touch_registry=False)
    try:
        values = play_vars(job, tenant.display_name)
    except JobRefused as e:
        return fail("runner", f"refused: {e}")

    os.makedirs(cfg.log_dir, mode=0o700, exist_ok=True)
    log_path = os.path.join(cfg.log_dir, f"{job_id}-{tenant_id}.log")
    vars_path = _write_vars(cfg, job_id, values)
    try:
        argv = argv_for(cfg, job["playbook"], vars_path)
        log.info("%s: running %s for %s (log %s)", job_id, job["playbook"], tenant_id, log_path)
        try:
            rc, output = execute(argv, cfg.ansible_dir, log_path, cfg.timeout_s)
        except subprocess.TimeoutExpired:
            return fail("runner", f"the play did not finish within {cfg.timeout_s}s; "
                                  f"see {log_path} on the host")
        except OSError as e:
            return fail("runner", f"could not start the play: {e}", retry_safe=True)
    finally:
        try:
            os.unlink(vars_path)
        except OSError:
            pass

    outcome = summarise(rc, output)
    if not outcome.ok:
        return fail(outcome.step, f"{outcome.detail} (full log: {log_path} on the host)",
                    retry_safe=outcome.retry_safe)

    promoted = registry.complete_provisioning(tenant_id, job_id, by)
    detail = (f"welcome mail sent to {outcome.welcome_to}" if outcome.welcome_to
              else "provisioned (no welcome mail reported)")
    if promoted is None:
        # The play worked but the tenant moved under us. Say so instead of claiming
        # it is live.
        detail += "; the tenant was no longer waiting on this job, so it was NOT set live"
    jobs.finish(job_id, state=DONE, detail=detail)
    log.info("%s done: %s", job_id, detail)
    return job_id


# ── the process ───────────────────────────────────────────────────────────


class _Stop:
    requested = False


def _lock(path: str):
    """Hold an exclusive lock for the process lifetime, or exit: one runner per host."""
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        log.error("another provisioning runner holds %s — exiting", path)
        sys.exit(2)
    return fd


def main(argv: Optional[list] = None) -> int:
    ap = argparse.ArgumentParser(prog="amc-provisioner",
                                 description="Run the management console's provisioning queue.")
    ap.add_argument("--once", action="store_true",
                    help="run every queued job, then exit (default: keep polling)")
    args = ap.parse_args(argv)
    logging.basicConfig(level=os.environ.get("AMC_LOG_LEVEL", "INFO"),
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    cfg = RunnerConfig()
    config = Config()
    if not config.pg_user or not config.core_pg_user:
        log.error("AMC_PG_* (the queue) and AMC_CORE_PG_* (the registry) must both be "
                  "configured — a runner with an in-memory queue would run nothing")
        return 2
    jobs = job_store_mod.from_config(config)
    registry = registry_mod.from_config(config)
    lock_fd = _lock(cfg.lock_path)  # noqa: F841 — held until exit

    stop = _Stop()

    def _term(*_):
        # Finish the job in hand, then stop: killing a play halfway leaves a tenant
        # half-built, and the claim already says it is ours.
        stop.requested = True
        log.info("stop requested; finishing the current job first")

    signal.signal(signal.SIGTERM, _term)
    signal.signal(signal.SIGINT, _term)
    log.info("provisioning runner %s started (ansible dir %s)", cfg.runner_id, cfg.ansible_dir)
    while not stop.requested:
        try:
            ran = process_one(cfg, jobs, registry)
        except (StoreUnavailable, RegistryUnavailable) as e:
            log.warning("queue or registry unavailable: %s", e)
            ran = None
        if ran:
            continue
        if args.once:
            break
        for _ in range(cfg.poll_s):
            if stop.requested:
                break
            time.sleep(1)
    return 0


if __name__ == "__main__":
    sys.exit(main())
