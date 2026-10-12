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

"""The provisioning runner: claim, run, write back — with the play faked.

The executor is injected, so these exercise every decision the runner makes about a
job without running Ansible. What they pin is the contract with the console: which
states it moves the tenant through, what it records on failure, and what it refuses
to run at all.
"""
from __future__ import annotations

import json
import subprocess

import pytest

from admin_master_control.job_store import InMemoryJobStore
from admin_master_control.registry import (LIVE, PROVISIONING, StaticTenantRegistry,
                                           Tenant)
from admin_master_control.tenants import provisioning_job
from admin_master_control_runner import runner as r

OK_OUTPUT = """
PLAY [Add a FileEngine tenant] *************************************************

TASK [Record the tenant on the host] *******************************************
changed: [fileengine-do]

TASK [Send the administrator the welcome mail] *********************************
ok: [fileengine-do]

TASK [Report the welcome mail] *************************************************
ok: [fileengine-do] => {
    "msg": "Welcome mail sent to james@rationalboxes.com (set-password link valid 72h)."
}

PLAY RECAP *********************************************************************
fileengine-do              : ok=40   changed=12   unreachable=0    failed=0    skipped=3
"""

DNS_FAIL = """
TASK [Resolve the tenant hostnames] ********************************************
ok: [fileengine-do] => (item=acme.example.com)

TASK [Every tenant hostname must resolve before a certificate is requested] ****
fatal: [fileengine-do]: FAILED! => {
    "assertion": "...",
    "changed": false,
    "msg": "These do not resolve yet: acme-media.example.com. Add the A records at your DNS provider, let them propagate, and re-run. Nothing has been changed on the host."
}

PLAY RECAP *********************************************************************
fileengine-do              : ok=8    changed=0    unreachable=0    failed=1    skipped=0
"""

CERT_FAIL = """
TASK [Record the tenant on the host] *******************************************
changed: [fileengine-do]

TASK [ingress_nginx : Obtain certificates] *************************************
fatal: [fileengine-do]: FAILED! => {"changed": true, "msg": "non-zero return code", "rc": 1}

PLAY RECAP *********************************************************************
fileengine-do              : ok=20   changed=4    unreachable=0    failed=1    skipped=0
"""


def _setup(tmp_path, *, admin="james@rationalboxes.com", playbook=None, state=PROVISIONING):
    jobs = InMemoryJobStore()
    reg = StaticTenantRegistry().seed(Tenant(
        tenant_id="acme", schema_name="tenant_acme", state=state, display_name="Acme Ltd",
        base_domain="example.com", initial_admin=admin))
    job = provisioning_job(tenant_id="acme", base_domain="example.com", address="1.2.3.4",
                           initial_admin=admin, hostnames=["acme.example.com"],
                           requested_by="james", dns_verified=True)
    if playbook is not None:
        job["playbook"] = playbook
    job_id = jobs.record("acme", job)
    reg.attach_job("acme", job_id)
    cfg = r.RunnerConfig(ansible_dir=str(tmp_path), log_dir=str(tmp_path / "logs"),
                         command="./deploy.sh --no-capture", runner_id="runner@test",
                         extra_args="-e ansible_connection=local")
    return cfg, jobs, reg, job_id


class _Exec:
    def __init__(self, rc=0, output=OK_OUTPUT, raises=None):
        self.rc, self.output, self.raises = rc, output, raises
        self.calls = []

    def __call__(self, argv, cwd, log_path, timeout):
        vars_file = argv[-1][1:]
        with open(vars_file) as f:
            self.calls.append({"argv": argv, "cwd": cwd, "vars": json.load(f),
                               "log": log_path})
        if self.raises:
            raise self.raises
        return self.rc, self.output


def _job(jobs, job_id):
    return next(j for j in jobs.jobs() if j["job_id"] == job_id)


def test_success_runs_the_play_locally_and_sets_the_tenant_live(tmp_path):
    cfg, jobs, reg, job_id = _setup(tmp_path)
    ex = _Exec()
    assert r.process_one(cfg, jobs, reg, ex) == job_id
    call = ex.calls[0]
    assert call["argv"][:3] == ["./deploy.sh", "--no-capture", "playbooks/tenant.yml"]
    assert "-e" in call["argv"] and "ansible_connection=local" in call["argv"]
    assert call["cwd"] == str(tmp_path)
    # The play's own variable names, not the job's.
    assert call["vars"] == {"tenant": "acme", "tenant_admin_email": "james@rationalboxes.com",
                            "tenant_display_name": "Acme Ltd"}
    assert reg.get("acme").state == LIVE
    j = _job(jobs, job_id)
    assert j["state"] == "done" and "james@rationalboxes.com" in j["detail"]
    assert j["claimed_by"] == "runner@test"


def test_the_vars_file_does_not_outlive_the_run(tmp_path):
    cfg, jobs, reg, _ = _setup(tmp_path)
    ex = _Exec()
    r.process_one(cfg, jobs, reg, ex)
    import os
    assert not os.path.exists(ex.calls[0]["argv"][-1][1:])


def test_empty_queue_runs_nothing(tmp_path):
    cfg, jobs, reg, _ = _setup(tmp_path)
    ex = _Exec()
    r.process_one(cfg, jobs, reg, ex)
    assert r.process_one(cfg, jobs, reg, ex) is None
    assert len(ex.calls) == 1


def test_a_preflight_failure_is_recorded_and_safe_to_retry(tmp_path):
    cfg, jobs, reg, job_id = _setup(tmp_path)
    r.process_one(cfg, jobs, reg, _Exec(rc=2, output=DNS_FAIL))
    t = reg.get("acme")
    assert t.state == PROVISIONING                     # never `failed`, never live
    assert t.failed_step.startswith("Every tenant hostname must resolve")
    assert "acme-media.example.com" in t.failure_detail
    assert t.retry_safe is True                        # nothing had changed yet
    assert t.may_retry
    assert _job(jobs, job_id)["state"] == "failed"


def test_a_failure_after_changes_needs_a_human(tmp_path):
    cfg, jobs, reg, _ = _setup(tmp_path)
    r.process_one(cfg, jobs, reg, _Exec(rc=2, output=CERT_FAIL))
    t = reg.get("acme")
    assert t.failed_step == "ingress_nginx : Obtain certificates"
    assert t.retry_safe is False


def test_nothing_is_retried_automatically(tmp_path):
    cfg, jobs, reg, _ = _setup(tmp_path)
    ex = _Exec(rc=2, output=CERT_FAIL)
    r.process_one(cfg, jobs, reg, ex)
    assert r.process_one(cfg, jobs, reg, ex) is None
    assert len(ex.calls) == 1


def test_a_playbook_outside_the_allow_list_never_runs(tmp_path):
    cfg, jobs, reg, job_id = _setup(tmp_path, playbook="playbooks/site.yml")
    ex = _Exec()
    r.process_one(cfg, jobs, reg, ex)
    assert ex.calls == []
    assert "not one this runner will run" in reg.get("acme").failure_detail
    assert _job(jobs, job_id)["state"] == "failed"


@pytest.mark.parametrize("admin", ["", "not-an-address", "a@b.c; rm -rf /"])
def test_a_malformed_administrator_never_runs(tmp_path, admin):
    cfg, jobs, reg, _ = _setup(tmp_path, admin=admin)
    ex = _Exec()
    r.process_one(cfg, jobs, reg, ex)
    assert ex.calls == []


def test_a_stale_job_is_closed_without_touching_the_registry(tmp_path):
    cfg, jobs, reg, job_id = _setup(tmp_path)
    reg.attach_job("acme", "job-99")                   # re-queued under a newer job
    ex = _Exec()
    r.process_one(cfg, jobs, reg, ex)
    assert ex.calls == []
    assert reg.get("acme").failed_step == ""           # the newer job's state is untouched
    assert "stale job" in _job(jobs, job_id)["detail"]


def test_a_timeout_is_a_failure_that_names_the_log(tmp_path):
    cfg, jobs, reg, _ = _setup(tmp_path)
    r.process_one(cfg, jobs, reg, _Exec(raises=subprocess.TimeoutExpired("x", 1)))
    t = reg.get("acme")
    assert t.failed_step == "runner" and "on the host" in t.failure_detail
    assert t.retry_safe is False


def test_the_tenant_id_reaches_ansible_only_through_the_vars_file(tmp_path):
    cfg, jobs, reg, _ = _setup(tmp_path)
    ex = _Exec()
    r.process_one(cfg, jobs, reg, ex)
    assert not any("acme" in a for a in ex.calls[0]["argv"][:-1] if a != "-e")


def test_the_web_package_still_cannot_execute_anything():
    # The runner lives in its own package precisely so this stays true.
    import pathlib

    import admin_master_control
    pkg = pathlib.Path(admin_master_control.__file__).parent
    for src in pkg.rglob("*.py"):
        assert "admin_master_control_runner" not in src.read_text(), src.name


def test_summarise_reads_success():
    o = r.summarise(0, OK_OUTPUT)
    assert o.ok and o.welcome_to == "james@rationalboxes.com"
