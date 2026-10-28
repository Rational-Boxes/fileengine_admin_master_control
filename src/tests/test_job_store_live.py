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

"""The runner's half of the queue, against a real Postgres.

Skips without AMC_TEST_JOB_PG_DSN. Point it at a THROWAWAY database: the fixture
creates the table if needed and removes only rows whose tenant id starts with
`zztest`, never the whole table.
"""
from __future__ import annotations

import os
import threading

import pytest

from admin_master_control.job_store import PostgresJobStore

live = pytest.mark.skipif(not os.environ.get("AMC_TEST_JOB_PG_DSN"),
                          reason="set AMC_TEST_JOB_PG_DSN to run the live queue tests")


@pytest.fixture
def store():
    s = PostgresJobStore(dsn=os.environ["AMC_TEST_JOB_PG_DSN"])
    s.ensure_schema()

    def clean():
        with s._connect() as conn:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM provisioning_job WHERE tenant_id LIKE 'zztest%'")
            conn.commit()
    clean()
    # Anything else queued would be claimed by these tests. Refuse to run against a
    # database that holds real work rather than claim it.
    if any(j["state"] == "queued" for j in s.jobs(limit=1000)):
        pytest.skip("this database has real queued jobs — use a throwaway one")
    yield s
    clean()


@live
def test_live_claim_finish_round_trip(store):
    jid = store.record("zztesta", {"playbook": "playbooks/tenant.yml", "requested_by": "t"})
    job = store.claim_next("runner@a")
    assert job["job_id"] == jid and job["state"] == "claimed" and job["claimed_by"] == "runner@a"
    assert job["claimed_at"]
    assert store.claim_next("runner@a") is None
    assert store.finish(jid, state="done", detail="ok") is True
    assert store.finish(jid, state="failed", detail="again") is False    # only from claimed
    row = next(j for j in store.jobs() if j["job_id"] == jid)
    assert row["state"] == "done" and row["finished_at"]


@live
def test_live_two_runners_never_claim_the_same_job(store):
    for i in range(6):
        store.record(f"zztest{i}", {"playbook": "playbooks/tenant.yml", "requested_by": "t"})
    got: list = []
    lock = threading.Lock()

    def worker(name):
        while True:
            j = store.claim_next(name)
            if j is None:
                return
            with lock:
                got.append(j["job_id"])

    ts = [threading.Thread(target=worker, args=(f"r{n}",)) for n in range(4)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    assert len(got) == 6 and len(set(got)) == 6
