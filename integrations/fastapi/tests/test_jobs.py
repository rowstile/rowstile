"""Background jobs in a worker process of their own, on Redis: Celery's worker (prefork, one process) and RQ's
(SimpleWorker: every job in the worker's own process, so they share its connection). Each job is started by a
request; it acts for a service of its own (check 10), or for the user who asked, passed to it (never what a
request left behind); the next job on the worker's one connection never acts for the one before (check 4's twin);
a refusal inside a job raises the SDK's Refused or NotFound, which Celery's result gives back whole."""

import os
import signal
import subprocess
import sys
from collections.abc import AsyncIterator, Iterator
from pathlib import Path
from typing import Any

import httpx
import psycopg
import pytest
import rowstile
import rowstile.psycopg as pgp
from app import jobs, worker
from app.main import make_app
from fastapi import FastAPI
from rq.job import Job, JobStatus

from .conftest import OWNER, libpq

Answer = Any  # the JSON a route answers
pytestmark = pytest.mark.anyio
APP = os.environ.get("ROWSTILE_APP_URL", "")
HERE = Path(__file__).resolve().parent.parent


def client(app: FastAPI) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://jobs")


def as_(user: str) -> dict[str, str]:
    return {"x-user": user}


@pytest.fixture
async def app() -> AsyncIterator[FastAPI]:
    a = make_app(APP, check_connection=False)
    yield a
    await a.state.engine.dispose()


@pytest.fixture(scope="module")
def celery_worker(tmp_path_factory: pytest.TempPathFactory) -> Iterator[None]:
    """Celery's worker, as an app runs it: prefork, one process, which runs every task in turn."""
    if not os.environ.get("ROWSTILE_REDIS_URL"):
        pytest.skip("ROWSTILE_REDIS_URL is not set (test.sh starts Redis)")
    log = tmp_path_factory.mktemp("celery") / "worker.log"
    command = [sys.executable, "-m", "celery", "-A", "app.worker", "worker", "--pool", "prefork", "--concurrency", "1"]
    command += ["--without-gossip", "--without-mingle", "--without-heartbeat", "--loglevel", "warning"]
    with open(log, "w", encoding="utf-8") as out:
        proc = subprocess.Popen(command, cwd=HERE, stdout=out, stderr=subprocess.STDOUT)
    try:
        ready = False
        for _ in range(120):  # a minute
            ready = proc.poll() is None and bool(worker.celery.control.ping(timeout=0.5))
            if ready or proc.poll() is not None:
                break
        assert ready, log.read_text(encoding="utf-8")
        yield
    finally:
        proc.send_signal(signal.SIGTERM)  # a warm shutdown: the task it runs ends first
        try:
            proc.wait(30)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()


def rq_burst() -> None:
    """RQ's worker runs the jobs queued so far, one after the other in its own process, then stops."""
    if not os.environ.get("ROWSTILE_REDIS_URL"):
        pytest.skip("ROWSTILE_REDIS_URL is not set (test.sh starts Redis)")
    command = [sys.executable, "-m", "rq.cli", "worker", "--burst", "--worker-class", "rq.SimpleWorker"]
    command += ["--url", worker.REDIS, "--quiet", "conformance"]
    ran = subprocess.run(command, cwd=HERE, capture_output=True, text=True, timeout=120)
    assert ran.returncode == 0, ran.stdout + ran.stderr


def rq_job(job_id: str) -> Job:
    return Job.fetch(job_id, connection=worker.queue.connection)


def rq_result(job_id: str) -> Answer:
    """What an RQ job returned (RQ keeps it pickled)."""
    job = rq_job(job_id)
    assert job.get_status() == JobStatus.FINISHED, job.get_status()
    return job.return_value()


def rq_failure(job_id: str) -> str:
    """What a failed RQ job raised, as RQ keeps it: the traceback's text."""
    job = rq_job(job_id)
    assert job.get_status() == JobStatus.FAILED, job.get_status()
    result = job.latest_result()
    assert result is not None and result.exc_string is not None
    return result.exc_string


def forget(*ids: int) -> None:
    """Notes a check added, removed again as the owner: the other checks' rows stay as conftest wrote them."""
    with psycopg.connect(libpq(OWNER), autocommit=True) as conn:
        conn.execute("DELETE FROM app.notes WHERE id = ANY(%s)", (list(ids),))


def seen_by(who: str | None) -> list[int]:
    """The notes a user sees, asked here, outside a worker (the checks before these may have added some)."""
    with psycopg.connect(libpq(APP)) as conn, pgp.transaction(conn, who):
        return sorted(int(r[0]) for r in conn.execute("SELECT id FROM app.notes"))


def author_of(note_id: int) -> int | None:
    with psycopg.connect(libpq(OWNER), autocommit=True) as conn:
        row = conn.execute("SELECT author_id FROM app.notes WHERE id = %s", (note_id,)).fetchone()
        return None if row is None else int(row[0])


# 10: a background job signs in as a service principal, whoever asked, in a worker: sync and async
async def test_10_a_job_in_a_worker_acts_as_its_service(app: FastAPI, celery_worker: None) -> None:
    async with client(app) as c:
        started = (await c.post("/jobs/digest", headers=as_("3"))).json()  # cy would see projects 1 and 3 too
        for name in ("celery", "celery_async"):
            assert (await c.get(f"/jobs/celery/{started[name]}")).json() == {"result": 2}, name
    rq_burst()
    # project 1 (the service is added to it) and the public one
    assert [rq_result(started[name]) for name in ("rq", "rq_async")] == [2, 2]


# 10: a job for the user who asked acts for them, given to it as an argument
async def test_10_a_job_acts_for_the_user_who_asked(app: FastAPI, celery_worker: None) -> None:
    async with client(app) as c:
        started = (await c.post("/jobs/notes", json={"project_id": 1, "body": "later"}, headers=as_("3"))).json()
        note = (await c.get(f"/jobs/celery/{started['celery']}")).json()["result"]
    rq_burst()
    queued = rq_result(started["rq"])
    try:
        assert isinstance(note, int) and isinstance(queued, int) and note != queued
        assert author_of(note) == author_of(queued) == 3  # cy, a member of project 1
    finally:
        forget(note, queued)


# 6: a refused insert inside a job raises Refused, naming the rule; Celery's result gives it back whole (a 403)
async def test_6_a_refused_insert_in_a_job_raises_refused(app: FastAPI, celery_worker: None) -> None:
    async with client(app) as c:
        started = (await c.post("/jobs/notes", json={"project_id": 3, "body": "hi"}, headers=as_("2"))).json()
        r = await c.get(f"/jobs/celery/{started['celery']}")
    assert r.status_code == 403, r.text
    body: Answer = r.json()
    assert body["table"] == "app.notes" and body["command"] == "insert" and body["code"] == "AZ709", body
    assert "user 2 may not insert this row into app.notes" in body["detail"], body
    assert any("project.edit" in line for line in body["why"]), body["why"]
    # and in the worker itself: the exception Celery's result raises is the job's
    with pytest.raises(rowstile.Refused) as e:
        worker.celery.AsyncResult(started["celery"]).get(timeout=60)
    assert e.value.table == "app.notes" and e.value.command == "insert" and e.value.why == body["why"]
    rq_burst()
    failed = rq_failure(started["rq"])
    assert "rowstile.Refused: permission denied: user 2 may not insert this row into app.notes" in failed, failed


# 7: in a job, an update of a hidden row raises NotFound; of a row the user may see, not edit, Refused, with why
async def test_7_in_a_job_hidden_is_not_found_and_not_allowed_is_refused(app: FastAPI, celery_worker: None) -> None:
    async with client(app) as c:
        hidden = (await c.patch("/jobs/notes/1", json={"body": "x"}, headers=as_("2"))).json()
        refused = (await c.patch("/jobs/notes/1", json={"body": "x"}, headers=as_("3"))).json()
        gone = (await c.delete("/jobs/notes/1", headers=as_("2"))).json()
        no = (await c.delete("/jobs/notes/1", headers=as_("3"))).json()
        started = {"hidden": hidden, "refused": refused, "gone": gone, "no": no}
        answers = {name: await c.get(f"/jobs/celery/{s['celery']}") for name, s in started.items()}
    assert answers["hidden"].status_code == 404 and answers["gone"].status_code == 404, answers
    for name, command in (("refused", "update"), ("no", "delete")):
        r = answers[name]
        assert r.status_code == 403 and r.json()["command"] == command and r.json()["why"], r.text
        assert r.json()["detail"] == f"permission denied: user 3 may not {command} row 1 of app.notes", r.text
    rq_burst()
    assert "rowstile.NotFound: app.notes 1 not found" in rq_failure(hidden["rq"])
    assert "rowstile.NotFound: app.notes 1 not found" in rq_failure(gone["rq"])
    for started, command in ((refused, "update"), (no, "delete")):
        failed = rq_failure(started["rq"])
        assert f"rowstile.Refused: permission denied: user 3 may not {command} row 1 of app.notes" in failed, failed
    assert author_of(1) == 1  # note 1 is still there


# 4, for workers: on the worker's one connection, ann's job, then bo's, then one that names no one: none sees
# the one before's rows, and the connection, as the last job left it, holds no one
def test_4_a_workers_connection_carries_no_one_over(celery_worker: None) -> None:
    order: list[str | None] = ["1", "2", None, "1", None]
    expected = [seen_by(who) for who in order]
    assert len({tuple(notes) for notes in expected}) == 3, expected  # ann, bo and nobody each see other notes
    tasks = [worker.notes_seen.delay(who) for who in order]
    seen = [task.get(timeout=60) for task in tasks]
    held, code, connection = worker.left_behind.delay().get(timeout=60)
    assert [notes for notes, _ in seen] == expected
    assert {used for _, used in seen} == {connection}, seen  # one connection, the pool's
    assert held is None and code == "AZ701", (held, code)  # rowstile help AZ701
    queued = [worker.queue.enqueue(jobs.notes_seen, who) for who in order]
    last = worker.queue.enqueue(jobs.left_behind)
    rq_burst()
    seen = [rq_result(job.id) for job in queued]
    held, code, connection = rq_result(last.id)
    assert [notes for notes, _ in seen] == expected
    assert {used for _, used in seen} == {connection}, seen
    assert held is None and code == "AZ701", (held, code)


# what a job gives back to the code that waits for it: Refused and NotFound, whole, after pickle and JSON
def test_refused_and_not_found_cross_a_queue_whole() -> None:
    import pickle

    refused = rowstile.Refused("permission denied", "app.notes", "update", ["no: edit"], "AZ705")
    for copy in (pickle.loads(pickle.dumps(refused)), rowstile.Refused(*refused.args)):
        assert isinstance(copy, rowstile.Refused) and copy.problem() == refused.problem()
        assert str(copy) == "permission denied"
    hidden = rowstile.NotFound("app.notes", (1, "a b"))
    for copy in (pickle.loads(pickle.dumps(hidden)), rowstile.NotFound(*hidden.args)):
        assert isinstance(copy, rowstile.NotFound) and copy.problem() == hidden.problem()
        assert str(copy) == 'app.notes (1,"a b") not found'
    # Celery's own: what its result backend keeps of an error, and the error it makes of that
    backend = worker.celery.backend
    for exc in (refused, hidden):
        again = backend.exception_to_python(backend.prepare_exception(exc))
        assert isinstance(again, type(exc)) and type(again) is type(exc), again
        assert again.problem() == exc.problem(), again
