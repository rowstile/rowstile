# Python apps: SQLAlchemy, SQLModel, psycopg and asyncpg

<!-- tested: every line of code below is in integrations/fastapi (tests/unit_test.py checks it) -->

Any Python app (Flask, Litestar, a worker, a script) on SQLAlchemy's sync engine, SQLModel, psycopg or
asyncpg. (Django: [Django](django.md), a preview.) Each transaction signs in as whoever the code acts for, the database filters what it
reads and refuses what it may not write, and the SDK raises `Refused` (403) or `NotFound` (404). FastAPI:
[FastAPI](fastapi.md).

These come from the conformance suite (`integrations/fastapi/tests/test_conformance.py`).

```sh
pip install --pre "rowstile[sqlalchemy,psycopg]"   # or [asyncpg]; the command comes with it (--pre: the newest pre-release)
```

## Who a transaction acts for

`acting_as(who)` signs in every transaction begun inside it: `42` or `"42"` (a user), `("service", 3)` (another
principal type of the policy), or `None` (nobody: only what `anyone` may see). In a web app, enter it around
each request. A background job is `@rowstile.job(who)` ([Background jobs](#background-jobs-celery-and-rq-preview)). Every transaction signs in, even as nobody, and
nothing uses a session-level `SET`, so pools and poolers in transaction mode are safe (behind one that keeps no
prepared statements, turn the driver's off: [Behind a pooler](../operations.md#behind-a-pooler)). A transaction
already begun keeps who it
acts for: `acting_as` decides for the ones begun inside it.

## SQLAlchemy (sync) and SQLModel

`install(engine)` signs in every transaction the engine begins. SQLModel is built on the same engine.

```python
import pytest
import rowstile
from rowstile import sqlalchemy as authz_sa

    engine = authz_sa.install(create_engine(APP.replace("+asyncpg", "+psycopg")))
        with rowstile.acting_as(2), Session(engine) as s:
            assert sorted(s.scalars(select(Note.id)).all()) == [2, 3]
            assert authz_sa.can_sync(s, "note", 2, "edit") and not authz_sa.can_sync(s, "note", 3, "edit")
```

An ORM update the rules refuse changes 0 rows, which SQLAlchemy raises as `StaleDataError`. The SDK asks the
database why before the flush's transaction is rolled back, in it; `why_stale_sync` gives the answer, `Refused`
with the rule and the reason, or `NotFound` (`None` when the rules allow the change: the row changed since it
was read):

```python
            with pytest.raises(StaleDataError) as e, Session(engine) as s, s.begin():
                note = s.get(Note, 1)
                assert note is not None
                note.body = "x"
            verdict = authz_sa.why_stale_sync(e.value)
            assert isinstance(verdict, Refused) and verdict.why, verdict
```

## psycopg

```python
    import rowstile.psycopg as pgp
        with pgp.transaction(conn, 2):
            assert [r[0] for r in conn.execute("SELECT id FROM app.notes ORDER BY id")] == [2, 3]
```

`transaction(conn, who)` signs in as `who`; `None` is nobody, and with no `who` it is whoever the code acts
for. A sign-in lasts the database transaction, so a transaction is one principal's. A block inside another for
the same principal is a savepoint. One for someone else, or for code that acts for no one, raises a
`RuntimeError` before anything is sent, and the transaction goes on as its principal's: run that work after it, or
in a transaction of its own on another connection. So does a block inside a transaction no block began (psycopg
opens one at the first statement unless `autocommit` is on): who it is signed in as can't be known. asyncpg's
`transaction` does the same.

An UPDATE or DELETE the rules refuse changes 0 rows, without an error; `expect` asks why, and raises
`Refused` or `NotFound` (it takes the row count, the rows, or the cursor):

```python
        with pytest.raises(Refused), pgp.transaction(conn, 3):
            cur = conn.execute("UPDATE app.notes SET body = 'x' WHERE id = 1")
            pgp.expect(conn, cur.rowcount, "app.notes", "update", 1)
```

A refused INSERT is an error already: `rowstile.refusal(exc)` reads it as `Refused`.

A query in a transaction nobody signed in to (a connection the SDK doesn't sign in, an engine in `AUTOCOMMIT`)
fails with the not-signed-in error (AZ701), a bug in the app: `rowstile.not_signed_in(exc)` says whether an
error is that one. A login the database refuses (AZ703) and settings changed by hand (AZ702) have its
SQLSTATE, 28000, but are not it.

## asyncpg

```python
    import rowstile.asyncpg as pga
        with rowstile.acting_as(("service", "1")):
            async with pga.transaction(conn):
                assert [r["id"] for r in await conn.fetch("SELECT id FROM app.projects ORDER BY id")] == [1, 3]
        async with pga.transaction(conn, 2):
            with pytest.raises(rowstile.NotFound):
                await pga.expect(
                    conn, await conn.execute("DELETE FROM app.notes WHERE id = 1"), "app.notes", "delete", 1
                )
```

## Background jobs: Celery and RQ (preview)

**Preview**: what this section shows may change in any release. The conformance suite runs it in Celery's
worker and RQ's, on Redis (`integrations/fastapi/tests/test_jobs.py`).

```sh
pip install --pre "rowstile[sqlalchemy,psycopg]" "celery[redis]" rq
```

A job runs in a worker process, which knows nothing of the request that queued it. So a job says who it acts
for. One that works for the app acts for a principal of its own (`type service = app.services principal` in the
policy), whoever asked:

```python
# app/jobs.py
import functools
import os

import rowstile
from rowstile import NotFound, Principal
from rowstile import sqlalchemy as authz_sa

@functools.cache
def engine() -> Engine:
    url = os.environ["ROWSTILE_APP_URL"].replace("+asyncpg", "+psycopg")
    return authz_sa.install(create_engine(url, pool_size=1, max_overflow=0))

@rowstile.job(("service", 1))
def digest() -> int:
    """Signs in as service 1, whoever asked for it."""
    with Session(engine()) as s:
        return s.scalar(select(func.count()).select_from(Project)) or 0
```

Make the engine in the process that runs the jobs, as `engine()` does on its first call: Celery forks its
workers, and a connection made before the fork would be theirs together.

A job for the user who asked gets them as an argument. The request writes who it acts for as text
(`str(rowstile.current())`: a queue's message holds JSON), and the job reads it back with `Principal.parse`. A
job never reads `rowstile.current()` for this: in a worker it is unset, and a job run in the request's own
process (Celery's eager mode, FastAPI's `BackgroundTasks`) would get whatever the request left behind.

```python
def add_note(asked_by: str, project_id: int, body: str) -> int:
    """For the user who asked. A refused insert raises Refused, with the rule and why."""
    with rowstile.job(Principal.parse(asked_by)) as me, Session(engine()) as s, s.begin():
        note = Note(project_id=project_id, author_id=int(me.id or 0), body=body)
        s.add(note)
        s.flush()
        return note.id
```

The request queues it on Celery or on RQ (both run the same function):

```python
# app/worker.py
celery = Celery("conformance", broker=REDIS, backend=REDIS)
add_note = celery.task(jobs.add_note)
queue = Queue("conformance", connection=Redis.from_url(REDIS))
```

```python
        asked_by = str(rowstile.current())
        task = worker.add_note.delay(asked_by, n.project_id, n.body)
        job = worker.queue.enqueue(jobs.add_note, asked_by, n.project_id, n.body)
```

`with rowstile.job(who)` comes first in the `with`, so it closes last: after the session's transaction is rolled
back, which is when the SDK asks the database about an ORM update it refused. Inside the block, the database's
refusals are raised as the SDK's own: a refused write as `Refused`, with the rule and why; an ORM update of a
row the user may not edit (SQLAlchemy's `StaleDataError`) as `Refused` too, or `NotFound` for one they can't
see. The job's own errors stay as they are. `expect_sync` reads a Core delete that matched nothing:

```python
def remove_note(asked_by: str, note_id: int) -> None:
    """A delete that matched no row: NotFound if the user can't see it, Refused if they may not delete it."""
    with rowstile.job(Principal.parse(asked_by)), Session(engine()) as s, s.begin():
        result = s.execute(delete(Note).where(Note.id == note_id))
        authz_sa.expect_sync(s, result, "app.notes", "delete", note_id)
```

`Refused` and `NotFound` keep what they say in their arguments, so Celery's result gives them back whole to the
code that waits for it. A request that waits answers 403 or 404, as for its own writes:

```python
    @app.get("/jobs/celery/{task_id}")
    async def celery_result(task_id: str) -> dict[str, int | None]:
        # what the job returned; one the database refused raises its Refused or NotFound here: 403 or 404
        done = worker.celery.AsyncResult(task_id)
        return {"result": await asyncio.to_thread(done.get, timeout=60)}
```

RQ keeps a failed job's traceback as text: `rowstile.Refused: permission denied: user 2 may not insert this row
into app.notes`.

Every transaction a job begins signs in, as whoever the job acts for, or as nobody outside a job, and the
sign-in ends with the transaction. So the next job on a worker's pooled connection never acts for the one
before: the suite runs Ann's job, then Bob's, then one that names no one, on one worker with one connection.

An async job runs in an event loop of its own (RQ runs a coroutine with `asyncio.run`; in Celery, the task does).
A pool would keep connections of a loop that is gone, so its engine pools nothing:

```python
import asyncio

@functools.cache
def async_engine() -> AsyncEngine:
    """For async jobs: each runs in an event loop of its own (asyncio.run), so no connection outlives its job."""
    return authz_sa.install(create_async_engine(os.environ["ROWSTILE_APP_URL"], poolclass=NullPool))

@rowstile.job(("service", 1))
async def digest_async() -> int:
    async with AsyncSession(async_engine()) as s:
        return await s.scalar(select(func.count()).select_from(Project)) or 0

@celery.task
def digest_async() -> int:
    """Celery runs no coroutine itself: the job runs in an event loop of its own."""
    return asyncio.run(jobs.digest_async())
```

Whoever can put a message on the queue can name any user for a job, as whoever holds the app's database
password can. Keep the broker as private as the database.

## Migrations

Policy changes ship as migrations for your tool: `tool = "alembic"` (see [FastAPI](fastapi.md)), `"sql"`,
`"goose"`, `"dbmate"`, `"flyway"` or `"django"` ([Django](django.md)) in `rowstile.toml`. `rowstile migrate` writes the next one;
`rowstile migrate --check` in CI fails if a policy change has none.
