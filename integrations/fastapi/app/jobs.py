"""The app's background jobs, which a worker runs in a process of its own: Celery's (app/worker.py) and RQ's run
the same functions. No job takes who it acts for from what a request left behind. One acts for a service of its
own; the others for the user who asked, given to them as an argument: the text str(rowstile.current()) wrote in the
request (a queue's message holds JSON), which Principal.parse reads back."""

import functools
import os

import rowstile
from rowstile import NotFound, Principal
from rowstile import sqlalchemy as authz_sa
from sqlalchemy import Engine, create_engine, delete, func, select
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, create_async_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import NullPool

from .models import Note, Project


@functools.cache
def engine() -> Engine:
    """The worker's engine, made in the process that runs the jobs (Celery forks its workers: a connection made
    before the fork would be theirs together), with one connection, which every job of the worker reuses."""
    url = os.environ["ROWSTILE_APP_URL"].replace("+asyncpg", "+psycopg")
    return authz_sa.install(create_engine(url, pool_size=1, max_overflow=0))


@functools.cache
def async_engine() -> AsyncEngine:
    """For async jobs: each runs in an event loop of its own (asyncio.run), so no connection outlives its job."""
    return authz_sa.install(create_async_engine(os.environ["ROWSTILE_APP_URL"], poolclass=NullPool))


@rowstile.job(("service", 1))
def digest() -> int:
    """Signs in as service 1, whoever asked for it."""
    with Session(engine()) as s:
        return s.scalar(select(func.count()).select_from(Project)) or 0


@rowstile.job(("service", 1))
async def digest_async() -> int:
    async with AsyncSession(async_engine()) as s:
        return await s.scalar(select(func.count()).select_from(Project)) or 0


def add_note(asked_by: str, project_id: int, body: str) -> int:
    """For the user who asked. A refused insert raises Refused, with the rule and why."""
    with rowstile.job(Principal.parse(asked_by)) as me, Session(engine()) as s, s.begin():
        note = Note(project_id=project_id, author_id=int(me.id or 0), body=body)
        s.add(note)
        s.flush()
        return note.id


def edit_note(asked_by: str, note_id: int, body: str) -> int:
    """A row the user can't see raises NotFound; one they may see, not edit, Refused, with why."""
    with rowstile.job(Principal.parse(asked_by)), Session(engine()) as s, s.begin():
        note = s.get(Note, note_id)
        if note is None:
            raise NotFound("app.notes", note_id)
        note.body = body  # an update the rules refuse: StaleDataError, raised as Refused
        s.flush()
        return note_id


def remove_note(asked_by: str, note_id: int) -> None:
    """A delete that matched no row: NotFound if the user can't see it, Refused if they may not delete it."""
    with rowstile.job(Principal.parse(asked_by)), Session(engine()) as s, s.begin():
        result = s.execute(delete(Note).where(Note.id == note_id))
        authz_sa.expect_sync(s, result, "app.notes", "delete", note_id)


def notes_seen(asked_by: str | None) -> tuple[list[int], int]:
    """The notes a job sees, and which connection of the pool it ran on (the driver's, by its id in the worker).
    With asked_by None the job names no one: install()'s default, nobody, whoever the job before it acted for."""
    if asked_by is None:
        return _notes()
    with rowstile.job(Principal.parse(asked_by)):
        return _notes()


def _notes() -> tuple[list[int], int]:
    with Session(engine()) as s:
        seen = sorted(s.scalars(select(Note.id)).all())
        return seen, id(s.connection().connection.driver_connection)


def left_behind() -> tuple[str | None, str | None, int]:
    """The pool's one connection as the last job left it, in a transaction nobody signs in to: who it holds (a
    sign-in that outlived its transaction would show here), the code of the error a query gets, and which
    connection it is."""
    raw = engine().raw_connection()
    try:
        cur = raw.cursor()
        cur.execute("SELECT current_setting('authz.user_id', true)")
        row = cur.fetchone()
        held = None if row is None or row[0] in (None, "") else str(row[0])
        try:
            cur.execute("SELECT count(*) FROM app.notes")
            code = None
        except Exception as e:
            code = rowstile.error_code(e)
        return held, code, id(raw.driver_connection)
    finally:
        raw.rollback()
        raw.close()
