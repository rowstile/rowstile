"""The SDK's own calls, each way they can go, beyond the conformance checks (test_conformance.py): what each
promises, asked of the database where there is one to ask. test.sh measures what these and the conformance
checks run of the SDK (sdk/python/rowstile), and fails unless they run every line and branch of it."""

import asyncio
import contextvars
import importlib
import io
import os
import pathlib
import re
import subprocess
import sys
import threading
from collections.abc import AsyncIterator
from concurrent.futures import ThreadPoolExecutor
from types import MappingProxyType
from typing import LiteralString
from unittest import mock

import asyncpg
import httpx
import psycopg
import pytest
import rowstile
import rowstile.asyncpg as pga
import rowstile.psycopg as pgp
from app.authz_client import ObjectType, Permission
from app.main import make_app
from app.models import Base, Note, Project
from fastapi import FastAPI, Request, WebSocket
from rowstile import NotFound, NotSignedIn, Principal, Refused
from rowstile import sqlalchemy as authz_sa
from rowstile.fastapi import Rowstile
from rowstile.testing import AssertNotFound, AssertRefused, database_per_worker
from sqlalchemy import BigInteger, Connection, Engine, MetaData, Text, create_engine, join, select, text, update
from sqlalchemy.exc import ProgrammingError
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, column_property, mapped_column
from sqlalchemy.orm.exc import StaleDataError
from starlette.types import Message, Scope

from .conftest import OWNER, libpq

pytestmark = pytest.mark.anyio
APP = os.environ.get("ROWSTILE_APP_URL", "")
SYNC = APP.replace("+asyncpg", "+psycopg")  # the app's role, through a sync driver
PROJECTS = "SELECT id FROM app.projects ORDER BY id"  # ann (1) and cy (3) see 1 and 3, bo (2) 2 and 3, nobody 3
REFUSED = "permission denied: user 3 may not update row 1 of app.notes"  # cy may edit note 4, not note 1


def client(app: FastAPI) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://sdk")


def projects(conn: Connection) -> list[int]:
    return list(conn.scalars(text(PROJECTS)).all())


@pytest.fixture
async def app() -> AsyncIterator[FastAPI]:
    a = make_app(APP, check_connection=False)
    yield a
    await a.state.engine.dispose()


class NoteInProject(Base):
    """A model mapped to a join: an update of it names no one table."""

    __table__ = join(Note.__table__, Project.__table__, Note.__table__.c.project_id == Project.__table__.c.id)
    note_id: Mapped[int] = column_property(Note.__table__.c.id)
    project_id: Mapped[int] = column_property(Note.__table__.c.project_id, Project.__table__.c.id)
    body: Mapped[str] = column_property(Note.__table__.c.body)


class Versioned(DeclarativeBase):
    metadata = MetaData(schema="app")


class VersionedNote(Versioned):
    """app.notes, its body the version: an update of a note someone changed meanwhile matches no row."""

    __tablename__ = "notes"
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    body: Mapped[str] = mapped_column(Text)
    __mapper_args__ = MappingProxyType({"version_id_col": body, "version_id_generator": False})


# --- who a transaction acts for --------------------------------------------------------------------------------
def test_a_principal_as_it_is_and_one_without_an_id() -> None:
    service = Principal("service", "1")
    assert Principal.of(service) is service
    assert Principal.of(("service", None)) == Principal("service", None)
    assert rowstile.act_as_args(("service", None)) == (None, None)  # without an id it is nobody, whatever its type
    assert rowstile.act_as_sql(service) == "SELECT authz.act_as('service', '1')"
    assert rowstile.act_as_sql("o'k") == "SELECT authz.act_as('user', 'o''k')"


def test_a_job_in_a_plain_function() -> None:
    @rowstile.job(("service", 1))
    def report(label: str) -> tuple[str, list[int]]:
        with psycopg.connect(libpq(APP)) as conn, pgp.transaction(conn):
            return label, [r[0] for r in conn.execute(PROJECTS)]

    with rowstile.acting_as(2):  # whatever started it: bo would see 2 and 3
        assert report("daily") == ("daily", [1, 3])  # the project the service is added to, and the public one
        assert rowstile.current() == Principal("user", "2")
    assert report.__name__ == "report"


# --- SQLAlchemy -------------------------------------------------------------------------------------------------
def test_install_once_and_user_when_nothing_else_says() -> None:
    asked: list[str] = []

    def user() -> rowstile.Who:
        asked.append("user()")
        return 2

    engine = create_engine(SYNC)
    try:
        assert authz_sa.install(engine) is engine  # as Rowstile(app, engine) does: no user() yet
        assert authz_sa.install(engine, user=user) is engine  # given after it, user() is the engine's
        assert authz_sa.install(engine, user=user) is engine and authz_sa.install(engine) is engine  # it stays
        other = "install(engine) was given another user() for this engine before: an engine has one"
        with pytest.raises(ValueError, match=re.escape(other)):
            authz_sa.install(engine, user=lambda: 3)
        with engine.connect() as conn:  # nothing says who: user() does
            assert projects(conn) == [2, 3]
        with rowstile.acting_as(None), engine.connect() as conn:  # acting_as decides first, None too
            assert projects(conn) == [3]
    finally:
        engine.dispose()
    assert asked == ["user()"]


def test_a_driver_with_another_parameter_style_signs_in_with_the_values_written_in() -> None:
    engine = authz_sa.install(create_engine(SYNC, paramstyle="named"))  # neither %s nor $1
    try:
        with rowstile.acting_as(2), engine.connect() as conn:
            assert projects(conn) == [2, 3]
        with rowstile.acting_as("o'k"), engine.connect() as conn:  # quoted; not a user of this app: nobody
            assert projects(conn) == [3]
    finally:
        engine.dispose()


def test_why_stale_says_nothing_of_another_error() -> None:
    engine = authz_sa.install(create_engine(SYNC))
    try:
        # a flush that failed for another reason (the app role may not update projects at all): nothing to say
        denied = pytest.raises(ProgrammingError, match="permission denied for table projects")
        with rowstile.acting_as(3), denied as e, Session(engine) as s, s.begin():
            project = s.get(Project, 1)
            assert project is not None
            project.name = "x"
        assert authz_sa.why_stale_sync(e.value) is None
    finally:
        engine.dispose()


async def test_why_stale_for_either_engine(app: FastAPI) -> None:
    engine = authz_sa.install(create_engine(SYNC))
    try:
        with rowstile.acting_as(3):
            # an async engine's flush: the answer is on the error, which either function reads
            with pytest.raises(StaleDataError) as e:
                async with app.state.Session.begin() as s:
                    hidden = await s.get(Note, 1)
                    assert hidden is not None
                    hidden.body = "x"
            said = repr(authz_sa.why_stale_sync(e.value)), repr(await authz_sa.why_stale(e.value))
            assert said == (f"Refused({REFUSED!r})",) * 2, said
            # a sync engine's flush of two rows: the first the database says no for
            with pytest.raises(StaleDataError) as e, Session(engine) as ss, ss.begin():
                first, last = ss.get(Note, 1), ss.get(Note, 4)
                assert first is not None and last is not None
                first.body, last.body = "x", "y"
            verdict = await authz_sa.why_stale(e.value)
            assert isinstance(verdict, Refused) and verdict.message == REFUSED, verdict
    finally:
        engine.dispose()


def test_why_stale_is_asked_in_the_flushs_own_transaction() -> None:
    engine = authz_sa.install(create_engine(SYNC))
    try:
        with rowstile.acting_as(3):
            # a note ann adds in the transaction, which cy (a member of the project) sees and may not edit: only
            # this transaction sees it yet
            with pytest.raises(StaleDataError) as e, Session(engine) as s, s.begin():
                s.execute(text("SELECT authz.act_as('user', '1')"))
                note = Note(project_id=1, author_id=1, body="ann's")
                s.add(note)
                s.flush()
                made = note.id
                s.execute(text("SELECT authz.act_as('user', '3')"))
                note.body = "x"
            verdict = authz_sa.why_stale_sync(e.value)
            assert isinstance(verdict, Refused), verdict
            assert verdict.message == f"permission denied: user 3 may not update row {made} of app.notes", verdict
            # in a savepoint: asked before it is rolled back, and the transaction goes on
            with Session(engine) as s, s.begin():
                with pytest.raises(StaleDataError) as e, s.begin_nested():
                    hidden = s.get(Note, 1)
                    assert hidden is not None
                    hidden.body = "x"
                assert repr(authz_sa.why_stale_sync(e.value)) == f"Refused({REFUSED!r})"
                assert s.scalar(text("SELECT current_setting('authz.user_id')")) == "3"
    finally:
        engine.dispose()


def test_a_flush_of_many_rows_is_asked_about_each() -> None:
    # SQLAlchemy tells every row of a table before it sends the statements: the refused row is found among them,
    # however many come after it
    engine = authz_sa.install(create_engine(SYNC))
    try:
        with rowstile.acting_as(3):
            with pytest.raises(StaleDataError) as e, Session(engine) as s, s.begin():
                s.add_all([Note(project_id=1, author_id=3, body=str(i)) for i in range(30)])  # cy's own
                s.flush()
                hidden = s.get(Note, 1)  # the first of the flush's rows, by its key
                assert hidden is not None
                for note in s.scalars(select(Note).where(Note.author_id == 3)).all():
                    note.body += "!"
                hidden.body = "x"
            verdict = authz_sa.why_stale_sync(e.value)
            assert isinstance(verdict, Refused) and verdict.message == REFUSED, verdict
    finally:
        engine.dispose()


def test_why_stale_cant_tell_when_the_database_couldnt_be_asked() -> None:
    engine = authz_sa.install(create_engine(SYNC))
    try:
        with rowstile.acting_as(3), mock.patch.object(authz_sa, "_EXPLAIN_EACH", text("SELECT authz.no_such()")):
            failed = refused_flush(engine)
        assert authz_sa.why_stale_sync(failed) is None
        with rowstile.acting_as(3), engine.connect() as conn:  # the transaction was rolled back as ever
            assert projects(conn) == [1, 3]
    finally:
        engine.dispose()
    # an engine install() wasn't given (the owner's) remembers no rows, and has nothing to say
    owner = create_engine(OWNER)
    try:
        with pytest.raises(StaleDataError) as e, Session(owner) as s, s.begin():
            note = s.get(VersionedNote, 4)
            assert note is not None
            with psycopg.connect(libpq(OWNER)) as other:  # someone changes it meanwhile
                other.execute("UPDATE app.notes SET body = body || '.' WHERE id = 4")
            note.body = "mine"
        assert authz_sa.why_stale_sync(e.value) is None
    finally:
        owner.dispose()


def refused_flush(engine: Engine, note: int = 1) -> StaleDataError:
    """An ORM update of a note the user may see but not edit (cy: note 1, bo: note 3): what SQLAlchemy raised."""
    with pytest.raises(StaleDataError) as e, Session(engine) as s, s.begin():
        row = s.get(Note, note)
        assert row is not None
        row.body = "x"
    return e.value


def test_outside_a_block_each_thread_is_asked_about_its_own_write() -> None:
    # two people at once, signed in by install()'s user() alone (as a Flask app or a worker thread may be): each
    # one's why_stale_sync answers about the row it wrote, not the other's (bo can't even see note 1)
    me = threading.local()
    engine = authz_sa.install(create_engine(SYNC), user=lambda: me.user)
    both_wrote = threading.Barrier(2, timeout=60)

    def person(user: int, note: int) -> str:
        me.user = user
        failed = refused_flush(engine, note)
        both_wrote.wait()  # the other one has written too
        return repr(authz_sa.why_stale_sync(failed))

    try:
        with ThreadPoolExecutor(2) as pool:
            bo, cy = pool.submit(person, 2, 3), pool.submit(person, 3, 1)
            said = bo.result(), cy.result()
    finally:
        engine.dispose()
    assert said == (
        "Refused('permission denied: user 2 may not update row 3 of app.notes')",
        "Refused('permission denied: user 3 may not update row 1 of app.notes')",
    ), said


def test_outside_a_block_a_later_transaction_isnt_asked_about_an_earlier_write() -> None:
    engine = authz_sa.install(create_engine(SYNC), user=lambda: 3)
    try:
        verdict = authz_sa.why_stale_sync(refused_flush(engine))  # outside a block, a flush is asked about too
        assert isinstance(verdict, Refused) and verdict.message == REFUSED, verdict
        refused_flush(engine)
        # a later transaction, whose flush wrote no row it can ask about (a model mapped to a join): it can't
        # tell, rather than answer about the earlier one's row
        with pytest.raises(StaleDataError) as e, Session(engine) as s, s.begin():
            row = s.scalars(select(NoteInProject).where(NoteInProject.note_id == 1)).one()
            row.body = "x"
        assert authz_sa.why_stale_sync(e.value) is None
    finally:
        engine.dispose()


async def test_outside_a_block_an_async_flush_is_asked_about_too() -> None:
    engine = authz_sa.install(create_async_engine(APP), user=lambda: 3)
    try:
        with pytest.raises(StaleDataError) as e:
            async with AsyncSession(engine) as s, s.begin():
                note = await s.get(Note, 1)
                assert note is not None
                note.body = "x"
        verdict = await authz_sa.why_stale(e.value)
        assert isinstance(verdict, Refused) and verdict.message == REFUSED, verdict
    finally:
        await engine.dispose()


async def test_core_updates_expect_a_row(app: FastAPI) -> None:
    engine = authz_sa.install(create_engine(SYNC))
    try:
        with rowstile.acting_as(3):
            async with app.state.Session() as s:
                result = await s.execute(update(Note).where(Note.id == 4).values(body=Note.body))
                assert await authz_sa.expect(s, result, "app.notes", "update", 4) is result
                await s.rollback()
            with engine.connect() as conn:
                done = conn.execute(update(Note).where(Note.id == 4).values(body=Note.body))
                assert authz_sa.expect_sync(conn, done, "app.notes", "update", 4) is done
                none = conn.execute(update(Note).where(Note.id == 1).values(body="x"))
                with pytest.raises(Refused) as refused:
                    authz_sa.expect_sync(conn, none, "app.notes", "update", 1)
                assert refused.value.message == REFUSED
                conn.rollback()
    finally:
        engine.dispose()


async def test_queries_by_permission_sync_and_async(app: FastAPI) -> None:
    queries = authz_sa.Queries[ObjectType, Permission]()
    engine = authz_sa.install(create_engine(SYNC))
    try:
        with rowstile.acting_as(3):
            async with app.state.Session() as s:
                assert await authz_sa.can(s, "note", 4, "edit") and not await queries.can(s, "note", 1, "edit")
                assert sorted((await s.scalars(authz_sa.ids("project", "view", None))).all()) == ["1", "3"]  # text
            with Session(engine) as ss:
                assert queries.can_sync(ss, "project", 1, "edit") and not queries.can_sync(ss, "project", 3, "edit")
                assert authz_sa.perms_of_sync(ss, "project", [1, 3]) == {"1": ["edit", "view"], "3": ["view"]}
                assert queries.perms_of_sync(ss, "note", [1, 4]) == {"1": ["view"], "4": ["edit", "view"]}
    finally:
        engine.dispose()


async def test_the_connection_check_over_each_driver() -> None:
    owners, policy = "an owner skips row-level security", "is the policy's owner"
    # the owner is the policy's, and owns the four tables with rules
    for url, expected in ((SYNC, []), (OWNER, [policy] + [owners] * 4)):
        engine = create_engine(url)
        try:
            found = sorted(rowstile.check_problems(await authz_sa.connection_check(engine)))
        finally:
            engine.dispose()
        assert [owners if owners in p else policy if policy in p else p for p in found] == expected, found
        with psycopg.connect(libpq(url)) as conn:
            assert sorted(pgp.problems(conn)) == found
        aconn = await asyncpg.connect(libpq(url))
        try:
            assert sorted(await pga.problems(aconn)) == found
        finally:
            await aconn.close()


def test_the_sync_engine_without_greenlet() -> None:
    # SQLAlchemy's asyncio needs greenlet, which an app on the sync engine may not have
    code = "\n".join(
        [
            "import sys",
            "sys.modules['greenlet'] = None",
            "import rowstile",
            "from rowstile import sqlalchemy as authz_sa",
            "from sqlalchemy import create_engine, text",
            "engine = authz_sa.install(create_engine(sys.argv[1]))",
            "with rowstile.acting_as(2), engine.connect() as conn:",
            "    print(conn.scalars(text('SELECT id FROM app.projects ORDER BY id')).all())",
        ]
    )
    got = subprocess.run([sys.executable, "-c", code, SYNC], capture_output=True, text=True)
    assert got.returncode == 0 and got.stdout.strip() == "[2, 3]", got.stderr


# --- FastAPI ----------------------------------------------------------------------------------------------------
async def test_requests_without_a_user_act_for_whoever_the_code_says() -> None:
    a = FastAPI()
    Rowstile(a)

    @a.get("/me")
    async def me() -> str:
        return str(rowstile.current())

    async with client(a) as c:
        assert (await c.get("/me", headers={"x-user": "2"})).json() == "None"
    assert await Rowstile(FastAPI()).check() is None  # no engine: nothing to check


async def test_user_may_be_async() -> None:
    async def who(request: Request) -> str | None:
        return request.headers.get("x-user")

    a = FastAPI()
    Rowstile(a, None, user=who)

    @a.get("/me")
    async def me() -> str:
        return str(rowstile.current())

    async with client(a) as c:
        assert (await c.get("/me", headers={"x-user": "2"})).json() == "2"


async def test_websockets_are_not_signed_in() -> None:
    a = FastAPI()
    Rowstile(a, None, user=lambda request: request.headers.get("x-user"))

    @a.websocket("/ws")
    async def ws(socket: WebSocket) -> None:
        await socket.accept()
        await socket.send_text(str(rowstile.current()))
        await socket.close()

    scope: Scope = {"type": "websocket", "path": "/ws", "headers": [(b"x-user", b"2")], "query_string": b""}
    events: list[Message] = [{"type": "websocket.connect"}]
    sent: list[Message] = []

    async def receive() -> Message:
        return events.pop(0) if events else {"type": "websocket.disconnect", "code": 1000}

    async def send(message: Message) -> None:
        sent.append(message)

    await a({**scope, "asgi": {"version": "3.0"}, "root_path": "", "subprotocols": []}, receive, send)
    assert {"type": "websocket.send", "text": "None"} in sent, sent  # the endpoint says who: rowstile.acting_as()


async def test_a_database_error_that_isnt_a_refusal(app: FastAPI) -> None:
    autocommit = create_async_engine(APP, isolation_level="AUTOCOMMIT")
    a = FastAPI()
    Rowstile(a, autocommit, user=lambda request: "2", check_connection=False)

    @a.get("/notes")
    async def notes() -> list[int]:
        async with AsyncSession(autocommit) as s:
            return list((await s.scalars(select(Note.id))).all())

    @app.get("/denied")
    async def denied() -> None:
        async with app.state.Session() as s:
            await s.execute(text("SELECT * FROM public.alembic_version"))  # not the app role's to read

    try:
        async with client(a) as c:
            # the sign-in lasts a transaction, and an engine in AUTOCOMMIT ends it at once: the app's mistake
            with pytest.raises(NotSignedIn, match="is this engine in AUTOCOMMIT") as e:
                await c.get("/notes")
            assert rowstile.sqlstate(e.value) == "28000" and e.value.code == "AZ701"
        async with client(app) as c:
            with pytest.raises(ProgrammingError, match="permission denied for table alembic_version"):
                await c.get("/denied", headers={"x-user": "1"})
    finally:
        await autocommit.dispose()


# Postgres's own words, where no rule's refusal speaks first, read for what refused: an update after which the row
# would be hidden is the select rule's, and no read back; an upsert of a row the user may not change is the update
# rule's; MERGE's names no command, since Postgres doesn't say whether the update rule or the delete rule
def test_postgres_own_refusals_name_the_rule() -> None:
    with psycopg.connect(libpq(SYNC)) as conn:  # cy (3): author of note 4 in project 1, a member there

        def refused(sql: LiteralString) -> Refused | None:
            with pytest.raises(psycopg.errors.InsufficientPrivilege) as e, pgp.transaction(conn, 3):
                conn.execute(sql)
            return rowstile.refusal(e.value)

        hidden = refused("UPDATE app.notes SET project_id = 2 WHERE id = 4")  # into bo's project
        upsert = refused(
            "INSERT INTO app.notes (id, project_id, author_id, body) VALUES (1, 1, 3, 'x') "
            "ON CONFLICT (id) DO UPDATE SET body = 'x'",  # note 1 is ann's
        )
        merge = refused(
            "MERGE INTO app.notes n USING (VALUES (1)) s(id) ON n.id = s.id WHEN MATCHED THEN UPDATE SET body = 'x'"
        )
    assert hidden and (hidden.table, hidden.command, hidden.why) == ("notes", "select", []), vars(hidden)
    assert hidden.message == (
        'new row violates row-level security policy for table "notes": this user may not see the row as written '
        "(the select rule). An insert that reads it back (RETURNING), an upsert, and an update with a WHERE need to "
        "see it."
    )
    assert upsert and (upsert.table, upsert.command, upsert.why) == ("notes", "update", []), vars(upsert)
    assert upsert.message == (
        'new row violates row-level security policy (USING expression) for table "notes": the row is there already, '
        "and the update rule (or the select rule) doesn't let this user change it (ON CONFLICT DO UPDATE)"
    )
    assert merge and (merge.table, merge.command, merge.why) == ("notes", None, []), vars(merge)
    assert merge.message == (
        'target row violates row-level security policy (USING expression) for table "notes": MERGE matched a row '
        "the update or delete rule doesn't let this user change"
    )


async def test_an_update_the_rules_allow_that_matched_nothing_is_409(app: FastAPI) -> None:
    @app.patch("/versioned/{note_id}")
    async def edit(note_id: int) -> None:
        async with app.state.Session() as s:
            note = await s.get(VersionedNote, note_id)
            assert note is not None
            with psycopg.connect(libpq(OWNER)) as owner:  # someone changes it meanwhile
                owner.execute("UPDATE app.notes SET body = body || '.' WHERE id = %s", (note_id,))
            note.body = "mine"
            await s.commit()

    @app.patch("/joined/{note_id}")
    async def edit_joined(note_id: int) -> None:
        async with app.state.Session.begin() as s:
            mine = await s.get(Note, 4)  # a flush the rules allow first, of another row
            assert mine is not None
            mine.body += "!"
            await s.flush()
            row = (await s.scalars(select(NoteInProject).where(NoteInProject.note_id == note_id))).one()
            row.body = "x"  # a model mapped to a join names no one table: its row can't be asked about

    async with client(app) as c:
        r = await c.patch("/versioned/4", headers={"x-user": "3"})  # cy may edit note 4: not the rules' doing
        # the earlier flush's row isn't asked about in its place: this one's can't tell, and leaves it to the app
        with pytest.raises(StaleDataError):
            await c.patch("/joined/1", headers={"x-user": "3"})
    assert r.status_code == 409, r.text
    assert r.json() == {
        "type": "https://rowstile.dev/problems/conflict",
        "title": "Conflict",
        "status": 409,
        "detail": "the row changed since it was read, and the rules allow the change: read it again",
    }, r.text


async def test_a_refused_update_is_explained_with_the_pools_one_connection_held() -> None:
    # the session still holds the pool's one connection when the error is answered (closed late, as a dependency's
    # cleanup was on FastAPI before 0.106): the answer needs no other connection
    engine = create_async_engine(APP, pool_size=1, max_overflow=0, pool_timeout=3)
    a = FastAPI()
    Rowstile(a, engine, user=lambda request: "3", check_connection=False)
    sessions: list[AsyncSession] = []

    @a.patch("/notes/{note_id}")
    async def edit(note_id: int) -> None:
        s = AsyncSession(engine)
        sessions.append(s)
        note = await s.get(Note, note_id)
        assert note is not None
        note.body = "x"
        await s.commit()

    try:
        async with client(a) as c:
            r = await c.patch("/notes/1")
    finally:
        for s in sessions:
            await s.close()
        await engine.dispose()
    assert r.status_code == 403 and r.json()["detail"] == REFUSED, r.text


async def test_a_request_without_a_user_is_answered_about_its_own_write() -> None:
    # Rowstile without user=: the app signs in another way, here install()'s user(). A sync endpoint runs in a
    # worker thread; its refused flush is answered from the request's own writes: 403, with the rule's reason
    engine = authz_sa.install(create_engine(SYNC), user=lambda: 2)  # bo may see note 3, not edit it
    a = FastAPI()
    Rowstile(a, engine, check_connection=False)

    @a.patch("/notes/{note_id}")
    def edit(note_id: int) -> None:
        with Session(engine) as s, s.begin():
            note = s.get(Note, note_id)
            assert note is not None
            note.body = "x"

    async def patch() -> httpx.Response:
        async with client(a) as c:
            return await c.patch("/notes/3")

    try:
        # in a task of its own, as a server runs each request: nothing the checks before it left is there
        r = await asyncio.create_task(patch(), context=contextvars.Context())
    finally:
        engine.dispose()
    assert r.status_code == 403, r.text
    assert r.json()["detail"] == "permission denied: user 2 may not update row 3 of app.notes", r.text
    assert r.json()["why"][0].startswith("no   update : edit"), r.text


# --- the drivers without SQLAlchemy -------------------------------------------------------------------------------
async def test_psycopg_async_blocks_and_expect() -> None:
    async with await psycopg.AsyncConnection.connect(libpq(APP)) as aconn:
        async with pgp.atransaction(aconn, 2):  # nothing open: a transaction of its own
            assert [r[0] for r in await (await aconn.execute(PROJECTS)).fetchall()] == [2, 3]
        assert aconn.info.transaction_status == psycopg.pq.TransactionStatus.IDLE
        async with pgp.atransaction(aconn, 3):
            cur = await aconn.execute("UPDATE app.notes SET body = body WHERE id = 4")
            assert await pgp.aexpect(aconn, cur, "app.notes", "update", 4) is cur
            none = await aconn.execute("UPDATE app.notes SET body = 'x' WHERE id = 1")
            with pytest.raises(Refused) as refused:
                await pgp.aexpect(aconn, none, "app.notes", "update", 1)
            assert refused.value.message == REFUSED
        async with pgp.atransaction(aconn, 2):
            none = await aconn.execute("UPDATE app.notes SET body = 'x' WHERE id = 1")
            with pytest.raises(NotFound, match=r"app\.notes 1 not found"):
                await pgp.aexpect(aconn, none, "app.notes", "update", 1)


async def test_an_app_on_psycopg_or_asyncpg_alone_answers_as_the_pages_say() -> None:
    # Rowstile(app, None, user=...): no engine; the drivers' own errors are answered as SQLAlchemy's are
    a = FastAPI()
    Rowstile(a, None, user=lambda request: request.headers.get("x-user"))

    @a.post("/psycopg/notes")
    async def add() -> None:
        async with await psycopg.AsyncConnection.connect(libpq(APP)) as aconn, pgp.atransaction(aconn):
            await aconn.execute("INSERT INTO app.notes (project_id, author_id, body) VALUES (3, 2, 'hi')")

    @a.get("/asyncpg/page")
    async def page() -> None:
        conn = await asyncpg.connect(libpq(APP))
        try:
            async with pga.transaction(conn):
                await conn.fetch("SELECT x FROM authz.list('project', 'view', NULL, -1) x")
        finally:
            await conn.close()

    @a.get("/psycopg/unsigned")
    async def unsigned() -> None:
        async with await psycopg.AsyncConnection.connect(libpq(APP)) as aconn, aconn.transaction():
            await aconn.execute("SELECT count(*) FROM app.notes")  # a transaction of its own: nobody signed in

    async with client(a) as c:
        refused = await c.post("/psycopg/notes", headers={"x-user": "2"})
        negative = await c.get("/asyncpg/page", headers={"x-user": "1"})
        how = r"authz\.act_as\(\) \(rowstile\.psycopg\.transaction\(\) and rowstile\.asyncpg\.transaction\(\) do it\)"
        with pytest.raises(NotSignedIn, match=how):
            await c.get("/psycopg/unsigned", headers={"x-user": "1"})
    assert refused.status_code == 403, refused.text
    body = refused.json()
    assert (body["table"], body["command"], body["code"]) == ("app.notes", "insert", "AZ709"), body
    assert "user 2 may not insert this row into app.notes" in body["detail"], body
    assert negative.status_code == 400, negative.text
    assert negative.json() == {
        "type": "https://rowstile.dev/problems/bad-argument",
        "title": "Bad Request",
        "status": 400,
        "detail": "the page size must not be negative (got -1)",
        "code": "AZ710",
    }, negative.text


def test_an_app_without_a_driver_has_no_handler_for_its_errors() -> None:
    # neither psycopg nor asyncpg installed: SQLAlchemy's errors only
    code = "\n".join(
        [
            "import sys",
            "sys.modules['psycopg'] = sys.modules['asyncpg'] = None",
            "from fastapi import FastAPI",
            "from rowstile.fastapi import Rowstile",
            "app = FastAPI()",
            "Rowstile(app)",
            "ours = [e for e in app.exception_handlers if isinstance(e, type) and e.__module__.startswith(('rowstile', 'sqlalchemy'))]",
            "print(sorted(e.__module__ + '.' + e.__name__ for e in ours))",
        ]
    )
    got = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    handled = (
        "['rowstile.NotFound', 'rowstile.Refused', 'sqlalchemy.exc.DBAPIError', 'sqlalchemy.orm.exc.StaleDataError']"
    )
    assert got.returncode == 0 and got.stdout.strip() == handled, (got.stdout, got.stderr)


async def test_asyncpg_blocks_inside_a_block_and_expect() -> None:
    conn = await asyncpg.connect(libpq(APP))
    try:
        async with pga.transaction(conn, 1):
            async with pga.transaction(conn, 2):
                assert [r["id"] for r in await conn.fetch(PROJECTS)] == [2, 3]
            async with pga.transaction(conn, 3):
                pass
            assert [r["id"] for r in await conn.fetch(PROJECTS)] == [1, 3]  # back to the block around them
        async with pga.transaction(conn, 3):
            done = await conn.execute("UPDATE app.notes SET body = body WHERE id = 4")
            assert await pga.expect(conn, done, "app.notes", "update", 4) == "UPDATE 1"
    finally:
        await conn.close()


# ids holding a backslash, a quote, both, and more: where the sign-in is written into the statement (asyncpg's one
# simple statement, a driver of another parameter style), each must stay one string whatever standard_conforming_strings
# says; the first one, if its backslash ended the string, would go on to sign in as user 1
AWKWARD_IDS = ["x\\'); SELECT authz.act_as($$user$$, $$1$$); --", "\\'", "\\", "'", "o''k\\\\", "ünï 字 \\n ☃"]
SIGNED_IN_AS = "SELECT current_setting('authz.user_id')"


@pytest.mark.parametrize("conforming", ["off", "on"])
async def test_an_id_written_into_the_sign_in_is_that_id_whatever_standard_conforming_strings_says(
    conforming: str,
) -> None:
    conn = await asyncpg.connect(libpq(APP), server_settings={"standard_conforming_strings": conforming})
    try:
        assert await conn.fetchval("SHOW standard_conforming_strings") == conforming
        for awkward in AWKWARD_IDS:
            async with pga.transaction(conn, awkward):
                async with pga.transaction(conn, 2):
                    assert await conn.fetchval(SIGNED_IN_AS) == "2"
                assert await conn.fetchval(SIGNED_IN_AS) == awkward  # back to the block around, its id written in
    finally:
        await conn.close()
    options = {"options": f"-c standard_conforming_strings={conforming}"}
    engine = authz_sa.install(create_engine(SYNC, paramstyle="named", connect_args=options))  # act_as_sql()
    try:
        for awkward in AWKWARD_IDS:
            with rowstile.acting_as(awkward), engine.connect() as sync:
                assert sync.scalar(text("SHOW standard_conforming_strings")) == conforming
                assert sync.scalar(text(SIGNED_IN_AS)) == awkward
    finally:
        engine.dispose()


# --- the keys and answers as the database writes them ------------------------------------------------------------
def test_a_key_with_an_empty_field_and_no_answer() -> None:
    assert rowstile.key_text((1, None)) == '("1",)'
    assert rowstile.answer(None) == (None, None, None)  # no row: the row isn't there for this user
    hidden = rowstile.verdict("app.notes", "update", 7, *rowstile.answer(None))
    assert isinstance(hidden, NotFound) and str(hidden) == "app.notes 7 not found"
    said = [str(NotFound()), str(NotFound("app.notes")), str(NotFound(id_=7)), NotFound().problem()["detail"]]
    assert said == ["not found", "app.notes not found", "row 7 not found", "not found"], said


# --- the pytest helpers (rowstile.testing) ------------------------------------------------------------------------
def touch(note: int) -> None:
    """An update that changes nothing but needs the update rule."""
    with psycopg.connect(libpq(APP)) as conn, pgp.transaction(conn):
        cur = conn.execute("UPDATE app.notes SET body = body WHERE id = %s", (note,))
        pgp.expect(conn, cur, "app.notes", "update", note)


async def test_the_helpers_say_what_was_expected(
    assert_refused: AssertRefused, assert_not_found: AssertNotFound
) -> None:
    async def allowed() -> None:
        touch(4)

    with rowstile.acting_as(3):
        assert assert_refused(lambda: touch(1)).command == "update"  # any rule's refusal
        with pytest.raises(Refused):  # a refusal where a hidden row was expected: the test fails with it
            assert_not_found(lambda: touch(1))
        with pytest.raises(AssertionError, match="expected a refusal, got None"):
            await assert_refused(allowed)


HELPERS = """
import asyncio

import pytest
import rowstile


async def refused() -> None:
    raise rowstile.Refused("no")


async def hidden() -> None:
    raise rowstile.NotFound("app.notes", 1)


def test_awaited(as_user, assert_refused, assert_not_found):
    assert asyncio.run(assert_refused(refused)).message == "no"
    assert str(asyncio.run(assert_not_found(hidden))) == "app.notes 1 not found"


def test_refused_never_awaited(assert_refused):
    assert_refused(refused)


@pytest.mark.anyio
async def test_not_found_never_awaited(assert_not_found):
    assert_not_found(hidden)
"""


def test_the_helpers_load_by_themselves_and_fail_a_test_that_never_awaits_them(tmp_path: pathlib.Path) -> None:
    # installed, the package's entry point loads the fixtures: a test file and nothing else (no pytest_plugins). An
    # async function's check runs when it is awaited: a test that never awaits it fails, it doesn't pass unchecked
    (tmp_path / "test_helpers.py").write_text(HELPERS)
    got = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", str(tmp_path)],
        capture_output=True,
        text=True,
        cwd=tmp_path,
    )
    out = got.stdout
    assert got.returncode == 1 and "3 passed, 2 errors" in out, (
        out + got.stderr
    )  # each never-awaited: an error at teardown
    for helper in ("assert_refused", "assert_not_found"):
        never = f"{helper}() was given an async function, and what it returned was never awaited, so the check never ran: await it"
        assert f"ERROR at teardown of test_{helper.split('_', 1)[1]}_never_awaited" in out, out
        assert never in out, out
    assert "coroutine" not in out + got.stderr, (
        got.stderr
    )  # no warning of its own about a coroutine never awaited: closed, and said


def test_the_database_fixtures(authz_owner_url: str, authz_app_url: str) -> None:
    assert (authz_owner_url, authz_app_url) == (OWNER, APP)


def test_the_database_fixtures_skip_without_a_url(request: pytest.FixtureRequest) -> None:
    with mock.patch.dict(os.environ, {"ROWSTILE_OWNER_URL": "", "ROWSTILE_APP_URL": ""}):
        for fixture, variable in (("authz_owner_url", "ROWSTILE_OWNER_URL"), ("authz_app_url", "ROWSTILE_APP_URL")):
            with pytest.raises(pytest.skip.Exception, match=f"{variable} is not set"):
                request.getfixturevalue(fixture)


def test_a_database_per_worker_says_why_it_cant_copy(monkeypatch: pytest.MonkeyPatch) -> None:
    tests = os.environ["ROWSTILE_TESTS_URL"]
    monkeypatch.setenv("PYTEST_XDIST_WORKER", "gw1")
    busy = pytest.raises(RuntimeError, match=r"can't be copied while anything is connected to it")
    with psycopg.connect(libpq(tests)), busy:  # something connected to the original
        database_per_worker(tests)
    with pytest.raises(Exception, match="does not exist") as e:
        database_per_worker(tests + "_gone")
    assert not isinstance(e.value, RuntimeError)  # the database's own error, as it is


# --- where the command and the version come from ------------------------------------------------------------------
def test_where_the_command_is() -> None:
    from rowstile import command

    bundled = os.path.join(os.path.dirname(os.path.abspath(command.__file__)), "_command", "cli")
    with mock.patch.object(os.path, "isfile", lambda p: p == os.path.join(bundled, "rowstile_cli.py")):
        assert command.command_dir() == bundled  # in an installed package, inside it
    missing = pytest.raises(SystemExit, match=r"the command is missing from this installation \(rowstile/_command\)")
    with mock.patch.object(os.path, "isfile", lambda p: False), missing:
        command.command_dir()


def test_the_version_where_the_compiler_isnt_found() -> None:
    import rowstile._version as version

    try:
        with mock.patch.object(os.path, "isfile", lambda p: False):
            assert importlib.reload(version).__version__ == "0.0.0"
        with (
            mock.patch.object(os.path, "isfile", lambda p: True),
            mock.patch("builtins.open", lambda *a, **k: io.StringIO("no version here\n")),
        ):
            assert importlib.reload(version).__version__ == "0.0.0"
    finally:
        importlib.reload(version)
    assert version.__version__ == rowstile.__version__ != "0.0.0"


# --- Alembic ------------------------------------------------------------------------------------------------------
def test_autogenerate_leaves_rowstiles_tables_alone_with_include_object_alone() -> None:
    from alembic.autogenerate import compare_metadata
    from alembic.migration import MigrationContext
    from rowstile.alembic import include_object

    engine = create_engine(OWNER)
    try:
        with engine.connect() as conn:
            context = MigrationContext.configure(conn, opts={"include_schemas": True, "include_object": include_object})
            assert compare_metadata(context, Base.metadata) == []
    finally:
        engine.dispose()
