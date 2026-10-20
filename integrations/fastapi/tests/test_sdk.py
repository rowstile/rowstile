"""The SDK's own calls, each way they can go, beyond the conformance checks (test_conformance.py): what each
promises, asked of the database where there is one to ask. test.sh measures what these and the conformance
checks run of the SDK (sdk/python/rowstile), and fails unless they run every line and branch of it."""

import asyncio
import contextvars
import importlib
import io
import os
import subprocess
import sys
import threading
from collections.abc import AsyncIterator
from concurrent.futures import ThreadPoolExecutor
from types import MappingProxyType
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
        assert authz_sa.install(engine, user=user) is engine
        assert authz_sa.install(engine, user=lambda: 3) is engine  # installed once: the first one's user() stays
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


def test_why_stale_asks_about_the_last_flush_and_its_tables() -> None:
    engine = authz_sa.install(create_engine(SYNC))
    try:
        with rowstile.acting_as(3):
            # a flush that failed for another reason (the app role may not update projects at all), then one the
            # rules allowed: the database is asked about the last flush's rows only, and allowed them
            denied = pytest.raises(ProgrammingError, match="permission denied for table projects")
            with denied, Session(engine) as s, s.begin():
                project = s.get(Project, 1)
                assert project is not None
                project.name = "x"
            with Session(engine) as s:
                note = s.get(Note, 4)
                assert note is not None
                note.body = "y"
                s.flush()
                s.rollback()
            assert authz_sa.why_stale_sync() is None
            # a model mapped to a join names no one table: its rows aren't asked about (and the last flush that
            # names one was allowed)
            with pytest.raises(StaleDataError) as e, Session(engine) as s, s.begin():
                row = s.scalars(select(NoteInProject).where(NoteInProject.note_id == 1)).one()
                row.body = "x"
            assert authz_sa.why_stale_sync(e.value) is None
    finally:
        engine.dispose()


async def test_why_stale_for_the_engine_that_wrote(app: FastAPI) -> None:
    engine = authz_sa.install(create_engine(SYNC))
    try:
        with rowstile.acting_as(3):
            with Session(engine) as ss:  # a flush the rules allowed: nothing to say
                note = ss.get(Note, 4)
                assert note is not None
                note.body = "y"
                ss.flush()
                ss.rollback()
            assert await authz_sa.why_stale() is None
            # an async engine's flush is asked about with the async function
            with pytest.raises(StaleDataError) as e:
                async with app.state.Session.begin() as s:
                    hidden = await s.get(Note, 1)
                    assert hidden is not None
                    hidden.body = "x"
            with pytest.raises(TypeError, match=r"an async engine's write: await rowstile.sqlalchemy.why_stale\(\)"):
                authz_sa.why_stale_sync(e.value)
            # ... which asks about a sync engine's flush too: of two rows, the first the database says no for
            with pytest.raises(StaleDataError) as e, Session(engine) as ss, ss.begin():
                first, last = ss.get(Note, 1), ss.get(Note, 4)
                assert first is not None and last is not None
                first.body, last.body = "x", "y"
            verdict = await authz_sa.why_stale(e.value)
            assert isinstance(verdict, Refused) and verdict.message == REFUSED, verdict
    finally:
        engine.dispose()


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


def test_a_block_isnt_asked_about_a_write_made_outside_it() -> None:
    engine = authz_sa.install(create_engine(SYNC), user=lambda: 3)
    try:
        refused_flush(engine)  # outside a block
        with rowstile.acting_as(3):  # a block that wrote nothing has nothing to say
            assert authz_sa.why_stale_sync() is None
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
    owners = "owners skip row-level security"
    for url, expected in ((SYNC, []), (OWNER, [owners] * 4)):  # the owner owns the four tables with rules
        engine = create_engine(url)
        try:
            found = sorted(rowstile.check_problems(await authz_sa.connection_check(engine)))
        finally:
            engine.dispose()
        assert [owners if owners in p else p for p in found] == expected, found
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


async def test_an_update_the_rules_allow_that_matched_nothing_is_404(app: FastAPI) -> None:
    @app.patch("/versioned/{note_id}")
    async def edit(note_id: int) -> None:
        async with app.state.Session() as s:
            note = await s.get(VersionedNote, note_id)
            assert note is not None
            with psycopg.connect(libpq(OWNER)) as owner:  # someone changes it meanwhile
                owner.execute("UPDATE app.notes SET body = body || '.' WHERE id = %s", (note_id,))
            note.body = "mine"
            await s.commit()

    async with client(app) as c:
        r = await c.patch("/versioned/4", headers={"x-user": "3"})  # cy may edit note 4: not the rules' doing
    assert r.status_code == 404 and r.json()["detail"] == "the row not found", r.text


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
