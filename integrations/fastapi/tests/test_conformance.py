"""The conformance suite (integrations/README.md): the same checks for every stack. This is FastAPI,
SQLAlchemy async on asyncpg, Alembic. test.sh does check 11 (a fresh database: migrate, the policy's tests,
then Alembic's own diff shows no change) before these run."""

import asyncio
import os
import re
import shutil
import subprocess
import sys
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import asyncpg
import httpx
import psycopg
import pytest
import rowstile
from app.main import digest, make_app
from fastapi import FastAPI
from rowstile import ConnectionProblem, Refused
from rowstile.testing import (
    AssertNotFound,
    AssertRefused,
    AsUser,
    WorkerDatabase,
    database_per_worker,
    worker_id,
)
from sqlalchemy.exc import DBAPIError

from .conftest import OWNER, libpq

pytestmark = pytest.mark.anyio
APP = os.environ.get("ROWSTILE_APP_URL", "")
HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXPECTED: dict[str | None, list[int]] = {"1": [1, 3, 4], "2": [2, 3], "3": [1, 3, 4], None: [3]}
PROJECTS: dict[str | None, list[int]] = {"1": [1, 3], "2": [2, 3], None: [3]}  # the projects each may see


def client(app: FastAPI) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://conformance")


def as_(user: str | None) -> dict[str, str]:
    return {"x-user": user} if user else {}


@pytest.fixture
async def app() -> AsyncIterator[FastAPI]:
    a = make_app(APP, check_connection=False)
    yield a
    await a.state.engine.dispose()


# 1, 2: a list shows only the user's rows; signed out on purpose, only what anyone may see
async def test_1_2_lists_show_what_each_may_see(app: FastAPI) -> None:
    async with client(app) as c:
        for user, notes in EXPECTED.items():
            assert (await c.get("/notes", headers=as_(user))).json() == notes, user
        assert (await c.get("/projects", headers=as_(None))).json() == [3]


# 3: not signed in at all: the strict sign-in error, naming act_as
async def test_3_not_signed_in_is_an_error_that_says_how() -> None:
    conn = await asyncpg.connect(libpq(APP))
    try:
        async with conn.transaction():
            with pytest.raises(asyncpg.PostgresError) as e:
                await conn.fetchval("SELECT count(*) FROM app.notes")
        hint = str(getattr(e.value, "hint", "") or "")  # asyncpg sets its fields at run time
        assert rowstile.sqlstate(e.value) == "28000" and "act_as" in hint, (rowstile.sqlstate(e.value), hint)
        assert rowstile.error_code(e.value) == "AZ701", hint  # rowstile help AZ701
    finally:
        await conn.close()


# 4: one pooled connection, Ann then Bob: Bob never sees Ann's rows
async def test_4_a_pooled_connection_carries_no_one_over() -> None:
    a = make_app(APP, check_connection=False, pool_size=1)
    async with client(a) as c:
        assert (await c.get("/notes", headers=as_("1"))).json() == EXPECTED["1"]
        assert (await c.get("/notes", headers=as_("2"))).json() == EXPECTED["2"]
        assert (await c.get("/notes")).json() == EXPECTED[None]
    await a.state.engine.dispose()


# 5: concurrent requests never mix users
async def test_5_concurrent_requests_never_mix_users(app: FastAPI) -> None:
    users = ["1", "2", "3", None] * 10
    async with client(app) as c:
        got = await asyncio.gather(*[c.get("/notes", headers=as_(u)) for u in users])
    assert [r.json() for r in got] == [EXPECTED[u] for u in users]


# 6: a refused insert: 403, with the problem body naming the rule
async def test_6_a_refused_insert_says_which_rule(app: FastAPI) -> None:
    async with client(app) as c:
        r = await c.post("/notes", json={"project_id": 3, "body": "hi"}, headers=as_("2"))
    assert r.status_code == 403, r.text
    body = r.json()
    assert r.headers["content-type"] == "application/problem+json"
    assert body["table"] == "app.notes" and body["command"] == "insert", body
    assert body["code"] == "AZ709", body  # rowstile help AZ709
    assert "user 2 may not insert this row into app.notes" in body["detail"]
    assert any("project.edit" in line for line in body["why"]), body["why"]


# 7: an update of a hidden row: 404; of a visible row the user may not edit: 403, with the reason
async def test_7_hidden_is_404_and_not_allowed_is_403(app: FastAPI) -> None:
    async with client(app) as c:
        hidden = await c.patch("/notes/1", json={"body": "x"}, headers=as_("2"))
        refused = await c.patch("/notes/1", json={"body": "x"}, headers=as_("3"))
        mine = await c.patch("/notes/4", json={"body": "better idea"}, headers=as_("3"))
        gone = await c.delete("/notes/2", headers=as_("1"))
        no = await c.delete("/notes/1", headers=as_("3"))
    assert hidden.status_code == 404, hidden.text
    assert refused.status_code == 403 and refused.json()["command"] == "update", refused.text
    assert any("edit" in line for line in refused.json()["why"]), refused.json()
    # worded as the database words a refused insert: who, the command, the row, the table
    assert refused.json()["detail"] == "permission denied: user 3 may not update row 1 of app.notes", refused.text
    assert mine.status_code == 200, mine.text
    assert gone.status_code == 404, gone.text
    assert no.status_code == 403 and no.json()["command"] == "delete" and no.json()["why"], no.text
    assert no.json()["detail"] == "permission denied: user 3 may not delete row 1 of app.notes", no.text


# 8: an insert read back works when the select rule allows it, and is explained when not
async def test_8_insert_then_read_back(app: FastAPI) -> None:
    async with client(app) as c:
        ok = await c.post("/notes", json={"project_id": 1, "body": "new"}, headers=as_("1"))
        unreadable = await c.post("/inbox", json={"recipient_id": 2, "body": "hi bo"}, headers=as_("1"))
        quiet = await c.post("/inbox/quietly", json={"recipient_id": 2, "body": "hi bo"}, headers=as_("1"))
    assert ok.status_code == 201 and ok.json()["id"] > 100, ok.text
    assert unreadable.status_code == 403, unreadable.text
    assert unreadable.json()["command"] == "select" and "read the row back" in unreadable.json()["detail"]
    assert quiet.status_code == 202, quiet.text


# 16: a call the database turns down that is no refusal answers as its code's page says: what it names isn't there
# (AZ708) 404, a missing or wrong argument (AZ710) 400, with the database's words
async def test_16_not_there_is_404_and_a_wrong_argument_400(app: FastAPI) -> None:
    with psycopg.connect(libpq(OWNER)) as conn:  # an API key of ann's, in one transaction (it commits at the end)
        conn.execute("SELECT authz.act_as('user', '1')")
        conn.execute("SELECT authz.create_api_key('ci')")
        key = conn.execute("SELECT max(id) FROM authz.api_keys WHERE user_id = '1'").fetchone()
    assert key is not None
    async with client(app) as c:
        page = await c.get("/projects/page", params={"limit": 1}, headers=as_("1"))
        negative = await c.get("/projects/page", params={"limit": -1}, headers=as_("1"))
        cursor = await c.get("/projects/page", params={"limit": 1, "after": "x"}, headers=as_("1"))
        others = await c.delete(f"/keys/{key[0]}", headers=as_("2"))  # bo's key it isn't
        revoked = await c.delete(f"/keys/{key[0]}", headers=as_("1"))
        again = await c.delete(f"/keys/{key[0]}", headers=as_("1"))  # revoked: there is none now
    assert page.status_code == 200 and page.json() == ["1"], page.text
    for r, detail in [
        (negative, "the page size must not be negative (got -1)"),
        (cursor, "the page cursor 'x' is not a project id"),
    ]:
        assert r.headers["content-type"] == "application/problem+json", r.text
        assert r.json() == {
            "type": "https://rowstile.dev/problems/bad-argument",
            "title": "Bad Request",
            "status": 400,
            "detail": detail,
            "code": "AZ710",
        }, r.text
        assert r.status_code == 400
    assert revoked.status_code == 204, revoked.text
    # the database says it with a refusal's SQLSTATE (42501), but it is none: the key isn't there for this user
    for r in (others, again):
        assert r.headers["content-type"] == "application/problem+json", r.text
        assert r.json() == {
            "type": "https://rowstile.dev/problems/not-found",
            "title": "Not Found",
            "status": 404,
            "detail": f"no API key {key[0]} of yours",
            "code": "AZ708",
        }, r.text
        assert r.status_code == 404


Answer = Any


def problem(kind: str, title: str, status: int, detail: str, code: str) -> Answer:
    return {
        "type": f"https://rowstile.dev/problems/{kind}",
        "title": title,
        "status": status,
        "detail": detail,
        "code": code,
    }


# 16: and the other codes the runtime raises, each as its page says (rowstile help AZ703 and the like): a login refused
# or a call that needs someone signed in 401, a move inside itself 409, a refusal by the database's own code 403;
# a share the policy doesn't declare, a name not in the policy and who is signed in changed by hand are the app's
# mistakes, which stay errors (a 500)
async def test_16_each_code_answers_as_its_page_says(app: FastAPI) -> None:
    with psycopg.connect(libpq(OWNER)) as conn:  # a key of ann's that may only read
        conn.execute("SELECT authz.act_as('user', '1')")
        read_only = conn.execute("SELECT authz.create_api_key('ro', 'read')").fetchone()
    assert read_only is not None
    async with client(app) as c:
        nobody = await c.post("/keys", json={"name": "k"})
        asks = await c.post("/projects/1/requests", json={"relation": "member", "reason": "the review"})
        bad_key = await c.post("/keys", json={"name": "k"}, headers={**as_("1"), "x-api-key": "ak_nope"})
        scoped = await c.post("/keys", json={"name": "k"}, headers={**as_("1"), "x-api-key": read_only[0]})
        made = await c.post("/keys", json={"name": "k"}, headers=as_("1"))
        not_shared = await c.get("/projects/1/shares", headers=as_("2"))
        inside = await c.patch("/folders/1", json={"parent_id": 2}, headers=as_("1"))
        stays = await c.patch("/folders/2", json={"parent_id": 1}, headers=as_("1"))
        errors = []
        for call in (
            c.post("/projects/1/requests", json={"relation": "member", "reason": "the review"}, headers=as_("2")),
            c.post("/keys", json={"name": "k", "principal_type": "service", "principal_id": "1"}, headers=as_("1")),
            c.get("/notes/as/2", headers=as_("1")),
        ):
            with pytest.raises(DBAPIError) as e:  # the database's own error, not NotSignedIn nor a problem
                await call
            errors.append(e.value)
    assert made.status_code == 201 and made.json()["key"].startswith("ak_"), made.text
    assert stays.status_code == 200, stays.text
    for r, body in [
        (nobody, problem("not-signed-in", "Unauthorized", 401, "sign in to create an API key", "AZ714")),
        (asks, problem("not-signed-in", "Unauthorized", 401, "sign in first", "AZ714")),
        (bad_key, problem("not-signed-in", "Unauthorized", 401, "invalid API key", "AZ703")),
        (inside, problem("conflict", "Conflict", 409, "folder 1 cannot be moved inside itself", "AZ713")),
    ]:
        assert r.headers["content-type"] == "application/problem+json", r.text
        assert r.json() == body, r.text
        assert r.status_code == body["status"]
    # refusals, by the database's own code: 403, naming no rule
    for r, detail, code in [
        (scoped, "this session is read-only", "AZ704"),
        (not_shared, "you cannot see the shares of project 1", "AZ705"),
    ]:
        assert r.status_code == 403, r.text
        got = r.json()
        assert got["type"] == "https://rowstile.dev/problems/refused" and got["code"] == code, got
        assert got["detail"].startswith(detail) and got["table"] is None and got["command"] is None, got
    # a call that is for users, made by a service (rowstile help AZ715): a refusal too, 403
    with psycopg.connect(libpq(APP)) as conn, pytest.raises(psycopg.errors.InsufficientPrivilege) as e:
        conn.execute("SELECT authz.act_as('service', '1')")
        conn.execute("SELECT authz.create_api_key('mine')")
    users_only = rowstile.refusal(e.value)
    assert users_only is not None
    assert users_only.problem() == {
        "type": "https://rowstile.dev/problems/refused",
        "title": "Forbidden",
        "status": 403,
        "detail": "authz.create_api_key for oneself is for users, not services (service 1 is signed in)",
        "table": None,
        "command": None,
        "why": [],
        "code": "AZ715",
    }
    said = [(rowstile.error_code(e), rowstile.sqlstate(e)) for e in errors]
    assert said == [("AZ706", "P0001"), ("AZ707", "P0001"), ("AZ702", "28000")], said
    for e, words in zip(
        errors,
        [
            "the policy does not allow sharing project.member with a user",
            "the policy gives service no manage_keys permission, so nobody manages its keys",
            "who is signed in was changed after signing in",
        ],
        strict=True,
    ):
        assert words in str(e), str(e)


# 9: the generated names type-check, and a wrong permission name doesn't
def test_9_generated_names_type_check(tmp_path: Path) -> None:
    subprocess.run([sys.executable, "-m", "rowstile", "client"], cwd=HERE, check=True, capture_output=True)
    good = tmp_path / "good.py"
    bad = tmp_path / "bad.py"
    use = "from app.authz_client import Authz\n\ndef f(a: Authz) -> bool:\n    return a.can('note', 1, {!r})\n"
    good.write_text(use.format("edit"))
    bad.write_text(use.format("edt"))
    env = {**os.environ, "MYPYPATH": HERE}
    ok = subprocess.run(
        [sys.executable, "-m", "mypy", "--no-error-summary", str(good)], env=env, capture_output=True, text=True
    )
    wrong = subprocess.run(
        [sys.executable, "-m", "mypy", "--no-error-summary", str(bad)], env=env, capture_output=True, text=True
    )
    assert ok.returncode == 0, ok.stdout
    assert wrong.returncode != 0 and "edt" in wrong.stdout, wrong.stdout
    # the SDK's own queries take the same names (rowstile.sqlalchemy.Queries, as app/main.py makes it)
    sdk = (
        "from app.main import queries\nfrom sqlalchemy.orm import Session\n\n"
        "def f(s: Session) -> bool:\n    wanted = queries.ids({0!r}, {1!r})\n"
        "    return wanted is not None and queries.can_sync(s, {0!r}, 1, {1!r})\n"
    )
    for name, type_, perm, fine in (
        ("sdk_good", "note", "edit", True),
        ("sdk_perm", "note", "edt", False),
        ("sdk_type", "nte", "edit", False),
    ):
        path = tmp_path / f"{name}.py"
        path.write_text(sdk.format(type_, perm))
        got = subprocess.run(
            [sys.executable, "-m", "mypy", "--no-error-summary", str(path)], env=env, capture_output=True, text=True
        )
        assert (got.returncode == 0) is fine, got.stdout
        assert fine or ("edt" if name == "sdk_perm" else "nte") in got.stdout, got.stdout


# 10: a background job signs in as a service principal
async def test_10_a_job_acts_as_its_service(app: FastAPI) -> None:
    with rowstile.acting_as(3):  # whatever started it
        count, who = await digest(app.state.Session)
    assert who == rowstile.Principal("service", "1")
    assert count == 2  # project 1 (it is added to) and the public one


# ... and only when the code names it: an id is a user's, whatever it holds (ids come from outside)
def test_10_an_id_with_a_colon_is_a_users_not_a_service() -> None:
    assert rowstile.Principal.of("service:1") == rowstile.Principal("user", "service:1")
    assert rowstile.Principal.of(("service", 1)) == rowstile.Principal("service", "1")
    with rowstile.acting_as("service:1"):
        assert rowstile.current() == rowstile.Principal("user", "service:1")
    # what str() wrote, read back, for text the app wrote itself
    assert rowstile.Principal.parse(str(rowstile.Principal("service", "1"))) == rowstile.Principal("service", "1")
    assert rowstile.Principal.parse("42") == rowstile.Principal("user", "42")
    assert rowstile.Principal.parse("nobody") == rowstile.NOBODY


# 12: the framework's test database has the policy: a database per worker, copied from the migrated one
async def test_12_a_test_database_per_worker_has_the_policy(
    worker_database: WorkerDatabase, monkeypatch: pytest.MonkeyPatch
) -> None:
    import rowstile.psycopg as pgp

    tests = os.environ["ROWSTILE_TESTS_URL"]
    copied = tests.rsplit("/", 1)[1]  # the migrated test database (test.sh's conf_tests): each copy is named after it
    assert re.search(rf"/{copied}_w\d+$", worker_database.url), worker_database.url
    assert worker_database.url.startswith("postgresql+psycopg://")  # the URL's own form, another database
    assert worker_database.app_url and worker_database.app_url.startswith("postgresql+asyncpg://conf_app:")

    def projects(who: int) -> list[int]:
        with psycopg.connect(libpq(worker_database.app_url or "")) as conn, pgp.transaction(conn, who):
            return [r[0] for r in conn.execute("SELECT id FROM app.projects ORDER BY id")]

    def users(url: str) -> int:
        with psycopg.connect(libpq(url)) as conn:
            return int(conn.execute("SELECT count(*) FROM app.users").fetchall()[0][0])

    with psycopg.connect(libpq(worker_database.url), autocommit=True) as conn:
        conn.execute("INSERT INTO app.users VALUES (1, 'ann'), (2, 'bo')")
        conn.execute("INSERT INTO app.projects VALUES (1, 1, 'Plans', false)")
    copy = make_app(worker_database.app_url, check_connection=False)
    await copy.state.authz.check()  # the app's role, under row-level security
    await copy.state.engine.dispose()
    assert projects(1) == [1] and projects(2) == []
    assert users(tests) == 0  # the original is left as it was migrated
    assert database_per_worker(tests, fresh=False).url == worker_database.url  # kept, with what the tests wrote
    assert users(worker_database.url) == 2
    assert database_per_worker(tests).url == worker_database.url  # copied again: as migrated
    assert users(worker_database.url) == 0
    # one for each of pytest-xdist's workers; a run without workers has one
    assert worker_id() == "0"
    monkeypatch.setenv("PYTEST_XDIST_WORKER", "gw3")
    assert worker_id() == "3" and database_per_worker(tests).url.endswith(f"/{copied}_w3")
    with pytest.raises(ValueError, match="a database to copy"):
        database_per_worker("postgresql://conf_owner:owner@localhost")


# 13: the app refuses to start on a connection that skips row-level security
async def test_13_refuses_a_connection_that_skips_rls() -> None:
    owner_app = make_app(OWNER.replace("+psycopg", "+asyncpg"), check_connection=False)
    with pytest.raises(ConnectionProblem) as e:
        await owner_app.state.authz.check()
    assert "owners skip row-level security" in str(e.value) or "superuser" in str(e.value)
    await owner_app.state.engine.dispose()
    fine = make_app(APP, check_connection=False)
    await fine.state.authz.check()
    await fine.state.engine.dispose()


# queries by permission: set checks, and one call for a list's buttons
async def test_queries_by_permission(app: FastAPI) -> None:
    async with client(app) as c:
        assert (await c.get("/projects/editable", headers=as_("3"))).json() == [1]
        assert (await c.get("/projects/buttons", headers=as_("3"))).json() == {"1": ["edit", "view"], "3": ["view"]}


# SQLAlchemy's sync engine and ORM (and so SQLModel, which is built on them)
def test_sqlalchemy_sync_engine() -> None:
    from app.models import Note
    from rowstile import sqlalchemy as authz_sa
    from sqlalchemy import create_engine, select
    from sqlalchemy.orm import Session
    from sqlalchemy.orm.exc import StaleDataError

    engine = authz_sa.install(create_engine(APP.replace("+asyncpg", "+psycopg")))
    try:
        with rowstile.acting_as(2), Session(engine) as s:
            assert sorted(s.scalars(select(Note.id)).all()) == [2, 3]
            assert authz_sa.can_sync(s, "note", 2, "edit") and not authz_sa.can_sync(s, "note", 3, "edit")
        with rowstile.acting_as(3):
            with pytest.raises(StaleDataError) as e, Session(engine) as s, s.begin():
                note = s.get(Note, 1)
                assert note is not None
                note.body = "x"
            verdict = authz_sa.why_stale_sync(e.value)
            assert isinstance(verdict, Refused) and verdict.why, verdict
    finally:
        engine.dispose()


# the drivers without SQLAlchemy
def test_psycopg_transactions() -> None:
    import rowstile.psycopg as pgp

    with psycopg.connect(libpq(APP)) as conn:
        with pgp.transaction(conn, 2):
            assert [r[0] for r in conn.execute("SELECT id FROM app.notes ORDER BY id")] == [2, 3]
        # who the transaction signed in as, asked of the database: not whoever the code around it acts for
        with rowstile.acting_as(1), pytest.raises(Refused) as e, pgp.transaction(conn, 3):
            cur = conn.execute("UPDATE app.notes SET body = 'x' WHERE id = 1")
            pgp.expect(conn, cur.rowcount, "app.notes", "update", 1)
        assert e.value.message == "permission denied: user 3 may not update row 1 of app.notes"


def test_a_key_is_spelled_as_the_database_writes_it() -> None:
    """In a message: 7, (1,2), a field quoted only where Postgres would. One spelling, for 403 and 404."""
    shown = [rowstile.key_shown(k) for k in (7, (7,), (1, 2), ["a b", "x,y"], ("", 'q"t'), ("b\\s", "(1)"), (1, None))]
    assert shown == ["7", "7", "(1,2)", '("a b","x,y")', '("","q""t")', '("b\\\\s","(1)")', "(1,)"]
    assert str(rowstile.NotFound("app.members", (1, 2))) == "app.members (1,2) not found"
    assert rowstile.NotFound("app.members", (1, 2)).id == "(1,2)"
    refused = rowstile.verdict("app.members", "delete", (1, 2), ["no   delete : manage"], "service 3")
    assert str(refused) == "permission denied: service 3 may not delete row (1,2) of app.members"
    with rowstile.acting_as(None):  # who left out: whoever the code acts for
        nobody = rowstile.verdict("app.members", "delete", (1, 2), ["no   delete : manage"])
    assert str(nobody) == "permission denied: someone not signed in may not delete row (1,2) of app.members"


async def test_asyncpg_transactions() -> None:
    import rowstile.asyncpg as pga

    conn = await asyncpg.connect(libpq(APP))
    try:
        with rowstile.acting_as(("service", "1")):
            async with pga.transaction(conn):
                assert [r["id"] for r in await conn.fetch("SELECT id FROM app.projects ORDER BY id")] == [1, 3]
        async with pga.transaction(conn, 2):
            with pytest.raises(rowstile.NotFound):
                await pga.expect(
                    conn, await conn.execute("DELETE FROM app.notes WHERE id = 1"), "app.notes", "delete", 1
                )
    finally:
        await conn.close()


# 13, as it happens: the app refuses to start, whether or not it has a lifespan of its own
async def test_13_the_app_does_not_start_on_a_connection_that_skips_rls() -> None:
    import contextlib

    from rowstile.fastapi import Rowstile
    from sqlalchemy.ext.asyncio import create_async_engine

    started: list[str] = []

    @contextlib.asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        started.append("the app's own lifespan")
        yield

    for own in (None, lifespan):
        engine = create_async_engine(OWNER.replace("+psycopg", "+asyncpg"))
        a = FastAPI(lifespan=own)
        Rowstile(a, engine, user=lambda request: request.headers.get("x-user"))
        with pytest.raises(ConnectionProblem):
            async with a.router.lifespan_context(a):
                pass
        await engine.dispose()
    assert started == []
    # and on the app role's connection it starts, with its own lifespan run
    engine = create_async_engine(APP)
    a = FastAPI(lifespan=lifespan)
    Rowstile(a, engine, user=lambda request: request.headers.get("x-user"))
    async with a.router.lifespan_context(a):
        assert started == ["the app's own lifespan"]
    await engine.dispose()


# who the request is may be refused by the app (a bad token): its answer, not a 500
async def test_user_may_raise() -> None:
    from fastapi import HTTPException
    from rowstile.fastapi import Rowstile
    from starlette.requests import Request

    def who(request: Request) -> str | None:
        if request.headers.get("authorization") == "Bearer bad":
            raise HTTPException(401, "bad token")
        return request.headers.get("x-user")

    a = FastAPI()
    Rowstile(a, None, user=who)

    @a.get("/me")
    async def me() -> str:
        return str(rowstile.current())

    async with client(a) as c:
        bad = await c.get("/me", headers={"authorization": "Bearer bad"})
        assert bad.status_code == 401 and bad.json() == {"detail": "bad token"}, bad.text
        assert (await c.get("/me", headers=as_("2"))).json() == "2"


# None is nobody, also inside acting_as; only a left-out argument means whoever the code acts for
async def test_none_is_nobody_inside_acting_as() -> None:
    import rowstile.asyncpg as pga
    import rowstile.psycopg as pgp

    with rowstile.acting_as(1):
        assert rowstile.act_as_args(None) == (None, None) and rowstile.act_as_args() == ("user", "1")
        assert rowstile.act_as_sql(None) == "SELECT authz.act_as(NULL, NULL)"
        with psycopg.connect(libpq(APP)) as conn:
            with pgp.transaction(conn, None):
                assert [r[0] for r in conn.execute("SELECT id FROM app.projects ORDER BY id")] == PROJECTS[None]
            with pgp.transaction(conn):
                assert [r[0] for r in conn.execute("SELECT id FROM app.projects ORDER BY id")] == PROJECTS["1"]
        aconn = await asyncpg.connect(libpq(APP))
        try:
            async with pga.transaction(aconn, None):
                assert [r["id"] for r in await aconn.fetch("SELECT id FROM app.projects ORDER BY id")] == PROJECTS[None]
        finally:
            await aconn.close()


# a block inside a transaction already open is a savepoint: the sign-in ends with the block all the same
async def test_a_block_inside_an_open_transaction_signs_out_again() -> None:
    import rowstile.asyncpg as pga
    import rowstile.psycopg as pgp

    projects = "SELECT id FROM app.projects ORDER BY id"  # (the projects: no test adds one)
    with psycopg.connect(libpq(APP)) as conn:
        conn.execute("SELECT 1")  # psycopg begins a transaction here
        with pgp.transaction(conn, 2):
            assert [r[0] for r in conn.execute(projects)] == PROJECTS["2"]
        assert [r[0] for r in conn.execute(projects)] == PROJECTS[None]  # nobody, not bo
        conn.rollback()
        with pgp.transaction(conn, 1):
            with pgp.transaction(conn, 2):
                assert [r[0] for r in conn.execute(projects)] == PROJECTS["2"]
            assert [r[0] for r in conn.execute(projects)] == PROJECTS["1"]  # back to the block around it
    async with await psycopg.AsyncConnection.connect(libpq(APP)) as aconn:  # (a selector loop: conftest.py)
        await aconn.execute("SELECT 1")
        async with pgp.atransaction(aconn, 2):
            pass
        assert [r[0] for r in await (await aconn.execute(projects)).fetchall()] == PROJECTS[None]
    pconn = await asyncpg.connect(libpq(APP))
    try:
        async with pconn.transaction():
            async with pga.transaction(pconn, 2):
                assert [r["id"] for r in await pconn.fetch(projects)] == PROJECTS["2"]
            assert [r["id"] for r in await pconn.fetch(projects)] == PROJECTS[None]
    finally:
        await pconn.close()


# a flush of several rows: the verdict is about the row that was refused, not the last one written;
# an id with a % reaches the database as it is; a model that names no schema is found on the search_path
def test_sqlalchemy_which_row_and_which_table() -> None:
    from app.models import Note
    from rowstile import sqlalchemy as authz_sa
    from sqlalchemy import BigInteger, Text, create_engine, text
    from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column
    from sqlalchemy.orm.exc import StaleDataError

    engine = authz_sa.install(create_engine(APP.replace("+asyncpg", "+psycopg")))
    try:
        with rowstile.acting_as(3):  # cy may edit note 4, not note 1
            with pytest.raises(StaleDataError) as e, Session(engine) as s, s.begin():
                first, last = s.get(Note, 1), s.get(Note, 4)
                assert first is not None and last is not None
                first.body, last.body = "x", "y"
            verdict = authz_sa.why_stale_sync(e.value)
            assert isinstance(verdict, Refused), verdict
            assert verdict.message == "permission denied: user 3 may not update row 1 of app.notes", verdict
            assert verdict.why[0].startswith("no"), verdict.why
        for who in ("50%", "a%sb", "%(x)s"):  # not a user of this app: nobody, and no error
            with rowstile.acting_as(who), Session(engine) as s:
                assert s.scalars(text("SELECT id FROM app.notes ORDER BY id")).all() == EXPECTED[None]
    finally:
        engine.dispose()

    class Base(DeclarativeBase):
        pass

    class BareNote(Base):
        __tablename__ = "notes"
        id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
        body: Mapped[str] = mapped_column(Text)

    bare = authz_sa.install(
        create_engine(APP.replace("+asyncpg", "+psycopg"), connect_args={"options": "-c search_path=app"})
    )
    try:
        with rowstile.acting_as(3):
            with pytest.raises(StaleDataError) as e, Session(bare) as s, s.begin():
                note = s.get(BareNote, 1)
                assert note is not None
                note.body = "x"
            verdict = authz_sa.why_stale_sync(e.value)
            assert isinstance(verdict, Refused) and verdict.why[0].startswith("no"), verdict
    finally:
        bare.dispose()


# an UPDATE that matched nothing for another reason than access isn't a refusal; expect takes the cursor too;
# a 42501 that isn't a policy's (a table the app role was never granted) isn't one either
def test_refused_means_the_database_said_no() -> None:
    import rowstile.psycopg as pgp

    with psycopg.connect(libpq(APP)) as conn:
        with pytest.raises(rowstile.NotFound), pgp.transaction(conn, 3):  # cy may edit note 4
            cur = conn.execute("UPDATE app.notes SET body = 'x' WHERE id = 4 AND body = 'something else'")
            pgp.expect(conn, cur.rowcount, "app.notes", "update", 4)
        with pytest.raises(Refused), pgp.transaction(conn, 3):
            pgp.expect(conn, conn.execute("UPDATE app.notes SET body = 'x' WHERE id = 1"), "app.notes", "update", 1)
        with pytest.raises(psycopg.errors.InsufficientPrivilege) as e, pgp.transaction(conn, 1):
            conn.execute("SELECT * FROM public.alembic_version")
        assert rowstile.refusal(e.value) is None
    assert rowstile.key_text(("a,b", 1)) == '("a,b","1")' and rowstile.key_text((7,)) == "7"


# a database rowfence applied (rowstile's name before) says `rowfence help` in its hints: the code still reads
def test_the_code_in_a_hint_rowfence_wrote() -> None:
    class Old(Exception):
        sqlstate = "28000"
        hint = "sign in with authz.act_as(); rowfence help AZ701"

    assert rowstile.error_code(Old("sign in first")) == "AZ701"


# a refusal carries the database's own code, and names the table as the policy does
def test_a_refusal_has_the_databases_code_and_its_name_for_the_table() -> None:
    class Share(Exception):  # what authz.share raises for someone who may not share
        sqlstate = "42501"
        hint = "rowstile help AZ705"

    refused = rowstile.refusal(Share("you cannot share project 1"))
    assert refused is not None
    assert (refused.code, refused.table, refused.command) == ("AZ705", None, None)
    assert refused.problem()["code"] == "AZ705"
    import rowstile.psycopg as pgp

    # a table named without its schema is found on the search_path, and the refusal says app.notes, as an
    # insert's does
    with psycopg.connect(libpq(APP)) as conn:
        with pytest.raises(Refused) as e, pgp.transaction(conn, 3):
            conn.execute("SET LOCAL search_path = app")
            cur = conn.execute("UPDATE notes SET body = 'x' WHERE id = 1")
            pgp.expect(conn, cur.rowcount, "notes", "update", 1)
        assert e.value.message == "permission denied: user 3 may not update row 1 of app.notes"
        assert (e.value.table, e.value.command, e.value.code) == ("app.notes", "update", "AZ709")
        with pytest.raises(rowstile.NotFound) as hidden, pgp.transaction(conn, 2):
            conn.execute("SET LOCAL search_path = app")
            cur = conn.execute("UPDATE notes SET body = 'x' WHERE id = 1")
            pgp.expect(conn, cur.rowcount, "notes", "update", 1)
        assert str(hidden.value) == "app.notes 1 not found"


# the pytest helpers (rowstile.testing), with sync and async functions
async def test_the_pytest_helpers(
    as_user: AsUser, assert_refused: AssertRefused, assert_not_found: AssertNotFound
) -> None:
    import rowstile.psycopg as pgp

    def update(note: int) -> None:
        with psycopg.connect(libpq(APP)) as conn, pgp.transaction(conn):
            pgp.expect(
                conn,
                conn.execute("UPDATE app.notes SET body = 'x' WHERE id = %s", (note,)),
                "app.notes",
                "update",
                note,
            )

    async def insert_later() -> None:
        with psycopg.connect(libpq(APP)) as conn, pgp.transaction(conn):
            conn.execute("INSERT INTO app.notes (project_id, author_id, body) VALUES (3, 2, 'hi')")

    with as_user(3):
        assert assert_refused(lambda: update(1), command="update", table="app.notes").why
        with pytest.raises(AssertionError, match="expected the delete rule"):
            assert_refused(lambda: update(1), command="delete")
        with pytest.raises(AssertionError, match="expected a refusal"):
            assert_refused(lambda: update(4))
    with as_user(2):
        assert_not_found(lambda: update(1))
        assert (await assert_refused(insert_later, command="insert")).table == "app.notes"


# 14: after a policy change and a new migration, the app works with the new generated names
def test_14_a_policy_change_ships_as_the_next_migration(tmp_path: Path) -> None:
    work = tmp_path / "app"
    shutil.copytree(HERE, work, ignore=shutil.ignore_patterns(".venv", "__pycache__", ".pytest_cache", ".mypy_cache"))
    policy = work / "db" / "policy.authz"
    policy.write_text(
        policy.read_text().replace("  can read = recipient\n", "  can read = recipient\n  can reply = recipient\n")
    )
    cli = "-m", "rowstile"  # the command, as the rowstile package installs it
    subprocess.run([sys.executable, *cli, "migrate"], cwd=work, check=True, capture_output=True)
    subprocess.run([sys.executable, "-m", "alembic", "upgrade", "head"], cwd=work, check=True, capture_output=True)
    subprocess.run([sys.executable, *cli, "client"], cwd=work, check=True, capture_output=True)
    assert '"reply"' in (work / "app" / "authz_client.py").read_text()
    with psycopg.connect(libpq(APP)) as conn, conn.transaction():
        conn.execute("SELECT authz.act_as(%s, %s)", rowstile.act_as_args(2))
        got = conn.execute("SELECT authz.perms('message', id::text) FROM app.inbox WHERE recipient_id = 2").fetchall()
    assert got and all("reply" in r[0] for r in got), got
