"""The conformance suite (integrations/README.md): the same checks for every stack. This is Django on psycopg 3,
Django's migrations, pytest-django. test.sh does check 11 (a fresh database: migrate, the policy's tests, then
Django's own diff shows no change) before these run. The checks run on this worker's copy of the migrated test
database (check 12, conftest.py)."""

import asyncio
import json
import os
import re
import shutil
import subprocess
import sys
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import psycopg
import pytest
import rowstile
from app.views import digest
from django.db import DatabaseError, connection, connections
from django.db.backends.postgresql.base import DatabaseWrapper as PostgresWrapper
from django.test import AsyncClient, Client
from psycopg import sql
from rowstile import NotSignedIn, error_code, sqlstate
from rowstile import django as authz_dj
from rowstile.testing import worker_id

Answer = Any
HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXPECTED: dict[str | None, list[int]] = {"1": [1, 3, 4], "2": [2, 3], "3": [1, 3, 4], None: [3]}


def as_(user: str | None) -> dict[str, str]:
    return {"x-user": user} if user else {}


def send(c: Client, method: str, url: str, sent: object = None, **headers: str) -> Answer:
    """A request with a JSON body, as the checks' user."""
    call = getattr(c, method)
    return call(url, json.dumps(sent or {}), content_type="application/json", headers=headers)


def problem(kind: str, title: str, status: int, detail: str, code: str) -> Answer:
    return {
        "type": f"https://rowstile.dev/problems/{kind}",
        "title": title,
        "status": status,
        "detail": detail,
        "code": code,
    }


# 1, 2: a list shows only the user's rows; signed out on purpose, only what anyone may see
def test_1_2_lists_show_what_each_may_see() -> None:
    c = Client()
    for user, notes in EXPECTED.items():
        assert c.get("/notes", headers=as_(user)).json() == notes, user
    assert c.get("/projects", headers=as_(None)).json() == [3]


# 3: not signed in at all: the strict sign-in error, naming act_as. Code that acts for no one (a management
# command, the shell) signs nothing in
def test_3_not_signed_in_is_an_error_that_says_how() -> None:
    from app.models import Note

    with pytest.raises(DatabaseError) as e:
        list(Note.objects.all())
    cause = e.value.__cause__
    hint = cause.diag.message_hint if isinstance(cause, psycopg.Error) else None
    assert sqlstate(e.value) == "28000" and "act_as" in (hint or ""), (sqlstate(e.value), hint)
    assert error_code(e.value) == "AZ701", hint  # rowstile help AZ701


# 4: one connection, Ann then Bob: Bob never sees Ann's rows. Django's own persistent connection (the test client
# keeps it between requests, as CONN_MAX_AGE does), then psycopg's pool of one (OPTIONS["pool"], Django 5.1)
def test_4_a_persistent_connection_carries_no_one_over() -> None:
    c = Client()
    assert c.get("/notes", headers=as_("1")).json() == EXPECTED["1"]
    raw = connection.connection
    assert c.get("/notes", headers=as_("2")).json() == EXPECTED["2"]
    assert c.get("/notes").json() == EXPECTED[None]
    # a transaction that commits (a folder moved where it is)
    assert send(c, "patch", "/folders/2", {"parent_id": 1}, **as_("1")).status_code == 200
    assert connection.connection is raw  # the one connection served them all
    # each request signed in again, so the answers alone can't tell: the connection, as the last request left it,
    # in a transaction nobody signs in to, holds no one (a sign-in that outlived its transaction would be ann's)
    assert_holds_no_one(raw)


def assert_holds_no_one(raw: psycopg.Connection[Any]) -> None:
    """The driver's connection, used as it is (each statement a transaction of its own), has no one signed in."""
    row = raw.execute("SELECT current_setting('authz.user_id', true)").fetchone()
    assert row is not None and row[0] in (None, ""), row
    with pytest.raises(psycopg.Error) as e:
        raw.execute("SELECT count(*) FROM notes")
    assert error_code(e.value) == "AZ701", str(e.value)  # rowstile help AZ701


def postgres() -> PostgresWrapper:
    """Django's connection, as its Postgres backend's (the pool is its own)."""
    wrapper = connections["default"]
    assert isinstance(wrapper, PostgresWrapper)
    return wrapper


@pytest.fixture
def pool_of_one() -> Iterator[None]:
    """Django's connection from psycopg's pool, of one connection."""
    connection.close()
    options = connection.settings_dict["OPTIONS"]
    options["pool"] = {"min_size": 1, "max_size": 1}
    try:
        yield
    finally:
        connection.close()
        postgres().close_pool()
        del options["pool"]


def test_4_a_pooled_connection_carries_no_one_over(pool_of_one: None) -> None:
    c = Client()
    seen = []
    for user in ("1", "2", None, "3"):
        assert c.get("/notes", headers=as_(user)).json() == EXPECTED[user], user
        seen.append(connection.connection)
        connection.close()  # back to the pool, as at the end of each request
    assert len({id(x) for x in seen}) == 1, "the pool's one connection served them all"
    pool = postgres().pool
    assert pool is not None
    with pool.connection() as raw:
        assert_holds_no_one(raw)


# 5: concurrent requests never mix users: in threads (WSGI, a connection each), and in one event loop (ASGI, the
# async ORM)
def test_5_concurrent_requests_never_mix_users() -> None:
    users = ["1", "2", "3", None] * 10

    def get(user: str | None) -> list[int]:
        try:
            return Client().get("/notes", headers=as_(user)).json()
        finally:
            connections.close_all()

    with ThreadPoolExecutor(8) as pool:
        assert list(pool.map(get, users)) == [EXPECTED[u] for u in users]

    async def all_at_once() -> list[Answer]:
        c = AsyncClient()
        got = await asyncio.gather(*[c.get("/notes/async", headers=as_(u)) for u in users])
        return [r.json() for r in got]

    assert asyncio.run(all_at_once()) == [EXPECTED[u] for u in users]


# 6: a refused insert: 403, with the problem body naming the rule
def test_6_a_refused_insert_says_which_rule() -> None:
    r = send(Client(), "post", "/notes", {"project_id": 3, "body": "hi"}, **as_("2"))
    assert r.status_code == 403, r.content
    body = r.json()
    assert r.headers["content-type"] == "application/problem+json"
    assert body["table"] == "public.notes" and body["command"] == "insert", body
    assert body["code"] == "AZ709", body  # rowstile help AZ709
    assert "user 2 may not insert this row into public.notes" in body["detail"]
    assert any("project.edit" in line for line in body["why"]), body["why"]


# 7: an update of a hidden row: 404; of a visible row the user may not edit: 403, with the reason
def test_7_hidden_is_404_and_not_allowed_is_403() -> None:
    c = Client()
    hidden = send(c, "patch", "/notes/1", {"body": "x"}, **as_("2"))
    refused = send(c, "patch", "/notes/1", {"body": "x"}, **as_("3"))
    mine = send(c, "patch", "/notes/4", {"body": "better idea"}, **as_("3"))
    gone = c.delete("/notes/2", headers=as_("1"))
    no = c.delete("/notes/1", headers=as_("3"))
    assert hidden.status_code == 404, hidden.content
    assert hidden.json()["detail"] == "public.notes 1 not found", hidden.content
    assert refused.status_code == 403 and refused.json()["command"] == "update", refused.content
    assert any("edit" in line for line in refused.json()["why"]), refused.json()
    # worded as the database words a refused insert: who, the command, the row, the table
    assert refused.json()["detail"] == "permission denied: user 3 may not update row 1 of public.notes", refused.content
    assert mine.status_code == 200, mine.content
    assert gone.status_code == 404, gone.content
    assert no.status_code == 403 and no.json()["command"] == "delete" and no.json()["why"], no.content
    assert no.json()["detail"] == "permission denied: user 3 may not delete row 1 of public.notes", no.content


# 7: ... and the SDK's own 404: cy's note in ann's project, which ann reads and which is in bo's project by the
# time her update reaches the database. The app found the row: the 404 is the database's answer, which the SDK
# turns into one (save)
def test_7_a_row_hidden_before_the_update_is_404(data: str) -> None:
    from app.models import Note
    from django.db.models.signals import pre_save

    moved: list[int] = []

    def move_it(sender: object, **kwargs: object) -> None:
        if not moved:  # once: someone moves the note meanwhile
            with psycopg.connect(data, autocommit=True) as owner:
                moved.append(owner.execute("UPDATE notes SET project_id = 2 WHERE id = 4").rowcount)

    pre_save.connect(move_it, sender=Note)
    try:
        hidden = send(Client(), "patch", "/notes/4", {"body": "x"}, **as_("1"))
    finally:
        pre_save.disconnect(move_it, sender=Note)
        with psycopg.connect(data, autocommit=True) as owner:
            owner.execute("UPDATE notes SET project_id = 1 WHERE id = 4")
    assert moved == [1]
    assert hidden.headers["content-type"] == "application/problem+json", hidden.content
    assert hidden.json() == {
        "type": "https://rowstile.dev/problems/not-found",
        "title": "Not Found",
        "status": 404,
        "detail": "public.notes 4 not found",
    }, hidden.content


# 8: an insert read back works when the select rule allows it, and is explained when not
def test_8_insert_then_read_back() -> None:
    c = Client()
    ok = send(c, "post", "/notes", {"project_id": 1, "body": "new"}, **as_("1"))
    unreadable = send(c, "post", "/inbox", {"recipient_id": 2, "body": "hi bo"}, **as_("1"))
    quiet = send(c, "post", "/inbox/quietly", {"recipient_id": 2, "body": "hi bo"}, **as_("1"))
    assert ok.status_code == 201 and ok.json()["id"] > 100, ok.content
    assert unreadable.status_code == 403, unreadable.content
    assert unreadable.json()["command"] == "select" and "may not see the row as written" in unreadable.json()["detail"]
    assert quiet.status_code == 202, quiet.content


# 9: the generated names type-check, and a wrong permission name doesn't
def test_9_generated_names_type_check(tmp_path: Path) -> None:
    # the committed client is the one the policy makes (rowstile client py POLICY prints it, and writes nothing)
    made = subprocess.run(
        [sys.executable, "-m", "rowstile", "client", "py", "db/policy.authz"],
        cwd=HERE,
        check=True,
        capture_output=True,
        text=True,
    )
    committed = Path(HERE, "app", "authz_client.py").read_text(encoding="utf-8")
    assert made.stdout == committed, "app/authz_client.py is out of date: run rowstile client"

    def mypy(name: str, code: str) -> subprocess.CompletedProcess[str]:
        path = tmp_path / f"{name}.py"
        path.write_text(code, encoding="utf-8")
        return subprocess.run(
            [sys.executable, "-m", "mypy", "--no-error-summary", "--ignore-missing-imports", str(path)],
            env={**os.environ, "MYPYPATH": HERE},
            capture_output=True,
            text=True,
        )

    use = "from app.authz_client import Authz\n\ndef f(a: Authz) -> bool:\n    return a.can('note', 1, {!r})\n"
    ok, wrong = mypy("good", use.format("edit")), mypy("bad", use.format("edt"))
    assert ok.returncode == 0, ok.stdout
    assert wrong.returncode != 0 and "edt" in wrong.stdout, wrong.stdout
    # the SDK's own queries take the same names (rowstile.django.Queries, as app/views.py makes it)
    sdk = (
        "from app.views import queries\n\n"
        "def f() -> bool:\n    wanted = queries.ids({0!r}, {1!r})\n"
        "    return wanted is not None and queries.can({0!r}, 1, {1!r})\n"
    )
    for name, type_, perm, fine in (
        ("sdk_good", "note", "edit", True),
        ("sdk_perm", "note", "edt", False),
        ("sdk_type", "nte", "edit", False),
    ):
        got = mypy(name, sdk.format(type_, perm))
        assert (got.returncode == 0) is fine, got.stdout
        assert fine or ("edt" if name == "sdk_perm" else "nte") in got.stdout, got.stdout


# 10: a background job signs in as a service principal
def test_10_a_job_acts_as_its_service() -> None:
    with rowstile.acting_as(3):  # whatever started it
        count, who = digest()
    assert who == rowstile.Principal("service", "1")
    assert count == 2  # project 1 (it is added to) and the public one


# 12: the framework's test database has the policy: a database per worker, copied from the migrated one, which
# Django's connection uses (conftest.py's django_db_setup)
def test_12_the_test_database_is_a_copy_per_worker_with_the_policy(data: str) -> None:
    tests = os.environ["ROWSTILE_TESTS_URL"]
    copied = tests.rsplit("/", 1)[1]  # the migrated test database (test.sh's conf_tests): each copy is named after it
    assert connection.settings_dict["NAME"] == f"{copied}_w{worker_id()}", connection.settings_dict["NAME"]
    assert data.endswith(f"/{copied}_w{worker_id()}")
    with connection.cursor() as cursor:
        cursor.execute("SELECT current_user, current_database()")
        assert cursor.fetchone() == ("conf_app", connection.settings_dict["NAME"])  # as the app role
    authz_dj.check()  # under row-level security
    with rowstile.acting_as(2):
        assert authz_dj.can("project", 2, "edit") and not authz_dj.can("project", 1, "view")


# 13: the app refuses to start on a connection that skips row-level security: its WSGI and ASGI applications, on
# the owner's connection, don't load; on the app role's they do
def test_13_the_app_does_not_start_on_a_connection_that_skips_rls(data: str) -> None:
    def start(url: str, kind: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-c", f"import conformance.{kind}"],
            cwd=HERE,
            env={**os.environ, "DATABASE_URL": url, "DJANGO_SETTINGS_MODULE": "conformance.settings"},
            capture_output=True,
            text=True,
        )

    for kind in ("wsgi", "asgi"):
        refused = start(data, kind)
        assert refused.returncode != 0, refused.stderr
        assert "rowstile.ConnectionProblem" in refused.stderr, refused.stderr
        assert "an owner skips row-level security" in refused.stderr, refused.stderr
        started = start(os.environ["DATABASE_URL"].rsplit("/", 1)[0] + "/" + connection.settings_dict["NAME"], kind)
        assert started.returncode == 0, started.stderr


# 14: after a policy change and a new migration, the app works with the new generated names. On a fresh database of
# its own, migrated with the app's migrations, the new one last
def test_14_a_policy_change_ships_as_the_next_migration(tmp_path: Path) -> None:
    import importlib.util

    tests = os.environ["ROWSTILE_TESTS_URL"]
    server, name = tests.rsplit("/", 1)[0], f"{tests.rsplit('/', 1)[1]}_14_w{worker_id()}"
    with psycopg.connect(f"{server}/postgres", autocommit=True) as owner:
        owner.execute(sql.SQL("DROP DATABASE IF EXISTS {} WITH (FORCE)").format(sql.Identifier(name)))
        owner.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(name)))
    work = tmp_path / "app"
    shutil.copytree(HERE, work, ignore=shutil.ignore_patterns(".venv", "__pycache__", ".pytest_cache", ".mypy_cache"))
    policy = work / "db" / "policy.authz"
    policy.write_text(
        policy.read_text(encoding="utf-8").replace(
            "  can read = recipient\n", "  can read = recipient\n  can reply = recipient\n"
        ),
        encoding="utf-8",
    )
    cli = "-m", "rowstile"  # the command, as the rowstile package installs it
    owner_env = {**os.environ, "DATABASE_URL": f"{server}/{name}"}  # manage.py migrate, as the tables' owner
    try:
        wrote = subprocess.run([sys.executable, *cli, "migrate"], cwd=work, check=True, capture_output=True, text=True)
        assert re.search(r"wrote app/migrations/0004_authz_\w+\.py", wrote.stdout), wrote.stdout
        manage = [sys.executable, "manage.py"]
        subprocess.run([*manage, "migrate", "--verbosity", "0"], cwd=work, env=owner_env, check=True)
        # Django's own diff still shows no change, rowstile's migration the latest
        subprocess.run([*manage, "makemigrations", "--check", "--dry-run"], cwd=work, env=owner_env, check=True)
        with psycopg.connect(f"{server}/{name}", autocommit=True) as owner:  # ann sends bo a message
            owner.execute("INSERT INTO users VALUES (1, 'ann'), (2, 'bo')")
            message = owner.execute(
                "INSERT INTO inbox (sender_id, recipient_id, body) VALUES (1, 2, 'hi') RETURNING id"
            ).fetchone()
        assert message is not None
        subprocess.run([sys.executable, *cli, "client"], cwd=work, check=True, capture_output=True)
        # the app's code, with the client the policy now makes: it names reply, and the database answers it
        spec = importlib.util.spec_from_file_location("regenerated_client", work / "app" / "authz_client.py")
        assert spec is not None and spec.loader is not None
        regenerated = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(regenerated)
        said: list[tuple[bool, bool]] = []
        with psycopg.connect(os.environ["DATABASE_URL"].rsplit("/", 1)[0] + "/" + name) as conn:
            for user in (2, 1):  # bo, to whom it is sent, may reply; ann, who sent it, may not even read it
                with conn.transaction():
                    authz = regenerated.Authz(conn)
                    authz.sign_in(user)
                    said.append((authz.can("message", message[0], "reply"), authz.can("message", message[0], "read")))
        assert said == [(True, True), (False, False)], said
        # and undoing rowstile's migration is refused, in a line: they go forward only
        back = subprocess.run(
            [*manage, "migrate", "app", "0003"], cwd=work, env=owner_env, capture_output=True, text=True
        )
        assert back.returncode != 0, back.stdout
        assert "RuntimeError: a rowstile migration isn't undone" in back.stderr, back.stderr[-2000:]
    finally:
        with psycopg.connect(f"{server}/postgres", autocommit=True) as owner:
            owner.execute(sql.SQL("DROP DATABASE IF EXISTS {} WITH (FORCE)").format(sql.Identifier(name)))


# 16: a call the database turns down that is no refusal answers as its code's page says: what it names isn't there
# (AZ708) 404, a missing or wrong argument (AZ710) 400, with the database's words
def test_16_not_there_is_404_and_a_wrong_argument_400(data: str) -> None:
    with psycopg.connect(data) as conn:  # an API key of ann's, in one transaction (it commits at the end)
        conn.execute("SELECT authz.act_as('user', '1')")
        conn.execute("SELECT authz.create_api_key('ci')")
        key = conn.execute("SELECT max(id) FROM authz.api_keys WHERE user_id = '1'").fetchone()
    assert key is not None
    c = Client()
    page = c.get("/projects/page", {"limit": 1}, headers=as_("1"))
    negative = c.get("/projects/page", {"limit": -1}, headers=as_("1"))
    cursor = c.get("/projects/page", {"limit": 1, "after": "x"}, headers=as_("1"))
    others = c.delete(f"/keys/{key[0]}", headers=as_("2"))  # bo's key it isn't
    revoked = c.delete(f"/keys/{key[0]}", headers=as_("1"))
    again = c.delete(f"/keys/{key[0]}", headers=as_("1"))  # revoked: there is none now
    assert page.status_code == 200 and page.json() == ["1"], page.content
    for r, detail in [
        (negative, "the page size must not be negative (got -1)"),
        (cursor, "the page cursor 'x' is not a project id"),
    ]:
        assert r.headers["content-type"] == "application/problem+json", r.content
        assert r.json() == problem("bad-argument", "Bad Request", 400, detail, "AZ710"), r.content
        assert r.status_code == 400
    assert revoked.status_code == 204, revoked.content
    # no refusal: for this user the key isn't there (bo's own keys don't hold it; ann's no longer do)
    for r in (others, again):
        assert r.headers["content-type"] == "application/problem+json", r.content
        assert r.json() == problem("not-found", "Not Found", 404, f"no API key {key[0]} of yours", "AZ708"), r.content
        assert r.status_code == 404


# 16: and the other codes the runtime raises, each as its page says (rowstile help AZ703 and the like): a login refused
# or a call that needs someone signed in 401, a move inside itself 409, a refusal by the database's own code 403;
# a share the policy doesn't declare, a name not in the policy and who is signed in changed by hand are the app's
# mistakes, which stay errors (a 500)
def test_16_each_code_answers_as_its_page_says(data: str) -> None:
    with psycopg.connect(data) as conn:  # a key of ann's that may only read
        conn.execute("SELECT authz.act_as('user', '1')")
        read_only = conn.execute("SELECT authz.create_api_key('ro', 'read')").fetchone()
    assert read_only is not None
    c = Client()
    nobody = send(c, "post", "/keys", {"name": "k"})
    asks = send(c, "post", "/projects/1/requests", {"relation": "member", "reason": "the review"})
    bad_key = send(c, "post", "/keys", {"name": "k"}, **as_("1"), **{"x-api-key": "ak_nope"})
    scoped = send(c, "post", "/keys", {"name": "k"}, **as_("1"), **{"x-api-key": str(read_only[0])})
    made = send(c, "post", "/keys", {"name": "k"}, **as_("1"))
    not_shared = c.get("/projects/1/shares", headers=as_("2"))
    inside = send(c, "patch", "/folders/1", {"parent_id": 2}, **as_("1"))
    stays = send(c, "patch", "/folders/2", {"parent_id": 1}, **as_("1"))
    service = send(c, "post", "/keys", {"name": "mine"}, **{"x-service": "1"})  # a key for itself
    errors = []
    for call in (
        lambda: send(c, "post", "/projects/1/requests", {"relation": "member", "reason": "the review"}, **as_("2")),
        lambda: send(c, "post", "/keys", {"name": "k", "principal_type": "service", "principal_id": "1"}, **as_("1")),
        lambda: c.get("/notes/as/2", headers=as_("1")),
    ):
        with pytest.raises(DatabaseError) as e:  # the database's own error, not NotSignedIn nor a problem
            call()
        errors.append(e.value)
    assert made.status_code == 201 and made.json()["key"].startswith("ak_"), made.content
    assert stays.status_code == 200, stays.content
    for r, body in [
        (nobody, problem("not-signed-in", "Unauthorized", 401, "sign in to create an API key", "AZ714")),
        (asks, problem("not-signed-in", "Unauthorized", 401, "sign in first", "AZ714")),
        (bad_key, problem("not-signed-in", "Unauthorized", 401, "invalid API key", "AZ703")),
        (inside, problem("conflict", "Conflict", 409, "folder 1 cannot be moved inside itself", "AZ713")),
    ]:
        assert r.headers["content-type"] == "application/problem+json", r.content
        assert r.json() == body, r.content
        assert r.status_code == body["status"]
    # refusals, by the database's own code: 403, naming no rule
    for r, detail, code in [
        (scoped, "this session is read-only", "AZ704"),
        (not_shared, "you cannot see the shares of project 1", "AZ705"),
    ]:
        assert r.status_code == 403, r.content
        got = r.json()
        assert got["type"] == "https://rowstile.dev/problems/refused" and got["code"] == code, got
        assert got["detail"].startswith(detail) and got["table"] is None and got["command"] is None, got
    # a call that is for users, made by a service (rowstile help AZ715): a refusal too, 403
    assert service.headers["content-type"] == "application/problem+json", service.content
    assert service.json() == {
        "type": "https://rowstile.dev/problems/refused",
        "title": "Forbidden",
        "status": 403,
        "detail": "authz.create_api_key for oneself is for users, not services (service 1 is signed in)",
        "table": None,
        "command": None,
        "why": [],
        "code": "AZ715",
    }, service.content
    assert service.status_code == 403
    said = [(error_code(e), sqlstate(e)) for e in errors]
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


# a query in a request that the hook didn't sign in (it was taken off the connection): a 500 that says how
def test_a_request_nobody_signed_in_says_how() -> None:
    c = Client()
    c.get("/projects", headers=as_("1"))  # the connection made, with the sign-in among its wrappers
    connection.execute_wrappers.remove(authz_dj._sign_in)
    try:
        with pytest.raises(NotSignedIn, match=r'"rowstile.django" in INSTALLED_APPS'):
            c.get("/notes", headers=as_("1"))
    finally:
        connection.execute_wrappers.insert(0, authz_dj._sign_in)
