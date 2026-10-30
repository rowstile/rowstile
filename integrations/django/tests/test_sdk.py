"""The Django module's own calls, each way they can go, beyond the conformance checks (test_conformance.py): what
each promises, asked of the database where there is one to ask. test.sh measures what these and the conformance
checks run of the module (sdk/python/rowstile/django), and fails unless they run every line and branch of it."""

import asyncio
import json
import os
import re
from collections.abc import AsyncIterator, Iterator
from types import SimpleNamespace
from typing import Any, cast
from unittest import mock

import psycopg
import pytest
import rowstile
from app.authz_client import ObjectType, Permission
from app.models import Folder, Note, Project
from django.core.exceptions import ImproperlyConfigured
from django.db import DatabaseError, connection, connections, transaction
from django.http import HttpRequest, HttpResponse, StreamingHttpResponse
from django.test import AsyncClient, Client, override_settings
from rowstile import ConnectionProblem, NotFound, Principal, Refused
from rowstile import django as authz_dj
from rowstile.testing import AssertNotFound, AssertRefused, AsUser

Answer = Any
# the projects each may see (no check adds one): ann (1) and cy (3) see 1 and 3, bo (2) 2 and 3, nobody 3
ANN, BO, NOBODY = [1, 3], [2, 3], [3]


def projects() -> list[int]:
    with connection.cursor() as cursor:
        cursor.execute("SELECT id FROM projects ORDER BY id")
        return [r[0] for r in cursor.fetchall()]


def who() -> str | None:
    with connection.cursor() as cursor:
        cursor.execute("SELECT principal_type || ' ' || principal_id FROM authz.principal()")
        row = cursor.fetchone()
    return row[0] if row else None


# --- each transaction signed in -----------------------------------------------------------------------
ALREADY = "this transaction is signed in as user 1 already, and a sign-in lasts the database transaction: "
AFTER = " run inside it. Run it after, or in a transaction of its own (another connection)"


def signed_in_as() -> str:
    """Who the open transaction is signed in as, asked on the driver's connection itself: past the SDK."""
    raw = connection.connection
    assert raw is not None
    row = raw.execute("SELECT coalesce(current_setting('authz.user_id', true), '')").fetchone()
    assert row is not None
    return str(row[0])


def last_sent() -> str:
    """The last statement Django's connection sent, as Postgres shows it to the same role (on another connection)."""
    raw = connection.connection
    assert raw is not None
    s = connection.settings_dict
    with psycopg.connect(
        dbname=s["NAME"], user=s["USER"], password=s["PASSWORD"], host=s["HOST"], port=s["PORT"], autocommit=True
    ) as other:
        row = other.execute("SELECT query FROM pg_stat_activity WHERE pid = %s", (raw.info.backend_pid,)).fetchone()
    assert row is not None
    return str(row[0])


def test_an_atomic_block_signs_in_as_whoever_the_code_acts_for_now() -> None:
    """A transaction is one principal's: no one's until a statement while the code acts for someone signs it in,
    theirs from then on. A statement for someone else, or for no one, is refused before it is sent, and the
    transaction goes on as its principal's: it reads, writes and commits."""
    with transaction.atomic():
        with connection.cursor() as cursor:  # not signed in yet: acts for no one
            cursor.execute("SELECT 1")
        with rowstile.acting_as(1):  # signs in: ann's from here on
            with transaction.atomic():  # a savepoint, the same principal's
                assert projects() == ANN
            assert projects() == ANN
        with pytest.raises(RuntimeError) as no_one:
            projects()
        assert last_sent() == "SELECT id FROM projects ORDER BY id"  # nothing sent for it
        with rowstile.acting_as(2), pytest.raises(RuntimeError) as bo:
            projects()
        with rowstile.acting_as(None), pytest.raises(RuntimeError) as nobody:
            projects()
        with transaction.atomic():  # a savepoint made, and released, while the code acts for no one: no one's work
            pass
        with rowstile.acting_as(1):
            assert who() == "user 1" and projects() == ANN
            assert Note.objects.filter(pk=1).update(body="plan") == 1
    assert not connection.in_atomic_block  # committed
    assert str(no_one.value) == ALREADY + "the work of code that acts for no one can't" + AFTER
    assert str(bo.value) == ALREADY + "user 2's work can't" + AFTER
    assert str(nobody.value) == ALREADY + "nobody's work can't" + AFTER
    with rowstile.acting_as(2), transaction.atomic():  # the next transaction is another's
        assert projects() == BO
    with transaction.atomic():  # a transaction no one is named in: the database refuses what needs to know
        with pytest.raises(DatabaseError) as e:
            projects()
        assert rowstile.error_code(e.value) == "AZ701"


def test_a_savepoint_rolled_back_leaves_the_transaction_signed_in_as_the_code_acts_for() -> None:
    """Rolled back to a savepoint made before the sign-in, Postgres has undone it: the transaction is still the same
    principal's, who signs in again at the next statement, and another is still refused. Rolled back to a
    savepoint made after it, the sign-in stays."""
    with transaction.atomic():
        try:
            with transaction.atomic(), rowstile.acting_as(1):  # the first sign-in, inside a savepoint
                assert projects() == ANN
                raise ValueError("undone")
        except ValueError:
            pass
        assert signed_in_as() == ""  # undone
        with rowstile.acting_as(2), pytest.raises(RuntimeError, match=ALREADY + "user 2's work can't"):
            projects()
        with rowstile.acting_as(1):
            assert projects() == ANN and signed_in_as() == "1"  # signed in again
            try:
                with transaction.atomic():
                    raise ValueError("undone")
            except ValueError:
                pass
            assert signed_in_as() == "1" and projects() == ANN  # kept


def test_a_statement_in_a_broken_transaction_fails_as_it_would() -> None:
    with rowstile.acting_as(2), transaction.atomic():
        with pytest.raises(DatabaseError), connection.cursor() as cursor:
            cursor.execute("SELECT 1 / 0")
        with pytest.raises(DatabaseError, match="current transaction is aborted"):
            projects()
        transaction.set_rollback(True)


def test_atomic_requests_and_a_server_side_cursor() -> None:
    connection.settings_dict["ATOMIC_REQUESTS"] = True
    try:
        assert Client().get("/projects", headers={"x-user": "2"}).json() == BO
    finally:
        connection.settings_dict["ATOMIC_REQUESTS"] = False
    # .iterator() reads through a cursor of the server's, declared WITH HOLD outside a transaction: kept past the
    # transaction it was signed in for
    with rowstile.acting_as(1):
        assert sorted(Project.objects.values_list("id", flat=True).iterator(chunk_size=1)) == ANN
        with transaction.atomic():
            assert sorted(Project.objects.values_list("id", flat=True).iterator(chunk_size=1)) == ANN


@pytest.mark.django_db
def test_pytest_djangos_own_transaction_around_a_test(client: Client) -> None:
    """The way most Django test suites run: each test in a transaction pytest-django rolls back. What the app runs
    goes as it would without it: a test acts for ann, then for bo. An atomic block the app begins in it is one
    principal's, as a transaction is, and is forgotten once released or rolled back."""
    assert client.get("/notes", headers={"x-user": "1"}).json() == [1, 3, 4]
    made = client.post(
        "/notes",
        json.dumps({"project_id": 1, "body": "kept for this test"}),
        "application/json",
        headers={"x-user": "1"},
    )
    assert made.status_code == 201, made.content
    with rowstile.acting_as(1):
        assert Note.objects.filter(pk=made.json()["id"]).exists()
    assert client.get("/notes", headers={"x-user": "2"}).json() == [2, 3]
    with rowstile.acting_as(None):
        assert projects() == NOBODY
    with transaction.atomic():  # the app's own block: ann's from its first statement for her
        with rowstile.acting_as(1):
            assert projects() == ANN
            with transaction.atomic():  # a savepoint inside it, hers too
                assert projects() == ANN
        with rowstile.acting_as(2), pytest.raises(RuntimeError, match=ALREADY + "user 2's work can't"):
            projects()
        with transaction.atomic():  # a savepoint made and released while the code acts for no one: no one's work
            pass
    with rowstile.acting_as(2):  # the block is released: bo again
        assert projects() == BO
    try:
        with transaction.atomic(), rowstile.acting_as(1):
            assert projects() == ANN
            raise ValueError("undone")
    except ValueError:
        pass
    with rowstile.acting_as(2):  # rolled back, forgotten too
        assert projects() == BO and who() == "user 2"


def test_only_postgres_with_psycopg_3_is_signed_in() -> None:
    sqlite: Any = SimpleNamespace(vendor="sqlite", execute_wrappers=[])
    authz_dj._install(None, sqlite)
    assert sqlite.execute_wrappers == []
    driver = type("connection", (), {"__module__": "psycopg2.extensions"})
    psycopg2: Any = SimpleNamespace(vendor="postgresql", connection=driver(), execute_wrappers=[])
    with pytest.raises(ImproperlyConfigured, match="needs psycopg 3"):
        authz_dj._install(None, psycopg2)
    Client().get("/projects")
    assert connection.execute_wrappers.count(authz_dj._sign_in) == 1  # once, however many times it connected


# --- the middleware -----------------------------------------------------------------------------------
def respond(request: HttpRequest) -> HttpResponse:
    return HttpResponse(str(rowstile.current()))


async def arespond(request: HttpRequest) -> HttpResponse:
    return HttpResponse(str(rowstile.current()))


def a_request(**attributes: object) -> HttpRequest:
    request = HttpRequest()
    for name, value in attributes.items():
        setattr(request, name, value)
    return request


def signed(pk: object) -> object:
    return SimpleNamespace(pk=pk, is_authenticated=True)


ANONYMOUS = SimpleNamespace(pk=None, is_authenticated=False)


def answer(request: HttpRequest) -> bytes:
    """Who a sync middleware's request acted for."""
    got = authz_dj.Middleware(respond)(request)
    assert isinstance(got, HttpResponse)
    return got.content


def aanswer(request: HttpRequest) -> bytes:
    """Who an async middleware's request acted for."""

    async def run() -> bytes:
        got = authz_dj.Middleware(arespond)(request)
        assert not isinstance(got, HttpResponse)
        return (await got).content

    return asyncio.run(run())


def test_who_a_request_is_by_default_is_request_user() -> None:
    with override_settings(ROWSTILE_USER=None):  # Django's request.user (django.contrib.auth's middleware sets it)
        assert answer(a_request(user=signed(7))) == b"7"
        assert answer(a_request(user=ANONYMOUS)) == b"nobody"
        assert answer(a_request()) == b"nobody"  # no auth middleware: nobody

        async def auser(user: object) -> object:
            return user

        assert aanswer(a_request(auser=lambda: auser(signed(8)))) == b"8"
        assert aanswer(a_request(auser=lambda: auser(ANONYMOUS))) == b"nobody"
        assert aanswer(a_request()) == b"nobody"


def test_who_a_request_is_may_be_any_function() -> None:
    async def service(request: HttpRequest) -> tuple[str, int]:
        return ("service", 1)

    def user(request: HttpRequest) -> int:
        return 5

    with override_settings(ROWSTILE_USER=user):  # the function itself, not its name
        assert answer(a_request()) == b"5"
        assert aanswer(a_request()) == b"5"
    with override_settings(ROWSTILE_USER=service):
        assert aanswer(a_request()) == b"service:1"
        with pytest.raises(ImproperlyConfigured, match="ROWSTILE_USER is async"):
            answer(a_request())


def test_the_middleware_needs_the_app() -> None:
    with (
        mock.patch.object(authz_dj.django_apps, "is_installed", return_value=False),
        pytest.raises(ImproperlyConfigured, match=re.escape('"rowstile.django" in INSTALLED_APPS')),
    ):
        authz_dj.Middleware(respond)


def test_what_the_middleware_leaves_to_django() -> None:
    mw = authz_dj.Middleware(respond)
    assert mw.process_exception(a_request(), ValueError("the app's")) is None


def test_an_async_view_signs_in_and_refusals_answer_the_same() -> None:
    async def run() -> list[Answer]:
        c = AsyncClient()
        listed = await c.get("/notes/async", headers={"x-user": "2"})
        refused = await c.patch("/notes/1", json.dumps({"body": "x"}), "application/json", headers={"x-user": "3"})
        return [listed.json(), refused.status_code, refused.json()["command"]]

    assert asyncio.run(run()) == [[2, 3], 403, "update"]


def test_a_streaming_response_streams_as_the_requests_user() -> None:
    sent = Client().get("/notes/streamed", headers={"x-user": "2"})
    assert isinstance(sent, StreamingHttpResponse) and rowstile.current() is None  # its content is made now
    assert json.loads(b"".join(cast(Iterator[bytes], sent.streaming_content))) == [2, 3]

    async def run() -> bytes:
        got = await AsyncClient().get("/notes/streamed/async", headers={"x-user": "2"})
        assert isinstance(got, StreamingHttpResponse)
        return b"".join([chunk async for chunk in cast(AsyncIterator[bytes], got.streaming_content)])

    assert json.loads(asyncio.run(run())) == [2, 3]


# --- the start-up check -------------------------------------------------------------------------------
@pytest.fixture
def unchecked() -> Iterator[None]:
    """The start-up check not yet run in this process."""
    checked = set(authz_dj._checked)
    authz_dj._checked.clear()
    try:
        yield
    finally:
        authz_dj._checked.update(checked)


def test_the_start_up_check_runs_once_and_leaves_no_connection_open(unchecked: None) -> None:
    connection.ensure_connection()
    authz_dj.Middleware(respond)
    assert authz_dj._checked == {"default"} and connection.connection is None  # closed after
    connection.ensure_connection()
    authz_dj.Middleware(respond)  # checked already: not again
    assert connection.connection is not None


@pytest.mark.django_db
def test_the_start_up_check_inside_a_tests_transaction_keeps_it(unchecked: None) -> None:
    authz_dj.Middleware(respond)
    assert connection.in_atomic_block and connection.connection is not None


def test_check_names_what_is_wrong() -> None:
    port = os.environ["ROWSTILE_OWNER_DSN"].rsplit(":", 1)[1].split("/")[0]  # the owner connects directly
    connections.settings["owner"] = {
        **connection.settings_dict,
        "USER": "conf_owner",
        "PASSWORD": "owner",
        "PORT": port,
    }
    try:
        assert authz_dj.connection_check("default") == []
        with pytest.raises(ConnectionProblem, match="an owner skips row-level security") as e:
            authz_dj.check("owner")
        assert "conf_owner" in e.value.problems[0]
    finally:
        connections["owner"].close()
        del connections["owner"]
        del connections.settings["owner"]


# --- writes that changed nothing, and queries by permission --------------------------------------------
def test_expect_and_save(data: str) -> None:
    with rowstile.acting_as(3):  # cy may edit note 4, not note 1
        assert authz_dj.expect(Note.objects.filter(pk=4).update(body="idea"), Note, "update", 4) == 1
        with pytest.raises(Refused) as refused:
            authz_dj.expect(Note.objects.filter(pk=1).update(body="x"), "notes", "update", 1)
        assert refused.value.message == "permission denied: user 3 may not update row 1 of public.notes"
        assert refused.value.why[0].startswith("no")
        with pytest.raises(NotFound):  # allowed, but the statement matched nothing for another reason
            authz_dj.expect(Note.objects.filter(pk=4, body="else").update(body="x"), Note, "update", 4, using="default")
        deleted = authz_dj.expect(Note.objects.filter(pk=4).delete(), Note, "delete", 4)
        assert deleted == (1, {"app.Note": 1})
        note = Note(project_id=1, author_id=3, body="idea")  # a new instance: inserted
        authz_dj.save(note)
        assert note.pk is not None and Note.objects.filter(pk=note.pk).exists()
        note.body = "a better one"
        authz_dj.save(note)
    with rowstile.acting_as(1):
        assert Note.objects.get(pk=note.pk).body == "a better one"
    with psycopg.connect(data, autocommit=True) as owner:  # as it was
        owner.execute("DELETE FROM notes WHERE id > 100")
        owner.execute("INSERT INTO notes (id, project_id, author_id, body) VALUES (4, 1, 3, 'idea')")


def test_queries_by_permission() -> None:
    queries = authz_dj.Queries[ObjectType, Permission]()
    with rowstile.acting_as(3):
        assert sorted(Project.objects.filter(id__in=queries.ids("project", "edit")).values_list("id", flat=True)) == [1]
        assert sorted(Project.objects.filter(id__in=authz_dj.ids("project", "view")).values_list("id", flat=True)) == [
            1,
            3,
        ]
        listed = authz_dj.ids("project", "view", key_type=None)
        assert listed.sql == "SELECT listed.id FROM authz.list(%s, %s) AS listed(id)"
        assert queries.can("project", 1, "edit") and not authz_dj.can("project", 2, "view")
        assert queries.perms_of("project", [1, 2, 3]) == {"1": ["edit", "view"], "2": [], "3": ["view"]}
        assert authz_dj.perms_of("project", []) == {}
    with rowstile.acting_as(("service", 1)):
        assert sorted(Folder.objects.values_list("id", flat=True)) == []  # a service owns no folder


def test_a_job_signs_in_whatever_runs_it() -> None:
    @rowstile.job(("service", 1))
    def count() -> int:
        return Project.objects.count()

    assert count() == 2
    with rowstile.acting_as(None):  # signed out on purpose: what anyone may see
        assert Project.objects.count() == 1
    assert rowstile.current() is None
    assert rowstile.Principal.of(("service", 1)) == Principal("service", "1")


def test_the_pytest_helpers_with_the_orm(
    as_user: AsUser, assert_refused: AssertRefused, assert_not_found: AssertNotFound
) -> None:
    """rowstile.testing's fixtures, on Django's errors: a refused insert, a refused update, a hidden row."""

    def edit(note_id: int) -> None:
        note = Note.objects.filter(pk=note_id).first()
        if note is None:
            raise NotFound("public.notes", note_id)
        note.body = "x"
        authz_dj.save(note, update_fields=["body"])

    with as_user(2):
        assert assert_refused(lambda: Note.objects.create(project_id=3, author_id=2, body="hi"), "insert").why
        assert_not_found(lambda: edit(1))
    with as_user(3):
        assert assert_refused(lambda: edit(1), command="update", table="public.notes").why
