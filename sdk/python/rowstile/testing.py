"""pytest fixtures for apps that use rowstile. Installing the package is enough: its pytest11 entry point loads
them (naming rowstile.testing in pytest_plugins too, pytest stops: it is loaded already).

    def test_bob_cannot_rename(client, as_user, assert_refused):
        with as_user(2):
            assert_refused(lambda: rename(note_id, "x"), command="update")

Environment: ROWSTILE_OWNER_URL (the tables' owner: migrations, test data) and ROWSTILE_APP_URL (the app's
role: what the app sees), both SQLAlchemy or libpq URLs, give the authz_owner_url and authz_app_url fixtures.
The fixtures' types, for annotating a test's arguments: AsUser, AssertRefused, AssertNotFound.

With an async function, await the helper in an async test: `await assert_refused(lambda: rename(note_id, "x"))`.
A test that never awaits it fails: the check runs only when it is awaited.

A database per worker: database_per_worker(owner_url) copies the migrated test database (with the policy) once
for each pytest-xdist worker, so tests that write don't meet each other.
"""

from __future__ import annotations

import importlib.util
import inspect
import os
import re
import urllib.parse
from collections.abc import Awaitable, Callable, Coroutine, Iterator, Mapping, Sequence
from contextlib import AbstractContextManager
from dataclasses import dataclass
from typing import Protocol, TypeVar, cast, overload

import pytest

from . import NotFound, Principal, Refused, Who, acting_as, refusal
from .command import command_dir

AsUser = Callable[[Who], AbstractContextManager["Principal | None"]]


@dataclass(frozen=True)
class WorkerDatabase:
    """A worker's own test database: its URL (the owner's), and the app role's if one was given."""

    url: str
    app_url: str | None = None


class _Connection(Protocol):
    def query(self, sql: str, args: Sequence[object] = ()) -> Sequence[Sequence[object]]: ...
    def script(self, sql: str) -> None: ...
    def close(self) -> None: ...


class _Postgres(Protocol):
    """What this module uses of the command's Postgres client (cli/pgwire.py)."""

    PgError: type[Exception]

    def parse_dsn(self, text: str | None) -> Mapping[str, object]: ...
    def connect(self, **settings: object) -> _Connection: ...


def _postgres() -> _Postgres:
    """The rowstile command's own Postgres client (standard library only), so copying a database needs no driver
    of the app's. Loaded from its file: nothing of the command becomes importable."""
    spec = importlib.util.spec_from_file_location("rowstile._pgwire", os.path.join(command_dir(), "pgwire.py"))
    assert spec is not None and spec.loader is not None  # a .py file's: its loader reads it, or says it isn't there
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return cast("_Postgres", module)


def worker_id() -> str:
    """This worker's number: pytest-xdist's (gw3 is "3"); "0" in a run without workers."""
    return re.sub(r"\D", "", os.environ.get("PYTEST_XDIST_WORKER", "")) or "0"


def _with_database(url: str, name: str) -> str:
    u = urllib.parse.urlsplit(url)
    return urllib.parse.urlunsplit(u._replace(path="/" + urllib.parse.quote(name, safe="")))


def database_per_worker(url: str, app_url: str | None = None, fresh: bool = True) -> WorkerDatabase:
    """A database for this worker, copied from `url`'s (migrated, with the policy): its URL, with the same user
    and in the same form (SQLAlchemy's or libpq's). The copy is made by a role that may create databases (the
    owner), while nothing else is connected to the original. A copy an earlier run left is made again, unless
    fresh=False. app_url: the app role's URL, returned for the copy.

        @pytest.fixture(scope="session")
        def worker_database() -> WorkerDatabase:
            return database_per_worker(os.environ["ROWSTILE_TESTS_URL"], app_url=os.environ["ROWSTILE_APP_URL"])
    """
    template = urllib.parse.unquote(urllib.parse.urlsplit(url).path.lstrip("/"))
    if not template:
        raise ValueError("database_per_worker needs a database to copy, and this URL names none")
    name = f"{template}_w{worker_id()}"

    def q(ident: str) -> str:
        return '"' + ident.replace('"', '""') + '"'

    pg = _postgres()
    # CREATE DATABASE ... TEMPLATE needs no one connected to the original, this connection included
    elsewhere = re.sub(r"^postgres(ql)?(\+\w+)?://", "postgresql://", _with_database(url, "postgres"))
    conn = pg.connect(**pg.parse_dsn(elsewhere))
    try:
        exists = bool(conn.query("SELECT 1 FROM pg_database WHERE datname = $1", [name]))
        if fresh or not exists:
            if exists:
                conn.script(f"DROP DATABASE {q(name)} WITH (FORCE)")
            try:
                conn.script(f"CREATE DATABASE {q(name)} TEMPLATE {q(template)}")
            except pg.PgError as e:
                # 55006: something is connected to the original (Postgres has waited five seconds for it to leave)
                if not str(e).startswith("55006"):
                    raise
                raise RuntimeError(
                    f"rowstile.testing: {template} can't be copied while anything is connected to it: close what "
                    "holds it (the app, a migration tool, a console). Where the service keeps a connection of its "
                    "own for minutes after yours (Neon does), a copy per worker can't be made: use one test "
                    "database, where each test rolls back, or a branch for each run"
                ) from e
    finally:
        conn.close()
    return WorkerDatabase(_with_database(url, name), _with_database(app_url, name) if app_url else None)


Raised = TypeVar("Raised", Refused, NotFound)
# what a helper returned for an async function, and that function's own awaitable: each must be awaited
_Pending = list[tuple[Coroutine[object, object, object], Awaitable[object]]]


class AssertRefused(Protocol):
    @overload
    def __call__(
        self, fn: Callable[[], Awaitable[object]], command: str | None = None, table: str | None = None
    ) -> Awaitable[Refused]: ...

    @overload
    def __call__(self, fn: Callable[[], object], command: str | None = None, table: str | None = None) -> Refused: ...


class AssertNotFound(Protocol):
    @overload
    def __call__(self, fn: Callable[[], Awaitable[object]]) -> Awaitable[NotFound]: ...

    @overload
    def __call__(self, fn: Callable[[], object]) -> NotFound: ...


@pytest.fixture
def as_user() -> AsUser:
    """as_user(42), as_user(("service", 3)), as_user(None): everything in the block acts for them."""
    return acting_as


def _raised(e: Exception, expected: type[Raised]) -> Raised:
    """e as the error expected, or e raised again: a driver's refusal counts as Refused."""
    if isinstance(e, expected):
        return e
    r = refusal(e)
    if r is not None and isinstance(r, expected):
        return r
    raise e


def _checked(
    fn: Callable[[], object], expected: type[Raised], what: str, check: Callable[[Raised], None], pending: _Pending
) -> Raised | Awaitable[Raised]:
    """fn() must raise `expected`: the error, checked; for an async function, an awaitable of it (in pending)."""
    try:
        out = fn()
    except Exception as e:
        err = _raised(e, expected)
        check(err)
        return err
    if not inspect.isawaitable(out):
        raise AssertionError(f"expected {what}, got {out!r}")
    inner = out

    async def later() -> Raised:
        try:
            got = await inner
        except Exception as e:
            err = _raised(e, expected)
            check(err)
            return err
        raise AssertionError(f"expected {what}, got {got!r}")

    checked = later()
    pending.append((checked, inner))
    return checked


def _never_awaited(helper: str, pending: _Pending) -> None:
    """At the end of the test: what the helper returned for an async function must have been awaited, or its check
    never ran. Fails the test if not (closing both, so Python doesn't warn of them as well)."""
    never = [
        (checked, inner) for checked, inner in pending if inspect.getcoroutinestate(checked) == inspect.CORO_CREATED
    ]
    for checked, inner in never:
        checked.close()
        getattr(inner, "close", lambda: None)()
    if never:
        pytest.fail(
            f"{helper}() was given an async function, and what it returned was never awaited, so the check never "
            "ran: await it",
            pytrace=False,
        )


@pytest.fixture
def assert_refused() -> Iterator[AssertRefused]:
    """assert_refused(fn, command=None, table=None): fn() must be refused by the policy; returns the Refused (for
    an async function, an awaitable of it, which the test must await)."""
    pending: _Pending = []

    def check(
        fn: Callable[[], object], command: str | None = None, table: str | None = None
    ) -> Refused | Awaitable[Refused]:
        def the_rule(err: Refused) -> None:
            if command:
                named = err.command is not None and err.command.startswith(command)
                assert named, f"expected the {command} rule to refuse it, but: {err.command}: {err.message}"
            if table:
                assert err.table == table, err.table

        return _checked(fn, Refused, "a refusal", the_rule, pending)

    yield cast("AssertRefused", check)
    _never_awaited("assert_refused", pending)


@pytest.fixture
def assert_not_found() -> Iterator[AssertNotFound]:
    """assert_not_found(fn): fn() must raise NotFound; returns it (for an async function, an awaitable of it, which
    the test must await)."""
    pending: _Pending = []

    def check(fn: Callable[[], object]) -> NotFound | Awaitable[NotFound]:
        return _checked(fn, NotFound, "NotFound", lambda err: None, pending)

    yield cast("AssertNotFound", check)
    _never_awaited("assert_not_found", pending)


@pytest.fixture
def authz_owner_url() -> str:
    url = os.environ.get("ROWSTILE_OWNER_URL")
    if not url:
        pytest.skip("ROWSTILE_OWNER_URL is not set")
    return url


@pytest.fixture
def authz_app_url() -> str:
    url = os.environ.get("ROWSTILE_APP_URL")
    if not url:
        pytest.skip("ROWSTILE_APP_URL is not set")
    return url
