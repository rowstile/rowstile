"""rowstile with FastAPI: one line.

    app = FastAPI()
    authz = Rowstile(app, engine, user=current_user)   # current_user(request): its user's id; before adding routes

Each request acts for user(request) (a user id, ("service", 3), a Principal, or None for nobody; it may be
async), so every transaction it begins on `engine` signs in as them. A refused write answers 403 with the
reason (an RFC 9457 problem body), a row the user can't see 404. A call the database turns down that is no refusal
answers as its code's page says, with its words: a login refused or a call that needs someone signed in 401 (AZ703,
AZ714), something it names that isn't there 404 too (AZ708: a share with someone who doesn't exist), an argument
missing or wrong 400 (AZ710), a move inside itself 409 (AZ713). An ORM update the rules allow that matched no row
(the row changed since it was read: a version counter) answers 409. At start-up the app refuses to run on a
connection that skips row-level security (authz.connection_check()), with or without a lifespan of its own.

An app on psycopg or asyncpg without SQLAlchemy passes no engine, Rowstile(app, None, user=...), and signs in with
rowstile.psycopg.transaction() or rowstile.asyncpg.transaction(): the drivers' errors are answered the same way
(there is no engine to check at start-up: rowstile.psycopg.problems(conn) and rowstile.asyncpg.problems(conn)).

user(request) runs in a middleware this adds: read the session or the token from the request itself. What a
middleware of the app's puts on request.state is there only if it was added after Rowstile(...) (Starlette
runs the one added last first). It may raise an HTTPException (a 401 for a bad token), which is answered as
it is. WebSockets are not signed in: use rowstile.acting_as() in the endpoint.
"""

from __future__ import annotations

import contextlib
import importlib
import inspect
from collections.abc import AsyncIterator, Awaitable, Callable, Mapping
from typing import TYPE_CHECKING, Any, TypeAlias, cast

from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm.exc import StaleDataError
from starlette.exceptions import HTTPException
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp, Receive, Scope, Send

from . import (
    ConnectionProblem,
    NotFound,
    NotSignedIn,
    Principal,
    Problem,
    Refused,
    Who,
    _current,
    call_problem,
    check_problems,
    not_signed_in,
    refusal,
)
from . import sqlalchemy as sa

if TYPE_CHECKING:
    from fastapi import FastAPI
    from sqlalchemy import Engine
    from sqlalchemy.ext.asyncio import AsyncEngine

# who a request acts for, from the request: a user id, ("service", 3), a Principal, or None; or an awaitable of one
UserOf: TypeAlias = "Callable[[Request], Who | Awaitable[Who]]"


class Rowstile:
    def __init__(
        self,
        app: FastAPI,
        engine: Engine | AsyncEngine | None = None,
        user: UserOf | None = None,
        check_connection: bool = True,
    ) -> None:
        self.app, self.engine, self.user = app, engine, user
        if engine is not None:
            sa.install(engine)
        app.add_middleware(_SignIn, user=user)
        app.add_exception_handler(Refused, _problem)
        app.add_exception_handler(NotFound, _problem)
        for error in _database_errors():
            app.add_exception_handler(error, _db_error)
        app.add_exception_handler(StaleDataError, _stale)
        if check_connection and engine is not None:
            # around the app's lifespan, whichever it has: Starlette runs "startup" handlers only when the app
            # was given no lifespan
            inner = app.router.lifespan_context

            @contextlib.asynccontextmanager
            async def checked(a: FastAPI) -> AsyncIterator[Mapping[str, Any]]:
                await self.check()
                async with inner(a) as state:
                    # what the app's own lifespan gave (its state, or nothing), as it gave it
                    yield cast("Mapping[str, Any]", state)

            app.router.lifespan_context = checked

    async def check(self) -> None:
        """Raises ConnectionProblem if the engine's connections skip row-level security."""
        if self.engine is None:
            return
        problems = check_problems(await sa.connection_check(self.engine))
        if problems:
            raise ConnectionProblem(problems)


class _SignIn:
    """Pure ASGI, so the principal set here is the one the endpoint (and its tasks) see."""

    def __init__(self, app: ASGIApp, user: UserOf | None = None) -> None:
        self.app, self.user = app, user

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        token = None
        if self.user is not None:
            try:
                got = self.user(Request(scope, receive))
                # user(request) gave who, or an awaitable of who (ty sees what it awaits as an object)
                who = cast("Who", await got) if inspect.isawaitable(got) else got
            except HTTPException as e:  # a bad token, say: this runs outside FastAPI's own handling
                answer = JSONResponse({"detail": e.detail}, status_code=e.status_code, headers=e.headers)
                return await answer(scope, receive, send)
            token = _current.set(Principal.of(who))
        try:
            await self.app(scope, receive, send)
        finally:
            if token is not None:
                _current.reset(token)


def _json(problem: Problem) -> JSONResponse:
    status = problem["status"]
    return JSONResponse(
        problem, status_code=status if isinstance(status, int) else 500, media_type="application/problem+json"
    )


async def _problem(request: Request, exc: Exception) -> Response:
    assert isinstance(exc, (Refused, NotFound))  # the handler of these two only
    return _json(exc.problem())


async def _db_error(request: Request, exc: Exception) -> Response:
    r = refusal(exc)
    if r is not None:
        return _json(r.problem())
    problem = call_problem(exc)
    if problem is not None:  # a share with someone who doesn't exist: 404; a negative page size: 400; ...
        return _json(problem)
    if not_signed_in(exc):  # the app's bug, not the user's doing: a 500 that says what
        how = (
            "rowstile.sqlalchemy.install(engine) does it; is this engine in AUTOCOMMIT, or the query on another "
            "connection?"
            if isinstance(exc, DBAPIError)
            else "rowstile.psycopg.transaction() and rowstile.asyncpg.transaction() do it"
        )
        raise NotSignedIn(
            f"a query ran in a transaction nobody signed in to: every transaction must begin with authz.act_as() ({how})"
        ) from exc
    raise exc


def _database_errors() -> list[type[Exception]]:
    """The errors a query raises: SQLAlchemy's, and psycopg's and asyncpg's own, for an app on the driver alone
    (Rowstile(app, None, user=...)), where they are installed."""
    errors: list[type[Exception]] = [DBAPIError]
    for module, name in (("psycopg", "Error"), ("asyncpg", "PostgresError")):
        try:
            errors.append(getattr(importlib.import_module(module), name))
        except ImportError:
            pass  # not installed: none of its errors to answer
    return errors


_CONFLICT: Problem = {
    "type": "https://rowstile.dev/problems/conflict",
    "title": "Conflict",
    "status": 409,
    "detail": "the row changed since it was read, and the rules allow the change: read it again",
}


async def _stale(request: Request, exc: Exception) -> Response:
    verdict = sa.why_stale_sync(exc)
    if verdict is not None:
        return _json(verdict.problem())
    if sa._rules_allow(exc):  # the row changed meanwhile (a version counter): the rules allow the change
        return _json(_CONFLICT)
    raise exc  # it can't tell (a model mapped to a join): the app's to answer
