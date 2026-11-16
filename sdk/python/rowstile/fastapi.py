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
It needs no SQLAlchemy installed.

user(request) runs in a middleware this adds: read the session or the token from the request itself. What a
middleware of the app's puts on request.state is there only if it was added after Rowstile(...) (Starlette
runs the one added last first). It may raise an HTTPException (a 401 for a bad token), which is answered as
it is. WebSockets are not signed in: use rowstile.acting_as() in the endpoint.

    authz.mount_scim("/scim/v2")      # an identity provider's users and groups (SCIM), answered by the database

An identity provider's requests under that address are passed to authz.scim and its answers sent back; an API key
of the principal authz.set_scim names is their bearer token, and user(request) isn't asked about them.
"""

from __future__ import annotations

import contextlib
import importlib
import inspect
import json
import logging
import urllib.parse
from collections.abc import AsyncIterator, Awaitable, Callable, Mapping, Sequence
from typing import TYPE_CHECKING, Any, TypeAlias, cast

from starlette.concurrency import run_in_threadpool
from starlette.exceptions import HTTPException
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route
from starlette.types import ASGIApp, Receive, Scope, Send

from . import (
    ConnectionProblem,
    NotFound,
    NotSignedIn,
    Principal,
    Problem,
    Refused,
    Who,
    _call_problem,
    _check_problems,
    _current,
    not_signed_in,
    refusal,
)

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
        self.engine = engine
        self._app = app
        # where an identity provider's requests come in (mount_scim()): the middleware reads it at each request
        self._provisioning: list[str] = []
        if engine is not None:
            from . import sqlalchemy as sa

            sa.install(engine)
        app.add_middleware(_SignIn, user=user, provisioning=self._provisioning)
        app.add_exception_handler(Refused, _problem)
        app.add_exception_handler(NotFound, _problem)
        for error in _database_errors():
            app.add_exception_handler(error, _db_error)
        try:
            from sqlalchemy.orm.exc import StaleDataError
        except ImportError:
            pass  # no SQLAlchemy (an app on psycopg or asyncpg alone): no ORM flush to answer for
        else:
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
        from . import sqlalchemy as sa

        problems = _check_problems(await sa.connection_check(self.engine))
        if problems:
            raise ConnectionProblem(problems)

    def mount_scim(self, prefix: str = "/scim/v2") -> None:
        """Answers an identity provider's SCIM requests (Okta, Microsoft Entra ID) under `prefix`: give the provider
        that address, and an API key of the principal authz.set_scim names as its bearer token.

        Each request is passed to the database (authz.scim) and its answer sent back: the status, the body as
        application/scim+json, and for what was made its address (Location). The token alone says who asks:
        user(request) isn't asked about these requests, an app-wide dependency doesn't run for them, and their
        transaction signs nobody in, so a session the request also carries counts for nothing. The body goes on
        unread: the database says when it is no JSON, once it knows who asks. Only a request that is no text (bytes
        that are no UTF-8, a NUL) is answered here, 400. An error (settings that no longer hold, the app's function
        failing, the database away) is answered 500 in SCIM's words and logged with its traceback (the logger
        "rowstile"): the app's to see, not the provider's.

        It asks on the engine, so an app without one (Rowstile(app, None)) writes its own route: authz.scim's five
        arguments in, its status, body and location out."""
        engine = self.engine
        if engine is None:
            raise ValueError(
                "Rowstile(app, None) has no engine to ask the database on: pass the request to authz.scim in a route "
                "of your own (the method, the path below the route, the query string, the body, the bearer token)"
            )
        from sqlalchemy import Engine

        from . import sqlalchemy as sa

        mount = prefix.rstrip("/")
        # (at the app's root every request would be a provider's, and user(request) never asked)
        if not mount.startswith("/"):
            raise ValueError(
                f"mount_scim({prefix!r}): give the address a provider's requests come in under, as /scim/v2"
            )
        name = f"rowstile scim {mount}"

        async def provisioning(request: Request) -> Response:
            raw = await request.body()
            scheme, _, token = request.headers.get("authorization", "").partition(" ")
            try:
                asked = (
                    request.method,
                    str(request.path_params["path"]),
                    request.url.query,
                    raw.decode() if raw else None,  # as it was sent: the database reads it, once it knows who asks
                    token.strip() if scheme.lower() == "bearer" else None,
                )
                if any("\x00" in part for part in asked if part is not None):
                    raise ValueError("a NUL, which no text of the database holds")
            except ValueError:  # that, or bytes that are no UTF-8: nothing to pass on
                return Response(_SCIM_NO_TEXT, 400, media_type=_SCIM)
            try:
                if isinstance(engine, Engine):  # a sync engine's call, in a thread: the loop goes on meanwhile
                    status, said, location = await run_in_threadpool(sa.scim_sync, engine, *asked)
                else:
                    status, said, location = await sa.scim(engine, *asked)
            except Exception:
                _log.exception("authz.scim failed (%s %r)", asked[0], asked[1])
                return Response(_SCIM_FAILED, 500, media_type=_SCIM)
            headers: dict[str, str] = {}
            if location is not None:  # what was made: the mount's own address, then where the database says it is
                headers["Location"] = str(request.url_for(name, path="")) + urllib.parse.quote(location)
            if status == 401:
                headers["WWW-Authenticate"] = "Bearer"
            return Response(said, status, headers, media_type=None if said is None else _SCIM)

        self._provisioning.append(mount + "/")
        # Starlette's own route, not FastAPI's: no dependency of the app's runs for it, and it is in no OpenAPI page
        self._app.router.routes.append(
            Route(mount + "/{path:path}", provisioning, methods=["GET", "POST", "PUT", "PATCH", "DELETE"], name=name)
        )


_log = logging.getLogger("rowstile")
_SCIM = "application/scim+json"
# the two answers a route gives by itself, in SCIM's words (RFC 7644, 3.12): every other one is the database's
_SCIM_NO_TEXT = json.dumps(
    {
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
        "status": "400",
        "scimType": "invalidSyntax",
        "detail": "the request is no text: bytes that are no UTF-8, or a NUL",
    }
)
_SCIM_FAILED = json.dumps(
    {
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
        "status": "500",
        "detail": "the request failed: the app's log says why",
    }
)


class _SignIn:
    """Pure ASGI, so the principal set here is the one the endpoint (and its tasks) see."""

    def __init__(self, app: ASGIApp, user: UserOf | None = None, provisioning: Sequence[str] = ()) -> None:
        self.app, self.user, self.provisioning = app, user, provisioning

    def _provider(self, scope: Scope) -> bool:
        """Whether the request is an identity provider's (under a mount of Rowstile.mount_scim): user(request)
        isn't asked about those. An app mounted in another gets its path whole or without the outer mount, as
        Starlette's version has it: both are looked at."""
        path, root = str(scope["path"]), str(scope.get("root_path", ""))
        return any(path.startswith((mount, root + mount)) for mount in self.provisioning)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        token = None
        if self.user is not None and not self._provider(scope):
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
    problem = _call_problem(exc)
    if problem is not None:  # a share with someone who doesn't exist: 404; a negative page size: 400; ...
        return _json(problem)
    if not_signed_in(exc):  # the app's bug, not the user's doing: a 500 that says what
        how = (
            "rowstile.sqlalchemy.install(engine) does it; is this engine in AUTOCOMMIT, or the query on another "
            "connection?"
            if type(exc).__module__ == "sqlalchemy.exc"  # SQLAlchemy's error: the query was on an engine
            else "rowstile.psycopg.transaction() and rowstile.asyncpg.transaction() do it"
        )
        raise NotSignedIn(
            f"a query ran in a transaction nobody signed in to: every transaction must begin with authz.act_as() ({how})"
        ) from exc
    raise exc


def _database_errors() -> list[type[Exception]]:
    """The errors a query raises: SQLAlchemy's, and psycopg's and asyncpg's own, for an app on the driver alone
    (Rowstile(app, None, user=...)), where they are installed."""
    errors: list[type[Exception]] = []
    for module, name in (("sqlalchemy.exc", "DBAPIError"), ("psycopg", "Error"), ("asyncpg", "PostgresError")):
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
    from . import sqlalchemy as sa

    verdict = sa.why_stale_sync(exc)
    if verdict is not None:
        return _json(verdict.problem())
    if sa._rules_allow(exc):  # the row changed meanwhile (a version counter): the rules allow the change
        return _json(_CONFLICT)
    raise exc  # it can't tell (a model mapped to a join): the app's to answer
