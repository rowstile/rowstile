"""rowstile with Django (a preview: it may change in any release). Django 5.2 or newer, on psycopg 3.

    INSTALLED_APPS = [..., "rowstile.django"]     # every transaction on Django's connections signs in
    MIDDLEWARE = [..., "rowstile.django.Middleware"]  # each request acts for its user (after AuthenticationMiddleware)
    ROWSTILE_USER = "app.auth.session_user"       # who a request acts for (left out: request.user)

Every transaction on a Django connection signs in as whoever the code acts for: the request's user (the
middleware), a job's principal (@rowstile.job), or rowstile.acting_as()'s. An atomic block signs in when it begins,
ATOMIC_REQUESTS or not; a query outside one is a transaction of its own, and signs in the same way. The sign-in
lasts the transaction, so a persistent connection (CONN_MAX_AGE) or a pooled one (OPTIONS["pool"]) carries no
one into the next request, and a streaming response acts for the request's user while it is sent. Code that acts for
no one (a management command, a migration as the tables' owner) signs nothing in: a query on a table with rules then
fails, saying how (AZ701).

A refused write answers 403 with the reason (an RFC 9457 problem body), and a row the user can't see 404, as
rowstile.fastapi does: raise NotFound, and give an update or a delete that changed nothing to expect(), or save an
instance with save(). A call the database turns down that is no refusal answers as its code's page says (AZ703 and
AZ714 401, AZ708 404, AZ710 400, AZ713 409). The middleware refuses to start on a connection that skips row-level
security (authz.connection_check(); ROWSTILE_CHECK_DATABASES, ["default"] if left out, names the aliases).
"""

from __future__ import annotations

import inspect
import re
from collections.abc import AsyncIterable, AsyncIterator, Awaitable, Callable, Iterable, Iterator
from typing import TYPE_CHECKING, Any, Generic, Literal, TypeAlias, TypeVar, cast

from asgiref.sync import iscoroutinefunction, markcoroutinefunction
from django.apps import apps as django_apps
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.db import DEFAULT_DB_ALIAS, DatabaseError, connections, router, transaction
from django.db.models import Model
from django.db.models.expressions import RawSQL
from django.http import HttpRequest, HttpResponse, JsonResponse, StreamingHttpResponse
from django.utils.module_loading import import_string

from .. import (
    ConnectionProblem,
    Id,
    NotFound,
    NotSignedIn,
    Principal,
    Problem,
    Refused,
    Who,
    _answer,
    _call_problem,
    _check_problems,
    _current,
    _explain_rule_args,
    _explain_rule_sql,
    act_as_args,
    current,
    not_signed_in,
    refusal,
    verdict,
)

if TYPE_CHECKING:
    from django.db.backends.base.base import BaseDatabaseWrapper

# who a request acts for, from the request: a user id, ("service", 3), a Principal, or None; or an awaitable of one
UserOf: TypeAlias = "Callable[[HttpRequest], Who | Awaitable[Who]]"
Changed = TypeVar("Changed", int, "tuple[int, dict[str, int]]")
Response = TypeVar("Response")
# the policy's names, as the generated client writes them (ObjectType, Permission): Queries
TypeName = TypeVar("TypeName", bound=str)
PermissionName = TypeVar("PermissionName", bound=str)
KeyType: TypeAlias = "Literal['bigint', 'integer', 'uuid'] | None"
_Args: TypeAlias = "tuple[str | None, str | None]"
_Execute: TypeAlias = "Callable[[str, Any, bool, dict[str, Any]], Any]"

_ACT_AS = "SELECT authz.act_as(%s, %s)"
_EXPLAIN = _explain_rule_sql("%(t)s", "%(c)s", "%(k)s")
_SIGNED = "_rowstile_signed_in"  # on the driver's connection: who its open transaction was signed in as
_STALE: _Args = ("", "")  # ... not known any more: a ROLLBACK TO SAVEPOINT may have undone the last sign-in
_ROLLBACK = re.compile(r"\s*ROLLBACK\b", re.IGNORECASE)
_checked: set[str] = set()  # the aliases authz.connection_check() found fine, in this process


# --- every transaction signed in ----------------------------------------------------------------------
def _sign_in(execute: _Execute, sql: str, params: object, many: bool, context: dict[str, Any]) -> object:
    """Django's execute wrapper: before a statement, its transaction is signed in as whoever the code acts for
    now. A statement outside a transaction (Django's autocommit) runs in one of its own, signed in first."""
    from psycopg import pq

    db: BaseDatabaseWrapper = context["connection"]
    raw = db.connection
    who = current()
    status = raw.info.transaction_status
    if status == pq.TransactionStatus.IDLE:
        setattr(raw, _SIGNED, None)
        if who is None:  # nobody said who: the database refuses what needs to know (AZ701)
            return execute(sql, params, many, context)
        args = act_as_args(who)
        if raw.autocommit:  # outside an atomic block: this statement is a transaction of its own
            with db.wrap_database_errors, raw.transaction():
                raw.execute(_ACT_AS, args)
                return execute(sql, params, many, context)
        with db.wrap_database_errors:
            raw.execute(_ACT_AS, args)  # it begins the transaction the atomic block opened
        setattr(raw, _SIGNED, args)
    elif status == pq.TransactionStatus.INTRANS:
        signed: _Args | None = getattr(raw, _SIGNED, None)
        # who the code acts for changed inside the transaction (acting_as in an atomic block, or after it): the
        # statements from here on act for them, and for nobody once no one is named
        if signed is not None or who is not None:
            args = act_as_args(who)
            if args != signed:
                with db.wrap_database_errors:
                    raw.execute(_ACT_AS, args)
                setattr(raw, _SIGNED, args)
    result = execute(sql, params, many, context)
    if _ROLLBACK.match(sql):
        setattr(raw, _SIGNED, _STALE)
    return result


def _install(sender: object, connection: BaseDatabaseWrapper, **kwargs: object) -> None:
    """connection_created: the sign-in goes first among the connection's execute wrappers, once."""
    if connection.vendor != "postgresql":
        return  # only Postgres has the policy
    if type(connection.connection).__module__.split(".")[0] != "psycopg":
        raise ImproperlyConfigured("rowstile.django needs psycopg 3 (pip install 'psycopg[binary]'), not psycopg2")
    if _sign_in not in connection.execute_wrappers:
        connection.execute_wrappers.insert(0, _sign_in)


# --- the start-up check -------------------------------------------------------------------------------
def connection_check(using: str = DEFAULT_DB_ALIAS) -> list[tuple[str, str]]:
    """authz.connection_check()'s rows (severity, problem) for this alias's connection."""
    with connections[using].cursor() as cursor:
        cursor.execute("SELECT severity, problem FROM authz.connection_check()")
        return [(str(r[0]), str(r[1])) for r in cursor.fetchall()]


def check(using: str = DEFAULT_DB_ALIAS) -> None:
    """Raises ConnectionProblem if this alias's connection skips row-level security (or worse)."""
    problems = _check_problems(connection_check(using))
    if problems:
        raise ConnectionProblem(problems)


def _check_at_start() -> None:
    """Each alias ROWSTILE_CHECK_DATABASES names, once a process: a worker that would skip row-level security
    doesn't start. The connection is closed after, unless a transaction holds it (a test's)."""
    for alias in getattr(settings, "ROWSTILE_CHECK_DATABASES", [DEFAULT_DB_ALIAS]):
        if alias in _checked:
            continue
        check(alias)
        _checked.add(alias)
        if not connections[alias].in_atomic_block:
            connections[alias].close()


# --- the middleware -----------------------------------------------------------------------------------
def _request_user(request: HttpRequest) -> Who:
    """request.user (django.contrib.auth): its key if signed in, else None (nobody)."""
    user = getattr(request, "user", None)
    return user.pk if user is not None and user.is_authenticated else None


async def _arequest_user(request: HttpRequest) -> Who:
    auser = getattr(request, "auser", None)
    if auser is None:
        return None  # no AuthenticationMiddleware: nobody
    user = await auser()
    return user.pk if user.is_authenticated else None


class Middleware:
    """Each request acts for user(request) (ROWSTILE_USER: a function or its dotted path; left out, request.user), so
    every transaction it begins signs in as them; refusals and hidden rows answer 403 and 404. Sync and async."""

    sync_capable = True
    async_capable = True

    def __init__(self, get_response: Callable[[HttpRequest], Any]) -> None:
        if not django_apps.is_installed("rowstile.django"):
            raise ImproperlyConfigured(
                'rowstile.django.Middleware signs requests in, and "rowstile.django" in INSTALLED_APPS signs their '
                "transactions in: add it there"
            )
        self.get_response = get_response
        given = getattr(settings, "ROWSTILE_USER", None)
        self.user: UserOf | None = import_string(given) if isinstance(given, str) else given
        self.is_async = iscoroutinefunction(get_response)
        if self.is_async:
            markcoroutinefunction(cast("Any", self))
        _check_at_start()

    def __call__(self, request: HttpRequest) -> HttpResponse | Awaitable[HttpResponse]:
        if self.is_async:
            return self.__acall__(request)
        got = _request_user(request) if self.user is None else self.user(request)
        if inspect.isawaitable(got):
            getattr(got, "close", lambda: None)()  # never awaited: closed, so Python doesn't warn of it as well
            raise ImproperlyConfigured("ROWSTILE_USER is async: serve the app with ASGI, or make it a plain function")
        who = Principal.of(got)
        token = _current.set(who)
        try:
            return _streaming_as(who, self.get_response(request))
        finally:
            _current.reset(token)

    async def __acall__(self, request: HttpRequest) -> HttpResponse:
        got = await _arequest_user(request) if self.user is None else self.user(request)
        # user(request) gave who, or an awaitable of who (ty sees what it awaits as an object)
        who = Principal.of(cast("Who", await got) if inspect.isawaitable(got) else got)
        token = _current.set(who)
        try:
            return _streaming_as(who, await self.get_response(request))
        finally:
            _current.reset(token)

    def process_exception(self, request: HttpRequest, exception: Exception) -> HttpResponse | None:
        if isinstance(exception, (Refused, NotFound)):
            return _response(exception.problem())
        if not isinstance(exception, DatabaseError):
            return None
        refused = refusal(exception)
        if refused is not None:
            return _response(refused.problem())
        problem = _call_problem(exception)
        if problem is not None:  # a share with someone who doesn't exist: 404; a negative page size: 400; ...
            return _response(problem)
        if not_signed_in(exception):  # the app's bug, not the user's doing: a 500 that says what
            raise NotSignedIn(
                "a query ran in a transaction nobody signed in to: every transaction must begin with authz.act_as() "
                '("rowstile.django" in INSTALLED_APPS does it on Django\'s connections; is this query on another '
                "connection, or in a thread the request started?)"
            ) from exception
        return None


def _streaming_as(who: Principal, response: Response) -> Response:
    """A streaming response's content is made after the view returns, as it is sent: it acts for the request's user
    all the same, each chunk (its queries) signed in as them."""
    if not isinstance(response, StreamingHttpResponse):
        return response
    content = response.streaming_content
    if isinstance(content, AsyncIterable):
        chunks = aiter(content)

        async def each_async() -> AsyncIterator[object]:
            while True:
                token = _current.set(who)
                try:
                    chunk = await anext(chunks)
                except StopAsyncIteration:
                    return
                finally:
                    _current.reset(token)
                yield chunk

        response.streaming_content = each_async()
    else:
        it = iter(content)

        def each() -> Iterator[object]:
            while True:
                token = _current.set(who)
                try:
                    chunk = next(it)
                except StopIteration:
                    return
                finally:
                    _current.reset(token)
                yield chunk

        response.streaming_content = each()
    return response


def _response(problem: Problem) -> JsonResponse:
    status = problem["status"]
    return JsonResponse(
        problem, status=status if isinstance(status, int) else 500, content_type="application/problem+json"
    )


# --- writes that changed nothing ----------------------------------------------------------------------
def _table(model: type[Model] | str) -> str:
    return model if isinstance(model, str) else model._meta.db_table


def _verdict(using: str, table: str, command: str, key: object) -> NotFound | Refused:
    """What an update or a delete of this row that changed nothing was, asked of the database as the same user."""
    t, c, k = _explain_rule_args(table, command, key)
    with connections[using].cursor() as cursor:
        cursor.execute(_EXPLAIN, {"t": t, "c": c, "k": k})
        row = cursor.fetchone()
    return verdict(table, command, key, *_answer(row))


def expect(changed: Changed, model: type[Model] | str, command: str, key: object, using: str | None = None) -> Changed:
    """An update's or a delete's result (QuerySet.update()'s count, delete()'s pair): returned if it changed a row,
    else NotFound (the row is hidden, or didn't match) or Refused (the user may not, and why), raised.

        expect(Note.objects.filter(pk=7).update(body=body), Note, "update", 7)"""
    count = changed if isinstance(changed, int) else changed[0]
    if count:
        return changed
    db = using or (DEFAULT_DB_ALIAS if isinstance(model, str) else router.db_for_write(model))
    raise _verdict(db, _table(model), command, key)


def save(instance: Model, update_fields: Iterable[str] | None = None, using: str | None = None) -> None:
    """instance.save(), for an instance read from the database: an update, never an insert. Django's own save()
    inserts the row when its update changed nothing, which a refused update does; here it raises NotFound (the row
    is hidden) or Refused (the user may not, and why), asked in the same transaction. A new instance is inserted."""
    if instance._state.adding:
        instance.save(using=using)
        return
    db = using or instance._state.db or router.db_for_write(type(instance))
    with transaction.atomic(using=db):
        try:
            with transaction.atomic(using=db):  # a savepoint: Django's own error leaves the transaction as it was
                instance.save(using=db, force_update=True, update_fields=update_fields)
        except DatabaseError as e:
            if e.__cause__ is not None:
                raise  # the database's own error (the new row refused: a 403 of its own)
            # Django's: the update changed no row
            raise _verdict(db, _table(type(instance)), "update", instance.pk) from None


# --- queries by permission ----------------------------------------------------------------------------
def ids(type_: str, perm: str, key_type: KeyType = "bigint") -> RawSQL:
    """The ids the signed-in user holds `perm` on, as a subquery: Project.objects.filter(id__in=ids("project",
    "edit")). key_type: the key's SQL type, which the ids are cast to; None for a text key (authz.list's own)."""
    column = "listed.id" if key_type is None else f"CAST(listed.id AS {key_type})"
    return RawSQL(f"SELECT {column} FROM authz.list(%s, %s) AS listed(id)", (type_, perm))


def can(type_: str, id_: Id, perm: str, using: str = DEFAULT_DB_ALIAS) -> bool:
    with connections[using].cursor() as cursor:
        cursor.execute("SELECT authz.can(%s, %s, %s)", [type_, str(id_), perm])
        row = cursor.fetchone()
    return bool(row and row[0])


def perms_of(type_: str, ids_: Iterable[Id], using: str = DEFAULT_DB_ALIAS) -> dict[str, list[str]]:
    """{id: [permissions]} for many objects in one call (a list's buttons)."""
    with connections[using].cursor() as cursor:
        cursor.execute("SELECT id, perms FROM authz.perms_of(%s, CAST(%s AS text[]))", [type_, [str(i) for i in ids_]])
        return {str(r[0]): [str(p) for p in r[1] or []] for r in cursor.fetchall()}


class Queries(Generic[TypeName, PermissionName]):
    """The queries by permission, taking only the policy's names, so a misspelled type or permission doesn't
    type-check. The names are the generated client's (rowstile client py):

        from app.authz_client import ObjectType, Permission
        queries = Queries[ObjectType, Permission]()
        Project.objects.filter(id__in=queries.ids("project", "edit"))

    Each method is the function of the same name."""

    def ids(self, type_: TypeName, perm: PermissionName, key_type: KeyType = "bigint") -> RawSQL:
        return ids(type_, perm, key_type)

    def can(self, type_: TypeName, id_: Id, perm: PermissionName, using: str = DEFAULT_DB_ALIAS) -> bool:
        return can(type_, id_, perm, using)

    def perms_of(
        self, type_: TypeName, ids_: Iterable[Id], using: str = DEFAULT_DB_ALIAS
    ) -> dict[str, list[PermissionName]]:
        return cast("dict[str, list[PermissionName]]", perms_of(type_, ids_, using))


__all__ = [
    "Middleware",
    "Queries",
    "can",
    "check",
    "connection_check",
    "expect",
    "ids",
    "perms_of",
    "save",
]
