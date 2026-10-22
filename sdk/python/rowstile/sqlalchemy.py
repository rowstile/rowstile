"""rowstile with SQLAlchemy 2 (sync and async engines, the ORM, SQLModel).

    engine = create_async_engine(url)
    rowstile.sqlalchemy.install(engine)           # every transaction signs in as rowstile.current()

Queries by permission use set checks, never a function call per row:

    select(Folder).where(Folder.id.in_(ids("folder", "edit")))
    await perms_of(session, "folder", [f.id for f in folders])      # {id: ["view", "edit"]}: a list's buttons

Queries[ObjectType, Permission]() has the same queries taking only the policy's names (the generated client's),
so a misspelled one doesn't type-check.

An ORM update of a row the user may not change matches no row, and SQLAlchemy raises StaleDataError. Before the
flush's transaction (or savepoint) is rolled back, the SDK asks the database about the flush's rows, in one
statement, in that transaction and as the same user: it sees what the transaction wrote, and needs no other
connection. why_stale(exc) gives the answer: NotFound (the row is hidden) or Refused (and why) for the first row
the database says no for. None when the rules allow every row (the row changed since it was read: a version
counter's conflict), or when it couldn't ask (a model mapped to a join names no one table). An ORM delete that
matches no row is only a warning in SQLAlchemy (an error with a version column alone): delete with Core's
delete() and expect().
"""

from __future__ import annotations

import sys
import typing
from collections.abc import Callable, Iterable, Sequence
from typing import TYPE_CHECKING, Any, Generic, TypeAlias, TypeVar

from sqlalchemy import (
    BigInteger,
    Connection,
    Engine,
    Select,
    Table,
    TextClause,
    cast,
    event,
    func,
    select,
    text,
)
from sqlalchemy.orm import Mapper, Session, object_session
from sqlalchemy.orm.exc import StaleDataError
from sqlalchemy.types import TypeEngine

from . import (
    NOBODY,
    Id,
    NotFound,
    Principal,
    Refused,
    Who,
    act_as_args,
    act_as_sql,
    answer,
    current,
    explain_rule_args,
    explain_rule_sql,
    key_text,
    verdict,
)

try:
    from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine, AsyncSession
except ImportError:
    # SQLAlchemy's asyncio needs greenlet, which SQLAlchemy 2.1 installs only when asked (sqlalchemy[asyncio]):
    # an app on the sync engine has neither, and needs neither
    if not TYPE_CHECKING:

        class AsyncEngine:
            """Stands in where SQLAlchemy's asyncio can't be loaded: no engine is one."""

        AsyncConnection = AsyncSession = AsyncEngine

AnyEngine = TypeVar("AnyEngine", bound="Engine | AsyncEngine")
Result = TypeVar("Result")
# the policy's names, as the generated client writes them (ObjectType, Permission): Queries
TypeName = TypeVar("TypeName", bound=str)
PermissionName = TypeVar("PermissionName", bound=str)

_users: dict[Engine, Callable[[], Who] | None] = {}  # each engine install() was given (the sync one): its user()
_orm_events = False
# a row an ORM flush updates or deletes: (the table, update or delete, the row's key)
_Row: TypeAlias = "tuple[str, str, tuple[object, ...]]"
_ROWS = "rowstile_rows"  # in a connection's info: the rows of the flush on it, as SQLAlchemy told them
_FLUSHING = "rowstile_flushing"  # in a session's info: a flush began, and its first row starts the rows again
_ASKED = "_rowstile_asked"  # on a StaleDataError: what the database said, NotFound or Refused; True: the rules allow


def install(engine: AnyEngine, user: Callable[[], Who] | None = None) -> AnyEngine:
    """Signs every transaction on `engine` in as whoever the code acts for (rowstile.acting_as, or the web
    integration), else as user() if given, else as nobody. When an ORM flush on it fails with StaleDataError, asks
    the database why, for why_stale(). Installing an engine again changes nothing, but gives it user() if it had
    none (Rowstile(app, engine) installs it without one); another user() than the one it has is a ValueError."""
    global _orm_events
    sync = engine.sync_engine if isinstance(engine, AsyncEngine) else engine
    if sync in _users:
        if user is not None and _users[sync] not in (None, user):
            raise ValueError("install(engine) was given another user() for this engine before: an engine has one")
        _users[sync] = _users[sync] or user
        return engine
    _users[sync] = user

    @event.listens_for(sync, "begin")
    def _sign_in(conn: Connection) -> None:
        conn.info[_ROWS] = []
        who = current()
        given = _users[sync]
        if who is None and given is not None:
            who = Principal.of(given())
        who = who or NOBODY
        # the id as a parameter where the driver takes them this way: psycopg reads % in a statement, so an id
        # written into it would be changed ('%s') or refused ('50%')
        style = conn.dialect.paramstyle
        if style in ("pyformat", "format"):
            conn.exec_driver_sql("SELECT authz.act_as(%s, %s)", act_as_args(who))
        elif style == "numeric_dollar":
            conn.exec_driver_sql("SELECT authz.act_as($1, $2)", act_as_args(who))
        else:
            conn.exec_driver_sql(act_as_sql(who))

    event.listen(sync, "rollback", _ask)
    event.listen(sync, "rollback_savepoint", _ask)
    if not _orm_events:
        _orm_events = True
        event.listen(Session, "before_flush", _flushing)
        event.listen(Mapper, "before_update", _remember("update"))
        event.listen(Mapper, "before_delete", _remember("delete"))
    return engine


def _flushing(session: Session, *_: object) -> None:
    session.info[_FLUSHING] = True


def _remember(command: str) -> Callable[[Mapper[Any], Connection, object], None]:
    def remember(mapper: Mapper[Any], connection: Connection, target: object) -> None:
        rows: list[_Row] | None = connection.info.get(_ROWS)
        if rows is None:
            return  # an engine install() wasn't given: nothing asks about its rows
        session = object_session(target)
        assert session is not None  # a row the session flushes
        if session.info.pop(_FLUSHING, False):
            rows.clear()  # the flush's first row: an earlier flush's rows aren't asked about
        table = mapper.local_table
        if not isinstance(table, Table):
            return  # mapped to a join or a query: no one table to ask about
        name = f"{table.schema}.{table.name}" if table.schema else table.name
        rows.append((name, command, mapper.primary_key_from_instance(target)))

    return remember


_EXPLAIN = explain_rule_sql("CAST(:t AS text)", ":c", ":k")
# each row's answer, in one statement, in the order of the rows
_EXPLAIN_EACH = text(
    "SELECT r.* FROM unnest(CAST(:t AS text[]), CAST(:c AS text[]), CAST(:k AS text[])) WITH ORDINALITY "
    "AS w(t, c, k, n) CROSS JOIN LATERAL (" + explain_rule_sql("w.t", "w.c", "w.k") + ") r ORDER BY w.n"
)


def _explain_sql(table: str, command: str, key: object) -> TextClause:
    t, c, k = explain_rule_args(table, command, key)
    return text(_EXPLAIN).bindparams(t=t, c=c, k=k)


def _last_run(rows: list[_Row]) -> list[_Row]:
    """The rows the failed statements were about: SQLAlchemy tells every row of a table before it sends that
    table's statements, so they are the last run of rows of one table and command."""
    start = len(rows)
    while start > 0 and rows[start - 1][:2] == rows[-1][:2]:
        start -= 1
    return rows[start:]


def _ask(conn: Connection, *_: object) -> None:
    """Before a transaction or a savepoint is rolled back because a flush failed with StaleDataError (an update or
    a delete matched no row): asks the database about the flush's rows, in that transaction, as the same user. The
    answer goes on the error, for why_stale()."""
    exc = sys.exc_info()[1]
    if not isinstance(exc, StaleDataError) or isinstance(getattr(exc, _ASKED, None), (NotFound, Refused)):
        return
    rows = _last_run(conn.info.get(_ROWS, []))
    if not rows:
        return  # nothing to ask about: a model mapped to a join
    asked = {"t": [r[0] for r in rows], "c": [r[1] for r in rows], "k": [key_text(r[2]) for r in rows]}
    try:
        answers = conn.execute(_EXPLAIN_EACH, asked).all()
    except Exception:
        return  # the error the app sees is the flush's: this one would hide it, and stop the rollback
    for (table, command, key), row in zip(rows, answers, strict=True):
        lines, who, named = answer(row)
        if not _allowed(lines):
            setattr(exc, _ASKED, verdict(table, command, key, lines, who, named))
            return
    setattr(exc, _ASKED, True)


def why_stale_sync(exc: BaseException) -> NotFound | Refused | None:
    """For a StaleDataError: NotFound (the user can't see the row) or Refused (they may not, and why), as the
    database said in the flush's own transaction. Returns the error to raise, or None: the rules allow every row
    of the flush (the row changed since it was read), or the SDK couldn't ask."""
    asked = getattr(exc, _ASKED, None)
    return asked if isinstance(asked, (NotFound, Refused)) else None


async def why_stale(exc: BaseException) -> NotFound | Refused | None:
    """why_stale_sync(exc), for code that awaits it."""
    return why_stale_sync(exc)


def _rules_allow(exc: BaseException) -> bool:
    """Whether the database said the rules allow every row of the flush that failed: not the rules' doing."""
    return getattr(exc, _ASKED, None) is True


def _allowed(lines: Sequence[str] | None) -> bool:
    """Whether authz.explain_rule's answer says the user may: this row of the flush isn't the one refused."""
    return bool(lines) and lines is not None and lines[0].lstrip().startswith("yes")


async def expect(
    session: AsyncSession | AsyncConnection, result: Result, table: str, command: str, key: object
) -> Result:
    """A Core UPDATE or DELETE's result: returned if it changed a row (rowcount), else NotFound or Refused,
    asked in the same transaction: delete(Note).where(Note.id == 7) that matched nothing, and why."""
    if getattr(result, "rowcount", 1):
        return result
    raise verdict(table, command, key, *answer((await session.execute(_explain_sql(table, command, key))).first()))


def expect_sync(session: Session | Connection, result: Result, table: str, command: str, key: object) -> Result:
    if getattr(result, "rowcount", 1):
        return result
    raise verdict(table, command, key, *answer(session.execute(_explain_sql(table, command, key)).first()))


# --- queries by permission ------------------------------------------------------------------------------
def ids(type_: str, perm: str, key_type: type[TypeEngine[Any]] | TypeEngine[Any] | None = BigInteger) -> Select[Any]:
    """The ids the signed-in user holds `perm` on, as a subquery: Folder.id.in_(ids("folder", "edit")).
    key_type: the key's SQL type, which the ids are cast to: BigInteger by default, Uuid for a uuid key, None for a
    text key (the ids as authz.list gives them, text). A key of several columns has no one type: its ids are the
    rows' text, so join authz.list on that text instead."""
    listed = func.authz.list(type_, perm).table_valued("id").render_derived(name="authz_ids")
    col = listed.c.id if key_type is None else cast(listed.c.id, key_type)
    return select(col)


async def can(session: AsyncSession | AsyncConnection, type_: str, id_: Id, perm: str) -> bool:
    return bool(await session.scalar(select(func.authz.can(type_, str(id_), perm))))


def can_sync(session: Session | Connection, type_: str, id_: Id, perm: str) -> bool:
    return bool(session.scalar(select(func.authz.can(type_, str(id_), perm))))


_PERMS_OF = text("SELECT id, perms FROM authz.perms_of(:t, CAST(:ids AS text[]))")


async def perms_of(session: AsyncSession | AsyncConnection, type_: str, ids_: Iterable[Id]) -> dict[str, list[str]]:
    """{id: [permissions]} for many objects in one call (a list's buttons)."""
    rows = (await session.execute(_PERMS_OF.bindparams(t=type_, ids=[str(i) for i in ids_]))).all()
    return {r[0]: list(r[1] or []) for r in rows}


def perms_of_sync(session: Session | Connection, type_: str, ids_: Iterable[Id]) -> dict[str, list[str]]:
    rows = session.execute(_PERMS_OF.bindparams(t=type_, ids=[str(i) for i in ids_])).all()
    return {r[0]: list(r[1] or []) for r in rows}


class Queries(Generic[TypeName, PermissionName]):
    """The queries by permission, taking only the policy's names, so a misspelled type or permission doesn't
    type-check. The names are the generated client's (rowstile client py):

        from app.authz_client import ObjectType, Permission
        queries = Queries[ObjectType, Permission]()
        select(Folder).where(Folder.id.in_(queries.ids("folder", "edit")))

    Each method is the function of the same name."""

    def ids(
        self,
        type_: TypeName,
        perm: PermissionName,
        key_type: type[TypeEngine[Any]] | TypeEngine[Any] | None = BigInteger,
    ) -> Select[Any]:
        return ids(type_, perm, key_type)

    async def can(
        self, session: AsyncSession | AsyncConnection, type_: TypeName, id_: Id, perm: PermissionName
    ) -> bool:
        return await can(session, type_, id_, perm)

    def can_sync(self, session: Session | Connection, type_: TypeName, id_: Id, perm: PermissionName) -> bool:
        return can_sync(session, type_, id_, perm)

    async def perms_of(
        self, session: AsyncSession | AsyncConnection, type_: TypeName, ids_: Iterable[Id]
    ) -> dict[str, list[PermissionName]]:
        return typing.cast("dict[str, list[PermissionName]]", await perms_of(session, type_, ids_))

    def perms_of_sync(
        self, session: Session | Connection, type_: TypeName, ids_: Iterable[Id]
    ) -> dict[str, list[PermissionName]]:
        return typing.cast("dict[str, list[PermissionName]]", perms_of_sync(session, type_, ids_))


async def connection_check(engine: Engine | AsyncEngine) -> list[tuple[str, str]]:
    """authz.connection_check()'s rows (severity, problem) for this engine's connections."""
    query = text("SELECT severity, problem FROM authz.connection_check()")
    if isinstance(engine, AsyncEngine):
        async with engine.connect() as aconn:
            rows = (await aconn.execute(query)).all()
            await aconn.rollback()
    else:
        with engine.connect() as conn:
            rows = conn.execute(query).all()
            conn.rollback()
    return [(r[0], r[1]) for r in rows]
