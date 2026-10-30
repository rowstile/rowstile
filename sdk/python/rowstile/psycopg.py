"""rowstile with psycopg 3, without SQLAlchemy.

    with rowstile.psycopg.transaction(conn, 42):              # BEGIN; SELECT authz.act_as('user', '42')
        conn.execute("UPDATE app.notes SET body = %s WHERE id = %s", (body, note_id))

    async with rowstile.psycopg.atransaction(aconn):          # as rowstile.current(), or nobody
        ...

A pooled connection never carries one request's user into another's: the sign-in ends with the transaction.
A sign-in lasts the database transaction, so a transaction is one principal's. A block inside another for the
same principal is a savepoint. A block for someone else (or, with no `who`, for code that acts for no one) is
refused with a RuntimeError before anything is sent, the transaction left as it was: run it after, or on another
connection. So is a block inside a transaction no block began (psycopg opens one at the first statement unless
autocommit is on), whose sign-in can't be known.
"""

from __future__ import annotations

import contextlib
from collections.abc import AsyncIterator, Iterator
from typing import TYPE_CHECKING, Any, TypeVar

from . import (
    _UNSET,
    NOBODY,
    Principal,
    Who,
    _answer,
    _begins,
    _check_problems,
    _explain_rule_args,
    _explain_rule_sql,
    _for,
    _Unset,
    act_as_args,
    verdict,
)

if TYPE_CHECKING:
    import psycopg

Conn = TypeVar("Conn", bound="psycopg.Connection[Any]")
AsyncConn = TypeVar("AsyncConn", bound="psycopg.AsyncConnection[Any]")
Result = TypeVar("Result")

_ACT_AS = "SELECT authz.act_as(%s, %s)"
_EXPLAIN = _explain_rule_sql("%(t)s", "%(c)s", "%(k)s")
_SIGNED = "_rowstile_signed_in"  # on the connection: who each open block of ours signed in as, outermost first


def _open(conn: psycopg.Connection[Any] | psycopg.AsyncConnection[Any]) -> bool:
    """Whether a transaction is open on the connection."""
    from psycopg import pq

    return conn.info.transaction_status != pq.TransactionStatus.IDLE


def _blocks(conn: object) -> list[Principal]:
    blocks: list[Principal] | None = getattr(conn, _SIGNED, None)
    if blocks is None:
        blocks = []
        setattr(conn, _SIGNED, blocks)
    return blocks


@contextlib.contextmanager
def transaction(conn: Conn, who: Who | _Unset = _UNSET) -> Iterator[Conn]:
    """A transaction signed in as `who` (None: nobody; left out: whoever the code acts for now, nobody if unset).
    Inside a block for the same principal, a savepoint; for anyone else, a RuntimeError before anything is sent."""
    p, blocks = _for(who), _blocks(conn)
    begins = _begins(blocks, p, _open(conn), "rowstile.psycopg.transaction()")
    with conn.transaction():  # inside a block of ours, a savepoint: the sign-in, made before it, stays
        if begins:
            conn.execute(_ACT_AS, act_as_args(p))
        blocks.append(p or NOBODY)
        try:
            yield conn
        finally:
            blocks.pop()


@contextlib.asynccontextmanager
async def atransaction(aconn: AsyncConn, who: Who | _Unset = _UNSET) -> AsyncIterator[AsyncConn]:
    p, blocks = _for(who), _blocks(aconn)
    begins = _begins(blocks, p, _open(aconn), "rowstile.psycopg.atransaction()")
    async with aconn.transaction():
        if begins:
            await aconn.execute(_ACT_AS, act_as_args(p))
        blocks.append(p or NOBODY)
        try:
            yield aconn
        finally:
            blocks.pop()


def _changed(result: object) -> bool:
    """Whether an UPDATE or DELETE's result changed anything: a row, rows, a count, or the cursor that ran it
    (its rowcount)."""
    count = getattr(result, "rowcount", None)
    if isinstance(count, int) and not isinstance(count, bool):
        return count > 0
    return bool(result)


def expect(conn: psycopg.Connection[Any], result: Result, table: str, command: str, key: object) -> Result:
    """An UPDATE or DELETE's result (a row, rows, a row count, or the cursor): returned if it changed something,
    else NotFound (the row is hidden, or didn't match) or Refused (the user may not, and why). In the same
    transaction."""
    if _changed(result):
        return result
    t, c, k = _explain_rule_args(table, command, key)
    row = conn.execute(_EXPLAIN, {"t": t, "c": c, "k": k}).fetchone()
    raise verdict(table, command, key, *_answer(row))


async def aexpect(aconn: psycopg.AsyncConnection[Any], result: Result, table: str, command: str, key: object) -> Result:
    """expect, on an async connection."""
    if _changed(result):
        return result
    t, c, k = _explain_rule_args(table, command, key)
    row = await (await aconn.execute(_EXPLAIN, {"t": t, "c": c, "k": k})).fetchone()
    raise verdict(table, command, key, *_answer(row))


def connection_check(conn: psycopg.Connection[Any]) -> list[tuple[str, str]]:
    return [(r[0], r[1]) for r in conn.execute("SELECT severity, problem FROM authz.connection_check()").fetchall()]


def problems(conn: psycopg.Connection[Any]) -> list[str]:
    return _check_problems(connection_check(conn))
