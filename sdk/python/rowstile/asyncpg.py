"""rowstile with asyncpg, without SQLAlchemy.

    async with rowstile.asyncpg.transaction(conn, 42):
        rows = await conn.fetch("SELECT id, body FROM app.notes")

A sign-in lasts the database transaction, so a transaction is one principal's. A block inside another for the
same principal is a savepoint. A block for someone else (or, with no `who`, for code that acts for no one) is
refused with a RuntimeError before anything is sent, the transaction left as it was: run it after, or on another
connection. So is a block inside a transaction no block began, whose sign-in can't be known.
"""

from __future__ import annotations

import contextlib
from collections.abc import AsyncIterator
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
    _literal,
    _Unset,
    act_as_args,
    verdict,
)

if TYPE_CHECKING:
    import asyncpg

Conn = TypeVar("Conn", bound="asyncpg.Connection[Any]")
Result = TypeVar("Result")
_Args = tuple[str | None, str | None]

_EXPLAIN = _explain_rule_sql("$1::text", "$2", "$3")
# who each open block of ours signed in as, by connection (asyncpg's connections take no attributes), outermost first
_signed: dict[int, list[Principal]] = {}


def _act_as(args: _Args) -> str:
    """The sign-in with its values written in: one simple statement, nothing prepared (PgBouncer)."""
    return f"SELECT authz.act_as({_literal(args[0])}, {_literal(args[1])})"


@contextlib.asynccontextmanager
async def transaction(conn: Conn, who: Who | _Unset = _UNSET) -> AsyncIterator[Conn]:
    """A transaction signed in as `who` (None: nobody; left out: whoever the code acts for now, nobody if unset).
    Inside a block for the same principal, a savepoint; for anyone else, a RuntimeError before anything is sent."""
    p, blocks = _for(who), _signed.setdefault(id(conn), [])
    try:
        begins = _begins(blocks, p, conn.is_in_transaction(), "rowstile.asyncpg.transaction()")
        async with conn.transaction():  # inside a block of ours, a savepoint: the sign-in, made before it, stays
            if begins:
                await conn.execute(_act_as(act_as_args(p)))
            blocks.append(p or NOBODY)
            try:
                yield conn
            finally:
                blocks.pop()
    finally:
        if not blocks:
            _signed.pop(id(conn), None)


async def expect(conn: asyncpg.Connection[Any], result: Result, table: str, command: str, key: object) -> Result:
    """An UPDATE or DELETE's result: returned if it changed something (asyncpg's 'UPDATE 1' counts), else
    NotFound (the row is hidden, or didn't match) or Refused, with why."""
    changed = result and not (isinstance(result, str) and result.split()[-1] == "0")
    if changed:
        return result
    row = await conn.fetchrow(_EXPLAIN, *_explain_rule_args(table, command, key))
    raise verdict(table, command, key, *_answer(row))


async def connection_check(conn: asyncpg.Connection[Any]) -> list[tuple[str, str]]:
    return [(r[0], r[1]) for r in await conn.fetch("SELECT severity, problem FROM authz.connection_check()")]


async def problems(conn: asyncpg.Connection[Any]) -> list[str]:
    return _check_problems(await connection_check(conn))
