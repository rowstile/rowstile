"""rowstile with asyncpg, without SQLAlchemy.

    async with rowstile.asyncpg.transaction(conn, 42):
        rows = await conn.fetch("SELECT id, body FROM app.notes")

Inside a transaction already open the block is a savepoint: when it ends, the transaction acts again for
whoever it acted for before the block (the block around it, else nobody).
"""

from __future__ import annotations

import contextlib
from collections.abc import AsyncIterator
from typing import TYPE_CHECKING, Any, TypeVar

from . import (
    _UNSET,
    Who,
    _answer,
    _check_problems,
    _explain_rule_args,
    _explain_rule_sql,
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
# who each open block of ours signed in, by connection (asyncpg's connections take no attributes), outermost first
_signed: dict[int, list[_Args]] = {}


def _act_as(args: _Args) -> str:
    """The sign-in with its values written in: one simple statement, nothing prepared (PgBouncer)."""
    return f"SELECT authz.act_as({_literal(args[0])}, {_literal(args[1])})"


@contextlib.asynccontextmanager
async def transaction(conn: Conn, who: Who | _Unset = _UNSET) -> AsyncIterator[Conn]:
    """A transaction signed in as `who` (None: nobody; left out: whoever the code acts for now, nobody if unset)."""
    args, inside = act_as_args(who), conn.is_in_transaction()
    blocks = _signed.setdefault(id(conn), [])
    try:
        async with conn.transaction():
            await conn.execute(_act_as(args))
            blocks.append(args)
            try:
                yield conn
            finally:
                blocks.pop()
            if inside:  # a savepoint keeps what act_as set: back to who it was (an error undoes it by itself)
                await conn.execute(_act_as(blocks[-1] if blocks else (None, None)))
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
