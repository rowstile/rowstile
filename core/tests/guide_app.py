#!/usr/bin/env python3
"""guide_app: the Python that docs/getting-started.md shows (its one ```python block) runs as written, against the
client the guide writes, in the database tests/docs_test.sh made by following the guide.

    python3 tests/guide_app.py GUIDE FOLDER DB REQUEST

FOLDER holds authz_client.py; REQUEST is a JSON object of the values the guide says are the request's (its
sentence "... are your request's" names them). Prints two lines of JSON: what the block's error handler returns for
the block run with that request (null: no error), then what it returns for the database's error when that user
adds a note to the project (null: allowed, and rolled back); an error it doesn't handle, as "not handled: ...".

psycopg isn't in the suites' image: a stand-in with what the block and the client use of it (connect, a
connection's transaction, execute and cursor, an error's sqlstate and diag) runs it over the command's Postgres
client. It connects as the role and password the block's URL names, to DB on PGHOST (the URL's host and database
are a reader's own).
"""

import ast
import contextlib
import json
import os
import re
import sys
import types
from collections.abc import Callable, Iterator, Sequence
from typing import Any
from urllib.parse import unquote, urlsplit

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "cli"))
import pgwire  # noqa: E402
from tools_test import Cursor  # noqa: E402

Answer = Any  # what the guide's error handler returns: JSON


class Diag:
    """psycopg's Error.diag: the fields of the database's error a client reads."""

    def __init__(self, fields: pgwire.Fields) -> None:
        self.message_primary = fields.get("M")
        self.message_detail = fields.get("D")
        self.schema_name = fields.get("s")
        self.table_name = fields.get("t")
        self.constraint_name = fields.get("n")


class Error(Exception):
    """psycopg.Error, as a refusal reaches the app: its SQLSTATE and its diag."""

    def __init__(self, e: pgwire.PgError) -> None:
        super().__init__(e.message)
        self.sqlstate = e.code
        self.diag = Diag(e.fields)


class PsycopgCursor(Cursor):
    def execute(self, sql: str, args: Sequence[object] = (), /) -> None:
        try:
            super().execute(sql, args)
        except pgwire.PgError as e:
            raise Error(e) from None


class Connection:
    """psycopg.Connection: a context that closes it, transaction(), execute() and cursor()."""

    def __init__(self, pg: pgwire.Connection) -> None:
        self.pg = pg

    def __enter__(self) -> "Connection":
        return self

    def __exit__(self, *exc: object) -> None:
        self.pg.close()

    @contextlib.contextmanager
    def transaction(self) -> Iterator[None]:
        """BEGIN, then COMMIT; an error leaves it to end with the connection, rolled back."""
        self.pg.execute("BEGIN")
        yield
        self.pg.execute("COMMIT")

    def cursor(self) -> PsycopgCursor:
        return PsycopgCursor(self.pg)

    def execute(self, sql: str, args: Sequence[object] = ()) -> PsycopgCursor:
        cur = self.cursor()
        cur.execute(sql, args)
        return cur


def stand_in(db: str, urls: list[str]) -> types.ModuleType:
    """A module named psycopg whose connect() records the URL it was given."""

    def connect(url: str) -> Connection:
        urls.append(url)
        parts = urlsplit(url)
        return Connection(
            pgwire.connect(
                host=os.environ.get("PGHOST", "/var/run/postgresql"),
                port=int(os.environ.get("PGPORT", "5432")),
                user=unquote(parts.username or ""),
                password=unquote(parts.password or ""),
                database=db,
            )
        )

    module = types.ModuleType("psycopg")
    module.__dict__.update(connect=connect, Error=Error, Connection=Connection)
    return module


def main() -> None:
    guide, folder, db, request = sys.argv[1:]
    with open(guide, encoding="utf-8") as fh:
        text = fh.read()
    blocks = re.findall(r"```python\n(.*?)```", text, re.S)
    if len(blocks) != 1:
        raise SystemExit(f"the guide has {len(blocks)} python blocks: this runs one")
    said = re.search(r"((?:`\w+`,?\s+)+and\s+`\w+`) are your request's", text)
    names = sorted(re.findall(r"`(\w+)`", said.group(1))) if said else []
    given: dict[str, object] = json.loads(request)
    if names != sorted(given):
        raise SystemExit(f"the guide says the request's values are {names}; this run gives {sorted(given)}")
    urls: list[str] = []
    sys.modules["psycopg"] = stand_in(db, urls)
    sys.path.insert(0, folder)
    # the block's statements one by one: the request's raises, as it would in the app, and the handler after it is
    # still defined for the framework to call
    scope: dict[str, object] = dict(given)
    error: BaseException | None = None
    for statement in ast.parse(blocks[0], guide).body:
        try:
            exec(compile(ast.Module([statement], []), guide, "exec"), scope)
        except Exception as e:
            error = error or e
    on_error: Callable[[BaseException], Answer] = scope["on_error"]  # ty: ignore[invalid-assignment]
    print(json.dumps(None if error is None else on_error(error) or f"not handled: {error!r}"))
    # the same handler, given the error the database raises for a write it refuses
    import authz_client  # ty: ignore[unresolved-import]  # the client the guide wrote, in FOLDER

    psycopg = sys.modules["psycopg"]
    refused: Answer = None
    with psycopg.connect(urls[0]) as conn:
        conn.pg.execute("BEGIN")
        authz_client.Authz(conn).sign_in(given["current_user_id"])
        try:
            conn.execute(
                "INSERT INTO app.notes (project_id, author_id, body) VALUES (%s, %s, 'mine')",
                (given["project_id"], given["current_user_id"]),
            )
        except Error as e:
            refused = on_error(e) or f"not handled: {e!r}"
        conn.pg.execute("ROLLBACK")
    print(json.dumps(refused))


if __name__ == "__main__":
    main()
