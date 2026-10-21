# Python apps: SQLAlchemy, SQLModel, psycopg and asyncpg

<!-- tested: every line of code below is in integrations/fastapi (tests/unit_test.py checks it) -->

Any Python app (Flask, Litestar, a worker, a script) on SQLAlchemy's sync engine, SQLModel, psycopg or
asyncpg. (The SDK has no adapter for Django's ORM.) Each transaction signs in as whoever the code acts for, the database filters what it
reads and refuses what it may not write, and the SDK raises `Refused` (403) or `NotFound` (404). FastAPI:
[FastAPI](fastapi.md).

These come from the conformance suite (`integrations/fastapi/tests/test_conformance.py`).

```sh
pip install --pre "rowstile[sqlalchemy,psycopg]"   # or [asyncpg]; the command comes with it (--pre: the newest pre-release)
```

## Who a transaction acts for

`acting_as(who)` signs in every transaction begun inside it: `42` or `"42"` (a user), `("service", 3)` (another
principal type of the policy), or `None` (nobody: only what `anyone` may see). In a web app, enter it around
each request. A background job is `@rowstile.job(who)`. Every transaction signs in, even as nobody, and
nothing uses a session-level `SET`, so pools and poolers in transaction mode are safe (behind one that keeps no
prepared statements, turn the driver's off: [Behind a pooler](../operations.md#behind-a-pooler)). A transaction
already begun keeps who it
acts for: `acting_as` decides for the ones begun inside it.

## SQLAlchemy (sync) and SQLModel

`install(engine)` signs in every transaction the engine begins. SQLModel is built on the same engine.

```python
import pytest
import rowstile
from rowstile import sqlalchemy as authz_sa

    engine = authz_sa.install(create_engine(APP.replace("+asyncpg", "+psycopg")))
        with rowstile.acting_as(2), Session(engine) as s:
            assert sorted(s.scalars(select(Note.id)).all()) == [2, 3]
            assert authz_sa.can_sync(s, "note", 2, "edit") and not authz_sa.can_sync(s, "note", 3, "edit")
```

An ORM update the rules refuse changes 0 rows, which SQLAlchemy raises as `StaleDataError`; `why_stale_sync`
asks the database why, and gives `Refused` with the rule and the reason, or `NotFound`:

```python
            with pytest.raises(StaleDataError) as e, Session(engine) as s, s.begin():
                note = s.get(Note, 1)
                assert note is not None
                note.body = "x"
            verdict = authz_sa.why_stale_sync(e.value)
            assert isinstance(verdict, Refused) and verdict.why, verdict
```

## psycopg

```python
    import rowstile.psycopg as pgp
        with pgp.transaction(conn, 2):
            assert [r[0] for r in conn.execute("SELECT id FROM app.notes ORDER BY id")] == [2, 3]
```

`transaction(conn, who)` signs in as `who`; `None` is nobody, and with no `who` it is whoever the code acts
for. Inside a transaction already open (psycopg opens one at the first statement unless `autocommit` is on)
the block is a savepoint, and when it ends the transaction acts again for whoever it did before the block.

An UPDATE or DELETE the rules refuse changes 0 rows, without an error; `expect` asks why, and raises
`Refused` or `NotFound` (it takes the row count, the rows, or the cursor):

```python
        with pytest.raises(Refused), pgp.transaction(conn, 3):
            cur = conn.execute("UPDATE app.notes SET body = 'x' WHERE id = 1")
            pgp.expect(conn, cur.rowcount, "app.notes", "update", 1)
```

A refused INSERT is an error already: `rowstile.refusal(exc)` reads it as `Refused`.

## asyncpg

```python
    import rowstile.asyncpg as pga
        with rowstile.acting_as(("service", "1")):
            async with pga.transaction(conn):
                assert [r["id"] for r in await conn.fetch("SELECT id FROM app.projects ORDER BY id")] == [1, 3]
        async with pga.transaction(conn, 2):
            with pytest.raises(rowstile.NotFound):
                await pga.expect(
                    conn, await conn.execute("DELETE FROM app.notes WHERE id = 1"), "app.notes", "delete", 1
                )
```

## Migrations

Policy changes ship as migrations for your tool: `tool = "alembic"` (see [FastAPI](fastapi.md)), `"sql"`,
`"goose"`, `"dbmate"` or `"flyway"` in `rowstile.toml`. `rowstile migrate` writes the next one;
`rowstile migrate --check` in CI fails if a policy change has none.
