"""Fast without tuning: the indexes the policy's lookups need, plans that would be slow, and a benchmark.

Indexes. The policy looks rows up by columns of the app's tables: a relation read from a column finds the
objects a subject is linked to by that column (`owner_id`, `parent_id`); one read from a link table looks it
up by the subject (lists, select rules) and by the object (checks, explanations). Without an index each is a
full scan. rowstile doesn't create them: they are the app's schema, and an index its ORM doesn't know about
would show as drift in Prisma's, Drizzle Kit's and Alembic's own diffs. It names each missing one, why it is
needed (the policy line), and the line to add for the app's migration tool.

Plans. Each governed table read as someone (EXPLAIN ANALYZE, as the app role), with the time it took, a full
scan of a large table other than the one read, and subplans run once per row.

Bench. The app's read paths (each governed table, authz.list per permission), checks (authz.can) and write
paths (an update of a visible row, undone), as several people, on the database's own data: p50 and p95.
"""

from __future__ import annotations

import json
import random
import time
from collections.abc import Sequence
from typing import TYPE_CHECKING, TypeAlias, TypedDict

from .connection import Db, Value, text
from .parse import Loc, Type, cols
from .sqlutil import POLICY_MARKS, ident, lit, q, qt

if TYPE_CHECKING:
    from . import Compiler

BIG = 10_000  # rows: a full scan of a table this size is worth a warning
SLOW_MS = 100  # a read slower than this on the data there is worth a warning
OWN_SCHEMAS = ("authz", "authz_gen", "authz_int", "authz_keep")  # rowstile's: their indexes are its own business

# a lookup the policy makes: (table, columns, why, the policy line, the columns that serve it alone too: a (type, id)
# pair's ids where they are two columns, its type where its id is one, as authz.lint() counts them)
Lookup: TypeAlias = "tuple[str, tuple[str, ...], str, str, tuple[str, ...]]"
# one that no index serves: whether its table is partitioned (Postgres makes no index on one concurrently), and the
# indexes on its columns that a CREATE INDEX CONCURRENTLY which failed left unfinished (to drop first)
Missing: TypeAlias = "tuple[str, tuple[str, ...], str, str, bool, tuple[str, ...]]"
# the tools that run each migration in a transaction, where Postgres builds no index concurrently, and the line a
# migration starts with to run outside one
NO_TRANSACTION = {"goose": "-- +goose NO TRANSACTION", "dbmate": "-- migrate:up transaction:false"}


class TablePlan(TypedDict):
    table: str
    ms: float | None  # None: the read failed
    warnings: list[str]


# 'as': who the tables were read as ('user:7', or 'anyone'); 'tables': each table (a keyword, so no class syntax)
Plans = TypedDict("Plans", {"as": str, "tables": list[TablePlan]})


class Path(TypedDict):
    path: str
    n: int  # the times it ran (one that failed is not timed)
    p50: float | None  # None: it never ran
    p95: float | None
    failed: str | None  # what the database said when it failed (the app role may not read the table, ...)


class Bench(TypedDict):
    round_trip: float | None  # ms: what any statement costs from where the command runs, before the server's work
    people: int
    rounds: int
    paths: list[Path]


def an(word: str) -> str:
    return ("an " if word[:1].lower() in "aeiou" else "a ") + word


def needed_indexes(c: Compiler) -> list[Lookup]:
    """[(table, columns, why, line, alone)]: the lookups the policy makes into app tables, one per table and
    columns. A (type, id) pair's lookup is by both columns, and an index on what Compiler.pair_alone names serves it
    too."""
    out: list[Lookup] = []
    seen: set[tuple[str, tuple[str, ...]]] = set()

    def add(table: str, columns: tuple[str, ...], why: str, loc: Loc, alone: tuple[str, ...] = ()) -> None:
        key = (table, tuple(columns))
        if key not in seen:
            seen.add(key)
            out.append((table, columns, why, str(loc), alone))

    for t in c.types.values():
        for r in t.relations.values():
            for src in r.sources:
                lead = (src.type_col,) if (src.kind == "column" or src.kind == "table") and src.type_col else ()
                if src.kind == "column":
                    # (the row's own key too, `owner : user = user_id` on a table keyed by its user's id: its primary
                    # key serves the lookup, and without one nothing does)
                    add(
                        t.table,
                        lead + cols(c.source_columns(src)),
                        f"finding the {t.name}s by their {t.name}.{r.name} (lists, select rules)",
                        r.loc,
                        c.pair_alone(src),
                    )
                elif src.kind == "table":
                    table = src.table
                    add(
                        table,
                        lead + cols(c.source_columns(src)),
                        f"finding the {t.name}s by their {t.name}.{r.name} (lists, select rules)",
                        r.loc,
                        c.pair_alone(src),
                    )
                    add(
                        table,
                        cols(src.obj_col),
                        f"finding the {r.name}s of {an(t.name)} (checks, explanations)",
                        r.loc,
                    )
        # every check on one object (authz.can, a write rule) finds its row by the type's key: a primary key serves
        # it, and on a table without one (or a unique index) each check scans the table
        add(t.table, tuple(k for k, _ in t.key), f"finding one {t.name} by its key (checks, write rules)", t.loc)
    return out


def table_indexes(db: Db, table: str) -> list[tuple[str, ...]]:
    """The column lists of the table's indexes (a primary key and unique constraints included): the columns
    each one starts with, up to its first expression (an index on (lower(name), team_id) serves no lookup by
    team_id). Its key columns only: an index on (a) INCLUDE (b) holds b but is not sorted by it, so it serves no
    lookup by (a, b). Valid indexes only."""
    rows = db.rows(
        "SELECT array(SELECT a.attname::text FROM unnest(i.indkey::int2[]) WITH ORDINALITY k(n, o) "
        "LEFT JOIN pg_catalog.pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = k.n WHERE k.o <= i.indnkeyatts "
        "ORDER BY k.o) AS cols "
        "FROM pg_catalog.pg_index i WHERE i.indrelid = to_regclass($1) AND i.indpred IS NULL AND i.indisvalid",
        [qt(table)],  # quoted: to_regclass folds a bare name to lower case, and "TeamMember" is then not found
    )
    out: list[tuple[str, ...]] = []
    for r in rows:
        leading: list[str] = []
        for x in r["cols"] or []:
            if not isinstance(x, str):  # an expression: what comes after it leads nothing
                break
            leading.append(x)
        out.append(tuple(leading))
    return out


def unfinished_indexes(db: Db, table: str) -> list[tuple[str, str]]:
    """(its name with its schema, as SQL writes it; its name) of each index on the table that a CREATE INDEX
    CONCURRENTLY which failed left unfinished (invalid): it serves nothing, and holds its name, the one rowstile
    advises when that build was of its advice."""
    rows = db.rows(
        "SELECT pg_catalog.quote_ident(n.nspname) || '.' || pg_catalog.quote_ident(c.relname) AS sql, "
        "c.relname::text AS name FROM pg_catalog.pg_index i JOIN pg_catalog.pg_class c ON c.oid = i.indexrelid "
        "JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace "
        "WHERE i.indrelid = to_regclass($1) AND NOT i.indisvalid ORDER BY 2",
        [qt(table)],
    )
    return [(text(r, "sql"), text(r, "name")) for r in rows]


def relkind(db: Db, table: str) -> str:
    """What the table is: r a table, p a partitioned one, v a view, m a materialized one ('' if there is none)."""
    rows = db.rows("SELECT c.relkind::text AS k FROM pg_catalog.pg_class c WHERE c.oid = to_regclass($1)", [qt(table)])
    return text(rows[0], "k") if rows else ""


def missing_indexes(db: Db, c: Compiler) -> list[Missing]:
    """[(table, columns, why, line, partitioned, unfinished)] for the needed lookups no index serves (its columns
    lead no index). A view can't have an index: the tables under it answer its lookups (authz.lint() skips it too)."""
    out: list[Missing] = []
    kinds: dict[str, str] = {}
    cache: dict[str, list[tuple[str, ...]]] = {}
    stale: dict[str, list[tuple[str, str]]] = {}
    for table, columns, why, line, alone in needed_indexes(c):
        if table not in kinds:
            kinds[table] = relkind(db, table)
            cache[table] = table_indexes(db, table)
            stale[table] = unfinished_indexes(db, table)
        # an index whose first columns are these, in any order (or what serves a (type, id) pair alone: pair_alone)
        serves = [set(x) for x in (columns, alone) if x]
        if kinds[table] != "v" and not any(set(ix[: len(s)]) == s for ix in cache[table] for s in serves):
            # one left unfinished under the name the advice gives (a build of it that failed): dropped first, or the
            # advice fails ("already exists")
            unfinished = tuple(sql for sql, name in stale[table] if name == index_name(table, columns))
            out.append((table, columns, why, line, kinds[table] == "p", unfinished))
    return out


def index_name(table: str, columns: Sequence[str]) -> str:
    """The name advice gives the index: the table's, its columns', _idx (as Prisma names one); shortened with a
    hash past 63 bytes, as every generated name, so that it is the name Postgres keeps."""
    return ident(f"{table.split('.')[-1]}_{'_'.join(columns)}_idx")


def advice(table: str, columns: Sequence[str], tool: str | None, partitioned: bool = False) -> str:
    """The line to add, for the app's migration tool. Postgres makes no index on a partitioned table concurrently:
    it makes one on each partition, which holds off writes to it meanwhile; nor inside a transaction, where goose
    and dbmate run each migration unless it says otherwise."""
    name = index_name(table, columns)
    fields = ", ".join(columns)
    if tool == "prisma":
        return f"@@index([{fields}]) on the model for {table} (prisma/schema.prisma)"
    if tool == "drizzle":
        return f"index({lit(name)}).on({', '.join('t.' + x for x in columns)}) in the table for {table}"
    if tool == "alembic":
        return (
            f"Index({lit(name)}, {', '.join(lit(x) for x in columns)}) in {table}'s model "
            f"(or index=True on the column), then alembic revision --autogenerate"
        )
    sql = (
        f"CREATE INDEX {'' if partitioned else 'CONCURRENTLY '}{q(name)} ON {qt(table)} "
        f"({', '.join(q(x) for x in columns)});"
    )
    if tool in NO_TRANSACTION and not partitioned:
        return f"{sql} in a migration of its own that starts with {NO_TRANSACTION[tool]}"
    return sql


def describe_missing(missing: list[Missing], tool: str | None) -> str:
    lines = []
    for table, columns, why, line, partitioned, unfinished in missing:
        lines.append(f"{table} has no index on ({', '.join(columns)}): {why} ({line})")
        lines += [
            f"  first, drop what a CREATE INDEX CONCURRENTLY that failed left unfinished: "
            f"DROP INDEX {'' if partitioned else 'CONCURRENTLY '}{name};"
            for name in unfinished
        ]
        lines.append(f"  add: {advice(table, columns, tool, partitioned)}")
    return "\n".join(lines)


# --- plans ---------------------------------------------------------------------------------------------
def app_role(db: Db) -> str | None:
    rows = db.rows(
        "SELECT DISTINCT r.rolname AS r FROM pg_catalog.pg_policy p JOIN pg_catalog.pg_description d "
        f"ON d.objoid = p.oid AND d.classoid = 'pg_catalog.pg_policy'::regclass AND d.description IN {POLICY_MARKS} "
        "CROSS JOIN unnest(p.polroles) ro JOIN pg_catalog.pg_roles r ON r.oid = ro"
    )
    return text(rows[0], "r") if rows else None


def sample_principal(db: Db, c: Compiler) -> tuple[str | None, str | None]:
    """Someone to look as: the first user (by key) in the data."""
    for t in c.types.values():
        if t.principal:
            r = db.rows(f"SELECT ({c.key(t, 'r')})::text AS id FROM {qt(t.table)} r ORDER BY 1 LIMIT 1")
            if r:
                return t.name, text(r[0], "id")
    return None, None


def _str(plan: dict[str, Value], key: str) -> str | None:
    v = plan.get(key)
    return v if isinstance(v, str) else None


def _num(plan: dict[str, Value], key: str, default: float) -> float:
    v = plan.get(key)
    return float(v) if isinstance(v, (int, float)) and not isinstance(v, bool) else default


def walk(plan: dict[str, Value], out: list[str], governed: str) -> None:
    """Warnings from one plan node (EXPLAIN's JSON) and those under it."""
    node = _str(plan, "Node Type") or ""
    rel = _str(plan, "Relation Name")
    schema = _str(plan, "Schema")
    table = f"{schema}.{rel}" if schema and rel else rel
    loops = _num(plan, "Actual Loops", 1)
    # the rows the scan read: the ones it gave and the ones its filter dropped (a missing index shows as a scan
    # that reads everything and keeps little)
    read = (_num(plan, "Actual Rows", 0) + _num(plan, "Rows Removed by Filter", 0)) * loops
    # (rowstile's own tables, read whole for someone who reaches most rows, are no index the app can add)
    if node == "Seq Scan" and table and table != governed and read >= BIG and schema not in OWN_SCHEMAS:
        out.append(f"reads all of {table} ({int(read)} rows): an index missing?")
    subplan = _str(plan, "Subplan Name")
    if subplan and _num(plan, "Actual Loops", 0) >= 1000:
        out.append(f"{subplan} runs once per row ({int(loops)} times)")
    children = plan.get("Plans")
    for child in [x for x in children if isinstance(x, dict)] if isinstance(children, list) else []:
        walk(child, out, governed)


def plans(db: Db, c: Compiler, who: tuple[str, str] | None = None) -> Plans:
    """Each governed table read as someone (default: a user in the data), with EXPLAIN ANALYZE as the app
    role: how long it took, and what looks slow. Runs in the caller's transaction (roll it back)."""
    from .database import Error, may_take, savepoint

    role = app_role(db)
    if role is None:
        raise Error("no policy with rules is applied, so there is no app role to read as")
    may_take(db, role)
    ptype, pid = who or sample_principal(db, c)
    out: list[TablePlan] = []
    for table in sorted({r.table for r in c.pol.rules if r.command == "select"}):
        db.rows("SELECT authz.act_as($1, $2)", [ptype, pid])
        try:
            with savepoint(db, "authz_plan"):
                db.rows(f"SET LOCAL ROLE {q(role)}")
                db.rows("SET LOCAL statement_timeout = '10s'")
                # VERBOSE: each scan's table with its schema
                raw = next(
                    iter(
                        db.rows(f"EXPLAIN (ANALYZE, VERBOSE, FORMAT JSON) SELECT count(*) FROM {qt(table)}")[0].values()
                    )
                )
                data = json.loads(raw) if isinstance(raw, str) else raw
                top = data[0] if isinstance(data, list) and data and isinstance(data[0], dict) else {}
                plan = top.get("Plan")
                plan = plan if isinstance(plan, dict) else {}
                warnings: list[str] = []
                walk(plan, warnings, table)
                ms = round(_num(top, "Execution Time", 0.0), 2)
                if ms > SLOW_MS:
                    warnings.insert(0, f"took {ms} ms")
                out.append({"table": table, "ms": ms, "warnings": list(dict.fromkeys(warnings))})
                db.rows("RESET ROLE")
        except db.errors as e:
            out.append({"table": table, "ms": None, "warnings": [f"failed: {getattr(e, 'message', e)}"]})
    return {"as": f"{ptype}:{pid}" if pid else "anyone", "tables": out}


def describe_plans(p: Plans) -> str:
    lines = [f"as {p['as']}:"]
    for t in p["tables"]:
        head = f"  {t['table']}: {t['ms']} ms" if t["ms"] is not None else f"  {t['table']}"
        lines.append(head + ("" if not t["warnings"] else "  <- " + "; ".join(t["warnings"])))
    return "\n".join(lines)


# --- bench ---------------------------------------------------------------------------------------------
def pct(values: list[float], p: float) -> float | None:
    if not values:
        return None
    v = sorted(values)
    return round(v[min(len(v) - 1, round(p / 100 * (len(v) - 1)))], 2)


def bench(db: Db, c: Compiler, people: int = 10, rounds: int = 20, seed: int = 0) -> Bench:
    """p50 and p95 (ms) of the app's paths as several people in the data: reads of each governed table, authz.list
    per permission, authz.can on objects, and updates of visible rows (undone). Runs in the caller's transaction."""
    from .database import Undo, may_take, savepoint

    rng = random.Random(seed)
    role = app_role(db)
    may_take(db, role)
    users: list[tuple[str | None, str | None]] = []
    for t in c.types.values():
        if t.principal:
            ids = [
                text(r, "id")
                for r in db.rows(f"SELECT ({c.key(t, 'r')})::text AS id FROM {qt(t.table)} r ORDER BY 1 LIMIT 1000")
            ]
            users += [(t.name, i) for i in rng.sample(ids, min(len(ids), people))]
    users = users[:people] or [(None, None)]
    timings: dict[str, list[float]] = {}
    failed: dict[str, str] = {}  # what the database said the first time a path failed

    def timed(label: str, sql: str, args: Sequence[Value] = (), as_app: bool = False) -> None:
        took = 0.0
        try:
            with savepoint(db, "authz_bench"):
                if as_app and role:
                    db.rows(f"SET LOCAL ROLE {q(role)}")
                start = time.perf_counter()  # the statement alone: one round trip, and the server's work
                db.rows(sql, list(args))
                took = (time.perf_counter() - start) * 1000
                raise Undo
        except Undo:
            pass
        except db.errors as e:
            failed.setdefault(label, str(getattr(e, "message", e)))
            timings.setdefault(label, [])  # said, not left out
            return
        timings.setdefault(label, []).append(took)

    for _ in range(5):
        timed("", "SELECT 1")
    round_trip = pct(timings.pop("", []), 50)

    reads = sorted({r.table for r in c.pol.rules if r.command == "select"})
    updates = sorted({r.table for r in c.pol.rules if r.command == "update"})
    perms = [(t, p) for t in c.types.values() for p in c.public_perms(t)]
    ids = {
        t.name: [text(r, "id") for r in db.rows(f"SELECT ({c.key(t, 'r')})::text AS id FROM {qt(t.table)} r LIMIT 200")]
        for t in c.types.values()
    }
    for _ in range(rounds):
        ptype, pid = rng.choice(users)
        db.rows("SELECT authz.act_as($1, $2)", [ptype, pid])
        for table in reads:
            timed(f"read {table}", f"SELECT count(*) FROM {qt(table)}", as_app=True)
        for t, p in perms:
            timed(f"authz.list {t.name} {p}", "SELECT count(*) FROM authz.list($1, $2)", [t.name, p])
            if ids[t.name]:
                timed(f"authz.can {t.name} {p}", "SELECT authz.can($1, $2, $3)", [t.name, rng.choice(ids[t.name]), p])
        for table in updates:
            t = c.governing(table)
            col = plain_column(db, c, t)
            if ids[t.name] and col:
                oid = rng.choice(ids[t.name])
                timed(
                    f"update {table}",
                    f"UPDATE {qt(table)} r SET {q(col)} = r.{q(col)} WHERE {c.key_is(t, 'r', lit(oid))}",
                    as_app=True,
                )
    return {
        "round_trip": round_trip,
        "people": len(users),
        "rounds": rounds,
        "paths": [
            {"path": k, "n": len(v), "p50": pct(v, 50), "p95": pct(v, 95), "failed": failed.get(k)}
            for k, v in sorted(timings.items())
        ],
    }


def plain_column(db: Db, c: Compiler, t: Type) -> str | None:
    """A column of t's table to write back unchanged: not in its key, and read by no relation (so no tree moves)."""
    used = {k for k, _ in t.key}
    for r in t.relations.values():
        for src in r.sources:
            if src.kind == "column":
                used |= set(cols(c.source_columns(src))) | ({src.type_col} if src.type_col else set())
    rows = db.rows(
        "SELECT attname::text AS a FROM pg_catalog.pg_attribute WHERE attrelid = to_regclass($1) AND attnum > 0 "
        "AND NOT attisdropped AND attgenerated = '' ORDER BY attnum",
        [qt(t.table)],
    )
    return next((text(r, "a") for r in rows if r["a"] not in used), None)


def describe_bench(b: Bench) -> str:
    width = max([len(x["path"]) for x in b["paths"]] + [4])
    lines = [
        f"{b['rounds']} rounds as {b['people']} people (ms, from here: a statement that does nothing takes "
        f"{b['round_trip']}):",
        f"  {'path'.ljust(width)}   p50      p95",
    ]
    for x in b["paths"]:
        times = f"  {x['p50']:>6}  {x['p95']:>7}" if x["n"] else f"  {'-':>6}  {'-':>7}"
        lines.append(f"  {x['path'].ljust(width)}{times}" + (f"  <- failed: {x['failed']}" if x["failed"] else ""))
    return "\n".join(lines)
