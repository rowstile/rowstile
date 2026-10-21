#!/usr/bin/env python3
"""conditions_test: the simple conditions the reference evaluator reads itself mean what Postgres says they mean.

    PGHOST=... PGUSER=... python3 tests/conditions_test.py [--cases 3000] [--seed 1] [--db authz_conditions]

`rowstile prove` and the review's refactor check read a simple condition (`{not archived}`, `{size > 10}`,
`{owner_id = authz.uid()}`) as a fact about a made-up row (authzlib/conditions.py); difftest never does, it asks
the database for each condition's rows. So this asks both: conditions made up at random over columns of each kind
(boolean, integer, numeric, double precision, real, text, and a column a relation reads, whose values the evaluator
holds as the ids' text; some named only in quotes, "B" beside b, "order"), every one Postgres accepts asked on the
same rows, signed in as each user and as nobody. Whatever
conditions.py takes as simple must give Postgres's answer on every row: true, false or NULL. One it doesn't take
(a function, arithmetic, a cast) is left to the database, as any other condition.

Two columns don't tell texts apart byte by byte: ci, under a collation that ignores case, accents and punctuation
and compares digits as numbers (ICU, not deterministic), and ch, a char(3). A made-up row holds one of the texts
its column is compared with, or another: a row of the database is read as the text it equals, so what the
evaluator reads of one must be Postgres's answer on the other. That holds while no row equals two texts the
evaluator reads apart: every two texts Postgres holds equal, under such collations or as a value of a type (a
date, a uuid, a tsvector...), must be alike (conditions.alike), and a condition comparing a column with two alike
texts is the database's to read (evaluate.facts). The run fails too when fewer than a fifth of the conditions are
read, or when some kind of them never is (a comparison, `in`, `is null`, authz.uid(), a column alone, a text on
ci): a reading that stopped would leave nothing to tell apart.
"""

from __future__ import annotations

import argparse
import os
import random
import re
import subprocess
import sys
from decimal import Decimal

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "cli"))
import pgwire  # noqa: E402
from authzlib.conditions import (  # noqa: E402
    Bool,
    Cmp,
    Col,
    In,
    IsNull,
    Node,
    Scalar,
    Uid,
    alike,
    alike_columns,
    plain,
    simple,
    texts_of,
    truth,
)

# the nondeterministic collation ci is under: case, accents and punctuation ignored, digits compared as numbers
LOOSE = "und-u-ka-shifted-kn-ks-level1"

# each column's values (None: NULL), as Python holds them in a made-up world, and as SQL writes them
COLUMNS: dict[str, tuple[str, list[Scalar]]] = {
    "b": ("boolean", [True, False, None]),
    "n": ("integer", [-1, 0, 1, 9, 10, 11, None]),
    # a decimal is read exactly, as numeric holds it; one with more digits than a double keeps is not read
    "x": ("numeric", [Decimal("0.5"), 1, Decimal("1.5"), 10, Decimal("0.1"), Decimal("1.00000000000000001"), None]),
    "f": ("double precision", [Decimal("0.5"), 1, Decimal("1.5"), Decimal("0.1"), Decimal("0.3"), None]),
    # a real column holds 0.1 as 0.100000001 (and 0.1::real = 0.1 is false), 16777217 as 16777216: as the worlds
    # draw the values around a constant (16777217 beside 16777216), a row may hold one it rounds
    "r": ("real", [Decimal("0.5"), 1, Decimal("0.25"), Decimal("0.1"), 16777216, 16777217, None]),
    "s": ("text", ["a", "b", "A", "B", "ab", "x", "it's", "10", "9", "", " a", None]),
    # a relation's column (`owner : user = o`): the evaluator holds its values as the linked ids' text
    "o": ("bigint", ["1", "2", "10", None]),
    # columns named in quotes: case kept ("B" is not b), a word SQL keeps for itself, a quote inside
    "B": ("boolean", [False, None, True]),
    "order": ("integer", [1, 2, None]),
    'a"b': ("text", ["a", "b", None]),
    # texts a column holds as one value: by its collation, by char(n)'s padding
    "ci": ("text COLLATE loose", ["a", "A", "á", "b", "B", "ab", "a-b", "a b", "x1", "x01", "", None]),
    "ch": ("char(3)", ["a", "a  ", "A", "ab", "", None]),
}
# the columns whose equality isn't byte by byte: a row is read as the text of the condition it equals
LOOSE_COLUMNS = ("ci", "ch")
BOOLEANS = ("b", "B")
USERS = ["1", "2", "10", None]  # who is signed in: authz.uid(); None, nobody
# the constants a condition compares each column with: some of another kind, as SQL allows ('10' for a number)
CONSTANTS: dict[str, list[str]] = {
    "b": ["true", "false", "TRUE", "'true'", "'t'", "'f'", "'yes'", "null"],
    "n": ["-1", "0", "1", "9", "10", "11", "9.5", "10.0", "'10'", "'010'", "'9'", "1e1", "'x'", "null"],
    "x": ["0.5", "1", "1.0", "1.50", "10", "'1.5'", "'1.50'", "1e1", "1.5e0", "0.1", "0.10", "null"]
    + ["1.00000000000000001", "1.000000000000001", "100.000000000000000000", "0.000000000000001", "0.0000000000000001"],
    "f": ["0.5", "1", "1.50", "0.1", "0.3", "0.30000000000000001", "0.1000000000000001", "100000000000000.1", "null"],
    "r": ["0.5", "1", "1.0", "0.25", "0.1", "0.10", "0.3", "'0.5'", "null"]
    + ["16777214", "16777215", "16777216", "16777217", "16777218"],
    "s": ["'a'", "'b'", "'A'", "'B'", "'ab'", "'it''s'", "'10'", "'9'", "''", "' a'", "10", "null"],
    "o": ["1", "2", "10", "'1'", "'10'", "9", "null"],
    "B": ["true", "false", "'t'", "null"],
    "order": ["1", "2", "1.5", "'2'", "null"],
    'a"b': ["'a'", "'b'", "'A'", "null"],
    "ci": ["'a'", "'A'", "'á'", "'b'", "'ab'", "'a-b'", "'x1'", "'x01'", "''", "'c'", "null"],
    "ch": ["'a'", "'a '", "'A'", "'ab'", "''", "' '", "null"],
}
# texts to ask Postgres about two by two (beside the constants'): what a collation or a type may hold as one value
TEXTS = [
    "a", "A", "á", "Á", "ä", "ae", "æ", "o", "ø", "oe", "œ", "l", "ł", "d", "đ", "ss", "ß", "i", "\u0131", "ab", "a-b",
    "a b", "a_b", "b a", "a a", "x1", "x01", "x 1", "draft", "Draft", "published", "a ", " ", "", "a\u00ad",
    "\uff41", "\u0663", "2024-01-01", "2024-1-1", "20240101", "Jan 1 2024", "now", "today", "epoch", "1970-01-01",
    "allballs", "00:00", "1 day", "24 hours", '{"a": 1}', '{"a":1}', '{"b": 2, "a": 1}', '{"a": 1, "b": 2}',
    "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11", "A0EEBC99-9C0B-4EF8-BB6D-6BB9BD380A11", "{a0eebc999c0b4ef8bb6d6bb9bd380a11}",
    "10.0.0.1", "10.0.0.1/32", "café", "cafe", "CAFE",
]  # fmt: skip
# what Postgres compares those texts under: collations ICU makes from its root, and types that read text
COLLATIONS = ["und-u-ks-level2", "und-u-ks-level1", "und-u-ka-shifted", "und-u-kn", LOOSE]
TYPES = ["char(12)", "date", "time", "uuid", "interval", "inet", "jsonb", "tsvector"]
OPS = ["=", "<>", "!=", "<", "<=", ">", ">="]


def sql_value(v: Scalar) -> str:
    if v is None:
        return "NULL"
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, str):
        return "'" + v.replace("'", "''") + "'"
    return str(v)


def word(rng: random.Random, w: str) -> str:
    return rng.choice([w, w.upper(), w.capitalize()])


def quoted(c: str) -> str:
    return '"' + c.replace('"', '""') + '"'


def column(rng: random.Random, c: str) -> str:
    if re.fullmatch(r"[a-z_][a-z0-9_]*", c) and c != "order":
        return rng.choice([c, c, f"this.{c}", f"THIS.{c}", c.upper(), quoted(c)])
    # (`order` bare is not a name, B bare is b: Postgres refuses the one, reads the other column)
    return rng.choice([quoted(c), quoted(c), f"this.{quoted(c)}", f"THIS . {quoted(c)}", c])


def atom(rng: random.Random) -> str:
    c = rng.choice(list(COLUMNS))
    k = rng.choice(CONSTANTS[c])
    col = column(rng, c)
    form = rng.randrange(12)
    if form == 0 and c in BOOLEANS:
        return col
    if form <= 4:
        op = rng.choice(OPS)
        return f"{col} {op} {k}" if rng.random() < 0.8 else f"{k} {op} {col}"
    if form <= 6:
        values = ", ".join(rng.choice(CONSTANTS[c]) for _ in range(rng.randint(1, 3)))
        return f"{col} {word(rng, 'not') + ' ' if rng.random() < 0.4 else ''}{word(rng, 'in')} ({values})"
    if form == 7:
        return f"{col} {word(rng, 'is')} {word(rng, 'not') + ' ' if rng.random() < 0.5 else ''}{word(rng, 'null')}"
    if form == 8:
        uid = rng.choice(["authz.uid()", "authz.uid ()", "AUTHZ.UID()"])
        return f"{column(rng, 'o')} {rng.choice(OPS)} {uid}" if rng.random() < 0.7 else f"{uid} = {column(rng, 'o')}"
    if form == 9:
        # what conditions.py leaves to the database: it must say so, not read it some other way
        return rng.choice(
            [
                f"{col} + 1 > 2" if c in ("n", "x", "f", "r", "order") else f"coalesce({col}, {k}) = {k}",
                f"{col} between {k} and {k}",
                f"{col} is true" if c in BOOLEANS else f"{col} = -1",
                "n = x",
                "1 = 1",
                f"{col} = {k}::text",
                f"lower({col}) = 'a'" if c == "s" else f"{col}::text = '1'",
                f"{col} {word(rng, 'is')} {word(rng, 'distinct')} from {k}",
                f"{col} is not distinct from {k}",
                f"{col} like 'a%'"
                if c == "s"
                else f"{col} is unknown"
                if c in BOOLEANS
                else f"{col} not between 1 and 2",
            ]
        )
    return f"{col} {rng.choice(OPS)} {k}" + rng.choice(["", "", "  "])  # now and then with spaces after


def condition(rng: random.Random, depth: int = 0) -> str:
    r = rng.random()
    if depth >= 3 or r < 0.35:
        return atom(rng)
    if r < 0.5:
        return f"{word(rng, 'not')} {condition(rng, depth + 1)}"
    if r < 0.6:
        return f"({condition(rng, depth + 1)})"
    joiner = word(rng, rng.choice(["and", "or"]))
    return f" {joiner} ".join(condition(rng, depth + 1) for _ in range(rng.randint(2, 3)))


def rows(rng: random.Random, n: int) -> list[dict[str, Scalar]]:
    """Every value of every column at least once, then rows drawn at random."""
    out: list[dict[str, Scalar]] = []
    longest = max(len(vs) for _, vs in COLUMNS.values())
    for i in range(longest):
        out.append({c: vs[i % len(vs)] for c, (_, vs) in COLUMNS.items()})
    while len(out) < n:
        out.append({c: rng.choice(vs) for c, (_, vs) in COLUMNS.items()})
    return out


def answer(v: object) -> bool | None:
    assert v is None or isinstance(v, bool), v
    return v


def kinds(node: Node) -> set[str]:
    """The kinds of reading a condition has: a comparison, `in`, `is null`, authz.uid(), a column alone."""
    match node:
        case Cmp(left=a, right=b):
            return {"authz.uid()" if Uid() in (a, b) else "a comparison"}
        case In():
            return {"in"}
        case IsNull():
            return {"is null"}
        case Col():
            return {"a column alone"}
        case Bool(items=items):
            return set().union(*(kinds(x) for x in items))
    return set()


FORMS = ("a comparison", "in", "is null", "authz.uid()", "a column alone", "a text on ci", "alike texts, drawn")


def one_value(conn: pgwire.Connection, texts: list[str]) -> list[str]:
    """Each two texts that Postgres holds as one value, under one of COLLATIONS or as one of TYPES, and that alike
    doesn't say may be."""
    conn.script(
        "SET client_min_messages = warning;\nCREATE TABLE texts (t text);\n"
        + "".join(f"INSERT INTO texts VALUES ({sql_value(t)});\n" for t in texts)
        + "".join(
            f"CREATE COLLATION c{i} (provider = icu, locale = '{loc}', deterministic = false);\n"
            for i, loc in enumerate(COLLATIONS)
        )
    )
    pairs: list[tuple[str, str, str]] = []
    for i, loc in enumerate(COLLATIONS):
        got = conn.query(
            f'SELECT a.t, b.t FROM texts a, texts b WHERE a.t < b.t COLLATE "C" AND a.t = b.t COLLATE c{i}'
        )
        pairs += [(str(a), str(b), f"collation {loc}") for a, b in got]
    for ty in TYPES:
        valid = f"pg_input_is_valid(a.t, '{ty}') AND pg_input_is_valid(b.t, '{ty}')"
        got = conn.query(
            f'SELECT a.t, b.t FROM texts a, texts b WHERE a.t < b.t COLLATE "C" AND {valid} '
            f"AND CASE WHEN {valid} THEN a.t::{ty} = b.t::{ty} END"
        )
        pairs += [(str(a), str(b), ty) for a, b in got]
    return [f"{a!r} and {b!r} are one value ({how}), and not alike" for a, b, how in pairs if not alike(a, b)]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--cases", type=int, default=3000)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--db", default="authz_conditions")
    ap.add_argument("--show", type=int, default=20, help="how many differences to print")
    args = ap.parse_args()
    rng = random.Random(args.seed)
    subprocess.run(["dropdb", "--if-exists", args.db], capture_output=True)
    subprocess.run(["createdb", args.db], check=True)
    conn = pgwire.connect(**pgwire.parse_dsn(f"dbname={args.db}"))
    data = rows(rng, 150)
    cols = ", ".join(f"{quoted(c)} {ty}" for c, (ty, _) in COLUMNS.items())
    conn.script(
        f"CREATE COLLATION loose (provider = icu, locale = '{LOOSE}', deterministic = false);\n"
        "CREATE SCHEMA authz;\n"
        "CREATE FUNCTION authz.uid() RETURNS bigint LANGUAGE sql STABLE AS "
        "$$ SELECT nullif(current_setting('conditions_test.uid', true), '')::bigint $$;\n"
        f"CREATE TABLE rows (id int PRIMARY KEY, {cols});\n"
        + "".join(
            f"INSERT INTO rows VALUES ({i}, {', '.join(sql_value(r[c]) for c in COLUMNS)});\n"
            for i, r in enumerate(data)
        )
    )
    collation = conn.query("SELECT datcollate FROM pg_database WHERE datname = current_database()")[0][0]
    tried = simple_ones = refused = drawn = 0
    differences: list[str] = []
    seen: set[str] = set()
    read: set[str] = set()
    equal: dict[tuple[str, str], set[int]] = {}  # (a loose column, a text): the rows Postgres says equal it

    def equals(col: str, text: str) -> set[int]:
        if (col, text) not in equal:
            got = conn.query(f"SELECT id FROM rows WHERE {quoted(col)} = $1", [text])
            equal[(col, text)] = {int(str(i)) for (i,) in got}
        return equal[(col, text)]

    def as_read(i: int, node: Node) -> dict[str, Scalar] | str:
        """Row i as a made-up row holds it for the condition: a loose column's value as the text it equals, or
        another; a message when it equals two texts."""
        row = dict(data[i])
        for col, texts in texts_of(node).items():
            if col in LOOSE_COLUMNS and row[col] is not None:
                hits = sorted(t for t in texts if i in equals(col, t))
                if len(hits) > 1:
                    return f"{col} = {sql_value(row[col])} equals each of {hits}, read as two values"
                row[col] = hits[0] if hits else "(another)"
        return row

    for _ in range(args.cases):
        cond = condition(rng)
        if cond in seen:
            continue
        seen.add(cond)
        tried += 1
        node = simple(cond)
        if node is None:
            continue
        answers: dict[str | None, dict[int, bool | None]] = {}
        try:
            for uid in USERS:
                conn.query("SELECT set_config('conditions_test.uid', $1, false)", [uid or ""])
                got = conn.query(f"SELECT id, ({cond}) FROM rows AS this")
                answers[uid] = {int(str(i)): answer(v) for i, v in got}
        except pgwire.PgError:
            refused += 1  # Postgres refuses it (a text compared with a number...): no policy has it
            continue
        if alike_columns([node]):
            drawn += 1  # two texts its column may hold as one: the evaluator draws its rows (evaluate.facts)
            read.add("alike texts, drawn")
            continue
        simple_ones += 1
        read |= kinds(node) | ({"a text on ci"} if "ci" in texts_of(node) else set())
        for uid, pg in answers.items():
            bad: list[tuple[int, object, bool | None]] = []
            for i in range(len(data)):
                row = as_read(i, node)
                ours = row if isinstance(row, str) else truth(node, row, uid)
                if ours != pg[i]:
                    bad.append((i, ours, pg[i]))
            if bad:
                i, ours, theirs = bad[0]
                shown = ", ".join(f"{c} = {sql_value(data[i][c])}" for c in COLUMNS)
                differences.append(
                    f"{{{cond}}} signed in as {uid or 'nobody'}: on ({shown}) conditions.py says {ours}, "
                    f"Postgres {theirs} ({len(bad)} rows)"
                )
                break
    texts = sorted(
        {t for t in TEXTS if plain(t)}
        | {k[1:-1].replace("''", "'") for c in ("s", "ci", "ch") for k in CONSTANTS[c] if k.startswith("'")}
    )
    missed = one_value(conn, texts)
    conn.close()
    subprocess.run(["dropdb", "--if-exists", args.db], capture_output=True)
    failures = [*differences, *missed]
    if simple_ones < tried // 5:
        failures.append(f"only {simple_ones} of {tried} conditions read: fewer than a fifth")
    failures += [f"no condition read as {form}" for form in FORMS if form not in read]
    print(
        f"{tried} conditions, {simple_ones} simple and accepted by Postgres, {drawn} with alike texts (drawn), "
        f"{refused} refused by Postgres, {len(differences)} read otherwise than Postgres (collation {collation}, "
        f"seed {args.seed}); {len(texts)} texts two by two under {len(COLLATIONS)} collations and {len(TYPES)} "
        f"types, {len(missed)} one value and not alike"
    )
    for d in failures[: args.show]:
        print("  " + d)
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
