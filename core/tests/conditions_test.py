#!/usr/bin/env python3
"""conditions_test: the simple conditions the reference evaluator reads itself mean what Postgres says they mean.

    PGHOST=... PGUSER=... python3 tests/conditions_test.py [--cases 3000] [--seed 1] [--db authz_conditions]

`rowstile prove` and the review's refactor check read a simple condition (`{not archived}`, `{size > 10}`,
`{owner_id = authz.uid()}`) as a fact about a made-up row (authzlib/conditions.py); difftest never does, it asks
the database for each condition's rows. So this asks both: conditions made up at random over columns of each kind
(boolean, integer, numeric, double precision, text, and a column a relation reads, whose values the evaluator
holds as the ids' text; some named only in quotes, "B" beside b, "order"), every one Postgres accepts asked on the
same rows, signed in as each user and as nobody. Whatever
conditions.py takes as simple must give Postgres's answer on every row: true, false or NULL. One it doesn't take
(a function, arithmetic, a cast) is left to the database, as any other condition.
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
from authzlib.conditions import Scalar, simple, truth  # noqa: E402

# each column's values (None: NULL), as Python holds them in a made-up world, and as SQL writes them
COLUMNS: dict[str, tuple[str, list[Scalar]]] = {
    "b": ("boolean", [True, False, None]),
    "n": ("integer", [-1, 0, 1, 9, 10, 11, None]),
    # a decimal is read exactly, as numeric holds it; one with more digits than a double keeps is not read
    "x": ("numeric", [Decimal("0.5"), 1, Decimal("1.5"), 10, Decimal("0.1"), Decimal("1.00000000000000001"), None]),
    "f": ("double precision", [Decimal("0.5"), 1, Decimal("1.5"), Decimal("0.1"), Decimal("0.3"), None]),
    "s": ("text", ["a", "b", "A", "B", "ab", "x", "it's", "10", "9", "", " a", None]),
    # a relation's column (`owner : user = o`): the evaluator holds its values as the linked ids' text
    "o": ("bigint", ["1", "2", "10", None]),
    # columns named in quotes: case kept ("B" is not b), a word SQL keeps for itself, a quote inside
    "B": ("boolean", [False, None, True]),
    "order": ("integer", [1, 2, None]),
    'a"b': ("text", ["a", "b", None]),
}
BOOLEANS = ("b", "B")
USERS = ["1", "2", "10", None]  # who is signed in: authz.uid(); None, nobody
# the constants a condition compares each column with: some of another kind, as SQL allows ('10' for a number)
CONSTANTS: dict[str, list[str]] = {
    "b": ["true", "false", "TRUE", "'true'", "'t'", "'f'", "'yes'", "null"],
    "n": ["-1", "0", "1", "9", "10", "11", "9.5", "10.0", "'10'", "'010'", "'9'", "1e1", "'x'", "null"],
    "x": ["0.5", "1", "1.0", "1.50", "10", "'1.5'", "'1.50'", "1e1", "1.5e0", "0.1", "0.10", "null"]
    + ["1.00000000000000001", "1.000000000000001", "100.000000000000000000", "0.000000000000001", "0.0000000000000001"],
    "f": ["0.5", "1", "1.50", "0.1", "0.3", "0.30000000000000001", "0.1000000000000001", "100000000000000.1", "null"],
    "s": ["'a'", "'b'", "'A'", "'B'", "'ab'", "'it''s'", "'10'", "'9'", "''", "' a'", "10", "null"],
    "o": ["1", "2", "10", "'1'", "'10'", "9", "null"],
    "B": ["true", "false", "'t'", "null"],
    "order": ["1", "2", "1.5", "'2'", "null"],
    'a"b': ["'a'", "'b'", "'A'", "null"],
}
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
                f"{col} + 1 > 2" if c in ("n", "x", "f", "order") else f"coalesce({col}, {k}) = {k}",
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
    tried = simple_ones = refused = 0
    differences: list[str] = []
    seen: set[str] = set()
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
        simple_ones += 1
        for uid, pg in answers.items():
            bad = [(i, ours, pg[i]) for i, r in enumerate(data) if (ours := truth(node, r, uid)) != pg[i]]
            if bad:
                i, ours, theirs = bad[0]
                shown = ", ".join(f"{c} = {sql_value(data[i][c])}" for c in COLUMNS)
                differences.append(
                    f"{{{cond}}} signed in as {uid or 'nobody'}: on ({shown}) conditions.py says {ours}, "
                    f"Postgres {theirs} ({len(bad)} rows)"
                )
                break
    conn.close()
    subprocess.run(["dropdb", "--if-exists", args.db], capture_output=True)
    print(
        f"{tried} conditions, {simple_ones} simple and accepted by Postgres, {refused} refused by Postgres, "
        f"{len(differences)} read otherwise than Postgres (collation {collation}, seed {args.seed})"
    )
    for d in differences[: args.show]:
        print("  " + d)
    sys.exit(1 if differences else 0)


if __name__ == "__main__":
    main()
