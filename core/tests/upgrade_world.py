#!/usr/bin/env python3
"""upgrade_world: a world of data made under an older release of rowstile, for tests/upgrade.sh to upgrade and judge.

    python3 tests/upgrade_world.py fill DB SEED          # in a database an older release applied the docs app to
    python3 tests/upgrade_world.py fresh FROM TO POLICY  # TO: a new database, FROM's rows, this version applied
    python3 tests/upgrade_world.py compare FRESH DB...   # each upgraded DB answers as FRESH, and as the reference
    python3 tests/upgrade_world.py differs DB NEW        # what DB holds that applying on a new one doesn't leave

fill makes the docs app's world as difftest makes it (tests/difftest.py's DocsGen, used as a library): its first rows,
shares in every state (live, until tomorrow, expired, not started yet; to users, teams and orgs), shares made through
the release's own `authz.share` as the people who may share (and one taken back with `authz.unshare`), then random
changes (moves, links, team nesting, new and deleted rows, ids changed, several in one transaction) and a subtree
moved last. All of it runs under the release that applied the database: its triggers keep the inheritance tables.

fresh makes the database each upgraded one is held to: the app's schema, the same rows (copied from FROM, in the
order the foreign keys need, with the sequences where FROM left them), this checkout's command applying the policy
on them whole, then the same shares.

compare asks each database what difftest asks (authz.can, authz.list, the rows each RLS policy lets the app role
read, explain, who, the sharing API's verdicts, ... for every user, object and permission) and holds the answers to
the reference evaluator (authzlib/evaluate.py) on the database's own rows, with authz.verify(); then it holds each
upgraded database's answers to the new database's, one by one.

differs prints how many objects the new database holds, then a line for each that differs: the catalog that
tests/migrate_test.py compares a migration by (the inheritance tables' rows among it), and the tables kept across
applies (schema authz), which only an upgrade finds as an older version left them: their columns in order, with
their types and defaults, and their constraints.

Each subcommand prints `ok ...` or `FAIL ...` lines (fill and fresh: only what failed) and exits 1 on a failure.
The docs app is the one upgrade.sh names, the older release's own (UPGRADE_DOCS_POLICY and UPGRADE_DOCS_SCHEMA, from
core/; tests/docs_app.py), core/example's where it doesn't.
"""

from __future__ import annotations

import os
import random
import subprocess
import sys
from collections.abc import Sequence

HERE = os.path.dirname(os.path.abspath(__file__))
CORE = os.path.dirname(HERE)
sys.path.insert(0, CORE)
import compile_policy  # noqa: E402
from authzlib.sqlutil import qt  # noqa: E402
from difftest import DB, Answer, Checker, DocsGen, Ids, Snapshot, idsql, lit, read  # noqa: E402
from migrate_test import objects, psql, snapshot  # noqa: E402

CHANGES = 40  # random changes under the older release, after the first rows and shares
# the tables of schema authz that hold what the app made (the docs app has no custom roles: empty, copied all the same)
MADE = ("shares", "roles", "role_permissions")
# the tables kept across applies, as an older version left them: columns in order, types, defaults, constraints
KEPT = r"""
SELECT 'column ' || c.oid::regclass::text || ' #' || row_number() OVER (PARTITION BY c.oid ORDER BY a.attnum) || ' '
       || a.attname || ' ' || format_type(a.atttypid, a.atttypmod) || CASE WHEN a.attnotnull THEN ' not null' ELSE '' END
       || coalesce(' default ' || pg_get_expr(d.adbin, d.adrelid), '')
FROM pg_class c JOIN pg_attribute a ON a.attrelid = c.oid LEFT JOIN pg_attrdef d ON d.adrelid = c.oid AND d.adnum = a.attnum
WHERE c.relnamespace = 'authz'::regnamespace AND c.relkind IN ('r', 'p') AND a.attnum > 0 AND NOT a.attisdropped
UNION ALL
SELECT 'table ' || conrelid::regclass::text || ' constraint ' || conname || ' ' || pg_get_constraintdef(oid)
FROM pg_constraint WHERE connamespace = 'authz'::regnamespace
ORDER BY 1;
"""


class ReleaseDocsGen(DocsGen):
    """difftest's docs world, on the docs app the older release was released with."""

    policy = os.environ.get("UPGRADE_DOCS_POLICY") or DocsGen.policy
    schema = os.environ.get("UPGRADE_DOCS_SCHEMA") or DocsGen.schema


def sh(*cmd: str, stdin: bytes | None = None) -> bytes:
    p = subprocess.run(list(cmd), input=stdin, capture_output=True)
    if p.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd[:6])}: {p.stderr.decode(errors='replace').strip()}")
    return p.stdout


def ids_of(db: DB, gen: DocsGen) -> Ids:
    pol = compile_policy.parse_policy(read(gen.policy), gen.policy)
    return {
        t.name: [x[0] for x in db.rows(f"SELECT {idsql(t)} FROM {qt(t.table)} ORDER BY 1")] for t in pol.types.values()
    }


def api_shares(db: DB, r: random.Random) -> str:
    """Shares made through authz.share, each by who may make it (the folder's or the file's owner), as the app role:
    live, until tomorrow, not started yet; with a user, a team's members, an org's members. Then one taken back."""
    owned = [("folder", i, o) for i, o in db.rows("SELECT id, owner_id FROM app.folders ORDER BY id")]
    owned += [("file", i, o) for i, o in db.rows("SELECT id, owner_id FROM app.files ORDER BY id")]
    when = ["NULL", "now() + interval '1 day'", "NULL, now() + interval '1 day'"]
    out = ["SET ROLE app_user;"]
    made: list[tuple[str, str]] = []
    for n, (t, i, owner) in enumerate(r.sample(owned, 12)):
        rel = r.choice(["viewer", "editor"]) if t == "folder" else "viewer"
        subject = [("user", str(r.randint(1, 8)), ""), ("team", str(r.randint(10, 15)), "member")]
        if rel == "viewer" and t == "folder":
            subject.append(("org", str(r.randint(1, 2)), "member"))
        st, sid, sr = subject[n % len(subject)]
        out.append(f"SET authz.user_id = {lit(owner)};")
        call = f"{lit(t)}, {lit(i)}, {lit(rel)}, {lit(st)}, {lit(sid)}, {lit(sr)}"
        out.append(f"SELECT authz.share({call}, {when[n % len(when)]});")
        made.append((owner, call))
    out += [f"SET authz.user_id = {lit(made[0][0])};", f"SELECT authz.unshare({made[0][1]});"]
    return "\n".join([*out, "RESET authz.user_id;", "RESET ROLE;"])


def fill(name: str, seed: int) -> list[str]:
    gen, db = ReleaseDocsGen(random.Random(seed)), DB(name)
    db.run(gen.initial())
    db.run(gen.grants())
    db.run(api_shares(db, gen.r))
    problems: list[str] = []
    sqlseed = random.Random(f"upgrade/{seed}/sql")
    for step in range(CHANGES):
        sql = gen.change(ids_of(db, gen))
        code, _, err = db.run(f"SELECT setseed({sqlseed.random():.6f});\n{sql}", check=False)
        if code != 0 and not any(e in err for e in gen.expected_errors):
            problems.append(f"change {step + 1}, under the older release: {sql.splitlines()[0][:100]}: {err.strip()}")
    # a subtree moved, last: the top of the deepest chain under another top, with what hangs under it
    deep = db.rows(
        "WITH RECURSIVE d(id, top, depth) AS (SELECT id, id, 0 FROM app.folders WHERE parent_id IS NULL "
        "UNION ALL SELECT f.id, d.top, d.depth + 1 FROM app.folders f JOIN d ON f.parent_id = d.id) "
        "SELECT top, (SELECT min(id) FROM app.folders WHERE parent_id IS NULL AND id <> d.top) FROM d "
        "ORDER BY depth DESC, id LIMIT 1"
    )
    if deep and deep[0][1]:
        top, under = deep[0]
        db.run(f"UPDATE app.folders SET parent_id = {under} WHERE id = {top};")
    else:
        problems.append("no subtree to move: the world has a single top folder")
    return problems


def tables(db: str) -> list[str]:
    """The app's tables, each after those its foreign keys name."""
    names = psql(
        db,
        "SELECT c.oid::regclass::text FROM pg_class c WHERE c.relnamespace = 'app'::regnamespace "
        "AND c.relkind IN ('r', 'p') AND NOT c.relispartition ORDER BY 1",
    ).split("\n")
    needs: dict[str, set[str]] = {n: set() for n in names if n}
    for line in psql(
        db,
        "SELECT conrelid::regclass::text || ' ' || confrelid::regclass::text FROM pg_constraint "
        "WHERE contype = 'f' AND connamespace = 'app'::regnamespace AND conrelid <> confrelid",
    ).split("\n"):
        if line:
            a, b = line.split(" ")
            needs[a].add(b)
    out: list[str] = []
    while needs:
        ready = sorted(n for n, d in needs.items() if d <= set(out))
        if not ready:
            raise RuntimeError(f"foreign keys in a loop among {sorted(needs)}")
        out.append(ready[0])
        del needs[ready[0]]
    return out


def copy(src: str, dst: str, table: str, columns: str = "*") -> None:
    rows = sh("psql", "-X", "-q", "-d", src, "-c", f"COPY (SELECT {columns} FROM {table}) TO STDOUT")
    into = "" if columns == "*" else f" ({columns})"
    sh("psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", "-d", dst, "-c", f"COPY {table}{into} FROM STDIN", stdin=rows)


def fresh(src: str, dst: str, policy: str) -> list[str]:
    sh("dropdb", "--if-exists", dst)
    sh("createdb", dst)
    schema = os.path.join(CORE, ReleaseDocsGen.schema)
    sh("psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", "-d", dst, "-c", "SET client_min_messages = error", "-f", schema)
    order = tables(src)
    psql(dst, f"TRUNCATE {', '.join(order)} CASCADE;")
    for t in order:
        copy(src, dst, t)
    for seq, value, called in (
        line.split("|")
        for line in psql(
            src,
            "SELECT format('%I.%I', schemaname, sequencename), last_value, "
            "last_value IS NOT NULL FROM pg_sequences WHERE schemaname = 'app'",
        ).split("\n")
        if line
    ):
        if called == "t":
            psql(dst, f"SELECT setval({lit(seq)}, {value});")
    cli = os.path.join(CORE, "cli", "rowstile_cli.py")
    p = subprocess.run([sys.executable, cli, "--db", f"dbname={dst}", "apply", policy], capture_output=True, text=True)
    if p.returncode != 0:
        return [f"this version applies the policy on a new database with the world's rows: {p.stdout}{p.stderr}"]
    # (the columns both have: one the upgrade left out is the catalog's to find, by name)
    for t in MADE:
        have = (
            f"SELECT attname FROM pg_attribute WHERE attrelid = 'authz.{t}'::regclass AND attnum > 0 "
            "AND NOT attisdropped ORDER BY attnum"
        )
        both = set(psql(src, have).split("\n"))
        columns = ", ".join(f'"{c}"' for c in psql(dst, have).split("\n") if c and c in both)
        copy(src, dst, f"authz.{t}", columns)
    return []


class Recording(Checker):
    """difftest's checker, keeping the last snapshot it judged: the database's answers, beside the rows it read."""

    last: Snapshot

    def snapshot(self) -> Snapshot:
        self.last = super().snapshot()
        return self.last


def judged(name: str) -> tuple[Recording, list[str]]:
    gen = ReleaseDocsGen(random.Random(0))
    checker = Recording(DB(name), gen.policy, gen)
    return checker, checker.check()


def every_check(checker: Checker) -> dict[tuple[str, ...], bool]:
    """authz.can for every user (and nobody), every object of every type, every permission (and an id no row has),
    as the app role: {(user, type, id, permission): its answer}."""
    lines = ["SET ROLE app_user;"]
    for u in checker.users:
        lines.append(f"SET authz.user_id = {lit(u)};" if u else "RESET authz.user_id;")
        for t in checker.types.values():
            for p in t.perms:
                lines.append(
                    f"SELECT {lit(u)}, {lit(t.name)}, i, {lit(p)}, authz.can({lit(t.name)}, i, {lit(p)}) FROM "
                    f"(SELECT {idsql(t)} AS i FROM {qt(t.table)} UNION SELECT '999999') ids;"
                )
    out = {tuple(row[:4]): row[4] == "t" for row in checker.db.rows("\n".join([*lines, "RESET ROLE;"]))}
    if len(out) < 100:
        raise RuntimeError(f"{checker.db.name}: only {len(out)} checks asked")
    return out


def sampled(value: Answer) -> dict[str, Answer]:
    """An answer about a sample of the rows (authz.can on TABLESAMPLE'd ids: [[id, answer], ...]), by id."""
    return {str(x[0]): x[1] for x in value} if isinstance(value, list) else {}


def differences(a: Snapshot, b: Snapshot) -> list[str]:
    """Each of difftest's answers that differs between two snapshots; those about a sample of the rows (which differs
    from one snapshot to the next) on the rows both asked about."""
    out: list[str] = []
    for key in sorted(set(a) | set(b), key=repr):
        x, y = a.get(key), b.get(key)
        if "can" in key[:2] and x is not None and y is not None:
            sx, sy = sampled(x), sampled(y)
            x, y = ({i: s[i] for i in set(sx) & set(sy)} for s in (sx, sy))
        if x != y:
            out.append(f"{key}: {x!r:.160}, a new database: {y!r:.160}")
    return out


def compare(new: str, upgraded: Sequence[str]) -> int:
    fails = 0

    def ok(label: str, problems: list[str]) -> None:
        nonlocal fails
        if problems:
            fails += 1
            print(f"FAIL  {label}: {len(problems)} problem(s)\n" + "\n".join(f"    {p}" for p in problems[:12]))
        else:
            print(f"ok    {label}")

    base, problems = judged(new)
    ok("world, a new database with its rows: its answers are the reference evaluator's", problems)
    checks = every_check(base)
    for name in upgraded:
        way = name.rsplit("_", 1)[-1]
        checker, problems = judged(name)
        ok(f"world, {way}: its answers are the reference evaluator's, and authz.verify() says true", problems)
        ok(
            f"world, {way}: difftest's questions, every user's, have a new database's answers",
            differences(checker.last, base.last),
        )
        got = every_check(checker)
        ok(
            f"world, {way}: authz.can, for every user, object and permission, answers as on a new database ({len(checks)} checks)",
            [
                f"{k}: {got.get(k)}, a new database: {checks.get(k)}"
                for k in sorted(set(got) | set(checks))
                if got.get(k) != checks.get(k)
            ],
        )
    return fails


def differs(db: str, new: str) -> None:
    upgraded, fresh_db = (objects(snapshot(d) + "\n" + psql(d, KEPT)) for d in (db, new))
    print(len(fresh_db))
    for k in sorted(set(upgraded) | set(fresh_db)):
        if k not in fresh_db:
            print(f"  only in the upgraded database: {k}")
        elif k not in upgraded:
            print(f"  only in the new one: {k}")
        elif upgraded[k] != fresh_db[k]:
            a, b = upgraded[k].split("\n"), fresh_db[k].split("\n")
            i = next((i for i, (x, y) in enumerate(zip(a, b, strict=False)) if x != y), min(len(a), len(b)))
            print(
                f"  differs: {k}\n    upgraded: {a[i] if i < len(a) else '(end)'}\n    new:      {b[i] if i < len(b) else '(end)'}"
            )


def main(argv: list[str]) -> int:
    os.chdir(CORE)
    match argv:
        case ["fill", db, seed]:
            problems = fill(db, int(seed))
        case ["fresh", src, dst, policy]:
            problems = fresh(src, dst, policy)
        case ["compare", new, *upgraded] if upgraded:
            return 1 if compare(new, upgraded) else 0
        case ["differs", db, new]:
            differs(db, new)
            return 0
        case _:
            print((__doc__ or "").split("\n\n")[1], file=sys.stderr)
            return 2
    for p in problems:
        print(f"FAIL  {p}")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
