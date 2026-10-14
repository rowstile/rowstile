#!/usr/bin/env python3
"""rewrites: the review's "no change in access", held against the database.

    python3 tests/rewrites.py --policies 12 --seed 1 [--db authz_rewrites]

`rowstile review` says of a pull request that only rewrites permissions and rules whether it grants the same as
before: it compares the two policies in small worlds made up for them, with the reference evaluator, and shows the
first difference it finds or says there is none (authzlib/review.py, Meaning). It reads no database for that. This
holds the verdict against one.

For each random policy (genpolicy's), a permission or a select rule is rewritten a few times:

  - in ways that change nothing, by what `or`, `and` and `not` mean: its parts turned round, a part said twice,
    `or nobody`, `and anyone`, a part absorbed (`a or (a and b)`), an `and` of an `or` written out;
  - in ways that may: an `and` for an `or`, a part dropped, one relation in place of another, `and not` added.

The policy is applied to a database with its random data, and for each rewrite the database says who would gain and
lose what were the rewrite applied (database.diff: authz.list and the rows each select rule shows, for every user,
every other principal and nobody, before and after; what `rowstile review` shows as Access), on the data as made and
again after a few random changes. A policy fails when

  - the review says the rewrite grants the same, and the database's answers change;
  - a rewrite that changes nothing is given a difference by the review, or changes the database's answers.

A rewrite that may change something, and for which the review shows a difference, is counted: with the database's
answers changing too, or on data that doesn't show it. And the first such difference of each policy is replayed in a
database of its own: the small world the review found it in, made as rows (small.load_sql), under the policy and then
under the rewrite; the user's answer must be the review's, before and after. Rows can't be made to hold a condition the
evaluator doesn't read as a fact about the row (a subquery, a function) where the world says: such a condition holds
where they say. So what the rows hold is read back (difftest's queries), and the user's answer must be the reference
evaluator's on that: the review's, where the rows hold its world; and they must hold it but for such conditions. A
world rows can't make (custom roles, keys of several columns or uuids) is counted, not replayed. A policy
the compiler refuses, or whose answers take seconds to read (a diff asks for all of them, as everyone), is not
checked, and counted so.
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import os
import random
import re
import subprocess
import sys
import tempfile
import time
from collections import Counter
from collections.abc import Callable, Iterator
from typing import NamedTuple

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "cli"))
import pgwire  # noqa: E402
import rowstile_cli  # noqa: E402
from authzlib import Compiler, PolicyError, database, evaluate, parse_policy, review  # noqa: E402
from authzlib.conditions import simple  # noqa: E402
from authzlib.parse import KEYWORDS, Policy  # noqa: E402
from authzlib.sqlutil import qt  # noqa: E402
from difftest import DB, Ids, idsql, lit  # noqa: E402
from difftest import Reference as Reader  # noqa: E402
from genpolicy import CONDS, Node, Spec, atoms, gen_class, make, policy_text, schema_text, write_policy  # noqa: E402
from small import Unloadable, load_sql  # noqa: E402

Path = tuple[int, ...]


class Rewrite(NamedTuple):
    what: str  # 't1.p2: a part said twice'
    same: bool  # it changes nothing, by what or, and and not mean
    spec: Spec


# ----------------------------------------------------------------------
# An expression's parts
# ----------------------------------------------------------------------
def paths(n: Node, at: Path = ()) -> Iterator[Path]:
    """Where each part of an expression is: the path to it, itself first."""
    yield at
    if not isinstance(n, str):
        for k, x in enumerate(n[1]):
            yield from paths(x, (*at, k))


def part(n: Node, path: Path) -> Node:
    for k in path:
        assert not isinstance(n, str)
        n = n[1][k]
    return n


def with_part(n: Node, path: Path, new: Node) -> Node:
    if not path:
        return new
    assert not isinstance(n, str)
    return (n[0], [with_part(x, path[1:], new) if k == path[0] else x for k, x in enumerate(n[1])])


def under_not(n: Node, path: Path) -> bool:
    """Whether a part is what a `not` denies, or inside it: left as it is (a `not` takes away from an `and`)."""
    return any(not isinstance(x, str) and x[0] == "not" for x in (part(n, path[:k]) for k in range(len(path))))


def is_not(n: Node) -> bool:
    return not isinstance(n, str) and n[0] == "not"


# ----------------------------------------------------------------------
# The rewrites: each gives the part rewritten, or None where it has nothing to do
# ----------------------------------------------------------------------
def turned(n: Node, r: random.Random, names: list[str]) -> Node | None:
    """Its parts the other way round (what a `not` denies stays last: it takes away from what is before it)."""
    if isinstance(n, str) or n[0] == "not" or len(n[1]) < 2:
        return None
    keep = [x for x in n[1] if not is_not(x)]
    return (n[0], [*reversed(keep), *(x for x in n[1] if is_not(x))])


def twice(n: Node, r: random.Random, names: list[str]) -> Node | None:
    return None if is_not(n) else (r.choice(["or", "and"]), [n, n])


def or_nobody(n: Node, r: random.Random, names: list[str]) -> Node | None:
    return None if is_not(n) else ("or", [n, "nobody"])


def and_anyone(n: Node, r: random.Random, names: list[str]) -> Node | None:
    return None if is_not(n) else ("and", [n, "anyone"])


def absorbed(n: Node, r: random.Random, names: list[str]) -> Node | None:
    """a or (a and b): b adds nothing."""
    return None if is_not(n) else ("or", [n, ("and", [n, r.choice(names)])])


def written_out(n: Node, r: random.Random, names: list[str]) -> Node | None:
    """a and (b or c) as (a and b) or (a and c)."""
    if isinstance(n, str) or n[0] != "and":
        return None
    ors = [k for k, x in enumerate(n[1]) if not isinstance(x, str) and x[0] == "or"]
    if not ors:
        return None
    k = r.choice(ors)
    inner = n[1][k]
    assert not isinstance(inner, str)
    return ("or", [("and", [x if j != k else y for j, x in enumerate(n[1])]) for y in inner[1]])


def other_word(n: Node, r: random.Random, names: list[str]) -> Node | None:
    """An `and` for an `or`, and the other way (an `or` takes no `not`: left as it is with one)."""
    if isinstance(n, str) or n[0] == "not" or any(is_not(x) for x in n[1]):
        return None
    return ("and" if n[0] == "or" else "or", n[1])


def dropped(n: Node, r: random.Random, names: list[str]) -> Node | None:
    if isinstance(n, str) or n[0] == "not":
        return None
    k = r.randrange(len(n[1]))
    left = [x for j, x in enumerate(n[1]) if j != k]
    if not left or all(is_not(x) for x in left):
        return None
    return left[0] if len(left) == 1 else (n[0], left)


def another(n: Node, r: random.Random, names: list[str]) -> Node | None:
    others = [a for a in [*names, *CONDS] if a != n]
    return r.choice(others) if isinstance(n, str) and others else None


def and_not(n: Node, r: random.Random, names: list[str]) -> Node | None:
    return None if is_not(n) else ("and", [n, ("not", [r.choice(CONDS[:3])])])


Law = Callable[[Node, random.Random, list[str]], "Node | None"]
SAME: dict[str, Law] = {
    "its parts turned round": turned,
    "a part said twice": twice,
    "`or nobody`": or_nobody,
    "`and anyone`": and_anyone,
    "a part absorbed": absorbed,
    "an `and` of an `or` written out": written_out,
}
OTHER: dict[str, Law] = {
    "an `and` for an `or`": other_word,
    "a part dropped": dropped,
    "another in a relation's place": another,
    "`and not` added": and_not,
}


def rewrites(spec: Spec, r: random.Random, each: int) -> list[Rewrite]:
    """`each` rewrites that change nothing and as many that may, of the policy's permissions and select rules, each
    of one part of one of them; fewer where the draws find nothing to rewrite."""
    targets: list[tuple[int, str, Node]] = []  # (the type's place, the permission's name or '' for its select rule)
    for k, o in enumerate(spec.objs):
        targets += [(k, p, n) for p, n in o.perms.items()]
        targets += [(k, "", n) for head, n in o.rules if head == "select"]
    out: list[Rewrite] = []
    for same, laws in ((True, SAME), (False, OTHER)):
        made = 0
        for _ in range(each * 20 if targets else 0):
            if made == each:
                break
            k, p, n = r.choice(targets)
            o = spec.objs[k]
            name, law = r.choice(sorted(laws.items()))
            path = r.choice([x for x in paths(n) if not under_not(n, x)])
            new = law(
                part(n, path), r, sorted({a for x in o.perms.values() for a in atoms(x) if not a.startswith("{")})
            )
            if new is None or with_part(n, path, new) == n:
                continue
            node = with_part(n, path, new)
            if p:
                rewritten = dataclasses.replace(o, perms={**o.perms, p: node})
            else:
                rewritten = dataclasses.replace(o, rules=[(h, node if h == "select" else x) for h, x in o.rules])
            what = f"{o.name}.{p}" if p else f"{o.name}'s select rule"
            objs = [rewritten if j == k else x for j, x in enumerate(spec.objs)]
            out.append(Rewrite(f"{what}: {name}", same, dataclasses.replace(spec, objs=objs)))
            made += 1
    return out


# ----------------------------------------------------------------------
# One policy
# ----------------------------------------------------------------------
class Refused(Exception):
    """The compiler refused the policy, or its reads are slow: lint says so, or one diff took more than SLOW."""


SLOW = 5.0  # seconds for one diff: such a policy's rewrites would take minutes, and say nothing more


class Tally:
    def __init__(self) -> None:
        self.same = self.agreed = self.shown = self.unshown = self.refused = self.beyond = 0
        self.replayed = 0
        self.reread = 0  # (replayed where a condition the review can't read holds where the rows say)
        self.unloadable: Counter[str] = Counter()  # (why rows can't make the world)


def said(m: review.Meaning) -> str:
    """The review's verdict on a rewrite, in a few words."""
    found = m.get("counterexample")
    if found:
        return f"{found['what']} differs for user {found['user']} on {found['object']}"
    return f"grants the same ({m['equivalent']})" if m.get("equivalent") else "no verdict"


LINK = "tok1"  # the share link's token the review's worlds hold (evaluate.first_difference), and the session here


def opaque(pol: Policy) -> tuple[set[evaluate.CondKey], set[str]]:
    """The conditions the evaluator doesn't read as facts about the row (a subquery, a function, conditions.py's
    limits): a world says which rows they hold for, and rows can't be made to say so. And the types whose `where`
    is one."""
    conds = {k for k in evaluate.Reference(pol).conditions() if k[1] not in KEYWORDS.values() and simple(k[1]) is None}
    return conds, {t.name for t in pol.types.values() if t.where and simple(t.where) is None}


def rows_hold(pol: Policy, world: evaluate.Data, back: evaluate.Data, user: str) -> str | None:
    """Whether the rows made of a world hold it, for what the policy grants the user: back is what they hold, read
    from them as difftest reads a database. None when the policy grants the same in both; "conditions" when it
    does once the conditions the evaluator doesn't read (and such a `where`) hold where the rows say; else the
    first thing granted otherwise (the rows aren't the world: the loader's mistake, or the evaluator's reading of
    a condition)."""
    ref = evaluate.Reference(pol)
    got = ref.evaluate(back, user, {hashlib.sha256(LINK.encode()).hexdigest()})
    if ref.evaluate(world, user, (LINK,)) == got:
        return None
    conds, wheres = opaque(pol)
    world = dataclasses.replace(
        world,
        cond={**world.cond, **{k: back.cond[k] for k in conds}},
        valid={**world.valid, **{t: back.valid[t] for t in wheres}},
    )
    want = ref.evaluate(world, user, (LINK,))
    if want == got:
        return "conditions"
    t, name = min(k for k in want.keys() | got.keys() if want.get(k) != got.get(k))
    return f"{t}.{name} holds on {sorted(want.get((t, name), ()))} in the world, {sorted(got.get((t, name), ()))} in its rows"


def replay(
    spec: Spec, base: review.Side, new: str, m: review.Meaning, sql: str, db: DB, worlds: int, tally: Tally
) -> str | None:
    """A difference the review shows, replayed in a database (db's name, _replay): the world it was found in made as
    rows under the policy (its compiled sql), then under the rewrite (new); the user's answer asked each time
    (authz.can) must be the review's. A condition the evaluator doesn't read holds where the rows say, which may not
    be where the world says: so what the rows hold is read back (difftest's queries), and the database must answer
    as the reference evaluator does on that; the review's world, where the rows hold it. The problem, if any;
    Unloadable if rows can't make that world."""
    found = m.get("counterexample")
    assert found is not None
    if m.get("unreadable") or not re.fullmatch(r"\w+\.\w+", found["what"]):
        raise Unloadable("a rule's difference, or one in conditions the review can't read")
    if spec.spelling.keytype == "uuid":
        raise Unloadable("uuid keys (a world's ids are numbers)")
    spec = dataclasses.replace(spec, spelling=dataclasses.replace(spec.spelling, words=()))  # (numbers, not words)
    head = parse_policy(new, "new.authz")
    first = evaluate.first_difference(base.pol, head, worlds=worlds)
    assert first is not None and first[0] == found, (first, found)  # (the review's own, found again)
    _, world_a, world_b = first
    tname, perm = found["what"].split(".")
    rows, shares = load_sql(base.pol, world_a, rows_decide=True)
    user = "" if found["user"].startswith("(") else found["user"]
    kind, pid = evaluate.principal_of(user, base.pol.types)
    # (asked holding a share link's first token, as the review's worlds are: evaluate.compare)
    signed = (
        f"SET authz.user_id = {lit(pid)}; SET authz.principal_type = {lit('' if kind == 'user' else kind)};\n"
        f"SET authz_ctx.links = {lit(LINK)};\n"
    )
    there = DB(f"{db.name}_replay")
    there.recreate()
    there.run(schema_text(spec))
    # a made-up world's columns may be NULL where the app's table says they can't be: they may here
    there.run(
        "DO $$ DECLARE c record; BEGIN FOR c IN SELECT table_schema, table_name, column_name FROM "
        "information_schema.columns WHERE table_schema NOT IN ('pg_catalog', 'information_schema') AND is_nullable = 'NO' "
        "AND column_default IS NOT NULL LOOP EXECUTE format('ALTER TABLE %I.%I ALTER COLUMN %I DROP NOT NULL', "
        "c.table_schema, c.table_name, c.column_name); END LOOP; END $$;"
    )
    for step, applying in ((rows, False), (sql, True), (shares, False)):
        code, _, err = there.run(step, check=applying)
        if code != 0:  # (a value the app's table doesn't take: a world made up for the policy alone)
            raise Unloadable(err.strip().splitlines()[0])

    def answer(pol: Policy) -> tuple[bool, evaluate.Data]:
        """The user's answer, and what the rows hold for the evaluator (read in the user's session)."""
        lines = [signed, f"SELECT 'can', authz.can({lit(tname)}, {lit(found['object'])}, {lit(perm)});"]
        lines += [f"SELECT {lit(json.dumps(list(key)))}, ({q});" for key, q in Reader(pol).data_queries()]
        got = there.rows("\n".join(lines))
        assert got[0][0] == "can", got[0]
        return got[0][1] == "t", evaluate.Data.of({tuple(json.loads(k)): json.loads(v) for k, v in got[1:]})

    before, back_a = answer(base.pol)
    there.run(Compiler(parse_policy(new, "new.authz")).compile("new.authz"))  # (compiling changes the policy)
    after, back_b = answer(head)
    subprocess.run(["dropdb", "--if-exists", there.name], capture_output=True)
    said = (
        f"the review says {found['what']} on {found['object']} for {found['user']} goes from {found['before']} to "
        f"{found['after']}"
    )
    world = "in the world: " + "; ".join(found["world"])
    held = [rows_hold(base.pol, world_a, back_a, user), rows_hold(head, world_b, back_b, user)]
    for h, which in zip(held, ("the policy", "the rewrite"), strict=True):
        if h not in (None, "conditions"):
            return f"{said}; its rows don't hold that world under {which}: {h}; {world}"
    links = {hashlib.sha256(LINK.encode()).hexdigest()}
    want = tuple(
        found["object"] in evaluate.Reference(pol).evaluate(back, user, links)[(tname, perm)]
        for pol, back in ((base.pol, back_a), (head, back_b))
    )
    if held == [None, None] and want != (found["before"], found["after"]):
        return f"{said}; on its rows, which hold that world, the reference says from {want[0]} to {want[1]}; {world}"
    if (before, after) != want:
        on = (
            "" if want == (found["before"], found["after"]) else f", on what its rows hold, from {want[0]} to {want[1]}"
        )
        return f"{said}{on}; replayed in a database, from {before} to {after}, {world}"
    tally.reread += "conditions" in held
    return None


def run(spec: Spec, db: DB, workdir: str, each: int, rounds: int, changes: int, worlds: int, tally: Tally) -> list[str]:
    """The problems found with this policy's rewrites (none: it passed); Refused if the policy isn't checked."""
    policy_path = os.path.join(workdir, "gen.authz")
    text = policy_text(spec)
    write_policy(policy_path, text, False)
    compiled = subprocess.run([sys.executable, "compile_policy.py", policy_path], capture_output=True, text=True)
    if compiled.returncode != 0 or "view definitions to plan" in compiled.stdout:
        raise Refused
    r = random.Random(f"rewrites/{spec.seed}")
    base = review.Side(text, None, None)
    tried: list[tuple[Rewrite, str, review.Meaning]] = []
    for rw in rewrites(spec, r, each):
        new = policy_text(rw.spec)
        try:
            m = review.meaning(base, review.Side(new, None, None), worlds)
        except PolicyError:
            tally.refused += 1  # (the compiler refuses the rewrite: a `not` where none may be, a deny off its links)
            continue
        tried.append((rw, new, m))
    gen = gen_class(spec, policy_path, os.path.join(workdir, "gen_schema.sql"))(random.Random(spec.seed))
    db.recreate()
    db.run(schema_text(spec))
    db.run(gen.initial())
    db.run(compiled.stdout)
    db.run(gen.grants())
    conn = pgwire.connect(**pgwire.parse_dsn(f"dbname={db.name}"))
    problems: list[str] = []
    changed: set[str] = set()  # the rewrites the database's answers changed with, on some data
    try:
        for n in range(rounds):
            for rw, new, m in tried:

                def diff(d: rowstile_cli.Db, new: str = new) -> list[database.DiffRow]:
                    return database.diff(d, new)

                started = time.monotonic()
                rows = rowstile_cli.transaction(conn, diff, keep=False)
                if time.monotonic() - started > SLOW:
                    raise Refused
                first = (
                    f"{rows[0]['change']} {rows[0]['what']} on {rows[0]['type']} {rows[0]['id']} "
                    f"for {rows[0]['user_id'] or 'nobody'}"
                    if rows
                    else ""
                )
                if rows:
                    changed.add(rw.what)
                if rows and m.get("equivalent"):
                    problems.append(
                        f"{rw.what}: the review says it {said(m)}, and in the database {len(rows)} answers "
                        f"change (round {n}): {first}"
                    )
                elif rows and rw.same:
                    problems.append(
                        f"{rw.what}: it changes nothing, and in the database {len(rows)} answers change "
                        f"(round {n}): {first}"
                    )
            if n + 1 < rounds:
                for _ in range(changes):
                    ids: Ids = {
                        t.name: [x[0] for x in db.rows(f"SELECT {idsql(t)} FROM {qt(t.table)} ORDER BY 1")]
                        for t in base.pol.types.values()
                    }
                    sql = gen.change(ids)
                    code, _, err = db.run(sql, check=False)
                    if code != 0 and not any(e in err for e in gen.expected_errors):
                        return [f"round {n}: unexpected error", f"  {sql}", f"  {err.strip()}"]
    finally:
        conn.close()
    for rw, new, m in tried:
        if rw.same or not m.get("counterexample"):
            continue
        try:
            wrong = replay(spec, base, new, m, compiled.stdout, db, worlds, tally)
        except Unloadable as e:
            tally.unloadable[str(e)] += 1
            continue
        tally.replayed += 1
        if wrong:
            problems.append(f"{rw.what}: {wrong}")
        break  # (one a policy)
    for rw, _, m in tried:
        if rw.same and not m.get("equivalent"):
            problems.append(f"{rw.what}: it changes nothing, and the review says: {said(m)}")
        elif rw.same:
            tally.same += 1
        elif m.get("equivalent"):
            tally.agreed += 1  # (it may change something; here it doesn't, the review says, and the database agreed)
        elif m.get("counterexample"):
            tally.shown += rw.what in changed
            tally.unshown += rw.what not in changed
        else:
            tally.beyond += 1
    return problems


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--db", default="authz_rewrites")
    ap.add_argument("--policies", type=int, default=12)
    ap.add_argument("--seed", type=int, default=1, help="the first policy's seed (each policy: the next one)")
    ap.add_argument("--only", type=int, help="run this one seed, and print its policy")
    ap.add_argument("--each", type=int, default=3, help="rewrites of each kind for a policy")
    ap.add_argument("--rounds", type=int, default=2, help="how many times the database is asked: as made, then ...")
    ap.add_argument("--changes", type=int, default=6, help="... after this many random changes each time")
    ap.add_argument("--worlds", type=int, default=200, help="the small worlds the review compares in (its own: 200)")
    args = ap.parse_args()
    os.chdir(ROOT)
    db = DB(args.db)
    seeds = [args.only] if args.only is not None else list(range(args.seed, args.seed + args.policies))
    tally = Tally()
    failed = passed = skipped = 0
    with tempfile.TemporaryDirectory() as workdir:
        for seed in seeds:
            spec = make(seed)
            if args.only is not None:
                print(f"seed {seed}:\n{policy_text(spec)}")
            try:
                problems = run(spec, db, workdir, args.each, args.rounds, args.changes, args.worlds, tally)
            except Refused:
                skipped += 1
                continue
            if not problems:
                passed += 1
                continue
            failed += 1
            print(f"seed {seed}: the review and the database disagree")
            for p in problems[:12]:
                print("   ", p)
    subprocess.run(["dropdb", "--if-exists", args.db], capture_output=True)
    print(
        f"rewrites seeds {seeds[0]}..{seeds[-1]}: {passed} policies passed, {failed} failed, {skipped} not checked "
        f"(refused, or slow to read); {tally.same} rewrites that change nothing, said so and seen so; of those that "
        f"may change something, {tally.shown} the review and the database both show changing, {tally.unshown} the "
        f"review shows and this data doesn't, {tally.agreed} that change nothing here, {tally.beyond} beyond the "
        f"review; {tally.refused} rewrites the compiler refuses; {tally.replayed} of the review's differences replayed "
        f"in a database, {tally.reread} of them where a condition the review can't read holds where the rows say "
        f"({sum(tally.unloadable.values())} in worlds rows can't make"
        + "".join(f"; {n}: {why}" for why, n in sorted(tally.unloadable.items()))
        + ")"
    )
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
