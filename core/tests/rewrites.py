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
answers changing too, or on data that doesn't show it. A policy the compiler refuses, or whose answers take seconds
to read (a diff asks for all of them, as everyone), is not checked, and counted so.
"""

from __future__ import annotations

import argparse
import dataclasses
import os
import random
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable, Iterator
from typing import NamedTuple

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "cli"))
import pgwire  # noqa: E402
import rowstile_cli  # noqa: E402
from authzlib import PolicyError, database, review  # noqa: E402
from authzlib.sqlutil import qt  # noqa: E402
from difftest import DB, Ids, idsql  # noqa: E402
from genpolicy import CONDS, Node, Spec, atoms, gen_class, make, policy_text, schema_text, write_policy  # noqa: E402

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


def said(m: review.Meaning) -> str:
    """The review's verdict on a rewrite, in a few words."""
    found = m.get("counterexample")
    if found:
        return f"{found['what']} differs for user {found['user']} on {found['object']}"
    return f"grants the same ({m['equivalent']})" if m.get("equivalent") else "no verdict"


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
        f"review; {tally.refused} rewrites the compiler refuses"
    )
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
