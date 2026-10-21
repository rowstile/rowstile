"""rowstile prove: every invariant checked in many small worlds, with no database.

An invariant (`never folder: share and not org.member`) says no one may ever hold that on any object. The
reference evaluator (evaluate.py) computes what the policy grants in made-up worlds, smallest first (1 object
of each type, then up to 4, every kind of link and share, columns that simple conditions read, every other
{condition} true or false per row), as each
person who can sign in and as nobody. At each size, worlds drawn row by row take turns with the corners
(evaluate.corners: each condition true on every row or on none): a counterexample that needs several conditions to
hold at once is rare in a draw (one world in nine for two coin tosses of three values, per row), and found in a
corner in a few worlds. Then the worlds a draw rarely makes (evaluate.rare_worlds): dense ones, where a link table
holds half its links or nearly all (a long `and` of links), and, for a policy that reads 2 links deep or more, chains
one link longer than it reads. A world where someone holds it is a counterexample, shrunk link by link
to the smallest that still breaks the invariant, and printed as a reviewer can read it. The same engine checks
that a refactor changed nothing in rowstile review.
"""

from __future__ import annotations

from typing import NotRequired, TypedDict

from .evaluate import Data, Reference, World, alike_in, kept_rows, principal_of, smallest, worlds_to_try
from .parse import Invariant, Policy

WORLDS = 400
MAX_SIZE = 4


class Proof(TypedDict):
    """What prove() found for one invariant."""

    invariant: str  # 'never type: expression'
    type: str
    line: str
    holds: bool
    worlds: int  # how many worlds were tried
    size: NotRequired[int]  # the most rows of a type a world tried had
    who: NotRequired[str]  # for a broken one: who holds it ('nobody', a user id, 'bot:2')
    object: NotRequired[str]  # ...on which object
    world: NotRequired[list[str]]  # ...in this world, the smallest found


def broken(ref: Reference, inv: Invariant, data: Data) -> tuple[str, str] | None:
    """(who, object) for someone holding the invariant's expression somewhere in this world, or None."""
    t = ref.types[inv.type]
    for user in World.principals_in(ref.pol, data):
        state = ref.evaluate(data, user, ("tok1",))
        bad = ref.eval_expr(state, t, inv.expr) & set(data.valid[t.name])
        if bad:
            return (user or "nobody"), sorted(bad)[0]
    return None


def shrink(ref: Reference, inv: Invariant, data: Data) -> Data:
    """The world with every link, share and condition taken away that the counterexample doesn't need (a row its
    type's where keeps keeps what the where needs)."""
    return smallest(data, lambda d: broken(ref, inv, d) is not None, kept_rows(ref.pol, alike_in([ref.pol])))


def prove(pol: Policy, worlds: int = WORLDS, seed: int = 0, max_size: int = MAX_SIZE) -> list[Proof]:
    """One result per invariant: whether it held in every world tried, and for a broken one who holds it, on
    what, in which world."""
    ref = Reference(pol)
    out: list[Proof] = []
    for inv in pol.invariants:
        result: Proof = {
            "invariant": f"never {inv.type}: {inv.src}",
            "type": inv.type,
            "line": str(inv.loc),
            "holds": True,
            "worlds": 0,
        }
        n = 0
        tried = list(worlds_to_try([pol], worlds, str(seed), max_size, by_size=True))
        result["size"] = max(w.size for w in tried)
        for w in tried:
            n += 1
            data = w.data(pol)
            if broken(ref, inv, data):
                small = shrink(ref, inv, data)
                found = broken(ref, inv, small)
                assert found is not None  # shrink keeps the world broken
                who, obj = found
                # the rows of the types the counterexample names: the invariant's, the holder's, and those the world
                # says something of (its links, roles, conditions and columns)
                used = {inv.type, *([principal_of(who, pol.types)[0]] if who != "nobody" else [])}
                lines = w.describe(pol, small, used | World.named(pol, small))
                result.update(holds=False, who=who, object=obj, world=lines)
                break
        result["worlds"] = n
        out.append(result)
    return out


def describe(results: list[Proof], max_size: int = MAX_SIZE) -> str:
    lines = []
    for r in results:
        lines.append(f"{r['line']}: {r['invariant']}")
        if r["holds"]:
            size = r.get("size", max_size)
            lines.append(
                f"  ok   holds in every world tried ({plural(r['worlds'], 'world')}, up to {size} of each type)"
            )
        else:
            who = r.get("who", "nobody")
            who = who if who == "nobody" else f"user {who}" if ":" not in who else who.replace(":", " ")
            lines.append(
                f"  no   {who} holds it on {r['type']} {r.get('object', '')} in this world (the smallest found, "
                f"after {plural(r['worlds'], 'world')}):"
            )
            lines += ["         " + x for x in r.get("world", [])]
    return "\n".join(lines)


def plural(n: int, word: str) -> str:
    return f"{n} {word}" + ("" if n == 1 else "s")
