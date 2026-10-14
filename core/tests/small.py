#!/usr/bin/env python3
"""small: every small policy of the core language, held against the reference evaluator and the database.

    python3 tests/small.py --count 7                        # how many policies each size has
    python3 tests/small.py --size 3 --db authz_small        # every policy up to size 3
    python3 tests/small.py --size 6 --slice 2/7 --jobs 3    # those whose number is 2 modulo 7 (a night's), in 3 jobs
    python3 tests/small.py --size 6 --no-db                 # without a database: the evaluator's side only
    python3 tests/small.py --only 5/123 --db authz_small    # one policy (size 5, number 123), printed

difftest and genpolicy check policies drawn at random, and many changes to their data: a mistake that needs one
particular small policy and one particular small world can wait long for a draw. Here the policies are not drawn:
every policy of the core language up to a size is listed, once each, and checked.

The core language, as listed (the policies are genpolicy's Spec, so its tables, its schema and its checks serve):
  - the user type, with or without `where {active}`; one object type, or two where the second names the first
    (two that don't are two smaller policies), each with or without `where {not b3}`;
  - relations from each kind of source (sources()): a column, a link table or shares, to users; shares to `user:*`
    and to `anyone`; a group's members from a link table, or from shares that may name the group's own members
    (groups in groups); a group of the first type named by the second, through a link table or shares; `parent`,
    from a column or a link table to the type's own rows, or a pair of columns naming either type (a polymorphic
    parent); `up`, a column naming a row of the first type;
  - one or two permissions a type, each of up to three of: a relation, the other permission, a relation followed
    (`parent.p1`, `up.p2`), a condition (`{b1}`), joined by `or`, `and` and `and not`, with parentheses where they
    meet: inheritance, inheritance stopped by a condition, and a deny (`(r1 or parent.p2) and not p1`). Where a
    type has two, one names the other: two that don't are two smaller policies.
  - each type with permissions is read through a select rule (its last permission) and an update rule (its first):
    the rules' row checks, as well as the permissions' views. A shared relation is shared by the first permission.
The size of a policy is how many sources, parts of permissions and `where`s it has. Two policies that differ only
in their names (r1 for r2, p1 for p2) or in the order of an `or`'s or an `and`'s parts are one: only the first of
them is listed (canonical(), which tests/unit_test.py holds to that). Every policy up to a size is listed, and those
of the next size that have a deny inside inheritance: the smallest is of size 7, where the whole size is out of
reach (334,846 policies). COUNTS and DENIES say how many there are; a run that lists another number fails: the
language changed, and the counts are written again (--count).

For each policy (the compiler refusing it: counted, by its code):
  1. Without a database: the reference evaluator (authzlib/evaluate.py) in every world of one and two rows of each
     type (users 1 and 2, the second failing the user type's where if it has one; each row's columns, each link,
     each share: every combination, up to WORLDS of them, drawn beyond that), and in some of three rows. The policy
     written another way (its names swapped, every `or` and `and` the other way round) must get the same answers
     from it in every world: a reading that depends on names or order. Another evaluator, written apart, would be
     held to it here, in every world (READINGS).
  2. The worlds that tell the policy's parts apart are chosen: for each part, a policy or a world with that part
     wrong (a permission held by nobody, by anyone; each part of it replaced by nobody or anyone, an `and` for an
     `or`, a `not` dropped, a relation not followed; each source's links to every subject, or on every object, or
     the other way round; a type's where ignored; inheritance one step deep), the first world in which the
     evaluator's answers differ from the policy's own. Then the fewest of them that still tell every such part apart.
  3. With a database: those worlds loaded as rows (load_sql: the bridge from a world to the tables, which
     tests/rewrites.py also uses), side by side under ids of their own, and many policies at once (BATCH), each its
     types renamed (s3t1), in one policy: one apply for them all. Then difftest's checks (tests/difftest.py:
     authz.list, can, explain, who, the rows each rule allows, the rules' expressions on every row, shares, verify),
     every answer against the evaluator; and the data read back must be the worlds loaded. Half the batches are
     loaded before the policy is applied (the trees are built from the rows), half after (the triggers keep them).
A policy that fails is checked again alone, and its world made as small as it can be while it still fails.
"""

from __future__ import annotations

import argparse
import dataclasses
import itertools
import os
import random
import re
import subprocess
import sys
import tempfile
import time
from collections import Counter
from collections.abc import Callable, Iterable, Iterator, Sequence
from typing import ClassVar, NamedTuple, TypeAlias

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))
from authzlib import Compiler, PolicyError, evaluate, parse_policy  # noqa: E402
from authzlib.conditions import Scalar, columns_of, simple, truth  # noqa: E402
from authzlib.evaluate import Data, State  # noqa: E402
from authzlib.parse import Policy  # noqa: E402
from authzlib.sqlutil import q, qt  # noqa: E402
from difftest import DB, Checker, Gen, lit  # noqa: E402
from genpolicy import Node, Obj, Rel, Spec, policy_text, schema_text  # noqa: E402

# ----------------------------------------------------------------------
# The core language, listed
# ----------------------------------------------------------------------
MAX_TYPES = 2  # object types
MAX_PERMS = 2  # permissions a type
MAX_PARTS = 3  # parts of one permission
NAMED = ("member", "parent", "up")  # relations named by what they are; the others are r1, r2, ... in order


class Decl(NamedTuple):
    """A relation's source as the set writes it: the relation's name (r: the next r1, r2, ...), where its links
    come from (column, table, shared), and what they name."""

    name: str
    kind: str
    subjects: tuple[str, ...]


def sources(me: str, earlier: Sequence[Obj]) -> list[Decl]:
    """The sources a type's relations may have, in the order they are listed: to users from a column, a link table or
    shares; shares to user:* and to anyone; another type's group from a link table or shares; a group's members
    from a link table, or from shares that may name the group's own members (groups in groups); parent from a
    column or a link table to the type's own rows, or a pair of columns naming them or another type's; up."""
    out = [
        Decl("r", "column", ("user",)),
        Decl("r", "table", ("user",)),
        Decl("r", "shared", ("user",)),
        Decl("r", "shared", ("user:*",)),
        Decl("r", "shared", ("anyone",)),
    ]
    for e in earlier:
        if any(rel.name == "member" for rel in e.rels):
            out += [Decl("r", "table", (f"{e.name}#member",)), Decl("r", "shared", (f"{e.name}#member",))]
    out += [Decl("member", "table", ("user",)), Decl("member", "shared", ("user", f"{me}#member"))]
    out += [Decl("parent", "column", (me,)), Decl("parent", "table", (me,))]
    for e in earlier:
        out += [Decl("parent", "column", (me, e.name)), Decl("up", "column", (e.name,))]
    return out


def expressions(atoms: Sequence[str], n: int) -> Iterator[Node]:
    """Every expression of n different atoms, its parts in order (one of each set of reorderings): `or`, `and`, and
    `and not` (a `not` is always an `and`'s part, beside one that isn't a `not`)."""
    for combo in itertools.combinations(sorted(atoms), n):
        if n == 1:
            yield combo[0]
        elif n == 2:
            a, b = combo
            yield from [("or", [a, b]), ("and", [a, b]), ("and", [a, ("not", [b])]), ("and", [b, ("not", [a])])]
        else:
            yield ("or", list(combo))
            yield ("and", list(combo))
            for x in combo:
                a, b = [y for y in combo if y != x]
                yield ("and", [a, b, ("not", [x])])
                yield ("and", [x, ("not", [a]), ("not", [b])])
                for inner in (("and", [a, b]), ("and", [a, ("not", [b])]), ("and", [b, ("not", [a])])):
                    yield ("or", [inner, x])
                yield ("and", [("or", [a, b]), x])
                yield ("and", [("or", [a, b]), ("not", [x])])
                yield ("and", [x, ("not", [("or", [a, b])])])


def atoms(n: Node) -> list[str]:
    return [n] if isinstance(n, str) else [a for x in n[1] for a in atoms(x)]


def parts(total: int, n: int) -> Iterator[tuple[int, ...]]:
    """total split into n parts of 1 to MAX_PARTS, in order."""
    if n == 0:
        if total == 0:
            yield ()
        return
    for first in range(1, min(MAX_PARTS, total - (n - 1)) + 1):
        for rest in parts(total - first, n - 1):
            yield (first, *rest)


def types(k: int, budget: int, earlier: Sequence[Obj]) -> Iterator[Obj]:
    """Every type t{k} of exactly this size, given the types before it."""
    me = f"t{k}"
    cat = sources(me, earlier)
    for where in (False, True):
        left = budget - where
        for n in range(1, left + 1):
            for chosen in itertools.combinations_with_replacement(range(len(cat)), n):
                decls = [cat[i] for i in chosen]
                named = [(d.name, d.kind) for d in decls if d.name != "r"]
                if len(set(named)) != len(named) or sum(d.name == "up" for d in decls) > 1:
                    continue  # (a named relation has each kind of source once: a column, a table)
                rels, r = [], 0
                for d in decls:
                    if d.name == "r":
                        r += 1
                    rels.append(Rel(f"r{r}" if d.name == "r" else d.name, d.kind, list(d.subjects)))
                rest = left - n
                for m in range(min(MAX_PERMS, rest) + 1):
                    for sizes in parts(rest, m):
                        yield from perms(Obj(me, where, rels, {}, []), sizes, earlier)


def perms(o: Obj, sizes: tuple[int, ...], earlier: Sequence[Obj]) -> Iterator[Obj]:
    """o with permissions of these sizes: p2 may name p1 (and either may follow a relation to either)."""
    names = [f"p{i + 1}" for i in range(len(sizes))]
    refs = list(dict.fromkeys(rel.name for rel in o.rels if rel.name not in ("parent", "up")))
    follow: list[str] = []
    if any(rel.name == "parent" for rel in o.rels):
        follow += [f"parent.{p}" for p in names]
    up = next((rel.subjects[0] for rel in o.rels if rel.name == "up"), None)
    if up is not None:
        follow += [f"up.{p}" for p in next(e for e in earlier if e.name == up).perms]
    choices = [list(expressions([*refs, *names[:i], *follow, "{b1}"], size)) for i, size in enumerate(sizes)]
    for exprs in itertools.product(*choices):
        o2 = dataclasses.replace(o, perms=dict(zip(names, exprs, strict=True)))
        if used(o2, last=int(o.name[1:]) == MAX_TYPES):
            yield o2


def used(o: Obj, last: bool) -> bool:
    """Whether every relation of a type is used (AZ208: in a permission; parent and up followed; a group's members
    may be used by a later type instead, if one may come), it has a permission if it has shares (shared by it) and
    its two permissions are joined (otherwise they are smaller policies side by side)."""
    named = {a for e in o.perms.values() for a in atoms(e)}
    for rel in o.rels:
        if rel.name in ("parent", "up"):
            if not any(a.startswith(f"{rel.name}.") for a in named):
                return False
        elif rel.name not in named and not (rel.name == "member" and not last):
            return False
    if not o.perms and any(rel.kind == "shared" for rel in o.rels):
        return False
    return len(o.perms) < 2 or bool(
        {"p1", "parent.p1"} & set(atoms(o.perms["p2"])) or "parent.p2" in atoms(o.perms["p1"])
    )


def well_formed(spec: Spec) -> bool:
    """Every relation is used (AZ208: a group by another type, or in a permission; parent and up followed), a type
    with shares or no permissions is one that can be (shared by its first permission; a group type), two
    permissions of a type and two types are joined (otherwise they are smaller policies side by side)."""
    # the groups another type names (a group named by its own members alone is used by nothing: the compiler takes
    # it, nothing reads it)
    groups = {
        g for o in spec.objs for rel in o.rels for s in rel.subjects if "#" in s and (g := s.split("#")[0]) != o.name
    }
    for o in spec.objs:
        used = {a for e in o.perms.values() for a in atoms(e)}
        for rel in o.rels:
            if rel.name in ("parent", "up"):
                if not any(a.startswith(f"{rel.name}.") for a in used):
                    return False
            elif rel.name not in used and not (rel.name == "member" and o.name in groups):
                return False
        if not o.perms and any(rel.kind == "shared" for rel in o.rels):
            return False
        if len(o.perms) == 2 and not (
            {"p1", "parent.p1"} & set(atoms(o.perms["p2"])) or "parent.p2" in atoms(o.perms["p1"])
        ):
            return False
    if len(spec.objs) == 2:
        t1, t2 = spec.objs
        if not any(s.split("#")[0] == t1.name for rel in t2.rels for s in rel.subjects):
            return False
    return True


def size(spec: Spec) -> int:
    """How many sources, parts of permissions and wheres the policy has."""
    return spec.user_where + sum(
        o.where + len(o.rels) + sum(len(atoms(e)) for e in o.perms.values()) for o in spec.objs
    )


def denies(spec: Spec) -> bool:
    """Whether a permission that inherits takes away another permission (`(r1 or parent.p2) and not p1`): a deny."""

    def takes(n: Node) -> bool:
        return not isinstance(n, str) and (
            (n[0] == "not" and isinstance(n[1][0], str) and re.fullmatch(r"p\d", n[1][0]) is not None)
            or any(takes(x) for x in n[1])
        )

    return any(takes(e) and any(a.startswith("parent.") for a in atoms(e)) for o in spec.objs for e in o.perms.values())


def bare(n: int) -> Iterator[Spec]:
    """Every well-formed policy of size n, in a fixed order, each as many times as it has spellings."""
    for user_where in (False, True):
        for count in range(1, MAX_TYPES + 1):
            for budgets in itertools.product(range(1, n + 1), repeat=count):
                if sum(budgets) != n - user_where:
                    continue

                def build(k: int, objs: list[Obj], budgets: tuple[int, ...] = budgets) -> Iterator[list[Obj]]:
                    if k == len(budgets):
                        yield objs
                        return
                    for o in types(k + 1, budgets[k], objs):
                        yield from build(k + 1, [*objs, o])

                for objs in build(0, []):
                    spec = Spec(0, user_where, False, objs)
                    if well_formed(spec):
                        yield spec


def canon_text(n: Node) -> str:
    """An expression's text with every `or`'s and `and`'s parts in order (and joined: (a or b) or c is a or b or c)."""
    if isinstance(n, str):
        return n
    op, items = n
    if op == "not":
        inner = canon_text(items[0])
        return f"not {inner}"
    flat: list[Node] = []
    for x in items:
        flat += x[1] if not isinstance(x, str) and x[0] == op else [x]
    texts = sorted(
        t if isinstance(x, str) or x[0] == "not" else f"({t})" for x, t in ((x, canon_text(x)) for x in flat)
    )
    return f" {op} ".join(texts)


def renamed(n: Node, own: dict[str, str], follows: dict[str, list[dict[str, str]]]) -> Node:
    """An expression with its relations and permissions renamed: own, the type's; follows, for each relation an arrow
    follows, the renaming of each type it links to (`parent.p1` of a pair of columns naming two types names p1 of
    both: renamed apart, it reads `parent.p2|p1`, which no policy writes)."""
    if isinstance(n, str):
        rel, dot, perm = n.partition(".")
        if dot:
            names = list(dict.fromkeys(m.get(perm, f"?{perm}") for m in follows.get(rel, [own])))
            return f"{rel}.{'|'.join(names)}"
        return own.get(n, n)
    return (n[0], [renamed(x, own, follows) for x in n[1]])


def follows(spec: Spec, o: Obj, maps: dict[str, dict[str, str]]) -> dict[str, list[dict[str, str]]]:
    """For each relation of o to objects, the permissions' renaming (maps, by type) of each type it links to."""
    out: dict[str, list[dict[str, str]]] = {}
    for rel in o.rels:
        for st in rel.subjects:
            if st in maps:
                out.setdefault(rel.name, []).append(maps[st])
    return out


def canonical(spec: Spec) -> str:
    """One text for every spelling of a policy: the least over every renaming of each type's relations r1, r2, ...
    (among those with the same sources) and permissions, with each expression's parts in order. The types keep
    their names: the second names the first. Rules and `shared by` aren't read: the set writes them from the rest."""
    per_type: list[list[tuple[dict[str, str], dict[str, str]]]] = []
    for o in spec.objs:
        sigs: dict[str, list[tuple[str, tuple[str, ...]]]] = {}
        for rel in o.rels:
            if rel.name not in NAMED:
                sigs.setdefault(rel.name, []).append((rel.kind, tuple(rel.subjects)))
        rs = sorted(sigs, key=lambda r: sorted(sigs[r]))
        maps: list[tuple[dict[str, str], dict[str, str]]] = []
        ps = list(o.perms)
        for order in itertools.permutations(rs):
            if any(sorted(sigs[a]) != sorted(sigs[b]) for a, b in zip(order, rs, strict=True)):
                continue
            rmap = {a: f"r{i + 1}" for i, a in enumerate(order)}
            for porder in itertools.permutations(ps):
                maps.append((rmap, {a: f"p{i + 1}" for i, a in enumerate(porder)}))
        per_type.append(maps)
    best: str | None = None
    for combo in itertools.product(*per_type):
        out = [f"user{' where' if spec.user_where else ''}"]
        pmaps = {o.name: pmap for o, (_, pmap) in zip(spec.objs, combo, strict=True)}
        for o, (rmap, pmap) in zip(spec.objs, combo, strict=True):
            arrows = follows(spec, o, pmaps)
            rels = sorted(f"{rmap.get(rel.name, rel.name)}:{rel.kind}:{','.join(rel.subjects)}" for rel in o.rels)
            ps = sorted(f"{pmap[p]}={canon_text(renamed(e, {**rmap, **pmap}, arrows))}" for p, e in o.perms.items())
            out.append(f"{o.name}{' where' if o.where else ''} [{'; '.join(rels)}] [{'; '.join(ps)}]")
        text = " | ".join(out)
        if best is None or text < best:
            best = text
    return best or ""


def decorated(spec: Spec) -> Spec:
    """The policy as checked: each type with permissions read through a select rule (its last permission) and an
    update rule (its first), each shared relation shared by its first permission."""
    objs = []
    for o in spec.objs:
        ps = list(o.perms)
        rules: list[tuple[str, Node]] = [("select", ps[-1]), ("update", ps[0])] if ps else []
        rels = [dataclasses.replace(rel, by=ps[0] if rel.kind == "shared" else "") for rel in o.rels]
        objs.append(dataclasses.replace(o, rels=rels, rules=rules))
    return dataclasses.replace(spec, objs=objs)


def listed(n: int) -> list[Spec]:
    """The set's policies of size n, in order: each policy once (its first spelling), decorated."""
    seen: set[str] = set()
    out: list[Spec] = []
    for spec in bare(n):
        key = canonical(spec)
        if key not in seen:
            seen.add(key)
            out.append(decorated(spec))
    return out


def the_set(n: int) -> list[Spec]:
    """Every policy up to size n, and those of size n + 1 with a deny, in order."""
    out = [spec for k in range(1, n + 1) for spec in listed(k)]
    return out + [spec for spec in listed(n + 1) if denies(spec)]


# how many policies the set has (the_set's, by size, its last line those of size n + 1 with a deny): a language
# change that changes them changes these (python3 tests/small.py --count N)
COUNTS: dict[int, int] = {1: 0, 2: 9, 3: 75, 4: 596, 5: 5416, 6: 45059}
DENIES: dict[int, int] = {1: 0, 2: 0, 3: 0, 4: 12, 5: 214, 6: 2386, 7: 19828}


# ----------------------------------------------------------------------
# Worlds
# ----------------------------------------------------------------------
USERS = ("1", "2")  # the users: the second fails the user type's where, if it has one
PRINCIPALS = (*USERS, "")  # who is asked: each user, and nobody
WORLDS = 400  # worlds of one size tried at most: every combination up to that many, else as many drawn
DEEP = 60  # worlds of three rows of each type, drawn
Fact: TypeAlias = "tuple[str, str, str, str, Scalar]"  # ('col', type, id, column, value) or ('pair', key, o, s, None)
Option: TypeAlias = "tuple[Fact, ...]"


def subject_ids(pol: Policy, ids: dict[str, list[str]], st: str, sr: str | None) -> list[str]:
    """The ids a link to subjects st#sr may name in a world with these rows."""
    if st == "anyone" or sr == "*":
        return ["*"]
    return list(USERS) if st == "user" else ids[st]


def pair_key(t: str, r: str, i: int, st: str, sr: str | None) -> str:
    return f"{t}\t{r}\t{i}\t{st}\t{sr or ''}"


def dims(pol: Policy, n: int) -> tuple[dict[str, list[str]], list[list[Option]]]:
    """The rows of a world of n rows of each object type, and what each of its facts may be: each a dimension of
    options (a column's value on a row; whether a link is there; what a row's column names)."""
    ids = {t.name: list(USERS) if t.name == "user" else [str(i) for i in range(1, n + 1)] for t in pol.types.values()}
    out: list[list[Option]] = []
    ref = evaluate.Reference(pol)
    for t in pol.types.values():
        if t.name == "user":
            continue
        conds = [c for tn, c in ref.conditions() if tn == t.name] + ([t.where] if t.where else [])
        cols = sorted({col for c in conds if (node := simple(c)) is not None for col in columns_of(node)})
        for i in ids[t.name]:
            for col in cols:
                out.append([(("col", t.name, i, col, False),), (("col", t.name, i, col, True),)])
        for r in t.relations.values():
            for k, src in enumerate(r.sources):
                if src.kind == "column":
                    for o in ids[t.name]:
                        opts: list[Option] = [()]
                        for st, sr in src.subjects:
                            key = pair_key(t.name, r.name, k, st, sr)
                            opts += [(("pair", key, o, s, None),) for s in subject_ids(pol, ids, st, sr)]
                        out.append(opts)
                else:
                    for st, sr in src.subjects:
                        key = pair_key(t.name, r.name, k, st, sr)
                        for o in ids[t.name]:
                            for s in subject_ids(pol, ids, st, sr):
                                out.append([(), (("pair", key, o, s, None),)])
    return ids, out


def loops(pol: Policy, facts: Sequence[Fact]) -> bool:
    """Whether a column names a row of its own type that is, or leads back to, the row itself: a tree's columns may
    not loop (the database refuses it, AZ713; links through tables may)."""
    up: dict[tuple[str, str], str] = {}
    for kind, key, o, s, _ in facts:
        if kind == "pair":
            t, r, i, st, _sr = key.split("\t")
            if pol.types[t].relations[r].sources[int(i)].kind == "column" and st == t:
                up[(t, o)] = s
    for t, o in up:
        seen, at = {o}, up.get((t, o))
        while at is not None:
            if at in seen:
                return True
            seen.add(at)
            at = up.get((t, at))
    return False


def data_of(pol: Policy, ids: dict[str, list[str]], facts: Sequence[Fact]) -> evaluate.Data:
    """The evaluator's data for a world: its rows, links and columns (the user type's where: users[1] fails it)."""
    data = evaluate.Data()
    data.ids = {t: list(v) for t, v in ids.items()}
    data.columns = {t: {i: {} for i in v} for t, v in ids.items()}
    for t in pol.types.values():
        for r in t.relations.values():
            for k, src in enumerate(r.sources):
                for st, sr in src.subjects:
                    data.pairs[(t.name, r.name, k, st, sr or "")] = []
    user = pol.types.get("user")
    if user is not None and user.where:
        node = simple(user.where)
        assert node is not None, "the user type's where in the set is a column's: {active}"
        for col in columns_of(node):
            for n, u in enumerate(USERS):
                data.columns["user"][u][col] = n == 0
    for kind, key, o, s, v in facts:
        if kind == "col":
            data.columns[key][o][s] = v
        else:
            t, r, i, st, sr = key.split("\t")
            data.pairs[(t, r, int(i), st, sr)].append((o, s))
    for t in pol.types.values():
        node = simple(t.where) if t.where else None
        data.valid[t.name] = [
            i for i in ids[t.name] if node is None or truth(node, data.columns[t.name][i], None) is True
        ]
    return data


def users(pol: Policy) -> evaluate.Data:
    """The users every world has (USERS: the second fails the user type's where, if it has one), alone."""
    return data_of(pol, {t: list(USERS) if t == "user" else [] for t in pol.types}, [])


def worlds(pol: Policy, key: str) -> Iterator[evaluate.Data]:
    """Every world of one row of each type, then of two (up to WORLDS of each size, the rest drawn), then DEEP of
    three, drawn: the first of each size has no link at all, the second every link it can."""
    for n, cap in ((1, WORLDS), (2, WORLDS), (3, DEEP)):
        ids, ds = dims(pol, n)
        total = 1
        for d in ds:
            total *= len(d)
        if total <= cap and n < 3:
            combos: Iterator[tuple[Option, ...]] = itertools.product(*ds)
        else:
            rng = random.Random(f"small/{key}/{n}")
            first = [tuple(d[0] for d in ds), tuple(d[-1] for d in ds)]
            combos = iter(first + [tuple(rng.choice(d) for d in ds) for _ in range(cap - 2)])
        seen: set[tuple[Option, ...]] = set()
        for combo in combos:
            if combo in seen:
                continue
            seen.add(combo)
            facts = [f for opt in combo for f in opt]
            if not loops(pol, facts):
                yield data_of(pol, ids, facts)


# ----------------------------------------------------------------------
# Readings: what a policy grants in a world
# ----------------------------------------------------------------------
Answers: TypeAlias = "dict[tuple[str, str, str], frozenset[str]]"  # (principal, type, permission): the ids
# An evaluator: given a policy's text, a function from a world (evaluate.Data) to its answers, for PRINCIPALS and
# every permission. A third evaluator, written apart from evaluate.py, would be one of these.
Evaluator: TypeAlias = "Callable[[str], Callable[[evaluate.Data], Answers]]"


def reference(
    text: str, ref_class: type[evaluate.Reference] = evaluate.Reference
) -> Callable[[evaluate.Data], Answers]:
    """The reference evaluator (authzlib/evaluate.py)."""
    pol = parse_policy(text, "small.authz")
    ref = ref_class(pol)
    perms = [(t.name, p) for t in pol.types.values() for p, x in t.perms.items() if not x.hidden]

    def answers(data: evaluate.Data) -> Answers:
        out: Answers = {}
        for u in PRINCIPALS:
            state = ref.evaluate(data, u)
            for t, p in perms:
                out[(u, t, p)] = state[(t, p)]
        return out

    return answers


def respelled(spec: Spec) -> tuple[Spec, dict[str, str], dict[str, str]]:
    """The policy written another way: each type's relations r1, r2, ... and its permissions named the other way
    round (not those of the types a pair of columns names together: `parent.p1` names p1 of both), the permissions
    declared the other way round, the parts of every `or` and `and` too. With the renaming of the relations (for
    the world's links) and of the permissions (for the answers), by type and name."""
    tied = {st for o in spec.objs for rel in o.rels if len(rel.subjects) > 1 for st in rel.subjects}
    rmaps, pmaps = {}, {}
    for o in spec.objs:
        rs = list(dict.fromkeys(rel.name for rel in o.rels if rel.name not in NAMED))
        ps = list(o.perms)
        rmaps[o.name] = dict(zip(rs, reversed(rs), strict=True))
        pmaps[o.name] = dict(zip(ps, ps if o.name in tied else reversed(ps), strict=True))
    out = []
    for o in spec.objs:
        rmap, pmap = rmaps[o.name], pmaps[o.name]
        arrows = follows(spec, o, pmaps)
        perms = {pmap[p]: turned(renamed(e, {**rmap, **pmap}, arrows)) for p, e in reversed(list(o.perms.items()))}
        rels = [
            dataclasses.replace(rel, name=rmap.get(rel.name, rel.name), by=pmap.get(rel.by, rel.by)) for rel in o.rels
        ]
        rules = [(h, renamed(e, pmap, {})) for h, e in o.rules]
        out.append(dataclasses.replace(o, rels=rels, perms=perms, rules=rules))
    rels_map = {f"{t}.{a}": b for t, m in rmaps.items() for a, b in m.items()}
    perms_map = {f"{t}.{a}": b for t, m in pmaps.items() for a, b in m.items()}
    return dataclasses.replace(spec, objs=out), rels_map, perms_map


def turned(n: Node) -> Node:
    """Every `or`'s and `and`'s parts the other way round."""
    return n if isinstance(n, str) else (n[0], [turned(x) for x in reversed(n[1])])


def respelled_reading(spec: Spec) -> Callable[[evaluate.Data], Answers]:
    """The reference evaluator on the policy written another way (respelled), its world and answers renamed back:
    a reading that depended on names or on order would differ from the policy's own."""
    other, rels_map, perms_map = respelled(spec)
    read = reference(policy_text(other))
    back = {f"{t}.{b}": a.split(".")[1] for a, b in perms_map.items() for t in [a.split(".")[0]]}

    def answers(data: evaluate.Data) -> Answers:
        moved = dataclasses.replace(
            data,
            pairs={(t, rels_map.get(f"{t}.{r}", r), i, st, sr): v for (t, r, i, st, sr), v in data.pairs.items()},
        )
        return {(u, t, back.get(f"{t}.{p}", p)): ids for (u, t, p), ids in read(moved).items()}

    return answers


# The readings held to the reference evaluator in every world. A third evaluator, written apart from evaluate.py,
# goes here: an Evaluator, read from the policy's text (`lambda spec: third(policy_text(spec))`)
READINGS: dict[str, Callable[[Spec], Callable[[evaluate.Data], Answers]]] = {
    "the reference evaluator, the policy written another way": respelled_reading,
}


# ----------------------------------------------------------------------
# Choosing the worlds: the policy's parts told apart
# ----------------------------------------------------------------------
class Shallow(evaluate.Reference):
    """The reference evaluator with each recursion followed one step only (inheritance one level deep): two rounds
    of each group of names that depend on each other, not as many as it takes."""

    def evaluate(self, data: Data, user: str, links: Iterable[str] = ()) -> State:
        self.data, self.links = data, set(links)
        kind, pid = evaluate.principal_of(user, self.types)
        self.principal = (kind, pid) if kind in self.types and pid in set(data.valid[kind]) else None
        state: evaluate.State = {
            (t.name, name): frozenset() for t in self.types.values() for name in list(t.relations) + list(t.perms)
        }
        for comp in self.order:
            for _ in range(2):
                for tname, name in comp:
                    t = self.types[tname]
                    state[(tname, name)] = frozenset(self.eval_name(state, t, name) & self.valid(t))
        return state


class Mutant(NamedTuple):
    what: str
    answers: Callable[[evaluate.Data], Answers]


def places(n: Node, at: tuple[int, ...] = ()) -> Iterator[tuple[int, ...]]:
    yield at
    if not isinstance(n, str):
        for k, x in enumerate(n[1]):
            yield from places(x, (*at, k))


def at(n: Node, path: tuple[int, ...]) -> Node:
    for k in path:
        assert not isinstance(n, str)
        n = n[1][k]
    return n


def put(n: Node, path: tuple[int, ...], new: Node) -> Node:
    if not path:
        return new
    assert not isinstance(n, str)
    return (n[0], [put(x, path[1:], new) if k == path[0] else x for k, x in enumerate(n[1])])


def wrong_parts(spec: Spec) -> Iterator[tuple[str, Spec]]:
    """The policy with one part of one permission wrong: the whole permission held by nobody or by anyone; each
    part replaced by nobody or anyone; an `and` for an `or` and the other way; a `not` dropped; a relation not
    followed (`parent.p1` read as `p1`)."""
    for k, o in enumerate(spec.objs):
        for p, e in o.perms.items():
            for path in places(e):
                x = at(e, path)
                where = f"{o.name}.{p}" + (f" at {canon_text(x)}" if path else "")
                news: list[tuple[str, Node]] = []
                if isinstance(x, str):
                    news += [("nobody", "nobody"), ("anyone", "anyone")]
                    if x.startswith("parent."):
                        news.append(("not followed", x.split(".")[1]))
                elif x[0] == "not":
                    news.append(("without its not", x[1][0]))
                else:
                    news += [
                        ("nobody", "nobody"),
                        ("anyone", "anyone"),
                        ("and/or swapped", ("and" if x[0] == "or" else "or", x[1])),
                    ]
                for what, new in news:
                    objs = [
                        dataclasses.replace(o, perms={**o.perms, p: put(e, path, new)}) if j == k else y
                        for j, y in enumerate(spec.objs)
                    ]
                    yield f"{where}: {what}", dataclasses.replace(spec, objs=objs)


def wrong_data(pol: Policy) -> Iterator[tuple[str, Callable[[evaluate.Data], evaluate.Data]]]:
    """The world read wrong: each source's links to every subject of the objects it links, or on every object for the
    subjects it links, or the other way round (a link to the type's own rows); each type's where ignored."""
    for t in pol.types.values():
        for r in t.relations.values():
            for k, src in enumerate(r.sources):
                for st, sr in src.subjects:
                    key = (t.name, r.name, k, st, sr or "")
                    if st == "anyone" or sr == "*":
                        continue

                    def every_subject(d: evaluate.Data, key: evaluate.PairsKey = key, st: str = st) -> evaluate.Data:
                        objs = {o for o, _ in d.pairs[key]}
                        return dataclasses.replace(
                            d, pairs={**d.pairs, key: [(o, s) for o in sorted(objs) for s in d.ids[st]]}
                        )

                    def every_object(d: evaluate.Data, key: evaluate.PairsKey = key, t: str = t.name) -> evaluate.Data:
                        subs = {s for _, s in d.pairs[key]}
                        return dataclasses.replace(
                            d, pairs={**d.pairs, key: [(o, s) for o in d.ids[t] for s in sorted(subs)]}
                        )

                    yield f"{t.name}.{r.name} ({src.kind}, {st}): to every subject", every_subject
                    yield f"{t.name}.{r.name} ({src.kind}, {st}): on every object", every_object
                    if st == t.name:

                        def reversed_links(d: evaluate.Data, key: evaluate.PairsKey = key) -> evaluate.Data:
                            return dataclasses.replace(d, pairs={**d.pairs, key: [(s, o) for o, s in d.pairs[key]]})

                        yield f"{t.name}.{r.name} ({src.kind}): the other way round", reversed_links
        if t.where:

            def ignored(d: evaluate.Data, t: str = t.name) -> evaluate.Data:
                return dataclasses.replace(d, valid={**d.valid, t: list(d.ids[t])})

            yield f"{t.name}'s where ignored", ignored


def mutants(spec: Spec, text: str) -> list[Mutant]:
    """Each part of the policy wrong (wrong_parts, wrong_data), and its recursions one step deep."""
    out: list[Mutant] = []
    for what, other in wrong_parts(spec):
        try:
            out.append(Mutant(what, reference(policy_text(other))))
        except (AssertionError, PolicyError):
            pass  # (a part made wrong that the evaluator can't read: a `not` inside a recursion)
    base = reference(text)
    pol = parse_policy(text, "small.authz")
    for what, change in wrong_data(pol):
        out.append(Mutant(what, lambda d, change=change: base(change(d))))
    out.append(Mutant("recursion one step deep", reference(text, Shallow)))
    return out


class Choice(NamedTuple):
    worlds: list[evaluate.Data]  # the worlds chosen, which tell apart every part told apart in any world
    tried: int  # the worlds the evaluator answered in
    told: int  # the parts made wrong that some world tells apart
    parts: int  # the parts made wrong
    problems: list[str]  # where another reading disagreed with the reference evaluator


def choose(spec: Spec, text: str, key: str) -> Choice:
    """The evaluator in every world (worlds()), each other reading held to it there (READINGS), and the fewest
    worlds that tell apart each part made wrong (mutants()) that any world tells apart."""
    pol = parse_policy(text, "small.authz")
    base = reference(text)
    others = {name: make(spec) for name, make in READINGS.items()}
    every = mutants(spec, text)
    alive = list(every)
    found: list[tuple[evaluate.Data, Answers]] = []
    problems: list[str] = []
    tried = held = 0
    fullest: evaluate.Data | None = None  # (where the policy grants most: checked when no world tells a part apart)
    for w in worlds(pol, key):
        tried += 1
        a = base(w)
        if fullest is None or sum(map(len, a.values())) > held:
            fullest, held = w, sum(map(len, a.values()))
        for name, read in list(others.items()):
            b = read(w)
            if b != a:
                k = next(k for k in a if a[k] != b.get(k))
                problems.append(
                    f"{name}: {k[1]}.{k[2]} for {k[0] or 'nobody'}: {sorted(b.get(k, []))}, the evaluator {sorted(a[k])}"
                )
                del others[name]
        dead = [m for m in alive if m.answers(w) != a]
        if dead:
            found.append((w, a))
            alive = [m for m in alive if m not in dead]
    # the fewest of those worlds that still tell every part apart: greedily, the world that tells most first
    apart = [m for m in every if m not in alive]
    kills = [{i for i, m in enumerate(apart) if m.answers(w) != a} for w, a in found]
    left = set(range(len(apart)))
    chosen: list[evaluate.Data] = []
    while left:
        best = max(range(len(found)), key=lambda i: len(kills[i] & left))
        chosen.append(found[best][0])
        left -= kills[best]
    if not chosen and fullest is not None:
        chosen.append(fullest)
    return Choice(chosen, tried, len(apart), len(every), problems)


# ----------------------------------------------------------------------
# A world as rows: the bridge from the evaluator's worlds to a database
# ----------------------------------------------------------------------
KEYWORD_SQL = set(evaluate.KEYWORDS.values())  # signed_in, anyone and nobody: no rows to make
NUMBERS = ("bigint", "int", "integer", "smallint")  # key types whose ids SQL writes as they are


class Unloadable(Exception):
    """A world rows can't make: a condition that isn't about the row's own columns, custom roles, a key of several
    columns."""


def sql_value(v: Scalar) -> str:
    if v is None:
        return "NULL"
    if isinstance(v, bool):
        return "true" if v else "false"
    return str(v) if isinstance(v, (int, float)) else lit(v)


def load_sql(pol: Policy, data: evaluate.Data, principals: bool = True, rows_decide: bool = False) -> tuple[str, str]:
    """The SQL that makes a world (evaluate.Data) in the policy's tables: (each type's rows, with the columns its
    simple conditions read and its column sources' links, then each link table's rows; the shares, which need
    authz.shares, made by applying). With principals False, the user type's and other principal types' rows are
    left out (another world made them). Rows can't make a condition that isn't about the row's own columns (a
    subquery holds where the rows it reads say) hold where the world says: such a world is refused, unless
    rows_decide (the caller reads back where such conditions hold: tests/rewrites.py)."""
    if any(data.rolepairs.values()):
        raise Unloadable("custom roles")
    if not rows_decide and any(k[1] not in KEYWORD_SQL and simple(k[1]) is None for k in data.cond):
        raise Unloadable("a condition that isn't about the row's own columns")

    def text_id(t: str, i: str) -> str:
        if pol.types[t].composite:
            raise Unloadable("a key of several columns")
        return i

    def ident(t: str, i: str) -> str:
        """A row's id in SQL."""
        return text_id(t, i) if pol.types[t].pktype in NUMBERS else lit(text_id(t, i))

    rows: list[str] = []
    links: list[str] = []
    shares: list[str] = []
    for t in pol.types.values():
        if (t.principal and not principals) or t.name not in data.ids:
            continue
        values: dict[str, dict[str, str]] = {i: {} for i in data.ids[t.name]}
        for i, cols in data.columns.get(t.name, {}).items():
            values[i] |= {c: sql_value(v) for c, v in cols.items()}
        for r in t.relations.values():
            for k, src in enumerate(r.sources):
                for st, sr in src.subjects:
                    pairs = data.pairs.get((t.name, r.name, k, st, sr or ""), [])
                    if src.kind == "column":
                        if not isinstance(src.column, str):
                            raise Unloadable("a key of several columns")
                        for o, s in pairs:
                            values[o][src.column] = ident(st, s)
                            if src.type_col:
                                values[o][src.type_col] = lit(st)
                    elif src.kind == "table":
                        if not isinstance(src.obj_col, str) or not isinstance(src.subj_col, str) or src.type_col:
                            raise Unloadable("a link table with keys of several columns, or naming types")
                        links += [
                            f"INSERT INTO {qt(src.table or '')} ({q(src.obj_col)}, {q(src.subj_col)}) "
                            f"VALUES ({ident(t.name, o)}, {ident(st, s)});"
                            for o, s in pairs
                        ]
                    elif src.kind == "shared":
                        # to user:* or anyone, the subject is '*', whoever the world's link names; to a link, the
                        # hash of its token (as authz.share_link() writes it), which the session holds
                        def subject(s: str, st: str = st, sr: str | None = sr) -> str:
                            if st == "link":
                                return f"encode(sha256(convert_to({lit(s)}, 'UTF8')), 'hex')"
                            return lit("*" if "*" in (s, sr) or st == "anyone" else text_id(st, s))

                        shares += [
                            "INSERT INTO authz.shares (object_type, object_id, relation, subject_type, subject_id, "
                            f"subject_relation) VALUES ({lit(t.name)}, {lit(text_id(t.name, o))}, {lit(r.name)}, "
                            f"{lit(st)}, {subject(s)}, {lit(sr if sr and sr != '*' else '')});"
                            for o, s in pairs
                        ]
                    else:
                        raise Unloadable(f"a source of kind {src.kind}")
        rows += [
            f"INSERT INTO {qt(t.table)} ({', '.join(q(c) for c in [t.pk or '', *v])}) "
            f"VALUES ({', '.join([ident(t.name, i), *v.values()])});"
            for i, v in values.items()
        ]
    return "\n".join(rows + links), "\n".join(dict.fromkeys(shares))


def moved(data: evaluate.Data, names: dict[str, str], shift: int, principals: set[str]) -> evaluate.Data:
    """A world with its types renamed (names) and each object's id moved up by shift (not the principals')."""

    def t(name: str) -> str:
        return names.get(name, name)

    def i(tname: str, x: str) -> str:
        return x if tname in principals or x == "*" else str(int(x) + shift)

    out = evaluate.Data()
    out.ids = {t(k): [i(k, x) for x in v] for k, v in data.ids.items()}
    out.valid = {t(k): [i(k, x) for x in v] for k, v in data.valid.items()}
    out.columns = {t(k): {i(k, x): dict(c) for x, c in v.items()} for k, v in data.columns.items()}
    out.pairs = {
        (t(a), r, n, t(st), sr): [(i(a, o), i(st, s)) for o, s in v] for (a, r, n, st, sr), v in data.pairs.items()
    }
    out.cond = {(t(a), c): [i(a, x) for x in v] for (a, c), v in data.cond.items()}
    return out


def union(datas: Sequence[evaluate.Data]) -> evaluate.Data:
    """Worlds side by side (their objects' ids apart, their principals the same): one world."""
    out = evaluate.Data()
    for d in datas:
        for k, v in d.ids.items():
            out.ids[k] = list(dict.fromkeys([*out.ids.get(k, []), *v]))
        for k, v in d.valid.items():
            out.valid[k] = list(dict.fromkeys([*out.valid.get(k, []), *v]))
        for k, v in d.columns.items():
            out.columns[k] = {**out.columns.get(k, {}), **v}
        for pk, pv in d.pairs.items():
            out.pairs[pk] = [*out.pairs.get(pk, []), *pv]
        for ck, cv in d.cond.items():
            out.cond[ck] = [*out.cond.get(ck, []), *cv]
    return out


def facts(pol: Policy, data: evaluate.Data) -> dict[str, frozenset[str]]:
    """What a world says, comparable whichever way it was made: each type's rows and those its where keeps, each
    source's links, and the rows each condition holds for (read from the columns, or given)."""
    out: dict[str, frozenset[str]] = {}
    for t in pol.types.values():
        out[f"{t.name} rows"] = frozenset(data.ids.get(t.name, []))
        out[f"{t.name} rows its where keeps"] = frozenset(data.valid.get(t.name, []))
    for (t, r, i, st, sr), v in data.pairs.items():
        out[f"{t}.{r} (source {i + 1}, {st}{'#' + sr if sr else ''})"] = frozenset(f"{o}->{s}" for o, s in v)
    for t, c in evaluate.Reference(pol).conditions():
        if c in KEYWORD_SQL:
            continue
        node = simple(c)
        if (t, c) in data.cond or node is None:
            holds = data.cond.get((t, c), [])
        else:
            rows = data.columns.get(t, {})
            holds = [i for i in data.ids.get(t, []) if truth(node, rows.get(i, {}), None) is True]
        out[f"{{{c}}} on {t}"] = frozenset(holds)
    return out


# ----------------------------------------------------------------------
# The database
# ----------------------------------------------------------------------
BATCH = 40  # policies applied together, as one
APART = 10  # how far apart the worlds of one policy are (a world has at most three rows of a type)
SHRUNK = 3  # the failing policies whose world is made smaller (each takes many applies): the first


class SmallGen(Gen):
    """Who difftest's checks ask as: USERS (and nobody)."""

    users: ClassVar[list[str]] = list(USERS)


def retyped(spec: Spec, prefix: str) -> tuple[Spec, dict[str, str]]:
    """A policy with its types renamed (t1 to s3t1), so that many sit side by side in one: and the renaming."""
    names = {o.name: prefix + o.name for o in spec.objs}

    def subject(s: str) -> str:
        base, sep, rest = s.partition("#")
        return names.get(base, base) + sep + rest

    objs = [
        dataclasses.replace(
            o,
            name=names[o.name],
            rels=[dataclasses.replace(r, subjects=[subject(s) for s in r.subjects]) for r in o.rels],
        )
        for o in spec.objs
    ]
    return dataclasses.replace(spec, objs=objs), names


class Item(NamedTuple):
    number: str  # its size and its number in the set: '5/123'
    spec: Spec
    worlds: list[evaluate.Data]


def check_batch(db: DB, items: Sequence[Item], workdir: str, before: bool) -> dict[str, list[str]]:
    """The items' policies applied as one (each its types renamed: s0t1, s1t1, ...), each its worlds loaded side by
    side, before the policy is applied or after; then difftest's checks, and the data read back against the worlds.
    The problems found, by item (by every item where a problem names none)."""
    user_where = items[0].spec.user_where
    assert all(it.spec.user_where == user_where for it in items), "a batch's policies have one user type"
    parts, names = [], {}
    for j, it in enumerate(items):
        spec, m = retyped(it.spec, f"s{j}")
        parts.append(spec)
        names[j] = m
    merged = dataclasses.replace(parts[0], objs=[o for s in parts for o in s.objs])
    path = os.path.join(workdir, "small.authz")
    text = policy_text(merged)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    pol = parse_policy(text, path)
    sql = Compiler(parse_policy(text, path)).compile(path)
    principals = {t.name for t in pol.types.values() if t.principal}
    datas = [moved(w, names[j], APART * k, principals) for j, it in enumerate(items) for k, w in enumerate(it.worlds)]
    world = union(datas)
    principals_rows = users(pol)
    loads = [load_sql(pol, d, principals=False) for d in datas]
    rows = "\n".join([load_sql(pol, principals_rows)[0], *(r for r, _ in loads)])
    shares = "\n".join(s for _, s in loads)
    db.recreate()
    db.run(schema_text(merged))
    if before:
        db.run(rows)
        db.run(sql)
        db.run(shares)
    else:
        db.run(sql)
        db.run(rows + "\n" + shares)
    checker = Checker(db, path, SmallGen(random.Random(0)))
    problems = checker.check()
    snap = checker.snapshot_data_only()
    read = evaluate.Data.of({tuple(k[2:]): v for k, v in snap.items() if k[0] == USERS[0] and k[1] == "data"})
    want, got = facts(pol, world), facts(pol, read)
    for k in sorted(set(want) | set(got)):
        if want.get(k, frozenset()) != got.get(k, frozenset()):
            problems.append(
                f"the data read back isn't the worlds loaded: {k}: {sorted(got.get(k, []))}, loaded {sorted(want.get(k, []))}"
            )
    out: dict[str, list[str]] = {}
    for p in problems:
        found = {int(m) for m in re.findall(r"\bs(\d+)t\d\b", p)}
        for j in found or range(len(items)):
            out.setdefault(items[j].number, []).append(p)
    return out


def revalid(pol: Policy, data: evaluate.Data) -> evaluate.Data:
    """The world with a column made NULL (evaluate.smallest) false (the set's columns are booleans its tables keep
    from being NULL), and the rows each type's where keeps read again from the columns."""
    columns = {
        t: {i: {c: bool(v) for c, v in row.items()} for i, row in rows.items()} for t, rows in data.columns.items()
    }
    data = dataclasses.replace(data, columns={**columns, "user": users(pol).columns["user"]})  # (the users are fixed)
    valid = {}
    for t in pol.types.values():
        node = simple(t.where) if t.where else None
        rows = data.columns.get(t.name, {})
        valid[t.name] = [i for i in data.ids[t.name] if node is None or truth(node, rows.get(i, {}), None) is True]
    return dataclasses.replace(data, valid=valid)


def smallest_failing(db: DB, workdir: str, it: Item, before: bool) -> list[str]:
    """A policy that failed beside others, checked again alone; then its first failing world made as small as it can
    be while it still fails (evaluate.smallest): what to print."""
    if not check_batch(db, [it], workdir, before):
        return ["it passes alone: the policies it was applied with are the ones to read (the batch's)"]
    pol = parse_policy(policy_text(it.spec), "small.authz")
    for w in it.worlds:
        if check_batch(db, [Item(it.number, it.spec, [w])], workdir, before):

            def still(d: evaluate.Data) -> bool:
                return bool(check_batch(db, [Item(it.number, it.spec, [revalid(pol, d)])], workdir, before))

            small = revalid(pol, evaluate.smallest(w, still))
            got = check_batch(db, [Item(it.number, it.spec, [small])], workdir, before)
            return [
                "in this world (the smallest found; users " + ", ".join(USERS) + "):",
                *("  " + x for x in evaluate.World("", 1).describe(pol, small)),
                *(re.sub(r"\bs0(t\d)\b", r"\1", p) for p in got.get(it.number, [])[:12]),
            ]
    return ["it fails only with its worlds side by side"]


# ----------------------------------------------------------------------
class Tally:
    """What a run (or one of its jobs) did."""

    def __init__(self) -> None:
        self.policies = self.checked = self.tried = self.chosen = self.told = self.parts = self.batches = 0
        self.slow = self.misread = 0  # slow to plan; another reading disagreeing with the evaluator
        self.refused: Counter[str] = Counter()
        self.failed: list[str] = []
        self.lines: list[str] = []  # what it says (a job's, printed when the run ends)

    def add(self, other: Tally) -> None:
        for name in ("policies", "checked", "tried", "chosen", "told", "parts", "batches", "slow", "misread"):
            setattr(self, name, getattr(self, name) + getattr(other, name))
        self.refused += other.refused
        self.failed += other.failed
        self.lines += other.lines


def judge(spec: Spec, number: str, tally: Tally, say: Callable[[str], None]) -> Item | None:
    """The evaluator's side of one policy: compiled (refused: counted), every world, the worlds chosen. None when it
    isn't checked further (refused, slow to plan) or failed (said)."""
    tally.policies += 1
    text = policy_text(spec)
    try:
        sql = Compiler(parse_policy(text, "small.authz")).compile("small.authz")
    except PolicyError as e:
        tally.refused[e.code or "?"] += 1
        return None
    if "view definitions to plan" in sql:
        tally.slow += 1
        return None
    choice = choose(spec, text, canonical(spec))
    tally.tried += choice.tried
    tally.told += choice.told
    tally.parts += choice.parts
    tally.chosen += len(choice.worlds)
    if choice.problems:
        tally.failed.append(number)
        tally.misread += 1
        say(f"FAIL policy {number}: another reading disagrees with the reference evaluator")
        say("    " + text.replace("\n", "\n    ").rstrip())
        for p in choice.problems:
            say(f"    {p}")
        return None
    tally.checked += 1
    return Item(number, spec, choice.worlds)


def run(
    policies: Sequence[tuple[str, Spec]], db_name: str, no_db: bool, say: Callable[[str], None] | None = None
) -> Tally:
    """Each policy judged by the evaluator, and those it doesn't set aside checked in the database, in batches of
    BATCH (by user type), loaded before applying in every other batch."""
    tally = Tally()
    out = say or tally.lines.append
    db = DB(db_name)
    queues: dict[bool, list[Item]] = {False: [], True: []}
    with tempfile.TemporaryDirectory() as workdir:

        def flush(queue: list[Item]) -> None:
            if not queue:
                return
            before = tally.batches % 2 == 0
            tally.batches += 1
            found = check_batch(db, queue, workdir, before)
            for j, it in enumerate(queue):
                if it.number in found:
                    tally.failed.append(it.number)
                    out(f"FAIL policy {it.number}: the database and the evaluator disagree")
                    out("    " + policy_text(it.spec).replace("\n", "\n    ").rstrip())
                    for p in found[it.number][:12]:
                        out("    " + re.sub(rf"\bs{j}(t\d)\b", r"\1", p))
                    if len(tally.failed) <= SHRUNK:
                        for p in smallest_failing(db, workdir, it, before):
                            out(f"    {p}")
            queue.clear()

        for number, spec in policies:
            it = judge(spec, number, tally, out)
            if it is None or no_db:
                continue
            queues[spec.user_where].append(it)
            if len(queues[spec.user_where]) == BATCH:
                flush(queues[spec.user_where])
        for queue in queues.values():
            flush(queue)
    if not no_db:
        subprocess.run(["dropdb", "--if-exists", db_name], capture_output=True)
    return tally


def job(args: tuple[Sequence[tuple[str, Spec]], str, bool]) -> Tally:
    return run(*args)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--db", default="authz_small")
    ap.add_argument("--size", type=int, default=3, help="every policy up to this size (and of the next, with a deny)")
    ap.add_argument("--slice", default="0/1", metavar="K/N", help="only the policies whose number is K modulo N")
    ap.add_argument("--jobs", type=int, default=1, help="side by side, each with a database of its own (DB_1, ...)")
    ap.add_argument("--only", metavar="SIZE/NUMBER", help="only this policy, printed")
    ap.add_argument("--no-db", action="store_true", help="the evaluator's side only")
    ap.add_argument("--count", type=int, metavar="SIZE", help="how many policies each size up to SIZE has, and stop")
    args = ap.parse_args()
    os.chdir(os.path.dirname(HERE))
    if args.count:
        # every size up to SIZE, and the denies of the next: the set --size SIZE checks
        for size in range(1, args.count + 2):
            started = time.monotonic()
            every = listed(size)
            specs = [spec for spec in every if size <= args.count or denies(spec)]
            refused = Counter[str]()
            for spec in specs:
                try:
                    Compiler(parse_policy(policy_text(spec), "small.authz")).compile("small.authz")
                except PolicyError as e:
                    refused[e.code or "?"] += 1
            what = "policies" if size <= args.count else f"policies with a deny (of {len(every)})"
            print(
                f"size {size}: {len(specs)} {what} ({sum(map(denies, specs))} with a deny), "
                f"{len(specs) - sum(refused.values())} compile ({', '.join(f'{c} {m}' for c, m in sorted(refused.items()))}), "
                f"{time.monotonic() - started:.0f}s",
                flush=True,
            )
        return
    k, n = (int(x) for x in args.slice.split("/"))
    started = time.monotonic()
    numbered: list[tuple[str, Spec]] = []
    for size in range(1, args.size + 2):
        specs = listed(size)
        numbered += [(f"{size}/{i + 1}", spec) for i, spec in enumerate(specs) if size <= args.size or denies(spec)]
    counts = Counter(int(x.split("/")[0]) for x, _ in numbered)
    want = {s: COUNTS.get(s) for s in range(1, args.size + 1)} | {args.size + 1: DENIES.get(args.size + 1)}
    have = {s: counts.get(s, 0) for s in want}
    if have != want:
        print(f"FAIL the set: {have} policies by size, COUNTS and DENIES say {want}: the language changed? (--count)")
        sys.exit(1)
    print(
        f"ok the set: {len(numbered)} policies up to size {args.size} and of size {args.size + 1} with a deny, as COUNTS says"
    )
    mine = [(x, spec) for g, (x, spec) in enumerate(numbered) if g % n == k and args.only in (None, x)]
    if args.only is not None:
        print(policy_text(mine[0][1]) if mine else f"no policy {args.only}")
    listing = time.monotonic() - started
    tally = Tally()
    if args.jobs > 1:
        import multiprocessing

        shares = [(mine[j :: args.jobs], f"{args.db}_{j + 1}", args.no_db) for j in range(args.jobs)]
        with multiprocessing.get_context("fork").Pool(args.jobs) as pool:
            for t in pool.map(job, shares):
                tally.add(t)
        for line in tally.lines:
            print(line)
    else:
        tally = run(mine, args.db, args.no_db, say=lambda line: print(line, flush=True))
    took = time.monotonic() - started
    what = f"slice {k} of {n}: " if n > 1 else ""
    line = (
        f"{what}{len(mine)} policies; {sum(tally.refused.values())} the compiler refuses "
        f"({', '.join(f'{c} {m}' for c, m in sorted(tally.refused.items()))}), {tally.slow} slow to plan; "
        f"{tally.checked} checked: the evaluator in {tally.tried} worlds, {tally.told} of {tally.parts} parts made "
        f"wrong told apart, in {tally.chosen} worlds chosen"
        + ("" if args.no_db else f", which the database answered as the evaluator ({tally.batches} batches)")
        + f" ({listing:.0f}s listing, {took:.0f}s in all)"
    )
    failed = len(set(tally.failed))
    judged = tally.checked + sum(tally.refused.values()) + tally.slow + tally.misread
    print(f"{'FAIL' if failed else 'ok'} {line}" + (f"; {failed} failed" if failed else ""))
    if judged == len(mine) == tally.policies:
        print(f"ok {what}every policy judged")
    else:
        print(f"FAIL {what}{judged} of {len(mine)} policies judged")
    sys.exit(1 if failed or judged != len(mine) else 0)


if __name__ == "__main__":
    main()
