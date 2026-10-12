"""decisions: which parts of a policy decided an answer in difftest's worlds.

    python3 tests/difftest.py --gen docs --steps 100 --decisions
    python3 tests/genpolicy.py --policies 12 --steps 8 --decisions

difftest holds the database's answers to the reference evaluator's (authzlib/evaluate.py) after each random change.
A part of the policy whose value never changed an answer there is one whose SQL was never judged: a mistake in it
(a mutant) would pass. So, over every snapshot and every principal asked, each part is watched: did it hold for some
(principal, object), fail for some, and decide an answer? Deciding is forcing it the other way, one more evaluation
with that part overridden (true on every row, or on none), and some answer difftest compares changes: a permission
held on an object, a row a rule allows. The parts:

  - each part of each permission's and each rule's expression (`parent.view`, `{inherit}`, `not hidden`);
  - each source of each relation, by the subject it names (a user, a service, a group, user:*, anyone, a link, an
    object that `parent.view` follows), the subjects of custom roles, and their `from`;
  - each type's where;
  - each share that doesn't count, had it counted (expired, not started yet, a caveat that doesn't hold), and each
    that counts by a caveat that holds, had it not;
  - each item of each scope, and what a scope leaves out (difftest asks one principal a snapshot with a scope);
  - each recursion's depth (inheritance, and groups inside groups: 1, 2, 3 or more links deep) and a loop in the
    data that it goes round.

The report says, per policy, by name and line, the parts never true, never false, never decisive, and those decisive
one way only: a mutant forcing them the other way would pass too. A part is forced only until it has decided (each
way), and only for a principal for whom forcing changes it at all, so the cost falls as a run goes on.

It also says what would make a part decide, on the last snapshot's data: a share that alone would change an answer
(gain), and links that would make a recursion's depth or its loop the only way to an answer (plan). difftest aims
some of its changes there.
"""

from __future__ import annotations

import dataclasses
import os
import random
import re
import sys
import time
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from functools import partial
from typing import NamedTuple, TypeAlias, TypeVar

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
from authzlib import evaluate  # noqa: E402
from authzlib.parse import (  # noqa: E402
    KEYWORDS,
    And,
    Arrow,
    Cond,
    Expr,
    Loc,
    Not,
    Or,
    Policy,
    PolicyError,
    Ref,
    Rule,
    ScopeItem,
    Source,
    Type,
    read_lines,
    strip_comment,
    written,
)

Key: TypeAlias = "tuple[str | int, ...]"
# what difftest compares, from one evaluation: ('perm', type, permission) and ('rule', its number) -> the ids
Answers: TypeAlias = "dict[Key, frozenset[str]]"
# the shares that don't count, by why (difftest's queries with --decisions): ('share', why, type, relation, source,
# st, sr) -> [[object, subject], ...], and ('role share', why, type, permission, st, sr) -> [[object, subject, the
# role's owner], ...]; why: 'expired', 'not started', 'caveat false', and 'caveat true' for those that count by it
Shares: TypeAlias = "Mapping[Key, Sequence[Sequence[str]]]"
# what a scope named read lets through without a line of its own: select, and every permission
READ: list[ScopeItem] = [("cmd", None, "select"), ("perm", None, "*")]
UNCOUNTED = ("expired", "not started")  # (shares that don't count, whatever the policy)
CAVEATED = ("caveat false", "caveat true")  # (and by their caveat, in a policy that has caveats)
WHY = {
    "expired": "an expired share",
    "not started": "a share not started yet",
    "caveat false": "a share whose caveat doesn't hold",
    "caveat true": "a share whose caveat holds",
}
# a kind of link a recursion follows: (the name it gives to, on the link's object; its source; the name it reads, on
# the link's subject), and a row on which a principal holds one of its names with none of its links followed
Edge: TypeAlias = "tuple[evaluate.Name, evaluate.PairsKey, evaluate.Name]"
Top: TypeAlias = "tuple[evaluate.Name, str]"
Link = TypeVar("Link", tuple[str, str], tuple[str, str, str])  # a link, or a custom role given: its object first
DEEPEST = 3  # a recursion's depths: 1, 2, and 3 or more
WATCHED_BY_VALUE = ("expr", "where", "source", "roles", "roles from", "share", "role share")


def allows(item: ScopeItem, kind: str, qual: str, word: str) -> bool:
    """Whether a scope's item lets through a command on a table (kind 'cmd') or a permission of a type ('perm')."""
    k, q, w = item
    return k == kind and (w == word or (kind == "perm" and w == "*")) and (q is None or q == qual)


def scope_items(pol: Policy, name: str) -> list[ScopeItem]:
    """A scope's items: its line's, or for `read` without one, what it is built in as."""
    sc = pol.scopes.get(name)
    return sc.items if sc else list(READ)


def rule_name(r: Rule) -> str:
    """A rule, as its line starts: 'rules app.folders update parent_id after'."""
    command, after = ("update", ["after"]) if r.command == "update check" else (r.command, [])
    return " ".join(["rules", r.table, command, *([", ".join(r.columns)] if r.columns else []), *after])


def short(text: str, most: int = 70) -> str:
    return text if len(text) <= most else text[: most - 3] + "..."


@dataclass
class Part:
    """One part of a policy, and what difftest's worlds made of it."""

    key: Key
    what: str  # whose part: 'folder.view', 'rules app.folders select', 'type folder', 'scope read'
    text: str  # the part: 'parent.view', 'team#member (shared)'
    loc: Loc | None  # where it is written (None: nowhere, as the read scope built in)
    ups: bool = True  # it may be forced true (made to hold where it fails)
    downs: bool = True  # it may be forced false
    trues: bool = True  # whether 'never true' says something of it
    falses: bool = True  # whether 'never false' does
    held: bool = False  # it held for some (principal, object)
    failed: bool = False  # it failed for some
    up: str = ""  # the first answer forcing it true changed ('': none yet)
    down: str = ""  # the first answer forcing it false changed

    def name(self) -> str:
        return f"{self.what}: {self.text}" + (f" at {self.loc}" if self.loc is not None else "")

    def settled(self) -> bool:
        """Whether nothing more can be learnt of it: seen true and false, and decisive each way it may be forced."""
        seen = (self.held or not self.trues) and (self.failed or not self.falses)
        return seen and bool(self.up or not self.ups) and bool(self.down or not self.downs)

    def nevers(self) -> list[str]:
        out: list[str] = []
        if self.trues and not self.held:
            out.append("never true")
        if self.falses and not self.failed:
            out.append("never false")
        if not self.up and not self.down:
            out.append("never decisive")
        # one way only, where the other was tried (it held, or failed, somewhere): forced that way, nothing changed
        elif self.ups and self.downs and self.held and not self.down:
            out.append("decisive only forced true")
        elif self.ups and self.downs and self.failed and not self.up:
            out.append("decisive only forced false")
        return out


@dataclass
class Recursion:
    """Names that depend on themselves (one of the evaluator's strata), and the links each round of it follows: the
    arrows of its permissions that lead back into it (inheritance), and the sources of its relations that name a
    group of it (groups inside groups)."""

    names: list[evaluate.Name]
    arrows: list[tuple[Arrow, Type]] = field(default_factory=list)
    nested: list[evaluate.PairsKey] = field(default_factory=list)
    edges: list[Edge] = field(default_factory=list)  # each kind of link a round follows


@dataclass
class Asked:
    """One principal's data in one snapshot, and the evaluator's answers on it."""

    data: evaluate.Data
    user: str
    links: set[str]
    principal: tuple[str, str] | None  # as the evaluator signed them in (None: nobody)
    state: evaluate.State
    answers: Answers
    shares: Shares
    rows: dict[str, set[str]]  # each type's rows that pass its where: those a part's value can matter on


class Gain(NamedTuple):
    """A share that would change an answer in the last snapshot: for whom, on which object, to which subject (the
    principal, a group of theirs, a link they hold, '*'); for a custom role, the permission it must give and the
    owner whose role counts there ('': anyone's)."""

    user: str
    object: str
    subject: str
    perm: str = ""
    owner: str = ""


class Plan(NamedTuple):
    """Links to take away and to add, as the evaluator names them, that would make a recursion's depth or its loop
    decide an answer of one principal's: what a change steered toward that part writes (difftest's Gen.write)."""

    user: str
    cut: list[tuple[evaluate.PairsKey, str]]  # (source, object): each link of that source on that object
    add: list[tuple[evaluate.PairsKey, str, str]]  # (source, object, subject)


class Forcing(evaluate.Reference):
    """The reference evaluator with one part of a policy overridden: an expression's node forced true (on every row)
    or false (on none), the check of whose custom roles count (`roles : ... from org`), or what some arrows read (the
    state a round behind, or their links without some). With nothing overridden it answers as the evaluator does;
    it can also record the value each node had."""

    def __init__(self, pol: Policy) -> None:
        super().__init__(pol)
        self.keys: dict[int, Key] = {}  # id(node) -> its part's key
        self.forced: tuple[Key, bool] | None = None
        self.behind: dict[int, evaluate.State] = {}  # id(arrow) -> the state it reads instead of the one now
        self.without: dict[int, dict[evaluate.PairsKey, set[evaluate.Pair]]] = {}  # id(arrow) -> links it skips
        self.skipping: dict[evaluate.PairsKey, set[evaluate.Pair]] | None = None
        self.seen: dict[Key, set[str]] | None = None  # when set: each node's last value

    def eval_expr(self, state: evaluate.State, t: Type, node: Expr, defining: str | None = None) -> set[str]:
        key = self.keys.get(id(node))
        if key is not None and self.forced is not None and self.forced[0] == key:
            return self.ids(t) if self.forced[1] else set()
        self.skipping = self.without.get(id(node))  # (only arrows are there, which have no parts of their own)
        try:
            got = super().eval_expr(self.behind.get(id(node), state), t, node, defining)
        finally:
            self.skipping = None
        if key is not None and self.seen is not None:
            self.seen[key] = got
        return got

    def pairs(self, t: Type, rname: str, i: int, st: str, sr: str | None) -> list[evaluate.Pair]:
        got = super().pairs(t, rname, i, st, sr)
        skip = self.skipping.get((t.name, rname, i, st, sr or "")) if self.skipping else None
        return [p for p in got if p not in skip] if skip else got

    def role_owners(self, t: Type) -> dict[str, set[str]] | None:
        if self.forced is not None and self.forced[0] == ("roles from", t.name):
            return None if self.forced[1] else {}
        return super().role_owners(t)


def logical_lines(text: str) -> dict[int, str]:
    """Each logical line of a policy file, by its first line's number: its physical lines as written, comments
    dropped (an included file's lines aren't there)."""
    if not text:
        return {}
    try:
        starts = sorted(loc.line for loc, _, _ in read_lines(None, text) if loc.file is None)
    except PolicyError:
        return {}
    raw = text.removeprefix("﻿").split("\n")
    out: dict[int, str] = {}
    for k, start in enumerate(starts):
        end = starts[k + 1] if k + 1 < len(starts) else len(raw) + 1
        out[start] = "\n".join(strip_comment(raw[n - 1]) for n in range(start, end))
    return out


def leaf_pattern(node: Expr) -> str | None:
    """How a leaf of an expression is written, as a pattern; None for a node with parts."""
    match node:
        case Ref(name=name):
            return rf"(?<![\w.#]){re.escape(name)}(?![\w.#])"
        case Arrow(rel=rel, perm=perm):
            return rf"(?<![\w.#]){re.escape(rel)}\.{re.escape(perm)}(?!\w)"
        case Cond(sql=sql) if sql in KEYWORDS.values():
            return rf"(?<![\w.#]){re.escape(written(node))}(?!\w)"
        case Cond(sql=sql):
            return r"\{\s*" + r"\s+".join(re.escape(w) for w in sql.split())
    return None


def components(edges: Mapping[tuple[str, str], set[tuple[str, str]]]) -> dict[tuple[str, str], int]:
    """Each row in a loop of links, and its loop's number (Tarjan's strongly connected components, iteratively)."""
    index: dict[tuple[str, str], int] = {}
    low: dict[tuple[str, str], int] = {}
    on: set[tuple[str, str]] = set()
    stack: list[tuple[str, str]] = []
    out: dict[tuple[str, str], int] = {}
    for root in sorted(edges):
        if root in index:
            continue
        index[root] = low[root] = len(index)
        stack.append(root)
        on.add(root)
        work: list[tuple[tuple[str, str], list[tuple[str, str]]]] = [(root, sorted(edges.get(root, set())))]
        while work:
            v, todo = work[-1]
            if todo:
                w = todo.pop()
                if w not in index:
                    index[w] = low[w] = len(index)
                    stack.append(w)
                    on.add(w)
                    work.append((w, sorted(edges.get(w, set()))))
                elif w in on:
                    low[v] = min(low[v], index[w])
                continue
            work.pop()
            if work:
                low[work[-1][0]] = min(low[work[-1][0]], low[v])
            if low[v] == index[v]:
                members: list[tuple[str, str]] = []
                while True:
                    w = stack.pop()
                    on.discard(w)
                    members.append(w)
                    if w == v:
                        break
                if len(members) > 1 or v in edges.get(v, set()):
                    n = len(set(out.values()))
                    out.update(dict.fromkeys(members, n))
    return out


class Decisions:
    """What the parts of one policy did over difftest's snapshots: observe() each principal's data in each snapshot,
    then report()."""

    def __init__(self, pol: Policy, text: str = "") -> None:
        self.pol = pol
        self.ref = Forcing(pol)
        self.parts: dict[Key, Part] = {}
        self.rows_of: dict[Key, str] = {}  # an expression part's type: whose rows it is about
        self.recursions: list[Recursion] = []
        self.snapshots = 0  # (difftest counts them)
        self.asked: set[str] = set()
        self.last: dict[str, Asked] = {}  # each principal's data in the last snapshot: what gain() reads
        self.seconds = 0.0
        self.lines = logical_lines(text)
        self.build()

    # --- the parts -------------------------------------------------------------------------------------------
    def add(self, part: Part) -> None:
        self.parts[part.key] = part

    def build(self) -> None:
        for t in self.pol.types.values():
            if t.where:
                self.add(Part(("where", t.name), f"type {t.name}", f"where {{{t.where}}}", t.loc))
            for r in t.relations.values():
                for i, src in enumerate(r.sources):
                    for st, sr in src.subjects:
                        self.source(t, r.name, i, src, st, sr)
            if t.roles:
                subjects, _, loc = t.roles
                what = f"{t.name} roles"
                for st, sr in subjects:
                    self.add(Part(("roles", t.name, st, sr or ""), what, self.subject(st, sr), loc))
                    for why in self.whys():
                        self.add(self.share_part(("role share", why, t.name, st, sr or ""), what, st, sr, loc))
                if t.roles_from:
                    self.add(Part(("roles from", t.name), what, f"from {t.roles_from}", loc))
            for p in t.perms.values():
                self.expression(("expr", "perm", t.name, p.name), f"{t.name}.{p.name}", t, p.expr, p.loc, "=")
        for n, r in enumerate(self.pol.rules):
            self.expression(("expr", "rule", n), rule_name(r), self.ref.type_of_table(r.table), r.expr, r.loc, ":")
        for name in sorted({"read", *self.pol.scopes}):
            sc = self.pol.scopes.get(name)
            loc = sc.loc if sc else None
            for j, (_, qual, word) in enumerate(scope_items(self.pol, name)):
                text = "every permission" if word == "*" else ".".join([*([qual] if qual else []), word])
                text += "" if sc else " (built in)"
                self.add(Part(("scope", name, j), f"scope {name}", text, loc, ups=False, falses=False))
            self.add(
                Part(("scope refuses", name), f"scope {name}", "what it leaves out", loc, downs=False, falses=False)
            )
        self.recursion_parts()

    def whys(self) -> tuple[str, ...]:
        """The kinds of share watched: those that don't count (expired, not started), and by a caveat."""
        return (*UNCOUNTED, *(CAVEATED if self.pol.caveats else ()))

    def subject(self, st: str, sr: str | None) -> str:
        if st in ("anyone", "link"):
            return "anyone" if st == "anyone" else "a link"
        return f"{st}:*" if sr == "*" else f"{st}#{sr}" if sr else st

    def kind(self, st: str, sr: str | None) -> str:
        """The kind of subject a source names."""
        if st in ("anyone", "link") or sr == "*":
            return self.subject(st, sr)
        if sr:
            return "a group"
        if st in self.pol.types and self.pol.types[st].principal:
            return "a user" if st == "user" else "a service"
        return "an object"

    def followed(self, st: str, sr: str | None) -> bool:
        """Whether a subject is an object a relation links to (what `rel.perm` follows), not one who holds anything."""
        return sr is None and st in self.pol.types and not self.pol.types[st].principal

    def source(self, t: Type, rname: str, i: int, src: Source, st: str, sr: str | None) -> None:
        how = {"column": "column", "table": f"table {src.table}"}.get(src.kind, src.kind)
        what = f"{t.name}.{rname}"
        self.add(Part(("source", t.name, rname, i, st, sr or ""), what, f"{self.subject(st, sr)} ({how})", src.loc))
        if src.kind == "shared" and not self.followed(st, sr):  # (a share to an object is a link: it never expires)
            for why in self.whys():
                self.add(self.share_part(("share", why, t.name, rname, i, st, sr or ""), what, st, sr, src.loc))

    def share_part(self, key: Key, what: str, st: str, sr: str | None, loc: Loc) -> Part:
        why = str(key[1])
        # one that doesn't count is forced to count (true); one that counts by its caveat, not to (false)
        caveat = why == "caveat true"
        text = f"{WHY[why]} to {self.subject(st, sr)}"
        return Part(key, what, text, loc, ups=not caveat, downs=caveat, falses=False)

    def expression(self, owner: Key, what: str, t: Type, node: Expr, loc: Loc, head: str) -> None:
        """Each node of an expression (but the one right under a `not`: that is the `not` the other way round), at
        the line it is written on."""
        text = self.lines.get(loc.line) if loc.file is None else None
        body = text.find(head) + 1 if text else 0
        counts: dict[str, int] = {}

        def line_of(leaf: Expr) -> Loc:
            pattern = leaf_pattern(leaf)
            if text is None or pattern is None:
                return loc
            n = counts[pattern] = counts.get(pattern, -1) + 1
            found = list(re.finditer(pattern, text[body:]))
            if n >= len(found):
                return loc
            return Loc(None, loc.line + text[: body + found[n].start()].count("\n"))

        def walk(x: Expr, path: tuple[int, ...], part: bool) -> Loc:
            match x:
                case Or(items=items) | And(items=items):
                    lines = [walk(item, (*path, k), True) for k, item in enumerate(items)]  # (every part walked)
                    first = lines[0]
                case Not(item=item):
                    first = walk(item, (*path, 0), False)
                case _:
                    first = line_of(x)
            if part:
                key = (*owner, *path)
                keyword = x.sql if isinstance(x, Cond) else None
                # (anyone is true and nobody false, as they say: never false and never true tell nothing there)
                trues, falses = keyword != KEYWORDS["nobody"], keyword != KEYWORDS["anyone"]
                self.add(Part(key, what, short(written(x)), first, trues=trues, falses=falses))
                self.rows_of[key] = t.name
                self.ref.keys[id(x)] = key
            return first

        walk(node, (), True)

    def recursion_parts(self) -> None:
        """For each stratum that depends on itself through links: how deep they go, and a loop in the data."""
        types = self.pol.types
        for names in self.ref.order:
            inside = set(names)
            rec = Recursion(list(names))

            def arrows(t: Type, of: str, x: Expr, rec: Recursion = rec, inside: set[evaluate.Name] = inside) -> None:
                match x:
                    case Arrow(rel=rel, perm=perm) if rel in t.relations:
                        links = [
                            (t.name, rel, i, st, "")
                            for i, src in enumerate(t.relations[rel].sources)
                            for st, sr in src.subjects
                            if sr is None and st in types and (st, perm) in inside
                        ]
                        if links:
                            rec.arrows.append((x, t))
                            rec.edges += [((t.name, of), k, (k[3], perm)) for k in links]
                    case Not(item=item):
                        arrows(t, of, item)
                    case Or(items=items) | And(items=items):
                        for item in items:
                            arrows(t, of, item)

            for tname, name in names:
                t = types[tname]
                if name in t.perms:
                    arrows(t, name, t.perms[name].expr)
                else:
                    for i, src in enumerate(t.relations[name].sources):
                        rec.nested += [(tname, name, i, st, sr) for st, sr in src.subjects if sr and (st, sr) in inside]
            rec.edges += [((k[0], k[1]), k, (k[3], k[4])) for k in rec.nested]
            if not rec.arrows and not rec.nested:
                continue
            c = len(self.recursions)
            self.recursions.append(rec)
            what = ", ".join(f"{tname}.{name}" for tname, name in names)
            links = [f"{a.rel}.{a.perm}" for a, _ in rec.arrows] + [f"{st}#{sr}" for _, _, _, st, sr in rec.nested]
            kind = "inheritance" if rec.arrows else "groups inside groups"
            first = types[names[0][0]]
            name = names[0][1]
            loc = first.perms[name].loc if name in first.perms else first.relations[name].loc
            via = f" (through {', '.join(dict.fromkeys(links))})"
            for d in range(1, DEEPEST + 1):
                deep = f"{d} deep" if d < DEEPEST else f"{d} or more deep"
                # (that deep, some answer is new, or none: it held where it decided)
                self.add(Part(("depth", c, d), what, f"{kind} {deep}{via}", loc, ups=False, trues=False, falses=False))
            # inheritance through columns alone never goes round a loop: the database refuses one (AZ713)
            if rec.nested or any(src.kind != "column" for a, t in rec.arrows for src in t.relations[a.rel].sources):
                self.add(Part(("loop", c), what, f"{kind} round a loop in the data{via}", loc, ups=False, falses=False))

    # --- watching --------------------------------------------------------------------------------------------
    def observe(
        self, data: evaluate.Data, user: str, links: Iterable[str] = (), shares: Shares | None = None, scope: str = ""
    ) -> None:
        """One principal's data in a snapshot: their links, the shares that don't count (and those that do by a
        caveat), and the scope they were asked with too, if any."""
        start = time.perf_counter()
        ref = self.ref
        ref.seen = {}
        try:
            state = ref.evaluate(data, user, set(links))
            answers = self.answers(state)
            seen = ref.seen
        finally:
            ref.seen = None
        rows = {t.name: set(data.ids[t.name]) & set(data.valid[t.name]) for t in self.pol.types.values()}
        asked = Asked(data, user, set(links), ref.principal, state, answers, shares or {}, rows)
        self.asked.add(user)
        self.last[user] = asked
        for part in self.parts.values():
            if part.key[0] not in WATCHED_BY_VALUE or part.settled():
                continue
            held, failed = self.values(part, asked, seen)
            part.held, part.failed = part.held or bool(held), part.failed or bool(failed)
            if part.key[0] in ("share", "role share"):
                failed = held  # (forced to count, or not to, where it would give something)
            if part.ups and not part.up and failed:
                part.up = self.decided(part, True, asked)
            if part.downs and not part.down and held:
                part.down = self.decided(part, False, asked)
        for c in range(len(self.recursions)):
            if not all(self.parts[("depth", c, d)].down for d in range(1, DEEPEST + 1)):
                self.depths(c, asked)
            loop = self.parts.get(("loop", c))
            if loop is not None and not loop.down:
                self.loop(c, asked)
        if scope:
            self.scoped(scope, asked)
        self.seconds += time.perf_counter() - start

    def answers(self, state: evaluate.State) -> Answers:
        """What difftest compares, for one principal: each permission's objects, and each rule's rows (a mask's: only
        those the select rule lets through)."""
        ref = self.ref
        ids = {t.name: ref.ids(t) for t in self.pol.types.values()}
        out: Answers = {}
        for t in self.pol.types.values():
            for p in t.perms:
                out[("perm", t.name, p)] = frozenset(state[(t.name, p)] & ids[t.name])
        select: dict[str, frozenset[str]] = {}
        for n, r in enumerate(self.pol.rules):
            t = ref.type_of_table(r.table)
            out[("rule", n)] = got = frozenset(ref.eval_expr(state, t, r.expr) & ids[t.name] & ref.valid(t))
            if r.command == "select" and not r.columns:
                select[r.table] = got
        for n, r in enumerate(self.pol.rules):
            if r.command == "mask":
                out[("rule", n)] = out[("rule", n)] & select.get(r.table, frozenset())
        return out

    def values(self, part: Part, asked: Asked, seen: Mapping[Key, set[str]]) -> tuple[set[str], set[str]]:
        """Where a part held for this principal, and where forcing it true would change it (where it failed, and a
        link there could give them something), on the rows it can matter on."""
        key, data, ref = part.key, asked.data, self.ref
        match key:
            case ("expr", *_):
                rows = asked.rows[self.rows_of[key]]
                got = seen.get(key, set()) & rows
                return got, rows - got
            case ("where", str(tname)):
                ids, valid = set(data.ids[tname]), set(data.valid[tname])
                return ids & valid, ids - valid
            case ("source", str(tname), str(rname), int(i), str(st), str(sr)):
                rows = asked.rows[tname]
                pairs = data.pairs[(tname, rname, i, st, sr)]
                if self.followed(st, sr or None):
                    got = {o for o, _ in pairs} & rows
                    return got, rows - got if data.ids.get(st) else set()
                got = ref.held(asked.state, list(pairs), st, sr or None) & rows
                return got, rows - got if self.can_hold(asked, st, sr or None) else set()
            case ("roles", str(tname), str(st), str(sr)):
                t, rows = self.pol.types[tname], asked.rows[tname]
                got = self.role_held(asked, t, st, sr or None, ref.role_owners(t), asked.data.rolepairs) & rows
                return got, rows - got if self.can_hold(asked, st, sr or None) else set()
            case ("roles from", str(tname)):
                t, rows = self.pol.types[tname], asked.rows[tname]
                assert t.roles is not None  # (only a roles line says `from`)
                every: set[str] = set()
                kept: set[str] = set()
                for st, sr in t.roles[0]:
                    every |= self.role_held(asked, t, st, sr, None, asked.data.rolepairs)
                    kept |= self.role_held(asked, t, st, sr, ref.role_owners(t), asked.data.rolepairs)
                return kept & rows, (every - kept) & rows
            case ("share", _, str(tname), str(rname), int(i), str(st), str(sr)):
                these = [(str(x[0]), str(x[1])) for x in asked.shares.get(key, [])]
                return ref.held(asked.state, these, st, sr or None) & asked.rows[tname], set()
            case ("role share", str(why), str(tname), str(st), str(sr)):
                t = self.pol.types[tname]
                got = self.role_held(
                    asked, t, st, sr or None, ref.role_owners(t), self.role_shares(asked, why, t, st, sr)
                )
                return got & asked.rows[tname], set()
        raise ValueError(f"not a part decisions watches by its values: {key!r}")

    def can_hold(self, asked: Asked, st: str, sr: str | None) -> bool:
        """Whether a link to subjects st#sr could give this principal anything (forced true, every row has one)."""
        if st in ("anyone", "link"):
            return st == "anyone" or bool(asked.links)
        if sr == "*" or (sr is None and st in self.pol.types and self.pol.types[st].principal):
            return asked.principal is not None and asked.principal[0] == st
        return bool(sr) and bool(asked.state[(st, str(sr))])

    def role_held(
        self,
        asked: Asked,
        t: Type,
        st: str,
        sr: str | None,
        owners: Mapping[str, set[str]] | None,
        rolepairs: Mapping[evaluate.RolePairsKey, Sequence[evaluate.RoleRow]],
    ) -> set[str]:
        """The objects of t on which the principal holds a custom role given to subjects st#sr (owners: the owners
        whose roles count on each object, or None: everyone's)."""
        assert t.roles is not None
        out: set[str] = set()
        for p in t.roles[1]:
            rows = rolepairs.get((t.name, p, st, sr or ""), [])
            out |= self.ref.held(
                asked.state, [(o, s) for o, s, w in rows if owners is None or w in owners.get(o, ())], st, sr
            )
        return out

    def role_shares(
        self, asked: Asked, why: str, t: Type, st: str, sr: str
    ) -> dict[evaluate.RolePairsKey, list[evaluate.RoleRow]]:
        """The role assignments that don't count (or count by a caveat) for why, by permission, as rolepairs are."""
        assert t.roles is not None
        return {
            (t.name, p, st, sr): [
                (str(x[0]), str(x[1]), str(x[2])) for x in asked.shares.get(("role share", why, t.name, p, st, sr), [])
            ]
            for p in t.roles[1]
        }

    # --- forcing ---------------------------------------------------------------------------------------------
    def decided(self, part: Part, up: bool, asked: Asked) -> str:
        """The first answer that changes with the part forced true (up) or false; '' if none does."""
        ref = self.ref
        data = asked.data
        if part.key[0] in ("expr", "roles from"):
            ref.forced = (part.key, up)
        else:
            data = self.forced_data(part.key, up, asked)
        try:
            return self.changed(asked, self.answers(ref.evaluate(data, asked.user, asked.links)))
        finally:
            ref.forced = None
            self.back(asked)

    def back(self, asked: Asked) -> None:
        """The evaluator as it was after the principal's own evaluation (what values() reads)."""
        self.ref.data, self.ref.links, self.ref.principal = asked.data, asked.links, asked.principal

    def forced_data(self, key: Key, up: bool, asked: Asked) -> evaluate.Data:
        data = asked.data
        match key:
            case ("where", str(tname)):
                return dataclasses.replace(data, valid={**data.valid, tname: list(data.ids[tname]) if up else []})
            case ("source", str(tname), str(rname), int(i), str(st), str(sr)):
                pairs = self.every_link(asked, tname, st, sr or None) if up else []
                return dataclasses.replace(data, pairs={**data.pairs, (tname, rname, i, st, sr): pairs})
            case ("roles", str(tname), str(st), str(sr)):
                t = self.pol.types[tname]
                assert t.roles is not None
                owners = self.ref.role_owners(t)
                rows: list[evaluate.RoleRow] = []
                for o, s in self.every_link(asked, tname, st, sr or None) if up else []:
                    if owners is None or owners.get(o):  # (with `from`: a role of one of the object's owners)
                        rows.append((o, s, sorted(owners[o])[0] if owners is not None else ""))
                return dataclasses.replace(
                    data, rolepairs={**data.rolepairs, **{(tname, p, st, sr): list(rows) for p in t.roles[1]}}
                )
            case ("share", _, str(tname), str(rname), int(i), str(st), str(sr)):
                these = [(str(x[0]), str(x[1])) for x in asked.shares.get(key, [])]
                now = data.pairs[(tname, rname, i, st, sr)]
                pairs = [*now, *(p for p in these if p not in now)] if up else [p for p in now if p not in these]
                return dataclasses.replace(data, pairs={**data.pairs, (tname, rname, i, st, sr): pairs})
            case ("role share", str(why), str(tname), str(st), str(sr)):
                rolepairs = dict(data.rolepairs)
                for k, these in self.role_shares(asked, why, self.pol.types[tname], st, sr).items():
                    now = rolepairs.get(k, [])
                    rolepairs[k] = (
                        [*now, *(x for x in these if x not in now)] if up else [x for x in now if x not in these]
                    )
                return dataclasses.replace(data, rolepairs=rolepairs)
        raise ValueError(f"not a part decisions forces through the data: {key!r}")

    def every_link(self, asked: Asked, tname: str, st: str, sr: str | None) -> list[evaluate.Pair]:
        """Each row of tname linked to the principal through subjects st#sr: what a source forced true holds."""
        ids = asked.data.ids[tname]
        if st == "anyone" or sr == "*":
            return [(o, "*") for o in ids]
        if st == "link":
            return [(o, x) for o in ids for x in sorted(asked.links)]
        if sr:
            return [(o, s) for o in ids for s in sorted(asked.state[(st, sr)])]
        if not self.followed(st, sr):
            me = asked.principal
            return [(o, me[1]) for o in ids] if me is not None and me[0] == st else []
        return [(o, s) for o in ids for s in asked.data.ids.get(st, [])]

    def changed(self, asked: Asked, got: Answers) -> str:
        """The first answer got gives otherwise than the principal's own evaluation: what, on which row, for whom."""
        for k, ids in asked.answers.items():
            if got[k] != ids:
                what = f"{k[1]}.{k[2]}" if k[0] == "perm" else rule_name(self.pol.rules[int(k[1])])
                return f"{what} on {sorted(got[k] ^ ids)[0]} for {asked.user or 'nobody'}"
        return ""

    def depths(self, c: int, asked: Asked) -> None:
        """A recursion's links followed at most 1, 2, ... deep: whether the answers change with each round."""
        rounds = self.rounds(c, asked)
        for d in range(1, DEEPEST + 1) if rounds else ():
            part = self.parts[("depth", c, d)]
            if not part.down:
                part.down = self.deepens(asked, rounds, d)
                part.held = part.held or bool(part.down)

    def rounds(self, c: int, asked: Asked) -> list[Answers]:
        """The answers with a recursion's links followed not at all, then 1, 2, ... deep (each arrow and nested group
        reading the state a round behind), and last as deep as they go; none if it holds nothing for the principal
        at any depth."""
        rec, ref = self.recursions[c], self.ref
        if not any(asked.state[name] for name in rec.names):
            return []
        before: evaluate.State = {name: frozenset() for name in asked.state}
        rounds: list[Answers] = []
        whole = False  # whether the last round gave the recursion all it holds: deeper ones give the same
        try:
            while len(rounds) < DEEPEST and not whole:
                before = self.round(rec, asked, before)
                rounds.append(self.answers(before))
                whole = all(before[name] == asked.state[name] for name in rec.names)
        finally:
            ref.behind = {}
            self.back(asked)
        return rounds + [asked.answers] * (DEEPEST + 1 - len(rounds))

    def round(self, rec: Recursion, asked: Asked, before: evaluate.State) -> evaluate.State:
        """The principal's state with a recursion's links reading the state before (a round behind)."""
        self.ref.behind = {id(a): before for a, _ in rec.arrows}
        data = asked.data
        if rec.nested:
            pairs = dict(data.pairs)
            for k in rec.nested:
                pairs[k] = [(o, s) for o, s in pairs[k] if s in before[(k[3], k[4])]]
            data = dataclasses.replace(data, pairs=pairs)
        return self.ref.evaluate(data, asked.user, asked.links)

    def deepens(self, asked: Asked, rounds: list[Answers], d: int) -> str:
        """Depth d: the first answer d rounds give that d - 1 don't (the last: what the whole recursion gives beyond)."""
        fewer = dataclasses.replace(asked, answers=rounds[d - 1])
        return self.changed(fewer, rounds[d] if d < DEEPEST else rounds[-1])

    def loop(self, c: int, asked: Asked) -> None:
        """Whether the links a recursion follows close a loop in the data, and whether the answers change without
        them (each arrow and nested group skipping them)."""
        loop = self.parts[("loop", c)]
        cycle = self.loop_links(self.recursions[c], asked)
        loop.held = loop.held or bool(cycle)
        if cycle and not loop.down:
            loop.down = self.unlooped(c, asked, cycle)

    def unlooped(self, c: int, asked: Asked, cycle: dict[evaluate.PairsKey, set[evaluate.Pair]]) -> str:
        """The first answer that changes without the links that close a loop in a recursion's data."""
        rec, ref = self.recursions[c], self.ref
        data = asked.data
        ref.without = {id(a): cycle for a, _ in rec.arrows}
        if rec.nested:
            pairs = dict(data.pairs)
            for k in rec.nested:
                pairs[k] = [p for p in pairs[k] if p not in cycle.get(k, set())]
            data = dataclasses.replace(data, pairs=pairs)
        try:
            return self.changed(asked, self.answers(ref.evaluate(data, asked.user, asked.links)))
        finally:
            ref.without = {}
            self.back(asked)

    def loop_links(self, rec: Recursion, asked: Asked) -> dict[evaluate.PairsKey, set[evaluate.Pair]]:
        """The links a recursion follows that close a loop in the data (both ends in one loop of rows), by source."""
        data = asked.data
        sources = list(dict.fromkeys(k for _, k, _ in rec.edges))
        edges: dict[tuple[str, str], set[tuple[str, str]]] = {}
        for k in sources:
            for o, s in data.pairs.get(k, []):
                edges.setdefault((k[0], o), set()).add((k[3], s))
        loops = components(edges)
        out: dict[evaluate.PairsKey, set[evaluate.Pair]] = {}
        for k in sources:
            for o, s in data.pairs.get(k, []):
                a, b = (k[0], o), (k[3], s)
                if a in loops and loops.get(b) == loops[a]:
                    out.setdefault(k, set()).add((o, s))
        return out

    def scoped(self, scope: str, asked: Asked) -> None:
        """The principal asked with a scope too: what each item lets through, and what the scope leaves out; each
        decisive where the answer without the scope has something (the other way, it would be refused, or not)."""
        items = scope_items(self.pol, scope)
        refuses = self.parts[("scope refuses", scope)]
        asks: list[tuple[str, str, str, frozenset[str]]] = [
            ("perm", t.name, p, asked.answers[("perm", t.name, p)]) for t in self.pol.types.values() for p in t.perms
        ]
        commands: dict[tuple[str, str], frozenset[str]] = {}
        for n, r in enumerate(self.pol.rules):
            if not r.columns and r.command != "mask":  # (the rules that are row-level security's policies)
                k = (r.table, "update" if r.command == "update check" else r.command)
                commands[k] = commands.get(k, frozenset()) | asked.answers[("rule", n)]
        asks += [("cmd", table, cmd, ids) for (table, cmd), ids in commands.items()]
        who = asked.user or "nobody"
        for kind, qual, word, ids in asks:
            by = [j for j, item in enumerate(items) if allows(item, kind, qual, word)]
            what = f"{qual}.{word}" if kind == "perm" else f"{word} on {qual}"
            for j in by:
                self.parts[("scope", scope, j)].held = True
            if len(by) == 1 and ids and not self.parts[("scope", scope, by[0])].down:
                self.parts[("scope", scope, by[0])].down = f"{what} for {who}"
            if not by:
                refuses.held = True
                if ids and not refuses.up:
                    refuses.up = f"{what} for {who}"

    # --- steering --------------------------------------------------------------------------------------------
    def gain(self, key: Key, rnd: random.Random, tries: int = 12) -> Gain | None:
        """For a share part (('share', why, type, relation, source, st, sr), or a type's roles: ('role share', why,
        type, st, sr)): a share of that relation, to that kind of subject, that alone would change an answer of one
        of the principals asked in the last snapshot, had it counted; None if a few tries find none. What a change
        steered toward the part writes, in the state the part names (difftest's Gen.steer): the next snapshot then
        sees it decide."""
        tname, st, sr = str(key[2]), str(key[-2]), str(key[-1])
        t = self.pol.types[tname]
        people = list(self.last.values())
        rnd.shuffle(people)
        for asked in people:
            if not self.can_hold(asked, st, sr or None):
                continue
            links = self.every_link(asked, tname, st, sr or None)
            if key[0] == "share":
                k: evaluate.PairsKey = (tname, str(key[3]), int(key[4]), st, sr)
                have = asked.data.pairs[k]
                pair = self.deciding(
                    asked, tname, [x for x in links if x not in have], partial(self.more_pairs, asked, k), rnd, tries
                )
                if pair is not None:
                    return Gain(asked.user, pair[0], pair[1])
                continue
            assert t.roles is not None
            self.back(asked)  # (whose roles count on an object is read from the evaluator's data)
            owners = self.ref.role_owners(t)
            wide = [(o, s, w) for o, s in links for w in (sorted(owners.get(o, ())) if owners is not None else [""])]
            perms = list(t.roles[1])
            rnd.shuffle(perms)
            for p in perms:
                rk: evaluate.RolePairsKey = (tname, p, st, sr)
                given = asked.data.rolepairs.get(rk, [])
                row = self.deciding(
                    asked, tname, [x for x in wide if x not in given], partial(self.more_roles, asked, rk), rnd, tries
                )
                if row is not None:
                    return Gain(asked.user, row[0], row[1], p, row[2])
        return None

    def more_pairs(self, asked: Asked, k: evaluate.PairsKey, pairs: Sequence[evaluate.Pair]) -> evaluate.Data:
        """A principal's data with more links of one source."""
        data = asked.data
        return dataclasses.replace(data, pairs={**data.pairs, k: [*data.pairs[k], *pairs]})

    def more_roles(self, asked: Asked, k: evaluate.RolePairsKey, rows: Sequence[evaluate.RoleRow]) -> evaluate.Data:
        """A principal's data with more custom roles giving one permission."""
        data = asked.data
        return dataclasses.replace(data, rolepairs={**data.rolepairs, k: [*data.rolepairs.get(k, []), *rows]})

    def deciding(
        self,
        asked: Asked,
        tname: str,
        links: Sequence[Link],
        more: Callable[[Sequence[Link]], evaluate.Data],
        rnd: random.Random,
        tries: int,
    ) -> Link | None:
        """One of the links (each starts with its object) that changes an answer of the principal's, added alone:
        those on a row whose own answers change with all of them added are tried first."""
        if not links:
            return None
        every = self.differing(asked, more(links))
        if not every:
            return None
        here = {i for k, ids in every.items() if self.type_of(k) == tname for i in ids}
        order = list(links)
        rnd.shuffle(order)
        order.sort(key=lambda x: x[0] not in here)
        try:
            return next((x for x in order[:tries] if self.differing(asked, more([x]))), None)
        finally:
            self.back(asked)

    def differing(self, asked: Asked, data: evaluate.Data) -> dict[Key, frozenset[str]]:
        """The answers that differ from the principal's own on other data, and on which rows."""
        got = self.answers(self.ref.evaluate(data, asked.user, asked.links))
        return {k: got[k] ^ ids for k, ids in asked.answers.items() if got[k] != ids}

    def type_of(self, answer: Key) -> str:
        """The type whose rows an answer is about: a permission's, a rule's table's."""
        if answer[0] == "perm":
            return str(answer[1])
        return self.ref.type_of_table(self.pol.rules[int(answer[1])].table).name

    def plan(
        self, key: Key, rnd: random.Random, can: Callable[[evaluate.PairsKey, str, str], bool], tries: int = 24
    ) -> Plan | None:
        """For a recursion's depth (('depth', its number, how deep)) or its loop (('loop', its number)): links that
        would make it decide an answer of one of the principals asked in the last snapshot; None if a few tries
        find none. From a row on which they hold one of the recursion's names with none of its links followed, a
        chain that many links long (or one link down and one back up, a loop) through rows on which they hold
        nothing of it, each taken out of whatever else it hung by: the chain is the only way down. Only by links
        the caller can write (can: a source, its object, its subject); each try is checked on the principal's data
        as it would be."""
        c = int(key[1])
        rec = self.recursions[c]
        edges = rec.edges
        people = [a for a in self.last.values() if any(a.state[name] for name in rec.names)]
        tops: dict[str, list[Top]] = {}
        for _ in range(tries if people else 0):
            asked = rnd.choice(people)
            if asked.user not in tops:  # where they hold a name of it with none of its links followed
                ids = {t: set(asked.data.ids[t]) for t in self.pol.types}
                try:
                    shallow = self.round(rec, asked, {name: frozenset() for name in asked.state})
                finally:
                    self.ref.behind = {}
                    self.back(asked)
                tops[asked.user] = [(n, i) for n in rec.names for i in sorted(shallow[n] & ids[n[0]])]
            deep, loop = (1, True) if key[0] == "loop" else (int(key[2]), False)
            plan = self.chain(edges, asked, tops[asked.user], deep, loop, rnd, can)
            if plan is not None and self.would(key, asked, plan):
                return plan
        return None

    def chain(
        self,
        edges: Sequence[Edge],
        asked: Asked,
        tops: Sequence[Top],
        deep: int,
        loop: bool,
        rnd: random.Random,
        can: Callable[[evaluate.PairsKey, str, str], bool],
    ) -> Plan | None:
        """Links from one of the tops down through that many rows; loop: and one back up from the first of them to
        the top."""
        if not tops:
            return None
        name, row = top = rnd.choice(tops)
        plan = Plan(asked.user, [], [])
        # (not through a row the top hangs under already, unless a loop is wanted: the chain would close one)
        used = {(name[0], row)} if loop else self.above(edges, asked.data, (name[0], row))
        try:
            for _ in range(deep):
                step = self.down(edges, asked, plan, name, row, top[0][0] if loop else None, used, rnd, can)
                if step is None:
                    return None
                plan, name, row = step
                used.add((name[0], row))
            return plan
        finally:
            self.back(asked)

    def down(
        self,
        edges: Sequence[Edge],
        asked: Asked,
        plan: Plan,
        name: evaluate.Name,
        row: str,
        back: str | None,
        used: set[tuple[str, str]],
        rnd: random.Random,
        can: Callable[[evaluate.PairsKey, str, str], bool],
    ) -> tuple[Plan, evaluate.Name, str] | None:
        """A plan with one more link: a row on which the principal holds nothing of the recursion, cut from its
        other links and hung under `row` (on which they hold `name`), where the reference says they then hold
        something on it (a few rows are tried); what, and the row. back: and a link back up from `row`, a row of
        that type, to the new one, which makes the two a loop: by a source that isn't a column, or under one that
        isn't (a loop through columns alone is refused)."""
        downs = [e for e in edges if e[2] == name]
        rnd.shuffle(downs)
        for child, k, _ in downs:
            ups = [
                e[1]
                for e in edges
                if e[0][0] == back and e[2] == child and {self.kind_of(k), self.kind_of(e[1])} != {"column"}
            ]
            if back is not None and not ups:
                continue
            free = [
                i
                for i in sorted(asked.rows[child[0]])
                if i not in asked.state[child] and (child[0], i) not in used and can(k, i, row)
            ]
            rnd.shuffle(free)
            for below in free[:6]:
                up = [x for x in ups if can(x, row, below)]
                if back is not None and not up:
                    continue
                cut = list(dict.fromkeys([*plan.cut, *((e[1], below) for e in edges if e[1][0] == child[0])]))
                add = [*plan.add, (k, below, row), *([(rnd.choice(up), row, below)] if back is not None else [])]
                then = Plan(asked.user, cut, add)
                if below in self.ref.evaluate(self.planned(asked, then), asked.user, asked.links)[child]:
                    return then, child, below
        return None

    def above(self, edges: Sequence[Edge], data: evaluate.Data, row: tuple[str, str]) -> set[tuple[str, str]]:
        """A row (type, id) and every row it hangs under, by the links a recursion follows."""
        sources = list(dict.fromkeys(k for _, k, _ in edges))
        seen, todo = {row}, [row]
        while todo:
            tname, i = todo.pop()
            for k in sources:
                for o, s in data.pairs.get(k, []) if k[0] == tname else ():
                    if o == i and (k[3], s) not in seen:
                        seen.add((k[3], s))
                        todo.append((k[3], s))
        return seen

    def idle(self, key: Key) -> list[Key]:
        """For a recursion's depth or loop, when it holds nothing for anyone asked in the last snapshot: the shares
        that would give someone something of it to begin with, as share parts' keys (state ''): those of the
        relations its permissions name. None while it holds something for someone."""
        rec = self.recursions[int(key[1])]
        if any(a.state[name] for a in self.last.values() for name in rec.names):
            return []
        out: list[Key] = []

        def named(t: Type, x: Expr) -> None:
            match x:
                case Ref(name=name) if name in t.relations:
                    for i, src in enumerate(t.relations[name].sources):
                        if src.kind == "shared":
                            out.extend(
                                ("share", "", t.name, name, i, st, sr or "")
                                for st, sr in src.subjects
                                if not self.followed(st, sr)
                            )
                case Not(item=item):
                    named(t, item)
                case Or(items=items) | And(items=items):
                    for item in items:
                        named(t, item)

        for tname, name in rec.names:
            t = self.pol.types[tname]
            if name in t.perms:
                named(t, t.perms[name].expr)
        return out

    def planned(self, asked: Asked, plan: Plan) -> evaluate.Data:
        """A principal's data as a plan makes it."""
        pairs = dict(asked.data.pairs)
        for k, o in plan.cut:
            pairs[k] = [p for p in pairs[k] if p[0] != o]
        for k, o, s in plan.add:
            pairs[k] = [*pairs[k], (o, s)]
        return dataclasses.replace(asked.data, pairs=pairs)

    def kind_of(self, k: evaluate.PairsKey) -> str:
        """How a source's links are kept: 'column', 'table' or 'shared'."""
        return self.pol.types[k[0]].relations[k[1]].sources[k[2]].kind

    def would(self, key: Key, asked: Asked, plan: Plan) -> bool:
        """Whether a recursion's depth or loop decides an answer of the principal's on their data as a plan makes
        it."""
        data = self.planned(asked, plan)
        c = int(key[1])
        try:
            state = self.ref.evaluate(data, asked.user, asked.links)
            then = dataclasses.replace(asked, data=data, state=state, answers=self.answers(state))
            if key[0] == "depth":
                rounds = self.rounds(c, then)
                return bool(rounds) and bool(self.deepens(then, rounds, int(key[2])))
            cycle = self.loop_links(self.recursions[c], then)
            return bool(cycle) and bool(self.unlooped(c, then, cycle))
        finally:
            self.back(asked)

    def wanting(self) -> list[Key]:
        """The parts that have decided no answer yet, as forcing tells: what a change steered toward them is for
        (difftest's Gen.steer)."""
        return [p.key for p in self.parts.values() if (p.ups or p.downs) and not p.up and not p.down]

    # --- the report ------------------------------------------------------------------------------------------
    def report(self, name: str, only_decisive: bool = False, of: float | None = None) -> list[str]:
        """Each part that missed something, by name and line, and what it never did (only_decisive: those that never
        decided an answer, alone). of: how long the whole run took, to say what share of it this took."""
        parts = sorted(
            self.parts.values(), key=lambda p: (p.loc is None, (p.loc.file or "", p.loc.line) if p.loc else ("", 0))
        )
        never = [p for p in parts if "never decisive" in p.nevers()]
        took = f"{self.seconds:.1f} s" + (f" of the run's {of:.0f} s" if of else "")
        snapshots = f"{self.snapshots} snapshot" + ("" if self.snapshots == 1 else "s")
        asking = f"{len(self.asked)} principal" + ("" if len(self.asked) == 1 else "s")
        lines = [
            f"decisions ({name}): {len(never)} of the policy's {len(parts)} parts never decided an answer, over "
            f"{snapshots} and {asking} asking ({took})"
        ]
        for p in never if only_decisive else parts:
            said = ["never decisive"] if only_decisive else p.nevers()
            if said:
                lines.append(f"  {p.name()}: {', '.join(said)}")
        if not only_decisive:
            kinds: dict[str, bool] = {}
            for p in self.parts.values():
                if p.key[0] in ("source", "roles"):
                    k = self.kind(str(p.key[-2]), str(p.key[-1]) or None)
                    kinds[k] = kinds.get(k, False) or bool(p.up or p.down)
            if kinds:
                lines.append(
                    "  subjects that decided an answer: "
                    + (", ".join(k for k, v in kinds.items() if v) or "none")
                    + ("; never: " + ", ".join(k for k, v in kinds.items() if not v) if not all(kinds.values()) else "")
                )
        return lines
