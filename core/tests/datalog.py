"""datalog: a small Datalog engine, standard library only: rules over facts, semi-naive, stratified negation.

The third evaluator (tests/third.py) writes a policy as rules and a world as facts, and runs them here. It shares
no code with authzlib: this engine knows nothing of policies.

    X, Y, Z = Var("X"), Var("Y"), Var("Z")
    rules = [Rule(Atom("path", (X, Y)), (Lit(Atom("edge", (X, Y))),)),
             Rule(Atom("path", (X, Z)), (Lit(Atom("path", (X, Y))), Lit(Atom("edge", (Y, Z)))))]
    run(rules, {"edge": {("a", "b"), ("b", "c")}})["path"]   # {("a","b"), ("b","c"), ("a","c")}

A rule's body is literals: atoms, some negated (`Lit(atom, negated=True)`: true when no such fact). A rule must
be safe: each variable of its head and of its negated literals is in one of its positive literals. Negation is
stratified: the predicates are ordered so that what a `not` reads is final before it is read; a program where a
predicate depends on itself through a `not` has no such order and is refused (NotStratified). Each stratum is
run to its least fixpoint, semi-naively: each round joins one literal against the facts the round before found
new, the others against all, so a fact is derived from new facts only.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from typing import NamedTuple, TypeAlias


@dataclass(frozen=True)
class Var:
    name: str

    def __repr__(self) -> str:
        return self.name


Term: TypeAlias = "str | Var"
Fact: TypeAlias = "tuple[str, ...]"
Facts: TypeAlias = "dict[str, set[Fact]]"


class Atom(NamedTuple):
    pred: str
    args: tuple[Term, ...]

    def __repr__(self) -> str:
        return f"{self.pred}({', '.join(a.name if isinstance(a, Var) else repr(a) for a in self.args)})"


class Lit(NamedTuple):
    atom: Atom
    negated: bool = False

    def __repr__(self) -> str:
        return ("not " if self.negated else "") + repr(self.atom)


class Rule(NamedTuple):
    head: Atom
    body: tuple[Lit, ...]

    def __repr__(self) -> str:
        return f"{self.head!r} :- {', '.join(repr(x) for x in self.body)}." if self.body else f"{self.head!r}."


class NotStratified(Exception):
    """A predicate depends on itself through a `not`: the program has no meaning as stratified Datalog."""


class Unsafe(Exception):
    """A rule whose head or negated literal has a variable no positive literal binds."""


def variables(atom: Atom) -> set[Var]:
    return {a for a in atom.args if isinstance(a, Var)}


def check_safe(rule: Rule) -> None:
    bound = {v for lit in rule.body if not lit.negated for v in variables(lit.atom)}
    free = variables(rule.head) - bound
    for lit in rule.body:
        if lit.negated:
            free |= variables(lit.atom) - bound
    if free:
        raise Unsafe(f"{rule!r}: {', '.join(sorted(v.name for v in free))} bound by no positive literal")


# ----------------------------------------------------------------------
# strata
# ----------------------------------------------------------------------
def strata(rules: Sequence[Rule]) -> list[list[str]]:
    """The derived predicates in groups, each after every group it reads: the strongly connected components of the
    dependency graph, in topological order. Refused (NotStratified) where a `not` reads a predicate of its own
    group."""
    heads = {r.head.pred for r in rules}
    edges: dict[str, set[tuple[str, bool]]] = {p: set() for p in heads}
    for r in rules:
        for lit in r.body:
            if lit.atom.pred in heads:
                edges[r.head.pred].add((lit.atom.pred, lit.negated))
    # Tarjan's algorithm, without recursion: components come out after all they depend on
    index: dict[str, int] = {}
    low: dict[str, int] = {}
    on: set[str] = set()
    stack: list[str] = []
    out: list[list[str]] = []
    counter = 0
    for root in sorted(heads):
        if root in index:
            continue
        work: list[tuple[str, Iterator[tuple[str, bool]]]] = [(root, iter(sorted(edges[root])))]
        index[root] = low[root] = counter
        counter += 1
        stack.append(root)
        on.add(root)
        while work:
            node, it = work[-1]
            advanced = False
            for nxt, _neg in it:
                if nxt not in index:
                    index[nxt] = low[nxt] = counter
                    counter += 1
                    stack.append(nxt)
                    on.add(nxt)
                    work.append((nxt, iter(sorted(edges[nxt]))))
                    advanced = True
                    break
                if nxt in on:
                    low[node] = min(low[node], index[nxt])
            if advanced:
                continue
            work.pop()
            if work:
                low[work[-1][0]] = min(low[work[-1][0]], low[node])
            if low[node] == index[node]:
                comp: list[str] = []
                while True:
                    x = stack.pop()
                    on.discard(x)
                    comp.append(x)
                    if x == node:
                        break
                out.append(sorted(comp))
    for comp in out:
        members = set(comp)
        for p in comp:
            for q, neg in edges[p]:
                if neg and q in members:
                    raise NotStratified(f"{p} depends on {q} through a `not`, and {q} on {p}: no stratum can hold both")
    return out


# ----------------------------------------------------------------------
# evaluation
# ----------------------------------------------------------------------
@dataclass
class Store:
    """Facts by predicate, with the indexes the joins ask for (by the positions bound), kept as facts are added."""

    facts: Facts = field(default_factory=dict)
    indexes: dict[tuple[str, tuple[int, ...]], dict[Fact, list[Fact]]] = field(default_factory=dict)

    def get(self, pred: str) -> set[Fact]:
        return self.facts.setdefault(pred, set())

    def add(self, pred: str, fact: Fact) -> bool:
        have = self.get(pred)
        if fact in have:
            return False
        have.add(fact)
        for (p, pos), idx in self.indexes.items():
            if p == pred:
                idx.setdefault(tuple(fact[i] for i in pos), []).append(fact)
        return True

    def lookup(self, pred: str, pos: tuple[int, ...], key: Fact) -> Sequence[Fact]:
        if not pos:
            return list(self.get(pred))
        idx = self.indexes.get((pred, pos))
        if idx is None:
            idx = {}
            for f in self.get(pred):
                idx.setdefault(tuple(f[i] for i in pos), []).append(f)
            self.indexes[(pred, pos)] = idx
        return idx.get(key, [])


Binding: TypeAlias = "dict[Var, str]"


def match(atom: Atom, fact: Fact, env: Binding) -> Binding | None:
    """env extended so that the atom is the fact, or None."""
    if len(fact) != len(atom.args):
        return None
    out = env
    for a, v in zip(atom.args, fact, strict=True):
        if isinstance(a, Var):
            have = out.get(a)
            if have is None:
                if out is env:
                    out = dict(env)
                out[a] = v
            elif have != v:
                return None
        elif a != v:
            return None
    return out


def bound_key(atom: Atom, env: Binding) -> tuple[tuple[int, ...], Fact]:
    pos: list[int] = []
    key: list[str] = []
    for i, a in enumerate(atom.args):
        if isinstance(a, Var):
            if a in env:
                pos.append(i)
                key.append(env[a])
        else:
            pos.append(i)
            key.append(a)
    return tuple(pos), tuple(key)


def solve(
    body: Sequence[Lit], store: Store, delta: tuple[int, set[Fact]] | None, env: Binding | None = None
) -> Iterator[Binding]:
    """Every binding that makes the body true: the literal delta names (its index) taken from the new facts only, the
    others from the store; each next positive literal the one with the most variables bound, a negated one as soon
    as its variables are."""
    todo = list(range(len(body)))
    first: Binding = {} if env is None else env

    def step(env: Binding, todo: list[int]) -> Iterator[Binding]:
        # negated literals whose variables are bound: check them now
        rest: list[int] = []
        for i in todo:
            lit = body[i]
            if lit.negated and variables(lit.atom) <= env.keys():
                pos, key = bound_key(lit.atom, env)
                if any(match(lit.atom, f, env) is not None for f in store.lookup(lit.atom.pred, pos, key)):
                    return
            else:
                rest.append(i)
        if not rest:
            yield env
            return
        positives = [i for i in rest if not body[i].negated]
        if delta is not None and delta[0] in positives:
            pick = delta[0]
        else:
            pick = max(positives, key=lambda i: (len(bound_key(body[i].atom, env)[0]), -i))
        atom = body[pick].atom
        remaining = [i for i in rest if i != pick]
        if delta is not None and pick == delta[0]:
            candidates: Iterable[Fact] = delta[1]
        else:
            pos, key = bound_key(atom, env)
            candidates = store.lookup(atom.pred, pos, key)
        for f in list(candidates):
            got = match(atom, f, env)
            if got is not None:
                yield from step(got, remaining)

    yield from step(first, todo)


def ground(head: Atom, env: Binding) -> Fact:
    return tuple(env[a] if isinstance(a, Var) else a for a in head.args)


def run(rules: Sequence[Rule], facts: Mapping[str, Iterable[Fact]]) -> Facts:
    """Every fact the rules derive from the facts given (which they keep): the least model, stratum by stratum."""
    for r in rules:
        check_safe(r)
    store = Store()
    for pred, fs in facts.items():
        for f in fs:
            store.add(pred, tuple(f))
    for comp in strata(rules):
        members = set(comp)
        own = [r for r in rules if r.head.pred in members]
        # the first round: every rule against everything known
        new: dict[str, set[Fact]] = {p: set() for p in comp}
        for r in own:
            for env in list(solve(r.body, store, None)):
                f = ground(r.head, env)
                if store.add(r.head.pred, f):
                    new[r.head.pred].add(f)
        # then semi-naively: only rules that read this stratum, once for each literal of it, against what is new
        recursive = [
            (r, i) for r in own for i, lit in enumerate(r.body) if not lit.negated and lit.atom.pred in members
        ]
        while any(new.values()):
            found: dict[str, set[Fact]] = {p: set() for p in comp}
            for r, i in recursive:
                d = new[r.body[i].atom.pred]
                if not d:
                    continue
                for env in list(solve(r.body, store, (i, d))):
                    f = ground(r.head, env)
                    if f not in store.get(r.head.pred):
                        found[r.head.pred].add(f)
            for p, fs in found.items():
                for f in fs:
                    store.add(p, f)
            new = found
    return store.facts
