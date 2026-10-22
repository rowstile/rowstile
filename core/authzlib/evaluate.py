"""What a policy grants, computed straight from what it says: the reference evaluator.

Relations and permissions are sets of ids, computed as a least fixpoint over some data. It is independent of
the SQL the compiler writes, so the tests compare the two (tests/difftest.py), and it answers questions about
a policy without a database: whether two policies grant the same in every small world (the review's check
that a refactor changed nothing), and if not, a world where they don't, made as small as it can be (smallest); or
whether an invariant holds in every one (`rowstile prove`).

The data (Data; difftest reads it from a database, World makes it up):
    ids[type]                                   every id of the type (text)
    valid[type]                                 the ids that pass the type's where
    pairs[(type, relation, i, st, sr)]          (object id, subject id) of source i of the relation
    rolepairs[(type, perm, st, sr)]             custom role assignments that include the permission: (object id,
                                                subject id, the role's owner id; '' when roles say no `from`)
    cond[(type, sql)]                           the ids for which a {condition} holds
    columns[type][id][column]                   a row's column values, for the simple conditions the evaluator
                                                reads itself (conditions.py); a condition in cond is read from there
"""

from __future__ import annotations

import dataclasses
import itertools
import random
from collections.abc import Callable, Collection, Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from decimal import Decimal
from typing import NamedTuple, TypeAlias, TypedDict, TypeVar, cast

from .conditions import Node, Scalar, alike_columns, columns_of, reads_alike, simple, truth, uses_uid
from .parse import (
    KEYWORDS,
    ROLES,
    And,
    Arrow,
    ArrowOn,
    Cond,
    Expr,
    Leaf,
    Not,
    Or,
    Policy,
    Ref,
    Relation,
    Rule,
    Source,
    Type,
    leaves,
)

# a relation or permission of a type, and the ids that hold it
Name: TypeAlias = "tuple[str, str]"
State: TypeAlias = "dict[Name, frozenset[str]]"
Pair: TypeAlias = "tuple[str, str]"  # (object id, subject id)
RoleRow: TypeAlias = "tuple[str, str, str]"  # (object id, subject id, the role's owner id or '')
PairsKey: TypeAlias = "tuple[str, str, int, str, str]"  # (type, relation, source i, subject type, relation or '')
RolePairsKey: TypeAlias = "tuple[str, str, str, str]"  # (type, permission, subject type, relation or '')
CondKey: TypeAlias = "tuple[str, str]"  # (type, condition)
K = TypeVar("K")
V = TypeVar("V")
# what the policies read here hold, being ones the compiler compiles: an arrow follows objects of the policy's types,
# never groups, type:*, anyone or links (AZ301) nor a subject of no type (AZ201)
FOLLOWS = "an arrow follows objects of the policy's types (AZ301, AZ201)"


@dataclass
class Data:
    """What the evaluator reads: ids, links and which rows pass each condition."""

    ids: dict[str, list[str]] = field(default_factory=dict)
    valid: dict[str, list[str]] = field(default_factory=dict)
    pairs: dict[PairsKey, list[Pair]] = field(default_factory=dict)
    rolepairs: dict[RolePairsKey, list[RoleRow]] = field(default_factory=dict)
    cond: dict[CondKey, list[str]] = field(default_factory=dict)
    columns: dict[str, dict[str, dict[str, Scalar]]] = field(default_factory=dict)

    @classmethod
    def of(cls, raw: Mapping[tuple[object, ...], Sequence[object]]) -> Data:
        """From ("ids", type) -> ids, ("pairs", type, relation, i, st, sr) -> [[object, subject]], and the
        like: difftest's form, read from a database as JSON."""
        out = cls()

        def pairs(v: Sequence[object]) -> list[Pair]:
            got = []
            for p in v:
                assert isinstance(p, (list, tuple)) and len(p) == 2, p
                got.append((str(p[0]), str(p[1])))
            return got

        for key, v in raw.items():
            match key:
                case ("ids", str(t)):
                    out.ids[t] = [str(x) for x in v]
                case ("valid", str(t)):
                    out.valid[t] = [str(x) for x in v]
                case ("pairs", str(t), str(r), int(i), str(st), str(sr)):
                    out.pairs[(t, r, i, st, sr)] = pairs(v)
                case ("rolepairs", str(t), str(p), str(st), str(sr)):
                    rows = []
                    for x in v:
                        assert isinstance(x, (list, tuple)) and len(x) in (2, 3), x
                        rows.append((str(x[0]), str(x[1]), str(x[2]) if len(x) == 3 else ""))
                    out.rolepairs[(t, p, st, sr)] = rows
                case ("cond", str(t), str(sql)):
                    out.cond[(t, sql)] = [str(x) for x in v]
                case _:
                    raise ValueError(f"not the evaluator's data: {key!r}")
        return out


def linked_column(src: Source) -> str | None:
    """The column a relation's source reads, when it is one column naming one object (`owner : user = owner_id`)."""
    if src.kind != "column" or not isinstance(src.column, str) or src.type_col or len(src.subjects) != 1:
        return None
    return src.column if src.subjects[0][1] is None else None


def role_owner_type(t: Type) -> str | None:
    """The type of the roles' owner, `roles : ... from rel`: what rel links to (None without `from`)."""
    r = t.relations.get(t.roles_from) if t.roles_from else None
    return r.subjects()[0][0] if r else None


def principal_of(user: str, types: Mapping[str, Type]) -> tuple[str, str]:
    """'bot:2' -> ('bot', '2') for a principal type other than user; a user's id -> ('user', id)."""
    kind, sep, pid = str(user).partition(":")
    if sep and kind in types and kind != "user":
        return kind, pid
    return "user", str(user)


class Reference:
    """Relations and permissions as sets of ids (as text), computed as a least fixpoint, straight from what
    the policy says. Names that depend on each other are computed together, after everything they depend
    on, so what a `not` reads is final: a deny inside inheritance (`(viewer or parent.view) and not denied`)
    means just what it says."""

    def __init__(self, pol: Policy) -> None:
        self.pol, self.types, self.rules = pol, pol.types, pol.rules
        self.of_table: dict[str, Type] = {}  # a table's type (one, where it has rules: AZ401)
        for t in pol.types.values():
            self.of_table.setdefault(t.table, t)
        self.graph: dict[Name, set[Name]] = {}
        self.order = self.strata()
        self.data = Data()
        self.links: set[str] = set()
        self.principal: tuple[str, str] | None = None
        # each type's rows (row_values), for the data they were read from: held, not its id(), which a later
        # world's data may take once this one is gone
        self._rows_of: Data | None = None
        self._rows: dict[str, dict[str, dict[str, Scalar]]] = {}

    def strata(self) -> list[list[Name]]:
        """Groups of names that depend on each other, each after the ones it depends on."""
        graph: dict[Name, set[Name]] = {}
        negated: set[tuple[Name, Name]] = set()

        def walk(t: Type, key: Name, node: Expr) -> None:
            """What the expression of t's `key` reads, into graph[key] (and negated, under a not)."""
            for leaf, nots in leaves(node):
                found: set[Name] = set()
                match leaf:
                    case Ref(name) if name == ROLES:
                        pass  # the role holders' groups: the roles line's subjects, below
                    case Ref(name):
                        found.add((t.name, name))
                    case Arrow(rel, perm) | ArrowOn(rel, perm, _):
                        found.add((t.name, rel))
                        for st, sr in t.relations[rel].subjects():
                            assert sr is None and st in self.types, FOLLOWS
                            found.add((st, perm))
                graph[key].update(found)
                if nots:
                    negated.update((key, f) for f in found)

        for t in self.types.values():
            for name in list(t.relations) + list(t.perms):
                out = graph[(t.name, name)] = set()
                subjects: list[tuple[str, str | None]] = []
                if name in t.perms:
                    walk(t, (t.name, name), t.perms[name].expr)
                    if t.roles and name in t.roles[1]:
                        subjects = t.roles[0]
                else:
                    subjects = [s for src in t.relations[name].sources for s in src.subjects]
                out.update((st, sr) for st, sr in subjects if sr and sr != "*" and st in self.types)
        index: dict[Name, int] = {}
        low: dict[Name, int] = {}
        stack: list[Name] = []
        on: set[Name] = set()
        order: list[list[Name]] = []

        def visit(v: Name) -> None:  # Tarjan: a group comes out after every group it reaches
            index[v] = low[v] = len(index)
            stack.append(v)
            on.add(v)
            for w in graph[v]:
                if w not in index:
                    visit(w)
                    low[v] = min(low[v], low[w])
                elif w in on:
                    low[v] = min(low[v], index[w])
            if low[v] == index[v]:
                comp = []
                while True:
                    w = stack.pop()
                    on.discard(w)
                    comp.append(w)
                    if w == v:
                        break
                order.append(comp)

        for v in graph:
            if v not in index:
                visit(v)
        # what a `not` reads comes before it: the compiler refuses a not inside a recursion (AZ302)
        assert not any((a, b) in negated for comp in order for a in comp for b in comp), "a not inside a recursion"
        self.graph = graph
        return order

    def conditions(self) -> list[CondKey]:
        """Every {sql} condition, by type, in the policy, its rules and invariants."""
        found: set[CondKey] = set()

        def walk(t: Type, node: Expr) -> None:
            found.update((t.name, leaf.sql) for leaf, _ in leaves(node) if isinstance(leaf, Cond))

        for t in self.types.values():
            for p in t.perms.values():
                walk(t, p.expr)
        for rule in self.rules:
            walk(self.type_of_table(rule.table), rule.expr)
        for inv in self.pol.invariants:
            walk(self.types[inv.type], inv.expr)
        return sorted(found)

    def type_of_table(self, table: str) -> Type:
        return self.of_table[table]

    # evaluation ----------------------------------------------------------
    def reads(self, names: Iterable[Name]) -> set[Name]:
        """These names and every name they read, themselves or through what they read."""
        out: set[Name] = set()
        todo = [n for n in names if n in self.graph]
        while todo:
            n = todo.pop()
            if n not in out:
                out.add(n)
                todo += self.graph[n]
        return out

    def evaluate(self, data: Data, user: str, links: Iterable[str] = (), names: set[Name] | None = None) -> State:
        """What each relation and permission holds in the data for this user (holding these share links); with
        names, only those and what they read are worked out (the others hold nothing in the state)."""
        self.data, self.links = data, set(links)
        kind, pid = principal_of(user, self.types)
        self.principal = (kind, pid) if kind in self.types and pid in set(data.valid[kind]) else None
        state: State = {
            (t.name, name): frozenset() for t in self.types.values() for name in list(t.relations) + list(t.perms)
        }
        for comp in self.order:
            if names is None or names.intersection(comp):
                self.settle(state, comp)
        return state

    def settle(self, state: State, comp: Sequence[Name]) -> None:
        """Works out a group of names that depend on each other, in state: a least fixpoint. No `not` in the group
        reads a name of it (strata), so each round only adds, and the rounds end."""
        changed = True
        while changed:
            changed = False
            for tname, name in comp:
                t = self.types[tname]
                new = frozenset(self.eval_name(state, t, name) & self.valid(t))
                if new != state[(tname, name)]:
                    state[(tname, name)] = new
                    changed = True

    def rule(self, state: State, rule: Rule) -> set[str]:
        """The rows (ids) of the rule's table the rule allows, in this state: never one that fails the type's where."""
        t = self.type_of_table(rule.table)
        return self.eval_expr(state, t, rule.expr) & self.ids(t) & self.valid(t)

    def ids(self, t: Type) -> set[str]:
        return set(self.data.ids[t.name])

    def valid(self, t: Type) -> set[str]:
        return set(self.data.valid[t.name])

    def role_owners(self, t: Type) -> dict[str, set[str]] | None:
        """For `roles : ... from rel`: each object's owners (what rel's columns and tables link it to); None
        without `from`."""
        if not t.roles_from:
            return None
        out: dict[str, set[str]] = {}
        r = t.relations[t.roles_from]
        for i, src in enumerate(r.sources):
            for st, sr in src.subjects:
                for o, w in self.data.pairs.get((t.name, r.name, i, st, sr or ""), []):
                    out.setdefault(o, set()).add(w)
        return out

    def held(self, state: State, pairs: list[Pair], st: str, sr: str | None) -> set[str]:
        if sr is None and st in self.types and self.types[st].principal:
            return {o for o, s in pairs if self.principal == (st, s)}
        if sr == "*":
            return {o for o, s in pairs} if self.principal is not None and self.principal[0] == st else set()
        if st == "anyone":
            return {o for o, s in pairs}
        if st == "link":
            return {o for o, s in pairs if s in self.links}
        if sr:
            return {o for o, s in pairs if s in state[(st, sr)]}
        return set()

    def row_values(self, t: Type) -> dict[str, dict[str, Scalar]]:
        """Each row's column values for simple conditions; a column a relation reads is its link's id (so a
        smaller world, with a link taken away, has the column NULL)."""
        if self._rows_of is not self.data:
            self._rows_of, self._rows = self.data, {}
        if t.name not in self._rows:
            rows = {i: dict(v) for i, v in self.data.columns.get(t.name, {}).items()}
            for r in t.relations.values():
                for i, src in enumerate(r.sources):
                    col = linked_column(src)
                    if col is None:
                        continue
                    for row in rows.values():
                        row[col] = None
                    for o, s in self.data.pairs.get((t.name, r.name, i, src.subjects[0][0], ""), []):
                        rows.setdefault(o, {})[col] = s
            self._rows[t.name] = rows
        return self._rows[t.name]

    def role_holders(self, state: State, t: Type, perm: str) -> set[str]:
        """The objects of t on which the principal holds a custom role that includes perm: what `roles` means in
        `can perm = ... or roles`."""
        assert t.roles, "the compiler refuses `roles` on a type without a roles line (AZ210)"
        out: set[str] = set()
        owners = self.role_owners(t)
        for st, sr in t.roles[0]:
            # with `from rel`, an assignment counts only if rel links its object to the role's owner
            pairs = [
                (o, s)
                for o, s, w in self.data.rolepairs[(t.name, perm, st, sr or "")]
                if owners is None or w in owners.get(o, ())
            ]
            out |= self.held(state, pairs, st, sr)
        return out

    def eval_name(self, state: State, t: Type, name: str) -> set[str]:
        if name in t.perms:
            return self.eval_expr(state, t, t.perms[name].expr, name)
        out = set()
        for i, src in enumerate(t.relations[name].sources):
            for st, sr in src.subjects:
                out |= self.held(state, self.pairs(t, name, i, st, sr), st, sr)
        return out

    def pairs(self, t: Type, rname: str, i: int, st: str, sr: str | None) -> list[Pair]:
        return list(self.data.pairs[(t.name, rname, i, st, sr or "")])

    def eval_expr(self, state: State, t: Type, node: Expr, defining: str | None = None) -> set[str]:
        """The ids of t for which the expression holds; defining: the permission it defines (what `roles` gives)."""
        match node:
            case Ref(name) if name == ROLES and defining is not None:
                return self.role_holders(state, t, defining)
            case Ref(name):
                return set(state[(t.name, name)])
            case Arrow(rel, perm):
                r = t.relations[rel]
                out: set[str] = set()
                for i, src in enumerate(r.sources):
                    for target, sr in src.subjects:
                        assert sr is None and target in self.types, FOLLOWS
                        held = state[(target, perm)]
                        out |= {o for o, s in self.pairs(t, r.name, i, target, None) if s in held}
                return out
            case Cond(sql) if sql == KEYWORDS["anyone"]:
                return self.ids(t)  # anyone at all, signed in or not
            case Cond(sql) if sql == KEYWORDS["nobody"]:
                return set()
            case Cond(sql) if sql == KEYWORDS["signed_in"]:
                # a user signed in (a service isn't: signed_in stays about users), on every row alike
                return self.ids(t) if self.principal is not None and self.principal[0] == "user" else set()
            case Cond(sql) if (t.name, sql) not in self.data.cond and t.name in self.data.columns:
                # a simple condition, on the row's column values (and who is signed in, for authz.uid())
                facts = simple(sql)
                if facts is None:
                    raise KeyError(f"no rows given for {{{sql}}} on {t.name}")
                rows = self.row_values(t)
                me = self.principal[1] if self.principal is not None and self.principal[0] == "user" else None
                return {i for i in self.ids(t) if truth(facts, rows.get(i, {}), me) is True}
            case Cond(sql):
                return set(self.data.cond[(t.name, sql)])
            case Not(item):
                return self.ids(t) - self.eval_expr(state, t, item, defining)
            case And(items):
                return set.intersection(*[self.eval_expr(state, t, x, defining) for x in items])
            case _:
                assert isinstance(node, Or), f"the reference evaluator doesn't evaluate {node!r}"
                return set.union(*[self.eval_expr(state, t, x, defining) for x in node.items])


# --- small worlds ----------------------------------------------------------------------------------
def source_key(t: Type, rname: str, src: Source, st: str, sr: str | None) -> tuple[object, ...]:
    """What a relation's source reads, whatever the relation is called: two policies that read the same
    column or link table see the same links in a world. Shares are kept by relation name, so theirs is too."""
    if src.kind == "column":
        return (t.name, "column", src.column, src.type_col, st, sr)
    if src.kind == "table":
        return (t.name, "table", src.table, src.obj_col, src.subj_col, src.where, src.type_col, st, sr)
    return (t.name, src.kind, rname, st, sr)


class Difference(TypedDict):
    """The first difference compare() found between two policies."""

    what: str  # 'type.perm', or 'rule schema.table command [columns]'
    user: str
    object: str
    before: bool  # whether the first policy grants it
    after: bool
    world: list[str]  # the world, as World.describe gives it
    worlds: int  # how many worlds were tried


def alike_in(pols: Iterable[Policy]) -> frozenset[str]:
    """The columns the policies' simple conditions compare with texts the column may hold as one value
    (conditions.alike_columns: 'a' and 'A' under a case-insensitive collation)."""
    conds: list[str] = []
    for p in pols:
        conds += [c for _, c in Reference(p).conditions()]
        for t in p.types.values():
            conds += [t.where] if t.where else []
            conds += [s.where for r in t.relations.values() for s in r.sources if s.kind == "table" and s.where]
    return alike_columns(node for c in dict.fromkeys(conds) if (node := simple(c)) is not None)


def facts(sql: str, alike: frozenset[str]) -> Node | None:
    """A condition as facts about its row's columns (conditions.simple), unless it compares a column of alike with a
    text: whether a row equal to one of its texts equals another is the column's collation's to say, so its rows are
    drawn as any other condition's are."""
    node = simple(sql)
    return None if node is None or reads_alike(node, alike) else node


def groups(nodes: list[tuple[Node, bool]]) -> list[list[tuple[Node, bool]]]:
    """Conditions in groups that read columns in common: a group's values are chosen together, apart from the
    others'."""
    out: list[tuple[set[str], list[tuple[Node, bool]]]] = []
    for item in nodes:
        cols, members = set(columns_of(item[0])), [item]
        for other in [g for g in out if g[0] & cols]:
            out.remove(other)
            cols |= other[0]
            members = other[1] + members
        out.append((cols, members))
    return [members for _, members in out]


class World:
    """Made-up data for one or more policies, the same for what they share: ids per type, the links each
    column, link table and share holds, the column values simple conditions read (conditions.py: `{archived}`
    and `{not archived}` read one column), and which rows pass each other {condition} (any yes or no per row,
    so policies that use the same condition text see the same answers).

    A drawn world has 1 to size rows of each type, a column names something on COLUMN of its rows, and a link
    table, a share or a role holds LINK (ROLE) of the links it could. Two kinds of world a draw rarely makes have
    size rows of each type: a dense one (density: a link table, share or role holds that much of what it could, and
    a column names something on nearly every row: a long `and` of links holds for someone), and one of chains
    (chained: each link the policies follow from an object to another, with a dot or to a group's members, goes
    from row i to row i + 1, so that it reaches as deep as the world is large)."""

    COLUMN, LINK, ROLE = 0.6, 0.3, 0.2

    def __init__(
        self,
        seed: str,
        size: int,
        conds: Mapping[str, bool] | None = None,
        pols: Sequence[Policy] = (),
        density: float | None = None,
        chained: bool = False,
    ) -> None:
        self.rng_seed, self.size = seed, size
        self.made: dict[tuple[object, ...], object] = {}
        # a corner: the conditions (by their text) that hold on every row, or on none, instead of being drawn
        self.conds = conds or {}
        # the policies that share the world: their simple conditions say which values each column takes
        self.pols = list(pols)
        self.density, self.chained = density, chained
        self._followed: dict[int, tuple[Policy, set[tuple[str, str]]]] = {}
        self._alike: dict[int, tuple[Policy, frozenset[str]]] = {}

    def facts(self, pol: Policy, sql: str) -> Node | None:
        """A condition as the world reads it from its rows' columns, or None when it draws the rows it holds for
        (evaluate.facts, over the world's policies and pol)."""
        if id(pol) not in self._alike or self._alike[id(pol)][0] is not pol:
            self._alike[id(pol)] = (pol, alike_in([*self.pols, pol]))
        return facts(sql, self._alike[id(pol)][1])

    def fill(self) -> float:
        """How many rows a column names something on."""
        return self.COLUMN if self.density is None else 0.95

    def followed(self, pol: Policy) -> set[tuple[str, str]]:
        """(type, relation) the world's policies follow from an object to another: with a dot (`parent.view`), or
        to the members of a group (`team#member`)."""
        if id(pol) not in self._followed or self._followed[id(pol)][0] is not pol:
            out: set[tuple[str, str]] = set()

            def walk(t: Type, node: Expr) -> None:
                out.update((t.name, leaf.rel) for leaf, _ in leaves(node) if isinstance(leaf, (Arrow, ArrowOn)))

            for p in [*self.pols, pol]:
                for t in p.types.values():
                    for perm in t.perms.values():
                        walk(t, perm.expr)
                    for r in t.relations.values():
                        if any(sr and sr != "*" and st in p.types for st, sr in r.subjects()):
                            out.add((t.name, r.name))
                governing: dict[str, Type] = {}  # a rule's table, its type's (AZ401: one type governs it)
                for t in p.types.values():
                    governing.setdefault(t.table, t)
                for rule in p.rules:
                    walk(governing[rule.table], rule.expr)
                for inv in p.invariants:
                    walk(p.types[inv.type], inv.expr)
            self._followed[id(pol)] = (pol, out)
        return self._followed[id(pol)][1]

    def chain(self, ids: list[str], targets: list[str]) -> list[Pair]:
        """Row i linked to row i + 1 of the type it names (the last one to none)."""
        return [(o, str(int(o) + 1)) for o in ids if str(int(o) + 1) in targets]

    def linked(self, pol: Policy) -> dict[tuple[str, str], tuple[str, str]]:
        """{(type, column): (the type it names, the relation)}: the columns a relation of one of the world's policies
        reads (`owner : user = owner_id`). A condition on one (`{owner_id = authz.uid()}`, `{parent_id is null}`)
        reads the relation's links: they are the same facts."""
        out: dict[tuple[str, str], tuple[str, str]] = {}
        for p in [*self.pols, pol]:
            for t in p.types.values():
                for r in t.relations.values():
                    for src in r.sources:
                        col = linked_column(src)
                        if col is not None:
                            out.setdefault((t.name, col), (src.subjects[0][0], r.name))
        return out

    def column_links(self, pol: Policy, tname: str, col: str, st: str, rname: str, ids: list[str]) -> list[Pair]:
        """The links a column holds, one per row at most: the same whatever reads them (its relation, or a simple
        condition on the column)."""
        targets = self.ids(st) if st in pol.types else ["1"]
        if self.chained and (tname, rname) in self.followed(pol):
            return self.chain(ids, targets)
        return self.pick(
            ("pairs", tname, "column", col, None, st, None),
            lambda rng: [(o, rng.choice(targets)) for o in ids if rng.random() < self.fill()],
        )

    def domains(self, pol: Policy) -> dict[tuple[str, str], list[Scalar]]:
        """{(type, column): the values it takes}: those the simple conditions of the world's policies compare it
        with, one none of them names, true and false for a column used alone, user ids for one compared with
        authz.uid(), and NULL."""
        hows: dict[tuple[str, str], list[tuple[str, Scalar]]] = {}
        for p in [*self.pols, pol]:
            conds = list(Reference(p).conditions()) + [(t.name, t.where) for t in p.types.values() if t.where]
            for tname, cond in conds:
                node = self.facts(pol, cond)
                if node is not None:
                    for col, how in columns_of(node).items():
                        hows.setdefault((tname, col), []).extend(how)
        return {key: self.values_of(used) for key, used in sorted(hows.items())}

    def values_of(self, used: list[tuple[str, Scalar]]) -> list[Scalar]:
        """The values a column takes, from how the simple conditions read it (columns_of's hows)."""
        values: list[Scalar] = []
        consts = [v for how, v in used if how not in ("bool", "uid", "null") and v is not None]
        if any(how == "bool" for how, _ in used) or any(isinstance(v, bool) for v in consts):
            values += [True, False]
        # (a number is an int or a Decimal; Decimal's 28 digits hold one of 15 and 2 more, exactly)
        for how, v in used:
            if how in ("<", "<=", ">", ">=") and isinstance(v, (int, Decimal)) and not isinstance(v, bool):
                values += [v - 1, v, v + 1]
            elif how not in ("bool", "uid", "null") and v is not None:
                values.append(v)
        if any(isinstance(v, str) for v in consts):
            values.append("(another)")
        numbers = [v for v in consts if isinstance(v, (int, Decimal)) and not isinstance(v, bool)]
        if numbers:
            values.append(max(numbers) + 2)
        if any(how == "uid" for how, _ in used):
            values += self.ids("user")
        if not values:
            values.append("x")  # only tested for NULL
        return [*dict.fromkeys(values), None]

    def link_domains(self, pol: Policy, table: str) -> dict[str, list[Scalar]]:
        """{column: the values it takes} for a link table's columns its simple wheres read, in any of the world's
        policies (as domains, for a type's columns)."""
        hows: dict[str, list[tuple[str, Scalar]]] = {}
        for p in [*self.pols, pol]:
            for t in p.types.values():
                for r in t.relations.values():
                    for src in r.sources:
                        read = src.kind == "table" and src.table == table and src.where
                        node = self.facts(pol, src.where) if read else None
                        if node is not None:
                            for col, how in columns_of(node).items():
                                hows.setdefault(col, []).extend(how)
        return {col: self.values_of(used) for col, used in sorted(hows.items())}

    def columns(self, pol: Policy) -> dict[str, dict[str, dict[str, Scalar]]]:
        """{type: {id: {column: value}}} for the columns the simple conditions read: drawn from the values the
        conditions name, or for a column a relation reads, the id its link names (the same draw as the link's)."""
        out: dict[str, dict[str, dict[str, Scalar]]] = {
            t.name: {i: {} for i in self.ids(t.name)} for t in pol.types.values()
        }
        linked = self.linked(pol)
        for (tname, col), values in self.domains(pol).items():
            if tname not in pol.types:
                continue
            ids = self.ids(tname)
            if (tname, col) in linked:
                st, rname = linked[(tname, col)]
                pairs = self.column_links(pol, tname, col, st, rname, ids)
                drawn: dict[str, Scalar] = {**dict.fromkeys(ids), **dict(pairs)}
            else:
                drawn = self.pick(
                    ("column", tname, col), lambda rng, ids=ids, vs=values: {i: rng.choice(vs) for i in ids}
                )
            for i in ids:
                out[tname][i][col] = drawn[i]
        self.corner_columns(pol, out)
        return out

    # a corner leaves drawn the values of columns its simple conditions read together (one reading two, another
    # reading one of those and a third...) when they have more than this many combinations of values
    CORNER_CHOICES = 4096

    def corner_columns(self, pol: Policy, out: dict[str, dict[str, dict[str, Scalar]]]) -> None:
        """In a corner, each row's values for the columns its type's simple conditions read: chosen so that as
        many of those conditions as can be say what the corner says. They are still read from the columns, so a
        condition and its opposite (`{archived}`, `{not archived}`) never both hold: the values decide. Conditions
        that share no column are chosen for apart. Not those that read who is signed in or a relation's column
        (those come from the links, the same facts as the relation). The conditions are those of every policy
        of the world: a column one reads beside another and its rewrite reads alone is chosen once, the same for
        both."""
        if not self.conds:
            return
        domains, linked = self.domains(pol), self.linked(pol)
        conds = [
            cond
            for p in [*self.pols, pol]
            for cond in [*Reference(p).conditions(), *((t.name, t.where) for t in p.types.values() if t.where)]
        ]
        wanted: dict[str, list[tuple[Node, bool]]] = {}
        for tname, cond in dict.fromkeys(conds):
            node = self.facts(pol, cond)
            if cond not in self.conds or tname not in pol.types or node is None or uses_uid(node):
                continue
            if not any((tname, col) in linked for col in columns_of(node)):
                wanted.setdefault(tname, []).append((node, self.conds[cond]))
        for tname, nodes in sorted(wanted.items(), key=lambda kv: kv[0]):
            for group in groups(nodes):
                cols = sorted({col for node, _ in group for col in columns_of(node)})
                combos = 1
                for col in cols:
                    combos *= len(domains[(tname, col)])
                if combos > self.CORNER_CHOICES:
                    continue

                def said(
                    values: tuple[Scalar, ...], cols: list[str] = cols, group: list[tuple[Node, bool]] = group
                ) -> int:
                    row = dict(zip(cols, values, strict=True))
                    return sum((truth(node, row, None) is True) == want for node, want in group)

                choices = list(itertools.product(*[domains[(tname, col)] for col in cols]))
                most = max(said(v) for v in choices)
                best = [v for v in choices if said(v) == most]
                for i in out[tname]:
                    values = self.pick(("corner", tname, i, *cols), lambda rng, best=best: rng.choice(best))
                    out[tname][i].update(zip(cols, values, strict=True))

    def pick(self, key: tuple[object, ...], make: Callable[[random.Random], V]) -> V:
        """What make gives for key, made once per world from the world's seed and the key."""
        if key not in self.made:
            rng = random.Random(f"{self.rng_seed}/{key!r}")
            self.made[key] = make(rng)
        return cast(V, self.made[key])  # what make gave for this key

    def ids(self, tname: str) -> list[str]:
        if self.density is not None or self.chained:  # as many rows as the world is large
            return [str(i) for i in range(1, self.size + 1)]
        return self.pick(("ids", tname), lambda rng: [str(i) for i in range(1, rng.randint(1, self.size) + 1)])

    def subset(self, key: tuple[object, ...], ids: list[str], p: float = 0.5) -> list[str]:
        return self.pick(key, lambda rng: [i for i in ids if rng.random() < p])

    def holds(self, tname: str, cond: str, ids: list[str], p: float = 0.5) -> list[str]:
        """The rows a {condition} (or a type's where) holds for: drawn row by row, unless this world is a corner."""
        if cond in self.conds:
            return list(ids) if self.conds[cond] else []
        return self.subset(("cond", tname, cond), ids, p)

    def data(self, pol: Policy) -> Data:
        """The evaluator's data for a policy, drawn from this world."""
        out = Data()
        out.columns = self.columns(pol)
        for t in pol.types.values():
            ids = self.ids(t.name)
            out.ids[t.name] = ids
            # the where is a condition like any other: the same text gives the same rows in a rule or a permission
            where = self.facts(pol, t.where) if t.where else None
            if t.where and where is not None and not uses_uid(where):
                out.valid[t.name] = [i for i in ids if truth(where, out.columns[t.name][i], None) is True]
            else:
                out.valid[t.name] = self.holds(t.name, t.where, ids, 0.85) if t.where else ids
            for r in t.relations.values():
                for i, src in enumerate(r.sources):
                    for st, sr in src.subjects:
                        out.pairs[(t.name, r.name, i, st, sr or "")] = self.links(pol, t, r, src, ids, st, sr)
            if t.roles:
                subjects, perms, _ = t.roles
                # with `from rel`, each assignment's role belongs to an object of rel's type (maybe not this one's)
                owner_type = role_owner_type(t)
                owner_ids = self.ids(owner_type) if owner_type in pol.types else [""]
                rate = self.ROLE if self.density is None else self.density
                for p in perms:
                    for st, sr in subjects:
                        sids = ["*"] if sr == "*" else self.ids(st) if st in pol.types else ["1"]
                        out.rolepairs[(t.name, p, st, sr or "")] = self.pick(
                            ("roles", t.name, p, st, sr, owner_type),
                            lambda rng, ids=ids, s=sids, w=owner_ids, rate=rate: [
                                (o, x, rng.choice(w)) for o in ids for x in s if rng.random() < rate
                            ],
                        )
        ref = Reference(pol)
        for tname, cond in ref.conditions():
            # signed_in, anyone and nobody mean the same in every world (Reference.eval_expr): nothing to draw;
            # a simple condition reads the row's columns
            if cond in KEYWORDS.values():
                out.cond[(tname, cond)] = []
            elif self.facts(pol, cond) is None:
                out.cond[(tname, cond)] = self.holds(tname, cond, self.ids(tname))
        return out

    def links(
        self, pol: Policy, t: Type, r: Relation, src: Source, ids: list[str], st: str, sr: str | None
    ) -> list[Pair]:
        """The links one source holds for subjects st#sr: at most one per row in a column."""
        # to user:* (or anyone) a link names no one row: its subject is '*', as authz.shares holds it
        subject_ids = (
            ["*"]
            if st == "anyone" or sr == "*"
            else ["tok1", "tok2"]
            if st == "link"
            else self.ids(st)
            if st in pol.types
            else ["1"]
        )
        key = ("pairs", *source_key(t, r.name, src, st, sr))
        chained = self.chained and subject_ids != ["*"] and st in pol.types and (t.name, r.name) in self.followed(pol)
        if src.kind == "column" and src.type_col:
            # (type_col, id_col): a row names one object of one type at most, whatever the types
            types = [x for x, _ in src.subjects if x in pol.types]
            rows = self.pick(
                ("poly", t.name, src.column, src.type_col),
                lambda rng: (
                    # in a chain, every row names the next one of one type: the world's choice
                    [(o, x, str(int(o) + 1)) for x in [rng.choice(types)] for o in ids]
                    if chained
                    else [
                        (o, x, rng.choice(self.ids(x)))
                        for o in ids
                        if rng.random() < self.fill()
                        for x in [rng.choice(types)]
                    ]
                ),
            )
            return [(o, s) for o, x, s in rows if x == st and s in subject_ids]
        col = linked_column(src)
        if col is not None:
            return self.column_links(pol, t.name, col, st, r.name, ids)
        if chained:
            return self.chain(ids, subject_ids)
        if src.kind == "column":
            return self.pick(key, lambda rng: [(o, rng.choice(subject_ids)) for o in ids if rng.random() < self.fill()])
        rate = self.LINK if self.density is None else self.density
        if src.kind == "table" and src.where:
            # the table's rows are the same whatever its where says, and the where holds for some of them: a policy
            # that adds a where to a link table reads fewer of the same rows, never other ones
            bare = ("pairs", *source_key(t, r.name, dataclasses.replace(src, where=None), st, sr))
            rows = self.pick(bare, lambda rng: [(o, x) for o in ids for x in subject_ids if rng.random() < rate])
            if src.where in self.conds:
                return list(rows) if self.conds[src.where] else []
            node = self.facts(pol, src.where)
            if node is None or uses_uid(node):
                return self.pick((*key, "holds"), lambda rng: [row for row in rows if rng.random() < 0.5])
            # a simple where reads the row's columns, drawn once a row for every policy: `{active}` and
            # `{active and not banned}` read the same values, so the second never holds where the first doesn't
            domains = self.link_domains(pol, src.table or "")
            values = {
                col: self.pick((*bare, col), lambda rng, vs=domains[col]: {row: rng.choice(vs) for row in rows})
                for col in columns_of(node)
            }
            return [row for row in rows if truth(node, {c: v.get(row) for c, v in values.items()}, None) is True]
        return self.pick(key, lambda rng: [(o, x) for o in ids for x in subject_ids if rng.random() < rate])

    def principals(self, pols: Iterable[Policy]) -> list[str]:
        """Who to ask as: every id of every type that signs in, in any of the policies, and nobody."""
        out: list[str] = []
        for tname in sorted({t.name for pol in pols for t in pol.types.values() if t.principal}):
            out += [i if tname == "user" else f"{tname}:{i}" for i in self.ids(tname)]
        return [*out, ""]

    @staticmethod
    def principals_in(pol: Policy, data: Data) -> list[str]:
        """Who to ask as in a world's data: every id of every type that signs in, and nobody ('')."""
        out: list[str] = []
        for t in pol.types.values():
            if t.principal:
                out += [i if t.name == "user" else f"{t.name}:{i}" for i in data.ids[t.name]]
        return [*out, ""]

    @staticmethod
    def named(pol: Policy, data: Data) -> set[str]:
        """The types whose rows the world says something of: those its links, custom roles, conditions and columns
        name (a smaller world names fewer)."""
        out: set[str] = set()
        for (tname, _, _, st, _), pairs in data.pairs.items():
            out |= {tname, st} if pairs else set()
        for (tname, _, st, _), roles in data.rolepairs.items():
            owner = role_owner_type(pol.types[tname])
            out |= {tname, st, *([owner] if owner else [])} if roles else set()
        out |= {tname for (tname, _), ids in data.cond.items() if ids}
        out |= {
            tname
            for tname, rows in data.columns.items()
            if any(v is not None for r in rows.values() for v in r.values())
        }
        return out & set(pol.types)

    def describe(self, pol: Policy, data: Data, types: Collection[str] | None = None) -> list[str]:
        """The world, as lines a reviewer can read: the rows of each type (with types, of those alone), the columns
        the simple conditions read, the rows each type's where keeps, those each other condition holds for, every
        link and every custom role given."""
        shown_types = [t for t in pol.types.values() if types is None or t.name in types]
        lines = [f"{t.name}: {', '.join(data.ids[t.name])}" for t in shown_types]
        # the columns simple conditions read (not NULL; a relation's column is its link, below)
        linked = {
            (t.name, linked_column(src)) for t in pol.types.values() for r in t.relations.values() for src in r.sources
        }
        for tname, rows in sorted(data.columns.items()):
            for i, values in rows.items() if types is None or tname in types else ():
                said = [(c, v) for c, v in sorted(values.items()) if v is not None and (tname, c) not in linked]
                if said:
                    lines.append(f"{tname} {i}: " + ", ".join(f"{c} = {shown(v)}" for c, v in said))
        # a row its type's where doesn't keep holds nothing and gives nothing: which rows it keeps, said
        for t in shown_types:
            if t.where:
                kept = data.valid[t.name]
                rows = f"{t.name} {', '.join(kept)}" if kept else f"no {t.name}"
                lines.append(f"{{{t.where}}} holds for {rows} (the type's where)")
        for (tname, cond), ids in sorted(data.cond.items(), key=lambda kv: repr(kv[0])):
            if ids:
                lines.append(f"{{{cond}}} holds for {tname} {', '.join(ids)}")
        for (tname, rname, _, st, sr), pairs in sorted(data.pairs.items(), key=lambda kv: repr(kv[0])):
            if pairs:
                lines.append(f"{tname}.{rname}: " + ", ".join(f"{tname} {o} -> {subject(st, sr, s)}" for o, s in pairs))
        for (tname, perm, st, sr), roles in sorted(data.rolepairs.items(), key=lambda kv: repr(kv[0])):
            if roles:
                owner = role_owner_type(pol.types[tname])
                lines.append(
                    f"{tname}.roles with {perm}: "
                    + ", ".join(
                        f"{tname} {o} -> {subject(st, sr, s)}" + (f" (a role of {owner} {w})" if owner else "")
                        for o, s, w in roles
                    )
                )
        return lines


def subject(st: str, sr: str | None, s: str) -> str:
    """A link's subject as the policy writes it: `user 2`, `team#member 1`, `user:*`, `anyone`, `link tok1`."""
    if sr == "*":
        return f"{st}:*"
    if st == "anyone":
        return st
    return f"{st}#{sr} {s}" if sr else f"{st} {s}"


def shown(v: str | int | Decimal | bool) -> str:
    """A column's value as SQL writes it (describe leaves NULL out: a smaller world's columns are NULL)."""
    if isinstance(v, bool):
        return "true" if v else "false"
    return f"'{v}'" if isinstance(v, str) else str(v)


def kept_rows(pol: Policy, alike: frozenset[str] = frozenset()) -> Callable[[Data], Data]:
    """What makes data whole again once a link or a column's value is taken away: the rows each type's where keeps,
    read again from the columns and links, where the evaluator reads that where itself (as World.data does; alike:
    the world's, World.facts). A row whose where needs a value then keeps it in a smaller world."""
    ref = Reference(pol)
    wheres: dict[str, Node] = {}
    for t in pol.types.values():
        node = facts(t.where, alike) if t.where else None
        if node is not None and not uses_uid(node):
            wheres[t.name] = node

    def whole(data: Data) -> Data:
        ref.data = data
        valid = {
            tname: [
                i for i in data.ids[tname] if truth(node, ref.row_values(pol.types[tname]).get(i, {}), None) is True
            ]
            for tname, node in wheres.items()
        }
        return dataclasses.replace(data, valid={**data.valid, **valid})

    return whole


def smallest(data: Data, still: Callable[[Data], bool], whole: Callable[[Data], Data] | None = None) -> Data:
    """The data with every link, role and condition row taken away, and every column value made NULL, that
    `still` doesn't need; whole (kept_rows) makes each smaller data whole again before `still` is asked."""
    return smallest_of([data], lambda ds: still(ds[0]), [whole] if whole else [])[0]


def smallest_of(
    datas: list[Data], still: Callable[[list[Data]], bool], whole: Sequence[Callable[[Data], Data]] = ()
) -> list[Data]:
    """smallest() for one world as several policies read it (each its data, made whole by its whole): a link, a
    role, a condition's row or a column's value is taken from all of them at once."""

    def made(ds: list[Data]) -> list[Data]:
        return [f(d) for f, d in zip(whole, ds, strict=True)] if whole else ds

    def without(entries: Callable[[Data], dict[K, list[V]]], put: Callable[[Data, dict[K, list[V]]], Data]) -> bool:
        """Each entry's items taken away one at a time, in key order, where `still` holds without it."""
        nonlocal datas
        changed = False
        for key in sorted({k for d in datas for k in entries(d)}, key=repr):
            for item in list(dict.fromkeys(x for d in datas for x in entries(d).get(key, []))):
                trial = made(
                    [
                        put(d, {**entries(d), key: [x for x in entries(d)[key] if x != item]})
                        if key in entries(d)
                        else d
                        for d in datas
                    ]
                )
                if still(trial):
                    datas, changed = trial, True
        return changed

    def nulled(cell: tuple[str, str, str]) -> list[Data]:
        tname, i, col = cell
        out = []
        for d in datas:
            if col in d.columns.get(tname, {}).get(i, {}):
                columns = {t: {k: dict(v) for k, v in rows.items()} for t, rows in d.columns.items()}
                columns[tname][i][col] = None
                d = dataclasses.replace(d, columns=columns)
            out.append(d)
        return made(out)

    changed = True
    while changed:
        # each trial is the data as it is now, one entry changed
        a = without(lambda d: d.cond, lambda d, e: dataclasses.replace(d, cond=e))
        b = without(lambda d: d.pairs, lambda d, e: dataclasses.replace(d, pairs=e))
        c = without(lambda d: d.rolepairs, lambda d, e: dataclasses.replace(d, rolepairs=e))
        d = False
        cells = {(t, i, col) for x in datas for t, rows in x.columns.items() for i, r in rows.items() for col in r}
        for cell in sorted(cells):
            if all(x.columns.get(cell[0], {}).get(cell[1], {}).get(cell[2]) is None for x in datas):
                continue
            trial = nulled(cell)
            if still(trial):
                datas, d = trial, True
        changed = a or b or c or d
    return datas


def corners(pols: Iterable[Policy]) -> list[dict[str, bool]]:
    """Worlds a row-by-row draw rarely makes: which conditions hold everywhere and which nowhere. A change behind
    `{a} and {b} and ... and {h}` shows only where all eight hold, one row in 256 when each is a coin toss. The
    corners: every condition written plainly holds and every one under a `not` doesn't (the most anyone can
    hold); the other way round; every condition holds. A type's where holds in all three (or nothing would)."""
    plain: set[str] = set()
    denied: set[str] = set()
    wheres: set[str] = set()

    def walk(node: Expr) -> None:
        for leaf, nots in leaves(node):
            if isinstance(leaf, Cond):
                (denied if nots % 2 else plain).add(leaf.sql)

    for pol in pols:
        for t in pol.types.values():
            if t.where:
                wheres.add(t.where)
            for p in t.perms.values():
                walk(p.expr)
        for rule in pol.rules:
            walk(rule.expr)
        for inv in pol.invariants:
            walk(inv.expr)
    every = plain | denied | wheres
    if not every:
        return []
    most = {c: c in plain or c in wheres for c in every}
    least = {c: c in wheres or (c in denied and c not in plain) for c in every}
    return [most, least, dict.fromkeys(every, True)]


def reach(pols: Iterable[Policy]) -> int:
    """How deep the policies read: the most links from an object to another (a dot, or a group's members) that one
    of their permissions, rules or invariants follows one after the other, a loop gone round once."""

    out = 0
    for pol in pols:
        known: dict[Name, int] = {}  # each name's depth, once worked out
        walking: set[Name] = set()  # the names being worked out: one met again closes a loop, which counts 0 more

        def deep(
            t: Type, name: str, pol: Policy = pol, known: dict[Name, int] = known, walking: set[Name] = walking
        ) -> int:
            key = (t.name, name)
            if key not in known and key not in walking:
                walking.add(key)
                if name in t.perms:
                    known[key] = depth(t, t.perms[name].expr)
                elif name in t.relations:  # a group's members: the group's own relation, one link further
                    subjects = t.relations[name].subjects()
                    groups = [(st, sr) for st, sr in subjects if sr and sr != "*" and st in pol.types]
                    known[key] = max((1 + deep(pol.types[st], sr) for st, sr in groups), default=0)
                else:
                    known[key] = 0
                walking.discard(key)
            return known.get(key, 0)

        def depth(t: Type, node: Expr, pol: Policy = pol) -> int:
            return max(leaf_depth(t, leaf, pol) for leaf, _ in leaves(node))

        def leaf_depth(t: Type, leaf: Leaf, pol: Policy = pol) -> int:
            match leaf:
                case Ref(name):
                    return deep(t, name)
                case Arrow(rel, perm) | ArrowOn(rel, perm, _) if rel in t.relations:
                    targets = [st for st, sr in t.relations[rel].subjects() if sr is None and st in pol.types]
                    return max((1 + deep(pol.types[st], perm) for st in targets), default=1)
            return 0

        for t in pol.types.values():
            out = max([out, *(deep(t, p) for p in t.perms)])
        governing: dict[str, Type] = {}  # a rule's table, its type's (AZ401: one type governs it)
        for x in pol.types.values():
            governing.setdefault(x.table, x)
        for rule in pol.rules:
            out = max(out, depth(governing[rule.table], rule.expr))
        for inv in pol.invariants:
            out = max(out, depth(pol.types[inv.type], inv.expr))
    return out


# a dense world holds half of the links it could, three quarters or nearly all: a long `and` of links (with a `not` or
# an `or` among them) holds for someone in a few of them, where a drawn world (LINK) has it one time in hundreds
DENSITIES = (0.5, 0.75, 0.9)
LONGEST = 10  # the longest chain of objects a world of chains has


def dense_worlds(worlds: int) -> int:
    """How many dense worlds go with this many drawn ones."""
    return max(8, worlds // 5)


def rare_worlds(pols: Sequence[Policy], worlds: int, seed: str) -> Iterable[World]:
    """Worlds a draw rarely makes, tried after the drawn ones and the corners: dense ones, of 3 and 4 rows of each
    type, and, when the policies read 2 links deep or more (reach), a dozen chains one link longer than the deepest
    they read (half of them dense too): a permission that follows 3 links and one that follows 4 differ only at the
    end of a chain of 5."""
    for k in range(dense_worlds(worlds)):
        yield World(f"{seed}/dense/{k}", 3 + k % 2, pols=pols, density=DENSITIES[k // 2 % len(DENSITIES)])
    deep = reach(pols)
    if deep >= 2:
        for k in range(12):
            density = None if k % 2 == 0 else DENSITIES[0]
            yield World(f"{seed}/chain/{k}", min(deep + 2, LONGEST), pols=pols, density=density, chained=True)


# --- every small world, listed ----------------------------------------------------------------------
# A draw rarely makes a world where many conditions each say one thing on one row (a change behind a long `and`), nor
# two linked rows on which one condition says one thing and another the other. So beside the drawn worlds, those of a
# few rows that two policies may be told apart in are listed, every one of them, the smallest first (Listing).
MOST_ROWS = 3  # the rows of one type a listed world has at most
LISTED = 15  # the listed worlds a comparison tries for each drawn one it asks for (the review's 200: 3,000), once ...
ALWAYS = 1  # ... it has tried every world with at most this many links, however many they are
CLASS_CHOICES = 4096  # the values a group of columns read together may take, for its classes to be listed whole
STEPS = 100_000  # the steps of looking for links a listing takes at most


class RowClass(NamedTuple):
    """What the conditions read of a type say of one of its rows: the values of the columns its simple conditions
    read (one choice of them for each different answer the conditions give), and the other conditions (and a `where`
    the evaluator doesn't read as a fact about the row) that hold on it."""

    columns: tuple[tuple[str, Scalar], ...]
    holds: frozenset[str]


Link: TypeAlias = "tuple[tuple[object, ...], str, str]"  # (what the source reads: source_key, the object, the subject)


class Candidate(NamedTuple):
    link: Link
    subject_type: str | None  # the type of the subject's row, if it is one
    column: tuple[object, ...] | None  # a column source: the column, which names one subject a row at most
    source: str  # the source, as text (to order links by)


class Cone(NamedTuple):
    """What a world needs to tell two policies apart: the types, conditions and relations the permissions and rules
    they define differently read, themselves or through what they name."""

    types: set[str]
    conds: set[CondKey]
    relations: set[tuple[str, str]]


def shape(pol: Policy) -> dict[str, object]:
    """A policy's types and relations, as the worlds see them (what each source reads; not where it is written)."""
    return {
        t.name: (
            t.table,
            t.where,
            t.principal,
            t.roles,
            t.roles_from,
            {
                r.name: [(source_key(t, r.name, s, st, sr), s.kind) for s in r.sources for st, sr in s.subjects]
                for r in t.relations.values()
            },
        )
        for t in pol.types.values()
    }


def cone(pols: Sequence[Policy]) -> Cone | None:
    """What the permissions and rules two policies define differently read (Cone). None when they differ in more
    than permissions and rules, or are more or fewer than two: a world may then tell them apart anywhere."""
    if len(pols) != 2 or shape(pols[0]) != shape(pols[1]):
        return None
    a, b = pols
    start: list[tuple[Policy, Type, Expr]] = []
    for t in a.types.values():
        tb = b.types[t.name]
        for name in sorted(set(t.perms) | set(tb.perms)):
            pa, pb = t.perms.get(name), tb.perms.get(name)
            if pa is None or pb is None or pa.expr != pb.expr:
                start += [
                    (p, p.types[t.name], p.types[t.name].perms[name].expr)
                    for p in pols
                    if name in p.types[t.name].perms
                ]
    for p, other in ((a, b), (b, a)):
        governing: dict[str, Type] = {}
        for t in p.types.values():
            governing.setdefault(t.table, t)
        theirs = {(r.table, r.command, r.columns): r.expr for r in other.rules}
        for r in p.rules:
            if theirs.get((r.table, r.command, r.columns)) != r.expr:
                start.append((p, governing[r.table], r.expr))
    out = Cone(set(), set(), set())
    seen: set[tuple[int, str, str]] = set()

    def visit(p: Policy, t: Type, name: str) -> None:
        if (id(p), t.name, name) in seen:
            return
        seen.add((id(p), t.name, name))
        out.types.add(t.name)
        if name in t.perms:
            walk(p, t, t.perms[name].expr)
            return
        # a relation (a name the policy reads is one or the other: AZ201)
        out.relations.add((t.name, name))
        for st, sr in t.relations[name].subjects():
            if st in p.types:
                out.types.add(st)
                if sr and sr != "*":
                    visit(p, p.types[st], sr)

    def walk(p: Policy, t: Type, node: Expr) -> None:
        out.types.add(t.name)
        for leaf, _ in leaves(node):
            match leaf:
                case Cond(sql):
                    out.conds.add((t.name, sql))
                case Ref(name) if name == ROLES:
                    pass  # custom roles: the drawn worlds hold them, not the listed ones
                case Ref(name):
                    visit(p, t, name)
                case _:  # an arrow: Arrow or ArrowOn, the leaves left
                    visit(p, t, leaf.rel)
                    for st, _ in t.relations[leaf.rel].subjects():
                        assert st in p.types, FOLLOWS
                        visit(p, p.types[st], leaf.perm)

    for p, t, expr in start:
        walk(p, t, expr)
    out.types.update(t.name for p in pols for t in p.types.values() if t.principal)  # (who asks)
    return out


def counts_up_to(n: int, total: int) -> Iterator[tuple[int, ...]]:
    """Every n counts of rows, each MOST_ROWS at most, whose sum is total at most, in order: those of
    itertools.product(range(MOST_ROWS + 1), repeat=n) that are, without going through the others."""
    if n == 0:
        yield ()
        return
    for first in range(min(MOST_ROWS, total) + 1):
        for rest in counts_up_to(n - 1, total - first):
            yield (first, *rest)


class Listing:
    """Every world of up to MOST_ROWS rows of each type that policies may be told apart in, the smallest first:
    those with no link, then those with one, then two, and so on. A world holds the rows its links name, numbered
    from 1 (one row of a type no link names); each row is of every class its type's conditions make (RowClass), but
    for a type no link names and nobody signs in as, whose row is of each class in turn (alone, its row's answers
    depend on nothing else). Only what the permissions and rules the policies define differently read (cone) varies.
    Two worlds that are one with rows renamed are listed once.

    As worlds() goes: listed, how many it gave; whole, the most links of the worlds it gave every one of (-1: not
    all of those with none); cut, a group of columns had more values than CLASS_CHOICES (a world's columns didn't
    take them all)."""

    def __init__(self, pols: Sequence[Policy]) -> None:
        self.pols = list(pols)
        self.types: dict[str, Type] = {}
        for p in self.pols:
            for t in p.types.values():
                self.types.setdefault(t.name, t)
        self.listed, self.whole, self.cut, self.steps, self.complete = 0, -1, False, 0, False
        self._renamings: dict[tuple[tuple[str, int], ...], list[dict[str, dict[str, str]]]] = {}
        self._conditions: dict[int, tuple[Policy, list[CondKey]]] = {}
        found = cone(self.pols)
        if found is None:
            every = {(t.name, r) for t in self.types.values() for r in t.relations}
            conds = {c for p in self.pols for c in Reference(p).conditions()}
            found = Cone(set(self.types), conds, every)
        self.cone = found
        # a simple condition on a column a relation reads reads its links (Reference.row_values): they vary too
        linked: dict[tuple[str, str], str] = {}
        for t in self.types.values():
            for r in t.relations.values():
                for src in r.sources:
                    col = linked_column(src)
                    if col is not None:
                        linked.setdefault((t.name, col), r.name)
        self.linked = linked
        self.alike = alike_in(self.pols)
        for tname, cond in found.conds:
            node = facts(cond, self.alike)
            if node is not None:
                found.relations.update((tname, linked[(tname, c)]) for c in columns_of(node) if (tname, c) in linked)
        domains = World("listing", MOST_ROWS, pols=self.pols, density=0.5).domains(self.pols[0])
        self.classes = {t.name: self.classes_of(t, domains) for t in self.types.values()}
        self.candidates = self.links_of()

    def classes_of(self, t: Type, domains: dict[tuple[str, str], list[Scalar]]) -> list[RowClass]:
        """The classes of t's rows: every different answer of the conditions the cone reads of t (or of its where
        alone, outside it)."""
        conds = {c for tn, c in self.cone.conds if tn == t.name} if t.name in self.cone.types else set()
        if t.where:
            conds.add(t.where)
        plain: list[tuple[Node, bool]] = []
        opaque: list[str] = []
        for c in sorted(conds):
            node = facts(c, self.alike)
            if c in KEYWORDS.values():
                continue
            if node is None or (c == t.where and uses_uid(node)):
                opaque.append(c)
            elif not any((t.name, col) in self.linked for col in columns_of(node)):
                plain.append((node, True))
        users = [str(i) for i in range(1, MOST_ROWS + 1)]
        parts: list[list[tuple[tuple[str, Scalar], ...]]] = []
        for group in groups(plain):
            cols = sorted({col for node, _ in group for col in columns_of(node)})
            uids: list[str | None] = [*users, None] if any(uses_uid(node) for node, _ in group) else [None]
            choices = itertools.product(*[domains.get((t.name, col), [None]) for col in cols])
            total = 1
            for col in cols:
                total *= len(domains.get((t.name, col), [None]))
            if total > CLASS_CHOICES:
                self.cut = True
                choices = itertools.islice(choices, CLASS_CHOICES)
            answers: dict[tuple[bool, ...], tuple[tuple[str, Scalar], ...]] = {}
            for values in choices:
                row = dict(zip(cols, values, strict=True))
                said = tuple(truth(node, row, uid) is True for node, _ in group for uid in uids)
                answers.setdefault(said, tuple(row.items()))
            parts.append(list(answers.values()))
        out: list[RowClass] = []
        for columns in itertools.product(*parts):
            for holds in itertools.product((True, False), repeat=len(opaque)):
                out.append(
                    RowClass(
                        tuple(kv for part in columns for kv in part),
                        frozenset(c for c, h in zip(opaque, holds, strict=True) if h),
                    )
                )
        return out

    def links_of(self) -> list[Candidate]:
        """Each link a world may hold: of each source the cone reads, from each row to each subject it may name
        (a row of the subject's type; `*` for anyone or type:*; a share link's first token), between low rows
        first."""
        rows = [str(i) for i in range(1, MOST_ROWS + 1)]
        out: list[Candidate] = []
        seen: set[tuple[object, ...]] = set()
        for p in self.pols:
            for t in p.types.values():
                for r in t.relations.values():
                    if (t.name, r.name) not in self.cone.relations:
                        continue
                    # (a relation the compiler makes for custom roles is never read by name: the cone has none)
                    for src in r.sources:
                        for st, sr in src.subjects:
                            key = source_key(t, r.name, src, st, sr)
                            if key in seen:
                                continue
                            seen.add(key)
                            column = (t.name, src.column, src.type_col) if src.kind == "column" else None
                            if st == "anyone" or sr == "*":
                                subjects, stype = ["*"], None
                            elif st == "link":
                                subjects, stype = ["tok1"], None
                            else:
                                assert st in self.types, FOLLOWS  # (no subject of no type: AZ201)
                                subjects, stype = rows, st
                            out += [Candidate((key, o, s), stype, column, repr(key)) for o in rows for s in subjects]

        def low(c: Candidate) -> tuple[int, int]:
            (_, o, s) = c.link
            n = int(s) if c.subject_type else 1
            return (max(int(o), n), int(o) + n)

        return sorted(out, key=low)

    def spent(self) -> bool:
        """Whether the steps of looking for links are spent (never before every world with ALWAYS links is listed)."""
        return self.steps > STEPS and self.whole >= ALWAYS

    def said(self) -> str:
        """What was listed, in words: '1,105 listed: every one of up to 3 rows of each type with at most 2 links',
        and where columns read together had more combinations of values than CLASS_CHOICES, that only those were
        tried."""
        most = "" if self.complete else f" with at most {self.whole} link" + ("" if self.whole == 1 else "s")
        cut = (
            f"; of columns read together, only the first {CLASS_CHOICES:,} combinations of their values"
            if self.cut
            else ""
        )
        return f"{self.listed:,} listed: every one of up to {MOST_ROWS} rows of each type{most}{cut}"

    def conditions(self, pol: Policy) -> list[CondKey]:
        if id(pol) not in self._conditions or self._conditions[id(pol)][0] is not pol:
            self._conditions[id(pol)] = (pol, Reference(pol).conditions())
        return self._conditions[id(pol)][1]

    def worlds(self) -> Iterator[Listed]:
        """The listed worlds, those with fewer links first, and of those, fewer rows first; up to STEPS steps of
        looking for links."""
        types = sorted(self.types)
        # only the rows of a type some link may name vary: no link names a row of another type, so it has none
        named_types = sorted({t for c in self.candidates for t, _ in self.ends(c)})
        for k in range(len(self.candidates) + 1):
            # the rows of each type the links name (0: none, a row of its own); each link names two at most
            for v in sorted(counts_up_to(len(named_types), 2 * k), key=sum):
                if k > 0 and not any(v):
                    continue
                said = dict(zip(named_types, v, strict=True))
                rows = {t: said.get(t, 0) for t in types}
                named = self.named(rows)
                cands = [c for c in self.candidates if self.ends(c) <= named]
                for combo in self.covering(cands, k, named):
                    autos = self.automorphisms(rows, combo)
                    if autos is None:
                        continue  # (listed as the world it is renamed)
                    for w in self.classed(rows, combo, autos):
                        self.listed += 1
                        yield w
                if self.spent():
                    return  # (this level isn't whole)
            self.whole = k
        self.complete = True

    @staticmethod
    def named(rows: dict[str, int]) -> frozenset[tuple[str, str]]:
        """The rows the links of a world with these counts name."""
        return frozenset((t, str(i)) for t, m in rows.items() for i in range(1, m + 1))

    @staticmethod
    def ends(c: Candidate) -> frozenset[tuple[str, str]]:
        """The rows a link names: its object's, and its subject's when that is a row."""
        (key, o, s) = c.link
        return frozenset({(str(key[0]), o), *([(c.subject_type, s)] if c.subject_type else [])})

    def covering(
        self, cands: list[Candidate], k: int, rows: frozenset[tuple[str, str]]
    ) -> Iterator[tuple[Candidate, ...]]:
        """Every k of the links that name every one of these rows between them, a column naming one subject a
        row."""

        def go(
            start: int, picked: tuple[Candidate, ...], named: frozenset[tuple[str, str]], cols: frozenset[object]
        ) -> Iterator[tuple[Candidate, ...]]:
            self.steps += 1
            left = k - len(picked)
            if left == 0:
                if named == rows:
                    yield picked
                return
            if len(rows - named) > 2 * left or self.spent():
                return
            for i in range(start, len(cands) - left + 1):
                c = cands[i]
                col = (c.column, c.link[1]) if c.column is not None else None
                if col is not None and col in cols:
                    continue
                more = cols | {col} if col is not None else cols
                yield from go(i + 1, (*picked, c), named | self.ends(c), more)

        yield from go(0, (), frozenset(), frozenset())

    def renamings(self, rows: dict[str, int]) -> list[dict[str, dict[str, str]]]:
        """Every renaming of the rows of each type a link names (more than one of them), but the one that keeps
        them all."""
        many = tuple((t, m) for t, m in sorted(rows.items()) if m > 1)
        if many not in self._renamings:
            out = []
            for perms in itertools.product(*[list(itertools.permutations(range(1, m + 1))) for _, m in many]):
                ren = {
                    t: {str(i): str(j) for i, j in enumerate(perm, 1)} for (t, _), perm in zip(many, perms, strict=True)
                }
                if any(a != b for r in ren.values() for a, b in r.items()):
                    out.append(ren)
            self._renamings[many] = out
        return self._renamings[many]

    @staticmethod
    def renamed(combo: Sequence[Candidate], ren: dict[str, dict[str, str]]) -> tuple[tuple[str, str, str], ...]:
        out = []
        for c in combo:
            (key, o, s) = c.link
            t = str(key[0])
            o2 = ren.get(t, {}).get(o, o)
            s2 = ren.get(c.subject_type, {}).get(s, s) if c.subject_type else s
            out.append((c.source, o2, s2))
        return tuple(sorted(out))

    def automorphisms(self, rows: dict[str, int], combo: Sequence[Candidate]) -> list[dict[str, dict[str, str]]] | None:
        """The renamings that leave the links as they are; None if another renaming gives links that come first
        (the same world is listed as that one)."""
        mine = self.renamed(combo, {})
        same: list[dict[str, dict[str, str]]] = []
        for ren in self.renamings(rows):
            theirs = self.renamed(combo, ren)
            if theirs < mine:
                return None
            if theirs == mine:
                same.append(ren)
        return same

    def classed(
        self, rows: dict[str, int], combo: Sequence[Candidate], autos: list[dict[str, dict[str, str]]]
    ) -> Iterator[Listed]:
        """The worlds of these links: every class of each row (each class in turn, for the row of a type no link
        names and nobody signs in as), each once up to the renamings that keep the links."""
        varied = [
            (t, str(i)) for t, m in rows.items() for i in range(1, max(m, 1) + 1) if m > 0 or self.types[t].principal
        ]
        alone = [t for t, m in rows.items() if m == 0 and not self.types[t].principal]
        turns = max([len(self.classes[t]) for t in alone], default=1)
        links = [c.link for c in combo]
        place = {row: k for k, row in enumerate(varied)}
        for choice in itertools.product(*[range(len(self.classes[t])) for t, _ in varied]):
            if any(tuple(choice[place[(t, ren.get(t, {}).get(i, i))]] for t, i in varied) < choice for ren in autos):
                continue  # (this world renamed comes first)
            for turn in range(turns):
                classes = {row: self.classes[row[0]][c] for row, c in zip(varied, choice, strict=True)}
                for t in alone:
                    classes[(t, "1")] = self.classes[t][turn % len(self.classes[t])]
                yield Listed(self, {t: max(m, 1) for t, m in rows.items()}, classes, links)


class Listed(World):
    """One world of a Listing: its rows, each row's class and its links."""

    def __init__(
        self, listing: Listing, rows: dict[str, int], classes: dict[tuple[str, str], RowClass], links: list[Link]
    ) -> None:
        super().__init__("listed", MOST_ROWS, pols=listing.pols)
        self.listing, self.rows, self.classes, self.links_held = listing, rows, classes, links

    def ids(self, tname: str) -> list[str]:
        return [str(i) for i in range(1, self.rows.get(tname, 1) + 1)]

    def data(self, pol: Policy) -> Data:
        out = Data()
        for t in pol.types.values():
            ids = self.ids(t.name)
            out.ids[t.name] = ids
            out.columns[t.name] = {i: dict(self.classes[(t.name, i)].columns) for i in ids}
            where = facts(t.where, self.listing.alike) if t.where else None
            if t.where and where is not None and not uses_uid(where):
                out.valid[t.name] = [i for i in ids if truth(where, out.columns[t.name][i], None) is True]
            else:
                out.valid[t.name] = [i for i in ids if not t.where or t.where in self.classes[(t.name, i)].holds]
            for r in t.relations.values():
                for k, src in enumerate(r.sources):
                    for st, sr in src.subjects:
                        key = source_key(t, r.name, src, st, sr)
                        # a link table's rows read with no where: also each row its wheres hold for (a where takes
                        # rows away, never adds one)
                        bare = src.kind == "table" and not src.where
                        out.pairs[(t.name, r.name, k, st, sr or "")] = list(
                            dict.fromkeys(
                                (o, s)
                                for x, o, s in self.links_held
                                if x == key or (bare and x[:5] == key[:5] and x[6:] == key[6:])
                            )
                        )
            if t.roles:
                subjects, perms, _ = t.roles
                for p in perms:
                    for st, sr in subjects:
                        out.rolepairs[(t.name, p, st, sr or "")] = []
        for tname, cond in self.listing.conditions(pol):
            if cond in KEYWORDS.values():
                out.cond[(tname, cond)] = []
            elif facts(cond, self.listing.alike) is None:
                out.cond[(tname, cond)] = [i for i in out.ids[tname] if cond in self.classes[(tname, i)].holds]
        return out


def worlds_to_try(
    pols: Sequence[Policy],
    worlds: int,
    seed: str,
    max_size: int = 4,
    listing: Listing | None = None,
    by_size: bool = False,
) -> Iterable[World]:
    """The worlds a comparison of policies, or prove, goes through: drawn ones, smallest first, then the corners,
    then the listed ones (with a listing: LISTED for each drawn one asked for, after every one with ALWAYS links at
    most), then the rare ones (rare_worlds). by_size (prove: its counterexample is the smallest it finds): at each
    size, the drawn worlds and the corners, one of each in turn while both last, so that neither waits for the
    other."""
    # the corners: each condition yes or no on every row (but those that read who is signed in or a relation)
    found = corners(pols)
    for size in range(1, max_size + 1):
        drawn = [World(f"{seed}/{size}/{k}", size, pols=pols) for k in range(max(1, worlds // max_size))]
        if not by_size:
            yield from drawn
            continue
        cornered = [
            World(f"{seed}/corner{n}/{size}/{k}", size, corner, pols=pols)
            for k in range(3)
            for n, corner in enumerate(found)
        ]
        for i in range(max(len(drawn), len(cornered))):
            yield from drawn[i : i + 1] + cornered[i : i + 1]
    if not by_size:
        for n, corner in enumerate(found):
            for size in range(1, max_size + 1):
                for k in range(3):
                    yield World(f"{seed}/corner{n}/{size}/{k}", size, corner, pols=pols)
    if listing is not None:
        for w in listing.worlds():
            yield w
            if listing.listed >= LISTED * worlds and listing.whole >= ALWAYS:
                break
    yield from rare_worlds(pols, worlds, seed)


def compare(
    pol_a: Policy, pol_b: Policy, worlds: int = 200, seed: int = 0, max_size: int = 4, listing: Listing | None = None
) -> Difference | None:
    """None if the two policies grant the same in every world tried (each permission of either, for everyone
    who signs in, and each rule), else the first difference found, in the order the worlds are tried (not the
    smallest world: a listed or a dense one may come first): what differs, for whom, on which object, before and
    after, and that world made as small as it still differs in (smallest). The worlds tried: drawn ones, and those
    listing lists (a Listing of the two; one is made if none is given: its counts say what was listed)."""
    found = first_difference(pol_a, pol_b, worlds, seed, max_size, listing)
    return found[0] if found else None


RuleKey: TypeAlias = "tuple[str, str, tuple[str, ...]]"  # (table, command, columns)
# what a permission or rule grants in two states, the first policy's and the second's (None: one of them hasn't it)
Ask: TypeAlias = "Callable[[State, State], tuple[set[str], set[str]] | None]"


def rule_key(rule: Rule) -> RuleKey:
    return (rule.table, rule.command, tuple(rule.columns))


def names_read(types: Mapping[str, Type], t: Type, node: Expr) -> set[Name]:
    """What an expression on type t reads itself: the relations and permissions it names, and for `rel.perm` the
    relation it follows and the permission on each type that relation reaches."""
    out: set[Name] = set()
    for leaf, _ in leaves(node):
        match leaf:
            case Ref(name):
                out.add((t.name, name))
            case Arrow(rel, perm) | ArrowOn(rel, perm, _):
                out.add((t.name, rel))
                for st, sr in t.relations[rel].subjects():
                    assert sr is None and st in types, FOLLOWS
                    out.add((st, perm))
    return out


def expr_reads(ref: Reference, rule: Rule) -> set[Name]:
    """The relations and permissions a rule reads itself (Reference.reads gives what they read)."""
    return names_read(ref.types, ref.type_of_table(rule.table), rule.expr)


def apart(pol_a: Policy, pol_b: Policy) -> tuple[set[Name], set[RuleKey]] | None:
    """The permissions and rules two policies may answer differently: those they define differently, and those that
    read one of them, themselves or through what they read. The others read the same, defined the same way, in the
    same world: they answer alike. None when the policies differ in more than permissions and rules."""
    if shape(pol_a) != shape(pol_b):
        return None
    differ: set[Name] = set()
    for t in pol_a.types.values():
        tb = pol_b.types[t.name]
        for p in set(t.perms) | set(tb.perms):
            if p not in t.perms or p not in tb.perms or t.perms[p].expr != tb.perms[p].expr:
                differ.add((t.name, p))
    perms: set[Name] = set(differ)
    rules: set[RuleKey] = set()
    for pol, other in ((pol_a, pol_b), (pol_b, pol_a)):
        ref = Reference(pol)
        perms.update(n for n in ref.graph if ref.reads({n}) & differ)
        theirs = {rule_key(r): r.expr for r in other.rules}
        rules.update(
            rule_key(r)
            for r in pol.rules
            if theirs.get(rule_key(r)) != r.expr or ref.reads(expr_reads(ref, r)) & differ
        )
    return perms, rules


def first_difference(
    pol_a: Policy, pol_b: Policy, worlds: int = 200, seed: int = 0, max_size: int = 4, listing: Listing | None = None
) -> tuple[Difference, Data, Data] | None:
    """compare()'s difference, with the world it shows in (made as small as it can be), as each policy's data
    (tests/rewrites.py loads it as rows, to see the database answer as the review says)."""
    ref_a, ref_b = Reference(pol_a), Reference(pol_b)
    told = apart(pol_a, pol_b)
    perms = sorted(
        {
            (t.name, p)
            for pol in (pol_a, pol_b)
            for t in pol.types.values()
            for p in t.perms
            if not t.perms[p].hidden and (told is None or (t.name, p) in told[0])
        }
    )
    rules_a = {rule_key(r): r for r in pol_a.rules if r.command != "mask" and (told is None or rule_key(r) in told[1])}
    rules_b = {rule_key(r): r for r in pol_b.rules if r.command != "mask" and (told is None or rule_key(r) in told[1])}
    # what is worked out in each world: those permissions and rules, and what they read
    names_a = names_b = None
    if told is not None:
        names_a, names_b = (
            ref.reads({*told[0], *(n for r in rules.values() for n in expr_reads(ref, r))})
            for ref, rules in ((ref_a, rules_a), (ref_b, rules_b))
        )
    # each permission and rule asked of both: what each policy grants (None for a permission one of them hasn't: a
    # change of meaning shown elsewhere)
    asks: list[tuple[str, Ask]] = []
    for name in perms:
        asks.append(
            (
                f"{name[0]}.{name[1]}",
                lambda sa, sb, name=name: (set(sa[name]), set(sb[name])) if name in sa and name in sb else None,
            )
        )
    for key in sorted(set(rules_a) & set(rules_b), key=repr):
        table, command, cols = key
        asks.append(
            (
                f"rule {table} {command}" + (f" {', '.join(cols)}" if cols else ""),
                lambda sa, sb, key=key: (ref_a.rule(sa, rules_a[key]), ref_b.rule(sb, rules_b[key])),
            )
        )
    links = ("tok1",)
    alike = alike_in((pol_a, pol_b))
    whole = [kept_rows(pol_a, alike), kept_rows(pol_b, alike)]
    n = 0
    listed = listing if listing is not None else Listing((pol_a, pol_b))
    for w in worlds_to_try((pol_a, pol_b), worlds, str(seed), max_size, listed):
        n += 1
        da, db = w.data(pol_a), w.data(pol_b)
        for user in w.principals((pol_a, pol_b)):
            sa, sb = ref_a.evaluate(da, user, links, names_a), ref_b.evaluate(db, user, links, names_b)
            for what, ask in asks:
                got = ask(sa, sb)
                if got is None or got[0] == got[1]:
                    continue
                o = sorted(got[0] ^ got[1])[0]
                answer = (o in got[0], o in got[1])

                def still(
                    ds: list[Data], user: str = user, ask: Ask = ask, o: str = o, answer: tuple[bool, bool] = answer
                ) -> bool:
                    now = ask(ref_a.evaluate(ds[0], user, links, names_a), ref_b.evaluate(ds[1], user, links, names_b))
                    return now is not None and (o in now[0], o in now[1]) == answer

                # the world made as small as it still tells them apart in, for this user on this object
                small_a, small_b = smallest_of([da, db], still, whole)
                return (
                    {
                        "what": what,
                        "user": user or "(nobody signed in)",
                        "object": o,
                        "before": answer[0],
                        "after": answer[1],
                        "world": w.describe(pol_b, small_b),
                        "worlds": n,
                    },
                    small_a,
                    small_b,
                )
    return None
