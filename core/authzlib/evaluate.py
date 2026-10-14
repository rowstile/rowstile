"""What a policy grants, computed straight from what it says: the reference evaluator.

Relations and permissions are sets of ids, computed as a least fixpoint over some data. It is independent of
the SQL the compiler writes, so the tests compare the two (tests/difftest.py), and it answers questions about
a policy without a database: whether two policies grant the same in every small world (the review's check
that a refactor changed nothing, `rowstile prove`), and the smallest world where they don't.

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
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from decimal import Decimal
from typing import TypeAlias, TypedDict, TypeVar, cast

from .conditions import Node, Scalar, columns_of, simple, truth, uses_uid
from .parse import KEYWORDS, ROLES, Expr, Or, Policy, Relation, Rule, Source, Type

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

        def walk(t: Type, key: Name, node: Expr, neg: bool) -> None:
            """What the expression of t's `key` reads, into graph[key] (and negated, under a not)."""
            found: set[Name] = set()
            match node:
                case ("ref", name) if name == ROLES:
                    pass  # the role holders' groups: the roles line's subjects, below
                case ("ref", name):
                    found.add((t.name, name))
                case ("arrow", rel, perm):
                    found.add((t.name, rel))
                    for st, sr in t.relations[rel].subjects():
                        assert sr is None and st in self.types, FOLLOWS
                        found.add((st, perm))
                case ("not", item):
                    walk(t, key, item, True)
                case ("and", items) | ("or", items):
                    for x in items:
                        walk(t, key, x, neg)
            graph[key].update(found)
            if neg:
                negated.update((key, f) for f in found)

        for t in self.types.values():
            for name in list(t.relations) + list(t.perms):
                out = graph[(t.name, name)] = set()
                subjects: list[tuple[str, str | None]] = []
                if name in t.perms:
                    walk(t, (t.name, name), t.perms[name].expr, False)
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
        return order

    def conditions(self) -> list[CondKey]:
        """Every {sql} condition, by type, in the policy, its rules and invariants."""
        found: set[CondKey] = set()

        def walk(t: Type, node: Expr) -> None:
            match node:
                case ("cond", sql):
                    found.add((t.name, sql))
                case ("and", items) | ("or", items):
                    for x in items:
                        walk(t, x)
                case ("not", item):
                    walk(t, item)

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
    def evaluate(self, data: Data, user: str, links: Iterable[str] = ()) -> State:
        self.data, self.links = data, set(links)
        kind, pid = principal_of(user, self.types)
        self.principal = (kind, pid) if kind in self.types and pid in set(data.valid[kind]) else None
        state: State = {
            (t.name, name): frozenset() for t in self.types.values() for name in list(t.relations) + list(t.perms)
        }
        for comp in self.order:
            # a least fixpoint: no `not` in the group reads a name of it (strata), so each round only adds, and the
            # rounds end
            changed = True
            while changed:
                changed = False
                for tname, name in comp:
                    t = self.types[tname]
                    new = frozenset(self.eval_name(state, t, name) & self.valid(t))
                    if new != state[(tname, name)]:
                        state[(tname, name)] = new
                        changed = True
        return state

    def rule(self, state: State, rule: Rule) -> set[str]:
        """The rows (ids) of the rule's table the rule allows, in this state: never one that fails the type's where."""
        t = self.type_of_table(rule.table)
        return self.eval_expr(state, t, rule.expr) & self.ids(t) & self.valid(t)

    def ids(self, t: Type) -> set[str]:
        return set(self.data.ids[t.name])

    def valid(self, t: Type) -> set[str]:
        return set(self.data.valid[t.name])

    def role_owner_type(self, t: Type) -> str | None:
        """The type `roles : ... from rel` names (what rel links to), or None."""
        return role_owner_type(t)

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
            case ("ref", name) if name == ROLES and defining is not None:
                return self.role_holders(state, t, defining)
            case ("ref", name):
                return set(state[(t.name, name)])
            case ("arrow", rel, perm):
                r = t.relations[rel]
                out: set[str] = set()
                for i, src in enumerate(r.sources):
                    for target, sr in src.subjects:
                        assert sr is None and target in self.types, FOLLOWS
                        held = state[(target, perm)]
                        out |= {o for o, s in self.pairs(t, r.name, i, target, None) if s in held}
                return out
            case ("cond", sql) if sql == KEYWORDS["anyone"]:
                return self.ids(t)  # anyone at all, signed in or not
            case ("cond", sql) if sql == KEYWORDS["nobody"]:
                return set()
            case ("cond", sql) if sql == KEYWORDS["signed_in"]:
                # a user signed in (a service isn't: signed_in stays about users), on every row alike
                return self.ids(t) if self.principal is not None and self.principal[0] == "user" else set()
            case ("cond", sql) if (t.name, sql) not in self.data.cond and t.name in self.data.columns:
                # a simple condition, on the row's column values (and who is signed in, for authz.uid())
                facts = simple(sql)
                if facts is None:
                    raise KeyError(f"no rows given for {{{sql}}} on {t.name}")
                rows = self.row_values(t)
                me = self.principal[1] if self.principal is not None and self.principal[0] == "user" else None
                return {i for i in self.ids(t) if truth(facts, rows.get(i, {}), me) is True}
            case ("cond", sql):
                return set(self.data.cond[(t.name, sql)])
            case ("not", item):
                return self.ids(t) - self.eval_expr(state, t, item, defining)
            case ("and", items):
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

    def fill(self) -> float:
        """How many rows a column names something on."""
        return self.COLUMN if self.density is None else 0.95

    def followed(self, pol: Policy) -> set[tuple[str, str]]:
        """(type, relation) the world's policies follow from an object to another: with a dot (`parent.view`), or
        to the members of a group (`team#member`)."""
        if id(pol) not in self._followed or self._followed[id(pol)][0] is not pol:
            out: set[tuple[str, str]] = set()

            def walk(t: Type, node: Expr) -> None:
                match node:
                    case ("arrow", rel, _) | ("arrow_on", rel, _, _):
                        out.add((t.name, rel))
                    case ("not", item):
                        walk(t, item)
                    case ("and", items) | ("or", items):
                        for x in items:
                            walk(t, x)

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
                node = simple(cond)
                if node is not None:
                    for col, how in columns_of(node).items():
                        hows.setdefault((tname, col), []).extend(how)
        out: dict[tuple[str, str], list[Scalar]] = {}
        for key, used in sorted(hows.items()):
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
            out[key] = [*dict.fromkeys(values), None]
        return out

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
            node = simple(cond)
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
            where = simple(t.where) if t.where else None
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
                        sids = self.ids(st) if st in pol.types else ["1"]
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
            elif simple(cond) is None:
                out.cond[(tname, cond)] = self.holds(tname, cond, self.ids(tname))
        return out

    def links(
        self, pol: Policy, t: Type, r: Relation, src: Source, ids: list[str], st: str, sr: str | None
    ) -> list[Pair]:
        """The links one source holds for subjects st#sr: at most one per row in a column."""
        subject_ids = (
            ["*"]
            if st == "anyone"
            else ["tok1", "tok2"]
            if st == "link"
            else self.ids(st)
            if st in pol.types
            else ["1"]
        )
        key = ("pairs", *source_key(t, r.name, src, st, sr))
        chained = self.chained and st in pol.types and (t.name, r.name) in self.followed(pol)
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

    def describe(self, pol: Policy, data: Data) -> list[str]:
        """The world, as lines a reviewer can read."""
        lines = [f"{t.name}: {', '.join(data.ids[t.name])}" for t in pol.types.values()]
        # the columns simple conditions read (not NULL; a relation's column is its link, below)
        linked = {
            (t.name, linked_column(src)) for t in pol.types.values() for r in t.relations.values() for src in r.sources
        }
        for tname, rows in sorted(data.columns.items()):
            for i, values in rows.items():
                said = [(c, v) for c, v in sorted(values.items()) if v is not None and (tname, c) not in linked]
                if said:
                    lines.append(f"{tname} {i}: " + ", ".join(f"{c} = {shown(v)}" for c, v in said))
        for (tname, cond), ids in sorted(data.cond.items(), key=lambda kv: repr(kv[0])):
            if ids:
                lines.append(f"{{{cond}}} holds for {tname} {', '.join(ids)}")
        for (tname, rname, _, st, sr), pairs in sorted(data.pairs.items(), key=lambda kv: repr(kv[0])):
            if pairs:
                who = st + (f"#{sr}" if sr and sr != "*" else "")
                lines.append(f"{tname}.{rname}: " + ", ".join(f"{tname} {o} -> {who} {s}" for o, s in pairs))
        return lines


def shown(v: str | int | Decimal | bool) -> str:
    """A column's value as SQL writes it (describe leaves NULL out: a smaller world's columns are NULL)."""
    if isinstance(v, bool):
        return "true" if v else "false"
    return f"'{v}'" if isinstance(v, str) else str(v)


def without_each(entries: dict[K, list[V]], still: Callable[[dict[K, list[V]]], bool]) -> tuple[dict[K, list[V]], bool]:
    """Each entry's items taken away one at a time, in key order, where `still` holds without it."""
    changed = False
    for key in sorted(entries, key=repr):
        i = 0
        while i < len(entries[key]):
            trial = dict(entries)
            trial[key] = entries[key][:i] + entries[key][i + 1 :]
            if still(trial):
                entries, changed = trial, True
            else:
                i += 1
    return entries, changed


def without_values(
    columns: dict[str, dict[str, dict[str, Scalar]]], still: Callable[[dict[str, dict[str, dict[str, Scalar]]]], bool]
) -> tuple[dict[str, dict[str, dict[str, Scalar]]], bool]:
    """Each column value made NULL, one at a time, where `still` holds with it NULL."""
    changed = False
    for tname in sorted(columns):
        for i in sorted(columns[tname]):
            for col in sorted(columns[tname][i]):
                if columns[tname][i][col] is None:
                    continue
                trial = {t: {k: dict(v) for k, v in rows.items()} for t, rows in columns.items()}
                trial[tname][i][col] = None
                if still(trial):
                    columns, changed = trial, True
    return columns, changed


def smallest(data: Data, still: Callable[[Data], bool]) -> Data:
    """The data with every link, role and condition row taken away, and every column value made NULL, that
    `still` doesn't need."""
    changed = True
    while changed:
        # each trial is the data as it is now, one entry changed
        cond, a = without_each(data.cond, lambda d, now=data: still(dataclasses.replace(now, cond=d)))
        data = dataclasses.replace(data, cond=cond)
        pairs, b = without_each(data.pairs, lambda d, now=data: still(dataclasses.replace(now, pairs=d)))
        data = dataclasses.replace(data, pairs=pairs)
        rolepairs, c = without_each(data.rolepairs, lambda d, now=data: still(dataclasses.replace(now, rolepairs=d)))
        data = dataclasses.replace(data, rolepairs=rolepairs)
        columns, d = without_values(data.columns, lambda cols, now=data: still(dataclasses.replace(now, columns=cols)))
        data = dataclasses.replace(data, columns=columns)
        changed = a or b or c or d
    return data


def corners(pols: Iterable[Policy]) -> list[dict[str, bool]]:
    """Worlds a row-by-row draw rarely makes: which conditions hold everywhere and which nowhere. A change behind
    `{a} and {b} and ... and {h}` shows only where all eight hold, one row in 256 when each is a coin toss. The
    corners: every condition written plainly holds and every one under a `not` doesn't (the most anyone can
    hold); the other way round; every condition holds. A type's where holds in all three (or nothing would)."""
    plain: set[str] = set()
    denied: set[str] = set()
    wheres: set[str] = set()

    def walk(node: Expr, negated: bool) -> None:
        match node:
            case ("cond", sql):
                (denied if negated else plain).add(sql)
            case ("not", item):
                walk(item, not negated)
            case ("and", items) | ("or", items):
                for x in items:
                    walk(x, negated)

    for pol in pols:
        for t in pol.types.values():
            if t.where:
                wheres.add(t.where)
            for p in t.perms.values():
                walk(p.expr, False)
        for rule in pol.rules:
            walk(rule.expr, False)
        for inv in pol.invariants:
            walk(inv.expr, False)
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
            match node:
                case ("ref", name):
                    return deep(t, name)
                case ("arrow", rel, perm) | ("arrow_on", rel, perm, _) if rel in t.relations:
                    targets = [st for st, sr in t.relations[rel].subjects() if sr is None and st in pol.types]
                    return max((1 + deep(pol.types[st], perm) for st in targets), default=1)
                case ("not", item):
                    return depth(t, item)
                case ("and", items) | ("or", items):
                    return max(depth(t, x) for x in items)
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


def worlds_to_try(pols: Sequence[Policy], worlds: int, seed: str, max_size: int = 4) -> Iterable[World]:
    """The worlds a comparison of policies goes through: drawn ones, smallest first, then the corners, then the
    rare ones (rare_worlds)."""
    for size in range(1, max_size + 1):
        for k in range(max(1, worlds // max_size)):
            yield World(f"{seed}/{size}/{k}", size, pols=pols)
    # the corners: each condition yes or no on every row (but those that read who is signed in or a relation)
    for n, corner in enumerate(corners(pols)):
        for size in range(1, max_size + 1):
            for k in range(3):
                yield World(f"{seed}/corner{n}/{size}/{k}", size, corner, pols=pols)
    yield from rare_worlds(pols, worlds, seed)


def compare(pol_a: Policy, pol_b: Policy, worlds: int = 200, seed: int = 0, max_size: int = 4) -> Difference | None:
    """None if the two policies grant the same in every world tried (each permission of either, for everyone
    who signs in, and each rule), else the first difference found in the smallest world: what differs, for
    whom, on which object, before and after, and the world."""
    found = first_difference(pol_a, pol_b, worlds, seed, max_size)
    return found[0] if found else None


def first_difference(
    pol_a: Policy, pol_b: Policy, worlds: int = 200, seed: int = 0, max_size: int = 4
) -> tuple[Difference, Data, Data] | None:
    """compare()'s difference, with the world it was found in, as each policy's data (tests/rewrites.py loads it as
    rows, to see the database answer as the review says)."""
    ref_a, ref_b = Reference(pol_a), Reference(pol_b)
    perms = sorted(
        {(t.name, p) for pol in (pol_a, pol_b) for t in pol.types.values() for p in t.perms if not t.perms[p].hidden}
    )
    rules_a = {(r.table, r.command, r.columns): r for r in pol_a.rules if r.command != "mask"}
    rules_b = {(r.table, r.command, r.columns): r for r in pol_b.rules if r.command != "mask"}
    n = 0
    for w in worlds_to_try((pol_a, pol_b), worlds, str(seed), max_size):
        n += 1
        da, db = w.data(pol_a), w.data(pol_b)
        for user in w.principals((pol_a, pol_b)):
            links = ("tok1",)
            sa, sb = ref_a.evaluate(da, user, links), ref_b.evaluate(db, user, links)
            for tname, p in perms:
                ga = sa.get((tname, p))
                gb = sb.get((tname, p))
                if ga is None or gb is None:
                    continue  # added or removed: a change of meaning shown elsewhere
                if ga != gb:
                    o = sorted(ga ^ gb)[0]
                    return (
                        {
                            "what": f"{tname}.{p}",
                            "user": user or "(nobody signed in)",
                            "object": o,
                            "before": o in ga,
                            "after": o in gb,
                            "world": w.describe(pol_b, db),
                            "worlds": n,
                        },
                        da,
                        db,
                    )
            for key in sorted(set(rules_a) & set(rules_b), key=repr):
                ra, rb = ref_a.rule(sa, rules_a[key]), ref_b.rule(sb, rules_b[key])
                if ra != rb:
                    o = sorted(ra ^ rb)[0]
                    table, command, cols = key
                    name = f"rule {table} {command}" + (f" {', '.join(cols)}" if cols else "")
                    return (
                        {
                            "what": name,
                            "user": user or "(nobody signed in)",
                            "object": o,
                            "before": o in ra,
                            "after": o in rb,
                            "world": w.describe(pol_b, db),
                            "worlds": n,
                        },
                        da,
                        db,
                    )
    return None
