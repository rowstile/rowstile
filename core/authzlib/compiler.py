"""Compiling a policy into views, closure tables, triggers and RLS policies."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Callable, Mapping, Sequence
from typing import TypeAlias, TypedDict

from .parse import (
    ROLES,
    And,
    Arrow,
    ArrowOn,
    Caveat,
    Cols,
    Cond,
    Expr,
    Link,
    Loc,
    Not,
    Or,
    Perm,
    Policy,
    Ref,
    Relation,
    RolesSource,
    Rule,
    Source,
    Span,
    Subject,
    TableSource,
    Type,
    cols,
    conditions_of,
    fail,
    head,
    names_roles,
    subject_spans,
    tail,
)
from .sqlutil import (
    CAVEAT_ARG,
    RESERVED,
    ROW_ALIAS,
    check_stable_condition,
    lit,
    names_this,
    on_row,
    or_join,
    q,
    qt,
    reads_more,
    reads_tables,
    reserved_names,
    row_cond,
    this_alone,
    union,
    with_uid,
)

UID = "(SELECT authz.uid())"
UIDT = "(SELECT authz.uid()::text)"
LINKS = "(SELECT authz.link_hashes())::text[]"
# what a function over every type does with a type the policy doesn't have (Core.dispatch_type)
NO_SUCH_TYPE = "RAISE EXCEPTION 'no type % in the policy', p_type USING HINT = 'rowstile help AZ707';"

# a type's relation or permission: (type name, its name)
Name: TypeAlias = "tuple[str, str]"
# an inheritance link of a recursive permission: (child type, relation, condition or None, parent type)
Edge: TypeAlias = "tuple[str, str, str | None, str]"
Edges: TypeAlias = "frozenset[Edge]"
# a recursion: the permissions that inherit through each other, sorted
SccKey: TypeAlias = "tuple[Name, ...]"
# a closure table: one type's links (type name, links), or a recursion across types
TreeKey: TypeAlias = "tuple[str, Edges] | SccKey"
# what one walk already covers, so same-type permissions inside it need no walk of their own
Flatten: TypeAlias = "tuple[str, Edges] | None"
# how a permission inherits through one item: (relation, condition or None, target type)
Inherit: TypeAlias = "tuple[str, str | None, str]"


class NextTree(TypedDict):
    """How to build a tree beside the one in use, while the app runs (TreeMixin.next_tree, migrate.py)."""

    types: list[str]
    tables: list[str]
    link_tables: list[str]
    next: str  # the table built beside
    next_name: str
    table: str  # the tree's table, quoted
    objects: list[tuple[str, str]]  # (kind, key) of what the first migration makes
    build: str  # the first migration's SQL
    catch_up: str  # the second's: what changed since the first one's snapshot


def rule_name(rule: Rule) -> str:
    """A write rule's head, as the policy writes it (`update owner_id after`), for messages."""
    # (two masks of one column are refused as masked twice before two rules alike, and refusals explain writes)
    assert rule.command != "mask", "a mask is never named in a message about rules"
    if not rule.columns:
        return "update after" if rule.command == "update check" else rule.command
    return "update " + ", ".join(rule.columns) + (" after" if rule.command == "update check" else "")


# what AZ302 says of a permission that depends on itself otherwise than by inheriting
DEPENDS_ON_ITSELF = (
    "{} depends on itself; a permission can only recurse as 'or rel.perm' (optionally 'and {{condition}}') "
    "through a relation to objects, and a group only as 'member : group#member'"
)


def only_on(node: Expr) -> list[str] | None:
    """The subject types an arrow the compiler narrowed (arrow_on) follows; None for any other item."""
    match node:
        case ArrowOn(_, _, types):
            return list(types)
    return None


def leaves(node: Expr) -> list[Expr]:
    """The names, arrows and conditions of an expression, in order."""
    match node:
        case Or(items=items) | And(items=items):
            return [x for item in items for x in leaves(item)]
        case Not(item=item):
            return leaves(item)
    return [node]


def renamed(node: Expr, old: str, new: str) -> Expr:
    """The expression with each `old` (a name of the same object) written `new`."""
    match node:
        case Ref(name=name) if name == old:
            return Ref(new)
        case Not(item=item):
            return Not(renamed(item, old, new))
        case Or(items=items):
            return Or([renamed(x, old, new) for x in items])
        case And(items=items):
            return And([renamed(x, old, new) for x in items])
    return node


def once(items: Sequence[Expr]) -> list[Expr]:
    """The operands of an `and` or an `or`, each once: `p and p` holds when `p` does, and each time a
    permission is named Postgres writes its whole definition out again."""
    out: list[Expr] = []
    for item in items:
        if item not in out:
            out.append(item)
    return out


# A view named in a query is written out in full each time, and so is each view it names: what Postgres plans
# for one read grows with every permission named more than once on the way (Core.expansions counts them).
VIEW_BODY = re.compile(r'CREATE VIEW authz_int\.("(?:[^"]|"")+"|\w+) AS\n(.*?);(?=\nCREATE VIEW authz_gen|\Z)', re.S)
VIEW_NAME = re.compile(r'authz_(?:int|gen)\.("(?:[^"]|"")+"|\w+)')
# the policies here stay under 25; from about 70, planning a read can take a tenth of a second and more
MANY_EXPANSIONS = 50


class Core:
    def expansions(self, sql: str) -> int:
        """How many view definitions Postgres writes out to plan `sql` (a rule's check): each view it names,
        and for each of those the views it names, again for every use."""

        def name(x: str) -> str:
            return x[1:-1].replace('""', '"') if x.startswith('"') else x

        bodies: dict[str, str] = {}
        for entry in self.view_sql:
            m = VIEW_BODY.search(entry)
            if m:
                bodies[name(m.group(1))] = m.group(2)
        counted: dict[str, int] = {}

        def count(view: str) -> int:
            if view not in counted:
                counted[view] = 1  # (a view never names itself: trees and functions stand between)
                counted[view] = 1 + sum(count(name(r)) for r in VIEW_NAME.findall(bodies[view]) if name(r) in bodies)
            return counted[view]

        return sum(count(name(r)) for r in VIEW_NAME.findall(sql) if name(r) in bodies)

    def line_sql(self, what: str | None, loc: Loc | str | None, key_sql: str | None = None) -> str:
        """Where something is written, as SQL that looks it up when a message is made: authz_gen.policy_lines
        holds each 'what' and its line, so a policy edit that only moves lines changes that table's rows,
        not the functions (a migration then holds only them). key_sql: the SQL giving the key."""
        if what is not None:
            self.lines[what] = str(loc)
        key = key_sql or lit(what)
        return f"coalesce((SELECT l.loc FROM authz_gen.policy_lines l WHERE l.what = {key}), '?')"

    def line_key(self, what: str, loc: Loc | str) -> str:
        """Records where `what` is written and gives the key to look it up with (line_sql)."""
        self.lines[what] = str(loc)
        return what

    def lines_sql(self) -> str:
        rows = ",\n  ".join(f"({lit(w)}, {lit(loc)})" for w, loc in sorted(self.lines.items()))
        return (
            "-- where each rule, relation and invariant is written, for messages (Core.line_sql)\n"
            "CREATE TABLE authz_gen.policy_lines (what text PRIMARY KEY, loc text NOT NULL);"
            + (f"\nINSERT INTO authz_gen.policy_lines VALUES\n  {rows};" if rows else "")
        )

    def __init__(self, pol: Policy) -> None:
        self.pol = pol
        if pol.role is None:
            fail(
                1,
                "name the app role, the Postgres role your app connects as, which the rules apply to: "
                "app role app_user",
                "AZ111",
            )
        self.role: str = pol.role
        self.types, self.rules, self.tests = pol.types, pol.rules, pol.tests
        self.view_state: dict[str, str] = {}  # view name -> 'busy' | 'done'
        self.view_sql: list[str] = []  # CREATE VIEW / FUNCTION statements, dependency order
        self.trees: dict[TreeKey, str] = {}  # tree key -> tree name
        # tree name -> (hash of its definition, tables it reads): kept across applies
        self.tree_keep: dict[str, tuple[str, list[str]]] = {}
        self.tree_sql: list[str] = []
        self.tree_names: list[str] = []  # the name of each tree_sql entry
        # tree name -> how to build it beside the one in use (migrate.py, two phases)
        self.tree_next: dict[str, NextTree] = {}
        self.lines: dict[str, str] = {}  # what -> where it is written ('line 12'), for run-time messages
        self.nested: dict[str, str] = {}  # relation views that expand nested groups -> their type's key type
        self.point_checks: dict[str, str] = {}  # recursive permission view -> its function checking one object
        self.direct_checks: dict[str, str] = {}  # recursive permission view -> view of what its columns give
        self.direct_sql: dict[str, str] = {}  # such views -> their SQL (permissions with the same share one)
        self.locked_types: set[str] = set()  # types with closure tables (one lock row each)
        self.cond_lines: dict[tuple[str, str], Loc] = {}  # (type, condition) -> loc, for apply-time errors
        self.columns: list[tuple[str, str, Loc]] = []  # (table, column, loc) to check exist
        self.pk_checks: list[tuple[str, str, str, Loc]] = []  # (table, pk, pktype, loc)
        self.recursive: dict[Name, SccKey] = {}  # (type, perm) -> scc key
        self.scc_members: dict[SccKey, list[Name]] = {}  # scc key -> [(type, perm)]
        self.denies: dict[Name, list[Expr]] = {}  # (type, perm) with a deny -> its `not` items
        self._invalid = "NULL"  # what dispatch_type's functions return for an id that isn't one
        # the compiled policy in parts, (mode, name, SQL): what a migration does with each (output.compile)
        self.parts: list[tuple[str, str, str]] = []
        self._list_cases = ""  # authz.list's branches (output.list_cases_sql)
        if "user" not in self.types:
            fail(1, "declare the user type, e.g.: type user = app.users", "AZ202")
        for t in self.types.values():
            if t.principal and t.composite:
                fail(
                    t.loc,
                    f"the {t.name} type signs in, so it needs a key of one column (who is signed in "
                    f"is one value); give its table one, e.g. an identity column",
                    "AZ206",
                )
        self.add_custom_roles()
        self.split_denies()
        self.validate()
        self.analyze_recursion()
        self.check_denies()

    # --- made by the other parts of the compiler --------------------------------------------------
    def compile(self, source_name: str, transaction: bool = True) -> str:
        """The whole policy as SQL (output.py)."""
        raise NotImplementedError

    def ensure_tree(self, t: Type, edges: Edges) -> str:
        """The closure table of one type's inheritance (trees.py)."""
        raise NotImplementedError

    def ensure_multi_tree(self, key: SccKey, edges: Edges) -> str:
        """The closure table of a recursion across types (trees.py)."""
        raise NotImplementedError

    # --- the model ------------------------------------------------------
    def T(self, name: str) -> Type:
        return self.types[name]

    def governing(self, table: str) -> Type:
        """The type whose permissions a table's rules name."""
        found = [t for t in self.types.values() if t.table == table]
        assert len(found) == 1, "validate refuses rules for a table no type or two types map to (AZ401)"
        return found[0]

    @staticmethod
    def public_perms(t: Type) -> list[str]:
        """The permissions the policy declares, without the ones the compiler made."""
        return [n for n, p in t.perms.items() if not p.hidden]

    def add_custom_roles(self) -> None:
        """`roles : subjects [from rel]` says who may hold the type's custom roles; a permission writes `roles`
        where a role that includes it gives it: `can view = (viewer or roles or parent.view) and not hidden`.
        Each permission's `roles` becomes a relation of its own (`roles:view`), held through role assignments whose
        role includes that permission. Runs before split_denies, on the permissions as written: there `roles:view`
        is one more relation of the `or` it is written in."""
        for rule in self.rules:
            if names_roles(rule.expr):
                fail(
                    rule.loc,
                    f"`{ROLES}` goes in a permission, which says what a custom role gives: write it there "
                    f"(`can edit = editor or roles`) and name the permission here",
                    "AZ210",
                )
        for inv in self.pol.invariants:
            if names_roles(inv.expr):
                fail(
                    inv.loc,
                    f"`{ROLES}` goes in a permission, which says what a custom role gives: name the permission here",
                    "AZ210",
                )
        for t in self.types.values():
            for p in t.perms.values():
                if any(isinstance(x, Arrow) and x.rel == ROLES for x in leaves(p.expr)):
                    fail(
                        p.loc,
                        f"{t.name}.{p.name}: `{ROLES}` gives the permission it is written in; it isn't a "
                        f"relation to follow with a dot",
                        "AZ210",
                    )
            named = [p for p in t.perms.values() if names_roles(p.expr)]
            if not t.roles:
                for p in named:
                    fail(
                        p.loc,
                        f"{t.name}.{p.name} writes `{ROLES}`, but {t.name} has no `roles : ...` line saying who "
                        f"may hold custom roles, e.g. roles : user from org",
                        "AZ210",
                    )
                continue
            subjects, _, loc = t.roles
            if t.roles_from:
                self.role_owner_type(t)  # refuses a relation that can't name an owner
            if not named:
                fail(
                    loc,
                    f"{t.name} says who may hold custom roles, but no permission writes `{ROLES}`: write it "
                    f"where a role gives the permission, e.g. can view = viewer or roles",
                    "AZ210",
                )
            for p in named:
                if any(names_roles(p.expr)):
                    fail(
                        p.loc,
                        f"{t.name}.{p.name}: `not {ROLES}` would take a permission away from whoever holds a "
                        f"custom role that includes it; a role only gives",
                        "AZ210",
                    )
                rel = Relation(
                    f"roles:{p.name}",
                    loc,
                    [RolesSource(subjects, loc, p.name, owner=t.roles_from, spans=t.roles_spans)],
                    synthetic=True,
                )
                t.relations[rel.name] = rel
                p.expr = renamed(p.expr, ROLES, rel.name)

    def role_owner_type(self, t: Type) -> str:
        """The type of the owner `roles : ... from rel` names: rel links each object to objects of one type,
        through columns or tables (what the data says, never a share)."""
        assert t.roles is not None and t.roles_from is not None
        loc, name = t.roles[2], t.roles_from
        r = t.relations.get(name)
        kinds = {src.kind for src in r.sources} if r else set()
        subjects = {s for src in r.sources for s in src.subjects} if r else set()
        if r is None or not kinds <= {"column", "table"} or len(subjects) != 1:
            fail(
                loc,
                f"custom roles on {t.name} come from '{name}', which must be a relation of {t.name} kept in "
                f"a column or a table and linking to one type, as `org : org = org_id`",
                "AZ211",
            )
        st, sr = next(iter(subjects))
        if sr is not None or st not in self.types:
            fail(
                loc,
                f"custom roles on {t.name} come from '{name}', which must link to objects of a type "
                f"(the roles' owner), not to {st}{'#' + sr if sr else ''}",
                "AZ211",
            )
        return st

    def role_rel_sql(self, t: Type, src: RolesSource, obj: str) -> str:
        """The share g is an assignment of a custom role that grants src.perm on object obj (an id of t) and, with
        `from rel`, one owned by what rel links obj to now: an assignment from another owner grants nothing."""
        sql = f"g.relation = ANY ((SELECT authz_int.role_relations({lit(t.name)}, {lit(src.perm)}))::text[])"
        if not src.owner:
            return sql
        return (
            f"{sql} AND EXISTS (SELECT 1 FROM authz.roles ro WHERE 'role:' || ro.id = g.relation "
            f"AND ro.owner_type = {lit(self.role_owner_type(t))} AND ro.owner_id IN ({self.role_owners_sql(t, obj)}))"
        )

    def role_owners_sql(self, t: Type, obj: str) -> str:
        """The ids (as text) of what `roles : ... from rel` links object obj to: the owners whose roles count."""
        assert t.roles_from is not None
        ot = self.role_owner_type(t)
        owners = []
        for o in t.relations[t.roles_from].sources:
            if o.kind == "column":
                owners.append(
                    f"SELECT ({self.subject_id(o, 'w', ot)})::text FROM {qt(t.table)} w "
                    f"WHERE {self.key_is(t, 'w', obj)}"
                )
            else:
                assert o.kind == "table", f"{t.name}.{t.roles_from}: custom roles come from a link"
                where = f" AND coalesce(({row_cond(o.where, 'w')}), false)" if o.where else ""
                owners.append(
                    f"SELECT ({self.subject_id(o, 'w', ot)})::text FROM {qt(self.source_table(o))} w "
                    f"WHERE {self.key_is(t, 'w', obj, o.obj_col)}{where}"
                )
        return " UNION ALL ".join(owners)

    def split_denies(self) -> None:
        """`can view = (viewer or parent.view) and not denied`. Its plain meaning is a fixpoint with a
        negation inside, which closure tables can't hold. When the deny covers everything below (denied
        inherits through the same links; check_denies), it equals `view__base and not denied`, with
        view__base = viewer or parent.view__base (hidden), which they can. Conditions joined with `and`
        go on every item: `(a or parent.view) and {c}` is `(a and {c}) or (parent.view and {c})`."""
        graph: dict[Name, set[Name]] = {}
        for t in self.types.values():
            for p in t.perms.values():
                out: set[Name] = set()
                self.deps(t, p.expr, out)
                graph[(t.name, p.name)] = out

        def loops(v: Name) -> bool:
            seen: set[Name] = set()
            todo = list(graph[v])
            while todo:
                w = todo.pop()
                if w == v:
                    return True
                if w not in seen:
                    seen.add(w)
                    todo += graph.get(w, ())
            return False

        for t in self.types.values():
            for p in list(t.perms.values()):
                if not isinstance(p.expr, And) or not loops((t.name, p.name)):
                    continue
                conds: list[Expr] = []
                negs: list[Expr] = []
                rest: list[Expr] = []
                for x in p.expr.items:
                    match x:
                        case Cond(_) | Not(Cond(_)):
                            conds.append(x)
                        case Not(_):
                            negs.append(x)
                        case _:
                            rest.append(x)
                if len(rest) > 1:
                    fail(
                        p.loc,
                        f"{t.name}.{p.name} inherits, so `and` can only join its inheritance with "
                        f"{{conditions}} and `not <permission>`, e.g. (viewer or parent.{p.name}) and not denied",
                        "AZ304",
                    )
                if not rest:  # it comes back to itself only through a `not`
                    fail(p.loc, DEPENDS_ON_ITSELF.format(f"{t.name}.{p.name}"), "AZ302")
                first = rest[0]
                items = list(first.items) if isinstance(first, Or) else [first]
                items = [
                    (And([*i.items, *conds]) if isinstance(i, And) else And([i, *conds])) if conds else i for i in items
                ]
                inherit = items[0] if len(items) == 1 else Or(items)
                if not negs:
                    p.expr = inherit
                    continue
                for x in negs:
                    if not (isinstance(x, Not) and isinstance(x.item, Ref)):
                        fail(
                            p.loc,
                            f"{t.name}.{p.name} inherits, so a deny on it is `not <permission of "
                            f"{t.name}>` that inherits the same way, e.g. `can denied = blocked or "
                            f"parent.denied` and `... and not denied`",
                            "AZ306",
                        )
                base = f"{p.name}__base"
                t.perms = {
                    **{k: v for k, v in t.perms.items() if k != p.name},
                    base: Perm(
                        base,
                        self.rename_arrows(t, inherit, p.name, base, p.loc),
                        f"{p.src}  (its inheritance, before the deny)",
                        p.loc,
                        hidden=True,
                    ),
                    p.name: p,
                }
                p.expr, p.base = And([Ref(base), *negs]), base
                self.denies[(t.name, p.name)] = negs
                graph[(t.name, base)] = set()

    def rename_arrows(self, t: Type, node: Expr, old: str, new: str, loc: Loc) -> Expr:
        """rel.old -> rel.new for relations to t itself (the base of a permission with a deny)."""
        match node:
            case Arrow(rel, perm) if perm == old and rel in t.relations:
                subjects = t.relations[rel].subjects()
                if any(st == t.name and not sr for st, sr in subjects):
                    if any(st != t.name for st, _ in subjects):
                        fail(
                            loc,
                            f"{t.name}.{old} has a deny and inherits through {rel}, which also points at "
                            f"other types; give those their own relation",
                            "AZ306",
                        )
                    return Arrow(rel, new)
            case Not(item):
                return Not(self.rename_arrows(t, item, old, new, loc))
            case And(items):
                return And([self.rename_arrows(t, x, old, new, loc) for x in items])
            case Or(items):
                return Or([self.rename_arrows(t, x, old, new, loc) for x in items])
        return node

    def check_denies(self) -> None:
        """`view = view__base and not denied` means what `(... or parent.view) and not denied` says only if
        denied holds on everything below a denied object: denied inherits through every link view__base
        does (without a condition, or with the same one). Otherwise the deny would cut inheritance at the
        denied object only, which needs each user's paths, and rowstile stores objects' ancestors. (A deny whose
        inheritance goes through another type's permission comes back to it: analyze_recursion says so.)"""
        for (tn, pn), negs in self.denies.items():
            t = self.T(tn)
            base_name = t.perms[pn].base
            assert base_name is not None  # split_denies gave every permission with a deny its base
            base = t.perms[base_name]
            edges = self.perm_edges(t, base) or frozenset()
            for x in negs:
                assert isinstance(x, Not) and isinstance(x.item, Ref), "split_denies refuses any other deny (AZ306)"
                name = x.item.name
                self.lookup(t, name, base.loc, x.item.span)
                if name not in t.perms:
                    fail(
                        base.loc,
                        f"{tn}.{pn}: `not {name}` must cover everything below, and {name} is a "
                        f"relation: make a permission that inherits, `can {name}_below = {name} or "
                        f"parent.{name}_below`, and deny with it",
                        "AZ306",
                    )
                if (tn, name) in self.denies:
                    fail(
                        base.loc,
                        f"{tn}.{pn}: `not {name}` must cover everything below, and {name} has a deny of "
                        f"its own, which can cut it below a denied object: deny with a permission "
                        f"without one",
                        "AZ306",
                    )
                got = self.perm_edges(t, t.perms[name]) or frozenset()
                missing = sorted({e[1] for e in edges if e not in got and (e[0], e[1], None, e[3]) not in got})
                if missing:
                    fail(
                        base.loc,
                        f"{tn}.{pn}: `not {name}` must cover everything below, so {name} must inherit "
                        f"through {', '.join(missing)} as {pn} does, e.g. `can {name} = ... or "
                        f"{missing[0]}.{name}`",
                        "AZ306",
                    )

    def validate(self) -> None:
        for t in self.types.values():
            for c, ty in t.key:
                self.columns.append((t.table, c, t.loc))
                self.pk_checks.append((t.table, c, ty, t.loc))
            for r in t.relations.values():
                for src in r.sources:
                    for (st, sr), at in zip(src.subjects, subject_spans(src), strict=True):
                        if st in ("anyone", "link"):
                            continue
                        if st not in self.types:
                            fail(src.loc, f"{t.name}.{r.name}: unknown type '{st}'", "AZ201", span=head(at, len(st)))
                        if sr == "*" and not self.T(st).principal:
                            fail(
                                src.loc,
                                f"{t.name}.{r.name}: {st}:* means any signed-in {st}, but {st} doesn't sign "
                                f"in: mark it `type {st} = ... principal`",
                                "AZ204",
                            )
                        if sr and sr != "*" and sr not in self.T(st).relations and sr not in self.T(st).perms:
                            fail(
                                src.loc,
                                f"{t.name}.{r.name}: {st} has no relation or permission '{sr}'",
                                "AZ203",
                                span=tail(at, len(sr)),
                            )
                    if src.kind == "column":
                        column = self.source_columns(src)
                        self.check_key_columns(t, r, src, column, [st for st, _ in src.subjects], "subject")
                        for c in cols(column) + ((src.type_col,) if src.type_col else ()):
                            self.columns.append((t.table, c, src.loc))
                    elif src.kind == "table":
                        assert src.obj_col is not None and src.subj_col is not None and src.table is not None
                        self.check_key_columns(t, r, src, src.obj_col, [t.name], "object")
                        self.check_key_columns(t, r, src, src.subj_col, [st for st, _ in src.subjects], "subject")
                        for c in cols(src.obj_col) + cols(src.subj_col) + ((src.type_col,) if src.type_col else ()):
                            self.columns.append((src.table, c, src.loc))
                    elif src.kind == "shared":
                        if src.shared_by and src.shared_by not in t.perms:
                            fail(
                                src.loc,
                                f"{t.name}.{r.name} is shared by '{src.shared_by}', but {t.name} "
                                f"has no such permission",
                                "AZ207",
                            )
                        if not src.shared_by and "share" not in t.perms:
                            fail(
                                src.loc,
                                f"{t.name}.{r.name} is shared, which needs a share permission on "
                                f"{t.name}: add `can share = ...` or write `shared by <permission>`",
                                "AZ207",
                            )
        for rule in self.rules:
            mapped = [t.name for t in self.types.values() if t.table == rule.table]
            if not mapped:
                fail(rule.loc, f"rules for {rule.table}, but no type maps to that table", "AZ401")
            if len(mapped) > 1:
                fail(
                    rule.loc,
                    f"rules for {rule.table}, which types {' and '.join(mapped)} both map to: rules name "
                    f"one type's permissions, so give each type its own table (or view)",
                    "AZ401",
                )
            for c in rule.columns:
                self.columns.append((rule.table, c, rule.loc))
        masked: dict[tuple[str, str], Loc] = {}
        for rule in self.rules:
            if rule.command != "mask":
                continue
            if rule.table not in self.pol.views:
                fail(
                    rule.loc,
                    f"masks are applied by a view: write 'rules {rule.table} view <schema.view_name>'",
                    "AZ402",
                )
            for c in rule.columns:
                if (rule.table, c) in masked:
                    fail(rule.loc, f"{rule.table}.{c} is masked twice (also on {masked[rule.table, c]})", "AZ109")
                masked[rule.table, c] = rule.loc
        shows: dict[str, str] = {}  # each view, as the SQL names it -> the table it shows
        for table, view in self.pol.views.items():
            view_loc = self.pol.view_locs[table]
            if not any(r.table == table and r.command == "select" and not r.columns for r in self.rules):
                fail(
                    view_loc, f"the view {view} shows the rows 'select' allows, so {table} needs a select rule", "AZ402"
                )
            if view == table or any(t.table == view for t in self.types.values()):
                fail(view_loc, f"{view} is a table of the policy; name a new view", "AZ402")
            other = shows.setdefault(qt(view), table)
            if other != table:
                fail(
                    view_loc,
                    f"{view} is already the view of {other} ({self.pol.view_locs[other]}): give {table} a view of "
                    f"its own",
                    "AZ109",
                )
        for sc in self.pol.scopes.values():
            for (kind, qual, word), at in zip(sc.items, sc.spans or [None] * len(sc.items), strict=True):
                if kind == "cmd" and qual and not any(t.table == qual for t in self.types.values()):
                    fail(sc.loc, f"scope {sc.name}: no type maps to {qual}", "AZ404")
                if kind == "perm" and qual:
                    if qual not in self.types:
                        fail(sc.loc, f"scope {sc.name}: unknown type '{qual}'", "AZ201", span=head(at, len(qual)))
                    if word not in self.public_perms(self.T(qual)):
                        fail(
                            sc.loc,
                            f"scope {sc.name}: {qual} has no permission '{word}'",
                            "AZ404",
                            span=at,
                        )
                if kind == "perm" and not qual and not any(word in self.public_perms(t) for t in self.types.values()):
                    fail(sc.loc, f"scope {sc.name}: no type has a permission '{word}'", "AZ404")
        for inv in self.pol.invariants:
            if inv.type not in self.types:
                fail(inv.loc, f"unknown type '{inv.type}'", "AZ201", span=inv.type_span)
        self.check_unused_relations()
        self.check_runtime_permissions()
        self.check_this()

    def check_this(self) -> None:
        """`this.` names the row a condition is about; a caveat has none, and `this` is no other name."""

        def conds(node: Expr) -> list[str]:
            return [x.sql for x in leaves(node) if isinstance(x, Cond)]

        written: list[tuple[str, Loc]] = []
        for t in self.types.values():
            written += [(c, p.loc) for p in t.perms.values() for c in conds(p.expr)]
            written += [(t.where, t.loc)] if t.where else []
            written += [(c, src.loc) for r in t.relations.values() for src in r.sources for c in conditions_of(src)]
        written += [(c, r.loc) for r in self.rules for c in conds(r.expr)]
        written += [(c, i.loc) for i in self.pol.invariants for c in conds(i.expr)]
        for sql, loc in written + [(cv.sql, cv.loc) for cv in self.pol.caveats.values()]:
            mine = reserved_names(sql)
            if mine:
                fail(
                    loc,
                    f"{{{sql}}} names {mine[0]}: names that start with {RESERVED} are rowstile's own (where a "
                    f"query of the condition's could hide the row's alias, the row is called {ROW_ALIAS}); call it "
                    f"something else",
                    "AZ113",
                )
        for sql, loc in written:
            if this_alone(sql):
                fail(
                    loc,
                    f"{{{sql}}}: `this` is the row the condition is about (this.column); call the table something else",
                    "AZ112",
                )
        for cv in self.pol.caveats.values():
            if names_this(cv.sql) or this_alone(cv.sql):
                fail(
                    cv.loc,
                    f"caveat {cv.name}: a caveat is checked with each request, on any share it goes with, "
                    f"so there is no row for `this`: it reads the request (authz.ctx('ip')) and what the "
                    f"share was made with (arg('ip'))",
                    "AZ112",
                )

    def check_runtime_permissions(self) -> None:
        """The permissions the runtime asks for by name (beside `share`, which shared relations check) are
        declared where it asks: anywhere else nothing would ever use them, or what they allow could never be done."""
        owners_of_roles = {self.role_owner_type(t) for t in self.types.values() if t.roles and t.roles_from}
        # the types whose custom roles any owner may make (a roles line without `from`)
        roles_anywhere = [t for t in self.types.values() if t.roles and not t.roles_from]
        for t in self.types.values():
            if "impersonate" in t.perms and t.name != "user":
                fail(
                    t.perms["impersonate"].loc,
                    f"{t.name}.impersonate: authz.view_as asks for `impersonate` on the "
                    f"user type (who may view the app as that user); on {t.name} nothing asks for it",
                    "AZ307",
                )
            if "manage_keys" in t.perms and not t.principal:
                fail(
                    t.perms["manage_keys"].loc,
                    f"{t.name}.manage_keys: API keys are made for types that sign in, "
                    f"and {t.name} doesn't (type {t.name} = ... principal)",
                    "AZ307",
                )
            if "manage_roles" in t.perms and not roles_anywhere and t.name not in owners_of_roles:
                fail(
                    t.perms["manage_roles"].loc,
                    f"{t.name}.manage_roles lets people create custom roles owned by a "
                    f"{t.name}, but no roles line counts them: write `roles : user from <relation to {t.name}>` on "
                    f"the type they are for, and `roles` in the permissions they may give",
                    "AZ307",
                )
            if "break_glass" in t.perms and not any(
                src.kind == "shared" and any(st == "user" and not sr for st, sr in src.subjects)
                for r in t.relations.values()
                for src in r.sources
            ):
                fail(
                    t.perms["break_glass"].loc,
                    f"{t.name}.break_glass: authz.break_glass gives its holder a relation "
                    f"of {t.name} shared with a user for a while, and {t.name} has none (`viewer : user shared`)",
                    "AZ307",
                )
            if t.roles and t.roles_from:
                owner = self.role_owner_type(t)
                if "manage_roles" not in self.T(owner).perms:
                    fail(
                        t.roles[2],
                        f"custom roles on {t.name} are the roles of its {t.roles_from}, which people with "
                        f"manage_roles on a {owner} create, and {owner} has no `can manage_roles`",
                        "AZ307",
                    )
        if roles_anywhere and not any("manage_roles" in t.perms for t in self.types.values()):
            t = roles_anywhere[0]
            assert t.roles is not None
            fail(
                t.roles[2],
                f"custom roles on {t.name} are made by people with manage_roles on their owner, and no "
                f"type has `can manage_roles` (on the org, say: can manage_roles = admin)",
                "AZ307",
            )

    @staticmethod
    def source_table(src: TableSource) -> str:
        """A table source's table."""
        return src.table

    @staticmethod
    def source_obj_columns(src: TableSource) -> Cols:
        """A table source's column(s) naming the object."""
        return src.obj_col

    @staticmethod
    def source_columns(src: Link) -> Cols:
        """A column or table source's subject column(s)."""
        return src.column if src.kind == "column" else src.subj_col

    def pair_alone(self, src: Link) -> tuple[str, ...]:
        """The columns an index on which serves a (type, id) pair's lookup by itself (none without a type column), as
        rowstile indexes and authz.lint() count them. Ids of two columns are compared column by column (key_in): an
        index on them. An id of one column is compared through (CASE WHEN type = 'x' THEN id END), which no index on
        it serves; the type's condition beside it (of_type) is what one serves: an index on the type column."""
        if not src.type_col:
            return ()
        ids = cols(self.source_columns(src))
        return ids if len(ids) > 1 else (src.type_col,)

    def check_key_columns(
        self, t: Type, r: Relation, src: Source, columns: Cols, targets: list[str], side: str
    ) -> None:
        """[a, b] where the key has two columns, one column where it has one."""
        n = len(cols(columns))
        for tn in targets:
            k = len(self.T(tn).key) if tn in self.types else 1
            if n != k:
                shown = "[" + ", ".join(c for c, _ in self.T(tn).key) + "]" if k > 1 else "one column"
                fail(
                    src.loc,
                    f"{t.name}.{r.name}: the {side} is a {tn}, whose key is {shown}, "
                    f"but this source gives {n} column{'s' if n > 1 else ''}"
                    + (": write them in square brackets, [col1, col2]" if k > 1 else ""),
                    "AZ206",
                )

    def check_unused_relations(self) -> None:
        """A relation nothing uses is almost always a typo (a second source of `member` spelt `memeber`
        silently becomes a new relation). Shared relations are exempt: the app may read them through
        authz.list_shares() even before a permission uses them. A name that is neither is said first, on its
        own line: a typo in a relation's only use would otherwise be reported as the relation being unused."""
        used: set[Name] = set()

        def walk(t: Type, node: Expr, loc: Loc) -> None:
            match node:
                case Ref(name):
                    self.lookup(t, name, loc, node.span)
                    used.add((t.name, name))
                case Arrow(rel, perm) | ArrowOn(rel, perm, _):
                    # what a dot follows: a relation to objects, each of which has what follows it
                    r, objects = self.targets(t, rel, loc, head(node.span, len(rel)))
                    for o in objects:
                        self.lookup(o, perm, loc, tail(node.span, len(perm)))
                    used.add((t.name, rel))
                    for st, _sr in r.subjects():
                        used.add((st, perm))
                case Not(item):
                    walk(t, item, loc)
                case And(items) | Or(items):
                    for x in items:
                        walk(t, x, loc)

        for t in self.types.values():
            if t.roles_from:
                used.add((t.name, t.roles_from))  # the roles' owner
            for p in t.perms.values():
                walk(t, p.expr, p.loc)
            for r in t.relations.values():
                for st, sr in r.subjects():
                    if sr and sr != "*":
                        used.add((st, sr))
        for rule in self.rules:
            walk(self.governing(rule.table), rule.expr, rule.loc)
        for inv in self.pol.invariants:
            walk(self.T(inv.type), inv.expr, inv.loc)
        for test in self.tests:
            used.add((test.type or "", test.perm or ""))
        for t in self.types.values():
            for r in t.relations.values():
                if r.synthetic or (t.name, r.name) in used or any(s.kind in ("shared", "roles") for s in r.sources):
                    continue
                fail(
                    r.loc,
                    f"{t.name}.{r.name} is declared but nothing uses it (no permission, rule, test or "
                    f"group refers to it): remove it, or if it is another source of an existing relation, "
                    f"give it that relation's name",
                    "AZ208",
                )

    def lookup(self, t: Type, name: str, loc: Loc, span: Span | None = None) -> None:
        if name in t.perms or name in t.relations:
            return
        known = sorted([n for n in t.relations if not t.relations[n].synthetic] + self.public_perms(t))
        has = f"it has: {', '.join(known)}" if known else "it has none"
        fail(loc, f"{t.name} has no relation or permission '{name}' ({has})", "AZ203", span=span)

    def targets(self, t: Type, relname: str, loc: Loc, span: Span | None = None) -> tuple[Relation, list[Type]]:
        """A relation followed with a dot must point at objects of one or several types; users are rows of
        a type too (`person.has_blocked`), groups (team#member), anyone and links are not. span: where the
        relation is written."""
        if relname not in t.relations:
            self.lookup(t, relname, loc, span)
            fail(loc, f"'{relname}' is a permission; only relations can be followed with a dot", "AZ301", span=span)
        r = t.relations[relname]
        subjects = r.subjects()
        if any(sr or st in ("anyone", "link") for st, sr in subjects):
            fail(
                loc,
                f"{t.name}.{relname} links to groups, anyone or links, so there is nothing to follow",
                "AZ301",
                span=span,
            )
        return r, [self.T(st) for st, _ in subjects]

    # --- dependency analysis: which permissions recurse, and through what ----
    def deps(self, t: Type, node: Expr, out: set[Name]) -> None:
        match node:
            case Ref(name):
                if name in t.perms:
                    out.add((t.name, name))
                elif name in t.relations:
                    self.rel_deps(t, t.relations[name], out, set())
            case Arrow(rel, perm):
                if rel in t.relations:
                    for st, _ in t.relations[rel].subjects():
                        if st in self.types and perm in self.T(st).perms:
                            out.add((st, perm))
            case Not(item):
                self.deps(t, item, out)
            case And(items) | Or(items):
                for x in items:
                    self.deps(t, x, out)

    def rel_deps(self, t: Type, r: Relation, out: set[Name], seen: set[Name]) -> None:
        if (t.name, r.name) in seen:
            return
        seen.add((t.name, r.name))
        for st, sr in r.subjects():
            if st in self.types and sr and sr != "*":
                s = self.T(st)
                if sr in s.perms:
                    out.add((st, sr))
                elif sr in s.relations:
                    self.rel_deps(s, s.relations[sr], out, seen)

    def analyze_recursion(self) -> None:
        graph: dict[Name, set[Name]] = {}
        for t in self.types.values():
            for p in t.perms.values():
                out: set[Name] = set()
                self.deps(t, p.expr, out)
                graph[(t.name, p.name)] = out
        # Tarjan's strongly connected components
        index: dict[Name, int] = {}
        low: dict[Name, int] = {}
        stack: list[Name] = []
        on: set[Name] = set()
        sccs: list[list[Name]] = []
        counter = [0]

        def visit(v: Name) -> None:
            index[v] = low[v] = counter[0]
            counter[0] += 1
            stack.append(v)
            on.add(v)
            for w in graph.get(v, ()):
                if w not in index:
                    visit(w)
                    low[v] = min(low[v], low[w])
                elif w in on:
                    low[v] = min(low[v], index[w])
            if low[v] == index[v]:
                comp: list[Name] = []
                while True:
                    w = stack.pop()
                    on.discard(w)
                    comp.append(w)
                    if w == v:
                        break
                sccs.append(comp)

        for v in graph:
            if v not in index:
                visit(v)
        for comp in sccs:
            members = set(comp)
            if len(comp) == 1 and comp[0] not in graph[comp[0]]:
                continue
            tnames = [tn for tn, _ in comp]
            first = self.T(comp[0][0]).perms[comp[0][1]]
            # a deny's inheritance (its base, split_denies) that comes back to it through another type's permission
            for tn, pn in comp:
                deny = self.T(tn).perms[pn]
                if deny.base is not None and (tn, deny.base) in members and len(set(tnames)) > 1:
                    fail(
                        deny.loc,
                        f"{tn}.{pn} has a deny, so it can only inherit within {tn} (like parent.{pn}), "
                        f"not through permissions of other types",
                        "AZ306",
                    )
            # every dependency inside the component must be a top-level inheritance item. split_inherit reads one
            # (and refuses following a relation to groups, type:*, anyone or links: a tree links objects alone)
            for tn, pn in comp:
                t, perm = self.T(tn), self.T(tn).perms[pn]
                for item in self.top_items(perm):
                    if self.split_inherit(t, perm, item)[0] is not None:
                        continue
                    inner: set[Name] = set()
                    self.deps(t, item, inner)
                    if inner & members and isinstance(item, And):
                        for x in item.items:
                            if (
                                isinstance(x, Arrow)
                                and x.rel in t.relations
                                and any(not sr and (st, x.perm) in members for st, sr in t.relations[x.rel].subjects())
                            ):
                                fail(
                                    perm.loc,
                                    f"inheritance through {x.rel} can only be narrowed with "
                                    f"{{conditions}} on the row, e.g. ({x.rel}.{pn} and {{inherit}})",
                                    "AZ304",
                                )
                    if inner & members:
                        fail(perm.loc, DEPENDS_ON_ITSELF.format(f"{tn}.{pn}"), "AZ302")
            if len(set(tnames)) != len(tnames):
                fail(
                    first.loc,
                    "permissions "
                    + ", ".join([f"{a}.{b}" for a, b in sorted(comp)])
                    + " inherit through each other; a recursion can use one permission per type",
                    "AZ302",
                )
            key = tuple(sorted(comp))
            self.scc_members[key] = sorted(comp)
            for v in comp:
                self.recursive[v] = key

    @staticmethod
    def top_items(perm: Perm) -> list[Expr]:
        return perm.expr.items if isinstance(perm.expr, Or) else [perm.expr]

    def split_inherit(self, t: Type, perm: Perm, item: Expr) -> tuple[Arrow, list[str]] | tuple[None, None]:
        """(arrow, [conditions]) for `rel.perm2` or `(rel.perm2 and {c} and not {c} ...)`,
        where rel points at objects; (None, None) otherwise."""
        conds: list[str] = []
        if isinstance(item, And):
            arrows = [x for x in item.items if isinstance(x, Arrow)]
            if len(arrows) != 1:
                return None, None
            for x in item.items:
                match x:
                    case Cond(sql):
                        conds.append(sql)
                    case Not(Cond(sql)):
                        conds.append(f"NOT coalesce(({sql}), false)")
                    case Arrow(_, _):
                        pass
                    case _:
                        return None, None
            item = arrows[0]
        if not isinstance(item, Arrow) or item.rel not in t.relations:
            return None, None
        self.targets(t, item.rel, perm.loc)  # following users is an error in any case
        return item, conds

    def recursive_parts(self, t: Type, perm: Perm, item: Expr) -> tuple[list[Inherit], Expr | None]:
        """For an item of a recursive permission: the inheritance edges it makes
        [(relation, condition, target type)], and what remains as a plain item."""
        key = self.recursive[(t.name, perm.name)]
        members = set(self.scc_members[key])
        arrow, conds = self.split_inherit(t, perm, item)
        if arrow is None or conds is None:
            # a plain item: analyze_recursion refused one that narrows the inheritance with more than conditions (AZ304)
            return [], item
        r = t.relations[arrow.rel]
        inside = [st for st, _ in r.subjects() if (st, arrow.perm) in members]
        if not inside:
            return [], item
        for c in conds:
            check_stable_condition(c, perm.loc)
        cond = None
        if conds:
            cond = conds[0] if len(conds) == 1 else " AND ".join(f"coalesce(({c}), false)" for c in conds)
            self.cond_lines.setdefault((t.name, cond), perm.loc)
        outside = [st for st, _ in r.subjects() if st not in inside]
        rest: Expr | None = None
        if outside:
            rest = ArrowOn(arrow.rel, arrow.perm, tuple(outside), arrow.span)
            if conds:
                rest = And([rest, *(Cond(c) for c in conds)])
        return [(arrow.rel, cond, st) for st in inside], rest

    # --- views ------------------------------------------------------------
    def where_holds(self, t: Type, id_sql: str) -> str:
        """The t whose id is id_sql passes the type's where. One that fails it holds nothing, and nothing passes
        through it: every view, walk and check of one object asks this."""
        assert t.where is not None, f"{t.name} has no where"
        return (
            f"EXISTS (SELECT 1 FROM {qt(t.table)} w WHERE {self.key_is(t, 'w', id_sql)} "
            f"AND coalesce(({row_cond(t.where, 'w')}), false))"
        )

    def where_kept(self, t: Type, sql: str) -> str:
        """sql (a query of ids of t) without the ids that fail the type's where."""
        return f"SELECT x.id FROM (\n  {sql}) x\n  WHERE {self.where_holds(t, 'x.id')}" if t.where else sql

    # Every relation and permission becomes a plain view in authz_int, which the
    # planner can flatten and push lookups into, plus a security-barrier view in
    # authz_gen with the same name: the only thing app roles can read, and it
    # only returns ids the current user holds.
    def add_view(self, name: str, sql: str, header: str, t: Type, public: bool = True) -> None:
        sql = self.where_kept(t, sql)
        self.view_sql.append(
            f"{header}CREATE VIEW authz_int.{q(name)} AS\n  {sql};"
            + (
                f"\nCREATE VIEW authz_gen.{q(name)} WITH (security_barrier) AS SELECT id FROM authz_int.{q(name)};"
                if public
                else ""
            )
        )

    def begin_view(self, name: str, loc: Loc, what: str) -> bool:
        state = self.view_state.get(name)
        if state == "done":
            return False
        if state == "busy":
            fail(
                loc,
                f"{what} depends on itself; a permission can only recurse as "
                f"'or rel.perm' through a relation to objects, and a group only as "
                f"'member : group#member'",
                "AZ302",
            )
        self.view_state[name] = "busy"
        return True

    def view_ref(self, t: Type, name: str, loc: Loc) -> str:
        self.lookup(t, name, loc)
        if name in t.perms:
            self.ensure_view(t, t.perms[name])
            return f"{t.name}__{name}"
        return self.ensure_rel_view(t, t.relations[name], loc)

    def lookup_sql(self, view: str, expr: str, point: bool = False) -> str:
        """Whether the user holds view's relation or permission on the object expr. point=True is for
        checks of one row at a time (writes, authz.can): recursive permissions then test that one
        object's ancestors (its __has function) instead of every object the user starts from."""
        if point and view in self.point_checks:
            return f"authz_gen.{q(self.point_checks[view])}({expr})"
        if view in self.direct_checks:
            # what the object's own columns give first: one index lookup, where most users who reach a
            # lot (an org admin: every folder) stop, instead of building every object they start from
            return (
                f"(EXISTS (SELECT 1 FROM authz_gen.{q(self.direct_checks[view])} v WHERE v.id = {expr})"
                f"\n    OR EXISTS (SELECT 1 FROM authz_gen.{q(view)} v WHERE v.id = {expr}))"
            )
        if view in self.nested:
            # a user's memberships are few: work them out once per query
            return f"coalesce({expr} = ANY ({self.group_ids(view)}), false)"
        return f"EXISTS (SELECT 1 FROM authz_gen.{q(view)} v WHERE v.id = {expr})"

    def group_ids(self, view: str, text: bool = False) -> str:
        """A user's nested groups as an array, worked out once per statement (a scalar subquery)."""
        return f"(SELECT authz_gen.{q(view + '__ids')}())::{'text' if text else self.nested[view]}[]"

    def ids_in(self, view: str, text: bool = False) -> str:
        """A match for 'is one of the ids in this view'."""
        col = "id::text" if text else "id"
        if view in self.nested:
            return f"= ANY ({self.group_ids(view, text)})"
        return f"IN (SELECT {col} FROM authz_int.{q(view)})"

    # --- the SQL for one source of a relation ---------------------------------
    def live(self, alias: str = "g") -> str:
        """A share counts between its start and its expiry, and while its caveat holds."""
        caveats = self.pol.caveats
        if caveats:
            cases = " ".join(
                f"WHEN {lit(c.name)} THEN coalesce(({self.caveat_sql(c, alias)}), false)" for c in caveats.values()
            )
            cav = f"({alias}.caveat IS NULL OR CASE {alias}.caveat {cases} ELSE false END)"
        else:
            cav = f"{alias}.caveat IS NULL"
        return (
            f"({alias}.expires_at IS NULL OR {alias}.expires_at > now()) "
            f"AND ({alias}.starts_at IS NULL OR {alias}.starts_at <= now()) AND {cav}"
        )

    @staticmethod
    def caveat_sql(c: Caveat, alias: str = "g") -> str:
        return with_uid(CAVEAT_ARG.sub(rf"({alias}.caveat_args ->> '\1')", c.sql))

    # --- functions over every type: one branch per type, the id converted to its key ----------------
    def id_vars(self) -> str:
        return "".join(f" v_{pt} {pt};" for pt in sorted({t.pktype for t in self.types.values()}))

    def dispatch_type(self, per_type: Callable[[Type], str], missing_type: str = NO_SUCH_TYPE) -> str:
        """CASE over types, with p_id checked and converted to the type's key in v_<pktype>."""
        branches = []
        for t in self.types.values():
            body = per_type(t)
            branches.append(
                f"    WHEN {lit(t.name)} THEN\n"
                f"      IF NOT pg_catalog.pg_input_is_valid(p_id, {lit(t.keytype)}) THEN RETURN {self._invalid}; END IF;\n"
                f"      v_{t.pktype} := p_id::{t.keytype}{'::text' if t.composite else ''};\n{body}"
            )
        return (
            ("  CASE p_type\n" + "\n".join(branches) + f"\n    ELSE\n      {missing_type}\n  END CASE;")
            if branches
            else f"  {missing_type}"
        )

    # --- keys: one column, or several (a composite key, whose ids are its canonical row text) ----
    @staticmethod
    def pk(t: Type) -> str:
        """The key column of a type with a key of one column."""
        assert t.pk is not None, f"{t.name} has a composite key"
        return t.pk

    def key(self, t: Type, a: str) -> str:
        """The id of t's row aliased a."""
        if not t.composite:
            return f"{a}.{q(self.pk(t))}"
        return "ROW(" + ", ".join(f"{a}.{q(c)}::{ty}" for c, ty in t.key) + ")::text"

    def ref(self, t: Type, a: str, columns: Cols) -> str:
        """The id of the t that row a's columns point at; NULL when any of them is."""
        columns = cols(columns)
        if not t.composite:
            return f"{a}.{q(columns[0])}"
        return (
            f"(CASE WHEN ({', '.join(f'{a}.{q(c)}' for c in columns)}) IS NOT NULL THEN ROW("
            + ", ".join(f"{a}.{q(c)}::{ty}" for c, (_, ty) in zip(columns, t.key, strict=True))
            + ")::text END)"
        )

    def key_is(self, t: Type, a: str, v: str, columns: Cols | None = None) -> str:
        """Row a's columns (t's key by default) hold the id v of a t, compared column by column so
        an index on them is used."""
        columns = cols(columns) if columns else tuple(c for c, _ in t.key)
        if not t.composite:
            return f"{a}.{q(columns[0])} = {v}"
        k = f"(({v})::{t.keytype})"
        return f"({', '.join(f'{a}.{q(c)}' for c in columns)}) = ({', '.join(f'{k}.{q(kc)}' for kc, _ in t.key)})"

    def key_in(self, t: Type, a: str, sub: str, columns: Cols | None = None) -> str:
        """Row a's columns (t's key by default) hold one of the ids that sub (a query of id) selects."""
        columns = cols(columns) if columns else tuple(c for c, _ in t.key)
        if not t.composite:
            return f"{a}.{q(columns[0])} IN ({sub})"
        return (
            f"({', '.join(f'{a}.{q(c)}' for c in columns)}) IN (SELECT "
            + ", ".join(f"(k.k).{q(kc)}" for kc, _ in t.key)
            + f" FROM (SELECT x.id::{t.keytype} AS k FROM ({sub}) x) k)"
        )

    def bare_key_text(self, t: Type) -> str:
        """A row's id as text, its columns unqualified (for dynamic SQL over the table or a view of it)."""
        if not t.composite:
            return f"{q(self.pk(t))}::text"
        return "ROW(" + ", ".join(f"{q(c)}::{ty}" for c, ty in t.key) + ")::text"

    def key_text(self, t: Type, a: str) -> str:
        return self.key(t, a) if t.composite else f"{self.key(t, a)}::text"

    def ref_text(self, t: Type, a: str, columns: Cols) -> str:
        return self.ref(t, a, columns) if t.composite else f"{self.ref(t, a, columns)}::text"

    def key_any(self, t: Type, a: str, arr: str) -> str:
        """Row a's key is in the array arr."""
        if not t.composite:
            return f"{self.key(t, a)} = ANY ({arr})"
        return self.key_in(t, a, f"SELECT unnest({arr}) AS id")

    def of_type(self, src: Link, a: str, subj_type: str, sql: str) -> str:
        """sql, which compares the id of row a's (type, id) pair with ids of subj_type, with the type's own condition
        beside it: the same answer (the pair's id is NULL on the other types' rows, and so is sql), and an index on
        (type, id) serves the type's part at least. A source without a type column: sql as it is."""
        return f"({a}.{q(src.type_col)} = {lit(subj_type)} AND {sql})" if src.type_col else sql

    def subject_is(self, src: Link, a: str, subj_type: str, v: str) -> str:
        """A column/table source's subject columns on row a hold v, an id of subj_type."""
        st = self.T(subj_type)
        if not st.composite:
            return self.of_type(src, a, subj_type, f"{self.subject_id(src, a, subj_type)} = {v}")
        sql = self.key_is(st, a, v, self.source_columns(src))
        return sql + (f" AND {a}.{q(src.type_col)} = {lit(subj_type)}" if src.type_col else "")

    def subject_in(self, src: Link, a: str, subj_type: str, view: str) -> str:
        """A column/table source's subject columns on row a hold one of the subj_type ids in view. A composite
        key's columns are compared column by column (key_in), so an index on them serves the lookup: its
        built id, compared as text, would need every row read."""
        st = self.T(subj_type)
        if not st.composite:
            return self.of_type(src, a, subj_type, f"{self.subject_id(src, a, subj_type)} {self.ids_in(view)}")
        ids = (
            f"SELECT unnest({self.group_ids(view)}) AS id"
            if view in self.nested
            else f"SELECT id FROM authz_int.{q(view)}"
        )
        sql = self.key_in(st, a, ids, self.source_columns(src))
        return sql + (f" AND {a}.{q(src.type_col)} = {lit(subj_type)}" if src.type_col else "")

    def subject_id(self, src: Link, alias: str, subj_type: str) -> str:
        """The subject id of a column/table source, typed as subj_type's key."""
        col = self.source_columns(src)
        st = self.types.get(subj_type)
        if src.type_col is None:
            return self.ref(st, alias, col) if st else f"{alias}.{q(cols(col)[0])}"
        assert st is not None, f"{subj_type}: a source with a type column links to types"
        if st.composite:
            return f"(CASE WHEN {alias}.{q(src.type_col)} = {lit(subj_type)} THEN {self.ref(st, alias, col)} END)"
        return (
            f"(CASE WHEN {alias}.{q(src.type_col)} = {lit(subj_type)} THEN {alias}.{q(cols(col)[0])} END)::{st.pktype}"
        )

    def is_principal(self, st: str) -> bool:
        return st in self.types and self.T(st).principal

    def me(self, st: str, text: bool = False) -> str:
        """The signed-in principal's id if it is a st (NULL otherwise): authz.uid() for users."""
        if st == "user":
            return UIDT if text else UID
        return f"(SELECT authz_int.{q(st + '__me')}(){'::text' if text else ''})"

    def source_sql(self, t: Type, r: Relation, src: Source, subj: Subject) -> str | None:
        """Ids of t linked through one source of relation r to what the current
        principal is (subject subj: a user or other principal, a group, user:*, anyone or a link)."""
        st, sr = subj
        if src.kind == "column" or src.kind == "table":
            a = "r" if src.kind == "column" else "s"
            if self.is_principal(st) and not sr:
                match = self.of_type(src, a, st, f"{self.subject_id(src, a, st)} = {self.me(st)}")
            elif sr:
                match = self.subject_in(src, a, st, self.view_ref(self.T(st), sr, src.loc))
            else:
                return None
            if src.kind == "column":
                return f"SELECT {self.key(t, 'r')} AS id FROM {qt(t.table)} r WHERE {match}"
            extra = f" AND coalesce(({row_cond(src.where, 's')}), false)" if src.where else ""
            return f"SELECT {self.ref(t, 's', src.obj_col)} AS id FROM {qt(src.table)} s WHERE {match}{extra}"
        # shares and custom roles live in authz.shares
        who = self.share_subject_sql(st, sr, src)
        if who is None:
            return None
        if src.kind == "roles":
            rel = self.role_rel_sql(t, src, f"g.object_id::{t.pktype}")
        else:
            rel = f"g.relation = {lit(r.name)}"
        return (
            f"SELECT g.object_id::{t.pktype} AS id FROM authz.shares g "
            f"WHERE g.object_type = {lit(t.name)} AND {rel} AND {who} AND {self.live()}"
        )

    def share_subject_sql(self, st: str, sr: str | None, src: Source) -> str | None:
        """The shares (g, in authz.shares) to subject st#sr that give the signed-in principal what they share: to them,
        to a group they are in, to every signed-in st, to anyone, or to a link they presented. None: no share can."""
        if sr == "*":
            return (
                f"g.subject_type = {lit(st)} AND g.subject_relation = '' AND g.subject_id = '*' "
                f"AND {self.me(st)} IS NOT NULL"
            )
        if st == "anyone":
            return "g.subject_type = 'anyone'"
        if st == "link":
            return f"g.subject_type = 'link' AND g.subject_id = ANY ({LINKS})"
        if self.is_principal(st) and not sr:
            return f"g.subject_type = {lit(st)} AND g.subject_relation = '' AND g.subject_id = {self.me(st, text=True)}"
        if sr:
            inner = self.view_ref(self.T(st), sr, src.loc)
            return (
                f"g.subject_type = {lit(st)} AND g.subject_relation = {lit(sr)} "
                f"AND g.subject_id {self.ids_in(inner, text=True)}"
            )
        return None

    def pair_sql(
        self,
        t: Type,
        r: Relation,
        src: Source,
        subj_type: str,
        subj_rel: str | None,
        obj: str,
        subj: str,
        extra: str = "",
        tree: bool = False,
        match: tuple[str, str] | None = None,
    ) -> str:
        """(object id, subject id) pairs of one source of relation r, for subjects of
        type subj_type (#subj_rel). Links used for inheritance ignore expiry: shares
        on them can't have any (a stored closure can't follow the clock). match=(side, v):
        only the pairs whose object ('obj') or subject ('subj') is v, looked up column by
        column (for composite keys, where a filter on the built id can't use an index)."""
        s = self.T(subj_type)
        side, v = match or (None, "")
        if src.kind == "column" or src.kind == "table":
            a = "r" if src.kind == "column" else "s"
            m = ""
            if side == "obj":
                m = " AND " + (self.key_is(t, a, v, src.obj_col) if src.kind == "table" else self.key_is(t, a, v))
            elif side == "subj":
                m = " AND " + self.subject_is(src, a, subj_type, v)
            sid = self.subject_id(src, a, subj_type)
            if src.kind == "column":
                return (
                    f"SELECT {extra}{self.key(t, 'r')} AS {obj}, {sid} AS {subj} "
                    f"FROM {qt(t.table)} r WHERE {sid} IS NOT NULL{m}"
                )
            where = f" AND coalesce(({on_row(src.where, 's')}), false)" if src.where else ""
            oid = self.ref(t, "s", src.obj_col)
            return (
                f"SELECT {extra}{oid} AS {obj}, {sid} AS {subj} "
                f"FROM {qt(src.table)} s WHERE {sid} IS NOT NULL "
                f"AND {oid} IS NOT NULL{where}{m}"
            )
        live = "" if tree else f" AND {self.live()}"
        m = {"obj": f" AND g.object_id = ({v})::text", "subj": f" AND g.subject_id = ({v})::text"}.get(side or "", "")
        return (
            f"SELECT {extra}g.object_id::{t.pktype} AS {obj}, g.subject_id::{s.pktype} AS {subj} "
            f"FROM authz.shares g WHERE g.object_type = {lit(t.name)} AND g.relation = {lit(r.name)} "
            f"AND g.subject_type = {lit(subj_type)} AND g.subject_relation = {lit(subj_rel)}{live}{m}"
        )

    def is_group_loop(self, t: Type, r: Relation, st: str, sr: str | None) -> bool:
        return st == t.name and sr == r.name

    def ensure_rel_view(self, t: Type, r: Relation, loc: Loc, ext: bool = False) -> str:
        """Ids of t the user holds relation r on. ext=True leaves out column
        sources (policies check those on the row itself)."""
        name = f"{t.name}__{r.name}" + ("__ext" if ext else "")
        if not self.begin_view(name, r.loc, f"{t.name}.{r.name}"):
            return name
        direct: list[str] = []
        loops: list[str] = []
        looked_up: list[str] = []  # the same, each one's groups found column by column (match)
        loop_kinds: set[str] = set()
        for src in r.sources:
            if ext and src.kind == "column":
                continue
            for st, sr in src.subjects:
                if sr and sr != "*" and self.is_group_loop(t, r, st, sr):
                    loops.append(self.pair_sql(t, r, src, st, sr, "obj", "subj"))
                    looked_up.append(self.pair_sql(t, r, src, st, sr, "obj", "subj", match=("subj", "m.id")))
                    loop_kinds.add(src.kind)
                    continue
                part = self.source_sql(t, r, src, (st, sr))
                if part:
                    direct.append(part)
        if not direct:
            if loops:
                fail(r.loc, f"{t.name}.{r.name} only contains itself; add a source of users", "AZ209")
            # the column sources left out (row_relation checks them on the row) may give users: then these give none
            if ext and any(
                sr or self.is_principal(st) for src in r.sources if src.kind == "column" for st, sr in src.subjects
            ):
                direct.append(f"SELECT NULL::{t.pktype} AS id WHERE false")
            else:
                fail(
                    loc,
                    f"{t.name}.{r.name} links to {r.subjects()[0][0]} objects, not users; "
                    f"follow it with a dot, e.g. {r.name}.view",
                    "AZ301",
                )
        if loops:
            # nested groups: members of a sub-group are members of the group, to
            # any depth; UNION stops on loops in the nesting. Nested through columns or
            # tables, each step looks up the groups containing each one found (an index
            # lookup per group) rather than joining every row at every step; as a subquery
            # per row, not a LATERAL join, which Postgres estimates so high that JIT compiles
            # each read. Nested through shares, even this estimates high (the random-change
            # tests: 5.8M, JIT inlining every read), so those keep the join.
            # A group that fails the type's where passes nothing on: the walk doesn't go through it.
            valid = self.where_holds(t, "m.id") if t.where else ""
            if loop_kinds <= {"column", "table"} and t.composite:
                # a composite id compared as text would read every row at each step: its columns are looked up
                step = f"SELECT unnest(ARRAY(SELECT e.obj FROM (\n  {union(looked_up)}) e)) FROM m" + (
                    f"\n    WHERE {valid}" if valid else ""
                )
            elif loop_kinds <= {"column", "table"}:
                step = f"SELECT unnest(ARRAY(SELECT e.obj FROM (\n  {union(loops)}) e WHERE e.subj = m.id)) FROM m" + (
                    f"\n    WHERE {valid}" if valid else ""
                )
            else:
                step = f"SELECT e.obj FROM (\n  {union(loops)}) e JOIN m ON e.subj = m.id" + (
                    f"\n    WHERE {valid}" if valid else ""
                )
            sql = (
                f"WITH RECURSIVE m(id) AS (\n"
                f"    SELECT id FROM (\n  {union(direct)}) d\n"
                f"    UNION\n"
                f"    {step})\n"
                f"  SELECT id FROM m"
            )
            self.nested[name] = t.pktype
        else:
            sql = union(direct)
        roles = r.sources[0]
        label = f"custom roles granting {roles.perm}" if r.synthetic and roles.kind == "roles" else r.name
        header = f"-- {t.name}.{label}" + (" (sources other than columns)" if ext else "") + f" ({r.loc})\n"
        self.add_view(name, sql, header, t)
        if name in self.nested:
            # what reads use: the walk behind a function, so a query's plan sees one call instead of a
            # recursive walk, whose estimate would make JIT compile every read that uses groups
            self.view_sql.append(
                f"-- {t.name}.{label} for the user signed in, as an array (reads ask once per statement)\n"
                f"CREATE FUNCTION authz_gen.{q(name + '__ids')}() RETURNS {t.pktype}[]\n"
                f"LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path FROM CURRENT AS $f$\n"
                f"BEGIN\n  RETURN ARRAY(SELECT id FROM authz_int.{q(name)});\nEND $f$;"
            )
        self.view_state[name] = "done"
        return name

    def ensure_link_view(
        self, t: Type, r: Relation, perm_name: str, loc: Loc, targets: Sequence[str] | None = None, ext: bool = False
    ) -> str:
        """Ids of t whose r points at something the user holds perm_name on."""
        all_targets = [st for st, _ in r.subjects()]
        targets = list(targets) if targets else all_targets
        suffix = "" if targets == all_targets else "__on_" + "_".join(targets)
        view = f"{t.name}__{r.name}__{perm_name}{suffix}" + ("__ext" if ext else "")
        if not self.begin_view(view, loc, f"{t.name}.{r.name}.{perm_name}"):
            return view
        parts = []
        for st in targets:
            inner = self.view_ref(self.T(st), perm_name, loc)
            for src in r.sources:
                if ext and src.kind == "column":
                    continue
                if (st, None) not in src.subjects:
                    continue
                if src.kind == "column":
                    parts.append(
                        f"SELECT {self.key(t, 'r')} AS id FROM {qt(t.table)} r "
                        f"WHERE {self.subject_in(src, 'r', st, inner)}"
                    )
                elif src.kind == "table":
                    assert src.table is not None and src.obj_col is not None
                    extra = f" AND coalesce(({row_cond(src.where, 's')}), false)" if src.where else ""
                    parts.append(
                        f"SELECT {self.ref(t, 's', src.obj_col)} AS id FROM {qt(src.table)} s "
                        f"WHERE {self.subject_in(src, 's', st, inner)}{extra}"
                    )
                else:
                    parts.append(
                        f"SELECT g.object_id::{t.pktype} AS id FROM authz.shares g "
                        f"WHERE g.object_type = {lit(t.name)} AND g.relation = {lit(r.name)} "
                        f"AND g.subject_type = {lit(st)} AND g.subject_relation = '' "
                        f"AND g.subject_id {self.ids_in(inner, text=True)} AND {self.live()}"
                    )
        # each type is named by a source read here: without the column sources (ext, row_arrow), the arrow follows
        # every type of the relation, which the sources left name some of
        assert parts, f"no source of {t.name}.{r.name} names {', '.join(targets)}"
        self.add_view(view, union(parts), f"-- {t.name}.{r.name}.{perm_name}\n", t)
        self.view_state[view] = "done"
        return view

    # --- permissions ------------------------------------------------------
    def perm_edges(self, t: Type, perm: Perm) -> Edges | None:
        """Inheritance edges of a recursive permission: frozenset of
        (child type, relation, condition, parent type)."""
        if (t.name, perm.name) not in self.recursive:
            return None
        edges: set[Edge] = set()
        for item in self.top_items(perm):
            es, _ = self.recursive_parts(t, perm, item)
            edges |= {(t.name, rel, cond, st) for rel, cond, st in es}
        return frozenset(edges)

    def own_base_items(self, t: Type, perm: Perm) -> list[Expr]:
        """What grants t.perm besides inheritance (empty: only inheritance)."""
        items = []
        for item in self.top_items(perm):
            rest = self.recursive_parts(t, perm, item)[1] if (t.name, perm.name) in self.recursive else item
            if rest is not None:
                items.append(rest)
        return items

    def base_items(self, t: Type, perm: Perm) -> list[Expr]:
        """t.perm's starting points. A permission of a loop through several types may have none of its own when
        another one of the loop has some (a domain's edit is only its org's, and an org's owner edits it): the
        walk starts there. A loop where none has any grants nothing to anyone: that is the mistake."""
        items = self.own_base_items(t, perm)
        if not items:
            key = self.recursive.get((t.name, perm.name))
            members = self.scc_members[key] if key is not None else [(t.name, perm.name)]
            if len(members) == 1 or not any(
                self.own_base_items(self.T(tn), self.T(tn).perms[pn]) for tn, pn in members
            ):
                fail(perm.loc, f"{t.name}.{perm.name} needs a starting point besides inheritance", "AZ303")
        return items

    def scc_edges(self, key: SccKey) -> Edges:
        edges: set[Edge] = set()
        for tn, pn in self.scc_members[key]:
            edges |= self.perm_edges(self.T(tn), self.T(tn).perms[pn]) or frozenset()
        return frozenset(edges)

    def ensure_view(self, t: Type, perm: Perm) -> None:
        name = f"{t.name}__{perm.name}"
        if not self.begin_view(name, perm.loc, f"{t.name}.{perm.name}"):
            return
        header = f"-- {t.name}.{perm.name} ({perm.loc}): {perm.src}\n"
        key = self.recursive.get((t.name, perm.name))
        if key is None:
            # as the row checks do (row_sql): the permissions of its type written out in place, so a lookup
            # another one covers is dropped. view names parent.view and, through edit, parent.edit, which
            # parent.view includes: named as views, each would be written out again at every level above
            items = self.prune(t, self.flat_items(t, perm, views=True))
            sql = union([self.set_sql(t, i, perm.loc) for i in items])
        else:
            members = self.scc_members[key]
            edges = self.scc_edges(key)
            if len(members) == 1:
                # one type: start from what the user holds directly, then walk down.
                # The starting points are a function, so their plan is made once per
                # session instead of with every query that uses this permission. Called in FROM, never in a
                # select list: a function scan keeps the rows it read and rereads them when a nested loop
                # scans it again, where a select list would run the function again for each outer row.
                tree = self.ensure_tree(t, edges)
                start = self.start_function(t, perm, (t.name, edges))
                sql = (
                    f"SELECT c.descendant AS id FROM authz_int.{q(tree)} c\n"
                    f"  WHERE c.ancestor IN (SELECT s.id FROM {start}() s(id))"
                )
                self.add_view(name, sql, header, t)
                self.view_state[name] = "done"
                self.point_check_function(t, perm, tree, (t.name, edges))
                self.direct_view(t, perm, name)
                return
            tree = self.ensure_multi_tree(key, edges)
            starts = []
            for tn, pn in members:
                # the other members' views are built from the same closure
                mt = self.T(tn)
                fn = self.start_function(mt, mt.perms[pn], None)
                starts.append(f"SELECT {lit(tn)}::text, x::text FROM {fn}() x")
            sql = (
                f"SELECT c.did::{t.pktype} AS id FROM authz_int.{q(tree)} c\n"
                f"  WHERE c.dtype = {lit(t.name)} AND (c.atype, c.aid) IN (\n  "
                + "\n  UNION ALL\n  ".join(starts)
                + ")"
            )
        self.add_view(name, sql, header, t)
        self.view_state[name] = "done"

    def start_sql(self, t: Type, perm: Perm, flatten: Flatten) -> str:
        """The ids where a recursive permission starts for the current user: what it holds directly (none, for
        a permission of a loop that only inherits: base_items)."""
        items = self.base_items(t, perm)
        body = (
            union([self.set_sql(t, i, perm.loc, flatten) for i in items])
            if items
            else f"SELECT NULL::{t.pktype} AS id WHERE false"
        )
        return self.where_kept(t, body)

    def point_check_function(self, t: Type, perm: Perm, tree: str, flatten: Flatten) -> None:
        """t.perm for one object: its ancestors (and itself) tested against the starting points, one index
        lookup each. The view builds every starting point first, which is right for lists and slow for
        one object when the user starts from many (an org admin: every folder). PL/pgSQL, so its plan
        is made once per session. In authz_gen, since the app role calls it (rules and their triggers)."""
        name = f"{t.name}__{perm.name}__has"
        self.point_checks[f"{t.name}__{perm.name}"] = name
        # like every view (add_view): an object failing its type's where holds nothing
        where = f"\n    AND {self.where_holds(t, 'p_id')}" if t.where else ""
        self.view_sql.append(
            f"-- {t.name}.{perm.name} for one object (checks of single rows and authz.can)\n"
            f"CREATE FUNCTION authz_gen.{q(name)}(p_id {t.pktype}) RETURNS boolean\n"
            f"LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path FROM CURRENT AS $f$\n"
            f"BEGIN\n"
            f"  RETURN EXISTS (SELECT 1 FROM authz_int.{q(tree)} c\n"
            f"    WHERE c.descendant = p_id\n"
            f"      AND EXISTS (SELECT 1 FROM (\n  {self.start_sql(t, perm, flatten)}) s WHERE s.id = c.ancestor)){where};\n"
            f"END $f$;"
        )

    def direct_view(self, t: Type, perm: Perm, view: str) -> None:
        """The starting points of t.perm that an object's own columns decide (owner, org.admin, {cond}).
        Checked on a row before the whole permission (lookup_sql): users whose starting points are many
        get them this way (an org admin starts from every folder of the org), and it costs one index
        lookup. Shares and link tables are left out: they make few starting points, and looking them up
        for every row would slow down everyone else."""
        edges = self.perm_edges(t, perm) or frozenset()
        items = [i for i in self.start_items(t, perm, edges) if self.item_cost(t, i) < 2 and self.own_columns(t, i)]
        if not items:
            return
        sql = union([self.set_sql(t, i, perm.loc) for i in items])
        same = [v for v, s in self.direct_sql.items() if s == sql]
        if same:
            self.direct_checks[view] = same[0]
            return
        name = f"{t.name}__{perm.name}__direct"
        self.add_view(name, sql, f"-- {t.name}.{perm.name}: what the object's own columns give\n", t)
        self.view_state[name] = "done"
        self.direct_sql[name] = sql
        self.direct_checks[view] = name

    def start_items(self, t: Type, perm: Perm, edges: Edges) -> list[Expr]:
        """A recursive permission's starting items, with same-type permissions that one walk covers
        (like start_sql's flatten) replaced by their own starting items."""
        out = []
        for item in self.base_items(t, perm):
            if isinstance(item, Ref) and item.name in t.perms:
                inner = t.perms[item.name]
                e = self.perm_edges(t, inner)
                if e is not None and e <= edges and len(self.scc_members[self.recursive[(t.name, inner.name)]]) == 1:
                    out += self.start_items(t, inner, edges)
                    continue
            out.append(item)
        return out

    def own_columns(self, t: Type, item: Expr) -> bool:
        """Whether item is decided by t's own columns (and small per-user sets), not by other rows of t."""
        match item:
            case Cond(sql):
                return not reads_tables(sql)
            case Not(inner):
                return self.own_columns(t, inner)
            case And(items) | Or(items):
                return all(self.own_columns(t, x) for x in items)
            case Ref(name) | Arrow(name, _) | ArrowOn(name, _, _) if name in t.relations:
                r = t.relations[name]
                return all(src.kind == "column" for src in r.sources) and not any(
                    sr and sr != "*" and self.is_group_loop(t, r, st, sr) for st, sr in r.subjects()
                )
        return False

    def item_cost(self, t: Type, item: Expr) -> int:
        """Rough cost of checking item on one row, for ordering: 0 columns only, 1 lookups in small
        per-user sets, 2 recursive permissions (their views build every starting point)."""
        match item:
            case Cond(sql):
                return 1 if reads_tables(sql) else 0
            case Not(inner):
                return self.item_cost(t, inner)
            case And(items) | Or(items):
                return max(self.item_cost(t, x) for x in items)
            case Arrow(rel, perm) | ArrowOn(rel, perm, _):
                r = t.relations.get(rel)
                assert r is not None, "validate refuses a dot that follows anything but a relation (AZ301)"
                on = only_on(item)
                names = on if on is not None else [st for st, _ in r.subjects()]
                return max(max(1, self.item_cost(self.T(st), Ref(perm))) for st in names)
            case _:
                assert isinstance(item, Ref), f"not an expression: {item!r}"
                name = item.name
                if name in t.relations:
                    rn = t.relations[name]
                    direct = all(src.kind == "column" for src in rn.sources) and all(
                        self.is_principal(st) and not sr for st, sr in rn.subjects()
                    )
                    return 0 if direct else 1
                if (t.name, name) in self.recursive:
                    return 2
                perm_ = t.perms.get(name)
                return max((self.item_cost(t, i) for i in self.top_items(perm_)), default=0) if perm_ else 2

    def start_function(self, t: Type, perm: Perm, flatten: Flatten) -> str:
        name = f"{t.name}__{perm.name}__start"
        fn = f"authz_int.{q(name)}"
        if self.view_state.get(name) == "done":
            return fn
        self.view_state[name] = "done"
        body = self.start_sql(t, perm, flatten)
        self.view_sql.append(
            f"-- {t.name}.{perm.name}: where inheritance starts, for the current user\n"
            f"CREATE FUNCTION {fn}() RETURNS SETOF {t.pktype}\n"
            f"LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path FROM CURRENT ROWS 100 AS $f$\n"
            f"BEGIN\n  RETURN QUERY\n  {body};\nEND $f$;"
        )
        return fn

    # --- set SQL: ids of t for which the expression holds -----------------
    def set_sql(self, t: Type, node: Expr, loc: Loc, flatten: Flatten = None) -> str:
        rid, tbl = self.key(t, "r"), qt(t.table)
        match node:
            case Ref(name):
                self.lookup(t, name, loc)
                if name in t.relations:
                    return f"SELECT id FROM authz_int.{q(self.ensure_rel_view(t, t.relations[name], loc))}"
                perm = t.perms[name]
                edges = self.perm_edges(t, perm)
                if (
                    flatten
                    and edges is not None
                    and flatten[0] == t.name
                    and edges <= flatten[1]
                    and len(self.scc_members[self.recursive[(t.name, perm.name)]]) == 1
                ):
                    # its links are a subset of the ones being walked: one walk covers both
                    return union([self.set_sql(t, i, loc, flatten) for i in self.base_items(t, perm)])
                self.ensure_view(t, perm)
                return f"SELECT id FROM authz_int.{q(t.name + '__' + name)}"
            case Arrow(rel, perm_name) | ArrowOn(rel, perm_name, _):
                r, targets = self.targets(t, rel, loc)
                on = only_on(node)
                names = on if on is not None else [x.name for x in targets]
                view = self.ensure_link_view(t, r, perm_name, loc, targets=names)
                return f"SELECT id FROM authz_int.{q(view)}"
            case Cond(sql):
                return f"SELECT {rid} AS id FROM {tbl} r WHERE coalesce(({row_cond(sql, 'r')}), false)"
            case Or(items):
                return union([self.set_sql(t, i, loc, flatten) for i in once(items)])
        items = once(node.items) if isinstance(node, And) else [node]
        where = []
        for item in items:
            match item:
                case Cond(sql):
                    where.append(f"coalesce(({row_cond(sql, 'r')}), false)")
                case Not(Cond(sql)):
                    where.append(f"NOT coalesce(({row_cond(sql, 'r')}), false)")
                case Not(inner):
                    where.append(f"NOT EXISTS (SELECT 1 FROM ({self.set_sql(t, inner, loc)}) x WHERE x.id = {rid})")
                case _:
                    where.append(self.key_in(t, "r", self.set_sql(t, item, loc)))
        return f"SELECT {rid} AS id FROM {tbl} r\n  WHERE " + "\n    AND ".join(where)

    # --- policies: flatten same-type permissions, drop redundant lookups ---
    def flat_items(self, t: Type, perm: Perm, stack: tuple[Name, ...] = (), views: bool = False) -> list[Expr]:
        """t.perm's operands, with the permissions of its type it names written out in place. views: for the
        permission's view, where one that inherits stays a name (its view walks a tree, which its operands
        written out here would not)."""
        key = (t.name, perm.name)
        assert key not in stack, "analyze_recursion refuses a permission that depends on itself (AZ302)"
        out = []
        for item in self.top_items(perm):
            if isinstance(item, Ref) and item.name in t.perms and not (views and (t.name, item.name) in self.recursive):
                out += self.flat_items(t, t.perms[item.name], (*stack, key), views)
            else:
                out.append(item)
        return out

    def reach(self, t: Type, name: str, seen: set[str] | None = None) -> set[str]:
        """Names a permission includes unconditionally (so they are subsets of it)."""
        seen = set() if seen is None else seen
        if name in seen or name not in t.perms:
            return seen
        seen.add(name)
        for item in self.top_items(t.perms[name]):
            if isinstance(item, Ref):
                self.reach(t, item.name, seen)
        return seen

    def lookup_key(self, t: Type, item: Expr) -> tuple[str, str, str | None] | None:
        """(relation, permission, condition) for rel.perm or (rel.perm and {cond}), where rel links to objects (one
        to anyone or links is refused where the arrow is made, targets)."""
        cond = None
        if isinstance(item, And) and len(item.items) == 2:
            arrows = [x for x in item.items if isinstance(x, Arrow)]
            conds = [x for x in item.items if isinstance(x, Cond)]
            if len(arrows) == 1 and len(conds) == 1:
                item, cond = arrows[0], conds[0].sql
        if (
            isinstance(item, Arrow)
            and item.rel in t.relations
            and all(not sr and st in self.types for st, sr in t.relations[item.rel].subjects())
        ):
            return (item.rel, item.perm, cond)
        return None

    def prune(self, t: Type, items: list[Expr]) -> list[Expr]:
        """items (the operands of an or) without those said twice, and without a lookup another one covers:
        parent.edit beside parent.view, when view includes edit on every type parent points at (reach)."""
        keep = []
        for i, item in enumerate(items):
            if item in items[:i]:
                continue
            ki = self.lookup_key(t, item)
            covered = False
            if ki:
                targets = [self.T(st) for st, _ in t.relations[ki[0]].subjects()]

                def within(inner: str, outer: str, targets: list[Type] = targets) -> bool:
                    return bool(targets) and all(inner in self.reach(target, outer) for target in targets)

                for j, other in enumerate(items):
                    kj = self.lookup_key(t, other)
                    if j == i or not kj or kj[0] != ki[0] or kj[2] != ki[2]:
                        continue
                    # (two that include each other say the same: the first stays)
                    if within(ki[1], kj[1]) and not (within(kj[1], ki[1]) and j > i):
                        covered = True
                        break
            if not covered:
                keep.append(item)
        return keep

    # --- row-level SQL for RLS policies -------------------------------------
    # A policy checks the row itself (its columns, and lookups of the rows it
    # links to), so INSERT ... RETURNING works before the new row is in any view.
    # invoker: the SQL runs as the app role (row-level security, column rules' triggers, refusals). There
    # nothing reads another table itself: what the policy reads, it reads with its own rights, in views and
    # functions that run as the owner, so a permission means the same wherever it is checked.
    def row_sql(
        self,
        t: Type,
        alias: str,
        node: Expr,
        loc: Loc,
        stack: tuple[Name, ...] = (),
        point: bool = False,
        invoker: bool = False,
    ) -> str:
        match node:
            case Cond(sql):
                if invoker and reads_more(sql):
                    return self.definer_cond(t, sql, alias)
                return f"coalesce(({row_cond(sql, alias)}), false)"
            case Not(inner_node):
                # NULL (a NULL column, or no user) must mean "not held", as it does in the views
                inner = self.row_sql(t, alias, inner_node, loc, stack, point, invoker)
                return f"NOT {inner}" if isinstance(inner_node, Cond) else f"NOT coalesce({inner}, false)"
            case And(items) | Or(items):
                # cheapest first: Postgres evaluates AND and OR from the left and stops once the answer is known
                joiner = f"\n    {'OR' if isinstance(node, Or) else 'AND'} "
                return (
                    "("
                    + joiner.join(
                        self.row_sql(t, alias, x, loc, stack, point, invoker)
                        for x in self.cheapest_first(t, once(items))
                    )
                    + ")"
                )
            case Arrow(rel, perm_name) | ArrowOn(rel, perm_name, _):
                return self.row_arrow(t, alias, node, rel, perm_name, loc, point, invoker)
            case _:
                assert isinstance(node, Ref), f"not an expression: {node!r}"
                self.lookup(t, node.name, loc)
                if node.name in t.relations:
                    return self.row_relation(t, t.relations[node.name], alias, loc, point)
                perm = t.perms[node.name]
                items = self.cheapest_first(t, self.prune(t, self.flat_items(t, perm, stack)))
                return or_join([self.row_sql(t, alias, item, perm.loc, point=point, invoker=invoker) for item in items])

    def definer_cond(self, t: Type, sql: str, alias: str) -> str:
        """A condition that reads more than its row's columns, where the app role checks it: a call of a function
        that runs it as the owner on the row, as the views and authz.can do, so it sees what the policy sees."""
        name = f"{t.name}__check_{hashlib.sha1(sql.encode()).hexdigest()[:10]}"
        fn = f"authz_gen.{q(name)}"
        if self.view_state.get(name) != "done":
            self.view_state[name] = "done"
            bare = q(t.table.split(".")[1])
            self.view_sql.append(
                f"-- {t.name}: a condition that reads other rows, run with the policy's rights wherever it is checked\n"
                f"CREATE FUNCTION {fn}(p_row {qt(t.table)}) RETURNS boolean\n"
                f"LANGUAGE sql STABLE SECURITY DEFINER SET search_path FROM CURRENT AS $f$\n"
                f"  SELECT coalesce(({row_cond(sql, bare)}), false) FROM (SELECT (p_row).*) AS {bare}\n$f$;"
            )
        return f"{fn}(ROW({alias}.*)::{qt(t.table)})"

    def link_checks(
        self, t: Type, r: Relation, names: list[str], checks: Mapping[str, str | None], obj: str
    ) -> list[str]:
        """rel.perm through the relation's link tables and shares, for the object whose id is obj: its links, each
        target checked on its own (what ensure_link_view selects)."""
        parts = []
        for src in r.sources:
            for st in names:
                check = checks[st]
                if src.kind == "column" or (st, None) not in src.subjects or check is None:
                    continue
                fn = f"authz_gen.{q(check)}"
                if src.kind == "table":
                    assert src.table is not None and src.obj_col is not None
                    extra = f" AND coalesce(({row_cond(src.where, 's')}), false)" if src.where else ""
                    holds = self.of_type(src, "s", st, f"{fn}({self.subject_id(src, 's', st)})")
                    parts.append(
                        f"EXISTS (SELECT 1 FROM {qt(src.table)} s WHERE "
                        f"{self.key_is(t, 's', obj, src.obj_col)}{extra} AND {holds})"
                    )
                else:
                    parts.append(
                        f"EXISTS (SELECT 1 FROM authz.shares g WHERE g.object_type = {lit(t.name)} "
                        f"AND g.object_id = {obj}::text AND g.relation = {lit(r.name)} "
                        f"AND g.subject_type = {lit(st)} AND g.subject_relation = '' AND {self.live()} "
                        f"AND {fn}(g.subject_id::{self.T(st).pktype}))"
                    )
        return parts

    def definer_links(
        self, t: Type, r: Relation, perm_name: str, names: list[str], checks: Mapping[str, str | None], alias: str
    ) -> str:
        """link_checks where the app role checks the row: a function that runs as the owner (the app role may read
        neither authz.shares nor, maybe, the link tables), on the row's id."""
        suffix = "" if names == [st for st, _ in r.subjects()] else "__on_" + "_".join(names)
        name = f"{t.name}__{r.name}__{perm_name}{suffix}__links"
        fn = f"authz_gen.{q(name)}"
        if self.view_state.get(name) != "done":
            self.view_state[name] = "done"
            body = or_join(self.link_checks(t, r, names, checks, "p_id"))
            self.view_sql.append(
                f"-- {t.name}.{r.name}.{perm_name} for one object, through link tables and shares: as the owner\n"
                f"CREATE FUNCTION {fn}(p_id {t.pktype}) RETURNS boolean\n"
                f"LANGUAGE sql STABLE SECURITY DEFINER SET search_path FROM CURRENT AS $f$\n"
                f"  SELECT {body}\n$f$;"
            )
        return f"{fn}({self.key(t, alias)})"

    def row_arrow(
        self, t: Type, alias: str, node: Expr, rel: str, perm_name: str, loc: Loc, point: bool, invoker: bool = False
    ) -> str:
        """rel.perm on the row itself: its columns looked up, then the relation's other sources."""
        r, targets = self.targets(t, rel, loc)
        on = only_on(node)
        names = on if on is not None else [x.name for x in targets]
        parts = []
        for src in r.sources:
            if src.kind != "column":
                continue
            for st in names:
                if (st, None) in src.subjects:
                    view = self.view_ref(self.T(st), perm_name, loc)
                    lookup = self.lookup_sql(view, self.subject_id(src, alias, st), point)
                    parts.append(self.of_type(src, alias, st, lookup))
        if any(src.kind != "column" for src in r.sources):
            checks = {st: self.point_checks.get(self.view_ref(self.T(st), perm_name, loc)) for st in names}
            if point and all(checks.values()):
                if invoker:
                    parts.append(self.definer_links(t, r, perm_name, names, checks, alias))
                else:
                    parts += self.link_checks(t, r, names, checks, self.key(t, alias))
            else:
                ext = any(src.kind == "column" for src in r.sources)
                view = self.ensure_link_view(t, r, perm_name, loc, targets=names, ext=ext)
                parts.append(self.lookup_sql(view, self.key(t, alias), point))
        return or_join(parts) if parts else "false"

    def cheapest_first(self, t: Type, items: list[Expr]) -> list[Expr]:
        """Items in order of item_cost, otherwise as written. Kept as OR/AND (not CASE), which Postgres
        can turn into hashed subplans when a query reads many rows."""
        return sorted(items, key=lambda i: self.item_cost(t, i))

    def row_relation(self, t: Type, r: Relation, alias: str, loc: Loc, point: bool = False) -> str:
        if any(sr and sr != "*" and self.is_group_loop(t, r, st, sr) for st, sr in r.subjects()):
            return self.lookup_sql(self.ensure_rel_view(t, r, loc), self.key(t, alias), point)
        parts = []
        for src in r.sources:
            if src.kind != "column":
                continue
            for st, sr in src.subjects:
                sid = self.subject_id(src, alias, st)
                if self.is_principal(st) and not sr:
                    me = self.of_type(src, alias, st, f"{sid} = {self.me(st)}")
                    parts.append(f"coalesce({me}, false)")
                elif sr:
                    lookup = self.lookup_sql(self.view_ref(self.T(st), sr, loc), sid, point)
                    parts.append(self.of_type(src, alias, st, lookup))
        if any(src.kind != "column" for src in r.sources):
            ext = any(src.kind == "column" for src in r.sources)  # only split off when needed
            parts.append(self.lookup_sql(self.ensure_rel_view(t, r, loc, ext=ext), self.key(t, alias), point))
        if not parts:
            fail(
                loc,
                f"{t.name}.{r.name} links to {r.subjects()[0][0]} objects, not users; "
                f"follow it with a dot, e.g. {r.name}.view",
                "AZ301",
            )
        return or_join(parts)

    def rule_sql(self, t: Type, alias: str, rule: Rule, point: bool = False, invoker: bool = False) -> str:
        """The rule on the row aliased alias, and the type's where; invoker: as the app role checks it (row_sql)."""
        sql = self.row_sql(t, alias, rule.expr, rule.loc, point=point, invoker=invoker)
        if t.where:
            where = (
                self.definer_cond(t, t.where, alias)
                if invoker and reads_more(t.where)
                else f"coalesce(({row_cond(t.where, alias)}), false)"
            )
            sql = f"({sql}\n    AND {where})"
        return sql
