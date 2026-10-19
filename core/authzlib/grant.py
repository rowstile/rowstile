"""Why, and how to grant: the smallest changes to the data that would give someone a permission they lack.

The permission's expression says where access can come from: a share, a row in a link table, a column, a
group the person could join, or the same permission on the object above. Each candidate change is tried in
a savepoint, as the policy's owner, then checked with authz.can as the person, and undone: only the ones
that grant it are kept, with what else they would do: every other permission the person would hold, on the
object and on any other, who else would hold the permission on the object, and what the people in what a change
replaces (the owner a column names now) would no longer hold. Only the permissions a change can reach are counted:
those that read what it writes, worked out from the policy. A preview that writes and rolls back belongs to the
command, not to the runtime.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, TypeAlias

from .conditions import Bool, Cmp, Col, Const, In, IsNull, Node, Scalar, simple
from .connection import Db, Value, flag, number, text
from .parse import And, Arrow, ArrowOn, Cols, Cond, Expr, Loc, Not, Or, Ref, Relation, SharedSource, Source, Type, cols
from .sqlutil import lit, q, qt, reads_more, row_cond

if TYPE_CHECKING:
    from . import Compiler

DEPTH = 3  # how far up inheritance (rel.perm) and into groups it looks
LINKED = 3  # how many current parents or groups of an object it follows
TRIES = 40  # how many candidate changes (or combinations) it tries
SHOWN = 5


def settles(where: str) -> dict[str, Scalar] | None:
    """The columns' values that make a relation's `where` true, when it says no more than that
    ({role = 'admin'}, {active and kind in ('a', 'b')}); None for any other condition."""
    node = simple(where)
    out: dict[str, Scalar] = {}

    def walk(n: Node) -> bool:
        match n:
            case Col(name=c):
                out[c] = True
            case Bool(op="not", items=(Col(name=c),)):
                out[c] = False
            case (
                Cmp(op="=", left=Col(name=c), right=Const(value=v))
                | Cmp(op="=", left=Const(value=v), right=Col(name=c))
            ):
                if v is None:
                    return False
                out[c] = v
            case IsNull(item=Col(name=c), negated=False):
                out[c] = None
            case In(item=Col(name=c), values=values, negated=False):
                if values[0] is None:
                    return False
                out[c] = values[0]
            case Bool(op="and", items=items):
                return all(walk(x) for x in items)
            case _:
                return False
        return True

    return out if node is not None and walk(node) else None


def constant(v: Scalar) -> str:
    """A condition's constant as SQL."""
    if v is None:
        return "NULL"
    if isinstance(v, bool):
        return "true" if v else "false"
    return lit(v) if isinstance(v, str) else str(v)


def holding(t: Type, columns: Cols, oid: str) -> list[tuple[str, str]]:
    """The columns that hold the id of t's object oid, each with its value as SQL: the id, or for a key of several
    columns (oid is then the key's row text) each of its fields."""
    if isinstance(columns, str):
        return [(columns, lit(oid))]
    key = f"({lit(oid)}::{t.keytype})"
    return [(c, f"{key}.{q(k)}") for c, (k, _) in zip(columns, t.key, strict=True)]


def more_of(items: Sequence[tuple[str, str, int]], first: str) -> list[str]:
    """(type, permission, n) in words, the permissions gained on as many objects of a type together, the one asked
    about (first) before the others: "view, edit on 3 more folders"."""
    groups: dict[tuple[str, int], list[str]] = {}
    for tn, pn, n in items:
        groups.setdefault((tn, n), []).append(pn)
    return [
        f"{', '.join(sorted(ps, key=lambda p: (p != first, p)))} on {n} more {tn}{'s' if n != 1 else ''}"
        for (tn, n), ps in groups.items()
    ]


def taken(items: Sequence[tuple[str, str, int, int]], first: str) -> list[str]:
    """(type, permission, objects, people) in words, the permissions people lose together, the one asked about
    (first) before the others: "share, edit on it from 1 person", "view on 2 other docs from 3 people" (0 objects:
    on the object asked about)."""
    groups: dict[tuple[str, int, int], list[str]] = {}
    for tn, pn, n, k in items:
        groups.setdefault((tn, n, k), []).append(pn)
    return [
        f"{', '.join(sorted(ps, key=lambda p: (p != first, p)))} on "
        + (f"{n} other {tn}{'s' if n != 1 else ''}" if n else "it")
        + f" from {k} {'person' if k == 1 else 'people'}"
        for (tn, n, k), ps in groups.items()
    ]


# What the policy reads: the shares of a relation ("share", type, relation), a table's rows ("table", name), or
# columns of them ("column", table, name); ANY, what any change may alter: a condition that reads more than its row
# (a subquery, a function). What a change writes: shares ("share", type, relation), a row ("rows", table), or columns
# of a row ("columns", table, name, ...)
Fact: TypeAlias = "tuple[str, ...]"
ANY: Fact = ("any",)
Part: TypeAlias = "tuple[str, str]"  # a relation or a permission: (type, name)
Person: TypeAlias = "tuple[str, str]"  # someone who signs in: (type, id)
Subject: TypeAlias = "tuple[str, str, str]"  # what a relation links to: (type, id, the group's relation or "")


def touches(writes: Fact, read: Fact) -> bool:
    """Whether what a change writes can change what the policy reads."""
    match read:
        case ("table", table):
            return writes[0] in ("rows", "columns") and writes[1] == table
        case ("column", table, name):
            return writes == ("rows", table) or (writes[:2] == ("columns", table) and name in writes[2:])
    return read in (ANY, writes)


def reads(c: Compiler) -> dict[Part, set[tuple[Fact, bool]]]:
    """What each relation and permission of the policy reads, through every relation, arrow and group it follows:
    the facts a change may write, each with whether it is read through a `not` (more of it can take away)."""

    def where(t: Type) -> set[tuple[Fact, bool]]:
        # a row its type's where leaves out holds nothing and passes nothing on
        return {(ANY if reads_more(t.where) else ("table", t.table), False)} if t.where else set()

    facts: dict[Part, set[tuple[Fact, bool]]] = {}
    follows: dict[Part, set[tuple[Part, bool]]] = {}

    def walk(t: Type, node: Expr, neg: bool, out: set[tuple[Fact, bool]], to: set[tuple[Part, bool]]) -> None:
        match node:
            case Ref(name=name):
                to.add(((t.name, name), neg))
            case Arrow(rel=rel, perm=perm) | ArrowOn(rel=rel, perm=perm):
                to.add(((t.name, rel), neg))
                to |= {((st, perm), neg) for st, sr in t.relations[rel].subjects() if sr is None}
            case Cond(sql=sql):
                out.add((ANY if reads_more(sql) else ("table", t.table), neg))
            case Not(item=item):
                walk(t, item, not neg, out, to)
            case _:
                for x in node.items:
                    walk(t, x, neg, out, to)

    for t in c.types.values():
        for r in t.relations.values():
            out, to = where(t), set[tuple[Part, bool]]()
            for src in r.sources:
                if src.kind == "shared":
                    # (a caveat on a share is a condition: it may read anything)
                    out |= {(("share", t.name, r.name), False)} | ({(ANY, False)} if c.pol.caveats else set())
                elif src.kind == "table":
                    # the row's columns that name the object and the subject, or (a where) any of them
                    x = src.table
                    on = [*cols(src.obj_col), *cols(src.subj_col or ()), *cols(src.type_col or ())]
                    out |= (
                        {(ANY if reads_more(src.where) else ("table", x), False)}
                        if src.where
                        else {(("column", x, n), False) for n in on}
                    )
                elif src.kind == "column":
                    out |= {
                        (("column", t.table, n), False) for n in [*cols(src.column or ()), *cols(src.type_col or ())]
                    }
                else:
                    # custom roles: shares no change makes, of roles no change makes; only those of the owner count
                    to |= {((t.name, src.owner), False)} if src.owner else set()
                for st, sr in src.subjects:
                    out |= where(c.types[st]) if st in c.types else set()
                    to |= {((st, sr), False)} if sr and sr != "*" else set()
            facts[(t.name, r.name)], follows[(t.name, r.name)] = out, to
        for p in t.perms.values():
            out, to = where(t), set[tuple[Part, bool]]()
            walk(t, p.expr, False, out, to)
            facts[(t.name, p.name)], follows[(t.name, p.name)] = out, to
    # everything it reads through what it follows, to a fixpoint (inheritance loops back on itself)
    changed = True
    while changed:
        changed = False
        for part, to in follows.items():
            more = {(f, neg != n) for x, n in to for f, neg in facts.get(x, ())} - facts[part]
            if more:
                facts[part] |= more
                changed = True
    return facts


@dataclass
class Held:
    objects: dict[Part, int]  # how many objects of each type the person holds each permission on (those counted)
    perms: set[str]  # every permission the person holds on the object asked about


@dataclass
class Change:
    kind: str  # share | link | column
    text: str  # in words: "share viewer on project 1 with user 2"
    sql: str  # what makes it, run as the owner
    loc: Loc  # the policy line of the relation it adds to
    cost: int  # shares first, then rows in link tables, then changed columns
    writes: Fact  # what the policy reads that it changes
    subject: Subject  # whom it links the object to
    replaces: list[Subject] = field(default_factory=list)  # whom it unlinks: the subject a column names now


@dataclass
class Way:
    changes: list[Change]
    grants: bool = False
    more_objects: int = 0  # other objects of the type the person gains the permission on
    more_people: int = 0  # other people who gain it on this object
    fewer_people: int = 0  # people who lose it on this object (a column that changes hands)
    also: list[str] = field(default_factory=list)  # the other permissions the person gains on this object
    # the other permissions the person gains on other objects: (type, permission, on how many)
    elsewhere: list[tuple[str, str, int]] = field(default_factory=list)
    # what other people lose, the permission asked about on this object first: (type, permission, on how many other
    # objects (0: this one), from how many people)
    takes: list[tuple[str, str, int, int]] = field(default_factory=list)
    error: str | None = None

    @property
    def text(self) -> str:
        return " and ".join(c.text for c in self.changes)

    @property
    def refused(self) -> str:
        """Why the database refused to try it: its error's first line."""
        assert self.error, f"{self.text} was tried"
        return self.error.splitlines()[0]


@dataclass
class Answer:
    holds: bool
    explain: list[str]  # authz.explain's lines
    needs: str  # the permission's definition, and its line
    ways: list[Way] = field(default_factory=list)  # Ways that grant it, best first
    untried: list[Way] = field(default_factory=list)  # Ways the database refused to try (their error says why)
    notes: list[str] = field(default_factory=list)  # what no change to the data would do (conditions, denies)
    # why no change was tried: the person or the object isn't there, or the type's where leaves it out
    stops: list[str] = field(default_factory=list)


class Grants:
    def __init__(self, c: Compiler, db: Db, ptype: str, pid: str) -> None:
        self.c, self.db, self.ptype, self.pid = c, db, ptype, pid
        self.notes: list[str] = []
        self.reads = reads(c)
        self.was: dict[Person, Held] = {}  # what each person held before any change, as far as it was counted

    # --- reading what is there now -------------------------------------------------------------------
    def probe(self, sql: str, args: Sequence[Value] = ()) -> list[dict[str, Value]]:
        """Rows of a read that may fail, in a savepoint of its own: none when it does. The ids asked about are
        checked first (stop()), so a read fails here on a condition of the policy this session can't read: a
        function on the search path the policy was applied with, and not on this one, say."""
        from .database import savepoint

        try:
            with savepoint(self.db, "authz_grant_probe"):
                return self.db.rows(sql, list(args))
        except self.db.errors:
            return []

    def linked(self, t: Type, r: Relation, src: Source, st: str, sr: str | None, oid: str) -> list[str]:
        """The subjects of type st (#sr) that relation r's source links object oid to now."""
        sql = self.c.pair_sql(t, r, src, st, sr or "", "o", "s", match=("obj", lit(oid)))
        return [str(x["s"]) for x in self.probe(f"SELECT DISTINCT s::text AS s FROM ({sql}) p LIMIT {LINKED}")]

    def groups_of(self, st: str, sr: str) -> list[str]:
        """The st objects the person already holds sr on (the groups they are in): authz.list for a permission,
        the relation's own links for a relation."""
        g = self.c.types[st]
        if sr in g.perms:
            self.sign_in()
            return [text(x, "x") for x in self.probe(f"SELECT x FROM authz.list($1, $2) x LIMIT {LINKED}", [st, sr])]
        out: list[str] = []
        r = g.relations.get(sr)
        for src in r.sources if r else []:
            if r and (self.ptype, None) in src.subjects and src.kind != "roles":
                sql = self.c.pair_sql(g, r, src, self.ptype, "", "o", "s", match=("subj", lit(self.pid)))
                out += [str(x["o"]) for x in self.probe(f"SELECT DISTINCT o::text AS o FROM ({sql}) p LIMIT {LINKED}")]
        return list(dict.fromkeys(out))[:LINKED]

    def sign_in(self, who: bool | Person = True) -> None:
        """Signs in the person (True), someone else (a Person), or nobody (False)."""
        if who:
            self.db.rows("SELECT authz.act_as($1, $2)", list((self.ptype, self.pid) if who is True else who))
        else:
            self.db.rows("SELECT authz.act_as(NULL, NULL)")

    def shared_if(
        self, t: Type, r: Relation, src: SharedSource, oid: str, st: str, sid: str, sr: str, who: str
    ) -> bool:
        """Whether the relation's `shared if` lets this share be made, judged as authz.share judges it: as the one
        who shares (it may read who that is), someone who may share t oid. Noted when it lets nobody who may."""
        from .database import text_array

        assert src.shared_if, f"{t.name}.{r.name}: a share without a condition"
        key = f"{t.name}.{r.name}.{st}#{sr}" if sr else f"{t.name}.{r.name}.{st}"
        obj, subj = f"authz_int.canon({lit(t.name)}, {lit(oid)})", f"authz_int.canon({lit(st)}, {lit(sid)})"
        self.sign_in(False)
        sharers = sorted(
            {
                text(x, "x")
                for x in self.probe("SELECT x FROM authz.who($1, $2, $3) x", [t.name, oid, src.shared_by or "share"])
            }
        )
        # authz.share also asks that they hold what the relation gives
        need = text_array(self.c.required_perms(t, r.name))
        ok = False
        for u in sharers:
            self.sign_in(("user", u))
            if self.probe(
                f"SELECT 1 AS x WHERE coalesce(authz_int.share_if({lit(key)}, {obj}, {lit(st)}, {subj}, {lit(sr)}), "
                f"false) AND NOT EXISTS (SELECT 1 FROM unnest($1::text[]) n "
                f"WHERE NOT coalesce(authz.can({lit(t.name)}, {lit(oid)}, n), false))",
                [need],
            ):
                ok = True
                break
        self.sign_in()
        if not ok:
            self.notes.append(
                f"{t.name}.{r.name} wasn't tried with {who}: its shared if {{{src.shared_if}}} refuses it to everyone "
                f"who may share {t.name} {oid}"
                if sharers
                else f"{t.name}.{r.name} wasn't tried with {who}: nobody may share {t.name} {oid}, and its shared if "
                f"{{{src.shared_if}}} is judged as the one who shares"
            )
        return ok

    def stop(self, t: Type, oid: str) -> str | None:
        """What no change to shares or links gets past, for the person or the object (t oid): an id its key can't
        hold, or no row with it ("there is no doc 999", as authz.share says of a subject); a row the type's where
        leaves out, which holds nothing and passes nothing on (a where that can't be read here is no stop: the
        changes are tried). None when it counts."""
        valid = flag(self.db.rows("SELECT pg_catalog.pg_input_is_valid($1, $2) AS ok", [oid, t.keytype])[0], "ok")
        find = f"FROM {qt(t.table)} o WHERE {self.c.key_is(t, 'o', lit(oid))}"
        if not valid or not self.db.rows(f"SELECT 1 AS x {find} LIMIT 1"):
            return f"there is no {t.name} {oid}"
        if t.where and self.probe(f"SELECT 1 AS x {find} AND NOT coalesce(({row_cond(t.where, 'o')}), false)"):
            return f"{t.name} {oid} fails the type's where {{{t.where}}}: no share or link changes that"
        return None

    # --- the candidate changes ----------------------------------------------------------------------
    def direct(
        self, t: Type, r: Relation, src: Source, st: str, sid: str, sr: str = ""
    ) -> Callable[[str], Change | None]:
        """The change that links oid to subject sid through this source (None when it is a link table whose `where`
        doesn't say which values make it true, or the subject's own table)."""

        def make(oid: str) -> Change | None:
            if src.kind == "shared":
                who = f"{st}#{sr} {sid}" if sr else f"{st} {sid}"
                obj, subj = f"authz_int.canon({lit(t.name)}, {lit(oid)})", f"authz_int.canon({lit(st)}, {lit(sid)})"
                # the share authz.share would make (it needs someone signed in who may share; this is the owner): only
                # one the relation's `shared if` allows, judged as someone who may share it
                if src.shared_if and not self.shared_if(t, r, src, oid, st, sid, sr, who):
                    return None
                share = (
                    f"object_type = {lit(t.name)} AND object_id = {obj} AND relation = {lit(r.name)} "
                    f"AND subject_type = {lit(st)} AND subject_id = {subj} AND subject_relation = {lit(sr)}"
                )
                if self.probe(
                    f"SELECT 1 AS x FROM authz.shares WHERE {share} "
                    "AND expires_at IS NULL AND starts_at IS NULL AND caveat IS NULL"
                ):
                    return None  # there already, for good: nothing to change
                # one there already (that expired, say) made again without an end, a start or a caveat, as
                # authz.share makes it again
                return Change(
                    "share",
                    f"share {r.name} on {t.name} {oid} with {who}",
                    "INSERT INTO authz.shares (object_type, object_id, relation, subject_type, subject_id, "
                    f"subject_relation) VALUES ({lit(t.name)}, {obj}, {lit(r.name)}, {lit(st)}, {subj}, {lit(sr)}) "
                    "ON CONFLICT ON CONSTRAINT shares_pkey "
                    "DO UPDATE SET expires_at = NULL, starts_at = NULL, caveat = NULL, caveat_args = NULL",
                    src.loc,
                    1,
                    ("share", t.name, r.name),
                    (st, sid, sr),
                )
            # a row of a link table, or a column of the object's own row (relation() never asks for a custom
            # role's): the subject's columns, each with its value, and in a polymorphic source the one naming its type
            assert src.kind == "table" or src.kind == "column", f"{t.name}.{r.name}: no change for a {src.kind} source"
            on = src.subj_col if src.kind == "table" else src.column
            subject = holding(self.c.types[st], on, sid) + ([(src.type_col, lit(st))] if src.type_col else [])
            if src.kind == "table":
                assert src.table and src.obj_col, f"{t.name}.{r.name}: a link table names the object's columns"
                if src.table == self.c.types[st].table:
                    # the subject's own row says where it is (a group inside a group, a user's team): no row to add,
                    # and changing that row would move it out of where it is
                    self.notes.append(
                        f"{t.name}.{r.name} wasn't tried: {st} {sid}'s own row of {src.table} says it, and changing "
                        f"that row would move {st} {sid}"
                    )
                    return None
                pairs = holding(t, src.obj_col, oid) + subject
                names, vals = [c for c, _ in pairs], [v for _, v in pairs]
                # a source with a `where`: the row must also hold what the condition asks, if it says which values
                held = settles(src.where) if src.where else {}
                if held is None or set(held) & set(names):
                    self.notes.append(
                        f"{t.name}.{r.name} wasn't tried: it reads {src.table} where {{{src.where}}}, and it isn't "
                        "known which values make that true"
                    )
                    return None
                more = ", ".join(f"{c} = {constant(v)}" for c, v in held.items())
                same = " AND ".join(f"{q(c)} = {v}" for c, v in zip(names, vals, strict=True))
                if self.probe(f"SELECT 1 AS x FROM {qt(src.table)} WHERE {same} LIMIT 1"):
                    # the link's row is there already: nothing to add, or (left out by the condition) its columns
                    # change, unless they hold what it asks already
                    holds = " AND ".join(f"{q(c)} IS NOT DISTINCT FROM {constant(v)}" for c, v in held.items())
                    if not held or self.probe(f"SELECT 1 AS x FROM {qt(src.table)} WHERE {same} AND {holds} LIMIT 1"):
                        return None
                    sets = ", ".join(f"{q(c)} = {constant(v)}" for c, v in held.items())
                    return Change(
                        "link",
                        f"set {more} on {st} {sid}'s row of {src.table} for {t.name} {oid}",
                        f"UPDATE {qt(src.table)} SET {sets} WHERE {same}",
                        src.loc,
                        2,
                        ("columns", src.table, *held),
                        (st, sid, sr),
                    )
                names += list(held)
                vals += [constant(v) for v in held.values()]
                return Change(
                    "link",
                    f"add {st} {sid} to {src.table} for {t.name} {oid}" + (f", with {more}" if held else ""),
                    f"INSERT INTO {qt(src.table)} ({', '.join(q(x) for x in names)}) VALUES ({', '.join(vals)})",
                    src.loc,
                    2,
                    ("rows", src.table),
                    (st, sid, sr),
                )
            # the subjects the object's columns name now, for every relation they hold: the change unlinks them, or
            # (the subject it would name) changes nothing
            now = [
                (st2, x, sr2 or "")
                for r2 in t.relations.values()
                for s2 in r2.sources
                if s2.kind == "column" and set(cols(s2.column or ())) & set(cols(on))
                for st2, sr2 in s2.subjects
                for x in self.linked(t, r2, s2, st2, sr2, oid)
            ]
            if (st, sid, sr) in now:
                return None
            return Change(
                "column",
                # a pair: its type column is set too (subject), so the change names it and the type
                (
                    f"set {src.type_col}, {', '.join(cols(on))} of {t.name} {oid} to {st} {sid}"
                    if src.type_col
                    else f"set {', '.join(cols(on))} of {t.name} {oid} to {sid}"
                ),
                f"UPDATE {qt(t.table)} r SET {', '.join(f'{q(c)} = {v}' for c, v in subject)} "
                f"WHERE {self.c.key_is(t, 'r', lit(oid))}",
                src.loc,
                3,
                ("columns", t.table, *(c for c, _ in subject)),
                (st, sid, sr),
                now,
            )

        return make

    def ways(
        self, t: Type, oid: str, node: Expr, depth: int, seen: frozenset[tuple[str, str, str]]
    ) -> list[list[Change]]:
        """Candidate ways (lists of changes, all needed) that could make node hold on t oid for the person."""
        match node:
            case Ref(name):
                if name in t.perms:
                    key = (t.name, oid, name)
                    if key in seen:
                        return []
                    return self.ways(t, oid, t.perms[name].expr, depth, seen | {key})
                return self.relation(t, oid, t.relations[name], depth, seen)
            case Arrow(rel, perm):
                r = t.relations[rel]
                out: list[list[Change]] = []
                if depth >= DEPTH:
                    return out
                for src in r.sources:
                    for target, sr in src.subjects:
                        # a relation followed with a dot links to objects, not to groups or anyone (AZ301)
                        assert sr is None and target in self.c.types, f"{t.name}.{rel} is followed to {target}"
                        for x in self.linked(t, r, src, target, None, oid):
                            out += self.ways(self.c.types[target], x, Ref(perm), depth + 1, seen)
                return out
            case Cond(sql):
                self.notes.append(f"{t.name} {oid} must meet {{{sql}}}: no share or link changes that")
                return []
            case Not(Cond(sql)):
                self.notes.append(f"{t.name} {oid} must not meet {{{sql}}}: no share or link changes that")
                return []
            case Not(_):
                self.notes.append(
                    f"a deny on {t.name} {oid} (not ...) may be what stops it: no share or link removes it"
                )
                return []
            case Or(items):
                return [w for x in items for w in self.ways(t, oid, x, depth, seen)]
        # an `and` (the compiler's own arrow_on is never in a permission's expression): a change for each part that
        # may not hold yet (or none, if it holds already)
        assert isinstance(node, And), node
        combos: list[list[Change]] = [[]]
        for x in node.items:
            options = [*sorted(self.ways(t, oid, x, depth, seen), key=len)[:3], []]
            combos = [a + b for a in combos for b in options][:TRIES]
        return [c for c in combos if c]

    def relation(
        self, t: Type, oid: str, r: Relation, depth: int, seen: frozenset[tuple[str, str, str]]
    ) -> list[list[Change]]:
        out: list[list[Change]] = []
        for src in r.sources:
            if src.kind == "roles":
                continue
            for st, sr in src.subjects:
                if st == self.ptype and not sr:
                    ch = self.direct(t, r, src, st, self.pid)(oid)
                    if ch:
                        out.append([ch])
                elif sr and sr != "*":  # (every user, user:*, is no group to join: a share with it is never offered)
                    # a group the person is in already: link the object to it
                    for g in self.groups_of(st, sr):
                        ch = self.direct(t, r, src, st, g, sr)(oid)
                        if ch:
                            out.append([ch])
                    # a group the object is linked to already: put the person in it
                    if depth < DEPTH:
                        for g in self.linked(t, r, src, st, sr, oid):
                            out += self.ways(self.c.types[st], g, Ref(sr), depth + 1, seen)
        return out

    # --- trying them ---------------------------------------------------------------------------------
    def reach(self, changes: Sequence[Change]) -> list[Part]:
        """The permissions changes can alter, for anyone, in the policy's order: those that read what they write."""
        return [
            (x.name, p)
            for x in self.c.types.values()
            for p in self.c.public_perms(x)
            if any(touches(ch.writes, f) for ch in changes for f, _ in self.reads[(x.name, p)])
        ]

    def people_in(self, s: Subject) -> set[Person]:
        """Who is in a subject: the person or the service it names, or the users of a group (all who may hold its
        relation; authz.who lists users)."""
        st, sid, sr = s
        g = self.c.types[st]
        if not sr:
            return {(st, sid)} if g.principal else set()
        found = self.probe(f"SELECT DISTINCT x::text AS x FROM {self.c.who_fn(g, sr)}($1::{g.pktype}) x", [sid])
        return {("user", text(x, "x")) for x in found}

    def others(self, way: Way, kinds: Sequence[Part]) -> set[Person]:
        """Who but the person may lose by a way: those in what it unlinks (the owner a column names now), and, when
        what it links to is read through a `not`, those in it. (A condition that reads more than its row is judged
        for the person alone.)"""
        out = {p for ch in way.changes for s in ch.replaces for p in self.people_in(s)}
        if any(neg and touches(ch.writes, f) for ch in way.changes for k in kinds for f, neg in self.reads[k]):
            out |= {p for ch in way.changes for p in self.people_in(ch.subject)}
        return out - {(self.ptype, self.pid)}

    def held(self, who: Person, kinds: Sequence[Part], t: Type, oid: str) -> Held:
        """What someone holds now: on how many objects of each type each permission of kinds, and every permission
        on t oid (in one query, signed in as them)."""
        from .database import text_array

        self.sign_in(who)
        rows = self.db.rows(
            "SELECT k.t, k.p, (SELECT count(*) FROM authz.list(k.t, k.p)) AS n, false AS here "
            "FROM unnest($1::text[], $2::text[]) k(t, p) "
            "UNION ALL SELECT $3, p, 0, true FROM unnest(authz.perms($3, $4)) p",
            [text_array(tn for tn, _ in kinds), text_array(pn for _, pn in kinds), t.name, oid],
        )
        return Held(
            {(text(r, "t"), text(r, "p")): number(r, "n") for r in rows if not flag(r, "here")},
            {text(r, "p") for r in rows if flag(r, "here")},
        )

    def before(self, who: Person, kinds: Sequence[Part], t: Type, oid: str) -> Held:
        """What someone held before any change (the data as it is): each permission counted once, when a change
        that grants it can reach it."""
        was = self.was.get(who)
        if was is None:
            was = self.was[who] = self.held(who, kinds, t, oid)
        missing = [k for k in kinds if k not in was.objects]
        if missing:
            was.objects.update(self.held(who, missing, t, oid).objects)
        return was

    def holders(self, t: Type, oid: str, perm: str) -> set[str]:
        """Who holds perm on t oid (authz.who: users)."""
        self.sign_in(False)
        return {text(r, "x") for r in self.db.rows("SELECT x FROM authz.who($1, $2, $3) x", [t.name, oid, perm])}

    def attempt(self, way: Way, t: Type, oid: str, perm: str, people: set[str]) -> Way:
        """Tries a way, in a savepoint undone after: whether it grants perm, and if it does, all else it does."""
        from .database import Undo, savepoint

        me = (self.ptype, self.pid)
        kinds = self.reach(way.changes)
        try:
            with savepoint(self.db, "authz_grant"):
                self.sign_in(False)
                others = self.others(way, kinds)
                after: dict[Person, Held] = {}
                try:
                    with savepoint(self.db, "authz_grant_try"):
                        for ch in way.changes:
                            self.db.script(ch.sql)
                        self.sign_in()
                        way.grants = flag(
                            self.db.rows("SELECT coalesce(authz.can($1, $2, $3), false) AS ok", [t.name, oid, perm])[0],
                            "ok",
                        )
                        if way.grants:
                            after = {p: self.held(p, kinds, t, oid) for p in [me, *sorted(others)]}
                            now = self.holders(t, oid, perm)
                            way.more_people = len(now - people - ({self.pid} if self.ptype == "user" else set()))
                            way.fewer_people = len(people - now)
                        raise Undo
                except Undo:
                    pass
                if way.grants:
                    self.judge(way, t, perm, kinds, {p: (self.before(p, kinds, t, oid), h) for p, h in after.items()})
                raise Undo
        except Undo:
            pass
        except self.db.errors as e:
            way.error = getattr(e, "message", str(e))
        return way

    def judge(self, way: Way, t: Type, perm: str, kinds: Sequence[Part], held: dict[Person, tuple[Held, Held]]) -> None:
        """What a way that grants it gives the person (on the object, and how many more of each kind), and what it
        takes from the others, from what each held before and after."""
        me = (self.ptype, self.pid)
        was, now = held.pop(me)
        way.also = sorted(now.perms - was.perms - {perm})
        # what it gives on other objects: what is held now on how many, but this one (asked about, or said as "on
        # it")
        more = {k: now.objects[k] - was.objects[k] for k in kinds}
        for p in [perm, *way.also]:
            more[(t.name, p)] -= 1
        way.more_objects = max(0, more.pop((t.name, perm)))
        # (this object's type first, then the policy's order)
        way.elsewhere = sorted(((tn, pn, n) for (tn, pn), n in more.items() if n > 0), key=lambda x: x[0] != t.name)
        # what the others lose: on it (who loses the permission asked about is authz.who's answer, for everyone),
        # and on how many other objects, the most any one of them loses, from how many people
        here: dict[str, int] = {perm: way.fewer_people}
        for before, after in held.values():
            for p in sorted(before.perms - after.perms - {perm}):
                here[p] = here.get(p, 0) + 1
        there: list[tuple[str, str, int, int]] = []
        for tn, pn in kinds:
            lost = []
            for before, after in held.values():
                # (what it gives or takes on the object asked about is said as on it)
                on_it = int(pn in before.perms) - int(pn in after.perms) if tn == t.name else 0
                n = before.objects[(tn, pn)] - after.objects[(tn, pn)] - on_it
                if n > 0:
                    lost.append(n)
            if lost:
                there.append((tn, pn, max(lost), len(lost)))
        way.takes = [(t.name, p, 0, n) for p, n in here.items() if n] + sorted(there, key=lambda x: x[0] != t.name)


def permission_of(c: Compiler, type_name: str, perm: str) -> Type:
    """The type, once it and the permission asked for on it are the policy's: what authz.can and authz.explain
    take, refused as they refuse it. A relation, or a permission the compiler made, is no permission of the type
    (a test's line doesn't take them either)."""
    from .database import Error

    if type_name not in c.types:
        raise Error(f"no type {type_name} in the policy", hint="rowstile help AZ707")
    t = c.types[type_name]
    if perm not in c.public_perms(t):
        raise Error(f"no permission {type_name}.{perm} in the policy", hint="rowstile help AZ707")
    return t


def how_to_grant(
    c: Compiler, db: Db, ptype: str, pid: str, type_name: str, oid: str, perm: str, tried: bool = True
) -> Answer:
    """Whether (ptype, pid) holds perm on type_name oid, why (authz.explain), and if not, the changes that would
    grant it, best first. c: the compiled policy in force; runs in the caller's transaction and leaves nothing
    behind (each change is undone). tried=False (a transaction that can't write): the changes that might grant
    it, none tried."""
    t = permission_of(c, type_name, perm)
    g = Grants(c, db, ptype, pid)
    g.sign_in(False)
    who = pid if ptype == "user" else f"{ptype}:{pid}"
    explain = (
        [text(x, "l") for x in db.rows("SELECT l FROM authz.explain($1, $2, $3, $4) l", [type_name, oid, perm, who])]
        if ptype == "user"
        else []
    )
    g.sign_in()
    holds = flag(db.rows("SELECT coalesce(authz.can($1, $2, $3), false) AS ok", [type_name, oid, perm])[0], "ok")
    if ptype != "user":
        explain = [text(x, "l") for x in db.rows("SELECT l FROM authz.explain($1, $2, $3) l", [type_name, oid, perm])]
    p = t.perms[perm]
    answer = Answer(holds, explain, f"{perm} = {p.src}  ({p.loc})")
    if holds:
        return answer
    # someone who counts as nobody signed in (an id their table doesn't have, or a row their type's where leaves
    # out), or an object that isn't there or holds nothing: no change to shares or links gives it, so none is tried
    answer.stops = [x for x in (g.stop(c.types[ptype], pid), g.stop(t, oid)) if x]
    if answer.stops:
        return answer
    candidates: list[Way] = []
    seen_sql: set[tuple[str, ...]] = set()
    for changes in g.ways(t, oid, Ref(perm), 0, frozenset()):
        key = tuple(ch.sql for ch in changes)
        if key not in seen_sql:
            seen_sql.add(key)
            candidates.append(Way(changes))
    candidates.sort(key=lambda w: (len(w.changes), sum(ch.cost for ch in w.changes)))
    if not tried:
        answer.ways, answer.notes = candidates[:SHOWN], list(dict.fromkeys(g.notes))
        return answer
    people = g.holders(t, oid, perm)
    for way in candidates[:TRIES]:
        g.attempt(way, t, oid, perm, people)
    # the way that gives the least beside what was asked comes first: the fewest other permissions, on the object
    # and on others (and the fewest people who lose any), then the fewest other objects and people
    answer.ways = sorted(
        [w for w in candidates if w.grants],
        key=lambda w: (
            len(w.changes),
            len(w.also) + len(w.elsewhere) + sum(k for *_, k in w.takes),
            w.more_people + w.more_objects + sum(n for _, _, n in w.elsewhere),
            sum(ch.cost for ch in w.changes),
        ),
    )[:SHOWN]
    answer.notes = [] if answer.ways else list(dict.fromkeys(g.notes))
    # a change that couldn't be made (the link table has another column that must be given, say) is no answer
    # either way: said, so "nothing grants it" isn't read where one change would
    answer.untried = [w for w in candidates[:TRIES] if w.error][:SHOWN]
    return answer


def describe(answer: Answer, who: str, type_name: str, oid: str, perm: str) -> str:
    """The answer as the command prints it."""
    out = []
    if answer.holds:
        out.append(f"yes: {who} holds {perm} on {type_name} {oid}")
        out += ["  " + x for x in answer.explain]
        return "\n".join(out)
    out.append(f"no: {who} does not hold {perm} on {type_name} {oid}")
    out += ["  " + x for x in answer.explain]
    out.append(f"{answer.needs}")
    if answer.ways:
        out.append("would be granted by:")
        for w in answer.ways:
            also = []
            if w.also:
                also.append(f"{', '.join(w.also)} on it")
            more = more_of(([(type_name, perm, w.more_objects)] if w.more_objects else []) + w.elsewhere, perm)
            if more:
                also.append(f"{', and '.join(more)} for {who}")
            if w.more_people:
                also.append(f"{perm} on it to {w.more_people} more {'people' if w.more_people != 1 else 'person'}")
            lines = sorted({str(ch.loc) for ch in w.changes})
            takes = taken(w.takes, perm)
            out.append(
                f"  {w.text}"
                + (f" (also gives {', and '.join(also)})" if also else "")
                + (f" (takes {', and '.join(takes)})" if takes else "")
                + f"  [{', '.join(lines)}]"
            )
    elif answer.stops:
        out += answer.stops
    elif answer.untried:
        out.append("no single change that could be tried grants it")
    else:
        out.append("no single change to shares or links grants it")
    for w in answer.untried:
        out.append(f"could not be tried: {w.text} ({w.refused})")
    for n in answer.notes:
        out.append(f"note: {n}")
    return "\n".join(out)
