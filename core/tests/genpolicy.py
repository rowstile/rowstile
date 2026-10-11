#!/usr/bin/env python3
"""genpolicy: random policies, each with its tables and data, checked like the fixed ones.

    python3 tests/genpolicy.py --db authz_gen --policies 20 --steps 20 --seed 1

Each seed makes a small policy from the language: a user type (sometimes `where {active}`), one to three object
types, sometimes a service that signs in; relations from columns, link tables (sometimes `where {active}`) and
shares, to users, the service, `user:*`, `anyone` and other types' members; permissions made of `or`, `and`,
`not`, conditions, `signed_in`, `anyone`, `nobody`, arrows to other types, inheritance (stopped by a condition or not,
across two types or not) and a deny that inherits; rules, the write rules sometimes with a condition that reads
another governed table (a subquery, a function called by a quoted name, an operator the app made); invariants.
Some also say what no draw above does, drawn apart so that the rest stays as it was (also(), shared_if(), masks(),
across(), perm_groups(), custom_roles(), share_links()): a starting point with a `not` in a permission that
inherits, a relation declared again for an earlier type through a link table (a `parent`, or a relation to users), a
condition on the shares made of a relation (`shared by p1 if {...}`, which around.py's calls of authz.share()
judge), a table read through a view the policy makes, a column masked there, a recursion through two types (an
earlier type's rows inside a later one's too, through a link table, inheriting back what the later type inherits
from it: one tree across both), a group named by a permission (`t1#p2`), custom roles, with and without `from`
(roles, permissions that give them, manage_roles where they are made, and some given in the data), and `link` among
a shared relation's subjects (shares to a token's hash, TOKENS in each user's context).
Then the tables it reads and their data. A third of the seeds name those tables and columns as an app's own may be
(AWKWARD: capitals, words SQL reserves, a double quote, 63 bytes), the policy otherwise the same; nearly half give
every key another type than bigint (KEYS: int, text or uuid), said on each type line; and a quarter of the others
key their object types by (org_id, id), every column that points at an object then naming one in its row's org
(`[org_id, c_up]`, `(parent_type, [org_id, parent_id])`, link tables `([org_id, obj_id] -> [org_id, subj_id])`).
Some have caveats (CAVEATS), which some of their shares carry, read in each user's context, and some scopes
(draw_scopes()), with which the checks ask one user again each time: each of these drawn apart too.
Now and then a seed's policy has a twin, checked after it over fewer steps (variants()): the same with no rule at
all, or with no permission at all, its rules naming relations.

A policy the compiler refuses is skipped (and counted). So is one whose reads Postgres plans slowly (authz.lint()
warns about its select rule: a check of it takes minutes to hours), and a seed that goes over --seconds: both are
counted and their seeds printed. For each of the others, after every one of a few random changes to the data:
  - difftest's checks (tests/difftest.py: list, can, explain, who, the rows each rule allows, verify)
  - authz.check_invariants() against the reference evaluator
and at the end, `rowstile prove`: an invariant it says holds must not be broken by the data seen.
A failing policy is shrunk (an invariant, a rule, a type, a part of a permission taken away while it still fails)
and printed with its seed, so `--only SEED` runs it again. With --decisions, each policy's parts that never decided
an answer in those checks are said after it (tests/decisions.py).
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import os
import random
import re
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import ClassVar, TypeAlias

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))
import difftest  # noqa: E402
from authzlib import evaluate, parse_policy, prove  # noqa: E402
from authzlib.sqlutil import q, qt  # noqa: E402
from difftest import DB, Checker, Gen, Ids, idsql, lit  # noqa: E402

# a permission's definition, as a tree that can be shrunk: an atom's text, or (op, parts)
Node: TypeAlias = "str | tuple[str, list[Node]]"
SCHEMA = "gp"
USERS = 5  # users 1..5
GONE = str(USERS + 1)  # an id the user table doesn't have: links may name it, and it signs in, as nobody
ROWS = 7  # rows of each object type at the start

# The database's names as a third of the policies spell them, as an app's own may be named: capitals, words SQL
# reserves, a double quote, a name as long as Postgres allows (63 bytes). The policy writes a name as it is, and the
# compiler quotes it in the SQL it writes; these policies' conditions, the data and the checks quote it themselves. A name
# quoted wrongly anywhere (a quoted function's name was one, an app's capitals another) is then met by the checks.
AWKWARD = {
    SCHEMA: "Gp",
    "users": "user",
    "bots": "Order",
    "t1": "select",
    "t2": "T2",
    "t3": "T3_" + "long_name_" * 6,
    "id": "Id",
    "b1": "B1",
    "b2": "order",
    "b3": 'Arch"ived',  # a quote in a name: doubled wherever it is quoted
    "parent_type": "ParentType",
    "parent_id": "parentId",
    "org_id": "OrgId",
    "obj_id": "Obj",
    "subj_id": "Subj",
    "active": "Active",
    "note": "Note",
}


# The types a policy's keys may have (every type's the same), drawn apart: bigint for most, as before
KEYS = ("bigint", "int", "text", "uuid")
UUID = "00000000-0000-4000-8000-{:012d}"  # row n's key, where keys are uuids
ORGS = 2  # where object types are keyed by (org_id, id): the orgs their rows are in


@dataclass(frozen=True)
class Spelling:
    """How a policy writes its database: its tables and columns named as genpolicy's plain names (gp.t1, b1), or
    AWKWARD's; and the type of its keys (KEYS), every type's the same. Row n's key is n, its text where keys are
    text, UUID's where they are uuids. composite: the object types are keyed by (org_id, id) instead, both bigint
    (their ids are the row's text, '(1,3)'), and whatever points at an object names one in its own row's org."""

    awkward: bool = False
    keytype: str = "bigint"
    composite: bool = False

    def name(self, plain: str) -> str:
        """The name, as the policy writes it."""
        if not self.awkward:
            return plain
        if plain in AWKWARD:
            return AWKWARD[plain]
        if plain.startswith("c_"):  # a relation's column
            return f"C_{plain[2:]}"
        return f"Link_{plain}" if "_" in plain else plain  # a link table, t1_r1

    def sql(self, plain: str) -> str:
        """The name, as SQL writes it: quoted, when it is awkward."""
        return q(self.name(plain)) if self.awkward else plain

    def table(self, plain: str) -> str:
        """A table, as SQL writes it."""
        return f"{self.sql(SCHEMA)}.{self.sql(plain)}"

    def policy_table(self, plain: str) -> str:
        """A table, as the policy writes it."""
        return f"{self.name(SCHEMA)}.{self.name(plain)}"

    def key(self, obj: bool = False) -> str:
        """A type line's key, said when the key column isn't id or its type isn't bigint (obj: an object type's)."""
        if obj and self.composite:
            return f" ({self.name('org_id')}, {self.name('id')})"
        if not self.awkward and self.keytype == "bigint":
            return ""
        return f" ({self.name('id')}{'' if self.keytype == 'bigint' else ' ' + self.keytype})"

    def ref(self, column: str) -> str:
        """A column that points at an object, as the policy writes it: with the row's org, where keys are composite."""
        return f"[{self.name('org_id')}, {self.name(column)}]" if self.composite else self.name(column)

    def ident(self, n: int | str) -> str:
        """Row n's key, as text (as the checks read ids)."""
        return UUID.format(int(n)) if self.keytype == "uuid" else str(n)

    def number(self, ident: str) -> int:
        """The n of row n's key."""
        return int(ident[-12:]) if self.keytype == "uuid" else int(ident)

    def literal(self, ident: str) -> str:
        """A key in SQL: a number as it is, text and uuids quoted."""
        return ident if self.keytype in ("bigint", "int") else lit(ident)

    def key_of(self, n: str) -> str:
        """The key of row n, n an SQL integer."""
        if self.keytype == "uuid":
            return f"('{UUID.split('{')[0]}' || lpad(({n})::text, 12, '0'))::uuid"
        return f"({n})::text" if self.keytype == "text" else n

    def cond(self, plain: str) -> str:
        """One of genpolicy's {conditions}, with its names spelled (they are SQL: quoted). Where keys are text or
        uuids, the next row's key is gp.nxt(this.id), not this.id + 1."""
        if self.keytype in ("text", "uuid"):
            plain = plain.replace("this.id + 1", f"{SCHEMA}.nxt(this.id)")
        if not self.awkward:
            return plain
        text = (
            plain.replace(f"{SCHEMA}.nxt(", f"{self.sql(SCHEMA)}.nxt(")
            .replace(f'{SCHEMA}."Flag"', f'{self.sql(SCHEMA)}."Flag"')
            .replace(f"{SCHEMA}.t1", self.table("t1"))
        )
        text = text.replace(f"{SCHEMA}.users", self.table("users"))
        return re.sub(r"\b(id|b1|b2|b3|active)\b", lambda m: self.sql(m.group(1)), text)


@dataclass
class Rel:
    name: str
    kind: str  # column | table | shared
    subjects: list[str]  # user, bot, user:*, anyone, tN#member, or an object type (links: up, parent)
    where: bool = False  # a link table's `where {active}`
    by: str = ""  # shared: `shared by <permission>`
    shared_if: str = ""  # shared: `if {...}`, one of SHARED_IFS


@dataclass
class Obj:
    name: str
    where: bool  # `where {not b3}`
    rels: list[Rel]
    perms: dict[str, Node]  # p1, p2, p3
    rules: list[tuple[str, Node]]  # (head, expression): 'select', 'update', 'update b1', 'delete', 'insert'
    mask: str = ""  # a permission: the table's rows through a view, its note NULL there unless it holds (masks())
    roles: tuple[list[str], str] | None = None  # custom roles: who may hold them, and `from` what (custom_roles())


@dataclass
class Spec:
    seed: int
    user_where: bool
    bot: bool
    objs: list[Obj]
    invariants: list[tuple[str, Node]] = field(default_factory=list)
    spelling: Spelling = field(default_factory=Spelling)
    caveats: bool = False  # the policy says CAVEATS, and some shares carry one
    # scopes, what a token limited to them may do: (name, [(kind, qualifier, word)]), kind cmd or perm, a command
    # qualified by a type's table (named by the type) and a permission by a type
    scopes: list[tuple[str, list[tuple[str, str, str]]]] = field(default_factory=list)

    def obj(self, name: str) -> Obj:
        return next(o for o in self.objs if o.name == name)


# ----------------------------------------------------------------------
# The policy
# ----------------------------------------------------------------------
CONDS = ["{b1}", "{not b2}", "{b1 and b2}", "signed_in", "anyone", "nobody"]
# conditions that read another governed table (t1, whose rows the app role sees only through its select rule): a
# subquery, a function called by a quoted name, an operator the app made. They must read with the policy's rights
# where the app role checks a row; write rules take them (not inheritance: the trees would store their answer).
# Each reads the next row of t1, one the user may not see even where the row checked is t1's own
READS = [
    f"{{exists (select 1 from {SCHEMA}.t1 x where x.id = this.id + 1 and x.b2)}}",
    f'{{{SCHEMA}."Flag"(this.id + 1)}}',
    "{=!= (this.id + 1)}",
]
# `shared ... if {...}`: a condition on the share being made, which authz.share() checks. difftest and genpolicy
# write shares as the owner, which no condition sees; around.py's calls of authz.share() judge it, by what each
# says here: (the object's id, the subject's type, its id, the users whose row is active) -> may it be shared
SHARED_IFS: dict[str, Callable[[str, str, str, set[str]], bool]] = {
    "{object_id::text ~ '[02468][)]?$'}": lambda obj, st, sid, active: obj.rstrip(")")[-1] in "02468",
    "{subject_type <> 'user' or right(subject_id, 1) <> '2'}": lambda obj, st, sid, active: (
        st != "user" or sid[-1] != "2"
    ),
    f"{{subject_type <> 'user' or subject_id = '*' or exists (select 1 from {SCHEMA}.users u where "
    "u.id::text = subject_id and u.active)}": lambda obj, st, sid, active: st != "user" or sid in ("*", *active),
}


# caveats, conditions a share carries and each request checks (in its context, authz_ctx.*): one on the context
# alone, one on what the share was made with too. A share may also name one the policy doesn't have
CAVEATS = {"c_mode": "{authz.ctx('mode') = 'business'}", "c_ip": "{authz.ctx('ip') = arg('ip')}"}


def make(seed: int, respell: bool | None = None, keytype: str | None = None, composite: bool | None = None) -> Spec:
    """The seed's policy. Its names are AWKWARD's for a third of the seeds (respell: for this one, or not), its keys
    are int, text or uuid for about one seed in seven each, bigint otherwise (keytype: these), and a quarter of
    those with bigint keys key their object types by (org_id, id) (composite: these, or not), each drawn apart from
    the rest, so that a seed's policy is the same either way."""
    awkward = random.Random(f"genpolicy/{seed}/spelling").random() < 1 / 3 if respell is None else respell
    if keytype is None:
        x = random.Random(f"genpolicy/{seed}/keys").random()
        keytype = KEYS[3 if x < 0.15 else 2 if x < 0.3 else 1 if x < 0.45 else 0]
    if composite is None:
        composite = keytype == "bigint" and random.Random(f"genpolicy/{seed}/composite").random() < 0.25
    spec = make_plain(seed)
    shared = any(rel.kind == "shared" for o in spec.objs for rel in o.rels)  # (caveats ride on shares)
    caveats = random.Random(f"genpolicy/{seed}/caveats").random() < 0.3 and shared
    scopes = draw_scopes(spec, random.Random(f"genpolicy/{seed}/scopes"))
    return dataclasses.replace(spec, spelling=Spelling(awkward, keytype, composite), caveats=caveats, scopes=scopes)


def draw_scopes(spec: Spec, x: random.Random) -> list[tuple[str, list[tuple[str, str, str]]]]:
    """For a third of the seeds, a scope or two, of commands and permissions, each plain or qualified (gp.t1.select,
    t2.p1); the first, now and then, the built-in `read` said again."""
    if x.random() >= 1 / 3:
        return []
    names = [o.name for o in spec.objs]
    pool = [("cmd", "", c) for c in ("select", "insert", "update", "delete")]
    pool += [("cmd", n, c) for n in names for c in ("select", "update")]
    pool += [("perm", "", p) for p in ("p1", "p2", "p3")] + [("perm", n, p) for n in names for p in ("p1", "p2", "p3")]
    out: list[tuple[str, list[tuple[str, str, str]]]] = []
    for k in range(x.randint(1, 2)):
        name = "read" if k == 0 and x.random() < 0.3 else f"s{k + 1}"
        out.append((name, x.sample(pool, x.randint(1, 3))))
    return out


def variants(seed: int) -> list[tuple[str, Spec]]:
    """The seed's policy, and now and then (drawn apart) a twin of it that no policy is otherwise: with no rule at
    all, or with no permission at all (each type's rules naming its relations). A twin is checked over fewer
    steps (TWIN_STEPS): it is there for what its SQL leaves out."""
    spec = make(seed)
    x = random.Random(f"genpolicy/{seed}/twins")
    out = [("", spec)]
    if x.random() < 0.15:
        out.append(
            (
                "without rules",
                dataclasses.replace(spec, objs=[dataclasses.replace(o, rules=[], mask="") for o in spec.objs]),
            )
        )
    if x.random() < 0.15:
        out.append(("without permissions", without_permissions(spec, x)))
    return out


TWIN_STEPS = 3


def without_permissions(spec: Spec, x: random.Random) -> Spec:
    """The policy with no permission on any type: each keeps the relations a rule may name alone (from columns and
    link tables, to users, the service and groups that stay), and its rules name them, or {conditions}."""
    names = [o.name for o in spec.objs]
    kept: dict[str, list[Rel]] = {}
    for o in spec.objs:
        # shares need a permission to share them, and links to rows of a type are followed by one: they go, and so
        # does a group whose members were shared, and one named by a permission (perm_groups())
        kept[o.name] = [
            rel
            for rel in o.rels
            if rel.kind in ("column", "table")
            and rel.name not in ("up", "parent")
            and not any(s in names for s in rel.subjects)
            and all(
                s.endswith("#member") and any(m.name == "member" for m in kept.get(s.split("#")[0], []))
                for s in rel.subjects
                if "#" in s
            )
        ]
    groups = {s for rels in kept.values() for rel in rels for s in rel.subjects if "#" in s}
    objs: list[Obj] = []
    for o in spec.objs:
        atoms = list(dict.fromkeys(rel.name for rel in kept[o.name])) or ["{b1}"]
        rules: list[tuple[str, Node]] = [
            (head, "{b1}" if head == "insert" else expr(x, atoms, 1)) for head, _ in o.rules
        ]
        # every relation is used (AZ208): one no rule names goes into the select rule, but a group, used as one
        named = " ".join(text(e) for _, e in rules).replace("(", " ").replace(")", " ").split()
        for name in atoms:
            if name not in named and f"{o.name}#{name}" not in groups and not name.startswith("{"):
                rules = [(h, ("or", [e, name]) if h == "select" else e) for h, e in rules]
        objs.append(Obj(o.name, o.where, kept[o.name], {}, rules))  # (no mask: masks name permissions)
    # a scope's permissions go with them; a scope left with nothing goes too
    scopes = [(n, items) for n, s_items in spec.scopes if (items := [i for i in s_items if i[0] == "cmd"])]
    return dataclasses.replace(spec, objs=objs, invariants=[], scopes=scopes)


def make_plain(seed: int) -> Spec:
    r = random.Random(f"genpolicy/{seed}")
    spec = Spec(seed, r.random() < 0.4, r.random() < 0.3, [])
    for k in range(1, r.randint(1, 3) + 1):
        name = f"t{k}"
        earlier = [o.name for o in spec.objs]
        rels: list[Rel] = []
        held: list[str] = []
        groups = [f"{o.name}#member" for o in spec.objs if any(x.name == "member" for x in o.rels)]
        for i in range(1, r.randint(1, 3) + 1):
            kind = r.choice(["column", "column", "table", "shared"])
            if kind == "shared":
                pool = ["user", "user:*", "anyone", *groups, *(["bot"] if spec.bot else [])]
                subjects = sorted(set(r.sample(pool, r.randint(1, min(3, len(pool))))), key=pool.index)
            elif kind == "table":
                subjects = [r.choice(["user", *groups])]
            else:
                subjects = [r.choice(["user", "user", *(["bot"] if spec.bot else [])])]
            rels.append(
                Rel(f"r{i}", kind, subjects, kind == "table" and r.random() < 0.4, r.choice(["p1", "p2", "p3"]))
            )
            held.append(f"r{i}")
        if r.random() < 0.5:  # members: others' `tN#member` subjects, groups in groups
            kind = r.choice(["table", "shared"])
            subjects = ["user"] + ([f"{name}#member"] if kind == "shared" and r.random() < 0.5 else [])
            rels.append(Rel("member", kind, subjects, by=r.choice(["p1", "p2", "p3"])))
            held.append("member")
        if earlier and r.random() < 0.6:
            rels.append(Rel("up", "column", [r.choice(earlier)]))
        parent = r.random() < 0.6
        if parent:
            poly = earlier and r.random() < 0.3
            rels.append(Rel("parent", "column", [name, r.choice(earlier)] if poly else [name]))
        o = Obj(name, r.random() < 0.3, rels, {}, [])
        deny = parent and r.random() < 0.3
        base: dict[str, Node] = {}
        for i in (1, 2, 3):
            atoms = (
                held
                + [f"p{j}" for j in range(1, i)]
                + [f"up.p{j}" for j in (1, 2, 3) if has(o, "up")]
                + [f"parent.p{j}" for j in range(1, i) if parent]
            )
            base[f"p{i}"] = r.choice(held) if deny and i == 1 else expr(r, atoms, 2)
        # every relation is used (AZ208): one nothing names goes into p3, before any inheritance
        named = " ".join(text(e) for e in base.values()).replace(".", " . ").replace("(", " ").replace(")", " ").split()
        for rel in rels:
            if rel.name not in named:
                base["p3"] = ("or", [base["p3"], f"{rel.name}.p1" if rel.name in ("up", "parent") else rel.name])
        for p, e in base.items():
            if deny and p == "p1":  # a deny that inherits: p1 = r or parent.p1
                e = ("or", [e, "parent.p1"])
            elif parent and r.random() < 0.6:  # inheritance, stopped by a condition or a deny or not at all
                e = ("or", [e, f"parent.{p}"])
                if deny and r.random() < 0.6:
                    e = ("and", [e, ("not", ["p1"])])
                elif r.random() < 0.3:
                    e = ("and", [e, "{not b3}"])
            o.perms[p] = e
        perms = list(o.perms)
        o.rules.append(("select", r.choice(perms)))
        for head in ("update", "delete"):
            if r.random() < 0.6:
                o.rules.append((head, r.choice(perms)))
        if r.random() < 0.3:
            o.rules.append(("insert", r.choice(["{b1}", *[f"up.p{j}" for j in (1, 2) if has(o, "up")]])))
        if r.random() < 0.2 and any(h == "update" for h, _ in o.rules):
            o.rules.append(("update b1", r.choice(perms)))
        o.rules = [
            (head, ("and", [e, r.choice(READS)]) if head != "select" and r.random() < 0.4 else e) for head, e in o.rules
        ]
        spec.objs.append(o)
    for _ in range(r.randint(0, 2)):
        o = r.choice(spec.objs)
        a, b = r.sample(list(o.perms), 2)
        inv = (o.name, ("and", [a, r.choice([("not", [b]), "{b1}", ("not", ["{b2}"])])]))
        if inv not in spec.invariants:
            spec.invariants.append(inv)
    also(spec, random.Random(f"genpolicy/{seed}/also"))
    shared_if(spec, random.Random(f"genpolicy/{seed}/shared-if"))
    masks(spec, random.Random(f"genpolicy/{seed}/masks"))
    across(spec, random.Random(f"genpolicy/{seed}/across"))
    perm_groups(spec, random.Random(f"genpolicy/{seed}/perm-groups"))
    custom_roles(spec, random.Random(f"genpolicy/{seed}/roles"))
    share_links(spec, random.Random(f"genpolicy/{seed}/links"))
    return spec


def also(spec: Spec, x: random.Random) -> None:
    """What some policies say besides, drawn apart from the rest (x), so that each seed's policy keeps all it drew
    before: a starting point with a `not` in a permission that inherits (`(r1 and not {b1}) or ... or
    parent.p2`); `parent` declared again for an earlier type, through a link table (a type's row inside another's);
    and a relation to users declared again for objects, through a link table (alone in a rule, its users)."""
    for k, o in enumerate(spec.objs):
        earlier = [e.name for e in spec.objs[:k]]
        users = [rel.name for rel in o.rels if rel.kind == "column" and rel.name not in ("up", "parent")]
        inherits = [
            p for p, e in o.perms.items() if not isinstance(e, str) and e[0] == "or" and e[1][-1] == f"parent.{p}"
        ]
        start = ""
        if inherits and x.random() < 0.3:
            p, start = x.choice(inherits), x.choice(users) if users else "{b2}"
            item: Node = ("and", [start, ("not", ["{b1}"])])
            e = o.perms[p]
            assert not isinstance(e, str)
            o.perms[p] = ("or", [item, *e[1]])
        # (a deny that inherits through parent can't through another type's: no second source of it there)
        if earlier and has(o, "parent") and not denies(o) and x.random() < 0.5:
            o.rels.append(Rel("parent", "table", [x.choice(earlier)], x.random() < 0.4))
        others = [u for u in users if u != start]
        if earlier and others and x.random() < 0.2:
            o.rels.append(Rel(x.choice(others), "table", [x.choice(earlier)]))


def shared_if(spec: Spec, x: random.Random) -> None:
    """A condition on the shares made of some shared relations (SHARED_IFS), drawn apart from the rest (x)."""
    for o in spec.objs:
        for rel in o.rels:
            if rel.kind == "shared" and x.random() < 0.4:
                rel.shared_if = x.choice(list(SHARED_IFS))


def masks(spec: Spec, x: random.Random) -> None:
    """Now and then a table read through a view of the policy's, its note masked (NULL there) unless a permission
    holds, drawn apart from the rest (x)."""
    for o in spec.objs:
        if any(head == "select" for head, _ in o.rules) and x.random() < 0.25:
            o.mask = x.choice(list(o.perms))


def across(spec: Spec, x: random.Random) -> None:
    """Recursion through two types, as folders sit in projects and projects in folders, drawn apart from the rest
    (x): where a type's `parent` names an earlier type, now and then that earlier type's rows sit inside the
    type's too, through a link table (`inside`, sometimes `where {active}`), and a permission the type inherits
    through `parent` is inherited back (`or inside.pN`): one recursion, one tree, across the two."""
    for o in spec.objs:
        earlier = [s for rel in o.rels if rel.name == "parent" for s in rel.subjects if s != o.name]
        if not earlier or denies(o) or x.random() < 0.2:
            continue
        e = spec.obj(x.choice(earlier))
        # (one that reaches the earlier type by `parent` alone: by `up` too, it would recurse otherwise than by
        # inheriting, which the compiler refuses)
        up = any(rel.name == "up" and rel.subjects == [e.name] for rel in o.rels)
        inherits = [p for p, ex in o.perms.items() if f"parent.{p}" in atoms(ex) and not (up and reaches_up(o, p))]
        # (nor what the earlier type denies, or denies with: a deny inherits through the links of what it denies)
        inherits = [p for p in inherits if not (denies(e) and (p == "p1" or ("not", ["p1"]) in atoms_and(e.perms[p])))]
        if not inherits or has(e, "inside"):
            continue
        p = x.choice(inherits)
        e.rels.append(Rel("inside", "table", [o.name], x.random() < 0.5))
        e.perms[p] = ("or", [e.perms[p], f"inside.{p}"])


def perm_groups(spec: Spec, x: random.Random) -> None:
    """A group named by a permission of another type instead of its members (`t1#p2`: whoever holds p2 on the
    linked row), now and then, drawn apart from the rest (x)."""
    for o in spec.objs:
        for rel in o.rels:
            for i, subject in enumerate(rel.subjects):
                st = subject.split("#")[0]
                if "#" in subject and st != o.name and x.random() < 0.4:
                    rel.subjects[i] = f"{st}#{x.choice(list(spec.obj(st).perms))}"


def custom_roles(spec: Spec, x: random.Random) -> None:
    """Custom roles on some types, drawn apart from the rest (x): users may hold them, sometimes an earlier type's
    members too; where the type has `up`, often `from up` (a role then counts where up links the object to the
    role's owner); one or two permissions a role may give (`... or roles`); and `can manage_roles` on the type
    that owns them, for whoever makes them (the checks try the roles API too)."""
    for k, o in enumerate(spec.objs):
        if x.random() >= 0.15:
            continue
        groups = [f"{e.name}#member" for e in spec.objs[:k] if has(e, "member")]
        subjects = ["user"] + ([x.choice(groups)] if groups and x.random() < 0.5 else [])
        up = next((rel.subjects[0] for rel in o.rels if rel.name == "up" and rel.kind == "column"), "")
        o.roles = (subjects, "up" if up and x.random() < 0.6 else "")
        for p in x.sample(["p1", "p2", "p3"], x.randint(1, 2)):
            e = o.perms[p]  # (in what a deny or a condition narrows, if that is how it reads: it stays that shape)
            narrowed = not isinstance(e, str) and e[0] == "and" and not isinstance(e[1][0], str) and e[1][0][0] == "or"
            o.perms[p] = ("and", [("or", [*e[1][0][1], "roles"]), *e[1][1:]]) if narrowed else ("or", [e, "roles"])
        # who makes the roles: whoever holds manage_roles on their owner, of up's type (`from up`) or of any type
        owner = spec.obj(up) if o.roles[1] else o
        owner.perms.setdefault("manage_roles", x.choice(["p1", "p2", "p3"]))


# share links: a share to `link` names a token's hash; whoever holds the token (in the request's context) has it
TOKENS = ["tok-a", "tok-b", "tok-c"]


def share_links(spec: Spec, x: random.Random) -> None:
    """`link` among the subjects of some shared relations, drawn apart from the rest (x)."""
    for o in spec.objs:
        for rel in o.rels:
            if rel.kind == "shared" and "link" not in rel.subjects and x.random() < 0.3:
                rel.subjects.append("link")


def links(spec: Spec) -> bool:
    return any("link" in rel.subjects for o in spec.objs for rel in o.rels)


def denies(o: Obj) -> bool:
    """Whether a permission of o takes away what it inherits (`... and not p1`)."""
    return any(not isinstance(e, str) and e[0] == "and" and ("not", ["p1"]) in e[1] for e in o.perms.values())


def reaches_up(o: Obj, p: str, seen: frozenset[str] = frozenset()) -> bool:
    """Whether o.p follows `up`, itself or through the permissions of o it names."""
    return any(
        a.startswith("up.") or (a in o.perms and a not in seen and reaches_up(o, a, seen | {p}))
        for a in atoms(o.perms[p])
    )


def atoms_and(n: Node) -> list[Node]:
    """The items of an `and` (itself, for anything else)."""
    return n[1] if not isinstance(n, str) and n[0] == "and" else [n]


def atoms(n: Node) -> list[str]:
    return [n] if isinstance(n, str) else [a for x in n[1] for a in atoms(x)]


def has(o: Obj, rel: str) -> bool:
    return any(x.name == rel for x in o.rels)


def expr(r: random.Random, atoms: list[str], depth: int) -> Node:
    if depth == 0 or r.random() < 0.35:
        return r.choice(CONDS) if r.random() < 0.25 else r.choice(atoms)
    op = r.choice(["or", "and"])
    parts = [expr(r, atoms, depth - 1) for _ in range(r.randint(2, 3))]
    if op == "and" and r.random() < 0.3:
        parts.append(("not", [r.choice(CONDS[:3] + [a for a in atoms if not a.startswith("parent.")])]))
    return (op, parts)


def text(n: Node, top: bool = True, s: Spelling | None = None) -> str:
    if isinstance(n, str):
        return (s or Spelling()).cond(n) if n.startswith("{") else n
    op, parts = n
    if op == "not":
        return "not " + text(parts[0], False, s)
    flat: list[Node] = []  # (a or b) or c is written a or b or c
    for x in parts:
        flat += x[1] if not isinstance(x, str) and x[0] == op else [x]
    out = f" {op} ".join(text(x, False, s) for x in flat)
    return out if top else f"({out})"


def policy_text(spec: Spec) -> str:
    s = spec.spelling
    active, archived = s.cond("{active}"), s.cond("{not b3}")
    out = [
        "app role app_user",
        f"type user = {s.policy_table('users')}{s.key()}" + (f" where {active}" if spec.user_where else ""),
    ]
    if spec.bot:
        out.append(f"type bot = {s.policy_table('bots')}{s.key()} principal where {active}")
    for o in spec.objs:
        out.append(
            f"type {o.name} = {s.policy_table(o.name)}{s.key(obj=True)}" + (f" where {archived}" if o.where else "")
        )
        names = {x.name for x in spec.objs}
        for rel in o.rels:
            subj = ", ".join(rel.subjects)
            to_objects = rel.subjects[0].split("#")[0] in names
            if rel.kind == "column" and rel.name == "parent" and len(rel.subjects) == 2:
                src = f"({s.name('parent_type')}, {s.ref('parent_id')})"
            elif rel.kind == "column" and rel.name == "parent":
                src = s.ref("parent_id")
            elif rel.kind == "column":
                src = s.ref(f"c_{rel.name}") if to_objects else s.name(f"c_{rel.name}")
            elif rel.kind == "table":
                subj_col = s.ref("subj_id") if to_objects else s.name("subj_id")
                src = f"{s.policy_table(f'{o.name}_{rel.name}')}({s.ref('obj_id')} -> {subj_col})" + (
                    f" where {active}" if rel.where else ""
                )
            else:
                src = "shared"
            if src == "shared":
                src = f"shared by {rel.by}" + (f" if {s.cond(rel.shared_if)}" if rel.shared_if else "")
                out.append(f"  {rel.name} : {subj} {src}")
            else:
                out.append(f"  {rel.name} : {subj} = {src}")
        if o.roles:
            out.append(f"  roles : {', '.join(o.roles[0])}" + (f" from {o.roles[1]}" if o.roles[1] else ""))
        for p, e in o.perms.items():
            out.append(f"  can {p} = {text(e, s=s)}")
    for name, items in spec.scopes:
        written = [
            f"{s.policy_table(qual)}.{word}" if kind == "cmd" and qual else f"{qual}.{word}" if qual else word
            for kind, qual, word in items
        ]
        out.append(f"scope {name} = {', '.join(written)}")
    if spec.caveats:
        out += [f"caveat {name} = {cond}" for name, cond in CAVEATS.items()]
    for o in spec.objs:
        if o.rules:
            view = f" view {s.policy_table(f'{o.name}_seen')}" if o.mask else ""
            out.append(f"rules {s.policy_table(o.name)}{view}")
            out += [f"  mask {s.name('note')} : {o.mask}"] if o.mask else []
            out += [
                f"  {' '.join([head.split()[0], *map(s.name, head.split()[1:])])} : {text(e, s=s)}"
                for head, e in o.rules
            ]
    if spec.invariants:
        out.append("invariants")
        out += [f"  never {t}: {text(e, s=s)}" for t, e in spec.invariants]
    return "\n".join(out) + "\n"


def schema_text(spec: Spec) -> str:
    n = spec.spelling
    i, active, k = n.sql("id"), n.sql("active"), n.keytype
    s = [
        f"CREATE SCHEMA {n.sql(SCHEMA)};",
        f"CREATE TABLE {n.table('users')} ({i} {k} PRIMARY KEY, {active} boolean NOT NULL DEFAULT true);",
        f"CREATE TABLE {n.table('bots')} ({i} {k} PRIMARY KEY, {active} boolean NOT NULL DEFAULT true);",
    ]
    org = n.sql("org_id")
    for o in spec.objs:
        cols = [
            f"{org} bigint, {i} bigint" if n.composite else f"{i} {k} PRIMARY KEY",
            f"{n.sql('b1')} boolean",
            f"{n.sql('b2')} boolean",
            f"{n.sql('b3')} boolean NOT NULL DEFAULT false",
            f"{n.sql('parent_type')} text",
            f"{n.sql('parent_id')} {k}",
        ]
        cols += [f"{n.sql(f'c_{rel.name}')} {k}" for rel in o.rels if rel.kind == "column" and rel.name != "parent"]
        cols += [f"{n.sql('note')} text"] if o.mask else []
        cols += [f"PRIMARY KEY ({org}, {i})"] if n.composite else []
        s.append(f"CREATE TABLE {n.table(o.name)} ({', '.join(cols)});")
        for rel in o.rels:
            if rel.kind == "table":
                # link rows go with their object and with the group they name, as the limits page tells apps
                # (a leftover row would still count); a user they name may be no row at all (GONE)
                follow = "ON DELETE CASCADE ON UPDATE CASCADE"
                group = rel.subjects[0].split("#")[0] if "#" in rel.subjects[0] else ""
                obj, subj = n.sql("obj_id"), n.sql("subj_id")
                if n.composite:  # one org for the object and an object it names
                    s.append(
                        f"CREATE TABLE {n.table(f'{o.name}_{rel.name}')} ({org} bigint, {obj} bigint, {subj} {k}, "
                        f"{active} boolean NOT NULL DEFAULT true, "
                        f"FOREIGN KEY ({org}, {obj}) REFERENCES {n.table(o.name)} {follow}, "
                        + (f"FOREIGN KEY ({org}, {subj}) REFERENCES {n.table(group)} {follow}, " if group else "")
                        + f"UNIQUE ({org}, {obj}, {subj}));"
                    )
                    continue
                s.append(
                    f"CREATE TABLE {n.table(f'{o.name}_{rel.name}')} ("
                    f"{n.sql('obj_id')} {k} REFERENCES {n.table(o.name)} {follow}, "
                    f"{n.sql('subj_id')} {k}{f' REFERENCES {n.table(group)} {follow}' if group else ''}, "
                    f"{active} boolean NOT NULL DEFAULT true, UNIQUE ({n.sql('obj_id')}, {n.sql('subj_id')}));"
                )
    # what READS calls: t1's b2, read by a function with a quoted name and by an operator made on it; and the next
    # row's key, where keys are text or uuids
    s.append(
        f'CREATE FUNCTION {n.sql(SCHEMA)}."Flag"(p {k}) RETURNS boolean LANGUAGE sql STABLE '
        f"AS 'SELECT exists (SELECT 1 FROM {n.table('t1')} x WHERE x.{i} = p AND x.{n.sql('b2')})';"
    )
    s.append(f'CREATE OPERATOR public.=!= (FUNCTION = {n.sql(SCHEMA)}."Flag", RIGHTARG = {k});')
    if k in ("text", "uuid"):
        number = "p::bigint" if k == "text" else "right(p::text, 12)::bigint"
        s.append(
            f"CREATE FUNCTION {n.sql(SCHEMA)}.nxt(p {k}) RETURNS {k} LANGUAGE sql IMMUTABLE "
            f"AS $$SELECT {n.key_of(number + ' + 1')}$$;"
        )
    s.append(
        "DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'app_user') THEN CREATE ROLE app_user; "
        "END IF; END $$;"
    )
    s.append(f"GRANT USAGE ON SCHEMA {n.sql(SCHEMA)} TO app_user;")
    s.append(f"GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA {n.sql(SCHEMA)} TO app_user;")
    return "\n".join(s) + "\n"


# ----------------------------------------------------------------------
# The data
# ----------------------------------------------------------------------
class GenPolicyGen(Gen):
    """Data for a generated policy: rows with random flags and links, link tables, shares; random changes."""

    spec: ClassVar[Spec]

    def subject_ids(self, subject: str, ids: Ids | None) -> list[str]:
        """The keys a subject may be, as text: their SQL is spelling.literal()'s (an object's, where keys are
        composite, is '(org,id)': its parts are org() and part()'s)."""
        n = self.spec.spelling
        if subject in ("user", "user:*"):
            return [n.ident(i) for i in range(1, USERS + 1)] + [n.ident(GONE)]
        if subject == "bot":
            return [n.ident(1), n.ident(2)]
        name = subject.split("#")[0]
        if n.composite:  # the first rows: row i in org 1 + i % 2
            return (ids or {}).get(name) or [f"({1 + i % ORGS},{i})" for i in range(1, ROWS + 1)]
        return (ids or {}).get(name) or [n.ident(i) for i in range(1, ROWS + 1)]

    @staticmethod
    def org(ident: str) -> str:
        """The org of an object keyed by (org_id, id)."""
        return ident.strip("()").split(",")[0]

    @staticmethod
    def part(ident: str) -> str:
        """The id of an object keyed by (org_id, id), within its org."""
        return ident.strip("()").split(",")[1]

    def pointer(self, subject: str, ids: Ids | None, org: str | None) -> str:
        """What a column pointing at subject holds, in SQL: where keys are composite, the id of an object in org
        (one of another org if it has none: a link to nothing)."""
        if org is None or subject.split("#")[0] not in {o.name for o in self.spec.objs}:
            return self.subject_id(subject, ids)
        idents = self.subject_ids(subject, ids)
        return self.part(self.r.choice([x for x in idents if self.org(x) == org] or idents))

    def subject_id(self, subject: str, ids: Ids | None) -> str:
        """One of them, in SQL."""
        return self.spec.spelling.literal(self.r.choice(self.subject_ids(subject, ids)))

    def pointers(self, subject: str, ids: Ids | None) -> list[str]:
        """What a column pointing at subject may hold, in SQL (an object's id within its org, where keys are
        composite)."""
        idents = self.subject_ids(subject, ids)
        if self.spec.spelling.composite and subject.split("#")[0] in {o.name for o in self.spec.objs}:
            return [self.part(x) for x in idents]
        return [self.spec.spelling.literal(x) for x in idents]

    def row(self, o: Obj, i: int, ids: Ids | None, org: str | None = None) -> str:
        """Row i of o (in org, where keys are composite)."""
        r, n = self.r, self.spec.spelling
        cols = ["id", "b1", "b2", "b3"]
        vals = [
            n.literal(n.ident(i)),
            r.choice(["true", "false", "NULL"]),
            r.choice(["true", "false"]),
            r.choice(["true", "false", "false"]),
        ]
        if org is not None:
            cols, vals = ["org_id", *cols], [org, *vals]
        if o.mask:  # what the view shows only to whoever holds the mask's permission
            cols, vals = [*cols, "note"], [*vals, f"'note {i}'"]
        for rel in o.rels:
            if rel.kind != "column":
                continue
            if rel.name == "parent":
                if len(rel.subjects) == 2 and r.random() < 0.4:
                    cols += ["parent_type", "parent_id"]
                    vals += [lit(rel.subjects[1]), self.pointer(rel.subjects[1], ids, org)]
                elif r.random() < 0.7:
                    cols += ["parent_type", "parent_id"]
                    vals += [lit(o.name), self.pointer(o.name, ids, org)]
                continue
            if r.random() < 0.75:
                cols.append(f"c_{rel.name}")
                vals.append(self.pointer(rel.subjects[0], ids, org))
        return (
            f"INSERT INTO {n.table(o.name)} ({', '.join(map(n.sql, cols))}) VALUES ({', '.join(vals)}) "
            "ON CONFLICT DO NOTHING;"
        )

    def initial(self) -> str:
        r, n = self.r, self.spec.spelling
        s = [
            f"INSERT INTO {n.table('users')} SELECT {n.key_of('i')}, random() < 0.8 FROM generate_series(1, {USERS}) i;",
            f"INSERT INTO {n.table('bots')} VALUES ({n.literal(n.ident(1))}, true), "
            f"({n.literal(n.ident(2))}, {str(r.random() < 0.5).lower()});",
        ]
        for o in self.spec.objs:
            s += [self.row(o, i, None, str(1 + i % ORGS) if n.composite else None) for i in range(1, ROWS + 1)]
            for rel in o.rels:
                if rel.kind == "table":
                    s += [self.link(o, rel, None) for _ in range(4)]
        return "\n".join(s)

    def link(self, o: Obj, rel: Rel, ids: Ids | None) -> str:
        r = self.r
        if self.spec.spelling.composite:  # the object's org, and an object of that org
            ident = r.choice(self.subject_ids(o.name, ids))
            org = self.org(ident)
            subj = self.pointer(rel.subjects[0], ids, org)
            return (
                f"INSERT INTO {self.spec.spelling.table(f'{o.name}_{rel.name}')} VALUES ({org}, {self.part(ident)}, "
                f"{subj}, {str(r.random() < 0.8).lower()}) ON CONFLICT DO NOTHING;"
            )
        obj = self.subject_id(o.name, ids)
        subj = self.subject_id(rel.subjects[0], ids)
        return (
            f"INSERT INTO {self.spec.spelling.table(f'{o.name}_{rel.name}')} VALUES ({obj}, {subj}, "
            f"{str(r.random() < 0.8).lower()}) ON CONFLICT DO NOTHING;"
        )

    def context(self, u: str) -> dict[str, str]:
        """Each user's request context, where the policy reads it: for caveats, business hours for half of them and
        an ip of three; for share links, the tokens they hold (nobody too: a link is for whoever has it)."""
        i = self.users.index(u) if u in self.users else len(self.users)
        ctx = {"mode": "business" if i % 2 == 0 else "night", "ip": f"10.0.0.{i % 3}"} if self.spec.caveats else {}
        if links(self.spec):
            ctx["links"] = ",".join(t for j, t in enumerate(TOKENS) if (i + j) % 3 == 0)
        return ctx

    def grants(self) -> str:
        return "\n".join([*self.custom_roles(), *(self.grant(None) for _ in range(12))])

    def when(self) -> tuple[str, str]:
        """A share's expires_at and starts_at: live, not started yet, expired, or live until tomorrow."""
        return self.r.choice(
            [
                ("NULL", "NULL"),
                ("NULL", "NULL"),
                ("NULL", difftest.LATER),
                (difftest.EXPIRED, "NULL"),
                ("now() + interval '1 day'", "NULL"),
            ]
        )

    def custom_roles(self) -> list[str]:
        """Two custom roles on each type that has them: one owned where the type takes its roles `from` (an object
        of up's type), or by a user; one giving a permission, the other two (a role may name one that doesn't
        write `roles`: it gives nothing there)."""
        r = self.r
        self.role_ids: list[tuple[int, Obj]] = []
        rows, perms = [], []
        for o in self.spec.objs:
            if not o.roles:
                continue
            owner = next((rel.subjects[0] for rel in o.rels if rel.name == "up" and rel.kind == "column"), "")
            for n in (1, 2):
                rid = len(self.role_ids) + 1
                self.role_ids.append((rid, o))
                owned = (
                    (owner, r.choice(self.subject_ids(owner, None)))
                    if o.roles[1]
                    else ("user", self.spec.spelling.ident(1))
                )
                rows.append(f"({rid}, {lit(owned[0])}, {lit(owned[1])}, {lit(o.name)}, 'r{rid}')")
                perms += [f"({rid}, {lit(p)})" for p in r.sample(["p1", "p2", "p3"], n)]
        if not rows:
            return []
        return [
            f"INSERT INTO authz.roles (id, owner_type, owner_id, object_type, name) VALUES {', '.join(rows)};",
            f"INSERT INTO authz.role_permissions VALUES {', '.join(perms)};",
            "SELECT setval(pg_get_serial_sequence('authz.roles', 'id'), 100);",
        ]

    def grant(self, ids: Ids | None) -> str:
        r = self.r
        if getattr(self, "role_ids", []) and r.random() < 0.3:  # a custom role given on an object
            rid, o = r.choice(self.role_ids)
            assert o.roles is not None
            subject = r.choice(o.roles[0])
            st, sr = subject.split("#")[0], subject.split("#")[1] if "#" in subject else ""
            return (
                f"INSERT INTO authz.shares ({difftest.SHARE_COLUMNS}) VALUES ({lit(o.name)}, "
                f"{lit(r.choice(self.subject_ids(o.name, ids)))}, 'role:{rid}', {lit(st)}, "
                f"{lit(r.choice(self.subject_ids(subject, ids)))}, {lit(sr)}, {', '.join(self.when())}) "
                "ON CONFLICT DO NOTHING;"
            )
        shared = [(o, rel) for o in self.spec.objs for rel in o.rels if rel.kind == "shared"]
        if not shared:
            return "SELECT 1;"
        o, rel = r.choice(shared)
        subject = r.choice(rel.subjects)
        st, sr = (
            subject.split("#")[0] if "#" in subject else subject.split(":")[0],
            subject.split("#")[1] if "#" in subject else "",
        )
        if subject == "link":  # a token's hash, as authz.share_link() writes it
            sid = f"encode(sha256(convert_to({lit(r.choice(TOKENS))}, 'UTF8')), 'hex')"
        else:
            sid = lit("*" if subject in ("user:*", "anyone") else r.choice(self.subject_ids(subject, ids)))
        expires, starts = self.when()
        oid = lit(r.choice(self.subject_ids(o.name, ids)))
        if self.spec.caveats:  # most carry none; some one of the policy's (with what it was made with), or another
            caveat, args = r.choice(
                [("NULL", "NULL")] * 3
                + [("'c_mode'", "NULL"), ("'c_ip'", f'\'{{"ip": "10.0.0.{r.randint(0, 2)}"}}\''), ("'c_gone'", "NULL")]
            )
            return (
                f"INSERT INTO authz.shares ({difftest.SHARE_COLUMNS}, caveat, caveat_args) VALUES ({lit(o.name)}, "
                f"{oid}, {lit(rel.name)}, {lit(st)}, {sid}, {lit(sr)}, {expires}, {starts}, {caveat}, {args}) "
                "ON CONFLICT DO NOTHING;"
            )
        return (
            f"INSERT INTO authz.shares ({difftest.SHARE_COLUMNS}) VALUES ({lit(o.name)}, "
            f"{oid}, {lit(rel.name)}, {lit(st)}, {sid}, {lit(sr)}, "
            f"{expires}, {starts}) ON CONFLICT DO NOTHING;"
        )

    def change(self, ids: Ids) -> str:
        r, n = self.r, self.spec.spelling
        o = r.choice(self.spec.objs)
        i, b1, b2, b3, active = (n.sql(c) for c in ("id", "b1", "b2", "b3", "active"))
        ptype, pid, obj, org = n.sql("parent_type"), n.sql("parent_id"), n.sql("obj_id"), n.sql("org_id")
        tbl = n.table(o.name)
        if n.composite:  # the row picked, by its two columns; a new one in either org
            mine = ids.get(o.name) or ["(1,1)"]
            xid = r.choice(mine)
            top = max(int(self.part(k)) for k in mine)
            is_x, is_obj_x = f"({org}, {i}) = {xid}", f"({org}, {obj}) = {xid}"
            mine_ids, at = [self.part(k) for k in mine], str(r.randint(1, ORGS))
        else:
            mine = ids.get(o.name) or [n.ident(1)]
            xid = r.choice(mine)
            x, top = n.literal(xid), max(n.number(k) for k in mine)
            is_x, is_obj_x = f"{i} = {x}", f"{obj} = {x}"
            mine_ids, at = [n.literal(k) for k in mine], None

        def even(odd: int) -> str:  # the rows whose key is even (odd: odd)
            if n.keytype in ("bigint", "int"):
                return f"{i} % 2 = {odd}"
            return f"{i}::text ~ '{'[13579]' if odd else '[02468]'}$'"

        ops: list[Callable[[], str]] = [
            lambda: f"UPDATE {tbl} SET {b1} = {r.choice(['true', 'false', 'NULL'])} WHERE {is_x};",
            lambda: f"UPDATE {tbl} SET {b2} = NOT {b2}, {b3} = {r.choice(['true', 'false'])} WHERE {is_x};",
            lambda: f"UPDATE {tbl} SET {b1} = random() < 0.5 WHERE {even(r.randint(0, 1))};",
            lambda: self.row(o, top + 1, ids, at),
            lambda: f"DELETE FROM {tbl} WHERE {is_x};",
            lambda: f"UPDATE {tbl} SET {i} = {n.literal(n.ident(top + r.randint(1, 9)))} WHERE {is_x};",
            lambda: self.grant(ids),
            lambda: self.grant(ids),
            lambda: f"DELETE FROM authz.shares WHERE object_id = {lit(xid)};",
            lambda: f"UPDATE authz.shares SET expires_at = {difftest.EXPIRED} WHERE random() < 0.2;",
            lambda: (
                f"UPDATE {n.table('users')} SET {active} = NOT {active} "
                f"WHERE {i} = {n.literal(n.ident(r.randint(1, USERS)))};"
            ),
            lambda: (
                f"UPDATE {n.table('bots')} SET {active} = NOT {active} WHERE {i} = {n.literal(n.ident(r.randint(1, 2)))};"
            ),
        ]
        for rel in o.rels:
            if rel.kind == "column" and rel.name == "parent":
                ops.append(
                    lambda: f"UPDATE {tbl} SET {ptype} = {lit(o.name)}, {pid} = {r.choice(mine_ids)} WHERE {is_x};"
                )
                ops.append(lambda: f"UPDATE {tbl} SET {ptype} = NULL, {pid} = NULL WHERE {is_x};")
                if len(rel.subjects) == 2:
                    other = rel.subjects[1]
                    ops.append(
                        lambda other=other: (
                            f"UPDATE {tbl} SET {ptype} = {lit(other)}, {pid} = "
                            f"{self.pointer(other, ids, self.org(xid) if n.composite else None)} WHERE {is_x};"
                        )
                    )
            elif rel.kind == "column":
                ops.append(
                    lambda rel=rel: (
                        f"UPDATE {tbl} SET {n.sql(f'c_{rel.name}')} = "
                        f"{r.choice([*self.pointers(rel.subjects[0], ids), 'NULL'])} WHERE {is_x};"
                    )
                )
            elif rel.kind == "table":
                lt = n.table(f"{o.name}_{rel.name}")
                ops.append(lambda rel=rel: self.link(o, rel, ids))
                ops.append(lambda lt=lt: f"DELETE FROM {lt} WHERE {is_obj_x};")
                ops.append(lambda lt=lt: f"UPDATE {lt} SET {active} = NOT {active} WHERE {is_obj_x};")
                ops.append(lambda lt=lt: f"TRUNCATE {lt};")
        if r.random() < 0.15:
            return "BEGIN;\n" + "\n".join(r.choice(ops)() for _ in range(r.randint(2, 4))) + "\nCOMMIT;"
        return r.choice(ops)()


def gen_class(spec: Spec, policy_path: str, schema_path: str) -> type[GenPolicyGen]:
    n = spec.spelling
    users = [n.ident(i) for i in range(1, USERS + 1)] + [n.ident(GONE)]
    users += [f"bot:{n.ident(1)}", f"bot:{n.ident(2)}"] if spec.bot else []

    class G(GenPolicyGen):
        pass

    G.spec, G.policy, G.schema, G.users = spec, policy_path, schema_path, users
    return G


# ----------------------------------------------------------------------
# Checking one policy
# ----------------------------------------------------------------------
class Refused(Exception):
    """The compiler refused the generated policy."""


class Slow(Exception):
    """The policy's reads are slow to plan (lint says so), or the seed went over its time."""


def invariant_problems(checker: Checker) -> list[str]:
    """authz.check_invariants() against the evaluator: the first five ids each user, each bot and nobody breaks."""
    pol = checker.pol
    if not pol.invariants:
        return []
    got: dict[tuple[int, str], list[str]] = {}
    for inv, user, ids in checker.db.rows(
        "SELECT invariant, coalesce(user_id, ''), array_to_json(object_ids) FROM authz.check_invariants()"
    ):
        i = next(n for n, x in enumerate(pol.invariants) if inv.startswith(f"never {x.type}: {x.src} ("))
        got[(i, user)] = json.loads(ids)
    snap = checker.snapshot_data_only()
    problems: list[str] = []
    for u in checker.users:
        if u in (GONE, UUID.format(int(GONE))):  # asked as each row of a principal type, and as nobody
            continue
        data = evaluate.Data.of({tuple(k[2:]): v for k, v in snap.items() if k[0] == u and k[1] == "data"})
        state = checker.ref.evaluate(data, u, set())
        for i, inv in enumerate(pol.invariants):
            t = checker.types[inv.type]
            bad = checker.ref.eval_expr(state, t, inv.expr) & checker.ref.ids(t) & checker.ref.valid(t)
            have = set(got.get((i, u), []))
            if (len(bad) <= 5 and have != bad) or (len(bad) > 5 and (len(have) != 5 or not have <= bad)):
                problems.append(
                    f"{u or '(nobody)'}: check_invariants() for 'never {inv.type}: {inv.src}' "
                    f"gives {sorted(have)}, expected {sorted(bad)[:5]}"
                )
    return problems


def run(
    spec: Spec,
    db: DB,
    steps: int,
    workdir: str,
    seconds: float = 900,
    report: list[str] | None = None,
    name: str = "",
) -> list[str]:
    """The problems found with this policy (none: it passed); Refused if the compiler refuses it, Slow if lint
    warns that its reads are slow to plan or the checks take more than `seconds`. With report: the parts of the
    policy (named name) that never decided an answer go there (tests/decisions.py)."""
    policy_path, schema_path = os.path.join(workdir, "gen.authz"), os.path.join(workdir, "gen_schema.sql")
    with open(policy_path, "w", encoding="utf-8") as fh:
        fh.write(policy_text(spec))
    with open(schema_path, "w", encoding="utf-8") as fh:
        fh.write(schema_text(spec))
    compiled = subprocess.run([sys.executable, "compile_policy.py", policy_path], capture_output=True, text=True)
    if compiled.returncode != 0:
        raise Refused(compiled.stderr.strip().splitlines()[-1] if compiled.stderr.strip() else "refused")
    if "view definitions to plan" in compiled.stdout:
        raise Slow("authz.lint() warns that a select rule is slow to plan")
    started = time.monotonic()
    gen = gen_class(spec, policy_path, schema_path)(random.Random(spec.seed))
    db.recreate()
    db.run(schema_text(spec))
    db.run(gen.initial())
    db.run(compiled.stdout)
    db.run(gen.grants())
    checker = Checker(db, policy_path, gen, decisions=report is not None)
    broken: set[int] = set()  # invariants the data broke at some step
    for step in range(steps + 1):
        if time.monotonic() - started > seconds:
            raise Slow(f"over {seconds:.0f} s at step {step} of {steps}")
        problems = checker.check() + invariant_problems(checker)
        if problems:
            return [f"step {step}:", *problems[:12]]
        for inv, *_ in db.rows("SELECT invariant FROM authz.check_invariants()") if checker.pol.invariants else []:
            broken |= {n for n, x in enumerate(checker.pol.invariants) if inv.startswith(f"never {x.type}: {x.src} (")}
        if step == steps:
            break
        ids: Ids = {
            t.name: [x[0] for x in db.rows(f"SELECT {idsql(t)} FROM {qt(t.table)} ORDER BY 1")]
            for t in checker.types.values()
        }
        sql = gen.change(ids)
        code, _, err = db.run(sql, check=False)
        if code != 0 and not any(e in err for e in gen.expected_errors):
            return [f"step {step + 1}: unexpected error", f"  {sql}", f"  {err.strip()}"]
    if report is not None and checker.decisions is not None:
        report += checker.decisions.report(name or f"seed {spec.seed}", only_decisive=True)
    if broken:
        results = prove.prove(parse_policy(policy_text(spec)), worlds=200)
        for n in sorted(broken):
            if results[n]["holds"]:
                return [f"prove says {results[n]['invariant']} holds, but the data broke it"]
    return []


# ----------------------------------------------------------------------
# Shrinking
# ----------------------------------------------------------------------
def smaller(spec: Spec) -> list[Spec]:
    """Each spec with one thing taken away or made simpler."""
    out: list[Spec] = []
    for i in range(len(spec.invariants)):
        out.append(dataclasses.replace(spec, invariants=spec.invariants[:i] + spec.invariants[i + 1 :]))
    for k, o in enumerate(spec.objs):
        if k == len(spec.objs) - 1 and len(spec.objs) > 1:  # the last type: nothing after it names it
            out.append(
                dataclasses.replace(
                    spec, objs=spec.objs[:-1], invariants=[x for x in spec.invariants if x[0] != o.name]
                )
            )
        if o.mask:
            out.append(with_obj(spec, k, dataclasses.replace(o, mask="")))
        for i in range(len(o.rules)):
            out.append(with_obj(spec, k, dataclasses.replace(o, rules=o.rules[:i] + o.rules[i + 1 :])))
        for p, e in o.perms.items():
            for simpler in parts_of(e):
                out.append(with_obj(spec, k, dataclasses.replace(o, perms={**o.perms, p: simpler})))
        for i, rel in enumerate(o.rels):
            out.append(with_obj(spec, k, dataclasses.replace(o, rels=o.rels[:i] + o.rels[i + 1 :])))
            if rel.shared_if:
                plain = dataclasses.replace(rel, shared_if="")
                out.append(with_obj(spec, k, dataclasses.replace(o, rels=o.rels[:i] + [plain] + o.rels[i + 1 :])))
            if len(rel.subjects) > 1:
                for j in range(len(rel.subjects)):
                    fewer = dataclasses.replace(rel, subjects=rel.subjects[:j] + rel.subjects[j + 1 :])
                    out.append(with_obj(spec, k, dataclasses.replace(o, rels=o.rels[:i] + [fewer] + o.rels[i + 1 :])))
    if spec.bot:
        out.append(dataclasses.replace(spec, bot=False))
    if spec.user_where:
        out.append(dataclasses.replace(spec, user_where=False))
    return out


def with_obj(spec: Spec, k: int, o: Obj) -> Spec:
    return dataclasses.replace(spec, objs=spec.objs[:k] + [o] + spec.objs[k + 1 :])


def parts_of(n: Node) -> list[Node]:
    """Simpler versions of an expression: each of its parts alone, or with one part simplified or taken away."""
    if isinstance(n, str):
        return [] if n in CONDS else ["{b1}"]
    op, parts = n
    out: list[Node] = list(parts) if op != "not" else []
    for i, x in enumerate(parts):
        if op != "not" and len(parts) > 2:
            out.append((op, parts[:i] + parts[i + 1 :]))
        out += [(op, parts[:i] + [y] + parts[i + 1 :]) for y in parts_of(x)]
    return out


def shrink(spec: Spec, still: Callable[[Spec], bool]) -> Spec:
    changed = True
    while changed:
        changed = False
        for s in smaller(spec):
            if still(s):
                spec, changed = s, True
                break
    return spec


# ----------------------------------------------------------------------
def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--db", default="authz_genpolicy")
    ap.add_argument("--policies", type=int, default=20)
    ap.add_argument("--steps", type=int, default=20)
    ap.add_argument("--seed", type=int, default=1, help="the first policy's seed (each policy: the next one)")
    ap.add_argument("--only", type=int, help="run this one seed, and print its policy")
    ap.add_argument("--no-shrink", action="store_true")
    ap.add_argument("--seconds", type=float, default=900, help="a seed that takes longer is given up (and said)")
    ap.add_argument(
        "--decisions", action="store_true", help="and say, for each policy, the parts that never decided an answer"
    )
    args = ap.parse_args()
    os.chdir(os.path.dirname(HERE))
    db = DB(args.db)
    seeds = [args.only] if args.only is not None else range(args.seed, args.seed + args.policies)
    refused: dict[str, int] = {}
    failed = passed = 0
    slow: list[str] = []
    twins: dict[str, int] = {}  # checked, by what they leave out
    with tempfile.TemporaryDirectory() as workdir:
        for seed in seeds:
            for label, spec in variants(seed):
                name = f"seed {seed}" + (f" {label}" if label else "")
                steps = min(args.steps, TWIN_STEPS) if label else args.steps

                def fails(s: Spec, steps: int = steps) -> bool:
                    try:
                        return bool(run(s, db, steps, workdir, args.seconds))
                    except (Refused, Slow):
                        return False

                if args.only is not None:
                    print(f"{name}:\n{policy_text(spec)}")
                said: list[str] | None = [] if args.decisions else None
                try:
                    problems = run(spec, db, steps, workdir, args.seconds, said, name)
                except Slow as e:
                    slow.append(name)
                    print(f"{name}: not checked ({e})", flush=True)
                    continue
                except Refused as e:
                    code = str(e).rsplit("[", 1)[-1].rstrip("]") if "[" in str(e) else str(e)[:60]
                    refused[code] = refused.get(code, 0) + 1
                    if args.only is not None:
                        print(f"refused: {e}")
                    continue
                if label:
                    twins[label] = twins.get(label, 0) + 1
                if said:
                    print("\n".join(said), flush=True)
                if not problems:
                    passed += 1
                    continue
                failed += 1
                print(f"{name}: the database and the evaluator disagree")
                for p in problems:
                    print("   ", p)
                if not args.no_shrink:
                    small = shrink(spec, fails)
                    print(f"  the smallest policy found that still fails ({name}):")
                    print("    " + policy_text(small).replace("\n", "\n    ").rstrip())
                    for p in run(small, db, steps, workdir):
                        print("   ", p)
    print(
        f"genpolicy seeds {seeds[0]}..{seeds[-1]}: {passed} passed, {failed} failed, "
        f"{sum(refused.values())} refused by the compiler"
        + (f" ({refused})" if refused else "")
        + (f", {len(slow)} too slow to check ({', '.join(slow)})" if slow else "")
        + (f"; twins checked: {', '.join(f'{n} {k}' for k, n in sorted(twins.items()))}" if twins else "")
    )
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
