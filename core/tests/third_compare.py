#!/usr/bin/env python3
"""third_compare: the third evaluator (tests/third.py, written apart) against the reference evaluator, in many worlds.

    python3 tests/third_compare.py --write DIR --gen 20            # the policies: hand cases, 20 of genpolicy's
    npx tree-sitter parse --xml --paths LIST > all.xml             # in editor/tree-sitter-authz (editor/test.sh)
    python3 tests/third_compare.py all.xml --worlds 40             # every policy in the XML parse.py accepts
    python3 tests/third_compare.py --parse --gen 5 --worlds 20     # all three, with npx here (a checkout's own run)

The reference evaluator (authzlib/evaluate.py) and the compiler read a policy through one parser, and the evaluator
is the reading of the page the database is held to (tests/difftest.py): a misreading in it would pass there. The
third evaluator reads the policy through the editors' grammar and writes the page as Datalog rules; the two must
give the same answers. For each policy, in each world: every relation and permission for each one asked (each who
signs in, holding a share link's token, and nobody), the rows each rule allows, and who breaks each invariant where.

A world is drawn as the reference evaluator's data (evaluate.World, as `rowstile prove` draws them; or a hand case's)
and made into rows here (to_world): each type's rows, the columns its sources read, link tables' rows, shares, custom
roles; with rows no source should count, the world says they are there: a link row its table's `where` leaves out,
shares that ended, start later or whose caveat fails. The reference evaluator then gets the data read back from those
rows (data_of): both read one world. Conditions are the one thing given to both, not read: the rows each holds on
(and, for one that reads authz.uid(), for whom).

A disagreement is shrunk (evaluate.smallest) and printed with the policy, the world and the paragraphs of
docs/reference/language.md it concerns: one of the two readings is wrong, or the page is unclear.
The unit test cases worked out by hand from the page (HandAnswers in tests/unit_test.py) are run through the third
evaluator too, and its answers held to theirs.
"""

from __future__ import annotations

import argparse
import os
import random
import re
import subprocess
import sys
import time
import unittest
from collections.abc import Iterator, Sequence
from typing import NamedTuple, Protocol, cast

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)
import third  # noqa: E402
from authzlib import Compiler, evaluate, parse  # noqa: E402
from authzlib.conditions import simple, truth, uses_uid  # noqa: E402
from authzlib.evaluate import Data  # noqa: E402
from authzlib.parse import Policy, PolicyError, Source, Type  # noqa: E402

TOKENS = ("tok1",)  # the share links' tokens each one asked holds (as `rowstile prove` asks)
KEYWORD_SQL = set(parse.KEYWORDS.values())
PAGE = os.path.join(os.path.dirname(ROOT), "docs", "reference", "language.md")


# ----------------------------------------------------------------------
# keys: an id of the evaluator's data <-> a row's key columns
# ----------------------------------------------------------------------
def unrecord(text: str) -> list[str] | None:
    """'(1,2)' -> ['1', '2'] (the plain ids the worlds use need no quotes); None if not a row's text."""
    if not (text.startswith("(") and text.endswith(")")):
        return None
    return [p.strip('"') for p in text[1:-1].split(",")]


def key_values(t: Type, i: str) -> list[str]:
    """The key columns' values for id i: a composite key's own parts, or every column but the last in org 1."""
    n = len(t.key) or 1
    if n == 1:
        return [i]
    parts = unrecord(i)
    if parts is not None and len(parts) == n:
        return parts
    return ["1"] * (n - 1) + [i]


def text_of(values: Sequence[str]) -> str:
    return values[0] if len(values) == 1 else "(" + ",".join(values) + ")"


def key_cols(t: Type) -> tuple[str, ...]:
    return tuple(c for c, _ in t.key) if t.key else (t.pk or "id",)


# ----------------------------------------------------------------------
# a world as rows (the third evaluator's input), and back (the reference evaluator's)
# ----------------------------------------------------------------------
class Asked(NamedTuple):
    who: str  # as the reference evaluator asks: a user's id, 'svc:1', '' for nobody
    links: tuple[str, ...]


def asked(pol: Policy, data: Data) -> list[Asked]:
    """Each who signs in (holding TOKENS), and nobody: with them and without."""
    return [Asked(w, TOKENS) for w in evaluate.World.principals_in(pol, data)] + [Asked("", ())]


def session_id(a: Asked) -> str:
    return f"{a.who}|{','.join(a.links)}"


def to_world(pol: Policy, data: Data, seed: str, who: Sequence[Asked]) -> third.World:
    """The data as rows, shares and roles, with rows that must count for nothing beside them (drawn from seed), for
    these sessions."""
    rng = random.Random(f"third/{seed}")
    w = third.World()
    at: dict[tuple[str, tuple[str, ...]], int] = {}  # (table, key values) -> the row

    def row_of(t: Type, i: str) -> third.Row:
        return w.tables[t.table][at[(t.table, tuple(key_values(t, i)))]]

    def put(row: third.Row, cols: Sequence[str], values: Sequence[str]) -> bool:
        """Set the columns, unless one already holds something else."""
        if any(row.get(c) is not None and row.get(c) != v for c, v in zip(cols, values, strict=True)):
            return False
        row.update(zip(cols, values, strict=True))
        return True

    def subject_values(st: str, s: str) -> list[str]:
        return key_values(pol.types[st], s) if st in pol.types else [s]

    for t in pol.types.values():
        rows = w.tables.setdefault(t.table, [])
        for i in data.ids.get(t.name, []):
            k = (t.table, tuple(key_values(t, i)))
            if k not in at:
                at[k] = len(rows)
                rows.append(dict(zip(key_cols(t), k[1], strict=True)))
        # the type's where: the rows it keeps
        if t.where:
            valid = set(data.valid.get(t.name, []))
            for i in data.ids.get(t.name, []):
                if i in valid:
                    w.conds.add((t.table, third.norm(t.where), at[(t.table, tuple(key_values(t, i)))]))
    of_table = {t.table: t for t in reversed(list(pol.types.values()))}
    shares: list[third.Share] = []
    for t in pol.types.values():
        for r in t.relations.values():
            for n, src in enumerate(r.sources):
                for st, sr in src.subjects:
                    pairs = data.pairs.get((t.name, r.name, n, st, sr or ""), [])
                    if src.kind == "column":
                        cols = parse.cols(src.column) if src.column else ()
                        for o, s in pairs:
                            if (t.table, tuple(key_values(t, o))) not in at:
                                continue
                            row = row_of(t, o)
                            if src.type_col and not put(row, [src.type_col], [st]):
                                continue
                            put(row, cols, subject_values(st, s))
                    elif src.kind == "table" and src.table:
                        ocols = parse.cols(src.obj_col) if src.obj_col else ()
                        scols = parse.cols(src.subj_col) if src.subj_col else ()
                        rows = w.tables.setdefault(src.table, [])
                        owner = of_table.get(src.table)
                        made: list[int] = []
                        for o, s in pairs:
                            link: third.Row = dict(zip(ocols, key_values(t, o), strict=True))
                            if not put(link, scols, subject_values(st, s)):
                                continue
                            if src.type_col:
                                link[src.type_col] = st
                            if owner is not None and set(key_cols(owner)) <= set(link):
                                # the link table is a type's own table: the link is that row's (one link a row)
                                k = (src.table, tuple(str(link[c]) for c in key_cols(owner)))
                                if k in at and put(rows[at[k]], list(link), [str(v) for v in link.values()]):
                                    made.append(at[k])
                                continue
                            made.append(len(rows))
                            rows.append(link)
                        if src.where:
                            for k in made:
                                w.conds.add((src.table, third.norm(src.where), k))
                            if owner is None and pairs and rng.random() < 0.5:
                                # a link its where leaves out: it must link nothing
                                o, s = rng.choice(pairs)
                                o2 = rng.choice(data.ids.get(t.name, [o]))
                                link = dict(zip(ocols, key_values(t, o2), strict=True))
                                link.update(zip(scols, subject_values(st, s), strict=True))
                                if src.type_col:
                                    link[src.type_col] = st
                                rows.append(link)
                    elif src.kind == "shared":
                        for o, s in pairs:
                            shares.append(share_of(pol, t, r.name, o, st, sr, s))
                        if pairs and rng.random() < 0.5:
                            # shares not in force: ended, starting later, a caveat that fails
                            o, s = rng.choice(pairs)
                            o2 = rng.choice(data.ids.get(t.name, [o]))
                            base = share_of(pol, t, r.name, o2, st, sr, s)
                            shares += [
                                base._replace(ended=True),
                                base._replace(starts_later=True),
                                base._replace(caveat="c", caveat_holds=False),
                            ]
    # custom roles: a role per assignment's object, subject and owner, including each permission it gives there
    grouped: dict[tuple[str, str, str, str, str, str], list[str]] = {}
    for (tname, p, st, sr), rows3 in data.rolepairs.items():
        for o, x, owner in rows3:
            grouped.setdefault((tname, o, st, sr, x, owner), []).append(p)
    for n, ((tname, o, st, sr, x, owner), perms) in enumerate(sorted(grouped.items())):
        t = pol.types[tname]
        owner_type = evaluate.role_owner_type(t) or ""
        owner_id = text_of(key_values(pol.types[owner_type], owner)) if owner_type in pol.types and owner else owner
        rid = str(n + 1)
        w.roles.append(third.Role(rid, owner_type, owner_id, tname, tuple(sorted(set(perms)))))
        shares.append(share_of(pol, t, f"role:{rid}", o, st, sr or None, x))
    w.shares = list(dict.fromkeys(shares))
    # the conditions: on which rows each holds, and for whom where it reads who is signed in
    for tname, c in evaluate.Reference(pol).conditions():
        if c in KEYWORD_SQL:
            continue
        t = pol.types[tname]
        node = simple(c)
        for i in data.ids.get(tname, []):
            k = at[(t.table, tuple(key_values(t, i)))]
            if (tname, c) in data.cond or node is None:
                if i in data.cond.get((tname, c), []):
                    w.conds.add((t.table, third.norm(c), k))
            elif uses_uid(node):
                # the row's columns, those its relations' sources set too
                row = {**w.tables[t.table][k], **data.columns.get(tname, {}).get(i, {})}
                for a in who:
                    if truth(node, row, uid_of(pol, data, a.who)) is True:
                        w.conds_as.add((t.table, third.norm(c), k, session_id(a)))
            elif truth(node, data.columns.get(tname, {}).get(i, {}), None) is True:
                w.conds.add((t.table, third.norm(c), k))
    for a in who:
        kind, pid = evaluate.principal_of(a.who, pol.types) if a.who else ("", "")
        if a.who and kind in pol.types:
            w.sessions.append(third.Session(session_id(a), kind, text_of(key_values(pol.types[kind], pid)), a.links))
        else:
            w.sessions.append(third.Session(session_id(a), None, None, a.links))
    return w


def uid_of(pol: Policy, data: Data, who: str) -> str | None:
    """authz.uid() for one asked: the user's id, if a user that counts is signed in."""
    kind, pid = evaluate.principal_of(who, pol.types)
    return pid if who and kind == "user" and pid in data.valid.get("user", []) else None


def share_of(pol: Policy, t: Type, rel: str, o: str, st: str, sr: str | None, s: str) -> third.Share:
    """A share as authz.share() writes it."""
    star = st == "anyone" or sr == "*"
    sid = "*" if star else s if st == "link" else text_of(key_values(pol.types[st], s)) if st in pol.types else s
    return third.Share(t.name, text_of(key_values(t, o)), rel, st, sid, "" if star or not sr else sr)


def data_of(pol: Policy, w: third.World, like: Data) -> Data:
    """The reference evaluator's data, read from the rows (what a database's would be): ids are the keys' text.
    like: the data the rows were made from, for the columns conditions that read authz.uid() read."""
    out = Data()
    texts: dict[tuple[str, int], str] = {}
    for t in pol.types.values():
        rows = w.tables.get(t.table, [])
        ids = []
        for k, row in enumerate(rows):
            values = [row.get(c) for c in key_cols(t)]
            if all(v is not None for v in values):
                texts[(t.table, k)] = text_of([str(v) for v in values])
                ids.append(texts[(t.table, k)])
        out.ids[t.name] = list(dict.fromkeys(ids))
        where = third.norm(t.where) if t.where else None
        out.valid[t.name] = list(
            dict.fromkeys(
                texts[(t.table, k)]
                for k in range(len(rows))
                if (t.table, k) in texts and (where is None or (t.table, where, k) in w.conds)
            )
        )
    active = [s for s in w.shares if not (s.ended or s.starts_later or (s.caveat and not s.caveat_holds))]
    for t in pol.types.values():
        for r in t.relations.values():
            for n, src in enumerate(r.sources):
                for st, sr in src.subjects:
                    out.pairs[(t.name, r.name, n, st, sr or "")] = pairs_of(
                        pol, w, t, r.name, src, st, sr, texts, active
                    )
    roles = {role.id: role for role in w.roles}
    for t in pol.types.values():
        if not t.roles:
            continue
        subjects, perms, _ = t.roles
        for p in perms:
            for st, sr in subjects:
                got: list[tuple[str, str, str]] = []
                for s in active:
                    role = roles.get(s.relation[5:]) if s.relation.startswith("role:") else None
                    if role is None or s.object_type != t.name or p not in role.perms or role.object_type != t.name:
                        continue
                    if (
                        s.subject_type == st
                        and s.subject_relation == ("" if sr in (None, "*") else sr)
                        and ((s.subject_id == "*") == (sr == "*" or st == "anyone"))
                    ):
                        got.append((s.object_id, s.subject_id, role.owner_id if t.roles_from else ""))
                out.rolepairs[(t.name, p, st, sr or "")] = got
    for tname, c in evaluate.Reference(pol).conditions():
        if c in KEYWORD_SQL:
            continue
        t = pol.types[tname]
        node = simple(c)
        if node is not None and uses_uid(node) and (tname, c) not in like.cond:
            # read from the columns, for whoever is asked
            back = {text_of(key_values(t, i)): i for i in like.ids.get(tname, [])}
            out.columns.setdefault(tname, {})
            for i in out.ids[tname]:
                out.columns[tname][i] = dict(like.columns.get(tname, {}).get(back.get(i, i), {}))
            continue
        out.cond[(tname, c)] = [
            texts[(t.table, k)]
            for k in range(len(w.tables.get(t.table, [])))
            if (t.table, k) in texts and (t.table, third.norm(c), k) in w.conds
        ]
    for tname in out.ids:
        out.columns.setdefault(tname, {})
        for i in out.ids[tname]:
            out.columns[tname].setdefault(i, {})
    return out


def pairs_of(
    pol: Policy,
    w: third.World,
    t: Type,
    rel: str,
    src: Source,
    st: str,
    sr: str | None,
    texts: dict[tuple[str, int], str],
    active: list[third.Share],
) -> list[tuple[str, str]]:
    """The links one source holds, read from the rows: (object, subject)."""
    out: list[tuple[str, str]] = []
    if src.kind == "column":
        cols = parse.cols(src.column) if src.column else ()
        for k, row in enumerate(w.tables.get(t.table, [])):
            values = [row.get(c) for c in cols]
            if (t.table, k) not in texts or any(v is None for v in values):
                continue
            if src.type_col and row.get(src.type_col) != st:
                continue
            out.append((texts[(t.table, k)], text_of([str(v) for v in values])))
    elif src.kind == "table" and src.table:
        ocols = parse.cols(src.obj_col) if src.obj_col else ()
        scols = parse.cols(src.subj_col) if src.subj_col else ()
        where = third.norm(src.where) if src.where else None
        for k, row in enumerate(w.tables.get(src.table, [])):
            o = [row.get(c) for c in ocols]
            s = [row.get(c) for c in scols]
            if any(v is None for v in o + s):
                continue
            if src.type_col and row.get(src.type_col) != st:
                continue
            if where is not None and (src.table, where, k) not in w.conds:
                continue
            out.append((text_of([str(v) for v in o]), text_of([str(v) for v in s])))
    elif src.kind == "shared":
        star = st == "anyone" or sr == "*"
        for s in active:
            if (s.object_type, s.relation, s.subject_type) != (t.name, rel, st):
                continue
            if s.subject_relation != ("" if star or not sr else sr) or (s.subject_id == "*") != star:
                continue
            out.append((s.object_id, s.subject_id))
    return list(dict.fromkeys(out))


# ----------------------------------------------------------------------
# the two readings, side by side
# ----------------------------------------------------------------------
class Policies(NamedTuple):
    pol: Policy  # parse.py's reading
    prog: third.Program  # the third evaluator's


def rule_keys(rules: Sequence[tuple[str, str, tuple[str, ...]]]) -> list[str]:
    """A name for each rule, the same in both readings: table, command (an `after` one 'update check'), columns,
    and a number where one is written twice."""
    seen: dict[str, int] = {}
    out = []
    for table, command, cols in rules:
        name = f"rule {table} {command}" + (f" {', '.join(cols)}" if cols else "")
        seen[name] = seen.get(name, 0) + 1
        out.append(name if seen[name] == 1 else f"{name} #{seen[name]}")
    return out


class Compared(NamedTuple):
    differences: list[str]
    answers: int  # the sets of ids compared
    held: int  # how many ids they held in all (an answer that is always empty proves little)


def differences(p: Policies, data: Data, seed: str) -> Compared:
    """Where the two disagree in this world (the data read back from its rows), and what was compared."""
    w = to_world(p.pol, data, seed, asked(p.pol, data))
    d = data_of(p.pol, w, data)
    got = third.evaluate(p.prog, w)
    ref = evaluate.Reference(p.pol)
    out: list[str] = []
    n = held = 0
    mine_keys = rule_keys(
        [(r.table, "update check" if r.when == "after" else r.command, r.columns) for r in p.prog.pol.rules]
    )
    theirs = rule_keys([(r.table, r.command, tuple(r.columns)) for r in p.pol.rules])
    mine_rules = dict(zip(mine_keys, got.rules, strict=True))
    for a in asked(p.pol, d):
        sid = session_id(a)
        state = ref.evaluate(d, a.who, a.links)
        for t in p.pol.types.values():
            for name in [*t.relations, *t.perms]:
                n += 1
                theirs_ids = set(state[(t.name, name)])
                held += len(theirs_ids)
                mine = set(got.held.get((sid, t.name, name), frozenset()))
                if theirs_ids != mine:
                    out.append(said(f"{t.name}.{name}", a, theirs_ids, mine))
        for key, rule in zip(theirs, p.pol.rules, strict=True):
            n += 1
            theirs_ids = ref.rule(state, rule)
            held += len(theirs_ids)
            mine = set(mine_rules.get(key, {}).get(sid, frozenset()))
            if theirs_ids != mine:
                out.append(said(key, a, theirs_ids, mine))
        for k, inv in enumerate(p.pol.invariants):
            n += 1
            t = p.pol.types[inv.type]
            theirs_ids = ref.eval_expr(state, t, inv.expr) & set(d.valid[t.name])
            held += len(theirs_ids)
            mine = {o for s, o in got.broken[k] if s == sid}
            if theirs_ids != mine:
                out.append(said(f"invariant never {inv.type}: {inv.src}", a, theirs_ids, mine))
    return Compared(out, n, held)


def same_names(p: Policies) -> list[str]:
    """What one reading has and the other hasn't: types, their relations and permissions, rules, invariants."""
    theirs = {(t.name, n) for t in p.pol.types.values() for n in [*t.relations, *t.perms]}
    mine = {(t.name, n) for t in p.prog.pol.types.values() for n in [*t.relations, *t.perms]}
    out = [f"only the parser reads {t}.{n}" for t, n in sorted(theirs - mine)]
    out += [f"only the grammar reads {t}.{n}" for t, n in sorted(mine - theirs)]
    a = set(rule_keys([(r.table, r.command, tuple(r.columns)) for r in p.pol.rules]))
    b = set(
        rule_keys([(r.table, "update check" if r.when == "after" else r.command, r.columns) for r in p.prog.pol.rules])
    )
    out += [f"only the parser reads {x}" for x in sorted(a - b)] + [
        f"only the grammar reads {x}" for x in sorted(b - a)
    ]
    if [i.type for i in p.pol.invariants] != [i.type for i in p.prog.pol.invariants]:
        out.append(
            f"the invariants: the parser reads {len(p.pol.invariants)}, the grammar {len(p.prog.pol.invariants)}"
        )
    return out


def shown(w: third.World) -> list[str]:
    """The rows the third evaluator read, as lines: each table's, the shares, the roles, where conditions hold."""
    out = []
    for table, rows in sorted(w.tables.items()):
        for k, row in enumerate(rows):
            holds = sorted({c for tb, c, i in w.conds if tb == table and i == k})
            cells = ", ".join(f"{c} = {v}" for c, v in row.items() if v is not None)
            out.append(
                f"{table} row {k}: {cells}" + (f"; holds {', '.join('{' + c + '}' for c in holds)}" if holds else "")
            )
    for sh in w.shares:
        state = [x for x, on in (("ended", sh.ended), ("starts later", sh.starts_later)) if on]
        if sh.caveat:
            state.append(f"caveat {sh.caveat} {'holds' if sh.caveat_holds else 'fails'}")
        rel = f"#{sh.subject_relation}" if sh.subject_relation else ""
        out.append(
            f"share {sh.object_type} {sh.object_id} {sh.relation} to {sh.subject_type}{rel} {sh.subject_id}"
            + (f" ({', '.join(state)})" if state else "")
        )
    for role in w.roles:
        owner = f", owned by {role.owner_type} {role.owner_id}" if role.owner_type else ""
        out.append(f"role {role.id} for {role.object_type}: {', '.join(role.perms)}{owner}")
    return out


def said(what: str, a: Asked, theirs: set[str], mine: set[str]) -> str:
    who = f"as {a.who}" if a.who else "as nobody"
    who += f" holding {', '.join(a.links)}" if a.links else ""
    return f"{what}, {who}: the reference evaluator says {sorted(theirs)}, the third {sorted(mine)}"


# ----------------------------------------------------------------------
# the page: the paragraphs a disagreement concerns
# ----------------------------------------------------------------------
CONSTRUCTS = {
    "where": ["rows-hold-nothing", "rows-no-rule"],
    "column": ["relation-sources"],
    "table": ["relation-sources", "relation-again"],
    "pair": ["polymorphic-type-names"],
    "shared": ["shares-expire", "subjects", "caveats"],
    "group": ["subjects"],
    "principal": ["principals"],
    "arrow": ["follow-relation", "inheritance"],
    "not": ["permission-operators", "deny-below", "condition-every-level"],
    "cond": ["conditions-null", "conditions-this"],
    "word": ["signed-in-anyone-nobody"],
    "roles": ["roles-include", "roles-from", "roles-refused", "roles-without-from"],
    "rule": ["rules-commands"],
    "invariant": ["invariants"],
}


def paragraphs() -> dict[str, str]:
    """Each anchor of the page (`<!-- answer: name -->`) and the paragraph (list item) it ends a sentence of."""
    with open(PAGE, encoding="utf-8") as fh:
        text = fh.read()
    out: dict[str, str] = {}
    for block in re.split(r"\n(?=- \*\*|\n)", text):
        clean = re.sub(r"\s*<!--.*?-->", "", block, flags=re.S).strip()
        for names in re.findall(r"<!-- answer: ([^>]*?) -->", block):
            for name in names.split(","):
                out[name.strip()] = " ".join(clean.split())
    return out


def constructs(pol: Policy) -> set[str]:
    """What of the language the policy uses."""
    found: set[str] = set()

    def walk(e: parse.Expr) -> None:
        match e:
            case parse.Or(items=items) | parse.And(items=items):
                for x in items:
                    walk(x)
            case parse.Not(item=item):
                found.add("not")
                walk(item)
            case parse.Cond(sql=s):
                found.add("word" if s in KEYWORD_SQL else "cond")
            case parse.Ref(name=n):
                if n == parse.ROLES:
                    found.add("roles")
            case _:
                found.add("arrow")

    for t in pol.types.values():
        if t.where:
            found.add("where")
        if t.principal and t.name != "user":
            found.add("principal")
        for r in t.relations.values():
            for src in r.sources:
                found.add("pair" if src.type_col and src.kind == "column" else src.kind)
                if any(sr and sr != "*" for _, sr in src.subjects):
                    found.add("group")
        for p in t.perms.values():
            walk(p.expr)
    for rule in pol.rules:
        found.add("rule")
        walk(rule.expr)
    for inv in pol.invariants:
        found.add("invariant")
        walk(inv.expr)
    return found


def concerns(pol: Policy) -> list[str]:
    page = paragraphs()
    names = [a for c in sorted(constructs(pol)) for a in CONSTRUCTS.get(c, [])]
    said = dict.fromkeys(page[a] for a in names if a in page)
    return [f"  {x}" for x in said]


def label(path: str) -> str:
    """A policy's path as printed: in the repository, from its root; else its folder and name."""
    top = os.path.dirname(ROOT)
    if path.startswith(top + os.sep):
        return os.path.relpath(path, top)
    return os.path.join(os.path.basename(os.path.dirname(path)), os.path.basename(path))


# ----------------------------------------------------------------------
# the policies
# ----------------------------------------------------------------------
class Chosen(NamedTuple):
    """Which policies to compare: genpolicy's seeds (gen of them from seed), small.py's set up to a size (a slice of
    it: those whose number is part[0] modulo part[1]), the hand cases, the repository's."""

    gen: int = 0
    seed: int = 1
    small: int = 0
    part: tuple[int, int] = (0, 1)
    hand: bool = True
    repository: bool = True


def write(folder: str, chosen: Chosen) -> list[str]:
    """The policies to compare, as files in folder (genpolicy's each in a folder of its own, some in two files), and
    the repository's: their paths."""
    os.makedirs(folder, exist_ok=True)
    out: list[str] = []
    if chosen.gen:
        import genpolicy

        for seed in range(chosen.seed, chosen.seed + chosen.gen):
            spec = genpolicy.make(seed)
            path = os.path.join(folder, f"gen_{seed}", "policy.authz")
            os.makedirs(os.path.dirname(path), exist_ok=True)
            genpolicy.write_policy(path, genpolicy.policy_text(spec), spec.include)
            out += [os.path.join(os.path.dirname(path), f) for f in sorted(os.listdir(os.path.dirname(path)))]
    for name, case in hand_cases().items() if chosen.hand else ():
        path = os.path.join(folder, f"hand_{name}.authz")
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(case.policy)
        out.append(path)
    if chosen.small:
        for name, text in small_set(chosen.small, chosen.part):
            path = os.path.join(folder, f"small_{name}.authz")
            with open(path, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(text)
            out.append(path)
    return out + (repository() if chosen.repository else [])


def small_set(size: int, part: tuple[int, int]) -> list[tuple[str, str]]:
    """small.py's policies up to size (tests/small.py: every small policy of the core language), if it is there:
    those whose number is part[0] modulo part[1]."""
    small = small_module()
    if small is None:
        return []
    return [(f"{k}", small.policy_text(spec)) for k, spec in enumerate(small.the_set(size)) if k % part[1] == part[0]]


def repository() -> list[str]:
    """Every policy in the repository (not the ones the tests write: those are in --write's folder)."""
    out = []
    top = os.path.dirname(ROOT)
    for base, dirs, files in os.walk(top):
        dirs[:] = [d for d in dirs if d not in ("node_modules", ".venv", ".git", ".ci")]
        out += [os.path.join(base, f) for f in files if f.endswith(".authz")]
    return sorted(out)


class HandCase(NamedTuple):
    policy: str
    world: str
    answers: dict[str, dict[str, str]]
    links: Sequence[str]
    broken: str | None


def hand_cases() -> dict[str, HandCase]:
    """The evaluator's cases worked out by hand from the page (HandAnswers in tests/unit_test.py), as they call
    check(): the policy, the world, the answers."""
    import unit_test

    found: dict[str, HandCase] = {}

    class Collect(unit_test.HandAnswers):
        def check(
            self,
            policy: str,
            world: str,
            answers: dict[str, dict[str, str]],
            links: Sequence[str] = (),
            broken: str | None = None,
        ) -> None:
            name = self._testMethodName[5:]
            # a test that checks twice: each its own case
            name = next(f"{name}_{n}" if n else name for n in range(100) if (f"{name}_{n}" if n else name) not in found)
            found[name] = HandCase(self.HEAD + policy, world, answers, links, broken)

    for name in unittest.TestLoader().getTestCaseNames(Collect):
        getattr(Collect(name), name)()
    return found


def hand_check(p: Policies, case: HandCase, data: Data) -> list[str] | None:
    """The third evaluator's answers in a hand case's world against the answers worked out by hand: where they
    differ. None if rows can't hold the world (a row of a type's table that is two links' row in it, each naming
    another parent)."""
    # those the answers are for; for an invariant, each who can sign in and nobody, as `rowstile prove` asks
    asking = list(case.answers) + (evaluate.World.principals_in(p.pol, data) if case.broken is not None else [])
    who = [Asked(x, tuple(case.links)) for x in dict.fromkeys(asking)]
    w = to_world(p.pol, data, "hand", who)
    back = {k: set(v) for k, v in data_of(p.pol, w, data).pairs.items()}
    if back != {k: set(v) for k, v in data.pairs.items()}:
        return None
    got = third.evaluate(p.prog, w)
    keys = rule_keys(
        [(r.table, "update check" if r.when == "after" else r.command, r.columns) for r in p.prog.pol.rules]
    )
    rules = dict(zip(keys, got.rules, strict=True))
    out = []
    for a in who:
        sid = session_id(a)
        for name, ids in case.answers.get(a.who, {}).items():
            want = {x.strip() for x in ids.split(",") if x.strip()}
            if name in rules:
                mine = set(rules[name].get(sid, frozenset()))
            else:
                tname, _, n = name.partition(".")
                mine = set(got.held.get((sid, tname, n), frozenset()))
            if mine != want:
                out.append(f"{name}, as {a.who or 'nobody'}: by hand {sorted(want)}, the third {sorted(mine)}")
    if case.broken is not None:
        # who breaks the invariant, and where: by hand one of them ('service:1 on 1', 'nobody on 1') or 'none'
        names = {session_id(a): a.who or "nobody" for a in who}
        found = {f"{names[s]} on {o}" for s, o in got.broken[0]}
        if (case.broken == "none") != (not found) or (case.broken != "none" and case.broken not in found):
            out.append(f"the invariant: by hand {case.broken}, the third {sorted(found) or 'none'}")
    return out


# ----------------------------------------------------------------------
# the run
# ----------------------------------------------------------------------
def files_of(path: str, text: str) -> dict[str, str]:
    """The files a policy includes (and they include), from beside it."""
    files: dict[str, str] = {}
    todo = re.findall(r'^include "([^"]+)"', text, re.M)
    while todo:
        name = todo.pop()
        full = os.path.join(os.path.dirname(path), name)
        if name not in files and os.path.isfile(full):
            with open(full, encoding="utf-8") as fh:
                files[name] = fh.read()
            todo += re.findall(r'^include "([^"]+)"', files[name], re.M)
    return files


def included(paths: Sequence[str]) -> set[str]:
    """The files another of these includes: compared as part of it, not alone."""
    out: set[str] = set()
    for p in paths:
        with open(p, encoding="utf-8") as fh:
            text = fh.read()
        out |= {os.path.normpath(os.path.join(os.path.dirname(p), f)) for f in files_of(p, text)}
    return out


def shrink(p: Policies, data: Data, seed: str) -> tuple[Data, list[str]]:
    """The world with every link, row and condition taken away that the disagreement doesn't need."""
    small = evaluate.smallest(data, lambda d: bool(differences(p, d, seed).differences))
    return small, differences(p, small, seed).differences


class Tally:
    """What a run compared."""

    def __init__(self) -> None:
        self.policies = self.worlds = self.answers = self.held = self.refused = self.hand = self.unheld = 0
        self.problems: list[str] = []


def worlds_of(path: str, pol: Policy, worlds: int) -> Iterator[Data]:
    """The worlds a policy is asked in: small.py's for one of its set (every world of one and two rows), else those
    `rowstile prove` draws (evaluate.worlds_to_try: drawn, smallest first; the corners; dense ones and chains)."""
    base = os.path.basename(path)
    small = small_module() if base.startswith("small_") else None
    if small is not None:
        yield from small.worlds(pol, base[len("small_") : -len(".authz")])
        return
    for world in evaluate.worlds_to_try([pol], worlds, path, 4):
        yield world.data(pol)


def check(path: str, trees: dict[str, third.Tree], hand: dict[str, HandCase], worlds: int, tally: Tally) -> bool:
    """One policy: its names in both readings, its hand case if it is one, then each world. Whether all agreed."""
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    files = files_of(path, text)
    try:
        # a policy the compiler takes (parsed apart: compiling splits denies, the evaluator reads them as written)
        Compiler(parse.parse_policy(text, os.path.basename(path), files=files)).compile("p")
        pol = parse.parse_policy(text, os.path.basename(path), files=files)
    except PolicyError:
        tally.refused += 1
        return True
    if not any(t.perms for t in pol.types.values()):
        tally.refused += 1
        return True
    try:
        p = Policies(pol, third.Program(third.read(trees, path)))
    except third.Unreadable as e:
        tally.problems.append(f"{path}: the third evaluator can't read it: {e}")
        return False
    tally.policies += 1
    names = same_names(p)
    if names:
        tally.problems.append(f"{path}: the two read different names: {'; '.join(names)}")
        return False
    base = os.path.basename(path)
    case = hand.get(base[len("hand_") : -len(".authz")]) if base.startswith("hand_") else None
    if case is not None:
        found = hand_check(p, case, hand_world(pol, case))
        if found is None:
            tally.unheld += 1
        else:
            tally.hand += 1
            if found:
                tally.problems.append(f"{path}: the third evaluator against the answers worked out by hand:")
                tally.problems += [f"  {x}" for x in found]
                return False
    for k, data in enumerate(worlds_of(path, pol, worlds)):
        seed = f"{path}/{k}"
        c = differences(p, data, seed)
        tally.worlds += 1
        tally.answers += c.answers
        tally.held += c.held
        if c.differences:
            small, still = shrink(p, data, seed)
            tally.problems.append(
                "\n".join(
                    [
                        f"{path}: the two evaluators disagree (world {k}, shrunk):",
                        *[f"  {x}" for x in still[:6]],
                        "the world, as the reference evaluator reads it:",
                        *[f"  {x}" for x in evaluate.World("shown", 1).describe(pol, small)],
                        "as rows (the third evaluator's):",
                        *[f"  {x}" for x in shown(to_world(pol, small, seed, asked(pol, small)))],
                        "the policy:",
                        *[f"  {x}" for x in text.strip().split("\n")],
                        "what the page says of what it uses (docs/reference/language.md):",
                        *concerns(pol),
                    ]
                )
            )
            return False
    return True


def run(xml: str, worlds: int, only: str | None, quiet: bool) -> int:
    trees = third.trees(xml)
    paths = [p for p in trees if only is None or only in p]
    inside = included(paths)
    hand = hand_cases()
    started = time.time()
    tally = Tally()
    for path in sorted(paths):
        if path in inside:
            continue
        agreed = check(path, trees, hand, worlds, tally)
        if not quiet or not agreed:
            print(f"{'ok' if agreed else 'FAIL'}    {label(path)}")
    for x in tally.problems:
        print(x)
    print(
        f"third evaluator: {tally.policies} policies, {tally.worlds} worlds, {tally.answers} answers ({tally.held} ids "
        f"held) compared with the reference evaluator in {time.time() - started:.0f} s, "
        + (f"{len(tally.problems)} disagreements" if tally.problems else "all alike")
        + f"; {tally.hand} cases worked out by hand ({tally.unheld} whose world rows can't hold not asked); "
        f"{tally.refused} policies not compared (the compiler refuses them, or they have no permission)"
    )
    return 1 if tally.problems or not tally.policies else 0


def hand_world(pol: Policy, case: HandCase) -> Data:
    """A hand case's world, as HandAnswers reads it."""
    import unit_test

    return unit_test.HandAnswers("test_not_takes_the_item_after_it").world(pol, case.world)


class SmallSet(Protocol):
    """What is used of tests/small.py: its set of policies, their text, and every small world of one."""

    def the_set(self, n: int) -> Sequence[object]: ...

    def policy_text(self, spec: object) -> str: ...

    def worlds(self, pol: Policy, key: str) -> Iterator[Data]: ...


def small_module() -> SmallSet | None:
    """tests/small.py, every small policy of the core language, if it is there (None if not)."""
    import importlib

    try:
        return cast(SmallSet, importlib.import_module("small"))
    except ImportError:
        return None


def main(argv: Sequence[str]) -> int:
    ap = argparse.ArgumentParser(description="The third evaluator against the reference evaluator.")
    ap.add_argument("xml", nargs="?", help="what `tree-sitter parse --xml` wrote")
    ap.add_argument("--write", metavar="DIR", help="write the policies to compare into DIR, and list their paths")
    ap.add_argument("--parse", action="store_true", help="write them, parse them with npx here, and compare")
    ap.add_argument("--gen", type=int, default=0, help="as many of genpolicy's policies")
    ap.add_argument("--seed", type=int, default=1, help="genpolicy's first seed")
    ap.add_argument("--small", type=int, default=0, help="small.py's policies up to this size")
    ap.add_argument("--slice", default="0/1", help="of small.py's: those whose number is A modulo B")
    ap.add_argument("--no-hand", action="store_true", help="without the hand cases")
    ap.add_argument("--no-repository", action="store_true", help="without the repository's policies")
    ap.add_argument("--worlds", type=int, default=40, help="worlds drawn for each policy (small.py's: its own)")
    ap.add_argument("--only", help="the policies whose path holds this")
    ap.add_argument("-q", "--quiet", action="store_true", help="print the policies that disagree only")
    a = ap.parse_args(argv)
    part = tuple(int(x) for x in a.slice.split("/"))
    chosen = Chosen(a.gen, a.seed, a.small, (part[0], part[1]), not a.no_hand, not a.no_repository)
    if a.write and not a.parse:
        print("\n".join(write(a.write, chosen)))
        return 0
    if a.parse:
        import tempfile

        with tempfile.TemporaryDirectory() as d:
            listing, xml = os.path.join(d, "paths"), os.path.join(d, "all.xml")
            with open(listing, "w", encoding="utf-8") as fh:
                fh.write("\n".join(write(os.path.join(d, "p"), chosen)) + "\n")
            with open(xml, "w", encoding="utf-8") as out:
                subprocess.run(
                    ["npx", "tree-sitter", "parse", "--xml", "--paths", listing],
                    cwd=os.path.join(os.path.dirname(ROOT), "editor", "tree-sitter-authz"),
                    stdout=out,
                    stderr=subprocess.DEVNULL,
                    check=False,
                )
            return run(xml, a.worlds, a.only, a.quiet)
    if not a.xml:
        ap.error("name the XML, or --write DIR, or --parse")
    return run(a.xml, a.worlds, a.only, a.quiet)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
