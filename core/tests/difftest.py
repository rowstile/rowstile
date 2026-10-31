#!/usr/bin/env python3
"""difftest: check the compiled policy against an independent evaluator.

    python3 tests/difftest.py --db authz_difftest --gen docs --steps 150 --seed 1

Builds a random data set for the policy, applies the compiled policy, then
repeatedly changes the data at random (moves, links, team nesting, shares,
expiry, inheritance flags, deletes, id changes, TRUNCATE, several changes in
one transaction) and after every change compares, for every user:

  - authz.list() for every permission of every type, and for one of them (in
    turn) in pages of two: each page after the last id of the one before, the
    whole in key order as the database orders the key (its collation's)
  - authz.can() for every object and permission, whether the user may see the
    row or not, plus an id no row has
  - the rows each RLS policy lets the app role read
  - every policy expression (USING and WITH CHECK) evaluated on every row
  - every column rule's condition (a trigger's), evaluated on every row
  - both again as the app role, on the rows it may select (where the app role
    checks them: a condition must read with the policy's rights there too)
  - for one of them, again with a scope: lists, checks and policies
  - authz.explain() of every object and permission, as an administrator asks it and as the user asks it of
    themselves (by their id too), authz.who() and authz.who_among(), authz.perms_of() and authz.explain_rule()
  - the sharing API tried as the user and undone: authz.share(), unshare(), create_link(), list_shares(), the
    links API (list_links) and the custom roles API (create_role and the rest)
  - requests for access, breaking the glass and access reviews, tried by the same user and undone: what each call
    says, the requests it shows, the shares it makes or revokes, and the lines it writes in the audit trail
  - the masked views, read as each user: their rows, and the rows each masked column is shown on
  - authz.verify(): the closure tables match a rebuild

(check() has them all, each with the words a difference is reported in.)

against a reference evaluator written directly from the language's meaning:
relations and permissions are sets of object ids, computed together as the
least fixpoint of the policy. It shares only the parser with the compiler.

A change may fail only as random changes may: a key it repeats or a row it
names that isn't there, raised by its own statement (by SQLSTATE), or a refusal
of rowstile's that the generator expects (by the code in its HINT). Anything
else, or more than half the changes refused, fails the run.

With --decisions it says at the end which parts of the policy never decided an
answer in those checks, whose SQL the run never judged (tests/decisions.py),
and a quarter of its changes aim at the parts that haven't yet: a share that
doesn't count where the reference says it would decide had it counted, a chain
of links as deep as the part says, a loop of them (Gen.steered).
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import random
import re
import subprocess
import sys
import time
from collections import Counter
from collections.abc import Sequence
from concurrent.futures import ThreadPoolExecutor
from typing import Any, ClassVar

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import compile_policy  # noqa: E402
from authzlib import evaluate  # noqa: E402
from authzlib.parse import Arrow, ArrowOn, Caveat, Cols, Cond, Policy, Ref, Rule, Source, Type, leaves  # noqa: E402
from authzlib.sqlutil import ident, q, qt, reads_more  # noqa: E402  (names as the policy writes them, quoted: ...)
from decisions import Decisions, Gain, Plan, allows, scope_items  # noqa: E402

# the database's answers, read back as JSON: their shape is what the checks compare
Answer = Any
Snapshot = dict[tuple[str, ...], Answer]
Ids = dict[str, list[str]]  # the ids of each type's rows, as text


def read(path: str) -> str:
    with open(path, encoding="utf-8") as fh:
        return fh.read()


REFUSE = re.compile(r'authz_gen\."[^"]*:refuse"\(')
# a column rule's check, in its trigger's WHEN (kept parsed, as a policy is, so it may call what is in authz_int): the
# function that says whether the rule holds (`<table>:column_<n>:holds`, or that name shortened with a hash when it is
# longer than Postgres allows), and the row it checks
COLUMN_WHEN = re.compile(
    r"NOT (authz_int\.\"[^\"]+\")\(jsonb_populate_record\(NULL::[^,]+, to_jsonb\((old|new)(?:\.\*)?\)\)\)", re.I
)


def refusals_of(pol: Policy) -> re.Pattern[str]:
    """The calls of the refuse functions a policy's write rules make, by their names as the compiler makes them
    (refusals.rule_fn): a long table's are shortened with a hash, and no longer end in `:refuse`."""
    names = sorted(
        {
            "authz_gen." + q(f"{r.table}:{r.command.replace('update after', 'update_after')}:refuse")
            for r in pol.rules
            if r.command in ("insert", "update", "update after")
        }
    )
    return re.compile("|".join([REFUSE.pattern, *(re.escape(n) + r"\(" for n in names)]))


# a share's end in the past, far enough that a clock set back (a machine's clock resyncing, seconds at a
# time) doesn't make it live again half way through a check, which reads the data and the answers at different times
EXPIRED = "now() - interval '1 hour'"
# a share's start ahead, far enough that it doesn't come during a run (a soak's takes hours): not started throughout.
# A generator gives one in place of one of its draws' live shares, so that its draws, and all it makes, stay the same
LATER = "now() + interval '1 day'"
# a share's start a day back: it has started
EARLIER = "now() - interval '1 day'"
# A random change runs with psql's errors in full (VERBOSITY verbose): what Gen.refused reads is their SQLSTATE, the
# code a rowstile refusal gives in its HINT, and the functions they were raised in (CONTEXT), not their words
CHANGE = "\\set VERBOSITY verbose\n"
SQLSTATE = re.compile(r"^(?:psql:\S* )?ERROR:\s+([0-9A-Z]{5}): ", re.M)
ROWSTILE_HINT = re.compile(r"^HINT:\s+rowstile help (AZ\d+)", re.M)
IN_ROWSTILE = re.compile(r'\bfunction "?authz(?:_int|_gen)?"?\.')
KEY_ERRORS = ("23505", "23503")  # unique_violation, foreign_key_violation
SHARE_COLUMNS = "object_type, object_id, relation, subject_type, subject_id, subject_relation, expires_at, starts_at"
STEER = 0.25  # of the changes, those aimed at parts of the policy that have decided no answer yet (Gen.steered)
AIMS = 3  # how many parts one such change aims at, at most; or an eighth of the parts left, when that is more
PAGE = 2  # authz.list's page size, where it is asked in pages

# How many sessions answer a snapshot's questions, side by side (DIFFTEST_SESSIONS=1: one after the other). The
# questions are the same either way, each user's in one session from first to last: what it saves is the wait.
SESSIONS = int(os.environ.get("DIFFTEST_SESSIONS") or min(4, os.cpu_count() or 1))


def without_refusals(expr: str, refuse: re.Pattern[str] = REFUSE) -> str:
    """A WITH CHECK is `check OR <refuse>(row)`, and the refuse function raises (with the reason) when it runs:
    evaluated on every row here, the call becomes false, leaving the check itself. (refuse: refusals_of(policy).)"""
    while True:
        m = refuse.search(expr)
        if not m:
            return expr
        depth, i = 1, m.end()
        while depth:
            depth += {"(": 1, ")": -1}.get(expr[i], 0)
            i += 1
        expr = expr[: m.start()] + "false" + expr[i:]


# ----------------------------------------------------------------------
# psql
# ----------------------------------------------------------------------
class DB:
    def __init__(self, name: str) -> None:
        self.name = name

    def run(self, sql: str, check: bool = True) -> tuple[int, str, str]:
        p = subprocess.run(
            ["psql", "-X", "-q", "-At", "-F", "\t", "-v", "ON_ERROR_STOP=1", "-d", self.name],
            input="SET client_min_messages = warning;\n" + sql,
            capture_output=True,
            text=True,
        )
        if check and p.returncode != 0:
            raise RuntimeError(f"psql failed:\n{p.stderr}\n--- sql ---\n{sql[:3000]}")
        return p.returncode, p.stdout, p.stderr

    def rows(self, sql: str) -> list[list[str]]:
        return [line.split("\t") for line in self.run(sql)[1].splitlines() if line]

    def rows_together(self, scripts: Sequence[str]) -> list[list[str]]:
        """The rows of scripts that change nothing, each in a session of its own, all at the same time."""
        if len(scripts) == 1:
            return self.rows(scripts[0])
        with ThreadPoolExecutor(len(scripts)) as pool:
            return [row for rows in pool.map(self.rows, scripts) for row in rows]

    def recreate(self) -> None:
        for cmd in (["dropdb", "--if-exists", self.name], ["createdb", self.name]):
            subprocess.run(cmd, check=True, capture_output=True)
        # JIT off, as the docs tell apps: a check is many small subplans, whose estimated cost passes Postgres's
        # thresholds, and it then compiles for seconds to read a handful of rows (4.7 s for 7 rows, 41 ms without)
        self.run(f'ALTER DATABASE "{self.name}" SET jit = off;')


def lit(s: object) -> str:
    return "'" + str(s).replace("'", "''") + "'"


def text_array(items: Sequence[str]) -> str:
    return "ARRAY[" + ", ".join(lit(i) for i in items) + "]::text[]"


# a custom role's id no role has: changing or deleting it is refused as one the user may not manage is
MISSING_ROLE = "999999"
# an object's id no row has, which authz.can is asked about beside every row's: false, whoever asks
MISSING_ROW = "999999"
# a link's id (the start of its token's hash) no link has
MISSING_LINK = "ffffffffffffffff"


def asked_of_every_row(who: str, tname: str, perm: str, answers: Answer, ids: set[str], *more: str) -> list[str]:
    """authz.can is asked of every row a snapshot holds (and of more ids, which no row has): not of some of them."""
    asked = {i for i, _ in answers}
    if asked == {*ids, *more}:
        return []
    return [f"{who}: authz.can('{tname}', ..., '{perm}') was asked of {sorted(asked)}, not of {sorted({*ids, *more})}"]


def signs_in_as_user(u: str, types: dict[str, Type]) -> bool:
    """Whether u signs in as a user id (a row of the user table or not), not as nobody or another principal."""
    kind, pid = evaluate.principal_of(u, types)
    return kind == "user" and bool(pid)


def subject_key(st: str, sid: str, sr: str) -> str:
    """Whom a share is to, as the catalog of what may be shared with whom says it: user, user:*, team#member,
    anyone, link."""
    if st in ("anyone", "link"):
        return st
    if sid == "*" and sr == "":
        return f"{st}:*"
    return f"{st}#{sr}" if sr else st


def link_ids(links: list[tuple[str, str]]) -> list[str]:
    """The ids of an object's links (relation, id), and one no link has: what is tried to turn off, in order."""
    return [*sorted({lid for _, lid in links}), MISSING_LINK]


# ----------------------------------------------------------------------
# The reference evaluator
# ----------------------------------------------------------------------
def caveat_case(caveats: dict[str, Caveat], alias: str = "g") -> str:
    """A share's caveat as SQL (written separately from the compiler's version)."""
    if not caveats:
        return f"{alias}.caveat IS NULL"
    whens = []
    for c in caveats.values():
        sql = re.sub(r"\barg\s*\(\s*'([^']*)'\s*\)", lambda m: f"({alias}.caveat_args ->> '{m.group(1)}')", c.sql)
        whens.append(f"WHEN {lit(c.name)} THEN coalesce(({sql}), false)")
    return f"({alias}.caveat IS NULL OR CASE {alias}.caveat {' '.join(whens)} ELSE false END)"


def idsql(t: Type, a: str | None = None, columns: Cols | None = None) -> str:
    """The text id of t's row a, or of the t that columns point at: the key column, or for a
    composite key the text Postgres prints for the row (what rowstile's ids are)."""
    p = f"{a}." if a else ""
    cols = [columns] if isinstance(columns, str) else list(columns or [c for c, _ in t.key])
    if len(t.key) == 1:
        return f"{p}{q(cols[0])}::text"
    return "ROW(" + ", ".join(f"{p}{q(c)}::{ty}" for c, (_, ty) in zip(cols, t.key, strict=True)) + ")::text"


def pages_sql(t: Type, p: str) -> str:
    """authz.list(t, p) in pages of PAGE, each after the last id of the one before, and whole in key order as the
    database orders the key (a text key by its collation): [pages, whole], which must be the same list."""
    tp = f"{lit(t.name)}, {lit(p)}"
    order = ", ".join(f"(x::{t.keytype}).{q(c)}" for c, _ in t.key) if t.composite else f"x::{t.pktype}"
    return (
        f"WITH RECURSIVE pages(n, page) AS (SELECT 1, ARRAY(SELECT x FROM authz.list({tp}, NULL, {PAGE}) x) "
        f"UNION ALL SELECT n + 1, ARRAY(SELECT x FROM authz.list({tp}, page[{PAGE}], {PAGE}) x) "
        f"FROM pages WHERE cardinality(page) = {PAGE} AND n < 1000) "
        "SELECT json_build_array((SELECT coalesce(json_agg(x ORDER BY n, k), '[]') FROM pages, "
        "unnest(page) WITH ORDINALITY u(x, k)), "
        f"(SELECT coalesce(json_agg(x ORDER BY {order}), '[]') FROM authz.list({tp}) x))"
    )


def notnull(a: str, columns: Cols | None) -> str:
    cols = [columns] if isinstance(columns, str) else list(columns or ())
    return " AND ".join(f"{a}.{q(c)} IS NOT NULL" for c in cols)


NOT_EXPIRED = "(g.expires_at IS NULL OR g.expires_at > now())"
STARTED = "(g.starts_at IS NULL OR g.starts_at <= now())"

# The sync index (a preview): each policy is checked with its types synced, by a sync line each, which the reference's
# answers hold the index to (Checker.sync_problems). The role the lines name needs only to be there for applying.
SYNC_ROLE = "authz_sync_engine"
MAKE_SYNC_ROLE = (
    f"DO $r$ BEGIN CREATE ROLE {SYNC_ROLE}; EXCEPTION WHEN duplicate_object OR unique_violation THEN NULL; END $r$;"
)


def synced(text: str, path: str, seed: int) -> str:
    """The policy, with a sync line for each type the index takes one of: one public permission each, or the
    table's select rule (no permission), in turn by seed; a type of which it takes none (a condition on who asks,
    one reading other rows) isn't synced."""
    from authzlib import Compiler, PolicyError

    pol = compile_policy.parse_policy(text, path)
    lines: list[str] = []
    for n, t in enumerate(pol.types.values()):
        ways = [f" : {p}" for p, x in t.perms.items() if not x.hidden]
        if any(r.table == t.table and r.command == "select" and not r.columns for r in pol.rules):
            ways.append("")
        taken = []
        for way in ways:
            try:
                Compiler(
                    compile_policy.parse_policy(f"{text}\nsync role {SYNC_ROLE}\nsync {t.table}{way}\n", path)
                ).compile(path)
                taken.append(way)
            except PolicyError:
                continue
        if taken:
            lines.append(f"sync {t.table}{taken[(seed + n) % len(taken)]}")
    if not lines:
        return text
    return f"{text.rstrip(chr(10))}\n\n-- the sync index (difftest)\nsync role {SYNC_ROLE}\n" + "\n".join(lines) + "\n"


class Reference(evaluate.Reference):
    """The reference evaluator (authzlib/evaluate.py: relations and permissions as sets of ids, computed as a
    least fixpoint, straight from what the policy says), with the queries that read its data from a database."""

    def live(self) -> str:
        return f"{NOT_EXPIRED} AND {STARTED} AND {caveat_case(self.pol.caveats)}"

    def shares_sql(self, t: Type, rname: str, st: str, sr: str | None, when: str) -> str:
        """The (object, subject) pairs of t's shares of rname with st#sr, for the shares g `when` holds of."""
        srel = "" if sr in (None, "*") else sr
        # a principal type's shares: to one (bot 2), or to every one signed in (bot:*)
        one = sr is None and st in self.types and self.types[st].principal
        sid = " AND g.subject_id = '*'" if sr == "*" else (" AND g.subject_id <> '*'" if one else "")
        return (
            "SELECT coalesce(json_agg(json_build_array(g.object_id, g.subject_id)), '[]') "
            f"FROM authz.shares g WHERE g.object_type = {lit(t.name)} "
            f"AND g.relation = {lit(rname)} AND g.subject_type = {lit(st)} "
            f"AND g.subject_relation = {lit(srel)}{sid} AND {when}"
        )

    def role_shares_sql(self, t: Type, p: str, st: str, sr: str | None, when: str) -> str:
        """The custom roles given on t that include p to st#sr, for the shares g `when` holds of: (object, subject,
        the role's owner when it is of the type `from rel` names, '' otherwise: it never counts)."""
        owner = (
            f"CASE WHEN ro.owner_type = {lit(evaluate.role_owner_type(t))} THEN ro.owner_id ELSE '' END"
            if t.roles_from
            else "''"
        )
        return (
            f"SELECT coalesce(json_agg(json_build_array(g.object_id, g.subject_id, {owner})), '[]') "
            f"FROM authz.shares g JOIN authz.roles ro ON g.relation = 'role:' || ro.id "
            f"JOIN authz.role_permissions rp ON rp.role_id = ro.id "
            f"WHERE g.object_type = {lit(t.name)} AND ro.object_type = {lit(t.name)} "
            f"AND rp.permission = {lit(p)} "
            f"AND g.subject_type = {lit(st)} AND g.subject_relation = {lit(sr or '')} AND {when}"
        )

    def decisions_queries(self) -> list[tuple[tuple[str | int, ...], str]]:
        """(key, sql) for tests/decisions.py: the shares that don't count, by why (expired, not started yet, a
        caveat that doesn't hold), each live otherwise, and those that count by a caveat that holds. (A share to an
        object is a link of an inheritance tree: it can't expire, start later or have a caveat.)"""
        caveat = caveat_case(self.pol.caveats)
        whens = {
            "expired": f"NOT {NOT_EXPIRED} AND {STARTED} AND {caveat}",
            "not started": f"{NOT_EXPIRED} AND NOT {STARTED} AND {caveat}",
        }
        if self.pol.caveats:
            whens["caveat false"] = f"{NOT_EXPIRED} AND {STARTED} AND g.caveat IS NOT NULL AND NOT {caveat}"
            whens["caveat true"] = f"{NOT_EXPIRED} AND {STARTED} AND g.caveat IS NOT NULL AND {caveat}"
        out: list[tuple[tuple[str | int, ...], str]] = []
        for t in self.types.values():
            for r in t.relations.values():
                for i, src in enumerate(r.sources):
                    for st, sr in src.subjects:
                        if src.kind == "shared" and not (
                            sr is None and st in self.types and not self.types[st].principal
                        ):
                            out += [
                                (
                                    ("share", why, t.name, r.name, i, st, sr or ""),
                                    self.shares_sql(t, r.name, st, sr, when),
                                )
                                for why, when in whens.items()
                            ]
            if t.roles:
                for p in t.roles[1]:
                    for st, sr in t.roles[0]:
                        out += [
                            (("role share", why, t.name, p, st, sr or ""), self.role_shares_sql(t, p, st, sr, when))
                            for why, when in whens.items()
                        ]
        return out

    def data_queries(self) -> list[tuple[tuple[str | int, ...], str]]:
        """(key, sql returning a json array) for everything the evaluator reads."""
        out: list[tuple[tuple[str | int, ...], str]] = []
        for t in self.types.values():
            out.append((("ids", t.name), f"SELECT coalesce(json_agg({idsql(t, 'r')}), '[]') FROM {qt(t.table)} r"))
            # a condition's row is the table aliased `this`: `this.id` and a bare column mean what SQL makes of
            # them, with nothing of the compiler's (sqlutil.on_row) between
            where = f"coalesce(({t.where}), false)" if t.where else "true"
            out.append(
                (
                    ("valid", t.name),
                    f"SELECT coalesce(json_agg({idsql(t, 'this')}), '[]') FROM {qt(t.table)} this WHERE {where}",
                )
            )
            for r in t.relations.values():
                for i, src in enumerate(r.sources):
                    for st, sr in src.subjects:
                        key = ("pairs", t.name, r.name, i, st, sr or "")
                        if src.kind == "column":
                            poly = f" AND r.{q(src.type_col)} = {lit(st)}" if src.type_col else ""
                            sql = (
                                f"SELECT coalesce(json_agg(json_build_array({idsql(t, 'r')}, "
                                f"{idsql(self.types[st], 'r', src.column)})), '[]') "
                                f"FROM {qt(t.table)} r WHERE {notnull('r', src.column)}{poly}"
                            )
                        elif src.kind == "table":
                            where = f" AND coalesce(({src.where}), false)" if src.where else ""
                            poly = f" AND this.{q(src.type_col)} = {lit(st)}" if src.type_col else ""
                            sql = (
                                f"SELECT coalesce(json_agg(json_build_array({idsql(t, 'this', src.obj_col)}, "
                                f"{idsql(self.types[st], 'this', src.subj_col)})), '[]') "
                                f"FROM {qt(src.table or '')} this WHERE {notnull('this', src.obj_col)} "
                                f"AND {notnull('this', src.subj_col)}{where}{poly}"
                            )
                        else:
                            sql = self.shares_sql(t, r.name, st, sr, self.live())
                        out.append((key, sql))
            if t.roles:
                subjects, perms, _ = t.roles
                for p in perms:
                    for st, sr in subjects:
                        out.append(
                            (("rolepairs", t.name, p, st, sr or ""), self.role_shares_sql(t, p, st, sr, self.live()))
                        )
        for tname, cond in self.conditions():
            t = self.types[tname]
            out.append(
                (
                    ("cond", tname, cond),
                    f"SELECT coalesce(json_agg({idsql(t, 'this')}), '[]') FROM {qt(t.table)} this WHERE coalesce(({cond}), false)",
                )
            )
        return out


class SyncReference(Reference):
    """The reference as the sync index holds to it: a share with a caveat gives nothing (a caveat is checked at each
    request, with what it says), and nobody presents a link."""

    def live(self) -> str:
        return f"{NOT_EXPIRED} AND {STARTED} AND g.caveat IS NULL"


# ----------------------------------------------------------------------
# Comparing
# ----------------------------------------------------------------------
def unfed(pol: Policy) -> set[tuple[str, str]]:
    """The permissions whose answer may change with no change the feed hears of: those reading a condition that
    reads other rows (a subquery, the app's function), in themselves, a relation's `where` or `shared if`, a caveat
    or the type's where, or through what they read."""
    types = pol.types
    caveats = any(reads_more(c.sql) for c in pol.caveats.values())

    def rel_reads(t: Type, rname: str) -> bool:
        r = t.relations.get(rname)
        if r is None:
            return False
        for src in r.sources:
            where = src.where if src.kind == "table" else src.shared_if if src.kind == "shared" else None
            if (where and reads_more(where)) or (src.kind in ("shared", "roles") and caveats):
                return True
        return False

    out: set[tuple[str, str]] = set()
    changed = True
    while changed:
        changed = False
        for t in types.values():
            for p in t.perms.values():
                if (t.name, p.name) in out:
                    continue
                bad = bool(t.where and reads_more(t.where))
                for x, _ in leaves(p.expr):
                    if isinstance(x, Cond):
                        bad = bad or reads_more(x.sql)
                    elif isinstance(x, Ref):
                        bad = bad or (t.name, x.name) in out or rel_reads(t, x.name)
                        for st, sr in t.relations[x.name].subjects() if x.name in t.relations else []:
                            bad = (
                                bad
                                or (st, sr or "") in out
                                or (st in types and bool(sr) and rel_reads(types[st], sr or ""))
                            )
                    elif isinstance(x, (Arrow, ArrowOn)):
                        bad = bad or rel_reads(t, x.rel)
                        for st, _ in t.relations[x.rel].subjects() if x.rel in t.relations else []:
                            bad = bad or (st, x.perm) in out
                if bad:
                    out.add((t.name, p.name))
                    changed = True
    return out


class Checker:
    # requests, breaking the glass and reviews tried in each snapshot (workflow_setup, workflow_problems)
    workflows: ClassVar[bool] = True

    def __init__(self, db: DB, policy_path: str, gen: Gen, decisions: bool = False, text: str | None = None) -> None:
        self.db, self.gen = db, gen
        # everyone who signs in, and nobody ('': signed out, what `anyone` and links are for)
        self.users, self.role = [*gen.users, ""], gen.role
        # (text: the policy as applied, where it isn't the file's: with sync lines, synced())
        text = read(policy_path) if text is None else text
        self.pol = compile_policy.parse_policy(text, policy_path)
        self.sync_ref = SyncReference(self.pol)
        self.refuse = refusals_of(self.pol)
        self.types, self.rules = self.pol.types, self.pol.rules
        self.ref = Reference(self.pol)
        # with decisions: which parts of the policy decided an answer, over every snapshot (tests/decisions.py)
        self.decisions = Decisions(self.pol, text) if decisions else None
        gen.ledger = self.decisions
        self.decisions_queries = self.ref.decisions_queries() if decisions else []
        self._nocontext: dict[tuple[str, str, str], set[str]] | None = None
        self._nocontext_all: dict[tuple[str, str, str], set[str]] | None = None
        self.policies: list[list[str]] = json.loads(
            self.db.run(
                "SELECT coalesce(json_agg(json_build_array(schemaname || '.' || tablename, policyname, "
                "coalesce(qual, ''), coalesce(with_check, '')) ORDER BY tablename, policyname), '[]') "
                "FROM pg_policies WHERE policyname LIKE 'authz\\_%'"
            )[1]
        )
        # each rule on a command (not on columns: a trigger's, below) is a policy named after it on its table, which
        # the checks below then compare: one missing would refuse that command on every row, and compare nothing
        made = {(table, name) for table, name, _, _ in self.policies}
        wanted = {
            (r.table, f"authz_{r.command}")
            for r in self.rules
            if not r.columns and r.command not in ("mask", "update after")
        }
        if made != wanted:
            raise SystemExit(
                f"{len(wanted)} rules on a command in the policy, {len(made)} row-level security policies for them: "
                f"missing {sorted(wanted - made)}, not in the policy {sorted(made - wanted)}"
            )
        # Column rules (`update owner_id : share`) are triggers, named after the rule's head on their table: each
        # one's condition is read back from its WHEN, to be evaluated on every row as the policies' are.
        triggers: dict[tuple[str, str], str] = {
            (table, name): body
            for table, name, body in json.loads(
                self.db.run(
                    "SELECT coalesce(json_agg(json_build_array(n.nspname || '.' || c.relname, tg.tgname, "
                    "pg_get_triggerdef(tg.oid))), '[]') FROM pg_trigger tg "
                    "JOIN pg_class c ON c.oid = tg.tgrelid "
                    "JOIN pg_namespace n ON n.oid = c.relnamespace "
                    "WHERE (tg.tgname LIKE 'authz\\_update %' OR tg.tgname LIKE 'authz\\_update\\_after %') AND NOT tg.tgisinternal"
                )[1]
            )
        }
        by_table: dict[str, list[Rule]] = {}
        for r in self.rules:
            by_table.setdefault(r.table, []).append(r)
        ruled = [r for rules in by_table.values() for r in rules if r.columns and r.command != "mask"]
        triggers = {k: v for k, v in triggers.items() if k[0] in by_table}  # (not the copies on tables that inherit)
        if len(triggers) != len(ruled):
            raise SystemExit(
                f"{len(ruled)} column rules in the policy, {len(triggers)} triggers for them: {sorted(triggers)}"
            )
        self.column_rules: list[tuple[Rule, str]] = []
        for r in ruled:
            name = ident(f"authz_update{'_after' if r.command == 'update after' else ''} {', '.join(r.columns)}")
            w = COLUMN_WHEN.search(triggers.get((r.table, name), ""))
            if not w or (w.group(2).upper() == "NEW") != (r.command == "update after"):
                raise SystemExit(
                    f"{r.table}, the rule on {', '.join(r.columns)}: its trigger {name} is missing, or doesn't "
                    f"check the row {'after' if r.command == 'update after' else 'before'} the change"
                )
            self.column_rules.append((r, f"{w.group(1)}(the_row)"))  # asked of each row, FROM <table> the_row
        self.checks = 0  # how many snapshots so far: who is asked with a scope, and which
        self.scoped: tuple[str, str] = ("", "read")
        # the change feed: where it was after the last snapshot, what each user held then, and who signed in
        self.fed: tuple[int, dict[tuple[str, str, str], frozenset[str]], dict[str, bool]] | None = None
        self.unfed = unfed(self.pol)

    def feed_position(self) -> int:
        rows = self.db.rows("SELECT coalesce(max(pos), 0) FROM authz.changes")
        return int(rows[0][0]) if rows else 0  # (none: a database made up for a test, which keeps no feed)

    def feed_problems(
        self, start: int, held: dict[tuple[str, str, str], frozenset[str]], signed: dict[str, bool]
    ) -> list[str]:
        """The change feed names every object whose answer changed for anyone since the last snapshot (by its id,
        or `*` for its type): what the reference says each user held then and holds now, against what the feed
        announced in between. Not a user whose row came or went (all they hold changes with it), nor a permission
        that reads a condition on other rows (unfed: what a subquery reads is the app's SQL)."""
        if self.fed is None:
            return []
        end, before, was = self.fed
        announced: dict[str, set[str]] = {}
        for t, ids in self.db.rows(
            f"SELECT object_type, array_to_json(object_ids) FROM authz.changes WHERE pos > {end} AND pos <= {start}"
        ):
            announced.setdefault(t, set()).update(json.loads(ids))
        problems: list[str] = []
        for (u, t, p), now in sorted(held.items()):
            if (t, p) in self.unfed or was.get(u) != signed[u] or (u, t, p) not in before:
                continue
            fed = announced.get(t, set())
            for i in sorted(now ^ before[(u, t, p)]):
                if "*" not in fed and i not in fed:
                    problems.append(
                        f"the change feed: user {u} {'gained' if i in now else 'lost'} {p} on {t} {i}, "
                        f"which the feed did not announce (it announced {sorted(fed)[:8]})"
                    )
        return problems[:12]

    def context(self, u: str) -> dict[str, str]:
        return self.gen.context(u)

    def scope_allows(self, scope: str, kind: str, qual: str, word: str) -> bool:
        """Whether a transaction limited to this scope may run a command on a table (kind 'cmd') or use a
        permission of a type ('perm'). `read` is built in unless the policy defines it. (What an item lets
        through is the rule decisions.py reports by, so these checks judge it too.)"""
        return any(allows(item, kind, qual, word) for item in scope_items(self.pol, scope))

    def snapshot(self) -> Snapshot:
        """The evaluator's inputs and the database's answers, per user. Each user's questions are a block that
        leaves its session as it found it, so the blocks can be asked in any order, in a few sessions side by
        side (SESSIONS). A session still answers for several users, one after the other: what it keeps from one
        (cached plans, settings) must not show in the next one's answers, and which users share a session, and
        in what order, changes with each snapshot."""
        blocks: list[list[str]] = []
        lines: list[str] = []

        def emit(key: list[str | int], sql: str) -> None:
            lines.append(f"SELECT {lit(json.dumps(key))}, ({sql});")

        self.db.run("\n".join(self.as_app_functions()))
        self.shares_tried = self.shareable(conditions=True)
        self.links_tried = self.shareable("link")  # (a link's `shared if` would read its hash, made at random)
        # who tries to share in this snapshot: one user, in turn (each attempt is a subtransaction of its own)
        sharer = self.users[self.checks % len(self.users)]
        # what lets someone share anything on an object of a type: share, or a permission a relation is shared by
        self.share_perms: dict[str, set[str]] = {}
        for row in self.db.rows("SELECT object_type || '|' || shared_by FROM authz_int.shared_relations"):
            tname, by = row[0].split("|")
            self.share_perms.setdefault(tname, {"share"}).add(by)
        # whom the sharer tries to share with: a user id, another in each snapshot (one that is no row, or fails the
        # user type's where, now and then: what a `shared if` may ask about)
        targets = [u for u in self.users if signs_in_as_user(u, self.types)]
        self.share_target = targets[self.checks % len(targets)] if targets else ""
        # the custom roles API, tried by the same user: the types that may own roles (manage_roles), the types that
        # have them with the permissions a role there may give (every other turn, one more it may not), and the
        # roles there are, owned by such a type
        self.role_owners = [t.name for t in self.types.values() if "manage_roles" in t.perms]
        self.role_perms: dict[str, list[str]] = {}
        for t in self.types.values():
            if t.roles:
                more = [p for p, x in t.perms.items() if p not in t.roles[1] and not x.hidden][:1]
                self.role_perms[t.name] = t.roles[1] + (more if self.checks // len(self.users) % 2 else [])
        self.roles_now = {
            rid: (owner_type, owner_id, object_type)
            for rid, owner_type, owner_id, object_type in self.db.rows(
                "SELECT id, owner_type, owner_id, object_type FROM authz.roles ORDER BY id"
            )
            if owner_type in self.role_owners
        }
        # the relations a link may be given on each type, with the permission that manages them (unsharing one, or
        # turning it off: none if the type hasn't it), as the compiled catalog says
        self.link_by: dict[tuple[str, str], str | None] = {
            (tname, rname): by if by in self.types[tname].perms else None
            for tname, rname, by in self.db.rows(
                "SELECT object_type, relation, shared_by FROM authz_int.shared_relations WHERE subject = 'link'"
            )
        }
        # every row's id, as the owner reads them: authz.can is asked of each, whether the user may see the row or not
        every = {
            t.name: [row[0] for row in self.db.rows(f"SELECT {idsql(t)} FROM {qt(t.table)}")]
            for t in self.types.values()
        }
        # the rows explain is asked about by each user themselves, whether they may see them or not: picked here
        sample = {
            t.name: [
                row[0] for row in self.db.rows(f"SELECT {idsql(t)} FROM {qt(t.table)} ORDER BY md5({idsql(t)}) LIMIT 2")
            ]
            for t in self.types.values()
        }
        # the links on those rows of the types links may be given on, and on up to three more rows of each that have
        # some: (relation, the link's id), as the owner reads them, expired or not, as authz.list_links lists them
        self.links_now: dict[tuple[str, str], list[tuple[str, str]]] = {
            (tname, i): [] for tname in dict.fromkeys(t for t, _ in self.link_by) for i in sample[tname]
        }
        if self.links_now:
            more: dict[str, int] = {}
            for tname, i, rname, lid in self.db.rows(
                "SELECT object_type, object_id, relation, left(subject_id, 16) FROM authz.shares "
                "WHERE subject_type = 'link' ORDER BY md5(object_id), 1, 2, 3, 4"
            ):
                if (tname, i) not in self.links_now:
                    if more.get(tname, 0) == 3 or not any(t == tname for t, _ in self.link_by):
                        continue
                    more[tname] = more.get(tname, 0) + 1
                    self.links_now[(tname, i)] = []
                self.links_now[(tname, i)].append((rname, lid))
        # every share on the rows of each type with `share`, as the owner reads them, as authz.list_shares lists them
        # to those who may share there: (relation, subject type, subject id, subject relation), a link's id hidden
        self.shares_now: dict[tuple[str, str], list[list[str]]] = {}
        inspected = [t.name for t in self.types.values() if "share" in t.perms]
        if inspected:
            for tname, i, rname, st, sid, sr in self.db.rows(
                "SELECT object_type, object_id, relation, subject_type, subject_id, subject_relation FROM authz.shares "
                f"WHERE object_type IN ({', '.join(lit(t) for t in inspected)})"
            ):
                self.shares_now.setdefault((tname, i), []).append([rname, st, "(link)" if st == "link" else sid, sr])
        self.inspected = inspected
        self.workflow_setup(sharer, sample)
        for u in self.users:
            lines = []
            blocks.append(lines)
            kind, pid = evaluate.principal_of(u, self.types)
            lines.append(f"SET authz.user_id = {lit(pid)};")
            lines.append(f"SET authz.principal_type = {lit('' if kind == 'user' else kind)};")
            for k, v in self.context(u).items():
                lines.append(f"SET authz_ctx.{k} = {lit(v)};")
            for key, sql in self.ref.data_queries():
                emit([u, "data", *key], sql)
            # the sync index: the rows of each synced table whose readers hold a key the principal holds
            for table in self.pol.syncs:
                t = self.ref.type_of_table(table)
                emit(
                    [u, "sync", t.name],
                    f"SELECT coalesce(json_agg(DISTINCT {idsql(t, 'r')}), '[]') FROM authz_sync.{q(t.name + '__readers')} r "
                    f"WHERE r.key IN (SELECT k.key FROM authz_sync.keys k WHERE k.principal_type = {lit(kind)} "
                    f"AND k.principal_id = {lit(pid)})",
                )
            for key, sql in self.decisions_queries:
                emit([u, "decisions", *key], sql)
            # a `shared if` on the shares the one whose turn it is tries: the rows on which it holds, for the share as
            # it would be made, evaluated as conditions are (by the database, as the policy's owner, them signed in);
            # to the user shared with, and to each other who asks for access (approving a request shares with them)
            for (tname, rname), (_, _, cond) in self.shares_tried.items() if pid and u == sharer else ():
                for to in dict.fromkeys([self.share_target, *self.requesters]) if cond else ():
                    t = self.types[tname]
                    emit(
                        [u, "share if", tname, rname, *([] if to == self.share_target else [to])],
                        f"SELECT coalesce(json_agg({idsql(t, 'o')}), '[]') FROM {qt(t.table)} o WHERE (SELECT "
                        f"coalesce(({cond}), false) FROM (SELECT ({idsql(t, 'o')})::{t.pktype} AS object_id, "
                        f"'user'::text AS subject_type, {lit(to)}::text AS subject_id, "
                        "''::text AS subject_relation) this)",
                    )
            # the database's answers, as the app role
            lines.append(f"SET ROLE {self.role};")
            for t in self.types.values():
                for p in t.perms:
                    emit(
                        [u, "list", t.name, p],
                        f"SELECT coalesce(json_agg(x ORDER BY x), '[]') FROM authz.list({lit(t.name)}, {lit(p)}) x",
                    )
                    if u == sharer:
                        emit([u, "pages", t.name, p], pages_sql(t, p))
                    emit(
                        [u, "can", t.name, p],
                        f"SELECT coalesce(json_agg(json_build_array(i, authz.can({lit(t.name)}, i, {lit(p)}))), '[]') "
                        f"FROM unnest({text_array([*every[t.name], MISSING_ROW])}) i",
                    )
            # authz.perms_of (authz.perms for each): every permission held on a few objects at once, a list's buttons
            for t in self.types.values():
                ids = "ARRAY[" + ", ".join(lit(i) for i in sample[t.name]) + "]::text[]"
                emit(
                    [u, "perms_of", t.name],
                    f"SELECT coalesce(json_agg(json_build_array(x.id, x.perms)), '[]') "
                    f"FROM authz.perms_of({lit(t.name)}, {ids}) x",
                )
            if kind == "user" and pid:
                # authz.explain asked by the user themselves: about a row they can't see, nothing (and the same
                # when they name their own id; one whose row isn't there signs in as nobody, and names another's)
                for t in self.types.values():
                    ids = "ARRAY[" + ", ".join(lit(i) for i in sample[t.name]) + "]::text[]"
                    for p in t.perms:
                        emit(
                            [u, "explain self", t.name, p],
                            f"SELECT coalesce(json_agg(json_build_array(i, (SELECT e FROM authz.explain("
                            f"{lit(t.name)}, i, {lit(p)}, NULL) e LIMIT 1))), '[]') FROM unnest({ids}) i",
                        )
                        emit(
                            [u, "explain self by id", t.name, p],
                            f"SELECT coalesce(json_agg(json_build_array(i, difftest_app.try_explain("
                            f"{lit(t.name)}, i, {lit(p)}, {lit(pid)}))), '[]') FROM unnest({ids}) i",
                        )
                # authz.explain_rule's verdict on an update and on a delete, as the app asks it (without the changes)
                for table in dict.fromkeys(r.table for r in self.rules):
                    t = self.ref.type_of_table(table)
                    ids = "ARRAY[" + ", ".join(lit(i) for i in sample[t.name]) + "]::text[]"
                    for cmd in ("update", "delete"):
                        emit(
                            [u, "explain_rule", table, cmd],
                            f"SELECT coalesce(json_agg(json_build_array(i, (authz.explain_rule({lit(table)}, "
                            f"{lit(cmd)}, i, NULL))[1])), '[]') FROM unnest({ids}) i",
                        )
            if pid and u == sharer:
                # the APIs that share, tried by whoever's turn it is (a user, or a service), each attempt undone:
                # authz.share and unshare, what sharing lets through and how it refuses
                for (tname, rname), (by, _, _) in self.shares_tried.items():
                    t = self.types[tname]
                    # the sample rows, and two that they may share it on (if the database says so: what they get
                    # there is judged all the same)
                    rows = "SELECT unnest(ARRAY[" + ", ".join(lit(i) for i in sample[tname]) + "]::text[])"
                    if by in t.perms:
                        rows += (
                            f" UNION (SELECT {idsql(t)} FROM {qt(t.table)} WHERE authz.can({lit(tname)}, {idsql(t)}, "
                            f"{lit(by)}) ORDER BY md5({idsql(t)}) LIMIT 2)"
                        )
                    for what in ("share", "unshare"):
                        emit(
                            [u, what, tname, rname],
                            f"SELECT coalesce(json_agg(json_build_array(i, difftest_app.try_{what}({lit(tname)}, i, "
                            f"{lit(rname)}, 'user', {lit(self.share_target)}))), '[]') FROM ({rows}) s(i)",
                        )
                for tname, rname in self.links_tried:
                    ids = "ARRAY[" + ", ".join(lit(i) for i in sample[tname]) + "]::text[]"
                    emit(
                        [u, "create_link", tname, rname],
                        f"SELECT coalesce(json_agg(json_build_array(i, difftest_app.try_create_link({lit(tname)}, i, "
                        f"{lit(rname)}))), '[]') FROM unnest({ids}) i",
                    )
                # the custom roles API: a role made for each type that has them by each owner tried, each role there
                # is given its type's permissions and deleted (and one that isn't there), and the roles each owner
                # tried has
                for owner in self.role_owners:
                    ids = "ARRAY[" + ", ".join(lit(i) for i in sample[owner]) + "]::text[]"
                    for tname, perms in self.role_perms.items():
                        emit(
                            [u, "create_role", tname, owner],
                            f"SELECT coalesce(json_agg(json_build_array(i, difftest_app.try_create_role({lit(owner)}, "
                            f"i, {lit(tname)}, {text_array(perms)}))), '[]') FROM unnest({ids}) i",
                        )
                    emit(
                        [u, "roles_of", owner],
                        f"SELECT coalesce(json_agg(json_build_array(i, difftest_app.try_roles_of({lit(owner)}, i))), "
                        f"'[]') FROM unnest({ids}) i",
                    )
                for rid in [*self.roles_now, MISSING_ROLE] if self.role_owners else ():
                    perms = self.role_perms.get(self.roles_now[rid][2], []) if rid in self.roles_now else []
                    emit(
                        [u, "role", rid],
                        f"SELECT json_build_array(difftest_app.try_set_role_permissions({rid}, {text_array(perms)}), "
                        f"difftest_app.try_delete_role({rid}))",
                    )
                # the links on each row tried: listed, and each turned off (and one that isn't there)
                for (tname, i), links in self.links_now.items():
                    tries = [f"difftest_app.try_list_links({lit(tname)}, {lit(i)})"] + [
                        f"difftest_app.try_revoke_link({lit(tname)}, {lit(i)}, {lit(lid)})" for lid in link_ids(links)
                    ]
                    emit([u, "links", tname, i], f"SELECT json_build_array({', '.join(tries)})")
                # the shares on the sample rows of each type with `share`, and on two they may share
                for tname in self.inspected:
                    t = self.types[tname]
                    emit(
                        [u, "list_shares", tname],
                        f"SELECT coalesce(json_agg(json_build_array(i, difftest_app.try_list_shares({lit(tname)}, i))), "
                        f"'[]') FROM (SELECT unnest(ARRAY[{', '.join(lit(i) for i in sample[tname])}]::text[]) UNION "
                        f"(SELECT {idsql(t)} FROM {qt(t.table)} WHERE authz.can({lit(tname)}, {idsql(t)}, 'share') "
                        f"ORDER BY md5({idsql(t)}) LIMIT 2)) s(i)",
                    )
                # requests, breaking the glass and reviews, tried by the same user, each attempt undone
                for tname, rname in self.requests_tried:
                    emit(
                        [u, "request", tname, rname],
                        f"SELECT coalesce(json_agg(json_build_array(i, difftest_app.try_request({lit(tname)}, i, "
                        f"{lit(rname)}))), '[]') FROM unnest({text_array(sample[tname])}) i",
                    )
                for n in self.requests:
                    emit(
                        [u, "decide", str(n)],
                        f"SELECT json_build_array(difftest_app.try_decide({n}, true), "
                        f"difftest_app.try_decide({n}, false), difftest_app.try_cancel({n}))",
                    )
                if self.workflows:
                    emit([u, "pending"], "SELECT difftest_app.try_pending()")
                for tname, rname in self.glass_tried:
                    emit(
                        [u, "break_glass", tname, rname],
                        f"SELECT coalesce(json_agg(json_build_array(i, difftest_app.try_break_glass({lit(tname)}, i, "
                        f"{lit(rname)}))), '[]') FROM unnest({text_array(sample[tname])}) i",
                    )
                for tname in self.inspected if self.workflows else ():
                    t = self.types[tname]
                    emit(
                        [u, "review", tname],
                        f"SELECT coalesce(json_agg(json_build_array(i, difftest_app.try_review({lit(tname)}, i, "
                        f"{'true' if self.review_undecided else 'false'}))), '[]') "
                        f"FROM (SELECT unnest({text_array(sample[tname])}) UNION "
                        f"(SELECT {idsql(t)} FROM {qt(t.table)} WHERE authz.can({lit(tname)}, {idsql(t)}, 'share') "
                        f"ORDER BY md5({idsql(t)}) LIMIT 2)) s(i)",
                    )
            for table in dict.fromkeys(r.table for r in self.rules if r.command == "select"):
                t = self.ref.type_of_table(table)
                emit([u, "rls", table], f"SELECT coalesce(json_agg({idsql(t)}), '[]') FROM {qt(table)}")
            for table, view in self.pol.views.items():
                t = self.ref.type_of_table(table)
                emit([u, "view", table], f"SELECT coalesce(json_agg({idsql(t)}), '[]') FROM {qt(view)}")
                for r in self.rules:
                    if r.table == table and r.command == "mask":
                        for c in r.columns:
                            emit(
                                [u, "mask", table, c],
                                f"SELECT coalesce(json_agg({idsql(t)}), '[]') FROM {qt(view)} WHERE {q(c)} IS NOT NULL",
                            )
            # the policy expressions and column rules again, as the app role checks them (on the rows it may
            # select): a condition run with the app role's rights instead of the policy's shows here only
            for key, fn in self.as_app_keys():
                emit([u, *key], f"SELECT {fn}()")
            lines.append("RESET ROLE;")
            # authz.explain's verdict, as an administrator asking about this user
            for t in self.types.values():
                for p in t.perms:
                    asked = lit(u) if kind == "user" and u else "NULL"  # other principals, nobody: as themselves
                    emit(
                        [u, "explain", t.name, p],
                        f"SELECT coalesce(json_agg(json_build_array(i, (SELECT e FROM authz.explain({lit(t.name)}, i, "
                        f"{lit(p)}, {asked}) e LIMIT 1))), '[]') FROM (SELECT {idsql(t)} AS i FROM {qt(t.table)} "
                        f"ORDER BY md5({idsql(t)}) LIMIT 2) s",
                    )
            # every policy expression on every row (as the owner, so RLS does not filter)
            for table, name, qual, check in self.policies:
                t = self.ref.type_of_table(table)
                for part, expr in (("using", qual), ("check", without_refusals(check, self.refuse))):
                    if expr:
                        emit(
                            [u, "policy", table, name, part],
                            f"SELECT coalesce(json_agg({idsql(t)}), '[]') FROM {qt(table)} WHERE ({expr})",
                        )
            for n, (r, cond) in enumerate(self.column_rules):
                emit(
                    [u, "column", str(n)],
                    f"SELECT coalesce(json_agg({idsql(self.ref.type_of_table(r.table))}), '[]') "
                    f"FROM {qt(r.table)} the_row WHERE coalesce(({cond}), false)",
                )
            for k in self.context(u):
                lines.append(f"RESET authz_ctx.{k};")
            lines += ["RESET authz.user_id;", "RESET authz.principal_type;"]
        # One of them again with a scope (what a token limited to it may do), another pair each time
        scopes = sorted({"read", *self.pol.scopes})
        u, scope = self.users[self.checks % len(self.users)], scopes[self.checks // len(self.users) % len(scopes)]
        self.scoped, self.checks = (u, scope), self.checks + 1
        kind, pid = evaluate.principal_of(u, self.types)
        lines = []
        blocks.append(lines)
        lines += [
            f"SET authz.user_id = {lit(pid)};",
            f"SET authz.principal_type = {lit('' if kind == 'user' else kind)};",
            *[f"SET authz_ctx.{k} = {lit(v)};" for k, v in self.context(u).items()],
            f"SET authz.scopes = {lit(scope)};",
            f"SET ROLE {self.role};",
        ]
        for t in self.types.values():
            for p in t.perms:
                emit(
                    ["scoped", "list", t.name, p],
                    f"SELECT coalesce(json_agg(x ORDER BY x), '[]') FROM authz.list({lit(t.name)}, {lit(p)}) x",
                )
                emit(
                    ["scoped", "can", t.name, p],
                    f"SELECT coalesce(json_agg(json_build_array(i, authz.can({lit(t.name)}, i, {lit(p)}))), '[]') "
                    f"FROM unnest({text_array(every[t.name])}) i",
                )
        lines.append("RESET ROLE;")
        for table, name, qual, check in self.policies:
            t = self.ref.type_of_table(table)
            for part, expr in (("using", qual), ("check", without_refusals(check, self.refuse))):
                if expr:
                    emit(
                        ["scoped", "policy", table, name, part],
                        f"SELECT coalesce(json_agg({idsql(t)}), '[]') FROM {qt(table)} WHERE ({expr})",
                    )
        lines += ["RESET authz.scopes;", *[f"RESET authz_ctx.{k};" for k in self.context(u)]]
        lines.append("RESET authz.user_id;")
        lines.append("RESET authz.principal_type;")
        # authz.who for a few objects of each type (as an administrator)
        lines = []
        blocks.append(lines)
        for t in self.types.values():
            for p in t.perms:
                emit(
                    ["who", t.name, p],
                    f"SELECT coalesce(json_agg(json_build_array(i, (SELECT coalesce(json_agg(x ORDER BY x), '[]') "
                    f"FROM authz.who({lit(t.name)}, i, {lit(p)}) x))), '[]') FROM (SELECT {idsql(t)} AS i "
                    f"FROM {qt(t.table)} ORDER BY md5({idsql(t)} || 'w') LIMIT 6) s",
                )
        # authz.who_among on the same rows, for every user id the suite signs in (rows of the user table or not):
        # one public permission of each type, in turn
        user_ids = [u for u in self.users if signs_in_as_user(u, self.types)]  # (a user's id is its name here)
        for t in self.types.values():
            public = [p for p, x in t.perms.items() if not x.hidden]
            if public and user_ids:
                p = public[self.checks % len(public)]
                emit(
                    ["who_among", t.name, p],
                    f"SELECT coalesce(json_agg(json_build_array(i, (SELECT coalesce(json_agg(x ORDER BY x), '[]') "
                    f"FROM authz.who_among({lit(t.name)}, i, {lit(p)}, {text_array(user_ids)}) x))), '[]') "
                    f"FROM (SELECT {idsql(t)} AS i FROM {qt(t.table)} ORDER BY md5({idsql(t)} || 'w') LIMIT 6) s",
                )
        lines.append("SELECT '[\"verify\"]', to_json(authz.verify());")
        if self.pol.syncs:
            # what the sync index reads that differs from what the reference reads for each user: the shares, without
            # those with a caveat; and whether it matches a rebuild
            ours = dict(self.ref.data_queries())
            for key, sql in self.sync_ref.data_queries():
                if ours.get(key) != sql:
                    emit(["sync data", *key], sql)
            lines.append("SELECT '[\"sync verify\"]', to_json(authz.sync_verify());")
        # two blocks or more to a session, where there are enough
        random.Random(self.checks).shuffle(blocks)
        n = max(1, min(SESSIONS, len(blocks) // 2))
        scripts = ["\n".join(line for block in blocks[i::n] for line in block) for i in range(n)]
        out: Snapshot = {}
        for key, val in self.db.rows_together(scripts):
            out[tuple(json.loads(key))] = json.loads(val)
        return out

    def as_app(self, table: str) -> bool:
        """Whether the app role can evaluate a table's rules on its rows: it may select some of them (a select
        rule), and it may name every column (a table with masked columns is read through its view)."""
        return table not in self.pol.views and any(
            r.table == table and r.command == "select" and not r.columns for r in self.rules
        )

    def as_app_queries(self) -> list[tuple[list[str], str]]:
        """Each policy expression and column rule the app role can evaluate: (key, the query of the rows it holds
        for)."""
        out: list[tuple[list[str], str]] = []
        for table, name, qual, check in self.policies:
            if self.as_app(table):
                t = self.ref.type_of_table(table)
                for part, expr in (("using", qual), ("check", without_refusals(check, self.refuse))):
                    if expr:
                        out.append(
                            (
                                ["policy as app", table, name, part],
                                f"SELECT coalesce(json_agg({idsql(t)}), '[]') FROM {qt(table)} WHERE ({expr})",
                            )
                        )
        for n, (r, cond) in enumerate(self.column_rules):
            if self.as_app(r.table):
                out.append(
                    (
                        ["column as app", str(n)],
                        f"SELECT coalesce(json_agg({idsql(self.ref.type_of_table(r.table))}), "
                        f"'[]') FROM {qt(r.table)} the_row WHERE coalesce(({cond}), false)",
                    )
                )
        return out

    def as_app_keys(self) -> list[tuple[list[str], str]]:
        return [(key, f"difftest_app.q{n}") for n, (key, _) in enumerate(self.as_app_queries())]

    def as_app_functions(self) -> list[str]:
        """The queries above as functions the owner makes, BEGIN ATOMIC: parsed once, as row-level security's
        expressions are, so the app role runs them (as itself, through the rules) without looking up names it may
        not (authz_int). Made again for each snapshot: applying again would drop them with what they name."""
        lines = ["CREATE SCHEMA IF NOT EXISTS difftest_app;", f"GRANT USAGE ON SCHEMA difftest_app TO {self.role};"]
        for n, (_, sql) in enumerate(self.as_app_queries()):
            lines.append(
                f"CREATE OR REPLACE FUNCTION difftest_app.q{n}() RETURNS json LANGUAGE sql STABLE "
                f"BEGIN ATOMIC {sql}; END;"
            )
        # authz.share, unshare, create_link and the custom roles API, each tried as the caller and always undone: 'ok',
        # or the refusal's SQLSTATE and words
        for name, args, call in (
            ("share", "t text, i text, r text, st text, sid text", "authz.share(t, i, r, st, sid)"),
            ("unshare", "t text, i text, r text, st text, sid text", "authz.unshare(t, i, r, st, sid)"),
            ("create_link", "t text, i text, r text", "authz.create_link(t, i, r)"),
            (
                "create_role",
                "ot text, oi text, t text, ps text[]",
                "authz.create_role(ot, oi, t, 'difftest tried', ps)",
            ),
            ("set_role_permissions", "r bigint, ps text[]", "authz.set_role_permissions(r, ps)"),
            ("delete_role", "r bigint", "authz.delete_role(r)"),
            ("revoke_link", "t text, i text, l text", "authz.revoke_link(t, i, l)"),
        ):
            lines.append(
                f"CREATE OR REPLACE FUNCTION difftest_app.try_{name}({args}) RETURNS text "
                f"LANGUAGE plpgsql AS $f$ BEGIN BEGIN PERFORM {call}; "
                "RAISE EXCEPTION USING ERRCODE = 'P0099', MESSAGE = 'done'; "
                "EXCEPTION WHEN OTHERS THEN RETURN CASE WHEN SQLSTATE = 'P0099' THEN 'ok' ELSE SQLSTATE || ': ' || SQLERRM END; "
                "END; END $f$;"
            )
        lines.append(  # and the roles an owner has: 'ok' and their ids, or the refusal
            "CREATE OR REPLACE FUNCTION difftest_app.try_roles_of(ot text, oi text) RETURNS text "
            "LANGUAGE plpgsql AS $f$ BEGIN "
            "RETURN 'ok ' || coalesce((SELECT string_agg(r.id::text, ',' ORDER BY r.id) FROM authz.roles_of(ot, oi) r), ''); "
            "EXCEPTION WHEN OTHERS THEN RETURN SQLSTATE || ': ' || SQLERRM; END $f$;"
        )
        lines.append(  # and the shares on an object: {"ok": [[relation, subject type, id, relation], ...]} or the refusal
            "CREATE OR REPLACE FUNCTION difftest_app.try_list_shares(t text, i text) RETURNS json "
            "LANGUAGE plpgsql AS $f$ BEGIN RETURN json_build_object('ok', (SELECT coalesce(json_agg(json_build_array("
            "s.relation, s.subject_type, s.subject_id, s.subject_relation)), '[]') FROM authz.list_shares(t, i) s)); "
            "EXCEPTION WHEN OTHERS THEN RETURN json_build_object('refused', SQLSTATE || ': ' || SQLERRM); END $f$;"
        )
        lines.append(  # and authz.explain's first line for a user, or the refusal
            "CREATE OR REPLACE FUNCTION difftest_app.try_explain(t text, i text, p text, u text) RETURNS text "
            "LANGUAGE plpgsql AS $f$ DECLARE v text; BEGIN "
            "SELECT e INTO v FROM authz.explain(t, i, p, u) e LIMIT 1; RETURN v; "
            "EXCEPTION WHEN OTHERS THEN RETURN SQLSTATE || ': ' || SQLERRM; END $f$;"
        )
        # requests, breaking the glass and reviews, tried as the caller and always undone: {"refused": SQLSTATE and
        # words}, or what the call left (each as below) with "trail", the audit trail it wrote, as the owner reads it
        lines.append(
            "CREATE OR REPLACE FUNCTION difftest_app.trail() RETURNS json LANGUAGE sql SECURITY DEFINER "
            "SET search_path = pg_catalog, pg_temp AS $f$ SELECT coalesce(json_agg(json_build_array(a.action, "
            "a.object_type, a.object_id, a.relation, a.subject_type, a.subject_id, a.subject_relation, a.user_id, "
            "CASE WHEN a.action IN ('share', 'share_changed') THEN a.detail ? 'expires_at' END) ORDER BY a.id), '[]') "
            "FROM authz.audit a WHERE a.txid = txid_current() $f$;"
        )
        lines.append(  # whether a user's share of a relation lets them in now, and until then
            "CREATE OR REPLACE FUNCTION difftest_app.lets_in(t text, i text, r text, s text, until timestamptz) "
            "RETURNS boolean LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $f$ "
            "SELECT EXISTS (SELECT 1 FROM authz.shares g WHERE g.object_type = t AND g.object_id = i "
            "AND g.relation = r AND g.subject_type = 'user' AND g.subject_id = s AND g.subject_relation = '' "
            "AND g.caveat IS NULL AND (g.starts_at IS NULL OR g.starts_at <= now()) "
            "AND (g.expires_at IS NULL OR g.expires_at >= until)) $f$;"
        )
        for name, args, body in (
            (
                "request",
                "t text, i text, r text",
                "PERFORM authz.request_access(t, i, r, 'difftest', interval '3 days');",
            ),
            ("decide", "n bigint, yes boolean", "PERFORM authz.decide_request(n, yes, 'difftest');"),
            ("cancel", "n bigint", "PERFORM authz.cancel_request(n);"),
            (  # the ids of the requests difftest made that the caller is shown
                "pending",
                "",
                "SELECT coalesce(json_agg(p.id ORDER BY p.id), '[]') INTO v FROM authz.pending_requests() p "
                "WHERE p.reason = 'difftest'; v := json_build_object('ids', v);",
            ),
            (  # and whether the caller's share now lets them in for the hour asked
                "break_glass",
                "t text, i text, r text",
                "PERFORM authz.break_glass(t, i, r, 'difftest', interval '1 hour'); v := json_build_object('lets_in', "
                "difftest_app.lets_in(t, i, r, authz.uid()::text, now() + interval '1 hour'));",
            ),
            (  # a review started, its items, each decided in turn (kept, revoked, left undecided), and closed
                "review",
                "t text, i text, undecided boolean",
                "rv := authz.start_review(t, i); "
                "SELECT coalesce(json_agg(json_build_array(x.item, x.relation, x.subject_type, x.subject_id, "
                "x.subject_relation) ORDER BY x.item), '[]') INTO items FROM authz.review_items(rv) x; "
                "FOR it IN SELECT x.item FROM authz.review_items(rv) x WHERE x.item % 3 <> 0 ORDER BY x.item LOOP "
                "BEGIN PERFORM authz.review_decide(rv, it.item, it.item % 3 = 2); "
                "decided := decided || jsonb_build_array(jsonb_build_array(it.item, 'ok')); "
                "EXCEPTION WHEN OTHERS THEN decided := decided || jsonb_build_array(jsonb_build_array(it.item, "
                "SQLSTATE || ': ' || SQLERRM)); END; END LOOP; "
                "v := json_build_object('items', items, 'decided', decided, "
                "'revoked', authz.close_review(rv, undecided));",
            ),
        ):
            lines.append(
                f"CREATE OR REPLACE FUNCTION difftest_app.try_{name}({args}) RETURNS json LANGUAGE plpgsql AS $f$ "
                "DECLARE v json := '{}'; rv bigint; it record; items json; decided jsonb := '[]'; "
                f"BEGIN BEGIN {body} "
                "RAISE EXCEPTION USING ERRCODE = 'P0099', "
                "MESSAGE = (v::jsonb || jsonb_build_object('trail', difftest_app.trail()))::text; "
                "EXCEPTION WHEN OTHERS THEN RETURN CASE WHEN SQLSTATE = 'P0099' THEN SQLERRM::json "
                "ELSE json_build_object('refused', SQLSTATE || ': ' || SQLERRM) END; END; END $f$;"
            )
        lines.append(  # and the links on an object: 'ok' and each one's relation:id, or the refusal
            "CREATE OR REPLACE FUNCTION difftest_app.try_list_links(t text, i text) RETURNS text "
            "LANGUAGE plpgsql AS $f$ BEGIN "
            "RETURN 'ok ' || coalesce((SELECT string_agg(l.relation || ':' || l.id, ',') FROM authz.list_links(t, i) l), ''); "
            "EXCEPTION WHEN OTHERS THEN RETURN SQLSTATE || ': ' || SQLERRM; END $f$;"
        )
        return lines

    def shareable(
        self, subject: str = "user", conditions: bool = False
    ) -> dict[tuple[str, str], tuple[str, list[str], str | None]]:
        """The relations a subject (a user, or a link) may be shared: (type, relation) -> (the permission sharing it
        needs, the permissions it feeds into, which the sharer must hold too, as the compiled catalog says; and the
        relation's `shared if` for that subject, as the policy says). Without conditions, those with a `shared if`
        are left out."""
        conds = {
            (t.name, r.name): src.shared_if
            for t in self.types.values()
            for r in t.relations.values()
            for src in r.sources
            if src.kind == "shared" and (subject, None) in src.subjects
        }
        out: dict[tuple[str, str], tuple[str, list[str], str | None]] = {}
        for row in self.db.rows(
            "SELECT object_type || '|' || relation || '|' || shared_by || '|' || array_to_string(required, ',') "
            f"FROM authz_int.shared_relations WHERE subject = {lit(subject)}"
        ):
            tname, rname, by, required = row[0].split("|")
            if (tname, rname) in conds and (conditions or not conds[(tname, rname)]):
                out[(tname, rname)] = (by, [p for p in required.split(",") if p], conds[(tname, rname)])
        return out

    def expected_rule(self, state: evaluate.State, table: str, command: str) -> set[str]:
        t = self.ref.type_of_table(table)
        rule = next((r for r in self.rules if r.table == table and r.command == command and not r.columns), None)
        if not rule:
            raise LookupError(f"{table}: no {command} rule")
        return self.ref.eval_expr(state, t, rule.expr) & self.ref.ids(t) & self.ref.valid(t)

    def share_verdict(
        self,
        state: evaluate.State,
        signed_in: bool,
        t: Type,
        i: str,
        by: str,
        required: list[str],
        to_user: bool,
        target: str | None = None,
    ) -> str:
        """How authz.share answers, from what the reference says the sharer holds on row i of t: in the order its
        guards go (nobody signed in, or nothing to share there: the answer a missing object gets; no such user; the
        permission the relation is shared by; a permission it feeds into), or 'ok'."""

        def holds(p: str) -> bool:
            return p in t.perms and i in state[(t.name, p)] & self.ref.ids(t)

        if not signed_in or not any(holds(p) for p in self.share_perms.get(t.name, {"share"})):
            return "42501: you cannot share"
        if to_user and (target or self.share_target) not in self.ref.ids(self.types["user"]):
            return "P0001: there is no"
        if not holds(by):
            return f"42501: you cannot share {t.name} {i} (needs {by})"
        if not all(holds(p) for p in required):
            return "42501: you cannot grant"
        return "ok"

    def role_problems(self, snap: Snapshot, u: str, state: evaluate.State, signed_in: bool) -> list[str]:
        """The custom roles API as u, a user or a service, tried it (when it was their turn): making, changing and
        deleting a role needs a user signed in who holds manage_roles on its owner (by the reference); then what the
        policy alone says, in the guards' order (whose roles count on the type, what a role there may give).
        roles_of: the owner's roles, to whoever manages it or may view it. These are for users: a service signed
        in is told so first (AZ715), whatever the policy gives it."""
        problems: list[str] = []
        user_in = signed_in and evaluate.principal_of(u, self.types)[0] == "user"
        who = self.ref.principal

        def users_only(call: str) -> str | None:
            if who is None or who[0] == "user":
                return None
            return f"42501: authz.{call} is for users, not services ({who[0]} {who[1]} is signed in)"

        def holds(owner: str, i: str, perm: str) -> bool:
            t = self.types[owner]
            return user_in and perm in t.perms and i in state[(owner, perm)] & self.ref.ids(t)

        def cannot_grant(tname: str, perms: list[str]) -> str:
            roles = self.types[tname].roles
            bad = [p for p in perms if not roles or p not in roles[1]]
            return f"P0001: custom roles on {tname} cannot grant {', '.join(bad)}" if bad else ""

        for owner in self.role_owners:
            for tname, perms in self.role_perms.items():
                from_type = evaluate.role_owner_type(self.types[tname])
                for i, got in snap.get((u, "create_role", tname, owner), []):
                    service = users_only("create_role")
                    if service:
                        want = service
                    elif not holds(owner, i, "manage_roles"):
                        want = f"42501: you cannot manage roles of {owner} {i}"
                    elif from_type and from_type != owner:
                        want = (
                            f"P0001: custom roles on {tname} belong to a {from_type} (the policy says where they come "
                            f"from), not to a {owner}"
                        )
                    else:
                        want = cannot_grant(tname, perms) or "ok"
                    if got != want:
                        problems.append(
                            f"user {u}: authz.create_role('{owner}', {i}, '{tname}', {perms}) says {got!r}, "
                            f"expected {want!r}"
                        )
            for i, got in snap.get((u, "roles_of", owner), []):
                service = users_only("roles_of")
                if service:
                    want = service
                elif holds(owner, i, "manage_roles") or holds(owner, i, "view"):
                    mine = [rid for rid, (o, oid, _) in self.roles_now.items() if o == owner and oid == i]
                    want = "ok " + ",".join(sorted(mine, key=int))
                else:
                    want = f"42501: you cannot see roles of {owner} {i}"
                if got != want:
                    problems.append(f"user {u}: authz.roles_of('{owner}', {i}) says {got!r}, expected {want!r}")
        for rid in [*self.roles_now, MISSING_ROLE]:
            got = snap.get((u, "role", rid))
            if got is None:
                continue
            cannot = f"42501: you cannot manage role {rid}"
            role = self.roles_now.get(rid)
            service = users_only("set_role_permissions")
            if service:
                want = [service, users_only("delete_role") or ""]
            elif role is None or not holds(role[0], role[1], "manage_roles"):
                want = [cannot, cannot]
            else:
                want = [cannot_grant(role[2], self.role_perms.get(role[2], [])) or "ok", "ok"]
            if got != want:
                problems.append(
                    f"user {u}: authz.set_role_permissions and delete_role of role {rid} ({role}) say {got}, "
                    f"expected {want}"
                )
        return problems

    def link_problems(self, snap: Snapshot, u: str, state: evaluate.State, signed_in: bool) -> list[str]:
        """The links API as u, a user or a service, tried it (when it was their turn), by the reference: whoever
        holds share on the object sees all its links (signed in or not); otherwise the links of the relations they
        may manage (signed in, holding the permission a relation is shared by), and none at all is a refusal.
        Turning one off: among those, each link with that id must be one they could unshare; an id none has is no
        link."""
        problems: list[str] = []
        for (tname, i), links in self.links_now.items():
            got = snap.get((u, "links", tname, i))
            if got is None:
                continue
            t = self.types[tname]
            held = {p for p in t.perms if i in state[(tname, p)] & self.ref.ids(t)}
            manageable = {r for (o, r), by in self.link_by.items() if o == tname and signed_in and by in held}
            visible: set[str] | None = {r for r, _ in links} if "share" in held else (manageable or None)
            if visible is None:
                want = [f"42501: you cannot see the links of {tname} {i}"]
                want += [f"42501: you cannot turn off the links of {tname} {i}"] * len(link_ids(links))
            else:
                listed = ",".join(sorted(f"{r}:{lid}" for r, lid in links if r in visible))
                want = [f"ok {listed}"]
                for lid in link_ids(links):
                    rows = [r for r, x in links if x == lid and r in visible]
                    if not rows:
                        want.append(f"P0001: no link {lid} on {tname} {i}")
                    elif not all(r in manageable for r in rows):
                        want.append(f"42501: you cannot turn off link {lid} of {tname} {i} (you could not unshare it)")
                    else:
                        want.append("ok")
            # the list's order is the database's (its collation): compared as a set
            if got[0].startswith("ok "):
                got = [f"ok {','.join(sorted(x for x in got[0][3:].split(',') if x))}", *got[1:]]
            if got != want:
                problems.append(f"user {u}: authz.list_links and revoke_link on {tname} {i} say {got}, expected {want}")
        return problems

    def list_share_problems(self, snap: Snapshot, u: str, state: evaluate.State) -> list[str]:
        """authz.list_shares as u tried it (when it was their turn): every share on the object, a link's id hidden,
        to whoever holds share there by the reference, signed in or not; refused to anyone else."""
        problems: list[str] = []
        for tname in self.inspected:
            t = self.types[tname]
            for i, got in snap.get((u, "list_shares", tname), []):
                if i in state[(tname, "share")] & self.ref.ids(t):
                    want: Answer = {"ok": sorted(self.shares_now.get((tname, i), []))}
                    got = {"ok": sorted(got["ok"])} if "ok" in got else got  # (the order is the database's)
                else:
                    want = {"refused": f"42501: you cannot see the shares of {tname} {i}"}
                if got != want:
                    problems.append(f"user {u}: authz.list_shares('{tname}', {i}) says {got}, expected {want}")
        return problems

    def workflow_setup(self, sharer: str, sample: dict[str, list[str]]) -> None:
        """What requests, breaking the glass and reviews are tried on, as the owner reads and makes it: the catalog
        of what may be shared with whom (with the permission that shares it), the custom roles' types, and the
        shares of the users below. The requests are made again for each snapshot, pending: by the user shared with,
        the one whose turn it is and another user, on the sample rows, for two of the relations the share tries
        try (in turn), with a duration or without, in turn, and one more on a row no table has."""
        self.requests_tried, self.glass_tried, self.requesters = [], [], []
        self.requests: dict[int, tuple[str, str, str, str, bool]] = {}
        if not self.workflows:
            return
        self.catalog: dict[tuple[str, str, str], str] = {
            (tname, rname, subject): by
            for tname, rname, subject, by in self.db.rows(
                "SELECT object_type, relation, subject, shared_by FROM authz_int.shared_relations"
            )
        }
        self.role_types: dict[str, str] = {
            row[0]: row[1] for row in self.db.rows("SELECT id::text, object_type FROM authz.roles")
        }
        self.review_undecided = self.checks % 2 == 0  # closing a review revokes what nobody decided, or keeps it
        # what is asked for and broken into: the relations shared with a user, and up to two that aren't
        others = [
            (t.name, r) for t in self.types.values() for r in t.relations if (t.name, r, "user") not in self.catalog
        ]
        self.requests_tried = [*self.shares_tried, *others[:2]]
        self.glass_tried = [(tn, rn) for tn, rn in self.requests_tried if "break_glass" in self.types[tn].perms]
        # who asks: the user shared with, the one whose turn it is, and another user than them, in turn
        users = [x for x in self.users if signs_in_as_user(x, self.types)]
        askers = [x for x in users if x != sharer]
        other = [askers[self.checks % len(askers)]] if askers else []
        self.requesters = list(dict.fromkeys(x for x in (self.share_target, sharer, *other) if x in users))
        # on two of those relations in each snapshot, in turn
        asked = list(self.shares_tried)
        asked = [asked[(self.checks * 2 + k) % len(asked)] for k in range(min(2, len(asked)))] if asked else []
        made = [(tname, i, rname, who) for tname, rname in asked for i in sample[tname] for who in self.requesters]
        if made and other:
            made.append((made[0][0], MISSING_ROW, made[0][2], other[0]))
        lasting = ("interval '3 days'", "NULL")
        values = ", ".join(
            f"({lit(tname)}, {lit(i)}, {lit(rname)}, {lit(who)}, 'difftest', {lasting[n % 2]})"
            for n, (tname, i, rname, who) in enumerate(made)
        )
        insert = (
            "INSERT INTO authz.requests (object_type, object_id, relation, requester, reason, duration) "
            f"VALUES {values} RETURNING id, object_type, object_id, relation, requester, (duration IS NOT NULL)::text"
        )
        self.requests = {
            int(n): (tname, i, rname, who, dur == "true")
            for n, tname, i, rname, who, dur in self.db.rows(
                "DELETE FROM authz.requests WHERE reason = 'difftest';" + (f"\n{insert};" if made else "")
            )
        }
        # each of those users' shares of a relation (as a user, not as one of a group's): whether it lets them in
        # now and for the next hour (breaking the glass leaves such a one as it is, and changes any other)
        shared = ", ".join(lit(x) for x in self.requesters) or "NULL"
        self.user_shares: dict[tuple[str, str, str, str], bool] = {
            (tname, i, rname, sid): lets == "true"
            for tname, i, rname, sid, lets in self.db.rows(
                "SELECT object_type, object_id, relation, subject_id, (caveat IS NULL AND (starts_at IS NULL OR "
                "starts_at <= now()) AND (expires_at IS NULL OR expires_at >= now() + interval '1 hour'))::text "
                f"FROM authz.shares WHERE subject_type = 'user' AND subject_relation = '' AND subject_id IN ({shared})"
            )
        }

    def workflow_problems(self, snap: Snapshot, u: str, state: evaluate.State) -> list[str]:
        """Requests, breaking the glass and reviews as u tried them (when it was their turn), each undone: what
        each call says, what it leaves (the requests shown, a share that lets them in, a review's items, what its
        close revokes) and the audit trail it writes, from the policy and what the reference says u holds. All are
        for users: a service is told so first (AZ715). Deciding a request, or an item of a review, needs the
        permission that shares the relation (the one unsharing it needs), and approving one is a share, as
        authz.share judges it; breaking the glass needs `break_glass`, and starting a review `share`."""
        if (u, "pending") not in snap:
            return []
        problems: list[str] = []
        who = self.ref.principal
        uid = who[1] if who is not None and who[0] == "user" else None
        kind, pid = evaluate.principal_of(u, self.types)
        actor = pid if kind == "user" else f"{kind}:{pid}"  # (who acted, as the trail names them: 42, bot:2)
        service = who is not None and who[0] != "user"

        def users_only(call: str) -> str:
            return f"42501: authz.{call} is for users, not services ({who[0]} {who[1]} is signed in)" if who else ""

        def holds(t: Type, i: str, p: str) -> bool:
            return p in t.perms and i in state[(t.name, p)] & self.ref.ids(t)

        def may_manage(t: Type, i: str, rname: str, subject: str) -> bool:
            if rname.startswith("role:"):  # a custom role of the type: shared by `share`
                by = "share" if self.role_types.get(rname.removeprefix("role:")) == t.name else None
            else:
                by = self.catalog.get((t.name, rname, subject))
            return uid is not None and by is not None and holds(t, i, by)

        def judge(call: str, got: Answer, want: str | dict[str, Answer]) -> None:
            """want: the refusal's start, or what the call leaves (its trail in any order)."""
            if isinstance(want, str):
                bad = not isinstance(got, dict) or not str(got.get("refused", "")).startswith(want)
            else:
                trail = sorted(json.dumps(x) for x in want["trail"])
                bad = (
                    not isinstance(got, dict)
                    or "refused" in got
                    or {**got, "trail": sorted(json.dumps(x) for x in got.get("trail", []))} != {**want, "trail": trail}
                )
            if bad:
                problems.append(f"user {u}: {call} says {got}, expected {want}")

        def entry(action: str, t: str, i: str, rname: str | None = None, subject: str | None = None) -> list[Answer]:
            """A line of the trail: a user subject's share, or the call's own line (subject: the user it names)."""
            return [action, t, i, rname, *(("user", subject, "") if subject else (None, None, None)), actor, None]

        for tname, rname in self.requests_tried:
            t = self.types[tname]
            for i, got in snap.get((u, "request", tname, rname), []):
                by = self.catalog.get((tname, rname, "user"))
                if service:
                    want: str | dict[str, Answer] = users_only("request_access")
                elif uid is None:
                    want = "42501: sign in first"
                elif by is None or by not in t.perms:
                    want = f"P0001: the policy does not allow sharing {tname}.{rname} with a user"
                else:
                    want = {"trail": [entry("request_access", tname, i, rname, uid)]}
                judge(f"authz.request_access('{tname}', {i}, '{rname}')", got, want)
        for n, (tname, i, rname, requester, lasts) in self.requests.items():
            if (u, "decide", str(n)) not in snap:
                continue
            t = self.types[tname]
            approved, denied, cancelled = snap[(u, "decide", str(n))]
            if service:
                approve: str | dict[str, Answer] = users_only("decide_request")
                deny: str | dict[str, Answer] = approve
            elif uid is None:
                approve = deny = "42501: sign in to decide a request"
            elif requester == uid:
                approve = deny = "42501: you cannot decide your own request"
            elif not may_manage(t, i, rname, "user"):
                approve = deny = f"42501: you cannot decide request {n}"
            else:
                by, required, cond = self.shares_tried[(tname, rname)]
                verdict = self.share_verdict(state, True, t, i, by, required, to_user=True, target=requester)
                asked = (u, "share if", tname, rname, *([] if requester == self.share_target else [requester]))
                if verdict == "ok" and cond and i not in snap.get(asked, []):
                    verdict = "42501: the policy does not allow this share"
                made = "share_changed" if (tname, i, rname, requester) in self.user_shares else "share"
                share = entry(made, tname, i, rname, requester)
                share[-1] = lasts
                approve = (
                    verdict
                    if verdict != "ok"
                    else {"trail": [share, entry("approve_request", tname, i, rname, requester)]}
                )
                deny = {"trail": [entry("deny_request", tname, i, rname, requester)]}
            if service:
                cancel: str | dict[str, Answer] = users_only("cancel_request")
            elif uid is not None and requester == uid:
                cancel = {"trail": [entry("cancel_request", tname, i, rname, requester)]}
            else:
                cancel = f"P0001: no pending request {n} of yours"
            judge(f"authz.decide_request({n}, true) of {requester}'s on {tname} {i}", approved, approve)
            judge(f"authz.decide_request({n}, false) of {requester}'s on {tname} {i}", denied, deny)
            judge(f"authz.cancel_request({n}) of {requester}'s", cancelled, cancel)
        # the requests shown: their own, and those they may decide
        shown = sorted(
            n
            for n, (tname, i, rname, requester, _) in self.requests.items()
            if uid is not None and (requester == uid or may_manage(self.types[tname], i, rname, "user"))
        )
        judge(
            "authz.pending_requests()",
            snap[(u, "pending")],
            users_only("pending_requests") if service else {"ids": shown, "trail": []},
        )
        for tname, rname in self.glass_tried:
            t = self.types[tname]
            for i, got in snap.get((u, "break_glass", tname, rname), []):
                if service:
                    want = users_only("break_glass")
                elif uid is None or not holds(t, i, "break_glass"):
                    want = f"42501: you cannot break the glass on {tname} {i}"
                elif (tname, rname, "user") not in self.catalog:
                    want = f"P0001: the policy does not allow sharing {tname}.{rname} with a user"
                else:
                    lets = self.user_shares.get((tname, i, rname, uid))
                    share = entry("share" if lets is None else "share_changed", tname, i, rname, uid)
                    share[-1] = True
                    want = {
                        "lets_in": True,
                        "trail": [*([] if lets else [share]), entry("break_glass", tname, i, rname, uid)],
                    }
                judge(f"authz.break_glass('{tname}', {i}, '{rname}')", got, want)
        for tname in self.inspected:
            t = self.types[tname]
            for i, got in snap.get((u, "review", tname), []):
                if service:
                    judge(f"authz.start_review('{tname}', {i})", got, users_only("start_review"))
                    continue
                if not holds(t, i, "share"):
                    judge(f"authz.start_review('{tname}', {i})", got, f"42501: you cannot review {tname} {i}")
                    continue
                items = got.get("items", []) if isinstance(got, dict) else []
                if sorted(x[1:] for x in items) != sorted(self.shares_now.get((tname, i), [])):
                    problems.append(
                        f"user {u}: the review of {tname} {i} has the items {items}, expected the shares on it: "
                        f"{sorted(self.shares_now.get((tname, i), []))}"
                    )
                # each item decided in turn (revoked, kept, left), by someone who may unshare it; closing revokes
                # what was marked, and what nobody decided if asked, where the one closing may unshare it
                decided: list[Answer] = []
                trail = [entry("start_review", tname, i), entry("close_review", tname, i)]
                for k, rname, st, sid, sr in items:
                    ok = may_manage(t, i, rname, subject_key(st, sid, sr))
                    if k % 3:
                        decided.append([k, "ok" if ok else f"42501: you cannot decide on {rname} in review"])
                    if ok and (k % 3 == 1 or (self.review_undecided and k % 3 == 0)):
                        trail.append(["unshare", tname, i, rname, st, sid, sr, actor, None])
                said = got.get("decided", []) if isinstance(got, dict) else []
                if len(said) != len(decided) or any(
                    g[0] != w[0] or not str(g[1]).startswith(w[1]) or (w[1] == "ok") != (g[1] == "ok")
                    for g, w in zip(said, decided, strict=False)
                ):
                    problems.append(
                        f"user {u}: in the review of {tname} {i}, the decisions say {said}, expected {decided}"
                    )
                judge(
                    f"authz.close_review of {tname} {i} (undecided {'revoked' if self.review_undecided else 'kept'})",
                    got,
                    {"items": items, "decided": said, "revoked": len(trail) - 2, "trail": trail},
                )
        return problems

    def rule_allows(self, state: evaluate.State, table: str, cmd: str, i: str) -> bool:
        """What authz.explain_rule's first line says of cmd on row i as it is, asked without the changes: whether
        its rule lets it through (an update by the update rule alone: the call explains an update that matched no
        rows; one that an `update after` rule refuses raises, with its own words)."""
        has = {r.command for r in self.rules if r.table == table and not r.columns}
        return cmd in has and i in self.expected_rule(state, table, cmd)

    def visible(self, state: evaluate.State, t: Type, i: str) -> bool:
        """Whether the user may select row i of t, as explain asks (authz_int.visible): by the table's select rule;
        a table without rules is readable (its where aside); one with rules but no select rule, by nobody."""
        rules = [r for r in self.rules if r.table == t.table]
        if not rules:
            return i in self.ref.ids(t) & self.ref.valid(t)
        if not any(r.command == "select" and not r.columns for r in rules):
            return False
        return i in self.expected_rule(state, t.table, "select")

    def links_of(self, u: str) -> set[str]:
        tokens = [x.strip() for x in self.context(u).get("links", "").split(",") if x.strip()]
        return {hashlib.sha256(x.encode()).hexdigest() for x in tokens}

    def sync_problems(self, snap: Snapshot) -> list[str]:
        """The sync index: for every principal signed in (a row of its type, passing its where), the rows of each
        synced table its keys read are those the reference says it holds the synced permission (or the table's select
        rule) on, without shares that have a caveat and without links. And it matches a rebuild."""
        if not self.pol.syncs:
            return []
        problems = [] if snap[("sync verify",)] is True else ["authz.sync_verify() is false: the sync index is stale"]
        theirs: dict[tuple[object, ...], Answer] = {tuple(k[1:]): v for k, v in snap.items() if k[0] == "sync data"}
        for u in self.users:
            if not u:
                continue
            raw: dict[tuple[object, ...], Answer] = {
                tuple(k[2:]): v for k, v in snap.items() if k[0] == u and k[1] == "data"
            }
            raw.update(theirs)
            state = self.sync_ref.evaluate(evaluate.Data.of(raw), u, set())
            if self.sync_ref.principal is None:
                continue  # nobody: an id no row has, or failing the type's where, holds no keys
            for table, line in self.pol.syncs.items():
                t = self.ref.type_of_table(table)
                if line.perm is None:
                    want = self.sync_ref.eval_expr(
                        state,
                        t,
                        next(
                            r.expr for r in self.rules if r.table == table and r.command == "select" and not r.columns
                        ),
                    )
                else:
                    want = state[(t.name, line.perm)]
                want = want & self.sync_ref.ids(t) & self.sync_ref.valid(t)
                got = set(snap[(u, "sync", t.name)])
                if got != want:
                    problems.append(
                        f"the sync index: {u} reads {sorted(got - want)} of {table} it may not "
                        f"({line.perm or 'select'}), and not {sorted(want - got)} it may"
                    )
        return problems[:12]

    def check(self) -> list[str]:
        self._nocontext = self._nocontext_all = None
        start = self.feed_position()
        snap = self.snapshot()
        problems: list[str] = []
        if snap[("verify",)] is not True:
            problems.append("authz.verify() is false: a closure table is stale")
        problems += self.sync_problems(snap)
        holders: dict[tuple[str, str, str], set[str]] = {}
        among: dict[tuple[str, str, str], set[str]] = {}  # every user id signed in, a row or not (who_among)
        if self.decisions is not None:
            self.decisions.snapshots += 1
        held: dict[tuple[str, str, str], frozenset[str]] = {}  # what each user holds, for the change feed
        signed: dict[str, bool] = {}
        for u in self.users:
            data = evaluate.Data.of({tuple(k[2:]): v for k, v in snap.items() if k[0] == u and k[1] == "data"})
            state = self.ref.evaluate(data, u, self.links_of(u))
            signed[u] = self.ref.principal is not None
            for t in self.types.values():
                for p in t.perms:
                    held[(u, t.name, p)] = state[(t.name, p)] & self.ref.ids(t)
            if self.decisions is not None:
                # (the shares that don't count, by why: what --decisions asks besides)
                shares: dict[tuple[str | int, ...], Answer] = {
                    tuple(k[2:]): v for k, v in snap.items() if k[0] == u and k[1] == "decisions"
                }
                scope = self.scoped[1] if u == self.scoped[0] else ""
                self.decisions.observe(data, u, self.links_of(u), shares, scope)
            for t in self.types.values():
                for p in t.perms:
                    for i in state[(t.name, p)] & self.ref.ids(t):
                        if self.listed(u):
                            holders.setdefault((t.name, p, i), set()).add(u)
                        if signs_in_as_user(u, self.types):
                            among.setdefault((t.name, p, i), set()).add(u)
                    for i, line in snap[(u, "explain", t.name, p)]:
                        want = i in state[(t.name, p)] & self.ref.ids(t)
                        if not line or line.startswith("yes") != want:
                            problems.append(
                                f"user {u}: authz.explain('{t.name}', {i}, '{p}') says "
                                f"{line!r}, expected {'yes' if want else 'no'}"
                            )
                    # asked by the user themselves: the same, but nothing about a row they can't see (unless they
                    # may share it, and so inspect it)
                    for key in ("explain self", "explain self by id"):
                        for i, line in snap.get((u, key, t.name, p), []):
                            inspects = "share" in t.perms and i in state[(t.name, "share")] & self.ref.ids(t)
                            if key == "explain self by id" and self.ref.principal is None:
                                # signed in as nobody (their row isn't there): the id is another user's, explained
                                # only to one who may inspect the object
                                if not inspects and line != f"42501: you cannot inspect access to {t.name} {i}":
                                    problems.append(
                                        f"user {u}: authz.explain('{t.name}', {i}, '{p}') by an id that signs in as "
                                        f"nobody says {line!r}, expected the refusal to inspect another's access"
                                    )
                                holds = i in state[(t.name, p)] & self.ref.ids(t)
                                if inspects and (not line or line.startswith("yes") != holds):
                                    problems.append(
                                        f"user {u}: authz.explain('{t.name}', {i}, '{p}') by an id that signs in as "
                                        f"nobody says {line!r}, expected {'yes' if holds else 'no'}"
                                    )
                                continue
                            seen = self.visible(state, t, i) or inspects
                            want = i in state[(t.name, p)] & self.ref.ids(t) and seen
                            if not line or line.startswith("yes") != want:
                                problems.append(
                                    f"user {u}: authz.explain('{t.name}', {i}, '{p}') {key} says "
                                    f"{line!r}, expected {'yes' if want else 'no'}"
                                )
                            elif not seen and line != f"no   you have no access to {t.name} {i}":
                                problems.append(
                                    f"user {u}: authz.explain('{t.name}', {i}, '{p}') {key} says {line!r} of a "
                                    "row they can't see, not what it says of a missing one"
                                )
            # authz.share as the user: through exactly where the reference says they hold what sharing it needs,
            # refused otherwise, in the order the guards go (nobody signed in or nothing to share there, no such
            # user, the permission sharing needs, one it gives). An id the user table doesn't have signs in as
            # nobody, who shares nothing, though a condition alone may give them a permission.
            signed_in = self.ref.principal is not None
            for (tname, rname), (by, required, cond) in self.shares_tried.items():
                t = self.types[tname]
                for i, got in snap.get((u, "share", tname, rname), []):
                    want = self.share_verdict(state, signed_in, t, i, by, required, to_user=True)
                    # last, the relation's `shared if`, on the share as it would be made (evaluated beside the data)
                    if want == "ok" and cond and i not in snap.get((u, "share if", tname, rname), []):
                        want = "42501: the policy does not allow this share"
                    if not str(got).startswith(want) or (want == "42501: you cannot share" and "(needs" in str(got)):
                        problems.append(
                            f"user {u}: authz.share('{tname}', {i}, '{rname}', user {self.share_target}) says "
                            f"{got!r}, expected {want!r}"
                        )
                # unsharing needs the permission the relation is shared by, if the type has it, and someone signed
                # in; what it says comes from the policy alone (the same words for a hidden object and a missing one)
                for i, got in snap.get((u, "unshare", tname, rname), []):
                    cannot = f"42501: you cannot unshare {rname} on {tname} {i}"
                    if by not in t.perms:
                        want = cannot
                    elif not signed_in or i not in state[(tname, by)] & self.ref.ids(t):
                        want = f"{cannot} (needs {by})"
                    else:
                        want = "ok"
                    if str(got) != want:
                        problems.append(
                            f"user {u}: authz.unshare('{tname}', {i}, '{rname}', user {self.share_target}) says "
                            f"{got!r}, expected {want!r}"
                        )
            # create_link: the same rule, for a link (no one to look up)
            for (tname, rname), (by, required, _) in self.links_tried.items():
                t = self.types[tname]
                for i, got in snap.get((u, "create_link", tname, rname), []):
                    want = self.share_verdict(state, signed_in, t, i, by, required, to_user=False)
                    if not str(got).startswith(want) or (want == "42501: you cannot share" and "(needs" in str(got)):
                        problems.append(
                            f"user {u}: authz.create_link('{tname}', {i}, '{rname}') says {got!r}, expected {want!r}"
                        )
            problems += self.role_problems(snap, u, state, signed_in)
            problems += self.link_problems(snap, u, state, signed_in)
            problems += self.list_share_problems(snap, u, state)
            problems += self.workflow_problems(snap, u, state)
            # perms_of: the public permissions held on each object, no more (a type without any: none)
            for t in self.types.values():
                public = [p for p, x in t.perms.items() if not x.hidden]
                for i, got in snap.get((u, "perms_of", t.name), []):
                    want = sorted(p for p in public if i in state[(t.name, p)] & self.ref.ids(t))
                    if sorted(got or []) != want:
                        problems.append(f"user {u}: authz.perms_of('{t.name}', [{i}]) says {got}, expected {want}")
            # explain_rule as the app asks it: nothing about a row the user can't see; on one they see, yes exactly
            # where the rules let the command through
            for table in dict.fromkeys(r.table for r in self.rules):
                t = self.ref.type_of_table(table)
                for cmd in ("update", "delete"):
                    for i, line in snap.get((u, "explain_rule", table, cmd), []):
                        seen = self.visible(state, t, i)
                        want = ("yes" if self.rule_allows(state, table, cmd, i) else "no") if seen else None
                        got = None if line is None else "yes" if line.startswith("yes") else "no"
                        if got != want:
                            problems.append(
                                f"user {u}: authz.explain_rule('{table}', '{cmd}', {i}) says {line!r}, "
                                f"expected {want or 'nothing (a row they can not see)'}"
                            )
            for t in self.types.values():
                ids = self.ref.ids(t)
                for p in t.perms:
                    want = state[(t.name, p)] & ids
                    got = set(snap[(u, "list", t.name, p)])
                    if got != want:
                        problems.append(
                            f"user {u}: authz.list('{t.name}', '{p}') "
                            f"extra {sorted(got - want)} missing {sorted(want - got)}"
                        )
                    pages = snap.get((u, "pages", t.name, p))
                    if pages is not None and pages[0] != pages[1]:
                        problems.append(
                            f"user {u}: authz.list('{t.name}', '{p}') in pages of {PAGE} gives {pages[0]}, "
                            f"in key order (as the database orders it) {pages[1]}"
                        )
                    for i, ok in snap[(u, "can", t.name, p)]:
                        if bool(ok) != (i in want):
                            problems.append(f"user {u}: authz.can('{t.name}', {i}, '{p}') = {ok}, expected {i in want}")
                    problems += asked_of_every_row(
                        f"user {u}", t.name, p, snap[(u, "can", t.name, p)], ids, MISSING_ROW
                    )
            for table in dict.fromkeys(r.table for r in self.rules if r.command == "select"):
                want = self.expected_rule(state, table, "select")
                got = set(snap[(u, "rls", table)])
                if got != want:
                    problems.append(
                        f"user {u}: SELECT from {table} extra {sorted(got - want)} missing {sorted(want - got)}"
                    )
            for table in self.pol.views:
                want = self.expected_rule(state, table, "select")
                got = set(snap[(u, "view", table)])
                if got != want:
                    problems.append(
                        f"user {u}: the view of {table} extra {sorted(got - want)} missing {sorted(want - got)}"
                    )
                t = self.ref.type_of_table(table)
                for r in self.rules:
                    if r.table == table and r.command == "mask":
                        shown = want & self.ref.eval_expr(state, t, r.expr)
                        for c in r.columns:
                            got = set(snap[(u, "mask", table, c)])
                            if got != shown:
                                problems.append(
                                    f"user {u}: {table}.{c} shown in the view: extra {sorted(got - shown)} "
                                    f"missing {sorted(shown - got)}"
                                )
            for table, name, qual, check in self.policies:
                command = name[len("authz_") :]
                for part, expr in (("using", qual), ("check", check)):
                    if not expr:
                        continue
                    # an update's check is its 'after' rule if it has one, otherwise the update rule again
                    after = any(r.table == table and r.command == "update after" and not r.columns for r in self.rules)
                    cmd = "update after" if command == "update" and part == "check" and after else command
                    want = self.expected_rule(state, table, cmd)
                    got = set(snap[(u, "policy", table, name, part)])
                    if got != want:
                        problems.append(
                            f"user {u}: policy {name} ({part}) on {table} "
                            f"extra {sorted(got - want)} missing {sorted(want - got)}"
                        )
                    if self.as_app(table):
                        mine = want & self.expected_rule(state, table, "select")
                        got = set(snap[(u, "policy as app", table, name, part)])
                        if got != mine:
                            problems.append(
                                f"user {u}: policy {name} ({part}) on {table}, as the app role "
                                f"extra {sorted(got - mine)} missing {sorted(mine - got)}"
                            )
            for n, (r, _) in enumerate(self.column_rules):
                t = self.ref.type_of_table(r.table)
                want = self.ref.eval_expr(state, t, r.expr) & self.ref.ids(t) & self.ref.valid(t)
                got = set(snap[(u, "column", str(n))])
                if got != want:
                    problems.append(
                        f"user {u}: the rule on {', '.join(r.columns)} of {r.table} ({r.src}) "
                        f"extra {sorted(got - want)} missing {sorted(want - got)}"
                    )
                if self.as_app(r.table):
                    mine = want & self.expected_rule(state, r.table, "select")
                    got = set(snap[(u, "column as app", str(n))])
                    if got != mine:
                        problems.append(
                            f"user {u}: the rule on {', '.join(r.columns)} of {r.table} ({r.src}), as the "
                            f"app role extra {sorted(got - mine)} missing {sorted(mine - got)}"
                        )
            if u == self.scoped[0]:
                problems += self.check_scoped(snap, state)
        for t in self.types.values():
            for p in t.perms:
                for i, got in snap[("who", t.name, p)]:
                    # who() lists users; context-dependent shares (caveats, links) are judged
                    # in the administrator's context, where no link or context is set
                    want = (
                        set(holders.get((t.name, p, i), set()))
                        if not self.has_context()
                        else self.who_reference(t, p, i)
                    )
                    if set(got) != want:
                        problems.append(
                            f"authz.who('{t.name}', {i}, '{p}') extra {sorted(set(got) - want)} "
                            f"missing {sorted(want - set(got))}"
                        )
                # authz.who_among, asked as an administrator too: each id signed in in turn, so one the user table
                # doesn't have holds what nobody holds
                for i, got in snap.get(("who_among", t.name, p), []):
                    want = (
                        set(among.get((t.name, p, i), set()))
                        if not self.has_context()
                        else self.who_reference(t, p, i, everyone=True)
                    )
                    if set(got) != want:
                        problems.append(
                            f"authz.who_among('{t.name}', {i}, '{p}', every user) extra {sorted(set(got) - want)} "
                            f"missing {sorted(want - set(got))}"
                        )
        problems += self.feed_problems(start, held, signed)
        # (after this snapshot's own writes, tried and undone: the next change's entries are what follow)
        self.fed = (self.feed_position(), held, signed)
        return problems

    def check_scoped(self, snap: Snapshot, state: evaluate.State) -> list[str]:
        """The same user limited to a scope: what the scope names is as without it, the rest is refused."""
        u, scope = self.scoped
        who = f"user {u} with scope {scope}"
        problems: list[str] = []
        for t in self.types.values():
            for p in t.perms:
                want = state[(t.name, p)] & self.ref.ids(t) if self.scope_allows(scope, "perm", t.name, p) else set()
                got = set(snap[("scoped", "list", t.name, p)])
                if got != want:
                    problems.append(
                        f"{who}: authz.list('{t.name}', '{p}') extra {sorted(got - want)} missing {sorted(want - got)}"
                    )
                for i, ok in snap[("scoped", "can", t.name, p)]:
                    if bool(ok) != (i in want):
                        problems.append(f"{who}: authz.can('{t.name}', {i}, '{p}') = {ok}, expected {i in want}")
                problems += asked_of_every_row(who, t.name, p, snap[("scoped", "can", t.name, p)], self.ref.ids(t))
        for table, name, qual, check in self.policies:
            command = name[len("authz_") :]
            for part, expr in (("using", qual), ("check", check)):
                if not expr:
                    continue
                after = any(r.table == table and r.command == "update after" and not r.columns for r in self.rules)
                cmd = "update after" if command == "update" and part == "check" and after else command
                want = (
                    self.expected_rule(state, table, cmd) if self.scope_allows(scope, "cmd", table, command) else set()
                )
                got = set(snap[("scoped", "policy", table, name, part)])
                if got != want:
                    problems.append(
                        f"{who}: policy {name} ({part}) on {table} extra {sorted(got - want)} missing {sorted(want - got)}"
                    )
        return problems

    def has_context(self) -> bool:
        return any(self.context(u) for u in self.users)

    def listed(self, u: str) -> bool:
        """Whether authz.who can list u: it lists the user table's rows (also one failing the type's where, who
        holds what nobody holds), not other principals, and not an id signed in that the table doesn't have."""
        return bool(u) and evaluate.principal_of(u, self.types)[0] == "user" and u in self.ref.ids(self.types["user"])

    def who_reference(self, t: Type, p: str, i: str, everyone: bool = False) -> set[str]:
        """Holders of p on i when evaluated without any request context (what who() sees): the users it lists, or
        everyone: every user id signed in, a row of the user table or not (what who_among sees)."""
        if self._nocontext is None or self._nocontext_all is None:
            snap = self.snapshot_data_only()  # sets no context
            out: dict[tuple[str, str, str], set[str]] = {}
            out_all: dict[tuple[str, str, str], set[str]] = {}
            for u in self.users:
                data = evaluate.Data.of({tuple(k[2:]): v for k, v in snap.items() if k[0] == u and k[1] == "data"})
                state = self.ref.evaluate(data, u, set())
                for tt in self.types.values():
                    for pp in tt.perms:
                        for ii in state[(tt.name, pp)] & self.ref.ids(tt):
                            if self.listed(u):
                                out.setdefault((tt.name, pp, ii), set()).add(u)
                            if signs_in_as_user(u, self.types):
                                out_all.setdefault((tt.name, pp, ii), set()).add(u)
            self._nocontext, self._nocontext_all = out, out_all
        return (self._nocontext_all if everyone else self._nocontext).get((t.name, p, i), set())

    def snapshot_data_only(self, context: bool = False, after: str = "") -> Snapshot:
        """The data each user's evaluation reads, without the request context (what who() and the invariants see),
        or with it: what the user's own session sees (around's writes). after: as it would be after these
        statements, which are undone."""
        lines: list[str] = ["BEGIN;", after] if after else []
        for u in self.users:
            kind, pid = evaluate.principal_of(u, self.types)
            lines.append(f"SET authz.user_id = {lit(pid)};")
            lines.append(f"SET authz.principal_type = {lit('' if kind == 'user' else kind)};")
            ctx = self.context(u) if context else {}
            lines += [f"SET authz_ctx.{k} = {lit(v)};" for k, v in ctx.items()]
            for key, sql in self.ref.data_queries():
                lines.append(f"SELECT {lit(json.dumps([u, 'data', *key]))}, ({sql});")
            lines += [f"RESET authz_ctx.{k};" for k in ctx]
        lines.append("RESET authz.user_id;")
        lines.append("RESET authz.principal_type;")
        lines += ["ROLLBACK;"] if after else []
        return {tuple(json.loads(k)): json.loads(v) for k, v in self.db.rows("\n".join(lines))}


# ----------------------------------------------------------------------
# Random data and changes
# ----------------------------------------------------------------------
class Gen:
    """A policy's test data: its schema, who signs in, and the SQL for the first data, the first shares and each
    random change."""

    policy: ClassVar[str]
    schema: ClassVar[str]
    users: ClassVar[list[str]]
    role: ClassVar[str] = "app_user"
    # rowstile's own refusals a random change may meet, by the code in their HINT: a move under itself (AZ713)
    refusals: ClassVar[tuple[str, ...]] = ("AZ713",)
    # a share's expires_at and starts_at: live, not started yet, expired, or live until tomorrow
    WHEN: ClassVar[list[tuple[str, str]]] = [("NULL", "NULL"), ("NULL", LATER), (EXPIRED, "NULL"), (LATER, "NULL")]

    def refused(self, err: str) -> bool:
        """Whether a change failed as random changes may (err: psql's, with VERBOSITY verbose; CHANGE): a key the
        change repeats, or a row it names that isn't there, raised by the change's own statement, or one of
        rowstile's refusals the generator expects. Not the same constraint raised inside rowstile's own functions
        (a trigger's): an app would meet that as a refused write it may make."""
        state = SQLSTATE.search(err)
        hint = ROWSTILE_HINT.search(err)
        if hint:
            return hint.group(1) in self.refusals
        return bool(state) and state.group(1) in KEY_ERRORS and not IN_ROWSTILE.search(err)

    def context(self, u: str) -> dict[str, str]:
        """The request context (authz_ctx.*) the user's session sets."""
        return {}

    def initial(self) -> str:
        raise NotImplementedError

    def grants(self) -> str:
        raise NotImplementedError

    def change(self, ids: Ids) -> str:
        """One random change, as SQL. ids: current ids by type."""
        raise NotImplementedError

    tokens: ClassVar[list[str]] = []  # the share links' tokens the users' contexts hold, if the policy has links

    def __init__(self, rnd: random.Random) -> None:
        self.r = rnd
        self.ledger: Decisions | None = None  # the decision ledger, whose parts steer() aims at
        self.aimed: Counter[tuple[str | int, ...]] = Counter()  # how often at each

    def steered(self, ids: Ids) -> str | None:
        """One change aimed at parts of the policy that have decided no answer yet, a few at once (AIMS; more
        while many are left), those aimed at least often first; None when there is none, or nothing to do for
        them. Shares that don't count change no answer, so several go together; of what moves the data about (a
        chain of links, a loop), one."""
        if self.ledger is None:
            return None
        wanting = self.ledger.wanting()
        self.r.shuffle(wanting)
        wanting.sort(key=lambda k: self.aimed[k])
        out: list[str] = []
        moved = aims = 0
        most = max(AIMS, len(wanting) // 8)
        for key in wanting:
            moves = key[0] not in ("share", "role share")
            if aims == most or (moves and moved):
                continue
            aims, moved = aims + 1, moved + moves
            self.aimed[key] += 1
            sql = self.steer(key, ids)
            if sql:
                out.append(sql)
        return "BEGIN;\n" + "\n".join(out) + "\nCOMMIT;" if out else None

    def alone(self, tname: str, rname: str, st: str = "user", sr: str = "") -> str | None:
        """A share of a relation, to that kind of subject, where it alone changes an answer."""
        sources = self.ledger.pol.types[tname].relations[rname].sources if self.ledger else []
        for i, src in enumerate(sources):
            if src.kind == "shared" and (st, sr or None) in src.subjects:
                return self.live(("share", "", tname, rname, i, st, sr))
        return None

    def live(self, key: tuple[str | int, ...]) -> str | None:
        """The share a share part's key names, one that counts, where it alone changes an answer (Decisions.gain)."""
        gain = self.ledger.gain(key, self.r) if self.ledger else None
        return self.share(key, gain, "NULL", "NULL") if gain else None

    def steer(self, key: tuple[str | int, ...], ids: Ids) -> str | None:
        """Statements aimed at a part of the policy that has decided no answer yet (the decision ledger's key), or
        None: here, a share in the state the part names (expired, not started), or a custom role given so, where
        the reference says it would change an answer had it counted (Decisions.gain); a generator may know more."""
        when = {"expired": (EXPIRED, "NULL"), "not started": ("NULL", LATER)}
        if self.ledger is None:
            return None
        if key[0] in ("depth", "loop"):  # a chain of links that deep, or a loop of them, the only way down
            plan = self.ledger.plan(key, self.r, lambda k, o, s: self.tie(k, o, s) is not None)
            if plan:
                return self.write(plan)
            idle = self.ledger.idle(key)  # nobody holds anything of it: first a share that gives someone some
            return self.live(self.r.choice(idle)) if idle else None
        if key[0] not in ("share", "role share") or key[1] not in when:
            return None
        gain = self.ledger.gain(key, self.r)
        return self.share(key, gain, *when[str(key[1])]) if gain else None

    # --- links, written as the policy's sources read them --------------------------------------------------
    # what a row of a link table holds besides its two ends, for the sources whose `where` reads it
    columns: ClassVar[dict[str, dict[str, str]]] = {}

    def write(self, plan: Plan) -> str | None:
        """A plan's links taken away and added, as SQL; None if one of them can't be written."""
        out = [self.untie(k, o) for k, o in plan.cut] + [self.tie(k, o, s) for k, o, s in plan.add]
        return None if None in out else "\n".join(x for x in out if x)

    def source(self, k: evaluate.PairsKey) -> tuple[Type, Source, Type]:
        """A source's type, the source, and the type of the subjects it links to."""
        assert self.ledger is not None
        types = self.ledger.pol.types
        return types[k[0]], types[k[0]].relations[k[1]].sources[k[2]], types[k[3]]

    def own(self, k: evaluate.PairsKey) -> bool:
        """Whether a table source is the subjects' own table: each subject's row names the object it is in."""
        _, src, st = self.source(k)
        return src.kind == "table" and src.table == st.table and cols(src.subj_col) == [c for c, _ in st.key]

    def tie(self, k: evaluate.PairsKey, o: str, s: str) -> str | None:
        """SQL that links object o to subject s through a source: a share, the object's columns, a row of a link
        table (or the subject's own row, when the table is the subjects'); None if the two can't be linked so: a
        column that is part of a key would change, or the table's rows count only under a `where` and `columns`
        doesn't say what passes it."""
        t, src, st = self.source(k)
        if src.kind == "shared":
            return (
                "INSERT INTO authz.shares (object_type, object_id, relation, subject_type, subject_id, "
                f"subject_relation) VALUES ({lit(k[0])}, {lit(o)}, {lit(k[1])}, {lit(k[3])}, {lit(s)}, {lit(k[4])}) "
                "ON CONFLICT (object_type, object_id, relation, subject_type, subject_id, subject_relation) "
                "DO UPDATE SET expires_at = NULL, starts_at = NULL, caveat = NULL, caveat_args = NULL;"
            )
        assert src.kind == "column" or src.kind == "table", f"no links of a {src.kind} source to write"
        kind = {src.type_col: k[3]} if src.type_col else {}
        if src.kind == "column":
            row, to = (
                dict(zip([c for c, _ in t.key], parts(t, o), strict=True)),
                dict(zip(cols(src.column), parts(st, s), strict=True)),
            )
            if any(row.get(c, v) != v for c, v in to.items()):
                return None
            new = {**{c: v for c, v in to.items() if c not in row}, **kind}
            return f"UPDATE {qt(t.table)} SET {given(new, ', ')} WHERE {given(row)};" if new else None
        table = qt(src.table)
        ends = dict(zip(cols(src.obj_col), parts(t, o), strict=True))
        there = dict(zip(cols(src.subj_col), parts(st, s), strict=True))
        if any(ends.get(c, v) != v for c, v in there.items()) or (src.where and src.table not in self.columns):
            return None  # (two values for one column; a `where` nobody said how to pass)
        more = self.columns.get(src.table, {})
        if self.own(k):
            new = {c: v for c, v in ends.items() if c not in there}
            sets = ", ".join([given(new, ", "), *(f"{q(c)} = {v}" for c, v in more.items())])
            return f"UPDATE {table} SET {sets} WHERE {given(there)};" if new else None
        row = {**ends, **there, **kind}
        names = ", ".join(q(c) for c in [*row, *more])
        values = ", ".join([*(lit(v) for v in row.values()), *more.values()])
        return f"DELETE FROM {table} WHERE {given(row)};\nINSERT INTO {table} ({names}) VALUES ({values});"

    def untie(self, k: evaluate.PairsKey, o: str) -> str | None:
        """SQL that takes away each link of a source on object o."""
        t, src, st = self.source(k)
        if src.kind == "shared":
            return (
                f"DELETE FROM authz.shares WHERE object_type = {lit(k[0])} AND object_id = {lit(o)} "
                f"AND relation = {lit(k[1])} AND subject_type = {lit(k[3])} AND subject_relation = {lit(k[4])};"
            )
        assert src.kind == "column" or src.kind == "table", f"no links of a {src.kind} source to take away"
        kind = {src.type_col: k[3]} if src.type_col else {}
        if src.kind == "column":
            row = dict(zip([c for c, _ in t.key], parts(t, o), strict=True))
            gone = [c for c in [*cols(src.column), *kind] if c not in row]
            sets = ", ".join(f"{q(c)} = NULL" for c in gone)
            return f"UPDATE {qt(t.table)} SET {sets} WHERE {given({**row, **kind})};" if gone else None
        table = qt(src.table)
        ends = dict(zip(cols(src.obj_col), parts(t, o), strict=True))
        if self.own(k):
            gone = [c for c in ends if c not in [c for c, _ in st.key]]
            sets = ", ".join(f"{q(c)} = NULL" for c in gone)
            return f"UPDATE {table} SET {sets} WHERE {given(ends)};" if gone else None
        return f"DELETE FROM {table} WHERE {given({**ends, **kind})};"

    def share(self, key: tuple[str | int, ...], gain: Gain, expires: str, starts: str, more: str = "NULL, NULL") -> str:
        """The share a part's key and a gain name (a relation's, or one of the type's roles that gives the gain's
        permission and whose owner counts there), written in a state: when it expires and starts, its caveat and
        the caveat's arguments. One that is there already takes that state."""
        tname, st, sr = lit(key[2]), lit(key[-2]), lit("" if key[-1] == "*" else key[-1])  # (bot:* is to subject '*')
        state = f"{expires}, {starts}, {more}"
        to = (
            "ON CONFLICT (object_type, object_id, relation, subject_type, subject_id, subject_relation) DO UPDATE "
            "SET expires_at = EXCLUDED.expires_at, starts_at = EXCLUDED.starts_at, caveat = EXCLUDED.caveat, "
            "caveat_args = EXCLUDED.caveat_args;"
        )
        head = f"INSERT INTO authz.shares ({SHARE_COLUMNS}, caveat, caveat_args)"
        if key[0] == "share":
            return (
                f"{head} VALUES ({tname}, {lit(gain.object)}, {lit(key[3])}, {st}, {lit(gain.subject)}, {sr}, "
                f"{state}) {to}"
            )
        owner = f" AND ro.owner_id = {lit(gain.owner)}" if gain.owner else ""
        giving = (
            f"authz.roles ro JOIN authz.role_permissions rp ON rp.role_id = ro.id WHERE ro.object_type = {tname} "
            f"AND rp.permission = {lit(gain.perm)}{owner}"
        )
        made = ""
        owned_by = evaluate.role_owner_type(self.ledger.pol.types[str(key[2])]) if self.ledger else None
        if gain.owner and owned_by:  # no role of that owner's gives it (the changes delete roles): one that does
            made = (
                "INSERT INTO authz.roles (owner_type, owner_id, object_type, name) "
                f"SELECT {lit(owned_by)}, {lit(gain.owner)}, {tname}, 'steered' WHERE NOT EXISTS (SELECT 1 FROM {giving}) "
                "ON CONFLICT DO NOTHING;\n"
                f"INSERT INTO authz.role_permissions SELECT ro.id, {lit(gain.perm)} FROM authz.roles ro "
                f"WHERE ro.object_type = {tname} AND ro.name = 'steered'{owner} "
                f"AND NOT EXISTS (SELECT 1 FROM {giving}) ON CONFLICT DO NOTHING;\n"
            )
        return (
            f"{made}{head} SELECT {tname}, {lit(gain.object)}, 'role:' || ro.id, {st}, {lit(gain.subject)}, {sr}, "
            f"{state} FROM {giving} ORDER BY ro.id LIMIT 1 {to}"
        )


def cols(columns: Cols | None) -> list[str]:
    """A source's column, or its columns for a composite key, as a list."""
    return [columns] if isinstance(columns, str) else list(columns or ())


def parts(t: Type, i: str) -> list[str]:
    """A row's id as its key columns' values: the id, or for a composite key the fields of the row's text."""
    return [i] if len(t.key) == 1 else row_of(i)


def given(values: dict[str, str], sep: str = " AND ") -> str:
    """`a = '1' AND b = 'x'`: columns with their values, as a condition (or, joined by commas, as assignments)."""
    return sep.join(f"{q(c)} = {lit(v)}" for c, v in values.items())


def ints(ids: Ids | None, name: str) -> list[int]:
    return [int(x) for x in (ids or {}).get(name, [])]


NOTHING = "SELECT 1;"  # a change that changes nothing: a share with no row there to be on or to (there())


def there(ids: Ids | None, name: str, first: int) -> list[int]:
    """The rows of a type a share the generator writes may be on or to: those there are now (ids), or before any
    change (no ids) the first data's 1..first. Never a row that is gone: rowstile forgets the shares on and to a row
    when it goes and authz.share refuses one, so on such a share the database and the reference need not agree (a
    column still naming the row counts it in one, not in the other). With none left, the generator writes NOTHING."""
    return ints(ids, name) if ids is not None else list(range(1, first + 1))


class DocsGen(Gen):
    """The example app (example/app_schema.sql). Its first data is steered toward what the decision ledger found
    never deciding an answer: user 8 starts an outsider (no org, nothing owned, alone in team 15, which no folder
    names), so a share that doesn't count, to user 8 or team 15, would decide had it counted; and folders 1 to 4 are
    a chain whose top only user 7 owns, so user 7 edits folder 4 only three links up."""

    policy = "example/docs.authz"
    schema = "example/app_schema.sql"
    users: ClassVar[list[str]] = [str(i) for i in range(1, 9)]

    def initial(self) -> str:
        r = self.r
        s = [
            "TRUNCATE app.folder_links, app.folder_team_access, app.files, app.folders, app.team_members, "
            "app.teams, app.org_members, app.orgs, app.users CASCADE;"
        ]
        s.append("INSERT INTO app.users SELECT i, 'u' || i FROM generate_series(1, 8) i;")
        s.append("INSERT INTO app.orgs VALUES (1, 'o1'), (2, 'o2');")
        for u in self.users[:7]:  # (user 8: the outsider)
            for o in (1, 2):
                if r.random() < 0.45:
                    s.append(
                        f"INSERT INTO app.org_members VALUES ({o}, {u}, '{r.choice(['admin', 'member', 'member'])}');"
                    )
        for i in range(10, 16):
            parent = r.choice([None, None] + list(range(10, i)))
            parent = {11: 10, 12: 11, 13: 12, 15: None}.get(i, parent)  # 13 in 12 in 11 in 10; the outsider's alone
            s.append(f"INSERT INTO app.teams VALUES ({i}, {r.choice([1, 2])}, {parent or 'NULL'}, 't{i}');")
        for u in self.users[:7]:
            for t in r.sample(range(10, 15), r.choice([0, 1, 1, 2])):
                s.append(f"INSERT INTO app.team_members VALUES ({t}, {u});")
        s.append("INSERT INTO app.team_members VALUES (15, 8);")
        for i in range(1, 26):
            parent = r.choice([None] + list(range(1, i)) * 3) if i > 1 else None
            owner, inherit = r.choice(self.users[:6]), "false" if r.random() < 0.15 else "true"
            if i <= 4:  # the chain: 4 in 3 in 2 in 1, whose owner is user 7's only folder
                parent, owner, inherit = i - 1 if i > 1 else None, "7" if i == 1 else owner, "true"
            s.append(
                f"INSERT INTO app.folders (id, org_id, parent_id, owner_id, name, inherit) VALUES "
                f"({i}, {r.choice([1, 2])}, {parent or 'NULL'}, {owner}, 'f{i}', {inherit});"
            )
        for i in range(1, 51):
            s.append(
                f"INSERT INTO app.files (id, folder_id, owner_id, name, confidential) VALUES "
                f"({i}, {r.randint(1, 25)}, {r.choice(self.users[:7])}, 'x{i}', {'true' if r.random() < 0.15 else 'false'});"
            )
        for _ in range(8):
            s.append(
                f"INSERT INTO app.folder_team_access VALUES ({r.randint(1, 25)}, {r.randint(10, 14)}, "
                f"'{r.choice(['view', 'edit'])}') ON CONFLICT DO NOTHING;"
            )
        for _ in range(5):
            a, b = r.randint(1, 25), r.randint(1, 25)
            if a != b:
                s.append(f"INSERT INTO app.folder_links VALUES ({a}, {b}) ON CONFLICT DO NOTHING;")
        s.append("SELECT setval(pg_get_serial_sequence('app.folders', 'id'), 100);")
        s.append("SELECT setval(pg_get_serial_sequence('app.files', 'id'), 100);")
        return "\n".join(s)

    def grants(self) -> str:
        # drawn, then shares that don't count (expired, not started) to the outsider, its team and an org, for each
        # relation: had they counted, they would have decided something
        r = self.r
        targeted = []
        for expires, starts in ((EXPIRED, "NULL"), ("NULL", LATER)):
            for obj, rel, subjects in (
                ("folder", "viewer", [("user", "8", ""), ("team", "15", "member"), ("org", "1", "member")]),
                ("folder", "editor", [("user", "8", ""), ("team", "15", "member")]),
                ("file", "viewer", [("user", "8", ""), ("team", "15", "member")]),
            ):
                for st, sid, sr in subjects:
                    oid = r.randint(1, 25) if obj == "folder" else r.randint(1, 50)
                    targeted.append(
                        f"INSERT INTO authz.shares ({SHARE_COLUMNS}) VALUES ('{obj}', {oid}, '{rel}', '{st}', {sid}, "
                        f"'{sr}', {expires}, {starts}) ON CONFLICT DO NOTHING;"
                    )
        return "\n".join([self.grant() for _ in range(25)] + targeted)

    def grant(self, ids: Ids | None = None) -> str:
        r = self.r
        folders, files = there(ids, "folder", 25), there(ids, "file", 50)
        if not (folders and files):
            return NOTHING
        expires, starts = r.choice([self.WHEN[0], *self.WHEN])  # live twice as often
        kind = r.random()
        if kind < 0.6:
            obj, oid, rel = "folder", r.choice(folders), r.choice(["viewer", "editor"])
            st, sid, sr = r.choice(
                [
                    ("user", r.choice(self.users), ""),
                    ("team", r.randint(10, 15), "member"),
                    ("org", r.choice([1, 2]), "member"),
                ]
            )
            if rel == "editor" and st == "org":
                st, sid, sr = "user", r.choice(self.users), ""
        else:
            obj, oid, rel = "file", r.choice(files), "viewer"
            st, sid, sr = r.choice([("user", r.choice(self.users), ""), ("team", r.randint(10, 15), "member")])
        return (
            f"INSERT INTO authz.shares ({SHARE_COLUMNS}) VALUES ('{obj}', {oid}, '{rel}', '{st}', {sid}, '{sr}', "
            f"{expires}, {starts}) ON CONFLICT DO NOTHING;"
        )

    def change(self, ids: Ids) -> str:
        r = self.r
        folders = ints(ids, "folder") or [1]
        files = ints(ids, "file") or [1]
        teams = ints(ids, "team") or [10]
        f, g = r.choice(folders), r.choice(folders)
        ops = [
            lambda: f"UPDATE app.folders SET parent_id = {r.choice([g, g, 'NULL'])} WHERE id = {f};",
            lambda: f"UPDATE app.folders SET parent_id = {g} WHERE id IN ({f}, {r.choice(folders)});",
            lambda: f"UPDATE app.folders SET inherit = NOT inherit WHERE id = {f};",
            lambda: f"UPDATE app.folders SET inherit = random() < 0.5 WHERE id % 3 = {r.randint(0, 2)};",
            lambda: (
                f"UPDATE app.folders SET org_id = {r.choice([1, 2])}, owner_id = {r.choice(self.users)} WHERE id = {f};"
            ),
            lambda: (
                f"INSERT INTO app.folders (org_id, parent_id, owner_id, name, inherit) VALUES "
                f"({r.choice([1, 2])}, {r.choice([f, 'NULL'])}, {r.choice(self.users)}, 'n', {r.choice(['true', 'false'])});"
            ),
            lambda: (
                f"INSERT INTO app.folders (org_id, parent_id, owner_id, name) "
                f"SELECT 1, {f}, {r.choice(self.users)}, 'bulk' FROM generate_series(1, 3);"
            ),
            lambda: f"DELETE FROM app.files WHERE folder_id = {f}; DELETE FROM app.folders WHERE id = {f};",
            lambda: f"UPDATE app.folders SET id = {max(folders) + r.randint(1, 50)} WHERE id = {f};",
            lambda: f"INSERT INTO app.folder_links VALUES ({f}, {g}) ON CONFLICT DO NOTHING;",
            lambda: f"DELETE FROM app.folder_links WHERE folder_id = {f} OR parent_id = {f};",
            lambda: f"UPDATE app.folder_links SET parent_id = {g} WHERE folder_id = {f};",
            lambda: "TRUNCATE app.folder_links;",
            lambda: (
                f"INSERT INTO app.folder_team_access VALUES ({f}, {r.choice(teams)}, '{r.choice(['view', 'edit'])}') "
                "ON CONFLICT (folder_id, team_id) DO UPDATE SET access = EXCLUDED.access;"
            ),
            lambda: f"DELETE FROM app.folder_team_access WHERE folder_id = {f};",
            lambda: (
                f"INSERT INTO app.team_members VALUES ({r.choice(teams)}, {r.choice(self.users)}) ON CONFLICT DO NOTHING;"
            ),
            lambda: f"DELETE FROM app.team_members WHERE user_id = {r.choice(self.users)};",
            lambda: self.sync(r.choice(teams)),
            lambda: (
                f"UPDATE app.teams SET parent_id = {r.choice(teams + [None, None]) or 'NULL'} WHERE id = {r.choice(teams)};"
            ),
            lambda: (
                f"INSERT INTO app.org_members VALUES ({r.choice([1, 2])}, {r.choice(self.users)}, "
                f"'{r.choice(['admin', 'member'])}') ON CONFLICT (org_id, user_id) DO UPDATE SET role = EXCLUDED.role;"
            ),
            lambda: f"DELETE FROM app.org_members WHERE user_id = {r.choice(self.users)};",
            lambda: self.grant(ids),
            lambda: self.grant(ids),
            lambda: f"DELETE FROM authz.shares WHERE object_id = '{r.choice(folders)}';",
            lambda: f"UPDATE authz.shares SET expires_at = {EXPIRED} WHERE random() < 0.2;",
            lambda: f"UPDATE app.files SET folder_id = {g} WHERE id = {r.choice(files)};",
            lambda: (
                f"UPDATE app.files SET confidential = NOT confidential, owner_id = {r.choice(self.users)} WHERE id = {r.choice(files)};"
            ),
            lambda: f"DELETE FROM app.files WHERE id = {r.choice(files)};",
            lambda: f"INSERT INTO app.files (folder_id, owner_id, name) VALUES ({f}, {r.choice(self.users)}, 'new');",
            lambda: f"UPDATE app.files SET id = {max(files) + r.randint(1, 50)} WHERE id = {r.choice(files)};",
        ]
        if r.random() < 0.15:  # several changes in one transaction
            return "BEGIN;\n" + "\n".join(r.choice(ops)() for _ in range(r.randint(2, 4))) + "\nCOMMIT;"
        return r.choice(ops)()

    def sync(self, team: int) -> str:
        """authz.sync_members makes a team's rows of app.team_members a list an identity provider sends: then
        they are that list, no more, no less (and the checks after the change judge what it gives)."""
        members = sorted(self.r.sample(self.users, self.r.randint(0, 3)), key=int)
        listed = "ARRAY[" + ", ".join(f"'{m}'" for m in members) + "]::text[]"
        return (
            f"DO $s$ BEGIN PERFORM authz.sync_members('team', '{team}', 'member', {listed}); "
            f"IF (SELECT coalesce(array_agg(user_id::text ORDER BY user_id), '{{}}') FROM app.team_members "
            f"WHERE team_id = {team}) IS DISTINCT FROM {listed} THEN "
            f"RAISE EXCEPTION 'sync_members left another list than %', {listed}; END IF; END $s$;"
        )


class AltGen(Gen):
    """tests/alt.authz: non-id keys, NULL columns under `not`, groups of groups by
    sharing, inheritance through shares and through conditions that read another
    table, relations with several sources pointing at another type, a deny that
    inherits, and custom roles granting a permission with a deny and one with a condition."""

    policy = "tests/alt.authz"
    schema = "tests/alt_schema.sql"
    users: ClassVar[list[str]] = [str(i) for i in range(1, 8)]

    def maybe(self, xs: Sequence[str | int], p: float = 0.5) -> str | int:
        return self.r.choice(xs) if self.r.random() < p else "NULL"

    def initial(self) -> str:
        r = self.r
        s = ["INSERT INTO alt.users SELECT i FROM generate_series(1, 7) i;"]
        for g in range(1, 6):
            s.append(f"INSERT INTO alt.groups VALUES ({g}, {r.choice(self.users)});")
        for u in self.users:
            for g in r.sample(range(1, 6), r.choice([0, 1, 1, 2])):
                s.append(f"INSERT INTO alt.group_members VALUES ({g}, {u}, {r.random() < 0.8});")
        for pj in range(1, 4):
            s.append(f"INSERT INTO alt.projects VALUES ({pj}, {r.choice(self.users)});")
            for g in r.sample(range(1, 6), r.choice([0, 1, 2])):
                s.append(f"INSERT INTO alt.project_groups VALUES ({pj}, {g});")
        for d in range(1, 31):
            up = r.choice([None] + list(range(1, d)) * 2) if d > 1 else None
            s.append(
                f"INSERT INTO alt.docs VALUES ({d}, {r.choice(self.users)}, {self.maybe(self.users, 0.2)}, "
                f"{up or 'NULL'}, {self.maybe([1, 2, 3], 0.3)}, {r.random() < 0.15});"
            )
        for _ in range(6):
            a, b = r.randint(1, 30), r.randint(1, 30)
            if a != b:
                s.append(f"INSERT INTO alt.doc_links VALUES ({a}, {b}) ON CONFLICT DO NOTHING;")
        for _ in range(4):
            s.append(
                f"INSERT INTO alt.doc_projects VALUES ({r.randint(1, 30)}, {r.randint(1, 3)}) ON CONFLICT DO NOTHING;"
            )
        for _ in range(3):
            s.append(f"INSERT INTO alt.holds VALUES ({r.randint(1, 30)}) ON CONFLICT DO NOTHING;")
        return "\n".join(s)

    def grants(self) -> str:
        roles = [
            "INSERT INTO authz.roles (id, owner_type, owner_id, object_type, name) VALUES "
            "(1, 'user', '1', 'doc', 'reader'), (2, 'user', '1', 'doc', 'publisher');",
            "INSERT INTO authz.role_permissions VALUES (1, 'view'), (2, 'view'), (2, 'publish');",
            "SELECT setval(pg_get_serial_sequence('authz.roles', 'id'), 10);",
        ]
        return "\n".join(roles + [self.grant() for _ in range(25)])

    def grant(self, ids: Ids | None = None) -> str:
        r = self.r
        docs, groups = there(ids, "doc", 30), there(ids, "grp", 5)
        if not (docs and groups):
            return NOTHING
        k = r.random()
        if k < 0.12:  # a custom role: inside view's deny and publish's condition
            row = (
                "doc",
                r.choice(docs),
                f"role:{r.choice([1, 2])}",
                *r.choice([("user", r.choice(self.users), ""), ("grp", r.choice(groups), "member")]),
            )
        elif k < 0.3:
            row = (
                "doc",
                r.choice(docs),
                "reader",
                *r.choice([("user", r.choice(self.users), ""), ("grp", r.choice(groups), "member")]),
            )
        elif k < 0.45:
            row = ("doc", r.choice(docs), "writer", "user", r.choice(self.users), "")
        elif k < 0.55:  # a deny: view is taken away here and below
            row = (
                "doc",
                r.choice(docs),
                "banned",
                *r.choice([("user", r.choice(self.users), ""), ("grp", r.choice(groups), "member")]),
            )
        elif k < 0.75:
            row = ("doc", r.choice(docs), "shortcut", "doc", r.choice(docs), "")
        else:
            row = ("grp", r.choice(groups), "member", "grp", r.choice(groups), "member")
        expires, starts = "NULL", "NULL"
        if row[2] != "shortcut":  # (a link of a tree: it never expires, nor starts later)
            draw = r.random()
            if draw < 0.25:
                expires = r.choice([EXPIRED, LATER])
            elif draw < 0.31:  # not started yet (with no draw of its own)
                starts = LATER
        vals = ", ".join(lit(x) if isinstance(x, str) else str(x) for x in row)
        return (
            f"INSERT INTO authz.shares ({SHARE_COLUMNS}) VALUES ({vals}, {expires}, {starts}) ON CONFLICT DO NOTHING;"
        )

    # the parts of an `and` that decide where a share alone gives the permission: a reader's view (blocked or not
    # then decides), a writer's edit (viewing or not)
    ALONE: ClassVar[dict[tuple[str, str], str]] = {
        ("doc.view", "not blocked"): "reader",
        ("doc.edit", "view"): "writer",
    }

    def steer(self, key: tuple[str | int, ...], ids: Ids) -> str | None:
        if self.ledger is not None and key[0] == "expr":
            part = self.ledger.parts[key]
            if (part.what, part.text) in self.ALONE:
                return self.alone("doc", self.ALONE[(part.what, part.text)])
        return super().steer(key, ids)

    def change(self, ids: Ids) -> str:
        r = self.r
        docs = ints(ids, "doc") or [1]
        groups = ints(ids, "grp") or [1]
        d, e = r.choice(docs), r.choice(docs)
        ops = [
            lambda: f"UPDATE alt.docs SET up = {r.choice([e, e, 'NULL'])} WHERE doc_no = {d};",
            lambda: f"UPDATE alt.docs SET locked = NOT locked WHERE doc_no = {d};",
            lambda: f"UPDATE alt.docs SET blocked_id = {self.maybe(self.users)} WHERE doc_no = {d};",
            lambda: (
                f"UPDATE alt.docs SET owner_id = {r.choice(self.users)}, project_id = {self.maybe([1, 2, 3])} WHERE doc_no = {d};"
            ),
            lambda: (
                f"INSERT INTO alt.docs VALUES ({max(docs) + 1}, {r.choice(self.users)}, NULL, {r.choice([d, 'NULL'])}, NULL, false);"
            ),
            lambda: f"DELETE FROM alt.docs WHERE doc_no = {d};",
            lambda: f"UPDATE alt.docs SET doc_no = {max(docs) + r.randint(1, 20)} WHERE doc_no = {d};",
            lambda: f"INSERT INTO alt.doc_links VALUES ({d}, {e}) ON CONFLICT DO NOTHING;",
            lambda: f"DELETE FROM alt.doc_links WHERE child = {d} OR parent = {d};",
            lambda: "TRUNCATE alt.doc_links;",
            lambda: f"INSERT INTO alt.holds VALUES ({d}) ON CONFLICT DO NOTHING;",
            lambda: f"DELETE FROM alt.holds WHERE target = {r.choice(docs)};",
            lambda: f"UPDATE alt.holds SET target = {e} WHERE target = {d};",
            lambda: "TRUNCATE alt.holds;",
            lambda: f"INSERT INTO alt.doc_projects VALUES ({d}, {r.randint(1, 3)}) ON CONFLICT DO NOTHING;",
            lambda: f"DELETE FROM alt.doc_projects WHERE doc_no = {d};",
            lambda: f"UPDATE alt.group_members SET active = NOT active WHERE user_id = {r.choice(self.users)};",
            lambda: (
                f"INSERT INTO alt.group_members VALUES ({r.choice(groups)}, {r.choice(self.users)}, true) ON CONFLICT DO NOTHING;"
            ),
            lambda: f"DELETE FROM alt.group_members WHERE group_id = {r.choice(groups)};",
            lambda: (
                f"INSERT INTO alt.project_groups VALUES ({r.randint(1, 3)}, {r.choice(groups)}) ON CONFLICT DO NOTHING;"
            ),
            lambda: f"UPDATE alt.projects SET lead_id = {r.choice(self.users)} WHERE id = {r.randint(1, 3)};",
            lambda: f"DELETE FROM alt.groups WHERE gid = {r.choice(groups)};",
            lambda: f"INSERT INTO alt.groups VALUES ({max(groups) + 1}, {r.choice(self.users)});",
            lambda: self.grant(ids),
            lambda: self.grant(ids),
            lambda: self.grant(ids),
            lambda: f"DELETE FROM authz.shares WHERE object_id = '{d}' OR subject_id = '{d}';",
            lambda: f"UPDATE authz.shares SET expires_at = {EXPIRED} WHERE relation <> 'shortcut' AND random() < 0.2;",
            lambda: (
                f"INSERT INTO authz.role_permissions VALUES (1, {lit(r.choice(['view', 'publish']))}) ON CONFLICT DO NOTHING;"
            ),
            lambda: "DELETE FROM authz.role_permissions WHERE role_id = 1 AND permission = 'publish';",
        ]
        if r.random() < 0.15:
            return "BEGIN;\n" + "\n".join(r.choice(ops)() for _ in range(r.randint(2, 4))) + "\nCOMMIT;"
        return r.choice(ops)()


def uid(i: int, prefix: str = "00000000-0000-4000-8000-") -> str:
    return f"{prefix}{i:012d}"


class MultiGen(Gen):
    """tests/multi.authz: UUID keys, suspended users and orgs, archived folders,
    folders and projects nested in each other (inheritance across types),
    documents in either, user:*, anyone, link tokens, shares that start later or
    carry a caveat, and custom roles: a folder's from its org's column, a doc's
    from the orgs a table lists (mt.doc_orgs, while active), a project's of any owner."""

    policy = "tests/multi.authz"
    schema = "tests/multi_schema.sql"
    users: ClassVar[list[str]] = [uid(i) for i in range(1, 8)]
    tokens: ClassVar[list[str]] = ["tok-a", "tok-b", "tok-c"]

    def context(self, u: str) -> dict[str, str]:
        i = self.users.index(u) if u else len(self.users)  # nobody: signed out, holding a link or not
        ctx = {"mode": "business" if i % 2 == 0 else "night", "ip": f"10.0.0.{i % 3}"}
        ctx["links"] = ",".join(t for j, t in enumerate(self.tokens) if (i + j) % 3 == 0)
        return ctx

    def u(self) -> str:
        return lit(self.r.choice(self.users))

    def maybe_user(self) -> str:
        return self.u() if self.r.random() < 0.8 else "NULL"

    def steer(self, key: tuple[str | int, ...], ids: Ids) -> str | None:
        """A share with a caveat, where the reference says the share alone would change an answer: one that holds
        in that principal's session, or one that doesn't, as the part says. And when no share of the part's
        would give anything: for a doc's roles, which count only by an org the doc lists, a few docs list an org;
        for one to a team's members, someone joins a team; each for the next try."""
        if key[0] in ("share", "role share") and key[1] in ("caveat false", "caveat true"):
            gain = self.ledger.gain(key, self.r) if self.ledger else None
            holds = key[1] == "caveat true"
            sql = self.share(key, gain, "NULL", "NULL", self.caveat(gain.user, holds)) if gain else None
        else:
            sql = super().steer(key, ids)
        if sql is None and key[0] == "role share" and key[2] == "doc":
            return (
                "INSERT INTO mt.doc_orgs SELECT d.id, o.id, true FROM (SELECT id FROM mt.docs ORDER BY random() "
                "LIMIT 4) d, (SELECT id FROM mt.orgs ORDER BY random() LIMIT 1) o "
                "ON CONFLICT (doc_id, org_id) DO UPDATE SET active = true;"
            )
        if sql is None and key[0] in ("share", "role share") and key[-2:] == ("team", "member"):
            return f"INSERT INTO mt.team_members VALUES ({self.r.randint(1, 4)}, {self.u()}) ON CONFLICT DO NOTHING;"
        return sql

    def caveat(self, u: str, holds: bool) -> str:
        """A caveat and its arguments, as SQL, that holds in a user's session (context()) or doesn't: business
        hours where their mode says so, else the ip they come from, or another."""
        ctx = self.context(u)
        if (ctx["mode"] == "business") == holds:
            return "'business_hours', NULL"
        ip = ctx["ip"] if holds else f"10.0.0.{(int(ctx['ip'][-1]) + 1) % 3}"
        return f"""'from_ip', '{{"ip": "{ip}"}}'"""

    def initial(self) -> str:
        r = self.r
        s = [f"INSERT INTO mt.users VALUES ({lit(u)}, {str(i != 6).lower()});" for i, u in enumerate(self.users)]
        s.append("INSERT INTO mt.orgs VALUES (1, false), (2, false);")
        for u in self.users:
            for o in (1, 2):
                if r.random() < 0.4:
                    s.append(
                        f"INSERT INTO mt.org_members VALUES ({o}, {lit(u)}, '{r.choice(['admin', 'member', 'member'])}');"
                    )
        s.append("INSERT INTO mt.teams SELECT i FROM generate_series(1, 4) i;")
        for u in self.users:
            for t in r.sample(range(1, 5), r.choice([0, 1, 1, 2])):
                s.append(f"INSERT INTO mt.team_members VALUES ({t}, {lit(u)});")
        for i in range(1, 11):
            parent = r.choice([None] + list(range(1, i))) if i > 1 else None
            s.append(
                f"INSERT INTO mt.folders VALUES ({i}, {lit('folder') if parent else 'NULL'}, {parent or 'NULL'}, "
                f"{self.maybe_user()}, {str(r.random() < 0.15).lower()}, {str(r.random() < 0.1).lower()});"
            )
        for p in range(1, 7):
            s.append(
                f"INSERT INTO mt.projects VALUES ({p}, {r.choice([1, 2])}, {r.choice([None] + list(range(1, 11))) or 'NULL'}, "
                f"{self.maybe_user()});"
            )
        for i in range(11, 21):
            kind = r.choice(["folder", "project", None])
            parent = r.randint(1, i - 1) if kind == "folder" else r.randint(1, 6) if kind == "project" else None
            s.append(
                f"INSERT INTO mt.folders VALUES ({i}, {lit(kind) if kind else 'NULL'}, {parent or 'NULL'}, "
                f"{self.maybe_user()}, {str(r.random() < 0.15).lower()}, {str(r.random() < 0.1).lower()});"
            )
        for d in range(1, 31):
            kind = r.choice(["folder", "folder", "project"])
            cid = r.randint(1, 20) if kind == "folder" else r.randint(1, 6)
            s.append(
                f"INSERT INTO mt.docs VALUES ({lit(uid(d, '10000000-0000-4000-8000-'))}, {lit(kind)}, {cid}, {self.maybe_user()});"
            )
        s.append("UPDATE mt.folders SET org_id = (ARRAY[1, 2, NULL])[1 + id % 3];")  # whose roles count there
        # the orgs whose roles count on a doc: a table's rows, none, one or both, some not active
        for d in range(1, 31):
            for o in r.sample([1, 2], r.choice([0, 1, 1, 2])):
                s.append(
                    f"INSERT INTO mt.doc_orgs VALUES ({lit(uid(d, '10000000-0000-4000-8000-'))}, {o}, "
                    f"{str(r.random() < 0.7).lower()});"
                )
        return "\n".join(s)

    def grants(self) -> str:
        roles = [
            # org 2's role too, from the start: shared on a folder of org 1 (or of none), as only a direct
            # insert or a folder moved to another org makes it, it must give nothing
            "INSERT INTO authz.roles (id, owner_type, owner_id, object_type, name) VALUES "
            "(1, 'org', '1', 'folder', 'reader'), (2, 'org', '1', 'folder', 'writer'), (3, 'org', '2', 'folder', 'editor3');",
            # (the writer may archive: a role gives what an owner does there)
            "INSERT INTO authz.role_permissions VALUES (1, 'view'), (2, 'view'), (2, 'edit'), (2, 'archive'), (3, 'edit');",
            # a doc's roles, one per org; view gives nothing on a doc, whose view doesn't name its roles
            "INSERT INTO authz.roles (id, owner_type, owner_id, object_type, name) VALUES "
            "(4, 'org', '1', 'doc', 'doc writer'), (5, 'org', '2', 'doc', 'doc writer');",
            "INSERT INTO authz.role_permissions VALUES (4, 'edit'), (5, 'edit'), (5, 'view');",
            # a project's role, a team's (any owner's counts there), given on three projects to a user or a team
            "INSERT INTO authz.roles (id, owner_type, owner_id, object_type, name) VALUES "
            "(6, 'team', '1', 'project', 'project reader');",
            "INSERT INTO authz.role_permissions VALUES (6, 'view');",
            "INSERT INTO authz.shares (object_type, object_id, relation, subject_type, subject_id, subject_relation) "
            f"VALUES ('project', '1', 'role:6', 'user', {lit(uid(3))}, ''), ('project', '2', 'role:6', 'team', '2', "
            f"'member'), ('project', '4', 'role:6', 'user', {lit(uid(5))}, '');",
            "SELECT setval(pg_get_serial_sequence('authz.roles', 'id'), 10);",
        ]
        # ... and a few such from the start: folders 3, 6, 9 are org 1's, 1 and 4 org 2's, 2 nobody's (initial)
        cross = [
            "INSERT INTO authz.shares (object_type, object_id, relation, subject_type, subject_id, subject_relation) "
            f"VALUES ('folder', '{f}', 'role:{role}', 'user', {self.u()}, '') ON CONFLICT DO NOTHING;"
            for f, role in ((3, 3), (6, 3), (9, 3), (1, 1), (4, 2), (2, 2))
        ]
        # and org 1's writer on its folder 12, where it counts (and gives archive), written out: no draw. To user 1,
        # who doesn't own folder 12 in the first data of the seed the suites run: there the role alone gives archive
        cross.append(
            "INSERT INTO authz.shares (object_type, object_id, relation, subject_type, subject_id, subject_relation) "
            f"VALUES ('folder', '12', 'role:2', 'user', {lit(uid(1))}, '') ON CONFLICT DO NOTHING;"
        )
        # a doc's roles from the start, on docs whose orgs may be listed, not listed, or listed but not active
        docs = [
            "INSERT INTO authz.shares (object_type, object_id, relation, subject_type, subject_id, subject_relation) "
            f"VALUES ('doc', {lit(uid(d, '10000000-0000-4000-8000-'))}, 'role:{self.r.choice([4, 5])}', 'user', "
            f"{self.u()}, '') ON CONFLICT DO NOTHING;"
            for d in range(1, 13)
        ]
        return "\n".join(roles + cross + docs + [self.grant() for _ in range(30)])

    def subject(self, allowed: list[str]) -> tuple[str, str, str]:
        r = self.r
        kind = r.choice(allowed)
        if kind == "user":
            return ("user", r.choice(self.users), "")
        if kind == "team":
            return ("team", str(r.randint(1, 4)), "member")
        if kind == "user:*":
            return ("user", "*", "")
        if kind == "anyone":
            return ("anyone", "*", "")
        return ("link", f"encode(sha256(convert_to({lit(r.choice(self.tokens))}, 'UTF8')), 'hex')", "")

    def grant(self, ids: Ids | None = None) -> str:
        r = self.r
        folders, projects = there(ids, "folder", 20), there(ids, "project", 6)
        docs = (
            (ids or {}).get("doc", [])
            if ids is not None
            else [uid(d, "10000000-0000-4000-8000-") for d in range(1, 31)]
        )
        if not (folders and projects and docs):
            return NOTHING
        k = r.random()
        if k < 0.3:
            obj, oid, rel = "project", r.choice(projects), "viewer"
            st, sid, sr = self.subject(["user", "team", "user:*", "anyone", "link"])
        elif k < 0.5:
            obj, oid, rel = "folder", r.choice(folders), "viewer"
            st, sid, sr = self.subject(["user", "team", "user:*", "link"])
        elif k < 0.6:
            obj, oid, rel = "folder", r.choice(folders), "editor"
            st, sid, sr = self.subject(["user", "team"])
        elif k < 0.77:
            obj, oid, rel = "folder", r.choice(folders), f"role:{r.choice([1, 2, 3])}"
            st, sid, sr = self.subject(["user", "team"])
        elif k < 0.85:  # a doc's role: it counts while the doc lists its org (mt.doc_orgs, active)
            obj, oid, rel = "doc", r.choice(docs), f"role:{r.choice([4, 5])}"
            st, sid, sr = self.subject(["user"])
        else:
            obj, oid, rel = "team", r.randint(1, 4), "member"
            st, sid, sr = "team", str(r.randint(1, 4)), "member"
        sid_sql = sid if sid.startswith("encode(") else lit(sid)
        expires = r.choice(["NULL"] * 4 + [EXPIRED, LATER])
        starts = r.choice(["NULL"] * 4 + [LATER, EARLIER])
        caveat, args = r.choice(
            [("NULL", "NULL")] * 4
            + [
                ("'business_hours'", "NULL"),
                ("'from_ip'", f'\'{{"ip": "10.0.0.{r.randint(0, 2)}"}}\''),
                ("'nonexistent'", "NULL"),
            ]
        )
        return (
            f"INSERT INTO authz.shares (object_type, object_id, relation, subject_type, subject_id, subject_relation, "
            f"expires_at, starts_at, caveat, caveat_args) VALUES ('{obj}', '{oid}', '{rel}', '{st}', {sid_sql}, '{sr}', "
            f"{expires}, {starts}, {caveat}, {args}) ON CONFLICT DO NOTHING;"
        )

    def change(self, ids: Ids) -> str:
        r = self.r
        folders = ints(ids, "folder") or [1]
        projects = ints(ids, "project") or [1]
        docs = ids.get("doc") or [uid(1, "10000000-0000-4000-8000-")]
        f, g, p = r.choice(folders), r.choice(folders), r.choice(projects)
        newdoc = uid(r.randint(100, 999), "10000000-0000-4000-8000-")
        ops = [
            lambda: f"UPDATE mt.folders SET parent_type = 'folder', parent_id = {g} WHERE id = {f};",
            lambda: f"UPDATE mt.folders SET parent_type = 'project', parent_id = {p} WHERE id = {f};",
            lambda: f"UPDATE mt.folders SET parent_type = NULL, parent_id = NULL WHERE id = {f};",
            lambda: f"UPDATE mt.projects SET folder_id = {r.choice([f, 'NULL'])} WHERE id = {p};",
            lambda: f"UPDATE mt.folders SET locked = NOT locked WHERE id = {f};",
            lambda: f"UPDATE mt.folders SET archived = NOT archived WHERE id = {f};",
            lambda: f"UPDATE mt.folders SET owner_id = {self.maybe_user()} WHERE id = {f};",
            lambda: f"UPDATE mt.folders SET org_id = {r.choice(['1', '2', 'NULL'])} WHERE id = {f};",
            lambda: f"UPDATE mt.orgs SET suspended = NOT suspended WHERE id = {r.choice([1, 2])};",
            lambda: f"UPDATE mt.users SET active = NOT active WHERE id = {self.u()};",
            lambda: (
                f"UPDATE mt.projects SET lead_id = {self.maybe_user()}, org_id = {r.choice([1, 2])} WHERE id = {p};"
            ),
            lambda: (
                f"INSERT INTO mt.org_members VALUES ({r.choice([1, 2])}, {self.u()}, '{r.choice(['admin', 'member'])}') "
                "ON CONFLICT (org_id, user_id) DO UPDATE SET role = EXCLUDED.role;"
            ),
            lambda: f"DELETE FROM mt.org_members WHERE user_id = {self.u()};",
            lambda: f"INSERT INTO mt.team_members VALUES ({r.randint(1, 4)}, {self.u()}) ON CONFLICT DO NOTHING;",
            lambda: f"DELETE FROM mt.team_members WHERE team_id = {r.randint(1, 4)};",
            lambda: (
                f"INSERT INTO mt.folders VALUES ({max(folders) + 1}, {r.choice([chr(39) + 'folder' + chr(39), 'NULL'])}, "
                f"{f}, {self.maybe_user()}, false, false);"
            ),
            lambda: f"DELETE FROM mt.folders WHERE id = {f};",
            lambda: f"UPDATE mt.folders SET id = {max(folders) + r.randint(1, 20)} WHERE id = {f};",
            lambda: f"DELETE FROM mt.projects WHERE id = {p};",
            lambda: (
                f"INSERT INTO mt.docs VALUES ({lit(newdoc)}, {lit(r.choice(['folder', 'project']))}, "
                f"{r.choice([f, p])}, {self.maybe_user()}) ON CONFLICT DO NOTHING;"
            ),
            lambda: (
                f"UPDATE mt.docs SET container_type = 'project', container_id = {p} WHERE id = {lit(r.choice(docs))};"
            ),
            lambda: (
                f"UPDATE mt.docs SET container_type = 'folder', container_id = {f} WHERE id = {lit(r.choice(docs))};"
            ),
            lambda: f"UPDATE mt.docs SET id = {lit(newdoc)} WHERE id = {lit(r.choice(docs))};",
            lambda: f"DELETE FROM mt.docs WHERE id = {lit(r.choice(docs))};",
            lambda: self.grant(ids),
            lambda: self.grant(ids),
            lambda: self.grant(ids),
            lambda: f"DELETE FROM authz.shares WHERE object_id = '{r.choice([f, p])}';",
            lambda: f"UPDATE authz.shares SET expires_at = {EXPIRED} WHERE random() < 0.2;",
            lambda: f"UPDATE authz.shares SET starts_at = {LATER} WHERE random() < 0.1;",
            lambda: (
                f"INSERT INTO authz.role_permissions VALUES ({r.choice([1, 2, 3])}, 'edit') ON CONFLICT DO NOTHING;"
            ),
            lambda: f"DELETE FROM authz.role_permissions WHERE role_id = {r.choice([1, 2])} AND permission = 'edit';",
            lambda: (
                "INSERT INTO authz.roles (id, owner_type, owner_id, object_type, name) VALUES "
                "(3, 'org', '2', 'folder', 'editor3') ON CONFLICT DO NOTHING;"
            ),
            lambda: f"DELETE FROM authz.roles WHERE id = {r.choice([1, 2, 3])};",
            # the orgs whose roles count on a doc, and a doc's roles
            lambda: (
                f"INSERT INTO mt.doc_orgs VALUES ({lit(r.choice(docs))}, {r.choice([1, 2])}, true) "
                "ON CONFLICT (doc_id, org_id) DO UPDATE SET active = NOT mt.doc_orgs.active;"
            ),
            lambda: f"DELETE FROM mt.doc_orgs WHERE doc_id = {lit(r.choice(docs))};",
            lambda: f"UPDATE mt.doc_orgs SET org_id = 3 - org_id WHERE doc_id = {lit(r.choice(docs))};",
            lambda: "TRUNCATE mt.doc_orgs;",
            lambda: f"DELETE FROM authz.roles WHERE id = {r.choice([4, 5])};",
            lambda: "INSERT INTO authz.role_permissions VALUES (4, 'view') ON CONFLICT DO NOTHING;",
        ]
        if r.random() < 0.15:
            return "BEGIN;\n" + "\n".join(r.choice(ops)() for _ in range(r.randint(2, 4))) + "\nCOMMIT;"
        return r.choice(ops)()


def row_of(text: str) -> list[str]:
    """'(1,"a b")' -> ['1', 'a b']: the fields of a row's text (Postgres quotes and doubles quotes)."""
    return next(csv.reader([text[1:-1]]))


class CompositeGen(Gen):
    """tests/composite.authz: tables keyed (org_id, id) and (org_id, slug text); keys with commas
    and quotes; keys renumbered and renamed; inheritance through composite columns, link tables and
    polymorphic pairs, across folders and projects; nested teams; shares with ids written loosely."""

    policy = "tests/composite.authz"
    schema = "tests/composite_schema.sql"
    users: ClassVar[list[str]] = [str(i) for i in range(1, 7)] + [
        "bot:1",
        "bot:2",
        "bot:3",
    ]  # bots sign in as themselves
    people: ClassVar[list[str]] = [str(i) for i in range(1, 7)]
    slugs: ClassVar[list[str]] = ["a b", 'x,y "q"', "plain", "Ünï", "(p)"]

    def maybe_user(self) -> str:
        return self.r.choice(self.people + ["NULL"])

    def initial(self) -> str:
        r = self.r
        s = ["INSERT INTO cx.users SELECT generate_series(1, 6);", "INSERT INTO cx.orgs VALUES (1), (2);"]
        for u in range(2, 7):
            if r.random() < 0.7:
                s.append(f"UPDATE cx.users SET manager_id = {r.randint(1, u - 1)} WHERE id = {u};")
        for b in (1, 2, 3):
            s.append(f"INSERT INTO cx.bots VALUES ({b}, {r.choice(self.people)}, {str(r.random() < 0.8).lower()});")
        for o in (1, 2):
            for u in r.sample(self.people, 1):
                s.append(f"INSERT INTO cx.org_admins VALUES ({o}, {u});")
            slugs = r.sample(self.slugs, 4)
            for i, slug in enumerate(slugs):
                parent = r.choice([None] + slugs[:i]) if i else None
                s.append(
                    f"INSERT INTO cx.teams VALUES ({o}, {lit(slug)}, {self.maybe_user()}, "
                    f"{lit(parent) if parent else 'NULL'});"
                )
                for u in r.sample(self.people, r.choice([0, 1, 2])):
                    s.append(f"INSERT INTO cx.team_members VALUES ({o}, {lit(slug)}, {u});")
                if r.random() < 0.3:
                    s.append(f"INSERT INTO cx.team_bots VALUES ({o}, {lit(slug)}, {r.randint(1, 3)});")
            for i in range(1, 11):
                kind = r.choice(["folder", "folder", "project", None]) if i > 1 else None
                parent = r.randint(1, i - 1) if kind == "folder" else r.randint(1, 3) if kind == "project" else None
                s.append(
                    f"INSERT INTO cx.folders VALUES ({o}, {i}, {self.maybe_user()}, "
                    f"{lit(kind) if kind else 'NULL'}, {parent or 'NULL'});"
                )
            for pj in range(1, 4):
                s.append(
                    f"INSERT INTO cx.projects VALUES ({o}, {pj}, {self.maybe_user()}, "
                    f"{r.choice([None, 1, 2, 3, 4, 5]) or 'NULL'});"
                )
            for _ in range(3):
                s.append(
                    f"INSERT INTO cx.folder_links VALUES ({o}, {r.randint(2, 10)}, {r.randint(1, 10)}) "
                    f"ON CONFLICT DO NOTHING;"
                )
            for _ in range(3):
                s.append(
                    f"INSERT INTO cx.folder_teams VALUES ({o}, {r.randint(1, 10)}, {lit(r.choice(slugs))}) "
                    f"ON CONFLICT DO NOTHING;"
                )
            for i in range(1, 13):
                s.append(
                    f"INSERT INTO cx.files VALUES ({o}, {i}, {r.randint(1, 10)}, {self.maybe_user()}, "
                    f"{r.choice([1, 2, 3, 'NULL', 'NULL'])});"
                )
        return "\n".join(s)

    def grants(self) -> str:
        return "\n".join(self.grant() for _ in range(20))

    def team(self, ids: Ids | None = None) -> tuple[int, str]:
        teams = [row_of(x) for x in (ids or {}).get("team", [])] or [["1", "a b"]]
        o, slug = self.r.choice(teams)
        return int(o), slug

    def id_text(self, o: int, i: int) -> str:
        """A folder's id as a caller might write it: canonical or with spaces."""
        return self.r.choice([f"({o},{i})", f"( {o}, {i} )"])

    def grant(self, ids: Ids | None = None) -> str:
        r = self.r
        folders = [tuple(map(int, row_of(x))) for x in (ids or {}).get("folder", [])] or [(1, 1)]
        if ids is not None and not (ids.get("folder") and ids.get("team")):  # (see there())
            return NOTHING
        o, f = r.choice(folders)
        if r.random() < 0.25:  # a team inside a team, by sharing
            (o1, s1), (o2, s2) = self.team(ids), self.team(ids)
            return (
                f"INSERT INTO authz.shares VALUES ('team', ROW({o1}, {lit(s1)})::text, 'member', 'team', "
                f"ROW({o2}, {lit(s2)})::text, 'member', NULL) ON CONFLICT DO NOTHING;"
            )
        k = r.random()
        if k < 0.1:
            subj, sid = ("bot", None, ""), "'*'"  # any signed-in bot
        elif k < 0.25:
            subj, sid = ("bot", None, ""), lit(str(r.randint(1, 3)))
        elif k < 0.55:
            subj = ("user", r.choice(self.people), "")
            sid = lit(subj[1])
        else:
            to, ts = self.team(ids)
            subj = ("team", None, "member")
            sid = f"ROW({to}, {lit(ts)})::text"
        expires, starts = r.choice(self.WHEN)
        return (
            f"INSERT INTO authz.shares ({SHARE_COLUMNS}) VALUES ('folder', {lit(self.id_text(o, f))}, 'viewer', "
            f"{lit(subj[0])}, {sid}, {lit(subj[2])}, {expires}, {starts}) ON CONFLICT DO NOTHING;"
        )

    def change(self, ids: Ids) -> str:
        r = self.r
        folders = [tuple(map(int, row_of(x))) for x in ids.get("folder", [])] or [(1, 1)]
        projects = [tuple(map(int, row_of(x))) for x in ids.get("project", [])] or [(1, 1)]
        files = [tuple(map(int, row_of(x))) for x in ids.get("file", [])] or [(1, 1)]
        o, f = r.choice(folders)
        g = r.choice([x for x in folders if x[0] == o] or [(o, 1)])[1]
        p = r.choice([x for x in projects if x[0] == o] or [(o, 1)])[1]
        fo, fi = r.choice(files)
        to, ts = self.team(ids)
        ts2 = r.choice([s for oo, s in [row_of(x) for x in ids.get("team", [])] if int(oo) == to] or [ts])
        top = max(i for _, i in folders)
        here = f"(org_id, id) = ({o}, {f})"
        ops = [
            lambda: f"UPDATE cx.folders SET parent_type = 'folder', parent_id = {g} WHERE {here};",
            lambda: f"UPDATE cx.folders SET parent_type = 'project', parent_id = {p} WHERE {here};",
            lambda: f"UPDATE cx.folders SET parent_type = NULL, parent_id = NULL WHERE {here};",
            lambda: f"UPDATE cx.projects SET folder_id = {r.choice([f, 'NULL'])} WHERE (org_id, id) = ({o}, {p});",
            lambda: f"UPDATE cx.folders SET owner_id = {self.maybe_user()} WHERE {here};",
            lambda: f"UPDATE cx.projects SET lead_id = {self.maybe_user()} WHERE (org_id, id) = ({o}, {p});",
            lambda: f"INSERT INTO cx.folders VALUES ({o}, {top + 1}, {self.maybe_user()}, 'folder', {f});",
            lambda: f"DELETE FROM cx.folders WHERE {here};",
            lambda: f"UPDATE cx.folders SET id = {top + r.randint(1, 9)} WHERE {here};",  # renumbered
            lambda: (
                f"UPDATE cx.folders SET org_id = {3 - o} WHERE {here} AND NOT EXISTS "
                f"(SELECT 1 FROM cx.folders x WHERE (x.org_id, x.id) = ({3 - o}, {f}));"
            ),  # half the key changes
            lambda: f"INSERT INTO cx.folder_links VALUES ({o}, {f}, {g}) ON CONFLICT DO NOTHING;",
            lambda: f"DELETE FROM cx.folder_links WHERE org_id = {o} AND (child_id = {f} OR parent_id = {f});",
            lambda: f"INSERT INTO cx.folder_teams VALUES ({to}, {f}, {lit(ts)}) ON CONFLICT DO NOTHING;",
            lambda: f"DELETE FROM cx.folder_teams WHERE org_id = {o} AND folder_id = {f};",
            lambda: (
                f"UPDATE cx.teams SET parent_slug = {r.choice([lit(ts2), 'NULL'])} WHERE (org_id, slug) = ({to}, {lit(ts)});"
            ),
            lambda: f"UPDATE cx.teams SET slug = {lit(ts + '!')} WHERE (org_id, slug) = ({to}, {lit(ts)});",  # renamed
            lambda: f"UPDATE cx.teams SET disbanded = NOT disbanded WHERE (org_id, slug) = ({to}, {lit(ts)});",
            lambda: (
                f"UPDATE cx.team_members SET team_slug = {lit(ts2)} WHERE org_id = {to} AND team_slug = {lit(ts)} "
                f"AND user_id = {r.choice(self.people)} AND NOT EXISTS (SELECT 1 FROM cx.team_members m "
                f"WHERE m.org_id = {to} AND m.team_slug = {lit(ts2)} AND m.user_id = team_members.user_id);"
            ),
            lambda: (
                f"INSERT INTO cx.team_members VALUES ({to}, {lit(ts)}, {r.choice(self.people)}) ON CONFLICT DO NOTHING;"
            ),
            lambda: f"DELETE FROM cx.team_members WHERE org_id = {to} AND team_slug = {lit(ts)};",
            lambda: f"DELETE FROM cx.teams WHERE (org_id, slug) = ({to}, {lit(ts)});",
            lambda: (
                f"INSERT INTO cx.org_admins VALUES ({r.choice([1, 2])}, {r.choice(self.people)}) ON CONFLICT DO NOTHING;"
            ),
            lambda: f"DELETE FROM cx.org_admins WHERE user_id = {r.choice(self.people)};",
            lambda: f"UPDATE cx.files SET folder_id = {g} WHERE (org_id, id) = ({fo}, {fi});",
            lambda: f"UPDATE cx.files SET owner_id = {self.maybe_user()} WHERE (org_id, id) = ({fo}, {fi});",
            lambda: f"DELETE FROM cx.files WHERE (org_id, id) = ({fo}, {fi});",
            lambda: (
                f"UPDATE cx.files SET uploaded_by = {r.choice([1, 2, 3, 'NULL'])} WHERE (org_id, id) = ({fo}, {fi});"
            ),
            lambda: f"UPDATE cx.bots SET active = NOT active WHERE id = {r.randint(1, 3)};",
            lambda: (
                f"UPDATE cx.users SET manager_id = {r.choice(self.people + ['NULL'])} WHERE id = {r.choice(self.people)};"
            ),
            lambda: f"INSERT INTO cx.team_bots VALUES ({to}, {lit(ts)}, {r.randint(1, 3)}) ON CONFLICT DO NOTHING;",
            lambda: f"DELETE FROM cx.team_bots WHERE bot_id = {r.randint(1, 3)};",
            lambda: self.grant(ids),
            lambda: self.grant(ids),
            lambda: f"DELETE FROM authz.shares WHERE object_type = 'folder' AND object_id = '({o},{f})';",
            lambda: f"UPDATE authz.shares SET expires_at = {EXPIRED} WHERE random() < 0.2;",
        ]
        if r.random() < 0.15:
            return "BEGIN;\n" + "\n".join(r.choice(ops)() for _ in range(r.randint(2, 4))) + "\nCOMMIT;"
        return r.choice(ops)()


class LoopGen(Gen):
    """tests/loop.authz: inheritance round a loop of foreign keys through four types, two of which have no
    starting point of their own (their edit is only what the loop brings round), and a condition that stops it
    (an address not verified); links re-pointed, cut (NULL) and their rows deleted, so the loop opens, closes and
    runs through rows that are gone."""

    policy = "tests/loop.authz"
    schema = "tests/loop_schema.sql"
    users: ClassVar[list[str]] = [str(i) for i in range(1, 7)]
    tables: ClassVar[dict[str, tuple[str, str, str]]] = {  # type: (table, the link column, the type it names)
        "org": ("lp.orgs", "settings_id", "setting"),
        "setting": ("lp.settings", "email_id", "email"),
        "email": ("lp.emails", "domain_id", "domain"),
        "domain": ("lp.domains", "org_id", "org"),
    }

    def maybe(self, ids: list[int]) -> str:
        return str(self.r.choice(ids)) if ids and self.r.random() < 0.8 else "NULL"

    def initial(self) -> str:
        r = self.r
        s = ["INSERT INTO lp.users SELECT i, 'u' || i FROM generate_series(1, 6) i;"]
        for table, _, _ in self.tables.values():
            s.append(f"INSERT INTO {table} (id) SELECT generate_series(1, 6);")
        for i in range(1, 7):
            s.append(
                f"UPDATE lp.orgs SET owner_id = {r.choice(self.users) if r.random() < 0.6 else 'NULL'} WHERE id = {i};"
            )
            for table, col, _ in self.tables.values():
                s.append(f"UPDATE {table} SET {col} = {self.maybe(list(range(1, 7)))} WHERE id = {i};")
            s.append(f"UPDATE lp.emails SET verified = {str(r.random() < 0.75).lower()} WHERE id = {i};")
        s += [f"SELECT setval(pg_get_serial_sequence('{table}', 'id'), 100);" for table, _, _ in self.tables.values()]
        return "\n".join(s)

    def grants(self) -> str:
        # one share in each state first (the decision ledger found no expired one in a run), then two drawn
        return "\n".join([*(self.grant(None, when) for when in self.WHEN), self.grant(), self.grant()])

    def grant(self, ids: Ids | None = None, when: tuple[str, str] | None = None) -> str:
        r = self.r
        expires, starts = when or r.choice(self.WHEN)
        settings = there(ids, "setting", 6)
        if not settings:
            return NOTHING
        sid = r.choice(settings)
        return (
            f"INSERT INTO authz.shares ({SHARE_COLUMNS}) VALUES ('setting', {sid}, 'admin', 'user', "
            f"{r.choice(self.users)}, '', {expires}, {starts}) ON CONFLICT DO NOTHING;"
        )

    def change(self, ids: Ids) -> str:
        r = self.r
        t = r.choice(list(self.tables))
        table, col, target = self.tables[t]
        mine, theirs = ints(ids, t) or [1], ints(ids, target)
        ops = [
            lambda: f"UPDATE {table} SET {col} = {self.maybe(theirs)} WHERE id = {r.choice(mine)};",
            lambda: f"UPDATE {table} SET {col} = {self.maybe(theirs)} WHERE id % 2 = {r.randint(0, 1)};",
            lambda: f"INSERT INTO {table} ({col}) VALUES ({self.maybe(theirs)});",
            lambda: f"DELETE FROM {table} WHERE id = {r.choice(mine)};",
            lambda: f"UPDATE {table} SET id = {max(mine) + r.randint(1, 50)} WHERE id = {r.choice(mine)};",
            lambda: (
                f"UPDATE lp.orgs SET owner_id = {r.choice(self.users + ['NULL'])} WHERE id = {r.choice(ints(ids, 'org') or [1])};"
            ),
            lambda: f"UPDATE lp.emails SET verified = NOT verified WHERE id = {r.choice(ints(ids, 'email') or [1])};",
            lambda: self.grant(ids),
            lambda: "DELETE FROM authz.shares WHERE object_type = 'setting' AND random() < 0.4;",
        ]
        if r.random() < 0.15:  # several changes in one transaction
            return "BEGIN;\n" + "\n".join(r.choice(ops)() for _ in range(r.randint(2, 4))) + "\nCOMMIT;"
        return r.choice(ops)()


class CrossGen(Gen):
    """tests/cross.authz: inheritance through two types at once, by every kind of link: a folder's column pair
    naming a folder or a project, a table placing projects in folders (whose rows stop counting when not active),
    and shares of a project with a folder. A condition that reads another table (cx.frozen) stops what editors pass
    down: rows put in it, taken out and truncated must change the inheritance at once. Loops close through the
    placements and the shares, which may loop; through the columns they are refused. Regions and sites hold each
    other through tables only, whose where is the only thing that stops them (and a relation with two sources,
    each naming another type). Shapes no other policy has: what is filed comes down through a relation whose
    types are partly inside the recursion and partly outside it, narrowed by a condition with a comment, dollar
    quotes and an E'' string in it; a type whose where reads another table (cx.closed); a region's chief named by
    a column and by shares; a region's guests, users or links, whose links whoever may share the region sees and
    only its chiefs turn off; a site's wardens, the chiefs of the region a column names; an update rule with an
    after rule on the whole row; notes, a table with rules and no select rule, whose `open` is conditions alone; a
    project's backers, folders or regions a table names with their type (one it doesn't know gives nothing); and a
    deny through each pair that names its rows' type (`not parent.file`, `not backer.fund`)."""

    policy = "tests/cross.authz"
    schema = "tests/cross_schema.sql"
    users: ClassVar[list[str]] = [str(i) for i in range(1, 7)]
    tokens: ClassVar[list[str]] = ["cx-a", "cx-b"]
    # the link tables whose rows count while active: what a steered link writes there
    columns: ClassVar[dict[str, dict[str, str]]] = {
        "cx.placements": {"active": "true"},
        "cx.site_links": {"active": "true"},
        "cx.site_regions": {"active": "true"},
    }
    # and a share that is a link of a tree, expiring, starting later or with a caveat: refused, as the docs say
    refusals: ClassVar[tuple[str, ...]] = (*Gen.refusals, "AZ605")

    def context(self, u: str) -> dict[str, str]:
        """Who presents which link's token: users 1 and 4 the first, 3 and 6 the second, 2 and 5 none, and nobody
        signed in the first."""
        i = self.users.index(u) if u else len(self.users)
        return {"links": ",".join(t for j, t in enumerate(self.tokens) if (i + j) % 3 == 0)}

    def maybe_user(self) -> str:
        return self.r.choice([*self.users, "NULL"])

    def initial(self) -> str:
        r = self.r
        s = ["INSERT INTO cx.users SELECT i, 'u' || i FROM generate_series(1, 6) i;"]
        s += [f"INSERT INTO cx.projects (id, lead_id) VALUES ({p}, {self.maybe_user()});" for p in range(1, 5)]
        for i in range(1, 11):
            # a folder sits in an earlier folder or in a project: no loop through the columns to begin with
            kind = r.choice(["folder", "project", None]) if i > 1 else r.choice(["project", None])
            parent = r.randint(1, i - 1) if kind == "folder" else r.randint(1, 4) if kind == "project" else None
            s.append(
                f"INSERT INTO cx.folders (id, parent_type, parent_id, owner_id, archived) VALUES ({i}, "
                f"{lit(kind) if kind else 'NULL'}, {parent or 'NULL'}, {self.maybe_user()}, {str(r.random() < 0.1).lower()});"
            )
        for _ in range(5):
            s.append(
                f"INSERT INTO cx.placements VALUES ({r.randint(1, 4)}, {r.randint(1, 10)}, "
                f"{str(r.random() < 0.8).lower()}) ON CONFLICT DO NOTHING;"
            )
        s += [f"INSERT INTO cx.frozen VALUES ({f}) ON CONFLICT DO NOTHING;" for f in r.sample(range(1, 11), 2)]
        s += [f"INSERT INTO cx.regions (id, chief_id) VALUES ({i}, {self.maybe_user()});" for i in range(1, 5)]
        s += [
            f"INSERT INTO cx.sites (id, region_id) VALUES ({i}, {r.choice(['1', '2', '3', '4', 'NULL'])});"
            for i in range(1, 5)
        ]
        s.append(f"INSERT INTO cx.closed VALUES ({r.randint(1, 4)});")
        s += [f"INSERT INTO cx.notes (id, author_id) VALUES ({i}, {self.maybe_user()});" for i in range(1, 5)]
        s += [f"{self.backing()} ON CONFLICT DO NOTHING;" for _ in range(6)]
        # whatever the draws give: a note nobody wrote (one the changes never touch), and a folder among the backers
        s += [
            "INSERT INTO cx.notes (id, author_id) VALUES (100, NULL);",
            "INSERT INTO cx.backings VALUES (1, 'folder', 2) ON CONFLICT DO NOTHING;",
        ]
        for _ in range(4):
            for table in ("site_links", "site_regions"):
                s.append(
                    f"INSERT INTO cx.{table} VALUES ({r.randint(1, 4)}, {r.randint(1, 4)}, "
                    f"{str(r.random() < 0.8).lower()}) ON CONFLICT DO NOTHING;"
                )
        s += [
            f"INSERT INTO cx.region_links VALUES ({r.randint(1, 4)}, {r.randint(1, 4)}) ON CONFLICT DO NOTHING;"
            for _ in range(2)
        ]
        s += [
            f"SELECT setval(pg_get_serial_sequence('cx.{t}', 'id'), 100);"
            for t in ("folders", "projects", "regions", "sites")
        ]
        return "\n".join(s)

    def steer(self, key: tuple[str | int, ...], ids: Ids) -> str | None:
        """What is filed comes down only to a folder nobody owns that sits in something, and few do: when no chain
        can be planned through those there are, a few folders that sit in something lose their owner, for the
        next try."""
        sql = super().steer(key, ids)
        if sql is not None or key[0] != "depth" or self.ledger is None:
            return sql
        if ("folder", "file") not in self.ledger.recursions[int(key[1])].names:
            return None
        return (
            "UPDATE cx.folders SET owner_id = NULL WHERE id IN (SELECT id FROM cx.folders "
            "WHERE parent_type IS NOT NULL ORDER BY random() LIMIT 4);"
        )

    def backing(self) -> str:
        """A project backed by a folder or a region (now and then by a type the policy doesn't name: nothing)."""
        r = self.r
        kind = r.choice(["folder", "folder", "region", "region", "desk"])
        return (
            f"INSERT INTO cx.backings VALUES ({r.randint(1, 4)}, {lit(kind)}, "
            f"{r.randint(1, 10) if kind == 'folder' else r.randint(1, 4)})"
        )

    def grants(self) -> str:
        # a link on each region to begin with: seen by whoever runs it, turned off only by its chiefs
        links = [
            f"INSERT INTO authz.shares VALUES ('region', {i}, 'guest', 'link', "
            f"encode(sha256(convert_to({lit(self.r.choice(self.tokens))}, 'UTF8')), 'hex'), '', NULL);"
            for i in range(1, 5)
        ]
        return "\n".join(links + [self.grant() for _ in range(10)])

    def grant(self, ids: Ids | None = None) -> str:
        r = self.r
        folders, projects, regions = there(ids, "folder", 10), there(ids, "project", 4), there(ids, "region", 4)
        if not (folders and projects and regions):
            return NOTHING
        if r.random() < 0.2:  # a region's chief by sharing, beside the one its column names
            return (
                f"INSERT INTO authz.shares VALUES ('region', {r.choice(regions)}, 'chief', 'user', "
                f"{r.choice(self.users)}, '', {r.choice(['NULL', EXPIRED])}) ON CONFLICT DO NOTHING;"
            )
        if r.random() < 0.2:  # a region's guest: a user, or a link (some present its token: context())
            token = lit(r.choice(self.tokens))
            kind, sid = r.choice(
                [("user", r.choice(self.users)), ("link", f"encode(sha256(convert_to({token}, 'UTF8')), 'hex')")]
            )
            return (
                f"INSERT INTO authz.shares VALUES ('region', {r.choice(regions)}, 'guest', '{kind}', {sid}, '', NULL) "
                "ON CONFLICT DO NOTHING;"
            )
        if r.random() < 0.5:  # a project shared with a folder: a link, which never expires
            return (
                f"INSERT INTO authz.shares VALUES ('project', {r.choice(projects)}, 'host', 'folder', "
                f"{r.choice(folders)}, '', NULL) ON CONFLICT DO NOTHING;"
            )
        expires, starts = r.choice(self.WHEN)
        return (
            f"INSERT INTO authz.shares ({SHARE_COLUMNS}) VALUES ('folder', {r.choice(folders)}, 'viewer', 'user', "
            f"{r.choice(self.users)}, '', {expires}, {starts}) ON CONFLICT DO NOTHING;"
        )

    def change(self, ids: Ids) -> str:
        r = self.r
        folders, projects = ints(ids, "folder") or [1], ints(ids, "project") or [1]
        f, g, p = r.choice(folders), r.choice(folders), r.choice(projects)
        parent = r.choice([f"'folder', {f}", f"'project', {p}", "NULL, NULL"])  # a new folder's (type, id)
        regions, sites = ints(ids, "region") or [1], ints(ids, "site") or [1]
        a, b, site = r.choice(regions), r.choice(regions), r.choice(sites)
        ops = [
            lambda: f"UPDATE cx.folders SET parent_type = 'folder', parent_id = {g} WHERE id = {f};",
            lambda: f"UPDATE cx.folders SET parent_type = 'project', parent_id = {p} WHERE id = {f};",
            lambda: f"UPDATE cx.folders SET parent_type = NULL, parent_id = NULL WHERE id = {f};",
            lambda: (
                f"UPDATE cx.folders SET parent_type = 'folder', parent_id = {g} WHERE id IN ({f}, {r.choice(folders)});"
            ),
            lambda: f"UPDATE cx.folders SET archived = NOT archived WHERE id = {f};",
            lambda: f"UPDATE cx.folders SET owner_id = {self.maybe_user()} WHERE id = {f};",
            lambda: f"UPDATE cx.projects SET lead_id = {self.maybe_user()} WHERE id = {p};",
            lambda: (
                f"INSERT INTO cx.folders (parent_type, parent_id, owner_id) VALUES ({parent}, {self.maybe_user()});"
            ),
            lambda: f"INSERT INTO cx.projects (lead_id) VALUES ({self.maybe_user()});",
            lambda: f"DELETE FROM cx.folders WHERE id = {f};",
            lambda: f"DELETE FROM cx.projects WHERE id = {p};",
            lambda: f"UPDATE cx.folders SET id = {max(folders) + r.randint(1, 50)} WHERE id = {f};",
            lambda: f"UPDATE cx.projects SET id = {max(projects) + r.randint(1, 50)} WHERE id = {p};",
            # the placements: a link table with a where
            lambda: (
                f"INSERT INTO cx.placements VALUES ({p}, {f}, {r.choice(['true', 'true', 'false'])}) ON CONFLICT DO NOTHING;"
            ),
            lambda: f"DELETE FROM cx.placements WHERE project_id = {p} OR folder_id = {f};",
            lambda: f"UPDATE cx.placements SET active = NOT active WHERE project_id = {p};",
            lambda: f"UPDATE cx.placements SET folder_id = {g} WHERE project_id = {p} AND folder_id = {f};",
            lambda: "TRUNCATE cx.placements;",
            # the table the condition reads
            lambda: f"INSERT INTO cx.frozen VALUES ({f}) ON CONFLICT DO NOTHING;",
            lambda: (
                f"INSERT INTO cx.frozen SELECT id FROM cx.folders WHERE id % 3 = {r.randint(0, 2)} ON CONFLICT DO NOTHING;"
            ),
            lambda: f"DELETE FROM cx.frozen WHERE folder_id = {r.choice(folders)};",
            lambda: f"UPDATE cx.frozen SET folder_id = {g} WHERE folder_id = {f};",
            lambda: "TRUNCATE cx.frozen;",
            # shares: links (project into folder), and viewers
            lambda: self.grant(ids),
            lambda: self.grant(ids),
            lambda: "DELETE FROM authz.shares WHERE relation = 'host' AND random() < 0.4;",
            lambda: f"DELETE FROM authz.shares WHERE object_type = 'folder' AND object_id = '{f}';",
            lambda: f"UPDATE authz.shares SET expires_at = {EXPIRED} WHERE relation = 'viewer' AND random() < 0.3;",
            lambda: (
                f"INSERT INTO authz.shares VALUES ('project', {p}, 'host', 'folder', {f}, '', {LATER});"
                if ints(ids, "project") and ints(ids, "folder")
                else NOTHING  # (see there())
            ),
            # regions and sites, through tables only
            lambda: (
                f"INSERT INTO cx.site_links VALUES ({a}, {site}, {r.choice(['true', 'false'])}) "
                "ON CONFLICT (region_id, site_id) DO UPDATE SET active = NOT cx.site_links.active;"
            ),
            lambda: f"INSERT INTO cx.site_regions VALUES ({site}, {a}, true) ON CONFLICT DO NOTHING;",
            lambda: f"UPDATE cx.site_regions SET active = NOT active WHERE site_id = {site};",
            lambda: f"INSERT INTO cx.region_links VALUES ({a}, {b}) ON CONFLICT DO NOTHING;",
            lambda: f"DELETE FROM cx.region_links WHERE region_id = {a} OR parent_id = {a};",
            lambda: (
                f"DELETE FROM cx.site_links WHERE site_id = {site}; DELETE FROM cx.site_regions WHERE region_id = {a};"
            ),
            lambda: f"UPDATE cx.regions SET chief_id = {self.maybe_user()} WHERE id = {a};",
            lambda: f"DELETE FROM cx.regions WHERE id = {a};",
            lambda: f"UPDATE cx.sites SET id = {max(sites) + r.randint(1, 50)} WHERE id = {site};",
            lambda: "INSERT INTO cx.sites DEFAULT VALUES;",
            # the closed sites, which the type's where reads
            lambda: f"INSERT INTO cx.closed VALUES ({site}) ON CONFLICT DO NOTHING;",
            lambda: f"DELETE FROM cx.closed WHERE site_id = {r.choice(sites)};",
            lambda: f"UPDATE cx.closed SET site_id = {r.choice(sites)} WHERE site_id = {site};",
            lambda: "TRUNCATE cx.closed;",
            # a region's chiefs by sharing, and the region whose chiefs are a site's wardens
            lambda: f"DELETE FROM authz.shares WHERE object_type = 'region' AND object_id = '{a}';",
            lambda: f"UPDATE cx.sites SET region_id = {r.choice([str(a), str(b), 'NULL'])} WHERE id = {site};",
            # a project's backers, folders or regions by a type column
            lambda: f"{self.backing()} ON CONFLICT DO NOTHING;",
            lambda: f"DELETE FROM cx.backings WHERE project_id = {p} OR backer_id = {f};",
            lambda: f"UPDATE cx.backings SET backer_type = 'region' WHERE backer_type = 'folder' AND backer_id = {a};",
            lambda: f"UPDATE cx.backings SET backer_id = {g} WHERE project_id = {p} AND backer_type = 'folder';",
            lambda: "TRUNCATE cx.backings;",
            # notes, which nobody may read back
            lambda: f"INSERT INTO cx.notes (author_id) VALUES ({self.maybe_user()});",
            lambda: f"UPDATE cx.notes SET author_id = {self.maybe_user()} WHERE id = {r.randint(1, 6)};",
            lambda: f"DELETE FROM cx.notes WHERE id = {r.randint(1, 6)};",
        ]
        if r.random() < 0.15:  # several changes in one transaction
            return "BEGIN;\n" + "\n".join(r.choice(ops)() for _ in range(r.randint(2, 4))) + "\nCOMMIT;"
        return r.choice(ops)()


GENERATORS: dict[str, type[Gen]] = {
    "docs": DocsGen,
    "alt": AltGen,
    "multi": MultiGen,
    "composite": CompositeGen,
    "loop": LoopGen,
    "cross": CrossGen,
}


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--db", default="authz_difftest")
    ap.add_argument("--gen", default="docs", choices=sorted(GENERATORS))
    ap.add_argument("--steps", type=int, default=100)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--quiet", action="store_true")
    ap.add_argument(
        "--decisions", action="store_true", help="and say which parts of the policy never decided an answer (a report)"
    )
    args = ap.parse_args()
    os.chdir(os.path.dirname(HERE))
    started = time.monotonic()

    rnd = random.Random(args.seed)
    sqlseed = random.Random(f"difftest/{args.seed}/sql")
    gen = GENERATORS[args.gen](rnd)
    db = DB(args.db)
    db.recreate()
    db.run(read(gen.schema))
    db.run(gen.initial())
    db.run(MAKE_SYNC_ROLE)
    text = synced(read(gen.policy), gen.policy, args.seed)
    compiled = compile_policy.Compiler(compile_policy.parse_policy(text, gen.policy)).compile(gen.policy)
    db.run(compiled)
    db.run(gen.grants())
    checker = Checker(db, gen.policy, gen, decisions=args.decisions, text=text)

    failures, refused, made = 0, 0, 0
    for step in range(args.steps + 1):
        problems = checker.check()
        if problems:
            failures += 1
            print(f"step {step}: {len(problems)} mismatch(es)")
            for p in problems[:12]:
                print("   ", p)
            if failures >= 3:
                break
        if step == args.steps:
            break
        ids: Ids = {
            t.name: [x[0] for x in db.rows(f"SELECT {idsql(t)} FROM {qt(t.table)} ORDER BY 1")]
            for t in checker.types.values()
        }
        # now and then a change aimed at parts of the policy that have decided no answer yet (with --decisions)
        sql = (gen.steered(ids) if checker.decisions is not None and gen.r.random() < STEER else None) or gen.change(
            ids
        )
        # (what a change draws with SQL's random() is the seed's too: a run can be made again)
        code, _, err = db.run(f"{CHANGE}SELECT setseed({sqlseed.random():.6f});\n{sql}", check=False)
        if code != 0:
            if gen.refused(err):
                refused += 1
            else:
                print(f"step {step + 1}: unexpected error\n  {sql}\n  {err.strip()}")
                failures += 1
        made += 1
        if not args.quiet:
            print(f"step {step + 1}: {'refused' if code else 'ok'}  {sql.splitlines()[0][:110]}")
    if refused > max(5, made // 2):  # (each generator has a tenth of its changes refused at most: 150 of each, seed 7)
        print(f"{refused} of {made} changes refused: more than half, so the run checked little")
        failures += 1
    print(
        f"{args.gen} seed {args.seed}: {args.steps} changes ({refused} refused as expected), "
        f"{'no mismatches' if not failures else f'{failures} failing step(s)'}"
    )
    if checker.decisions is not None:
        print("\n".join(checker.decisions.report(args.gen, of=time.monotonic() - started)))
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
