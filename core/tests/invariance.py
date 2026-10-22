#!/usr/bin/env python3
"""invariance: changes to a policy or its data that must change nothing.

    python3 tests/invariance.py --policies 4 --seed 1 [--db authz_invariance]
    python3 tests/invariance.py --fixed                  # the fixed policies' SQL alone (no database)

A policy written another way says the same, and data renumbered is the same data. So, for each random policy
(genpolicy's), with its random data and a few random changes to it:

  reordered     its declarations, its blocks, the lines of each block (relations and their sources, permissions,
                rules, invariants) and the operands of every `or` (and of every `and`, what a `not` takes away
                staying after what it takes from) in another order, written as they were (brackets kept)
  included      its blocks spread over files the policy includes, one of them included by another, from a
                folder below
  laid out      its expressions broken over lines, blank lines and comments between, then `rowstile fmt`
  renumbered    every key of each type replaced by another, by a shuffle (and the orgs of keys of two columns):
                in the app's rows, the link tables, the shares, the custom roles, the users who sign in; a
                condition that reads the next row reads it through the shuffle

For the first three the compiled policy must be the same, read back as objects as migrations read it
(migrate.read over authzlib/statements.py): the same functions, views, triggers, policies, tables and steps, each
made by the same SQL, but for these, which a policy written another way may change:

  - where things are written: the lines and the files of the policy's declarations (`line N`, in the rows of
    authz_gen.policy_lines and in the messages of the checks a migration runs)
  - the order things come in: statements and objects, a dispatch's CASE branches (types and permissions in the
    order the policy declares them), the rows of a VALUES list, an array's items, the parts of a UNION, the
    operands of an OR or an AND (the compiler keeps the written order among operands that cost the same,
    compiler.item_cost). An object is the same when its lines are the same in another order ('lines'), or its
    words and symbols ('tokens': then also the place an explanation gives each item, v[n], and a tree's hash,
    which is of its SQL)
  - names the compiler gives in the order it meets what they are for (NUMBERED, ON_TYPES): invariants
    (__never__N), a second tree of the same types and relations (__tree2), the types an arrow is followed to
    (__on_t2_t1), and a view of starting points two permissions share (named after the first the compiler meets:
    __direct). Objects so named are matched by what they make. A rule on columns isn't among them: Postgres fires
    a table's triggers in the order of their names, so its trigger is named after the rule's head

Then each is applied to the database, and its answers must be the policy's own, read the same way (answers()):
authz.list (whole, and in pages of two: each page after the last id of the one before, in key order), authz.can
on every row and one that isn't, authz.perms_of, the rows each select rule lets the app role read, the masked
views, authz.who, authz.explain_rule's verdict on an update and a delete, which rule on columns refuses an update
of every column they guard, where a table has two or more (the first trigger to refuse says why),
authz.check_invariants(), for every principal and nobody. For the renumbered data, in a database of its own, the
answers mapped back (but which rule refuses an update: a rule after the change judges the values set).

--fixed compiles the fixed policies (the example's and difftest's) reordered, included and laid out, and
compares their SQL alone.
"""

from __future__ import annotations

import argparse
import io
import json
import os
import random
import re
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable
from typing import Any

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, ROOT)
import difftest  # noqa: E402
from authzlib import Compiler, PolicyError, database, evaluate, fmt, migrate  # noqa: E402
from authzlib.parse import (  # noqa: E402
    Loc,
    Policy,
    Token,
    Type,
    cols,
    parse_policy,
    read_lines,
    tokenize,
)
from authzlib.sqlutil import q, qt  # noqa: E402
from difftest import DB, SESSIONS, Ids, idsql, lit  # noqa: E402
from genpolicy import INCLUDED as INCLUDED_BY_GENPOLICY  # noqa: E402
from genpolicy import UUID, Spec, Spelling, gen_class, make, policy_text, schema_text, write_policy  # noqa: E402

Answer = Any
Files = dict[str, str]

# ----------------------------------------------------------------------
# The policy written another way
# ----------------------------------------------------------------------
Block = list[str]  # a top-level line, then the lines of its block (stripped)


def blocks_of(text: str, files: Files) -> list[Block]:
    """The policy's logical lines (continuations joined, comments dropped, included files read in), by block."""
    out: list[Block] = []
    for _, indent, s in read_lines(None, text, files=files):
        if indent == 0 or not out:
            out.append([s])
        else:
            out[-1].append(s)
    return out


def render(blocks: list[Block]) -> str:
    return "".join(b[0] + "\n" + "".join(f"  {line}\n" for line in b[1:]) + "\n" for b in blocks)


def is_test(b: Block) -> bool:
    return b[0] == "test" or b[0].startswith("test ")


Nested = list["Token | Nested"]  # an expression's words, what brackets hold as a list


def shuffled_text(text: str, rank: Callable[[str], float]) -> str:
    """The expression with the operands of every `or` and `and` in another order (by rank, of each as written: two
    written alike stay alike, as the compiler checks an operand said twice once); in an `and`, what a `not` takes
    away stays after what it takes away from. Written as it was but for that order: its brackets kept, those that
    change nothing too (the parser reads `a or (b or c)` as `a or b or c`, and an explanation says it as written)."""
    stack: list[Nested] = [[]]
    for tok in tokenize(text, Loc(None, 0)):
        if tok.kind == "(":
            stack.append([])
        elif tok.kind == ")":
            inner = stack.pop()
            stack[-1].append(inner)
        else:
            stack[-1].append(tok)

    def say(items: Nested) -> str:
        """The words in order, each bracket's in another."""
        out: list[str] = []
        for x in items:
            out.append(f"({level(x)})" if isinstance(x, list) else "{" + x.text + "}" if x.kind == "cond" else x.text)
        return " ".join(out)

    def level(items: Nested) -> str:
        """One level of brackets: its `or`'s operands, else its `and`'s, in another order."""
        for word in ("or", "and"):
            parts: list[Nested] = [[]]
            for x in items:
                if isinstance(x, Token) and x.kind == word:
                    parts.append([])
                else:
                    parts[-1].append(x)
            if len(parts) > 1:
                said = sorted((say(p) for p in parts), key=rank)
                nots = [s for s in said if s.startswith("not ")] if word == "and" else []
                return f" {word} ".join([s for s in said if s not in nots] + nots)
        return say(items)

    return level(stack[0])


def ranks(r: random.Random) -> Callable[[str], float]:
    """A random rank for each text, the same each time it is asked."""
    seen: dict[str, float] = {}
    return lambda text: seen.setdefault(text, r.random())


def shuffled_line(line: str, block: str, rank: Callable[[str], float]) -> str:
    """A permission's or a rule's line with its expression's operands shuffled (any other line as it is)."""
    m = re.fullmatch(r"(can\s+\w+\s*=\s*)(.+)", line) if block.startswith("type ") else None
    if block.startswith("rules ") and not line.startswith("mask "):
        m = re.fullmatch(r"([^:{]+:\s*)(.+)", line)
    if not m:
        return line
    return m.group(1) + shuffled_text(m.group(2), rank)


def reordered(text: str, files: Files, r: random.Random) -> tuple[str, Files]:
    """The policy with its blocks, the lines in each and the operands of each expression in another order (tests
    stay last, as they were)."""
    blocks = blocks_of(text, files)
    tests = [b for b in blocks if is_test(b)]
    rest = [b for b in blocks if not is_test(b)]
    r.shuffle(rest)
    out: list[Block] = []
    rank = ranks(r)
    for b in rest:
        body = [shuffled_line(line, b[0], rank) for line in b[1:]]
        r.shuffle(body)
        out.append([b[0], *body])
    return render(out + tests), {}


INCLUDED = ("sub/part_a.authz", "sub/part_b.authz")


def included(text: str, files: Files, r: random.Random) -> tuple[str, Files]:
    """The policy's blocks spread over three files: the policy's own, sub/part_a.authz, which it includes, and
    sub/part_b.authz, which part_a includes as "part_b.authz" (a name relative to the file that includes it);
    each include line somewhere among the blocks."""
    blocks = blocks_of(text, files)
    tests = [b for b in blocks if is_test(b)]
    parts: list[list[Block]] = [[], [], []]
    for b in blocks:
        if not is_test(b):
            parts[r.randrange(3)].append(b)
    parts[0].insert(r.randint(0, len(parts[0])), ['include "sub/part_a.authz"'])
    parts[1].insert(r.randint(0, len(parts[1])), ['include "part_b.authz"'])
    return render(parts[0] + tests), {INCLUDED[0]: render(parts[1]), INCLUDED[1]: render(parts[2])}


def laid_out(text: str, files: Files, r: random.Random) -> tuple[str, Files]:
    """The policy laid out another way (its expressions broken over lines at an `or` or an `and`, indented as
    they come, blank lines and comments between), then formatted by `rowstile fmt`."""
    lines: list[str] = []
    for b in blocks_of(text, files):
        lines.append(b[0] + ("   -- " + "a comment" if r.random() < 0.2 else ""))
        for line in b[1:]:
            if r.random() < 0.2:
                lines.append("")
            if r.random() < 0.1:
                lines.append(" " * r.randint(0, 6) + "-- a comment")
            words = line.split(" ")
            out = " " * r.randint(1, 4) + words[0]
            depth = 0
            for w in words[1:]:
                depth += w.count("{") - w.count("}")
                if w in ("or", "and") and depth == 0 and r.random() < 0.3:
                    out += "\n" + " " * r.randint(3, 12) + w
                else:
                    out += " " + w
            lines.append(out)
        lines += [""] * r.randint(1, 2)
    messy = "\n".join(lines) + "\n"
    return fmt.format(messy, {}), {}


# ----------------------------------------------------------------------
# The compiled policy, as objects
# ----------------------------------------------------------------------
LINE = re.compile(r"\b(?:[\w./-]+\.authz )?line \d+\b")
TOKEN = re.compile(r"[A-Za-z_][A-Za-z0-9_$]*|\d+|<>|<=|>=|::|\S")
# names the compiler numbers in the order it meets what they are for: invariants and the trees of the same types
# and relations (a rule on columns, its functions and its trigger are named after its head: Postgres fires a
# table's triggers in the order of their names, so those must be the same)
NUMBERED = re.compile(r"(__never__)\d+|(__tree)\w*")
# what a body says by place, which follows the order of what it is about: the n-th item of an expression's
# explanation (v[n]), a tree's hash (of its SQL)
PLACES = re.compile(r"\bv\[\d+\]|'[0-9a-f]{32}'")


COMPILED: dict[str, str] = {}  # the SQL objects() compiled, by the policy's text and files


def objects(text: str, files: Files) -> dict[str, str]:
    """The compiled policy read back as migrations read it (migrate.read): each object, step and tree by its name,
    with the SQL that makes it, comments aside and line numbers (with the file they are in) as `line N`."""
    sql, c, _ = database.migratable(text, files)
    COMPILED[json.dumps([text, files])] = f"BEGIN;\n{sql}\nCOMMIT;\n"  # (as rowstile apply runs it)
    out: dict[str, str] = {}
    for it in c.items:
        if isinstance(it, migrate.Step):
            out[f"step {it.name}"] = migrate.code(it.sql)
        elif isinstance(it, migrate.Tree):
            out[f"tree {it.name}"] = "\n;\n".join(migrate.code(s) for o in it.objs for _, s in o.stmts)
    for o in c.objects():
        out[o.ident] = "\n;\n".join(migrate.code(s) for _, s in o.stmts)
    out = {k: LINE.sub("line N", v) for k, v in out.items()}
    # a view two permissions share (the starting points their own columns give, alike: compiler.direct_view) is
    # named after the first the compiler met: named here by what it holds
    for k, v in list(out.items()):
        m = re.fullmatch(r'view authz_int\."(\w+?)__(\w+)__direct"', k)
        if m:
            body = sorted(TOKEN.findall(v.split("\n", 1)[1]))  # (its union's parts in any order)
            alias = f"{m.group(1)}__{migrate.digest(' '.join(body), 8)}__direct"
            out = {
                kk.replace(f'"{m.group(1)}__{m.group(2)}__direct"', f'"{alias}"'): vv.replace(
                    f'"{m.group(1)}__{m.group(2)}__direct"', f'"{alias}"'
                )
                for kk, vv in out.items()
            }
    return out


# a view of an arrow followed to some of its relation's types names them in the order the relation's sources do
ON_TYPES = re.compile(r"__on_(\w+?)(?=__links\b|__ext\b|\")")


def unordered(text: str) -> str:
    """text with the names that follow the policy's order made the same whatever it is (NUMBERED, ON_TYPES)."""
    text = NUMBERED.sub(r"\1\2#", text)
    return ON_TYPES.sub(lambda m: "__on_" + "_".join(sorted(m.group(1).split("_"))), text)


def numbered(objs: dict[str, str]) -> dict[str, list[str]]:
    """The objects with their names, and the names in their SQL, unordered(): several may then have one name,
    whose SQL is compared as a set."""
    out: dict[str, list[str]] = {}
    for k, v in objs.items():
        out.setdefault(unordered(k), []).append(unordered(v))
    return {k: sorted(v) for k, v in out.items()}


def how_differs(a: str, b: str) -> str:
    """'' when the same; else 'lines' when the same lines in another order, 'tokens' when the same words and
    symbols in another order, 'more' when anything else differs."""
    if a == b:
        return ""
    if sorted(a.split("\n")) == sorted(b.split("\n")):
        return "lines"
    if sorted(TOKEN.findall(PLACES.sub("#", a))) == sorted(TOKEN.findall(PLACES.sub("#", b))):
        return "tokens"
    return "more"


def sql_differences(before: dict[str, str], after: dict[str, str]) -> tuple[list[str], dict[str, int]]:
    """The objects that differ beyond what the module's description says may (lines to print), and how many are
    the same or differ in each way it allows: 'lines' (in another order), 'tokens' (the same words in another
    order)."""
    a, b = numbered(before), numbered(after)
    problems: list[str] = []
    counts: dict[str, int] = {"same": 0, "lines": 0, "tokens": 0}
    for k in sorted(set(a) | set(b)):
        if len(a.get(k, [])) != len(b.get(k, [])):
            problems.append(f"{k}: made {len(a.get(k, []))} times before the change, {len(b.get(k, []))} after")
            continue
        left = list(b[k])
        for x in a[k]:
            # its match: the same, else the same but for order (a name numbered may have changed places)
            ways = [(("", "lines", "tokens", "more").index(how_differs(x, y)), j) for j, y in enumerate(left)]
            rank, j = min(ways)
            y = left.pop(j)
            if rank == 3:
                lx, ly = x.split("\n"), y.split("\n")
                problems.append(
                    f"{k}: differs: before {[z for z in lx if z not in ly][:2]}, after {[z for z in ly if z not in lx][:2]}"
                )
            else:
                counts[("same", "lines", "tokens")[rank]] += 1
    return problems, counts


# ----------------------------------------------------------------------
# The database's answers
# ----------------------------------------------------------------------
PAGE = 2  # authz.list's pages are read this long


# an update tried as the app role and undone: what refused it, else 'allowed' (made by answers(), as the owner)
TRY_UPDATE = """CREATE OR REPLACE FUNCTION public.invariance_try_update(p_sql text) RETURNS text LANGUAGE plpgsql AS $f$
BEGIN
  EXECUTE p_sql;
  RAISE EXCEPTION 'invariance: allowed';
EXCEPTION WHEN OTHERS THEN
  RETURN CASE WHEN SQLERRM = 'invariance: allowed' THEN 'allowed' ELSE SQLSTATE || ': ' || SQLERRM END;
END $f$;"""


def guarded(pol: Policy) -> dict[str, list[str]]:
    """The tables with two rules on columns or more, and every column those rules guard: an update of them all
    is refused by each rule that doesn't hold, and Postgres says the first one's words."""
    rules: dict[str, list[tuple[str, ...]]] = {}
    for r in pol.rules:
        if r.columns:
            rules.setdefault(r.table, []).append(r.columns)
    return {t: list(dict.fromkeys(c for cs in heads for c in cs)) for t, heads in rules.items() if len(heads) > 1}


def answers(
    db: DB,
    pol: Policy,
    users: list[str],
    context: Callable[[str], dict[str, str]],
    role: str,
    refusals: bool = True,
) -> Answers:
    """Every answer the policy gives on the data there, for each principal in users and nobody: keyed by what was
    asked, each the database's JSON. Read the same way each time (no sample, no order of the database's own), each
    principal's questions a block that leaves its session as it found it, the blocks in a few sessions side by
    side (difftest's SESSIONS). With refusals, also which rule on columns refuses an update of every column such
    rules guard, on each row of a table with two of them or more (guarded(); a rule after the change judges the
    values set, so data renumbered isn't asked it)."""
    blocks: list[list[str]] = []
    lines: list[str] = []
    tried = guarded(pol) if refusals else {}
    if tried:
        db.run(TRY_UPDATE)

    def emit(key: list[str], sql: str) -> None:
        lines.append(f"SELECT {lit(json.dumps(key))}, ({sql});")

    types = list(pol.types.values())
    rows = {t.name: f"SELECT {idsql(t)} FROM {qt(t.table)}" for t in types}
    public = {t.name: [p for p, x in t.perms.items() if not x.hidden] for t in types}
    for u in [*users, ""]:
        lines = []
        blocks.append(lines)
        kind, pid = evaluate.principal_of(u, pol.types)
        lines += [
            f"SET authz.user_id = {lit(pid)};",
            f"SET authz.principal_type = {lit('' if kind == 'user' else kind)};",
        ]
        lines += [f"SET authz_ctx.{k} = {lit(v)};" for k, v in context(u).items()]
        lines.append(f"SET ROLE {role};")
        for t in types:
            for p in public[t.name]:
                tp = f"{lit(t.name)}, {lit(p)}"
                emit([u, "list", t.name, p], f"SELECT coalesce(json_agg(x ORDER BY x), '[]') FROM authz.list({tp}) x")
                # in pages, each after the last id of the one before: every id once, in key order
                emit(
                    [u, "pages", t.name, p],
                    f"WITH RECURSIVE pages(n, page) AS (SELECT 1, ARRAY(SELECT x FROM authz.list({tp}, NULL, {PAGE}) x) "
                    f"UNION ALL SELECT n + 1, ARRAY(SELECT x FROM authz.list({tp}, page[{PAGE}], {PAGE}) x) "
                    f"FROM pages WHERE cardinality(page) = {PAGE} AND n < 1000) "
                    "SELECT coalesce(json_agg(x ORDER BY n, k), '[]') FROM pages, unnest(page) WITH ORDINALITY u(x, k)",
                )
                emit(
                    [u, "can", t.name, p],
                    f"SELECT coalesce(json_agg(json_build_array(i, authz.can({tp.replace(', ', ', i, ')}))), '[]') "
                    f"FROM ({rows[t.name]} UNION SELECT '999999') s(i)",
                )
            emit(
                [u, "perms_of", t.name],
                f"SELECT coalesce(json_agg(json_build_array(x.id, (SELECT array_agg(p ORDER BY p) FROM unnest(x.perms) "
                f"p))), '[]') FROM authz.perms_of({lit(t.name)}, ARRAY({rows[t.name]})) x",
            )
        for rule_table in dict.fromkeys(r.table for r in pol.rules if r.command == "select"):
            t = type_of_table(pol, rule_table)
            emit([u, "rls", t.name, rule_table], f"SELECT coalesce(json_agg({idsql(t)}), '[]') FROM {qt(rule_table)}")
        for rule_table, view in pol.views.items():
            t = type_of_table(pol, rule_table)
            emit([u, "view", t.name, rule_table], f"SELECT coalesce(json_agg({idsql(t)}), '[]') FROM {qt(view)}")
            for r in pol.rules:
                if r.table == rule_table and r.command == "mask":
                    for c in r.columns:
                        emit(
                            [u, "mask", t.name, rule_table, c],
                            f"SELECT coalesce(json_agg({idsql(t)}), '[]') FROM {qt(view)} WHERE {q(c)} IS NOT NULL",
                        )
        if pid:
            for rule_table in dict.fromkeys(r.table for r in pol.rules):
                t = type_of_table(pol, rule_table)
                for cmd in ("update", "delete"):
                    emit(
                        [u, "explain_rule", t.name, rule_table, cmd],
                        f"SELECT coalesce(json_agg(json_build_array(i, to_json(authz.explain_rule({lit(rule_table)}, "
                        f"{lit(cmd)}, i, NULL)))), '[]') FROM ({rows[t.name]}) s(i)",
                    )
        for rule_table, columns in tried.items() if pid else ():
            t = type_of_table(pol, rule_table)
            # each column set to NULL, or one that is NULL to the least value another row has
            sets = ", ".join(
                f"{q(c)} = CASE WHEN o.{q(c)} IS NULL THEN (SELECT x.{q(c)} FROM {qt(rule_table)} x "
                f"WHERE x.{q(c)} IS NOT NULL ORDER BY 1 LIMIT 1) END"
                for c in columns
            )
            update = f"UPDATE {qt(rule_table)} o SET {sets} WHERE {idsql(t, 'o')} = "
            emit(
                [u, "refused", t.name, rule_table],
                f"SELECT coalesce(json_agg(json_build_array(i, public.invariance_try_update({lit(update)} || "
                f"quote_literal(i)))), '[]') FROM ({rows[t.name]}) s(i)",
            )
        lines += ["RESET ROLE;", *[f"RESET authz_ctx.{k};" for k in context(u)]]
        lines += ["RESET authz.user_id;", "RESET authz.principal_type;"]
    lines = []
    blocks.append(lines)
    for t in types:
        for p in public[t.name]:
            emit(
                ["who", t.name, p],
                f"SELECT coalesce(json_agg(json_build_array(i, (SELECT coalesce(json_agg(x ORDER BY x), '[]') "
                f"FROM authz.who({lit(t.name)}, i, {lit(p)}) x))), '[]') FROM ({rows[t.name]}) s(i)",
            )
    if pol.invariants:
        emit(
            ["invariants"],
            "SELECT coalesce(json_agg(json_build_array(regexp_replace(invariant, ' \\([^()]*\\)$', ''), "
            "coalesce(user_id, ''), object_ids)), '[]') FROM authz.check_invariants()",
        )
    n = max(1, min(SESSIONS, len(blocks)))
    scripts = ["\n".join(line for block in blocks[i::n] for line in block) for i in range(n)]
    return {tuple(json.loads(k)): json.loads(v) for k, v in db.rows_together(scripts)}


Answers = dict[tuple[str, ...], Answer]


def type_of_table(pol: Policy, table: str) -> Type:
    return next(t for t in pol.types.values() if t.table == table)


def page_problems(got: Answers) -> list[str]:
    """authz.list in pages against authz.list whole: every id once (pages in another order than the cursor
    follows show as an id missed, or said twice)."""
    out: list[str] = []
    for key, pages in got.items():
        if len(key) > 1 and key[1] == "pages":
            whole = got[(key[0], "list", *key[2:])]
            if sorted(pages) != sorted(whole) or len(set(pages)) != len(pages):
                out.append(
                    f"{key[0] or '(nobody)'}: authz.list({key[2]}, {key[3]}) in pages of {PAGE} gives {pages}, whole {whole}"
                )
    return out


def verdicts(lines: list[str]) -> list[str]:
    """authz.explain_rule's lines on the rule and on each of its items (not those authz.explain adds under them,
    which name the first few rows a relation points at, in the order of their ids): each its verdict, then its
    words in an order of their own (where it is written aside, and what a {condition} says: on the data renumbered
    it reads the next row another way), so that only what each line says is compared."""
    out: list[str] = []
    for line in lines:
        indent = len(line) - len(line.lstrip())
        if indent <= 2:
            words = re.sub(r"\{[^{}]*\}", "{}", re.sub(r"\s+\([^()]*\)$", "", line)).split()
            out.append(" " * indent + " ".join(words[:1] + sorted(TOKEN.findall(" ".join(words[1:])))))
    return sorted(out)


def principal(u: str, back: Callable[[str, str], str]) -> str:
    """Who signs in ('3', 'bot:2', '' for nobody), as back maps ids."""
    kind, sep, pid = u.partition(":")
    return f"{kind}:{back(kind, pid)}" if sep else back("user", u) if u else u


def normal(key: tuple[str, ...], value: Answer, back: Callable[[str, str], str] | None = None) -> Answer:
    """An answer as compared: ids mapped back (back(type, id), renumbered data), and in an order of their own
    where the database's isn't the point (perms_of's lists, who's rows: the order of authz.list's pages is checked
    by page_problems)."""
    b = back or (lambda _t, i: i)
    kind = key[1] if key[0] not in ("who", "invariants") else key[0]
    if kind == "who":
        return sorted([b(key[1], i), sorted(b("user", x) for x in users)] for i, users in value)
    if kind == "invariants":  # (the first five ids each breaks it for, in the order of their text: five, if more)
        return sorted(
            [
                inv,
                principal(u, b),
                sorted(b(inv.split()[1].rstrip(":"), i) for i in ids) if len(ids) < 5 else 5,
            ]
            for inv, u, ids in value
        )
    t = key[2]
    if kind == "explain_rule":
        return sorted([b(t, i), verdicts(lines)] for i, lines in value)
    if kind == "refused":  # (which rule: its columns and table, not the row's key nor the rule as written)
        return sorted(
            [b(t, i), re.sub(r"^(42501: changing .+? of \S+) \S+ needs: .*", r"\1", said, flags=re.S)]
            for i, said in value
        )
    if kind in ("list", "pages", "rls", "view", "mask"):
        return sorted(b(t, i) for i in value)
    return sorted([b(t, i), v] for i, v in value)


# ----------------------------------------------------------------------
# The data renumbered
# ----------------------------------------------------------------------
def domain(t: Type, k: int) -> str:
    """Whose keys a key column's values are: its type's; where keys are composite, the columns before the last
    (genpolicy's org) are one domain across types, as an org's rows and the rows they point at share it."""
    return f"column {t.key[k][0]}" if t.composite and k < len(t.key) - 1 else t.name


def parts(t: Type, ident: str) -> list[str]:
    """A key's columns' values, from its text (a composite key's is the row's text, '(1,3)')."""
    return ident.strip("()").split(",") if t.composite else [ident]


Where = tuple[tuple[str, ...], Callable[[dict[str, Answer]], "Type | None"]]  # columns, and the type they name


class Renumbering:
    """A shuffle of every key of each type (and of genpolicy's orgs): new keys, drawn at random, of the key's own
    type (numbers of 1 to 5 digits; their text, or uuids made from them), in no order of the old ones."""

    def __init__(self, pol: Policy, r: random.Random) -> None:
        self.pol, self.r = pol, r
        self.new: dict[str, dict[str, str]] = {}  # domain -> old key -> new
        self.old: dict[str, dict[str, str]] = {}
        self.keytypes: dict[str, str] = {}
        for t in pol.types.values():
            for k, (_, kt) in enumerate(t.key):
                self.keytypes[domain(t, k)] = kt
        # the columns of each app table that hold keys, and of which type
        self.wheres: dict[str, list[Where]] = {}
        for t in pol.types.values():
            self.add(t.table, tuple(c for c, _ in t.key), lambda row, t=t: t)
            for rel in t.relations.values():
                for src in rel.sources:
                    subject = src.subjects[0][0] if src.subjects else ""
                    type_col = src.type_col if src.kind == "column" or src.kind == "table" else None
                    named = (
                        (lambda row, c=type_col: pol.types.get(str(row[c])))
                        if type_col
                        else (lambda row, s=subject: pol.types.get(s))
                    )
                    if src.kind == "column":
                        self.add(t.table, cols(src.column), named)
                    elif src.kind == "table":
                        self.add(src.table, cols(src.obj_col), lambda row, t=t: t)
                        self.add(src.table, cols(src.subj_col), named)

    def add(self, table: str, columns: tuple[str, ...], named: Callable[[dict[str, Answer]], Type | None]) -> None:
        self.wheres.setdefault(table, []).append((columns, named))

    def see(self, dom: str, value: str) -> None:
        self.new.setdefault(dom, {}).setdefault(value, "")

    def draw(self) -> None:
        """New keys for every key seen: distinct, of each domain's type."""
        for dom, keys in self.new.items():
            numbers: list[int] = []
            while len(numbers) < len(keys):  # (of 1 to 5 digits: their text in another order than their values)
                n = int(10 ** self.r.uniform(0, 5))
                numbers += [] if n in numbers else [n]
            kt = self.keytypes.get(dom, "bigint")
            for old, n in zip(sorted(keys), numbers, strict=True):
                keys[old] = UUID.format(n) if kt == "uuid" else str(n)
            self.old[dom] = {v: k for k, v in keys.items()}

    def ident(self, t: Type, ident: str, back: bool = False) -> str:
        """A key's text, renumbered (back: the old one again); an id no row of the data had stays as it is."""
        ps = parts(t, ident)
        table = self.old if back else self.new
        if len(ps) != len(t.key) or any(p not in table.get(domain(t, k), {}) for k, p in enumerate(ps)):
            return ident
        out = [table[domain(t, k)][p] for k, p in enumerate(ps)]
        return f"({','.join(out)})" if t.composite else out[0]

    def row(self, table: str, row: dict[str, Answer], seeing: bool) -> dict[str, Answer]:
        """A row of an app table, its keys renumbered (seeing: only noted, to be drawn)."""
        out = dict(row)
        for columns, named in self.wheres.get(table, []):
            t = named(row)
            if t is None or any(row.get(c) is None for c in columns):
                continue
            for k, c in enumerate(columns):
                if seeing:
                    self.see(domain(t, k), str(row[c]))
                else:
                    new = self.new[domain(t, k)][str(row[c])]
                    out[c] = int(new) if isinstance(row[c], int) else new
        return out

    def principal(self, u: str, back: bool = False) -> str:
        """Who signs in ('3', 'bot:2', '' for nobody), renumbered."""
        if not u:
            return u
        kind, pid = evaluate.principal_of(u, self.pol.types)
        new = self.ident(self.pol.types[kind], pid, back)
        return new if kind == "user" else f"{kind}:{new}"


APP_TABLES = "SELECT coalesce(json_agg(row_to_json(x)), '[]') FROM {} x"
AUTHZ_ROWS = ("authz.roles", "authz.role_permissions", "authz.shares")


def renumber_data(db: DB, pol: Policy, users: list[str], ren: Renumbering) -> dict[str, list[dict[str, Answer]]]:
    """The data of db (the app's tables, then the custom roles and the shares), every key renumbered: by table."""
    tables = list(dict.fromkeys(ren.wheres))
    data: dict[str, list[dict[str, Answer]]] = {}
    for table in [*tables, *AUTHZ_ROWS]:
        data[table] = json.loads(db.rows(APP_TABLES.format(qt(table) if table in tables else table))[0][0])
    types = pol.types

    def key_of(tname: str, ident: str, seeing: bool) -> str:
        t = types.get(tname)
        if t is None or ident in ("*", "") or tname == "link":
            return ident
        if seeing:
            for k, p in enumerate(parts(t, ident)):
                ren.see(domain(t, k), p)
            return ident
        return ren.ident(t, ident)

    for seeing in (True, False):
        if not seeing:
            ren.draw()
        out: dict[str, list[dict[str, Answer]]] = {}
        for table in tables:
            out[table] = [ren.row(table, row, seeing) for row in data[table]]
        out["authz.roles"] = [
            {**row, "owner_id": key_of(row["owner_type"], row["owner_id"], seeing)} for row in data["authz.roles"]
        ]
        out["authz.role_permissions"] = data["authz.role_permissions"]
        out["authz.shares"] = [
            {
                **row,
                "object_id": key_of(row["object_type"], row["object_id"], seeing),
                "subject_id": key_of(row["subject_type"], row["subject_id"], seeing),
            }
            for row in data["authz.shares"]
        ]
        for u in users:
            if u and seeing:
                kind, pid = evaluate.principal_of(u, types)
                key_of(kind, pid, True)
    return out


def load(db: DB, table: str, rows: list[dict[str, Answer]]) -> None:
    if rows:
        db.run(
            f"INSERT INTO {table} SELECT * FROM json_populate_recordset(NULL::{table}, $rows${json.dumps(rows)}$rows$);"
        )


# genpolicy's conditions that read the next row of t1 (READS: `this.id + 1`, or gp.nxt(this.id) where keys are text
# or uuids), spelled plainly or awkwardly: on renumbered data they read it through the shuffle (renum_next)
NEXT_ROW = re.compile(r'this\.(id|"Id") \+ 1|(?:gp|"Gp")\.nxt\(this\.(id|"Id")\)')


def through_shuffle(text: str, files: Files, pol: Policy) -> str:
    """The policy, its conditions that read the next row reading it through renum_next (and in one file)."""
    t1 = pol.types.get("t1")
    blocks = blocks_of(text, files)
    if t1 is None:
        return render(blocks)
    schema = q(t1.table.split(".")[0])
    for b in blocks:
        m = re.fullmatch(r"rules\s+(\S+).*", b[0])
        if m:
            tname = type_of_table(pol, m.group(1)).name

            def via(x: re.Match[str], tname: str = tname) -> str:
                return f"{schema}.renum_next({lit(tname)}, this.{x.group(1) or x.group(2)})"

            b[1:] = [NEXT_ROW.sub(via, line) for line in b[1:]]
    return render(blocks)


def renum_next_sql(pol: Policy, ren: Renumbering, spelling: Spelling) -> str:
    """renum_next(type, key): the new key of the row of t1 after the one whose old key is key's, in type's keys
    (one no row has, where there is none), for through_shuffle()."""
    t1 = pol.types.get("t1")
    if t1 is None:
        return ""
    kt = t1.key[-1][1]
    schema = q(t1.table.split(".")[0])
    rows: list[str] = []
    for t in pol.types.values():
        for old, new in ren.new.get(t.name, {}).items():
            succ = spelling.ident(spelling.number(old) + 1)  # (as genpolicy's gp.nxt: words too)
            nxt = ren.new.get("t1", {}).get(succ, UUID.format(0) if kt == "uuid" else "0")
            rows.append(f"({lit(t.name)}, {lit(new)}, {lit(nxt)})")
    values = ", ".join(rows) or "(NULL, NULL, NULL)"
    return (
        f"CREATE TABLE {schema}.renum_next (t text, k {kt}, n {kt});\n"
        f"INSERT INTO {schema}.renum_next SELECT t, k::{kt}, n::{kt} FROM (VALUES {values}) v(t, k, n);\n"
        f"GRANT SELECT ON {schema}.renum_next TO app_user;\n"
        f"CREATE FUNCTION {schema}.renum_next(p_t text, p_k {kt}) RETURNS {kt} LANGUAGE sql STABLE "
        f"AS $$SELECT n FROM {schema}.renum_next WHERE t = p_t AND k = p_k$$;\n"
    )


# ----------------------------------------------------------------------
# One policy
# ----------------------------------------------------------------------
class Skipped(Exception):
    """The compiler refuses the policy, or its reads are slow to plan (lint says so)."""


TRANSFORMS: dict[str, Callable[[str, Files, random.Random], tuple[str, Files]]] = {
    "reordered": reordered,
    "included": included,
    "laid out": laid_out,
}


def policy_files(spec: Spec, workdir: str) -> tuple[str, str, Files]:
    """The seed's policy as genpolicy writes it (in two files for some): its path, text and included files."""
    path = os.path.join(workdir, "gen.authz")
    write_policy(path, policy_text(spec), spec.include)
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    more = os.path.join(workdir, INCLUDED_BY_GENPOLICY)
    files: Files = {}
    if spec.include and os.path.exists(more):
        with open(more, encoding="utf-8") as fh:
            files[INCLUDED_BY_GENPOLICY] = fh.read()
        os.unlink(more)
    return path, text, files


def compiled(text: str, files: Files) -> str:
    """The policy's SQL, as applied: objects() compiled it already, or compiled now."""
    return COMPILED.get(json.dumps([text, files])) or Compiler(parse_policy(text, "gen.authz", files)).compile(
        "gen.authz"
    )


def differences(
    a: Answers, b: Answers, back: Callable[[str, str], str] | None = None, users: Callable[[str], str] | None = None
) -> list[str]:
    """Where two sets of answers differ (b's ids mapped back, b's principals by users), as lines to print."""
    mapped: Answers = {
        (users(k[0]) if users and k[0] not in ("who", "invariants") else k[0], *k[1:]): v for k, v in b.items()
    }
    out: list[str] = []
    for k in sorted(set(a) | set(mapped)):
        if k not in a or k not in mapped:
            out.append(f"{k}: asked only {'after' if k not in a else 'before'}")
            continue
        x, y = normal(k, a[k]), normal(k, mapped[k], back)
        if x != y:
            out.append(
                f"{' '.join(k[1:]) if k[0] else ' '.join(k)} for {k[0] or '(nobody)'}: {json.dumps(x)[:300]}, then {json.dumps(y)[:300]}"
            )
    return out


def check(spec: Spec, db: DB, db2: DB, steps: int, workdir: str) -> tuple[list[str], list[str]]:
    """(what passed, the problems) for the seed's policy and each change to it. Skipped if not checked."""
    path, text, files = policy_files(spec, workdir)
    try:
        base_objs = objects(text, files)
        base_sql = compiled(text, files)
    except PolicyError as e:
        raise Skipped(str(e)) from None
    except database.Error as e:  # (migratable() says the compiler's refusal so: "policy line N: ...")
        if not str(e).startswith("policy "):
            raise
        raise Skipped(str(e)) from None
    if "view definitions to plan" in base_sql:
        raise Skipped("authz.lint() warns that a permission or a select rule is slow to plan")
    r = random.Random(f"invariance/{spec.seed}")
    passed: list[str] = []
    problems: list[str] = []
    changed: list[tuple[str, str, Files]] = []
    for name, transform in TRANSFORMS.items():
        new_text, new_files = transform(text, files, r)
        try:
            diffs, counts = sql_differences(base_objs, objects(new_text, new_files))
        except PolicyError as e:
            problems.append(f"{name}: the compiler refuses it: {e}")
            continue
        if diffs:
            problems += [f"{name}: the compiled policy differs: {d}" for d in diffs[:8]]
            continue
        how = ", ".join(f"{n} {w}" for w, n in counts.items() if n)
        passed.append(f"{name}: the same SQL ({how})")
        changed.append((name, new_text, new_files))
    gen = gen_class(spec, path, os.path.join(workdir, "gen_schema.sql"))(random.Random(spec.seed))
    pol = parse_policy(text, path, files)
    db.recreate()
    db.run(schema_text(spec))
    db.run(gen.initial())
    db.run(base_sql)
    db.run(gen.grants())
    for _ in range(steps):
        ids: Ids = {
            t.name: [x[0] for x in db.rows(f"SELECT {idsql(t)} FROM {qt(t.table)} ORDER BY 1")]
            for t in pol.types.values()
        }
        sql = gen.change(ids)
        code, _, err = db.run(difftest.CHANGE + sql, check=False)
        if code != 0 and not gen.refused(err):
            return passed, [f"a random change failed: {sql}: {err.strip()}"]
    users = list(gen.users)
    base = answers(db, pol, users, gen.context, gen.role)
    own = page_problems(base)
    if own:
        return passed, [f"as written: {p}" for p in own[:8]]
    for name, new_text, new_files in changed:
        db.run(compiled(new_text, new_files))
        got = answers(db, pol, users, gen.context, gen.role)
        diffs = differences(base, got) + page_problems(got)
        if diffs:
            problems += [f"{name}: {d}" for d in diffs[:8]]
        else:
            passed.append(f"{name}: the same answers ({len(base)} questions)")
    # renumbered, in a database of its own
    ren = Renumbering(pol, r)
    data = renumber_data(db, pol, users, ren)
    new_users = [ren.principal(u) for u in users]
    contexts = {ren.principal(u): gen.context(u) for u in [*users, ""]}
    db2.recreate()
    db2.run(schema_text(spec))
    db2.run(renum_next_sql(pol, ren, spec.spelling))
    for table in ren.wheres:
        load(db2, qt(table), data[table])
    db2.run(compiled(through_shuffle(text, files, pol), {}))
    for table in AUTHZ_ROWS:
        load(db2, table, data[table])
    db2.run("SELECT setval(pg_get_serial_sequence('authz.roles', 'id'), 100);")
    got = answers(db2, pol, new_users, lambda u: contexts[u], gen.role, refusals=False)
    back = lambda tname, i: ren.ident(pol.types[tname], i, back=True) if tname in pol.types else i
    asked = {k: v for k, v in base.items() if k[1:2] != ("refused",)}
    diffs = differences(asked, got, back, lambda u: ren.principal(u, back=True)) + page_problems(got)
    if diffs:
        problems += [f"renumbered: {d}" for d in diffs[:8]]
    else:
        passed.append(f"renumbered: the same answers ({len(base)} questions)")
    return passed, problems


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--db", default="", help="the database (and DB_renumbered); --fixed without it: no database")
    ap.add_argument("--policies", type=int, default=4)
    ap.add_argument("--seed", type=int, default=1, help="the first policy's seed (each policy: the next one)")
    ap.add_argument("--only", type=int, help="run this one seed, and print its policy")
    ap.add_argument("--steps", type=int, default=3, help="random changes to the data before it is asked")
    ap.add_argument("--fixed", action="store_true", help="the fixed policies instead (their SQL; with --db, answers)")
    ap.add_argument("--ways", type=int, default=1, help="--fixed: each policy written each way this many times")
    args = ap.parse_args()
    os.chdir(ROOT)
    if isinstance(sys.stdout, io.TextIOWrapper):
        sys.stdout.reconfigure(line_buffering=True)  # (each line as it comes, in a log too)
    if args.fixed:
        fixed_db = DB(args.db) if args.db else None
        code = fixed(args.ways, fixed_db, args.steps)
        if fixed_db is not None:
            subprocess.run(["dropdb", "--if-exists", fixed_db.name], capture_output=True)
        sys.exit(code)
    db, db2 = DB(args.db or "authz_invariance"), DB((args.db or "authz_invariance") + "_renumbered")
    seeds = [args.only] if args.only is not None else list(range(args.seed, args.seed + args.policies))
    failed = checked = skipped = 0
    started = time.monotonic()
    with tempfile.TemporaryDirectory() as workdir:
        for seed in seeds:
            spec = make(seed)
            if args.only is not None:
                print(f"seed {seed}:\n{policy_text(spec)}")
            try:
                passed, problems = check(spec, db, db2, args.steps, workdir)
            except Skipped as e:
                skipped += 1
                print(f"seed {seed}: not checked ({str(e)[:100]})")
                continue
            checked += 1
            for p in passed:
                print(f"ok seed {seed}, {p}")
            if problems:
                failed += 1
                print(f"FAIL seed {seed}:")
                for p in problems:
                    print(f"    {p}")
    for d in (db, db2):
        subprocess.run(["dropdb", "--if-exists", d.name], capture_output=True)
    print(
        f"invariance seeds {seeds[0]}..{seeds[-1]}: {checked - failed} policies passed, {failed} failed, "
        f"{skipped} not checked (refused, or slow to plan) ({time.monotonic() - started:.0f} s)"
    )
    sys.exit(1 if failed else 0)


FIXED = [
    "example/docs.authz",
    *(f"tests/{n}.authz" for n in ("alt", "multi", "composite", "loop", "cross", "children", "patterns", "prisma")),
]


def fixed(ways: int, db: DB | None, steps: int) -> int:
    """The fixed policies, each written another way `ways` times per change: the same SQL. With db, those
    difftest has data for (its generators) are also asked, as written and written each way once, on the data its
    generator makes and changes `steps` times: the same answers."""
    failed = 0
    for path in FIXED:
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
        base = objects(text, {})
        changed: list[tuple[str, str, Files]] = []
        for name, transform in TRANSFORMS.items():
            for k in range(ways):
                new_text, new_files = transform(text, {}, random.Random(f"invariance/{path}/{k}"))
                diffs, counts = sql_differences(base, objects(new_text, new_files))
                if diffs:
                    failed += 1
                    print(f"FAIL {path}, {name} ({k + 1}): the compiled policy differs")
                    for d in diffs[:8]:
                        print(f"    {d}")
                    continue
                how = ", ".join(f"{n} {w}" for w, n in counts.items() if n)
                print(f"ok {path}, {name} ({k + 1}): the same SQL ({how})")
                if k == 0:
                    changed.append((name, new_text, new_files))
        gens = [g for g in difftest.GENERATORS.values() if g.policy == path]
        if db is None or not gens:
            continue
        gen = gens[0](random.Random(f"invariance/{path}"))
        pol = parse_policy(text, path, {})
        db.recreate()
        db.run(difftest.read(gen.schema))
        db.run(gen.initial())
        db.run(compiled(text, {}))
        db.run(gen.grants())
        for _ in range(steps):
            ids: Ids = {
                t.name: [x[0] for x in db.rows(f"SELECT {idsql(t)} FROM {qt(t.table)} ORDER BY 1")]
                for t in pol.types.values()
            }
            db.run(gen.change(ids), check=False)  # (one refused changes nothing)
        users = list(gen.users)
        answered = answers(db, pol, users, gen.context, gen.role)
        own = page_problems(answered)
        for name, new_text, new_files in changed:
            db.run(compiled(new_text, new_files))
            got = answers(db, pol, users, gen.context, gen.role)
            diffs = own + differences(answered, got) + page_problems(got)
            if diffs:
                failed += 1
                print(f"FAIL {path}, {name}: other answers")
                for d in diffs[:8]:
                    print(f"    {d}")
            else:
                print(f"ok {path}, {name}: the same answers ({len(answered)} questions)")
    return 1 if failed else 0


if __name__ == "__main__":
    main()
