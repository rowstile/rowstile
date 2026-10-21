#!/usr/bin/env python3
"""unit_test: fast checks that need no database: the generated SQL against golden files, included
files, what the rowstile command runs against a database, its file reading, and the version.

    python3 tests/unit_test.py            # a few seconds; runs anywhere Python 3.9+ does
    python3 tests/unit_test.py --update   # after an intended change to the generated SQL: rewrite
                                          # tests/golden/*.sql, then read the diff before committing
"""

import collections
import dataclasses
import fnmatch
import glob
import io
import itertools
import json
import os
import random
import re
import socket
import subprocess
import sys
import tempfile
import textwrap
import threading
import types
import unittest
from collections.abc import Callable, Iterable, Sequence
from decimal import Decimal
from typing import ClassVar, Protocol, cast
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "cli"))
import authzlib  # noqa: E402
import rowstile_cli  # noqa: E402
from authzlib import (  # noqa: E402
    Compiler,
    PolicyError,
    database,
    draft,
    evaluate,
    parse,
    parse_policy,
    statements,
)
from authzlib.compiler import strongly_connected  # noqa: E402
from authzlib.conditions import Scalar  # noqa: E402
from authzlib.connection import Row, Value  # noqa: E402
from authzlib.review import Group, Review  # noqa: E402
from authzlib.versions import STAGES, VERSION, pypi, spelled, stage  # noqa: E402

sys.path.insert(0, os.path.join(ROOT, "tests"))
import around  # noqa: E402
import decisions  # noqa: E402
import features  # noqa: E402
import genpolicy  # noqa: E402

sys.path.insert(0, os.path.join(ROOT, "mutants"))
import mutants  # noqa: E402
import plan as sweep_plan  # noqa: E402
import sweep  # noqa: E402

GOLDEN = os.path.join(ROOT, "tests", "golden")
UPDATE = "--update" in sys.argv
POLICIES = {
    "docs": "example/docs.authz",
    "alt": "tests/alt.authz",
    "multi": "tests/multi.authz",
    "composite": "tests/composite.authz",
    "loop": "tests/loop.authz",
    "cross": "tests/cross.authz",
}


def read(rel: str) -> str:
    with open(os.path.join(ROOT, rel), encoding="utf-8") as fh:
        return fh.read()


def errors_prelude() -> str:
    """`app role` and the user type: what a small policy in a test starts with."""
    from authzlib.errors import PRELUDE

    return PRELUDE


def compiled(name: str, transaction: bool = True) -> str:
    return Compiler(parse_policy(read(POLICIES[name]), POLICIES[name])).compile(POLICIES[name], transaction)


def search(pattern: str, text: str, flags: int = 0) -> re.Match[str]:
    m = re.search(pattern, text, flags)
    assert m is not None, f"{pattern!r} is not in the text"
    return m


class KeyTypeChecks(unittest.TestCase):
    """pg_input_is_valid(text, type name) is given the type by a literal or a subquery, never a PL/pgSQL variable:
    Postgres keeps the type it looked up for the first value of a variable there, for each later call from the same
    line, so a function that checks a bigint key and then a uuid key in one transaction finds the uuid invalid
    (authz.break_glass refused a support user of an app whose users have uuid keys and folders bigint ones)."""

    def test_no_type_comes_from_a_variable(self) -> None:
        for name in POLICIES:
            for m in re.finditer(r"pg_input_is_valid\(([^()]|\([^()]*\))*?,\s*(\w+)\s*\)", compiled(name)):
                self.assertFalse(m.group(2).startswith(("v_", "p_")), f"{name}: {m.group(0)}")

    def test_the_rule_finds_a_variable(self) -> None:
        sql = "IF NOT pg_catalog.pg_input_is_valid(p_id, v_keytype) THEN"
        m = re.search(r"pg_input_is_valid\(([^()]|\([^()]*\))*?,\s*(\w+)\s*\)", sql)
        self.assertIsNotNone(m)
        assert m is not None
        self.assertEqual(m.group(2), "v_keytype")


class ThisRow(unittest.TestCase):
    """`this.` in a condition is the alias its row has where the condition is placed: views, row checks, row-level
    security, triggers, trees and the migrations that build them beside. None is left in the SQL."""

    @staticmethod
    def code(sql: str) -> str:
        """The SQL without comments, string literals and quoted names (function bodies stay: they are code)."""
        out: list[str] = []
        i, n = 0, len(sql)
        while i < n:
            if sql.startswith("--", i):
                j = sql.find("\n", i)
                i = n if j < 0 else j
            elif sql.startswith("/*", i):
                j = sql.find("*/", i + 2)
                i = n if j < 0 else j + 2
            elif sql[i] == "'":
                escapes, j = i > 0 and sql[i - 1] in "eE", i + 1
                while j < n and not (sql[j] == "'" and sql[j + 1 : j + 2] != "'"):
                    j += 2 if (escapes and sql[j] == "\\") or sql[j : j + 2] == "''" else 1
                out.append(" ")
                i = j + 1
            elif sql[i] == '"':
                j = sql.find('"', i + 1)
                out.append(" ")
                i = n if j < 0 else j + 1
            else:
                out.append(sql[i])
                i += 1
        return "".join(out)

    def left(self, sql: str) -> list[str]:
        from authzlib.sqlutil import THIS

        text = self.code(sql)
        return [text[max(0, m.start() - 60) : m.end() + 20] for m in THIS.finditer(text)]

    def test_no_this_is_left_in_the_sql(self) -> None:
        for name in ("alt", "multi", "composite"):
            text = read(POLICIES[name])
            self.assertIn("this.", text, name)
            c = Compiler(parse_policy(text, POLICIES[name]))
            sql = c.compile(POLICIES[name]) + c.tests_function_sql()
            sql += "".join(n["build"] + n["catch_up"] for n in c.tree_next.values())
            self.assertEqual(self.left(sql), [], name)

    def test_the_rewrite(self) -> None:
        from authzlib.sqlutil import names_this, on_row, this_alone

        self.assertEqual(
            on_row("exists (select 1 from app.m m where m.p = this.id and 'this.x' = m.y)", "r"),
            "exists (select 1 from app.m m where m.p = r.id and 'this.x' = m.y)",
        )
        self.assertEqual(
            on_row("this.\"Name\" = $$this.x$$ /* this.y */ and E'a\\'s this.z' = THIS . w", '"files"'),
            '"files"."Name" = $$this.x$$ /* this.y */ and E\'a\\\'s this.z\' = "files".w',
        )
        self.assertEqual(on_row("t.this.x = xthis.y", "r"), "t.this.x = xthis.y")
        # inside $$...$$, past its first word: text, not the row (right after $$, the pattern's own look-behind skips it)
        self.assertEqual(on_row("this.a = $$see this.x$$", "r"), "r.a = $$see this.x$$")
        # a doubled quote doesn't end the text it is in (before an escaped one, in an E'' string; in a quoted name),
        # and a quote never closed runs to the end
        self.assertEqual(on_row("x = E'it''s \\' this.y' and this.z", "r"), "x = E'it''s \\' this.y' and r.z")
        self.assertEqual(on_row('"a""this".x = this.z', "r"), '"a""this".x = r.z')
        self.assertEqual(on_row("this.z = 'it''s this.y", "r"), "r.z = 'it''s this.y")
        # a query of the condition's own that may call a table by the row's alias: this. reads the row's columns
        # first, under a name no condition writes (AZ113); a mention in a string, or no query, changes nothing
        self.assertEqual(
            on_row('exists (select 1 from app.m r where r.p = this.id and r.q = this."Q" and r.z = this.id)', "r"),
            '(SELECT (exists (select 1 from app.m r where r.p = authz__this.id and r.q = authz__this."Q" and '
            'r.z = authz__this.id)) FROM (SELECT r.id, r."Q") AS authz__this)',
        )
        self.assertEqual(
            on_row("not exists (select 1 from app.folders where parent_id = this.id)", '"folders"'),
            "(SELECT (not exists (select 1 from app.folders where parent_id = authz__this.id)) "
            'FROM (SELECT "folders".id) AS authz__this)',
        )
        self.assertEqual(
            on_row('exists (select 1 from app.m "O" where "O".p = this.id)', "o"),
            '(SELECT (exists (select 1 from app.m "O" where "O".p = authz__this.id)) FROM (SELECT o.id) AS authz__this)',
        )
        self.assertEqual(
            on_row("exists (select 1 from app.m m where m.p = this.id and m.k = 'r')", "r"),
            "exists (select 1 from app.m m where m.p = r.id and m.k = 'r')",
        )
        self.assertEqual(on_row("r(this.id)", "r"), "r(r.id)")
        # a condition that starts with a quote is no E'' string, whatever letter it ends with
        self.assertEqual(on_row("'\\' <> this.name or true", "r"), "'\\' <> r.name or true")
        self.assertTrue(names_this("this.a = 1") and not names_this("'this.a' = x"))
        self.assertTrue(this_alone("exists (select 1 from app.t this where this.x)") and not this_alone("this.x"))

    def test_what_reads_more_than_its_row(self) -> None:
        """A condition that may read other rows runs with the policy's rights where the app role checks it: a
        function of the app's, however its name is written or as an operator, reads more; built-ins don't."""
        from authzlib.sqlutil import operators, reads_more

        for sql in (
            "app.member(this.id)",
            'app."Member"(this.id)',
            '"app".member(this.id)',
            '"member"(this.id)',
            'app . "Member" /* c */ (this.id)',
            "member /* c */ (id)",
            "exists (select 1 from app.t)",
            "lower(name) = app.f('x')",
            "=!= this.id",
            "id OPERATOR(app.===) 3",
            "a <=> b",
            "a ||- 1",
        ):
            self.assertTrue(reads_more(sql), sql)
        for sql in (
            "not archived",
            "lower(name) = 'f(x)'",
            "authz.uid() = owner_id",
            '"Owner" = authz.uid()',
            "coalesce(n, 0) > 1 /* f(x) */",
            "id in (1, 2)",
            "$$g(x)$$ = name",
            "n<>-1 and n*-2<=+3",
            "tags @> array['a'] and data->>'k' ~* '^x' and name || 'a' !~~ 'b%'",
            "'=!=' = name",
        ):
            self.assertFalse(reads_more(sql), sql)
        self.assertEqual(operators("a=-1 and b<=+-2 and c@-3"), ["=", "-", "<=", "+", "-", "@-"])

    def test_a_condition_is_read_as_postgres_reads_its_quotes(self) -> None:
        """An apostrophe inside E'...', $$...$$, a quoted name or a comment ends nothing: the subquery after it is
        code. Read as a quote's end, it would pair with the next quote and hide the subquery, and a rule would then
        run the condition with the app role's rights."""
        from authzlib.parse import Loc, PolicyError
        from authzlib.sqlutil import check_stable_condition, on_row, reads_more, reads_tables, sql_code

        sub = "not exists (select 1 from app.blocks b where b.kind = 'mute')"
        for before in (
            "title <> E'don\\'t'",
            "title <> e'\\\\' and x <> 'y'",
            "title <> $$it's$$",
            "title <> $q$it's$q$",
            '"o\'neil"',
            "x /* it's /* nested */ ' */ = 1",
            "x = 1 -- it's\n",
            "x <> name'a\\'",
        ):
            sql = f"{before} and {sub}"
            self.assertEqual((reads_tables(sql), reads_more(sql)), (True, True), sql)
        # $ goes on a name: a$$x and b$$y are columns, not a dollar quote around the subquery
        self.assertTrue(reads_tables(f"a$$x = 1 and {sub} and b$$y = 2"))
        self.assertEqual(
            on_row("title <> E'don\\'t' and exists (select 1 from app.d d where d.p = this.id)", "d"),
            "(SELECT (title <> E'don\\'t' and exists (select 1 from app.d d where d.p = authz__this.id)) "
            "FROM (SELECT d.id) AS authz__this)",
        )
        # a name or a number is read whole: the'x' is a name then a literal, 1$$y$$ a number then a $$ string
        self.assertEqual(
            sql_code('the\'x\' = 1$$y$$ and "a""b"'),
            [(True, "the"), (False, "'x'"), (True, " = 1"), (False, "$$y$$"), (True, " and "), (False, '"a""b"')],
        )
        for cond in (
            "x = $$'$$ and y = 'a' and created < now() and z = 'b'",
            "x = E'\\'' and created < now() and z = 'b'",
            "\"o'neil\" and created < now() and z = 'b'",
            "created < $$ Today $$::date",
        ):
            with self.assertRaisesRegex(PolicyError, "can't limit inheritance: .* the same answer", msg=cond):
                check_stable_condition(cond, Loc(None, 1))
        for cond in ("x = $$now()$$", "x = 'nowhere' and \"now\" = 1"):
            check_stable_condition(cond, Loc(None, 1))

    def test_names_past_ascii(self) -> None:
        """Postgres takes any character past ASCII as a letter in a name, and folds only ASCII letters to lower case:
        a function so named is a call, which may read other rows; `this.` goes before such a column; a bare one is
        a column, read whole."""
        from authzlib.conditions import tokens
        from authzlib.database import BARE
        from authzlib.parse import Loc, PolicyError
        from authzlib.sqlutil import (
            check_stable_condition,
            fold,
            names_in,
            on_row,
            reads_more,
            reads_tables,
            this_alone,
            this_spans,
        )

        for sql in ("not app.muté(this.owner_id)", "muté(id)", "ma\u212ae_date(1, 2, 3) > x", "f$x(1)"):
            self.assertTrue(reads_more(sql), sql)
        self.assertFalse(reads_more("not archivé and make_date(année, 1, 1) > x"))
        self.assertEqual((fold("ARCHIVÉ"), fold("MA\u212aE")), ("archivÉ", "ma\u212ae"))
        self.assertEqual(on_row("this.étage > 1", "r"), "r.étage > 1")
        self.assertEqual(
            on_row("exists (select 1 from app.d d where d.p = this.archivé)", "d"),
            "(SELECT (exists (select 1 from app.d d where d.p = authz__this.archivé)) FROM (SELECT d.archivé) AS authz__this)",
        )
        self.assertEqual(this_spans("→this.x = 1"), [])  # →this is a name: x is that table's
        self.assertFalse(this_alone("→this = 1") or this_alone("this→ = 1"))
        self.assertEqual(names_in("archivé and année"), {"archivé", "and", "année"})
        self.assertEqual(
            [m.group(1) for m in BARE.finditer("archivé and d.é or é(1) > année")], ["archivé", "and", "or", "année"]
        )
        self.assertEqual(
            tokens("not ARCHIVÉ and this.année > 1"),
            [("word", "not"), ("name", "archivÉ"), ("word", "and"), ("name", "année"), ("op", ">"), ("num", "1")],
        )
        # what reads another table, or changes with time, after names and a dollar quote past ASCII
        self.assertTrue(reads_tables("titré$$ <> $é$it's$é$ and exists (select 1 from app.t)"))
        with self.assertRaisesRegex(PolicyError, "it depends on now"):
            check_stable_condition("titré$$ <> $é$it's$é$ and créé > now()", Loc(None, 1))

    def test_rewrites_touch_only_the_conditions_code(self) -> None:
        """authz.uid() is asked once per query only where the condition calls it: a string or a comment that names
        it stays as written. A column `this.` names in two cases is one column, as Postgres folds names: taken
        twice where the row's columns are taken first, the condition's name for it would be ambiguous."""
        from authzlib.sqlutil import on_row, with_uid

        self.assertEqual(
            with_uid("note <> 'set by authz.uid()' and owner_id = authz.uid() /* authz.uid() */"),
            "note <> 'set by authz.uid()' and owner_id = (SELECT authz.uid()) /* authz.uid() */",
        )
        self.assertEqual(
            with_uid('x = $$authz.uid()$$ and "authz.uid()" = 1'), 'x = $$authz.uid()$$ and "authz.uid()" = 1'
        )
        self.assertEqual(
            on_row('exists (select 1 from app.m o where o.r = this.ID and o.s = this.id and o.t = this."id")', "o"),
            "(SELECT (exists (select 1 from app.m o where o.r = authz__this.ID and o.s = authz__this.id and "
            'o.t = authz__this."id")) FROM (SELECT o.ID) AS authz__this)',
        )
        # a quoted name in capitals is another column, and only ASCII letters fold (É is not é)
        self.assertEqual(
            on_row('exists (select 1 from app.m o where o.r = this."ID" and o.s = this.id and this.É = this.é)', "o"),
            '(SELECT (exists (select 1 from app.m o where o.r = authz__this."ID" and o.s = authz__this.id and '
            'authz__this.É = authz__this.é)) FROM (SELECT o."ID", o.id, o.É, o.é) AS authz__this)',
        )
        # text no policy gets past the parser with (a quoted name left open, a call with no closing parenthesis):
        # read without a failure all the same
        from authzlib.sqlutil import one_argument

        self.assertEqual(on_row('this."open', "d"), 'd."open')
        self.assertEqual((one_argument("x", 0), one_argument("x, y", 0), one_argument("(x, y", 0)), (True, False, True))

    def test_what_inheritance_cant_read_is_named_where_it_is_refused(self) -> None:
        """The language's reference and AZ305's page name what a condition that limits inheritance can't read, and
        the check refuses each, as the page writes it, and nothing else: no name of its own is missing there."""
        from authzlib.errors import CODES
        from authzlib.parse import Loc, PolicyError
        from authzlib.sqlutil import TIME_WORDS, UNSTABLE_CALLS, UNSTABLE_WORDS, check_stable_condition

        with open(os.path.join(os.path.dirname(ROOT), "docs", "reference", "language.md"), encoding="utf-8") as fh:
            page = " ".join(line.strip() for line in fh)
        listed = {
            "the language's reference": re.search(r"It can't read the clock (.*?) is refused \(AZ305\)", page),
            "AZ305's page": re.search(r"They can't read the clock (.*?)and a link table", CODES["AZ305"].text),
        }
        code = {*UNSTABLE_CALLS, *UNSTABLE_WORDS, "age", "now", "today", "tomorrow", "yesterday"}
        for where, found in listed.items():
            assert found, where
            written = re.findall(r"`([^`]+)`", found.group(1))
            names = {re.sub(r"\(.*", "", w).strip("'") for w in written}
            self.assertEqual(names, code, where)
            for w in written:
                cond = f"x = {w}" if w.startswith("'") else f"{w} = x"
                with self.assertRaisesRegex(PolicyError, "AZ305", msg=f"{where}: {w}"):
                    check_stable_condition(cond, Loc(None, 1))
        self.assertTrue(all(TIME_WORDS.fullmatch(w) for w in ("now", "today", "tomorrow", "yesterday")))
        # age(x, y) counts from y; a column named like a function, or a word after a dot, is a column
        for cond in ("age(a, b) > interval '1 day'", "age(coalesce(a, b), c) > x", "now and random", "t.user = 1"):
            check_stable_condition(cond, Loc(None, 1))
        for cond in ("age(coalesce(a, b)) > x", "AGE (ARRAY[1, 2][1]) > x", "pg_catalog.now() > x", "AUTHZ.UID() = 1"):
            with self.assertRaisesRegex(PolicyError, "AZ305", msg=cond):
                check_stable_condition(cond, Loc(None, 1))


class Golden(unittest.TestCase):
    """The generated SQL is what it was; after an intended change, run with --update and read the diff."""

    def check(self, name: str, sql: str) -> None:
        path = os.path.join(GOLDEN, name)
        if UPDATE:
            os.makedirs(GOLDEN, exist_ok=True)
            with open(path, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(sql)
            return
        with open(path, encoding="utf-8") as fh:
            want = fh.read()
        if sql != want:
            a, b = sql.split("\n"), want.split("\n")
            line = next((i for i, (x, y) in enumerate(zip(a, b, strict=False)) if x != y), min(len(a), len(b)))
            self.fail(
                f"{name} differs from line {line + 1}:\n  now:    {a[line] if line < len(a) else '(end)'}\n"
                f"  golden: {b[line] if line < len(b) else '(end)'}\n(intended? python3 tests/unit_test.py --update)"
            )

    def test_psql_scripts(self) -> None:
        for name in POLICIES:
            self.check(f"{name}.sql", compiled(name))

    def test_diff_script(self) -> None:
        c = Compiler(parse_policy(read(POLICIES["multi"]), POLICIES["multi"]))
        self.check("multi.diff.sql", c.compile_diff(POLICIES["multi"], ["1", "2"]))

    def test_the_functions_each_apply_makes_again(self) -> None:
        # base.GENERATED_FUNCTIONS (dropped whatever their signature, then made again) names what compiling makes in
        # authz, but the base's own (made or replaced, never dropped) and uid (its type is checked first)
        from authzlib.base import GENERATED_FUNCTIONS

        made = set(re.findall(r"(?m)^CREATE (?:OR REPLACE )?FUNCTION authz\.(\w+)\(", compiled("docs")))
        self.assertEqual(made - {"ctx", "link_hashes", "uid"}, set(GENERATED_FUNCTIONS))


class Compiling(unittest.TestCase):
    def test_the_policy_compiled_stays_as_parsed(self) -> None:
        """The compiler adds relations and permissions of its own (a custom role's, a deny's inheritance) and rewrites
        what names them, in its own copy: what else reads the parsed policy (the language server) sees it as written."""
        text = errors_prelude() + (
            "type org = app.orgs\n  admin : user = admin_id\n  can manage_roles = admin\n"
            "type folder = app.folders\n  org : org = org_id\n  parent : folder = parent_id\n  owner : user = owner_id\n"
            "  blocked : user = blocked_id\n  roles : user from org\n  can denied = blocked or parent.denied\n"
            "  can view = (owner or roles or parent.view) and not denied\n"
        )
        pol = parse_policy(text)
        c = Compiler(pol)
        c.compile("the policy")
        self.assertEqual(pol, parse_policy(text))
        folder = c.pol.types["folder"]
        self.assertEqual(
            ({"roles:view"} & set(folder.relations), {"view__base"} & set(folder.perms)),
            ({"roles:view"}, {"view__base"}),
        )

    def test_a_name_stands_for_one_thing(self) -> None:
        """A function made when first asked for is made once, and a second source for its name is a bug, not the
        first function used again: a condition's function is named by a hash of the condition, cut short."""
        c = Compiler(parse_policy(read(POLICIES["docs"])))
        self.assertTrue(c.first_time("doc__check_x", "{a}"))
        self.assertFalse(c.first_time("doc__check_x", "{a}"))
        with self.assertRaisesRegex(AssertionError, "doc__check_x would stand for two things"):
            c.first_time("doc__check_x", "{b}")

    def test_loops_of_permissions_are_found_each_after_what_it_reaches(self) -> None:
        a, b, c, d = ("t", "a"), ("t", "b"), ("t", "c"), ("u", "d")
        # a and b name each other, and c; c names itself; d is named by nothing and names a
        graph = {a: {b, c}, b: {a}, c: {c}, d: {a}}
        self.assertEqual(
            [sorted(x) for x in strongly_connected(graph)], [[c], [a, b], [d]], "each one after those it reaches"
        )

    def test_who_may_hold_what_a_condition_narrows(self) -> None:
        """authz.who lists the people a permission's relations name; an `or` of conditions inside an `and` narrows
        nothing it can list (anyone may pass it), so the owner's list is the permission's."""
        text = (
            errors_prelude()
            + "type doc = app.docs\n  owner : user = owner_id\n  can see = owner and ({public} or {listed})\n"
        )
        sql = Compiler(parse_policy(text)).compile("the policy")
        body = sql.split('CREATE FUNCTION authz_int."doc__see__who"(p_id bigint)', 1)[1].split("$f$")[1]
        self.assertEqual(body.strip(), 'SELECT x FROM authz_int."doc__owner__who"(p_id) x')

    def test_the_condition_an_error_points_just_after(self) -> None:
        """Postgres may point a little past a condition it refused (a syntax error at what follows it): up to two
        characters past its end, that condition is the one named, among several in the statement."""

        class Refused(Exception):
            def __init__(self, fields: dict[str, str]) -> None:
                super().__init__("refused")
                self.fields = fields

        policy = "app role app_user\ntype user = app.users\ntype doc = app.docs\n  can a = {x > 1}\n  can b = {y < 2}\n"
        sql = "SELECT 1;\nSELECT (x > 1) OR (y < 2) FROM t;\n"
        for past, line in ((2, 4), (3, None)):
            at = sql.index("x > 1") + len("x > 1") + past
            got = database.condition_error(Refused({"M": "syntax error", "P": str(at + 1)}), sql, policy, {})
            self.assertEqual(
                None if got is None else str(got).split(":")[0], None if line is None else f"policy line {line}"
            )

    def test_the_conditions_on_rows(self) -> None:
        """What an apply that fails asks Postgres about one at a time (AZ613), and the captured names' warning: a
        type's where, a link table's, a permission's and a rule's, each on its table, the keywords left out."""
        text = errors_prelude().replace("type user = app.users", "type user = app.users where {active}") + (
            "type team = app.teams\n  member : user = app.team_members(team_id -> user_id) where {not banned}\n"
            "  can see = member and {open} and signed_in\nrules app.teams\n  select : see or {public}\n"
        )
        got = [(table, cond) for table, cond, _ in database.row_conditions(Compiler(parse_policy(text)))]
        self.assertEqual(
            sorted(got),
            [
                ("app.team_members", "not banned"),
                ("app.teams", "open"),
                ("app.teams", "public"),
                ("app.users", "active"),
            ],
        )


class Walks(unittest.TestCase):
    def test_walks_look_up_each_source(self) -> None:
        """Tree walks must not join the sources' UNION ALL view: the planner can't use indexes through it,
        so every step would scan every row (measured with bench/)."""
        for name in POLICIES:
            sql = compiled(name)
            self.assertIsNone(re.search(r'JOIN authz_int\."[^"]+_(links|parents)"', sql), name)
            self.assertIn("CROSS JOIN LATERAL", sql)


class Loops(unittest.TestCase):
    LOOP = (
        "type org = app.orgs\n  owner : user = owner_id\n  settings : setting = settings_id\n  can edit = {start}settings.edit\n"
        "type setting = app.settings\n  email : email = email_id\n  can edit = email.edit\n"
        "type email = app.emails\n  domain : domain = domain_id\n  can edit = domain.edit\n"
        "type domain = app.domains\n  org : org = org_id\n  can edit = org.edit\n"
    )

    def test_a_loop_through_types_needs_one_starting_point(self) -> None:
        """Inheritance round a loop of types: one starting point anywhere in it is enough (an org's owner edits its
        domain, and so on round); none at all is the mistake AZ303 names. Its meaning is checked against the
        reference evaluator by difftest --gen loop."""
        sql = Compiler(parse_policy(errors_prelude() + self.LOOP.format(start="owner or "))).compile("the policy")
        self.assertIn('authz_int."domain__edit__start"', sql)
        self.assertIn("SELECT NULL::bigint AS id WHERE false", sql)  # domain's own start: none
        with self.assertRaisesRegex(
            PolicyError, r"line \d+: \w+\.edit needs a starting point besides inheritance \[AZ303\]"
        ):
            Compiler(
                parse_policy(errors_prelude() + self.LOOP.format(start="").replace("  owner : user = owner_id\n", ""))
            ).compile("the policy")


class LockRoom(unittest.TestCase):
    """GitLab's draft, applied whole, stopped after 150 s with Postgres's 'out of shared memory': one lock per
    object made, more than the lock table holds. apply says so before it starts."""

    class Small:
        """A database whose lock table holds 10 locks (1 per connection, 10 connections)."""

        def __init__(self) -> None:
            self.warnings: list[tuple[str, str | None]] = []

        @property
        def errors(self) -> type[Exception]:
            return Exception

        def rows(self, sql: str, args: Sequence[Value] = ()) -> list[Row]:
            return [{"per": 1, "slots": 10}]

        def script(self, sql: str) -> None:
            pass

        def warn(self, message: str, detail: str | None = None, hint: str | None = None) -> None:
            self.warnings.append((message, hint))

    def test_more_objects_than_locks_is_said_first(self) -> None:
        db = self.Small()
        database.lock_room(db, "".join(f"CREATE VIEW v{i} AS SELECT 1;\n" for i in range(20)))
        self.assertEqual(len(db.warnings), 1)
        self.assertIn("about 20 objects in one transaction", db.warnings[0][0])
        self.assertEqual(
            db.warnings[0][1], "raise max_locks_per_transaction to 4 (a restart; on managed Postgres, a parameter)"
        )
        db = self.Small()
        database.lock_room(db, "CREATE VIEW v AS SELECT 1;\n")
        self.assertEqual(db.warnings, [])


class PointChecks(unittest.TestCase):
    def policy(self, sql: str, table: str, command: str) -> str:
        return search(
            rf'CREATE POLICY "authz_{command}" ON {re.escape(table)} FOR {command.upper()}.*?;\n', sql, re.S
        ).group(0)

    def test_writes_check_one_object_and_selects_keep_the_views(self) -> None:
        """Write rules and authz.can check one object at a time (__has functions); select rules may read many
        rows, so they must keep the views (a function call per row would make lists slow)."""
        sql = compiled("docs")
        self.assertIn('authz_int."folder__edit__has"', self.policy(sql, '"app"."folders"', "insert"))
        self.assertNotIn("__has", self.policy(sql, '"app"."folders"', "select"))
        self.assertNotIn("__has", self.policy(sql, '"app"."files"', "select"))
        can = sql[sql.index("CREATE OR REPLACE FUNCTION authz.can(p_type text, p_id text") :]
        self.assertIn("__has", can[: can.index("END $f$;")])
        lst = sql[sql.index("CREATE OR REPLACE FUNCTION authz.list(p_type text") :]
        self.assertNotIn("__has", lst[: lst.index("END $f$;")])

    def test_starting_points_are_read_in_from(self) -> None:
        """A recursive permission's starting points (its __start function) are read in FROM: a nested loop that
        scans them again rereads the rows the function gave. Called in a select list, the function ran again for
        each outer row (a list of seven rows of genpolicy's seed 3 took over a second; tests/confidence_test.py
        counts the calls)."""
        texts = {name: compiled(name) for name in POLICIES}
        texts["genpolicy 3"] = Compiler(parse_policy(genpolicy.policy_text(genpolicy.make(3)), "gen.authz")).compile(
            "gen.authz"
        )
        for name, sql in texts.items():
            calls = list(re.finditer(r'\w+__start"?\(', sql))
            if name in ("docs", "multi", "genpolicy 3"):
                self.assertTrue(calls, name)
            for call in calls:
                # where it is made, or a function scan with its alias
                said = sql[call.start() - 40 : call.end() + 10]
                before = sql[call.start() - 30 : call.start()]
                made = re.search(r'CREATE FUNCTION authz_int\."?$', before)
                scanned = re.search(r'FROM authz_int\."?$', before) and re.match(r"\) \w+", sql[call.end() :])
                self.assertTrue(made or scanned, f"{name}: {said}")

    def test_own_columns_first(self) -> None:
        """Reads check a recursive permission against what the object's own columns give (owner, org admin)
        before its view, and each check lists its cheapest items first."""
        sql = compiled("docs")
        files = self.policy(sql, '"app"."files"', "select")
        self.assertLess(
            files.index('"folder__share__direct" v WHERE v.id = "files"."folder_id"'),
            files.index('"folder__edit" v WHERE v.id = "files"."folder_id"'),
        )
        self.assertLess(files.index('"file__viewer"'), files.index('"folder__edit"'))
        folders = self.policy(sql, '"app"."folders"', "select")
        self.assertLess(folders.index("coalesce((inherit), false)"), folders.index('"folder__view" v'))

    def test_a_starting_point_with_a_not_is_the_rows_own(self) -> None:
        """`owner and not {locked}` is decided by the doc's own columns: it is checked first, as owner alone is."""
        text = errors_prelude() + (
            "type doc = app.docs\n  owner : user = owner_id\n  parent : doc = parent_id\n"
            "  can view = (owner and not {locked}) or parent.view\nrules app.docs\n  select : view\n"
        )
        direct = search(
            r'CREATE VIEW authz_int\."doc__view__direct" AS.*?;', Compiler(parse_policy(text)).compile("x"), re.S
        )
        self.assertIn(
            'IN (SELECT id FROM authz_int."doc__owner")\n    AND NOT coalesce((locked), false);', direct.group(0)
        )


class Refusals(unittest.TestCase):
    def test_a_relation_made_by_sharing_is_not_followed_from_the_row(self) -> None:
        """A refused write says, of a missing rel.perm, what authz.explain says on each object the row points at
        through a column or a link table, which the row reads; through shares, whose table the app role can't read,
        the item's yes or no is all it says."""
        text = replaced(
            read(POLICIES["cross"]), "  update after : edit\n", "  update after : lead or inside.edit or host.edit\n"
        )
        sql = Compiler(parse_policy(text)).compile("x")
        why = search(r'CREATE FUNCTION authz_gen\."cx\.projects:update_after:why".*?END \$f\$;', sql, re.S).group(0)
        self.assertIn("|| 'host.edit';", why)
        self.assertEqual(re.findall(r"authz\.explain\('(\w+)', v_t\.id, '(\w+)'\)", why), [("folder", "edit")])


class ColumnRules(unittest.TestCase):
    def test_before_is_the_default(self) -> None:
        """`update cols before : ...` is `update cols : ...` spelt out; `after` checks the row after the change."""
        text = read(POLICIES["docs"])
        spelt = text.replace("update id, owner_id, org_id, inherit :", "update id, owner_id, org_id, inherit before :")
        self.assertNotEqual(text, spelt)
        compile_ = lambda t: Compiler(parse_policy(t)).compile("x")
        self.assertEqual(compile_(text), compile_(spelt))
        self.assertIn("checked on the row after the change", compile_(text))

    # a function whose body is a string, without SECURITY DEFINER: Postgres reads the body when it runs, as the caller
    AS_CALLER = re.compile(
        r"CREATE (?:OR REPLACE )?FUNCTION ((?:authz|authz_gen|authz_int)\.(?:\"[^\"]+\"|\w+))\(.*?\)(.*?)AS \$(\w*)\$(.*?)\$\3\$;",
        re.S,
    )

    def test_what_runs_as_the_app_role_names_nothing_in_authz_int(self) -> None:
        # The app role may not use authz_int by name. A policy or a BEGIN ATOMIC body names it once, when the owner
        # makes it; a body in a string is read each time, as whoever runs it. A rule on a column is checked by
        # a trigger that runs as the app role: where the rule names a service (authz_int."bot__me"), the rule
        # is behind a BEGIN ATOMIC function, or every update of the column fails for want of the schema
        ruled = read(POLICIES["composite"]).replace(
            "  update folder_id after : folder.edit\n",
            "  update folder_id after : folder.edit\n  update name : uploader\n",
        )
        self.assertNotEqual(ruled, read(POLICIES["composite"]))
        # (these two run as the owner whoever calls: their callers are definer functions)
        owners = {"authz_int.session_ok", "authz_int.shares_canon"}
        for sql in [Compiler(parse_policy(ruled)).compile("x"), *(compiled(name) for name in POLICIES)]:
            for m in self.AS_CALLER.finditer(sql):
                name, head, body = m.group(1), m.group(2), m.group(4)
                if "SECURITY DEFINER" in head or name in owners:
                    continue
                self.assertNotRegex(body, r"\bauthz_int\.", f"{name} runs as its caller and names authz_int")
        sql = Compiler(parse_policy(ruled)).compile("x")
        holds = re.findall(r'CREATE FUNCTION authz_int\."cx\.\w+:column [\w, ]+:holds".*?END;', sql, re.S)
        self.assertEqual(len(holds), len(re.findall(r'AND NOT authz_int\."cx\.\w+:column [\w, ]+:holds"\(', sql)))
        self.assertTrue(any('"bot__me"' in fn for fn in holds), "the rule that names the bot is behind no function")

    def test_triggers_are_named_after_what_they_guard(self) -> None:
        # Postgres fires a table's triggers in the order of their names, and the first that refuses says why: so a
        # rule's trigger (and its functions) are named after the rule's head, the same wherever the rule is written
        # (rules on another table before it too), within 63 bytes and each its own; and a rule on the row before
        # the change speaks before one on the row after it, whatever their columns (`a after` sorts first by them)
        long = "a_column_named_at_some_length"
        heads = ["owner_id", "title after", "a_b", "a, b", f"{long}_1, {long}_2", f"{long}_1, {long}_3", "a after"]
        heads.append(f"{long}_1, {long}_4 after")
        rules = [f"  update {h} : owner\n" for h in heads]
        types = (
            "app role app_user\ntype user = app.users\ntype doc = app.docs\n  owner : user = owner_id\n"
            "  can edit = owner\ntype note = app.notes\n  doc : doc = doc_id\n"
        )
        docs = "rules app.docs\n  select : edit\n  update : edit\n"
        notes = "rules app.notes\n  update : doc.edit\n  update x : doc.edit\n"
        trigger = re.compile(
            r'CREATE TRIGGER ("[^"]+") BEFORE UPDATE ON ("\w+"\."\w+") FOR EACH ROW\n  WHEN .*?EXECUTE FUNCTION ([^(]+)\(\);',
            re.S,
        )

        def triggers(text: str) -> list[tuple[str, str, str]]:
            return trigger.findall(Compiler(parse_policy(text)).compile("x"))

        made = triggers(types + docs + "".join(rules) + notes)
        self.assertEqual(sorted(made), sorted(triggers(types + notes + docs + "".join(reversed(rules)))))
        mine = [n for n, t, _ in made if t == '"app"."docs"']
        self.assertEqual(
            mine[:4],
            ['"authz_update owner_id"', '"authz_update_after title"', '"authz_update a_b"', '"authz_update a, b"'],
        )
        self.assertEqual(len(set(mine)), len(heads))
        # (Postgres compares the names byte by byte, as sorted() does them here)
        fired = sorted(n[1:-1] for n in mine)
        self.assertEqual([n.startswith("authz_update_after ") for n in fired], [False] * 5 + [True] * 3, fired)
        self.assertEqual(fired[5], "authz_update_after a")
        self.assertTrue(all(len(n[1:-1].encode()) <= 63 for n in mine), mine)
        self.assertEqual(len({f for _, _, f in made}), len(made))
        self.assertIn(('"authz_update x"', '"app"."notes"', 'authz_int."app.notes:column x"'), made)


class SlowPlans(unittest.TestCase):
    """Each time a permission is named, Postgres writes its view out again when it plans a read. An operand
    named twice is written once; a select rule that still makes it write out many is a lint warning."""

    TEAMS = (
        "app role app_user\ntype user = app.users\ntype team = app.teams\n"
        "  member : user = app.team_members(team_id -> user_id)\n"
    )
    DOCS = "type doc = app.docs\n  team : team = team_id\n  can view = team.p{n}\nrules app.docs\n  select : view\n"

    def test_an_operand_named_twice_is_written_once(self) -> None:
        # in an or, p0 is written out in place (its relation, once); in an and, it is named, once
        for twice, p0, member in (("p0", 0, 1), ("p0 or p0", 0, 1), ("p0 and p0", 1, 0), ("p0 and p0 and p0", 1, 0)):
            text = self.TEAMS + f"  can p0 = member\n  can p1 = {twice}\n" + self.DOCS.format(n=1)
            sql = Compiler(parse_policy(text)).compile("x")
            body = search(r'CREATE VIEW authz_int\."?team__p1"? AS\n(.*?);\n', sql, re.S).group(1)
            self.assertEqual(
                (len(re.findall(r"team__p0\b", body)), len(re.findall(r"team__member\b", body))), (p0, member), twice
            )

    def heavy(self, levels: int) -> str:
        perms = "  can p0 = member\n" + "".join(
            f"  can p{n} = (p{n - 1} and {{a}}) or (p{n - 1} and {{b}})\n" for n in range(1, levels + 1)
        )
        return self.TEAMS + perms + self.DOCS.format(n=levels)

    def test_many_expansions_are_a_lint_warning(self) -> None:
        # p6 names p5 twice, which names p4 twice, ... down to p0 and its relation: 191 views for one read of app.docs
        c = Compiler(parse_policy(self.heavy(6)))
        sql = c.compile("x")
        self.assertRegex(
            sql,
            r"object := to_regclass\('\"app\".\"docs\"'\)::text;\n  problem := 'its select rule .* "
            r"\d+ view definitions to plan before a row is read",
        )
        doc = c.types["doc"]
        rule = next(r for r in c.rules if r.command == "select")
        self.assertEqual(c.expansions(c.rule_sql(doc, "t", rule)), 3 * 2**6 - 1)
        # two levels are few, and the policies here say nothing
        for text in (self.heavy(2), read(POLICIES["docs"]), read(POLICIES["multi"])):
            self.assertNotIn("view definitions to plan", Compiler(parse_policy(text)).compile("x"))

    def test_a_permission_no_rule_reads_is_a_lint_warning_too(self) -> None:
        # no rule: authz.list and authz.can still plan doc.view's 191 views, and team.p6's 64 (p5's 32 are few)
        text = self.heavy(6).replace("rules app.docs\n  select : view\n", "")
        sql = Compiler(parse_policy(text, "x.authz")).compile("x.authz")
        warned = re.findall(
            r"object := '([\w.]+)';\n  problem := 'names permissions [^\n]*view definitions to plan", sql
        )
        self.assertEqual(warned, ["team.p6", "doc.view"])
        self.assertIn(
            "  severity := 'warning'; object := 'doc.view';\n  problem := 'names permissions that name others more than "
            "once (' || coalesce((SELECT l.loc FROM authz_gen.policy_lines l WHERE l.what = 'permission doc.view'), "
            "'?') || '), and Postgres writes each one out again every time: 191 view definitions to plan each check of "
            "it (authz.list, authz.can, a rule that names it) before a row is read, which can take a tenth of a second "
            "and more, up to a second or two. Name each permission once on the way';",
            sql,
        )
        self.assertIn("('permission doc.view', 'line 14')", sql)
        # with the select rule, its table is named as before, and each permission too
        sql = Compiler(parse_policy(self.heavy(6), "x.authz")).compile("x.authz")
        self.assertEqual(re.findall(r"object := '([\w.]+)';\n  problem := 'names permissions", sql), warned)
        self.assertIn('object := to_regclass(\'"app"."docs"\')::text;\n  problem := \'its select rule', sql)

    def test_fifty_view_definitions_are_not_many(self) -> None:
        # q names p5 (32), p4 (16) and p1 (2): 50, the most that says nothing, as a permission and as a select rule;
        # a rule for another command is no select rule, whatever it names (p6's 64 are said once, as p6's)
        from authzlib.parse import Ref

        text = (
            self.heavy(6).split("type doc")[0]
            + "  can q = (p5 and {a}) or (p4 and {b}) or (p1 and {a and b})\n"
            + "rules app.teams\n  select : q\n  update : p6\n"
        )
        c = Compiler(parse_policy(text, "x.authz"))
        sql = c.compile("x.authz")
        team = c.types["team"]
        rule = next(r for r in c.rules if r.command == "select")
        self.assertEqual(c.expansions(c.rule_sql(team, "t", rule)), 50)
        self.assertEqual(c.expansions(c.row_sql(team, "o", Ref("q"), team.perms["q"].loc)), 50)
        self.assertEqual(re.findall(r"object := '([\w.]+)';\n  problem := 'names permissions", sql), ["team.p6"])
        self.assertNotIn("its select rule", sql)

    def test_a_table_named_like_rowstiles_schemas_counts_its_views_only(self) -> None:
        # the rule reads the row's columns under the table's name, quoted: authz_gen."team__p6" would read as the view
        text = self.heavy(6).replace("app.docs", "app.authz_gen").replace("team = team_id", "team = team__p6")
        sql = Compiler(parse_policy(text)).compile("x")
        self.assertRegex(sql, r"problem := 'its select rule .* 191 view definitions to plan before a row is read")

    @staticmethod
    def chain(levels: int) -> str:
        """Types in a chain (an org, its workspaces, their projects, ...): each row is inside one of the type
        above, and manage, edit and view each include the one before and inherit from the row above."""
        text = (
            "app role app_user\ntype user = app.users\ntype t0 = app.t0\n"
            "  member : user = app.t0_members(t0_id -> user_id)\n"
            "  admin  : user = app.t0_admins(t0_id -> user_id)\n"
            "  can manage = admin\n  can edit = manage\n  can view = edit or member\n"
        )
        for n in range(1, levels + 1):
            text += (
                f"type t{n} = app.t{n}\n  parent : t{n - 1} = parent_id\n  owner  : user = owner_id\n"
                f"  editor : user = app.t{n}_editors(t{n}_id -> user_id)\n"
                f"  viewer : user = app.t{n}_viewers(t{n}_id -> user_id)\n"
                "  can manage = owner or parent.manage\n  can edit = manage or editor or parent.edit\n"
                "  can view = edit or viewer or parent.view\n"
            )
        return text + f"rules app.t{levels}\n  select : view\n"

    def test_tiers_that_include_each_other_are_looked_up_once(self) -> None:
        # view names parent.view, and through edit and manage parent.edit and parent.manage, which parent.view
        # includes: only parent.view is looked up, so each level adds the same few views (it was 7, 21, 46, 85, 141)
        counts = []
        for levels in range(1, 6):
            c = Compiler(parse_policy(self.chain(levels)))
            sql = c.compile("x")
            rule = next(r for r in c.rules if r.command == "select")
            counts.append(c.expansions(c.rule_sql(c.types[f"t{levels}"], "t", rule)))
        self.assertEqual(len({b - a for a, b in itertools.pairwise(counts[1:])}), 1, counts)
        self.assertLess(counts[3], 30, counts)
        self.assertNotIn("view definitions to plan", sql)
        # the view of view: what its own relations give and the parent's view, not the parent's edit or manage
        body = search(r'CREATE VIEW authz_int\."?t5__view"? AS\n(.*?);\n', sql, re.S).group(1)
        self.assertIn("parent__view", body)
        self.assertNotRegex(body, r"parent__(edit|manage)\b|t5__(edit|manage)\b")
        # edit still includes manage's people, written out: the owner, and the parent's edit alone
        body = search(r'CREATE VIEW authz_int\."?t5__edit"? AS\n(.*?);\n', sql, re.S).group(1)
        self.assertIn("parent__edit", body)
        self.assertIn("owner", body)
        self.assertNotRegex(body, r"parent__manage\b|t5__manage\b")

    def test_a_lookup_is_dropped_only_where_every_type_the_relation_names_covers_it(self) -> None:
        # up names a folder or a drive. A folder's view includes its edit; where a drive's doesn't, up.view
        # doesn't cover up.edit (a drive's owner would lose the notes on it), and both lookups stay
        def see(drive_view: str) -> str:
            policy = (
                "app role app_user\ntype user = app.users\n"
                "type folder = app.folders\n  owner : user = owner_id\n"
                "  viewer : user = app.folder_viewers(folder_id -> user_id)\n"
                "  can edit = owner\n  can view = edit or viewer\n"
                "type drive = app.drives\n  owner : user = owner_id\n"
                "  viewer : user = app.drive_viewers(drive_id -> user_id)\n"
                f"  can edit = owner\n  can view = {drive_view}\n"
                "type note = app.notes\n  up : folder, drive = (up_type, up_id)\n  can see = up.view or up.edit\n"
                "rules app.notes\n  select : see\n"
            )
            sql = Compiler(parse_policy(policy)).compile("x")
            return search(r'CREATE VIEW authz_int\."?note__see"? AS\n(.*?);\n', sql, re.S).group(1)

        self.assertRegex(see("viewer"), r"note__up__view\b")
        self.assertRegex(see("viewer"), r"note__up__edit\b")
        # ... and where the drive's view includes its edit too, one lookup says it all
        self.assertRegex(see("edit or viewer"), r"note__up__view\b")
        self.assertNotRegex(see("edit or viewer"), r"note__up__edit\b")


class LanguageForms(unittest.TestCase):
    def test_a_line_is_lexed_once_and_read_from_anywhere(self) -> None:
        # a line's pieces are lexed in one pass, as piece_at reads each one: a doubled quote inside a quote, -> as
        # one mark, a quote left open a mark; a reader placed where no piece ends lexes from there
        from authzlib.parse import Piece, Words, piece_at

        text = "x 'it''s' -> ''' {a}"
        pieces = Words(text).all()
        self.assertEqual(
            [(p.kind, p.text) for p in pieces],
            [("name", "x"), ("quote", "'it''s'"), ("mark", "->"), ("mark", "'"), ("quote", "''"), ("cond", "a")],
        )
        self.assertEqual(pieces, [piece_at(text, p.start) for p in pieces])
        self.assertEqual(Words("ab cd", 1).peek(), Piece("name", "b", 1, 2))
        # a mark that must be glued to the piece before isn't taken after a space, and stays to be read
        spaced = Words("a -b")
        spaced.name("a")
        self.assertIsNone(spaced.mark("-", glued=True))
        self.assertEqual(spaced.mark("-"), Piece("mark", "-", 2, 3))

    def test_named_columns_mean_the_arrow(self) -> None:
        text = read(POLICIES["docs"])
        named = text.replace("app.teams(parent_id -> id)", "app.teams(subject: id, object: parent_id)")
        self.assertNotEqual(text, named)
        compile_ = lambda t: Compiler(parse_policy(t)).compile("x")
        self.assertEqual(compile_(text), compile_(named))

    def test_words_for_conditions(self) -> None:
        text = read(POLICIES["docs"]).replace(
            "  can break_glass = org.member", "  can break_glass = org.member and signed_in"
        )
        sql = Compiler(parse_policy(text)).compile("x")
        self.assertIn("authz.uid()) IS NOT NULL", sql)
        for word, written in (("anyone", "true"), ("nobody", "false")):
            pol = parse_policy(
                read(POLICIES["docs"]).replace("  can break_glass = org.member", f"  can break_glass = {word}")
            )
            self.assertEqual(pol.types["folder"].perms["break_glass"].expr, authzlib.parse.Cond(written))

    def test_sql_comments_in_a_condition_end_at_the_line(self) -> None:
        # the lines of a condition are joined into one: a comment left in would swallow the lines after it
        text = read(POLICIES["docs"])
        commented = text.replace("on a.org_id = b.org_id\n", "on a.org_id = b.org_id -- don't drop the next line\n")
        self.assertNotEqual(text, commented)
        compile_ = lambda t: Compiler(parse_policy(t)).compile("x")
        self.assertEqual(compile_(text), compile_(commented))

    def test_quotes_in_a_condition_are_read_as_sql_reads_them(self) -> None:
        # a brace or -- inside "a name", $$text$$ or E'text' is the condition's text: it closes or comments nothing
        base = "app role app_user\ntype user = app.users\ntype doc = app.docs\n  owner : user = owner_id\n"

        def condition(text: str) -> object:
            expr = parse_policy(base + text).types["doc"].perms["view"].expr
            assert isinstance(expr, authzlib.parse.And), expr
            return expr.items[1]

        for cond in ('"we}ird" = 1', "note = $$--}$$", "note = E'a\\'}'", "note = 'it''s {'"):
            self.assertEqual(condition("  can view = owner and {" + cond + "}\n"), authzlib.parse.Cond(cond))
        # a quote may go on to the next line inside a condition; outside, an apostrophe opens none
        self.assertEqual(
            condition("  can view = owner and {note = 'a\n  -- b}'}\n"), authzlib.parse.Cond("note = 'a -- b}'")
        )
        pol = parse_policy(base + '  can view = owner\ntest "Bob\'s test" -- the comment\n  user 1 can view doc 1\n')
        self.assertEqual(pol.scenarios[0].name, "Bob's test")
        # a quoted name runs to the quote that ends the line, and may hold it (Studio names tests after a check)
        pol = parse_policy(
            base + '  can view = owner\ntest "user 2 cannot view doc \'(1,"a b")\'"\n  user 1 can view doc 1\n'
        )
        self.assertEqual(pol.scenarios[0].name, "user 2 cannot view doc '(1,\"a b\")'")
        # a /* comment */ hides what it holds, nested and over lines; a $ that goes on a name opens no dollar quote
        for cond in (
            "/* don't } */ true",
            "/* a /* nested } */ ' { */ true",
            "price$$ > 0",
            "a$ = $1",
            "$$ $$$$}$$ <> ''",
        ):
            self.assertEqual(condition("  can view = owner and {" + cond + "}\n"), authzlib.parse.Cond(cond))
        self.assertEqual(
            condition("  can view = owner and {/* it's\n  } */ true}\n"), authzlib.parse.Cond("/* it's } */ true")
        )
        # outside braces, /* is no comment: a policy's comments start with --
        with self.assertRaisesRegex(PolicyError, "unexpected '/' in expression"):
            parse_policy(base + "  can view = owner /* the owner */\n")

    def test_a_mistake_says_which_words_it_is_about(self) -> None:
        # (line, column, end line, end column): what an editor underlines; a line that goes on is followed there
        base = "app role app_user\ntype user = app.users\ntype doc = app.docs\n  owner : user = owner_id\n"
        for tail, words in (
            ("  can view = owner\n      or parent.nosuch\n", (6, 9, 6, 15)),  # (doc has no relation `parent`)
            ("  can view = owner or nosuch\n", (5, 22, 5, 28)),
            ("  can view = owner or (owner and {x}\n", (5, 22, 5, 23)),
            ("  can view = owner or } x\n", (5, 22, 5, 23)),
            ("  can view = owner or owner and {a}\n", (5, 13, 5, 35)),
            ("  ed__it : user = owner_id\n", (5, 2, 5, 8)),
            ("  r : user, teem#member shared\n", (5, 12, 5, 16)),
            ("  r : user,, user shared\n", (5, 11, 5, 12)),
            ("  can view = owner and {a = $f$x$f$}\n", (5, 28, 5, 31)),
            ("  can view = owner and {a = 1\n      and b} and {\n", (6, 17, 6, 18)),
            ("invariants\n  never teem: owner\n", (6, 8, 6, 12)),
            # a name written twice on its line: the one the mistake is about (folder has no owner; doc has)
            (
                "  parent : folder = folder_id\n  can view = owner or parent.owner\n"
                "type folder = app.folders\n  viewer : user = viewer_id\n  can see = viewer\n",
                (6, 29, 6, 34),
            ),
            ("  can view = owner.view\n", (5, 19, 5, 23)),  # (user has no view)
            ("  can view = owner\nscope s = doc.view, teem.view\n", (6, 20, 6, 24)),
            ("  roles : user, teem#member\n  can view = owner or roles\n", (5, 16, 5, 20)),
            # a line that isn't its form: the piece where reading stopped
            ("  can view owner\n", (5, 11, 5, 16)),
            ("type folder app.folders\n", (5, 12, 5, 15)),
            ("  r : user = app.links(doc_id => user_id)\n", (5, 30, 5, 31)),
            ('  can view = owner\ntest "t"\n  as user 1 alowed {SELECT 1}\n', (7, 12, 7, 18)),
            ("  can view = owner\ninvariants\n  never doc view\n", (7, 12, 7, 16)),
            ('  can view = owner\ntest "t"\n  as user 1 sees 3x {SELECT 1}\n', (7, 17, 7, 19)),
            ("  can view = owner\nscope files-:read = doc.view\n", (6, 12, 6, 13)),
        ):
            with self.subTest(tail), self.assertRaises(PolicyError) as e:
                Compiler(parse_policy(base + tail)).compile("x")
            self.assertEqual(e.exception.span, words, str(e.exception))
        # a scope's name may go on with - and :, written without spaces; a test names it the same way
        pol = parse_policy(
            base + '  can view = owner\nscope files:read-only = doc.view\ntest "t"\n'
            "  user 1 with scope files:read-only, files:read-only can view doc 1\n"
            "  as user 1 with scope files:read-only sees 1 {SELECT 1}\n"
        )
        self.assertEqual(list(pol.scopes), ["files:read-only"])
        steps = pol.scenarios[0].steps
        self.assertEqual(
            [st.scopes for st in steps if isinstance(st, (authzlib.parse.CheckStep, authzlib.parse.AsStep))],
            [("files:read-only",) * 2, ("files:read-only",)],
        )
        # a line the parser didn't read has no words to point at
        with self.assertRaises(PolicyError) as e:
            Compiler(parse_policy("app role app_user\n")).compile("x")
        self.assertIsNone(e.exception.span)
        self.assertIsNone(authzlib.parse.Loc(None, 3).span(0, 2))

    def test_a_permission_line_takes_a_tab_after_can(self) -> None:
        # as any line does: `can` is a word, followed by a space or a tab
        base = "app role app_user\ntype user = app.users\ntype doc = app.docs\n  owner : user = owner_id\n"
        pol = parse_policy(base + "  can\tview = owner\n")
        self.assertEqual(list(pol.types["doc"].perms), ["view"])
        self.assertEqual(list(pol.types["doc"].relations), ["owner"])

    def test_sees_n_takes_queries_that_only_read(self) -> None:
        # a WITH whose queries read, or one whose words say delete in a string or a comment, and a row lock: counted
        base = "app role app_user\ntype user = app.users\ntype doc = app.docs\n  owner : user = owner_id\n"
        for sql in (
            "WITH x AS (SELECT 1 AS n) SELECT * FROM x",
            "WITH x AS (SELECT 'as (delete' AS n) SELECT * FROM x",
            "WITH x AS (/* as (delete */ SELECT 1) SELECT * FROM x",
            "SELECT * FROM app.docs FOR UPDATE",
        ):
            pol = parse_policy(base + f'  can view = owner\ntest "t"\n  as user 1 sees 1 {{{sql}}}\n')
            self.assertEqual([st.sql for st in pol.scenarios[0].steps if isinstance(st, authzlib.parse.AsStep)], [sql])

    def test_a_condition_ends_at_its_closing_brace(self) -> None:
        # not at the line's last }: `if {a} and {b}` was read as the one condition `a} and {b`, which only Postgres
        # refused, when applying; and two lines run together as one
        base = "app role app_user\ntype user = app.users\ntype doc = app.docs\n  owner : user = owner_id\n"
        for tail, wrong in (
            ("  r : user shared if {true} and {false}\n", "and {false}"),
            ("  r : user = app.links(doc_id -> user_id) where {a} and {b}\n", "and {b}"),
            ("  can view = owner\ntype note = app.notes where {a} and {b}\n", "and {b}"),
            ("  can view = owner\ncaveat c = {a} caveat d = {b}\n", "caveat d"),
            ('  can view = owner\ntest "t"\n  given a = {SELECT 1} given b = {SELECT 2}\n', "given b"),
            ('  can view = owner\ntest "t"\n  as user 1 allowed {SELECT 1}} as user 2 allowed {SELECT 2}\n', "}"),
        ):
            text = base + tail
            with self.subTest(tail), self.assertRaises(PolicyError) as e:
                parse_policy(text)
            assert e.exception.span is not None, str(e.exception)
            line, col = e.exception.span[:2]
            self.assertTrue(text.split("\n")[line - 1][col:].startswith(wrong), (str(e.exception), e.exception.span))
        pol = parse_policy(base + "  r : user shared if {a = '}'}\n  can view = owner or r\n")  # (a } in quotes)
        source = pol.types["doc"].relations["r"].sources[0]
        self.assertEqual(source.shared_if if source.kind == "shared" else None, "a = '}'")

    def test_the_parser_reads_on_after_a_mistake(self) -> None:
        # each mistake once: the lines of a block whose first line is wrong are not read, nor said again
        text = (
            "app role app_user\ntype user = app.users\ntype doc = app.docs (\n  owner : user = owner_id\n"
            "type file = app.files\n  owner : user = owner_id\n  can view = owner or (owner\n  can edit = owner and }\n"
            'scope s = select\nscope s = delete\n  stray\ntest "empty"\n'
        )
        with self.assertRaises(PolicyError) as e:
            parse_policy(text)
        self.assertEqual(
            [(str(x).split(":")[0], x.code) for x in e.exception.errors],
            [("line 3", "AZ101"), ("line 7", "AZ102"), ("line 8", "AZ102"), ("line 10", "AZ109"), ("line 12", "AZ106")],
        )
        self.assertIs(e.exception.errors[0], e.exception)

    def test_quotes_in_include_names_and_test_ids(self) -> None:
        pol = parse_policy('include "a--b.authz"  -- the rest\n', files={"a--b.authz": read(POLICIES["docs"])})
        self.assertIn("folder", pol.types)
        pol = parse_policy(read(POLICIES["docs"]) + "test\n  user 'it''s' cannot view file 'o''k'\n")
        self.assertEqual((pol.tests[-1].who, pol.tests[-1].obj), ("it's", "o'k"))

    def test_a_byte_order_mark_before_an_include(self) -> None:
        # some editors start a UTF-8 file with one: the includes read from disk were missed then
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "docs.authz"), "w", encoding="utf-8") as fh:
                fh.write(read(POLICIES["docs"]))
            text = '\ufeffinclude "docs.authz"\n'
            self.assertIn("folder", parse_policy(text, os.path.join(d, "main.authz")).types)

    def test_the_test_section_signs_in_as_the_principal_it_names(self) -> None:
        text = (
            errors_prelude() + "type service = app.services principal\n  owner : user = owner_id\n"
            "  can manage_keys = owner\ntest\n  service 1 can manage_keys service 1\n  anyone cannot manage_keys service 1\n"
        )
        sql = Compiler(parse_policy(text)).tests_function_sql()
        self.assertIn(
            "set_config('authz.user_id', coalesce('1', ''), true), set_config('authz.principal_type', 'service', true)",
            sql,
        )
        self.assertIn(
            "set_config('authz.user_id', coalesce('', ''), true), set_config('authz.principal_type', '', true)", sql
        )

    def test_lint_notes_relations_named_like_types(self) -> None:
        text = (
            read(POLICIES["docs"])
            .replace("  owner  : user   = owner_id\n", "  owner  : user   = owner_id\n  user   : user   = owner_id\n")
            .replace("  can share = owner or folder.share", "  can share = owner or user or folder.share")
        )
        sql = Compiler(parse_policy(text)).compile("x")
        self.assertIn("('file', 'user',", sql)
        # ...when the type signs in: `user` alone in a rule reads like any user. `folder : folder = folder_id` (what
        # init drafts and the guide writes) is only ever followed, `folder.view`, which reads as what it means
        self.assertIn("  folder : folder = folder_id\n", text)
        self.assertNotIn("('file', 'folder',", sql)

    def test_lint_knows_the_commands_the_rules_ask_for(self) -> None:
        # a rule for a command the app role has no privilege for never applies, and the statement fails with
        # Postgres's own message: lint is given each table's commands that have a rule. `nobody` asks for none; a
        # column's rule, or `after`, is an update's
        def rows(rules: str) -> list[str]:
            text = errors_prelude() + "  boss : user = boss_id\n  can edit = boss\nrules app.users\n" + rules
            sql = Compiler(parse_policy(text)).compile("x")
            return re.findall(r"""\('"app"\."users"', '(\w+)'\)""", search(r"v\(tbl, cmd\)", sql).string)

        self.assertEqual(rows("  select : edit\n  update : edit\n  delete : nobody\n"), ["select", "update"])
        self.assertEqual(
            rows("  select : edit\n  update : edit\n  update boss_id after : edit\n"), ["select", "update"]
        )
        self.assertEqual(rows("  select : edit\n  update : nobody\n  insert : nobody\n"), ["select"])

    def test_a_subject_given_twice_is_listed_once(self) -> None:
        # a second source of a shared relation that names a subject again (`user` here): the clients list it once
        text = errors_prelude() + (
            "type doc = app.docs\n  owner : user = owner_id\n  viewer : user  shared\n  viewer : user, user:*  shared\n"
            "  can share = owner\n  can view = owner or viewer\n"
        )
        ts = Compiler(parse_policy(text)).client("ts", "x")
        shared = json.loads(search(r"export const sharedRelations = (\{.*?\}) as const;", ts, re.S).group(1))
        self.assertEqual(shared, {"doc": {"viewer": ["user", "user:*"]}})

    def test_a_subject_that_is_a_relation_is_listed_with_it(self) -> None:
        # a share with a team's members (`team#member`) is listed so in both clients, not as a share with the team
        text = errors_prelude() + (
            "type team = app.teams\n  member : user = app.team_members(team_id -> user_id)\n"
            "type doc = app.docs\n  owner : user = owner_id\n  viewer : user, team#member  shared\n"
            "  can share = owner\n  can view = owner or viewer\n"
        )
        c = Compiler(parse_policy(text))
        ts = c.client("ts", "x")
        shared = json.loads(search(r"export const sharedRelations = (\{.*?\}) as const;", ts, re.S).group(1))
        self.assertEqual(shared, {"doc": {"viewer": ["user", "team#member"]}})
        py = search(r"SHARED_RELATIONS: dict\[str, dict\[str, list\[str\]\]\] = (\{.*?\n\})", c.client("py", "x"), re.S)
        self.assertEqual(json.loads(py.group(1)), {"doc": {"viewer": ["user", "team#member"]}})

    def test_your_own_row_is_not_a_move(self) -> None:
        # a relation from the row's own key to its type (`self : user = id`) is "this row": lint doesn't ask for an
        # 'after' rule on the key, as it does for a parent's column
        text = errors_prelude() + (
            "  self : user = id\n  boss : user = boss_id\n  can edit = self or boss\n"
            "rules app.users\n  select : edit\n  update : edit\n"
        )
        sql = Compiler(parse_policy(text)).compile("x")
        self.assertNotIn("('\"app\".\"users\"', 'id', 'self',", sql)
        self.assertIn("('\"app\".\"users\"', 'boss_id', 'boss',", sql)

    def test_a_column_nobody_may_update_needs_no_rule_of_its_own(self) -> None:
        # lint asks for a rule on a column a relation reads when the plain `update` rule lets someone change the row.
        # `update : nobody` lets no one; and the rule lint suggests names `share` only where the type has it (a
        # suggestion that doesn't compile helps no one)
        def sql(perms: str, update: str) -> str:
            text = (
                errors_prelude()
                + f"  boss : user = boss_id\n{perms}rules app.users\n  select : edit\n  update : {update}\n"
            )
            return Compiler(parse_policy(text)).compile("x")

        row = "('\"app\".\"users\"', 'boss_id', 'user.boss', '[^']*', '%s')"
        self.assertRegex(
            sql("  can edit = boss\n", "edit"), re.escape(row % "nobody").replace(re.escape("[^']*"), "[^']*")
        )
        self.assertRegex(
            sql("  can edit = boss\n  can share = boss\n", "edit"),
            re.escape(row % "share").replace(re.escape("[^']*"), "[^']*"),
        )
        self.assertNotIn("'boss_id', 'user.boss',", sql("  can edit = boss\n", "nobody"))


class Denies(unittest.TestCase):
    def test_hidden_base(self) -> None:
        c = Compiler(parse_policy(read(POLICIES["alt"])))
        sql = c.compile("x")
        self.assertIn('CREATE VIEW authz_int."doc__view__base"', sql)
        self.assertRegex(sql, r"\('doc', 'view'\)[,;]")
        self.assertNotIn("'view__base'", sql)  # not in the catalog, authz.can/list/perms, who or explain
        self.assertNotIn("view__base", c.client("py", "x") + c.client("ts", "x"))
        # sharing into a deny takes away: it needs the share permission, not the deny itself
        self.assertIn("('doc', 'banned', 'user', 'share', ARRAY[]::text[]", sql)

    def test_conditions_go_on_every_item(self) -> None:
        text = read(POLICIES["docs"])
        line = "  can share = owner or org.admin or (parent.share and {inherit})"
        joined = text.replace(line, "  can share = (owner or org.admin or parent.share) and {inherit}")
        spread = text.replace(
            line, "  can share = (owner and {inherit}) or (org.admin and {inherit}) or (parent.share and {inherit})"
        )
        self.assertNotEqual(joined, text)
        strip = lambda t: [ln for ln in Compiler(parse_policy(t)).compile("x").splitlines() if "{inherit}" not in ln]
        self.assertEqual(strip(joined), strip(spread))


class CompositeKeys(unittest.TestCase):
    def test_brackets(self) -> None:
        pol = parse_policy(read(POLICIES["composite"]))
        folder = pol.types["folder"]
        self.assertEqual(folder.key, [("org_id", "bigint"), ("id", "bigint")])
        self.assertEqual(pol.types["team"].key, [("org_id", "bigint"), ("slug", "text")])
        column, table = folder.relations["parent"].sources
        assert column.kind == "column" and table.kind == "table", (column, table)
        self.assertEqual((column.type_col, column.column), ("parent_type", ("org_id", "parent_id")))
        self.assertEqual((table.obj_col, table.subj_col), (("org_id", "child_id"), ("org_id", "parent_id")))

    def test_lookups_by_key_go_column_by_column(self) -> None:
        """A composite id compared as a whole can't use the table's index: lookups into app tables go
        column by column."""
        sql = compiled("composite")
        self.assertIn('(c."org_id", c."id") = (((up._a)::authz_gen."folder__key")."org_id"', sql)
        self.assertNotRegex(sql, r'ROW\(c\."org_id"[^)]*\)::text = up\._a')

    def test_lookups_for_a_set_go_column_by_column(self) -> None:
        """The rows whose columns name one of a set (the folders a user edits, the teams they are in, a (type,
        [org_id, id]) pair's projects) are looked up by the columns: a row's id built as text and compared
        could only be found by reading every row (tests/confidence_test.py shows the plans)."""
        sql = compiled("composite")
        views = "\n".join(re.findall(r'CREATE VIEW authz_int\."[^"]+" AS\n.*?;\n', sql, re.S))
        self.assertNotRegex(views, r"IS NOT NULL THEN ROW\([^)]*\)::text END\)\s*(IN \(SELECT id FROM authz_int|= ANY)")
        for view, lookup in (
            (
                "file__folder__edit",
                '(r."org_id", r."folder_id") IN (SELECT (k.k)."org_id", (k.k)."id" FROM (SELECT '
                'x.id::authz_gen."folder__key" AS k FROM (SELECT id FROM authz_int."folder__edit") x) k)',
            ),
            (
                "folder__editor",
                '(s."org_id", s."team_slug") IN (SELECT (k.k)."org_id", (k.k)."slug" FROM (SELECT '
                'x.id::authz_gen."team__key" AS k FROM (SELECT unnest((SELECT authz_int."team__member__ids"())::text[]) '
                "AS id) x) k)",
            ),
            (
                "folder__parent__edit__on_project",
                '(r."org_id", r."parent_id") IN (SELECT (k.k)."org_id", (k.k)."id" '
                'FROM (SELECT x.id::authz_gen."project__key" AS k FROM (SELECT id FROM authz_int."project__edit") x) k) '
                "AND r.\"parent_type\" = 'project'",
            ),
        ):
            body = search(rf'CREATE VIEW authz_int\."{view}" AS\n(.*?);\n', sql, re.S).group(1)
            self.assertIn(lookup, body, view)
        # teams in teams, with no shares among them: each step of the walk finds the teams a team is in by their
        # columns (with shares among them too, each step still joins)
        text = read(POLICIES["composite"]).replace("  member : team#member  shared\n", "")
        walk = search(
            r'CREATE VIEW authz_int\."team__member" AS\n(.*?);\n',
            Compiler(parse_policy(text, POLICIES["composite"])).compile("x"),
            re.S,
        ).group(1)
        self.assertIn('(s."org_id", s."slug") = (((m.id)::authz_gen."team__key")."org_id"', walk)
        self.assertNotIn("e.subj = m.id", walk)

    def test_a_pairs_type_is_beside_its_case(self) -> None:
        """A (type, id) pair whose id is one column is read through a CASE on the type, which no index serves: the
        type's own condition beside it is what an index on (type, id) serves (tests/confidence_test.py shows the
        plans), in the views and in the row checks alike."""
        sql = compiled("cross")
        for view, lookup in (
            (
                "folder__parent__file__on_project",
                '(r."parent_type" = \'project\' AND (CASE WHEN r."parent_type" = \'project\' THEN r."parent_id" END)'
                '::bigint IN (SELECT id FROM authz_int."project__file"))',
            ),
            (
                "project__backer__fund__on_region",
                '(s."backer_type" = \'region\' AND (CASE WHEN s."backer_type" = \'region\' THEN s."backer_id" END)'
                '::bigint IN (SELECT id FROM authz_int."region__fund"))',
            ),
        ):
            body = search(rf'CREATE VIEW authz_int\."{view}" AS\n(.*?);\n', sql, re.S).group(1)
            self.assertIn(lookup, body, view)
        self.assertNotRegex(
            sql,
            r"(?<!AND )\(CASE WHEN [rs]\.\"(parent|backer)_type\" = '\w+' THEN [rs]\.\"\w+\" END\)"
            r"::bigint IN",
        )

    def test_user_key_is_one_column(self) -> None:
        text = read(POLICIES["composite"]).replace("type user = cx.users", "type user = cx.users (org_id, id)")
        with self.assertRaisesRegex(PolicyError, "the user type signs in, so it needs a key of one column"):
            Compiler(parse_policy(text))

    def test_client_formats_rows(self) -> None:
        c = Compiler(parse_policy(read(POLICIES["composite"])))
        ns = {}
        exec(c.client("py", "x"), ns)
        self.assertEqual(ns["_id"]((1, 'x,y "q"')), '("1","x,y \\"q\\"")')
        self.assertEqual(ns["_id"](7), "7")

    def test_client_names_each_types_permissions(self) -> None:
        # a type checker refuses a permission the type hasn't: each type's are a Literal
        c = Compiler(parse_policy(read(POLICIES["docs"])))
        self.assertIn('FilePermission = Literal["share", "edit", "view"]', c.client("py", "x").split("\n"))


class ClientNames(unittest.TestCase):
    """The generated clients' names, and the reference's lists of them (docs/reference/app-code.md)."""

    CASES = (
        errors_prelude()
        + "type doc = app.docs\n  owner : user = owner_id\n  can view = owner\n"
        + "type Doc = app.docs2\n  owner : user = owner_id\n  can edit = owner\n"
        + "type orgUnit = app.units\n  owner : user = owner_id\n  can see = owner\n"
    )

    @staticmethod
    def python(policy: str) -> dict[str, object]:
        ns: dict[str, object] = {}
        exec(database.client("py", policy), ns)
        return ns

    @staticmethod
    def bullet(start: str) -> str:
        """The reference's paragraph about a client, from its first words to the blank line after it."""
        text = read("../docs/reference/app-code.md")
        return text[text.index(start) :].split("\n\n")[0]

    @staticmethod
    def named(text: str) -> list[str]:
        """The names in backquotes, without what is in parentheses after one (`list` (with `after` ...))."""
        return re.findall(r"`(\w+)`", re.sub(r" \([^()]*(?:\([^()]*\)[^()]*)*\)", "", text))

    def test_each_type_gets_its_own_alias(self) -> None:
        # a type's name keeps its own case: orgUnit's alias isn't OrgunitPermission
        lines = database.client("py", self.CASES).split("\n")
        self.assertIn('OrgUnitPermission = Literal["see"]', lines)
        # doc and Doc would get the same alias, the second one replacing the first: neither has one, and why
        self.assertEqual([x for x in lines if x.startswith("DocPermission")], [])
        self.assertIn("# doc and Doc would both be DocPermission: neither has it, use Permission", lines)
        self.assertNotIn("DocPermission", self.python(self.CASES))

    def test_share_takes_caveat_args_as_a_dict(self) -> None:
        sent: list[Sequence[object]] = []

        class Cursor:
            def __enter__(self) -> "Cursor":
                return self

            def __exit__(self, *exc: object) -> None:
                return None

            def execute(self, sql: str, params: Sequence[object]) -> None:
                sent.append(params)

            def fetchone(self) -> None:
                return None

        class Connection:
            def cursor(self) -> Cursor:
                return Cursor()

        class Sharing(Protocol):
            def share(self, *args: object, **kwargs: object) -> None: ...

        authz = cast(Callable[[Connection], Sharing], self.python(read(POLICIES["docs"]))["Authz"])(Connection())
        share = authz.share
        share("folder", 3, "viewer", "user", 4, caveat="from_ip", caveat_args={"ip": "10.0.0.7", "n": 1})
        share("folder", 3, "viewer", "user", 4)
        self.assertEqual([p[-2:] for p in sent], [("from_ip", '{"ip": "10.0.0.7", "n": 1}'), (None, None)])

    def test_the_reference_lists_the_python_clients_calls(self) -> None:
        ns = self.python(read(POLICIES["docs"]))
        calls = {n for n in vars(cast(type, ns["Authz"])) if not n.startswith("_")}
        text = self.bullet("- **Python: supported.**")
        listed = self.named(text[text.index("`Authz(conn)`, with ") : text.index("; the errors")])
        self.assertEqual(sorted(set(listed) | {"refusal"}), sorted(calls))
        self.assertIn("`refusal(error)`", text)
        for name in ("Refused", "NotFound", "ObjectType", "Permission", "FilePermission"):
            self.assertIn(f"`{name}`", text)
            self.assertIn(name, ns)
        self.assertIn("(its `caveat_args` a dict)", text)

    def test_the_reference_lists_the_typescript_clients_calls(self) -> None:
        ts = database.client("ts", read(POLICIES["docs"]))
        body = ts[ts.index("export function authz(db: Queryable)") :]
        calls = re.findall(r"^    (\w+): async", body, re.M)
        text = self.bullet("- **TypeScript: preview.**")
        listed = self.named(text[text.index("`authz(db)` has ") : text.index(": Python's calls in camelCase")])
        self.assertEqual(sorted(listed), sorted(calls))
        # Python's calls in camelCase, except principal and signing in (asUser and asPrincipal)
        python = {n for n in vars(cast(type, self.python(read(POLICIES["docs"]))["Authz"])) if not n.startswith("_")}
        camel = {re.sub(r"_(\w)", lambda m: m.group(1).upper(), n) for n in python}
        self.assertEqual(sorted(camel - set(calls)), ["principal", "refusal", "signIn", "signInAs"])
        self.assertIn("except `principal`", text)
        for name in ("asUser", "asPrincipal", "refusal", "Refused", "NotFound"):
            self.assertRegex(ts, rf"export (async function|function|class) {name}\b")
        share = search(r"\n    share: [^\n]*\n[^\n]*", body).group(0)
        for option in ("subjectRelation", "expiresAt", "startsAt", "caveat", "caveatArgs"):
            self.assertIn(f"{option}?:", share)
            self.assertIn(f"`{option}`", text)

    def test_the_reference_lists_the_sdks_calls(self) -> None:
        sdk = read("../sdk/typescript/client/src/index.ts")
        interface = search(r"export interface AuthzCalls \{\n(.*?)\n\}", sdk, re.S).group(1)
        calls = set(re.findall(r"^  (\w+)[<(]", interface, re.M))
        prisma = search(
            r"export type PrismaAuthz = [^{]*\{(.*?)\n\};", read("../sdk/typescript/prisma/src/index.ts"), re.S
        )
        text = read("../docs/reference/app-code.md")
        sentence = text[text.index("The SDK's calls") :].split(". Its `share`")[0]
        listed = re.findall(r"`(\w+)`", sentence[sentence.index(") are ") :])
        self.assertEqual(
            sorted(listed), sorted(calls | {"expect"} | set(re.findall(r"^  (\w+)<", prisma.group(1), re.M)))
        )
        self.assertNotIn("expiresAt", search(r"\n  share<[^;]*;", interface).group(0))  # no expiry, start or caveat
        self.assertIn("Its `share` takes no expiry, start or caveat.", text)

    def test_the_reference_names_every_function_the_app_role_may_call(self) -> None:
        c = Compiler(parse_policy(read(POLICIES["docs"])))
        c.compile("x")
        reference = "".join(
            read(f"../docs/reference/{p}") for p in sorted(os.listdir(os.path.join(ROOT, "..", "docs", "reference")))
        )
        # authz.link_hashes is what the rules read (the links the transaction presents), not a call for apps
        missing = {s.split("(")[0] for s in c.api_signatures()} - {"authz.link_hashes"}
        self.assertEqual(sorted(n for n in missing if f"{n}(" not in reference), [])


class Principals(unittest.TestCase):
    def test_principal_types(self) -> None:
        pol = parse_policy(read(POLICIES["composite"]))
        self.assertTrue(pol.types["bot"].principal and pol.types["user"].principal)
        self.assertFalse(pol.types["folder"].principal)
        self.assertIn(("bot", "*"), pol.types["folder"].relations["viewer"].sources[0].subjects)

    def test_holding_compares_with_the_signed_in_principal(self) -> None:
        sql = compiled("composite")
        self.assertIn(
            "g.subject_type = 'bot' AND g.subject_relation = '' AND g.subject_id = (SELECT authz_int.\"bot__me\"()::text)",
            sql,
        )
        self.assertIn('coalesce("files"."uploaded_by" = (SELECT authz_int."bot__me"()), false)', sql)

    def test_lint_notes_principals_without_keys(self) -> None:
        text = read(POLICIES["composite"]).replace("  can manage_keys = owner\n", "  can see = owner\n")
        self.assertIn("nobody can make API keys for it", Compiler(parse_policy(text)).compile("x"))


class CommandMode(unittest.TestCase):
    """What the rowstile command runs inside its own transaction."""

    def test_no_transaction_control_but_base_tables(self) -> None:
        psql, cmd = compiled("docs"), compiled("docs", transaction=False)
        self.assertIn("\nBEGIN;\n", psql)
        for text in ("\nBEGIN;\n", "\nCOMMIT;\n"):
            self.assertNotIn(text, cmd)
        for sql in (psql, cmd):
            self.assertIn("CREATE TABLE IF NOT EXISTS authz.shares", sql)
            self.assertIn("CREATE TABLE IF NOT EXISTS authz.policy_versions", sql)
            self.assertNotIn("plpython3u", sql)
            self.assertNotIn("pg_extension", sql)

    def test_diff_parts(self) -> None:
        c = Compiler(parse_policy(read(POLICIES["docs"])))
        parts = c.diff_parts("x", ["3"])
        self.assertEqual(list(parts), ["setup", "before", "body", "after"])
        self.assertNotIn("ROLLBACK", "".join(parts.values()))
        self.assertNotIn("\nBEGIN;\n", parts["body"])
        self.assertIn("'3'", parts["before"])

    def test_files_argument(self) -> None:
        make = lambda c: c.compile("x", transaction=False)
        database.build('include "a.authz"', {"a.authz": read(POLICIES["docs"])}, make)
        database.build('include "a.authz"', '{"a.authz": ' + repr_json(read(POLICIES["docs"])) + "}", make)
        with self.assertRaisesRegex(PolicyError, "files must be a map"):
            database.build("app role app_user", '["a.authz"]', make)
        with self.assertRaisesRegex(PolicyError, "files must be a map"):
            database.build("app role app_user", '{"a.authz": 1}', make)

    def test_check_needs_no_database(self) -> None:
        self.assertIsNone(database.check(read(POLICIES["docs"])))
        self.assertRegex(
            database.check("app role app_user\ntype x = app.x") or "", r"^policy line 1: declare the user type"
        )

    def test_check_reads_the_policys_own_tests(self) -> None:
        # a test line of the policy is part of it: check (and the editor) say what rowstile test would refuse
        docs = read(POLICIES["docs"])
        for line, said in (
            ("test\n  user 1 can view widget 1\n", r"unknown type 'widget' \[AZ201\]"),
            ("test\n  user 1 with scope nope cannot edit file 1\n", r"no scope 'nope' in the policy .*\[AZ503\]"),
            ('test "t"\n  user $ann can view file 1\n', r"\$ann is not named yet.*\[AZ501\]"),
        ):
            self.assertRegex(database.check(docs + "\n" + line) or "", r"^policy line \d+: " + said)

    def test_remove_drops_what_apply_makes(self) -> None:
        for text in (
            "DROP SCHEMA IF EXISTS authz_gen, authz_int CASCADE",
            "DROP POLICY",
            "GRANT SELECT ON %s TO %I",
            "shares\\_obj\\_%",
            "NOT IN ('ctx', 'link_hashes')",
        ):
            self.assertIn(text, database.REMOVE_SQL)


def repr_json(s: object) -> str:
    import json

    return json.dumps(s)


class Includes(unittest.TestCase):
    """Included files passed as a map (tests/policy_errors.py has the mistakes)."""

    def test_nested_include_is_relative(self) -> None:
        pol = parse_policy(
            'include "sub/a.authz"', files={"sub/a.authz": 'include "b.authz"', "sub/b.authz": read(POLICIES["docs"])}
        )
        self.assertIn("file", pol.types)

    def test_locations_name_the_included_file(self) -> None:
        with self.assertRaises(PolicyError) as e:
            parse_policy('include "x/y.authz"', files={"x/y.authz": "app role app_user\nnot valid"})
        self.assertTrue(str(e.exception).startswith("x/y.authz line 2:"), str(e.exception))

    def test_disk_includes_still_work_for_the_file_compiler(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "part.authz"), "w", encoding="utf-8") as fh:
                fh.write(read(POLICIES["docs"]))
            pol = parse_policy('include "part.authz"', os.path.join(d, "main.authz"))
            self.assertIn("folder", pol.types)

    def test_the_file_compiler_reads_nothing_above_the_policy(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "p"))
            with open(os.path.join(d, "secret.authz"), "w", encoding="utf-8") as fh:
                fh.write("SECRET=1\n")
            with self.assertRaises(PolicyError) as e:
                parse_policy('include "../secret.authz"', os.path.join(d, "p", "main.authz"))
            self.assertIn("an included file is in the policy's folder", str(e.exception))
            self.assertNotIn("SECRET", str(e.exception))

    def test_a_byte_order_mark_is_not_part_of_the_policy(self) -> None:
        pol = parse_policy("﻿" + read(POLICIES["docs"]), files={"sub/a.authz": "﻿app role app_user\n"})
        self.assertIn("folder", pol.types)
        self.assertIn(
            "folder",
            parse_policy(
                'include "sub/a.authz"\n' + read(POLICIES["docs"]),
                files={"sub/a.authz": "﻿caveat mfa = {authz.ctx('mfa') = 'yes'}\n"},
            ).types,
        )


class Command(unittest.TestCase):
    def test_reads_included_files(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "sub"))
            files = {
                "main.authz": 'include "sub/a.authz"  -- the rest\n',
                "sub/a.authz": 'include "b.authz"\n  include "not-an-include.authz"\n-- include "commented.authz"\n',
                "sub/b.authz": "app role app_user\n",
            }
            for name, body in files.items():
                with open(os.path.join(d, *name.split("/")), "w", encoding="utf-8") as fh:
                    fh.write(body)
            text, got = rowstile_cli.read_policy(os.path.join(d, "main.authz"))
            self.assertEqual(text, files["main.authz"])
            self.assertEqual(got, {"sub/a.authz": files["sub/a.authz"], "sub/b.authz": files["sub/b.authz"]})

    def test_missing_includes_are_left_to_the_compiler(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "main.authz"), "w", encoding="utf-8") as fh:
                fh.write('include "nope.authz"\n')
            self.assertEqual(rowstile_cli.read_policy(os.path.join(d, "main.authz"))[1], {})

    def test_reads_nothing_outside_the_policys_folder(self) -> None:
        # the review runs on a pull request's files: an include must not read the runner's
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "p", "sub"))
            with open(os.path.join(d, "outside.authz"), "w", encoding="utf-8") as fh:
                fh.write("SECRET=1\n")
            names = [
                "../outside.authz",
                "sub/../../outside.authz",
                os.path.join(d, "outside.authz").replace(os.sep, "/"),
                "sub\\..\\..\\outside.authz",
            ]
            try:
                os.symlink(os.path.join(d, "outside.authz"), os.path.join(d, "p", "sub", "link.authz"))
                names.append("sub/link.authz")
            except OSError:
                pass  # Windows without the right to make links
            with open(os.path.join(d, "p", "main.authz"), "w", encoding="utf-8") as fh:
                fh.write("".join(f'include "{n}"\n' for n in names))
            self.assertEqual(rowstile_cli.read_policy(os.path.join(d, "p", "main.authz"))[1], {})

    def test_a_link_to_another_drive_is_outside(self) -> None:
        # on Windows, commonpath raises for paths on two drives (a link or a junction to D:): outside, not a traceback
        other_drive = mock.patch.object(
            os.path, "commonpath", side_effect=ValueError("Paths don't have the same drive")
        )
        with tempfile.TemporaryDirectory() as d:
            for name, text in (("main.authz", 'include "x.authz"\n'), ("x.authz", "")):
                with open(os.path.join(d, name), "w", encoding="utf-8") as fh:
                    fh.write(text)
            with other_drive:
                self.assertEqual(rowstile_cli.read_policy(os.path.join(d, "main.authz"))[1], {})
                with self.assertRaises(SystemExit):
                    rowstile_cli.Config(os.path.join(d, "rowstile.toml"), {}).inside("x.authz", "policy")

    def test_a_path_on_another_drive_is_said_as_it_is(self) -> None:
        # on Windows, relpath raises for a path on another drive than the folder it is told from: the command names
        # the path as it was given, the review reads nothing of it from git, no .gitattributes names it
        import studio

        other_drive = mock.patch.object(
            os.path, "relpath", side_effect=ValueError("path is on mount 'R:', start on mount 'C:'")
        )
        path = os.path.join(os.sep, "elsewhere", "policy.authz")
        with tempfile.TemporaryDirectory() as d, other_drive:
            self.assertIsNone(rowstile_cli.at_base("HEAD", path))
            self.assertEqual(rowstile_cli.in_repository(path), "/elsewhere/policy.authz")
            self.assertEqual(rowstile_cli.relative(path), path)
            self.assertEqual(studio.shown(path), path)
            self.assertIsNone(rowstile_cli.Config(os.path.join(d, "rowstile.toml"), {}).below(path))
        # the MCP server's check names the file with the mistake as the command said it
        import mcp

        said = f"{path}: line 3: folder has no relation or permission 'editr' [AZ203]\n"
        with other_drive, mock.patch.object(mcp, "run", return_value=(1, said)):
            result = mcp.call(None, "check", {})["structuredContent"]
        error = result.get("error") if isinstance(result, dict) else result
        self.assertEqual(error.get("file") if isinstance(error, dict) else error, path.replace(os.sep, "/"))

    def test_an_editors_address_on_windows_names_the_drive(self) -> None:
        # an editor on Windows sends file:///C:/a%20b/p.authz: the file is C:/a b/p.authz, not /C:/...
        import lsp

        with mock.patch.object(sys, "platform", "win32"):
            self.assertEqual(lsp.uri_path("file:///C:/a%20b/p.authz"), os.path.normpath("C:/a b/p.authz"))
            self.assertEqual(lsp.uri_path("file:///srv/p.authz"), os.path.normpath("/srv/p.authz"))

    def test_a_warning_on_a_connection_with_no_handler_goes_nowhere(self) -> None:
        # Studio's connections have none: a warning applying gives in its access diff (a policy that makes more
        # objects than the lock table holds) goes nowhere, and the diff goes on
        import pgwire

        db = rowstile_cli.Db(cast(pgwire.Connection, types.SimpleNamespace(on_notice=None)))
        self.assertIsNone(db.warn("this makes about 9000 objects in one transaction", hint="raise it"))
        got: list[dict[str, str]] = []
        rowstile_cli.Db(cast(pgwire.Connection, types.SimpleNamespace(on_notice=got.append))).warn("w", "d", "h")
        self.assertEqual(got, [{"S": "WARNING", "V": "WARNING", "M": "w", "D": "d", "H": "h"}])

    def test_init_finds_the_stack_in_a_folder_it_cant_list(self) -> None:
        # a project folder it may read files of but not list (no r, an x): the requirements files aren't found,
        # what pyproject.toml says is, and init goes on (a traceback stopped it, after it had written the policy)
        import stack

        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "pyproject.toml"), "w", encoding="utf-8") as fh:
                fh.write('[project]\ndependencies = ["fastapi"]\n')
            with open(os.path.join(d, "requirements.txt"), "w", encoding="utf-8") as fh:
                fh.write("sqlalchemy\n")
            self.assertEqual(stack.detect(d).found, ["FastAPI", "SQLAlchemy"])
            with mock.patch.object(stack.os, "listdir", side_effect=PermissionError(13, "Permission denied", d)):
                self.assertEqual(stack.detect(d).found, ["FastAPI"])

    def test_review_stops_where_git_cant_read_the_base(self) -> None:
        # a repository missing objects of the base (an interrupted fetch, a partial clone that can't reach its
        # remote): read as missing, a test file's checks would be listed as added and a policy reviewed as new. The
        # review stops instead, exit 2, and says what git can't read and how to fetch it (tests/review.sh: the
        # command, for the policy, a file it includes, the lock file and the tests). A file that isn't at the base
        # is none, as before.
        import contextlib
        import shutil
        import stat

        if shutil.which("git") is None:
            self.skipTest("git is not installed")
        before = os.getcwd()
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "tests"))
            for name, text in (("a.authz", "test one\n"), ("b.authz", "test two\n")):
                with open(os.path.join(d, "tests", name), "w", encoding="utf-8", newline="\n") as fh:
                    fh.write(text)

            def git(*args: str) -> str:
                return subprocess.run(
                    ["git", "-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "core.autocrlf=false", *args],
                    cwd=d,
                    check=True,
                    capture_output=True,
                    text=True,
                ).stdout.strip()

            def lose(sha: str) -> None:
                """An object taken out of the repository (git writes its objects read-only)."""
                path = os.path.join(d, ".git", "objects", sha[:2], sha[2:])
                os.chmod(path, stat.S_IWRITE | stat.S_IREAD)
                os.remove(path)

            def stops(read: Callable[[], object]) -> str:
                """What the review says as it stops, exit 2."""
                err = io.StringIO()
                with contextlib.redirect_stderr(err), self.assertRaises(SystemExit) as stop:
                    read()
                self.assertEqual(stop.exception.code, 2)
                return err.getvalue()

            for args in (["init", "-q"], ["add", "-A"], ["commit", "-q", "-m", "base"]):
                git(*args)
            blob, folder = git("rev-parse", "HEAD:tests/b.authz", "HEAD:tests").split()
            cfg = rowstile_cli.Config(os.path.join(d, "rowstile.toml"), {"tests": ["tests/*.authz"]})
            fetch = (
                ": this repository is missing objects of that commit (a partial clone that can't fetch them? fetch the "
                "base's history: fetch-depth: 0 with actions/checkout, and no filter)\n"
            )
            b, c = os.path.join("tests", "b.authz"), os.path.join("tests", "c.authz")  # as the command names them
            os.chdir(d)
            try:
                both = {"tests/a.authz": "test one\n", "tests/b.authz": "test two\n"}
                self.assertEqual(rowstile_cli.base_tests(cfg, "HEAD"), both)
                self.assertIsNone(rowstile_cli.at_base("HEAD", c))  # a file added since: not at the base
                lose(blob)
                said = stops(lambda: rowstile_cli.base_tests(cfg, "HEAD"))
                self.assertEqual(said, f"rowstile review: git can't read tests/b.authz at HEAD{fetch}")
                said = stops(lambda: rowstile_cli.at_base("HEAD", b))
                self.assertEqual(said, f"rowstile review: git can't read {b} at HEAD{fetch}")
                lose(folder)
                said = stops(lambda: rowstile_cli.base_tests(cfg, "HEAD"))
                self.assertEqual(said, f"rowstile review: git can't list the files at HEAD{fetch}")
                # the same file in a folder git can't list: whether it is there can't be known
                said = stops(lambda: rowstile_cli.at_base("HEAD", c))
                self.assertEqual(said, f"rowstile review: git can't read {c} at HEAD{fetch}")
            finally:
                os.chdir(before)

    def test_prints_utf8_whatever_the_systems_encoding(self) -> None:
        # on Windows, Python writes into a pipe or a file in the system's code page: an arrow or a name in another
        # script stopped the command there (UnicodeEncodeError), and a graph written to a file was not UTF-8
        policy = (
            "app role app_user\ntype user = app.users\ntype doc = app.docs\n  owner : user = owner_id\n"
            "  can view = owner or {note = '閲覧 →'}\ninvariants\n  never doc: view and not owner\n"
        )
        cli = os.path.join(ROOT, "cli", "rowstile_cli.py")
        env = {k: v for k, v in os.environ.items() if k != "PYTHONUTF8"} | {"PYTHONIOENCODING": "cp1252"}
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "policy.authz"), "w", encoding="utf-8", newline="\n") as fh:
                fh.write(policy)
            for command, shown in (("prove", "doc 1: note = '閲覧 →'"), ("graph", "doc · app.docs")):
                p = subprocess.run([sys.executable, cli, command, "policy.authz"], cwd=d, env=env, capture_output=True)
                self.assertNotIn(b"Traceback", p.stderr, command)
                self.assertIn(shown, p.stdout.decode("utf-8"), command)
            p = subprocess.run([sys.executable, cli, "check", "閲.authz"], cwd=d, env=env, capture_output=True)
            self.assertIn("閲.authz: ", p.stderr.decode("utf-8"))

    def test_a_row_that_isnt_json_is_shown_as_it_arrived(self) -> None:
        # Windows PowerShell 5 and cmd take the double quotes out of '{"column": 1}': JSON's message alone
        # ("Expecting property name enclosed in double quotes") doesn't say what happened
        import contextlib
        import io

        def refused(row: str) -> str:
            err = io.StringIO()
            with contextlib.redirect_stderr(err), self.assertRaises(SystemExit) as stop:
                rowstile_cli.check_row(row)
            self.assertEqual(stop.exception.code, 2)
            return err.getvalue()

        rowstile_cli.check_row('{"project_id": 1, "author_id": 3}')
        said = refused("{project_id: 1, author_id: 3}")
        self.assertIn("--row: not JSON: {project_id: 1, author_id: 3}\n", said)
        self.assertIn("The shell took the double quotes: in Windows PowerShell write '{\\\"column\\\": 1}'", said)
        self.assertIn('in cmd "{\\"column\\": 1}"', said)
        self.assertNotIn("The shell", refused('{"project_id": }'))  # a mistake of one's own
        self.assertIn("JSON object", refused("[1]"))

    def test_only_what_is_below_is_marked_generated(self) -> None:
        # .gitattributes names files from its own folder: a migrations folder or a lock file outside it gets no line
        import migrations

        with tempfile.TemporaryDirectory() as d:
            cfg = rowstile_cli.Config(os.path.join(d, "p", "rowstile.toml"), {})
            self.assertEqual(cfg.below(os.path.join(d, "p", "db", "policy.lock")), "db/policy.lock")
            self.assertIsNone(cfg.below(os.path.join(d, "migrations")))
            self.assertIsNone(cfg.below(d))
        self.assertEqual(
            migrations.generated_patterns("prisma", "prisma/migrations", "db/policy.lock"),
            ["db/policy.lock linguist-generated=true", "prisma/migrations/*_authz_*/** linguist-generated=true"],
        )
        self.assertEqual(
            migrations.generated_patterns("sql", None, "db/policy.lock"), ["db/policy.lock linguist-generated=true"]
        )
        self.assertEqual(migrations.generated_patterns("sql", None, None), [])

    def test_review_names_files_from_this_folder_not_from_the_top_folders_path(self) -> None:
        # git names the top folder by its resolved path; through a subst drive or a junction (Windows) this
        # process reaches the same folder by another one, even on another drive, so the two are never compared
        import shutil

        if shutil.which("git") is None:
            self.skipTest("git is not installed")
        real_git = rowstile_cli.git

        def git(*args: str) -> str | None:
            return "Z:/elsewhere\n" if args == ("rev-parse", "--show-toplevel") else real_git(*args)

        before = os.getcwd()
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "p", "tests"))
            # a name with an accent: git lists it quoted ("tests/acc\303\250s.authz") unless asked not to
            for name, text in (("a.authz", b"test one\n"), ("accès.authz", b"test two\n")):
                with open(os.path.join(d, "p", "tests", name), "wb") as fh:
                    fh.write(text)
            with open(os.path.join(d, "p", "latin1.authz"), "wb") as fh:
                fh.write("-- propriétaire\n".encode("latin-1"))
            for args in (["init", "-q"], ["add", "-A"], ["commit", "-q", "-m", "base"]):
                subprocess.run(
                    ["git", "-c", "user.name=t", "-c", "user.email=t@example.com", *args],
                    cwd=d,
                    check=True,
                    capture_output=True,
                )
            os.chdir(os.path.join(d, "p"))  # the project in a folder of the repository
            try:
                cfg = rowstile_cli.Config(os.path.join(os.getcwd(), "rowstile.toml"), {"tests": ["tests/*.authz"]})
                with mock.patch.object(rowstile_cli, "git", git):
                    self.assertEqual(
                        rowstile_cli.base_tests(cfg, "HEAD"),
                        {"tests/a.authz": "test one\n", "tests/accès.authz": "test two\n"},
                    )
                    self.assertEqual(rowstile_cli.in_repository(os.path.join("tests", "a.authz")), "p/tests/a.authz")
                self.assertEqual(list(rowstile_cli.read_tests(cfg.tests())), ["tests/a.authz", "tests/accès.authz"])
                # a file at the base that isn't UTF-8 is read, the byte replaced: no traceback from the review
                self.assertEqual(rowstile_cli.at_base("HEAD", "latin1.authz"), "-- propri�taire\n")
            finally:
                os.chdir(before)

    def test_typescript_sdk_gets_only_the_names(self) -> None:
        # an app on the TypeScript SDK (a @rowstile/* dependency) gets the policy's names, registered with it
        with tempfile.TemporaryDirectory() as d:
            toml = os.path.join(d, "rowstile.toml")
            cfg = rowstile_cli.Config(toml, {"clients": {"ts": "src/authz.gen.ts", "py": "authz.py"}})
            self.assertEqual(sorted(cfg.clients), ["py", "ts"])
            with open(os.path.join(d, "package.json"), "w", encoding="utf-8") as fh:
                fh.write('{"dependencies": {"next": "16", "pg": "8"}}')
            self.assertEqual(sorted(cfg.clients), ["py", "ts"])  # an app without the SDK: the whole client
            with open(os.path.join(d, "package.json"), "w", encoding="utf-8") as fh:
                fh.write('{"dependencies": {"next": "16", "@rowstile/prisma": "0.1.0"}}')
            self.assertEqual(sorted(cfg.clients), ["py", "ts-sdk"])
        names = Compiler(parse_policy(read(POLICIES["docs"]))).compile("x") and database.client(
            "ts-sdk", read(POLICIES["docs"])
        )
        self.assertIn('declare module "@rowstile/client"', names)
        self.assertIn("permissions: typeof permissions;", names)
        self.assertNotIn("class Refused", names)  # the SDK's own errors, or instanceof would fail

    def test_stack(self) -> None:
        import stack

        def at(files: dict[str, str]) -> str:
            d = tempfile.mkdtemp()
            for name, body in files.items():
                os.makedirs(os.path.dirname(os.path.join(d, name)) or d, exist_ok=True)
                with open(os.path.join(d, name), "w", encoding="utf-8") as fh:
                    fh.write(body)
            return d

        s = stack.detect(
            at(
                {
                    "package.json": '{"dependencies": {"drizzle-orm": "1", "pg": "8"}}',
                    "drizzle.config.ts": 'export default { out: "./db/drizzle" }',
                    "src/db.ts": "drizzle(pool)",
                }
            )
        )
        self.assertEqual(
            (s.tool, s.migrations_dir, s.clients, s.npm, s.setup_file),
            ("drizzle", "db/drizzle", {"ts": "src/authz.gen.ts"}, ["@rowstile/drizzle"], "src/db.ts"),
        )
        s = stack.detect(
            at(
                {
                    "requirements.txt": "fastapi>=0.110\nsqlmodel\n",
                    "alembic.ini": "script_location = %(here)s/alembic\n",
                    "app/main.py": "app = FastAPI()\n",
                }
            )
        )
        self.assertEqual(
            (s.found, s.tool, s.migrations_dir, s.pip, s.setup_file),
            (
                ["FastAPI", "SQLModel", "Alembic"],
                "alembic",
                "alembic/versions",
                "rowstile[fastapi,sqlalchemy]",
                "app/main.py",
            ),
        )
        self.assertFalse(s.pip_there)
        # the stack pages install FastAPI's part through rowstile's own extras: the stack is found there too, and
        # rowstile, a dependency already, isn't asked for again
        s = stack.detect(
            at(
                {
                    "pyproject.toml": '[project]\ndependencies = [\n    "rowstile[asyncpg,fastapi,sqlalchemy]>=0.1.0a4",\n]\n',
                    "alembic.ini": "script_location = migrations\n",
                }
            )
        )
        self.assertEqual((s.found, s.pip_there), (["FastAPI", "SQLAlchemy", "Alembic"], True))
        self.assertEqual(s.setup[0], "from rowstile.fastapi import Rowstile")
        # a release's name is bare; an alpha, a beta, a candidate or main's build asks for at least itself, which
        # lets pip take a pre-release (a bare name got the 0.0.0 placeholder while only an alpha was published)
        self.assertEqual(stack.pip_requirement("rowstile[fastapi]", "0.2.0"), "rowstile[fastapi]")
        self.assertEqual(stack.pip_requirement("rowstile[fastapi]", "0.1.0-alpha.1"), "rowstile[fastapi]>=0.1.0a1")
        self.assertEqual(stack.pip_requirement("rowstile[fastapi]", "0.1.0-beta.1"), "rowstile[fastapi]>=0.1.0b1")
        self.assertEqual(stack.pip_requirement("rowstile", "0.2.0-rc.12"), "rowstile>=0.2.0rc12")
        self.assertEqual(stack.pip_requirement("rowstile", "0.2.0-dev"), "rowstile>=0.2.0.dev0")
        s = stack.detect(at({"migrations/0001.sql": "CREATE TABLE t ();"}))
        self.assertEqual((s.tool, s.migrations_dir, s.npm, s.pip), ("sql", "migrations", [], ""))
        d = at({"package.json": '{\n\t"dependencies": {\n\t\t"next": "16"\n\t}\n}\n'})
        self.assertEqual(stack.add_npm(d, ["@rowstile/next"], "1.2.3"), ["@rowstile/next", "rowstile"])
        with open(os.path.join(d, "package.json"), encoding="utf-8") as fh:
            text = fh.read()
        self.assertIn('\t\t"@rowstile/next": "^1.2.3"', text)
        self.assertIn('"devDependencies"', text)
        self.assertEqual(stack.add_npm(d, ["@rowstile/next"], "1.2.3"), [])
        self.assertEqual(stack.add_npm(at({}), ["@rowstile/pg"], "1.2.3"), [])  # no package.json: nothing to add to

    def test_stack_as_apps_write_their_files(self) -> None:
        """What init finds in the files apps have: requirements with comments, extras and markers, Poetry's
        dependencies on one line, a package.json that isn't JSON or holds only tools, each Node driver."""
        import stack

        def detect(files: dict[str, str]) -> stack.Stack:
            d = tempfile.mkdtemp()
            for name, body in files.items():
                os.makedirs(os.path.dirname(os.path.join(d, name)) or d, exist_ok=True)
                with open(os.path.join(d, name), "w", encoding="utf-8") as fh:
                    fh.write(body)
            return stack.detect(d)

        fastapi = ["FastAPI", "SQLAlchemy"]
        for files in (
            {
                "requirements.txt": "# the app\n-r base.txt\n--index-url https://pypi.org/simple\n"
                'fastapi[standard]>=0.110 ; python_version >= "3.11"\nSQLAlchemy==2.0.30  # pinned\n'
                "psycopg[binary,pool]~=3.2\n\nasyncpg\n-e .\n"
            },
            # Poetry writes a version in parentheses; a list on one line has no line of its own for each
            {"pyproject.toml": '[project]\ndependencies = ["fastapi (>=0.115.0,<0.116.0)", "sqlalchemy (>=2.0)"]\n'},
            {
                "pyproject.toml": '[project]\ndependencies = ["fastapi @ git+https://example.com/fastapi", "sqlalchemy"]\n'
            },
        ):
            s = detect(files)
            self.assertEqual((s.found, s.setup[:1]), (fastapi, ["from rowstile.fastapi import Rowstile"]), files)
        self.assertEqual(s.pip, "rowstile[fastapi,sqlalchemy]")
        # SQLAlchemy without FastAPI, and Alembic where alembic.ini says
        s = detect({"requirements.txt": "sqlalchemy\npsycopg\n", "alembic.ini": "script_location = db/migrations\n"})
        self.assertEqual(
            (s.found, s.tool, s.migrations_dir, s.pip, s.setup[:2]),
            (
                ["SQLAlchemy", "Alembic"],
                "alembic",
                "db/migrations/versions",
                "rowstile[sqlalchemy,psycopg]",
                [
                    "import rowstile.sqlalchemy",
                    "rowstile.sqlalchemy.install(engine)   # with rowstile.acting_as(user_id): ...",
                ],
            ),
        )
        self.assertEqual(
            s.setup[2:],
            [
                "# alembic env.py: context.configure(..., include_name=include_name, include_object=include_object)",
                "from rowstile.alembic import include_name, include_object",
            ],
        )
        # a driver alone: what to install, no line of setup to change, no tool
        s = detect({"requirements.txt": "psycopg\n"})
        self.assertEqual((s.found, s.pip, s.setup, s.tool), ([], "rowstile[psycopg]", [], ""))
        # a package.json that isn't JSON is read as none, and one that holds only the tools of a Python app's
        # front end leaves the Python stack to be found
        s = detect({"package.json": "{ not json", "requirements.txt": "fastapi\n"})
        self.assertEqual((s.found, s.npm, s.pip), (["FastAPI"], [], "rowstile[fastapi]"))
        s = detect(
            {
                "package.json": '{"devDependencies": {"prettier": "3"}}',
                "requirements.txt": "fastapi\nsqlalchemy\n",
                "alembic.ini": "script_location = alembic\n",
            }
        )
        self.assertEqual(
            (s.found, s.npm, s.clients, s.tool), (fastapi + ["Alembic"], [], {"py": "authz_types.py"}, "alembic")
        )
        # each Node driver gets its package, and the client the SDK registers the names with
        s = detect({"package.json": '{"dependencies": {"postgres": "3"}}'})
        self.assertEqual(
            (s.npm, s.setup[:1], s.clients),
            (["@rowstile/postgres"], ['import { authz } from "@rowstile/postgres";'], {"ts": "authz.gen.ts"}),
        )
        # ... and React's and Vitest's are named, not added: what the app needs to run is all init adds
        s = detect({"package.json": '{"dependencies": {"pg": "8", "react": "19"}, "devDependencies": {"vitest": "3"}}'})
        self.assertEqual(
            (s.npm, s.npm_maybe, s.setup[:1]),
            (["@rowstile/pg"], ["@rowstile/react", "@rowstile/vitest"], ['import { authz } from "@rowstile/pg";']),
        )
        self.assertEqual(
            detect({"package.json": '{"dependencies": {"react": "19", "@rowstile/react": "0"}}'}).npm_maybe, []
        )
        # each package init adds or names has its reason
        sdks = os.path.join(os.path.dirname(ROOT), "sdk", "typescript")
        packages = {"@rowstile/" + d for d in os.listdir(sdks) if os.path.isfile(os.path.join(sdks, d, "package.json"))}
        self.assertLessEqual(packages - {"@rowstile/client"} | {"rowstile"}, set(stack.NPM_WHY))
        # Drizzle without its config file: its default folder; and a migrations folder with no SQL in it is no tool
        s = detect({"package.json": '{"dependencies": {"drizzle-orm": "0.40"}}'})
        self.assertEqual((s.found, s.tool, s.migrations_dir, s.setup_file), (["Drizzle"], "drizzle", "drizzle", ""))
        self.assertEqual(detect({"migrations/README": "x"}).tool, "")
        # the source files init looks through for the line to change stop at a limit (a big tree isn't read whole)
        d = tempfile.mkdtemp()
        for name in ("a.ts", "b.ts", "c.ts"):
            with open(os.path.join(d, name), "w", encoding="utf-8") as fh:
                fh.write("export {};\n")
        self.assertEqual(stack._files(d, (".ts",), limit=2), ["a.ts", "b.ts"])

    def test_no_database_named_is_said(self) -> None:
        # with no --db, no `database` in rowstile.toml and no variable, libpq's defaults are tried (a local socket):
        # when they fail the message says nothing named a database and how to name one, not only a socket nobody
        # gave. A database that was named fails as itself
        e = rowstile_cli.pgwire.Unreachable("the socket /var/run/postgresql/.s.PGSQL.5432", "no such file or directory")
        named = ("PGHOST", "PGPORT", "PGDATABASE", "PGUSER", "PGSERVICE")
        with mock.patch.dict(os.environ, {k: v for k, v in os.environ.items() if k not in named}, clear=True):
            said = rowstile_cli.cant_connect(e, None)
            self.assertTrue(
                said.startswith(
                    "can't connect: no database was named, and the default failed (the socket "
                    "/var/run/postgresql/.s.PGSQL.5432: no such file or directory)\n"
                ),
                said,
            )
            self.assertIn("--db DSN, `database` in rowstile.toml, or DATABASE_URL", said)
            self.assertEqual(rowstile_cli.cant_connect(e, "host=db"), f"can't connect to {e}")
        with mock.patch.dict(os.environ, {"PGHOST": "db"}):
            self.assertEqual(rowstile_cli.cant_connect(e, None), f"can't connect to {e}")

    def test_env_files_are_read_for_the_database_only(self) -> None:
        # a .env file as apps write them: comments, export, quotes, ${NAME} from the environment or the lines above
        with mock.patch.dict(os.environ, {"FROM_ENV": "e"}, clear=True):  # (a PGHOST of the suite's would come first)
            self.assertEqual(
                rowstile_cli.parse_env(
                    "# the app's own\n"
                    "DATABASE_URL=postgresql://o:p@localhost:5432/dev   # the owner\n"
                    "export PGHOST = db\n"
                    'QUOTED="a \\"b\\"\\n#c"  # after\n'
                    "SINGLE='${FROM_ENV} as written' and more\n"
                    'URL="postgresql://${PGHOST}:${FROM_ENV}@${LATER}/d"\n'
                    "LATER=l\n"
                    "EMPTY=\n"
                    "not a line\n=x\n1BAD=x\nA-B=x\n"
                ),
                {
                    "DATABASE_URL": "postgresql://o:p@localhost:5432/dev",
                    "PGHOST": "db",
                    "QUOTED": 'a "b"\n#c',
                    "SINGLE": "${FROM_ENV} as written",
                    "URL": "postgresql://db:e@/d",
                    "LATER": "l",
                    "EMPTY": "",
                },
            )
        with tempfile.TemporaryDirectory() as d:

            def write(name: str, text: str) -> None:
                with open(os.path.join(d, name), "w", encoding="utf-8") as fh:
                    fh.write(text)

            write(".env", "DATABASE_URL=from-env-file\nPGHOST=h1\nOWNER=o1\nGIT_SSH_COMMAND=evil\nPATH=/evil\n")
            write(".env.local", "\ufeffPGHOST=h2\nOWNER=o2\nPGPORT=1\n")  # with a byte order mark
            # the environment first, then .env.local, then .env; and of the files' names, only those that say
            # where the database is reach the environment: a pull request's .env is read by the review in CI
            with mock.patch.dict(os.environ, {"PGPORT": "7", "PATH": "/bin"}, clear=True):
                e = rowstile_cli.EnvFiles()
                e.load(d)
                self.assertEqual(
                    dict(os.environ), {"PGPORT": "7", "PATH": "/bin", "DATABASE_URL": "from-env-file", "PGHOST": "h2"}
                )
                self.assertEqual((e.get("OWNER"), e.get("PGPORT"), e.get("NOWHERE")), ("o2", "7", None))
                self.assertEqual(e.files(["DATABASE_URL"]), ".env")
                self.assertEqual(e.files(["PGPORT"]), "")  # the environment's own
                self.assertEqual(e.files(["DATABASE_URL", "PGHOST", "OWNER"]), ".env and .env.local")
                self.assertEqual(e.skipped, [])
                # which files named the database a command uses: none for --db or a literal in rowstile.toml
                with mock.patch.object(rowstile_cli, "ENV", e):
                    config = lambda data: rowstile_cli.Config(os.path.join(d, "rowstile.toml"), data)
                    self.assertEqual(config({}).database_from(None), ".env")
                    self.assertEqual(config({}).database_from("dbname=x"), "")
                    self.assertEqual(config({"database": "env:OWNER"}).database_from(None), ".env.local")
                    self.assertEqual(config({"database": "env:OWNER"}).database, "o2")
                    self.assertEqual(config({"database": "dbname=x"}).database_from(None), "")
                    e.where = ".env"
                    said = rowstile_cli.cant_connect(OSError("refused"), "from-env-file")
                    self.assertEqual(said, "can't connect: refused\n(the database is the one .env names)")
            # a .env that is a link out of the folder isn't read (as the policy isn't), and a failure says so
            outside = os.path.join(d, "outside")
            os.mkdir(os.path.join(d, "in"))
            write("outside", "DATABASE_URL=theirs\n")
            try:
                os.symlink(outside, os.path.join(d, "in", ".env"))
            except OSError:
                return  # Windows without the right to make links
            with mock.patch.dict(os.environ, {}, clear=True):
                e = rowstile_cli.EnvFiles()
                e.load(os.path.join(d, "in"))
                self.assertNotIn("DATABASE_URL", os.environ)
                self.assertEqual(e.skipped, [".env is a link out of its folder: it isn't read"])
                with mock.patch.object(rowstile_cli, "ENV", e):
                    self.assertTrue(rowstile_cli.cant_connect(OSError("x"), None).endswith(e.skipped[0]))

    def test_without_git_and_help_after_a_command(self) -> None:
        # a machine without git: the review says so, not a traceback; `rowstile review --help` is the usage
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "rowstile.toml"), "w", encoding="utf-8") as fh:
                fh.write('policy = "policy.authz"\n')
            with open(os.path.join(d, "policy.authz"), "w", encoding="utf-8") as fh:
                fh.write(read(POLICIES["docs"]))
            env = dict(os.environ, PATH=d)
            run = lambda *a: subprocess.run(
                [sys.executable, os.path.join(ROOT, "cli", "rowstile_cli.py"), *a],
                cwd=d,
                env=env,
                capture_output=True,
                text=True,
            )
            p = run("review", "--base", "main")
            self.assertEqual(p.returncode, 2, p.stderr)
            self.assertIn("git is not installed", p.stderr)
            self.assertNotIn("Traceback", p.stderr)
            # a command's own lines of the usage, where the database comes from, and nothing of the others
            p = run("review", "--help")
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertTrue(p.stdout.startswith("rowstile review  [POLICY.authz] [--base REF]"), p.stdout)
            self.assertIn("\nThe database is --db DSN", p.stdout)
            self.assertIn("\nrowstile --help: every command, and rowstile.toml\n", p.stdout)
            self.assertNotIn("rowstile fmt", p.stdout)
            self.assertNotIn("policy   =", p.stdout)

    def test_every_command_has_help_of_its_own(self) -> None:
        for cmd in rowstile_cli.ARGUMENTS:
            text = rowstile_cli.command_help(cmd)
            self.assertTrue(text.startswith(f"rowstile {cmd}"), cmd)
            self.assertEqual(len(re.findall(r"^rowstile \S", text, re.M)), 2, text)  # its own, and the last line
        # init says which schema it reads when none is named: the question a first run asked of --help
        self.assertIn("(every schema of\n", rowstile_cli.command_help("init"))
        self.assertIn("the app's, or those --schema names)", rowstile_cli.command_help("init"))
        # each of a command's lines, to the last; and where the database comes from, .env files too
        review = rowstile_cli.command_help("review")
        self.assertRegex(review, r"\n +\(exit 0 whatever it finds: test and migrate --check gate\)\n\n")
        self.assertIn("\nWithout --db, those variables may be in .env.local or .env beside rowstile.toml", review)

    @staticmethod
    def arguments_named(signature: str) -> tuple[int, int | None]:
        """How many arguments a usage line's signature names, its options left out: (fewest, most; None: any)."""
        words = re.sub(r"\[--[^\]]*\]", "", signature)  # [--as WHO], [--markdown|--json]
        words = re.sub(rf"(?:{'|'.join(rowstile_cli.VALUED)}) \S+", "", words)  # --as WHO
        words = re.sub(r"--[a-z][a-z-]*", "", words)  # --yes
        fewest, most = 0, 0
        for word in re.findall(r'\[[^\]]*\]|"[^"]*"|\S+', words):  # [ID], "SELECT ...", TYPE
            fewest += not word.startswith("[")
            most += 1
        return fewest, None if re.search(r"\.\.\.\]", words) else most

    @staticmethod
    def reference_table() -> dict[str, tuple[set[str], bool]]:
        """The commands docs/reference/tools.md's table names in its first column, each with the options it names
        and whether it names a policy file (p.authz)."""
        with open(os.path.join(os.path.dirname(ROOT), "docs", "reference", "tools.md"), encoding="utf-8") as fh:
            page = fh.read()
        rows = page[page.index("\n| command | what |\n") :].split("\n\n")[0].splitlines()[3:]
        out: dict[str, tuple[set[str], bool]] = {}
        for row in rows:
            first = re.split(r"(?<!\\)\|", row)[1]
            for span in re.findall(r"`rowstile ([^`]*)`", first):
                head = span.split()[0].split("\\|")
                for cmd in head if all(c in rowstile_cli.ARGUMENTS for c in head) else head[:1]:
                    options, policy = out.get(cmd, (set(), False))
                    options |= set(re.findall(r"(?<![\w-])--[a-z][a-z-]*", span)) - {cmd}
                    out[cmd] = (options, policy or "p.authz" in span)
        return out

    def test_each_command_takes_the_options_its_usage_names(self) -> None:
        # the options the command takes (it refuses the others) are those its usage names, and those the reference's
        # table names (docs/reference/tools.md), and --db where it reads a database; --downgrade on push, migrate and
        # remove is named once in the usage, under apply. The usage names the arguments it takes, and the table the
        # policy file where the usage does
        import features
        import mcp

        listed = features.usage()
        table = self.reference_table()
        self.assertEqual(set(table), set(listed), "the commands of docs/reference/tools.md's table and of --help")
        for cmd, takes in rowstile_cli.ARGUMENTS.items():
            options = set(takes.options.split())
            named = listed[cmd] | ({"--downgrade"} if cmd in ("push", "migrate", "remove") else set())
            self.assertEqual(options - {"--db"}, named - {"--db"}, cmd)  # (review names --db: its access part)
            self.assertEqual(options - {"--db"}, table[cmd][0] - {"--db"}, f"docs/reference/tools.md: rowstile {cmd}")
            line = rowstile_cli.usage_lines(cmd)[0]  # its words, then (at column 47, if on this line) what it does
            signature = (line[:47] if line[45:47] == "  " else line).removeprefix(f"rowstile {cmd}")
            self.assertEqual(self.arguments_named(signature), (takes.fewest, takes.most), f"rowstile {cmd} --help")
            self.assertEqual(table[cmd][1], "POLICY.authz" in signature, f"docs/reference/tools.md: rowstile {cmd}")
        # the MCP server passes its --db to the commands that read a database, and to no other
        for tool in features.mcp_tools():
            name = tool.removeprefix("mcp.")
            self.assertEqual(name in mcp.NO_DATABASE, "--db" not in rowstile_cli.ARGUMENTS[name].options, name)

    def test_every_setting_is_in_help_and_the_reference(self) -> None:
        # the rowstile.toml that --help and docs/reference/tools.md show holds every setting rowstile reads, and no other
        import tomllib

        assert rowstile_cli.__doc__ is not None
        usage = rowstile_cli.__doc__.split("\nrowstile.toml:\n\n")[1].split("\n\n")[0]
        with open(os.path.join(os.path.dirname(ROOT), "docs", "reference", "tools.md"), encoding="utf-8") as fh:
            page = fh.read()
        reference = page.split("\n```toml\n")[1].split("\n```\n")[0]
        for where, text in (("rowstile --help", textwrap.dedent(usage)), ("docs/reference/tools.md", reference)):
            shown = tomllib.loads(text)
            tables = {k: set(v) for k, v in shown.items() if isinstance(v, dict)}
            tables[""] = {k for k, v in shown.items() if not isinstance(v, dict)}
            self.assertEqual(tables, {k: set(v) for k, v in rowstile_cli.SETTINGS.items()}, where)

    def test_an_env_file_that_isnt_utf8_is_said(self) -> None:
        # a .env saved in another encoding (an accent in a comment) isn't read: nothing of it reaches the
        # environment, and a connection that fails says why
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, ".env"), "wb") as fh:
                fh.write("# the café's database\nDATABASE_URL=dbname=x\n".encode("latin-1"))
            with mock.patch.dict(os.environ, {}, clear=True):
                e = rowstile_cli.EnvFiles()
                e.load(d)
                self.assertNotIn("DATABASE_URL", os.environ)
                self.assertEqual(len(e.skipped), 1, e.skipped)
                self.assertTrue(e.skipped[0].startswith(".env can't be read ('utf-8' codec can't decode"), e.skipped)
                with mock.patch.object(rowstile_cli, "ENV", e):
                    self.assertTrue(rowstile_cli.cant_connect(OSError("x"), None).endswith(e.skipped[0]))

    def test_dev_writes_migrations_only_with_a_migrations_table(self) -> None:
        # rowstile dev writes the migration write_after seconds after the last save, and only in a project whose
        # rowstile.toml has [migrations]: without it, never
        config = lambda data: rowstile_cli.Config(None, data)
        self.assertEqual(config({"policy": "db/policy.authz"}).write_after, 0)
        self.assertEqual(config({"migrations": {"tool": "sql"}}).write_after, 300)
        self.assertEqual(config({"migrations": {"write_after": 5}}).write_after, 5)
        self.assertEqual(config({"migrations": {"write_after": 0}}).write_after, 0)

    def test_migrate_says_what_stops_the_tool_and_how_much_changed(self) -> None:
        # Alembic with two heads (two branches each added a revision): said, and nothing written; a migration of
        # many changes lists the first twenty of them, and how many more (--check too, which listed twenty alone)
        text = read(POLICIES["docs"])
        with tempfile.TemporaryDirectory() as d:
            policy = os.path.join(d, "policy.authz")
            with open(policy, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(text)
            os.makedirs(os.path.join(d, "versions"))
            for rev in ("aaa", "bbb"):
                with open(os.path.join(d, "versions", f"{rev}.py"), "w", encoding="utf-8") as fh:
                    fh.write(f'revision = "{rev}"\ndown_revision = None\n')
            run = lambda *a: subprocess.run(
                [sys.executable, os.path.join(ROOT, "cli", "rowstile_cli.py"), *a],
                cwd=d,
                capture_output=True,
                text=True,
                encoding="utf-8",
            )
            p = run("migrate", "policy.authz", "--tool", "alembic", "--dir", "versions")
            self.assertEqual(p.returncode, 2, p.stderr)
            self.assertTrue(p.stderr.startswith("rowstile migrate: "), p.stderr)
            self.assertTrue(
                p.stderr.endswith("versions has several heads (aaa, bbb): merge them first (alembic merge heads)\n"),
                p.stderr,
            )
            self.assertFalse(os.path.exists(os.path.join(d, "policy.lock")))
            self.assertEqual(run("migrate", "policy.authz", "--tool", "sql").returncode, 0)
            extra = "".join(f"  can extra{i} = view\n" for i in range(25))
            with open(policy, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(
                    replaced(
                        text, "  can share = owner or folder.share\n", "  can share = owner or folder.share\n" + extra
                    )
                )
            for check, code in ((["--check"], 1), ([], 0)):
                p = run("migrate", "policy.authz", "--tool", "sql", *check)
                self.assertEqual(p.returncode, code, p.stderr)
                self.assertEqual(p.stdout.count("  + type file: can extra"), 20, p.stdout)
                self.assertIn("\n  ... and 5 more\n", p.stdout)

    def test_migrate_dir_is_a_folder_of_rowstile_tomls(self) -> None:
        # --dir, as [migrations] dir and the other paths rowstile.toml holds, is read from rowstile.toml's folder,
        # wherever the command runs (docs/reference/tools.md says so)
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "rowstile.toml"), "w", encoding="utf-8") as fh:
                fh.write('policy = "policy.authz"\n[migrations]\ntool = "sql"\n')
            with open(os.path.join(d, "policy.authz"), "w", encoding="utf-8", newline="\n") as fh:
                fh.write(read(POLICIES["docs"]))
            os.makedirs(os.path.join(d, "sub"))
            p = subprocess.run(
                [sys.executable, os.path.join(ROOT, "cli", "rowstile_cli.py"), "migrate", "--dir", "m", "--name", "a"],
                cwd=os.path.join(d, "sub"),
                capture_output=True,
                text=True,
                encoding="utf-8",
            )
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertEqual([f.endswith("_a.sql") for f in os.listdir(os.path.join(d, "m"))], [True], p.stdout)
            self.assertEqual(os.listdir(os.path.join(d, "sub")), [])

    def test_migrate_finds_alembics_head_as_revisions_are_written(self) -> None:
        # a merge's revisions, laid out over lines (black and Ruff do it to a long tuple): the merge is the head, where
        # the two it merges were taken for heads too ("several heads: merge them first"). And a revision that names
        # no down_revision (Alembic wants one, None for the first) counts as a first one
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "policy.authz"), "w", encoding="utf-8", newline="\n") as fh:
                fh.write(read(POLICIES["docs"]))

            def head_written(revisions: dict[str, str | None]) -> str:
                """The down_revision of the revision rowstile migrate writes after these (name: their down_revision,
                None for no such line), or what it said instead."""
                versions = tempfile.mkdtemp(dir=d)
                for name, down in revisions.items():
                    with open(os.path.join(versions, f"{name}.py"), "w", encoding="utf-8") as fh:
                        fh.write(f'"""{name}"""\n\nrevision: str = "{name}"\n')
                        if down is not None:
                            fh.write(f"down_revision: Union[str, Sequence[str], None] = {down}\n")
                        fh.write("branch_labels = None\n")
                lock = os.path.join(d, "policy.lock")
                if os.path.exists(lock):
                    os.remove(lock)
                p = subprocess.run(
                    [sys.executable, os.path.join(ROOT, "cli", "rowstile_cli.py"), "migrate", "policy.authz"]
                    + ["--tool", "alembic", "--dir", versions],
                    cwd=d,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                )
                written = [f for f in os.listdir(versions) if f.endswith("_policy.py")]
                if p.returncode or len(written) != 1:
                    return p.stderr
                with open(os.path.join(versions, written[0]), encoding="utf-8") as fh:
                    return re.findall(r"(?m)^down_revision: str \| None = (.*)$", fh.read())[0]

            merged: dict[str, str | None] = {
                "r0": "None",
                "r1": '"r0"',
                "r2": '"r0"',
                "m": '(\n    "r1",\n    "r2",\n)',
            }
            self.assertEqual(head_written(merged), "'m'")
            self.assertEqual(head_written({"x": None}), "'x'")

    def test_a_file_it_cant_write_is_named(self) -> None:
        # the client's path is a folder: the file and why, exit 2, where the command stopped with a traceback
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "rowstile.toml"), "w", encoding="utf-8") as fh:
                fh.write('policy = "policy.authz"\n[clients]\npy = "out"\n')
            with open(os.path.join(d, "policy.authz"), "w", encoding="utf-8") as fh:
                fh.write(read(POLICIES["docs"]))
            os.mkdir(os.path.join(d, "out"))
            p = subprocess.run(
                [sys.executable, os.path.join(ROOT, "cli", "rowstile_cli.py"), "client"],
                cwd=d,
                capture_output=True,
                text=True,
                encoding="utf-8",
            )
            self.assertEqual(p.returncode, 2, p.stderr)
            self.assertNotIn("Traceback", p.stderr)
            self.assertTrue(p.stderr.startswith("out: "), p.stderr)  # Is a directory (on Windows, Permission denied)

    def test_lsp_takes_no_db(self) -> None:
        # the language server reads the database rowstile.toml names, the editor's folder's: a --db it would ignore
        # is refused, as an option a command doesn't take is
        with tempfile.TemporaryDirectory() as d:
            p = subprocess.run(
                [sys.executable, os.path.join(ROOT, "cli", "rowstile_cli.py"), "lsp", "--db", "dbname=x"],
                cwd=d,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=120,
            )
        self.assertEqual(p.returncode, 2, p.stderr)
        self.assertEqual(
            p.stderr, "rowstile lsp: --db is not an option it has: it reads the database rowstile.toml names\n"
        )

    def test_run_as_a_script_it_is_the_module_others_import(self) -> None:
        # npm and Docker run the command as a script, which makes it __main__: Studio imports rowstile_cli by name
        # when it connects, and gets this one, with the .env files it read, not a second copy without them
        cli = os.path.join(ROOT, "cli", "rowstile_cli.py")
        code = (
            "import runpy, sys\n"
            f"sys.argv = [{cli!r}, '--version']\n"
            f"ran = runpy.run_path({cli!r}, run_name='__main__')\n"
            "import rowstile_cli\n"
            "print(rowstile_cli.ENV is ran['ENV'])\n"
        )
        p = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=120)
        self.assertEqual(p.stdout.splitlines()[-1:], ["True"], p.stdout + p.stderr)

    def test_array_literal(self) -> None:
        self.assertEqual(database.text_array(["1", 'a"b', "c\\d"]), '{"1","a\\"b","c\\\\d"}')


class Imports(unittest.TestCase):
    """Each run of the command imports only what it uses: importing all of it cost every run ~50 ms of its ~150."""

    WATCH = (
        "ssl",
        "socket",
        "hashlib",
        "urllib.parse",
        "authzlib.assembled",
        "authzlib.migrate",
        "authzlib.statements",
    )

    def loaded(self, *argv: str) -> tuple[set[str], set[str]]:
        """Which of WATCH a fresh interpreter holds after running the command with argv and didn't before, and which
        it held before (what starts with the interpreter isn't the command's: coverage.py, started by a .pth where
        the suites measure)."""
        code = (
            "import contextlib, io, sys\n"
            "before = set(sys.modules)\n"
            "import rowstile_cli\n"
            "with contextlib.redirect_stdout(io.StringIO()), contextlib.suppress(SystemExit):\n"
            f"    rowstile_cli.main({list(argv)!r})\n"
            f"print(' '.join(m for m in {self.WATCH!r} if m in sys.modules and m not in before))\n"
            f"print(' '.join(m for m in {self.WATCH!r} if m in before))\n"
        )
        env = dict(os.environ, PYTHONPATH=os.pathsep.join([os.path.join(ROOT, "cli"), ROOT]))
        run = subprocess.run([sys.executable, "-c", code], cwd=ROOT, env=env, capture_output=True, text=True)
        self.assertEqual(run.returncode, 0, run.stderr)
        added, started = (set(line.split()) for line in run.stdout.splitlines()[-2:])
        return added, started

    def test_each_command_imports_what_it_uses(self) -> None:
        # the version: no compiler, no TLS, no hashes (pgwire imports them as a connection needs them)
        self.assertEqual(self.loaded("--version")[0], set())
        # formatting parses: no compiler
        self.assertEqual(self.loaded("fmt", "--check", "example/docs.authz")[0], set())
        # checking compiles (and the compiler hashes long names): no migrations, no connection
        added, started = self.loaded("check", "example/docs.authz")
        self.assertEqual(added, {"hashlib", "authzlib.assembled", "authzlib.statements"} - started)

    def test_names_made_when_first_asked_for(self) -> None:
        for name in authzlib.__all__:
            self.assertIsNotNone(getattr(authzlib, name), name)
        from authzlib.assembled import Compiler as assembled

        self.assertIs(authzlib.__getattr__("Compiler"), assembled)
        self.assertIs(Compiler, assembled)
        self.assertEqual(authzlib.__getattr__("BUILD"), authzlib._build())
        with self.assertRaisesRegex(AttributeError, "module 'authzlib' has no attribute 'nosuch'"):
            authzlib.__getattr__("nosuch")


class Statements(unittest.TestCase):
    """Reading the compiled SQL back as statements, the way psql does (the migrations work on them)."""

    def test_nested_comments_quoted_names_and_what_it_refuses(self) -> None:
        from authzlib import statements

        sql = (
            "CREATE TABLE a (x int); /* outer /* inner; */ still a comment; */\n"
            'CREATE TABLE "b;""c" (y int);\n'
            "CREATE VIEW v AS SELECT 1 -- a comment; inside\n  AS z;\n"
        )
        self.assertEqual(
            statements.split(sql),
            [
                ("", "CREATE TABLE a (x int)"),
                ("/* outer /* inner; */ still a comment; */", 'CREATE TABLE "b;""c" (y int)'),
                ("", "CREATE VIEW v AS SELECT 1 -- a comment; inside\n  AS z"),
            ],
        )
        with self.assertRaisesRegex(ValueError, re.escape("unterminated dollar quote $x$")):
            statements.split("DO $x$ BEGIN END")
        with self.assertRaisesRegex(ValueError, "unbalanced parentheses in a function's arguments"):
            statements.made("CREATE FUNCTION f(a int RETURNS int AS 1")

    def test_quotes_comments_and_atomic_bodies(self) -> None:
        from authzlib.statements import split

        sql = (
            "-- a comment; not a statement\nSELECT 'a;b', E'it\\'s; fine', \"x;y\";\n"
            "CREATE FUNCTION f() RETURNS int LANGUAGE plpgsql AS $f$ BEGIN RETURN 1; END $f$;\n"
            "CREATE FUNCTION g(p int) RETURNS int LANGUAGE sql BEGIN ATOMIC\n"
            "  SELECT CASE WHEN p > 0 THEN 1 ELSE 2 END; SELECT 3;\nEND;\n/* a; block */ DO $$ BEGIN NULL; END $$"
        )
        got = split(sql)
        self.assertEqual([c for c, _ in got], ["-- a comment; not a statement", "", "", "/* a; block */"])
        self.assertEqual(len(got), 4)
        self.assertTrue(got[2][1].endswith("SELECT 3;\nEND"))

    def test_a_quote_left_open_runs_to_the_end(self) -> None:
        # as psql reads it: the rest is one statement, and Postgres says what is wrong with it (a named test's SQL
        # may leave one open, `{SELECT "name FROM app.files}`: the policy's braces know single quotes only)
        from authzlib.statements import split

        for sql in ("SELECT 'a; b", 'SELECT "a; b', "SELECT E'\\'; SELECT 1"):
            self.assertEqual(split(sql), [("", sql)], sql)

    def test_a_quote_that_starts_the_text(self) -> None:
        # nothing is before it: not an E'' string, nor a $ inside a name, whatever the text's last letter is
        from authzlib.statements import split

        self.assertEqual(split("'a\\'; SELECT 1 e"), [("", "'a\\'"), ("", "SELECT 1 e")])
        self.assertEqual(split("$a$ x; $a$; SELECT 1"), [("", "$a$ x; $a$"), ("", "SELECT 1")])

    def test_names_past_ascii(self) -> None:
        # Postgres reads any character past ASCII as a letter, unquoted (archivé, ², →): psql splits these so
        from authzlib.statements import made, split

        self.assertEqual(split("SELECT café FROM t; SELECT 1"), [("", "SELECT café FROM t"), ("", "SELECT 1")])
        self.assertEqual(split("SELECT année, ñ, ²x FROM t"), [("", "SELECT année, ñ, ²x FROM t")])
        # a name that ends in E is no E'' string, nor is a number's: its backslash escapes nothing
        self.assertEqual(split("SELECT x →E'a\\'; SELECT 2"), [("", "SELECT x →E'a\\'"), ("", "SELECT 2")])
        self.assertEqual(split("SELECT 1E'a\\'; SELECT 2"), [("", "SELECT 1E'a\\'"), ("", "SELECT 2")])
        self.assertEqual(split("SELECT x E'a\\'; b'; SELECT 3"), [("", "SELECT x E'a\\'; b'"), ("", "SELECT 3")])
        # a dollar quote's tag, and a $ inside a name
        self.assertEqual(
            split("DO $é$ BEGIN NULL; END $é$; SELECT 4"), [("", "DO $é$ BEGIN NULL; END $é$"), ("", "SELECT 4")]
        )
        self.assertEqual(split("SELECT 1 AS é$a$; SELECT 5"), [("", "SELECT 1 AS é$a$"), ("", "SELECT 5")])
        self.assertEqual(
            made("CREATE TRIGGER déclencheur AFTER INSERT ON app.dossiés FOR EACH ROW EXECUTE FUNCTION f()"),
            ("trigger", "déclencheur ON app.dossiés"),
        )
        self.assertEqual(made("CREATE FUNCTION app.fé(a int) RETURNS int AS $$ $$"), ("function", "app.fé(a int)"))
        # the same letters as a condition's reading (sqlutil.py; statements.py imports nothing of ours)
        from authzlib import sqlutil, statements

        self.assertEqual(statements.LETTER, sqlutil.LETTER)

    def test_what_each_makes(self) -> None:
        from authzlib.statements import made

        self.assertEqual(
            made(
                "CREATE FUNCTION authz.list(p_type text, p_after text DEFAULT NULL, p_limit int DEFAULT NULL) "
                "RETURNS SETOF text AS $$ $$"
            ),
            ("function", "authz.list(p_type text, p_after text, p_limit int)"),
        )
        self.assertEqual(
            made('CREATE TRIGGER "t" AFTER INSERT ON "app"."x" FOR EACH ROW EXECUTE FUNCTION f()'),
            ("trigger", '"t" ON "app"."x"'),
        )
        self.assertEqual(made("DO $mv$ BEGIN END $mv$", '-- @object view "mt"."v"'), ("view", '"mt"."v"'))
        # the forms that make it again or only if it isn't there name what they make too
        self.assertEqual(made("CREATE OR REPLACE VIEW authz_gen.v AS SELECT 1"), ("view", "authz_gen.v"))
        self.assertEqual(
            made('CREATE OR REPLACE TRIGGER "t" AFTER INSERT ON "app"."x" FOR EACH ROW EXECUTE FUNCTION f()'),
            ("trigger", '"t" ON "app"."x"'),
        )
        self.assertEqual(made("CREATE TABLE IF NOT EXISTS authz.x (a int)"), ("table", "authz.x"))
        self.assertEqual(made("CREATE INDEX IF NOT EXISTS x_a ON authz.x (a)"), ("index", "x_a"))
        # a parenthesis in a quoted default doesn't end the arguments
        self.assertEqual(
            made("CREATE FUNCTION authz.f(p text DEFAULT ')', q int) RETURNS int AS $$ $$"),
            ("function", "authz.f(p text, q int)"),
        )
        # nor one in a quoted name; a comma inside a type's parentheses or an array's brackets parts no argument
        self.assertEqual(
            made(
                'CREATE FUNCTION authz.f("a)" int, b numeric(10, 2) DEFAULT round(1, 2), c text[] DEFAULT '
                "ARRAY['x', 'y']) RETURNS int AS $$ $$"
            ),
            ("function", 'authz.f("a)" int, b numeric(10, 2), c text[])'),
        )
        self.assertEqual(made("CREATE SCHEMA IF NOT EXISTS authz"), ("schema", "authz"))
        self.assertIsNone(made("INSERT INTO authz_int.x VALUES (1)"))


def replaced(text: str, old: str, new: str) -> str:
    """text with old replaced: a test that edits a policy fails when the text it edits isn't there (rowstile fmt
    realigning a file would otherwise leave the policy as it was, and the test checking nothing)."""
    assert old in text, f"not in the policy: {old!r}"
    return text.replace(old, new)


class Migrations(unittest.TestCase):
    """What rowstile migrate writes, without a database (tests/migrate_test.py applies them)."""

    def setUp(self) -> None:
        from authzlib import migrate

        self.migrate = migrate
        self.text = read(POLICIES["docs"])

    def test_which_version_is_older(self) -> None:
        older = database.older_than
        for mine, theirs in (
            ("0.1.0-rc.1", "0.1.0-rc.2"),
            ("0.1.0-rc.2", "0.1.0"),
            ("0.9.0", "0.10.0"),
            ("0.1.0-dev+abc", "0.2.0-dev+def"),
            ("0.1.0", "1.0.0-rc.1"),
            # an alpha comes before its version's candidates, whatever their numbers
            ("0.1.0-alpha.1", "0.1.0-alpha.2"),
            ("0.1.0-alpha.9", "0.1.0-rc.1"),
            ("0.1.0-alpha.2", "0.1.0"),
            ("0.1.0", "0.2.0-alpha.1"),
            ("0.1.0-alpha.2", "0.1.0-alpha.10"),
            # a beta after its version's alphas, before its candidates
            ("0.1.0-alpha.9", "0.1.0-beta.1"),
            ("0.1.0-beta.1", "0.1.0-beta.2"),
            ("0.1.0-beta.9", "0.1.0-beta.10"),
            ("0.1.0-beta.12", "0.1.0-rc.1"),
            ("0.1.0-beta.1", "0.1.0"),
            ("0.1.0", "0.2.0-beta.1"),
            ("0.1.0-beta.1+abc", "0.1.0-rc.1"),
        ):
            self.assertTrue(older(mine, theirs), (mine, theirs))
            self.assertFalse(older(theirs, mine), (theirs, mine))
        # a development build can't be placed among its own version's candidates; nothing recorded, or not a version
        for mine, theirs in (
            ("0.1.0-dev+abc", "0.1.0-rc.2"),
            ("0.1.0-rc.1", "0.1.0-dev+abc"),
            ("0.1.0-dev+a", "0.1.0-dev+b"),
            ("0.1.0-dev+abc", "0.1.0-alpha.1"),
            ("0.1.0-alpha.1", "0.1.0-dev+abc"),
            ("0.1.0-dev+abc", "0.1.0-beta.1"),
            ("0.1.0-beta.1", "0.1.0-dev+abc"),
            ("0.1.0", "0.1.0"),
            ("0.1.0", None),
            ("0.1.0", "what"),
            ("0.1.0-gamma.1", "0.2.0"),
            ("0.1.0-beta.1-dev", "0.2.0"),
        ):
            self.assertFalse(older(mine, theirs), (mine, theirs))
        # the guard on the lock file (and on the database, the same function): a beta's command is refused over what
        # a candidate wrote, an alpha's over what a beta wrote; a candidate's goes on over what a beta wrote
        beta = self.migrate.lock_of(database.migratable(self.text, {})[1]).replace(
            f"# rowstile {authzlib.__version__}:", "# rowstile 0.1.0-beta.1:", 1
        )
        for build, lock in (("0.1.0-beta.1", beta.replace("0.1.0-beta.1:", "0.1.0-rc.1:", 1)), ("0.1.0-alpha.9", beta)):
            with mock.patch.object(authzlib, "BUILD", build):
                newer = lock.split(":", 1)[0].removeprefix("# rowstile ")
                with self.assertRaisesRegex(database.Error, rf"the lock file was last written by rowstile {newer},"):
                    database.migrations(self.text, {}, lock)
        with mock.patch.object(authzlib, "BUILD", "0.1.0-rc.1"):
            self.assertTrue(all(m.empty for m in database.migrations(self.text, {}, beta)))
        lock = self.migrate.lock_of(database.migratable(self.text, {})[1]).replace(
            f"# rowstile {authzlib.__version__}:", "# rowstile 99.0.0:", 1
        )
        with self.assertRaisesRegex(database.Error, r"the lock file was last written by rowstile 99\.0\.0.*\[AZ616\]"):
            database.migrations(self.text, {}, lock)
        self.assertTrue(all(m.empty for m in database.migrations(self.text, {}, lock, downgrade=True)))

    def lock(self, text: str) -> str:
        return self.migrate.lock_of(database.migratable(text, {})[1])

    def test_the_same_policy_gives_the_same_bytes(self) -> None:
        a, b = database.migration(self.text, {}, ""), database.migration(self.text, {}, "")
        self.assertEqual((a.sql, a.lock), (b.sql, b.lock))
        self.assertEqual(self.migrate.parse_lock(a.lock).text, a.lock)
        self.assertTrue(database.migration(self.text, {}, a.lock).empty)

    def test_the_first_is_the_whole_policy(self) -> None:
        m = database.migration(self.text, {}, "")
        self.assertIn(compiled("docs", transaction=False).split("\n", 1)[1], m.sql)
        self.assertNotIn("$authz_guard$", m.sql)

    def test_a_new_permission_is_a_small_migration(self) -> None:
        new = replaced(
            self.text,
            "  can share = owner or folder.share\n",
            "  can share = owner or folder.share\n  can comment = folder.view\n",
        )
        m = database.migration(new, {}, self.lock(self.text))
        self.assertIn('CREATE VIEW authz_int."file__comment"', m.sql)
        self.assertIn("CREATE OR REPLACE FUNCTION authz.can(p_type text, p_id text, p_perm text)", m.sql)
        self.assertNotIn('CREATE TABLE authz_int."folder__parent__tree"', m.sql)
        self.assertNotIn("CREATE POLICY", m.sql)
        self.assertIn("$authz_guard$", m.sql)
        self.assertEqual(m.summary, ["+ type file: can comment = folder.view"])
        self.assertIn("> type file: can comment = folder.view", m.lock)

    def test_the_lock_holds_the_policys_lines_and_not_its_tests(self) -> None:
        meaning = [x for x in self.lock(self.text).splitlines() if x.startswith("> ")]
        self.assertEqual(meaning[:2], ["> app role app_user", "> type user = app.users"])
        self.assertIn("> rules app.files", meaning)
        self.assertEqual([x for x in meaning if x.startswith("> test")], [])
        # a type line that changes is what the migration says changed
        m = database.migration(
            replaced(self.text, "type org = app.orgs\n", "type org = app.orgs (id int)\n"), {}, self.lock(self.text)
        )
        self.assertEqual(m.summary, ["- type org = app.orgs", "+ type org = app.orgs (id int)"])

    def test_lines_that_only_move_need_no_migration(self) -> None:
        moved = replaced(self.text, "app role app_user\n", "app role app_user\n\n-- a note\n")
        self.assertTrue(database.migration(moved, {}, self.lock(self.text)).empty)
        sql, comp, _ = database.migratable(moved, {})
        pushed = self.migrate.migration(sql, comp, self.migrate.parse_lock(self.lock(self.text)), lines=True)
        self.assertIn("DELETE FROM authz_gen.policy_lines", pushed.sql)

    def test_a_body_that_calls_what_goes_is_not_made_again(self) -> None:
        # a PL/pgSQL or SQL body looks up what it calls when it runs: rebuilding a tree (the views and functions
        # made from it) makes none of the API's functions again, only what can't outlive them (atomic bodies, views)
        changed = replaced(
            self.text,
            "can view  = edit or viewer or (parent.view and {inherit})",
            "can view  = edit or viewer or parent.view",
        )
        swap = database.migrations(changed, {}, self.lock(self.text), "x")[-1].sql
        self.assertIn("folder__linked_into_parent__tree", swap)
        self.assertIsNone(re.search(r"CREATE (OR REPLACE )?FUNCTION authz\.create_api_key\(", swap))

    def test_a_new_version_alone_needs_no_migration(self) -> None:
        # upgrading rowstile fails no one's `migrate --check` unless the new version makes something different
        lock = self.lock(self.text)
        older = re.sub(r"^# rowstile \S+:", "# rowstile 0.0.1:", lock, count=1, flags=re.M)
        self.assertNotEqual(older, lock)
        self.assertTrue(database.migration(self.text, {}, older).empty)

    def test_a_changed_step_every_migration_runs_is_a_migration(self) -> None:
        lock = self.lock(self.text)
        self.assertRegex(lock, r"(?m)^always \| [0-9a-f]{12}$")
        m = database.migration(self.text, {}, re.sub(r"(?m)^always \| \w+$", "always | 000000000000", lock))
        self.assertIn("REVOKE ALL ON ALL FUNCTIONS IN SCHEMA authz FROM PUBLIC;", m.sql)
        self.assertEqual(m.summary, ["the same policy; what rowstile makes of it changed"])
        self.assertIn(f"always | {self.migrate.always_hash(database.migratable(self.text, {})[1])}", m.lock)
        # those steps alone: a new type with a shared relation changes others (the tables, the share indexes, the
        # sweep), and leaves the hash as it was
        more = replaced(
            self.text,
            "type folder = app.folders\n",
            "type org2 = app.orgs\n  reader : user shared by see\n  can see = reader\n\ntype folder = app.folders\n",
        )
        self.assertEqual(
            self.migrate.always_hash(database.migratable(more, {})[1]),
            self.migrate.always_hash(database.migratable(self.text, {})[1]),
        )

    def test_a_changed_grant_alone_is_a_migration(self) -> None:
        # a new version that grants the app role another function, and changes nothing else
        lock = self.lock(self.text)
        older = re.sub(r"(?m)^step grant_api \| \w+$", "step grant_api | 000000000000", lock)
        self.assertNotEqual(older, lock)
        m = database.migration(self.text, {}, older)
        self.assertRegex(m.sql, r"GRANT EXECUTE ON FUNCTION\n  authz\.uid\(\),")
        self.assertEqual(m.lock, lock)

    def test_a_tree_function_changed_alone_is_replaced_in_place(self) -> None:
        # a new version that changes a message of an inheritance tree's function: the tree keeps its rows
        lock = self.lock(self.text)
        line = r'(?m)^(function authz_int\."folder__parent__tree_check_loops"\(p_ids bigint\[\]\) \| )\w+'
        older = re.sub(line, r"\g<1>000000000000", lock)
        self.assertNotEqual(older, lock)
        m = database.migration(self.text, {}, older)
        self.assertIn('CREATE OR REPLACE FUNCTION authz_int."folder__parent__tree_check_loops"(p_ids bigint[])', m.sql)
        self.assertEqual(m.rebuilt, [])
        self.assertNotIn("_rebuild", m.sql)
        self.assertEqual(m.lock, lock)

    def test_a_lock_without_those_steps_runs_them(self) -> None:
        # every lock rowstile migrate writes has the line; without it (cut by hand), nothing says the steps are the
        # same: the migration runs them, and writes the line
        lock = re.sub(r"(?m)^always \| \w+\n", "", self.lock(self.text))
        self.assertIsNone(self.migrate.parse_lock(lock).always)
        m = database.migration(self.text, {}, lock)
        self.assertIn("REVOKE ALL ON ALL FUNCTIONS IN SCHEMA authz FROM PUBLIC;", m.sql)
        self.assertEqual(m.summary, ["the same policy; what rowstile makes of it changed"])
        self.assertRegex(m.lock, r"(?m)^always \| [0-9a-f]{12}$")
        # a lock another version wrote says so
        older = re.sub(r"^# rowstile \S+:", "# rowstile 0.0.1:", self.lock(self.text), count=1, flags=re.M)
        older = re.sub(r"(?m)^always \| \w+$", "always | 000000000000", older)
        self.assertEqual(
            database.migration(self.text, {}, older).summary,
            [f"rowstile 0.0.1 -> {authzlib.__version__}: what the new version makes differently"],
        )

    def test_a_lock_gives_the_version_that_wrote_it(self) -> None:
        # its header, `# rowstile <version>:`; a header of another name gives none
        lock = self.lock(self.text)
        self.assertEqual(self.migrate.parse_lock(lock).version, authzlib.__version__)
        renamed = re.sub(r"^# rowstile ", "# rowfence ", lock, count=1, flags=re.M)
        self.assertIsNone(self.migrate.parse_lock(renamed).version)
        newer = re.sub(r"^# rowstile \S+:", "# rowstile 99.0.0:", lock, count=1, flags=re.M)
        with self.assertRaises(database.Error):  # refused when a newer one wrote it
            database.migrations(self.text, {}, newer)

    def test_a_tree_that_changes_is_built_beside_first(self) -> None:
        new = replaced(
            self.text,
            "can view  = edit or viewer or (parent.view and {inherit})",
            "can view  = edit or viewer or parent.view",
        )
        ms = database.migrations(new, {}, self.lock(self.text))
        self.assertEqual(len(ms), 2)
        self.assertIn('INSERT INTO authz_int."folder__linked_into_parent__tree__next"', ms[0].sql)
        self.assertNotIn("CREATE TRIGGER", ms[0].sql)
        self.assertIn("$authz_catch_up$", ms[1].sql)
        self.assertEqual(len(database.migrations(new, {}, self.lock(self.text), two_phase=False)), 1)

    def test_file_names(self) -> None:
        import migrations

        self.assertEqual(migrations.slug("File comment!"), "authz_file_comment")
        with tempfile.TemporaryDirectory() as d:
            self.assertRegex(migrations.sql_file_name(d, "authz_x", "20260101000000"), r"^20260101000000_authz_x\.sql$")
            open(os.path.join(d, "0004_schema.sql"), "w", encoding="utf-8").close()
            self.assertEqual(migrations.sql_file_name(d, "authz_x", "20260101000000"), "0005_authz_x.sql")

    def test_what_a_tool_is_refused_for(self) -> None:
        import migrations

        with tempfile.TemporaryDirectory() as d:
            for rev in ("aaa", "bbb"):  # two revisions, neither the other's down_revision: two heads
                with open(os.path.join(d, f"{rev}.py"), "w", encoding="utf-8") as fh:
                    fh.write(f'revision = "{rev}"\ndown_revision = None\n')
            with self.assertRaisesRegex(migrations.Error, re.escape("has several heads (aaa, bbb): merge them first")):
                migrations.write_migration("alembic", d, "x", "SELECT 1;\n")
        with self.assertRaisesRegex(migrations.Error, "unknown migration tool 'liquibase'"):
            migrations.write_migration("liquibase", ".", "x", "SELECT 1;\n")
        for journal, said in (({}, "isn't a journal (no entries)"), ({"entries": [1]}, "an entry that isn't one: 1")):
            with self.assertRaisesRegex(migrations.Error, re.escape(said)):
                migrations.journal_of(journal)

    def test_migrations_written_the_same_second_come_one_after_the_other(self) -> None:
        # (the suites write migrations a moment apart, with no pause for the clock): one written in the same second
        # as the last, or before it, is named a second after it
        import migrations

        with tempfile.TemporaryDirectory() as d:
            now = 1767225600  # 2026-01-01 00:00:00
            names = [
                os.path.basename(migrations.write_migration("goose", d, name, "SELECT 1;\n", now=at)[0])
                for name, at in (("a", now), ("b", now), ("c", now - 60))
            ]
        self.assertEqual(
            names, ["20260101000000_authz_a.sql", "20260101000001_authz_b.sql", "20260101000002_authz_c.sql"]
        )

    def test_what_the_tools_folders_may_hold(self) -> None:
        import migrations

        # Alembic: an __init__.py among the revisions, as many projects have, is no revision
        with tempfile.TemporaryDirectory() as d:
            open(os.path.join(d, "__init__.py"), "w", encoding="utf-8").close()
            with open(os.path.join(d, "aaa.py"), "w", encoding="utf-8") as fh:
                fh.write('revision = "aaa"\ndown_revision = None\n')
            py, _ = migrations.write_migration("alembic", d, "x", "SELECT 1;\n")
            with open(py, encoding="utf-8") as fh:
                self.assertIn("down_revision: str | None = 'aaa'", fh.read())
        # Drizzle: a journal whose last migration has no snapshot (one written by hand): the next starts from none
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "meta"))
            with open(os.path.join(d, "meta", "_journal.json"), "w", encoding="utf-8") as fh:
                json.dump({"version": "7", "dialect": "postgresql", "entries": [{"idx": 0, "tag": "0000_init"}]}, fh)
            migrations.write_migration("drizzle", d, "x", "SELECT 1;\n")
            with open(os.path.join(d, "meta", "0001_snapshot.json"), encoding="utf-8") as fh:
                snap = json.load(fh)
            self.assertEqual((snap["prevId"], snap["tables"]), ("00000000-0000-0000-0000-000000000000", {}))
            with open(os.path.join(d, "meta", "_journal.json"), encoding="utf-8") as fh:
                self.assertEqual([e["tag"] for e in json.load(fh)["entries"]], ["0000_init", "0001_authz_x"])

    def test_the_alembic_revision_says_asyncpg_in_a_line(self) -> None:
        # a policy's revision is one script, and asyncpg takes one statement at a time: its own error carries the
        # whole script (four thousand lines for a small policy). The revision says it first, with the way out; with a
        # sync driver it sends the script as before
        import migrations

        class Bind:
            def __init__(self, driver: str) -> None:
                self.dialect = types.SimpleNamespace(driver=driver)
                self.sent: list[str] = []

            def exec_driver_sql(self, sql: str, execution_options: dict[str, bool]) -> None:
                self.sent.append(sql)

        with tempfile.TemporaryDirectory() as d:
            py, _ = migrations.alembic(d, "authz_x", "SELECT 1;\n", 0)
            with open(py, encoding="utf-8") as fh:
                code = compile(fh.read(), py, "exec")
            for driver in ("asyncpg", "psycopg"):
                bind = Bind(driver)
                fake = types.ModuleType("alembic")
                fake.__dict__["op"] = types.SimpleNamespace(get_bind=lambda bind=bind: bind)
                scope: dict[str, object] = {"__file__": py}
                with mock.patch.dict(sys.modules, {"alembic": fake}):
                    exec(code, scope)
                    upgrade = cast(Callable[[], None], scope["upgrade"])
                    if driver == "asyncpg":
                        with self.assertRaisesRegex(RuntimeError, r"asyncpg.*one script.*postgresql\+psycopg://"):
                            upgrade()
                        self.assertEqual(bind.sent, [])
                    else:
                        upgrade()
                        self.assertEqual(bind.sent, ["SELECT 1;\n"])


class Review(unittest.TestCase):
    """rowstile review without a database; tests/review.sh runs it with git and a database."""

    def setUp(self) -> None:
        from authzlib import review

        self.review = review
        self.text = read(POLICIES["docs"])

    def run_review(
        self,
        new: str,
        tests_before: dict[str, str] | None = None,
        tests_after: dict[str, str] | None = None,
        lock: bool = True,
    ) -> Review:
        from authzlib import migrate

        base_lock = migrate.lock_of(database.migratable(self.text, {})[1]) if lock else None
        return self.review.review(
            (self.text, {}, tests_before or {}), (new, {}, tests_after or {}), base_lock, None, None, worlds=120
        )

    def test_a_new_policy_is_added_whole(self) -> None:
        # the pull request that adds the policy: nothing at the base. Every declaration is added, the app role and
        # the user type too: none is said to change from a role or a table nobody wrote
        text = replaced(self.text, "app role app_user\n", "app role web\n")
        r = self.review.review(None, (text, {}, {}), None, None, None, worlds=120)
        changed = r["meaning"]["changed"]
        self.assertEqual({c["kind"] for c in changed}, {"added"})
        self.assertIn(("app role", "app role web"), [(c["what"], c["after"]) for c in changed])
        self.assertIn("type user", [c["what"] for c in changed])
        self.assertNotRegex(self.review.text(r), r"(?m)^\s+changed\s")
        # with its first migration (a lock file at the head, none at the base): the tables it locks are the app's,
        # not the ones rowstile keeps (its audit trail's triggers, its shares')
        from authzlib import migrate

        head_lock = migrate.lock_of(database.migratable(text, {})[1])
        [m] = self.review.review(None, (text, {}, {}), None, head_lock, None, worlds=10)["deploy"]["migrations"]
        self.assertEqual(
            sorted(m["locks"]),
            [f'"app"."{t}"' for t in ("files", "folder_links", "folders", "orgs", "teams", "users")],
        )

    def test_comments_only(self) -> None:
        r = self.run_review(replaced(self.text, "app role app_user\n", "app role app_user   -- the app's role\n\n"))
        self.assertEqual(r["meaning"]["equivalent"], "text")
        self.assertEqual(r["deploy"]["migrations"], [])
        self.assertIn("**Meaning**: unchanged", self.review.markdown(r))

    def test_a_refactor_is_checked_in_small_worlds(self) -> None:
        r = self.run_review(
            replaced(
                self.text,
                "can edit  = share or editor or (parent.edit and {inherit})",
                "can edit  = editor or share or ({inherit} and parent.edit)",
            )
        )
        # and the worlds listed: every one of a few rows, with at most two links here (then the budget is spent: 15
        # listed for each drawn world)
        self.assertEqual(
            r["meaning"]["equivalent"],
            "120 small worlds and 1,800 listed: every one of up to 3 rows of each type with at most 2 links",
        )
        md = self.review.markdown(r)
        self.assertIn("unchanged: every permission and rule grants the same", md)
        self.assertNotIn("<details>", md)

    def test_what_changes_through_it(self) -> None:
        r = self.run_review(
            replaced(
                self.text,
                "can view  = edit or viewer or (parent.view and {inherit})",
                "can view  = edit or viewer or parent.view",
            )
        )
        m = r["meaning"]
        self.assertEqual([c["what"] for c in m["changed"]], ["folder.view"])
        self.assertIn({"what": "file.view", "via": ["folder.view"], "line": "line 63"}, m["through"])
        self.assertIn("a permission widened", [f["why"] for f in r["risk"]])
        self.assertEqual(len(r["deploy"]["migrations"]), 2)  # built beside, then swapped in
        self.assertTrue(r["deploy"]["migrations"][0]["builds_beside"])
        # the tree the first builds beside, the second swaps in: neither rebuilds it under lock. No lock file at the
        # head (the pull request hasn't run rowstile migrate), so none is said to be behind
        tree = "folder__linked_into_parent__tree"
        self.assertEqual(
            [(m["builds_beside"], m["swaps_in"], m["rebuilds"]) for m in r["deploy"]["migrations"]],
            [([tree], [], []), ([], [tree], [])],
        )
        self.assertEqual(
            self.review.summary(r)["Deploy"],
            '2 migrations. Locks `"app"."files"`, `"app"."folder_links"`, `"app"."folders"` while it runs. '
            "It also locks the partitions and child tables of the tables rowstile watches. "
            f"Builds {tree} beside the tables in use, then swaps in.",
        )

    def test_what_changes_through_a_groups_members(self) -> None:
        # who is in a team: what is shared with the team's members (team#member) changes through it
        r = self.run_review(
            replaced(
                self.text,
                "  member : user        = app.team_members(team_id -> user_id)\n",
                "  member : user        = app.team_users(team_id -> user_id)\n",
            )
        )
        m = r["meaning"]
        self.assertEqual([c["what"] for c in m["changed"]], ["team.member"])
        self.assertIn({"what": "folder.view", "via": ["team.member"], "line": "line 50"}, m["through"])
        self.assertIn({"what": "file.view", "via": ["team.member"], "line": "line 63"}, m["through"])

    def test_a_test_file_that_doesnt_parse_is_said(self) -> None:
        # its checks are missing from the comparison, which read as "no change to what the tests claim"
        good = (
            'test "owners"\n  given ann = {INSERT INTO app.users (id) VALUES (1) RETURNING id}\n'
            "  user $ann can view folder 1\n"
        )
        after = {"tests/a.authz": good.replace("can view", "cannot view"), "tests/b.authz": 'test "broken"\n  given\n'}
        # (one that only the base has, which the pull request takes out, is the base's: not named)
        r = self.run_review(self.text, {"tests/a.authz": good, "tests/old.authz": 'test "old"\n  given\n'}, after)
        t = r["tests"]
        # a check is on its file's line, not on a line of the policy
        self.assertEqual([(x["test"], x["line"]) for x in t["flipped"]], [("owners", "tests/a.authz line 3")])
        self.assertEqual([x["file"] for x in t["unread"]], ["tests/b.authz"])
        self.assertRegex(t["unread"][0]["error"], r"^tests/b\.authz line 2: .* \[AZ106\]$")
        self.assertIn("1 test file can't be read, so its checks aren't compared.", self.review.text(r))
        self.assertIn("  test     can't read: tests/b.authz line 2: ", self.review.text(r))
        self.assertIn("- can't read: tests/b.authz line 2: ", self.review.markdown(r))
        same = self.run_review(self.text, {"tests/a.authz": good}, {"tests/a.authz": good})
        self.assertEqual((same["tests"]["unread"], same["tests"]["flipped"], same["tests"]["count"]), ([], [], 16))

    def test_a_test_file_the_policy_refuses_is_said(self) -> None:
        # it parses, but names a permission the type doesn't have, or a test another file names: `rowstile test`
        # refuses it, so its checks are neither compared nor run
        good = 'test "owners"\n  user 1 can view folder 1\n'
        after = {
            "tests/a.authz": good,
            "tests/b.authz": 'test "broken"\n  user 3 can nosuch file 11\n',
            "tests/c.authz": good,
        }
        r = self.run_review(self.text, {"tests/a.authz": good}, after)
        t = r["tests"]
        self.assertEqual(
            [x["error"] for x in t["unread"]],
            [
                "tests/b.authz line 2: file has no permission 'nosuch' (it has: share, edit, view) [AZ203]",
                "tests/c.authz line 1: there is already a test named 'owners' [AZ109]",
            ],
        )
        self.assertEqual((t["flipped"], t["removed"], t["added"], t["count"]), ([], [], [], 16))
        self.assertIn("2 test files can't be read, so their checks aren't compared.", self.review.text(r))

    def test_risk_flags(self) -> None:
        widened = replaced(
            self.text, "  viewer : user, team#member shared\n", "  viewer : user, team#member, anyone shared\n"
        )
        flags = {f["why"] for f in self.run_review(widened)["risk"]}
        self.assertIn("access widened", flags)
        # a relation people can newly share is flagged once, however many kinds of subjects it may be shared with
        shared = replaced(
            self.text,
            "  viewer : user, team#member shared\n",
            "  viewer : user, team#member shared\n  reader : user, team#member, org#member shared\n",
        )
        shared = replaced(shared, "  can view  = edit or viewer\n", "  can view  = edit or viewer or reader\n")
        self.assertEqual(
            [f["flag"] for f in self.run_review(shared)["risk"] if f["why"] == "a relation newly shared"],
            ["`file.reader` is newly shared (by whoever holds `share`)"],
        )
        no_deny = replaced(self.text, "           or (folder.view and not {confidential})", "           or folder.view")
        flags = {f["why"] for f in self.run_review(no_deny)["risk"]}
        self.assertIn("a deny removed", flags)
        looser = replaced(
            self.text, "  delete                            : edit", "  delete                            : view"
        )
        risk = self.run_review(looser)["risk"]
        self.assertIn("a write rule loosened", {f["why"] for f in risk})
        self.assertTrue(all(f["line"] for f in risk))
        notes = self.review.annotations(self.run_review(looser), "example/docs.authz")
        self.assertRegex(notes, r"^::warning file=example/docs.authz,line=\d+,title=rowstile review::")

    def test_conditions_are_read_as_postgres_reads_them(self) -> None:
        """A quoted column name was a condition the review couldn't read, and a decimal was read as a float: the
        same column quoted was said to change the meaning, and a number past a float's digits not to."""
        old = "           or (folder.view and not {confidential})"
        base = replaced(self.text, old, old[:-1] + " and {size >= 1})")
        quoted = (replaced(self.text, old, old[:-1] + ' and {"size" >= 1})'), {}, {})
        r = self.review.review((base, {}, {}), quoted, None, None, None, worlds=120)
        self.assertRegex(r["meaning"]["equivalent"] or "", "^120 small worlds")
        # on a numeric column, a file of size 1 loses view: not unchanged (a double precision column would differ)
        longer = (replaced(self.text, old, old[:-1] + " and {size >= 1.00000000000000001})"), {}, {})
        r = self.review.review((base, {}, {}), longer, None, None, None, worlds=120)
        self.assertIsNone(r["meaning"]["equivalent"])
        self.assertIn("file.view", [c["what"] for c in r["meaning"]["changed"]])

    def test_a_condition_it_cannot_read_reworded(self) -> None:
        """A subquery's `id` rewritten as `this.id` (two real changes, d62fa2e and e853285) was reported as a widening
        with a made-up example: the small worlds hold such a condition as rows of their own, per text."""
        reworded = replaced(self.text, "and b.user_id = this.id)}", "and b.user_id = this.id and true)}")
        self.assertNotEqual(reworded, self.text)
        r = self.run_review(reworded)
        self.assertEqual(r["meaning"].get("unreadable"), ["user.impersonate"])
        self.assertNotIn("counterexample", r["meaning"])
        whys = [f["why"] for f in r["risk"]]
        self.assertEqual(whys, ["a condition it can't read changed"])
        self.assertIn("read both, it can't tell more from less", r["risk"][0]["flag"])
        self.assertIn("can't tell: user.impersonate", self.review.text(r))
        # a condition it reads still says what widened
        r = self.run_review(
            replaced(self.text, "can share = owner or org.admin", "can share = owner or org.admin or {true}")
        )
        self.assertIn("a permission widened", [f["why"] for f in r["risk"]])
        self.assertNotIn("unreadable", r["meaning"])

    def test_no_lock_file_is_no_migration(self) -> None:
        """A project that applies its policy keeps no lock file: Deploy said every change was the whole policy, a
        migration that locks every table and rebuilds every tree."""
        r = self.run_review(
            replaced(self.text, "app role app_user\n", "app role app_user   -- the app's role\n"), lock=False
        )
        self.assertEqual(r["deploy"]["migrations"], [])
        self.assertIn("no lock file, so no migrations: `rowstile apply`", self.review.summary(r)["Deploy"])
        # a change that means something: its details, and none for migrations there are none of
        r = self.run_review(replaced(self.text, "  can break_glass = org.member\n", ""), lock=False)
        md = self.review.markdown(r)
        self.assertIn("<details><summary>Meaning</summary>", md)
        self.assertNotIn("<summary>Deploy</summary>", md)

    def test_tests_that_flip(self) -> None:
        before = {"t.authz": 'test "carol"\n  user 3 can view file 11\n  user 3 cannot view file 12\n'}
        after = {"t.authz": 'test "carol"\n  user 3 cannot view file 11\n'}
        t = self.run_review(self.text, before, after)["tests"]
        self.assertEqual(
            [(x["before"], x["after"]) for x in t["flipped"]],
            [("user 3 can view file 11", "user 3 cannot view file 11")],
        )
        self.assertEqual([x["check"] for x in t["removed"]], ["user 3 cannot view file 12"])
        # the summary's line counts them, one or several
        both = {"t.authz": 'test "carol"\n  user 3 cannot view file 11\n  user 3 can view file 12\n'}
        one = self.review.summary(self.run_review(self.text, before, after))["Tests"]
        two = self.review.summary(self.run_review(self.text, before, both))["Tests"]
        self.assertIn("1 check changed what it expects", one)
        self.assertIn("2 checks changed what they expect", two)

    def test_a_renamed_test_is_not_its_checks_removed(self) -> None:
        # a test under a new name, with one check that changed and one more: said as a new name and the check
        # that changed. "2 checks removed" would read as tests taken out to let the change pass
        before = {"t.authz": 'test "carol, neither shares"\n  user 3 can view file 11\n  user 3 cannot share file 11\n'}
        after = {
            "t.authz": 'test "carol"\n  user 3 can view file 11\n  user 3 can share file 11\n  user 3 can edit file 11\n'
        }
        r = self.run_review(self.text, before, after)
        t = r["tests"]
        self.assertEqual(t["renamed"], [{"before": "carol, neither shares", "after": "carol"}])
        self.assertEqual(t["removed"], [])
        self.assertEqual(
            [(x["test"], x["before"], x["after"]) for x in t["flipped"]],
            [("carol", "user 3 cannot share file 11", "user 3 can share file 11")],
        )
        self.assertEqual([x["check"] for x in t["added"]], ["user 3 can edit file 11"])
        self.assertIn("1 check changed what it expects. 1 test renamed.", self.review.summary(r)["Tests"])
        self.assertIn('- renamed: "carol, neither shares" is now "carol"', self.review.markdown(r))
        self.assertIn('  test     renamed: "carol, neither shares" is now "carol"', self.review.text(r))
        # a name alone: nothing removed, and the name is said
        same = {"t.authz": 'test "carol"\n  user 3 can view file 11\n  user 3 cannot share file 11\n'}
        t = self.run_review(self.text, before, same)["tests"]
        self.assertEqual(
            (t["renamed"], t["removed"], t["flipped"]),
            ([{"before": "carol, neither shares", "after": "carol"}], [], []),
        )
        # not a new name: a check of the old test is in no new one, or its checks are in two new tests
        fewer = {"t.authz": 'test "carol"\n  user 3 can view file 11\n'}
        t = self.run_review(self.text, before, fewer)["tests"]
        self.assertEqual(t["renamed"], [])
        self.assertEqual(len(t["removed"]), 2)
        twice = {
            "t.authz": 'test "a"\n  user 3 can view file 11\n  user 3 cannot share file 11\n'
            'test "b"\n  user 3 can view file 11\n  user 3 cannot share file 11\n'
        }
        t = self.run_review(self.text, before, twice)["tests"]
        self.assertEqual(t["renamed"], [])
        self.assertEqual(len(t["removed"]), 2)
        # two tests put into one: both names are said, nothing is removed
        two = {"t.authz": 'test "x"\n  user 3 can view file 11\ntest "y"\n  user 3 cannot share file 11\n'}
        one = {"t.authz": 'test "carol"\n  user 3 can view file 11\n  user 3 cannot share file 11\n'}
        t = self.run_review(self.text, two, one)["tests"]
        self.assertEqual([n["before"] for n in t["renamed"]], ["x", "y"])
        self.assertEqual(t["removed"], [])

    def test_a_new_permission_no_test_names(self) -> None:
        new = replaced(
            self.text,
            "  can share = owner or folder.share\n",
            "  can share = owner or folder.share\n  can comment = folder.view\n",
        )
        r = self.run_review(new)
        self.assertEqual([x["what"] for x in r["tests"]["untested"]], ["file.comment"])
        self.assertEqual(r["deploy"]["migrations"][0]["locks"], {})
        self.assertIn("No table locks", self.review.markdown(r))

    # a small policy for the changes Risk must see: each line of it is one a pull request may loosen
    SMALL = """app role app_user
type user = app.users where {active}
type org = app.orgs
  member : user = app.org_members(org_id -> user_id)
  admin  : user = app.org_members(org_id -> user_id) where {role = 'admin'}
  can manage = admin
  can see = member
type folder = app.folders where {not archived}
  org    : org = org_id
  owner  : user = owner_id
  viewer : user shared by edit
  can edit = owner or org.admin
  can view = edit or viewer
  can remove = owner and {status = 'a  b'}
  can deep = owner and {c1} and {c2} and {c3} and {c4} and {c5} and {c6} and {c7} and {c8}
rules app.folders
  select : view
  update : edit
"""

    def small(self, old: str, new: str, files: dict[str, str] | None = None) -> Review:
        self.assertIn(old, self.SMALL)
        return self.review.review(
            (self.SMALL, files or {}, {}), (self.SMALL.replace(old, new), files or {}, {}), worlds=120
        )

    def test_risks_example_overrules_a_comparison_that_found_nothing(self) -> None:
        # where the comparison's worlds miss a widening (made to here) that Risk shows by an example, the review
        # doesn't call the change equivalent: a select rule loosened, break_glass given to more people
        glass = self.SMALL.replace("  can remove = owner", "  can break_glass = owner\n  can remove = owner")
        cases = {
            "a select rule loosened": (
                self.SMALL,
                self.SMALL.replace("  select : view\n", "  select : view or signed_in\n"),
            ),
            "break_glass given to more people": (
                glass,
                glass.replace("can break_glass = owner", "can break_glass = edit"),
            ),
        }
        for why, (base, head) in cases.items():
            self.assertNotEqual(base, head, why)
            with mock.patch.object(self.review, "compare", return_value=None):
                r = self.review.review((base, {}, {}), (head, {}, {}), worlds=40)
            self.assertIn(why, {f["why"] for f in r["risk"]}, why)
            self.assertIsNone(r["meaning"]["equivalent"], why)

    def test_a_widening_is_flagged_however_it_is_made(self) -> None:
        cases = {
            "a select rule loosened": ("  select : view\n", "  select : view or signed_in\n"),
            "a rule added": ("  update : edit\n", "  update : edit\n  delete : view\n"),
            "a permission widened through what it uses": (" where {role = 'admin'}", ""),  # every member an admin
            "a rule loosened through what it uses": ("owner  : user = owner_id", "owner  : user = created_by"),
            "a type's where loosened": (" where {not archived}", ""),
        }
        for why, (old, new) in cases.items():
            risk = self.small(old, new)["risk"]
            self.assertIn(why, {f["why"] for f in risk}, why)
            self.assertTrue(all(f["line"] for f in risk), why)
        self.assertIn(
            "a type's where loosened", {f["why"] for f in self.small(" where {active}", "")["risk"]}
        )  # the user type's
        # the type whose where changed is named, not the other one that has a where, with a permission it widens
        for old, shown in ((" where {not archived}", "`type folder`: its where changed, and more rows count: `folder.edit`"),
                           (" where {active}", "`type user`: its where changed, and more rows count: `org.manage`")):  # fmt: skip
            flags = [f["flag"] for f in self.small(old, "")["risk"] if f["why"] == "a type's where loosened"]
            self.assertEqual([f.split(" allows")[0] for f in flags], [shown], old)

    def test_a_where_loosened_on_a_type_with_rules_only_is_flagged(self) -> None:
        # a type with no permissions: its where removed shows in its rule alone, which is said
        base = (
            "app role app_user\ntype user = app.users\ntype box = app.boxes where {not archived}\n"
            "  owner : user = owner_id\nrules app.boxes\n  select : owner or {shown}\n"
        )
        head = base.replace(" where {not archived}", "")
        flags = [f["flag"] for f in self.review.review((base, {}, {}), (head, {}, {}), worlds=40)["risk"]
                 if f["why"] == "a type's where loosened"]  # fmt: skip
        self.assertEqual(
            [f.split(" allows")[0] for f in flags],
            ["`type box`: its where changed, and more rows count: `app.boxes select`"],
        )

    def test_a_warning_of_something_removed_names_the_file_only(self) -> None:
        # an invariant removed has no line in the head: its annotation names the file, without a line
        base = self.SMALL + "invariants\n  never folder: remove and not edit\n"
        r = self.review.review((base, {}, {}), (self.SMALL, {}, {}), worlds=40)
        [gone] = [f for f in r["risk"] if f["why"] == "an invariant removed"]
        self.assertIsNone(gone["line"])
        self.assertIn(
            "::warning file=db/policy.authz,title=rowstile review::", self.review.annotations(r, "db/policy.authz")
        )

    def test_a_relation_to_a_type_already_reached_is_no_new_way(self) -> None:
        # folders reach users already (owner): an editor column is another relation, not a new way to reach a type
        head = self.SMALL.replace(
            "  owner  : user = owner_id\n", "  owner  : user = owner_id\n  editor : user = editor_id\n"
        )
        head = head.replace("can edit = owner or org.admin", "can edit = owner or org.admin or editor")
        whys = {f["why"] for f in self.review.review((self.SMALL, {}, {}), (head, {}, {}), worlds=40)["risk"]}
        self.assertNotIn("a new way to reach a type", whys)

    def test_each_change_the_review_warns_of(self) -> None:
        def risk(base: str, head: str) -> set[str]:
            return {f["why"] for f in self.review.review((base, {}, {}), (head, {}, {}), worlds=40)["risk"]}

        mask, scope, never = (
            "  mask status : edit\n",
            "scope reading = select, view",
            "  never folder: remove and not edit",
        )
        base = self.SMALL.replace("rules app.folders\n", "rules app.folders view app.folders_seen\n") + (
            f"{mask}{scope}\ninvariants\n{never}\n"
        )
        cases = {
            "sharing needs another permission": (self.SMALL, self.SMALL.replace("shared by edit", "shared by view")),
            "a new way to reach a type": (
                self.SMALL,
                self.SMALL.replace(
                    "  owner  : user = owner_id\n", "  owner  : user = owner_id\n  parent : folder = up\n"
                ).replace("can view = edit or viewer", "can view = edit or viewer or parent.view"),
            ),
            "a new inheritance path": (
                self.SMALL,
                self.SMALL.replace("can view = edit or viewer", "can view = edit or viewer or org.see"),
            ),
            "a mask or column rule removed": (base, base.replace(mask, "")),
            "a mask changed": (base, base.replace(mask, "  mask status : view\n")),
            "a scope changed": (base, base.replace(scope, scope + ", edit")),
            "an invariant removed": (base, base.replace(f"invariants\n{never}\n", "")),
            "a cascade marked as meant": (base, base.replace(mask, mask + "  cascade from app.orgs\n")),
        }
        for why, (b, h) in cases.items():
            self.assertNotEqual(b, h, why)
            self.assertIn(why, risk(b, h), why)
        # which it is, a mask or a column rule, is said
        ruled = replaced(base, "  update : edit\n", "  update : edit\n  update owner_id : edit\n")
        for b, h, said in (
            (base, base.replace(mask, ""), "the mask `app.folders mask status` is removed"),
            (ruled, base, "the column rule `app.folders update owner_id` is removed"),
        ):
            flags = [f["flag"] for f in self.review.review((b, {}, {}), (h, {}, {}), worlds=40)["risk"]]
            self.assertIn(said, flags)

    def test_a_cascade_line_added_and_removed(self) -> None:
        """`cascade from` makes nothing a permission or rule grants: the review shows the line, and flags it added."""
        meant = self.SMALL.replace("  update : edit\n", "  update : edit\n  cascade from app.orgs (org_id)\n")
        for b, h, kind, whys in (
            (self.SMALL, meant, "added", ["a cascade marked as meant"]),
            (meant, self.SMALL, "removed", []),
        ):
            r = self.review.review((b, {}, {}), (h, {}, {}), worlds=40)
            self.assertEqual(
                [(c["what"], c["kind"], c["entity"]) for c in r["meaning"]["changed"]],
                [("cascade app.folders from app.orgs (org_id)", kind, "cascade")],
            )
            self.assertEqual([f["why"] for f in r["risk"]], whys)
            self.assertEqual(self.review.summary(r)["Meaning"], f"1 cascade {kind}")

    def test_a_tightening_is_not_flagged(self) -> None:
        for old, new in (
            ("  select : view\n", "  select : edit\n"),
            ("rules app.folders\n  select : view\n  update : edit\n", ""),  # no rules: the table stays closed
            ("  update : edit\n", "  update : edit\n  update owner_id : edit\n"),  # a column rule narrows
            ("can view = edit or viewer", "can view = viewer or edit"),
            (" where {not archived}", " where {not archived and not deleted}"),  # fewer rows count
        ):
            self.assertEqual(self.small(old, new)["risk"], [], new)

    def test_text_in_quotes_is_compared_as_written(self) -> None:
        r = self.small("'a  b'", "'a b'")
        self.assertIsNone(r["meaning"]["equivalent"])
        self.assertEqual([c["what"] for c in r["meaning"]["changed"]], ["folder.remove"])
        # spaces outside quotes are still only spacing
        self.assertEqual(
            self.small("can edit = owner or org.admin", "can edit  =  owner   or org.admin")["meaning"]["equivalent"],
            "text",
        )

    def test_a_widening_behind_many_conditions(self) -> None:
        r = self.small("can deep = owner and", "can deep = (owner or viewer) and")
        self.assertIsNone(r["meaning"]["equivalent"])
        self.assertIn("a permission widened", {f["why"] for f in r["risk"]})

    def test_a_policy_with_a_mistake_is_refused_with_its_message(self) -> None:
        with self.assertRaises(PolicyError) as e:
            self.small("can view = edit or viewer", "can view = edit or viewer or nosuch.view")
        self.assertEqual(e.exception.code, "AZ203")

    def test_a_base_with_a_mistake_is_said_and_the_head_reviewed_as_new(self) -> None:
        """The pull request that fixes the base's mistake is reviewed: as one that adds the policy, and every output
        says first that the base has a mistake, where there and its code."""
        broken = replaced(self.SMALL, "can see = member", "can see = nosuch")
        r = self.review.review((broken, {}, {}), (self.SMALL, {}, {}), worlds=40)
        mistake = r.get("base_mistake")
        assert mistake is not None
        self.assertEqual((mistake["line"], mistake["code"]), ("line 7", "AZ203"))
        self.assertTrue(mistake["message"].startswith("org has no relation or permission 'nosuch'"), mistake)
        # the rest is the review of a new policy, as where the base has none
        new = self.review.review(None, (self.SMALL, {}, {}), worlds=40)
        self.assertEqual({k: v for k, v in r.items() if k != "base_mistake"}, new)
        self.assertNotIn("base_mistake", new)
        said = f"line 7 there: {mistake['message']} [AZ203]"
        note = f"The policy at the base has a mistake ({said}), so the review reads this one as new."
        self.assertTrue(self.review.text(r).startswith(f"Base     {note}\nMeaning  "), self.review.text(r))
        md = self.review.markdown(r).splitlines()
        self.assertEqual(md[3:5], [note, ""])
        self.assertEqual(json.loads(self.review.as_json(r))["base_mistake"], mistake)
        notes = self.review.annotations(r, "db/policy.authz").splitlines()
        self.assertEqual(notes[0], f"::warning file=db/policy.authz,title=rowstile review::{note}")
        # a mistake that names no line: the whole message, no line
        self.assertEqual(
            self.review.mistake_of(PolicyError("the policy: something", "AZ999")),
            {"line": None, "message": "the policy: something", "code": "AZ999"},
        )
        self.assertEqual(
            self.review.mistake_of(PolicyError("roles.authz line 3: a 100% mistake", "AZ201"))["line"],
            "roles.authz line 3",
        )

    def test_a_base_in_forms_the_language_does_not_have_is_a_base_with_a_mistake(self) -> None:
        """`role x` for the app role, `roles : user grant view` for custom roles, a word after an update rule's
        columns: the parser refuses each, and the review reads no such form itself. The head is reviewed as new."""
        for old, new, mistake in (
            ("app role app_user\n", "role app_user\n", ("line 1", "AZ101", "expected 'app role', 'type', ")),
            (
                "  viewer : user shared by edit\n",
                "  roles : user grant view\n",
                ("line 11", "AZ103", "bad subject 'user grant view'"),
            ),
            (
                "  update : edit\n",
                "  update : edit\n  update org_id check : edit\n",
                ("line 19", "AZ105", "write column rules as: update col1, col2 : expression"),
            ),
        ):
            r = self.review.review((replaced(self.SMALL, old, new), {}, {}), (self.SMALL, {}, {}), worlds=10)
            said = r.get("base_mistake")
            assert said is not None, new
            self.assertEqual((said["line"], said["code"]), mistake[:2], said)
            self.assertTrue(said["message"].startswith(mistake[2]), said)
            self.assertEqual({c["kind"] for c in r["meaning"]["changed"]}, {"added"})

    def test_the_details_are_written_when_the_meaning_is_unchanged(self) -> None:
        before = {"t.authz": 'test "carol"\n  user 3 can view file 11\n  user 3 cannot view file 12\n'}
        after = {"t.authz": 'test "carol"\n  user 3 cannot view file 11\n'}
        r = self.run_review(self.text, before, after)
        self.assertEqual(r["meaning"]["equivalent"], "text")
        md = self.review.markdown(r)
        self.assertIn("<details><summary>Tests</summary>", md)
        self.assertIn("`user 3 can view file 11` -> `user 3 cannot view file 11`", md)
        self.assertIn("removed from carol: `user 3 cannot view file 12`", md)
        self.assertIn("removed from carol: user 3 cannot view file 12", self.review.text(r))

    def test_a_flag_in_an_included_file_is_annotated_there(self) -> None:
        main = self.SMALL.replace(
            "type org = app.orgs\n  member : user = app.org_members(org_id -> user_id)\n"
            "  admin  : user = app.org_members(org_id -> user_id) where {role = 'admin'}\n"
            "  can manage = admin\n  can see = member\n",
            'include "org.authz"\n',
        )
        org = (
            "type org = app.orgs\n  member : user = app.org_members(org_id -> user_id)\n"
            "  admin  : user = app.org_members(org_id -> user_id) where {role = 'admin'}\n"
            "  can manage = admin\n  can see = member\n"
        )
        self.assertNotEqual(main, self.SMALL)
        r = self.review.review(
            (main, {"org.authz": org}, {}),
            (main, {"org.authz": org.replace("can manage = admin", "can manage = admin or member")}, {}),
            worlds=120,
        )
        notes = self.review.annotations(r, "db/policy.authz")
        self.assertRegex(notes, r"^::warning file=db/org.authz,line=4,title=rowstile review::a permission widened")

    def test_a_column_rule_is_known_however_its_head_is_written(self) -> None:
        """`update owner_id before : ...` says what `update owner_id : ...` says, and `update a,b` what `update a, b`
        says. The review named a rule by its text, and looked for what allows more by the rule as read: the two
        names didn't meet, and such a column rule loosened went unflagged."""
        base = replaced(
            self.SMALL,
            "  update : edit\n",
            "  update : edit\n  update owner_id before : owner\n  update org_id,status : owner\n",
        )
        for old, new, name in (
            ("update owner_id before : owner", "update owner_id before : edit", "app.folders update owner_id"),
            ("update org_id,status : owner", "update org_id,status : edit", "app.folders update org_id, status"),
        ):
            r = self.review.review((base, {}, {}), (replaced(base, old, new), {}, {}), worlds=120)
            self.assertEqual([c["what"] for c in r["meaning"]["changed"]], [f"rule {name}"], name)
            self.assertIn(
                ("a write rule loosened", f"`{name}` allows more than before"),
                [(f["why"], f["flag"].split(" (e.g. ")[0]) for f in r["risk"]],
                name,
            )
        # written the other way, it is the same rule
        same = replaced(replaced(base, "owner_id before :", "owner_id :"), "org_id,status", "org_id, status")
        self.assertEqual(self.review.review((base, {}, {}), (same, {}, {}), worlds=40)["meaning"]["equivalent"], "text")

    def test_what_changes_beside_a_condition_it_cannot_read(self) -> None:
        """A small world draws the rows a condition it can't read holds for by the condition's text, so a reworded one
        holds for other rows there whatever it says, and what reads it differed there too: a permission that only
        reordered its `or` around one was said to allow more, with a made-up example; one that only read it was
        named as the difference that makes it no refactor (when its name came first); an `after` rule too, by a
        name the policy doesn't write."""
        lock = "{exists (select 1 from app.locks l where l.folder_id = this.id)}"
        member = "{exists (select 1 from app.org_members m where m.org_id = this.org_id)}"
        base = replaced(
            self.SMALL,
            "  can view = edit or viewer\n",
            f"  can view = edit or viewer\n  can open = owner and not {lock}\n  can archive = open or org.admin\n",
        )
        base = replaced(base, "  update : edit\n", f"  update : edit\n  update org_id after : {member}\n")
        reworded = replaced(base, "this.id)}", "this.id and true)}").replace("this.org_id)}", "this.org_id and true)}")
        r = self.review.review(
            (base, {}, {}), (replaced(reworded, "open or org.admin", "org.admin or open"), {}, {}), worlds=120
        )
        self.assertEqual(r["meaning"].get("unreadable"), ["folder.open", "rule app.folders update org_id after"])
        self.assertIsNone(r["meaning"]["equivalent"])  # what it can't compare is no "unchanged"
        self.assertNotIn("counterexample", r["meaning"])
        self.assertEqual({f["why"] for f in r["risk"]}, {"a condition it can't read changed"})
        self.assertNotIn("not a refactor", self.review.text(r))
        # what changed beside them is compared as ever: a widening, and its example
        wider = replaced(reworded, "can view = edit or viewer\n", "can view = edit or viewer or org.see\n")
        r = self.review.review((base, {}, {}), (wider, {}, {}), worlds=120)
        self.assertEqual(r["meaning"].get("counterexample", {}).get("what"), "folder.view")
        self.assertIn("a permission widened", {f["why"] for f in r["risk"]})
        # a rule written `after` is named so
        r = self.review.review((base, {}, {}), (replaced(base, f"after : {member}", "after : view"), {}, {}))
        self.assertIn("not a refactor: rule app.folders update org_id after differs for ", self.review.text(r))

    def test_texts_a_column_may_hold_alike_are_beyond_the_review(self) -> None:
        # `{status = 'a  b'}` and `{status = 'a  b' and status <> 'A  B'}` were read as the same, "Meaning unchanged",
        # where a case-insensitive column holds the second for no row: the worlds draw such conditions' rows, so the
        # review says it can't read the change
        r = self.small("{status = 'a  b'}", "{status = 'a  b' and status <> 'A  B'}")
        self.assertIsNone(r["meaning"]["equivalent"])
        self.assertEqual(r["meaning"].get("unreadable"), ["folder.remove"])
        self.assertEqual({f["why"] for f in r["risk"]}, {"a condition it can't read changed"})
        # other words are read as two values: the same meaning, checked in small worlds
        r = self.small("{status = 'a  b'}", "{status = 'a  b' and status <> 'draft'}")
        self.assertIn("small worlds", r["meaning"]["equivalent"] or "")
        self.assertNotIn("unreadable", r["meaning"])

    def test_text_between_dollar_quotes_is_compared_as_written(self) -> None:
        # $$a  b$$ is a string, as 'a  b' is: its spaces are what it says, not the policy's layout
        base = replaced(self.SMALL, "{status = 'a  b'}", "{status = $$a  b$$}")
        r = self.review.review((base, {}, {}), (replaced(base, "$$a  b$$", "$$a b$$"), {}, {}), worlds=40)
        self.assertIsNone(r["meaning"]["equivalent"])
        self.assertEqual([c["what"] for c in r["meaning"]["changed"]], ["folder.remove"])
        self.assertEqual(r["meaning"].get("unreadable"), ["folder.remove"])  # a condition it doesn't read itself

    def test_a_widening_beside_a_condition_it_cannot_read_is_put_down_to_the_where(self) -> None:
        # a type's where taken off, and a condition it can't read reworded: what allows more does so because more rows
        # count, not because of the reworded condition (nor of what reads it)
        base = replaced(
            self.SMALL,
            "  can view = edit or viewer\n",
            "  can view = edit or viewer\n  can open = owner and not {exists (select 1 from app.locks l where "
            "l.folder_id = this.id)}\n  can archive = open or org.admin\n",
        )
        head = replaced(replaced(base, " where {not archived}", ""), "this.id)}", "this.id and true)}")
        r = self.review.review((base, {}, {}), (head, {}, {}), worlds=120)
        self.assertEqual(
            sorted(f["why"] for f in r["risk"]), ["a condition it can't read changed", "a type's where loosened"]
        )

    def test_a_rule_that_denies_through_a_permission(self) -> None:
        # `delete : edit and not frozen`: a narrower frozen lets more be deleted
        base = replaced(self.SMALL, "  update : edit\n", "  update : edit\n  delete : edit and not frozen\n")
        base = replaced(base, "  can view = edit or viewer\n", "  can view = edit or viewer\n  can frozen = {locked}\n")
        r = self.review.review(
            (base, {}, {}), (replaced(base, "= {locked}", "= {locked} and {hard}"), {}, {}), worlds=120
        )
        self.assertIn(
            {"what": "rule app.folders delete", "via": ["folder.frozen"], "line": "line 20"}, r["meaning"]["through"]
        )
        self.assertIn(
            (
                "a rule loosened through what it uses",
                "`app.folders delete` allows more than before through `folder.frozen`",
            ),
            [(f["why"], f["flag"].split(" (e.g. ")[0]) for f in r["risk"]],
        )

    def test_a_lock_another_version_wrote_is_current_when_nothing_changes(self) -> None:
        # a pull request that upgrades rowstile, whose lock file says the new version: no migration, and not behind
        from authzlib import migrate

        lock = migrate.lock_of(database.migratable(self.text, {})[1])
        old = replaced(lock, f"# rowstile {authzlib.__version__}:", "# rowstile 0.0.9:")
        for base_lock, head_lock in ((old, lock), (lock, old)):
            d = self.review.review((self.text, {}, {}), (self.text, {}, {}), base_lock, head_lock, None)["deploy"]
            self.assertEqual((d["migrations"], d["lock_current"]), ([], True))

    def test_the_comment_says_which_trees_are_rebuilt(self) -> None:
        # links that come from shares too: the tree can't be built beside the one in use, it is rebuilt under lock
        r = self.run_review(
            replaced(
                self.text,
                "  linked_into : folder      = app.folder_links(folder_id -> parent_id)  -- also shown inside these\n",
                "  linked_into : folder      = app.folder_links(folder_id -> parent_id)  -- also shown inside these\n"
                "  linked_into : folder shared by share\n",
            )
        )
        self.assertEqual([m["rebuilds"] for m in r["deploy"]["migrations"]], [["folder__linked_into_parent__tree"]])
        self.assertIn(
            "  - rebuilds `folder__linked_into_parent__tree`, its tables locked meanwhile\n", self.review.markdown(r)
        )

    def test_what_is_removed_has_no_after(self) -> None:
        r = self.small("  can manage = admin\n", "")
        self.assertTrue(self.review.text(r).endswith("\n  removed  org.manage\n             before: admin\n"))

    def test_a_widening_risk_finds_is_no_refactor(self) -> None:
        """Meaning and Risk draw their small worlds apart: when Risk finds an example the comparison didn't (here,
        none at all), Meaning doesn't say unchanged."""
        with mock.patch.object(self.review, "compare", return_value=None):
            r = self.small("can view = edit or viewer", "can view = edit or viewer or org.see")
        self.assertIsNone(r["meaning"]["equivalent"])
        self.assertIn("a permission widened", {f["why"] for f in r["risk"]})
        md = self.review.markdown(r)
        self.assertIn("**Meaning**: 1 permission changed", md)
        # three flags: the summary names all three (no "..."), and the comment lists each under Risk
        self.assertEqual(len(r["risk"]), 3)
        self.assertIn(f"**Risk**: 3 flags: {'; '.join(f['flag'] for f in r['risk'])}  \n", md)
        self.assertIn(f"\n<details><summary>Risk</summary>\n\n- {r['risk'][0]['flag']} (", md)
        # and when all Risk found is that it allows more, no other flag beside it
        with mock.patch.object(self.review, "compare", return_value=None):
            r = self.small("can remove = owner and {status = 'a  b'}", "can remove = owner")
        self.assertEqual([f["why"] for f in r["risk"]], ["a permission widened"])
        self.assertIsNone(r["meaning"]["equivalent"])

    def test_a_where_on_a_link_table_narrows_or_widens_as_it_reads(self) -> None:
        """A link table's rows are the same whatever its where says: adding a where (even one the review can't
        read), or a where that holds for fewer rows, allows less; taking it off, or one that holds for more or other rows, allows more."""
        plain = (
            "app role app_user\ntype user = app.users\ntype doc = app.docs\n"
            "  viewer : user = app.v(doc_id -> user_id)\n  can view = viewer\n"
        )
        where = plain.replace("user_id)\n", "user_id) where {active}\n")
        flag = "a permission widened through what it uses"
        for base, head, widens in (
            (plain, where, False),
            (where, plain, True),
            (where, where.replace("{active}", "{active and not banned}"), False),
            (where, where.replace("{active}", "{active or invited}"), True),
            (where, where.replace("{active}", "{role = 'admin'}"), True),
            # one it can't read holds for some of the rows, drawn row by row: added, it narrows too
            (plain, plain.replace("user_id)\n", "user_id) where {exists (select 1 from app.bans)}\n"), False),
        ):
            r = self.review.review((base, {}, {}), (head, {}, {}), worlds=40)
            self.assertEqual(flag in {f["why"] for f in r["risk"]}, widens, (head, r["risk"]))
        # in the listed worlds too: the rows with no where hold every row the where holds for
        listing = evaluate.Listing([parse_policy(plain, "a.authz"), parse_policy(where, "b.authz")])
        for w in itertools.islice(listing.worlds(), 400):
            no, yes = (set(w.data(p).pairs[("doc", "viewer", 0, "user", "")]) for p in listing.pols)
            self.assertLessEqual(yes, no)

    def test_a_widening_the_comparison_found_is_flagged(self) -> None:
        """The other way round: when Risk's worlds (here, none) miss what the comparison found, the review said
        "not a refactor" and "nothing flagged" at once, of a permission that allows more."""
        for old, new, what, flag in (
            ("can view = edit or viewer", "can view = edit or viewer or org.see", "folder.view", "`folder.view`"),
            ("  select : view\n", "  select : view or org.see\n", "rule app.folders select", "`app.folders select`"),
        ):
            with mock.patch.object(self.review, "grants_more", side_effect=lambda *_: {}):
                r = self.small(old, new)
            ce = r["meaning"].get("counterexample")
            assert ce is not None
            self.assertEqual((ce["what"], ce["before"], ce["after"]), (what, False, True))
            self.assertIn(
                f"{flag} allows more than before (e.g. user {ce['user']} on folder {ce['object']})",
                [f["flag"] for f in r["risk"]],
            )

    def test_a_permission_opened_to_someone_not_signed_in(self) -> None:
        # signed_in, anyone and nobody are words the review reads: from signed_in to anyone is a widening for someone
        # not signed in, not "a condition it can't read changed (`{authz.uid() IS NOT NULL}` -> `{true}`)"
        base = (
            "app role app_user\ntype user = app.users\ntype doc = app.docs\n  owner : user = owner_id\n"
            "  can view = owner or signed_in\nrules app.docs\n  select : view\n"
        )
        r = self.review.review((base, {}, {}), (replaced(base, "or signed_in", "or anyone"), {}, {}), worlds=40)
        self.assertNotIn("unreadable", r["meaning"])
        self.assertEqual(
            (r["risk"][0]["why"], r["risk"][0]["flag"]),
            ("a permission widened", "`doc.view` allows more than before (e.g. nobody signed in on doc 1)"),
        )
        self.assertNotIn("a condition it can't read changed", {f["why"] for f in r["risk"]})
        self.assertIn("  not a refactor: doc.view differs for nobody signed in on doc 1\n", self.review.text(r))

    def test_the_review_data_in_words(self) -> None:
        """Who gains and loses, said as who they are: a service is no user, nor is someone not signed in (both were
        counted as users), and a user whose id holds a ':' (written user:<id>) is a user, even one that reads like a
        bot. And a project without a lock file has its policy applied whole on the review data: when that fails,
        Tests said "the migration fails", and Deploy nothing."""
        rows = [
            {"change": "gains", "user_id": "user:google:123", "type": "file", "what": "permission view", "id": "11"},
            # (bot is a type that signs in: the preview writes the user whose id is bot:9 as user:bot:9)
            {"change": "gains", "user_id": "user:bot:9", "type": "file", "what": "permission view", "id": "12"},
            {"change": "gains", "user_id": "bot:7", "type": "folder", "what": "permission view", "id": "1"},
            {"change": "gains", "user_id": None, "type": "folder", "what": "permission view", "id": "2"},
            {"change": "gains", "user_id": "3", "type": "folder", "what": "permission view", "id": "1"},
            {"change": "loses", "user_id": "bot:7", "type": "file", "what": "permission edit", "id": "11"},
        ]
        head = replaced(
            replaced(self.text, "  can break_glass = org.member\n", ""),
            "type org = app.orgs\n",
            "type bot = app.bots principal\n\ntype org = app.orgs\n",
        )
        for error, deploy in (
            ("column x not found", " **It fails on the review database: column x not found**"),
            (None, " Applied on the review database in 0.2 s."),
        ):
            how = {("user:google:123", "file", "11", "view"): ["yes  owner"]}
            ran = {"deployed": None if error else 0.2, "error": error, "tests": [], "how": how}
            with (
                mock.patch.object(database, "diff", return_value=rows),
                mock.patch.object(database, "review_run", return_value=ran) as run,
            ):
                r = self.review.review((self.text, {}, {}), (head, {}, {}), None, None, mock.Mock(), worlds=10)
            s = self.review.summary(r)
            self.assertEqual(
                s["Access"],
                "2 users gain `view` on 2 files; 1 user, 1 bot and someone not signed in gain `view` on 2 folders. "
                "1 bot loses `edit` on 1 file.",
            )
            md = self.review.markdown(r)
            self.assertIn(
                "| gains | `file` view | 2 users | 2 | user google:123, file 11: owner; user bot:9, file 12 |", md
            )
            self.assertIn(
                "| gains | `folder` view | 1 user, 1 bot and someone not signed in | 2 | "
                "bot 7, folder 1; nobody signed in, folder 2 |",
                md,
            )
            # what it asks database.review_run to explain: each one as --as writes it
            self.assertEqual(
                run.call_args.args[5],
                [
                    ("user:google:123", "file", "11", "view"),
                    ("user:bot:9", "file", "12", "view"),
                    ("bot:7", "folder", "1", "view"),
                    ("", "folder", "2", "view"),
                ],
            )
            self.assertTrue(s["Deploy"].startswith("no lock file, so no migrations: "), s["Deploy"])
            self.assertTrue(s["Deploy"].endswith(deploy), s["Deploy"])
            if error:
                self.assertEqual(s["Tests"], f"not run: applying the policy fails: {error}.")

    def test_the_review_data_shows_three_examples_of_a_change(self) -> None:
        # five users gain view on five files: all counted, three of them kept as examples, two shown in the comment's
        # table, under its header
        rows = [
            {"change": "gains", "user_id": str(u), "type": "file", "what": "permission view", "id": str(10 + u)}
            for u in range(1, 6)
        ]
        ran = {"deployed": 0.2, "error": None, "tests": [], "how": {}}
        with (
            mock.patch.object(database, "diff", return_value=rows),
            mock.patch.object(database, "review_run", return_value=ran),
        ):
            head = replaced(self.text, "  can break_glass = org.member\n", "")
            r = self.review.review((self.text, {}, {}), (head, {}, {}), None, None, mock.Mock(), worlds=10)
        a = r["access"]
        assert a is not None
        [g] = a["groups"]
        self.assertEqual((g["users"], g["objects"], [e["id"] for e in g["examples"]]), (5, 5, ["11", "12", "13"]))
        self.assertIn(
            "\n| change | what | who | objects | examples |\n|---|---|---|---|---|\n"
            "| gains | `file` view | 5 users | 5 | user 1, file 11; user 2, file 12 |\n",
            self.review.markdown(r),
        )

    def test_how_someone_gains_is_what_grants_it(self) -> None:
        # authz.explain's answer (as the database gave it): {inherit} holds, inside a part that doesn't, so it is no
        # part of how bot 7 holds view (the comment said "bot 7, folder 2: {inherit}, bot_viewer, ...")
        explained = [
            "yes  bot 7 holds view on folder 2",
            "  folder.view = edit or viewer or (parent.view and {inherit}) or linked_into.view or bot_viewer",
            "  no   edit",
            "  no   (parent.view and {inherit})",
            "    no   parent.view",
            "           parent is a folder you can't see",
            "    yes  {inherit}",
            "  yes  bot_viewer",
            "    yes  bot_viewer: a row in app.folder_bots names",
        ]
        self.assertEqual(
            database.granting(explained),
            ["yes  bot 7 holds view on folder 2", "yes  bot_viewer", "yes  bot_viewer: a row in app.folder_bots names"],
        )

    class Explaining:
        """A database with the pull request's policy in force: authz.explain answers, and refuses file 13."""

        class Refused(Exception):
            pass

        def __init__(self) -> None:
            self.said: list[tuple[str, list[Value]]] = []

        @property
        def errors(self) -> type[Exception]:
            return self.Refused

        def rows(self, sql: str, args: Sequence[Value] = ()) -> list[Row]:
            self.said.append((sql, list(args)))
            if "authz.explain" in sql and args[1] == "13":
                raise self.Refused("canceling statement due to statement timeout")
            if "authz.explain" in sql:
                return [{"l": "yes  it holds view on file"}, {"l": "  file.view = owner"}, {"l": "  yes  owner"}]
            return []

        def script(self, sql: str) -> None:
            self.said.append((sql, []))

        def warn(self, message: str, detail: str | None = None, hint: str | None = None) -> None:
            pass

    def test_how_is_asked_as_each_one_and_a_refusal_left_out(self) -> None:
        # each example asked as who it is: a user by their id (one with a ':' in it too), a bot signed in as itself,
        # nobody as nobody; one explain refuses has no how, and the review goes on (the tests run)
        db = self.Explaining()
        wanted = [
            ("user:google:123", "file", "11", "view"),
            ("bot:7", "file", "12", "view"),
            ("user:3", "file", "13", "view"),
            ("", "file", "14", "view"),
        ]
        with mock.patch.object(database, "apply"), mock.patch.object(database, "test", return_value=[]) as test:
            ran = database.review_run(db, self.text, {}, {}, None, wanted)
        self.assertEqual(sorted(ran["how"]), sorted(w for w in wanted if w[2] != "13"))
        self.assertEqual(ran["how"][("bot:7", "file", "12", "view")], ["yes  owner"])
        test.assert_called_once()
        self.assertEqual(
            [args for sql, args in db.said if "authz.explain" in sql or "authz.act_as" in sql],
            [
                ["file", "11", "view", "google:123"],
                ["bot", "7"],
                ["file", "12", "view", None],
                ["file", "13", "view", "3"],
                ["file", "14", "view", None],
            ],
        )
        # each in a savepoint undone after it: nothing an example did stays, a bot's sign-in say
        self.assertEqual(sum("ROLLBACK TO SAVEPOINT authz_review_explain" in sql for sql, _ in db.said), 4)

    def test_the_summary_at_its_edges(self) -> None:
        # three groups are all said, with no "and 0 more"; a permission lost is said before the rows lost with it;
        # a test that failed without a detail; and of two statements locking a table alike, the first says why
        r = self.run_review(self.text)

        def group(change: str, what: str, objects: int) -> Group:
            return {"change": change, "type": "file", "what": what, "users": 1, "who": "1 user", "objects": objects,
                    "examples": []}  # fmt: skip

        r["access"] = {
            "groups": [
                group("gains", "permission view", 1),
                group("gains", "permission edit", 2),
                group("gains", "permission share", 3),
                group("loses", "rows to select", 4),
                group("loses", "permission view", 5),
            ],
            "users_in_data": 1,
        }
        r["tests"]["run"] = {
            "checks": 3,
            "failed": [
                {"test": "a test", "line": None, "detail": None},
                {"test": "another", "line": "tests/a.authz line 3", "detail": "user 1 can view file 2: no\nmore"},
            ],
        }
        self.assertEqual(
            self.review.summary(r)["Access"],
            "1 user gains `view` on 1 file; 1 user gains `edit` on 2 files; 1 user gains `share` on 3 files. "
            "1 user loses `view` on 5 files.",
        )
        # its line and the first line of its detail where it has them, and no empty code quotes where it hasn't
        failed = [x for x in self.review.tests_details(r) if x.startswith("- fails: ")]
        self.assertEqual(
            failed, ["- fails: a test", "- fails: another (tests/a.authz line 3): `user 1 can view file 2: no`"]
        )
        sql = "ALTER TABLE app.docs ENABLE ROW LEVEL SECURITY;\nDROP TRIGGER t ON app.docs;\n"
        self.assertEqual(
            self.review.table_locks(sql), {"app.docs": ("ACCESS EXCLUSIVE", "row-level security turned on")}
        )

    # a rule that reads a relation's permission itself, a share condition, a caveat and a plain `update after`
    WATCHED = """app role app_user
type user = app.users where {active}
type folder = app.folders
  owner  : user = owner_id
  viewer : user shared if {subject_id <> '0'}
  can share = owner
  can edit = owner
  can view = edit or viewer
type file = app.files
  folder : folder = folder_id
  can view = folder.view
caveat hours = {authz.ctx('mode') = 'business'}
rules app.files
  select : view
  insert : folder.edit
  update : view
  update after : folder.edit
"""

    def watched(self, old: str, new: str, base: str | None = None) -> Review:
        base = base or self.WATCHED
        self.assertIn(old, base)
        return self.review.review((base, {}, {}), (base.replace(old, new), {}, {}), worlds=50)

    def test_a_rule_that_reads_a_relation_it_follows_changes_through_it(self) -> None:
        # `insert : folder.edit` reads file.folder as much as `select : view` does: another column there changes
        # both, and who may insert is flagged with an example
        r = self.watched("folder : folder = folder_id", "folder : folder = other_id")
        through = {t["what"]: t["via"] for t in r["meaning"]["through"]}
        for rule in ("insert", "update after"):
            self.assertEqual(through.get(f"rule app.files {rule}"), ["file.folder"], rule)
        flags = {f["flag"].split(" (e.g.")[0]: f["why"] for f in r["risk"]}
        for rule in ("insert", "update after"):
            self.assertEqual(
                flags.get(f"`app.files {rule}` allows more than before through `file.folder`"),
                "a rule loosened through what it uses",
                rule,
            )

    def test_who_a_share_may_name_widened_is_flagged(self) -> None:
        cond = "shared if {subject_id <> '0'}"
        r = self.watched(cond, "shared")
        self.assertEqual(
            [(f["flag"], f["why"], f["line"]) for f in r["risk"]],
            [
                (
                    "`folder.viewer`: its share condition is removed (was `{subject_id <> '0'}`)",
                    "a share condition removed or changed",
                    "line 5",
                )
            ],
        )
        r = self.watched(cond, "shared if {subject_id <> '1'}")
        self.assertEqual(
            [f["flag"] for f in r["risk"]],
            ["`folder.viewer`: its share condition changed: `{subject_id <> '0'}` -> `{subject_id <> '1'}`"],
        )
        # one added, or the same one written another way, only narrows or says the same: nothing flagged
        open_ = self.WATCHED.replace(cond, "shared")
        self.assertEqual(self.watched("user shared\n", f"user {cond}\n", base=open_)["risk"], [])
        self.assertNotIn(
            "a share condition removed or changed",
            {f["why"] for f in self.watched(cond, "shared if {subject_id  <>  '0'}")["risk"]},
        )

    def test_a_caveat_changed_is_flagged(self) -> None:
        r = self.watched("{authz.ctx('mode') = 'business'}", "{true}")
        self.assertEqual(
            [(f["flag"], f["why"], f["line"]) for f in r["risk"]],
            [
                (
                    "`caveat hours` changed: `caveat hours = {authz.ctx('mode') = 'business'}` -> "
                    "`caveat hours = {true}`",
                    "a caveat changed",
                    "line 12",
                )
            ],
        )

    def test_the_rule_after_an_update_is_no_column_rule(self) -> None:
        # taken out, `update` checks the rows after an update too: here it lets more through (view is wider)
        r = self.watched("  update after : folder.edit\n", "")
        self.assertEqual(
            [(f["flag"].split(" (e.g.")[0], f["why"], f["line"]) for f in r["risk"]],
            [
                (
                    "`app.files update after` is removed, and `update` lets more rows through after an update "
                    "than it did",
                    "a write rule loosened",
                    "line 16",
                )
            ],
        )
        # one new on a table that had rules checks the rows after an update instead of `update`: wider, flagged
        narrow = self.WATCHED.replace("  update : view\n  update after : folder.edit\n", "  update : folder.edit\n")
        r = self.watched("  update : folder.edit\n", "  update : folder.edit\n  update after : view\n", base=narrow)
        self.assertEqual(
            [(f["flag"].split(" (e.g.")[0], f["why"]) for f in r["risk"]],
            [
                (
                    "`app.files update after` is new, and lets more rows through after an update than `update` did",
                    "a write rule loosened",
                )
            ],
        )
        # narrower than `update`, or taken out where `update` is narrower: nothing flagged
        self.assertEqual(
            self.watched(
                "  update : folder.edit\n",
                "  update : folder.edit\n  update after : folder.edit and {done}\n",
                base=narrow,
            )["risk"],
            [],
        )
        wide_after = self.WATCHED.replace("  update : view\n  update after : folder.edit\n",
                                          "  update : folder.edit\n  update after : view\n")  # fmt: skip
        self.assertEqual(self.watched("  update after : view\n", "", base=wide_after)["risk"], [])
        # taken out with the `update` rule: no update is allowed, nothing checks the rows after one, nothing flagged
        self.assertEqual(self.watched("  update : view\n  update after : folder.edit\n", "")["risk"], [])

    def test_deploy_names_the_tables_found_as_it_runs(self) -> None:
        # a trigger on each table an inheritance condition reads, row-level security on the partitions: the DO
        # blocks find those tables in the database, and say what they lock
        from authzlib import migrate

        policy = (
            "app role app_user\ntype user = app.users\ntype folder = app.folders\n  parent : folder = parent_id\n"
            "  owner  : user = owner_id\n"
            "  can view = owner or (parent.view and {exists (select 1 from app.settings s where s.folder_id = this.id)})\n"
            "rules app.folders\n  select : view\n"
        )
        lock = migrate.lock_of(database.migratable(policy, {})[1])
        r = self.review.review(None, (policy, {}, {}), None, lock, None, worlds=10)
        [m] = r["deploy"]["migrations"]
        self.assertEqual(
            m["found_locks"],
            [
                {"what": "the tables the inheritance conditions read (line 6)", "mode": "SHARE ROW EXCLUSIVE"},
                {
                    "what": "the partitions and child tables of the tables it turns row-level security on for",
                    "mode": "ACCESS EXCLUSIVE",
                },
            ],
        )
        self.assertIn(
            '1 migration. Locks `"app"."folders"`, `"app"."users"` while it runs. It also locks the tables '
            "the inheritance conditions read (line 6), and the partitions and child tables of the tables it turns "
            "row-level security on for. ",
            self.review.summary(r)["Deploy"],
        )
        md = self.review.markdown(r)
        self.assertIn("  - the tables the inheritance conditions read (line 6): SHARE ROW EXCLUSIVE\n", md)
        self.assertIn("- every migration also gives rowstile's triggers to the partitions and child tables", md)

    def test_the_comment_shows_why_it_is_no_refactor(self) -> None:
        # a narrowing: Risk flags nothing, so the example is all the comment has to show what changed
        r = self.small("can view = edit or viewer", "can view = edit")
        self.assertEqual(r["risk"], [])
        ce = r["meaning"].get("counterexample")
        assert ce is not None
        md = self.review.markdown(r)
        said = f"Not a refactor: {self.review.differs(ce, code=True)} (the base grants it, this change doesn't), in this world:"
        self.assertRegex(said, r"^Not a refactor: `folder\.view` differs for user \S+ on folder \S+ \(")
        self.assertIn(said + "\n\n```\n" + "\n".join(ce["world"]) + "\n```\n", md)
        self.assertIn(f"  not a refactor: {self.review.differs(ce)}\n", self.review.text(r))


class Graph(unittest.TestCase):
    """rowstile graph: the Mermaid diagram's nodes."""

    @staticmethod
    def nodes(policy: str) -> tuple[list[str], set[str]]:
        """The ids the diagram declares (nodes and boxes), and the ids its arrows use."""
        c = Compiler(parse_policy(policy, None, files={}))
        c.compile("the policy")
        g = c.graph()
        declared = re.findall(r"^\s+([A-Za-z0-9_]+)(?:\[|\(|\(\()", g, re.M) + re.findall(
            r"^\s+subgraph ([A-Za-z0-9_]+)\[", g, re.M
        )
        used: set[str] = set()
        for a, b in re.findall(r"^\s+([A-Za-z0-9_]+) [-=.]+>(?:\|[^|]*\|)? ([A-Za-z0-9_]+)$", g, re.M):
            used |= {a, b}
        return declared, used

    def test_two_things_never_share_a_node(self) -> None:
        base = "app role app_user\ntype user = app.users\n"
        declared, used = self.nodes(
            base
            + "type team = app.teams\n  owner : user = owner_id\n  can member_view = owner\nrules app.teams\n  select : member_view\n"
            "type team_member = app.team_members\n  owner : user = owner_id\n  can view = owner\nrules app.team_members\n  select : view\n"
            "type t = app.t\n  user : user = user_id\n  can view = user\nrules app.t\n  select : view\n"
        )
        self.assertEqual(len(declared), len(set(declared)), sorted(x for x in declared if declared.count(x) > 1))
        self.assertLessEqual(used, set(declared))

    def test_every_signed_in_service_is_drawn_to_its_type(self) -> None:
        declared, used = self.nodes(
            "app role app_user\ntype user = app.users\ntype service = app.services principal\ntype doc = app.docs\n"
            "  owner : user = owner_id\n  viewer : user, service, service:*, anyone shared by view\n  can view = owner or viewer\n"
            "rules app.docs\n  select : view\n"
        )
        self.assertLessEqual(used, set(declared), sorted(used - set(declared)))
        self.assertEqual(len(declared), len(set(declared)))

    def test_the_whole_diagram(self) -> None:
        # what rowstile graph prints, line by line: the styles, a box per type, shares dotted and columns solid, a
        # share with a team's members to the member relation (the team has no permission), with every service to
        # the services' box, and a permission inherited through a relation in double lines, saying which
        c = Compiler(
            parse_policy(
                "app role app_user\ntype user = app.users\ntype service = app.services principal\n"
                "type team = app.teams\n  member : user = app.team_members(team_id -> user_id)\n"
                "type folder = app.folders\n  parent : folder = parent_id\n  owner : user = owner_id\n"
                "  can view = owner or parent.view\n"
                "type doc = app.docs\n  folder : folder = folder_id\n"
                "  viewer : user, team#member, service:* shared by view\n  can view = viewer or folder.view\n"
                "rules app.docs\n  select : view\n",
                None,
                files={},
            )
        )
        c.compile("the policy")
        self.assertEqual(
            c.graph().split("\n"),
            [
                "%% Generated by rowstile graph. Paste into any Mermaid viewer (GitHub renders it in ```mermaid blocks).",
                "flowchart LR",
                "  classDef perm fill:#e8f0fe,stroke:#4a6fd1,color:#1b2a4a",
                "  classDef rel fill:#f6f6f6,stroke:#888,color:#222",
                "  classDef user fill:#fff4e0,stroke:#d19a4a,color:#4a2f0b",
                '  user(("user")):::user',
                '  subgraph service__0["service · app.services"]',
                "  end",
                '  subgraph team__0["team · app.teams"]',
                '    team__member["member"]:::rel',
                "  end",
                '  subgraph folder__0["folder · app.folders"]',
                '    folder__parent["parent"]:::rel',
                '    folder__owner["owner"]:::rel',
                '    folder__view(["view"]):::perm',
                "  end",
                '  subgraph doc__0["doc · app.docs"]',
                '    doc__folder["folder"]:::rel',
                '    doc__viewer["viewer"]:::rel',
                '    doc__view(["view"]):::perm',
                "  end",
                '  team__member -->|"app.team_members"| user',
                '  folder__parent -->|"parent_id"| folder__0',
                '  folder__owner -->|"owner_id"| user',
                "  folder__view --> folder__owner",
                '  folder__view ==>|"parent"| folder__view',
                '  doc__folder -->|"folder_id"| folder__0',
                '  doc__viewer -.->|"shared"| user',
                '  doc__viewer -.->|"shared"| team__member',
                '  doc__viewer -.->|"shared (every service)"| service__0',
                "  doc__view --> doc__viewer",
                '  doc__view ==>|"folder"| folder__view',
                "",
            ],
        )

    def test_a_condition_on_what_is_inherited_is_drawn(self) -> None:
        # the docs app's folders pass access down only while the folder above isn't sealed: the arrow says so
        c = Compiler(parse_policy(read(POLICIES["docs"]), None, files={}))
        c.compile("the policy")
        self.assertIn('  folder__view ==>|"parent · if {…}"| folder__view', c.graph().split("\n"))


class AgentsNote(unittest.TestCase):
    """rowstile init's note for the app's coding agent: written, added to a file that is there, never twice."""

    def test_written_added_and_kept(self) -> None:
        import init

        note = init.agents_note("db/policy.authz", "db/tests/*.authz", "tracker_app")
        self.assertTrue(note.startswith(init.BEGIN + "\n") and note.endswith(init.END + "\n"))
        for said in ("`db/policy.authz`", "`db/tests/*.authz`", "`rowstile.toml`", "connects as `tracker_app`"):
            self.assertIn(said, note)
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "AGENTS.md")
            self.assertEqual(init.write_agents_note(note, d), "wrote")
            with open(path, encoding="utf-8", newline="") as fh:
                self.assertEqual(fh.read(), note)
            self.assertIsNone(init.write_agents_note(note, d), "run twice, it changes nothing")
            for before, after in (
                ("# My app\n\nRun the tests with make.\n", "# My app\n\nRun the tests with make.\n\n" + note),
                ("# My app", "# My app\n\n" + note),
                ("", note),
                ("# My app\r\n", "# My app\r\n\r\n" + note.replace("\n", "\r\n")),
            ):
                with open(path, "w", encoding="utf-8", newline="") as fh:
                    fh.write(before)
                self.assertEqual(init.write_agents_note(note, d), "added")
                with open(path, encoding="utf-8", newline="") as fh:
                    self.assertEqual(fh.read(), after)
                self.assertIsNone(init.write_agents_note(note, d))
            # a section someone changed is theirs: the markers are enough
            with open(path, "w", encoding="utf-8", newline="") as fh:
                fh.write(f"# My app\n{init.BEGIN}\nours\n{init.END}\n")
            self.assertIsNone(init.write_agents_note(note, d))

    def test_it_names_commands_the_reference_has(self) -> None:
        """The commands the note names are in the reference's table, and its link is the site's llms.txt."""
        import init

        note = init.agents_note("db/policy.authz", "db/tests/*.authz", "app_user")
        with open(os.path.join(os.path.dirname(ROOT), "docs", "reference", "tools.md"), encoding="utf-8") as fh:
            tools = fh.read()
        named = set(re.findall(r"`rowstile (\w+)", note))
        self.assertEqual(named, {"check", "push", "test", "dev", "help", "migrate", "why", "mcp"})
        for command in named:
            self.assertIn(f"| `rowstile {command}", tools, f"docs/reference/tools.md has no rowstile {command}")
        self.assertIn("https://rowstile.dev/llms.txt", note)
        self.assertLessEqual(max(len(line) for line in note.split("\n")), 112)


class Draft(unittest.TestCase):
    """rowstile init: the first policy, from tables whose names are not the tidy ones (tests/devx.sh applies one)."""

    @staticmethod
    def table(
        name: str,
        columns: dict[str, str],
        pk: list[str],
        fks: tuple[tuple[list[str], str, list[str]], ...] = (),
        uniques: list[list[str]] | None = None,
    ) -> draft.Table:
        return {
            "name": name,
            "columns": list(columns.items()),
            "pk": pk,
            "fks": [{"cols": c, "ref": r, "ref_cols": rc} for c, r, rc in fks],
            "uniques": uniques or [],
        }

    def compiled(self, tables: list[draft.Table]) -> str:
        text = draft.draft(tables, schemas=("app",))
        Compiler(parse_policy(text, None, files={})).compile("the policy")  # what the guide promises: it compiles
        return text

    def test_plurals_names_and_what_is_left_out(self) -> None:
        # what init meets in a real schema: plurals in -xes, -sses, -ches; a name SQL reserves; two tables of one
        # name in two schemas; and a table it can't name, one without a key, one keyed by a type it can't use, each
        # left out with why. What it writes compiles
        text = draft.draft(
            [
                self.table("app.users", {"id": "bigint"}, ["id"]),
                self.table("app.boxes", {"id": "bigint"}, ["id"]),
                self.table("app.classes", {"id": "bigint"}, ["id"]),
                self.table("app.matches", {"id": "bigint"}, ["id"]),
                self.table("app.order", {"id": "bigint"}, ["id"]),
                self.table("other.boxes", {"id": "bigint"}, ["id"]),
                self.table("app.user-data", {"id": "bigint"}, ["id"]),
                self.table("app.logs", {"line": "text"}, []),
                self.table("app.blobs", {"k": "jsonb"}, ["k"]),
            ],
            schemas=("app", "other"),
        )
        Compiler(parse_policy(text, None, files={})).compile("the policy")
        for line in ("box = app.boxes", "box2 = other.boxes", "class = app.classes", "match = app.matches"):
            self.assertIn(f"\ntype {line}\n", text)
        self.assertIn("\ntype order = app.order\n", text)
        self.assertIn("-- app.user-data: a name the policy language can't write", text)
        self.assertIn("-- app.logs: no primary key (rowstile needs one to name its rows)", text)
        self.assertIn("-- app.blobs: its key's type isn't one rowstile can use", text)

    def test_finding_the_user_table(self) -> None:
        # by its name, or else by what refers to it (an author_id, an owner_id, ...); a users table keyed by two
        # columns is named with what it lacks; nothing to go by, or a --users table that isn't there: asked
        accounts = self.table("app.accounts", {"id": "bigint"}, ["id"])
        posts = self.table(
            "app.posts", {"id": "bigint", "author_id": "bigint"}, ["id"], ((["author_id"], "app.accounts", ["id"]),)
        )
        self.assertIn("\ntype user = app.accounts\n", draft.draft([accounts, posts], schemas=("app",)))
        wide = self.table("app.users", {"org": "bigint", "id": "bigint"}, ["org", "id"])
        with self.assertRaisesRegex(
            draft.DraftError, r"^app\.users: the user table needs a key of one column.* \[AZ622\]$"
        ):
            draft.draft([wide], schemas=("app",))
        with self.assertRaisesRegex(draft.DraftError, r"^which table holds your users\?.* \[AZ621\]$"):
            draft.draft([self.table("app.things", {"id": "bigint"}, ["id"])], schemas=("app",))
        with self.assertRaisesRegex(
            draft.DraftError, r"^app\.nosuch: no such table with a primary key in app \[AZ621\]$"
        ):
            draft.draft([accounts, posts], users="app.nosuch", schemas=("app",))

    def test_a_user_table_the_draft_leaves_out_is_said(self) -> None:
        """The keys that name users point to a table outside the draft (Supabase's auth.users, with --schema public),
        or to one it leaves out: the command said KeyError."""
        posts = lambda ref: self.table(
            "public.posts", {"id": "bigint", "user_id": "uuid"}, ["id"], ((["user_id"], ref, ["id"]),)
        )
        with self.assertRaises(draft.DraftError) as e:
            draft.draft([posts("auth.users")], schemas=("public",))
        self.assertEqual(
            str(e.exception),
            "auth.users: public.posts.user_id points to it, and it isn't in public: draft its schema too (--schema "
            "public,auth), or name the table that holds your users: rowstile init --users schema.table [AZ621]",
        )
        odd = self.table("public.Benutzer-2", {"id": "uuid"}, ["id"])
        with self.assertRaises(draft.DraftError) as e:
            draft.draft([odd, posts("public.Benutzer-2")], schemas=("public",))
        self.assertEqual(
            str(e.exception),
            "public.Benutzer-2: public.posts.user_id points to it, and the draft leaves it out: a name the policy "
            "language can't write (letters, digits and _ only): give it a view with a plain name, and name the "
            "view. Name the table that holds your users with rowstile init --users schema.table [AZ621]",
        )

    def test_the_first_row_of_a_tree_can_be_made(self) -> None:
        # folders inside folders: "inside one you edit" alone lets nobody make the first folder through the app, so
        # the drafted rule also lets a row with nothing above it be made, in the maker's own name. The column is
        # written as SQL reads it (a capital needs its quotes), the relation by its name
        tree = lambda parent, owner: self.compiled(
            [
                self.table("app.users", {"id": "bigint"}, ["id"]),
                self.table(
                    "app.folders",
                    {"id": "bigint", parent: "bigint", owner: "bigint"},
                    ["id"],
                    (([parent], "app.folders", ["id"]), ([owner], "app.users", ["id"])),
                ),
            ]
        )
        self.assertIn(
            "  insert : owner and (parent.edit or {parent_id is null})   -- decide", tree("parent_id", "owner_id")
        )
        self.assertIn(
            '  insert : owner and (parent.edit or {"parentId" is null})   -- decide', tree("parentId", "ownerId")
        )

    def test_your_own_row_and_a_link_table_named_in_one_word(self) -> None:
        # a user's own row is drafted as the reference says to write it, a relation from the key; and a link
        # table's relation leaves the type's name out whichever way the table is spelled
        users = lambda pk: self.table("app.User", {pk: "integer"}, [pk])
        links = lambda name: self.table(
            name,
            {"teamId": "integer", "userId": "integer"},
            ["teamId", "userId"],
            ((["teamId"], "app.Team", ["id"]), (["userId"], "app.User", ["id"])),
        )
        team = self.table("app.Team", {"id": "integer"}, ["id"])
        text = self.compiled([users("id"), team, links("app.TeamMember")])
        self.assertIn("  self : user = id  -- your own row\n  can edit = self\n", text)
        self.assertNotIn("authz.uid()", text)
        self.assertIn("  member : user = app.TeamMember(teamId -> userId)\n", text)
        self.assertIn(
            "  member : user = app.team_members(teamId -> userId)\n",
            self.compiled([users("id"), team, links("app.team_members")]),
        )
        # a key under another name, and a column of the user's own that would be called self too
        boss = self.table(
            "app.User", {"userId": "integer", "selfId": "integer"}, ["userId"], ((["selfId"], "app.User", ["userId"]),)
        )
        text = self.compiled([boss])
        self.assertIn("  self2 : user = userId  -- your own row\n  self : user = selfId\n", text)
        self.assertIn("  can edit = self2 or self\n", text)

    def test_names_the_language_or_sql_reads_another_way(self) -> None:
        users = self.table("app.users", {"id": "bigint"}, ["id"])
        to_user = lambda col: ([col], "app.users", ["id"])
        text = self.compiled(
            [
                self.table("app.User", {"id": "integer"}, ["id"]),
                self.table(
                    "app.Post",
                    {"id": "integer", "authorId": "integer", "order": "integer"},
                    ["id"],
                    ((["authorId"], "app.User", ["id"]), (["order"], "app.User", ["id"])),
                ),
                self.table("app._prisma_migrations", {"id": "character varying(36)"}, ["id"]),
            ]
        )
        self.assertIn("  author : user = authorId\n", text)
        self.assertIn("  insert : author\n", text)  # the relation, not its column once more
        self.assertIn("app._prisma_migrations: the migration tool's own table", text)
        self.assertNotIn("type _prisma_migration", text)
        # a column named like a word of the language, a link table and a column named like a permission
        text = self.compiled(
            [
                users,
                self.table(
                    "app.docs",
                    {"id": "bigint", "if": "bigint", "after": "bigint", "view_id": "bigint"},
                    ["id"],
                    (to_user("if"), to_user("after"), to_user("view_id")),
                ),
                self.table(
                    "app.doc_edits",
                    {"doc_id": "bigint", "user_id": "bigint"},
                    ["doc_id", "user_id"],
                    ((["doc_id"], "app.docs", ["id"]), to_user("user_id")),
                ),
            ]
        )
        self.assertIn("  viewer : user = view_id\n", text)
        self.assertIn("  editor : user = app.doc_edits(doc_id -> user_id)\n", text)
        self.assertIn("-- left out: if (to app.users)", text)
        # names the language can't write, and a link through a unique column that isn't the key
        text = self.compiled(
            [
                users,
                self.table("app.teams", {"id": "bigint", "slug": "text"}, ["id"]),
                self.table(
                    "app.team_members",
                    {"team_slug": "text", "user_id": "bigint"},
                    ["team_slug", "user_id"],
                    ((["team_slug"], "app.teams", ["slug"]), to_user("user_id")),
                ),
                self.table("app.owner list", {"id": "bigint"}, ["id"]),
                self.table("app.docs", {"id": "bigint", "owner id": "bigint"}, ["id"], (to_user("owner id"),)),
            ]
        )
        self.assertNotIn("app.team_members(team_slug", text)
        self.assertIn("-- app.owner list: a name the policy language can't write", text)
        self.assertIn("-- left out: owner id (to app.users)", text)

    def test_the_user_table_is_users_before_accounts(self) -> None:
        """Chatwoot's accounts (its tenants) and GitLab's members (a link table) were taken over their users."""
        to_user = lambda col: ([col], "app.users", ["id"])
        text = self.compiled(
            [
                self.table("app.accounts", {"id": "bigint"}, ["id"]),
                self.table(
                    "app.members",
                    {"id": "bigint", "user_id": "bigint", "account_id": "bigint"},
                    ["id"],
                    (to_user("user_id"), (["account_id"], "app.accounts", ["id"])),
                ),
                self.table("app.users", {"id": "bigint"}, ["id"]),
            ]
        )
        self.assertIn("type user = app.users\n", text)
        text = self.compiled(
            [self.table("app.User", {"id": "integer"}, ["id"]), self.table("app.accounts", {"id": "bigint"}, ["id"])]
        )
        self.assertIn("type user = app.User (id int)\n", text)  # Prisma's model User, before accounts

    def test_a_foreign_key_declared_twice_is_one_relation(self) -> None:
        """GitLab's project_saved_replies: the same key twice gave two relations and two `after` rules (AZ109)."""
        fk = (["project_id"], "app.projects", ["id"])
        text = self.compiled(
            [
                self.table("app.users", {"id": "bigint"}, ["id"]),
                self.table(
                    "app.projects",
                    {"id": "bigint", "owner_id": "bigint"},
                    ["id"],
                    ((["owner_id"], "app.users", ["id"]),),
                ),
                self.table("app.replies", {"id": "bigint", "project_id": "bigint"}, ["id"], (fk, fk)),
            ]
        )
        self.assertEqual(text.count("update project_id after"), 1)
        self.assertNotIn("project2", text)

    def test_the_whole_draft(self) -> None:
        # what init writes, line by line: the user's own row and the team it is in (no rule to change who it is in:
        # accounts change outside the app role, the team's edit decides), pies as one pie, and a profile keyed by
        # its user: the relation inside the key comes first, before the team, though its column comes after
        to = lambda col, table: ([col], table, ["id"])
        text = self.compiled(
            [
                self.table("app.users", {"id": "bigint", "team_id": "bigint"}, ["id"], (to("team_id", "app.teams"),)),
                self.table("app.teams", {"id": "bigint"}, ["id"]),
                self.table("app.pies", {"id": "bigint", "owner_id": "bigint"}, ["id"], (to("owner_id", "app.users"),)),
                self.table(
                    "app.profiles",
                    {"team_id": "bigint", "user_id": "bigint"},
                    ["user_id"],
                    (to("team_id", "app.teams"), to("user_id", "app.users")),
                ),
            ]
        )
        self.assertEqual(
            text.split("\n"),
            [
                "-- A first policy drafted by rowstile from the tables in app.",
                "-- It compiles, and it is a draft: read every '-- decide:' and change what isn't so.",
                "-- Then: rowstile dev (applies it on each save, runs the tests, writes the clients).",
                "",
                "app role app_user                          -- decide: the Postgres role your app connects as",
                "",
                "type user = app.users",
                "  self : user = id  -- your own row",
                "  team : team = team_id",
                "  can edit = self or team.edit",
                "  can view = signed_in                  -- decide: may everyone signed in see everyone?",
                "",
                "type pie = app.pies",
                "  owner : user = owner_id",
                "  can edit = owner",
                "  can view = edit",
                "",
                "type profile = app.profiles (user_id)",
                "  person : user = user_id",
                "  team : team = team_id",
                "  can edit = person   -- decide: owners, and whoever edits what it is in",
                "  can view = person or team.view",
                "",
                "type team = app.teams",
                "  can edit = nobody                      -- decide: nobody changes these through the app",
                "  can view = signed_in                  -- decide: a list everyone signed in may read?",
                "",
                "rules app.users",
                "  select : view",
                "  update : edit",
                "  -- no insert or delete rule: accounts are made and removed outside the app role",
                "  update team_id after : team.edit",
                "",
                "rules app.pies",
                "  select : view",
                "  insert : owner",
                "  update : edit",
                "  delete : edit",
                "  update owner_id : edit   -- decide: who may change who owns it, or where it is",
                "",
                "rules app.profiles",
                "  select : view",
                "  insert : team.edit and person   -- decide: who may add one",
                "  update : edit",
                "  delete : edit",
                "  update user_id, team_id : edit   -- decide: who may change who owns it, or where it is",
                "  update team_id after : team.edit",
                "",
                "rules app.teams",
                "  select : view",
                "  insert : signed_in   -- decide: who may add one",
                "  update : edit",
                "  delete : edit",
                "",
            ],
        )
        # a link table named for its type and nothing more (team_): the relation keeps the whole name
        text = self.compiled(
            [
                self.table("app.users", {"id": "bigint"}, ["id"]),
                self.table("app.teams", {"id": "bigint"}, ["id"]),
                self.table(
                    "app.team_",
                    {"team_id": "bigint", "user_id": "bigint"},
                    ["team_id", "user_id"],
                    (to("team_id", "app.teams"), to("user_id", "app.users")),
                ),
            ]
        )
        self.assertIn("\ntype team = app.teams\n  team_ : user = app.team_(team_id -> user_id)\n", text)

    def test_teams_inside_teams(self) -> None:
        # a team with members and a parent team: the members of the teams inside count as members above (what the
        # cookbook's nested teams do, and what an app usually means), and the draft says the other reading. A folder
        # with members and a parent folder still passes its view down
        to = lambda col, table: ([col], table, ["id"])
        tables = [self.table("app.users", {"id": "bigint"}, ["id"])]
        for kind in ("teams", "folders"):
            tables += [
                self.table(
                    f"app.{kind}", {"id": "bigint", "parent_id": "bigint"}, ["id"], (to("parent_id", f"app.{kind}"),)
                ),
                self.table(
                    f"app.{kind[:-1]}_members",
                    {f"{kind[:-1]}_id": "bigint", "user_id": "bigint"},
                    [f"{kind[:-1]}_id", "user_id"],
                    (to(f"{kind[:-1]}_id", f"app.{kind}"), to("user_id", "app.users")),
                ),
            ]
        text = self.compiled(tables)
        self.assertIn(
            "\ntype team = app.teams\n"
            "  parent : team = parent_id\n"
            "  member : user = app.team_members(team_id -> user_id)\n"
            "  member : team#member = app.teams(parent_id -> id)   -- the members of the teams inside count here too\n"
            "  -- decide: members of the teams inside are members of this one. For this team's view to pass\n"
            "  --   down to those inside instead: remove that line, and write can view = member or parent.view\n"
            "  can edit = nobody   -- decide: nobody edits what it is in; who edits these?\n"
            "  can view = member\n",
            text,
        )
        self.assertIn("  member : user = app.folder_members(folder_id -> user_id)\n", text)
        self.assertIn("  can view = member or parent.view\n", text)
        self.assertNotIn("folder#member", text)

    def test_a_loop_of_foreign_keys_with_an_owner_compiles(self) -> None:
        """Documenso, Cal.com, Mastodon and GitLab: org -> settings -> email -> domain -> org; only orgs have owners."""
        to = lambda col, table: ([col], table, ["id"])
        text = self.compiled(
            [
                self.table("app.users", {"id": "bigint"}, ["id"]),
                self.table(
                    "app.orgs",
                    {"id": "bigint", "owner_id": "bigint", "settings_id": "bigint"},
                    ["id"],
                    (to("owner_id", "app.users"), to("settings_id", "app.settings")),
                ),
                self.table(
                    "app.settings", {"id": "bigint", "email_id": "bigint"}, ["id"], (to("email_id", "app.emails"),)
                ),
                self.table(
                    "app.emails", {"id": "bigint", "domain_id": "bigint"}, ["id"], (to("domain_id", "app.domains"),)
                ),
                self.table("app.domains", {"id": "bigint", "org_id": "bigint"}, ["id"], (to("org_id", "app.orgs"),)),
            ]
        )
        self.assertIn("type domain = app.domains\n  org : org = org_id\n  can edit = org.edit", text)
        # the same loop with no owner anywhere in it (Cal.com's, Mastodon's, GitLab's): inheriting round it gives
        # nobody anything, so the draft doesn't write it, and says why
        text = self.compiled(
            [
                self.table("app.users", {"id": "bigint"}, ["id"]),
                self.table(
                    "app.orgs", {"id": "bigint", "settings_id": "bigint"}, ["id"], (to("settings_id", "app.settings"),)
                ),
                self.table("app.settings", {"id": "bigint", "org_id": "bigint"}, ["id"], (to("org_id", "app.orgs"),)),
            ]
        )
        self.assertIn(
            "type org = app.orgs\n  settings : setting = settings_id\n  can edit = nobody   -- decide: the loop "
            "of foreign keys it is in has no owner anywhere; who edits these?\n  can view = signed_in",
            text,
        )

    def test_a_membership_with_an_id_of_its_own_is_a_link(self) -> None:
        """Plausible's site_memberships (id, site_id, user_id, role): read as a type, so a site was everyone's."""
        to_user = lambda col: ([col], "app.users", ["id"])
        users = self.table("app.users", {"id": "bigint"}, ["id"])
        sites = self.table("app.sites", {"id": "bigint", "domain": "text"}, ["id"])
        member = lambda extra, uniques: self.table(
            "app.site_memberships",
            {"id": "bigint", "site_id": "bigint", "user_id": "bigint", **extra},
            ["id"],
            ((["site_id"], "app.sites", ["id"]), to_user("user_id")),
            uniques,
        )
        link = "  membership : user = app.site_memberships(site_id -> user_id)\n"
        for extra, uniques in (
            ({"role": "text", "inserted_at": "timestamp"}, []),  # a role and timestamps only
            ({"note": "text"}, [["site_id", "user_id"]]),
        ):  # anything, with the pair unique
            text = self.compiled([users, sites, member(extra, uniques)])
            self.assertIn(link, text)
            self.assertIn("-- decide: app.site_memberships is read as a membership", text)
            self.assertIn("  can view = edit or membership\n", text)
        # something else about a user and a site is not a membership: a note and no unique pair, or no role
        for extra in ({"note": "text"}, {}, {"inserted_at": "timestamp"}):
            self.assertNotIn(link, self.compiled([users, sites, member(extra, [])]))
        # each column that makes it a membership may say who does more, and the draft says so (`permission` too)
        for col in draft.ROLE_COLUMNS:
            text = self.compiled([users, sites, member({col: "text"}, [])])
            self.assertIn(link, text)
            self.assertIn(
                f"  -- decide: app.site_memberships.{col} may say who does more, e.g.\n  --   admin : user = "
                f"app.site_memberships(site_id -> user_id) where {{{col} = 'admin'}}\n",
                text,
            )

    def test_view_names_each_parent_once(self) -> None:
        """`view = edit or parent.view` with `edit = ... or parent.edit` named each parent twice per level: lint's
        warning on six of nine apps' drafts."""
        to = lambda col, table: ([col], table, ["id"])
        text = self.compiled(
            [
                self.table("app.users", {"id": "bigint"}, ["id"]),
                self.table("app.sites", {"id": "bigint", "owner_id": "bigint"}, ["id"], (to("owner_id", "app.users"),)),
                self.table(
                    "app.goals",
                    {"id": "bigint", "site_id": "bigint", "creator_id": "bigint"},
                    ["id"],
                    (to("site_id", "app.sites"), to("creator_id", "app.users")),
                ),
            ]
        )
        self.assertIn("  can edit = creator or site.edit   -- decide: owners", text)
        self.assertIn("  can view = creator or site.view\n", text)

    def test_the_user_table_named_or_found_by_what_refers_to_it(self) -> None:
        # --users names it; with none of the usual names, it is the table most foreign keys of people point at
        # (owner_id, author_id, ...); a --users table keyed by two columns is said, as one found by its name is
        to = lambda col, table: ([col], table, ["id"])
        customers = self.table("app.customers", {"id": "bigint"}, ["id"])
        staff = self.table("app.staff", {"id": "bigint"}, ["id"])
        notes = self.table(
            "app.notes",
            {"id": "bigint", "author_id": "bigint", "owner_id": "bigint", "editor_id": "bigint"},
            ["id"],
            (to("author_id", "app.customers"), to("owner_id", "app.customers"), to("editor_id", "app.staff")),
        )
        self.assertIn("\ntype user = app.customers\n", self.compiled([customers, staff, notes]))
        self.assertIn(
            "\ntype user = app.staff\n", draft.draft([customers, staff, notes], "app.staff", schemas=("app",))
        )
        wide = self.table("app.accounts", {"org": "bigint", "id": "bigint"}, ["org", "id"])
        with self.assertRaisesRegex(
            draft.DraftError, r"^app\.accounts: the user table needs a key of one column \[AZ622\]$"
        ):
            draft.draft([wide, customers], "app.accounts", schemas=("app",))
        refs = self.table("app.docs", {"id": "bigint", "owner_id": "bigint"}, ["id"], (to("owner_id", "app.accounts"),))
        with self.assertRaisesRegex(
            draft.DraftError, r"^app\.accounts: the user table needs a key of one column \[AZ622\]$"
        ):
            draft.draft([wide, refs], schemas=("app",))

    def test_names_a_type_cannot_have_and_a_key_it_cannot_write(self) -> None:
        # a table named like a word of the language is a type of another name (and a users table that isn't the
        # user table is too, with --users naming another); one whose key's column the language can't write is
        # left out, with why
        text = draft.draft(
            [
                self.table("app.accounts", {"id": "bigint"}, ["id"]),
                self.table("app.tests", {"id": "bigint"}, ["id"]),
                self.table("app.users", {"id": "bigint"}, ["id"]),
                self.table("app.s", {"id": "bigint"}, ["id"]),
                self.table("app.things", {"thing id": "bigint"}, ["thing id"]),
            ],
            "app.accounts",
            schemas=("app",),
        )
        Compiler(parse_policy(text, None, files={})).compile("the policy")
        for line in ("user = app.accounts", "test_row = app.tests", "user_row = app.users", "t_ = app.s"):
            self.assertIn(f"\ntype {line}\n", text)
        self.assertIn("-- app.things: its key has a column name the policy language can't write (thing id)", text)

    def test_what_nobody_edits_above_a_type_is_said_as_it_is(self) -> None:
        # products in categories nobody changes through the app: nobody edits what a product is in, and there is
        # no loop of foreign keys to look for (categories in categories are a tree, not a loop); a link table
        # named for neither of its sides keeps its own name
        to = lambda col, table: ([col], table, ["id"])
        text = self.compiled(
            [
                self.table("app.users", {"id": "bigint"}, ["id"]),
                self.table(
                    "app.categories",
                    {"id": "bigint", "parent_id": "bigint"},
                    ["id"],
                    (to("parent_id", "app.categories"),),
                ),
                self.table(
                    "app.products",
                    {"id": "bigint", "category_id": "bigint"},
                    ["id"],
                    (to("category_id", "app.categories"),),
                ),
                self.table(
                    "app.memberships",
                    {"category_id": "bigint", "user_id": "bigint"},
                    ["category_id", "user_id"],
                    (to("category_id", "app.categories"), to("user_id", "app.users")),
                ),
            ]
        )
        self.assertIn(
            "type product = app.products\n  category : category = category_id\n"
            "  can edit = nobody   -- decide: nobody edits what it is in; who edits these?\n"
            "  can view = category.view\n",
            text,
        )
        self.assertIn(
            "  parent : category = parent_id\n  membership : user = app.memberships(category_id -> user_id)\n"
            "  can edit = nobody   -- decide: nobody edits what it is in; who edits these?\n",
            text,
        )

    def test_a_user_table_whose_key_it_cannot_use_is_said(self) -> None:
        with self.assertRaisesRegex(draft.DraftError, "its key is character\\(8\\).*--users.* \\[AZ622\\]$"):
            draft.draft(
                [
                    self.table("app.users", {"id": "character(8)"}, ["id"]),
                    self.table("app.docs", {"id": "bigint"}, ["id"]),
                ]
            )

    def test_where_prisma_keeps_its_migrations(self) -> None:
        import stack

        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "db"))
            with open(os.path.join(d, "package.json"), "w", encoding="utf-8") as fh:
                json.dump({"dependencies": {"@prisma/client": "7"}, "prisma": {"schema": "db/schema.prisma"}}, fh)
            with open(os.path.join(d, "db", "schema.prisma"), "w", encoding="utf-8") as fh:
                fh.write("datasource db {}\n")
            found = stack.detect(d)
            self.assertEqual((found.tool, found.migrations_dir), ("prisma", "db/migrations"))


class Wire(unittest.TestCase):
    """The command's own Postgres client (cli/pgwire.py): what a connection string says, and TLS, against a
    made-up server (the handshake only: no database)."""

    def setUp(self) -> None:
        import pgwire

        self.pgwire = pgwire
        self.env = {k: os.environ.pop(k) for k in list(os.environ) if k.startswith("PG")}
        # libpq's folder (root.crt, root.crl) is in HOME, or APPDATA on Windows: an empty one, the test's own
        self.home = tempfile.TemporaryDirectory()
        self.homes = mock.patch.dict(os.environ, {"HOME": self.home.name, "APPDATA": self.home.name})
        self.homes.start()
        self.folder = os.path.join(self.home.name, "postgresql" if sys.platform == "win32" else ".postgresql")

    def tearDown(self) -> None:
        self.homes.stop()
        self.home.cleanup()
        os.environ.update(self.env)

    def test_a_url_and_its_options(self) -> None:
        parse = self.pgwire.parse_dsn
        got = parse("postgresql://ann:p%23w@db.example.com:6543/app?sslmode=require&connect_timeout=3")
        self.assertEqual(
            (got["host"], got["port"], got["user"], got["password"], got["database"], got["sslmode"], got["timeout"]),
            ("db.example.com", 6543, "ann", "p#w", "app", "require", 3.0),
        )
        got = parse("postgresql:///app?host=/tmp/sock&port=5499&user=bo")  # how a URL names a socket
        self.assertEqual((got["host"], got["port"], got["user"], got["database"]), ("/tmp/sock", 5499, "bo", "app"))
        self.assertEqual(
            parse("postgresql://h/app?schema=public&pgbouncer=true")["host"], "h"
        )  # an ORM's own: left alone
        self.assertEqual(parse("host=h sslmode=verify-full sslrootcert=ca.pem")["sslrootcert"], "ca.pem")
        self.assertEqual(parse("host=h")["sslmode"], "prefer")
        # as Neon's dashboard gives it
        got = parse("postgresql://o:p@ep.example.tech/db?sslmode=require&channel_binding=require")
        self.assertEqual((got["sslmode"], got["channel_binding"]), ("require", "require"))
        self.assertEqual(parse("host=h")["channel_binding"], "prefer")
        os.environ["PGSSLMODE"] = "require"
        self.assertEqual(parse("host=h")["sslmode"], "require")
        del os.environ["PGSSLMODE"]
        # a keyword string as libpq reads it (psql given the same string reaches the same database as the same
        # user): spaces around =, a value in single quotes, \' and \\ in a value, and a " as it is
        got = parse("host = h dbname='my db' user=it\\'s password='a\\\\b\\'c\"d'")
        self.assertEqual(
            (got["host"], got["database"], got["user"], got["password"]), ("h", "my db", "it's", "a\\b'c\"d")
        )
        self.assertEqual(parse("host=h password='it\\'s'")["password"], "it's")  # as the message below shows it
        # a URL's query decoded as libpq decodes it: %XX, and nothing else; a + is a + (a web form's space isn't)
        got = parse("postgresql://me@h/?dbname=a+b&password=x+y%2Bz&options=-c%20search_path%3Da+b&sslmode=require")
        self.assertEqual(
            (got["database"], got["password"], got["options"], got["sslmode"]),
            ("a+b", "x+y+z", "-c search_path=a+b", "require"),
        )
        got = parse("postgresql://h/app?&sslmode=require&&port=5499&")  # an empty part is nothing, as libpq has it
        self.assertEqual((got["sslmode"], got["port"]), ("require", 5499))

    def test_a_urls_ssl_option_as_libpq_reads_it(self) -> None:
        # libpq reads ssl=true in a URL's query as sslmode=require (JDBC's way to ask for TLS), in its place among
        # the others: the one written last wins. Left out, it was prefer, which goes on without TLS when the server
        # (or what is between) says it has none
        parse = self.pgwire.parse_dsn
        self.assertEqual(parse("postgresql://h/app?ssl=true")["sslmode"], "require")
        self.assertEqual(parse("postgresql://h/app?ssl=%74rue")["sslmode"], "require")  # decoded first
        self.assertEqual(parse("postgresql://h/app?sslmode=verify-full&ssl=true")["sslmode"], "require")
        self.assertEqual(parse("postgresql://h/app?ssl=true&sslmode=verify-full")["sslmode"], "verify-full")
        os.environ["PGSSLMODE"] = "disable"  # a variable comes after what the URL says
        self.assertEqual(parse("postgresql://h/app?ssl=true")["sslmode"], "require")
        del os.environ["PGSSLMODE"]
        # any other value is no setting libpq has: refused, in its words (ssl=false isn't sslmode=disable)
        for value in ("false", "True", "1", ""):
            with self.assertRaisesRegex(
                ValueError,
                '^invalid URI query parameter: "ssl" .*: libpq reads only ssl=true .*say sslmode= instead',
                msg=value,
            ):
                parse(f"postgresql://h/app?ssl={value}")
        # a keyword string has no ssl setting, in libpq or here
        with self.assertRaisesRegex(ValueError, "unknown connection setting 'ssl'"):
            parse("host=h ssl=true")

    def test_what_it_cannot_honour_is_refused_not_dropped(self) -> None:
        for dsn, said in (
            ("postgresql://h/app?sslmode=maybe", "sslmode=maybe"),
            ("postgresql://h/app?sslcert=client.crt", "client certificates"),
            ("postgresql://h/app?channel_binding=maybe", "channel_binding=maybe"),
            ("host=h colour=blue", "unknown connection setting 'colour'"),
            ("postgresql://u:pa#ss@h/app", "must be written %23"),
            ("host=h port=abc", "the port is a number from 1 to 65535, not 'abc'"),
            # SQL's doubled quote isn't libpq's (psql refuses it too): it was read as "its"; what follows the password
            # is likely the rest of it, and isn't repeated
            ("host=h password='it''s'", "after its password (not repeated here): put a value with spaces in single"),
            ("host=h password=my secret", "can't read the connection string after its password (not repeated here)"),
            ("host=h dbname=my db", '"db" has no "=" after it: put a value with spaces in single quotes'),
            ("host=h password='secret", "a quote isn't closed"),
            # libpq tries each host in turn; this client connects to one, and says so rather than looking up "h1,h2"
            ("host=h1,h2 dbname=app", "the connection asks for several hosts (h1,h2), which the rowstile command"),
            ("postgresql://u@h1:5432,h2:5432/app", "several hosts (h1:5432,h2:5432)"),
        ):
            with self.assertRaisesRegex(ValueError, re.escape(said), msg=dsn) as caught:
                self.pgwire.parse_dsn(dsn)
            self.assertNotIn("secret", str(caught.exception), dsn)

    def server(
        self,
        tls: bool,
        scram: str | None = None,
        auth: str | None = None,
        certificate: str = "wire_test.crt",
        params: dict[str, str] | None = None,
        answer: tuple[str, int] | None = None,
        tls_cap: bool = False,
        address: str = "127.0.0.1",
    ) -> tuple[int, dict[str, object]]:
        """A made-up server on a local port: answers the TLS request (yes with the test certificate, or no), reads
        the start-up message, says the client is signed in. seen: whether TLS was used, and the start-up parameters.
        scram: it asks for the password "secret" with SCRAM first, offering channel binding as Postgres does, over
        TLS only ("plus"; "plus anyway": without TLS too), not offering it ("plain"), or holding another certificate
        than the one the client sees ("other": a server in the middle); or it answers with a nonce that isn't the
        client's ("badnonce"), or a proof that is wrong ("badproof"). seen then has the mechanism the client chose
        and whether it bound the exchange to the certificate. auth: it asks for the password in clear ("cleartext")
        or hashed with MD5 ("md5"), and seen has what the client sent; or it asks in a way the client doesn't know
        ("gss"), offers SASL without SCRAM-SHA-256 ("sasl-other"), or answers the TLS request as no Postgres does
        ("not postgres"). seen["sent"]: what the client sent in answer to the first request for the password (or,
        signed in unasked, until it went), byte for byte. certificate: the one it holds (with the test key), tls_cap:
        it goes no further than TLSv1.2, seen["version"]: the TLS version agreed. params: what it says as the
        session starts; answer: what it answers (a text, and its type) to one statement the client then sends,
        whose text is seen["query"]. address: where it listens (127.0.0.2: a name its certificates don't have)."""
        import base64
        import hashlib
        import hmac
        import socket
        import ssl
        import struct
        import threading

        fixtures = os.path.join(ROOT, "tests", "fixtures")
        listener = socket.socket()
        listener.bind((address, 0))
        listener.listen(1)
        seen: dict[str, object] = {"tls": False, "asked": False}

        def exactly(conn: socket.socket, n: int) -> bytes:
            data = b""
            while len(data) < n:
                chunk = conn.recv(n - len(data))
                if not chunk:
                    raise ConnectionError("closed")
                data += chunk
            return data

        def received(conn: socket.socket, n: int) -> bytes:
            """Up to n bytes: what came before the client stopped sending."""
            data = b""
            while len(data) < n:
                try:
                    chunk = conn.recv(n - len(data))
                except OSError:
                    break
                if not chunk:
                    break
                data += chunk
            return data

        def said(kind: bytes, body: bytes = b"") -> bytes:
            return kind + struct.pack("!i", 4 + len(body)) + body

        def sasl(conn: socket.socket) -> bool:
            salt, rounds = b"0123456789abcdef", 4096
            plus = scram == "plus anyway" or (tls and scram != "plain")
            mechs = (b"SCRAM-SHA-256-PLUS\0" if plus else b"") + b"SCRAM-SHA-256\0\0"
            conn.sendall(b"R" + struct.pack("!ii", 8 + len(mechs), 10) + mechs)
            head = received(conn, 5)
            seen["sent"] = head
            if len(head) < 5:
                return False
            body = exactly(conn, struct.unpack("!i", head[1:])[0] - 4)
            mechanism, rest = body.split(b"\0", 1)
            first = rest[4:].decode()
            header, bare = first[: first.index(",,") + 2], first[first.index(",,") + 2 :]
            seen["mechanism"], seen["header"] = mechanism.decode(), header
            theirs = dict(kv.split("=", 1) for kv in bare.split(","))["r"]
            nonce = ("someone else's" if scram == "badnonce" else theirs) + "server"
            server_first = f"r={nonce},s={base64.b64encode(salt).decode()},i={rounds}"
            conn.sendall(b"R" + struct.pack("!ii", 8 + len(server_first), 11) + server_first.encode())
            final = exactly(conn, struct.unpack("!i", exactly(conn, 5)[1:])[0] - 4).decode()
            attrs = dict(kv.split("=", 1) for kv in final.split(","))
            with open(os.path.join(fixtures, certificate), encoding="ascii") as fh:
                held = ssl.PEM_cert_to_DER_cert(fh.read())
            if scram == "other":
                held += b"another"
            bound = hashlib.sha256(held).digest() if header.startswith("p=") else b""
            salted = hashlib.pbkdf2_hmac("sha256", b"secret", salt, rounds)
            stored = hashlib.sha256(hmac.new(salted, b"Client Key", hashlib.sha256).digest()).digest()
            message = f"{bare},{server_first},{final[: final.rindex(',p=')]}".encode()
            signature = hmac.new(stored, message, hashlib.sha256).digest()
            key = bytes(a ^ b for a, b in zip(base64.b64decode(attrs["p"]), signature, strict=True))
            seen["bound"] = header.startswith("p=") and attrs["c"] == base64.b64encode(header.encode() + bound).decode()
            if (
                hashlib.sha256(key).digest() != stored
                or attrs["c"] != base64.b64encode(header.encode() + bound).decode()
            ):
                refused = b"SFATAL\0C28P01\0Mpassword authentication failed\0\0"
                conn.sendall(b"E" + struct.pack("!i", 4 + len(refused)) + refused)
                return False
            proof = hmac.new(hmac.new(salted, b"Server Key", hashlib.sha256).digest(), message, hashlib.sha256).digest()
            last = b"v=" + base64.b64encode(bytes(32) if scram == "badproof" else proof)
            conn.sendall(b"R" + struct.pack("!ii", 8 + len(last), 12) + last)
            return True

        def serve() -> None:
            conn, _ = listener.accept()
            try:
                conn.settimeout(5)
                length, code = struct.unpack("!ii", exactly(conn, 8))
                if code == 80877103:
                    seen["asked"] = True
                    if auth == "not postgres":
                        conn.sendall(b"H")  # as a web server's "HTTP/1.1 400" begins
                        return
                    conn.sendall(b"S" if tls else b"N")
                    if tls:
                        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                        context.minimum_version = ssl.TLSVersion.TLSv1_2
                        if tls_cap:
                            context.maximum_version = ssl.TLSVersion.TLSv1_2
                        context.load_cert_chain(
                            os.path.join(fixtures, certificate), os.path.join(fixtures, "wire_test.key")
                        )
                        wrapped = context.wrap_socket(conn, server_side=True)
                        seen["tls"], seen["version"], conn = True, wrapped.version(), wrapped
                    length, code = struct.unpack("!ii", exactly(conn, 8))
                seen["start"] = exactly(conn, length - 8).split(b"\0")
                if scram and not sasl(conn):
                    return
                if auth in ("cleartext", "md5"):
                    asked = struct.pack("!ii", 8, 3) if auth == "cleartext" else struct.pack("!ii", 12, 5) + b"salt"
                    conn.sendall(b"R" + asked)
                    head = received(conn, 5)
                    seen["sent"] = head
                    if len(head) < 5:
                        return
                    body = exactly(conn, struct.unpack("!i", head[1:])[0] - 4)
                    seen["sent"], seen["password"] = head + body, body[:-1].decode()
                elif auth in ("gss", "sasl-other"):
                    mechs = b"SCRAM-SHA-1\0\0"
                    asked = (
                        struct.pack("!ii", 8, 7) if auth == "gss" else struct.pack("!ii", 8 + len(mechs), 10) + mechs
                    )
                    conn.sendall(b"R" + asked)
                    return
                statuses = b"".join(
                    said(b"S", k.encode() + b"\0" + v.encode() + b"\0") for k, v in (params or {}).items()
                )
                conn.sendall(said(b"R", struct.pack("!i", 0)) + statuses + said(b"Z", b"I"))
                if answer is not None:
                    query: list[tuple[bytes, bytes]] = []
                    while not query or query[-1][0] != b"S":
                        kind = exactly(conn, 1)
                        query.append((kind, exactly(conn, struct.unpack("!i", exactly(conn, 4))[0] - 4)))
                    seen["query"] = next(body for kind, body in query if kind == b"P").split(b"\0")[1].decode()
                    value, oid = answer
                    column = said(b"T", struct.pack("!h", 1) + b"x\0" + struct.pack("!ihihih", 0, 0, oid, -1, -1, 0))
                    row = said(b"D", struct.pack("!hi", 1, len(value)) + value.encode())
                    conn.sendall(said(b"1") + said(b"2") + column + row + said(b"C", b"SELECT 1\0") + said(b"Z", b"I"))
                after = received(conn, 1 << 16)
                seen.setdefault("sent", after)
            except (OSError, ConnectionError):
                pass
            finally:
                conn.close()
                listener.close()
                finished.set()

        finished = threading.Event()
        seen["done"] = finished
        threading.Thread(target=serve, daemon=True).start()
        return listener.getsockname()[1], seen

    @staticmethod
    def sent(seen: dict[str, object]) -> object:
        """What the client sent the made-up server once asked for the password, when the server is done."""
        import threading

        done = seen["done"]
        assert isinstance(done, threading.Event)
        done.wait(5)
        return seen.get("sent")

    @staticmethod
    def started_with(seen: dict[str, object], name: bytes) -> bytes | None:
        """A start-up parameter's value as the made-up server read it (None: not sent)."""
        start = seen["start"]
        assert isinstance(start, list)
        fields = [x for x in start if isinstance(x, bytes)]
        return fields[fields.index(name) + 1] if name in fields else None

    def test_options_reach_the_server(self) -> None:
        # a connection string's options (`-c search_path=app`, or what a managed service routes by) go in the
        # start-up message as written, from a URL (encoded) or a keyword string
        for dsn in (
            "postgresql://ann@127.0.0.1:{port}/app?options=-c%20search_path%3Dapp&sslmode=disable",
            "host=127.0.0.1 port={port} user=ann dbname=app options='-c search_path=app' sslmode=disable",
        ):
            port, seen = self.server(tls=False)
            self.pgwire.connect(**self.pgwire.parse_dsn(dsn.format(port=port))).close()
            self.assertEqual(self.started_with(seen, b"options"), b"-c search_path=app", dsn)

    def test_pgoptions_as_psql_reads_it(self) -> None:
        # where the connection string gives no options, PGOPTIONS does, as libpq has it; given ones come first
        with mock.patch.dict(os.environ, {"PGOPTIONS": "-c search_path=env"}):
            port, seen = self.server(tls=False)
            self.pgwire.connect(**self.pgwire.parse_dsn(f"host=127.0.0.1 port={port} sslmode=disable")).close()
            self.assertEqual(self.started_with(seen, b"options"), b"-c search_path=env")
            dsn = f"host=127.0.0.1 port={port} options='-c search_path=app'"
            self.assertEqual(self.pgwire.parse_dsn(dsn)["options"], "-c search_path=app")

    def test_tls_as_sslmode_says(self) -> None:
        connect = self.pgwire.connect
        crt = os.path.join(ROOT, "tests", "fixtures", "wire_test.crt")
        port, seen = self.server(tls=True)
        connect(host="127.0.0.1", port=port, sslmode="require", timeout=5).close()
        self.assertTrue(seen["tls"])
        start = seen["start"]
        assert isinstance(start, list)
        self.assertIn(b"rowstile", start)  # application_name
        port, seen = self.server(tls=True)
        connect(host="127.0.0.1", port=port, timeout=5).close()  # prefer: taken when the server has it
        self.assertTrue(seen["tls"])
        port, seen = self.server(tls=False)
        connect(host="127.0.0.1", port=port, timeout=5).close()  # ... and done without when it doesn't
        self.assertEqual((seen["asked"], seen["tls"]), (True, False))
        port, seen = self.server(tls=False)
        with self.assertRaisesRegex(self.pgwire.ProtocolError, "doesn't do TLS, and sslmode=require asks for it"):
            connect(host="127.0.0.1", port=port, sslmode="require", timeout=5)
        port, seen = self.server(tls=True)
        connect(host="127.0.0.1", port=port, sslmode="disable", timeout=5).close()
        self.assertFalse(seen["asked"])
        # verify-full: the certificate must be one the client trusts, for the name it connected to
        port, seen = self.server(tls=True)
        connect(host="127.0.0.1", port=port, sslmode="verify-full", sslrootcert=crt, timeout=5).close()
        self.assertTrue(seen["tls"])
        # ... and with no root certificate to check it against, as libpq, it doesn't go on
        port, seen = self.server(tls=True)
        root = re.escape(os.path.join(self.folder, "root.crt"))
        with self.assertRaisesRegex(self.pgwire.ProtocolError, f'^root certificate file "{root}" does not exist: '):
            connect(host="127.0.0.1", port=port, sslmode="verify-full", timeout=5)
        self.assertNotIn("start", seen)

    def tries(self, *ways: str) -> tuple[int, list[str], Callable[[], None]]:
        """A made-up server on a local port for one connection per way, in turn. A way is what it answers the TLS
        request (S: yes, with the test certificate; N: no), then what it does with the session: signs the client in
        (in), refuses it as a pg_hba.conf line for the other way would (out), as a server starting up does (busy,
        57P03), or saying the password is wrong (wrong). seen: how each connection went ("tls in", "plain out", "tls
        failed": the client gave up in the handshake). The function returned waits until the server is done."""
        import ssl
        import struct

        fixtures = os.path.join(ROOT, "tests", "fixtures")
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(os.path.join(fixtures, "wire_test.crt"), os.path.join(fixtures, "wire_test.key"))
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(len(ways))
        seen: list[str] = []

        def exactly(conn: socket.socket, n: int) -> bytes:
            data = b""
            while len(data) < n:
                chunk = conn.recv(n - len(data))
                if not chunk:
                    raise ConnectionError("closed")
                data += chunk
            return data

        def one(conn: socket.socket, answer: str, then: str, held: list[socket.socket]) -> None:
            conn.settimeout(5)
            length, code = struct.unpack("!ii", exactly(conn, 8))
            how = "plain"
            if code == 80877103:
                conn.sendall(answer.encode())
                if answer == "S":
                    try:
                        conn = context.wrap_socket(conn, server_side=True)
                    except OSError:
                        seen.append("tls failed")
                        return
                    held.append(conn)
                    how = "tls"
                length, code = struct.unpack("!ii", exactly(conn, 8))
            exactly(conn, length - 8)
            seen.append(f"{how} {then}")
            if then == "in":
                conn.sendall(self.said(b"R", struct.pack("!i", 0)) + self.said(b"Z", b"I"))
                while conn.recv(1024):
                    pass
                return
            code, message = {
                "out": (
                    "28000",
                    f'no pg_hba.conf entry for host "127.0.0.1", user "ann", database "app", '
                    f"{'SSL encryption' if how == 'tls' else 'no encryption'}",
                ),
                "busy": ("57P03", "the database system is starting up"),
                "wrong": ("28P01", 'password authentication failed for user "ann"'),
            }[then]
            conn.sendall(self.said(b"E", f"SFATAL\0C{code}\0M{message}\0\0".encode()))

        def serve() -> None:
            try:
                for way in ways:
                    conn, _ = listener.accept()
                    held = [conn]
                    try:
                        answer, then = way.split()
                        one(conn, answer, then, held)
                    except OSError:
                        pass
                    finally:
                        for sock in held:
                            sock.close()
            finally:
                listener.close()

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        return listener.getsockname()[1], seen, lambda: thread.join(5)

    def test_prefer_and_allow_as_libpq_tries_them(self) -> None:
        import shutil

        pgwire = self.pgwire

        def connect(port: int, sslmode: str = "prefer") -> None:
            pgwire.connect(host="127.0.0.1", port=port, user="ann", database="app", sslmode=sslmode, timeout=5).close()

        # prefer: TLS that fails (a root.crt in libpq's folder that didn't sign the server's certificate, which psql
        # takes all the same) is tried again without TLS, as libpq tries it
        os.makedirs(self.folder)
        shutil.copy(os.path.join(ROOT, "tests", "fixtures", "wire_ca.crt"), os.path.join(self.folder, "root.crt"))
        port, seen, done = self.tries("S in", "N in")
        connect(port)
        done()
        self.assertEqual(seen, ["tls failed", "plain in"])
        os.remove(os.path.join(self.folder, "root.crt"))
        # ... and so is a session the server refuses over TLS (a hostnossl line in pg_hba.conf)
        port, seen, done = self.tries("S out", "N in")
        connect(port)
        done()
        self.assertEqual(seen, ["tls out", "plain in"])
        # ... not one refused where the server has no TLS (nothing else to try), nor a server starting up (as libpq)
        for way, said in (("N out", "28000: no pg_hba.conf entry .*, no encryption"), ("S busy", "57P03: ")):
            port, seen, done = self.tries(way)
            with self.assertRaisesRegex(pgwire.PgError, f"^{said}", msg=way):
                connect(port)
            done()
            self.assertEqual(len(seen), 1, way)
        # refused both ways: both said, in turn; once where the words are the same (a wrong password)
        port, seen, done = self.tries("S out", "N out")
        with self.assertRaisesRegex(
            pgwire.ProtocolError,
            '^28000: no pg_hba.conf entry for host "127.0.0.1", user "ann", database "app", SSL encryption; then '
            'without TLS: 28000: no pg_hba.conf entry for host "127.0.0.1", user "ann", database "app", no encryption$',
        ):
            connect(port)
        port, seen, done = self.tries("S wrong", "N wrong")
        with self.assertRaisesRegex(pgwire.PgError, '^28P01: password authentication failed for user "ann"$'):
            connect(port)
        done()
        self.assertEqual(seen, ["tls wrong", "plain wrong"])
        # allow: without TLS first (it was asked for first, as prefer asks), then with it where that was refused
        port, seen, done = self.tries("S in")
        connect(port, "allow")
        done()
        self.assertEqual(seen, ["plain in"])
        port, seen, done = self.tries("N out", "S in")
        connect(port, "allow")
        done()
        self.assertEqual(seen, ["plain out", "tls in"])
        port, seen, done = self.tries("N out", "N in")
        with self.assertRaisesRegex(
            pgwire.ProtocolError,
            "no encryption; then with TLS: the server doesn't do TLS, and sslmode=allow asks for it$",
        ):
            connect(port, "allow")
        # require: one way, refused as the server refuses it
        port, seen, done = self.tries("S out")
        with self.assertRaisesRegex(pgwire.PgError, "^28000: .*, SSL encryption$"):
            connect(port, "require")

    def test_copy_from_stdin_is_failed_not_waited_on(self) -> None:
        # the server waits for the rows of a COPY ... FROM STDIN (rowstile sql can send one): the client fails the
        # copy (CopyFail), and the server's error comes back; the connection goes on (both protocols)
        import struct

        pgwire, said = self.pgwire, self.said
        ready = said(b"Z", b"I")
        copy_in = said(b"G", struct.pack("!bh", 0, 0))
        failed = said(b"E", b"SERROR\0C57014\0MCOPY from stdin failed: " + pgwire.NO_COPY.encode() + b"\0\0")
        selected = said(b"C", b"SELECT 0\0") + ready

        def session(replies: list[tuple[bytes, bytes]]) -> tuple[pgwire.Connection, list[bytes], Callable[[], None]]:
            """A made-up server over a socket pair: it signs the client in, then answers each message of the kind
            replies names next with that reply. got: the kinds of the messages it was sent (f with its text)."""
            mine, theirs = socket.socketpair()
            got: list[bytes] = []

            def serve() -> None:
                theirs.settimeout(5)
                theirs.recv(struct.unpack("!i", theirs.recv(4, socket.MSG_WAITALL))[0] - 4, socket.MSG_WAITALL)
                theirs.sendall(said(b"R", struct.pack("!i", 0)) + ready)
                while replies:
                    kind = theirs.recv(1)
                    body = theirs.recv(
                        struct.unpack("!i", theirs.recv(4, socket.MSG_WAITALL))[0] - 4, socket.MSG_WAITALL
                    )
                    got.append(kind + body if kind == b"f" else kind)
                    if kind == replies[0][0]:
                        theirs.sendall(replies.pop(0)[1])
                theirs.close()

            server = threading.Thread(target=serve, daemon=True)
            server.start()
            return pgwire.Connection(mine, "ann", None, "app", None), got, lambda: server.join(5)

        refusal = re.escape(f"57014: COPY from stdin failed: {pgwire.NO_COPY}")
        # the extended protocol (rowstile sql): the Sync sent with the statement is ignored during the copy, so one
        # follows the CopyFail
        conn, got, done = session([(b"S", said(b"1") + said(b"2") + copy_in), (b"S", failed + ready), (b"S", selected)])
        with self.assertRaisesRegex(pgwire.PgError, f"^{refusal}$"):
            conn.query("COPY t FROM STDIN")
        self.assertEqual(conn.query("SELECT 0"), [])
        conn.close()
        done()
        stop = b"f" + pgwire.NO_COPY.encode() + b"\0"
        self.assertEqual(got, [b"P", b"B", b"D", b"E", b"S", stop, b"S", b"P", b"B", b"D", b"E", b"S"])
        # the simple protocol (script): the CopyFail alone
        conn, got, done = session([(b"Q", copy_in), (b"f", failed + ready), (b"Q", selected)])
        with self.assertRaisesRegex(pgwire.PgError, f"^{refusal}$"):
            conn.script("COPY t FROM STDIN")
        conn.script("SELECT 0")
        conn.close()
        done()
        self.assertEqual(got, [b"Q", stop, b"Q"])

    def test_scram_is_bound_to_the_tls_channel(self) -> None:
        wrong = self.pgwire.ProtocolError

        def connect(port: int, channel_binding: str = "prefer", sslmode: str = "prefer") -> None:
            self.pgwire.connect(
                host="127.0.0.1",
                port=port,
                password="secret",
                timeout=5,
                sslmode=sslmode,
                channel_binding=channel_binding,
            ).close()

        # offered over TLS: taken, without being asked for (as libpq does)
        port, seen = self.server(tls=True, scram="plus")
        connect(port)
        self.assertEqual((seen["mechanism"], seen["bound"]), ("SCRAM-SHA-256-PLUS", True))
        port, seen = self.server(tls=True, scram="plus")
        connect(port, "require", "require")  # Neon's string
        self.assertEqual((seen["mechanism"], seen["bound"]), ("SCRAM-SHA-256-PLUS", True))
        port, seen = self.server(tls=True, scram="plus")
        connect(port, "disable")
        self.assertEqual((seen["mechanism"], seen["header"]), ("SCRAM-SHA-256", "n,,"))
        # not offered: done without, saying so (y), unless it was required
        port, seen = self.server(tls=True, scram="plain")
        connect(port)
        self.assertEqual((seen["mechanism"], seen["header"]), ("SCRAM-SHA-256", "y,,"))
        # required: refused before anything is sent, in libpq's words, unless the server takes SCRAM bound to TLS
        port, seen = self.server(tls=True, scram="plain")
        with self.assertRaisesRegex(
            wrong,
            "^channel binding is required, but server did not offer an authentication method that supports channel "
            "binding$",
        ):
            connect(port, "require")
        self.assertEqual(self.sent(seen), b"")
        port, seen = self.server(tls=False, scram="plus")
        with self.assertRaisesRegex(wrong, "^channel binding required, but SSL not in use$"):
            connect(port, "require")
        self.assertEqual(self.sent(seen), b"")
        port, seen = self.server(tls=False, scram="plus")
        connect(port)  # no TLS: nothing to bind to
        self.assertEqual((seen["mechanism"], seen["header"]), ("SCRAM-SHA-256", "n,,"))
        port, seen = self.server(tls=True)  # signs in without asking anything
        with self.assertRaisesRegex(
            wrong, "^channel binding required, but server authenticated client without channel binding$"
        ):
            connect(port, "require")
        self.assertEqual(self.sent(seen), b"")
        for auth in ("cleartext", "md5"):  # the password, or a hash of it: never sent, asked that way
            port, seen = self.server(tls=True, auth=auth)
            with self.assertRaisesRegex(
                wrong, "^channel binding required but not supported by server's authentication request$", msg=auth
            ):
                connect(port, "require", "require")
            self.assertEqual(self.sent(seen), b"", auth)
        # a server offers SCRAM-SHA-256-PLUS over TLS only: offered without it, it is for another connection than
        # this one (libpq refuses it whatever channel_binding says)
        for binding in ("prefer", "disable"):
            port, seen = self.server(tls=False, scram="plus anyway")
            with self.assertRaisesRegex(
                wrong, "^server offered SCRAM-SHA-256-PLUS authentication over a non-SSL connection$", msg=binding
            ):
                connect(port, binding)
            self.assertEqual(self.sent(seen), b"", binding)
        # a server in the middle holds another certificate than the one the client was shown: the exchange fails
        port, seen = self.server(tls=True, scram="other")
        with self.assertRaisesRegex(self.pgwire.PgError, "28P01"):
            connect(port, sslmode="require")  # (prefer tries again without TLS, as libpq does: nothing to bind then)
        with open(os.path.join(ROOT, "tests", "fixtures", "wire_test.crt"), encoding="ascii") as fh:
            import ssl

            certificate = ssl.PEM_cert_to_DER_cert(fh.read())
        self.assertEqual(self.pgwire._signature_hash(certificate), "sha256")
        self.assertIsNone(self.pgwire._signature_hash(b"not a certificate"))

        # a signature algorithm named by something else than an OID (DER's tag 6): no hash, even where its bytes
        # are those of one (OpenSSL takes no such certificate; this reads the bytes alone)
        def signed_with(tag: int) -> bytes:
            sha256_with_rsa = bytes.fromhex("2a864886f70d01010b")  # 1.2.840.113549.1.1.11
            algorithm = bytes([0x30, 2 + len(sha256_with_rsa), tag, len(sha256_with_rsa)]) + sha256_with_rsa
            return bytes([0x30, 2 + len(algorithm), 0x30, 0]) + algorithm  # what is signed (empty), the algorithm

        self.assertEqual(self.pgwire._signature_hash(signed_with(6)), "sha256")
        self.assertIsNone(self.pgwire._signature_hash(signed_with(4)))  # an OCTET STRING
        # RSA-PSS names its hash in its parameters; SHA-1, also when none is named, counts as SHA-256 (RFC 5929).
        # Made with openssl req -x509 -newkey rsa-pss -sigopt rsa_padding_mode:pss -sha384 (and -sha1); a server
        # holding each signed in with channel_binding=require, from psql and from this client alike
        for name, hashed in (("wire_pss_sha384.crt", "sha384"), ("wire_pss_sha1.crt", "sha256")):
            with open(os.path.join(ROOT, "tests", "fixtures", name), encoding="ascii") as fh:
                self.assertEqual(self.pgwire._signature_hash(ssl.PEM_cert_to_DER_cert(fh.read())), hashed, name)

    def test_each_way_a_server_asks_for_the_password(self) -> None:
        import hashlib

        wrong = self.pgwire.ProtocolError

        def connect(port: int, password: str | None = "secret") -> None:
            self.pgwire.connect(host="127.0.0.1", port=port, user="ann", password=password, timeout=5).close()

        port, seen = self.server(tls=False, auth="cleartext")
        connect(port)
        self.assertEqual(seen["password"], "secret")
        port, seen = self.server(tls=False, auth="md5")  # md5(md5(password + user) + salt), as libpq sends it
        connect(port)
        inner = hashlib.md5(b"secretann").hexdigest()
        self.assertEqual(seen["password"], "md5" + hashlib.md5(inner.encode() + b"salt").hexdigest())
        for auth, scram, password, said in (
            (
                "cleartext",
                None,
                None,
                "the server asks for a password, and none was given: put it in the connection string or PGPASSWORD "
                "(the rowstile command reads no password file, such as ~/.pgpass)",
            ),
            ("gss", None, "secret", "unsupported authentication method 7"),
            ("sasl-other", None, "secret", "unsupported SASL mechanisms"),
            (None, "badnonce", "secret", "the server's nonce does not extend ours"),
            (None, "badproof", "secret", "the server could not prove it knows the password"),
            ("not postgres", None, "secret", "the server didn't answer as Postgres does"),
        ):
            port, seen = self.server(tls=False, scram=scram, auth=auth)
            with self.assertRaisesRegex(wrong, re.escape(said), msg=auth or scram):
                connect(port, password)

    def test_what_it_refuses_to_send(self) -> None:
        port, _ = self.server(tls=False)
        conn = self.pgwire.connect(host="127.0.0.1", port=port, user="ann", timeout=5)
        try:
            with self.assertRaisesRegex(ValueError, "SQL cannot contain NUL characters"):
                conn.script("SELECT 1\0")
            with self.assertRaisesRegex(ValueError, "parameters cannot contain NUL characters"):
                conn.query("SELECT $1", ["a\0b"])
        finally:
            conn.close()

    @staticmethod
    def said(kind: bytes, body: bytes = b"") -> bytes:
        """One message as a server sends it: its kind, its length, its body."""
        import struct

        return kind + struct.pack("!i", 4 + len(body)) + body

    def talking(
        self, start: bytes, answers: Sequence[bytes | None] = (), listen: bool = True
    ) -> tuple[int, dict[str, object], Callable[[], None]]:
        """A made-up server for what comes after the handshake (no TLS, no password asked): it reads the start-up
        message and sends `start`; then for each of `answers` it reads one query (up to its Sync) and sends that
        answer, or, for None, closes the connection without one; then it waits until the client goes. seen: each
        query's messages, and the CancelRequest a second connection brought within half a second (None: none),
        unless listen is False: then nobody listens once the client is connected. The function returned waits until
        the made-up server is done."""
        import socket
        import struct
        import threading

        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(2)
        port = listener.getsockname()[1]
        queries: list[list[tuple[bytes, bytes]]] = []
        seen: dict[str, object] = {"queries": queries, "cancel": None}

        def exactly(conn: socket.socket, n: int) -> bytes:
            data = b""
            while len(data) < n:
                chunk = conn.recv(n - len(data))
                if not chunk:
                    raise ConnectionError("closed")
                data += chunk
            return data

        def serve() -> None:
            conn, _ = listener.accept()
            if not listen:
                listener.close()
            try:
                conn.settimeout(5)
                exactly(conn, struct.unpack("!i", exactly(conn, 4))[0] - 4)  # the start-up message
                conn.sendall(start)
                for answer in answers:
                    query: list[tuple[bytes, bytes]] = []
                    while not query or query[-1][0] != b"S":
                        kind = exactly(conn, 1)
                        query.append((kind, exactly(conn, struct.unpack("!i", exactly(conn, 4))[0] - 4)))
                    queries.append(query)
                    if answer is None:
                        return
                    conn.sendall(answer)
                while conn.recv(1024):
                    pass
            except OSError:
                pass
            finally:
                conn.close()
                if listen:
                    listener.settimeout(0.5)
                    try:
                        cancel, _ = listener.accept()
                        cancel.settimeout(5)
                        seen["cancel"] = exactly(cancel, 16)
                        cancel.close()
                    except OSError:
                        pass
                    listener.close()

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        return port, seen, lambda: thread.join(5)

    def test_what_the_server_says_once_signed_in(self) -> None:
        import struct

        said = self.said
        signed_in, ready = said(b"R", struct.pack("!i", 0)), said(b"Z", b"I")
        warning = said(b"N", b"SWARNING\0Mcareful\0\0")
        done_with = said(b"C", b"SELECT 1\0") + ready
        # a warning while it starts (a database's setting the server can't take, a collation version that doesn't
        # match the system's: psql shows it) goes to the on_notice connect is given, and what the server says after
        # it is kept; with none given (Studio), it is read past
        start = signed_in + warning + said(b"S", b"server_version\x0016\0") + said(b"K", struct.pack("!ii", 41, 42))
        for given in (True, False):
            port, seen, done = self.talking(start + ready)
            started: list[dict[str, str]] = []
            conn = self.pgwire.connect(
                host="127.0.0.1", port=port, sslmode="disable", timeout=5, on_notice=started.append if given else None
            )
            self.assertEqual((conn.params, conn.backend), ({"server_version": "16"}, (41, 42)))
            self.assertEqual(started, [{"S": "WARNING", "M": "careful"}] if given else [])
            conn.close()
        # one while a statement runs goes to on_notice (rowstile sql shows a WARNING, as psql does), and the rows
        # come after it
        column = said(b"T", struct.pack("!h", 1) + b"n\0" + struct.pack("!ihihih", 0, 0, 23, 4, -1, 0))
        row = said(b"D", struct.pack("!hi", 1, 1) + b"7")
        port, seen, done = self.talking(
            signed_in + ready, [said(b"1") + said(b"2") + column + warning + row + done_with]
        )
        conn = self.pgwire.connect(host="127.0.0.1", port=port, sslmode="disable", timeout=5)
        notices: list[dict[str, str]] = []
        conn.on_notice = notices.append
        self.assertEqual(conn.query("SELECT 7"), [(7,)])
        self.assertEqual(notices, [{"S": "WARNING", "M": "careful"}])
        conn.close()
        # ... and on a connection with no handler (Studio's), it is read past: the rows come all the same
        port, seen, done = self.talking(
            signed_in + ready, [said(b"1") + said(b"2") + column + warning + row + done_with]
        )
        conn = self.pgwire.connect(host="127.0.0.1", port=port, sslmode="disable", timeout=5)
        self.assertIsNone(conn.on_notice)
        self.assertEqual(conn.query("SELECT 7"), [(7,)])
        conn.close()
        # parameters as psycopg sends them: a list as an array (the generated Python client's who_among, through
        # this client's cursor), a dict as JSON
        port, seen, done = self.talking(signed_in + ready, [said(b"1") + said(b"2") + said(b"n") + done_with])
        conn = self.pgwire.connect(host="127.0.0.1", port=port, sslmode="disable", timeout=5)
        conn.query("SELECT $1, $2, $3, $4, $5", [["a", 'b"c', None, "d\\e"], {"k": [1]}, True, None, [[1], [None]]])
        conn.close()
        done()
        queries = cast("list[list[tuple[bytes, bytes]]]", seen["queries"])
        bind = next(body for kind, body in queries[0] if kind == b"B")
        at = bind.index(b"\0", bind.index(b"\0") + 1) + 1  # after the portal's name and the statement's
        at += 2 + 2 * struct.unpack("!h", bind[at : at + 2])[0]  # the formats
        count, at = struct.unpack("!h", bind[at : at + 2])[0], at + 2
        sent: list[bytes | None] = []
        for _ in range(count):
            n = struct.unpack("!i", bind[at : at + 4])[0]
            sent.append(None if n < 0 else bind[at + 4 : at + 4 + n])
            at += 4 + max(n, 0)
        self.assertEqual(sent, [b'{"a","b\\"c",NULL,"d\\\\e"}', b'{"k": [1]}', b"true", None, b'{{"1"},{NULL}}'])
        # a server that goes away in the middle of a statement without a word (it crashed, or the network did)
        port, seen, done = self.talking(signed_in + ready, [None])
        conn = self.pgwire.connect(host="127.0.0.1", port=port, sslmode="disable", timeout=5)
        with self.assertRaisesRegex(self.pgwire.ProtocolError, "^the server closed the connection$"):
            conn.query("SELECT 1")
        conn.sock.close()

    def test_the_servers_reason_when_it_ends_the_session(self) -> None:
        """A server that ends the session (pg_terminate_backend, a shutdown) sends a FATAL that says why, then
        closes. Over a Unix socket the next statement's send fails first (a broken pipe): the error is the server's
        words all the same, read as libpq reads them after a write that failed; and on the way out, undoing a
        savepoint or looking for the policy's condition that failed doesn't put another error in their place."""
        import contextlib
        import select
        import socket
        import struct

        from authzlib import database

        pgwire, said = self.pgwire, self.said
        # as Postgres sends it
        fatal = said(b"E", b"SFATAL\0VFATAL\0C57P01\0Mterminating connection due to administrator command\0\0")
        ended = ("57P01", "terminating connection due to administrator command", "FATAL")

        def session(answers: Sequence[bytes] = (), then: bytes = b"", waits: bool = False) -> pgwire.Connection:
            """A connection over a Unix socket whose server signs it in, answers each statement with the next of
            answers, then sends `then` and closes. With no answers, it has closed when this returns. One that waits
            closes once the client's next statement has come, unread: the system then resets the connection (as
            Postgres's does when it ends a session while a statement is on its way), and the client's next read
            fails with the reset, every time, where it would find the end."""
            mine, theirs = socket.socketpair()

            def serve() -> None:
                theirs.recv(65536)  # the start-up message
                theirs.sendall(said(b"R", struct.pack("!i", 0)) + said(b"Z", b"I"))
                for answer in answers:
                    kind = b""
                    while kind not in (b"S", b"Q"):  # one statement: up to its Sync, or a simple query
                        kind = theirs.recv(1)
                        length = struct.unpack("!i", theirs.recv(4, socket.MSG_WAITALL))[0]
                        theirs.recv(length - 4, socket.MSG_WAITALL)
                    theirs.sendall(answer)
                theirs.sendall(then)
                if waits:
                    select.select([theirs], [], [], 5)
                theirs.close()

            server = threading.Thread(target=serve, daemon=True)
            server.start()
            conn = pgwire.Connection(mine, "ann", None, "app", None)
            if not answers and not waits:
                server.join(5)
            return conn

        # between two statements: the next one's send finds the connection closed
        for send in ("query", "script", "execute"):
            conn = session(then=fatal)
            with self.assertRaises(pgwire.PgError, msg=send) as caught:
                getattr(conn, send)("SELECT 1")
            e = caught.exception
            self.assertEqual((e.code, e.message, e.fields["S"]), ended, send)
            # what is asked after it (by a probe that took the error for an answer, say) is told why again
            with self.assertRaises(pgwire.PgError, msg=send) as caught:
                conn.query("SELECT 2")
            e = caught.exception
            self.assertEqual((e.code, e.message, e.fields["S"]), ended, send)
            conn.close()  # on a connection that is gone: nothing raised
        # a warning before the FATAL (a shutdown's): read past, the FATAL is the reason
        notice = said(b"N", b"SWARNING\0VWARNING\0C01000\0Mthe server is shutting down\0\0")
        conn = session(then=notice + fatal)
        with self.assertRaises(pgwire.PgError) as caught:
            conn.query("SELECT 1")
        e = caught.exception
        self.assertEqual((e.code, e.message, e.fields["S"]), ended)
        conn.close()
        conn = session()  # closed without a word (the network, a crash)
        with self.assertRaisesRegex(pgwire.ProtocolError, "^the server closed the connection$"):
            conn.query("SELECT 1")
        conn.close()
        # a statement on its way: the server closes with it unread, and the connection is reset; what the server
        # said before is read first, and the reset is the server closing the connection
        for send in ("query", "script", "execute"):
            conn = session(then=fatal, waits=True)
            with self.assertRaises(pgwire.PgError, msg=send) as caught:
                getattr(conn, send)("SELECT 1")
            e = caught.exception
            self.assertEqual((e.code, e.message, e.fields["S"]), ended, send)
            conn.close()
            conn = session(waits=True)
            with self.assertRaisesRegex(pgwire.ProtocolError, "^the server closed the connection$", msg=send):
                getattr(conn, send)("SELECT 1")
            conn.close()
        # a connection the system aborted (Windows says so of one that broke): the same, on a read or a write
        for broken in (("recv",), ("recv", "sendall")):
            conn = session(waits=True)
            with contextlib.ExitStack() as stack:
                for call in broken:
                    stack.enter_context(mock.patch.object(socket.socket, call, side_effect=ConnectionAbortedError))
                with self.assertRaisesRegex(pgwire.ProtocolError, "^the server closed the connection$", msg=broken):
                    conn.query("SELECT 1")
            conn.close()

        class Db:
            """authzlib's Db over the connection, each statement it was asked for kept."""

            errors = pgwire.PgError

            def __init__(self, conn: pgwire.Connection) -> None:
                self.conn, self.sent = conn, list[str]()

            def rows(self, sql: str, args: Sequence[Value] = ()) -> list[Row]:
                self.sent.append(sql)
                result, cols = self.conn.query_described(sql, list(args))
                return [dict(zip(cols, r, strict=True)) for r in result]

            def script(self, sql: str) -> None:
                self.sent.append(sql)
                self.conn.script(sql)

            def warn(self, message: str, detail: str | None = None, hint: str | None = None) -> None:
                pass

        saved = said(b"C", b"SAVEPOINT\0") + said(b"Z", b"T")
        # ended in the middle of a savepoint: undoing it fails, and the error raised is still the server's
        db = Db(session([saved, fatal]))
        with self.assertRaises(pgwire.PgError) as caught, database.savepoint(db, "sp"):
            db.rows("SELECT 1")
        self.assertEqual((caught.exception.code, caught.exception.message), ended[:2])
        self.assertEqual(db.sent, ["SAVEPOINT sp", "SELECT 1", "ROLLBACK TO SAVEPOINT sp; RELEASE SAVEPOINT sp"])
        db.conn.close()
        # ... and Ctrl-C there stays Ctrl-C (the command says it stopped, and nothing was kept)
        db = Db(session([saved]))
        with self.assertRaises(KeyboardInterrupt), database.savepoint(db, "sp"):
            raise KeyboardInterrupt
        db.conn.close()
        # ... but Undo asks for the undoing: a failure to undo is that failure
        db = Db(session([saved], waits=True))
        with (
            self.assertRaisesRegex(pgwire.ProtocolError, "^the server closed the connection$"),
            database.savepoint(db, "sp"),
        ):
            raise database.Undo
        db.conn.close()

        # the policy's SQL, ended by the server: its words, and no condition of the policy tried alone after them
        def columns(oid: int, *names: bytes) -> bytes:
            return said(
                b"T",
                struct.pack("!h", len(names))
                + b"".join(n + b"\0" + struct.pack("!ihihih", 0, 0, oid, -1, -1, 0) for n in names),
            )

        def row(*values: bytes) -> bytes:
            return said(b"D", struct.pack("!h", len(values)) + b"".join(struct.pack("!i", len(v)) + v for v in values))

        done = said(b"C", b"SELECT 1\0") + said(b"Z", b"T")
        room = columns(23, b"per", b"slots") + row(b"64", b"300") + done  # lock_room: the lock table's room
        before = columns(25, b"sp", b"cfb", b"lt") + row(b"app", b"on", b"0") + done  # run: the settings it gives back
        db = Db(session([room, saved, before, fatal]))
        policy = "app role app_user\ntype user = app.users\ntype doc = app.docs\n  owner : user = owner_id\n  can view = owner or {not archived}\n"
        with self.assertRaises(pgwire.PgError) as caught:
            database.run_policy(db, "CREATE VIEW v AS SELECT 1;\n", policy, {})
        self.assertEqual((caught.exception.code, caught.exception.message), ended[:2])
        self.assertEqual(
            db.sent[1:], ["SAVEPOINT authz_policy", db.sent[2], "CREATE VIEW v AS SELECT 1;\n", db.sent[4]], db.sent
        )
        self.assertEqual(len(db.sent), 5, db.sent)  # nothing after undoing the savepoint
        db.conn.close()

    def test_cancel(self) -> None:
        """Ctrl-C in the command: a CancelRequest with the session's key, on a connection of its own; then this one
        is closed."""
        import struct

        said = self.said
        key = said(b"K", struct.pack("!ii", 41, 42))
        start = said(b"R", struct.pack("!i", 0)) + key + said(b"Z", b"I")
        for given, listen, sent in (
            (start, True, struct.pack("!iiii", 16, 80877102, 41, 42)),
            (start.replace(key, b""), True, None),  # no key from the server (or the pooler): nothing to cancel with
            (start, False, None),  # nobody takes the request (the server went away): no error, and closed all the same
        ):
            port, seen, done = self.talking(given, listen=listen)
            conn = self.pgwire.connect(host="127.0.0.1", port=port, sslmode="disable", timeout=5)
            conn.cancel()
            done()
            self.assertEqual((seen["cancel"], conn.sock.fileno()), (sent, -1), (listen, sent))

    def test_the_defaults_are_libpqs(self) -> None:
        # where nothing names them (no setting, no PG* variable): the user is the system's, as libpq has it (psql
        # connects as `dev`, not postgres), the database is named after the user, and the host is the socket folder
        # libpq is built with: Debian's and Ubuntu's (/var/run/postgresql), else /tmp (libpq's own default, as
        # Homebrew and Postgres.app build it; first on macOS), whichever has the server's socket; localhost on Windows
        import pwd

        parse = self.pgwire.parse_dsn
        me = pwd.getpwuid(os.geteuid()).pw_name
        got = parse(None)
        self.assertEqual((got["user"], got["database"], got["port"]), (me, me, 5432))
        self.assertEqual(parse("dbname=app")["user"], me)
        self.assertEqual(parse("user=ann")["database"], "ann")

        def where(platform: str, sockets: set[str]) -> str:
            with (
                mock.patch.object(sys, "platform", platform),
                mock.patch.object(os.path, "exists", lambda p: p in sockets),
            ):
                return parse("port=5433 user=u")["host"]

        debian, tmp = "/var/run/postgresql/.s.PGSQL.5433", "/tmp/.s.PGSQL.5433"
        self.assertEqual(where("linux", {debian, tmp}), "/var/run/postgresql")
        self.assertEqual(where("linux", {tmp}), "/tmp")
        self.assertEqual(where("linux", set()), "/var/run/postgresql")  # none there: libpq's on Debian, said
        self.assertEqual(where("darwin", {debian, tmp}), "/tmp")
        self.assertEqual(where("darwin", {debian}), "/var/run/postgresql")
        self.assertEqual(where("darwin", set()), "/tmp")
        self.assertEqual(where("win32", {debian, tmp}), "localhost")
        # on Windows, the user is the one Windows signed in (USERNAME, what libpq asks Windows for)
        with mock.patch.object(sys, "platform", "win32"), mock.patch.dict(os.environ, {"USERNAME": "Ann"}):
            got = parse(None)
            self.assertEqual((got["host"], got["user"], got["database"]), ("localhost", "Ann", "Ann"))
        with mock.patch.object(sys, "platform", "win32"), mock.patch.dict(os.environ, {"PGUSER": "bo"}):
            self.assertEqual(parse(None)["user"], "bo")
        with (
            mock.patch.object(sys, "platform", "win32"),
            mock.patch.dict(os.environ, {"USERNAME": ""}),
            self.assertRaisesRegex(
                ValueError, r"^no user name from Windows \(USERNAME\): name one with user= or PGUSER$"
            ),
        ):
            parse(None)
        # a user the system can't name (a container's uid with no line in /etc/passwd) is said, with what to set
        with (
            mock.patch.object(pwd, "getpwuid", side_effect=KeyError("getpwuid(): uid not found: 4242")),
            mock.patch.object(os, "geteuid", return_value=4242),
            self.assertRaisesRegex(
                ValueError, "^no user name for the system's user 4242: name one with user= or PGUSER$"
            ),
        ):
            parse("host=h")
        self.assertEqual(parse("host=h user=x")["user"], "x")  # one named isn't looked up

    def test_where_it_could_not_connect_is_said(self) -> None:
        # a server it can't reach is said with where it tried (the host and port, or the socket's path) and why, in
        # words, as psql says it: the database may have come from rowstile.toml, DATABASE_URL, a .env file or PG*
        import socket

        connect, Unreachable = self.pgwire.connect, self.pgwire.Unreachable
        free = socket.socket()
        free.bind(("127.0.0.1", 0))
        port = free.getsockname()[1]  # bound, not listening: refused
        try:
            with self.assertRaises(Unreachable) as caught:
                connect(host="127.0.0.1", port=port, sslmode="disable", timeout=5)
        finally:
            free.close()
        self.assertEqual(str(caught.exception), f"127.0.0.1 port {port}: connection refused")
        self.assertEqual(caught.exception.where, f"127.0.0.1 port {port}")
        closed: list[int] = []
        close = socket.socket.close

        def closing(sock: socket.socket) -> None:
            closed.append(sock.family)
            close(sock)

        with (
            tempfile.TemporaryDirectory() as folder,
            mock.patch.object(socket.socket, "close", closing),
            self.assertRaises(Unreachable) as caught,
        ):
            connect(host=folder, port=5433, timeout=5)
        self.assertEqual(str(caught.exception), f"the socket {folder}/.s.PGSQL.5433: no such file or directory")
        self.assertEqual(closed, [socket.AF_UNIX])  # the socket it made is closed, not left to the collector
        # a name with no address (as the system's resolver says it)
        no_name = socket.gaierror(socket.EAI_NONAME, "Name or service not known")
        with mock.patch.object(socket, "getaddrinfo", side_effect=no_name), self.assertRaises(Unreachable) as caught:
            connect(host="nosuchhost.invalid", port=5432, timeout=5)
        self.assertEqual(str(caught.exception), "nosuchhost.invalid port 5432: name or service not known")
        # something that takes the connection and never answers: as long as connect_timeout says
        mute = socket.socket()
        mute.bind(("127.0.0.1", 0))
        mute.listen(1)  # never accepted: the system answers the connection, and nobody the start-up
        port = mute.getsockname()[1]
        try:
            with self.assertRaises(Unreachable) as caught:
                connect(host="127.0.0.1", port=port, sslmode="disable", timeout=0.5)
        finally:
            mute.close()
        self.assertEqual(str(caught.exception), f"127.0.0.1 port {port}: no answer in 0.5 s (connect_timeout)")
        # ... and the command says it so, with nothing named too (libpq's defaults, tried)
        refused = Unreachable("db.example.com port 5433", "connection refused")
        named = ("PGHOST", "PGPORT", "PGDATABASE", "PGUSER", "PGSERVICE")
        with mock.patch.dict(os.environ, {k: v for k, v in os.environ.items() if k not in named}, clear=True):
            self.assertEqual(
                rowstile_cli.cant_connect(refused, "postgresql://me@db.example.com:5433/app"),
                "can't connect to db.example.com port 5433: connection refused",
            )
            self.assertTrue(
                rowstile_cli.cant_connect(refused, None).startswith(
                    "can't connect: no database was named, and the default failed (db.example.com port 5433: "
                    "connection refused)\n"
                )
            )

    def test_the_port_and_connect_timeout_as_libpq_reads_them(self) -> None:
        parse = self.pgwire.parse_dsn
        # a whole number, a sign and spaces around it allowed (strtol); a port from 1 to 65535
        self.assertEqual(parse("host=h port=' 5433 '")["port"], 5433)
        self.assertEqual(parse("postgresql://h:5433/app")["port"], 5433)
        for dsn, env, port in (
            ("postgresql://h:70000/app", {}, "70000"),  # was blamed on a # in the password
            ("postgresql://h:0/app", {}, "0"),
            ("postgresql://u:p@[::1]:70000/app", {}, "70000"),
            ("host=h port=70000", {}, "70000"),
            ("host=h port=-1", {}, "-1"),
            ("host=h", {"PGPORT": "99999"}, "99999"),
        ):
            with (
                mock.patch.dict(os.environ, env),
                self.assertRaisesRegex(ValueError, f"^the port is a number from 1 to 65535, not '{port}'$", msg=dsn),
            ):
                parse(dsn)
        with self.assertRaisesRegex(ValueError, "^the URL's port isn't a number: a #, \\? or / in the password"):
            parse("postgresql://u:pa/ss@h/app")
        # connect_timeout: zero or less waits as long as it takes (None), as libpq; not given, 10 s (libpq: no limit)
        for written, timeout in (("0", None), ("-1", None), ("' 7 '", 7.0), ("+3", 3.0)):
            self.assertEqual(parse(f"host=h connect_timeout={written}")["timeout"], timeout, written)
        self.assertEqual(parse("host=h")["timeout"], 10.0)
        with mock.patch.dict(os.environ, {"PGCONNECT_TIMEOUT": "0"}):
            self.assertIsNone(parse("host=h")["timeout"])
        for written in ("x", "1.5", "99999999999"):
            with self.assertRaisesRegex(ValueError, f"^connect_timeout is a number of seconds, not '{written}'$"):
                parse(f"host=h connect_timeout={written}")

    def test_a_socket_on_windows(self) -> None:
        # Windows has no Unix sockets: a host that is a folder is refused, saying what to write instead
        said = "^host=/var/run/postgresql is a Unix socket, which Windows doesn't have: use host=localhost$"
        with mock.patch.object(sys, "platform", "win32"), self.assertRaisesRegex(self.pgwire.ProtocolError, said):
            self.pgwire.connect(host="/var/run/postgresql", timeout=1)

    def test_values_it_reads(self) -> None:
        convert = self.pgwire._convert
        self.assertEqual(convert(1000, b"{t,f,NULL}"), [True, False, None])  # booleans
        self.assertEqual(convert(1009, b'{"a\\"b",c}'), ['a"b', "c"])  # a quote escaped inside quotes
        self.assertEqual(convert(1007, b"{1,2,NULL}"), [1, 2, None])
        self.assertEqual(convert(1007, b"{{1,2},{3,4}}"), "{{1,2},{3,4}}")  # two dimensions: as Postgres writes it
        self.assertEqual(convert(1009, b"{{a,b},{c,d}}"), "{{a,b},{c,d}}")  # ... text and booleans too (rowstile sql
        self.assertEqual(convert(1000, b"{{t,f},{f,t}}"), "{{t,f},{f,t}}")  # showed ['{a', 'b'] and [False, False])
        self.assertEqual(convert(1009, b"[0:1]={a,b}"), "[0:1]={a,b}")
        self.assertEqual(self.pgwire._saslprep("pa\u00adss\u2168"), "passIX")  # as psql prepares a password for SCRAM
        self.assertEqual(self.pgwire._saslprep("caf\u00e9"), "caf\u00e9")

    def test_require_auth_as_libpq_reads_it(self) -> None:
        # the ways the server may ask for the password: any other is refused before anything is sent to it
        wrong = self.pgwire.ProtocolError
        for require, tls, scram, auth, said in (
            ("scram-sha-256", True, None, "cleartext", "server requested a cleartext password"),
            ("scram-sha-256", True, None, "md5", "server requested a hashed password"),
            ("password", True, "plus", None, "server requested SASL authentication"),
            ("scram-sha-256", True, None, None, "server did not complete authentication"),  # signs in unasked
            ("!password", False, None, "cleartext", "server requested a cleartext password"),
            ("!scram-sha-256", True, "plus", None, "server requested SCRAM-SHA-256-PLUS authentication"),
            ("password", False, None, None, "server did not complete authentication"),
            ("scram-sha-256", True, None, "gss", "server requested GSSAPI authentication"),
        ):
            port, seen = self.server(tls=tls, scram=scram, auth=auth)
            dsn = f"host=127.0.0.1 port={port} password=secret require_auth={require}"
            with self.assertRaisesRegex(wrong, f'^authentication method requirement "{require}" failed: {said}$'):
                self.pgwire.connect(**self.pgwire.parse_dsn(dsn))
            self.assertIn(self.sent(seen), (b"", None), (require, said))  # nothing; or not asked for anything yet
        for require, tls, scram, auth in (
            ("scram-sha-256", True, "plus", None),
            ("md5,scram-sha-256", False, "plain", None),
            ("password", False, None, "cleartext"),
            ("!password", False, None, "md5"),
            ("none", False, None, None),
            ("scram-sha-256,none", False, None, None),
            ("!password,!md5", True, "plus", None),
        ):
            port, seen = self.server(tls=tls, scram=scram, auth=auth)
            dsn = f"host=127.0.0.1 port={port} password=secret require_auth={require}"
            self.pgwire.connect(**self.pgwire.parse_dsn(dsn)).close()
        for require, said in (
            ("password,!md5", 'negative require_auth method "!md5" cannot be mixed with non-negative methods'),
            ("!md5,password", 'require_auth method "password" cannot be mixed with negative methods'),
            ("passwd", 'invalid require_auth value: "passwd"'),
            ("password, md5", 'invalid require_auth value: " md5"'),
            ("md5,md5", 'require_auth method "md5" is specified more than once'),
            ("!none,!none", 'require_auth method "!none" is specified more than once'),
        ):
            with self.assertRaisesRegex(ValueError, f"^{re.escape(said)}$", msg=require):
                self.pgwire.parse_dsn(f"host=h require_auth='{require}'")

    def test_the_servers_certificate_as_libpq_checks_it(self) -> None:
        import shutil

        # made with openssl: an authority (wire_ca.crt, its key thrown away), the certificate it signed for localhost
        # and 127.0.0.1 with wire_test.key (wire_ca_server.crt), and its lists of revoked certificates, one empty and
        # one naming that certificate (wire_ca_empty.crl, wire_ca_revoked.crl), all good for a hundred years
        fixtures = os.path.join(ROOT, "tests", "fixtures").replace(os.sep, "/")  # a backslash escapes, in a string
        authority, other = f"{fixtures}/wire_ca.crt", f"{fixtures}/wire_test.crt"
        signed = "wire_ca_server.crt"  # the authority's, for localhost and 127.0.0.1
        wrong = self.pgwire.ProtocolError

        def connect(dsn: str) -> dict[str, object]:
            """Signs in to a made-up server holding the certificate the authority signed; what the server saw."""
            port, seen = self.server(tls=True, certificate=signed)
            self.pgwire.connect(**self.pgwire.parse_dsn(f"host=127.0.0.1 port={port} {dsn}")).close()
            return seen

        def refused(dsn: str, said: str) -> None:
            """... refused, nothing sent once TLS was taken: no start-up message."""
            port, seen = self.server(tls=True, certificate=signed)
            with self.assertRaisesRegex(wrong, said, msg=dsn):
                self.pgwire.connect(**self.pgwire.parse_dsn(f"host=127.0.0.1 port={port} {dsn}"))
            self.assertNotIn("start", seen, dsn)

        # require with a root certificate checks the server's certificate against it, as verify-ca
        self.assertTrue(connect(f"sslmode=require sslrootcert={authority}")["tls"])
        refused(
            f"sslmode=require sslrootcert={other}", r"^TLS with the server failed \(sslmode=require\): .*verify fail"
        )
        # ... the one in libpq's folder too, where nothing names one; PGSSLROOTCERT names one
        os.makedirs(self.folder)
        shutil.copy(other, os.path.join(self.folder, "root.crt"))
        refused("sslmode=require", "certificate verify failed")
        shutil.copy(authority, os.path.join(self.folder, "root.crt"))
        connect("sslmode=require")
        with mock.patch.dict(os.environ, {"PGSSLROOTCERT": other}):
            refused("sslmode=require", "certificate verify failed")
        os.remove(os.path.join(self.folder, "root.crt"))
        # a root certificate file that isn't there: require goes on without checking, as libpq does; verify-ca
        # and verify-full don't go on
        connect(f"sslmode=require sslrootcert={fixtures}/nowhere.crt")
        connect("sslmode=require")
        refused(
            "sslmode=verify-ca", f'^root certificate file "{re.escape(os.path.join(self.folder, "root.crt"))}" does'
        )
        # verify-full checks the name it connected to as well: the certificate's names are localhost and 127.0.0.1
        connect(f"sslmode=verify-full sslrootcert={authority}")
        # sslrootcert=system: the system's roots, which this test authority isn't among, and verify-full by default;
        # a weaker sslmode with it is refused, as libpq refuses it
        self.assertEqual(self.pgwire.parse_dsn("host=h sslrootcert=system")["sslmode"], "verify-full")
        refused("sslrootcert=system", "certificate verify failed")
        # ... the system's roots are what OpenSSL takes for them, as libpq loads them (SSL_CERT_FILE names a file)
        with mock.patch.dict(os.environ, {"SSL_CERT_FILE": authority}):
            connect("sslrootcert=system")
        # ... and the name is checked: the certificates are for localhost and 127.0.0.1, not 127.0.0.2
        port, seen = self.server(tls=True, certificate=signed, address="127.0.0.2")
        with mock.patch.dict(os.environ, {"SSL_CERT_FILE": authority}), self.assertRaisesRegex(wrong, "mismatch"):
            self.pgwire.connect(**self.pgwire.parse_dsn(f"host=127.0.0.2 port={port} sslrootcert=system"))
        port, seen = self.server(tls=True, certificate=signed, address="127.0.0.2")
        dsn = f"host=127.0.0.2 port={port} sslmode=verify-full sslrootcert={authority}"
        with self.assertRaisesRegex(wrong, "IP address mismatch"):
            self.pgwire.connect(**self.pgwire.parse_dsn(dsn))
        self.assertNotIn("start", seen)
        port, seen = self.server(tls=True, certificate=signed, address="127.0.0.2")
        dsn = f"host=127.0.0.2 port={port} sslmode=verify-ca sslrootcert={authority}"
        self.pgwire.connect(**self.pgwire.parse_dsn(dsn)).close()  # verify-ca: the authority, not the name
        for weak in ("require", "verify-ca", "prefer"):
            with self.assertRaisesRegex(
                ValueError, f'^weak sslmode "{weak}" may not be used with sslrootcert=system \\(use "verify-full"\\)$'
            ):
                self.pgwire.parse_dsn(f"host=h sslrootcert=system sslmode={weak}")
        # revoked: with a root certificate file, a certificate sslcrl (or sslcrldir, or root.crl in libpq's folder)
        # lists is refused; one that lists nothing changes nothing
        empty, revoked = f"{fixtures}/wire_ca_empty.crl", f"{fixtures}/wire_ca_revoked.crl"
        connect(f"sslmode=verify-ca sslrootcert={authority} sslcrl={empty}")
        refused(f"sslmode=verify-ca sslrootcert={authority} sslcrl={revoked}", "certificate revoked")
        with mock.patch.dict(os.environ, {"PGSSLCRL": revoked}):
            refused(f"sslmode=require sslrootcert={authority}", "certificate revoked")
        crls = os.path.join(self.home.name, "crls")
        os.makedirs(crls)
        shutil.copy(revoked, os.path.join(crls, "231ef00c.r0"))  # its issuer's hash: openssl crl -hash
        refused(f"sslmode=verify-ca sslrootcert={authority} sslcrldir={crls.replace(os.sep, '/')}", "revoked")
        shutil.copy(revoked, os.path.join(self.folder, "root.crl"))
        refused(f"sslmode=require sslrootcert={authority}", "certificate revoked")
        # with no folder of libpq's (no home), the root certificate sslrootcert names is still checked, and no list
        # of revoked certificates is looked for
        with mock.patch.object(self.pgwire, "_libpq_file", return_value=None):
            connect(f"sslmode=require sslrootcert={authority}")
            refused(f"sslmode=require sslrootcert={other}", "certificate verify failed")
        # a root certificate file that holds no certificate: refused, saying which file, before anything is sent
        unreadable = os.path.join(self.home.name, "not-a-certificate.crt").replace(os.sep, "/")
        with open(unreadable, "w", encoding="utf-8") as fh:
            fh.write("not a certificate\n")
        refused(f"sslmode=require sslrootcert={unreadable}", f'^could not read root certificate file "{unreadable}"')
        # TLS's version: TLSv1.3 where both have it, TLSv1.2 at most if the maximum says so; a minimum of TLSv1.3
        # refuses a server that stops at TLSv1.2
        os.remove(os.path.join(self.folder, "root.crl"))
        self.assertEqual(connect("sslmode=require")["version"], "TLSv1.3")
        self.assertEqual(connect("sslmode=require ssl_max_protocol_version=TLSv1.2")["version"], "TLSv1.2")
        port, seen = self.server(tls=True, certificate=signed, tls_cap=True)
        dsn = f"host=127.0.0.1 port={port} sslmode=require ssl_min_protocol_version=tlsv1.3"
        with self.assertRaisesRegex(wrong, "TLS with the server failed"):
            self.pgwire.connect(**self.pgwire.parse_dsn(dsn))
        self.assertNotIn("start", seen)

    def test_libpqs_folder(self) -> None:
        # where libpq looks for root.crt and root.crl: ~/.postgresql, from HOME, else the user's own folder (as
        # libpq: in a container whose user has no entry, nowhere), or %APPDATA%\postgresql on Windows
        folder = self.pgwire._libpq_file
        with mock.patch.object(sys, "platform", "win32"), mock.patch.dict(os.environ, {"APPDATA": "C:/Roaming"}):
            self.assertEqual(folder("root.crt"), os.path.join("C:/Roaming", "postgresql", "root.crt"))
            del os.environ["APPDATA"]
            self.assertIsNone(folder("root.crt"))
        if sys.platform == "win32":
            return
        import pwd

        with mock.patch.dict(os.environ, {"HOME": ""}):
            self.assertEqual(
                folder("root.crl"), os.path.join(pwd.getpwuid(os.geteuid()).pw_dir, ".postgresql", "root.crl")
            )
            with mock.patch("pwd.getpwuid", side_effect=KeyError(os.geteuid())):
                self.assertIsNone(folder("root.crt"))
                port, seen = self.server(tls=True)
                with self.assertRaisesRegex(self.pgwire.ProtocolError, "^no home folder to find root.crt in: give it"):
                    self.pgwire.connect(host="127.0.0.1", port=port, sslmode="verify-ca", timeout=5)
                self.assertNotIn("start", seen)

    def test_a_certificate_channel_binding_has_no_hash_for(self) -> None:
        # (Ed25519's signature names none): with SCRAM-SHA-256-PLUS offered, the exchange can't be bound, and is
        # refused before anything is sent, as libpq refuses it, whatever channel_binding (but disable) says
        for binding in ("prefer", "require"):
            port, seen = self.server(tls=True, scram="plus")
            with (
                mock.patch.object(self.pgwire, "_end_point", return_value=None),
                self.assertRaisesRegex(
                    self.pgwire.ProtocolError, "^the server's certificate is signed in a way channel"
                ),
            ):
                self.pgwire.connect(host="127.0.0.1", port=port, password="secret", channel_binding=binding, timeout=5)
            self.assertEqual(self.sent(seen), b"", binding)

    def test_target_session_attrs_as_libpq_checks_it(self) -> None:
        # one host, checked once signed in: from what the server said as the session started, else by asking it
        rw = {"default_transaction_read_only": "off", "in_hot_standby": "off"}
        ro = {"default_transaction_read_only": "on", "in_hot_standby": "off"}
        standby = {"default_transaction_read_only": "off", "in_hot_standby": "on"}
        show, recovery = "SHOW transaction_read_only", "SELECT pg_catalog.pg_is_in_recovery()"
        for wanted, params, answer, said, asked in (
            ("read-write", rw, None, None, None),
            ("read-write", ro, None, "session is read-only", None),
            ("read-write", standby, None, "session is read-only", None),
            ("read-only", rw, None, "session is not read-only", None),
            ("read-only", standby, None, None, None),
            ("primary", standby, None, "server is in hot standby mode", None),
            ("primary", ro, None, None, None),
            ("standby", rw, None, "server is not in hot standby mode", None),
            ("prefer-standby", rw, None, None, None),
            ("any", standby, None, None, None),
            ("read-write", {}, ("on", 25), "session is read-only", show),
            ("read-only", {"in_hot_standby": "off"}, ("on", 25), None, show),
            ("standby", {}, ("t", 16), None, recovery),
            ("primary", {}, ("t", 16), "server is in hot standby mode", recovery),
        ):
            port, seen = self.server(tls=False, params=params, answer=answer)
            dsn = f"host=127.0.0.1 port={port} sslmode=disable target_session_attrs={wanted}"
            if said:
                with self.assertRaisesRegex(self.pgwire.ProtocolError, f"^{said}$", msg=(wanted, params)):
                    self.pgwire.connect(**self.pgwire.parse_dsn(dsn))
            else:
                self.pgwire.connect(**self.pgwire.parse_dsn(dsn)).close()
            self.assertEqual(seen.get("query"), asked, (wanted, params))

    def test_each_libpq_setting_is_honoured_left_alone_or_refused(self) -> None:
        p, parse = self.pgwire, self.pgwire.parse_dsn
        # every one of libpq's settings is in exactly one list (passfile: refused only without a password)
        groups = [p.HONOURED, set(p.IGNORED), set(p.ONLY), set(p.REFUSED), {"passfile"}]
        self.assertEqual(sorted(p.LIBPQ), sorted(set().union(*groups)))
        self.assertEqual(sum(len(g) for g in groups), len(p.LIBPQ))
        # left alone, from a keyword string too: what they change is neither what is checked nor where it connects
        got = parse(
            "host=h application_name=x keepalives=1 sslsni=0 gssencmode=disable sslcertmode=allow "
            "min_protocol_version=3.0 sslnegotiation=postgres replication=off load_balance_hosts=random"
        )
        self.assertEqual(got["host"], "h")
        # refused, naming the setting or the variable that gave it
        for dsn, env, said in (
            ("host=h hostaddr=10.0.0.1", {}, "a host address apart from its name (hostaddr=10.0.0.1)"),
            ("postgresql://h/d?hostaddr=10.0.0.1", {}, "a host address apart from its name (hostaddr=10.0.0.1)"),
            ("host=h", {"PGHOSTADDR": "10.0.0.1"}, "a host address apart from its name (PGHOSTADDR=10.0.0.1)"),
            ("host=h", {"PGSERVICE": "prod"}, "connection services (PGSERVICE=prod)"),
            ("service=prod", {}, "connection services (service=prod)"),
            ("host=h", {"PGSSLCERT": "c.crt"}, "client certificates (PGSSLCERT=c.crt)"),
            ("host=h", {"PGREQUIREPEER": "postgres"}, "requirepeer (PGREQUIREPEER=postgres)"),
            ("postgresql://h/d?gssencmode=require", {}, "GSS encryption (gssencmode=require)"),
            ("host=h", {"PGGSSENCMODE": "require"}, "GSS encryption (PGGSSENCMODE=require)"),
            ("host=h", {"PGSSLCERTMODE": "require"}, "a client certificate (PGSSLCERTMODE=require)"),
            ("postgresql://h/d?sslnegotiation=direct", {}, "TLS without asking the server first (sslnegotiation"),
            ("postgresql://h/d?oauth_client_id=x", {}, "OAuth (oauth_client_id=x)"),
            # a secret's value isn't repeated
            ("host=h scram_client_key=a2V5", {}, "SCRAM keys in place of the password (scram_client_key), which"),
            ("host=h scram_server_key=a2V5", {}, "SCRAM keys in place of the password (scram_server_key), which"),
            ("postgresql://h/d?oauth_client_secret=a2V5", {}, "OAuth (oauth_client_secret), which the rowstile"),
            ("host=h replication=database", {}, "a replication connection (replication=database)"),
            ("host=h", {"PGMINPROTOCOLVERSION": "3.2"}, "a protocol version above 3.0 (PGMINPROTOCOLVERSION=3.2)"),
            ("host=h", {"PGPASSFILE": "/p"}, "a password file (PGPASSFILE=/p)"),
            ("host=h passfile=/p", {}, "a password file (passfile=/p)"),
            (
                "host=h ssl_min_protocol_version=TLSv1 ssl_max_protocol_version=TLSv1.1",
                {},
                "TLS older than TLSv1.2 (ssl_max_protocol_version=TLSv1.1)",
            ),
        ):
            with (
                mock.patch.dict(os.environ, env),
                self.assertRaisesRegex(ValueError, re.escape(said), msg=dsn) as caught,
            ):
                parse(dsn)
            self.assertNotIn("a2V5", str(caught.exception), dsn)
        for dsn, said in (
            ("host=h ssl_min_protocol_version=TLSv9", 'invalid "ssl_min_protocol_version" value: "TLSv9"'),
            (
                "host=h ssl_min_protocol_version=TLSv1.3 ssl_max_protocol_version=TLSv1.2",
                "invalid SSL protocol version",
            ),
            ("host=h ssl_max_protocol_version=TLSv1.1", "invalid SSL protocol version range"),  # the minimum is 1.2
            ("host=h target_session_attrs=primaryish", 'invalid target_session_attrs value: "primaryish"'),
        ):
            with self.assertRaisesRegex(ValueError, re.escape(said), msg=dsn):
                parse(dsn)
        # a password file is no matter where the password is given: libpq reads it only without one
        with mock.patch.dict(os.environ, {"PGPASSFILE": "/p"}):
            self.assertEqual(parse("host=h password=x")["password"], "x")
        # honoured from the variables too
        with mock.patch.dict(
            os.environ, {"PGCONNECT_TIMEOUT": "7", "PGREQUIRESSL": "1", "PGTARGETSESSIONATTRS": "standby"}
        ):
            got = parse("host=h")
            self.assertEqual((got["timeout"], got["sslmode"], got["target_session_attrs"]), (7.0, "require", "standby"))
            self.assertEqual(parse("host=h sslmode=disable")["sslmode"], "disable")  # what the string says comes first
        self.assertEqual(parse("host=h requiressl=1")["sslmode"], "require")  # libpq's old name for it
        # what libpq sends with its start-up from PGDATESTYLE, PGTZ and PGGEQO (not "default"), so does this client
        with mock.patch.dict(os.environ, {"PGDATESTYLE": "ISO, DMY", "PGTZ": "UTC", "PGGEQO": "default"}):
            port, seen = self.server(tls=False)
            self.pgwire.connect(**parse(f"host=127.0.0.1 port={port} sslmode=disable")).close()
        self.assertEqual(
            (
                self.started_with(seen, b"datestyle"),
                self.started_with(seen, b"timezone"),
                self.started_with(seen, b"geqo"),
            ),
            (b"ISO, DMY", b"UTC", None),
        )


class TestFiles(unittest.TestCase):
    """Named tests in files of their own (rowstile.toml's tests): a mistake there is named with its file and line,
    and so are a test named as one the policy has, and a test about a type the policy lacks."""

    POLICY = (
        "app role app_user\ntype user = app.users\ntype doc = app.docs\n  owner : user = owner_id\n  can view = owner\n"
        "rules app.docs\n  select : view\n"
    )

    def test_what_a_test_file_is_refused_for(self) -> None:
        for policy, body, said in (
            ("", 'test "a"\n  user 1 cann view doc 1\n', "t.authz line 2: a test's lines are:"),
            (
                'test "a"\n  user 1 can view doc 1\n',
                'test "a"\n  user 1 can view doc 1\n',
                "t.authz line 1: there is already a test named 'a'",
            ),
            ("", 'test "a"\n  user 1 can view nothing 1\n', "t.authz line 2: unknown type 'nothing'"),
        ):
            c = Compiler(parse_policy(self.POLICY + policy, "p.authz"))
            with self.assertRaisesRegex(PolicyError, re.escape(said)):
                c.add_test_files({"t.authz": body})
                c.check_scenarios()


class CompilePolicy(unittest.TestCase):
    """compile_policy.py, the suites' compiler without a database: one mode at a time, a flag it doesn't know or
    a flag's value missing is refused (exit 2) rather than read as something else, and a file it can't read is
    named, whichever it is."""

    POLICY = TestFiles.POLICY

    def setUp(self) -> None:
        import compile_policy

        self.cp = compile_policy

    def run_main(self, argv: list[str]) -> tuple[int, str, str]:
        import contextlib

        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                rc = self.cp.main(argv)
            except SystemExit as stop:
                rc = stop.code if isinstance(stop.code, int) else 1
        return rc, out.getvalue(), err.getvalue()

    def test_what_each_command_line_reads_as(self) -> None:
        o = self.cp.Options
        for argv, read in (
            (["p.authz"], o("p.authz", "compile", [], None)),
            (["--check", "/dev/stdin"], o("/dev/stdin", "check", [], None)),
            (["p.authz", "--tests"], o("p.authz", "tests", [], None)),
            (["p.authz", "--tests", "a.authz", "b.authz"], o("p.authz", "tests", ["a.authz", "b.authz"], None)),
            (["p.authz", "--diff"], o("p.authz", "diff", [], None)),
            (["p.authz", "--diff", "--users", "1,,service:7"], o("p.authz", "diff", [], ["1", "service:7"])),
        ):
            with self.subTest(argv=argv):
                self.assertEqual(self.cp.options(argv), read)

    def test_a_command_line_it_cant_read_one_way_is_refused(self) -> None:
        for argv, said in (
            (["p.authz", "--users", "--diff"], "--users: expected one argument"),
            (["p.authz", "--test"], "unrecognized arguments: --test"),
            (["p.authz", "--graph"], "unrecognized arguments: --graph"),
            (["p.authz", "--client", "ts"], "unrecognized arguments: --client ts"),
            (["p.authz", "--diff", "--tests"], "not allowed with argument"),
            (["p.authz", "--check", "--diff"], "not allowed with argument"),
            (["p.authz", "--users", "1,2"], "--users only goes with --diff"),
            (["p.authz", "q.authz"], "unrecognized arguments: q.authz"),
            ([], "the following arguments are required: policy"),
        ):
            with self.subTest(argv=argv):
                rc, out, err = self.run_main(argv)
                self.assertEqual((rc, out), (2, ""))
                self.assertIn(said, err)
                self.assertIn("usage: compile_policy.py", err)

    def test_check_only_reports_a_mistake(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            broken = os.path.join(d, "broken.authz")
            with open(broken, "w", encoding="utf-8") as fh:
                fh.write(self.POLICY.replace("owner : user", "owner : person"))
            rc, out, err = self.run_main([broken, "--check"])
            self.assertEqual((rc, out), (1, ""))
            self.assertRegex(err, rf"^{re.escape(broken)}: line 4: .+\n$")
        rc, out, err = self.run_main([os.path.join(ROOT, "example", "docs.authz"), "--check"])
        self.assertEqual((rc, err), (0, ""))
        self.assertEqual(out, f"{os.path.join(ROOT, 'example', 'docs.authz')}: ok\n")

    def test_a_file_it_cant_read_is_the_one_named(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            policy, bad, missing = (os.path.join(d, n) for n in ("p.authz", "bad.authz", "missing.authz"))
            with open(policy, "w", encoding="utf-8") as fh:
                fh.write(self.POLICY)
            with open(bad, "wb") as fh:
                fh.write(b'test "a"\n  \xff\n')
            for argv, said in (
                ([policy, "--tests", bad], f"{bad}: not UTF-8: "),
                ([policy, "--tests", missing], f"{missing}: No such file or directory"),
                ([bad], f"{bad}: not UTF-8: "),
                ([missing], f"{missing}: No such file or directory"),
            ):
                with self.subTest(argv=argv):
                    rc, out, err = self.run_main(argv)
                    self.assertEqual((rc, out), (2, ""))
                    self.assertTrue(err.startswith(said), err)


class Readers(unittest.TestCase):
    """authzlib/connection.py's typed readers of a row: a value of another type than asked is a TypeError that says
    which value and what was wanted (a boolean is no integer)."""

    def test_a_value_of_another_type_is_said(self) -> None:
        from authzlib import connection as c

        row: Row = {"n": 1, "s": "x", "b": True, "z": None}
        self.assertEqual(
            (c.text(row, "s"), c.text_or_none(row, "z"), c.number(row, "n"), c.flag(row, "b")), ("x", None, 1, True)
        )
        for read, key, said in (
            (c.text, "n", "n is 1, not text"),
            (c.text_or_none, "n", "n is 1, not text or NULL"),
            (c.number, "b", "b is True, not an integer"),
            (c.flag, "n", "n is 1, not a boolean"),
        ):
            with self.assertRaisesRegex(TypeError, re.escape(said)):
                read(row, key)


class Fmt(unittest.TestCase):
    def test_a_line_continued_after_a_comment_hangs_under_its_expression(self) -> None:
        # an invariant's `and` on the line after a comment: under the expression, as it would be without the comment
        from authzlib.fmt import format

        head = (
            "app role app_user\n\ntype user = app.users\n\ntype org = app.orgs\n"
            "  member : user = app.org_members(org_id -> user_id)\n\ntype folder = app.folders\n"
            "  org   : org  = org_id\n  owner : user = owner_id\n  can share = owner\n\ninvariants\n"
        )
        src = head + "  never folder: share\n  -- whoever may share is in its org\n    and not org.member\n"
        want = head + "  never folder: share\n  -- whoever may share is in its org\n            and not org.member\n"
        self.assertEqual(format(src), want)

    def test_a_cascade_line(self) -> None:
        # one space between its words, before the key's columns and after each comma; a rule's ':' doesn't line up
        # with it
        from authzlib.fmt import format

        head = "app role app_user\n\ntype user = app.users\n\ntype doc = app.docs\n  owner : user = owner_id\n\n"
        src = (
            head
            + "rules app.docs\n  select : owner\n   cascade  from app.users(owner_id ,editor_id)\n  cascade from app.orgs\n"
        )
        want = (
            head
            + "rules app.docs\n  select : owner\n  cascade from app.users (owner_id, editor_id)\n  cascade from app.orgs\n"
        )
        self.assertEqual(format(src), want)
        self.assertEqual(format(want), want)

    def test_an_odd_layout(self) -> None:
        # blank lines first, a comment before a type, a condition and an expression continued on the next line
        from authzlib.fmt import format

        src = (
            "\n\napp role app_user\ntype user = app.users\n-- the documents\ntype doc = app.docs\n"
            "  owner : user = owner_id\n  can see = owner and {kind = 1\n      and size > 2}\n"
            "  can view = owner\n      or see\n"
        )
        want = (
            "app role app_user\n\ntype user = app.users\n\n-- the documents\ntype doc = app.docs\n"
            "  owner : user = owner_id\n  can see  = owner and {kind = 1\n         and size > 2}\n"
            "  can view = owner\n          or see\n"
        )
        self.assertEqual(format(src), want)
        self.assertEqual(format(want), want)

    def test_a_comment_inside_a_relation_or_at_the_end(self) -> None:
        # a comment line inside a relation's condition: what follows it lines up as it would without it, under the
        # subjects (no source) or the source; and a policy may end on a comment
        from authzlib.fmt import format

        src = (
            "app role app_user\ntype user = app.users\ntype doc = app.docs\n  owner : user = owner_id\n"
            "  editor : user shared if {a = 1\n  -- why\n and b = 2}\n"
            "  viewer : user = app.dv(doc_id -> user_id) where {c = 1\n  -- why\n and d = 2}\n-- the end\n"
        )
        want = (
            "app role app_user\n\ntype user = app.users\n\ntype doc = app.docs\n  owner  : user = owner_id\n"
            "  editor : user shared if {a = 1\n  -- why\n       and b = 2}\n"
            "  viewer : user = app.dv(doc_id -> user_id) where {c = 1\n  -- why\n              and d = 2}\n"
            "-- the end\n"
        )
        self.assertEqual(format(src), want)

    def test_every_policy_formats_the_same_twice_and_says_the_same(self) -> None:
        from authzlib.fmt import format
        from authzlib.migrate import meaning_lines

        for rel in list(POLICIES.values()) + [
            "example/docs.test.authz",
            "../docs/cookbook/sharing-and-links/policy.authz",
            "../examples/filemanager/db/policy.authz",
            "../examples/messenger/db/policy.authz",
        ]:
            text = read(rel)
            once = format(text)
            self.assertEqual(format(once), once, rel)
            self.assertEqual(meaning_lines(once, {}), meaning_lines(text, {}), rel)

    def test_the_format(self) -> None:
        from authzlib.fmt import format

        got = format(
            "app role app_user\ntype user = app.users\n\n\n\ntype doc = app.docs\n  owner : user = owner_id  -- who\n"
            "  editor:user   shared\n  can edit = owner or editor\n  can  view=   edit\n     or owner\n"
            "rules app.docs\n  select : view\n  update after : edit\n"
        )
        self.assertEqual(
            got,
            "app role app_user\n\ntype user = app.users\n\ntype doc = app.docs\n"
            "  owner  : user = owner_id  -- who\n  editor : user shared\n"
            "  can edit = owner or editor\n  can view = edit\n          or owner\n\n"
            "rules app.docs\n  select       : view\n  update after : edit\n",
        )

    BASE = (
        "app role app_user\n\ntype user = app.users\n\ntype doc = app.docs\n  owner : user = owner_id\n"
        "  can view = owner\n\nrules app.docs\n  select : view\n"
    )

    def test_tests_come_out_saying_the_same(self) -> None:
        from authzlib.fmt import format, tests_of

        for name, tests in {
            "a brace in a string": "\ntest \"one\"\n  as user 1 allowed {UPDATE app.docs SET name = '{' WHERE id = 1}\n"
            '\ntest "two"\n  user 1 can view doc 1\n',
            "names that differ by their spaces": '\ntest "a  b"\n  user 1 can view doc 1\n\ntest "a b"\n  user 1 cannot view doc 1\n',
            "a name with --": '\ntest "before -- after"  -- a comment\n  user 1 can view doc 1\n',
        }.items():
            text = self.BASE + tests
            done = format(text)
            self.assertEqual(tests_of(done, {}), tests_of(text, {}), name)
            self.assertEqual(format(done), done, name)
            Compiler(parse_policy(done, None, files={})).compile("the policy")  # it still compiles
        self.assertIn('test "a  b"', format(self.BASE + '\ntest "a  b"\n  user 1 can view doc 1\n'))
        self.assertIn(
            "{name <> '{'}", format(self.BASE.replace("can view = owner", "can view = owner and {name <> '{'}"))
        )

    def test_what_compiles_formats(self) -> None:
        from authzlib.fmt import FormatError, format

        for word in ("role", "type", "scope", "test"):  # relations may have these names
            text = self.BASE.replace("owner", word)
            self.assertEqual(format(text), text, word)
        self.assertEqual(format(self.BASE.replace("can view", "can\tview")), self.BASE)  # (a tab after can)
        commented = self.BASE.replace("can view = owner", "can view = owner and {/* the owner's } */ true}")
        self.assertEqual(format(commented), commented)
        with_include = 'include "roles.authz"\n\n' + self.BASE
        self.assertEqual(format(with_include, {"roles.authz": "-- nothing here\n"}), with_include)
        with self.assertRaisesRegex(FormatError, "AZ104"):  # a mistake: its message, not an assertion
            format(self.BASE.replace("can view = owner", "can view"))

    def test_a_type_continued_on_the_next_line(self) -> None:
        # a type's where on the line below its type: it hangs so that the condition starts under the table
        from authzlib.fmt import format

        src = self.BASE.replace("type doc = app.docs\n", "type doc = app.docs\n    where {not archived}\n")
        want = self.BASE.replace("type doc = app.docs\n", "type doc = app.docs\n     where {not archived}\n")
        self.assertEqual(format(src), want)
        self.assertEqual(format(want), want)

    def test_comments_stay_and_a_comment_inside_an_expression_moves_nothing(self) -> None:
        # a comment at the end of a block's first line, of the line continuing it, and a comment line between an
        # expression's lines: each kept, and what follows still hangs under the expression
        from authzlib.fmt import format

        src = self.BASE.replace(
            "type doc = app.docs\n", "type doc = app.docs  -- the documents\n    where {not archived}  -- live ones\n"
        ).replace("  can view = owner\n", "  can view = owner\n  -- or a team's\n    or {public}\n")
        want = self.BASE.replace(
            "type doc = app.docs\n", "type doc = app.docs  -- the documents\n     where {not archived}  -- live ones\n"
        ).replace("  can view = owner\n", "  can view = owner\n  -- or a team's\n          or {public}\n")
        self.assertEqual(format(src), want)
        self.assertEqual(format(want), want)

    def test_a_continuation_at_the_start_of_its_line_hangs_too(self) -> None:
        # the parser reads a line that starts with or (and, where, if, grant) as the line before it continued,
        # however little it is indented: it hangs under the expression like any other, with no blank line before it
        from authzlib.fmt import format

        want = self.BASE.replace("  can view = owner\n", "  can view = owner\n          or {public}\n")
        self.assertEqual(format(self.BASE.replace("  can view = owner\n", "  can view = owner\nor {public}\n")), want)

    def test_a_layout_that_would_change_what_the_policy_says_is_refused(self) -> None:
        # the layout is read back before it is written: a bug in it that changed a declaration, or a test, is refused
        from authzlib import fmt

        text = self.BASE + '\ntest "x"\n  user 1 can view doc 1\n'
        for old, new in (("can view = owner", "can view = owner or {true}"), ("can view doc 1", "cannot view doc 1")):
            with (
                mock.patch.object(fmt, "format_policy", lambda t, old=old, new=new: t.replace(old, new)),
                self.assertRaisesRegex(
                    fmt.FormatError, r"^formatting would change what the policy says \(a bug in rowstile fmt"
                ),
            ):
                fmt.format(text)
        self.assertEqual(fmt.format(text), text)  # (the layout itself says the same)

    def test_a_layout_that_does_not_parse_is_fmts_mistake_not_the_policys(self) -> None:
        # the policy is read before it is laid out: only a policy that doesn't parse is told so
        from authzlib import fmt

        text = self.BASE + '\ntest "x"\n  user 1 can view doc 1\n'
        with (
            mock.patch.object(fmt, "format_policy", lambda t: t.replace("doc 1\n", "doc\n")),  # (a test's line)
            self.assertRaisesRegex(fmt.FormatError, r"^formatting would change what the policy says \(a bug"),
        ):
            fmt.format(text)
        with self.assertRaisesRegex(fmt.FormatError, r"^can't format a policy that doesn't parse: .*AZ104"):
            fmt.format(self.BASE.replace("can view = owner", "can view"))

    def test_a_line_that_starts_with_dashes_inside_a_quote_is_no_comment(self) -> None:
        # a string, a name or a dollar quote left open on the line before goes on: its -- is in the quote, and the
        # line is laid out as the condition's next line
        from authzlib.fmt import format
        from authzlib.parse import meaning_lines

        for quote, close in (("'", "'"), ('"', '"'), ("$$", "$$")):
            src = self.BASE.replace(
                "  can view = owner\n", f"  can view = owner and {{x <> {quote}a\n-- b{close} or y}}\n"
            )
            want = self.BASE.replace(
                "  can view = owner\n", f"  can view = owner and {{x <> {quote}a\n             -- b{close} or y}}\n"
            )
            self.assertEqual(format(src), want, quote)
            self.assertEqual(format(want), want, quote)
            self.assertIn(f"type doc: can view = owner and {{x <> {quote}a -- b{close} or y}}", meaning_lines(want, {}))

    def test_spaces_inside_a_quote_are_what_the_policy_says(self) -> None:
        # a run of spaces counts inside a string or a name, not between words: the lock file's lines and fmt's
        # check see a layout that changed one
        from authzlib import fmt
        from authzlib.parse import meaning_lines

        def view(cond: str) -> list[str]:
            return meaning_lines(self.BASE.replace("can view = owner", f"can view = owner and {cond}"), {})

        self.assertNotEqual(view("{name <> 'a   b'}"), view("{name <> 'a b'}"))
        self.assertNotEqual(view('{"a   b" = 1}'), view('{"a b" = 1}'))
        self.assertNotEqual(view("{name <> $$a   b$$}"), view("{name <> $$a b$$}"))
        self.assertEqual(view("{name  <>\t'a b'   or  x}"), view("{name <> 'a b' or x}"))
        self.assertIn("type doc: can view = owner and {name <> 'a   b'}", view("{name   <>   'a   b'}"))
        text = self.BASE.replace("can view = owner", "can view = owner and {name <> 'a   b'}")
        self.assertEqual(fmt.format(text), text)
        with (
            mock.patch.object(fmt, "format_policy", lambda t: t.replace("'a   b'", "'a b'")),
            self.assertRaisesRegex(fmt.FormatError, r"^formatting would change what the policy says \(a bug"),
        ):
            fmt.format(text)


class Confidence(unittest.TestCase):
    """rowstile prove (invariants in small worlds) and coverage (branches no test makes true)."""

    def test_prove_finds_the_smallest_counterexample(self) -> None:
        from authzlib import prove

        pol = parse_policy(read(POLICIES["docs"]), "docs.authz")
        [r] = prove.prove(pol)
        # a folder's owner may share it even if they aren't in its org: the data never has that, the policy allows it
        self.assertFalse(r["holds"])
        self.assertEqual((r["who"], r["type"]), ("1", "folder"))
        self.assertEqual(r["world"], ["user: 1", "folder: 1", "folder.owner: folder 1 -> user 1"])
        self.assertIn("no   user 1 holds it on folder 1", prove.describe([r]))

    def test_a_counterexample_shows_the_types_it_uses(self) -> None:
        # the rows of the types it names: the invariant's, the holder's (none for someone not signed in), and those a
        # link goes to, though the type is named nowhere else
        from authzlib import prove

        def world(body: str, invariant: str) -> tuple[str | None, list[str] | None]:
            [r] = prove.prove(parse_policy(self.HEAD + body + f"invariants\n  never doc: {invariant}\n", "p.authz"))
            return r.get("who"), r.get("world")

        self.assertEqual(
            world("type doc = app.docs\n  owner : user = owner_id\n  can view = {public} and not signed_in\n", "view"),
            ("nobody", ["doc: 1", "doc 1: public = true"]),
        )
        self.assertEqual(
            world(
                "type org = app.orgs\n  can see = signed_in\ntype doc = app.docs\n  owner : user = owner_id\n"
                "  org : org = org_id\n  can view = org.see\n",
                "view and not owner",
            ),
            ("1", ["user: 1", "org: 1", "doc: 1", "doc.org: doc 1 -> org 1"]),
        )

    def test_prove_on_the_multi_tenant_recipe_is_as_its_page_says(self) -> None:
        # docs/cookbook/multi-tenant-app.md: admins read from the members' table with a where are members, so
        # `can view = member` holds too; admins from a table of their own may be no member, and prove finds one
        from authzlib import prove

        text = read("../docs/cookbook/multi-tenant-app/policy.authz")
        member = text.replace("can view   = manage or member", "can view   = member")
        own = member.replace(
            "app.org_members(org_id -> user_id) where {role = 'admin'}", "app.org_admins(org_id -> user_id)"
        )
        self.assertNotEqual(member, text)
        self.assertNotEqual(own, member)
        held = [prove.prove(parse_policy(t, "policy.authz"))[0]["holds"] for t in (text, member, own)]
        self.assertEqual(held, [True, True, False])

    def test_prove_says_when_none_is_found(self) -> None:
        from authzlib import evaluate, prove

        text = read(POLICIES["docs"]).replace(
            "never folder: share and not org.member", "never folder: edit and not view"
        )
        pol = parse_policy(text, "docs.authz")
        [r] = prove.prove(pol, worlds=80)
        self.assertTrue(r["holds"])
        # the 80 drawn, each corner 3 times at each of the 4 sizes, and the worlds a draw rarely makes
        rare = list(evaluate.rare_worlds([pol], 80, "0"))
        self.assertEqual(r["worlds"], 80 + 3 * 4 * len(evaluate.corners([pol])) + len(rare))
        # the docs read 3 links deep (a file's folder's org's admins, a team's): a dozen chains of 5
        self.assertEqual(len(rare), evaluate.dense_worlds(80) + 12)
        self.assertEqual((evaluate.reach([pol]), r.get("size")), (3, 5))

    def test_prove_finds_a_counterexample_that_needs_conditions_at_once(self) -> None:
        # a t3 holds p3 through its t1, where {b1 and b2} must hold, and the invariant asks {b1} on the t3 too: a
        # world drawn row by row has that one time in hundreds (the first found was the 191st world), a corner at
        # once (found by a soak, where 200 worlds said it holds)
        from authzlib import prove

        [r] = prove.prove(
            parse_policy(
                self.HEAD + "type t1 = app.t1\n  r1 : user = c_r1\n  parent : t1 = parent_id\n  can p2 = r1\n"
                "  can p3 = parent.p2 and {b1 and b2}\ntype t3 = app.t3\n  up : t1 = c_up\n  can p3 = up.p3\n"
                "invariants\n  never t3: p3 and {b1}\n",
                "p.authz",
            ),
            worlds=200,
        )
        self.assertFalse(r["holds"])
        self.assertLessEqual(r["worlds"], 20)
        self.assertEqual(r["world"][:3], ["user: 1", "t1: 1", "t3: 1"])

    def test_simple_conditions_read_names_and_numbers_as_postgres_does(self) -> None:
        from authzlib.conditions import Bool, Cmp, Col, Const, simple, truth

        # a quoted name keeps its case and its doubled quotes; a bare one is in lower case
        self.assertEqual(simple('"B1" and "order"'), Bool("and", (Col("B1"), Col("order"))))
        self.assertEqual(simple('not "archived"'), Bool("not", (Col("archived"),)))
        self.assertEqual(simple('this."a""b" = 1'), Cmp("=", Col('a"b'), Const(1)))
        self.assertEqual(simple('Done or "Done"'), Bool("or", (Col("done"), Col("Done"))))
        # a decimal exactly, as numeric reads it, where a numeric, a double precision and a real column all hold it
        # as written (1.50, 0.25), and the values the worlds draw around it (one less, one more, two past); any other
        # is the database's: a real column holds 0.1 as 0.100000001 and 16777217 as 16777216, a double precision one
        # 1.00000000000000001 as 1
        self.assertEqual(simple("price >= 1.50"), Cmp(">=", Col("price"), Const(Decimal("1.50"))))
        node = simple("price > 0.25")
        assert node is not None
        self.assertEqual([truth(node, {"price": Decimal(v)}, None) for v in ("0.25", "0.2500000001")], [False, True])
        for sql in ("price > 0.1", "price >= 1.10", "price = 1.00000000000000001", "price < 16777217"):
            self.assertIsNone(simple(sql), sql)
        # 2^24 itself a real column holds, but not 2^24 + 1, which the worlds draw beside it: 2^24 - 2 is the last
        self.assertEqual([simple(f"price < {n}") is None for n in (16777214, 16777215, 16777216)], [False, True, True])
        # one that ends on a `not` (as `x not in (...)` begins) is none the evaluator reads: never a crash
        self.assertIsNone(simple("archived not"))
        # up to 15 digits written (1 + 2^-14, its neighbours held by every column), not 16 (1 + 2^-15); and null
        self.assertEqual(simple("price < 1.00006103515625"), Cmp("<", Col("price"), Const(Decimal("1.00006103515625"))))
        self.assertIsNone(simple("price < 1.000030517578125"))
        self.assertEqual(simple("price = null"), Cmp("=", Col("price"), Const(None)))
        # a digit past ASCII is a letter to Postgres: `size > ٣` compares two columns
        self.assertIsNone(simple("size > \u0663"))
        self.assertEqual(simple("size > 3"), Cmp(">", Col("size"), Const(3)))

    def test_texts_a_column_may_hold_as_one_value(self) -> None:
        from authzlib.conditions import alike

        # each pair one value to a collation ICU makes from its root (und-u-ks-level1, -ks-level2, -ka-shifted, -kn)
        # or to a type (char(n), date, tsvector)
        for a, b in (
            ("a", "A"),
            ("cafe", "café"),
            ("ab", "a-b"),
            ("ab", "a b"),
            ("a1", "a01"),
            ("ae", "æ"),
            ("o", "ø"),
            ("l", "ł"),
            ("ss", "ß"),
            ("a", "a\u00ad"),
            ("a", "\uff41"),
            ("a", "a "),
            ("2024-01-01", "2024-1-1"),
            ("now", "today"),
            ("epoch", "1970-01-01"),
            ("a b", "b a"),
            ("draft", "draft"),  # the same text, first of all
        ):
            self.assertTrue(alike(a, b), (a, b))
        # words no collation of that kind holds alike: the evaluator reads them as two values
        for a, b in (
            ("draft", "published"),
            ("admin", "member"),
            ("publié", "brouillon"),
            ("v1", "admin"),
            ("ab", "ba"),
        ):
            self.assertFalse(alike(a, b), (a, b))

    def test_prove_leaves_texts_a_column_may_hold_alike_to_the_database(self) -> None:
        """{status = 'Public'} and {status = 'public'} were read as two values, so prove said an invariant held that
        a case-insensitive column breaks (a row 'public' equals both). Texts that may be one value are the
        database's to read, drawn as rows of their own; different words are still read as two."""
        from authzlib import prove

        def check(view: str, other: str) -> prove.Proof:
            [r] = prove.prove(
                parse_policy(
                    self.HEAD + f"type doc = app.docs\n  owner : user = owner_id\n  can view = owner or {{{view}}}\n"
                    f"invariants\n  never doc: view and {{{other}}} and not owner\n",
                    "p.authz",
                ),
                worlds=80,
            )
            return r

        r = check("status = 'Public'", "status = 'public'")
        self.assertFalse(r["holds"])
        self.assertIn("{status = 'Public'} holds for doc 1", r["world"])
        self.assertIn("{status = 'public'} holds for doc 1", r["world"])
        self.assertTrue(check("status = 'published'", "status = 'draft'")["holds"])
        self.assertTrue(check("status in ('a', 'b')", "status not in ('a', 'b')")["holds"])

    def test_prove_reads_quoted_columns_and_long_decimals_as_postgres_does(self) -> None:
        """A quoted column was a condition prove couldn't read, so {"done"} and {not "done"} were drawn apart and
        both held on one row; a decimal was read as a float, so {price = 1.00000000000000001} held where
        {price = 1} did, which a numeric column never has."""
        from authzlib import prove

        def check(perms: str, invariant: str) -> prove.Proof:
            [r] = prove.prove(
                parse_policy(
                    self.HEAD + f"type file = app.files\n  owner : user = owner_id\n{perms}"
                    f"invariants\n  never file: {invariant}\n",
                    "p.authz",
                ),
                worlds=80,
            )
            return r

        r = check('  can view = owner and {"done"}\n  can edit = owner and {not "done"}\n', "view and edit")
        self.assertTrue(r["holds"], r.get("world"))
        r = check(
            "  can view = owner and {price = 1}\n  can edit = owner and {price = 1.00000000000000001}\n",
            "view and edit",
        )
        # the database's to read: drawn as rows of its own, so a counterexample names it held, not price = 1 alone
        self.assertFalse(r["holds"])
        self.assertIn("{price = 1.00000000000000001} holds for file 1", r["world"])

    def test_the_evaluator_reads_the_rows_of_the_data_it_is_given(self) -> None:
        # the column values it reads for a world were kept by the world's id(): once that world was gone, another
        # could be made at its address and read the first one's rows (prove counted a counterexample that wasn't).
        # Every id the same here: the rows must still be the second world's
        from unittest import mock

        from authzlib import evaluate

        pol = parse_policy(self.HEAD + "type doc = app.docs\n  can view = {published}\n", "p.authz")

        def world(published: bool) -> evaluate.Data:
            ids = {"user": ["1"], "doc": ["1"]}
            return evaluate.Data(
                ids=ids, valid=ids, columns={"user": {"1": {}}, "doc": {"1": {"published": published}}}
            )

        ref = evaluate.Reference(pol)
        with mock.patch.object(evaluate, "id", lambda _: 0, create=True):
            self.assertEqual(ref.evaluate(world(True), "1")[("doc", "view")], {"1"})
            self.assertEqual(ref.evaluate(world(False), "1")[("doc", "view")], set())

    HEAD = "app role app_user\ntype user = app.users\n"

    def proofs(self, text: str) -> list[bool]:
        from authzlib import prove

        return [r["holds"] for r in prove.prove(parse_policy(self.HEAD + text, "p.authz"))]

    def same(self, before: str, after: str) -> bool:
        from authzlib import evaluate

        return (
            evaluate.compare(parse_policy(self.HEAD + before, "a.authz"), parse_policy(self.HEAD + after, "b.authz"))
            is None
        )

    def test_a_widening_through_a_column_of_two_or_a_groups_column_is_found(self) -> None:
        # a column that names no single object by itself (a parent by two columns, a team whose members it names):
        # the worlds draw its links too, so the review finds a widening through it
        box = "type box = app.boxes (org_id, id)\n  owner : user = owner_id\n  parent : box = [org_id, parent_id]\n"
        self.assertFalse(self.same(box + "  can view = owner\n", box + "  can view = owner or parent.view\n"))
        team = (
            "type team = app.teams\n  member : user = app.team_members(team_id -> user_id)\n"
            "type doc = app.docs\n  owner : user = owner_id\n  crew : team#member = team_id\n"
        )
        self.assertFalse(self.same(team + "  can view = owner\n", team + "  can view = owner or crew\n"))

    def test_anyone_nobody_and_signed_in_are_the_same_on_every_row(self) -> None:
        folder = "type folder = app.folders\n  owner : user = owner_id\n  viewer : user = viewer_id\n"
        self.assertEqual(self.proofs(folder + "  can view = anyone\ninvariants\n  never folder: not view\n"), [True])
        self.assertEqual(self.proofs(folder + "  can view = nobody\ninvariants\n  never folder: view\n"), [True])
        self.assertEqual(
            self.proofs(folder + "  can view = signed_in\ninvariants\n  never folder: owner and not view\n"), [True]
        )
        self.assertEqual(
            self.proofs(folder + "  can view = signed_in\ninvariants\n  never folder: view and not owner\n"), [False]
        )
        for word in ("anyone", "signed_in"):
            self.assertTrue(
                self.same(folder + f"  can view = viewer or {word}\n", folder + f"  can view = {word}\n"), word
            )
        self.assertTrue(self.same(folder + "  can view = viewer or nobody\n", folder + "  can view = viewer\n"))
        self.assertFalse(
            self.same(folder + "  can view = signed_in\n", folder + "  can view = anyone\n")
        )  # nobody signed in

    def test_simple_conditions_are_facts_about_the_row(self) -> None:
        folder = "type folder = app.folders\n  owner : user = owner_id\n  parent : folder = parent_id\n"
        # two spellings of one condition, and a condition that says what a relation says
        self.assertTrue(
            self.same(
                folder + "  can view = owner and {not archived}\n",
                folder + "  can view = owner and {archived = false}\n",
            )
        )
        self.assertTrue(
            self.same(
                folder + "  can view = owner and {kind in ('a', 'b')}\n",
                folder + "  can view = owner and ({kind = 'a'} or {kind = 'b'})\n",
            )
        )
        self.assertTrue(
            self.same(
                folder + "  can view = owner\nrules app.folders\n  insert : {owner_id = authz.uid()}\n",
                folder + "  can view = owner\nrules app.folders\n  insert : owner\n",
            )
        )
        self.assertTrue(
            self.same(
                folder + "  can top = owner and {parent_id is null}\n",
                folder + "  can top = owner and {this.parent_id is null}\n",
            )
        )
        # NULL: {not archived} is false where archived is NULL, not {archived} is true there
        self.assertFalse(
            self.same(
                folder + "  can view = owner and {not archived}\n", folder + "  can view = owner and not {archived}\n"
            )
        )
        self.assertFalse(
            self.same(folder + "  can view = owner and {size > 10}\n", folder + "  can view = owner and {size >= 10}\n")
        )

    def test_prove_tries_what_a_counterexample_may_need(self) -> None:
        # two rows of a type; a number either side of a bound; a text no condition names; NULL
        doc = "type doc = app.docs\n  owner : user = owner_id\n  parent : doc = parent_id\n  can edit = owner\n"
        cases = [
            "  can view = owner or parent.view\ninvariants\n  never doc: view and not owner\n",
            "  can view = {size > 8}\ninvariants\n  never doc: view and {size < 10}\n",
            "  can view = {kind <> 'a'}\ninvariants\n  never doc: view and {kind <> 'b'}\n",
            "  can view = not {archived}\ninvariants\n  never doc: view and not {archived = false}\n",
        ]
        for case in cases:
            self.assertEqual(self.proofs(doc + case), [False], case)
        # the refactor check too: two rows, and a link presented
        self.assertFalse(self.same(doc + "  can view = owner or parent.view\n", doc + "  can view = owner\n"))
        shared = (
            "type doc = app.docs\n  owner : user = owner_id\n  viewer : link shared\n  can share = owner\n"
            "  can peek = viewer\n"
        )
        self.assertFalse(self.same(shared + "  can view = owner or viewer\n", shared + "  can view = owner\n"))
        # a permission only one side has is no refactor's business (the review says it is added or removed)
        self.assertTrue(self.same(doc + "  can view = owner\n", doc + "  can view = owner\n  can peek = edit\n"))
        self.assertTrue(self.same(doc + "  can view = owner\n  can peek = edit\n", doc + "  can view = owner\n"))

    def test_a_counterexample_is_shrunk_until_nothing_more_goes(self) -> None:
        from authzlib import prove

        # p is needed while {a} holds; once a is NULL, p can go too: a second pass
        pol = parse_policy(
            self.HEAD + "type doc = app.docs\n  p : user = p_id\n  q : user = q_id\n"
            "  can view = q and (not {a} or p)\n",
            "p.authz",
        )
        ref = evaluate.Reference(pol)
        ids = {"user": ["1"], "doc": ["1"]}
        data = evaluate.Data(
            ids=ids,
            valid=ids,
            pairs={("doc", "p", 0, "user", ""): [("1", "1")], ("doc", "q", 0, "user", ""): [("1", "1")]},
            columns={"user": {"1": {}}, "doc": {"1": {"a": True}}},
        )
        small = evaluate.smallest(data, lambda d: "1" in ref.evaluate(d, "1")[("doc", "view")])
        self.assertEqual(small.pairs, {("doc", "p", 0, "user", ""): [], ("doc", "q", 0, "user", ""): [("1", "1")]})
        self.assertEqual(small.columns["doc"]["1"], {"a": None})
        # a link taken away takes its column's value with it: owner_id = authz.uid() holds only while the owner
        # link is there, so the smallest world keeps it
        [r] = prove.prove(
            parse_policy(
                self.HEAD + "type doc = app.docs\n  owner : user = owner_id\n  can see = owner\n"
                "  can edit = {owner_id = authz.uid()}\ninvariants\n  never doc: edit\n",
                "p.authz",
            )
        )
        self.assertEqual(r["world"], ["user: 1", "doc: 1", "doc.owner: doc 1 -> user 1"])

    def test_a_counterexample_is_shrunk_through_conditions_and_roles(self) -> None:
        # what a condition the evaluator can't read as a fact passes, and what a custom role gives, go too when the
        # view still holds without them; and they stay when it needs them
        cond = "exists (select 1 from app.flags)"
        pol = parse_policy(
            self.HEAD + f"type doc = app.docs\n  q : user = q_id\n  roles : user\n  can view = q or {{{cond}}}\n"
            "  can edit = q or roles\n",
            "p.authz",
        )
        ref = evaluate.Reference(pol)
        ids = {"user": ["1"], "doc": ["1"]}
        q = ("doc", "q", 0, "user", "")
        role = ("doc", "edit", "user", "")
        data = evaluate.Data(
            ids=ids,
            valid=ids,
            pairs={q: [("1", "1")]},
            rolepairs={role: [("1", "1", "")]},
            cond={("doc", cond): ["1"]},
            columns={"user": {"1": {}}, "doc": {"1": {}}},
        )
        small = evaluate.smallest(data, lambda d: "1" in ref.evaluate(d, "1")[("doc", "view")])
        self.assertEqual(
            (small.cond, small.pairs, small.rolepairs), ({("doc", cond): []}, {q: [("1", "1")]}, {role: []})
        )
        small = evaluate.smallest(data, lambda d: "1" in ref.evaluate(d, "1")[("doc", "edit")])
        self.assertEqual(
            (small.cond, small.pairs, small.rolepairs), ({("doc", cond): []}, {q: []}, {role: [("1", "1", "")]})
        )

    def test_the_corners_set_a_denied_condition_false(self) -> None:
        # six conditions that must hold and two that mustn't, on one row: one row in 256 drawn row by row
        from authzlib import prove

        conds = " and ".join([*[f"{{b{i}}}" for i in range(1, 7)], "not {b7}", "not {b8}"])
        [r] = prove.prove(
            parse_policy(
                self.HEAD + f"type doc = app.docs\n  owner : user = owner_id\n  can view = owner and {conds}\n"
                "invariants\n  never doc: view\n",
                "p.authz",
            )
        )
        self.assertFalse(r["holds"])
        self.assertLessEqual(r["worlds"], 30)

    def test_a_counterexample_shows_the_columns_it_needs(self) -> None:
        from authzlib import prove

        folder = "type folder = app.folders\n  owner : user = owner_id\n  can view = owner\n"
        [r] = prove.prove(
            parse_policy(self.HEAD + folder + "invariants\n  never folder: view and {status = 'gone'}\n", "p.authz")
        )
        self.assertFalse(r["holds"])
        self.assertIn("folder 1: status = 'gone'", r["world"])
        self.assertIn("folder.owner: folder 1 -> user 1", r["world"])

    def test_a_counterexample_names_who_holds_it_and_the_types_between(self) -> None:
        # who holds it (a user, or a service by its type), with their row, and the types its links go through, with
        # theirs; no other type's rows
        from authzlib import prove

        def found(text: str) -> tuple[list[str], str]:
            [r] = prove.prove(parse_policy(self.HEAD + text + "invariants\n  never doc: view\n", "p.authz"))
            return r.get("world", []), prove.describe([r])

        world, said = found(
            "type bot = app.bots principal\ntype doc = app.docs\n  owner : user = owner_id\n"
            "  viewer : bot shared by edit\n  can edit = owner\n  can view = viewer\n"
        )
        self.assertEqual(world, ["bot: 1", "doc: 1", "doc.viewer: doc 1 -> bot 1"])
        self.assertIn("\n  no   bot 1 holds it on doc 1 in this world", said)
        # a user no link names: their row still
        world, _ = found("type doc = app.docs\n  can view = {public}\n")
        self.assertEqual(world, ["user: 1", "doc: 1", "doc 1: public = true"])
        # a team its members hold it through: the team's row, which only the link from it names
        world, _ = found(
            "type team = app.teams\n  member : user = app.team_members(team_id -> user_id)\n"
            "type doc = app.docs\n  viewer : team#member = app.doc_teams(doc_id -> team_id)\n  can view = viewer\n"
        )
        self.assertEqual(
            world,
            ["user: 1", "team: 1", "doc: 1", "doc.viewer: doc 1 -> team#member 1", "team.member: team 1 -> user 1"],
        )

    def test_a_counterexample_says_which_rows_the_types_where_keeps(self) -> None:
        # a row its type's where doesn't keep holds nothing: the world keeps what the where needs as it is made
        # smaller (active = true), and says which rows the where keeps, one the evaluator can't read too
        from authzlib import prove

        folder = (
            "type org = app.orgs\n  member : user = app.members(org_id -> user_id)\n"
            "type folder = app.folders\n  org : org = org_id\n  owner : user = owner_id\n  can share = owner\n"
            "invariants\n  never folder: share and not org.member\n"
        )
        opaque = "exists (select 1 from app.bans b where b.user_id = this.id) is false"
        for where, said in (
            ("active", ["user 1: active = true", "{active} holds for user 1 (the type's where)"]),
            (opaque, [f"{{{opaque}}} holds for user 1 (the type's where)"]),
        ):
            head = self.HEAD.replace("app.users\n", f"app.users where {{{where}}}\n")
            [r] = prove.prove(parse_policy(head + folder, "p.authz"))
            self.assertEqual(r.get("world"), ["user: 1", "folder: 1", *said, "folder.owner: folder 1 -> user 1"])
        # a team its members hold it through
        [r] = prove.prove(
            parse_policy(
                self.HEAD + "type team = app.teams where {not disbanded}\n"
                "  member : user = app.team_members(team_id -> user_id)\n"
                "type folder = app.folders\n  viewer : team#member = app.folder_teams(folder_id -> team_id)\n"
                "  can view = viewer\ninvariants\n  never folder: view\n",
                "p.authz",
            )
        )
        self.assertIn("team 1: disbanded = false", r.get("world", []))
        self.assertIn("{not disbanded} holds for team 1 (the type's where)", r.get("world", []))

    def test_a_link_to_every_user_reads_as_one(self) -> None:
        # a share to user:* is to every signed-in user, not to one: its subject is '*' in every world, as in
        # authz.shares, and the counterexample says user:*
        from authzlib import evaluate, prove

        text = (
            "type folder = app.folders\n  viewer : user:* shared\n  owner : user = owner_id\n  can share = nobody\n"
            "  can view = viewer\ninvariants\n  never folder: view and not owner\n"
        )
        pol = parse_policy(self.HEAD + text, "p.authz")
        [r] = prove.prove(pol)
        self.assertEqual(r.get("world"), ["user: 1", "folder: 1", "folder.viewer: folder 1 -> user:*"])
        roles = parse_policy(
            self.HEAD + "type doc = app.docs\n  admin : user = admin_id\n  roles : user:*\n"
            "  can manage_roles = admin\n  can view = roles\n",
            "p.authz",
        )
        held = set()
        for k in range(20):
            held |= {s for _, s in evaluate.World(f"s/{k}", 4).data(pol).pairs[("folder", "viewer", 0, "user", "*")]}
            held |= {s for _, s, _ in evaluate.World(f"s/{k}", 4).data(roles).rolepairs[("doc", "view", "user", "*")]}
        self.assertEqual(held, {"*"})

    def test_a_world_says_what_each_link_and_role_names(self) -> None:
        # who a link or a custom role is given to, as the policy writes it, and whose role it is; which rows a where
        # keeps, none here; and with types, only those types' rows
        from authzlib import evaluate

        pol = parse_policy(
            self.HEAD.replace("app.users\n", "app.users where {active}\n")
            + "type org = app.orgs\n  admin : user = admin_id\n  can manage_roles = admin\n"
            "type doc = app.docs\n  org : org = org_id\n  reader : anyone shared by view\n  roles : user, user:* from org\n"
            "  can view = roles\n  can edit = roles\n  can read = reader\n",
            "p.authz",
        )
        ids = {"user": ["1", "2"], "org": ["1"], "doc": ["1"]}
        data = evaluate.Data(
            ids=ids,
            valid={**ids, "user": []},
            pairs={("doc", "reader", 0, "anyone", ""): [("1", "*")], ("doc", "org", 0, "org", ""): []},
            rolepairs={
                ("doc", "edit", "user", ""): [],
                ("doc", "view", "user", ""): [("1", "2", "1")],
                ("doc", "view", "user", "*"): [("1", "*", "1")],
            },
            columns={"user": {"1": {"active": False}, "2": {}}},
        )
        lines = [
            "user 1: active = false",
            "{active} holds for no user (the type's where)",
            "doc.reader: doc 1 -> anyone",
            "doc.roles with view: doc 1 -> user 2 (a role of org 1)",
            "doc.roles with view: doc 1 -> user:* (a role of org 1)",
        ]
        world = evaluate.World("", 1)
        self.assertEqual(world.describe(pol, data), ["user: 1, 2", "org: 1", "doc: 1", *lines])
        self.assertEqual(evaluate.World.named(pol, data), {"user", "org", "doc"})
        self.assertEqual(world.describe(pol, data, {"doc"}), ["doc: 1", *lines[2:]])

    def test_prove_counts_one_world_as_one(self) -> None:
        from authzlib import prove

        for n, said in ((1, "1 world"), (2, "2 worlds")):
            ok = prove.Proof(invariant="never doc: view", type="doc", line="line 9", holds=True, worlds=n, size=1)
            self.assertIn(f"  ok   holds in every world tried ({said}, up to 1 of each type)", prove.describe([ok]))
            no = prove.Proof(
                invariant="never doc: view", type="doc", line="line 9", holds=False, worlds=n, who="1", object="1"
            )
            self.assertIn(f"in this world (the smallest found, after {said}):", prove.describe([no]))

    def test_a_difference_is_shown_in_the_smallest_world_it_shows_in(self) -> None:
        # a viewer taken away: the folder's parent plays no part, so the world shown has no parent link, though
        # the world it was found in had one; it is one world, as each policy reads it
        from authzlib import evaluate

        base = (
            self.HEAD + "type folder = app.folders\n  parent : folder = parent_id\n  owner : user = owner_id\n"
            "  viewer : user = app.folder_viewers(folder_id -> user_id)\n  can view = owner or viewer or parent.view\n"
        )
        a = parse_policy(base, "a.authz")
        b = parse_policy(base.replace("owner or viewer or parent.view", "owner or parent.view"), "b.authz")
        found = evaluate.first_difference(a, b)
        assert found is not None
        diff, da, db = found
        self.assertEqual(
            (diff["what"], diff["user"], diff["object"], diff["before"], diff["after"]),
            ("folder.view", "1", "1", True, False),
        )
        self.assertEqual(diff["world"], ["user: 1", "folder: 1", "folder.viewer: folder 1 -> user 1"])
        self.assertEqual((da.pairs, da.columns), (db.pairs, db.columns))

    def test_one_world_as_two_policies_read_it_is_made_smaller_as_one(self) -> None:
        # a link both read goes from both at once; a condition or a column only one reads, from that one
        from authzlib import evaluate

        ids = {"user": ["1"], "doc": ["1"]}
        q = ("doc", "q", 0, "user", "")
        a = evaluate.Data(ids=ids, valid=ids, pairs={q: [("1", "1")]}, columns={"doc": {"1": {"x": None}}})
        b = evaluate.Data(
            ids=ids, valid=ids, pairs={q: [("1", "1")]}, cond={("doc", "c"): ["1"]}, columns={"doc": {"1": {"y": 1}}}
        )
        sa, sb = evaluate.smallest_of([a, b], lambda ds: True)
        self.assertEqual((sa.pairs, sa.cond, sa.columns), ({q: []}, {}, {"doc": {"1": {"x": None}}}))
        self.assertEqual((sb.pairs, sb.cond, sb.columns), ({q: []}, {("doc", "c"): []}, {"doc": {"1": {"y": None}}}))
        # the link stays where one of them needs it, in both
        sa, sb = evaluate.smallest_of([a, b], lambda ds: bool(ds[1].pairs[q]))
        self.assertEqual((sa.pairs, sb.pairs), ({q: [("1", "1")]}, {q: [("1", "1")]}))

    def test_a_polymorphic_row_has_one_parent(self) -> None:
        both = "  owner : user = owner_id\n  can x = owner\n  can y = not owner\n"
        text = (
            "type project = app.projects\n"
            + both
            + "type folder = app.folders\n  parent : folder, project = (parent_type, parent_id)\n"
            + both
            + "  can a = parent.x\n  can b = parent.y\ninvariants\n  never folder: a and b\n  never folder: a and not b\n"
        )
        self.assertEqual(self.proofs(text), [True, False])

    def test_what_worlds_compare_beyond_permissions_and_rules(self) -> None:
        # a type moved to another table, roles no longer limited by `from`, or a type that signs in now: more than
        # permissions and rules changed, so no narrower comparison is made (None); and a policy without conditions
        # has no corners
        from authzlib import evaluate

        base = (
            self.HEAD + "type org = app.orgs\n  admin : user = admin_id\n  can manage_roles = admin\n"
            "type doc = app.docs\n  owner : user = owner_id\n  org : org = org_id\n  roles : user from org\n"
            "  can view = owner or roles\nrules app.docs\n  select : view\n"
        )
        moved = base.replace("type doc = app.docs\n", "type doc = app.docs2\n").replace(
            "rules app.docs\n", "rules app.docs2\n"
        )
        signs_in = base.replace("type org = app.orgs\n", "type org = app.orgs principal\n")
        for head in (moved, base.replace("  roles : user from org\n", "  roles : user\n"), signs_in):
            a, b = parse_policy(base), parse_policy(head)
            self.assertIsNone(evaluate.apart(a, b), head)
            self.assertIsNone(evaluate.cone([a, b]), head)
        self.assertEqual(
            evaluate.corners([parse_policy(self.HEAD + "type doc = app.docs\n  owner : user = owner_id\n")]), []
        )

    def test_a_polymorphic_row_names_an_object_of_its_type(self) -> None:
        # in every world drawn: a row's (type, id) gives one link, to an object of that type that is there
        from authzlib.evaluate import World

        pol = parse_policy(
            self.HEAD + "type project = app.projects\n  owner : user = owner_id\n  can see = owner\n"
            "type folder = app.folders\n  parent : folder, project = (parent_type, parent_id)\n  can see = parent.see\n"
        )
        for seed in range(40):
            data = World(str(seed), 4).data(pol)
            links = {st: data.pairs[("folder", "parent", 0, st, "")] for st in ("folder", "project")}
            for st, pairs in links.items():
                self.assertTrue(all(s in data.ids[st] for _, s in pairs), (seed, st, pairs))
            self.assertFalse({o for o, _ in links["folder"]} & {o for o, _ in links["project"]}, seed)

    def test_a_drawn_role_belongs_to_an_object_of_its_owner_type(self) -> None:
        # `roles : user from org`: each role given in a drawn world is an org's, one that is there, so roles reach
        from authzlib.evaluate import World

        pol = parse_policy(
            self.HEAD + "type org = app.orgs\n  admin : user = admin_id\n  can manage_roles = admin\n"
            "type folder = app.folders\n  org : org = org_id\n  roles : user from org\n  can view = roles\n"
        )
        given = 0
        for seed in range(20):
            data = World(str(seed), 4).data(pol)
            for o, s, w in data.rolepairs[("folder", "view", "user", "")]:
                self.assertIn(w, data.ids["org"], (seed, o, s, w))
                given += 1
        self.assertGreater(given, 0)

    def test_a_column_naming_a_group_is_no_link_of_one_object(self) -> None:
        # `owner : user = owner_id` names one user: its links are the column's values. `keeper : folder#owner =
        # folder_id` names a group (the folder's owners): the column holds the folder, which conditions read as drawn
        from authzlib.evaluate import linked_column

        pol = parse_policy(
            self.HEAD + "type folder = app.folders\n  owner : user = owner_id\n  can view = owner\n"
            "type note = app.notes\n  keeper : folder#owner = folder_id\n  can keep = keeper\n"
        )
        self.assertEqual(linked_column(pol.types["folder"].relations["owner"].sources[0]), "owner_id")
        self.assertIsNone(linked_column(pol.types["note"].relations["keeper"].sources[0]))

    def test_two_policies_whose_types_differ_are_told_apart(self) -> None:
        # the same permissions and rules over a type whose where, or whose relation's column, differs: the worlds
        # aren't narrowed to where the permissions differ (there is no such place), and one tells them apart
        folder = (
            "type folder = app.folders{}\n  owner : user = {}\n  can view = owner\nrules app.folders\n  select : view\n"
        )
        plain = folder.format("", "owner_id")
        self.assertFalse(self.same(plain, folder.format(" where {not archived}", "owner_id")))
        self.assertFalse(self.same(plain, folder.format("", "creator_id")))
        self.assertTrue(self.same(plain, plain))

    def test_a_change_seen_only_through_the_permission_that_reads_it_is_found(self) -> None:
        # a deny inside inheritance is split into a hidden view__base and `view__base and not hidden` (compiling
        # does it, and the review compares compiled policies): widening the inheritance changes only the hidden
        # one, which isn't compared itself; view, which reads it, is
        from authzlib import Compiler, evaluate

        folder = (
            "type folder = app.folders\n  owner : user = owner_id\n  editor : user = editor_id\n"
            "  parent : folder = parent_id\n  blocked : user = blocked_id\n"
            "  can edit = editor\n  can hidden = blocked or parent.hidden\n  can view = ({} or parent.view) and not hidden\n"
        )

        def split(text: str) -> authzlib.parse.Policy:
            c = Compiler(parse_policy(self.HEAD + text, "p.authz"))
            c.compile("p.authz")
            return c.pol

        a, b = split(folder.format("owner")), split(folder.format("owner or editor"))
        self.assertTrue(a.types["folder"].perms["view__base"].hidden)
        self.assertIsNotNone(evaluate.compare(a, b))

    def test_a_rule_gives_no_row_the_type_leaves_out(self) -> None:
        head = "type folder = app.folders where {not archived}\n  owner : user = owner_id\n  can view = owner\nrules app.folders\n"
        self.assertTrue(
            self.same(head + "  select : {shared_flag}\n", head + "  select : {shared_flag} and {not archived}\n")
        )
        self.assertTrue(
            self.same(
                head + "  select : view or {public}\n", head + "  select : view or ({public} and {not archived})\n"
            )
        )
        self.assertFalse(self.same(head + "  select : view or {public}\n", head + "  select : view\n"))

    # five link tables in one `and`, then an editor as good as the owner: a drawn world holds all five for one person
    # one time in hundreds, and 200 of them said the review's refactor check and Risk found nothing, 400 that
    # `never doc: approve and not owner` held
    SIGNOFFS = ("legal", "finance", "security", "privacy")

    def approve(self, also: tuple[str, ...] = (), lines: str = "") -> str:
        rels = ("editor", *self.SIGNOFFS, *also)
        return (
            "type doc = app.docs\n  owner : user = app.doc_owners(doc_id -> user_id)\n"
            + "".join(f"  {n} : user = app.doc_{n}(doc_id -> user_id)\n" for n in rels)
            + lines
            + "  can edit = owner or editor\n"
        )

    def test_a_condition_on_who_is_signed_in_is_listed_with_the_where_that_says_it_too(self) -> None:
        # a type's where on authz.uid() and a permission that asks it again: the where adds nothing, and the
        # listed worlds (alone here) say the two policies are the same
        from authzlib import evaluate

        doc = "type doc = app.docs{}\n  owner : user = owner_id\n  can view = owner and {{editor_id = authz.uid()}}\n"
        a = parse_policy(self.HEAD + doc.format(" where {editor_id = authz.uid()}"), "a.authz")
        b = parse_policy(self.HEAD + doc.format(""), "b.authz")
        self.assertIsNone(evaluate.compare(a, b, worlds=0))

    def test_the_listing_stops_where_its_steps_are_spent(self) -> None:
        # past its budget of steps (made small here), the listing stops once every world of one link is listed,
        # not before, and says how far it got
        from authzlib import evaluate

        policy = self.approve()
        a = parse_policy(self.HEAD + policy + "  can approve = owner and legal and finance and security and privacy\n")
        b = parse_policy(
            self.HEAD + policy + "  can approve = (owner or editor) and legal and finance and security and privacy\n"
        )
        for steps, listed in ((10, 7), (17, 12), (200, 64)):  # (17: the one step past 16 lists five more)
            with mock.patch.object(evaluate, "STEPS", steps):
                listing = evaluate.Listing((a, b))
                self.assertEqual(sum(1 for _ in listing.worlds()), listed, steps)
            self.assertEqual((listing.whole, listing.complete), (1, False), steps)
            self.assertEqual(
                listing.said(), f"{listed} listed: every one of up to 3 rows of each type with at most 1 link"
            )

    def test_a_long_and_of_links_widened_is_found(self) -> None:
        from authzlib import evaluate

        # a dense world has as many rows of each type as it is large: every pair of them may hold the links
        self.assertEqual(evaluate.World("s", 4, density=0.75).ids("doc"), ["1", "2", "3", "4"])
        folder = (
            "type folder = app.folders\n  head : user = app.folder_heads(folder_id -> user_id)\n  can sign = head\n"
        )
        signoffs = " and ".join(self.SIGNOFFS)
        for also, lines, rest in (
            ((), "", ""),
            (("audit",), "", " and audit"),  # six links
            (("audit", "board"), "", " and audit and board"),  # eight: no drawn world, nor one only as dense as them
            ((), "  folder : folder = folder_id\n", " and folder.sign"),  # an arrow among them
            (("blocked",), "", " and not blocked"),  # a deny
        ):
            policy = (folder if "folder" in lines else "") + self.approve(also, lines)
            before = policy + f"  can approve = owner and {signoffs}{rest}\n"
            after = policy + f"  can approve = (owner or editor) and {signoffs}{rest}\n"
            self.assertFalse(self.same(before, after), rest)
            invariant = "invariants\n  never doc: approve and not owner\n"
            self.assertEqual(self.proofs(after + invariant), [False], rest)
            self.assertEqual(self.proofs(before + invariant), [True], rest)
        # an `and` written in another order is the same
        policy = self.approve()
        self.assertTrue(
            self.same(
                policy + f"  can approve = owner and {signoffs}\n",
                policy + f"  can approve = {' and '.join(reversed(self.SIGNOFFS))} and owner\n",
            )
        )

    def test_a_chain_deeper_than_the_drawn_worlds_is_found(self) -> None:
        # a share that reaches three folders down, widened to four: only five folders in a row show it, and a drawn
        # world has four at most; the worlds have chains one link longer than the policies read
        from authzlib import evaluate, prove

        levels = "".join(f"  can v{i} = v{i - 1} or parent.v{i - 1}\n" for i in (1, 2, 3))
        # a project a folder may sit in, as its parent, holds nothing of its own
        project = "type project = app.projects\n" + "".join(f"  can v{i} = nobody\n" for i in range(4))
        for parent, other in (
            ("folder = parent_id", ""),  # a column
            ("folder = app.folder_links(folder_id -> parent_id)", ""),  # a link table
            ("folder, project = (parent_type, parent_id)", project),  # a pair of columns, folders or projects
        ):
            policy = (
                other + f"type folder = app.folders\n  parent : {parent}\n  owner : user = owner_id\n"
                "  viewer : user shared\n  can share = owner\n  can v0 = viewer\n" + levels
            )
            before, after = policy + "  can view = v3\n", policy + "  can view = v3 or parent.v3\n"
            pols = [parse_policy(self.HEAD + x, "p.authz") for x in (before, after)]
            self.assertEqual((evaluate.reach(pols[:1]), evaluate.reach(pols)), (3, 4))
            self.assertFalse(self.same(before, after), parent)
            invariant = "invariants\n  never folder: view and not v3\n"
            [r] = prove.prove(parse_policy(self.HEAD + after + invariant, "p.authz"))
            self.assertEqual((r["holds"], r.get("size")), (False, 6), parent)
            self.assertEqual(self.proofs(before + invariant), [True], parent)
            # the same three levels, written out one more step, are the same
            self.assertTrue(self.same(before, policy + "  can view = v2 or parent.v2\n"), parent)

    def test_a_type_one_side_has_alone_may_read_columns(self) -> None:
        # the worlds draw the columns both sides' simple conditions read: the side without the type has no rows of it
        doc = "type doc = app.docs\n  owner : user = owner_id\n  can view = owner\n"
        tag = "type tag = app.tags\n  owner : user = owner_id\n  can see = owner and {not hidden}\n"
        self.assertTrue(self.same(doc, doc + tag))
        self.assertTrue(self.same(doc + tag, doc))

    def test_a_corner_leaves_drawn_what_has_too_many_values_to_try(self) -> None:
        # four columns of nine values each (the seven named, one none of them names, NULL): more combinations than a
        # corner tries, so their values stay as the world drew them
        from authzlib import evaluate

        cond = " and ".join(f"{c} in (1, 2, 3, 4, 5, 6, 7)" for c in "abcd")
        pol = parse_policy(
            self.HEAD + f"type doc = app.docs\n  owner : user = owner_id\n  can view = owner and {{{cond}}}\n",
            "p.authz",
        )
        self.assertGreater(9**4, evaluate.World.CORNER_CHOICES)
        drawn = evaluate.World("s", 4, pols=[pol]).columns(pol)
        self.assertEqual(evaluate.World("s", 4, {cond: True}, pols=[pol]).columns(pol), drawn)

    def test_the_first_difference_comes_with_its_world_as_each_policys_data(self) -> None:
        # what tests/rewrites.py loads into a database, to see it answer as the review says: a permission's
        # difference, or a rule's
        from authzlib import evaluate

        doc = "type doc = app.docs\n  owner : user = owner_id\n  viewer : user = viewer_id\n  can view = owner"
        for change, rule, what in (
            (" or viewer", "owner", "doc.view"),
            ("", "owner or viewer", "rule app.docs select"),
        ):
            a, b = (
                parse_policy(self.HEAD + doc + x + f"\nrules app.docs\n  select : {r}\n", "p.authz")
                for x, r in (("", "owner"), (change, rule))
            )
            found = evaluate.first_difference(a, b)
            assert found is not None
            diff, data_a, data_b = found
            self.assertEqual((diff["what"], diff["before"], diff["after"]), (what, False, True))
            self.assertEqual((data_a.ids, data_a.pairs), (data_b.ids, data_b.pairs))  # one world, the same relations

    def test_a_worlds_column_a_relation_reads_holds_its_links_id(self) -> None:
        # {parent_id is null} and the parent link are one fact: the rows a world gives the database (tests/small.py
        # load_sql) have the column the link says, in drawn worlds and in chains
        from authzlib import evaluate

        pol = parse_policy(
            self.HEAD + "type folder = app.folders\n  owner : user = owner_id\n  parent : folder = parent_id\n"
            "  can view = owner or parent.view\n  can top = owner and {parent_id is null}\n",
            "p.authz",
        )
        for k in range(10):
            for chained in (False, True):
                data = evaluate.World(f"s/{k}", 4, pols=[pol], chained=chained).data(pol)
                links = dict(data.pairs[("folder", "parent", 0, "folder", "")])
                columns = {i: row.get("parent_id") for i, row in data.columns["folder"].items()}
                self.assertEqual(columns, {i: links.get(i) for i in data.ids["folder"]}, (k, chained))

    def test_a_chain_world_nests_groups_in_a_chain_too(self) -> None:
        # a team inside the next one, as a folder inside the next: what a policy reads at the end of a long nesting
        from authzlib import evaluate

        pol = parse_policy(
            self.HEAD + "type team = app.teams\n  member : user = owner_id\n"
            "  member : team#member = app.team_links(team_id -> sub_id)\n  can view = member\n",
            "p.authz",
        )
        data = evaluate.World("s", 5, pols=[pol], chained=True).data(pol)
        chain = [("1", "2"), ("2", "3"), ("3", "4"), ("4", "5")]
        self.assertEqual(data.pairs[("team", "member", 1, "team", "member")], chain)

    def test_a_dense_world_gives_most_of_the_custom_roles_it_could(self) -> None:
        # as it holds most of the links it could (DENSITIES); a drawn one gives a few (World.ROLE)
        from authzlib import evaluate

        pol = parse_policy(
            self.HEAD + "type org = app.orgs\n  admin : user = admin_id\n  can manage_roles = admin\n"
            "type doc = app.docs\n  org : org = org_id\n  roles : user from org\n  can view = roles\n",
            "p.authz",
        )

        def given(density: float | None) -> float:
            n = could = 0
            for k in range(10):
                data = evaluate.World(f"s/{k}", 4, pols=[pol], density=density).data(pol)
                n += sum(len(pairs) for pairs in data.rolepairs.values())
                could += len(data.ids["doc"]) * len(data.ids["user"])
            return n / could

        self.assertGreater(given(0.9), 0.75)
        self.assertLess(given(None), 0.5)

    def test_a_policy_that_reads_two_links_deep_is_tried_on_chains(self) -> None:
        # a file's folder's org's members: two links deep, so beside the dense worlds a dozen chains of four
        from authzlib import evaluate

        pol = parse_policy(
            self.HEAD
            + "type org = app.orgs\n  member : user = app.org_members(org_id -> user_id)\n  can view = member\n"
            "type folder = app.folders\n  org : org = org_id\n  can view = org.view\n"
            "type file = app.files\n  in : folder = folder_id\n  can view = in.view\n",
            "p.authz",
        )
        self.assertEqual(evaluate.reach([pol]), 2)
        rare = list(evaluate.rare_worlds([pol], 80, "0"))
        self.assertEqual(len(rare), evaluate.dense_worlds(80) + 12)
        self.assertEqual([w.size for w in rare if w.chained], [4] * 12)

    def test_a_corner_chooses_as_many_values_as_it_tries(self) -> None:
        # four columns of eight values each (the six named, one none of them names, NULL): just as many combinations
        # as a corner tries, so it chooses them, and the condition it says holds holds on every row
        from authzlib import evaluate

        cond = " and ".join(f"{c} in (1, 2, 3, 4, 5, 6)" for c in "abcd")
        pol = parse_policy(
            self.HEAD + f"type doc = app.docs\n  owner : user = owner_id\n  can view = owner and {{{cond}}}\n",
            "p.authz",
        )
        self.assertEqual(8**4, evaluate.World.CORNER_CHOICES)
        rows = evaluate.World("s", 4, {cond: True}, pols=[pol]).columns(pol)["doc"]
        self.assertTrue(rows)
        self.assertEqual([i for i, row in rows.items() if not all(row[c] in range(1, 7) for c in "abcd")], [])

    def test_a_corner_gives_both_policies_the_same_rows(self) -> None:
        # a corner chooses together the values of columns that conditions read together. The rewrite reads b1
        # beside b2, the policy b1 alone: chosen for each policy's own conditions, a row's b1 differed between them,
        # and a rewrite that changes nothing showed a difference ({not b1} held before, on a row with b1 true)
        from authzlib import evaluate

        doc = "type doc = app.docs\n  r : user = owner_id\n  can p = r and {b1}\n  can q = {not b1}"
        before, after = doc + "\n", doc + " or ({b1 and b2} and nobody)\n"
        self.assertTrue(self.same(before, after))
        a, b = parse_policy(self.HEAD + before, "a.authz"), parse_policy(self.HEAD + after, "b.authz")
        for n, corner in enumerate(evaluate.corners([a, b])):
            for k in range(8):
                w = evaluate.World(f"s/{n}/{k}", 4, corner, pols=[a, b])
                self.assertEqual(w.columns(a), w.columns(b), corner)

    def test_a_condition_added_to_a_long_and_is_found(self) -> None:
        # what shows it is a row where every other condition holds and this one doesn't (or does): no drawn world
        # had it (one row in hundreds), nor a corner (every condition holds there, or none); a listed world does
        long = "owner and not {archived} and {tier = 2} and {level = 3} and {zone = 4} and {year = 2024}"
        doc = "type doc = app.docs\n  owner : user = owner_id\n  can view = "
        rules = "\nrules app.docs\n  select : view\n"
        self.assertFalse(self.same(doc + long + rules, doc + long + " and not {hidden}" + rules))
        self.assertFalse(self.same(doc + long + " and not {hidden}" + rules, doc + long + rules))

    def test_conditions_that_differ_between_two_linked_rows_are_found(self) -> None:
        # the child (b1 false, b2 false) of a parent with b1: only nobody signed in, through the parent's b1, holds
        # p on it before; a world of two linked rows, each with its own values
        t1 = "type t1 = app.t1\n  parent : t1 = parent_id\n  can p = "
        self.assertFalse(
            self.same(
                t1 + "({b1} or parent.p) and {not b3}\n", t1 + "({b1} or (parent.p and not {not b2})) and {not b3}\n"
            )
        )

    def test_the_small_worlds_are_listed(self) -> None:
        # a row of a document is of two classes ({a} holds or not); with no link, then each document's owner. A world
        # that is another with its rows renamed is listed once: two documents of one owner, both {a} or one of them
        # or neither (3), and of two owners (3); three: 14. Every one of them, then: a document has one owner
        from authzlib import evaluate

        doc = self.HEAD + "type doc = app.docs\n  owner : user = owner_id\n  can view = "
        a, b = parse_policy(doc + "owner and {a}\n", "a.authz"), parse_policy(doc + "{a} and owner\n", "b.authz")
        listing = evaluate.Listing((a, b))
        self.assertEqual(collections.Counter(len(w.links_held) for w in listing.worlds()), {0: 2, 1: 2, 2: 6, 3: 14})
        self.assertTrue(listing.complete)
        self.assertEqual(listing.said(), "24 listed: every one of up to 3 rows of each type")
        # only what the permissions defined differently read varies: here, nothing of tag
        tag = "type tag = app.tags\n  owner : user = owner_id\n  can see = owner and {b} and {c}\n"
        listing = evaluate.Listing(
            (parse_policy(doc + "owner\n" + tag, "a"), parse_policy(doc + "owner or {a}\n" + tag, "b"))
        )
        self.assertEqual({t: len(c) for t, c in listing.classes.items()}, {"user": 1, "doc": 2, "tag": 1})
        self.assertEqual(sorted(listing.cone.relations), [("doc", "owner")])
        # more than the budget (LISTED for each of the 200 drawn worlds): every world with one link at most, then up
        # to the budget in all
        many = " and ".join(f"{{k{i} = {i}}}" for i in range(10))
        a, b = (
            parse_policy(doc + f"owner and {many}\n", "a.authz"),
            parse_policy(doc + f"{many} and owner\n", "b.authz"),
        )
        listing = evaluate.Listing((a, b))
        self.assertIsNone(evaluate.compare(a, b, listing=listing))
        self.assertEqual((listing.whole, listing.complete), (1, False))
        self.assertEqual(listing.said(), "3,000 listed: every one of up to 3 rows of each type with at most 1 link")
        # fewer drawn worlds, fewer listed: but never before every world with one link at most (2,048 here)
        listing = evaluate.Listing((a, b))
        self.assertIsNone(evaluate.compare(a, b, worlds=10, listing=listing))
        self.assertEqual(listing.said(), "2,049 listed: every one of up to 3 rows of each type with at most 1 link")

    def test_the_types_a_change_doesnt_read_cost_the_listing_nothing(self) -> None:
        # only the rows of a type some link may name vary: here user and doc. Each count of rows of all 14 types
        # was gone through (4^14 of them, for each number of links): minutes, and the steps spent on worlds no
        # link could make left it at fewer links
        import time

        from authzlib import evaluate

        doc = self.HEAD + "type doc = app.docs\n  owner : user = owner_id\n  can view = "
        others = "".join(f"type t{i} = app.t{i}\n  owner : user = owner_id\n  can see = owner\n" for i in range(12))
        a, b = parse_policy(doc + "owner\n" + others, "a.authz"), parse_policy(doc + "owner or owner\n" + others, "b")
        self.assertEqual(len(a.types), 14)
        start = time.monotonic()
        listing = evaluate.Listing((a, b))
        self.assertIsNone(evaluate.compare(a, b, listing=listing))
        self.assertLess(time.monotonic() - start, 20)
        self.assertEqual(listing.said(), "7 listed: every one of up to 3 rows of each type")
        # the counts it goes through: those of the whole product whose sum is small enough, in its order
        for n, total in ((0, 0), (1, 2), (3, 4), (4, 12)):
            self.assertEqual(
                list(evaluate.counts_up_to(n, total)),
                [v for v in itertools.product(range(evaluate.MOST_ROWS + 1), repeat=n) if sum(v) <= total],
                (n, total),
            )

    def test_a_listed_world_shares_with_everyone_and_by_link(self) -> None:
        # a share names a row of its subject's type, or `*` (every user, anyone), or a link's token: the one asked with
        from authzlib import evaluate

        doc = self.HEAD + "type doc = app.docs\n  viewer : user, user:*, anyone, link shared by view\n  can view = "
        a, b = parse_policy(doc + "viewer\n", "a.authz"), parse_policy(doc + "viewer and signed_in\n", "b.authz")
        listing = evaluate.Listing((a, b))
        named = {(c.link[0][3], c.link[0][4], c.link[2]) for c in listing.candidates}
        self.assertEqual(
            named,
            {
                ("user", None, "1"),
                ("user", None, "2"),
                ("user", None, "3"),
                ("user", "*", "*"),
                ("anyone", None, "*"),
                ("link", None, "tok1"),
            },
        )
        found = evaluate.compare(a, b, listing=listing)
        assert found is not None
        self.assertEqual(
            (found["what"], found["user"], found["before"], found["after"]),
            ("doc.view", "(nobody signed in)", True, False),
        )

    def test_the_listing_says_where_it_took_some_values_only(self) -> None:
        # four columns of nine values each (the seven named, one none of them names, NULL), read by one condition:
        # more combinations than a row's classes are made from, so only the first are, and the review says so
        from authzlib import evaluate

        cond = " and ".join(f"{c} in (1, 2, 3, 4, 5, 6, 7)" for c in "abcd")
        doc = self.HEAD + "type doc = app.docs\n  owner : user = owner_id\n  can view = "
        a, b = (
            parse_policy(doc + f"owner and {{{cond}}}\n", "a.authz"),
            parse_policy(doc + f"{{{cond}}} and owner\n", "b.authz"),
        )
        self.assertGreater(9**4, evaluate.CLASS_CHOICES)
        listing = evaluate.Listing((a, b))
        self.assertIsNone(evaluate.compare(a, b, worlds=10, listing=listing))
        self.assertTrue(listing.cut)
        self.assertEqual(
            listing.said(),
            "24 listed: every one of up to 3 rows of each type; of columns read together, only the first 4,096 "
            "combinations of their values",
        )
        from authzlib import review

        r = review.review(
            (doc + f"owner and {{{cond}}}\n", {}, {}),
            (doc + f"{{{cond}}} and owner\n", {}, {}),
            None,
            None,
            None,
            worlds=10,
        )
        said = r["meaning"]["equivalent"] or ""
        self.assertTrue(said.endswith("only the first 4,096 combinations of their values"), said)

    def test_the_evaluator_refuses_data_it_cannot_read(self) -> None:
        from authzlib import evaluate

        with self.assertRaisesRegex(ValueError, "not the evaluator's data"):
            evaluate.Data.of({("idz", "doc"): ["1"]})
        # a condition it doesn't read as a fact about the row, with no rows said to hold it
        pol = parse_policy(
            self.HEAD + "type doc = app.docs\n  can view = {exists (select 1 from app.flags)}\n", "p.authz"
        )
        ids = {"user": ["1"], "doc": ["1"]}
        data = evaluate.Data(ids=ids, valid=ids, columns={"user": {"1": {}}, "doc": {"1": {}}})
        with self.assertRaisesRegex(KeyError, r"no rows given for \{exists \(select 1 from app.flags\)\} on doc"):
            evaluate.Reference(pol).evaluate(data, "1")

    def test_coverage_reads_explain(self) -> None:
        from authzlib import coverage

        explain = "\n".join(
            [
                "yes  user 1 holds edit on folder 3",
                "  folder.edit = share or editor or (parent.edit and {inherit})",
                "  yes  share",
                "    folder.share = owner or org.admin or (parent.share and {inherit})",
                "    yes  owner",
                "    no   org.admin",
                "  no   editor",
                "  yes  (parent.edit and {inherit})",
            ]
        )
        self.assertEqual(
            coverage.covered([explain]),
            {
                ("folder", "edit", "share"),
                ("folder", "share", "owner"),
                ("folder", "edit", "(parent.edit and {inherit})"),
            },
        )
        c = Compiler(parse_policy(read(POLICIES["docs"])))
        c.compile("x")
        r = coverage.report(c, [explain])
        self.assertEqual(r["covered"], 3)
        self.assertIn(("line 49", "folder.edit", "editor"), r["missing"])
        self.assertIn('branches no "can" check reaches (line ', coverage.summary(r))

    def test_coverage_of_every_branch_and_of_none(self) -> None:
        # what rowstile test --coverage prints when a test makes every branch true, and when there are no
        # permissions; rowstile dev's line then says nothing more than how many checks pass
        from authzlib import coverage

        c = Compiler(parse_policy(self.HEAD + "type doc = app.docs\n  can see = signed_in\n"))
        c.compile("x")
        r = coverage.report(c, ["yes  user 1 holds see on doc 1\n  doc.see = signed_in\n  yes  signed_in"])
        self.assertEqual(coverage.describe(r), "coverage: 1 of 1 branches made true by a test (all of them)")
        self.assertEqual(coverage.summary(r), "")
        c = Compiler(parse_policy(self.HEAD + "type doc = app.docs\n"))
        c.compile("x")
        self.assertEqual(coverage.describe(coverage.report(c, [])), "coverage: no permissions")

    def test_rowstile_devs_line_shortens_what_it_names(self) -> None:
        # the first two branches: 32 characters are shown whole, a longer one cut to 29 and '...' (a condition keeps
        # its closing brace); '...' after them only when there are more than two
        from authzlib import coverage

        whole, cond, ref = (
            "{owner_id = authz.uid() or open}",
            "{owner_id = authz.uid() and not archived}",
            "parent.edit_everything_inside_it_too",
        )
        two: coverage.Report = {
            "total": 5,
            "covered": 3,
            "missing": [("line 3", "doc.view", whole), ("line 4", "doc.edit", cond)],
        }
        self.assertEqual(
            coverage.summary(two),
            '2 branches no "can" check reaches (line 3: {owner_id = authz.uid() or open}, '
            "line 4: {owner_id = authz.uid() and n...})",
        )
        three: coverage.Report = {
            "total": 5,
            "covered": 2,
            "missing": [("line 3", "doc.view", whole), ("line 5", "doc.edit", ref), ("line 6", "doc.see", "owner")],
        }
        self.assertEqual(
            coverage.summary(three),
            '3 branches no "can" check reaches (line 3: {owner_id = authz.uid() or open}, '
            "line 5: parent.edit_everything_inside..., ...)",
        )

    def test_coverage_of_a_deny_inside_inheritance(self) -> None:
        from authzlib import coverage

        c = Compiler(
            parse_policy(
                self.HEAD + "type folder = app.folders\n  parent : folder = parent_id\n  owner : user = owner_id\n"
                "  viewer : user = viewer_id\n  can hidden = {blocked} or parent.hidden\n"
                "  can view = (owner or viewer or parent.view) and not hidden\n  can see = signed_in\n"
            )
        )
        c.compile("x")
        self.assertEqual(
            [(p, i) for _, p, i, _, _ in coverage.branches(c)],
            [
                ("hidden", "{blocked}"),
                ("hidden", "parent.hidden"),
                ("see", "signed_in"),
                ("view", "owner"),
                ("view", "viewer"),
                ("view", "parent.view (before the deny)"),
            ],
        )
        explain = "\n".join(
            [
                "yes  user 1 holds view on folder 1",
                "  folder.view = (owner or viewer or parent.view) and not hidden",
                "  yes  (view (before the deny) and not hidden)",
                "    yes  view (before the deny)",
                "      folder.view__base = (owner or viewer or parent.view) and not hidden  (its inheritance, before the deny)",
                "      yes  owner",
                "      no   viewer",
                "      no   parent.view (before the deny)",
                "    yes  not hidden",
            ]
        )
        r = coverage.report(c, [explain])
        self.assertEqual((r["covered"], r["total"]), (1, 6))
        # the branches are the ones the policy writes, in its words
        self.assertEqual(
            [(name, item) for _, name, item in r["missing"]],
            [
                ("folder.hidden", "{blocked}"),
                ("folder.hidden", "parent.hidden"),
                ("folder.see", "signed_in"),
                ("folder.view", "viewer"),
                ("folder.view", "parent.view"),
            ],
        )


class Indexes(unittest.TestCase):
    """rowstile indexes: the lookups a policy makes (tests/confidence_test.py asks a database which an index serves)."""

    def test_what_serves_a_type_and_id_pair_alone(self) -> None:
        # a (type, id) pair, in the type's table or in a link table, is looked up by both columns. Where its id is
        # one column, the id is compared through a CASE on the type, which no index serves: the type's condition
        # beside it is what one serves, so an index on the type column serves it alone, and one on the id alone
        # doesn't. Where its id is two columns, they are compared column by column: an index on them serves it.
        from authzlib import perf

        def pairs(name: str) -> list[tuple[str, tuple[str, ...], tuple[str, ...]]]:
            c = Compiler(parse_policy(read(POLICIES[name])))
            return [(table, columns, alone) for table, columns, _, _, alone in perf.needed_indexes(c) if alone]

        self.assertEqual(
            pairs("cross"),
            [
                ("cx.folders", ("parent_type", "parent_id"), ("parent_type",)),
                ("cx.backings", ("backer_type", "backer_id"), ("backer_type",)),
            ],
        )
        self.assertEqual(
            pairs("composite"), [("cx.folders", ("parent_type", "org_id", "parent_id"), ("org_id", "parent_id"))]
        )

    def test_why_a_link_tables_lookup_is_needed(self) -> None:
        # the members of an org, of a team: what each check looks up in the link table by its object's column
        from authzlib import perf

        c = Compiler(parse_policy(read(POLICIES["docs"])))
        why = {(table, columns): why for table, columns, why, _, _ in perf.needed_indexes(c)}
        self.assertEqual(why[("app.org_members", ("org_id",))], "finding the members of an org (checks, explanations)")
        self.assertEqual(
            why[("app.team_members", ("team_id",))], "finding the members of a team (checks, explanations)"
        )


class Plans(unittest.TestCase):
    """rowstile plans: what it reads in EXPLAIN's JSON (tests/confidence_test.py reads a database's own plans)."""

    def test_what_plans_says_of_each_table(self) -> None:
        from authzlib import perf

        p: perf.Plans = {
            "as": "user:7",
            "tables": [
                {"table": "app.docs", "ms": 3.5, "warnings": []},
                {"table": "app.files", "ms": 9.0, "warnings": ["a", "b"]},
                {"table": "app.notes", "ms": None, "warnings": ["failed: x"]},
            ],
        }
        self.assertEqual(
            perf.describe_plans(p),
            "as user:7:\n  app.docs: 3.5 ms\n  app.files: 9.0 ms  <- a; b\n  app.notes  <- failed: x",
        )

    def test_a_subplan_run_once_per_row_is_named(self) -> None:
        # the plan Postgres 16 gives a read of app.files as an org admin with 15,000 files and work_mem at 64kB, cut
        # down to what plans reads: the set the check looks in no longer fits in memory to be hashed, so it is
        # looked through again for each row. The governed table's own scan is no warning, nor an initplan (once)
        from authzlib import perf

        plan: dict[str, Value] = {
            "Node Type": "Aggregate",
            "Actual Rows": 1,
            "Actual Loops": 1,
            "Plans": [
                {
                    "Node Type": "Result",
                    "Parent Relationship": "InitPlan",
                    "Subplan Name": "InitPlan 1 (returns $0)",
                    "Actual Rows": 1,
                    "Actual Loops": 1,
                },
                {
                    "Node Type": "Seq Scan",
                    "Parent Relationship": "Outer",
                    "Relation Name": "files",
                    "Schema": "app",
                    "Actual Rows": 15006,
                    "Actual Loops": 1,
                    "Rows Removed by Filter": 1,
                    "Plans": [
                        {
                            "Node Type": "Subquery Scan",
                            "Parent Relationship": "SubPlan",
                            "Subplan Name": "SubPlan 11",
                            "Actual Rows": 1,
                            "Actual Loops": 15003,
                        }
                    ],
                },
            ],
        }
        out: list[str] = []
        perf.walk(plan, out, "app.files")
        self.assertEqual(out, ["SubPlan 11 runs once per row (15003 times)"])

    def test_rowstiles_own_tables_read_whole_are_no_warning(self) -> None:
        # someone who reaches every folder (an org's admin) has the closure table read whole: no index the app can
        # add would change that. An app table read whole is still named
        from authzlib import perf

        scan = lambda schema, table, rows: {
            "Node Type": "Seq Scan",
            "Relation Name": table,
            "Schema": schema,
            "Actual Rows": rows,
            "Actual Loops": 1,
        }
        plan: dict[str, Value] = {
            "Node Type": "Hash Join",
            "Actual Loops": 1,
            "Plans": [scan("authz_int", "folder__parent__tree", 20014), scan("app", "org_members", 12001)],
        }
        out: list[str] = []
        perf.walk(plan, out, "app.files")
        self.assertEqual(out, ["reads all of app.org_members (12001 rows): an index missing?"])

    def test_the_bounds_of_a_warning(self) -> None:
        # a scan that reads BIG rows is named, one fewer isn't; a subplan run 1000 times is named, 999 isn't
        from authzlib import perf

        def said(plan: dict[str, Value]) -> list[str]:
            out: list[str] = []
            perf.walk(plan, out, "app.files")
            return out

        scan = lambda rows: {
            "Node Type": "Seq Scan",
            "Relation Name": "org_members",
            "Schema": "app",
            "Actual Rows": rows - 100,
            "Rows Removed by Filter": 100,
            "Actual Loops": 1,
        }
        self.assertEqual(said(scan(perf.BIG)), [f"reads all of app.org_members ({perf.BIG} rows): an index missing?"])
        self.assertEqual(said(scan(perf.BIG - 1)), [])
        sub = lambda loops: {"Node Type": "Subquery Scan", "Subplan Name": "SubPlan 3", "Actual Loops": loops}
        self.assertEqual(said(sub(1000)), ["SubPlan 3 runs once per row (1000 times)"])
        self.assertEqual(said(sub(999)), [])

    class Planned:
        """A database whose reads of app.folders take a little more than SLOW_MS, and of app.files that exactly."""

        class Refused(Exception):
            pass

        @property
        def errors(self) -> type[Exception]:
            return self.Refused

        def rows(self, sql: str, args: Sequence[Value] = ()) -> list[Row]:
            from authzlib import perf

            if "pg_policy" in sql:
                return [{"r": "app_user"}]
            if "pg_has_role" in sql:
                return [{"me": "owner", "ok": True}]
            if sql.startswith("EXPLAIN"):
                ms = perf.SLOW_MS + (0.01 if "folders" in sql else 0)
                plan = {"Node Type": "Seq Scan", "Actual Rows": 3, "Actual Loops": 1}
                return [{"QUERY PLAN": json.dumps([{"Plan": plan, "Execution Time": ms}])}]
            return []

        def script(self, sql: str) -> None:
            pass

        def warn(self, message: str, detail: str | None = None, hint: str | None = None) -> None:
            pass

    def test_a_read_slower_than_the_limit_is_named(self) -> None:
        from authzlib import perf

        c = Compiler(parse_policy(read(POLICIES["docs"])))
        p = perf.plans(self.Planned(), c, ("user", "1"))
        self.assertEqual(
            [(t["table"], t["ms"], t["warnings"]) for t in p["tables"]],
            [("app.files", 100.0, []), ("app.folders", 100.01, ["took 100.01 ms"])],
        )


HandCase = Callable[["HandAnswers"], None]
HAND_ANCHORS: dict[HandCase, tuple[str, ...]] = {}


def worked_from(*anchors: str) -> Callable[[HandCase], HandCase]:
    """Names the paragraphs of docs/reference/language.md a HandAnswers case is worked out from: their anchors."""

    def mark(case: HandCase) -> HandCase:
        HAND_ANCHORS[case] = anchors
        return case

    return mark


class HandAnswers(unittest.TestCase):
    """The reference evaluator against answers worked out by hand from the language's reference
    (docs/reference/language.md), not by running anything. difftest holds the database to the evaluator, but both
    read the policy through one parser: a misreading there would be in both, and they would agree on it. Neither
    wrote these answers.

    Each paragraph of the page that says what an answer is (who may do what on which row) ends with an anchor
    readers don't see, `<!-- answer: rows-hold-nothing -->`, and each anchor has a case: here, `@worked_from(...)` on a
    test, or, where the answer is the database's alone (a share that expires, a caveat, a write checked before and
    after, a masked column), a policy with named tests in tests/hand/, whose first lines say `-- answer: name`
    (tests/hand_answers.sh runs them). test_every_answering_paragraph_has_a_case checks both ways.

    A world, one fact a line:
        folder: 1, 2, 3                      the ids of a type
        folder 2 fails its where             a row the type's where leaves out
        folder 2 parent folder 1             a link: folder 2's parent is folder 1, through the relation's first
                                             source naming that subject (parent[1]: its second source)
        folder 1 viewer team#member 2        a link to a group's members; user:* *, anyone *, link tok1
        {inherit} on folder 2, 4             the rows a condition holds for (none unless said)
        doc 1: archived = false, size = 11   a row's columns: the type's simple conditions read them
        role view on folder 1 for user ann from org 1   a custom role that includes view, org 1's
    The answers: for each one asking ('' is nobody, 'service:1' a service), the ids each permission, relation or rule
    ('rule app.folders update') holds for."""

    HEAD = "app role app_user\n"

    @staticmethod
    def value(text: str) -> Scalar:
        text = text.strip()
        if text in ("true", "false", "null"):
            return {"true": True, "false": False, "null": None}[text]
        if text.startswith("'"):
            return text[1:-1]
        return Decimal(text) if "." in text else int(text)

    def world(self, pol: authzlib.parse.Policy, text: str) -> evaluate.Data:
        from authzlib.conditions import simple

        data = evaluate.Data()
        for t in pol.types.values():
            data.ids[t.name] = []
            for r in t.relations.values():
                for i, src in enumerate(r.sources):
                    for st, sr in src.subjects:
                        data.pairs[(t.name, r.name, i, st, sr or "")] = []
            if t.roles:
                for p in t.roles[1]:
                    for st, sr in t.roles[0]:
                        data.rolepairs[(t.name, p, st, sr or "")] = []
        failing: set[tuple[str, str]] = set()
        conds: dict[tuple[str, str], list[str]] = {}
        for line in [x.strip() for x in text.strip().splitlines() if x.strip()]:
            if m := re.fullmatch(r"\{(.*)\} on (\w+) (.*)", line):
                conds[(m[2], m[1])] = [x.strip() for x in m[3].split(",")]
            elif m := re.fullmatch(r"(\w+): (.*)", line):
                data.ids[m[1]] = [x.strip() for x in m[2].split(",")]
            elif m := re.fullmatch(r"(\w+) (\S+) fails its where", line):
                failing.add((m[1], m[2]))
            elif m := re.fullmatch(r"(\w+) (\S+): (.*)", line):
                data.columns.setdefault(m[1], {})[m[2]] = {
                    c.strip(): self.value(v) for c, v in (x.split("=") for x in m[3].split(","))
                }
            elif m := re.fullmatch(r"role (\w+) on (\w+) (\S+) for (\S+) (\S+)(?: from \w+ (\S+))?", line):
                st, _, sr = m[4].partition("#")
                data.rolepairs[(m[2], m[1], st, sr)].append((m[3], m[5], m[6] or ""))
            elif m := re.fullmatch(r"(\w+) (\S+) (\w+)(?:\[(\d)\])? (\S+) (\S+)", line):
                tname, oid, rname, i, subject, sid = m.groups()
                st, sr = (subject[:-2], "*") if subject.endswith(":*") else subject.partition("#")[::2]
                sources = pol.types[tname].relations[rname].sources
                n = int(i) if i else next(k for k, s in enumerate(sources) if (st, sr or None) in s.subjects)
                data.pairs[(tname, rname, n, st, sr)].append((oid, sid))
            else:
                raise ValueError(f"not a fact: {line}")
        for t in pol.types.values():
            data.valid[t.name] = [i for i in data.ids[t.name] if (t.name, i) not in failing]
            if t.name in data.columns:
                data.columns[t.name] = {i: data.columns[t.name].get(i, {}) for i in data.ids[t.name]}
        for tname, cond in evaluate.Reference(pol).conditions():
            if not (tname in data.columns and simple(cond) is not None):
                data.cond[(tname, cond)] = conds.pop((tname, cond), [])
        self.assertEqual(conds, {}, "conditions the policy doesn't have, or that its columns say")
        return data

    def check(
        self,
        policy: str,
        world: str,
        answers: dict[str, dict[str, str]],
        links: Sequence[str] = (),
        broken: str | None = None,
    ) -> None:
        """broken: who breaks the policy's invariant, and where, as `rowstile prove` asks each who can sign in and
        nobody in a world ('service:1 on 1', 'nobody on 1'), or 'none'."""
        from authzlib import prove

        # a policy the compiler takes (parsed apart: compiling splits denies, the evaluator reads them as written)
        Compiler(parse_policy(self.HEAD + policy, "hand.authz")).compile("hand.authz")
        pol = parse_policy(self.HEAD + policy, "hand.authz")
        ref = evaluate.Reference(pol)
        data = self.world(pol, world)
        rules = {f"rule {r.table} {r.command}": r for r in pol.rules}
        for who, expected in answers.items():
            state = ref.evaluate(data, who, links)
            for name, ids in expected.items():
                tname, _, perm = name.partition(".")
                got = ref.rule(state, rules[name]) if name in rules else state[(tname, perm)]
                want = {x.strip() for x in ids.split(",") if x.strip()}
                self.assertEqual(sorted(got), sorted(want), f"{name}, asked as {who or 'nobody'}")
        if broken is not None:
            (inv,) = pol.invariants
            found = prove.broken(ref, inv, data)
            self.assertEqual(" on ".join(found) if found else "none", broken, inv.src)

    @worked_from("permission-operators")
    def test_not_takes_the_item_after_it(self) -> None:
        self.check(
            "type user = app.users\ntype doc = app.docs\n  a : user = a_id\n  b : user = b_id\n"
            "  can p = not a and b\n  can q = not (a and b)\n  can r = a or (b and not a)\n",
            "user: ann\ndoc: 1, 2, 3, 4\ndoc 1 a user ann\ndoc 1 b user ann\ndoc 2 b user ann\ndoc 3 a user ann\n",
            {
                "ann": {"doc.p": "2", "doc.q": "2, 3, 4", "doc.r": "1, 2, 3"},
                "": {"doc.p": "", "doc.q": "1, 2, 3, 4", "doc.r": ""},
            },
        )

    @worked_from("inheritance")
    def test_a_condition_stops_inheritance_where_it_fails(self) -> None:
        self.check(
            "type user = app.users\ntype folder = app.folders\n  parent : folder = parent_id\n"
            "  owner : user = owner_id\n  can view = owner or (parent.view and {inherit})\n",
            "user: ann, bo\nfolder: 1, 2, 3, 4\nfolder 2 parent folder 1\nfolder 3 parent folder 2\n"
            "folder 4 parent folder 3\nfolder 1 owner user ann\n{inherit} on folder 2, 4\n",
            {"ann": {"folder.view": "1, 2"}, "bo": {"folder.view": ""}, "": {"folder.view": ""}},
        )

    @worked_from("rows-hold-nothing", "rows-no-rule")
    def test_a_row_the_where_leaves_out_holds_nothing_and_passes_nothing_on(self) -> None:
        # an archived folder and what is inside it; no rule allows anything on it either
        self.check(
            "type user = app.users\ntype folder = app.folders where {not archived}\n  parent : folder = parent_id\n"
            "  owner : user = owner_id\n  can view = owner or parent.view\n"
            "rules app.folders\n  select : view\n  update : anyone\n  delete : nobody\n",
            "user: ann, bo\nfolder: 1, 2, 3, 4\nfolder 2 parent folder 1\nfolder 3 parent folder 2\n"
            "folder 4 parent folder 1\nfolder 1 owner user ann\nfolder 2 owner user bo\nfolder 2 fails its where\n",
            {
                "ann": {"folder.view": "1, 4", "rule app.folders select": "1, 4", "rule app.folders update": "1, 3, 4"},
                "bo": {"folder.view": "", "rule app.folders select": "", "rule app.folders delete": ""},
                "": {"rule app.folders update": "1, 3, 4", "rule app.folders delete": ""},
            },
        )

    @worked_from("rows-hold-nothing")
    def test_a_suspended_user_holds_nothing(self) -> None:
        self.check(
            "type user = app.users where {active}\ntype folder = app.folders\n  owner : user = owner_id\n"
            "  viewer : user, user:* shared\n  can share = owner\n  can view = owner or viewer\n  can open = signed_in\n",
            "user: ann, cy\nuser cy fails its where\nfolder: 1, 2, 3\nfolder 1 owner user cy\nfolder 2 viewer user:* *\n"
            "folder 3 owner user ann\n",
            {
                "ann": {"folder.view": "2, 3", "folder.share": "3", "folder.open": "1, 2, 3"},
                "cy": {"folder.view": "", "folder.share": "", "folder.open": ""},
                "": {"folder.view": "", "folder.open": ""},
            },
        )

    @worked_from("subjects", "rows-hold-nothing")
    def test_groups_nest_loop_and_stop_at_a_group_the_where_leaves_out(self) -> None:
        self.check(
            "type user = app.users\ntype team = app.teams where {not disbanded}\n"
            "  member : user = app.team_members(team_id -> user_id)\n"
            "  member : team#member = app.teams(parent_id -> id)\n"
            "type folder = app.folders\n  owner : user = owner_id\n  viewer : user, team#member shared\n"
            "  can share = owner\n  can view = viewer\n",
            "user: ann, bo, cy\nteam: 1, 2, 3, 4, 5\nteam 3 member user ann\nteam 2 member team#member 3\n"
            "team 3 member team#member 2\nteam 1 member team#member 4\nteam 4 member user bo\nteam 4 fails its where\n"
            "team 5 member user cy\nfolder: 1, 2, 3, 4\nfolder 1 viewer team#member 2\nfolder 2 viewer team#member 1\n"
            "folder 3 viewer team#member 4\nfolder 4 viewer team#member 5\n",
            {
                "ann": {"team.member": "2, 3", "folder.view": "1"},
                "bo": {"team.member": "", "folder.view": ""},
                "cy": {"team.member": "5", "folder.view": "4"},
            },
        )

    @worked_from("subjects", "principals")
    def test_who_each_subject_is(self) -> None:
        # user:* any signed-in user, service:* any signed-in service, anyone also signed out, link who holds the
        # token; signed_in is about users; a share to service 2 is not one to user 2
        self.check(
            "type user = app.users\ntype service = app.services principal\ntype folder = app.folders\n"
            "  owner : user = owner_id\n  bot : service = bot_id\n"
            "  viewer : user, service, user:*, service:*, anyone, link shared\n"
            "  can share = owner\n  can view = owner or bot or viewer\n  can open = signed_in\n",
            "user: ann, 2\nservice: 1, 2\nfolder: 1, 2, 3, 4, 5, 6, 7\nfolder 1 viewer user:* *\n"
            "folder 2 viewer anyone *\nfolder 3 viewer link tok1\nfolder 4 viewer link tok2\n"
            "folder 5 viewer service:* *\nfolder 6 bot service 1\nfolder 7 viewer service 2\n",
            {
                "ann": {"folder.view": "1, 2, 3", "folder.open": "1, 2, 3, 4, 5, 6, 7"},
                "2": {"folder.view": "1, 2, 3", "folder.open": "1, 2, 3, 4, 5, 6, 7"},
                "service:1": {"folder.view": "2, 3, 5, 6", "folder.open": ""},
                "service:2": {"folder.view": "2, 3, 5, 7", "folder.open": ""},
                "": {"folder.view": "2, 3", "folder.open": ""},
            },
            links=["tok1"],
        )

    @worked_from("deny-below")
    def test_a_deny_inside_inheritance_covers_everything_below(self) -> None:
        self.check(
            "type user = app.users\ntype folder = app.folders\n  parent : folder = parent_id\n"
            "  owner : user = owner_id\n  can hidden = {secret} or parent.hidden\n"
            "  can view = (owner or parent.view) and not hidden\n",
            "user: ann, bo, cy\nfolder: 1, 2, 3, 4, 5\nfolder 2 parent folder 1\nfolder 3 parent folder 2\n"
            "folder 4 parent folder 3\nfolder 5 parent folder 1\nfolder 1 owner user ann\nfolder 3 owner user bo\n"
            "folder 2 owner user cy\n{secret} on folder 2\n",
            {
                "ann": {"folder.view": "1, 5", "folder.hidden": "2, 3, 4"},
                "bo": {"folder.view": ""},
                "cy": {"folder.view": ""},
            },
        )

    @worked_from("permission-operators", "deny-below")
    def test_parentheses_that_change_nothing_and_a_denys_conditions_in_another_order(self) -> None:
        # folders 1 > 2 > 3 > 4 and 1 > 5; ann owns 1, bo owns 4; folder 3 is secret, 4 is open but not deep.
        # see: an `or` inside an `or`. view: an `and` inside an `and`; hidden inherits on the same conditions,
        # written in another order. edit: its inheritance and a condition, in parentheses, then the deny; blocked
        # inherits on fewer conditions (open alone), so it reaches 4, which bo owns, and takes edit away there
        self.check(
            "type user = app.users\ntype folder = app.folders\n  parent : folder = parent_id\n"
            "  owner : user = owner_id\n  can see = owner or (parent.see or owner)\n"
            "  can hidden = {secret} or (parent.hidden and {deep} and {open})\n"
            "  can view = (owner or (parent.view and ({open} and {deep}))) and not hidden\n"
            "  can blocked = {secret} or (parent.blocked and {open})\n"
            "  can edit = ((owner or (parent.edit and {deep} and {open})) and {open}) and not blocked\n",
            "user: ann, bo\nfolder: 1, 2, 3, 4, 5\nfolder 2 parent folder 1\nfolder 3 parent folder 2\n"
            "folder 4 parent folder 3\nfolder 5 parent folder 1\nfolder 1 owner user ann\nfolder 4 owner user bo\n"
            "{secret} on folder 3\n{open} on folder 1, 2, 3, 4, 5\n{deep} on folder 2, 3, 5\n",
            {
                "ann": {
                    "folder.see": "1, 2, 3, 4, 5",
                    "folder.hidden": "3",
                    "folder.view": "1, 2, 5",
                    "folder.blocked": "3, 4",
                    "folder.edit": "1, 2, 5",
                },
                "bo": {"folder.see": "4", "folder.view": "4", "folder.edit": ""},
                "": {"folder.see": "", "folder.view": "", "folder.edit": ""},
            },
        )

    @worked_from("inheritance")
    def test_folders_and_projects_inside_each_other(self) -> None:
        self.check(
            "type user = app.users\n"
            "type project = app.projects\n  owner : user = owner_id\n  parent : folder = folder_id\n"
            "  can view = owner or parent.view\n"
            "type folder = app.folders\n  owner : user = owner_id\n  parent : folder, project = (parent_type, parent_id)\n"
            "  can view = owner or parent.view\n"
            "type file = app.files\n  folder : folder = folder_id\n  can view = folder.view\n"
            "rules app.files\n  select : view or {public}\n",
            "user: ann, bo\nproject: 1, 2\nfolder: 1, 2, 3, 4\nfile: 1, 2, 3\nproject 1 owner user ann\n"
            "folder 1 parent project 1\nfolder 2 parent folder 1\nproject 2 parent folder 2\nfolder 3 parent project 2\n"
            "folder 4 owner user bo\nfile 1 folder folder 3\nfile 2 folder folder 4\n{public} on file 3\n",
            {
                "ann": {
                    "project.view": "1, 2",
                    "folder.view": "1, 2, 3",
                    "file.view": "1",
                    "rule app.files select": "1, 3",
                },
                "bo": {"project.view": "", "folder.view": "4", "file.view": "2", "rule app.files select": "2, 3"},
                "": {"file.view": "", "rule app.files select": "3"},
            },
        )

    ROLES = (
        "type user = app.users\ntype org = app.orgs\n  admin : user = app.org_admins(org_id -> user_id)\n"
        "  can manage_roles = admin\n"
        "type folder = app.folders\n  org : org = org_id\n  owner : user = owner_id\n  roles : user{from}\n"
        "  can share = owner or org.admin\n  can view = owner or roles\n  can edit = owner or roles\n"
    )
    ROLE_WORLD = (
        "user: ann, bo\norg: 1, 2\nfolder: 1, 2, 3\nfolder 1 org org 1\nfolder 2 org org 2\n"
        "role view on folder 1 for user ann from org 1\nrole view on folder 2 for user ann from org 1\n"
        "role edit on folder 1 for user bo from org 2\nrole edit on folder 3 for user bo from org 1\n"
        "role view on folder 2 for user bo from org 2\n"
    )

    @worked_from("roles-from")
    def test_roles_from_an_org_count_only_on_its_objects(self) -> None:
        self.check(
            self.ROLES.format(**{"from": " from org"}),
            self.ROLE_WORLD,
            {"ann": {"folder.view": "1", "folder.edit": ""}, "bo": {"folder.view": "2", "folder.edit": ""}},
        )

    @worked_from("roles-without-from")
    def test_roles_without_from_count_wherever_they_are_given(self) -> None:
        self.check(
            self.ROLES.format(**{"from": ""}),
            re.sub(r" from org \d", "", self.ROLE_WORLD),
            {"ann": {"folder.view": "1, 2", "folder.edit": ""}, "bo": {"folder.view": "2", "folder.edit": "1, 3"}},
        )

    @worked_from("conditions-null", "conditions-sql")
    def test_simple_conditions_read_columns_as_sql_does(self) -> None:
        # NULL holds nothing: {not archived} is false where archived is NULL, not {archived} true there; NULL and
        # false is false; numbers compare as numbers; authz.uid() is a user's id, never a service's
        self.check(
            "type user = app.users\ntype service = app.services principal\ntype doc = app.docs\n"
            "  owner : user = owner_id\n  bot : service = bot_id\n  can run = bot\n"
            "  can a = owner and {not archived}\n  can b = owner and not {archived}\n"
            "  can c = {owner_id = authz.uid()}\n  can d = {size > 10 or kind in ('x', 'w')}\n"
            "  can e = {kind not in ('x', null)}\n  can f = {kind <> 'x'}\n  can g = {size > 9}\n"
            "  can h = {not (archived and kind = 'z')}\n  can i = {archived is not null}\n",
            "user: 1, 2\nservice: 1\ndoc: 1, 2, 3\ndoc 1 owner user 1\ndoc 2 owner user 1\ndoc 3 owner user 1\n"
            "doc 1: archived = false, size = 11, kind = 'z'\ndoc 2: archived = null, size = null, kind = 'x'\n"
            "doc 3: archived = true, size = 10, kind = null\n",
            {
                "1": {"doc.a": "1", "doc.b": "1, 2", "doc.c": "1, 2, 3", "doc.d": "1, 2", "doc.e": "", "doc.f": "1"},
                "2": {"doc.a": "", "doc.b": "", "doc.c": "", "doc.d": "1, 2", "doc.e": "", "doc.f": "1"},
                "service:1": {"doc.c": ""},
                "": {"doc.c": "", "doc.d": "1, 2", "doc.g": "1, 3", "doc.h": "1, 2", "doc.i": "1, 3"},
            },
        )

    @worked_from("conditions-sql")
    def test_what_depends_on_the_column_type_is_left_to_the_database(self) -> None:
        # text in order follows the collation; text Postgres casts to the column's type; the user key's order. A
        # linked column's id compared with a number is a number (tests/conditions_test.py asks Postgres)
        from authzlib.conditions import compare, simple

        for sql in ("name < 'b'", "size = '10'", "done = 't'", "kind in ('x', 'yes')", "owner_id < authz.uid()"):
            self.assertIsNone(simple(sql), sql)
        for sql in ("name = 'b'", "size < 10", "done", "kind in ('x', 'w')", "owner_id = authz.uid()", "x = ''"):
            self.assertIsNotNone(simple(sql), sql)
        self.assertIs(compare("<", "2", 10), True)
        self.assertIs(compare("<", "2", "10"), False)

    @worked_from("relation-again")
    def test_a_relation_with_two_sources(self) -> None:
        self.check(
            "type user = app.users\ntype folder = app.folders\n  viewer : user = viewer_id\n"
            "  viewer : user = app.folder_viewers(folder_id -> user_id)\n  can view = viewer\n",
            "user: ann, bo\nfolder: 1, 2, 3\nfolder 1 viewer user ann\nfolder 2 viewer[1] user ann\n"
            "folder 3 viewer[1] user bo\n",
            {"ann": {"folder.view": "1, 2"}, "bo": {"folder.view": "3"}},
        )

    @worked_from("subjects")
    def test_a_group_named_by_a_permission(self) -> None:
        # shared with team#manage, a permission: whoever holds it on the team holds the relation, as with a relation
        self.check(
            "type user = app.users\ntype team = app.teams\n  member : user = app.team_members(team_id -> user_id)\n"
            "  boss : user = boss_id\n  can manage = boss\n"
            "type doc = app.docs\n  owner : user = owner_id\n  reader : user, team#member, team#manage shared\n"
            "  can share = owner\n  can view = owner or reader\n",
            "user: 1, 2, 3, 4\nteam: 1, 2\nteam 1 boss user 1\nteam 2 boss user 3\nteam 1 member user 2\n"
            "team 2 member user 4\ndoc: 10, 11, 12\ndoc 10 reader team#manage 1\ndoc 11 reader team#member 1\n"
            "doc 12 reader team#manage 2\n",
            {
                "1": {"doc.view": "10", "team.manage": "1"},
                "2": {"doc.view": "11", "team.manage": ""},
                "3": {"doc.view": "12", "team.manage": "2"},
                "4": {"doc.view": ""},
                "": {"doc.view": ""},
            },
        )

    @worked_from("relation-again")
    def test_a_relation_declared_again_for_another_type(self) -> None:
        # a doc's parent is a doc (a column, or a link table) or its project: inheritance goes through each; and
        # `owner and not {locked}` gives nothing on a locked doc
        self.check(
            "type user = app.users\ntype project = app.projects\n  owner : user = lead_id\n  can view = owner\n"
            "type doc = app.docs\n  owner : user = owner_id\n  parent : doc = up\n"
            "  parent : doc = app.doc_links(child -> parent)\n  parent : project = project_id\n"
            "  can view = (owner and not {locked}) or parent.view\nrules app.docs\n  select : view\n",
            "user: 1, 2, 3\nproject: 1\ndoc: 1, 2, 3, 4, 5, 6, 7\nproject 1 owner user 3\ndoc 1 owner user 1\n"
            "doc 2 owner user 1\ndoc 7 owner user 2\ndoc 1: locked = false\ndoc 2: locked = true\n"
            "doc 7: locked = false\ndoc 3 parent doc 1\ndoc 4 parent[1] doc 2\ndoc 6 parent[1] doc 5\n"
            "doc 5 parent project 1\ndoc 7 parent project 1\n",
            {
                "1": {"doc.view": "1, 3", "rule app.docs select": "1, 3"},
                "2": {"doc.view": "7"},
                "3": {"doc.view": "5, 6, 7", "rule app.docs select": "5, 6, 7"},
                "": {"doc.view": ""},
            },
        )

    @worked_from("relation-again")
    def test_a_relation_to_users_and_to_objects_gives_its_users(self) -> None:
        # alone in a rule it is the users it links to; the docs it links to give no one
        self.check(
            "type user = app.users\ntype doc = app.docs\n  watcher : user = owner_id\n"
            "  watcher : doc = app.doc_links(child -> parent)\nrules app.docs\n  select : watcher\n",
            "user: 1, 2\ndoc: 1, 2, 3\ndoc 1 watcher user 1\ndoc 3 watcher user 2\ndoc 2 watcher doc 1\n"
            "doc 3 watcher doc 1\n",
            {
                "1": {"rule app.docs select": "1"},
                "2": {"rule app.docs select": "3"},
                "": {"rule app.docs select": ""},
            },
        )

    @worked_from("conditions-sql")
    def test_what_is_not_a_fact_about_the_row(self) -> None:
        # a list that holds a column, or nothing (which Postgres refuses): read as a condition of its own, never as
        # a list of constants
        from authzlib.conditions import simple

        for sql in ("kind in (other_kind)", "kind in ()", "id in (select doc_id from holds)"):
            self.assertIsNone(simple(sql), sql)
        # a number some column type holds otherwise than written (a real column rounds whole numbers past 2^24),
        # the longest Python reads (4300 digits) among them: the database's to read, as any other it can't
        for sql in (
            "size > " + "9" * 4301,
            "size in (1, " + "9" * 5000 + ")",
            "size > " + "9" * 8,
            "size > 0.1",
            "size = 16777216",
        ):
            self.assertIsNone(simple(sql), sql[:20])
        self.assertIsNotNone(simple("size > " + "9" * 7))

    @worked_from("conditions-sql")
    def test_not_in_a_list_is_read_as_a_fact_about_the_row(self) -> None:
        # `kind not in ('a', 'b')`: true for another kind, false for one listed, NULL for no kind, as SQL says
        from authzlib.conditions import simple, truth

        node = simple("kind not in ('a', 'b')")
        assert node is not None
        self.assertEqual([truth(node, {"kind": k}, None) for k in ("c", "a", None)], [True, False, None])

    @worked_from("rows-hold-nothing")
    def test_a_disbanded_team_passes_its_members_on_to_no_team(self) -> None:
        # team 2 is disbanded: its members are no one's, not team 1's (which holds it), nor through team 3 inside it
        self.check(
            "type user = app.users\ntype team = app.teams where {not disbanded}\n"
            "  member : user = app.team_members(team_id -> user_id)\n"
            "  member : team#member = app.teams(parent_id -> id)\n"
            "type folder = app.folders\n  owner : user = owner_id\n  viewer : user, team#member shared\n"
            "  can share = owner\n  can view = viewer\n",
            "user: ann, cy, dan\nteam: 1, 2, 3\nteam 2 fails its where\nteam 1 member team#member 2\n"
            "team 2 member team#member 3\nteam 2 member user ann\nteam 1 member user cy\nteam 3 member user dan\n"
            "folder: 1, 2, 3\nfolder 1 viewer team#member 1\nfolder 2 viewer team#member 2\n"
            "folder 3 viewer team#member 3\n",
            {
                "ann": {"team.member": "", "folder.view": ""},
                "cy": {"team.member": "1", "folder.view": "1"},
                "dan": {"team.member": "3", "folder.view": "3"},
                "": {"team.member": "", "folder.view": ""},
            },
        )

    @worked_from("rows-hold-nothing")
    def test_an_archived_folder_passes_nothing_on_through_any_source(self) -> None:
        # folder 2 is inside the archived folder 1 (a link table) and inside folder 4: only 4 passes view on
        self.check(
            "type user = app.users\ntype folder = app.folders where {not archived}\n  parent : folder = parent_id\n"
            "  linked_into : folder = app.folder_links(folder_id -> parent_id)\n  owner : user = owner_id\n"
            "  can view = owner or parent.view or linked_into.view\n",
            "user: ann, bo, cy\nfolder: 1, 2, 3, 4\nfolder 1 fails its where\nfolder 1 owner user ann\n"
            "folder 2 linked_into folder 1\nfolder 2 linked_into folder 4\nfolder 2 owner user bo\n"
            "folder 3 parent folder 2\nfolder 4 owner user cy\n",
            {"ann": {"folder.view": ""}, "bo": {"folder.view": "2, 3"}, "cy": {"folder.view": "2, 3, 4"}},
        )

    @worked_from("rows-no-rule")
    def test_no_rule_allows_anything_on_a_row_the_where_leaves_out(self) -> None:
        self.check(
            "type user = app.users\ntype folder = app.folders where {not archived}\n  owner : user = owner_id\n"
            "rules app.folders\n  select : anyone\n  update : signed_in\n  delete : owner\n",
            "user: ann\nfolder: 1, 2\nfolder 2 fails its where\nfolder 1 owner user ann\nfolder 2 owner user ann\n",
            {
                "ann": {"rule app.folders select": "1", "rule app.folders update": "1", "rule app.folders delete": "1"},
                "": {"rule app.folders select": "1", "rule app.folders update": "", "rule app.folders delete": ""},
            },
        )

    @worked_from("rows-in-permissions")
    def test_archived_said_in_a_permission_takes_only_that_permission(self) -> None:
        # no where: the archived folder 2 still counts, and passes view on; only edit says {not archived}
        self.check(
            "type user = app.users\ntype folder = app.folders\n  parent : folder = parent_id\n"
            "  owner : user = owner_id\n  can view = owner or parent.view\n  can edit = owner and {not archived}\n"
            "rules app.folders\n  select : view\n  update : edit\n",
            "user: ann\nfolder: 1, 2, 3\nfolder 1 owner user ann\nfolder 2 owner user ann\nfolder 3 parent folder 2\n"
            "folder 1: archived = false\nfolder 2: archived = true\nfolder 3: archived = false\n",
            {
                "ann": {
                    "folder.view": "1, 2, 3",
                    "folder.edit": "1",
                    "rule app.folders select": "1, 2, 3",
                    "rule app.folders update": "1",
                },
                "": {
                    "folder.view": "",
                    "folder.edit": "",
                    "rule app.folders select": "",
                    "rule app.folders update": "",
                },
            },
        )

    @worked_from("relation-sources")
    def test_each_kind_of_source_links_its_subjects(self) -> None:
        # a column, a table with its columns named, a polymorphic pair in a link table, shares
        self.check(
            "type user = app.users\ntype service = app.services principal\ntype project = app.projects\n"
            "  lead : user = lead_id\n  member : user = app.project_members(object: project_id, subject: user_id)\n"
            "  backer : user, service = app.backings(project_id -> (backer_type, backer_id))\n"
            "  guest : user shared\n  can share = lead\n  can view = lead or member or backer or guest\n",
            "user: 1, 2, 3, 4, 5\nservice: 1\nproject: 1, 2\nproject 1 lead user 1\nproject 1 member user 2\n"
            "project 1 guest user 4\nproject 2 backer user 3\nproject 2 backer service 1\n",
            {
                "1": {"project.view": "1"},
                "2": {"project.view": "1"},
                "3": {"project.view": "2"},
                "4": {"project.view": "1"},
                "5": {"project.view": ""},
                "service:1": {"project.view": "2"},
                "": {"project.view": ""},
            },
        )

    @worked_from("relation-again")
    def test_a_relation_declared_three_times_one_of_them_shared(self) -> None:
        self.check(
            "type user = app.users\ntype team = app.teams\n  member : user = app.team_members(team_id -> user_id)\n"
            "type doc = app.docs\n  owner : user = owner_id\n  editor : user = editor_id\n"
            "  editor : user = app.doc_editors(doc_id -> user_id)\n  editor : team#member shared\n"
            "  can share = owner\n  can edit = editor\n",
            "user: ann, bo, cy\nteam: 1\nteam 1 member user cy\ndoc: 1, 2, 3\ndoc 1 editor user ann\n"
            "doc 2 editor[1] user bo\ndoc 3 editor[2] team#member 1\n",
            {
                "ann": {"doc.edit": "1"},
                "bo": {"doc.edit": "2"},
                "cy": {"doc.edit": "3"},
                "": {"doc.edit": ""},
            },
        )

    @worked_from("subjects")
    def test_groups_nest_to_any_depth_and_loop_and_a_token_is_held_by_whoever_brings_it(self) -> None:
        policy = (
            "type user = app.users\ntype team = app.teams\n  member : user = app.team_members(team_id -> user_id)\n"
            "  member : team#member = app.teams(parent_id -> id)\n"
            "type folder = app.folders\n  owner : user = owner_id\n"
            "  viewer : user, team#member, user:*, anyone, link shared\n  can share = owner\n  can view = viewer\n"
        )
        # 2 in 1, 3 in 2, 4 in 3, 2 in 4 (a loop), 5 in itself
        world = (
            "user: ann, bo\nteam: 1, 2, 3, 4, 5\nteam 1 member team#member 2\nteam 2 member team#member 3\n"
            "team 3 member team#member 4\nteam 4 member team#member 2\nteam 5 member team#member 5\n"
            "team 4 member user ann\nteam 1 member user bo\nfolder: 1, 2, 3, 4, 5, 6\nfolder 1 viewer team#member 1\n"
            "folder 2 viewer team#member 3\nfolder 3 viewer team#member 5\nfolder 4 viewer user:* *\n"
            "folder 5 viewer anyone *\nfolder 6 viewer link tok9\n"
        )
        self.check(
            policy,
            world,
            {
                "ann": {"team.member": "1, 2, 3, 4", "folder.view": "1, 2, 4, 5"},
                "bo": {"team.member": "1", "folder.view": "1, 4, 5"},
                "": {"team.member": "", "folder.view": "5"},
            },
        )
        self.check(
            policy,
            world,
            {"ann": {"folder.view": "1, 2, 4, 5, 6"}, "bo": {"folder.view": "1, 4, 5, 6"}, "": {"folder.view": "5, 6"}},
            links=["tok9"],
        )

    @worked_from("principals")
    def test_services_are_named_like_users_and_signed_in_is_about_users(self) -> None:
        # user 1 and service 1 share an id, and are two
        self.check(
            "type user = app.users\ntype service = app.services principal\ntype folder = app.folders\n"
            "  owner : user = owner_id\n  bot : service = bot_id\n  reader : user, service shared\n"
            "  viewer : user:*, service:* shared\n  can share = owner\n  can view = reader or bot or viewer\n"
            "  can open = signed_in\n",
            "user: 1, 2\nservice: 1, 2\nfolder: 1, 2, 3, 4, 5\nfolder 1 reader service 1\nfolder 2 reader user 1\n"
            "folder 3 viewer user:* *\nfolder 4 viewer service:* *\nfolder 5 bot service 2\n",
            {
                "1": {"folder.view": "2, 3", "folder.open": "1, 2, 3, 4, 5"},
                "2": {"folder.view": "3", "folder.open": "1, 2, 3, 4, 5"},
                "service:1": {"folder.view": "1, 4", "folder.open": ""},
                "service:2": {"folder.view": "4, 5", "folder.open": ""},
                "": {"folder.view": "", "folder.open": ""},
            },
        )

    @worked_from("permission-operators")
    def test_parentheses_say_what_goes_first(self) -> None:
        # ann holds, on docs 1 to 8: nothing, a, b, c, a b, a c, b c, a b c
        self.check(
            "type user = app.users\ntype doc = app.docs\n  a : user = a_id\n  b : user = b_id\n  c : user = c_id\n"
            "  can p = a or (b and c)\n  can q = (a or b) and c\n  can r = not (a or b)\n"
            "  can s = a and not b and c\n",
            "user: ann\ndoc: 1, 2, 3, 4, 5, 6, 7, 8\ndoc 2 a user ann\ndoc 3 b user ann\ndoc 4 c user ann\n"
            "doc 5 a user ann\ndoc 5 b user ann\ndoc 6 a user ann\ndoc 6 c user ann\ndoc 7 b user ann\n"
            "doc 7 c user ann\ndoc 8 a user ann\ndoc 8 b user ann\ndoc 8 c user ann\n",
            {
                "ann": {"doc.p": "2, 5, 6, 7, 8", "doc.q": "6, 7, 8", "doc.r": "1, 4", "doc.s": "6"},
                "": {"doc.p": "", "doc.q": "", "doc.r": "1, 2, 3, 4, 5, 6, 7, 8", "doc.s": ""},
            },
        )

    @worked_from("follow-relation")
    def test_a_relation_followed_to_a_users_own_permission(self) -> None:
        # user 2's manager is user 1; user 3 blocked user 4; user 4 is org 1's admin
        self.check(
            "type user = app.users\n  manager : user = manager_id\n  can oversee = manager\n"
            "  blocked : user = app.blocks(blocker_id -> blocked_id)\n  can has_blocked = blocked\n"
            "type org = app.orgs\n  admin : user = app.org_admins(org_id -> user_id)\n"
            "type doc = app.docs\n  author : user = author_id\n  org : org = org_id\n"
            "  can review = author.oversee or org.admin\n  can comment = signed_in and not author.has_blocked\n",
            "user: 1, 2, 3, 4\nuser 2 manager user 1\nuser 3 blocked user 4\norg: 1\norg 1 admin user 4\n"
            "doc: 1, 2, 3\ndoc 1 author user 2\ndoc 2 author user 3\ndoc 3 author user 1\ndoc 3 org org 1\n",
            {
                "1": {"user.oversee": "2", "doc.review": "1", "doc.comment": "1, 2, 3"},
                "2": {"doc.review": "", "doc.comment": "1, 2, 3"},
                "3": {"doc.review": "", "doc.comment": "1, 2, 3"},
                "4": {"doc.review": "3", "doc.comment": "1, 3"},
                "": {"doc.review": "", "doc.comment": ""},
            },
        )

    @worked_from("signed-in-anyone-nobody")
    def test_signed_in_anyone_and_nobody(self) -> None:
        self.check(
            "type user = app.users\ntype service = app.services principal\ntype dir = app.dirs\n"
            "  owner : user = owner_id\n  can a = signed_in\n  can b = anyone\n  can c = nobody or owner\n"
            "rules app.dirs\n  select : anyone\n  update : signed_in\n  delete : nobody\n",
            "user: 1\nservice: 1\ndir: 1, 2\ndir 2 owner user 1\n",
            {
                "1": {
                    "dir.a": "1, 2",
                    "dir.b": "1, 2",
                    "dir.c": "2",
                    "rule app.dirs select": "1, 2",
                    "rule app.dirs update": "1, 2",
                    "rule app.dirs delete": "",
                },
                "service:1": {
                    "dir.a": "",
                    "dir.b": "1, 2",
                    "dir.c": "",
                    "rule app.dirs select": "1, 2",
                    "rule app.dirs update": "",
                    "rule app.dirs delete": "",
                },
                "": {
                    "dir.a": "",
                    "dir.b": "1, 2",
                    "dir.c": "",
                    "rule app.dirs select": "1, 2",
                    "rule app.dirs update": "",
                    "rule app.dirs delete": "",
                },
            },
        )

    @worked_from("conditions-null")
    def test_a_null_condition_holds_nothing_and_not_of_it_holds(self) -> None:
        self.check(
            "type user = app.users\ntype doc = app.docs\n  owner : user = owner_id\n  can a = {archived}\n"
            "  can b = {not archived}\n  can c = not {archived}\n  can d = not {not archived}\n"
            "rules app.docs\n  select : {not archived} or owner\n",
            "user: ann\ndoc: 1, 2, 3\ndoc 3 owner user ann\ndoc 1: archived = true\ndoc 2: archived = false\n"
            "doc 3: archived = null\n",
            {
                "ann": {"doc.a": "1", "doc.b": "2", "doc.c": "2, 3", "doc.d": "1, 3", "rule app.docs select": "2, 3"},
                "": {"doc.a": "1", "doc.b": "2", "doc.c": "2, 3", "doc.d": "1, 3", "rule app.docs select": "2"},
            },
        )

    @worked_from("inheritance")
    def test_inheritance_goes_as_deep_as_it_goes_through_any_mix_of_sources(self) -> None:
        # folders 1 to 9 in a chain, each inside the one before by a column or a link table in turn, folder 1 inside
        # project 1; edit stops where {inherit} doesn't hold (folder 4)
        self.check(
            "type user = app.users\ntype project = app.projects\n  owner : user = owner_id\n  can view = owner\n"
            "type folder = app.folders\n  owner : user = owner_id\n  parent : folder = parent_id\n"
            "  parent : folder = app.folder_links(folder_id -> parent_id)\n  inside : project = project_id\n"
            "  can view = owner or parent.view or inside.view\n  can edit = owner or (parent.edit and {inherit})\n",
            "user: ann, bo\nproject: 1\nproject 1 owner user ann\nfolder: 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11\n"
            "folder 1 inside project 1\nfolder 1 owner user ann\nfolder 2 parent folder 1\nfolder 3 parent[1] folder 2\n"
            "folder 4 parent folder 3\nfolder 5 parent[1] folder 4\nfolder 6 parent folder 5\n"
            "folder 7 parent[1] folder 6\nfolder 8 parent folder 7\nfolder 9 parent[1] folder 8\n"
            "folder 10 parent[1] folder 11\nfolder 11 owner user bo\n{inherit} on folder 2, 3, 5\n",
            {
                "ann": {"folder.view": "1, 2, 3, 4, 5, 6, 7, 8, 9", "folder.edit": "1, 2, 3", "project.view": "1"},
                "bo": {"folder.view": "10, 11", "folder.edit": "11"},
                "": {"folder.view": "", "folder.edit": ""},
            },
        )

    @worked_from("deny-below")
    def test_a_deny_for_one_person_covers_everything_below_even_where_she_is_named(self) -> None:
        self.check(
            "type user = app.users\ntype folder = app.folders\n  parent : folder = parent_id\n"
            "  viewer : user = app.folder_viewers(folder_id -> user_id)\n"
            "  blocked : user = app.folder_blocks(folder_id -> user_id)\n  can hidden = blocked or parent.hidden\n"
            "  can view = (viewer or parent.view) and not hidden\n",
            "user: ann, bo\nfolder: 1, 2, 3, 4, 5\nfolder 2 parent folder 1\nfolder 3 parent folder 2\n"
            "folder 4 parent folder 3\nfolder 5 parent folder 1\nfolder 1 viewer user ann\nfolder 1 viewer user bo\n"
            "folder 3 viewer user ann\nfolder 2 blocked user ann\n",
            {
                "ann": {"folder.view": "1, 5", "folder.hidden": "2, 3, 4"},
                "bo": {"folder.view": "1, 2, 3, 4, 5", "folder.hidden": ""},
            },
        )

    @worked_from("deny-other-types")
    def test_a_deny_beside_another_types_permission(self) -> None:
        # ann: project 1's member, so folders 1 and 3 (in project 1) and all below 1; blocked on 2, so 2 and 3 are
        # hidden from her, even 3, which project.view gives her on its own
        policy = (
            "type user = app.users\ntype project = app.projects\n"
            "  member : user = app.project_members(project_id -> user_id)\n  can view = member\n"
            "type folder = app.folders\n  parent : folder = parent_id\n  project : project = project_id\n"
            "  viewer : user = app.folder_viewers(folder_id -> user_id)\n"
            "  blocked : user = app.folder_blocks(folder_id -> user_id)\n  can hidden = blocked or parent.hidden\n"
            "  can view = (viewer or parent.view or project.view) and not hidden\n"
        )
        self.check(
            policy,
            "user: ann, bo\nproject: 1\nproject 1 member user ann\nfolder: 1, 2, 3, 4\nfolder 2 parent folder 1\n"
            "folder 3 parent folder 2\nfolder 4 parent folder 1\nfolder 1 project project 1\n"
            "folder 3 project project 1\nfolder 4 viewer user bo\nfolder 2 blocked user ann\n",
            {
                "ann": {"project.view": "1", "folder.view": "1, 4", "folder.hidden": "2, 3"},
                "bo": {"project.view": "", "folder.view": "4", "folder.hidden": ""},
                "": {"folder.view": ""},
            },
        )
        # refused: the deny's inheritance through a relation that points at projects too, and through a project.view
        # that comes back to folders
        for text, words in (
            (
                policy.replace(
                    "  parent : folder = parent_id\n", "  parent : folder, project = (parent_type, parent_id)\n"
                ),
                "folder.view has a deny and inherits through parent, which also points at other types",
            ),
            (
                policy.replace(
                    "  can view = member\n", "  folder : folder = folder_id\n  can view = member or folder.view\n"
                ),
                "folder.view has a deny, so it can only inherit within folder",
            ),
        ):
            with self.assertRaisesRegex(PolicyError, re.escape(words) + r".*\[AZ306\]"):
                Compiler(parse_policy(self.HEAD + text, "hand.authz")).compile("hand.authz")

    @worked_from("condition-every-level")
    def test_a_condition_joined_to_inheritance_stops_it_but_names_below_still_count(self) -> None:
        self.check(
            "type user = app.users\ntype folder = app.folders\n  parent : folder = parent_id\n"
            "  viewer : user = app.folder_viewers(folder_id -> user_id)\n"
            "  can view = (viewer or parent.view) and {not archived}\n",
            "user: ann, cy\nfolder: 1, 2, 3, 4\nfolder 2 parent folder 1\nfolder 3 parent folder 2\n"
            "folder 4 parent folder 3\nfolder 1 viewer user ann\nfolder 3 viewer user cy\nfolder 1: archived = false\n"
            "folder 2: archived = true\nfolder 3: archived = false\nfolder 4: archived = false\n",
            {"ann": {"folder.view": "1"}, "cy": {"folder.view": "3, 4"}},
        )

    @worked_from("roles-include")
    def test_a_role_gives_the_permissions_it_includes_and_the_deny_holds_for_it(self) -> None:
        # ann: view on 1, blocked on 2; bo: edit only, on 2; team 1's members (cy): view on 3; dan: view and edit on 1
        self.check(
            "type user = app.users\ntype team = app.teams\n  member : user = app.team_members(team_id -> user_id)\n"
            "type org = app.orgs\n  admin : user = app.org_admins(org_id -> user_id)\n  can manage_roles = admin\n"
            "type folder = app.folders\n  owner : user = owner_id\n  parent : folder = parent_id\n"
            "  viewer : user shared\n  blocked : user = app.folder_blocks(folder_id -> user_id)\n"
            "  roles : user, team#member\n  can share = owner\n  can hidden = blocked or parent.hidden\n"
            "  can view = (viewer or roles or parent.view) and not hidden\n  can edit = owner or roles\n",
            "user: ann, bo, cy, dan\nteam: 1\nteam 1 member user cy\norg: 1\nfolder: 1, 2, 3\nfolder 2 parent folder 1\n"
            "folder 3 parent folder 2\nfolder 2 blocked user ann\nrole view on folder 1 for user ann\n"
            "role edit on folder 2 for user bo\nrole view on folder 3 for team#member 1\n"
            "role view on folder 1 for user dan\nrole edit on folder 1 for user dan\n",
            {
                "ann": {"folder.view": "1", "folder.edit": ""},
                "bo": {"folder.view": "", "folder.edit": "2"},
                "cy": {"folder.view": "3", "folder.edit": ""},
                "dan": {"folder.view": "1, 2, 3", "folder.edit": "1"},
            },
        )

    @worked_from("roles-from")
    def test_roles_from_an_org_a_table_links(self) -> None:
        self.check(
            "type user = app.users\ntype org = app.orgs\n  admin : user = app.org_admins(org_id -> user_id)\n"
            "  can manage_roles = admin\n"
            "type folder = app.folders\n  org : org = app.org_folders(folder_id -> org_id)\n  owner : user = owner_id\n"
            "  roles : user from org\n  can share = owner or org.admin\n  can view = owner or roles\n",
            "user: ann, bo\norg: 1, 2\nfolder: 1, 2, 3\nfolder 1 org org 1\nfolder 2 org org 2\n"
            "role view on folder 1 for user ann from org 1\nrole view on folder 2 for user ann from org 1\n"
            "role view on folder 3 for user ann from org 1\nrole view on folder 3 for user bo from org 2\n",
            {"ann": {"folder.view": "1"}, "bo": {"folder.view": ""}},
        )

    @worked_from("roles-refused")
    def test_a_folder_moved_to_another_org_honours_that_orgs_roles(self) -> None:
        policy = self.ROLES.format(**{"from": " from org"})
        roles = "role view on folder 1 for user ann from org 1\nrole view on folder 1 for user bo from org 2\n"
        before = "user: ann, bo\norg: 1, 2\nfolder: 1\nfolder 1 org org 1\n" + roles
        self.check(policy, before, {"ann": {"folder.view": "1"}, "bo": {"folder.view": ""}})
        self.check(
            policy, before.replace("org org 1", "org org 2"), {"ann": {"folder.view": ""}, "bo": {"folder.view": "1"}}
        )

    @worked_from("rules-commands")
    def test_each_command_needs_what_its_rule_says(self) -> None:
        self.check(
            "type user = app.users\ntype doc = app.docs\n  owner : user = owner_id\n"
            "  viewer : user = app.doc_viewers(doc_id -> user_id)\n  can view = owner or viewer\n  can edit = owner\n"
            "rules app.docs\n  select : view\n  update : edit\n  delete : owner and {not locked}\n",
            "user: ann, bo\ndoc: 1, 2, 3\ndoc 1 owner user ann\ndoc 2 owner user ann\ndoc 1 viewer user bo\n"
            "doc 1: locked = false\ndoc 2: locked = true\ndoc 3: locked = false\n",
            {
                "ann": {"rule app.docs select": "1, 2", "rule app.docs update": "1, 2", "rule app.docs delete": "1"},
                "bo": {"rule app.docs select": "1", "rule app.docs update": "", "rule app.docs delete": ""},
                "": {"rule app.docs select": "", "rule app.docs update": "", "rule app.docs delete": ""},
            },
        )

    INVARIANT = (
        "type user = app.users\ntype service = app.services principal\ntype folder = app.folders\n"
        "  owner : user = owner_id\n  viewer : user, service, anyone shared\n  can share = owner\n"
        "  can view = owner or viewer\ninvariants\n  never folder: view and not signed_in\n"
    )

    @worked_from("invariants")
    def test_an_invariant_is_asked_as_each_service(self) -> None:
        self.check(
            self.INVARIANT, "user: 1\nservice: 1\nfolder: 1\nfolder 1 viewer service 1\n", {}, broken="service:1 on 1"
        )

    @worked_from("invariants")
    def test_an_invariant_is_asked_as_nobody(self) -> None:
        self.check(self.INVARIANT, "folder: 1\nfolder 1 viewer anyone *\n", {}, broken="nobody on 1")

    @worked_from("invariants")
    def test_an_invariant_no_one_breaks(self) -> None:
        self.check(self.INVARIANT, "user: 1\nfolder: 1\nfolder 1 viewer user 1\n", {}, broken="none")

    @worked_from("rows-no-invariant")
    def test_an_invariant_is_not_asked_of_a_row_the_where_leaves_out(self) -> None:
        # nobody owns either folder, but the second is archived: only the first breaks it
        policy = (
            "type user = app.users\ntype folder = app.folders where {not archived}\n  owner : user = owner_id\n"
            "  can view = owner\n  can orphan = not owner\ninvariants\n  never folder: orphan\n"
        )
        self.check(
            policy, "user: 1\nfolder: 2\nfolder 2 fails its where\n", {"1": {"folder.orphan": ""}}, broken="none"
        )
        self.check(
            policy, "user: 1\nfolder: 1, 2\nfolder 2 fails its where\n", {"1": {"folder.orphan": "1"}}, broken="1 on 1"
        )

    ANCHOR = re.compile(r"<!-- answer: ([a-z0-9-]+(?:, [a-z0-9-]+)*) -->")

    def test_every_answering_paragraph_has_a_case(self) -> None:
        # each anchor on the page has a case here or in tests/hand/, each case names anchors the page has, and each
        # case here names one
        with open(os.path.join(os.path.dirname(ROOT), "docs", "reference", "language.md"), encoding="utf-8") as fh:
            page = fh.read()
        anchors = self.ANCHOR.findall(page)
        self.assertEqual(len(re.findall(r"<!--\s*answer\b", page)), len(anchors), "an anchor not in the form")
        on_page = [a for m in anchors for a in m.split(", ")]
        self.assertEqual(len(on_page), len(set(on_page)), "an anchor twice on the page")
        cases: dict[str, set[str]] = {}
        for name, fn in vars(HandAnswers).items():
            if name.startswith("test_") and name != "test_every_answering_paragraph_has_a_case":
                self.assertIn(fn, HAND_ANCHORS, f"{name} names no paragraph (@worked_from)")
                for a in HAND_ANCHORS[fn]:
                    cases.setdefault(a, set()).add(name)
        hand = sorted(glob.glob(os.path.join(ROOT, "tests", "hand", "*.authz")))
        self.assertTrue(hand)
        for path in hand:
            with open(path, encoding="utf-8") as fh:
                named = [a for line in fh for a in re.findall(r"^-- answer: (.+)$", line.rstrip("\n"))]
            self.assertTrue(named, f"{path} names no paragraph (-- answer: name)")
            for a in ", ".join(named).split(", "):
                cases.setdefault(a, set()).add(os.path.basename(path))
        self.assertEqual(sorted(set(on_page) - set(cases)), [], "anchors with no case")
        self.assertEqual({a: c for a, c in cases.items() if a not in on_page}, {}, "cases naming no anchor")


class Rewrites(unittest.TestCase):
    """tests/rewrites.py holds the review's "grants the same" against the database on rewrites of random policies.
    Here, the rewrites themselves: those it lists as changing nothing change no truth table, each of the others
    changes one somewhere, and a policy's rewrites each rewrite one permission or select rule of it."""

    ATOMS: ClassVar[list[str]] = ["a", "b", "c"]
    NODES: ClassVar[list[object]] = [
        "a",
        ("or", ["a", "b"]),
        ("and", ["a", ("or", ["b", "c"])]),
        ("and", ["a", "b", ("not", ["c"])]),
        ("or", [("and", ["a", "b"]), "c", ("and", ["b", ("or", ["a", "c"]), ("not", ["a"])])]),
    ]

    def holds(self, n: object, facts: dict[str, bool]) -> bool:
        if isinstance(n, str):
            return {"anyone": True, "nobody": False}.get(n, facts.get(n, False))
        assert isinstance(n, tuple)
        op, parts = n
        assert isinstance(parts, list)
        values = [self.holds(x, facts) for x in parts]
        return not values[0] if op == "not" else any(values) if op == "or" else all(values)

    def tables(self, law: Callable[..., object]) -> list[tuple[object, object, list[bool], list[bool]]]:
        """Each node a law rewrites (over a few draws), the node it gives, and the truth table of each."""
        import random

        import rewrites

        out = []
        names = [*self.ATOMS, *rewrites.CONDS[:3]]  # (and the conditions `and not` may add)
        worlds = [dict(zip(names, v, strict=True)) for v in itertools.product([False, True], repeat=len(names))]
        for n in self.NODES:
            for seed in range(6):
                new = law(n, random.Random(seed), self.ATOMS)
                if new is not None:
                    out.append((n, new, [self.holds(n, w) for w in worlds], [self.holds(new, w) for w in worlds]))
        return out

    def test_the_rewrites_that_change_nothing_change_no_truth_table(self) -> None:
        import rewrites

        self.assertEqual(len(rewrites.SAME), 6)
        for name, law in rewrites.SAME.items():
            made = self.tables(law)
            self.assertTrue(made, name)  # (each has a node here it rewrites)
            for n, new, before, after in made:
                self.assertNotEqual(n, new, name)
                self.assertEqual(before, after, (name, n, new))

    def test_each_of_the_others_changes_one_somewhere(self) -> None:
        import rewrites

        self.assertEqual(len(rewrites.OTHER), 4)
        for name, law in rewrites.OTHER.items():
            self.assertTrue(any(before != after for _, _, before, after in self.tables(law)), name)

    def test_a_part_under_a_not_is_left_as_it_is(self) -> None:
        import random

        import rewrites

        n = ("and", ["a", ("not", [("or", ["b", "c"])])])
        self.assertEqual(list(rewrites.paths(n)), [(), (0,), (1,), (1, 0), (1, 0, 0), (1, 0, 1)])
        self.assertEqual([p for p in rewrites.paths(n) if rewrites.under_not(n, p)], [(1, 0), (1, 0, 0), (1, 0, 1)])
        self.assertEqual(rewrites.with_part(n, (0,), "z"), ("and", ["z", ("not", [("or", ["b", "c"])])]))
        # the `not` itself is no part to say twice or to turn round, and it stays last where the parts are turned
        for law in rewrites.SAME.values():
            self.assertIsNone(law(n[1][1], random.Random(1), self.ATOMS))
        self.assertEqual(
            rewrites.turned(("and", ["a", "b", ("not", ["c"])]), random.Random(1), []),
            ("and", ["b", "a", ("not", ["c"])]),
        )
        # an `or` takes no `not`: an `and` that has one is not made an `or`, nor left with it alone
        self.assertIsNone(rewrites.other_word(("and", ["a", ("not", ["c"])]), random.Random(1), []))
        for seed in range(8):
            left = rewrites.dropped(("and", ["a", ("not", ["c"])]), random.Random(seed), [])
            self.assertIn(left, (None, "a"))

    def test_a_policys_rewrites_each_rewrite_one_permission_or_select_rule(self) -> None:
        import random

        import genpolicy
        import rewrites

        spec = genpolicy.make(1)
        made = rewrites.rewrites(spec, random.Random("rewrites/1"), 3)
        self.assertEqual([rw.same for rw in made], [True] * 3 + [False] * 3)
        text = genpolicy.policy_text(spec)
        for rw in made:
            new = genpolicy.policy_text(rw.spec)
            lines = [(a, b) for a, b in zip(text.split("\n"), new.split("\n"), strict=True) if a != b]
            self.assertEqual(len(lines), 1, rw.what)  # (one line of the policy, the one its name says)
            head = lines[0][0].split("=")[0].split(":")[0].split()
            where, _, law = rw.what.partition(": ")
            self.assertIn(law, {**rewrites.SAME, **rewrites.OTHER})
            self.assertEqual(head[-1], "select" if where.endswith("select rule") else where.split(".")[1], rw.what)


class Invariance(unittest.TestCase):
    """tests/invariance.py writes policies another way and renumbers their data, and wants the same SQL and the same
    answers. Here, what it compares by: a policy written each way compiles to the same objects, one that says
    something else doesn't, and keys renumbered map back."""

    def test_the_docs_policy_written_each_way_compiles_to_the_same_sql(self) -> None:
        import random

        import invariance

        text = read("example/docs.authz")
        base = invariance.objects(text, {})
        for name, transform in invariance.TRANSFORMS.items():
            new_text, files = transform(text, {}, random.Random(1))
            self.assertNotEqual(new_text, text, name)
            self.assertEqual(bool(files), name == "included", name)
            diffs, counts = invariance.sql_differences(base, invariance.objects(new_text, files))
            self.assertEqual(diffs, [], name)
            self.assertGreater(counts["same"], 300, name)

    def test_a_policy_that_says_something_else_is_another_sql(self) -> None:
        import invariance

        text = read("example/docs.authz")
        other = text.replace("can edit  = share or editor or", "can edit  = share or")
        self.assertNotEqual(other, text)
        diffs, _ = invariance.sql_differences(invariance.objects(text, {}), invariance.objects(other, {}))
        self.assertIn('view authz_int."folder__editor": made 1 times before the change, 0 after', diffs)
        self.assertTrue(any(d.startswith('function authz_int."folder__edit__why"') for d in diffs), diffs)

    def test_operands_written_alike_stay_alike(self) -> None:
        import random

        import invariance

        e = authzlib.parse.ExprParser("(a or b or c) and (a or b or c) and not d", authzlib.parse.Loc(None, 0)).parse()
        for seed in range(6):
            new = authzlib.parse.written(invariance.shuffled_expr(e, invariance.ranks(random.Random(seed))))
            first, second, last = new.split(" and ")
            self.assertEqual(first, second)
            self.assertEqual(last, "not d")  # (what a `not` takes away from stays before it)

    def test_keys_renumbered_map_back(self) -> None:
        import random

        import invariance

        pol = authzlib.parse.parse_policy(genpolicy.policy_text(genpolicy.make(2)), "gen.authz", {})
        t1 = pol.types["t1"]
        self.assertTrue(t1.composite)
        ren = invariance.Renumbering(pol, random.Random(1))
        for ident in ("(1,2)", "(2,3)"):
            for k, p in enumerate(invariance.parts(t1, ident)):
                ren.see(invariance.domain(t1, k), p)
        ren.see("user", "1")
        ren.see("bot", "2")
        ren.draw()
        for ident in ("(1,2)", "(2,3)"):
            new = ren.ident(t1, ident)
            self.assertNotEqual(new, ident)
            self.assertEqual(ren.ident(t1, new, back=True), ident)
        self.assertEqual(ren.ident(t1, "999999"), "999999")  # (an id no row had stays as it is)
        self.assertEqual(ren.principal(ren.principal("bot:2"), back=True), "bot:2")
        self.assertEqual(ren.principal(""), "")


class SmallPolicies(unittest.TestCase):
    """tests/small.py lists every policy of the core language up to a size, once each: two spellings of one policy
    (its names swapped, its parts in another order) are one, two policies are two, and the set has as many as
    COUNTS says. The worlds the evaluator answers in are made as rows (load_sql), the bridge to a database."""

    def setUp(self) -> None:
        import small

        self.s = small

    def spec(self, text: str) -> genpolicy.Spec:
        """A policy of the set's kind from its text: each type's relations and permissions as genpolicy keeps them."""
        import textwrap

        objs: list[genpolicy.Obj] = []
        user_where = False
        for line in textwrap.dedent(text).strip().splitlines():
            words = line.split()
            if line.startswith("type user"):
                user_where = "where" in words
            elif line.startswith("type "):
                objs.append(genpolicy.Obj(words[1], "where" in words, [], {}, []))
            elif line.startswith("  can "):
                name, _, expr = line[6:].partition(" = ")
                objs[-1].perms[name] = self.node(expr)
            else:
                name, _, rest = line.strip().partition(" : ")
                subjects, kind = rest.rsplit(" ", 1)
                objs[-1].rels.append(genpolicy.Rel(name, kind, subjects.split(", ")))
        return genpolicy.Spec(0, user_where, False, objs)

    def node(self, text: str) -> genpolicy.Node:
        """`a or (b and not c)` as genpolicy's tree (the set's expressions: or, and, not, parentheses)."""
        tokens = re.findall(r"\(|\)|[^\s()]+", text)

        def parse(i: int) -> tuple[genpolicy.Node, int]:
            items: list[genpolicy.Node] = []
            op = ""
            while i < len(tokens) and tokens[i] != ")":
                if tokens[i] in ("or", "and"):
                    op, i = tokens[i], i + 1
                    continue
                negated = tokens[i] == "not"
                i += negated
                if tokens[i] == "(":
                    item, i = parse(i + 1)
                    i += 1
                else:
                    item, i = tokens[i], i + 1
                items.append(("not", [item]) if negated else item)
            return (items[0] if len(items) == 1 else (op, items)), i

        return parse(0)[0]

    def test_two_spellings_of_one_policy_are_one(self) -> None:
        one = self.spec("""
            type user
            type t1 where
              r1 : user column
              r2 : user table
              r3 : user table
              parent : t1 column
              can p1 = (r1 or r2) and not {b1}
              can p2 = (r3 and p1) or parent.p2
        """)
        other = self.spec("""
            type user
            type t1 where
              parent : t1 column
              r3 : user table
              r1 : user column
              r2 : user table
              can p2 = not {b1} and (r3 or r1)
              can p1 = parent.p1 or (p2 and r2)
        """)
        self.assertEqual(self.s.canonical(one), self.s.canonical(other))
        # every policy of size 4 written another way: names the other way round, declared the other way round,
        # every `or` and `and` turned round
        for spec in self.s.listed(4):
            if "?" in self.s.canonical(spec):
                continue  # (an arrow to a permission one of its types doesn't have: refused, AZ203)
            again, _, _ = self.s.respelled(spec)
            again = dataclasses.replace(again, objs=[dataclasses.replace(o, rels=o.rels[::-1]) for o in again.objs])
            self.assertEqual(self.s.canonical(again), self.s.canonical(spec), genpolicy.policy_text(spec))

    def test_two_policies_are_two(self) -> None:
        def key(text: str) -> str:
            return self.s.canonical(self.spec(text))

        base = "type user\ntype t1\n  r1 : user column\n  r2 : user table\n"
        self.assertNotEqual(key(base + "  can p1 = r1 or r2\n"), key(base + "  can p1 = r1 and r2\n"))
        self.assertNotEqual(key(base + "  can p1 = r1 and not r2\n"), key(base + "  can p1 = r2 and not r1\n"))
        # r1 and r2 aren't each other's: their sources differ
        self.assertNotEqual(
            key(base + "  can p1 = r1\n  can p2 = p1 or r2\n"), key(base + "  can p1 = r2\n  can p2 = p1 or r1\n")
        )
        # `parent.p1` through a pair of columns naming t2 and t1 is p1 of both: renaming t2's alone is another policy
        two = "type user\ntype t1\n  r1 : user column\n  can p1 = r1\ntype t2\n  parent : t2, t1 column\n"
        self.assertNotEqual(
            key(two + "  can p1 = parent.p1 or {b1}\n  can p2 = p1\n"),
            key(two + "  can p1 = p2\n  can p2 = parent.p2 or {b1}\n"),
        )
        keys = [self.s.canonical(spec) for spec in self.s.listed(4)]
        self.assertEqual(len(keys), len(set(keys)))

    def test_the_counts(self) -> None:
        for n in range(1, 5):
            specs = self.s.listed(n)
            self.assertEqual((len(specs), sum(map(self.s.denies, specs))), (self.s.COUNTS[n], self.s.DENIES[n]), n)
        self.assertTrue(all(map(self.s.well_formed, self.s.listed(4))))
        # each policy of the set is of its size
        self.assertEqual({self.s.size(spec) for spec in self.s.listed(4)}, {4})

    def test_a_world_as_rows(self) -> None:
        self.maxDiff = None
        spec = self.s.decorated(
            self.spec("""
            type user where
            type t1 where
              r1 : user column
              member : user, t1#member shared
              parent : t1 table
              can p1 = r1 or member or parent.p1
        """)
        )
        pol = parse_policy(genpolicy.policy_text(spec), "small.authz")
        ids, dims = self.s.dims(pol, 2)
        self.assertEqual(ids, {"user": ["1", "2"], "t1": ["1", "2"]})
        # b3 of each row; r1 of each row (none, user 1 or 2); member: each row to each user and each group;
        # parent: each row to each row
        self.assertEqual([len(d) for d in dims], [2, 2, 3, 3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2])
        data = self.s.data_of(
            pol,
            ids,
            [
                ("col", "t1", "1", "b3", False),
                ("col", "t1", "2", "b3", True),
                ("pair", "t1\tr1\t0\tuser\t", "1", "2", None),
                ("pair", "t1\tmember\t0\tt1\tmember", "2", "1", None),
                ("pair", "t1\tparent\t0\tt1\t", "2", "1", None),
            ],
        )
        self.assertEqual((data.valid["user"], data.valid["t1"]), (["1"], ["1"]))
        rows, shares = self.s.load_sql(pol, data)
        self.assertEqual(
            rows.splitlines(),
            [
                'INSERT INTO "gp"."users" ("id", "active") VALUES (1, true);',
                'INSERT INTO "gp"."users" ("id", "active") VALUES (2, false);',
                'INSERT INTO "gp"."t1" ("id", "b3", "c_r1") VALUES (1, false, 2);',
                'INSERT INTO "gp"."t1" ("id", "b3") VALUES (2, true);',
                'INSERT INTO "gp"."t1_parent" ("obj_id", "subj_id") VALUES (2, 1);',
            ],
        )
        self.assertEqual(
            shares,
            "INSERT INTO authz.shares (object_type, object_id, relation, subject_type, subject_id, subject_relation) "
            "VALUES ('t1', '2', 'member', 't1', '1', 'member');",
        )
        # moved up, beside another world: the objects' ids, not the users'
        moved = self.s.moved(data, {"t1": "s3t1"}, 10, {"user"})
        self.assertEqual((moved.ids["s3t1"], moved.ids["user"]), (["11", "12"], ["1", "2"]))
        self.assertEqual(moved.pairs[("s3t1", "member", 0, "s3t1", "member")], [("12", "11")])
        # what rows can't make
        with self.assertRaises(self.s.Unloadable):
            self.s.load_sql(pol, dataclasses.replace(data, cond={("t1", "exists (select 1)"): ["1"]}))

    def test_a_world_whose_conditions_the_rows_decide(self) -> None:
        # tests/rewrites.py replays a difference the review shows: the world is made as rows, but a condition that
        # reads other tables holds where they say, not where the world says. So what the rows hold is read back: the
        # replay holds when they hold the world but for such conditions, and fails when they don't
        import rewrites

        flag = "exists (select 1 from gp.flags)"
        pol = parse_policy(
            "app role app_user\ntype user = gp.users\ntype t1 = gp.t1\n  r1 : user = c_r1\n"
            f"  can p1 = r1 and not {{{flag}}}\n  can p2 = r1 and {{b1}}\n",
            "small.authz",
        )
        world = self.s.data_of(
            pol,
            {"user": ["1"], "t1": ["1"]},
            [("pair", "t1\tr1\t0\tuser\t", "1", "1", None), ("col", "t1", "1", "b1", True)],
        )
        world.cond[("t1", flag)] = ["1"]
        with self.assertRaises(self.s.Unloadable):
            self.s.load_sql(pol, world)
        rows, _ = self.s.load_sql(pol, world, rows_decide=True)
        self.assertEqual(
            rows,
            'INSERT INTO "gp"."users" ("id") VALUES (1);\nINSERT INTO "gp"."t1" ("id", "b1", "c_r1") VALUES (1, true, 1);',
        )

        def back(flagged: list[str], b1: list[str], pairs: list[list[str]]) -> evaluate.Data:
            return evaluate.Data.of(
                {
                    ("ids", "user"): ["1"],
                    ("valid", "user"): ["1"],
                    ("ids", "t1"): ["1"],
                    ("valid", "t1"): ["1"],
                    ("pairs", "t1", "r1", 0, "user", ""): pairs,
                    ("cond", "t1", flag): flagged,
                    ("cond", "t1", "b1"): b1,
                }
            )

        self.assertIsNone(rewrites.rows_hold(pol, world, back(["1"], ["1"], [["1", "1"]]), "1"))
        # the flag holds nowhere in the rows: p1 holds there, not in the world, and that's the condition alone
        self.assertEqual(rewrites.rows_hold(pol, world, back([], ["1"], [["1", "1"]]), "1"), "conditions")
        # b1, a column the world gives: the rows must hold it as the world does
        self.assertEqual(
            rewrites.rows_hold(pol, world, back(["1"], [], [["1", "1"]]), "1"),
            "t1.p2 holds on ['1'] in the world, [] in its rows",
        )
        self.assertEqual(
            rewrites.rows_hold(pol, world, back([], ["1"], []), "1"),
            "t1.p1 holds on ['1'] in the world, [] in its rows",
        )

    def test_the_parts_made_wrong_are_told_apart(self) -> None:
        spec = self.s.decorated(
            self.spec("""
            type user
            type t1
              r1 : user column
              parent : t1 column
              can p1 = r1 or parent.p1
        """)
        )
        text = genpolicy.policy_text(spec)
        made = [m.what for m in self.s.mutants(spec, text)]
        for what in (
            "t1.p1: nobody",
            "t1.p1 at parent.p1: not followed",
            "t1.parent (column): the other way round",
            "t1.r1 (column, user): to every subject",
            "recursion one step deep",
        ):
            self.assertIn(what, made)
        choice = self.s.choose(spec, text, self.s.canonical(spec))
        self.assertEqual(choice.problems, [])
        self.assertEqual((choice.told, choice.parts), (14, 14))
        self.assertLessEqual(len(choice.worlds), 4)
        # the worlds chosen tell apart each part told apart anywhere
        base = self.s.reference(text)
        told = {m.what for m in self.s.mutants(spec, text) for w in choice.worlds if m.answers(w) != base(w)}
        self.assertEqual(len(told), choice.told)


class Decisions(unittest.TestCase):
    """tests/decisions.py, which says which parts of a policy decided an answer in difftest's worlds, on worlds made by
    hand (HandAnswers' facts): a part forced the other way that changes some answer decided it there; one that
    changes none, held or not, never did (its SQL was never judged). Each by its name and the line it is on."""

    DOCS = (
        "type user = app.users\ntype doc = app.docs\n  owner : user = owner_id\n  viewer : user shared\n"
        "  can share = owner\n  can edit = owner\n  can view = edit or viewer or (viewer and edit)\n"
        "rules app.docs\n  select : view\n  insert : {draft}\n"
    )
    # ann edits doc 1 and is a viewer there too; bo is a viewer of doc 2 alone; {draft} holds on doc 2
    DOC_WORLD = "user: ann, bo\ndoc: 1, 2\ndoc 1 owner user ann\ndoc 1 viewer user ann\ndoc 2 viewer user bo\n{draft} on doc 2\n"
    VIEW = ("expr", "perm", "doc", "view")
    FOLDERS = (
        "type user = app.users\ntype folder = app.folders\n  owner : user = owner_id\n  parent : folder = parent_id\n"
        "  can view = owner or parent.view\n"
    )

    def watch(
        self,
        policy: str,
        worlds: Sequence[str],
        asked: Sequence[str] = ("ann", "bo", ""),
        shares: dict[str, decisions.Shares] | None = None,
        scope: tuple[str, str] | None = None,
    ) -> decisions.Decisions:
        text = HandAnswers.HEAD + policy
        Compiler(parse_policy(text, "hand.authz")).compile("hand.authz")  # (a policy the compiler takes)
        pol = parse_policy(text, "hand.authz")
        out = decisions.Decisions(pol, text)
        for world in worlds:
            data = HandAnswers().world(pol, world)
            out.snapshots += 1
            for who in asked:
                out.observe(data, who, (), (shares or {}).get(who), scope[1] if scope and scope[0] == who else "")
        return out

    def test_a_part_that_decides_and_one_that_never_does(self) -> None:
        t = self.watch(self.DOCS, [self.DOC_WORLD])
        # (viewer and edit) holds only where edit does: neither of its parts ever decides, whichever way forced
        self.assertEqual(t.parts[(*self.VIEW, 2, 0)].nevers(), ["never decisive"])
        self.assertEqual(t.parts[(*self.VIEW, 2, 1)].nevers(), ["never decisive"])
        # edit, and the whole (viewer and edit): forced true they give more, forced false nothing goes (viewer stays)
        self.assertEqual(t.parts[(*self.VIEW, 0)].nevers(), ["decisive only forced true"])
        self.assertEqual(t.parts[(*self.VIEW, 2)].nevers(), ["decisive only forced true"])
        # viewer decides both ways: bo views doc 2 by it alone
        self.assertEqual(t.parts[(*self.VIEW, 1)].nevers(), [])
        self.assertEqual(t.parts[(*self.VIEW, 1)].down, "doc.view on 2 for bo")
        self.assertEqual(t.parts[(*self.VIEW, 0)].up, "doc.view on 2 for ann")
        # a condition nothing but a rule reads decides that rule's rows
        self.assertEqual(t.parts[("expr", "rule", 1)].nevers(), [])
        self.assertEqual(t.parts[("expr", "rule", 1)].down, "rules app.docs insert on 2 for ann")

    def test_the_report_names_each_part_by_its_line(self) -> None:
        t = self.watch(self.DOCS, [self.DOC_WORLD])
        lines = t.report("hand")
        self.assertRegex(
            lines[0],
            r"^decisions \(hand\): 7 of the policy's 17 parts never decided an answer, over 1 snapshot and 3 "
            r"principals asking \(\d+\.\d s\)$",
        )
        self.assertIn("  doc.view: edit at line 8: decisive only forced true", lines)
        self.assertIn("  doc.viewer: a share not started yet to user at line 5: never true, never decisive", lines)
        self.assertIn("  subjects that decided an answer: a user", lines)
        self.assertEqual(
            t.report("hand", only_decisive=True)[1:],
            [
                "  doc.viewer: an expired share to user at line 5: never decisive",
                "  doc.viewer: a share not started yet to user at line 5: never decisive",
                "  doc.view: viewer at line 8: never decisive",
                "  doc.view: edit at line 8: never decisive",
                "  scope read: select (built in): never decisive",
                "  scope read: every permission (built in): never decisive",
                "  scope read: what it leaves out: never decisive",
            ],
        )

    def test_a_part_on_a_line_that_goes_on(self) -> None:
        t = self.watch(
            "type user = app.users\ntype doc = app.docs\n  owner : user = owner_id\n  viewer : user shared\n"
            "  can share = owner\n  can view = owner\n           or viewer  -- or one it is shared with\n",
            ["user: ann\ndoc: 1\n"],
            asked=["ann"],
        )
        self.assertEqual(str(t.parts[(*self.VIEW, 1)].loc), "line 8")
        self.assertEqual(str(t.parts[self.VIEW].loc), "line 7")

    def test_a_where_never_false_and_a_source_never_true(self) -> None:
        t = self.watch(
            "type user = app.users where {active}\n  boss : user = boss_id\n  can manage = boss\n  can greet = anyone\n"
            "type doc = app.docs where {not archived}\n  owner : user = owner_id\n"
            "  editor : user = app.doc_editors(doc_id -> user_id)\n  can view = owner or editor\n",
            [
                "user: ann, bo\nuser bo boss user ann\ndoc: 1, 2, 3\ndoc 2 fails its where\ndoc 1 owner user ann\n"
                "doc 3 owner user bo\n"
            ],
        )
        # every user passes: never false, and false it takes everything away (signed in, they are nobody)
        self.assertEqual(t.parts[("where", "user")].nevers(), ["never false"])
        self.assertEqual(t.parts[("where", "user")].down, "user.manage on bo for ann")
        # ann's part of bo, read just after that: as she is, not as nobody
        self.assertEqual(t.parts[("source", "user", "boss", 0, "user", "")].nevers(), [])
        # doc 2 fails it, and nobody holds anything there: letting it through changes nothing
        self.assertEqual(t.parts[("where", "doc")].nevers(), ["decisive only forced false"])
        # no editor anywhere: never true, yet one everywhere would show
        editor = t.parts[("source", "doc", "editor", 0, "user", "")]
        self.assertEqual((editor.nevers(), editor.up), (["never true"], "doc.view on 3 for ann"))
        # anyone is never false, as it says: no news
        self.assertEqual(t.parts[("expr", "perm", "user", "greet")].nevers(), [])

    def test_a_share_that_does_not_count_had_it_counted(self) -> None:
        expired = ("share", "expired", "doc", "viewer", 0, "user", "")
        later = ("share", "not started", "doc", "viewer", 0, "user", "")
        t = self.watch(
            "type user = app.users\ntype doc = app.docs\n  owner : user = owner_id\n  viewer : user shared\n"
            "  can share = owner\n  can view = owner or viewer\n",
            ["user: ann, bo\ndoc: 1, 2\ndoc 1 owner user ann\n"],
            shares={"ann": {expired: [["2", "ann"]], later: [["1", "ann"]]}},
        )
        # expired on doc 2: counted, ann would view it; not started on doc 1, which she owns: nothing would change
        self.assertEqual((t.parts[expired].nevers(), t.parts[expired].up), ([], "doc.view on 2 for ann"))
        self.assertEqual(t.parts[later].nevers(), ["never decisive"])

    def test_how_deep_inheritance_decided_and_a_loop(self) -> None:
        depths = [("depth", 0, d) for d in (1, 2, 3)]
        two = self.watch(
            self.FOLDERS, ["user: ann\nfolder: 1, 2\nfolder 2 parent folder 1\nfolder 1 owner user ann\n"], ["ann"]
        )
        self.assertEqual([two.parts[k].nevers() for k in depths], [[], ["never decisive"], ["never decisive"]])
        # through a column alone, no loop to watch: the database refuses one (AZ713)
        self.assertNotIn(("loop", 0), two.parts)
        four = self.watch(
            self.FOLDERS,
            [
                "user: ann\nfolder: 1, 2, 3, 4\nfolder 2 parent folder 1\nfolder 3 parent folder 2\n"
                "folder 4 parent folder 3\nfolder 1 owner user ann\n"
            ],
            ["ann"],
        )
        self.assertEqual(
            [four.parts[k].down for k in depths],
            ["folder.view on 2 for ann", "folder.view on 3 for ann", "folder.view on 4 for ann"],
        )
        # through a table, folders 1 and 2 may be inside each other: 2 holds view through the loop alone
        linked = self.FOLDERS.replace("= parent_id", "= app.folder_links(folder_id -> parent_id)")
        world = (
            "user: ann\nfolder: 1, 2, 3\nfolder 2 parent folder 1\nfolder 3 parent folder 2\nfolder 1 owner user ann\n"
        )
        tree = self.watch(linked, [world], ["ann"])
        self.assertIn(
            "  folder.view: inheritance round a loop in the data (through parent.view) at line 6: never true, "
            "never decisive",
            tree.report("hand"),
        )
        loop = self.watch(linked, [world + "folder 1 parent folder 2\n"], ["ann"])
        self.assertEqual(loop.parts[("loop", 0)].down, "folder.view on 2 for ann")

    def test_how_deep_groups_inside_groups_decided(self) -> None:
        t = self.watch(
            "type user = app.users\ntype team = app.teams\n  member : user = app.team_members(team_id -> user_id)\n"
            "  member : team#member = app.teams(parent_id -> id)\ntype folder = app.folders\n  owner : user = owner_id\n"
            "  viewer : team#member shared\n  can share = owner\n  can view = viewer\n",
            [
                "user: ann\nteam: 1, 2, 3\nteam 3 member user ann\nteam 2 member team#member 3\n"
                "team 1 member team#member 2\nfolder: 1, 2, 3\nfolder 1 viewer team#member 2\n"
                "folder 2 viewer team#member 1\n"
            ],
            ["ann"],
        )
        # ann is in team 3, so in 2 (one group inside another) and in 1 (two)
        self.assertEqual(
            [t.parts[("depth", 0, d)].down for d in (1, 2, 3)],
            ["folder.view on 1 for ann", "folder.view on 2 for ann", ""],
        )
        # shared with a team of hers on folder 3 too, she would view it: the source decides both ways
        viewer = t.parts[("source", "folder", "viewer", 0, "team", "member")]
        self.assertEqual((viewer.nevers(), viewer.up), ([], "folder.view on 3 for ann"))

    def test_a_share_where_it_would_decide(self) -> None:
        import random

        policy = (
            "type user = app.users\n  self : user = id\n  can manage_roles = self\n"
            "type team = app.teams\n  member : user = app.team_members(team_id -> user_id)\n"
            "type doc = app.docs\n  owner : user = owner_id\n  viewer : user, team#member shared\n"
            "  roles : user\n  can share = owner\n  can view = owner or viewer\n  can edit = owner or roles\n"
        )
        world = (
            "user: ann, bo\nteam: 1, 2\nteam 2 member user bo\ndoc: 1, 2\ndoc 1 owner user ann\ndoc 2 owner user ann\n"
        )
        t = self.watch(policy, [world], ["ann", "bo"])
        # ann owns both docs: only to bo would a viewer's share give anything, on either
        for seed in range(8):
            gain = t.gain(("share", "expired", "doc", "viewer", 0, "user", ""), random.Random(seed))
            assert gain is not None
            self.assertEqual((gain.user, gain.subject, gain.perm), ("bo", "bo", ""))
            self.assertIn(gain.object, ("1", "2"))
        # to a team: bo's, never the one he isn't in
        team = t.gain(("share", "not started", "doc", "viewer", 0, "team", "member"), random.Random(1))
        assert team is not None
        self.assertEqual((team.user, team.subject), ("bo", "2"))
        # a custom role: one that gives edit, the permission that names the roles
        role = t.gain(("role share", "expired", "doc", "user", ""), random.Random(1))
        assert role is not None
        self.assertEqual((role.user, role.subject, role.perm, role.owner), ("bo", "bo", "edit", ""))
        # asked of ann alone, who holds everything already: no share would decide
        alone = self.watch(policy, [world], ["ann"])
        self.assertIsNone(alone.gain(("share", "expired", "doc", "viewer", 0, "user", ""), random.Random(1)))

    def test_a_chain_and_a_loop_planned_where_they_would_decide(self) -> None:
        import random

        world = "user: ann\nfolder: 1, 2, 3, 4, 5\nfolder 2 parent folder 1\nfolder 1 owner user ann\n"

        def anything(k: evaluate.PairsKey, o: str, s: str) -> bool:
            return True

        t = self.watch(self.FOLDERS, [world], ["ann"])
        self.assertEqual(t.parts[("depth", 0, 3)].nevers(), ["never decisive"])
        plan = t.plan(("depth", 0, 3), random.Random(1), anything)
        assert plan is not None
        # three links down from a folder ann views with no link followed (1, her own), through folders she holds
        # nothing on, each cut from whatever it hung by before
        k = ("folder", "parent", 0, "folder", "")
        self.assertEqual((plan.user, len(plan.add), plan.add[0][2]), ("ann", 3, "1"))
        self.assertEqual([s for _, _, s in plan.add[1:]], [o for _, o, _ in plan.add[:2]])
        self.assertEqual(plan.cut, [(k, o) for _, o, _ in plan.add])
        self.assertNotIn("2", [o for _, o, _ in plan.add])
        # written into the data, that depth decides: what the next snapshot sees
        t.observe(t.planned(t.last["ann"], plan), "ann")
        self.assertEqual(t.parts[("depth", 0, 3)].down, f"folder.view on {plan.add[2][1]} for ann")
        # only by links the caller can write: none it can, no plan
        self.assertIsNone(t.plan(("depth", 0, 3), random.Random(1), lambda k, o, s: False))
        # a loop: one link down and one back up, where a source that isn't a column can close it
        linked = self.FOLDERS.replace("= parent_id", "= app.folder_links(folder_id -> parent_id)")
        tree = self.watch(linked, [world], ["ann"])
        loop = tree.plan(("loop", 0), random.Random(1), anything)
        assert loop is not None
        (_, below, top), (_, back, under) = loop.add
        self.assertEqual((top, back, under), ("1", "1", below))
        tree.observe(tree.planned(tree.last["ann"], loop), "ann")
        self.assertEqual(tree.parts[("loop", 0)].down, f"folder.view on {below} for ann")
        # ann holding nothing anywhere, there is no top to hang a chain under
        nobody = self.watch(self.FOLDERS, ["user: ann\nfolder: 1, 2, 3, 4\n"], ["ann"])
        self.assertIsNone(nobody.plan(("depth", 0, 1), random.Random(1), anything))

    def test_links_written_as_the_sources_read_them(self) -> None:
        import random

        import difftest

        def made(kind: type[difftest.Gen]) -> difftest.Gen:
            gen = kind(random.Random(1))
            gen.ledger = decisions.Decisions(parse_policy(read(os.path.join(ROOT, gen.policy)), gen.policy))
            return gen

        gen = made(difftest.CompositeGen)
        # a column pair naming a folder or a project, in a table keyed by two columns, one of them the pair's too
        parent = ("folder", "parent", 0, "folder", "")
        here = """WHERE "org_id" = '1' AND "id" = '2'"""
        self.assertEqual(
            gen.tie(parent, "(1,2)", "(1,3)"),
            f"""UPDATE "cx"."folders" SET "parent_id" = '3', "parent_type" = 'folder' {here};""",
        )
        self.assertEqual(
            gen.untie(parent, "(1,2)"),
            f"""UPDATE "cx"."folders" SET "parent_id" = NULL, "parent_type" = NULL {here} AND "parent_type" = 'folder';""",
        )
        # a folder of another org: its key's column would change
        self.assertIsNone(gen.tie(parent, "(1,2)", "(2,3)"))
        # a link table
        links = ("folder", "parent", 1, "folder", "")
        row = """"org_id" = '1' AND "child_id" = '2'"""
        self.assertEqual(
            gen.tie(links, "(1,2)", "(1,3)"),
            f"""DELETE FROM "cx"."folder_links" WHERE {row} AND "parent_id" = '3';\n"""
            """INSERT INTO "cx"."folder_links" ("org_id", "child_id", "parent_id") VALUES ('1', '2', '3');""",
        )
        self.assertEqual(gen.untie(links, "(1,2)"), f"""DELETE FROM "cx"."folder_links" WHERE {row};""")
        # the subjects' own table: the team inside names the team it is in
        teams = ("team", "member", 1, "team", "member")
        self.assertEqual(
            gen.tie(teams, '(1,"a b")', "(1,plain)"),
            """UPDATE "cx"."teams" SET "parent_slug" = 'a b' WHERE "org_id" = '1' AND "slug" = 'plain';""",
        )
        self.assertEqual(
            gen.untie(teams, '(1,"a b")'),
            """UPDATE "cx"."teams" SET "parent_slug" = NULL WHERE "org_id" = '1' AND "parent_slug" = 'a b';""",
        )
        # a share, as it is kept: one that counts, whatever state it was in
        shared = gen.tie(("team", "member", 2, "team", "member"), '(1,"a b")', "(2,plain)")
        assert shared is not None
        self.assertIn("""VALUES ('team', '(1,"a b")', 'member', 'team', '(2,plain)', 'member') ON CONFLICT""", shared)
        self.assertIn("DO UPDATE SET expires_at = NULL, starts_at = NULL, caveat = NULL", shared)
        self.assertEqual(
            gen.untie(("team", "member", 2, "team", "member"), '(1,"a b")'),
            """DELETE FROM authz.shares WHERE object_type = 'team' AND object_id = '(1,"a b")' AND relation = 'member' """
            "AND subject_type = 'team' AND subject_relation = 'member';",
        )
        # a link table whose rows count under a where: written only where the generator says what passes it
        cross = made(difftest.CrossGen)
        over = ("region", "over", 1, "region", "")
        self.assertIn(
            """INSERT INTO "cx"."region_links" ("region_id", "parent_id") VALUES ('1', '2');""",
            str(cross.tie(over, "1", "2")),
        )
        with mock.patch.object(difftest.CrossGen, "columns", {}):
            self.assertIsNone(cross.tie(("project", "inside", 0, "folder", ""), "3", "7"))
        with mock.patch.object(difftest.CrossGen, "columns", {"cx.placements": {"active": "true"}}):
            self.assertEqual(
                cross.tie(("project", "inside", 0, "folder", ""), "3", "7"),
                """DELETE FROM "cx"."placements" WHERE "project_id" = '3' AND "folder_id" = '7';\n"""
                """INSERT INTO "cx"."placements" ("project_id", "folder_id", "active") VALUES ('3', '7', true);""",
            )
        self.assertEqual(
            cross.untie(("project", "inside", 0, "folder", ""), "3"),
            """DELETE FROM "cx"."placements" WHERE "project_id" = '3';""",
        )

    def test_cross_presents_link_tokens_and_makes_room_for_what_is_filed(self) -> None:
        import random

        import difftest

        gen = difftest.CrossGen(random.Random(1))
        # some present a link's token, some none, and nobody signed in presents one: a link's share can count
        self.assertEqual(
            [gen.context(u)["links"] for u in [*gen.users, ""]], ["cx-a", "", "cx-b", "cx-a", "", "cx-b", "cx-a"]
        )
        gen.ledger = decisions.Decisions(parse_policy(read(gen.policy), gen.policy))
        filed = next(c for c, rec in enumerate(gen.ledger.recursions) if ("folder", "file") in rec.names)
        other = next(c for c, rec in enumerate(gen.ledger.recursions) if ("folder", "file") not in rec.names)
        # no snapshot yet, so no chain can be planned: for what is filed, which comes down only to a folder nobody
        # owns, a few folders lose their owner; for any other recursion, nothing
        self.assertEqual(
            gen.steer(("depth", filed, 2), {}),
            "UPDATE cx.folders SET owner_id = NULL WHERE id IN (SELECT id FROM cx.folders "
            "WHERE parent_type IS NOT NULL ORDER BY random() LIMIT 4);",
        )
        self.assertIsNone(gen.steer(("depth", other, 2), {}))

    def test_multi_steers_caveats_and_what_roles_and_teams_need_first(self) -> None:
        import random

        import difftest

        gen = difftest.MultiGen(random.Random(1))
        first, second = gen.users[0], gen.users[1]  # (the first's session says business, from 10.0.0.0)
        self.assertEqual((gen.context(first)["mode"], gen.context(first)["ip"]), ("business", "10.0.0.0"))
        self.assertEqual(gen.caveat(first, True), "'business_hours', NULL")
        self.assertEqual(gen.caveat(first, False), """'from_ip', '{"ip": "10.0.0.1"}'""")
        self.assertEqual(gen.caveat(second, False), "'business_hours', NULL")
        self.assertEqual(gen.caveat(second, True), """'from_ip', '{"ip": "10.0.0.1"}'""")
        gen.ledger = decisions.Decisions(parse_policy(read(gen.policy), gen.policy))
        # a share where the reference says it would decide, with a caveat that holds there or doesn't
        key = ("share", "caveat true", "project", "viewer", 0, "user", "")
        with mock.patch.object(gen.ledger, "gain", lambda key, rnd: decisions.Gain(first, "3", first)):
            sql = str(gen.steer(key, {}))
            self.assertIn(
                f"VALUES ('project', '3', 'viewer', 'user', '{first}', '', NULL, NULL, 'business_hours', NULL)", sql
            )
            self.assertIn(
                """NULL, NULL, 'from_ip', '{"ip": "10.0.0.1"}')""",
                str(gen.steer(("share", "caveat false", *key[2:]), {})),
            )
        # a custom role whose owner has none left that gives the permission: one is made, then given
        with mock.patch.object(gen.ledger, "gain", lambda key, rnd: decisions.Gain(first, "7", first, "edit", "2")):
            role = str(gen.steer(("role share", "expired", "folder", "user", ""), {}))
        giving = "ro.object_type = 'folder' AND rp.permission = 'edit' AND ro.owner_id = '2'"
        self.assertIn(
            f"INSERT INTO authz.roles (owner_type, owner_id, object_type, name) SELECT 'org', '2', 'folder', 'steered' "
            f"WHERE NOT EXISTS (SELECT 1 FROM authz.roles ro JOIN authz.role_permissions rp ON rp.role_id = ro.id WHERE {giving})",
            role,
        )
        self.assertIn("INSERT INTO authz.role_permissions SELECT ro.id, 'edit' FROM authz.roles ro", role)
        self.assertIn(
            f"SELECT 'folder', '7', 'role:' || ro.id, 'user', '{first}', '', now() - interval '1 hour', NULL", role
        )
        # nowhere a share of the part would give anything (no snapshot yet): what it needs first. A doc's roles
        # count by an org the doc lists; a share to a team's members, with someone in a team
        self.assertIn(
            "INSERT INTO mt.doc_orgs SELECT d.id, o.id, true",
            str(gen.steer(("role share", "expired", "doc", "user", ""), {})),
        )
        self.assertRegex(
            str(gen.steer(("share", "not started", "folder", "viewer", 0, "team", "member"), {})),
            r"^INSERT INTO mt\.team_members VALUES \([1-4], '[0-9a-f-]{36}'\) ON CONFLICT DO NOTHING;$",
        )
        self.assertIsNone(gen.steer(("share", "not started", "folder", "viewer", 0, "user", ""), {}))

    def test_a_steered_change_aims_at_a_few_parts_the_least_tried_first(self) -> None:
        import random

        import difftest

        gen = difftest.AltGen(random.Random(1))
        self.assertIsNone(gen.steered({}))  # (no ledger: nothing to aim at)
        gen.ledger = decisions.Decisions(parse_policy(read(os.path.join(ROOT, gen.policy)), gen.policy))
        aimed: list[tuple[str | int, ...]] = []

        def steer(key: tuple[str | int, ...], ids: difftest.Ids) -> str | None:
            aimed.append(key)
            return None if key[0] == "loop" else f"-- {len(aimed)}"

        wanting = gen.ledger.wanting()
        with mock.patch.object(gen, "steer", steer):
            first = gen.steered({})
            # three parts at most (an eighth of those left, when that is more), of which one alone moves the data
            # about (a depth, a loop, an expression's part)
            most = max(difftest.AIMS, len(wanting) // 8)
            self.assertEqual(len(aimed), most)
            self.assertLessEqual(sum(k[0] not in ("share", "role share") for k in aimed), 1)
            said = sum(k[0] != "loop" for k in aimed)
            self.assertEqual(
                first,
                "BEGIN;\n" + "\n".join(f"-- {n}" for n in range(1, most + 1) if aimed[n - 1][0] != "loop") + "\nCOMMIT;"
                if said
                else None,
            )
            # the next ones aim elsewhere, until every part has had its turn
            for _ in range(len(wanting)):
                gen.steered({})
            self.assertEqual(set(aimed), set(wanting))
            self.assertLessEqual(
                max(gen.aimed.values()) - min(gen.aimed[k] for k in wanting if k[0] in ("share", "role share")), 1
            )

    def test_what_a_scope_let_through_and_left_out(self) -> None:
        policy = (
            "type user = app.users\ntype doc = app.docs\n  owner : user = owner_id\n  can view = owner\n"
            "  can edit = owner\nscope files = doc.view\nscope both = doc.view, view\nrules app.docs\n  select : view\n"
        )
        world = ["user: ann\ndoc: 1\ndoc 1 owner user ann\n"]
        t = self.watch(policy, world, ["ann"], scope=("ann", "files"))
        self.assertEqual(t.parts[("scope", "files", 0)].down, "doc.view for ann")
        self.assertEqual(t.parts[("scope refuses", "files")].up, "doc.edit for ann")
        self.assertEqual(t.parts[("scope", "read", 1)].nevers(), ["never true", "never decisive"])
        # two items let doc.view through: without either one, the other still does
        both = self.watch(policy, world, ["ann"], scope=("ann", "both"))
        self.assertEqual([both.parts[("scope", "both", j)].nevers() for j in (0, 1)], [["never decisive"]] * 2)

    def test_a_mask_decides_only_on_rows_one_may_select(self) -> None:
        # {shown} holds on doc 2 alone, which ann may not select: its column shows nowhere she sees, either way
        t = self.watch(
            "type user = app.users\ntype doc = app.docs\n  owner : user = owner_id\n  can view = owner\n"
            "rules app.docs view app.docs_seen\n  select : view\n  mask body : {shown}\n",
            ["user: ann\ndoc: 1, 2\ndoc 1 owner user ann\n{shown} on doc 2\n"],
            ["ann"],
        )
        self.assertEqual(t.parts[("expr", "rule", 1)].nevers(), ["decisive only forced true"])

    def test_whose_roles_count(self) -> None:
        t = self.watch(
            HandAnswers.ROLES.format(**{"from": " from org"}),
            [
                "user: ann\norg: 1, 2\nfolder: 1, 2\nfolder 1 org org 1\nfolder 2 org org 2\n"
                "role view on folder 1 for user ann from org 2\nrole view on folder 2 for user ann from org 2\n"
            ],
            ["ann"],
        )
        # org 2's role counts on its folder 2, not on org 1's folder 1: checked or not, view changes
        part = t.parts[("roles from", "folder")]
        self.assertEqual((part.up, part.down), ("folder.view on 1 for ann", "folder.view on 2 for ann"))

    def test_difftest_reads_the_shares_that_do_not_count_by_why(self) -> None:
        import difftest

        def queries(name: str) -> dict[tuple[str | int, ...], str]:
            return dict(difftest.Reference(parse_policy(read(POLICIES[name]), POLICIES[name])).decisions_queries())

        live, started = difftest.NOT_EXPIRED, difftest.STARTED
        multi = queries("multi")
        # each one live but for its why
        self.assertIn(
            f" AND NOT {live} AND {started} AND (g.caveat IS NULL OR CASE",
            multi[("share", "expired", "folder", "viewer", 0, "user", "")],
        )
        self.assertIn(
            f" AND {live} AND NOT {started} AND (g.caveat IS NULL OR CASE",
            multi[("share", "not started", "folder", "viewer", 0, "user", "")],
        )
        self.assertIn(
            f" AND {live} AND {started} AND g.caveat IS NOT NULL AND NOT (g.caveat IS NULL OR CASE",
            multi[("share", "caveat false", "folder", "viewer", 0, "user", "*")],
        )
        self.assertIn(
            f" AND {live} AND {started} AND g.caveat IS NOT NULL AND (g.caveat IS NULL OR CASE",
            multi[("share", "caveat true", "project", "viewer", 0, "link", "")],
        )
        # custom roles' shares too, by the permission a role gives
        self.assertIn("rp.permission = 'edit'", multi[("role share", "expired", "folder", "edit", "team", "member")])
        # no caveat in the policy: none of those; a share to an object is a link of a tree, which never expires
        self.assertEqual({str(k[1]) for k in queries("docs")}, {"expired", "not started"})
        self.assertEqual([k for k in queries("alt") if k[2:4] == ("doc", "shortcut")], [])

    def test_difftest_watches_each_principal_with_what_was_asked_as_them(self) -> None:
        # difftest's wiring, on a database made up whose every answer says in what session it was asked (who was
        # signed in, their context, the role): each principal is watched once a snapshot, with the data and the
        # shares asked in their own session (their context set, as the owner: a caveat judges a share by the
        # context), with their links; and the one asked with a scope too, with that scope, alone
        import random

        import difftest

        statement = re.compile(
            r"^(?:SET (?P<set>[\w.]+) = '(?P<value>(?:[^']|'')*)';|SET ROLE (?P<role>\w+);|RESET (?P<reset>[\w.]+);"
            r"|SELECT '(?P<key>\[(?:[^']|'')*\])', )",
            re.M,
        )
        session_of = (
            "authz.user_id",
            "authz.principal_type",
            "authz_ctx.mode",
            "authz_ctx.ip",
            "authz_ctx.links",
            "ROLE",
        )
        scoped: list[tuple[str, str, str]] = []  # the session each scoped question was asked in: who, and the scope

        def answer(key: tuple[str | int, ...], session: dict[str, str]) -> object:
            asked = "|".join(session.get(k, "") for k in session_of)
            if key == ("verify",):
                return True
            if key[0] == "scoped":
                who = (session.get("authz.user_id", ""), session.get("authz.principal_type", ""))
                scoped.append((*who, session.get("authz.scopes", "")))
            elif key[1] == "data" and key[2] in ("ids", "valid"):
                return [asked]  # (one row of each type, named by the session)
            elif key[1] == "decisions":
                return [[asked] * (3 if key[2] == "role share" else 2)]
            elif key[1] == "pages":
                return [[], []]  # (in pages, and whole in key order)
            return []

        class Made(difftest.DB):
            """A database that answers each question by its key, and by the session it is asked in."""

            def run(self, sql: str, check: bool = True) -> tuple[int, str, str]:
                return 0, "[]", ""  # (the policy expressions and column rules read back: none; what it makes: done)

            def rows(self, sql: str) -> list[list[str]]:
                session: dict[str, str] = {}
                out: list[list[str]] = []
                for m in statement.finditer(sql):
                    if m["set"]:
                        session[m["set"]] = m["value"].replace("''", "'")
                    elif m["role"]:
                        session["ROLE"] = m["role"]
                    elif m["reset"]:
                        session.pop(m["reset"], None)
                    else:
                        key = m["key"].replace("''", "'")
                        out.append([key, json.dumps(answer(tuple(json.loads(key)), session))])
                return out

            def rows_together(self, scripts: Sequence[str]) -> list[list[str]]:
                return [row for script in scripts for row in self.rows(script)]  # (each a session of its own)

        watched: list[tuple[str, evaluate.Data, set[str], dict[tuple[str | int, ...], list[list[str]]], str]] = []

        class Watching(decisions.Decisions):
            def observe(
                self,
                data: evaluate.Data,
                user: str,
                links: Iterable[str] = (),
                shares: "decisions.Shares | None" = None,
                scope: str = "",
            ) -> None:
                given = {k: [[str(x) for x in row] for row in rows] for k, rows in (shares or {}).items()}
                watched.append((user, data, set(links), given, scope))
                super().observe(data, user, links, shares, scope)

        gen = difftest.MultiGen(random.Random(1))  # (every principal in a context of their own, with a link)
        with mock.patch.object(difftest, "Decisions", Watching), mock.patch.object(difftest, "SESSIONS", 3):
            checker = difftest.Checker(Made("made up"), os.path.join(ROOT, gen.policy), gen, decisions=True)
            for _ in range(2):
                scoped.clear()
                watched.clear()
                checker.check()
                self.assertEqual([w[0] for w in watched], checker.users)
                for u, data, links, shares, _ in watched:
                    kind, pid = evaluate.principal_of(u, checker.types)
                    ctx = gen.context(u)
                    mine = "|".join([pid, "" if kind == "user" else kind, ctx["mode"], ctx["ip"], ctx["links"], ""])
                    self.assertEqual(data.ids["folder"], [mine], u)
                    self.assertEqual(set(shares), {k for k, _ in checker.decisions_queries}, u)
                    self.assertEqual({row[0] for rows in shares.values() for row in rows}, {mine}, u)
                    self.assertEqual(links, checker.links_of(u), u)
                with_scope = [(evaluate.principal_of(u, checker.types), scope) for u, *_, scope in watched if scope]
                self.assertEqual(len(with_scope), 1)
                (kind, pid), scope = with_scope[0]
                self.assertEqual(set(scoped), {(pid, "" if kind == "user" else kind, scope)})
        assert isinstance(checker.decisions, Watching)
        self.assertEqual((checker.decisions.snapshots, checker.decisions.asked), (2, set(checker.users)))
        self.assertTrue(checker.decisions.lines)  # (its parts named by line: the policy's text was read)

    def test_unforced_it_answers_as_the_evaluator(self) -> None:
        # what it watches with is the evaluator overridden only where told: otherwise the very same answers
        for name, path in POLICIES.items():
            pol = parse_policy(read(path), path)
            ref, forcing = evaluate.Reference(pol), decisions.Decisions(pol).ref
            forcing.seen = {}
            for k in range(3):
                world = evaluate.World(f"{name}/{k}", 5, pols=[pol], density=0.5 if k else None)
                data = world.data(pol)
                for who in world.principals([pol]):
                    self.assertEqual(forcing.evaluate(data, who, ["tok1"]), ref.evaluate(data, who, ["tok1"]), name)
            self.assertTrue(forcing.seen)


class Encodings(unittest.TestCase):
    """Text files are read and written as UTF-8 whatever the platform (Windows' locale is cp1252)."""

    def test_every_text_open_names_an_encoding(self) -> None:
        import ast
        import subprocess

        top = os.path.dirname(ROOT)
        try:
            listed = subprocess.run(["git", "ls-files", "*.py"], cwd=top, capture_output=True, text=True, check=True)
        except (OSError, subprocess.CalledProcessError):
            self.skipTest("no git here (the files are the repository's, not what builds leave)")
        missing = []
        for rel in listed.stdout.split():
            with open(os.path.join(top, rel), encoding="utf-8") as fh:
                tree = ast.parse(fh.read())
            for node in ast.walk(tree):
                if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "open"):
                    continue
                mode = (
                    node.args[1]
                    if len(node.args) > 1
                    else next((k.value for k in node.keywords if k.arg == "mode"), None)
                )
                binary = isinstance(mode, ast.Constant) and "b" in str(mode.value)
                if not binary and not any(k.arg == "encoding" for k in node.keywords):
                    missing.append(f"{rel} line {node.lineno}")
        self.assertEqual(missing, [], 'open() without encoding="utf-8"')


class SearchPath(unittest.TestCase):
    def test_functions_that_run_conditions_resolve_names_as_the_rules_do(self) -> None:
        # a condition may name a function, operator or type without its schema ({is_open(status)}, citext's =):
        # the rules and views resolve it when applying, so every function running one resolves it on the path
        # applying vetted (SET search_path FROM CURRENT), never on pg_catalog alone, where it fails at run time
        for name, path in POLICIES.items():
            lines = [
                ln
                if re.match(r"\s*(given|as|test)\b", ln)
                else re.sub(r"\{([^{}]*)\}", lambda m: "{zz_marked((" + m.group(1) + "))}", ln)
                for ln in read(path).split("\n")
            ]
            sql = Compiler(parse_policy("\n".join(lines))).compile("x")
            running = [st for _, st in statements.split(sql) if "FUNCTION" in st[:40] and "zz_marked" in st]
            self.assertGreater(len(running), 5, name)
            for st in running:
                self.assertNotIn("search_path = pg_catalog", st.split("$f$")[0], f"{name}: {st[:120]}")
                # nor on the caller's path, which may lack the schema the condition's names are in: a BEGIN ATOMIC
                # body is resolved when applying, any other names the path it keeps
                if "BEGIN ATOMIC" not in st:
                    self.assertIn("SET search_path FROM CURRENT", st.split("$f$")[0], f"{name}: {st[:120]}")


class ErrorCodes(unittest.TestCase):
    """Every mistake has a stable code and a page (authzlib/errors.py; docs/errors/ is written from it)."""

    def test_every_mistake_has_a_known_code(self) -> None:
        import ast

        from authzlib.errors import CODES

        used = set()
        for name in sorted(os.listdir(os.path.join(ROOT, "authzlib"))):
            if not name.endswith(".py") or name == "errors.py":
                continue
            src = read(f"authzlib/{name}")
            for node in ast.walk(ast.parse(src)):
                if not isinstance(node, ast.Call):
                    continue
                kind = node.func.id if isinstance(node.func, ast.Name) else None
                if kind == "DraftError" or (kind == "Error" and name == "database.py"):
                    # the command's own mistakes (rowstile init, snapshot, ...): a message of their own, ending
                    # with its code; one that passes another's on (Error(str(e)), with its code) has none of its own
                    segment = ast.get_source_segment(src, node) or ""
                    if re.search(r"\{e\}|str\(e\)", segment):
                        continue
                    said = re.findall(r"\[(AZ\d{3})\]", segment)
                    self.assertTrue(
                        len(said) == 1 and said[0] in CODES,
                        f"authzlib/{name} line {node.lineno}: a mistake of the command's without a known code",
                    )
                    continue
                if kind not in ("fail", "PolicyError", "reading") or (kind == "PolicyError" and name == "parse.py"):
                    continue  # fail() itself raises the PolicyError, and reading() (a line form read, or its mistake)
                code = (
                    node.args[2]
                    if kind == "reading"
                    else node.args[-1]
                    if kind == "fail" or len(node.args) == 2
                    else None
                )
                value = code.value if isinstance(code, ast.Constant) else None
                self.assertTrue(
                    isinstance(value, str) and value in CODES,
                    f"authzlib/{name} line {node.lineno}: a mistake without a known code",
                )
                used.add(str(value))
            used |= {a or b for a, b in re.findall(r"\[(AZ\d{3})\]|rowstile help (AZ\d{3})", src)}
        self.assertEqual(sorted(set(CODES) - used), [], "codes nothing raises (retire them in errors.py instead)")

    # raised and caught inside rowstile, or wrapping lines that carry their own code
    UNCODED = (
        "'bad'",
        "'the policy does not match this database:%'",
        "USING ERRCODE = 'AZT00'",
        "'given ",
        "'% policy test(s) failed'",
    )

    def test_every_raise_has_a_code(self) -> None:
        """What the generated SQL raises carries a code: in its message ([AZ601], applying) or its HINT
        (rowstile help AZ701, what apps see), as the errors index says: never a code apps meet at the end of
        the message."""
        from authzlib.errors import CODES

        for name in sorted(os.listdir(os.path.join(ROOT, "authzlib"))):
            if not name.endswith(".py"):
                continue
            src = read(f"authzlib/{name}")
            for m in re.finditer(r"RAISE EXCEPTION", src):
                end = re.compile(r";(?=\n|\"|')").search(src, m.start())  # the statement's end, in SQL or a string
                stmt = src[m.start() : end.end() if end else len(src)]
                for code in re.findall(r"\[(AZ\d{3})\]", stmt):
                    self.assertNotEqual(
                        CODES[code].when,
                        "runtime",
                        f"authzlib/{name} line {src.count(chr(10), 0, m.start()) + 1}: {code} is one apps meet: "
                        "its code goes in the HINT (rowstile help " + code + "), not at the end of the message",
                    )
                if re.search(r"\[AZ\d{3}\]|rowstile help AZ\d{3}|HINT = \{lit\(hint\)\}", stmt) or any(
                    u in stmt for u in self.UNCODED
                ):
                    continue
                self.fail(
                    f"authzlib/{name} line {src.count(chr(10), 0, m.start()) + 1}: a RAISE without a code: {stmt[:120]}"
                )

    def test_examples(self) -> None:
        """Each page's mistake gives its code; its fix compiles."""
        from authzlib import errors

        for code, c in errors.CODES.items():
            if c.wrong and c.right:
                self.assertNotEqual(c.wrong, c.right, f"{code}'s mistake and its fix are the same policy")
            for kind, text in (("mistake", c.wrong), ("fix", c.right)):
                if not text:
                    continue
                got = errors.said(text, dict(c.files), c.when)
                if kind == "fix" or c.when not in ("compile", "tests"):
                    self.assertIsNone(got, f"{code}'s {kind} should compile")
                else:
                    self.assertEqual(getattr(got, "code", None), code, f"{code}'s mistake gives: {got}")

    def test_pages(self) -> None:
        from authzlib import errors

        folder = os.path.join(os.path.dirname(ROOT), "docs", "errors")
        pages = {f"{code}.md": errors.page(code) for code in errors.CODES}
        pages["README.md"] = errors.index()
        if UPDATE:
            os.makedirs(folder, exist_ok=True)
            for name in os.listdir(folder):
                if name not in pages:
                    os.remove(os.path.join(folder, name))
            for name, text in pages.items():
                with open(os.path.join(folder, name), "w", encoding="utf-8", newline="\n") as fh:
                    fh.write(text)
            return
        self.assertEqual(
            sorted(os.listdir(folder)), sorted(pages), "docs/errors/ (python3 tests/unit_test.py --update)"
        )
        for name, text in pages.items():
            with open(os.path.join(folder, name), encoding="utf-8") as fh:
                self.assertEqual(fh.read(), text, f"docs/errors/{name} (python3 tests/unit_test.py --update)")

    def test_message_and_code(self) -> None:
        from authzlib import errors

        with self.assertRaises(PolicyError) as e:
            Compiler(
                parse_policy(
                    errors.PRELUDE + "type folder = app.folders\n  owner : person = owner_id\n  can view = owner\n"
                )
            ).compile("x")
        self.assertEqual(str(e.exception), "line 4: folder.owner: unknown type 'person' [AZ201]")
        self.assertEqual(e.exception.code, "AZ201")
        self.assertEqual(errors.split(str(e.exception)), ("line 4: folder.owner: unknown type 'person'", "AZ201"))
        self.assertEqual(errors.split("no code here"), ("no code here", None))


class RuntimeAnswers(unittest.TestCase):
    """Each code the runtime raises (rowstile help AZ7xx) comes with one SQLSTATE and one HTTP answer, both named on
    its page, and the SDKs answer it so: the same mistake looks the same whichever check found it, and an app
    answers it as the page says."""

    # the ERRCODE names the runtime raises with, and their SQLSTATEs (no ERRCODE: P0001, raise_exception)
    STATES: ClassVar[dict[str, str]] = {
        "": "P0001",
        "insufficient_privilege": "42501",
        "invalid_authorization_specification": "28000",
        "invalid_parameter_value": "22023",
        "check_violation": "23514",
        "object_not_in_prerequisite_state": "55000",
    }

    def raised(self) -> dict[str, set[str]]:
        """Each runtime code, and the SQLSTATEs the generated SQL raises it with."""
        out: dict[str, set[str]] = {}
        for name in sorted(os.listdir(os.path.join(ROOT, "authzlib"))):
            if not name.endswith(".py"):
                continue
            src = read(f"authzlib/{name}")
            for m in re.finditer(r"RAISE EXCEPTION", src):
                end = re.compile(r";(?=\n|\"|')").search(src, m.start())  # the statement's end, in SQL or a string
                stmt = src[m.start() : end.end() if end else len(src)]
                code = re.search(r"rowstile help (AZ7\d\d)", stmt)
                if not code:
                    continue
                state = re.search(r"ERRCODE = '(\w+)'", stmt)
                where = f"authzlib/{name} line {src.count(chr(10), 0, m.start()) + 1}"
                self.assertIn(state.group(1) if state else "", self.STATES, f"{where}: an ERRCODE this test can't name")
                out.setdefault(code.group(1), set()).add(self.STATES[state.group(1) if state else ""])
        return out

    def page(self, code: str) -> tuple[str, str]:
        """The SQLSTATE and the HTTP status the code's page names, one of each."""
        from authzlib.errors import CODES

        text = CODES[code].text
        states = set(re.findall(r"SQLSTATE ([0-9A-Z]{5})\b", text))
        answers = set(re.findall(r"\b([45]\d\d)\b", text))
        self.assertEqual(len(states), 1, f"{code}'s page names one SQLSTATE: {sorted(states)}")
        self.assertEqual(len(answers), 1, f"{code}'s page names one answer (an HTTP status): {sorted(answers)}")
        return states.pop(), answers.pop()

    def sdks(self) -> tuple[dict[str, tuple[str, str, int]], dict[str, tuple[str, str, int]]]:
        """The codes each SDK answers as a problem that is no refusal: (type, title, status), Python's and
        TypeScript's."""
        repo = os.path.dirname(ROOT)
        with open(os.path.join(repo, "sdk", "python", "rowstile", "__init__.py"), encoding="utf-8") as fh:
            py = fh.read()
        with open(os.path.join(repo, "sdk", "typescript", "client", "src", "index.ts"), encoding="utf-8") as fh:
            ts = fh.read()
        py_map = py[py.index("_CALL_PROBLEMS: dict") : py.index("}", py.index("_CALL_PROBLEMS: dict"))]
        ts_map = ts[ts.index("const CALL_PROBLEMS") : ts.index("]);", ts.index("const CALL_PROBLEMS"))]
        python = {
            c: (t, ti, int(s)) for c, t, ti, s in re.findall(r'"(AZ\d{3})": \("([^"]+)", "([^"]+)", (\d{3})\)', py_map)
        }
        typescript = {
            c: (t, ti, int(s))
            for c, t, ti, s in re.findall(
                r'\["(AZ\d{3})", \{ type: "([^"]+)", title: "([^"]+)", status: (\d{3}) \}\]', ts_map
            )
        }
        return python, typescript

    def test_each_code_is_raised_with_its_pages_sqlstate(self) -> None:
        from authzlib.errors import CODES

        raised = self.raised()
        runtime = sorted(c for c, v in CODES.items() if v.when == "runtime")
        self.assertEqual(sorted(raised), runtime, "every runtime code is raised, and only those")
        for code in runtime:
            self.assertEqual(raised[code], {self.page(code)[0]}, f"{code}: the SQLSTATEs it is raised with")

    def test_the_sdks_answer_each_code_as_its_page_says(self) -> None:
        from authzlib.errors import CODES

        python, typescript = self.sdks()
        self.assertEqual(python, typescript, "the two SDKs answer the same codes the same way")
        self.assertIn("AZ713", python)  # the reading found the entries
        site = os.path.join(os.path.dirname(ROOT), "site", "problems")
        for code in sorted(c for c, v in CODES.items() if v.when == "runtime"):
            state, answer = self.page(code)
            if answer == "403":  # a refusal: SQLSTATE 42501, which the SDKs read as Refused (a 403)
                self.assertEqual((state, code in python), ("42501", False), code)
            elif answer == "500":  # the app's mistake: no problem body, and not a refusal's SQLSTATE
                self.assertNotEqual(state, "42501", code)
                self.assertNotIn(code, python, code)
            else:
                self.assertEqual(python.get(code, ("", "", 0))[2], int(answer), f"{code}: the SDKs answer {answer}")
                page = os.path.join(site, python[code][0].rsplit("/", 1)[1] + ".md")
                self.assertTrue(os.path.exists(page), f"{code}: its problem type has a page, {page}")
                with open(page, encoding="utf-8") as fh:
                    self.assertIn(code, fh.read(), f"{code}: its problem page names it")


class StackPages(unittest.TestCase):
    """docs/stacks/: every line of code a page shows is in the tested app it comes from, so it can't drift."""

    REPO = os.path.dirname(ROOT)
    SOURCES: ClassVar[dict[str, list[str]]] = {
        "fastapi.md": ["integrations/fastapi"],
        "python.md": ["integrations/fastapi"],
        "nextjs.md": ["integrations/nextjs"],
        "node.md": ["integrations/nextjs"],
        "sql.md": ["docs/getting-started.md", "sdk/python/rowstile", "sdk/typescript"],
    }
    SKIP: ClassVar[set[str]] = {"node_modules", ".venv", ".next", ".work", "generated", "__pycache__", "dist"}
    CHECKED = ("python", "ts", "tsx", "toml", "authz", "sql")  # sh blocks are commands to type

    def lines(self, rel: str) -> set[str]:
        path = os.path.join(self.REPO, *rel.split("/"))
        files = (
            [path]
            if os.path.isfile(path)
            else [
                os.path.join(d, f)
                for d, dirs, fs in os.walk(path)
                if not dirs.__setitem__(slice(None), [x for x in dirs if x not in self.SKIP])
                for f in fs
            ]
        )
        out: set[str] = set()
        for f in files:
            if f.endswith((".py", ".ts", ".tsx", ".toml", ".authz", ".md", ".sql")):
                with open(f, encoding="utf-8") as fh:
                    out |= {" ".join(line.split()) for line in fh}
        return out

    def test_every_line_is_in_a_tested_app(self) -> None:
        folder = os.path.join(self.REPO, "docs", "stacks")
        pages = sorted(f for f in os.listdir(folder) if f.endswith(".md") and f != "README.md")
        self.assertEqual(pages, sorted(self.SOURCES), "a new page names the tested app its code comes from")
        for page in pages:
            with open(os.path.join(folder, page), encoding="utf-8") as fh:
                text = fh.read()
            have = set().union(*(self.lines(s) for s in self.SOURCES[page]))
            anywhere = "\n".join(have)
            shown = [
                (lang, " ".join(line.split()))
                for lang, block in re.findall(r"```(\w+)\n(.*?)```", text, re.S)
                if lang in self.CHECKED
                for line in block.split("\n")
                if line.strip()
            ]
            self.assertTrue(shown, page)
            missing = [
                line
                for lang, line in shown
                if line not in have and not self.caption(page, line) and not (lang == "sql" and line in anywhere)
            ]  # SQL the SDKs send, inside their strings
            self.assertEqual(
                missing, [], f"docs/stacks/{page}: lines in no tested app ({', '.join(self.SOURCES[page])})"
            )

    def blocks(self, page: str) -> list[tuple[str, str]]:
        """A page's code blocks: (language, text)."""
        with open(os.path.join(self.REPO, "docs", "stacks", page), encoding="utf-8") as fh:
            return re.findall(r"```(\w+)\n(.*?)```", fh.read(), re.S)

    def test_no_page_takes_the_user_from_a_header(self) -> None:
        """The conformance apps' checks name the user in a header; a page shows the app's session instead."""
        for page in sorted(self.SOURCES):
            shown = [line.strip() for lang, block in self.blocks(page) for line in block.split("\n")]
            self.assertEqual([line for line in shown if "x-user" in line], [], f"docs/stacks/{page}")

    def test_the_install_lines_have_what_the_code_imports(self) -> None:
        """Each rowstile package a page's code imports (or SDK module, for Python: its extra) is in its sh blocks."""
        with open(os.path.join(self.REPO, "sdk", "python", "pyproject.toml"), encoding="utf-8") as fh:
            extras = set(
                re.findall(r"^(\w+) = \[", fh.read().split("[project.optional-dependencies]")[1].split("\n[")[0], re.M)
            )
        self.assertIn("fastapi", extras)
        for page in sorted(self.SOURCES):
            blocks = self.blocks(page)
            sh = "\n".join(text for lang, text in blocks if lang == "sh")
            ts = "\n".join(text for lang, text in blocks if lang in ("ts", "tsx"))
            py = "\n".join(text for lang, text in blocks if lang == "python")
            packages = set(re.findall(r"""(?:from|import) "(@rowstile/[\w-]+)""", ts))
            missing = sorted(p for p in packages if f"{p}@" not in sh)
            installed = {e for group in re.findall(r"\[([\w,]+)\]", sh) for e in group.split(",")}
            modules = set(re.findall(r"\browstile\.(\w+)|from rowstile import (\w+)", py))
            missing += sorted(f"rowstile[{m}]" for pair in modules for m in pair if m in extras and m not in installed)
            self.assertEqual(missing, [], f"docs/stacks/{page}: imported, not installed")

    def test_a_module_the_python_uses_is_imported(self) -> None:
        """A module a page's Python uses by name (`os.environ`, `rowstile.job`) is imported on the page."""
        for page in sorted(self.SOURCES):
            py = "\n".join(text for lang, text in self.blocks(page) if lang == "python")
            if not py:
                continue
            have = set().union(*(self.lines(s) for s in self.SOURCES[page]))
            modules = {m.group(1) for line in have if (m := re.fullmatch(r"import (\w+)", line))}
            self.assertIn("os", modules, page)
            unimported = sorted(
                m
                for m in modules
                if re.search(rf"(?<![\w.]){m}\.\w", py) and not re.search(rf"^\s*import {m}\s*$", py, re.M)
            )
            self.assertEqual(unimported, [], f"docs/stacks/{page}: used, not imported")

    def caption(self, page: str, line: str) -> bool:
        """A comment naming the file a snippet is from ("// src/db.ts"), which the app has."""
        m = re.fullmatch(r"(?://|#|--) (\S+\.\w+)", line)
        return m is not None and any(
            os.path.exists(os.path.join(self.REPO, *s.split("/"), *m.group(1).split("/"))) for s in self.SOURCES[page]
        )


class Demo(unittest.TestCase):
    """demo/: the recording at the top of the README is made from the guide's own files (demo/files.py), and its
    tape still says what those files hold. The recording itself is made by hand (demo/record.sh: containers)."""

    REPO = os.path.dirname(ROOT)

    def test_the_tape_fits_the_guides_files(self) -> None:
        import importlib.util

        spec = importlib.util.spec_from_file_location("demo_files", os.path.join(self.REPO, "demo", "files.py"))
        assert spec is not None and spec.loader is not None
        files = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(files)
        with open(os.path.join(self.REPO, "demo", "demo.tape"), encoding="utf-8") as fh:
            tape = fh.read()
        with tempfile.TemporaryDirectory() as d:
            argv, sys.argv = sys.argv, ["files.py", d, os.path.join(d, "schema.sql")]
            try:
                files.main()
            finally:
                sys.argv = argv
            with open(os.path.join(d, "db", "policy.authz"), encoding="utf-8") as fh:
                policy = fh.read().split("\n")
            self.assertTrue(os.path.exists(os.path.join(d, "db", "tests", "first.authz")))
            self.assertTrue(os.path.exists(os.path.join(d, "rowstile.toml")))
            with open(os.path.join(d, "schema.sql"), encoding="utf-8") as fh:
                self.assertIn("CREATE TABLE app.notes", fh.read())
        # the lines the first scene shows: the project's relations to the note's permissions
        first, last = (int(x) for x in search(r"sed -n '(\d+),(\d+)p' db/policy.authz", tape).groups())
        self.assertEqual(policy[first - 1].split(), ["owner", ":", "user", "=", "owner_id"], "the first line shown")
        self.assertEqual(policy[last - 1].strip(), "can view = edit or project.view", "the last line shown")
        # the one word the pull request changes is there, once
        old, new = search(r"sed -i 's/([^/]+)/([^/]+)/' db/policy.authz", tape).groups()
        text = "\n".join(policy)
        self.assertEqual(text.count(old), 1, f"the tape changes {old!r}, which the guide's policy has once")
        Compiler(parse_policy(text.replace(old, new), "p.authz")).compile("p.authz")

    def test_the_readme_shows_the_recording(self) -> None:
        with open(os.path.join(self.REPO, "README.md"), encoding="utf-8") as fh:
            self.assertIn("](demo/demo.gif)", fh.read())
        size = os.path.getsize(os.path.join(self.REPO, "demo", "demo.gif"))
        self.assertLess(size, 2_000_000, "demo/demo.gif: keep it light, it loads with the README")


class ComparePages(unittest.TestCase):
    """docs/compare/: a page per alternative. What it says of rowstile is tested here (a whole policy compiles
    and is laid out as `rowstile fmt` writes it; a part of one, and the app's code, are lines of a conformance
    app); what it says of another project carries the day its docs were read, and each page says when the other
    is the better choice."""

    REPO = os.path.dirname(ROOT)
    SKIP = StackPages.SKIP
    lines = StackPages.lines
    OTHERS = ("openfga.md", "spicedb.md", "zenstack.md")  # pages that quote another project's documentation

    def test_what_the_pages_show_of_rowstile(self) -> None:
        from authzlib import fmt

        folder = os.path.join(self.REPO, "docs", "compare")
        pages = sorted(f for f in os.listdir(folder) if f.endswith(".md"))
        self.assertEqual(pages, ["app-code.md", "hand-written-rls.md", *self.OTHERS])
        have = self.lines("integrations/fastapi") | self.lines("integrations/nextjs")
        with open(os.path.join(self.REPO, "docs", "comparison.md"), encoding="utf-8") as fh:
            overview = fh.read()
        for page in pages:
            with open(os.path.join(folder, page), encoding="utf-8") as fh:
                text = fh.read()
            where = f"docs/compare/{page}"
            self.assertIn(f"](compare/{page})", overview, f"docs/comparison.md doesn't link {where}")
            self.assertIn("](../comparison.md)", text, f"{where} doesn't link the overview")
            self.assertRegex(text, r"\n## When .* the better choice\n", f"{where}: when the other is the better choice")
            if page in self.OTHERS:
                self.assertRegex(
                    text, r"read on \d{4}-\d{2}-\d{2} and linked", f"{where}: the day their docs were read"
                )
            policies = re.findall(r"```authz\n(.*?)```", text, re.S)
            self.assertTrue(policies, where)
            for policy in policies:
                if policy.startswith("app role "):
                    Compiler(parse_policy(policy, where)).compile(where)
                    self.assertEqual(fmt.format_policy(policy), policy, f"{where}: not as rowstile fmt writes it")
                else:
                    missing = [x for x in policy.split("\n") if x.strip() and " ".join(x.split()) not in have]
                    self.assertEqual(missing, [], f"{where}: policy lines in no conformance app")
            shown = [
                " ".join(line.split())
                for block in re.findall(r"```(?:python|ts|tsx)\n(.*?)```", text, re.S)
                for line in block.split("\n")
                if line.strip()
            ]
            self.assertEqual([x for x in shown if x not in have], [], f"{where}: code lines in no conformance app")

    def test_the_two_services_are_compared_with_one_policy(self) -> None:
        """The OpenFGA and the SpiceDB pages show the same model on rowstile's side: one policy, word for word."""
        shown = []
        for page in ("openfga.md", "spicedb.md"):
            with open(os.path.join(self.REPO, "docs", "compare", page), encoding="utf-8") as fh:
                shown.append(search(r"```authz\n(.*?)```", fh.read(), re.S).group(1))
        self.assertEqual(shown[0], shown[1])


class BlogPosts(unittest.TestCase):
    """docs/blog/: what a post shows can be run. Its SQL is lines of the files in the folder named like it
    (docs/blog/<slug>/, the experiment a reader can run), a policy compiles and is laid out as `rowstile fmt`
    writes it, and a plan's lines are lines of a run kept in that folder."""

    REPO = os.path.dirname(ROOT)

    def test_what_a_post_shows_is_beside_it(self) -> None:
        from authzlib import fmt

        folder = os.path.join(self.REPO, "docs", "blog")
        posts = sorted(f for f in os.listdir(folder) if re.fullmatch(r"\d{4}-\d{2}-\d{2}-[a-z0-9-]+\.md", f))
        for post in posts:
            where = f"docs/blog/{post}"
            with open(os.path.join(folder, post), encoding="utf-8") as fh:
                text = fh.read()
            beside = os.path.join(folder, post[11:-3])
            have: set[str] = set()
            runs = ""
            if os.path.isdir(beside):
                for name in sorted(os.listdir(beside)):
                    with open(os.path.join(beside, name), encoding="utf-8") as fh:
                        body = fh.read()
                    have |= {" ".join(line.split()) for line in body.split("\n")}
                    if name.endswith(".txt"):
                        runs += body
            shown = [
                " ".join(line.split())
                for block in re.findall(r"```sql\n(.*?)```", text, re.S)
                for line in block.split("\n")
                if line.strip()
            ]
            self.assertEqual([x for x in shown if x not in have], [], f"{where}: SQL in no file of its folder")
            for policy in re.findall(r"```authz\n(.*?)```", text, re.S):
                Compiler(parse_policy(policy, where)).compile(where)
                self.assertEqual(fmt.format_policy(policy), policy, f"{where}: not as rowstile fmt writes it")
            # a plan's lines are a run's own (a plan shown shortened leaves lines out, it changes none)
            plans = [
                line.strip()
                for block in re.findall(r"```\n(.*?)```", text, re.S)
                for line in block.split("\n")
                if "(actual rows=" in line or line.strip().startswith(("Filter:", "Rows Removed"))
            ]
            said = {" ".join(line.split()) for line in runs.split("\n")}
            self.assertEqual(
                [x for x in plans if " ".join(x.split()) not in said],
                [],
                f"{where}: plan lines in no run of its folder",
            )

    @staticmethod
    def shown(ms: float) -> str:
        """A timing as a post writes it: three figures from a second up, whole milliseconds from a hundred, two
        figures below."""
        if ms >= 1000:
            return f"{ms / 1000:.3g} s"
        return f"{ms:.0f} ms" if ms >= 100 else f"{ms:.2g} ms"

    def test_the_first_articles_numbers_are_its_runs(self) -> None:
        """Each cell of the article's two tables is the middle one of the three timings its run holds for that
        policy and that query, and the figures its text gives are the runs' too."""
        import statistics

        folder = os.path.join(self.REPO, "docs", "blog")
        with open(os.path.join(folder, "2026-10-07-recursive-row-level-security.md"), encoding="utf-8") as fh:
            text = fh.read()
        runs: dict[str, str] = {}
        for size, name in (("200,000 files", "run-20k-folders.txt"), ("2 million files", "run-200k-folders.txt")):
            with open(os.path.join(folder, "recursive-row-level-security", name), encoding="utf-8") as fh:
                runs[size] = fh.read()
            table = search(rf"\| {size} \|[^\n]*\n\|[-|]+\|\n((?:\|[^\n]*\n){{4}})", text).group(1)
            cells = [[c.strip() for c in row.strip("|").split("|")][1:] for row in table.strip().split("\n")]
            sections = re.split(r"\n=== ", runs[size])[1:5]
            self.assertEqual([s[:2] for s in sections], ["1.", "2.", "3.", "4."], name)
            for row, section in zip(cells, sections, strict=True):
                times = [float(x) for x in re.findall(r"Execution Time: ([\d.]+) ms", section)]
                self.assertEqual(len(times), 9, f"{name}: three queries, three times each, for {section[:40]!r}")
                medians = [statistics.median(times[i : i + 3]) for i in (0, 3, 6)]
                self.assertEqual(row, [self.shown(m) for m in medians], f"{size}: {section.splitlines()[0]}")
        small, large = runs["200,000 files"], runs["2 million files"]
        for said, run in (
            ("3,410 files in the\nsmall run, 54,610 in the large one", None),
            ("88,800 rows", small),
            ("8,728 kB", small),
            ("1,218,200", large),
            ("109 MB", large),
            ("1,365 folders", large),
            ("2,377 walks", small),
            ("5,461 folders", large),
        ):
            self.assertIn(said, text)
            if run is not None:
                number = search(r"[\d,]+", said).group(0).replace(",", "")
                self.assertRegex(run, rf"(?<!\d){number}(?!\d)", f"{said!r} is in no line of its run")
        self.assertRegex(small, r"files_user_7_sees \n-+\n\s+3410\n")
        self.assertRegex(large, r"files_user_7_sees \n-+\n\s+54610\n")
        for run in (small, large):
            # after the move, the table and a fresh build hold the same rows; and the policy on folders is refused
            self.assertRegex(
                run, r"rows_only_in_the_table \| rows_only_in_a_fresh_build \n[-+]+\n[^\n]*\|\s+0 \|\s+0\n"
            )
            self.assertIn('ERROR:  infinite recursion detected in policy for relation "folders"', run)
            self.assertIn("Parallel Index Only Scan using files_folder_id_idx on files", run.split("\n=== 4.")[1])


class SdkPackages(unittest.TestCase):
    """sdk/typescript/<package>/README.md: each package's own page on npm. It names its package, links nothing
    by a path (npm shows the file alone), and every line of code it shows is in the conformance app."""

    REPO = os.path.dirname(ROOT)
    SKIP = StackPages.SKIP
    lines = StackPages.lines

    def test_each_package_has_a_page_of_its_own(self) -> None:
        folder = os.path.join(self.REPO, "sdk", "typescript")
        packages = sorted(d for d in os.listdir(folder) if os.path.exists(os.path.join(folder, d, "package.json")))
        self.assertEqual(len(packages), 8, packages)
        have = self.lines("integrations/nextjs")
        for package in packages:
            with open(os.path.join(folder, package, "package.json"), encoding="utf-8") as fh:
                name = json.load(fh)["name"]
            path = os.path.join(folder, package, "README.md")
            self.assertTrue(os.path.exists(path), f"sdk/typescript/{package}/README.md: {name}'s page on npm")
            with open(path, encoding="utf-8") as fh:
                text = fh.read()
            self.assertTrue(text.startswith(f"# {name}\n"), f"sdk/typescript/{package}/README.md is {name}'s")
            self.assertIn(f"{name}@", text, f"sdk/typescript/{package}/README.md: the line that installs {name}")
            away = [t for t in re.findall(r"\]\(([^)]+)\)", text) if not t.startswith("https://")]
            self.assertEqual(away, [], f"sdk/typescript/{package}/README.md: links npm can't follow")
            others = set(re.findall(r"npmjs\.com/package/(@rowstile/[\w-]+)", text))
            self.assertEqual(
                others,
                {f"@rowstile/{p}" for p in packages} - {name},
                f"sdk/typescript/{package}/README.md: the other packages it lists",
            )
            shown = [
                " ".join(line.split())
                for lang, block in re.findall(r"```(\w+)\n(.*?)```", text, re.S)
                if lang in ("ts", "tsx")
                for line in block.split("\n")
                if line.strip()
            ]
            self.assertTrue(shown, package)
            missing = [
                line
                for line in shown
                if line not in have
                and not (
                    (m := re.fullmatch(r"// (\S+\.\w+)", line))
                    and os.path.exists(os.path.join(self.REPO, "integrations", "nextjs", *m.group(1).split("/")))
                )
            ]
            self.assertEqual(missing, [], f"sdk/typescript/{package}/README.md: lines not in integrations/nextjs")

    def test_the_release_ships_each_packages_own_page(self) -> None:
        with open(os.path.join(self.REPO, ".github", "workflows", "release.yml"), encoding="utf-8") as fh:
            release = fh.read()
        self.assertIn('for d in sdk/typescript/*/; do cp LICENSE "$d"; done', release)
        self.assertNotIn("cp sdk/typescript/README.md", release, "it would replace each package's own page")


def calls(text: str, opener: str) -> list[tuple[str, list[str]]]:
    """(name, arguments) for each `<opener>name(...)` in text: parentheses, brackets and quotes balanced."""
    out: list[tuple[str, list[str]]] = []
    for m in re.finditer(re.escape(opener) + r"(\w+)\(", text):
        depth, quote, args, start = 1, False, [], m.end()
        for i in range(m.end(), len(text)):
            ch = text[i]
            if ch == "'":
                quote = not quote
            elif quote:
                continue
            elif ch in "([{":
                depth += 1
            elif ch in ")]}":
                depth -= 1
                if not depth:
                    args.append(text[start:i])
                    out.append((m.group(1), [a.strip() for a in args if a.strip()]))
                    break
            elif ch == "," and depth == 1:
                args.append(text[start:i])
                start = i + 1
    return out


class DocPages(unittest.TestCase):
    """What the pages show that no suite runs: the language page's example compiles, the guide's files are laid
    out as `rowstile fmt` writes them, and each authz.* call a page writes is one the functions take."""

    REPO = os.path.dirname(ROOT)

    def page(self, *rel: str) -> str:
        with open(os.path.join(self.REPO, *rel), encoding="utf-8") as fh:
            return fh.read()

    def test_the_language_pages_example_compiles(self) -> None:
        example = search(r"```authz\n(.*?)```", self.page("docs", "reference", "language.md"), re.S).group(1)
        # the types it names and leaves to its include, as tests/reference.sh gives them
        rest = read("tests/fixtures/roles.authz")
        c = Compiler(parse_policy(example, "language.authz", files={"roles.authz": rest}))
        c.compile("language.authz")
        c.compile_tests("language.authz")
        # its tests name users by number (user 3, 9001): the user type's key is the default one
        self.assertEqual(c.types["user"].pktype, "bigint")

    def test_the_guides_files_are_laid_out_as_fmt_writes_them(self) -> None:
        from authzlib import fmt

        guide = self.page("docs", "getting-started.md")
        blocks = re.findall(r"```authz[ \t]+(\S+)\n(.*?)```", guide, re.S)
        self.assertEqual([name for name, _ in blocks], ["db/policy.authz", "db/tests/first.authz"])
        for name, body in blocks:
            self.assertEqual(
                fmt.format(body),
                body,
                f"docs/getting-started.md: {name} isn't as rowstile fmt writes it "
                "(the reference tells readers to run fmt --check in CI)",
            )

    def test_the_repositorys_policies_are_laid_out_as_fmt_writes_them(self) -> None:
        # what readers copy (the docs app, the cookbook, the example apps, the conformance apps): run through
        # `rowstile fmt --check` in their CI, as the reference says, they must pass. The suites' own fixtures are
        # left as they are (some are wrong on purpose)
        from authzlib import fmt

        # walked, not asked of git: CI's container doesn't own the mounted checkout, and git refuses it
        skip = {".git", "node_modules", ".venv", ".next", ".work", "dist", "tests", "editor"}
        files = []
        for top in ("core", "docs", "examples", "integrations"):
            for root, dirs, names in os.walk(os.path.join(self.REPO, top)):
                dirs[:] = [d for d in dirs if d not in skip or (d == "tests" and not root.endswith("core"))]
                files += [
                    os.path.relpath(os.path.join(root, n), self.REPO).replace(os.sep, "/")
                    for n in names
                    if n.endswith(".authz")
                ]
        self.assertGreater(len(files), 10, "the policies aren't found")
        loose = [f for f in files if fmt.format_policy(self.page(f)) != self.page(f)]
        self.assertEqual(loose, [], "not as rowstile fmt writes them: run rowstile fmt on each")

    def test_the_guides_path_is_the_commands_folder(self) -> None:
        folder = search(r'export PATH="\$PWD/([\w/]+):\$PATH"', self.page("docs", "getting-started.md")).group(1)
        self.assertTrue(
            os.path.exists(os.path.join(self.REPO, *folder.split("/"), "rowstile")),
            f"docs/getting-started.md puts {folder} on the PATH: the command isn't there",
        )

    def test_the_installing_page_holds_the_readmes_lines(self) -> None:
        import tomllib

        section = search(r"\n## Installing\n(.*?)\n## ", self.page("README.md"), re.S).group(1)
        page = self.page("docs", "installing.md")
        lines = [x for x in section.split("\n") if x.startswith("    ")]
        self.assertEqual(len(lines), 3, "README.md's Installing: npm, pip and the image")
        for line in lines:
            self.assertIn(
                line + "\n",
                page,
                "docs/installing.md (the site's page) doesn't have this line of README.md's Installing",
            )
        with open(os.path.join(self.REPO, "sdk", "python", "pyproject.toml"), "rb") as fh:
            extras = set(tomllib.load(fh)["project"]["optional-dependencies"])
        self.assertEqual(
            set(re.findall(r"`rowstile\[(\w+)\]`", page)), extras, "docs/installing.md: the Python package's extras"
        )

    def test_the_install_lines_ask_for_what_is_published(self) -> None:
        # While the version is an alpha, a beta or a candidate, a plain install gets the last final release once
        # one exists (before 0.1.0 a plain install gets the newest pre-release too: pip takes one when no final
        # one exists, and the release moves npm's `latest` to `next`; the image never has a pre-release as
        # `latest`): each install line asks for the pre-release, and the image names its version.
        # On a final release, none still does. A build of main (-dev) is left to the release pull request.
        version = authzlib.__version__
        if version.endswith("-dev"):
            self.skipTest("main between releases: the release pull request sets the install lines")
        pre = "-" in version
        pages = [
            "README.md",
            "llms.txt",
            "sdk/python/README.md",
            "editor/README.md",
            *[
                os.path.relpath(p, self.REPO).replace(os.sep, "/")
                for p in glob.glob(os.path.join(self.REPO, "docs", "**", "*.md"), recursive=True)
            ],
            *[
                os.path.relpath(p, self.REPO).replace(os.sep, "/")
                for p in glob.glob(os.path.join(self.REPO, "sdk", "typescript", "*", "README.md"))
            ],
        ]
        wrong: list[str] = []
        for rel in pages:
            text = self.page(rel)
            if rel == "docs/installing.md":  # its section on alphas, betas and candidates shows how to ask for one
                text = re.sub(r"\n## Alphas, betas and release candidates\n.*?(?=\n## )", "\n", text, flags=re.S)
            fenced = False
            for line in text.split("\n"):
                if line.startswith("```"):
                    fenced = not fenced
                    continue
                if not (fenced or line.startswith(("    ", "|"))):
                    continue
                npm = re.search(r"\bnpm (?:i|install)\b.*?(?<![\w/@-])rowstile(@\w+)?(?![\w/-])", line.split("#")[0])
                pip = re.search(r"\bpip install\b.*\browstile\b", line)
                uv = re.search(r"\buv add\b.*\browstile\b", line)
                image = re.search(r"ghcr\.io/rowstile/rowstile(:[\w.-]+)?", line)
                # the SDK's packages, each with its own tag: once a final release exists, a plain
                # `npm install @rowstile/prisma` gets it, not the pre-release
                sdk = (
                    re.findall(r"@rowstile/[\w-]+(@\w+)?", line.split("#")[0])
                    if re.search(r"\bnpm (?:i|install)\b", line)
                    else []
                )
                if pre:
                    bad = (
                        (npm and npm.group(1) != "@next")
                        or any(tag != "@next" for tag in sdk)
                        or (pip and "--pre" not in line)
                        # for uv, a requirement that names a pre-release allows rowstile's and no other
                        # package's (`--prerelease=allow` brought betas of the app's own dependencies)
                        or (uv and f">={version.split('-')[0]}a0" not in line)
                        or (image and image.group(1) != f":{version}")
                    )
                else:
                    bad = (
                        (npm and npm.group(1) == "@next")
                        or any(tag == "@next" for tag in sdk)
                        or (pip and "--pre" in line)
                        or (
                            uv
                            and ("--prerelease" in line or re.search(rf">=[\d.]+({'|'.join(STAGES.values())})\d", line))
                        )
                        or (image and "-" in (image.group(1) or ""))
                    )
                if bad:
                    wrong.append(f"{rel}: {line.strip()}")
        self.assertEqual(
            wrong,
            [],
            f"install lines that don't get {version} ({'ask for the pre-release' if pre else 'plain installs, no pre-release'})",
        )

    def test_a_release_is_never_called_a_preview(self) -> None:
        # core/CONTEXT.md: a preview is a feature outside the public surface, never a release; and what is published
        # so far is said without naming one stage (an alpha), which the next release would make untrue
        pages = [
            "README.md",
            "llms.txt",
            "context7.json",
            "site/index.md",
            "sdk/python/README.md",
            "playground/README.md",
            *glob.glob("examples/*/README.md", root_dir=self.REPO),
            *glob.glob("sdk/typescript/*/README.md", root_dir=self.REPO),
            *glob.glob("docs/**/*.md", root_dir=self.REPO, recursive=True),
        ]
        pages = [p.replace(os.sep, "/") for p in pages]
        pages = [p for p in pages if not p.startswith("docs/blog/")]  # a post is of its day
        stale = re.compile(
            r"\b0\.x preview\b|\browstile is (?:a )?preview\b|\bonly an alpha\b|\ban alpha so far\b", re.I
        )
        wrong = [
            f"{rel}: {m.group(0)}" for rel in sorted(pages) for m in stale.finditer(" ".join(self.page(rel).split()))
        ]
        self.assertEqual(wrong, [], "a release's stage in a preview's words, or what is published named as an alpha")

    def test_each_call_a_page_writes_is_one_the_functions_take(self) -> None:
        sql = Compiler(parse_policy(read("example/docs.authz"))).compile("x")
        made: dict[str, list[list[tuple[str, bool]]]] = {}  # name -> each form's (type, has a default)
        for name, params in calls(sql, "FUNCTION authz."):
            form = [(p.split()[1], "DEFAULT" in p.split()) for p in params if p.split()[0] != "OUT"]
            made.setdefault(name, []).append(form)
        pages = [
            ("README.md",),
            ("llms.txt",),
            ("core", "CONTEXT.md"),
            ("sdk", "python", "README.md"),
            ("sdk", "typescript", "README.md"),
        ]
        for folder, _, files in os.walk(os.path.join(self.REPO, "docs")):
            pages += [
                (*os.path.relpath(folder, self.REPO).split(os.sep), f) for f in sorted(files) if f.endswith(".md")
            ]
        wrong: list[str] = []
        for page in pages:
            for name, args in calls(self.page(*page), "authz."):
                if name not in made:
                    wrong.append(f"{'/'.join(page)}: authz.{name}() is not a function")
                elif (
                    args
                    and not any("..." in a for a in args)
                    and not any(
                        sum(not d for _, d in form) <= len(args) <= len(form)
                        and all(
                            form[i][0] in ("bigint", "int", "integer")
                            for i, a in enumerate(args)
                            if re.fullmatch(r"\d+", a)
                        )
                        for form in made[name]
                    )
                ):
                    wrong.append(f"{'/'.join(page)}: authz.{name}({', '.join(args)}): no form of it takes these")
        self.assertEqual(wrong, [], "calls the pages write that the functions don't take")


class Promises(unittest.TestCase):
    """Every promise the pages that promise make (docs/reference/*.md, docs/threat-model.md,
    docs/how-it-is-checked.md) names the check that holds it, or says why none does, in a comment readers don't see
    at its end (GitHub and the site hide it):

        a concurrent delete can't slip in between. <!-- checked: tests/concurrency.sh "the share waits for the delete, then is refused" -->
        rowstile has had self-review only. <!-- unchecked: a fact about the project, not about the code -->

    `checked:` names one check or more, `PATH "TEXT"` each, a `;` between them: PATH is a file under core/
    (tests/apply.sh) or the repository's root (.github/workflows/ci.yml), and TEXT is what that file holds of the
    check, its label as the suite prints it after `ok` (or a part of it), or a test's name. `unchecked:` says why,
    in three words or more.

    The rule. A promise is a sentence of a page's prose that says always, never, can't or cannot, only, refuses or
    refused, keeps or kept, removes or removed, each as a word of its own: "read-only" and "append-only" say only;
    "keep" and "remove", which bid the reader do something, make no promise. The prose is the page without its
    code (fenced blocks, blocks indented four spaces after a blank line, `inline code`, link targets) and without
    its comments, and it comes in blocks: a paragraph, a list item, a table row, a heading. A sentence ends at ".",
    "!" or "?" (with what closes there: quotes, brackets, emphasis) before a space or the end of its block. The
    tags right after a sentence, before the next one begins, are that sentence's, and so are tags inside it; a tag
    that follows no sentence (a blank line before it) ends none. A tag is written on its sentence's line: one that
    begins a line would end the paragraph there, and what follows would be a paragraph of its own.

    A tag holds no "--", ">", "|" or backtick: VitePress and GitHub show a comment with "--" in it as text, the
    site's search index keeps what follows a ">" in one, a "|" cuts a table's cell, and a backtick may open code."""

    REPO = os.path.dirname(ROOT)
    WORDS = re.compile(r"\b(?:always|never|can't|cannot|only|refuses|refused|keeps|kept|removes|removed)\b", re.I)
    TAG = re.compile(r"<!--\s*(checked|unchecked):(.*?)-->", re.S)
    COMMENT = re.compile(r"<!--.*?-->", re.S)
    END = re.compile(r"[.!?][\"')\]*_]*(?=\s|$)")
    CHECK = re.compile(r'(\S+) "([^"]+)"')

    def pages(self) -> list[str]:
        found = sorted(glob.glob(os.path.join(self.REPO, "docs", "reference", "*.md")))
        found += [os.path.join(self.REPO, "docs", name) for name in ("threat-model.md", "how-it-is-checked.md")]
        return [os.path.relpath(p, self.REPO).replace(os.sep, "/") for p in found]

    @staticmethod
    def blocks(text: str) -> list[tuple[int, str]]:
        """(first line, text) of each block of a page's prose: a paragraph, list item, table row or heading, its
        lines joined, without the page's code blocks."""
        out: list[tuple[int, str]] = []
        lines: list[str] = []
        start, fence, code, blank = 0, "", False, True

        def close() -> None:
            if lines:
                out.append((start, " ".join(lines)))
            lines.clear()

        for n, line in enumerate(text.split("\n"), 1):
            s = line.strip()
            was_blank, blank = blank, not s
            if fence:
                fence = "" if s.startswith(fence) else fence
                continue
            if m := re.match(r"```+|~~~+", s):
                close()
                fence = m.group(0)
                continue
            if not s:
                close()
                continue
            if line.startswith("    ") and (code or (was_blank and not lines)):
                code = True
                continue
            code = False
            if s.startswith("|") or re.match(r"#{1,6} ", s):  # a table's row, a heading: a line each
                close()
                if not re.fullmatch(r"\|[\s:|-]+", s):
                    out.append((n, s))
                continue
            if re.match(r"[-*+] |\d+[.)] ", s):
                close()
            if not lines:
                start = n
            lines.append(s)
        close()
        return out

    @classmethod
    def sentences(cls, block: str) -> list[tuple[str, list[str]]]:
        """(sentence, the tags that end it) for each sentence of a block of prose; tags that follow no sentence
        come as a sentence of their own, with no words."""
        text = re.sub(r"(`+).+?\1", "CODE", block)
        text = re.sub(r"\]\([^)]*\)", "]", text)
        comments: list[str] = []

        def hide(m: re.Match[str]) -> str:
            comments.append(m.group(0))
            return f"\x00{len(comments) - 1}\x00"

        def tags(piece: str) -> list[str]:
            return [c for i in re.findall(r"\x00(\d+)\x00", piece) if cls.TAG.fullmatch(c := comments[int(i)])]

        text = cls.COMMENT.sub(hide, text)
        pieces, pos = [], 0
        for m in cls.END.finditer(text):
            pieces.append(text[pos : m.end()])
            pos = m.end()
        pieces.append(text[pos:])
        out: list[tuple[str, list[str]]] = []
        for piece in pieces:
            lead = re.match(r"\s*(?:\x00\d+\x00\s*)+", piece)
            if lead and tags(lead.group(0)):
                if out and out[-1][0]:
                    out[-1][1].extend(tags(lead.group(0)))
                else:
                    out.append(("", tags(lead.group(0))))
                piece = piece[lead.end() :]
            words = re.sub(r"\x00\d+\x00", "", piece).strip()
            if words:
                out.append((words, tags(piece)))
        return out

    @classmethod
    def promises(cls, text: str) -> tuple[list[tuple[int, str]], list[tuple[int, str]]]:
        """In a page's text: (line, sentence) of each promise no tag ends, and (line, tags) of tags that end no
        sentence."""
        untagged: list[tuple[int, str]] = []
        lost: list[tuple[int, str]] = []
        for line, block in cls.blocks(text):
            for sentence, tags in cls.sentences(block):
                if not sentence:
                    lost.append((line, " ".join(tags)))
                elif not tags and cls.WORDS.search(sentence):
                    untagged.append((line, sentence))
        return untagged, lost

    def tag_problems(self, tag: str) -> list[str]:
        """What is wrong with a tag: its form, or a check it names that isn't there."""
        m = self.TAG.fullmatch(tag)
        if m is None:
            return [f"not a tag: {tag}"]
        held = [c for c in ("--", ">", "|", "`") if c in tag[4:-3]]
        if held:
            return [f"{tag}: holds {' and '.join(held)}, which a page can't hide in a comment"]
        kind, body = m.group(1), m.group(2).strip()
        if kind == "unchecked":
            return [] if len(body.split()) > 2 else [f"{tag}: say why none does, in words"]
        if not re.fullmatch(r'\S+ "[^"]+"(?:\s*;\s*\S+ "[^"]+")*', body):
            return [f'{tag}: name each check as PATH "TEXT", with a ; between them']
        problems: list[str] = []
        for path, label in self.CHECK.findall(body):
            there = [p for p in (os.path.join(ROOT, path), os.path.join(self.REPO, path)) if os.path.isfile(p)]
            if not there:
                problems.append(f"{tag}: no file {path}, under core/ or the repository's root")
                continue
            with open(there[0], encoding="utf-8") as fh:
                if label not in fh.read():
                    problems.append(f"{tag}: {path} holds no {label!r}")
        return problems

    def test_every_promise_says_what_holds_it(self) -> None:
        untagged: list[str] = []
        lost: list[str] = []
        tagged = 0
        for page in self.pages():
            with open(os.path.join(self.REPO, page), encoding="utf-8") as fh:
                text = fh.read()
            missing, orphans = self.promises(text)
            untagged += [f"{page}:{n}: {s}" for n, s in missing]
            lost += [f"{page}:{n}: {t}" for n, t in orphans]
            tagged += len(self.TAG.findall(text))
        # the loops above find nothing if the pages or their tags aren't found: then nothing would be checked
        self.assertGreater(tagged, 150, "the pages' tags aren't found")
        self.assertEqual(
            untagged, [], "promises that name no check: end each with <!-- checked: ... --> or <!-- unchecked: why -->"
        )
        self.assertEqual(lost, [], "tags that end no sentence (a blank line before them?)")

    def test_each_tag_names_checks_that_are_there(self) -> None:
        wrong: list[str] = []
        for page in self.pages():
            with open(os.path.join(self.REPO, page), encoding="utf-8") as fh:
                text = fh.read()
            for m in self.TAG.finditer(text):
                line = text.count("\n", 0, m.start()) + 1
                wrong += [f"{page}:{line}: {p}" for p in self.tag_problems(m.group(0))]
                # a comment that begins a line ends the paragraph or list item it is in (an HTML block): what
                # follows it would be a paragraph of its own
                if not text[text.rfind("\n", 0, m.start()) + 1 : m.start()].strip():
                    wrong.append(f"{page}:{line}: begins a line: write it after its sentence, on the same line")
        self.assertEqual(wrong, [])

    def test_the_rule(self) -> None:
        page = "\n".join(
            [
                "# A heading that never ends",
                "",
                "One sentence. Another that refuses nothing! <!-- unchecked: made up here -->",
                "And one more, on the next line, that keeps",
                'going. <!-- checked: tests/x.sh "y" -->',
                "",
                "- a read-only item",
                "- an item with `never` in code, and a [link](never.md)",
                "- Keep the key in the backend, and remove it when done.",
                "",
                "| who | what |",
                "|---|---|",
                "| the app | can't, ever <!-- unchecked: made up here --> |",
                "| others | cannot |",
                "",
                "```sql",
                "SELECT 'never';",
                "```",
                "",
                "    rowstile never   # an indented block",
                "",
                "(It is always so.) <!-- unchecked: made up here --> And this kept going.",
                "",
                '<!-- checked: tests/x.sh "y" -->',
            ]
        )
        untagged, lost = self.promises(page)
        self.assertEqual(
            untagged,
            [
                (1, "# A heading that never ends"),
                (7, "- a read-only item"),
                (14, "| others | cannot |"),
                (22, "And this kept going."),
            ],
        )
        self.assertEqual(lost, [(24, '<!-- checked: tests/x.sh "y" -->')])
        good = '<!-- checked: tests/apply.sh "rowstile apply, on a database with no extension" -->'
        self.assertEqual(self.tag_problems(good), [])
        self.assertEqual(self.tag_problems(good.replace("-->", '; tests/cli.sh "check: ok, exit 0" -->')), [])
        for bad, said in (
            ('<!-- checked: tests/apply.sh "apply --force" -->', "holds --"),
            ('<!-- checked: tests/apply.sh "a -> b" -->', "holds >"),
            ('<!-- checked: tests/apply.sh "no check says this" -->', "tests/apply.sh holds no"),
            ('<!-- checked: tests/nowhere.sh "y" -->', "no file tests/nowhere.sh"),
            ("<!-- checked: tests/apply.sh -->", "name each check as"),
            ("<!-- unchecked: because -->", "say why none does"),
        ):
            with self.subTest(bad):
                problems = self.tag_problems(bad)
                self.assertEqual(len(problems), 1, problems)
                self.assertIn(said, problems[0])


class Why(unittest.TestCase):
    """rowstile why: a change the database refused to try is named, not passed over (studio_test.py tries the
    ones that work, on a database)."""

    def test_a_way_that_could_not_be_tried_is_said(self) -> None:
        from authzlib import grant
        from authzlib.parse import Loc

        way = grant.Way(
            [
                grant.Change(
                    "link",
                    "add user 2 to app.team_members for team 10",
                    "INSERT ...",
                    Loc(None, 4),
                    2,
                    ("table", "app.team_members"),
                    ("user", "2", ""),
                )
            ],
            error='null value in column "added_by" of relation "team_members" violates not-null constraint\nDETAIL: ...',
        )
        answer = grant.Answer(False, ["no   team.member"], "view = team.member  (line 7)", untried=[way])
        said = grant.describe(answer, "user:2", "doc", "1", "view").split("\n")
        self.assertEqual(
            said[-2:],
            [
                "no single change that could be tried grants it",
                "could not be tried: add user 2 to app.team_members for team 10 (null value in column "
                '"added_by" of relation "team_members" violates not-null constraint)',
            ],
        )
        nothing = grant.describe(grant.Answer(False, [], "view = owner  (line 3)"), "user:2", "doc", "1", "view")
        self.assertTrue(nothing.endswith("no single change to shares or links grants it"))

    def test_what_a_change_takes_in_words(self) -> None:
        from authzlib import grant

        self.assertEqual(
            grant.taken([("doc", "view", 0, 1), ("doc", "edit", 1, 2), ("folder", "view", 2, 3)], "view"),
            ["view on it from 1 person", "edit on 1 other doc from 2 people", "view on 2 other folders from 3 people"],
        )
        self.assertEqual(grant.more_of([("doc", "view", 1), ("doc", "edit", 2)], "view"),
                         ["view on 1 more doc", "edit on 2 more docs"])  # fmt: skip

    def test_what_isnt_a_permission_is_refused_before_the_database_is_asked(self) -> None:
        """A type the policy doesn't have, a permission it doesn't, a relation, or a permission the compiler made (a
        deny's split): refused in authz.can's words, with its code, before the database is asked anything (here
        there is none)."""
        from authzlib import grant

        c = database.policy_compiler(
            errors_prelude() + "type doc = app.docs\n"
            "  parent : doc  = parent_id\n"
            "  owner  : user = owner_id\n"
            "  can hidden = {hidden} or parent.hidden\n"
            "  can view = (owner or parent.view) and not hidden\n"
        )
        self.assertIn("view__base", c.types["doc"].perms)  # what the compiler made of the deny
        for type_name, perm, said in (
            ("nothing", "view", "no type nothing in the policy"),
            ("doc", "fly", "no permission doc.fly in the policy"),
            ("doc", "owner", "no permission doc.owner in the policy"),
            ("doc", "view__base", "no permission doc.view__base in the policy"),
        ):
            with self.subTest(perm=perm):
                with self.assertRaises(database.Error) as e:
                    grant.how_to_grant(c, cast("grant.Db", None), "user", "1", type_name, "1", perm)
                self.assertEqual((str(e.exception), e.exception.hint), (said, "rowstile help AZ707"))

    def test_a_where_that_names_its_values(self) -> None:
        """A relation's `where` that only gives columns their values can be filled in; any other can't."""
        from authzlib import grant

        for where, held in (
            ("role = 'admin'", {"role": "admin"}),
            ("'admin' = role", {"role": "admin"}),
            ("active and not blocked and level = 2", {"active": True, "blocked": False, "level": 2}),
            ("kind in ('a', 'b') and ended is null", {"kind": "a", "ended": None}),
            ("kind in (null, 'a')", None),  # a column set to NULL is in no list
            ("role <> 'guest'", None),
            ("role = 'admin' or role = 'owner'", None),
            ("ended is not null", None),
            ("added_by = authz.uid()", None),
            ("expires > now()", None),
            ("role = null", None),
        ):
            with self.subTest(where=where):
                self.assertEqual(grant.settles(where), held)
        self.assertEqual(
            [grant.constant(v) for v in ("it's", 2, Decimal("1.5"), True, False, None)],
            ["'it''s'", "2", "1.5", "true", "false", "NULL"],
        )

    def test_a_where_that_cannot_be_filled_in_is_named(self) -> None:
        """No candidate for it, and a note that says which relation was left out."""
        from authzlib import grant

        c = Compiler(
            parse_policy(
                errors_prelude() + "type org = app.orgs\n"
                "  admin : user = app.org_members(org_id -> user_id) where {expires > now()}\n"
                "  can manage = admin\n",
                "p.authz",
            )
        )
        g = grant.Grants(c, cast("grant.Db", None), "user", "4")
        t = c.types["org"]
        self.assertEqual(g.relation(t, "1", t.relations["admin"], 0, frozenset()), [])
        self.assertEqual(
            g.notes,
            [
                "org.admin wasn't tried: it reads app.org_members where {expires > now()}, and it isn't known "
                "which values make that true"
            ],
        )

    def test_what_a_change_can_reach_is_read_from_the_policy(self) -> None:
        """What each permission reads, through relations, arrows and groups: a change is counted only for the
        permissions that read what it writes (never fewer: a condition that reads more than its row, a caveat or a
        where calling a function reads anything), and what is read through a `not` is marked so."""
        from authzlib import grant
        from authzlib.parse import Loc

        c = database.policy_compiler(
            errors_prelude() + "type team = app.teams\n"
            "  member : user = app.team_members(team_id -> user_id)\n"
            "type org = app.orgs\n"
            "  member : user = app.org_members(org_id -> user_id) where {app.active(user_id)}\n"
            "  can manage_roles = member\n"
            "type folder = app.folders where {not deleted}\n"
            "  org     : org    = app.folder_orgs(folder_id -> org_id)\n"
            "  parent  : folder = parent_id\n"
            "  owner   : user   = owner_id\n"
            "  viewer  : user, team#member shared by view\n"
            "  blocked : user   = app.blocks(folder_id -> user_id)\n"
            "  roles   : user from org\n"
            "  can barred = blocked or parent.barred\n"
            "  can view   = (owner or viewer or roles or parent.view) and not barred\n"
            "  can audit  = {exists (select 1 from app.audits)}\n"
            "type file = app.files\n"
            "  folder : folder = folder_id\n"
            "  can view = folder.view\n"
        )
        r = grant.reads(c)
        view = r[("folder", "view")]
        self.assertEqual(
            view,
            {
                (("share", "folder", "viewer"), False),  # a share of the relation
                (("column", "app.team_members", "team_id"), False),  # a group shared with: who is in it
                (("column", "app.team_members", "user_id"), False),
                (("column", "app.folders", "owner_id"), False),  # a column
                (("table", "app.folders"), False),  # the type's where
                (("column", "app.blocks", "folder_id"), True),  # through the deny
                (("column", "app.blocks", "user_id"), True),
                (("column", "app.folders", "parent_id"), True),  # ... which inherits
                (("column", "app.folders", "parent_id"), False),  # (as view does)
                (("table", "app.folders"), True),
                # custom roles count only where the org they belong to is the object's: they read the folder's org
                (("column", "app.folder_orgs", "folder_id"), False),
                (("column", "app.folder_orgs", "org_id"), False),
            },
        )
        self.assertEqual(r[("file", "view")] - view, {(("column", "app.files", "folder_id"), False)})
        self.assertEqual(r[("org", "member")], {(grant.ANY, False)})  # a where that calls a function
        self.assertIn((grant.ANY, False), r[("folder", "audit")])  # a condition with a subquery
        g = grant.Grants(c, cast("grant.Db", None), "user", "4")

        def change(writes: grant.Fact) -> grant.Change:
            return grant.Change("link", "", "", Loc(None, 1), 2, writes, ("user", "4", ""))

        anything = {("org", "manage_roles"), ("folder", "audit")}
        for writes, reached in (
            # a new row of a link table: what reads it, and what reads anything
            (("rows", "app.blocks"), {("folder", "barred"), ("folder", "view"), ("file", "view")}),
            # a column: what reads it, or the whole row (the type's where)
            (("columns", "app.files", "folder_id"), {("file", "view")}),
            (("columns", "app.folders", "owner_id"), {("folder", "barred"), ("folder", "view"), ("file", "view")}),
            # a column no relation reads
            (("columns", "app.blocks", "note"), set()),
            (("columns", "app.files", "name"), set()),
            (("share", "folder", "viewer"), {("folder", "view"), ("file", "view")}),
        ):
            with self.subTest(writes=writes):
                self.assertEqual(set(g.reach([change(writes)])), reached | anything)
        # a caveat on a share is a condition: what is shared may read anything
        c = database.policy_compiler(
            errors_prelude() + "caveat business = {authz.ctx('mode') = 'business'}\n"
            "type doc = app.docs\n"
            "  viewer : user shared by view\n"
            "  can view = viewer\n"
        )
        self.assertEqual(grant.reads(c)[("doc", "view")], {(("share", "doc", "viewer"), False), (grant.ANY, False)})

    def test_a_loop_of_links_is_followed_once(self) -> None:
        """Folders shown inside each other (links may loop): the search comes back to the folder it started from
        and stops there, so each way is found and each link looked up once (not again until the depth runs out)."""
        from authzlib import grant
        from authzlib.parse import Ref, Relation, Source, Type

        c = Compiler(
            parse_policy(
                errors_prelude() + "type folder = app.folders\n"
                "  link  : folder = app.folder_links(folder_id -> parent_id)\n"
                "  owner : user   = owner_id\n"
                "  can view = owner or link.view\n",
                "p.authz",
            )
        )
        looked: list[str] = []

        class Loop(grant.Grants):
            def linked(self, t: Type, r: Relation, src: Source, st: str, sr: str | None, oid: str) -> list[str]:
                if r.name == "owner":
                    return []  # (the folders' owners, read to see whether a change would change anything)
                looked.append(oid)
                return ["2" if oid == "1" else "1"]  # folder 1 is shown in folder 2, and 2 in 1

        g = Loop(c, cast("grant.Db", None), "user", "4")
        ways = g.ways(c.types["folder"], "1", Ref("view"), 0, frozenset())
        self.assertEqual(
            [[ch.text for ch in w] for w in ways],
            [["set owner_id of folder 1 to 4"], ["set owner_id of folder 2 to 4"]],
        )
        self.assertEqual(looked, ["1", "2"])


WINDOWS_ONLY = (
    "Windows only: elsewhere no socket may bind an address and port another one listens on, whatever its options"
)


class StudioPage(unittest.TestCase):
    """Studio's page, which tests/studio_page.mjs opens in Chrome (CI's studio-page job): its graph is drawn by the
    playground's Mermaid, which Studio loads checked against its hash (a hash that isn't the file's fails there)."""

    def test_studio_and_the_playground_draw_with_one_mermaid(self) -> None:
        version = r"cdn\.jsdelivr\.net/npm/mermaid@(\d+\.\d+\.\d+)/dist/"
        self.assertEqual(
            search(version, read("cli/studio/app.js")).group(1),
            search(version, read("../playground/playground.mjs")).group(1),
        )

    def test_ci_opens_the_page_in_a_browser(self) -> None:
        self.assertIn("      - run: bash core/tests/studio_page.sh\n", read("../.github/workflows/ci.yml"))


class StudioPort(unittest.TestCase):
    """Studio's port on 127.0.0.1 is held by Studio alone: a port another program holds is refused, and no other
    program may bind it while Studio runs. On Windows SO_REUSEADDR lets a socket bind an address and port another
    one listens on, so Studio's server leaves it off there and asks for SO_EXCLUSIVEADDRUSE (studio_test.py starts
    the command on a port that is taken, on Linux). The checks of that branch run on Windows alone, and no CI runner
    or machine here runs Windows: nothing runs them."""

    def held(self, reuse: bool) -> int:
        """A port another program listens on, with SO_REUSEADDR (as python -m http.server sets it) or without."""
        s = socket.socket()
        self.addCleanup(s.close)
        if reuse:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("127.0.0.1", 0))
        s.listen()
        return s.getsockname()[1]

    def test_the_socket_options_are_the_ones_meant(self) -> None:
        import studio

        s = studio.Studio(None, port=0)
        s.start()
        self.addCleanup(s.stop)
        assert s.server is not None
        if sys.platform == "win32":
            self.assertEqual(s.server.socket.getsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE), 1)
            self.assertEqual(s.server.socket.getsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR), 0)
        else:
            # there it only lets a restart take the port again while it waits after a close
            self.assertNotEqual(s.server.socket.getsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR), 0)

    def test_the_url_names_the_address_studio_listens_on(self) -> None:
        # not localhost, which a browser may try as ::1 first, where Studio doesn't listen
        import studio

        s = studio.Studio(None, port=0, token="t0k")
        s.start()
        self.addCleanup(s.stop)
        assert s.server is not None
        host, port = s.server.server_address[:2]
        self.assertEqual((host, s.url()), ("127.0.0.1", f"http://127.0.0.1:{port}/?token=t0k"))

    @unittest.skipUnless(sys.platform == "win32", WINDOWS_ONLY)
    def test_a_port_another_program_holds_is_refused(self) -> None:
        import studio

        for reuse in (True, False):
            with self.subTest(reuse=reuse):
                s = studio.Studio(None, port=self.held(reuse))
                with self.assertRaises(OSError):
                    s.start()
                    self.addCleanup(s.stop)  # it took the port: stopped once the test is done

    @unittest.skipUnless(sys.platform == "win32", WINDOWS_ONLY)
    def test_no_other_program_may_bind_the_port_studio_holds(self) -> None:
        import studio

        s = studio.Studio(None, port=0)
        s.start()
        self.addCleanup(s.stop)
        other = socket.socket()
        self.addCleanup(other.close)
        other.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        with self.assertRaises(OSError):
            other.bind(("127.0.0.1", s.port))

    @unittest.skipUnless(sys.platform == "win32", WINDOWS_ONLY)
    def test_studio_says_it_did_not_start_and_how_to_choose_another_port(self) -> None:
        import studio

        port = self.held(True)
        said, ended = io.StringIO(), list[object]()

        def run() -> None:
            try:
                studio.serve(None, rowstile_cli.Config(), None, False, port, rowstile_cli.read_policy)
            except SystemExit as e:
                ended.append(e.code)

        # no database: the port is all this asks about. A Studio that took it would serve until stopped
        with mock.patch.object(studio.Studio, "work"), mock.patch.object(sys, "stderr", said):
            serving = threading.Thread(target=run, daemon=True)
            serving.start()
            serving.join(20)
        self.assertEqual(ended, [2], said.getvalue())
        self.assertRegex(
            said.getvalue(), r"\AStudio didn't start \(.+\): rowstile studio --port N for another port\n\Z"
        )


class LlmsTxt(unittest.TestCase):
    """llms.txt links only files that exist and its policy compiles; docs/llms_full.py (run when the docs are
    published) puts the files it links, and every error page, in one."""

    REPO = os.path.dirname(ROOT)

    def test_links_and_policy(self) -> None:
        sys.path.insert(0, os.path.join(self.REPO, "docs"))
        import llms_full

        text = read("../llms.txt")
        for link in llms_full.links(text):
            self.assertTrue(os.path.exists(os.path.join(self.REPO, *link.split("/"))), f"llms.txt links {link}")
        policy = search(r"```authz\n(.*?)```", text, re.S).group(1)
        Compiler(parse_policy(policy)).compile("x")
        full = llms_full.build()
        for link in ["docs/getting-started.md", "docs/stacks/nextjs.md", "docs/errors/AZ201.md"]:
            self.assertIn(f"<!-- {link} -->", full)

    def test_the_docs_index_for_agents(self) -> None:
        # context7.json says which folders an index of docs for coding agents reads, and what an agent should
        # know first: the folders and files it names are there, and its texts fit the index's limits
        with open(os.path.join(self.REPO, "context7.json"), encoding="utf-8") as fh:
            index = json.load(fh)
        self.assertLessEqual(len(index["projectTitle"]), 100)
        self.assertLessEqual(len(index["description"]), 200)
        for folder in index["folders"]:
            self.assertTrue(os.path.isdir(os.path.join(self.REPO, folder)), f"context7.json reads {folder}/")
        for name in index["excludeFiles"]:
            self.assertTrue(os.path.isfile(os.path.join(self.REPO, name)), f"context7.json leaves out {name}")
        for folder in index["excludeFolders"]:
            self.assertTrue(
                folder.startswith("**/") or glob.glob(os.path.join(self.REPO, *folder.split("/"))),
                f"context7.json leaves out {folder}, which matches nothing",
            )
        self.assertLessEqual(len(index["rules"]), 50)
        for rule in index["rules"]:
            self.assertLessEqual(len(rule), 255, rule)


class Licence(unittest.TestCase):
    """The Python package and the Zed extension ship the licence: their copies (sdk/python/LICENSE, what the build
    takes; editor/zed/LICENSE, what Zed's registry reads) are the repository's."""

    REPO = os.path.dirname(ROOT)

    def test_the_python_package_has_the_repositorys_licence(self) -> None:
        with (
            open(os.path.join(self.REPO, "LICENSE"), encoding="utf-8") as a,
            open(os.path.join(self.REPO, "sdk", "python", "LICENSE"), encoding="utf-8") as b,
        ):
            self.assertEqual(a.read(), b.read(), "sdk/python/LICENSE: copy the repository's LICENSE")

    def test_the_zed_extension_has_the_repositorys_licence(self) -> None:
        # Zed's registry reads the licence in the extension's own folder: one at the repository's root doesn't count
        with (
            open(os.path.join(self.REPO, "LICENSE"), encoding="utf-8") as a,
            open(os.path.join(self.REPO, "editor", "zed", "LICENSE"), encoding="utf-8") as b,
        ):
            self.assertEqual(a.read(), b.read(), "editor/zed/LICENSE: copy the repository's LICENSE")

    def test_the_vscode_extension_has_the_repositorys_licence(self) -> None:
        # vsce packages the licence package.json's files names from the extension's folder (editor/README.md's
        # npm run package, and the release's)
        with (
            open(os.path.join(self.REPO, "LICENSE"), encoding="utf-8") as a,
            open(os.path.join(self.REPO, "editor", "LICENSE"), encoding="utf-8") as b,
        ):
            self.assertEqual(a.read(), b.read(), "editor/LICENSE: copy the repository's LICENSE")


class CoverageReport(unittest.TestCase):
    """tests/coverage_report.py, which says what the suites run of authzlib and cli (ci.sh --coverage): how it reads
    runs of lines, a diff, and which steps compare the database's answers with the reference evaluator."""

    def setUp(self) -> None:
        sys.path.insert(0, os.path.join(ROOT, "tests"))
        import coverage_report

        self.report = coverage_report

    def test_runs_of_lines(self) -> None:
        ranges = self.report.ranges
        # a run goes on over lines that aren't statements, and stops at one that ran
        self.assertEqual(ranges([3, 4, 6, 9, 10], [1, 3, 4, 5, 6, 8, 9, 10]), [(3, 4), (6, 6), (9, 10)])
        self.assertEqual(ranges([3, 7], [3, 7]), [(3, 7)])
        self.assertEqual(ranges([], [1, 2]), [])

    def test_the_totals(self) -> None:
        files = [
            self.report.File(name="a.py", statements=[1, 2, 3, 4], missing=[4], never={}, branches=4, branches_run=1),
            self.report.File(name="b.py", statements=[1], missing=[], never={}, branches=0, branches_run=0),
        ]
        self.assertEqual(self.report.summary(files), "run: 4 of 5 lines (80.0%), 1 of 4 branches (25.0%)")

    def test_the_lines_a_diff_changes(self) -> None:
        diff = (
            "diff --git a/core/authzlib/parse.py b/core/authzlib/parse.py\n--- a/core/authzlib/parse.py\n"
            "+++ b/core/authzlib/parse.py\n@@ -10 +12 @@ def a():\n-x\n+y\n@@ -20,2 +22,3 @@\n-a\n-b\n+c\n+d\n+e\n"
            "@@ -40,2 +44,0 @@\n-gone\n-gone\n"
            "diff --git a/core/cli/old.py b/core/cli/old.py\n--- a/core/cli/old.py\n+++ /dev/null\n@@ -1 +0,0 @@\n-x\n"
            "diff --git a/docs/a.md b/docs/a.md\n--- a/docs/a.md\n+++ b/docs/a.md\n@@ -1 +1 @@\n-x\n+y\n"
        )
        self.assertEqual(self.report.changed(diff), {"authzlib/parse.py": {12, 22, 23, 24}})

    def test_never_judged(self) -> None:
        judged = "random changes, compared with the reference evaluator (docs, 15 changes)"
        f = self.report.File(
            name="authzlib/compiler.py",
            statements=[1, 2, 3, 5, 6, 7],
            missing=[6, 7],
            never={},
            branches=0,
            branches_run=0,
            functions=[
                self.report.Function("Core.a", [1, 2]),
                self.report.Function("Core.b", [5, 6]),
                self.report.Function("Core.c", [7]),
            ],
            steps={1: {"unit"}, 2: {judged}, 3: {"unit", "random policies in random worlds: ..."}, 5: {"apply"}},
        )
        # Core.a's line 2 was judged; Core.b ran only where nothing compares answers; Core.c never ran
        self.assertEqual(
            self.report.never_judged(f, "a = 1\nb = 2\nc = 3\n\nd = 4\ne = 5\nf = 6\n"), ([1, 5], ["Core.b"])
        )
        # a policy's mistake is reported on lines no policy that compiles reaches: all of a fail(...) call's
        self.assertEqual(
            self.report.never_judged(
                f, 'a = 1\nb = 2\nc = 3\nif c:\n    fail(\n        "a mistake",\n        "AZ999",\n    )\n'
            ),
            ([1], ["Core.b"]),
        )
        self.assertEqual(
            self.report.mistakes("try:\n    x = 1\nexcept ValueError:\n    y = 2\nraise KeyError(\n    'k'\n)\n"),
            {3, 4, 5, 6, 7},
        )
        # a check that only reports a mistake: an if ending in one (its message made first), a loop of them
        check = "if bad:\n    msg = 'm'\n    fail(msg)\nfor x in xs:\n    if x:\n        fail('x')\n"
        self.assertEqual(self.report.mistakes(check), {1, 2, 3, 4, 5, 6})
        # but not an if with an else, nor a loop that does more than look
        does = "if bad:\n    fail('m')\nelse:\n    a = 1\nfor x in xs:\n    out.append(x)\n    assert x\n"
        self.assertEqual(self.report.mistakes(does), {2, 7})  # an assert passes: the append isn't a message
        # after a way out, what only leads on to a report makes its message
        look = "def f(n):\n    if n in names:\n        return\n    known = sorted(names)\n    fail(n, known)\n"
        self.assertEqual(self.report.mistakes(look), {4, 5})

    def test_what_nothing_runs_is_shown_with_its_text(self) -> None:
        f = self.report.File(
            name="authzlib/__init__.py",
            statements=[1, 2, 3],
            missing=[2],
            never={3: [-1, 5]},
            branches=2,
            branches_run=0,
        )
        lines = read("authzlib/__init__.py").split("\n")
        two, three = self.report.text(lines, 2), self.report.text(lines, 3)
        self.assertEqual(two, lines[1].strip())
        self.assertEqual(
            self.report.not_run(f),
            [f"{2:>11}  {two}", f"{3:>11}  never to the function's end, line 5: {three}"],
        )
        # the way on from a failure at a loop's end (back to the loop) is no branch a run can take: not shown
        code = "for x in xs:\n    if bad(x):\n        fail(x)\nraise E\n"
        f = self.report.File(
            name="x.py",
            statements=[1, 2, 3, 4],
            missing=[],
            never={2: [1], 3: [1], 4: [-1]},
            branches=4,
            branches_run=1,
        )
        self.assertEqual(self.report.stops(code), {3, 4})
        self.assertEqual(self.report.not_run(f, code=code), [f"{2:>11}  never to line 1: if bad(x):"])

    def test_what_made_a_function(self) -> None:
        kind = self.report.kind
        for (schema, name, args), want in {
            ("authz_gen", "app.files:update:refuse", "t app.files"): "authz_gen.<table>:update:refuse",
            ("authz_gen", "app.files:column_2:holds", "r app.files"): "authz_gen.<table>:column_<n>:holds",
            ("authz_int", "folder__view__why", "p_id text"): "authz_int.<type>__<name>__why",
            ("authz_int", "user__forget_id", ""): "authz_int.<type>__forget_id",
            ("authz_int", "team__update_1", ""): "authz_int.<type>__update_<n>",
            ("authz_int", "folder_project__tree2_rows_project", ""): "authz_int.<tree>_rows_<type>",
            ("authz_int", "folder_project__host_inside_parent__tree_on_links1", ""): "authz_int.<tree>_on_links<n>",
            ("authz_int", "user__manager__tree_verify", ""): "authz_int.<tree>_verify",
            ("authz_int", "rel_audit_3_ins", ""): "authz_int.rel_audit_<n>_ins",
            ("authz_gen", "folder__check_13d4d15429", ""): "authz_gen.<type>__check_<hash>",
            (
                "authz_int",
                "domain_email_org_setting__domain_email_org_settings__t_07bd0a7e",
                "",
            ): "authz_int.<tree>_<hash>",
            ("authz_int", "canon", "p_type text, p_id text"): "authz_int.canon",
            ("authz", "can", "text, text, text"): "authz.can(text, text, text)",
        }.items():
            self.assertEqual(kind(schema, name, args), want, name)
        # each function the compiler names after a policy's own words (its types, relations and permissions) has a
        # kind with none of them: a new shape of name gets a kind of its own, not one per policy
        made = r'CREATE (?:OR REPLACE )?FUNCTION (authz_gen|authz_int)\."?([^"( ]+)'
        for name, path in POLICIES.items():
            c = Compiler(parse_policy(read(path), path))
            own = {w for t in c.types.values() for w in (t.name, *t.perms, *t.relations)}
            for schema, fn in set(re.findall(made, c.compile(path))):
                if "__" in fn or ":" in fn:
                    self.assertFalse(set(re.findall(r"[a-z0-9]+", kind(schema, fn, ""))) & own, f"{name}: {fn}")

    def test_the_calls_written_beside_the_data(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "functions.tsv"), "w", encoding="utf-8") as fh:
                fh.write("step a\tauthz_x\tauthz\tcan\ttext, text, text\t3\tplpgsql definer set\n")
                fh.write("step b\tauthz_x\tauthz_gen\tapp.files:update:refuse\tt app.files\t0\tplpgsql set\n")
                fh.write("step b\tauthz_y\tauthz_gen\tapp.docs:update:refuse\tt app.docs\t2\tplpgsql set\n")
                fh.write("step b\tauthz_y\tauthz_int\tfolder__forget\t\t0\tplpgsql definer set\n")
                fh.write("step c\tauthz_y\tauthz\tverify\t\t0\tsql\n")  # inlined: never counted
                fh.write("step c\tauthz_z\tauthz\tctx\tkey text\t0\n")  # written before the language was
                # a guard: called in one database, where every call raised (Postgres has a count for it, at 0)
                fh.write("step b\tauthz_x\tauthz_int\taudit_is_append_only\t\t0\tplpgsql\tf\n")
                fh.write("step b\tauthz_y\tauthz_int\taudit_is_append_only\t\t0\tplpgsql\tt\n")
                # a database measured before it applies again (the call), and when it is dropped (made anew since)
                fh.write("step d\tauthz_w\tauthz\tstart_review\tp_id text\t1\tplpgsql definer set\tt\n")
                fh.write("step d\tauthz_w\tauthz\tstart_review\tp_id text\t0\tplpgsql definer set\tf\n")
                fh.write("a line cut short\n")
            called = self.report.functions_measured([os.path.join(d, ".coverage")])
        self.assertEqual(len(called), 10)
        kinds = self.report.by_kind(called)
        refuse = kinds["authz_gen.<table>:update:refuse"]
        self.assertEqual((refuse.made, refuse.called, refuse.steps, refuse.counted), (2, 1, {"step b"}, True))
        self.assertFalse(kinds["authz.verify()"].counted)
        guard, review = kinds["authz_int.audit_is_append_only"], kinds["authz.start_review(p_id text)"]
        self.assertEqual((guard.made, guard.called, guard.raised), (2, 0, 1))
        self.assertEqual((review.made, review.called, review.raised, review.steps), (1, 1, 0, {"step d"}))
        report = self.report.functions_report(called)
        # counted: can, the refusals and the review (called), the guard (raised), the forget and ctx (whose
        # language was not written: counted)
        self.assertIn("3 of 6 kinds of function called, and 1 more whose every call raised", report[1])
        # every call raised: the guard, apart from what was never called; the inlined one apart, not counted
        raised, never, uncounted = (
            report.index("  authz_int.audit_is_append_only  (made in 2 database(s), called in 1)"),
            report.index("  authz_int.<type>__forget  (made in 1 database(s))"),
            report.index("  authz.verify()"),
        )
        self.assertLess(raised, never)
        self.assertLess(never, uncounted)
        self.assertLess(report.index("  authz.ctx(key text)  (made in 1 database(s))"), uncounted)
        self.assertFalse([line for line in report if "start_review" in line])

    def test_statements_lost_with_the_catalog_row(self) -> None:
        # Postgres counts calls by the function's oid; the profiler, by its catalog row, which a GRANT or REVOKE
        # (or applying again) makes anew: a function called and then granted, read after, has no statement counted
        plpgsql = self.report.coverage_plpgsql
        called = [
            self.report.Called("s", "authz_a", "authz", "connection_check", "", 9, "plpgsql definer set", True),
            self.report.Called("s", "authz_a", "authz", "can", "t text", 3, "plpgsql definer set", True),
            self.report.Called("s", "authz_a", "authz", "lint", "", 0, "plpgsql definer set", False),  # never called
            self.report.Called("s", "authz_a", "authz", "uid", "", 5, "sql", True),  # not PL/pgSQL
            self.report.Called("s", "authz_b", "authz", "connection_check", "", 1, "plpgsql definer set", True),
        ]
        runs = [
            plpgsql.Run("s", "authz_a", "authz", "connection_check", "", "m", {}, (0.0, 0.0)),
            plpgsql.Run("s", "authz_a", "authz", "can", "t text", "m", {1: 3}, (1.0, 1.0)),
            plpgsql.Run("s", "authz_a", "authz", "lint", "", "m", {}, (0.0, 0.0)),
            # measured twice (before applying again, and when dropped): what the first read counted stands
            plpgsql.Run("s", "authz_b", "authz", "connection_check", "", "m", {1: 1}, (1.0, 1.0)),
            plpgsql.Run("s", "authz_b", "authz", "connection_check", "", "n", {}, (0.0, 0.0)),
        ]
        lost = self.report.lost(called, plpgsql.Measured({}, runs, []))
        self.assertEqual(lost, ["  authz.connection_check() in authz_a (s)"])

    def test_the_steps_that_compare_answers_are_named_so(self) -> None:
        # the report knows them by their names in run_tests.sh: a step renamed must not leave the comparison
        steps = re.split(r'\n\s*step "', read("run_tests.sh"))[1:]
        self.assertGreater(len(steps), 20)
        compares = 0
        for text in steps:
            label = text.split('"', 1)[0]
            body = re.split(r"\n\s*record ", text, maxsplit=1)[0]  # the step's own commands
            runs = re.search(r"tests/(?:difftest|genpolicy|around)\.py", body) is not None
            compares += runs
            self.assertEqual(bool(self.report.ORACLE.search(label)), runs, label)
        self.assertGreaterEqual(compares, 6)

    def test_the_settings_name_the_code(self) -> None:
        settings = read("tests/coverage.ini")
        self.assertEqual(re.findall(r"^\s+\$\{ROWSTILE_COVERAGE_CODE\}/(\S+)$", settings, re.M), ["authzlib", "cli"])
        for name in self.report.DECIDES:
            self.assertTrue(os.path.isfile(os.path.join(ROOT, name)), name)


class CoveragePlpgsql(unittest.TestCase):
    """tests/coverage_plpgsql.py, which reads what plpgsql_check's profiler counted of rowstile's PL/pgSQL: which
    statements begin which arm (the profiler says only which statement holds which), the branches, and the report.
    The figures here are what plpgsql_check 2.10 answered for this function, called with 1, 3, 1 and -1."""

    SOURCE = """
DECLARE r text;
BEGIN
  IF x = 1 THEN
    r := 'one';
  ELSIF x = 2 THEN
    r := 'two';
  ELSIF x < 0 THEN
    RAISE EXCEPTION 'negative' USING HINT = 'AZ999';
  END IF;
  CASE WHEN x > 100 THEN r := 'big'; ELSE NULL; END CASE;
  FOR i IN 1..x LOOP
    IF i = 5 THEN EXIT; END IF;
  END LOOP;
  BEGIN
    PERFORM 1/(x-3);
  EXCEPTION WHEN division_by_zero THEN
    r := 'three';
  END;
  RETURN r;
END """
    # stmtid, parent_stmtid, block_num, lineno, stmtname, exec_stmts, exec_stmts_err
    PROFILE: ClassVar[list[list[int | str | None]]] = [
        [1, None, 1, 3, "statement block", 4, 1],
        [2, 1, 1, 4, "IF", 4, 1],
        [3, 2, 1, 5, "assignment", 2, 0],
        [4, 2, 2, 7, "assignment", 0, 0],
        [5, 2, 3, 9, "RAISE", 1, 1],
        [6, 1, 2, 11, "CASE", 3, 0],
        [7, 6, 1, 11, "assignment", 0, 0],
        [8, 1, 3, 12, "FOR with integer loop variable", 3, 0],
        [9, 8, 1, 13, "IF", 5, 0],
        [10, 9, 1, 13, "EXIT", 0, 0],
        [11, 1, 4, 15, "statement block", 3, 0],
        [12, 11, 1, 16, "PERFORM", 3, 1],
        [13, 11, 2, 18, "assignment", 1, 0],
        [14, 1, 5, 20, "RETURN", 3, 0],
    ]
    RATIOS: ClassVar[list[float]] = [
        0.7857142857142857,
        0.6363636363636364,
    ]  # plpgsql_coverage_statements, plpgsql_coverage_branches

    def setUp(self) -> None:
        sys.path.insert(0, os.path.join(ROOT, "tests"))
        import coverage_plpgsql
        import coverage_report

        self.p = coverage_plpgsql
        self.kind = coverage_report.kind

    def test_which_statements_begin_which_arm(self) -> None:
        body = self.p.read_body("m", self.SOURCE, self.PROFILE)
        self.assertEqual(body.why, "")
        assert body.branches is not None
        arms = [(b.statement, b.label, b.first) for b in body.branches]
        # NULL is no statement: the CASE's ELSE has none; an IF without ELSE has one more way, no arm taken
        self.assertEqual(
            arms,
            [(2, "then", 3), (2, "elsif", 4), (2, "elsif", 5), (2, "no arm", 0), (6, "when", 7), (6, "else", 0)]
            + [(8, "body", 9), (9, "then", 10), (9, "no arm", 0), (11, "body", 12), (11, "handler", 13)],
        )
        ran = {int(cast(int, r[0])): int(cast(int, r[5])) for r in self.PROFILE}
        # as plpgsql_check counts: the same shares it gave
        self.assertEqual(self.p.share(body, ran), (self.RATIOS[0], self.RATIOS[1]))
        # as the report counts: the CASE's ELSE without a statement was taken (the CASE ran 3 times, its WHEN never)
        self.assertEqual([self.p.taken(b, ran) for b in body.branches if b.statement == 6], [False, True])

    def test_what_the_source_is_read_through(self) -> None:
        source = """
#variable_conflict use_column
<<outer>>
DECLARE v int := CASE WHEN true THEN 1 ELSE 2 END; -- a comment: IF x THEN
BEGIN
  /* a comment /* nested */ END IF; */
  EXECUTE $q$ IF a THEN b; END IF; $q$;
  v := (SELECT CASE WHEN 'x;' = E'it\\'s; END' THEN 1 END);
  IF v IS NULL THEN NULL; ELSIF (SELECT CASE WHEN true THEN true END) THEN RETURN 1; END IF;
  <<inner>> WHILE v < 3 LOOP v := v + 1; END LOOP inner;
  CASE v WHEN 1 THEN RETURN "end"; END CASE;
  RETURN 2;
END outer;"""
        profile = [
            [1, None, 1, 5, "statement block"],
            [2, 1, 1, 7, "EXECUTE"],
            [3, 1, 2, 8, "assignment"],
            [4, 1, 3, 9, "IF"],
            [5, 4, 1, 9, "RETURN"],
            [6, 1, 4, 10, "WHILE"],
            [7, 6, 1, 10, "assignment"],
            [8, 1, 5, 11, "CASE"],
            [9, 8, 1, 11, "RETURN"],
            [10, 1, 6, 12, "RETURN"],
        ]
        body = self.p.read_body("m", source, profile)
        self.assertEqual(body.why, "")
        assert body.branches is not None
        self.assertEqual(
            [(b.statement, b.label, b.first) for b in body.branches],
            [(4, "then", 0), (4, "elsif", 5), (4, "no arm", 0), (6, "body", 7), (8, "when", 9)],
        )
        # a statement the profiler counts and the source here doesn't hold: the branches aren't guessed
        unread = self.p.read_body("m", source, [*profile, [11, 1, 7, 12, "RETURN"]])
        self.assertIsNone(unread.branches)
        self.assertEqual(unread.why, "10 statements read, the profiler counts 11")

    def test_the_policy_names_are_taken_out(self) -> None:
        self.assertEqual(
            self.p.plain("  IF NOT v THEN   RAISE 'cannot update app.files';", self.p.names("app.files:update:refuse")),
            "IF NOT v THEN RAISE 'cannot update <table>';",
        )
        self.assertEqual(
            self.p.plain("RETURN folder_id IN (SELECT id FROM folder__view);", self.p.names("folder__view__has")),
            "RETURN folder_id IN (SELECT id FROM folder__view);",  # (whole names only)
        )
        self.assertEqual(
            self.p.plain("PERFORM folder.view;", self.p.names("folder__view__has")), "PERFORM <type>.<name>;"
        )
        # a rule on columns: its columns and what it needs are the policy's words too; its key, of one column or several
        own = self.p.names("app.files:update:refuse")
        for line, key in (
            (
                """RAISE EXCEPTION 'changing owner_id of app.files % needs: share', OLD."id" USING ERRCODE = 'x'""",
                "OLD.<key>",
            ),
            (
                """RAISE EXCEPTION 'changing a, b of app.files % needs: {s = ''x''} or edit', """
                """ROW(OLD."org_id"::bigint, OLD."id"::bigint)::text USING ERRCODE = 'x'""",
                "ROW(OLD.<key>, ...)::text",
            ),
        ):
            self.assertEqual(
                self.p.plain(line, own),
                f"RAISE EXCEPTION 'changing <columns> of <table> % needs: <rule>', {key} USING ERRCODE = 'x'",
            )

    def test_the_databases_names_are_taken_out_everywhere(self) -> None:
        # a table (by its functions app.files:...) and a type (folder__...) of the database, in another function
        source = '\nBEGIN\n  RETURN \'folder\' = (SELECT 1 FROM "app"."files" WHERE app.files.folder);\nEND '
        profile = [[1, None, 1, 2, "statement block", 1, 0], [2, 1, 1, 3, "RETURN", 1, 0]]
        with tempfile.TemporaryDirectory() as d:
            for name in ("app.files:update:refuse", "folder__view__has", "lint"):
                fn = {"schema": "authz", "name": name, "args": "", "md5": "m", "source": source, "ratios": [1, 1]}
                self.p.save(d, "step", "authz_a", ["connected", json.dumps({**fn, "statements": profile}), "read"])
            t = self.p.totals(self.p.measured([d]), self.kind)
        texts = {x.kind: x.text for x in t.statements.values() if x.what == "RETURN"}
        # (a type's name in the SQL itself stays: only the function's own, or a string, is the policy's for sure)
        self.assertEqual(texts["authz.lint()"], "RETURN '<type>' = (SELECT 1 FROM <table> WHERE <table>.folder);")

    def test_saved_then_reported(self) -> None:
        line = {"schema": "authz_int", "md5": "m", "source": self.SOURCE, "ratios": self.RATIOS}
        with tempfile.TemporaryDirectory() as d:
            for db, name in (("authz_a", "folder__guard"), ("authz_b", "doc__guard")):
                fn = {**line, "name": name, "args": "x integer", "statements": self.PROFILE}
                self.assertEqual(self.p.save(d, "step a", db, ["connected", "off?", json.dumps(fn), "1", "read"]), 1)
            self.assertEqual(
                self.p.save(d, "step a", "authz_e", ["connected", "0", "read"]), 0
            )  # no function: nothing written
            self.assertEqual(self.p.save(d, "step b", "authz_c", ["connected", "ERROR: x"]), 0)  # couldn't be read
            self.assertEqual(
                self.p.save(d, "step b", "authz_d", ["connected", "off"]), 0
            )  # no profiler: nothing written
            self.assertEqual(self.p.save(d, "step b", "authz_f", []), 0)  # dropped already: nothing written
            with open(os.path.join(d, "plpgsql.jsonl"), encoding="utf-8") as fh:
                self.assertEqual(len(fh.read().splitlines()), 4)  # the body once, two functions, the unread
            with open(os.path.join(d, "plpgsql-memory.txt"), "w", encoding="utf-8") as fh:
                fh.write("NOTICE:  allocated stats: 100 (5kB), used stats: 95\n")
            reasons = os.path.join(d, "why.txt")
            with open(reasons, "w", encoding="utf-8") as fh:
                fh.write("# KIND | WORDS | WHY\nauthz_int.<type>__guard | r := 'two' | x is never 2\n")
                fh.write("authz_int.<type>__guard | gone | a reason nothing matches\n")
            m = self.p.measured([d])
            out = self.p.report(m, self.p.totals(m, self.kind), [d], reasons)
        self.assertEqual(m.unread, [("step b", "authz_c")])
        self.assertEqual(len(m.runs), 2)
        t = self.p.totals(m, self.kind)
        # each statement and branch once for the kind and its line, however many databases had it (the two blocks'
        # lines both say BEGIN: one)
        self.assertEqual(self.p.summary(t), "PL/pgSQL: 10 of 13 statements (76.9%), 8 of 11 branches (72.7%)")
        self.assertTrue(out[3].startswith("WARNING: the profiler's memory was 95.0% full"), out[3])
        text = "\n".join(out)
        g = "authz_int.<type>__guard"
        self.assertIn("RAISE never run (every guard should be met by some suite):\n  (none)", text)
        self.assertIn(
            f"Never run, and why (tests/coverage_plpgsql.txt):\n  {g}\n      r := 'two';  (assignment; in 2 function(s)): x is never 2",
            text,
        )
        self.assertIn(
            "Other statements never run, in the kinds of function some suite calls:\n  authz_int.<type>__guard\n      CASE WHEN x > 100 "
            "THEN r := 'big'; ELSE NULL; END CASE;  (assignment; in 2 function(s))\n      IF i = 5 THEN EXIT; END IF;  "
            "(EXIT; in 2 function(s))\n",
            text,
        )
        # branches: only those without a statement of their own (the elsif is its statement's, listed above)
        self.assertNotIn("(elsif;", text)
        self.assertIn(
            "Kinds of function no suite calls, and how many other statements that leaves never run:\n  (none)", text
        )
        self.assertIn(
            f"Reasons in tests/coverage_plpgsql.txt that nothing never run matches (remove them):\n  {g} | gone", text
        )
        self.assertNotIn("otherwise than read here", text)

    def test_the_coverage_image_and_ci_count_statements(self) -> None:
        # the package in the coverage image only, the profiler preloaded where ci.sh measures, and CI keeps the counts
        self.assertIn("${COVERAGE:+python3-coverage postgresql-$PG_MAJOR-plpgsql-check}", read("Dockerfile"))
        ci = read("ci.sh")
        for flag in ("shared_preload_libraries=plpgsql_check", "plpgsql_check.profiler=on", "cursors_leaks=off"):
            self.assertRegex(ci, r"\$\{STATEMENTS:\+[^}]*" + re.escape(flag), flag)
        self.assertIn('-e ROWSTILE_COVERAGE_STATEMENTS="$STATEMENTS"', ci)
        # nightly runs it and keeps the counts, which its report reads
        workflow = read("../.github/workflows/nightly.yml")
        self.assertIn("run: bash core/ci.sh --statements 16", workflow)
        for name in (".coverage", "functions.tsv", "plpgsql.jsonl", "plpgsql-memory.txt"):
            self.assertIn(f".ci/coverage-16/{name}", workflow)
        self.assertIn("tests/coverage_report.py --out /src/.ci/statements /src/.ci/parts/statements-pg16-*", workflow)
        # the read is rolled back: the extension is never left in a database a suite checks
        wrapper = read("tests/coverage_functions.sh")
        self.assertLess(wrapper.index("CREATE EXTENSION plpgsql_check"), wrapper.index("ROLLBACK;"))
        self.assertNotIn("COMMIT;", wrapper)

    def test_a_raise_never_run_comes_first(self) -> None:
        profile = [[*r[:5], 0 if r[0] == 5 else r[5], 0] for r in self.PROFILE]
        line = {"schema": "authz_gen", "name": "app.files:update:refuse", "args": "", "md5": "m"}
        with tempfile.TemporaryDirectory() as d:
            fn = {**line, "source": self.SOURCE, "statements": profile, "ratios": [None, None]}
            self.p.save(d, "step", "authz_a", ["connected", json.dumps(fn), "read"])
            m = self.p.measured([d])
            out = self.p.report(m, self.p.totals(m, self.kind), [d], os.path.join(d, "none.txt"))
        first = out.index("RAISE never run (every guard should be met by some suite):")
        self.assertEqual(
            out[first + 1 : first + 3],
            [
                "  authz_gen.<table>:update:refuse",
                "      RAISE EXCEPTION 'negative' USING HINT = 'AZ999';  (RAISE; in 1 function(s))",
            ],
        )


class Guards(unittest.TestCase):
    """Each refusal the SQL authzlib writes can raise is asked for by its own words in some suite: a check that asks
    only for an SQLSTATE can't tell which guard refused (two that answer 42501 look alike). A guard's own words are
    four in a row of the parts of its message that don't vary, which no other guard's message has, or its code
    ([AZ6xx]) when no other has that code. A guard whose words another's message has too is asked for by them once
    for each function of the API (authz.*) that raises it, a check naming that function beside them (within WINDOW
    characters): which functions raise it, the compiled policies in tests/golden say."""

    REPO = os.path.dirname(ROOT)
    N = 4
    # guards whose every run of words another guard's message has too: words can't tell them apart, so each is
    # reached by what its check sets up. A new guard listed here wants words of its own, or a line here.
    SHARED = frozenset(
        {
            "% cannot be moved inside itself",
            "bad",
            "custom roles on % cannot grant %",
            "invalid API key",
            "no API key % of yours",
            "no caveat % in the policy",
            "no item % in review %",
            "no link % on % %",
            "no pending request %",
            "no pending request % of yours",
            "no permission %.% in the policy",
            "no role % for %",
            "no scope % in the policy",
            "no type % in the policy",
            "the policy does not allow sharing %.% with %",
            "the policy does not allow sharing %.% with a user",
            "there is no % %",
            "you cannot manage role %",
            "you cannot share % %",
            "you cannot share % % (needs %)",
            "you cannot unshare % on % %",
            "you cannot unshare % on % % (needs %)",
            "{t.name} % cannot be moved inside itself",
        }
    )
    # guards with no message of their own, in the text: a column rule's refusal, whose message is made in Python
    # (principals.sh and children.sh ask for its words), and the named tests' end, never shown (AZT00)
    NO_MESSAGE = 2
    # guards their own function catches, whose callers see another message: asked for by that one's words
    CAUGHT: ClassVar[dict[str, str]] = {"bad": "invalid token"}
    WINDOW = 200

    def raisers(self) -> dict[str, set[str]]:
        """For each guard in SHARED, the functions of the API (authz.*) that raise it in the compiled policies of
        tests/golden; a message the words of two guards fit is the one's with the most words of its own."""

        def literal(m: str) -> int:
            return len(re.sub(r"%|\{[^{}]*\}", "", m))

        fits = {
            m: re.compile(
                "".join(
                    ".*?" if re.fullmatch(r"%|\{[^{}]*\}", p) else re.escape(p)
                    for p in re.split(r"(%|\{[^{}]*\})", m.replace("''", "'"))
                    if p
                )
                + "$"
            )
            for m in self.SHARED
        }
        out: dict[str, set[str]] = {m: set() for m in self.SHARED}
        for path in sorted(glob.glob(os.path.join(ROOT, "tests", "golden", "*.sql"))):
            fn = ""
            with open(path, encoding="utf-8") as fh:
                for line in fh:
                    made = re.search(r'CREATE (?:OR REPLACE )?FUNCTION\s+((?:"[^"]+"|\w+)\.(?:"[^"]+"|\w+))', line)
                    if made:
                        fn = made.group(1).replace('"', "")
                    for r in re.finditer(r"RAISE EXCEPTION '((?:[^']|'')*)'", line):
                        said = r.group(1).replace("''", "'")
                        best = max((m for m, f in fits.items() if f.match(said)), key=literal, default=None)
                        if best is not None and fn.startswith("authz."):
                            out[best].add(fn)
        return out

    def guards(self) -> list[tuple[str, str | None]]:
        """(file:line, the message's text as the source writes it) for each RAISE EXCEPTION in authzlib."""
        literal = re.compile(r"RAISE EXCEPTION\s+(?:USING[^;]*?MESSAGE\s*=\s*)?'((?:[^']|'')*)'")
        out = []
        for name in sorted(os.listdir(os.path.join(ROOT, "authzlib"))):
            if name.endswith(".py"):
                src = read(f"authzlib/{name}")
                for m in re.finditer(r"RAISE EXCEPTION", src):
                    lm = literal.match(src, m.start())
                    out.append((f"{name}:{src.count(chr(10), 0, m.start()) + 1}", lm.group(1) if lm else None))
        return out

    def runs(self, message: str) -> set[str]:
        """Every run of N words of the parts of the message that don't vary (% and {python} do); a part of fewer
        words, whole, if it is long enough to mean something."""
        text = message.replace("''", "'").replace("{{", "{").replace("}}", "}")
        out = set()
        for part in re.split(r"%|\{[^{}]*\}|\[AZ\d{3}\]", text):
            words = part.split()
            if len(words) >= self.N:
                out |= {" ".join(words[i : i + self.N]) for i in range(len(words) - self.N + 1)}
            elif len(" ".join(words)) >= 12:
                out.add(" ".join(words))
        return out

    def suites(self) -> str:
        """Every suite's text, white space made single and SQL's doubled quotes read back: the core's suites (but
        this file, which names the messages), the conformance apps' and the example apps' tests."""
        paths = [
            p
            for pattern in ("core/tests/*.*", "integrations/*/tests/*.*", "examples/*/backend/tests/*.*")
            for p in glob.glob(os.path.join(self.REPO, *pattern.split("/")))
            if p.endswith((".sh", ".py", ".sql", ".ts", ".tsx")) and os.path.basename(p) != "unit_test.py"
        ]
        self.assertGreater(len(paths), 40, "the suites aren't found")
        texts = []
        for p in paths:
            with open(p, encoding="utf-8", errors="replace") as fh:
                texts.append(re.sub(r"\s+", " ", fh.read()).replace("''", "'"))
        return "\n".join(texts)

    def sorted_out(self) -> tuple[list[str], set[str], int]:
        """(guards no suite asks for by their own words, the messages of those with no words of their own, how
        many have no message at all)."""
        guards = self.guards()
        seen: dict[str, int] = {}
        codes: dict[str, int] = {}
        for _, message in guards:
            for r in self.runs(message or ""):
                seen[r] = seen.get(r, 0) + 1
            for c in set(re.findall(r"\[(AZ\d{3})\]", message or "")):
                codes[c] = codes.get(c, 0) + 1
        text = self.suites()
        raisers = self.raisers()
        unasked, shared, no_message = [], set(), 0
        for where, message in guards:
            if message is None:
                no_message += 1
                continue
            own = {r for r in self.runs(message) if seen[r] == 1}
            own_codes = {c for c in re.findall(r"\[(AZ\d{3})\]", message) if codes[c] == 1}
            if not own and not own_codes:
                # its words are another's too: some check still asks for them, all of them, in order, beside the
                # name of each function of the API that raises it
                shared.add(message)
                said = self.CAUGHT.get(message, message).replace("''", "'")
                parts = [p.strip() for p in re.split(r"%|\{[^{}]*\}", said) if p.strip()]
                asked = [m.span() for m in re.finditer(r"[^\n]{0,80}?".join(re.escape(p) for p in parts), text)]
                if not asked:
                    unasked.append(f"{where}: {message[:100]} (words another guard has too)")
                for fn in sorted(raisers.get(message, set())):
                    name = re.compile(re.escape(fn) + r"\b")
                    if not any(name.search(text, max(0, a - self.WINDOW), b + self.WINDOW) for a, b in asked):
                        unasked.append(f"{where}: {message[:100]} (words another guard has too: no check names {fn})")
            elif not any(r in text for r in own) and not any(re.search(c + r"\b", text) for c in own_codes):
                unasked.append(f"{where}: {message[:100]}")
        return unasked, shared, no_message

    def test_each_guard_is_asked_for_by_its_words(self) -> None:
        unasked, shared, no_message = self.sorted_out()
        self.assertEqual(unasked, [], "a guard no suite asks for by its own words: write a check that does")
        self.assertEqual(sorted(shared), sorted(self.SHARED), "guards whose words another has (Guards.SHARED)")
        self.assertEqual(no_message, self.NO_MESSAGE, "guards with no message of their own (Guards.NO_MESSAGE)")

    def test_the_rule(self) -> None:
        self.assertEqual(
            self.runs("you cannot give role % on % %: you do not hold %"),
            {"you cannot give role", ": you do not", "you do not hold"},
        )
        self.assertEqual(self.runs("no type % in the policy"), {"in the policy"})
        self.assertEqual(self.runs("bad"), set())
        raisers = self.raisers()
        self.assertTrue(
            {"authz.can", "authz.list", "authz.who", "authz.explain"} <= raisers["no permission %.% in the policy"]
        )
        # each message to the guard it is most like: 'with a user' is not 'with %'
        self.assertNotIn("authz.share", raisers["the policy does not allow sharing %.% with a user"])
        self.assertNotIn("authz.break_glass", raisers["the policy does not allow sharing %.% with %"])
        self.assertEqual(raisers["% cannot be moved inside itself"], set())  # (the trees' own, in authz_int)
        self.assertIn("doesn't own", " ".join(self.runs("role % belongs to % %, which doesn''t own % %")))


class Features(unittest.TestCase):
    """tests/features.py, the registry of features, against the code: every item of the surface (the authz.*
    functions, the command's commands and flags, the language's forms, the error codes, what the SDKs export, the
    language server's methods, the MCP tools, Studio's routes) is in one feature; every check a feature names is
    still in its suite; a feature that decides access or keeps data is held to another answer at random; each
    refusal is asked for by its words. docs/how-it-is-checked.md shows its table (--update writes it)."""

    PAGE = os.path.join(os.path.dirname(ROOT), "docs", "how-it-is-checked.md")

    def test_every_item_is_in_a_feature_and_every_check_is_there(self) -> None:
        self.assertEqual(features.problems(), [], "tests/features.py: python3 tests/features.py says what")

    def test_each_refusal_is_asked_for_by_its_words(self) -> None:
        unasked, _, _ = Guards().sorted_out()
        where = features.guard_codes()
        out = []
        for line in unasked:
            codes = sorted(where.get(line.split(": ")[0], set()))
            owners = sorted({o for c in codes for o in features.owner(f"err.{c}")}) or ["(no code)"]
            out.append(f"{', '.join(owners)}: {line}")
        out += features.unnamed_codes()
        self.assertEqual(out, [], "a refusal no check asks for by its words")
        # every RAISE is found, and carries a code but the few ErrorCodes.UNCODED lists
        self.assertEqual(len(where), len(Guards().guards()))
        self.assertEqual(sum(1 for c in where.values() if not c), 7)

    def test_the_page_shows_the_table(self) -> None:
        with open(self.PAGE, encoding="utf-8") as fh:
            page = fh.read()
        start, end = page.index(features.BEGIN), page.index(features.END) + len(features.END)
        if UPDATE:
            with open(self.PAGE, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(page[:start] + features.page_table() + page[end:])
            return
        self.assertEqual(
            page[start:end], features.page_table(), "docs/how-it-is-checked.md (python3 tests/unit_test.py --update)"
        )

    def test_a_new_item_without_a_feature_is_said(self) -> None:
        with mock.patch.dict(features.SURFACES, {"made up": lambda: {"api.made_up", "cli.apply --made-up"}}):
            found = features.problems()
        self.assertIn("made up: api.made_up is in no feature", found)
        self.assertIn("the command: cli.apply --made-up: no suite uses the flag", found)
        self.assertNotIn("made up: cli.apply --made-up is in no feature", found)  # a flag is its command's

    def test_a_check_gone_and_a_tier_one_feature_without_an_oracle_are_said(self) -> None:
        f = next(x for x in features.FEATURES if x.id == "api.verify")
        changed = dataclasses.replace(
            f, checks=(*f.checks, features.Check("tests/apply.sh", "words no suite says")), oracle=()
        )
        found = features.problems([changed if x is f else x for x in features.FEATURES])
        self.assertIn("api.verify: tests/apply.sh no longer says 'words no suite says'", found)
        self.assertIn("api.verify: tier 1, and no check holds it to another answer at random", found)
        found = features.problems([x for x in features.FEATURES if x is not f])
        self.assertIn("the authz.* API: api.verify is in no feature", found)
        gone = dataclasses.replace(f, oracle=(features.Check("tests/scenario.sql", "authz.verify()"),))
        self.assertIn(
            "api.verify: tests/scenario.sql holds it to no other answer (ORACLES)",
            features.problems([gone if x is f else x for x in features.FEATURES]),
        )

    def test_the_surface_is_read_from_the_code(self) -> None:
        found = features.surface()
        self.assertIn("api.share", found["the authz.* API"])
        self.assertIn("api.uid", found["the authz.* API"])  # callable by the app role, not generated
        self.assertIn("cli.migrate --one-phase", found["the command"])
        self.assertIn("cli.migrate --check", found["the command"])
        self.assertNotIn("cli.review --check", found["the command"])  # 'migrate --check' on review's lines
        self.assertIn("lsp.documentSymbol", found["the language server"])
        self.assertIn("studio.decide", found["Studio"])
        self.assertIn("sdk.ts.prisma.AuthzCalls", found["the TypeScript SDK"])
        self.assertIn("sdk.ts.react.usePerms", found["the TypeScript SDK"])
        self.assertIn("sdk.py.fastapi.Rowstile", found["the Python SDK"])
        self.assertIn("lang.principal", found["the language"])
        self.assertNotIn("lang.identifier", found["the language"])
        self.assertEqual(features.owner("sdk.py.fastapi.Rowstile"), ["sdk.python.stacks"])
        self.assertEqual(features.owner("sdk.py.Refused"), ["sdk.python"])
        self.assertEqual(features.owner("cli.migrate --check"), ["cli.migrate"])


class ScannerSteps(unittest.TestCase):
    """The scanner's short ways (parse.py): where a line's code ends, and where its {conditions} are, read in one
    step when no quote, $ or comment can be in play, give what reading it character by character gives."""

    ALPHABET = (
        "a",
        "b",
        " ",
        "{",
        "}",
        "'",
        '"',
        "$",
        "$x$",
        "-",
        "--",
        "E'",
        "\\",
        "x--y",
        "/*",
        "*/",
        "/",
        "*",
        "a$",
    )

    @staticmethod
    def braced_by_marks(text: str) -> list[tuple[int, int]]:
        # the long way: each character's mark
        out: list[tuple[int, int]] = []
        start = -1
        for i, m in enumerate(parse.Scanner().marks(text)):
            if m.quoted or m.comment or m.depth:
                continue
            if text[i] == "{":
                start = i
            elif text[i] == "}" and start >= 0:
                out.append((start, i + 1))
                start = -1
        return out + ([(start, -1)] if start >= 0 else [])

    def test_the_short_ways_read_as_the_long_one(self) -> None:
        rng = random.Random(283)
        for _ in range(3000):
            lines = ["".join(rng.choice(self.ALPHABET) for _ in range(rng.randint(0, 12))) for _ in range(4)]
            short, long_ = parse.Scanner(), parse.Scanner()
            for line in lines:
                self.assertEqual(short.code_end(line), parse.comment_at(line, long_.marks(line)), lines)
                self.assertEqual((short.depth, short.quote), (long_.depth, long_.quote), lines)
                self.assertEqual(parse.braced_at(line), self.braced_by_marks(line), line)
        # the lines the short ways take: no quote or $ in them
        self.assertEqual(parse.braced_at("a {b {c}} d {e} {f"), [(2, 9), (12, 15), (16, -1)])
        self.assertEqual(parse.Scanner().code_end("can view = owner  -- the owner"), 18)


class ParseAgreement(unittest.TestCase):
    """tests/parse_agreement.py, which compares the editors' grammar's reading of each policy with parse.py's (the
    editor job runs it on Tree-sitter's XML): it finds them alike when they are, and says where they differ."""

    POLICY = "app role app_user\ntype user = app.users\ntype doc = app.docs\n  owner : user = owner_id\n  can view = owner or {public}\n"
    # what `tree-sitter parse --xml` writes for it, cut to what the comparison reads ({public} is row 4, columns 22-30)
    XML = (
        '<sources><source name="{path}"><source_file>'
        '<app_role>app role<identifier field="name">app_user</identifier></app_role>'
        '<type>type<identifier field="name">user</identifier>=<table_name field="table">'
        '<identifier field="schema">app</identifier>.<identifier field="name">users</identifier></table_name></type>'
        '<type>type<identifier field="name">doc</identifier>=<table_name field="table">'
        '<identifier field="schema">app</identifier>.<identifier field="name">docs</identifier></table_name>'
        '<relation><identifier field="name">owner</identifier>:<subject><identifier field="type">user</identifier>'
        "</subject>=<column><identifier>owner_id</identifier></column></relation>"
        '<permission>can<identifier field="name">view</identifier>=<{op} field="expression"><ref><identifier>owner'
        '</identifier></ref>or<sql srow="4" scol="22" erow="4" ecol="30">{{<sql_text>public</sql_text>}}</sql></{op}>'
        "</permission></type></source_file></source></sources>"
    )

    def compare(self, op: str) -> tuple[int, int, list[str]]:
        sys.path.insert(0, os.path.join(ROOT, "tests"))
        import parse_agreement

        with tempfile.TemporaryDirectory() as d:
            policy, xml = os.path.join(d, "p.authz"), os.path.join(d, "all.xml")
            with open(policy, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(self.POLICY)
            with open(xml, "w", encoding="utf-8") as fh:
                fh.write(self.XML.format(path=policy, op=op))
            return parse_agreement.compare(xml)

    def test_alike(self) -> None:
        self.assertEqual(self.compare("or"), (1, 0, []))

    def test_a_difference_is_found_and_placed(self) -> None:
        compared, _, problems = self.compare("and")
        self.assertEqual(compared, 1)
        self.assertEqual(len(problems), 1)
        self.assertIn("/types/doc/perms/view[0]: the parser reads 'or', the grammar 'and'", problems[0])

    def test_small_policies_written_two_ways(self) -> None:
        # small.py's set (to size 3: 96 policies), a slice of it, each as listed and written another way
        import parse_agreement
        import small

        with tempfile.TemporaryDirectory() as d:
            parse_agreement.write(d, 2, 3, (1, 4))
            names = sorted(os.listdir(d))
            mine = [k for k in range(len(small.the_set(3))) if k % 4 == 1]
            self.assertEqual(len(mine), 24)
            want = ["gen_1.authz", "gen_2.authz"] + [f"small_{k}{x}.authz" for k in mine for x in ("", "_other")]
            self.assertEqual(names, sorted(want))
            changed = 0
            for k in mine:
                with open(os.path.join(d, f"small_{k}.authz"), encoding="utf-8") as fh:
                    listed = fh.read()
                with open(os.path.join(d, f"small_{k}_other.authz"), encoding="utf-8") as fh:
                    other = fh.read()
                self.assertEqual(listed, small.policy_text(small.the_set(3)[k]))
                parse_policy(other, "other.authz")  # (it reads)
                changed += listed != other
            self.assertGreater(changed, len(mine) // 2, "written another way: not the same text")

    def test_several_xmls_counted_together(self) -> None:
        # the nightly parses the whole set in chunks, an XML each: the counts and the differences are all of them
        import parse_agreement

        with tempfile.TemporaryDirectory() as d:
            policy = os.path.join(d, "p.authz")
            with open(policy, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(self.POLICY)
            xmls = []
            for op in ("or", "and"):
                xmls.append(os.path.join(d, f"{op}.xml"))
                with open(xmls[-1], "w", encoding="utf-8") as fh:
                    fh.write(self.XML.format(path=policy, op=op))
            out = io.StringIO()
            with mock.patch("sys.stdout", out):
                code = parse_agreement.main(xmls)
            self.assertEqual(code, 1)
            self.assertIn(
                "parse agreement: 2 policies read alike by the grammar and the parser, 1 differences", out.getvalue()
            )


class Respelling(unittest.TestCase):
    """genpolicy names a third of its policies' tables and columns as an app's own may be (capitals, words SQL
    reserves, 63 bytes): the same policies, the names alone changed, written bare in the policy and quoted in SQL."""

    def setUp(self) -> None:
        sys.path.insert(0, os.path.join(ROOT, "tests"))
        import genpolicy

        self.g = genpolicy

    def test_the_same_policy_renamed(self) -> None:
        for seed in range(1, 30):
            plain, awkward = self.g.make(seed, respell=False), self.g.make(seed, respell=True)
            self.assertEqual((plain.objs, plain.invariants), (awkward.objs, awkward.invariants), seed)
            self.assertNotEqual(self.g.policy_text(plain), self.g.policy_text(awkward))
            parse_policy(self.g.policy_text(awkward), "gen.authz")  # the parser takes it
            for keytype in self.g.KEYS:  # and the same policy whatever its keys' type
                self.assertEqual(self.g.make(seed, respell=False, keytype=keytype).objs, plain.objs, seed)
        drawn = [self.g.make(seed).spelling.awkward for seed in range(1, 301)]
        self.assertTrue(60 < sum(drawn) < 140, sum(drawn))  # about a third, drawn apart from the policy

    def test_the_names(self) -> None:
        self.assertEqual(len(self.g.AWKWARD["t3"].encode()), 63)  # as long as Postgres allows
        s = self.g.Spelling(awkward=True)
        self.assertEqual(s.policy_table("t1"), "Gp.select")
        self.assertEqual(s.table("t1"), '"Gp"."select"')
        self.assertEqual(s.table("t1_r1"), '"Gp"."Link_t1_r1"')
        self.assertEqual(
            s.cond("{exists (select 1 from gp.t1 x where x.id = this.id + 1 and x.b2)}"),
            '{exists (select 1 from "Gp"."select" x where x."Id" = this."Id" + 1 and x."order")}',
        )
        self.assertEqual(self.g.Spelling().cond("{not b3}"), "{not b3}")  # plain: as before
        # keys other than bigint: said on the type line, written as SQL, and the next row's key
        uuids, text = self.g.Spelling(False, "uuid"), self.g.Spelling(True, "text")
        self.assertEqual(
            (uuids.key(), text.key(), s.key(), self.g.Spelling().key()), (" (id uuid)", " (Id text)", " (Id)", "")
        )
        self.assertEqual(uuids.literal(uuids.ident(7)), "'00000000-0000-4000-8000-000000000007'")
        self.assertEqual((uuids.number(uuids.ident(7)), text.literal("7"), s.literal("7")), (7, "'7'", "7"))
        self.assertEqual(uuids.cond("{=!= (this.id + 1)}"), "{=!= (gp.nxt(this.id))}")
        self.assertEqual(text.cond("{=!= (this.id + 1)}"), '{=!= ("Gp".nxt(this."Id"))}')
        # object types keyed by (org_id, id), and what points at them, in the row's org
        orgs = self.g.Spelling(True, "bigint", composite=True)
        self.assertEqual((orgs.key(obj=True), orgs.key(), orgs.ref("c_up")), (" (OrgId, Id)", " (Id)", "[OrgId, C_up]"))

    def test_sql_quotes_every_awkward_name(self) -> None:
        spec = next(s for s in map(self.g.make, range(1, 50)) if s.spelling.awkward)
        sql = self.g.schema_text(spec)
        for name in ("Gp", "user", "select", "Id", "order", "parentId"):
            self.assertIn(f'"{name}"', sql)
        self.assertNotRegex(sql, r"(?<![\"\w])(Gp|parentId)(?![\"\w])", "a name unquoted")
        self.assertIn('"Arch""ived"', sql)  # a quote in a name, doubled
        self.assertIn('"Activé"', sql)  # a letter outside ASCII
        self.assertEqual(self.g.Spelling(awkward=True).cond("{active}"), '{"Activé"}')

    def test_text_keys_that_are_words(self) -> None:
        g = self.g
        # half the seeds with text keys draw words, drawn apart: every other seed's policy and keys as before
        drawn = [seed for seed in range(1, 401) if g.make(seed).spelling.worded]
        texts = [seed for seed in range(1, 401) if g.make(seed).spelling.keytype == "text"]
        self.assertLessEqual(set(drawn), set(texts))
        self.assertTrue(len(texts) / 4 < len(drawn) < 3 * len(texts) / 4, (len(drawn), len(texts)))
        for seed in texts:
            plain, worded = g.make(seed, words=False), g.make(seed, words=True)
            self.assertEqual((plain.objs, plain.invariants), (worded.objs, worded.invariants), seed)
            self.assertFalse(plain.spelling.worded)
            self.assertTrue(worded.spelling.worded)
        self.assertFalse(g.make(texts[0], keytype="text").spelling.worded)  # (a caller that says text: numerals)
        # row n's key: the nth word, then a word and n; and back
        w = g.Spelling(keytype="text", words=g.WORDS)
        keys = [w.ident(n) for n in range(1, 13)]
        self.assertEqual(keys, [*g.WORDS, "ab11", "\u0130z12"])
        self.assertEqual([w.number(k) for k in [*keys, "Iz500000"]], [*range(1, 13), 500000])
        self.assertEqual(w.literal("O'Neil"), "'O''Neil'")
        # what they are made of: a space, both quotes, capitals, accents, a dotted and a dotless i, a prefix
        self.assertTrue(any(" " in k for k in keys) and any("'" in k for k in keys) and any('"' in k for k in keys))
        self.assertTrue({"\u0130z", "\u0131z", "iz", "Iz", "B", "ab"} <= set(keys))
        self.assertTrue(any(a != b and b.startswith(a) for a in keys for b in keys))
        self.assertEqual(sorted(keys)[:2], ["B", "Iz"])  # (in byte order capitals first; not so in most collations)
        # as SQL: the key of row n, and n of a key, which the next row's key (gp.nxt) is made of
        self.assertIn("ARRAY['ab', '\u0130z', 'ab c', 'O''Neil', 'iz', 'say \"hi\"',", w.key_of("x"))
        self.assertIn("array_position(", w.number_of("p"))
        self.assertIn("CREATE FUNCTION gp.nxt(p text) RETURNS text", g.schema_text(g.make(drawn[0])))
        # bigint keys have none (a world made plainer): numerals again
        self.assertEqual(g.Spelling(keytype="bigint", words=g.WORDS).ident(3), "3")
        # they are in the shapes the pairs are chosen by, and never with another key type
        self.assertIn("word keys", g.features(g.make(drawn[0])))
        self.assertIn(("bigint keys", "word keys"), g.APART)
        latin1 = {c for word in g.WORDS_LATIN1 for c in word}
        self.assertTrue(all(ord(c) < 256 for c in latin1))
        self.assertEqual(len(g.WORDS_LATIN1), len(g.WORDS))


class Worlds(unittest.TestCase):
    """around.py makes what is around a random policy: the tables under its tables, decoys, a search path. It
    names what it makes as the seed's policy names its own, and reads genpolicy's SQL by those names."""

    a, g = around, genpolicy

    def world(
        self, seed: int, respell: bool, unqualified: bool = False, keytype: str = "bigint", composite: bool = False
    ) -> tuple[genpolicy.Spec, around.World]:
        """The seed's policy, its first table with one that inherits from it, the next two partitioned."""
        spec = self.g.make(seed, respell=respell, keytype=keytype, composite=composite)
        layout = dict(zip((o.name for o in spec.objs), ("inherits", "range", "hash"), strict=False))
        return spec, self.a.World(seed, layout=layout, unqualified=unqualified)

    def test_each_run_has_a_world_named_as_an_apps_own(self) -> None:
        # (main() asks genpolicy for the seed's own names and keys: its first four seeds, what every run checks)
        self.assertIn("genpolicy.make(seed), seed)", read(os.path.join(ROOT, "tests", "around.py")))
        self.assertTrue(any(self.g.make(seed).spelling.awkward for seed in range(1, 5)))

    def test_the_worlds_draw_each_key_and_each_database(self) -> None:
        """Every run's four seeds meet a key that isn't bigint, a key of two columns and a database with a locale
        of its own; the first sixteen each key type, and each of DATABASES."""

        def drawn(seeds: range) -> tuple[set[str], set[str]]:
            specs = [self.g.make(seed) for seed in seeds]
            keys = {"two columns" if x.spelling.composite else x.spelling.keytype for x in specs}
            return keys, {self.a.draw(x.seed, x).database for x in specs}

        keys, databases = drawn(range(1, 5))
        self.assertLess({"two columns"}, keys)
        self.assertGreater(len(databases), 1)
        keys, databases = drawn(range(1, 17))
        self.assertEqual(keys, {*self.g.KEYS, "two columns"})
        self.assertEqual(databases, {"", *self.a.DATABASES})
        # what a seed's world drew before the database was drawn is as it was
        w = self.a.draw(7, self.g.make(7))
        self.assertEqual(w.session, "member")
        self.assertEqual({t: w.layout[t] for t in ("t1", "t2", "t3")}, {"t1": "range", "t2": "hash", "t3": "hash"})

    def test_the_other_tables_are_laid_out_too(self) -> None:
        """The users' table, the services' and the link tables: partitioned, or with a table that inherits from
        them, where half their first rows are stored; drawn apart from the object types' layout."""
        import random

        drawn: dict[str, set[str]] = {"users": set(), "bots": set(), "links": set()}
        gone = set()
        for seed in range(1, 17):
            spec = self.g.make(seed)
            w = self.a.draw(seed, spec)
            gone.add(w.gone)
            self.assertEqual(set(w.layout), {*(o.name for o in spec.objs), *self.a.others(spec)}, seed)
            for t in self.a.others(spec):
                drawn[t if t in drawn else "links"].add(w.layout[t])
        for layouts in drawn.values():
            self.assertEqual(layouts, set(self.a.LAYOUTS))
        self.assertEqual(gone, {"", "deleted", "rekeyed"})
        for respell, composite in ((False, False), (True, False), (False, True)):
            spec = next(
                x
                for x in (self.g.make(k, respell=respell, keytype="bigint", composite=composite) for k in range(1, 40))
                if x.bot and len(self.a.link_tables(x)) > 1 and len(x.objs) > 1
            )
            n = spec.spelling
            first, second = list(self.a.link_tables(spec))[:2]
            w = self.a.World(
                spec.seed, layout={"users": "range", "bots": "inherits", first: "inherits", second: "hash"}
            )
            sql = self.a.schema_text(spec, w)
            self.assertIn(
                f") PARTITION BY RANGE ({n.sql('id')});\nCREATE TABLE {n.table('users_low')} PARTITION OF", sql
            )
            self.assertIn(f"PARTITION OF {n.table('users')} FOR VALUES FROM (5) TO (MAXVALUE);", sql)
            self.assertIn(f"CREATE TABLE {n.table('bots_old')} () INHERITS ({n.table('bots')});", sql)
            by = f"{n.sql('org_id')}, {n.sql('obj_id')}" if composite else n.sql("obj_id")
            self.assertIn(f") PARTITION BY HASH ({by});\nCREATE TABLE {n.table(f'{second}_h0')} PARTITION OF", sql)
            # a foreign key is not inherited: the table under a link table has the link table's own
            owner = self.a.link_tables(spec)[first][0]
            self.assertIn(
                f"CREATE TABLE {n.table(f'{first}_old')} () INHERITS ({n.table(first)});\n"
                f"ALTER TABLE {n.table(f'{first}_old')} ADD FOREIGN KEY ({by}) REFERENCES {n.table(owner)} "
                "ON DELETE CASCADE ON UPDATE CASCADE;",
                sql,
            )
            gen = self.g.gen_class(spec, "p.authz", "s.sql")(random.Random(3))
            rows = self.a.initial(gen, w).splitlines()
            into = [x.startswith(f"INSERT INTO {n.table(f'{first}_old')} VALUES (") for x in rows]
            beside = [x.startswith(f"INSERT INTO {n.table(first)} VALUES (") for x in rows]
            self.assertEqual((sum(into), sum(beside)), (2, 2), rows)
            self.assertIn(
                f"WITH moved AS (DELETE FROM ONLY {n.table('bots')} WHERE {n.sql('id')}::text ~ '[02468]$' "
                f"RETURNING *) INSERT INTO {n.table('bots_old')} SELECT * FROM moved;",
                rows,
            )
            self.assertFalse(any(n.table("users_old") in x for x in rows))

    def test_partitions_and_followers_by_each_key(self) -> None:
        """A table partitioned by range is cut by its key's own type, a key moved past the cut stays one genpolicy
        reads, and a link table follows both columns of a key of two."""
        cuts = {k: self.a.cut(self.g.Spelling(keytype=k)) for k in self.g.KEYS}
        self.assertEqual(cuts["bigint"], ("5", "1000000", "2000000"))
        self.assertEqual(cuts["int"], cuts["bigint"])
        self.assertEqual(cuts["text"], ("'5'", "'9999'", "'99999999'"))
        self.assertEqual(cuts["uuid"][:2], (f"'{self.g.UUID.format(5)}'", f"'{self.g.UUID.format(1000000)}'"))
        self.assertEqual(self.a.raised(self.g.Spelling(True, "text")), "'9999' || \"Id\"")
        self.assertEqual(self.a.raised(self.g.Spelling()), "id + 1000000")
        self.assertIn("right(id::text, 12)::bigint + 1000000", self.a.raised(self.g.Spelling(keytype="uuid")))
        # words: cut at row 5's, the second partition ending at a letter after every word in every collation a
        # world's database may have (in a LATIN1 one, whose locale is C, its last letter), the one made later open
        words, latin1 = (self.g.Spelling(keytype="text", words=w) for w in (self.g.WORDS, self.g.WORDS_LATIN1))
        self.assertEqual(self.a.cut(words), ("'iz'", "'\u9999'", "MAXVALUE"))
        self.assertEqual(self.a.cut(latin1), ("'iz'", "'\u00ff'", "MAXVALUE"))
        self.assertEqual(self.a.raised(words), "'\u9999' || id")
        self.assertTrue(all(w < "\u00ff" for w in self.g.WORDS_LATIN1))
        # a seed with words in a LATIN1 world has the words LATIN1 holds; elsewhere, its own
        for seed in range(1, 400):
            spec, w = self.a.world_of(seed)
            if spec.spelling.worded:
                want = self.g.WORDS_LATIN1 if w.database == "latin1" else self.g.WORDS
                self.assertEqual(spec.spelling.words, want, seed)
                self.assertIn("keys: words", self.a.features(spec, w))
                self.assertNotIn("keys: text", self.a.features(spec, w))
        self.assertEqual(
            [x.words for x in self.a.plainer_spellings(words)], [(), ()], "made plainer: numerals, then bigint keys"
        )
        for keytype in ("text", "uuid", "int"):
            spec, w = self.world(3, False, keytype=keytype)
            sql = self.a.schema_text(spec, w)
            self.assertIn(f"CREATE TABLE around_scratch.t1 (id {keytype}, b2 boolean);", sql)
            self.assertIn(f"FOR VALUES FROM (MINVALUE) TO ({cuts[keytype][0]});", sql)
        met = 0
        for seed in range(1, 13):
            spec, w = self.world(seed, True, composite=True)
            sql = self.a.schema_text(spec, w)
            self.assertNotIn('REFERENCES "Gp"."select" ', sql, seed)
            if len(spec.objs) > 2:
                self.assertIn(') PARTITION BY HASH ("OrgId", "Id");', sql, seed)
            for rel in (rel.name for rel in spec.objs[0].rels if rel.kind == "table"):
                met += 1
                self.assertIn(
                    f'UPDATE "Gp"."Link_t1_{rel}" SET ("OrgId", "Obj") = (NEW."OrgId", NEW."Id") '
                    'WHERE ("OrgId", "Obj") = (OLD."OrgId", OLD."Id"); RETURN NEW;',
                    sql,
                )
                self.assertIn('AFTER UPDATE OF "OrgId", "Id" ON "Gp"."Link_t1_old" FOR EACH ROW', sql)
        self.assertGreater(met, 3)

    def test_the_tables_under_a_table_are_named_as_the_policys(self) -> None:
        for seed in range(1, 13):
            spec, w = self.world(seed, respell=True)
            sql = self.a.schema_text(spec, w)
            self.assertIn('CREATE TABLE "Gp"."Link_t1_old" () INHERITS ("Gp"."select");', sql, seed)
            if len(spec.objs) > 1:
                self.assertIn(') PARTITION BY RANGE ("Id");', sql, seed)
                self.assertIn('CREATE TABLE "Gp"."Link_t2_low" PARTITION OF "Gp"."T2" FOR VALUES', sql, seed)
            if len(spec.objs) > 2:
                self.assertIn(') PARTITION BY HASH ("Id");', sql, seed)
            # the decoys are found under the policy's names, by a session that searches their schema first
            self.assertIn('CREATE TABLE around_scratch."select" ("Id" bigint, "order" boolean);', sql)
            self.assertIn('CREATE TABLE around_scratch."user" ("Id" bigint, "Activé" boolean);', sql)
            self.assertNotRegex(sql, r"(?<![\"\w])(Gp|gp|t1|select|Id|id)(?![\"\w(])", "a name unquoted, or plain")
            plain, w = self.world(seed, respell=False)
            sql = self.a.schema_text(plain, w)
            self.assertIn("CREATE TABLE gp.t1_old () INHERITS (gp.t1);", sql, seed)
            self.assertIn("CREATE TABLE around_scratch.t1 (id bigint, b2 boolean);", sql, seed)

    def test_a_link_table_follows_the_rows_stored_under_its_table(self) -> None:
        """A foreign key to a table doesn't see the rows of a table that inherits from it: the world makes
        triggers in its place, on both."""
        met = 0
        for seed in range(1, 13):
            for respell in (False, True):
                spec, w = self.world(seed, respell)
                n = spec.spelling
                for line in self.a.schema_text(spec, w).splitlines():
                    if line.startswith("CREATE TABLE") and "REFERENCES" in line:
                        self.assertNotIn(f"REFERENCES {n.table('t1')} ", line, seed)
                links = [rel.name for rel in spec.objs[0].rels if rel.kind == "table"]
                for rel in links:
                    met += 1
                    self.assertIn(
                        f"CREATE TRIGGER {n.sql(f't1_{rel}_obj_id_upd')} AFTER UPDATE OF {n.sql('id')} ON "
                        f"{n.table('t1_old')} FOR EACH ROW EXECUTE FUNCTION {n.table(f't1_{rel}_obj_id_follow')}();",
                        self.a.schema_text(spec, w),
                    )
        self.assertGreater(met, 6)

    def test_half_the_first_rows_are_stored_under_a_table_with_one_that_inherits(self) -> None:
        import random

        for respell in (False, True):
            spec, w = self.world(3, respell)
            n = spec.spelling
            gen = self.g.gen_class(spec, "p.authz", "s.sql")(random.Random(3))
            rows = [x for x in self.a.initial(gen, w).splitlines() if "_old" in x]
            self.assertEqual(len(rows), self.g.ROWS // 2, rows)
            for row in rows:
                self.assertRegex(row, rf"^INSERT INTO {re.escape(n.table('t1_old'))} \(.*\) VALUES \([246], ")
        # by the key's own writing: a uuid's last digits, the second column of a key of two
        for keytype, composite, even in (("uuid", False, r"'[0-9-]+[246]', "), ("bigint", True, r"[12], [246], ")):
            spec, w = self.world(3, False, keytype=keytype, composite=composite)
            gen = self.g.gen_class(spec, "p.authz", "s.sql")(random.Random(3))
            rows = [x for x in self.a.initial(gen, w).splitlines() if "_old" in x]
            self.assertEqual(len(rows), self.g.ROWS // 2, rows)
            for row in rows:
                self.assertRegex(row, rf"^INSERT INTO gp\.t1_old \(.*\) VALUES \({even}")

    def test_rows_to_try_inserts_with(self) -> None:
        """Copies of a few rows of each governed table under keys no row has, ten apart, in the row's own org
        where keys are two columns: staged where the app role reads them, and inserted all at once for the
        reference's answers."""
        import difftest

        for respell, keytype, composite in ((False, "bigint", False), (True, "uuid", False), (False, "bigint", True)):
            spec = self.a.with_write_rules(self.g.make(3, respell=respell, keytype=keytype, composite=composite), 3)
            n = spec.spelling
            pol = parse_policy(self.g.policy_text(spec), "gen.authz")
            checker = cast(
                "around.AroundChecker", types.SimpleNamespace(spec=spec, rules=pol.rules, ref=difftest.Reference(pol))
            )
            old = ["(1,2)", "(2,3)"] if composite else [n.ident(2), n.ident(3)]
            stage, insert, keys = self.a.new_rows(checker, {o.name: old for o in spec.objs})
            governed = [o.name for o in spec.objs if o.rules]
            self.assertEqual(len(keys), len(governed))
            new = ["(1,500000)", "(2,500010)"] if composite else [n.ident(500000), n.ident(500010)]
            self.assertEqual(set(map(tuple, keys.values())), {tuple(new)})
            for name in governed:
                waiting, table = f"around_new.{n.sql(name)}", self.a.qt(n.policy_table(name))
                self.assertIn(f"CREATE TABLE {waiting} AS SELECT * FROM {table} WHERE false;", stage)
                self.assertIn(f"GRANT SELECT ON {waiting} TO PUBLIC;", stage)
                self.assertIn(f"INSERT INTO {table} SELECT * FROM {waiting};", insert)
            self.assertIn(f"jsonb_build_object('{n.name('id')}', '{n.ident(500010)}')", stage)
            self.assertEqual(stage.count("jsonb_populate_record(r, "), 2 * len(governed))

    def test_signing_in_by_token(self) -> None:
        """Worlds where the app signs each user in with what they sent: an API key or a JWT, tried under the
        connection's settings, the refusal kept and the user then signed in as elsewhere."""
        import base64
        import hashlib
        import hmac
        import time

        self.assertEqual({self.a.draw(seed, self.g.make(seed)).signs for seed in range(1, 5)}, {"", "api key", "jwt"})
        # a JWT as an identity provider signs it: HS256 with the secret, who, until when, the scope, a service's type
        signed, signature = self.a.jwt("bot", "7", "read").rsplit(".", 1)

        def decoded(part: str) -> bytes:
            return base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))

        head, claims = (json.loads(decoded(x)) for x in signed.split("."))
        self.assertEqual(head, {"alg": "HS256", "typ": "JWT"})
        self.assertEqual({k: v for k, v in claims.items() if k != "exp"}, {"sub": "7", "kind": "bot", "scope": "read"})
        self.assertGreater(claims["exp"], time.time() + 3000)
        self.assertEqual(decoded(signature), hmac.new(self.a.SECRET.encode(), signed.encode(), hashlib.sha256).digest())
        self.assertLess(json.loads(decoded(self.a.jwt("user", "1", lasts=-60).split(".")[1]))["exp"], time.time())
        self.assertNotIn("kind", json.loads(decoded(self.a.jwt("user", "1").split(".")[1])))
        keys = {
            self.a.api_key(u, scope, what) for u in ("1", "2") for scope in ("", "read") for what in ("", "expired")
        }
        self.assertEqual(len(keys), 8)
        # what the owner writes: a key for whoever signs in and one for each scope, two that sign nobody in
        # (a policy that says what `read` is itself: one key for it, not two)
        spec = next(
            x for x in map(self.g.make, range(1, 80)) if x.bot and "read" in dict(x.scopes) and len(x.scopes) > 1
        )
        pol = parse_policy(self.g.policy_text(spec), "gen.authz")
        checker = cast(
            "around.AroundChecker",
            types.SimpleNamespace(
                spec=spec,
                pol=pol,
                types=pol.types,
                role="app_user",
                users=["1", "bot:2", ""],
                context=lambda u: {"mode": u},
            ),
        )
        sql = self.a.tokens_sql(checker)
        self.assertEqual(sql.count("encode(sha256("), 2 * (1 + len({"read", *pol.scopes})) + 2)
        self.assertIn(f"('2', 'bot', 'around', '{self.a.api_key('bot:2')[:10]}', ", sql)
        self.assertIn("'', now() - interval '1 hour', NULL)", sql)
        self.assertIn("'', NULL, now())", sql)
        self.assertIn("('jwt_type_claim', 'kind')", sql)
        # the app's transaction: the connection's settings first, then the token, then the request's context
        w = self.a.World(1, session="member", signs="api key", decoys=True, read_only=True)
        w.settings = [("DateStyle", "German, DMY")]
        text = self.a.transaction(w, "1", checker, ["SELECT 1;"], reads=True)
        order = ["SET LOCAL DateStyle", "SET LOCAL search_path", "SET TRANSACTION READ ONLY", "authz.login_key("]
        order += ["SET LOCAL authz_ctx.mode = '1'", "SELECT 1;", "COMMIT;"]
        self.assertEqual(sorted(order, key=text.index), order)
        self.assertIn(f"PERFORM authz.login_key('{self.a.api_key('1')}');", text)
        self.assertIn(
            "EXCEPTION WHEN invalid_authorization_specification THEN\n"
            "  PERFORM set_config('around.login', SQLERRM, true);\n  PERFORM authz.act_as('user', '1');",
            text,
        )
        self.assertIn(self.a.api_key("1", "read"), self.a.transaction(w, "1", checker, [], reads=True, scope="read"))
        nobody = self.a.transaction(w, "", checker, [], reads=False)
        self.assertNotIn("login_key", nobody)
        self.assertNotIn("READ ONLY", nobody)
        self.assertIn("PERFORM authz.act_as(NULL, NULL);", nobody)
        # the owner's session: a service's JWT, else what it sets is believed; the app role after either
        w = self.a.World(1, session="owner", signs="jwt")
        text = self.a.transaction(w, "bot:2", checker, [], reads=True)
        self.assertRegex(text, r"PERFORM authz\.login_jwt\('[\w-]+\.[\w-]+\.[\w-]+'\);")
        self.assertIn("PERFORM set_config('authz.principal_type', 'bot', true);", text)
        self.assertLess(text.index("END $$;"), text.index("SET LOCAL ROLE app_user;"))
        self.assertNotIn("login_", self.a.transaction(self.a.World(1, session="set role"), "1", checker, [], True))

    def test_every_two_features_of_the_worlds_meet_in_the_full_runs(self) -> None:
        """--pairs 1000, what the full run checks: twenty-five worlds (no fewer than twenty-four could: six kinds of
        key, words among them, four of database) in which every two FEATURES meet but two values of what a world has
        one of; every feature is one a world can have, and every world's features are FEATURES'."""
        seeds, unmet, never = self.a.covering(1000)
        self.assertLessEqual(len(seeds), 26)
        self.assertEqual((unmet, never), (set(), set()))
        for seed in seeds:  # each one's policy can be checked: compiled, and not slow to plan
            sql = Compiler(parse_policy(self.a.policy_text(*self.a.world_of(seed)), "a.authz")).compile("a.authz")
            self.assertNotIn(self.a.SLOW, sql, seed)
        met = set().union(*(self.a.pairs(self.a.features(*self.a.world_of(seed))) for seed in seeds))
        every = {(x, y) for x, y in itertools.combinations(sorted(self.a.FEATURES), 2) if not self.a.apart(x, y)}
        self.assertEqual(met, every)
        self.assertEqual(len(self.a.FEATURES), len(set(self.a.FEATURES)))
        for seed in range(1, 200):
            self.assertLessEqual(self.a.features(*self.a.world_of(seed)), set(self.a.FEATURES), seed)
        self.assertTrue(self.a.apart("keys: uuid", "keys: text"))
        self.assertFalse(self.a.apart("a governed table: hash", "a governed table: range"))
        # each setting is of a kind, and the full run is asked for the pairs
        w = self.a.World(1, settings=[*self.a.SETTINGS, *self.a.LOCALES])
        kinds = {x for x in self.a.features(self.g.make(1), w) if x.startswith("settings") or x == "repeatable read"}
        self.assertEqual(kinds, {x for x in self.a.FEATURES if x.startswith("settings") or x == "repeatable read"})
        self.assertIn("tests/around.py --pairs 1000 ", read("run_tests.sh"))

    def test_runs_side_by_side_share_no_role(self) -> None:
        """A run's login roles are named after its database, and what names one of them is made again with it:
        run_tests.sh gives each share of the seeds a lane and a database of its own."""
        try:
            self.a.name_roles("authz_around_2")
            self.assertEqual(
                (self.a.MEMBER, self.a.SETROLE, self.a.OUTSIDER),
                ("authz_around_2_member", "authz_around_2_setrole", "authz_around_2_outsider"),
            )
            named = [x for x in (*self.a.DEFAULTS, *self.a.GRANTS) if "outsider" in x]
            self.assertEqual(len(named), 4)
            self.assertTrue(all(x.endswith(" TO authz_around_2_outsider") for x in named), named)
            drawn = {self.a.draw(seed, self.g.make(seed)).open_to for seed in range(1, 40)}
            self.assertEqual(drawn, {"", "app_user", "PUBLIC", "authz_around_2_outsider"})
        finally:
            self.a.name_roles("authz_around")
        self.assertEqual(self.a.OUTSIDER, "authz_around_outsider")
        script = read("run_tests.sh")
        self.assertIn('--pairs 1000 --share "$1/3" --steps 4 --db "authz_around_$1"', script)
        self.assertIn('--policies 4 --share "$1/2" --steps 6 --seed 1 --db "authz_around_$1"', script)
        self.assertIn("seeds = seeds[share - 1 :: shares]", read("tests/around.py"))

    def test_conditions_without_the_schema(self) -> None:
        """Where the world's conditions leave the schema to the search path, they still name the seed's table."""
        for respell, table in ((False, " from t1 x"), (True, ' from "select" x')):
            texts = [
                self.a.policy_text(spec, w)
                for spec, w in (self.world(seed, respell, unqualified=True) for seed in range(1, 40))
            ]
            self.assertTrue(any(table in t for t in texts))
            self.assertTrue(any(re.search(r'[{ (]"Flag"\(', t) for t in texts))
            self.assertFalse(any('."Flag"(' in t for t in texts))
            self.assertFalse(any(" x where" in t and table not in t for t in texts))
            spec, w = self.world(1, respell, unqualified=True)
            schema = '"Gp"' if respell else "gp"
            self.assertEqual(
                self.a.path_sql(self.a.DB("d"), spec, w, open_too=True),
                f'ALTER DATABASE "d" SET search_path = {schema}, around_open, public;',
            )


class GeneratedShapes(unittest.TestCase):
    """genpolicy's policies say now and then what no other draw does (also(), across(), perm_groups(), keys other than
    bigint, composite keys, caveats, scopes, masks, custom roles, share links, rules before and after, named link
    columns, a policy in two files, and the twins of variants()), drawn apart from the rest: a seed's policy keeps
    all it drew before, the first twelve seeds draw each of them (but across()), and their twins compile (one that
    didn't would only be counted as refused)."""

    def setUp(self) -> None:
        sys.path.insert(0, os.path.join(ROOT, "tests"))
        import genpolicy

        self.g = genpolicy

    NOT_FIRST = ("not", ["{b1}"])  # what also() puts first in a permission that inherits: (r1 and not {b1}) or ...

    def test_what_a_seed_drew_stays(self) -> None:
        for seed in range(1, 80):
            with (
                mock.patch.object(self.g, "also", lambda spec, x: None),
                mock.patch.object(self.g, "across", lambda spec, x: None),
                mock.patch.object(self.g, "custom_roles", lambda spec, x: None),
                mock.patch.object(self.g, "own_links", lambda spec, x: None),
            ):
                before = self.g.make(seed)
            after = self.g.make(seed)
            self.assertEqual(
                (before.invariants, before.bot, before.user_where), (after.invariants, after.bot, after.user_where)
            )
            for b, a in zip(before.objs, after.objs, strict=True):
                self.assertEqual((a.rels[: len(b.rels)], a.rules, a.where), (b.rels, b.rules, b.where), seed)
                for p, e in b.perms.items():
                    got = a.perms[p]
                    if not isinstance(got, str) and got[1][1:] == ["roles"]:  # what a custom role gives
                        got = got[1][0]
                    elif not isinstance(got, str) and not isinstance(got[1][0], str) and got[1][0][1][-1:] == ["roles"]:
                        got = ("and", [("or", got[1][0][1][:-1]), *got[1][1:]])  # ... inside what a deny narrows
                    if not isinstance(got, str) and got[1][1:] == [f"inside.{p}"]:  # inherited back (across())
                        got = got[1][0]
                    if got != e:  # a starting point put first, the rest as it was
                        op, items = got
                        self.assertEqual((op, items[0][1][1], items[1:]), ("or", self.NOT_FIRST, e[1]), seed)

    def test_the_full_runs_seeds_draw_each_shape(self) -> None:
        drawn: set[str] = set()
        for seed in range(1, 13):
            variants = self.g.variants(seed)
            for label, spec in variants[1:]:
                drawn.add(label)
                try:
                    Compiler(parse_policy(self.g.policy_text(spec), "gen.authz")).compile("gen.authz")
                except PolicyError as e:  # only where the seed's own policy is refused too
                    with self.assertRaises(PolicyError, msg=f"seed {seed} {label}: {e}"):
                        Compiler(parse_policy(self.g.policy_text(variants[0][1]), "gen.authz"))
            for o in variants[0][1].objs:
                for rel in o.rels:
                    if rel.kind == "table" and any(x.name == rel.name and x.kind == "column" for x in o.rels):
                        own = rel.subjects == [o.name]
                        drawn.add(
                            ("own links" if own else "parent again")
                            if rel.name == "parent"
                            else "a relation to users again"
                        )
                    drawn |= {"a group by a permission" for x in rel.subjects if "#p" in x}
                for e in o.perms.values():
                    if not isinstance(e, str) and e[0] == "or" and not isinstance(e[1][0], str):
                        drawn |= {"a not first" for item in [e[1][0]] if item[1][1:] == [self.NOT_FIRST]}
            drawn.add(f"{variants[0][1].spelling.keytype} keys")
            drawn |= {"composite keys"} if variants[0][1].spelling.composite else set()
            drawn |= {"caveats"} if variants[0][1].caveats else set()
            drawn |= {"scopes"} if variants[0][1].scopes else set()
            drawn |= {"masks"} if any(o.mask for o in variants[0][1].objs) else set()
            drawn |= {f"custom roles{' from' if o.roles[1] else ''}" for o in variants[0][1].objs if o.roles}
            drawn |= {"share links"} if self.g.links(variants[0][1]) else set()
            drawn |= (
                {"update after"} if any(h == "update after" for o in variants[0][1].objs for h, _ in o.rules) else set()
            )
            drawn |= {"named link columns"} if any(r.named for o in variants[0][1].objs for r in o.rels) else set()
            drawn |= {"includes"} if variants[0][1].include else set()
        self.assertLessEqual(
            {
                "without rules",
                "without permissions",
                "parent again",
                "a relation to users again",
                "a not first",
                "a group by a permission",
            },
            drawn,
        )
        self.assertLessEqual(
            {f"{k} keys" for k in self.g.KEYS}
            | {"composite keys", "caveats", "scopes", "masks"}
            | {"custom roles", "custom roles from", "share links", "update after", "named link columns", "includes"}
            | {"own links"},
            drawn,
        )
        # a column rule said to be checked before or after the change: rarer, in the first sixty seeds
        heads = {h for seed in range(1, 61) for o in self.g.make(seed).objs for h, _ in o.rules}
        self.assertLessEqual({"update b1 before", "update b1 after"}, heads)
        # around.py's four seeds of each push have caveats too, which its sessions read from their context
        self.assertTrue(any(self.g.make(seed).caveats for seed in range(1, 5)))

    def test_a_recursion_through_two_types(self) -> None:
        """across(): about one seed in seven (the nightly soak's hundred meet it, the first twelve may not),
        nearly all compiled, each into a tree across two types, some of them stopped by a link table's where
        alone."""
        drawn = compiled = alone = 0
        for seed in range(1, 101):
            spec = self.g.make(seed)
            if not any(rel.name == "inside" for o in spec.objs for rel in o.rels):
                continue
            drawn += 1
            try:
                sql = Compiler(parse_policy(self.g.policy_text(spec), "gen.authz")).compile("gen.authz")
            except PolicyError:
                continue
            compiled += 1
            self.assertRegex(sql, r"-- t\d, t\d: each node with every ancestor it inherits from", seed)
            alone += "AS SELECT NULL::text AS t, NULL::text AS id, NULL::boolean[] AS v WHERE false;" in sql
        self.assertGreaterEqual(drawn, 10)
        self.assertGreaterEqual(compiled, drawn * 4 // 5)
        self.assertGreaterEqual(alone, 1)

    def test_the_soak_checks_policies_slow_to_plan(self) -> None:
        """A policy lint says is slow to plan is set aside on each push's seeds and in --pairs' choice (their time),
        and checked in the soak: slow is not wrong, its answers count."""
        text = read("run_tests.sh")
        soak = text[text.index('if [ "$MODE" = soak ]; then') : text.index('if [ "$MODE" != proofs ]')]
        for tool in ("genpolicy", "around"):
            lines = [line for line in text.splitlines() if f"python3 tests/{tool}.py " in line]
            self.assertTrue(lines, tool)
            for line in lines:
                self.assertEqual("--slow" in line.split(), line in soak, line)

    def test_every_two_features_meet_in_the_full_runs_policies(self) -> None:
        """--pairs 1000, what the full run checks: a few seeds the compiler takes, in which every two FEATURES meet
        (all but APART meet in some policy of the pool), each feature drawn."""
        seeds, unmet, never = self.g.covering(1000)
        self.assertLessEqual(len(seeds), 20)
        self.assertEqual((unmet, never), (set(), set()))
        for seed in seeds:  # each one's policy can be checked: not slow to plan (run() would set it aside)
            sql = Compiler(parse_policy(self.g.policy_text(self.g.make(seed)), "g.authz")).compile("g.authz")
            self.assertNotIn("view definitions to plan", sql, seed)
        met = set().union(*(self.g.pairs(self.g.make(seed)) for seed in seeds))
        self.assertEqual(met, set(itertools.combinations(sorted(self.g.FEATURES), 2)) - self.g.APART)

    def test_arounds_seeds_draw_each_shared_if(self) -> None:
        """around.py judges `shared if` by its calls of authz.share() to users: its four seeds on each push draw
        one on a relation shared with users, and the full run's (--pairs 1000) each of the conditions; some of
        those have scopes, where the world signs in by API key and where it does by JWT."""
        drawn: dict[str, set[int]] = {}
        full = around.covering(1000)[0]
        for seed in [*range(1, 5), *full]:
            for o in self.g.make(seed).objs:
                for rel in o.rels:
                    if rel.shared_if and "user" in rel.subjects:
                        drawn.setdefault(rel.shared_if, set()).add(seed)
        self.assertEqual({cond for cond, seeds in drawn.items() if seeds & set(full)}, set(self.g.SHARED_IFS))
        self.assertTrue(any(seed <= 4 for seeds in drawn.values() for seed in seeds), drawn)
        scoped = {w.signs for spec, w in map(around.world_of, full) if spec.scopes}
        self.assertLessEqual({"api key", "jwt"}, scoped)


class CheckCounts(unittest.TestCase):
    """tests/check_counts.py, which ci.sh runs on run_tests.sh's log: each suite passes as many checks as
    tests/check_counts.txt says, no fewer and no more; the random ones aren't counted."""

    LOG = (
        "=== the share API\nok    one\nok    two\n--- passed: multi scenario (1s)\n"
        "=== the scenario\n93 checks passed\n--- passed: scenario (1s)\n"
        "Ran 216 tests in 69.120s\n\nOK\n--- passed: unit (69s)\n"
        "policy errors: 132 of 133 cases\n--- FAILED: policy errors (2s)\n"
        "ok    drawn at random\n--- passed: difftest docs (14s)\n"
        "--- passed: re-apply (0s)\n"
    )

    def setUp(self) -> None:
        sys.path.insert(0, os.path.join(ROOT, "tests"))
        import check_counts

        self.c = check_counts

    def test_what_a_log_counts(self) -> None:
        self.assertEqual(
            self.c.counted(self.LOG),
            {"multi scenario": 2, "scenario": 93, "unit": 216, "policy errors": 132, "re-apply": 0},
        )

    def test_fewer_or_more_is_said(self) -> None:
        want = {"multi scenario": 3, "scenario": 93, "unit": 215, "cli": 80}  # cli: not in this log, not asked
        self.assertEqual(
            self.c.differences(self.c.counted(self.LOG), want),
            [
                "multi scenario passed 2 checks, check_counts.txt says 3",
                "policy errors passed 132 checks, check_counts.txt doesn't name it",
                "unit passed 216 checks, check_counts.txt says 215",
            ],
        )

    def test_a_count_that_isnt_fixed(self) -> None:
        got, unfixed = self.c.together([{"a": 1}, {"a": 1, "b": 2}, {"a": 3}])
        self.assertEqual(got, {"a": 1, "b": 2})
        self.assertEqual(unfixed, ["a passed 1 checks in one log and 3 in another: its count isn't fixed"])

    def test_writing_keeps_the_comments(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "counts.txt")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("# what this is\nunit 1\n")
            self.c.write(path, {"unit": 216, "scenario": 93, "re-apply": 0})
            with open(path, encoding="utf-8") as fh:
                self.assertEqual(fh.read(), "# what this is\nscenario 93\nunit 216\n")
            self.assertEqual(self.c.expected(path), {"scenario": 93, "unit": 216})

    def test_each_suite_written_is_one_run_tests_records(self) -> None:
        with open(os.path.join(ROOT, "run_tests.sh"), encoding="utf-8") as fh:
            recorded = set(re.findall(r'^\s*record \S+ "([^"$]+)"$', fh.read(), re.M))
        written = self.c.expected()
        self.assertEqual(sorted(set(written) - recorded), [])
        self.assertEqual(sorted(k for k in written if not self.c.FIXED.match(k)), [])  # random ones aren't counted
        self.assertNotIn(0, written.values())

    def test_an_upgrade_with_nothing_to_upgrade_from(self) -> None:
        # until a release from the beta on is older than this version, tests/upgrade.sh says so and checks nothing:
        # run_tests.sh records it under a name of its own, which check_counts.txt doesn't count. The upgrade it
        # records when it runs keeps its count, and one that checks nothing under that name (PyPI out of reach) falls
        # short of it
        skipped = "skip  PyPI has no release ...\nupgrade: skipped, nothing to upgrade from\n"
        log = f"{skipped}--- passed: upgrade, skipped: nothing to upgrade from (3s)\n"
        self.assertEqual(self.c.differences(self.c.counted(log), self.c.expected()), [])
        self.assertGreater(self.c.expected()["upgrade"], 0)
        self.assertEqual(
            self.c.differences(self.c.counted("upgrade: skipped\n--- passed: upgrade (3s)\n"), self.c.expected()),
            [f"upgrade passed 0 checks, check_counts.txt says {self.c.expected()['upgrade']}"],
        )
        with open(os.path.join(ROOT, "run_tests.sh"), encoding="utf-8") as fh:
            run = fh.read()
        recorded = '= "upgrade: skipped, nothing to upgrade from" ]; then\n  record $rc "upgrade, skipped: nothing to upgrade from"'
        self.assertTrue(recorded in run, "run_tests.sh records no skipped upgrade under a name of its own")
        with open(os.path.join(ROOT, "tests", "upgrade.sh"), encoding="utf-8") as fh:
            self.assertEqual(fh.read().count('echo "upgrade: skipped, nothing to upgrade from"; exit 0'), 2)


class Lanes(unittest.TestCase):
    """tests/lanes.sh, which run_tests.sh's steps run in: a part's units side by side, each step's output printed
    whole in the order written, every result taken (a unit that stops before its end, a failure); with one lane,
    each unit where it is written, as one step after the other."""

    SCRIPT = r"""
set -u
failed=() STEPS_RUN=0
step() { echo "=== $1"; STEPS_RUN=$((STEPS_RUN + 1)); }
record() {
  if [ "$1" -eq 0 ]; then echo "--- passed: $2 (0s)"; else echo "--- FAILED: $2 (0s)"; failed+=("$2"); fi
  [ -z "${LANE_OUT:-}" ] || lane_next "$1" "$2"
}
. tests/lanes.sh
# with lanes, slow waits for quick 1, which a lane beside it runs; its first result is printed before it goes on
slow() {
  step slow
  if [ "$LANES" -gt 1 ]; then
    for _ in $(seq 100); do [ -e "$MARK" ] && break; sleep 0.1; done; [ -e "$MARK" ] && echo "beside quick 1"
  fi
  echo "slow's output"; record 0 slow; sleep 1; echo after; false; record $? "slow again"
}
quick() { step "quick $1"; echo "quick $1's output"; [ "$1" != 1 ] || : > "$MARK"; record 0 "quick $1"; }
gone() { step gone; echo "gone's output"; exit 3; }
unit a 10 slow
unit a 1 quick 1
[ "$LANES" -eq 1 ] || unit a 1 gone
unit a 1 quick 2
unit b 1 quick 3
echo written
for p in a b; do run_lanes "$p"; done
echo "failed: ${failed[*]}"
[ "$STEPS_RUN" -gt 0 ] && echo "results taken"
"""

    def run_lanes(self, lanes: str) -> tuple[int, str]:
        with tempfile.TemporaryDirectory() as d:
            env = {**os.environ, "ROWSTILE_LANES": lanes, "MARK": os.path.join(d, "mark")}
            p = subprocess.run(
                ["bash", "-c", self.SCRIPT], cwd=ROOT, env=env, capture_output=True, text=True, timeout=60
            )
        return p.returncode, p.stdout + p.stderr

    def test_side_by_side(self) -> None:
        rc, out = self.run_lanes("2")
        self.assertEqual(rc, 0, out)
        self.assertEqual(
            out.splitlines(),
            [
                "written",
                # slow alone in a lane, the three short ones in the other
                "part a in 2 lanes, about 10 3 seconds each (ROWSTILE_LANES=1: one step after the other)",
                "=== slow",
                "beside quick 1",
                "slow's output",
                "--- passed: slow (0s)",
                "after",
                "--- FAILED: slow again (0s)",
                "=== quick 1",
                "quick 1's output",
                "--- passed: quick 1 (0s)",
                "=== gone",
                "gone's output",
                "--- FAILED: gone stopped before its end",
                "=== quick 2",
                "quick 2's output",
                "--- passed: quick 2 (0s)",
                "part b in 2 lanes, about 1 0 seconds each (ROWSTILE_LANES=1: one step after the other)",
                "=== quick 3",
                "quick 3's output",
                "--- passed: quick 3 (0s)",
                "failed: slow again gone (stopped)",
                "results taken",
            ],
        )

    def test_one_lane_runs_each_where_it_is_written(self) -> None:
        rc, out = self.run_lanes("1")
        self.assertEqual(rc, 0, out)
        self.assertEqual(
            out.splitlines(),
            [
                "=== slow",
                "slow's output",
                "--- passed: slow (0s)",
                "after",
                "--- FAILED: slow again (0s)",
                "=== quick 1",
                "quick 1's output",
                "--- passed: quick 1 (0s)",
                "=== quick 2",
                "quick 2's output",
                "--- passed: quick 2 (0s)",
                "=== quick 3",
                "quick 3's output",
                "--- passed: quick 3 (0s)",
                "written",
                "failed: slow again",
                "results taken",
            ],
        )

    def test_a_number_of_lanes(self) -> None:
        for lanes in ("0", "two", "-1"):
            self.assertEqual(
                self.run_lanes(lanes), (2, f"ROWSTILE_LANES is a number of lanes, 1 or more, not '{lanes}'\n")
            )

    def test_each_step_of_the_parts_is_in_a_unit(self) -> None:
        # run_tests.sh's lanes run units: a step written outside one would run alone, before the lanes start
        runner = read("run_tests.sh")
        self.assertIn(". tests/lanes.sh\n", runner)
        parts = search(
            r'^if \[ "\$MODE" != proofs \].*?^for p in \$PARTS; do run_lanes "\$p"; done$', runner, re.S | re.M
        )
        functions = dict(re.findall(r"^ *([a-z_]+)\(\) \{\n(.*?)^ *\}$", parts.group(0), re.S | re.M))
        units = re.findall(r"^ *unit \S+ \S+ ([a-z_]+)", parts.group(0), re.M)
        self.assertEqual(sorted({f for f, body in functions.items() if 'step "' in body}), sorted(set(units)))
        self.assertGreater(len(units), 20)
        outside = re.sub(r"^ *[a-z_]+\(\) \{\n.*?^ *\}$", "", parts.group(0), flags=re.S | re.M)
        self.assertNotIn('step "', outside)


def run_example_test_script(name: str, uv: int, keep: str = "") -> tuple[int, list[str], str]:
    """examples/<name>/test.sh run with docker, uv and python3 that only say what was asked of them, and a git that
    finds the generated client unchanged (a checkout's owner may not be who runs this, as on CI): its exit status,
    docker's calls (each from its folder, the app's written <app>), and what it printed."""
    app = os.path.join(os.path.dirname(ROOT), "examples", name)
    with tempfile.TemporaryDirectory() as d:
        log = os.path.join(d, "log")
        for cmd, body in (
            ("docker", f'echo "$(pwd) docker $*" >> "{log}"'),
            ("uv", f"exit {uv}"),
            ("python3", ""),
            ("git", ""),
        ):
            with open(os.path.join(d, cmd), "w", encoding="utf-8") as fh:
                fh.write(f"#!/bin/sh\n{body}\n")
            os.chmod(os.path.join(d, cmd), 0o755)
        env = {**os.environ, "PATH": d + os.pathsep + os.environ["PATH"], "KEEP": keep}
        p = subprocess.run(["bash", os.path.join(app, "test.sh")], env=env, capture_output=True, text=True, timeout=60)
        with open(log, encoding="utf-8") as fh:
            calls = [line.replace(app, "<app>") for line in fh.read().splitlines()]
    return p.returncode, calls, p.stdout + p.stderr


class MessengerTestScript(unittest.TestCase):
    """examples/messenger/test.sh takes its database down however the run ends, a step that stops it early too
    (KEEP=1 leaves it running)."""

    UP = ("<app> docker compose down -v", "<app> docker compose up -d --build --wait db")  # a new database, started

    def run_script(self, uv: int, keep: str = "") -> tuple[int, list[str], str]:
        return run_example_test_script("messenger", uv, keep)

    def test_a_run_that_stops_early_takes_the_database_down(self) -> None:
        rc, calls, out = self.run_script(uv=1)  # migrate.py fails: the script exits right after starting the database
        self.assertEqual((rc, calls), (1, [*self.UP, "<app> docker compose down"]), out)
        self.assertNotIn("README.md says", out)  # it stopped before the checks

    def test_a_run_to_its_end_takes_it_down_and_keep_leaves_it(self) -> None:
        # uv says nothing: the policy's tests ran none, which the README's number doesn't match
        rc, calls, out = self.run_script(uv=0)
        self.assertIn("README.md says another number of checks than rowstile test ran ()", out)
        self.assertEqual((rc, calls), (1, [*self.UP, "<app> docker compose down"]), out)
        self.assertEqual(self.run_script(uv=1, keep="1")[:2], (1, [*self.UP]))


class FilemanagerTestScript(unittest.TestCase):
    """examples/filemanager/test.sh takes its database and storage down however the run ends, a step that stops it
    early too (KEEP=1 leaves them running)."""

    UP = ("<app> docker compose down -v", "<app> docker compose up -d --build --wait db storage")

    def test_a_run_that_stops_early_takes_the_services_down(self) -> None:
        rc, calls, out = run_example_test_script("filemanager", uv=1)  # migrate.py fails: it exits right there
        self.assertEqual((rc, calls), (1, [*self.UP, "<app> docker compose down"]), out)

    def test_a_run_to_its_end_takes_them_down_and_keep_leaves_them(self) -> None:
        rc, calls, out = run_example_test_script("filemanager", uv=0)  # every step passes
        self.assertEqual((rc, calls), (0, [*self.UP, "<app> docker compose down"]), out)
        self.assertEqual(run_example_test_script("filemanager", uv=1, keep="1")[:2], (1, [*self.UP]))


class PreviousRelease(unittest.TestCase):
    """tests/previous_release.py, which tests/upgrade.sh starts from: the release before a version is the newest
    PyPI has that is older, in the order RELEASING.md gives (a version's alphas, its betas, its candidates, then
    it), with a build of main after each alpha, beta and candidate of the version it is on its way to."""

    def setUp(self) -> None:
        sys.path.insert(0, os.path.join(ROOT, "tests"))
        import previous_release

        self.p = previous_release

    def test_the_release_before(self) -> None:
        before = self.p.before
        alphas = ["0.1.0a2", "0.1.0a6", "0.1.0a5"]
        self.assertEqual(before("0.1.0-dev", alphas), "0.1.0a6")
        # a release's own version is not before it, nor one after it
        self.assertEqual(before("0.1.0-alpha.6", [*alphas, "0.1.0a7"]), "0.1.0a5")
        self.assertEqual(before("0.1.0-rc.1", [*alphas, "0.1.0rc1"]), "0.1.0a6")
        # numbers, not text: rc10 comes after rc2, 0.10.0 after 0.9.0
        self.assertEqual(before("0.1.0", [*alphas, "0.1.0rc2", "0.1.0rc10"]), "0.1.0rc10")
        self.assertEqual(before("0.10.0-dev", ["0.9.0", "0.2.0", "0.10.0a1"]), "0.10.0a1")
        # main after a release: the release; a patch on an older line: the release it patches
        self.assertEqual(before("0.3.0-dev", ["0.1.0", "0.2.0", "0.2.1", "0.3.0a1"]), "0.3.0a1")
        self.assertEqual(before("0.2.0-dev", ["0.1.0", "0.2.0", "0.1.1"]), "0.1.1")
        self.assertEqual(before("0.1.2", ["0.1.0", "0.1.1", "0.2.0"]), "0.1.1")
        self.assertIsNone(before("0.1.0-alpha.2", ["0.1.0a2", "0.1.0a3"]))
        # a beta comes after its version's alphas and before its candidates
        betas = [*alphas, "0.1.0b1", "0.1.0b2"]
        self.assertEqual(before("0.1.0-beta.1", betas), "0.1.0a6")
        self.assertEqual(before("0.1.0-beta.2", betas), "0.1.0b1")
        self.assertEqual(before("0.1.0-rc.1", betas), "0.1.0b2")
        self.assertEqual(before("0.1.0-dev", betas), "0.1.0b2")
        # what the command never makes is left out: a post-release, a dev build published, a stage it doesn't have
        self.assertEqual(before("0.2.0", ["0.1.0", "0.1.1c1", "0.1.1.post1", "0.1.1.dev0"]), "0.1.0")
        with self.assertRaises(ValueError):
            before("0.1.0-gamma.1", alphas)

    def test_every_release_before_and_one_by_name(self) -> None:
        # tests/upgrade.sh --every: each release older than this version, oldest first, in the same order
        released = ["0.1.0a7", "0.1.0a2", "0.1.0b1", "0.1.0a10", "0.1.0", "0.1.1.post1", "0.1.0rc1"]
        self.assertEqual(self.p.older("0.1.0-dev", released), ["0.1.0a2", "0.1.0a7", "0.1.0a10", "0.1.0b1", "0.1.0rc1"])
        self.assertEqual(self.p.older("0.1.0-alpha.2", released), [])
        self.assertEqual(self.p.older("0.2.0-dev", released)[-1], "0.1.0")
        # --from: a release by either spelling, and none that PyPI hasn't
        self.assertEqual(self.p.named("0.1.0-alpha.10", released), "0.1.0a10")
        self.assertEqual(self.p.named("0.1.0rc1", released), "0.1.0rc1")
        self.assertEqual(self.p.named("0.1.0-beta.1", released), "0.1.0b1")
        with self.assertRaises(self.p.Wrong):
            self.p.named("0.1.0-alpha.3", released)

    def test_spelled_as_the_command_writes_it(self) -> None:
        self.assertEqual(
            [self.p.spelled(v) for v in ("0.1.0a6", "0.1.0b2", "0.1.0rc1", "0.2.0")],
            ["0.1.0-alpha.6", "0.1.0-beta.2", "0.1.0-rc.1", "0.2.0"],
        )

    def test_the_wheels_an_index_lists(self) -> None:
        def f(name: str, **more: object) -> dict[str, object]:
            return {"filename": name, "url": f"https://files.example/{name}", "hashes": {"sha256": "ab" * 32}, **more}

        index = {
            "files": [
                f("rowstile-0.1.0a5-py3-none-any.whl"),
                f("rowstile-0.1.0a5.tar.gz"),
                f("rowstile-0.1.0a6-py3-none-any.whl", yanked="broken"),
                f("rowstile-0.1.0a7-py3-none-any.whl", hashes={}),
            ]
        }
        self.assertEqual(
            self.p.wheels(index),
            {"0.1.0a5": ("https://files.example/rowstile-0.1.0a5-py3-none-any.whl", "ab" * 32)},
        )
        with self.assertRaises(self.p.Wrong):
            self.p.wheels({"meta": {}})

    def run_on(self, published: list[str], *argv: str) -> tuple[int, str, list[str]]:
        """main(argv) against a made-up PyPI that has these versions' wheels, for 0.1.0-dev: its exit status, what
        it printed, and the versions it installed (nothing is downloaded)."""
        index = {
            "files": [
                {
                    "filename": f"rowstile-{v}-py3-none-any.whl",
                    "url": f"https://files.example/{v}",
                    "hashes": {"sha256": "ab" * 32},
                }
                for v in published
            ]
        }
        import contextlib

        installed: list[str] = []
        out, err = io.StringIO(), io.StringIO()
        with (
            mock.patch.object(self.p, "__version__", "0.1.0-dev"),
            mock.patch.object(self.p, "fetch", return_value=json.dumps(index).encode()),
            mock.patch.object(self.p, "install", side_effect=lambda _dir, url, _sha: installed.append(url)),
            contextlib.redirect_stdout(out),
            contextlib.redirect_stderr(err),
        ):
            rc = self.p.main(list(argv))
        return rc, out.getvalue() + err.getvalue(), installed

    def test_the_alphas_are_never_the_release_before(self) -> None:
        # the beta started afresh: a database an alpha made is applied from scratch, so PyPI's alphas are nothing
        # to upgrade from. Until 0.1.0b1 is out the suite says so and skips (exit 3), the nightly's list too
        alphas = ["0.1.0a2", "0.1.0a7", "0.1.0a9"]
        nothing = (
            "PyPI has no release of rowstile from 0.1.0-beta.1 on that is older than 0.1.0-dev: there is nothing to "
            "upgrade from (a database an alpha before 0.1.0-beta.1 made is applied from scratch, never upgraded)\n"
        )
        self.assertEqual(self.p.FIRST, "0.1.0-beta.1")
        self.assertEqual(self.run_on(alphas, "DIR"), (3, nothing, []))
        self.assertEqual(self.run_on(alphas, "--list"), (3, nothing, []))
        self.assertEqual(self.run_on([], "DIR"), (3, nothing, []))
        # once the beta is out it is the release before, and the first the nightly upgrades from
        self.assertEqual(
            self.run_on([*alphas, "0.1.0b1"], "DIR"), (0, "0.1.0-beta.1\n", ["https://files.example/0.1.0b1"])
        )
        self.assertEqual(
            self.run_on([*alphas, "0.1.0b1", "0.1.0b2"], "--list"), (0, "0.1.0-beta.1\n0.1.0-beta.2\n", [])
        )
        # an alpha asked for by name is refused, not installed
        self.assertEqual(
            self.run_on([*alphas, "0.1.0b1"], "DIR", "0.1.0-alpha.9"),
            (
                1,
                "previous_release: 0.1.0-alpha.9 is older than 0.1.0-beta.1, the first release anything upgrades from\n",
                [],
            ),
        )
        self.assertEqual(self.run_on([*alphas, "0.1.0b1"], "DIR", "0.1.0b1")[0], 0)
        # a later version's alphas are releases like any other
        self.assertTrue(all(self.p.from_first(v) for v in ("0.1.0b1", "0.1.0rc1", "0.1.0", "0.2.0a1")))
        self.assertFalse(any(self.p.from_first(v) for v in ("0.1.0a9", "0.1.0-alpha.9", "0.0.9", "nonsense")))


class DocsApps(unittest.TestCase):
    """tests/docs_app.py: upgrade.sh upgrades each release with the docs app it was released with, a copy in
    tests/docs_apps/ where it differs from core/example's, core/example's where it is the same."""

    def setUp(self) -> None:
        import docs_app

        self.d = docs_app

    def test_each_release_is_upgraded_with_its_own(self) -> None:
        d = self.d
        record, main = d.recorded(), d.digest_of(d.files())
        # from the beta on: nothing upgrades from an alpha before it, so none is recorded (none is, until the beta's
        # own commit records it)
        self.assertEqual(d.FIRST, "0.1.0-beta.1")
        first = d.key(d.FIRST)
        assert first is not None
        self.assertEqual([v for v in record if (d.key(v) or ()) < first], [])
        for version, sha in record.items():
            used = d.files(version)
            # a copy where the release's docs app differs from this checkout's, none where it is the same: when
            # core/example changes, every release that had it wants a copy (python3 tests/docs_app.py --sync)
            self.assertEqual(d.digest_of(used), sha, f"{version}: not its docs app; python3 tests/docs_app.py --sync")
            self.assertEqual(used == d.files(), sha == main, version)
        copies = os.path.join(ROOT, d.COPIES)
        for name in sorted(os.listdir(copies)):
            if os.path.isdir(os.path.join(copies, name)):
                self.assertIn(name, record, f"tests/docs_apps/{name}: a copy of no release recorded")
                self.assertNotEqual(record[name], main, f"tests/docs_apps/{name}: the same as core/example")
                self.assertEqual(sorted(os.listdir(os.path.join(copies, name))), sorted(f"{f}.txt" for f in d.FILES))

    def test_as_the_tags_have_them(self) -> None:
        # where the checkout has the tags (here, and the release run's; CI's suites' checkouts haven't): every
        # release from the first on PyPI is recorded, as its tag has its docs app, and the release this checkout is
        # (its own commit records it, before its tag is made); after that commit and before its tag, one more
        tags = self.d.tags()
        if tags is not None:
            recorded, want = list(self.d.recorded()), self.d.expected()
            self.assertEqual(recorded[: len(want)], want, "a release not recorded: python3 tests/docs_app.py --sync")
            later = recorded[len(want) :]
            newest = self.d.key(want[-1]) if want else None
            self.assertTrue(
                len(later) <= 1 and all(newest is None or (self.d.key(v) or ()) > newest for v in later), later
            )
            for version in tags:
                self.assertEqual(self.d.digest(self.d.tagged(version)), self.d.recorded()[version], version)

    def test_the_release_being_made_records_itself(self) -> None:
        # a release's commit (its version not a -dev one) records its own docs app, which no tag has yet; a -dev
        # checkout records only what is tagged
        d = self.d
        with tempfile.TemporaryDirectory() as core:
            os.makedirs(os.path.join(core, "authzlib"))
            for version, want in (("0.2.0-alpha.1", ["0.1.0", "0.2.0-alpha.1"]), ("0.2.0-dev", ["0.1.0"])):
                with open(os.path.join(core, "authzlib", "__init__.py"), "w", encoding="utf-8") as fh:
                    fh.write(f'__version__ = "{version}"\n')
                with mock.patch.object(d, "CORE", core), mock.patch.object(d, "tags", return_value=["0.1.0"]):
                    self.assertEqual(d.expected(), want, version)
                    self.assertEqual(d.releasing(), None if version.endswith("-dev") else version)
            # no tags at all (CI's checkouts): nothing to hold releases.txt to
            with mock.patch.object(d, "CORE", core), mock.patch.object(d, "tags", return_value=None):
                self.assertEqual(d.expected(), [])
            # the beta's own commit, where the only tags are the alphas before it (tags() leaves them out): it
            # records itself, the first release anything upgrades from
            with open(os.path.join(core, "authzlib", "__init__.py"), "w", encoding="utf-8") as fh:
                fh.write('__version__ = "0.1.0-beta.1"\n')
            with mock.patch.object(d, "CORE", core), mock.patch.object(d, "tags", return_value=[]):
                self.assertEqual(d.expected(), ["0.1.0-beta.1"])

    def test_the_alphas_tags_are_left_out(self) -> None:
        d = self.d
        tags = "v0.1.0-alpha.2\nv0.1.0-alpha.9\nv0.1.0-beta.2\nv0.1.0-beta.1\n"
        with mock.patch.object(d, "git", return_value=subprocess.CompletedProcess([], 0, tags.encode(), b"")):
            self.assertEqual(d.tags(), ["0.1.0-beta.1", "0.1.0-beta.2"])
        with mock.patch.object(d, "git", return_value=subprocess.CompletedProcess([], 0, b"v0.1.0-alpha.9\n", b"")):
            self.assertEqual(d.tags(), [])
        with mock.patch.object(d, "git", return_value=subprocess.CompletedProcess([], 0, b"", b"")):
            self.assertIsNone(d.tags())

    def test_a_release_whose_docs_app_differs(self) -> None:
        # the docs app changed after 1.0.0: 1.0.0 is upgraded with its copy, 1.1.0 with this checkout's
        d = self.d
        with tempfile.TemporaryDirectory() as core:
            os.makedirs(os.path.join(core, d.MAIN))
            os.makedirs(os.path.join(core, d.COPIES, "1.0.0"))
            for name in d.FILES:
                for path, text in (
                    (os.path.join(d.MAIN, name), "now"),
                    (os.path.join(d.COPIES, "1.0.0", name + ".txt"), "then"),
                ):
                    with open(os.path.join(core, path), "w", encoding="utf-8") as fh:
                        fh.write(f"{text}: {name}\n")
            with mock.patch.object(d, "CORE", core):
                self.assertEqual(d.files("1.0.0"), [os.path.join(d.COPIES, "1.0.0", f + ".txt") for f in d.FILES])
                self.assertEqual(d.files("1.1.0"), [os.path.join("example", f) for f in d.FILES])
                self.assertNotEqual(d.digest_of(d.files("1.0.0")), d.digest_of(d.files("1.1.0")))
                with open(os.path.join(core, d.files("1.0.0")[0]), encoding="utf-8") as fh:
                    self.assertEqual(fh.read(), "then: docs.authz\n")


class Delivery(unittest.TestCase):
    """What the workflows run, what the packages are built from, and what this folder's README says is tested."""

    REPO = os.path.dirname(ROOT)

    def workflows(self) -> dict[str, list[str]]:
        paths = sorted(glob.glob(os.path.join(self.REPO, ".github", "workflows", "*.yml")))
        # the checks below loop over these: if they weren't found, the loops would check nothing and pass
        found = {os.path.basename(p) for p in paths}
        self.assertLessEqual({"ci.yml", "nightly.yml", "pr.yml", "release.yml"}, found, "the workflows aren't found")
        paths.append(os.path.join(self.REPO, "review-ci", "github", "action.yml"))
        out: dict[str, list[str]] = {}
        for path in paths:
            with open(path, encoding="utf-8") as fh:
                out[os.path.relpath(path, self.REPO).replace(os.sep, "/")] = fh.read().split("\n")
        return out

    def test_the_workflow_checks_need_their_files(self) -> None:
        # a loop over files that aren't there checks nothing, and passes: workflows() refuses to be empty
        with mock.patch.object(glob, "glob", return_value=[]), self.assertRaises(AssertionError):
            self.workflows()

    def test_actions_are_pinned_by_commit(self) -> None:
        # a tag can be moved to another commit, which then runs with the job's rights (release.yml's publish)
        loose = []
        for path, lines in self.workflows().items():
            for n, line in enumerate(lines, 1):
                m = re.match(r"\s*(?:- )?uses: (\S+)", line)
                if m and not m.group(1).startswith("./") and not re.search(r"@[0-9a-f]{40}$", m.group(1)):
                    loose.append(f"{path}:{n}: {m.group(1)}")
        self.assertEqual(loose, [], "an action by tag or branch: name its commit, the tag in a comment")

    def test_images_are_pinned_by_digest(self) -> None:
        # a tag can be pushed again with other contents; Dependabot moves the digests (its docker folders).
        # core/Dockerfile has a stage per Postgres major, and builds the one PG_MAJOR names
        # walked, not asked of git: the suites' containers may not trust the mounted checkout
        listed = []
        for root, dirs, files in os.walk(self.REPO):
            dirs[:] = sorted(d for d in dirs if d not in {".git", "node_modules", ".venv", ".ci", "dist"})
            if "Dockerfile" in files:
                listed.append(os.path.relpath(os.path.join(root, "Dockerfile"), self.REPO).replace(os.sep, "/"))
        self.assertIn("packaging/docker/Dockerfile", listed)
        dependabot = read("../.github/dependabot.yml")
        folders = search(r"package-ecosystem: docker\n    directories: \[([^\]]*)\]", dependabot).group(1)
        loose = []
        for path in listed:
            with open(os.path.join(self.REPO, path), encoding="utf-8") as fh:
                text = fh.read()
            stages = re.findall(r" AS (\S+)", text)
            images = re.findall(r"(?m)^FROM (\S+)|^COPY --from=(\S+)", text)
            for image in [a or b for a, b in images]:
                # pg${PG_MAJOR}: a stage for each version the suites and the apps build
                names = [image.replace("${PG_MAJOR}", v) for v in ("16", "17", "18")] if "${" in image else [image]
                if not re.search(r"@sha256:[0-9a-f]{64}$", image) and not set(names) <= set(stages):
                    loose.append(f"{path}: {image}")
            self.assertIn(f'"/{os.path.dirname(path)}"', folders, f"{path}: Dependabot's docker folders")
        self.assertEqual(loose, [], "an image by tag alone: add its digest (tag@sha256:...)")
        self.assertIn("FROM pg${PG_MAJOR}\n", read("Dockerfile"))

    def test_uv_and_vsce_have_a_version(self) -> None:
        # setup-uv without one asks GitHub for uv's latest release on each run; npx takes the newest in a range
        for path, lines in self.workflows().items():
            for n, line in enumerate(lines):
                if re.match(r"\s*(?:- )?uses: astral-sh/setup-uv@", line):
                    self.assertRegex(lines[n + 1], r'^\s+with: \{version: "\d+\.\d+\.\d+"\}$', f"{path}:{n + 1}")
                for tool in re.findall(r"npx --yes (\S+)", line):
                    self.assertRegex(tool, r"@\d+\.\d+\.\d+$", f"{path}:{n + 1}")

    def test_workflows_read_only_unless_a_job_says(self) -> None:
        for path, lines in self.workflows().items():
            if path.startswith(".github/"):
                self.assertIn("permissions: {contents: read}", lines, path)

    def test_a_site_tag_publishes_pages_and_no_package(self) -> None:
        # site-v3 deploys the site with the blog and the comparison pages (site.yml); only a release's tag
        # reaches the registries, so no pattern release.yml runs on may match a site tag
        on_tags: dict[str, list[str]] = {}
        for path, lines in self.workflows().items():
            for line in lines:
                m = re.fullmatch(r"    tags: \[(.*)\]", line)
                if m:
                    on_tags[path] = re.findall(r'"([^"]+)"', m.group(1))
        self.assertEqual(
            on_tags,
            {".github/workflows/release.yml": ["v*"], ".github/workflows/site.yml": ["v*", "site-v*"]},
        )
        for pattern in on_tags[".github/workflows/release.yml"]:
            self.assertFalse(fnmatch.fnmatchcase("site-v3", pattern), pattern)
        # the folders a site tag publishes are the ones the release steps name
        folders = re.findall(
            r'"([^"]+)"', search(r"export const FOLDERS = \[(.*?)\];", read("../site/source.mjs")).group(1)
        )
        self.assertEqual(folders, ["docs/blog", "docs/compare"])
        releasing = read("../RELEASING.md")
        for folder in folders:
            self.assertIn(f"`{folder}/`", releasing)

    def test_the_launcher_knows_the_platforms_built(self) -> None:
        build = read("../packaging/npm/build.mjs")
        targets = dict(re.findall(r'^  "([a-z0-9-]+)": \{ triple: [^\n]*\n\s+sha256: "([0-9a-f]*)" \}', build, re.M))
        launcher = search(
            r"const PLATFORMS = \[(.*?)\];", read("../packaging/npm/rowstile/bin/rowstile.js"), re.S
        ).group(1)
        self.assertEqual(sorted(targets), sorted(re.findall(r'"([a-z0-9-]+)"', launcher)))
        # each Python is the bytes its release published
        self.assertEqual([k for k, sha in targets.items() if not re.fullmatch(r"[0-9a-f]{64}", sha)], [])
        self.assertGreaterEqual(len(targets), 7)

    def test_the_readme_lists_every_suite(self) -> None:
        def suites(text: str) -> set[str]:
            return set(re.findall(r"tests/[a-z_0-9]+\.(?:sh|py|sql)", text))

        missing = suites(read("run_tests.sh")) - {"tests/make_owner.sh"} - suites(read("README.md"))
        self.assertEqual(sorted(missing), [], "core/README.md's table: a suite run_tests.sh runs isn't in it")

    def job(self, workflow: str, name: str) -> str:
        """A job's text in a workflow."""
        text = "\n".join(self.workflows()[f".github/workflows/{workflow}"])
        return search(rf"^  {name}:\n(.*?)(?=^  [a-z-]+:\n|\Z)", text, re.S | re.M).group(1)

    def test_the_workflows_run_every_part_of_a_run(self) -> None:
        # run_tests.sh's parts run side by side, a job each: a part no job names would run nowhere
        runner = read("run_tests.sh")
        parts = {k: search(rf'^PARTS_{k}="([^"]+)"', runner, re.M).group(1).split() for k in ("SUITES", "SOAK")}
        # ... and the script's steps are in those parts, by those names
        self.assertEqual(set(re.findall(r"\bpart ([a-z0-9-]+);", runner)), {*parts["SUITES"], *parts["SOAK"]})
        for workflow, name, kind in (
            ("ci.yml", "suites", "SUITES"),
            ("nightly.yml", "suites", "SUITES"),
            ("nightly.yml", "statements", "SUITES"),
            ("nightly.yml", "soak", "SOAK"),
        ):
            with self.subTest(workflow=workflow, job=name):
                body = self.job(workflow, name)
                self.assertEqual(search(r"^        part: \[([^\]]+)\]$", body, re.M).group(1).split(", "), parts[kind])
                self.assertIn('ROWSTILE_PART: "${{ matrix.part }}"', body)
        # ci.sh hands the part to the run in the container
        self.assertIn('-e ROWSTILE_PART="${ROWSTILE_PART:-}"', read("ci.sh"))

    def test_a_command_on_one_line_is_one_yaml_value(self) -> None:
        # `run: echo "a: b"` is not a string to YAML but a mapping inside one, and the whole workflow is refused
        # when it is pushed (no job runs): a command with ": " or " #" in it goes in a block (`run: |`)
        for path, lines in self.workflows().items():
            for n, line in enumerate(lines, 1):
                m = re.match(r"\s*(?:- )?run: (?![|>])(.*)$", line)
                if m:
                    self.assertNotRegex(m.group(1), r": | #", f"{path}:{n}")

    def test_the_required_checks_fail_unless_every_part_passed(self) -> None:
        # `main` requires a check per version ("postgres (16)"): a job that waits for the version's parts. A job
        # that is skipped counts as passed, so it runs whatever became of them, and fails unless they passed
        body = self.job("ci.yml", "postgres")
        self.assertIn("    needs: suites\n", body)
        self.assertIn("    if: always()\n", body)
        self.assertIn('test "$SUITES" = success', body)
        self.assertIn('SUITES: "${{ needs.suites.result }}"', body)
        self.assertEqual(
            re.findall(r'\{pg: "(\d+)", mode: "([^"]*)"\}', body), [("16", ""), ("17", "--short"), ("18", "--short")]
        )
        self.assertEqual(
            re.findall(r'\{pg: "(\d+)", mode: "([^"]*)"\}', self.job("ci.yml", "suites")),
            [("16", ""), ("17", "--short"), ("18", "--short")],
        )

    def test_a_releases_tag(self) -> None:
        sys.path.insert(0, os.path.join(self.REPO, "packaging"))
        try:
            import version
        finally:
            sys.path.pop(0)
        tags = ["v0.1.0-rc.1", "v0.1.0", "v0.2.0-rc.1", "v0.2.0", "v0.10.0-rc.1"]
        self.assertEqual(version.dist_tag("0.2.0", tags), "latest")
        self.assertEqual(version.dist_tag("0.2.1", tags), "latest")
        self.assertEqual(version.dist_tag("0.10.0-rc.1", tags), "next")
        # an alpha is published like a candidate: never what `npm i rowstile` installs, also when it is the first
        self.assertEqual(version.dist_tag("0.1.0-alpha.1", []), "next")
        self.assertEqual(version.dist_tag("0.11.0-alpha.2", tags), "next")
        # and a beta (npm's `next`, PyPI's 0.1.0b1)
        self.assertEqual(version.dist_tag("0.1.0-beta.1", ["v0.1.0-alpha.9"]), "next")
        self.assertEqual(version.dist_tag("0.11.0-beta.3", tags), "next")
        # the one grammar (authzlib/versions.py), which the site's rule for a release's tag (site/source.mjs) agrees with
        release = search(r"^const RELEASE = /(.*)/;$", read("../site/source.mjs"), re.M).group(1)
        goods = ("0.1.0", "0.1.0-alpha.1", "0.1.0-alpha.12", "0.1.0-beta.1", "0.1.0-beta.10", "0.1.0-rc.2", "0.2.0-dev")
        for good in goods:
            self.assertTrue(version.VERSION.fullmatch(good), good)
            self.assertEqual(bool(re.fullmatch(release, "v" + good)), not good.endswith("-dev"), good)
        bads = ("0.1.0-alpha", "0.1.0-alpha1", "0.1.0a1", "0.1.0b1", "0.1.0-beta", "0.1.0-gamma.1", "0.1.0-alpha.1-dev")
        for bad in (*bads, "v0.1.0-alpha.1"):
            self.assertFalse(version.VERSION.fullmatch(bad), bad)
            self.assertFalse(re.fullmatch(release, "v" + bad), bad)
        # its helpers, also on what isn't a version or a stage
        self.assertEqual(
            [pypi(v) for v in ("0.1.0-beta.1", "0.1.0-rc.2", "0.1.0-dev", "0.1.0", "0.1.0b1")],
            ["0.1.0b1", "0.1.0rc2", "0.1.0.dev0", "0.1.0", None],
        )
        self.assertEqual(
            [spelled(v) for v in ("0.1.0a3", "0.1.0b1", "0.1.0", "0.1.0-beta.1")],
            ["0.1.0-alpha.3", "0.1.0-beta.1", "0.1.0", None],
        )
        with self.assertRaisesRegex(ValueError, r"^gamma is not a stage of a version \(alpha, beta, rc\)$"):
            stage("gamma")
        with (
            mock.patch.object(version, "places", return_value=iter([])),  # writes nothing if it goes on
            self.assertRaisesRegex(
                SystemExit, r"0\.1\.0-gamma\.1 is not X\.Y\.Z, X\.Y\.Z-alpha\.N, X\.Y\.Z-beta\.N, X"
            ),
        ):
            version.set_version("0.1.0-gamma.1")
        # a patch to an older line doesn't become what `npm i rowstile` installs
        self.assertEqual(version.dist_tag("0.1.1", [*tags, "v0.1.1"]), "release-0.1")
        self.assertEqual(version.dist_tag("0.9.3", [*tags, "v0.10.0"]), "release-0.9")
        self.assertEqual(version.dist_tag("0.1.0", []), "latest")

    def test_a_tag_leaves_nothing_unreleased(self) -> None:
        sys.path.insert(0, os.path.join(self.REPO, "packaging"))
        try:
            import changelog
        finally:
            sys.path.pop(0)
        text = "# Changelog\n\n## Unreleased\n\n### Fixed\n- one\n- two\n\n## 0.2.0 (release candidate)\n- older\n"
        self.assertEqual(changelog.unreleased(text), ["- one", "- two"])
        self.assertEqual(changelog.unreleased(text.replace("- one\n- two\n", "")), [])
        # an alpha's notes are its version's section, as a candidate's are
        alpha = text.replace("(release candidate)", "(alpha)")
        self.assertEqual(changelog.heading("0.2.0-alpha.1", alpha), "## 0.2.0 (alpha)")
        self.assertEqual(changelog.section("0.2.0-alpha.1", alpha), "- older\n")
        self.assertEqual(changelog.section("0.3.0-alpha.1", alpha), "")
        # and a beta's
        beta = text.replace("(release candidate)", "(beta)")
        self.assertEqual(changelog.heading("0.2.0-beta.1", beta), "## 0.2.0 (beta)")
        self.assertEqual(changelog.section("0.2.0-beta.2", beta), "- older\n")


class ReviewInCI(unittest.TestCase):
    """The review for CI (review-ci/), its scripts run as the action and the template have them: the action's comment
    step against a stand-in for GitHub's API, the template's script with stand-ins for rowstile and curl."""

    REPO = os.path.dirname(ROOT)
    ACTION = os.path.join(REPO, "review-ci", "github", "action.yml")
    TEMPLATE = os.path.join(REPO, "review-ci", "gitlab", "rowstile-review.gitlab-ci.yml")
    MARK = "<!-- rowstile review -->"

    def review(self, size: int) -> str:
        """A comment of about `size` characters, a table in a <details> as review.markdown writes them."""
        rows = "".join(
            f"| `doc.perm{i}` (permission) | `viewer` | `viewer or editor` | line {i} |\n" for i in range(size // 70)
        )
        return f"{self.MARK}\n### rowstile\n\n<details><summary>Meaning</summary>\n\n| | before | after | line |\n{rows}\n</details>\n"

    def comment_step(self, name: str = "comment") -> tuple[str, list[str], str]:
        """(shell, the names its env sets, run) of the action's step of that name."""
        with open(self.ACTION, encoding="utf-8") as fh:
            text = fh.read()
        step = re.split(r"\n    - ", text.split(f"\n    - name: {name}\n", 1)[1])[0]
        shell = re.search(r"^      shell: (\S+)$", step, re.M)
        env = re.search(r"^      env:\n((?:        .*\n)+)", step + "\n", re.M)
        block = re.search(r"^      run: \|\n((?:        .*\n|\n)+)", step + "\n", re.M)
        line = re.search(r"^      run: (?!\|)(.+)$", step, re.M)
        assert shell and env and (block or line), f"the {name} step's shell, env and run aren't found"
        run = "\n".join(x[8:] for x in block.group(1).split("\n")) if block else line.group(1) if line else ""
        names = re.findall(r"^        ([A-Z_]+):", env.group(1), re.M)
        return shell.group(1), names, run

    def comment(
        self, review: str, fork: bool, readonly: bool, posted: list[dict[str, str]]
    ) -> tuple[int, str, list[str]]:
        """Runs the comment step on `review` against a stand-in for GitHub's API, which refuses a read-only token's
        writes (403) and a comment over 65,536 characters (422), as GitHub does. `posted` is the pull request's
        comments, as the stand-in keeps them. (exit status, output, each request's method)."""
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

        calls: list[str] = []

        class GitHub(BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: object) -> None:
                pass

            def reply(self, code: int, body: object) -> None:
                data = json.dumps(body).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self) -> None:
                calls.append("GET")
                self.reply(200, [{"id": i + 1, "body": c["body"]} for i, c in enumerate(posted)])

            def write(self) -> None:
                calls.append(self.command)
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))["body"]
                if readonly:
                    return self.reply(403, {"message": "Resource not accessible by integration"})
                if len(body) > 65536:
                    return self.reply(422, {"message": "Validation Failed"})
                if self.command == "POST":
                    posted.append({"body": body})
                else:
                    posted[int(self.path.rsplit("/", 1)[1]) - 1] = {"body": body}
                self.reply(200, {"id": 1, "body": body})

            do_POST = write
            do_PATCH = write

        server = ThreadingHTTPServer(("127.0.0.1", 0), GitHub)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        shell, names, run = self.comment_step()
        given = {"TOKEN": "t", "PR": "7", "REPO": "owner/app", "FORK": "true" if fork else "false"}
        try:
            with tempfile.TemporaryDirectory() as tmp:
                with open(os.path.join(tmp, "rowstile-review.md"), "w", encoding="utf-8") as fh:
                    fh.write(review)
                env = {
                    **os.environ,
                    **{k: given[k] for k in names},
                    "GITHUB_API_URL": f"http://127.0.0.1:{server.server_port}",
                    "GITHUB_SERVER_URL": "https://github.com",
                    "GITHUB_RUN_ID": "42",
                    "GITHUB_ACTION_PATH": os.path.dirname(self.ACTION),
                    "RUNNER_TEMP": tmp,
                }
                # as the runner runs a step: python {0}, or bash --noprofile --norc -eo pipefail {0}
                cmd = (
                    [sys.executable, "-c", run]
                    if shell == "python"
                    else ["bash", "--noprofile", "--norc", "-eo", "pipefail", "-c", run]
                )
                p = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=60)
        finally:
            server.shutdown()
            server.server_close()
        return p.returncode, p.stdout + p.stderr, calls

    def test_the_action_reviews_once_for_the_comment_and_the_annotations(self) -> None:
        # a stand-in for the command: it says how it was run, and writes as rowstile review does
        shell, names, run = self.comment_step("review")
        with tempfile.TemporaryDirectory() as tmp:
            os.mkdir(os.path.join(tmp, "bin"))
            fake = os.path.join(tmp, "bin", "rowstile")
            with open(fake, "w", encoding="utf-8") as fh:
                fh.write(
                    "#!/usr/bin/env python3\nimport os, sys\nargs = sys.argv[1:]\n"
                    "with open(os.environ['RUNS'], 'a') as fh: fh.write(' '.join(args) + '\\n')\n"
                    "if '--out' in args: open(args[args.index('--out') + 1], 'w').write('<!-- rowstile review -->\\n')\n"
                    "print('<!-- rowstile review -->' if '--markdown' in args else '::warning file=db/policy.authz')\n"
                )
            os.chmod(fake, 0o755)
            given = {"BASE": "abc123", "DATABASE": ""}
            env = {
                **os.environ,
                **{k: given[k] for k in names},
                "PATH": os.path.join(tmp, "bin") + os.pathsep + os.environ["PATH"],
                "RUNS": os.path.join(tmp, "runs"),
                "RUNNER_TEMP": tmp,
                "GITHUB_STEP_SUMMARY": os.path.join(tmp, "summary"),
            }
            self.assertEqual(shell, "bash")
            cmd = ["bash", "--noprofile", "--norc", "-eo", "pipefail", "-c", run]
            p = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=60, cwd=tmp)
            self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
            with open(env["RUNS"], encoding="utf-8") as fh:
                runs = fh.read().splitlines()
            with open(env["GITHUB_STEP_SUMMARY"], encoding="utf-8") as fh:
                summary = fh.read()
            with open(os.path.join(tmp, "rowstile-review.md"), encoding="utf-8") as fh:
                comment = fh.read()
        self.assertEqual(runs, [f"review --base abc123 --annotations --out {tmp}/rowstile-review.md"])
        self.assertIn("::warning file=db/policy.authz", p.stdout)  # in the log, where GitHub reads them
        self.assertEqual((comment, summary), ("<!-- rowstile review -->\n",) * 2)

    def test_the_comment_is_posted_then_updated_in_place(self) -> None:
        posted: list[dict[str, str]] = [{"body": "a person's comment"}]
        status, out, calls = self.comment(self.review(1000), fork=False, readonly=False, posted=posted)
        self.assertEqual((status, calls), (0, ["GET", "POST"]), out)
        status, out, calls = self.comment(self.review(1000) + "again\n", fork=False, readonly=False, posted=posted)
        self.assertEqual((status, calls), (0, ["GET", "PATCH"]), out)
        self.assertEqual([c["body"] for c in posted], ["a person's comment", self.review(1000) + "again\n"])

    def test_a_pull_request_from_a_fork_gets_the_summary_and_passes(self) -> None:
        # GitHub gives a fork's pull request a read-only token, whatever the workflow's permissions ask for
        status, out, calls = self.comment(self.review(1000), fork=True, readonly=True, posted=[])
        self.assertEqual(status, 0, out)
        self.assertIn(
            "::notice title=rowstile review::This pull request comes from a fork, and GitHub gives its workflow a "
            "read-only token: the review is in the run's summary, not in a comment.",
            out,
        )
        self.assertEqual(calls, ["GET", "POST"])
        # elsewhere a refusal is the workflow's permissions: the step fails, and says what to give it
        status, out, _ = self.comment(self.review(1000), fork=False, readonly=True, posted=[])
        self.assertEqual(status, 1, out)
        self.assertIn(
            "::error title=rowstile review::GitHub refused the comment (HTTP 403: Resource not accessible by "
            "integration). The job needs permissions: {pull-requests: write} to post it (or comment: false).",
            out,
        )

    def test_a_review_longer_than_a_comment_is_cut_and_says_where_the_rest_is(self) -> None:
        posted: list[dict[str, str]] = []
        review = self.review(200_000)
        status, out, _ = self.comment(review, fork=False, readonly=False, posted=posted)
        self.assertEqual(status, 0, out)
        body = posted[0]["body"]
        self.assertLessEqual(len(body), 65536)
        self.assertTrue(review.startswith(body.split("\n\n</details>\n\n**The review")[0]), body[-300:])
        self.assertTrue(
            body.endswith(
                "\n\n</details>\n\n**The review is longer than a comment may be. The rest is in [the run's summary]"
                "(https://github.com/owner/app/actions/runs/42).**\n"
            ),
            body[-300:],
        )
        # one that fits is posted whole
        posted.clear()
        self.assertEqual(self.comment(self.review(50_000), fork=False, readonly=False, posted=posted)[0], 0)
        self.assertEqual(posted, [{"body": self.review(50_000)}])

    def gitlab(self, review: str, notes: list[dict[str, object]]) -> tuple[int, str, list[dict[str, object]]]:
        """Runs the template's script as GitLab runs it (bash, -eo pipefail), with a rowstile that writes `review`
        and a curl that answers the notes `notes` and keeps what it was asked. (status, output, each call)."""
        with open(self.TEMPLATE, encoding="utf-8") as fh:
            lines = fh.read().split("\n")
        items: list[str] = []
        for line in lines[lines.index("  script:") + 1 :]:
            if line.startswith("    - "):
                items.append(line[6:])
            elif line.startswith("      ") or not line.strip():
                items[-1] += "\n" + line[6:]
            else:
                break
        script = "\n".join(x[2:] if x.startswith("|\n") else x for x in items)
        with tempfile.TemporaryDirectory() as tmp:
            stubs = os.path.join(tmp, "bin")
            os.mkdir(stubs)
            with open(os.path.join(tmp, "given.md"), "w", encoding="utf-8") as fh:
                fh.write(review)
            with open(os.path.join(tmp, "notes.json"), "w", encoding="utf-8") as fh:
                json.dump(notes, fh)
            with open(os.path.join(stubs, "rowstile"), "w", encoding="utf-8") as fh:
                fh.write(f"#!/bin/sh\ncat {tmp}/given.md\n")
            with open(os.path.join(stubs, "curl"), "w", encoding="utf-8") as fh:
                fh.write(
                    f"#!{sys.executable}\nimport json, sys\nargs = sys.argv[1:]\n"
                    "data = None\n"
                    "for flag in ('-d', '--data', '--data-binary'):\n"
                    "    if flag in args:\n"
                    "        data = args[args.index(flag) + 1]\n"
                    "        if data.startswith('@'):\n"
                    "            data = open(data[1:], encoding='utf-8').read()\n"
                    f"with open({tmp + '/calls'!r}, 'a', encoding='utf-8') as fh:\n"
                    "    fh.write(json.dumps({'args': [a for a in args if len(a) < 4096], 'long': max(map(len, args)), "
                    "'data': data and json.loads(data)}) + '\\n')\n"
                    f"if '-X' not in args:\n    print(open({tmp + '/notes.json'!r}).read())\n"
                )
            for name in ("rowstile", "curl"):
                os.chmod(os.path.join(stubs, name), 0o755)
            env = {
                **os.environ,
                "PATH": stubs + os.pathsep + os.environ["PATH"],
                "ROWSTILE_REVIEW_TOKEN": "t",
                "CI_API_V4_URL": "https://gitlab.example/api/v4",
                "CI_PROJECT_ID": "3",
                "CI_MERGE_REQUEST_IID": "5",
                "CI_MERGE_REQUEST_DIFF_BASE_SHA": "abc",
                "CI_JOB_URL": "https://gitlab.example/team/app/-/jobs/9",
            }
            work = os.path.join(tmp, "work")
            os.mkdir(work)
            p = subprocess.run(
                ["bash", "-eo", "pipefail", "-c", script], cwd=work, env=env, capture_output=True, text=True, timeout=60
            )
            calls: list[dict[str, object]] = []
            if os.path.exists(os.path.join(tmp, "calls")):
                with open(os.path.join(tmp, "calls"), encoding="utf-8") as fh:
                    calls = [json.loads(x) for x in fh.read().splitlines()]
        return p.returncode, p.stdout[-2000:] + p.stderr, calls

    def test_gitlab_posts_a_long_review_from_a_file_then_updates_it(self) -> None:
        # one argument holds 128 KiB at most on Linux: the note goes in a file
        review = self.review(200_000)
        status, out, calls = self.gitlab(review, [{"id": 8, "body": "a person's note"}])
        self.assertEqual(status, 0, out)
        self.assertEqual(len(calls), 2, calls)
        self.assertIn("POST", cast(list[str], calls[1]["args"]))
        self.assertIn("--data-binary", cast(list[str], calls[1]["args"]))
        self.assertLess(cast(int, calls[1]["long"]), 4096)
        self.assertEqual(calls[1]["data"], {"body": review})
        # the note posted before is updated in place
        status, out, calls = self.gitlab(review, [{"id": 8, "body": "a person's note"}, {"id": 9, "body": review}])
        self.assertEqual(status, 0, out)
        self.assertIn("PUT", cast(list[str], calls[1]["args"]))
        self.assertTrue(cast(list[str], calls[1]["args"])[-1].endswith("/merge_requests/5/notes/9"))

    def test_gitlab_cuts_a_review_longer_than_a_note(self) -> None:
        review = self.review(1_100_000)
        status, out, calls = self.gitlab(review, [])
        self.assertEqual(status, 0, out)
        body = cast(dict[str, str], calls[1]["data"])["body"]
        self.assertLessEqual(len(body), 1_000_000)
        self.assertTrue(review.startswith(body.split("\n\n</details>\n\n**The review")[0]), body[-300:])
        self.assertTrue(
            body.endswith(
                "\n\n</details>\n\n**The review is longer than a note may be. The rest is in [review.md]"
                "(https://gitlab.example/team/app/-/jobs/9/artifacts/file/review.md).**\n"
            ),
            body[-300:],
        )

    def test_gitlabs_header_sets_the_jobs_variables_in_the_job(self) -> None:
        # a job's own variables come before the pipeline's: a top-level ROWSTILE_VERSION would be ignored
        with open(self.TEMPLATE, encoding="utf-8") as fh:
            text = fh.read()
        header = [x[2:] for x in text.split("\nrowstile-review:\n")[0].split("\n") if x.startswith("#  ")]
        job = re.search(r"^  variables:\n((?:    .*\n)+)", text, re.M)
        assert job
        own = set(re.findall(r"^    ([A-Z_]+):", job.group(1), re.M))
        self.assertLessEqual({"ROWSTILE_VERSION", "ROWSTILE_PACKAGE"}, own)
        top = header[header.index("  variables:") + 1 :] if "  variables:" in header else []
        top = list(itertools.takewhile(lambda x: x.startswith("    "), top))
        self.assertEqual([x for x in top if x.split(":")[0].strip() in own], [], "set at the top level, ignored")
        # nor a token in the file: GitLab masks only a variable of the CI/CD settings
        self.assertNotIn("ROWSTILE_REVIEW_TOKEN:", "\n".join(header))
        # and how to set them: in the job, by its name, as its stage
        shown = "\n".join(header)
        self.assertIn("  rowstile-review:\n    stage: verify\n    variables:\n      ROWSTILE_VERSION: X.Y.Z", shown)


class Mutants(unittest.TestCase):
    """The mutation sweep's parts that need no database (core/mutants): the mutants and their ids, the shards,
    what carries over between runs, the survivors file, the report, and the workflow that runs it."""

    REPO = os.path.dirname(ROOT)
    # a docstring, a message and an SQL comment with SQL words in them, an f-string field with Python in it
    SAMPLE = (
        '"""Rows for a view: WHERE a = b AND c IS NULL, says the docstring."""\n\n\n'
        "def fail(msg: str) -> None:\n"
        "    raise ValueError(msg)\n\n\n"
        "def view_sql(t: str, x: int) -> str:\n"
        "    if x == 1:\n"
        '        fail("WHERE a = b AND c")\n'
        '    return f"SELECT 1 FROM {t} WHERE a = {x == 2} AND b IS NULL -- c = d AND e"\n'
    )

    def made(self, text: str, name: str = "view.py") -> list[mutants.Mutant]:
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "authzlib"))
            with open(os.path.join(d, "authzlib", name), "w", encoding="utf-8") as fh:
                fh.write(text)
            return mutants.generate(d)

    def test_a_clients_comments_are_not_sql(self) -> None:
        # the clients' TypeScript names SQL words in its // comments: no WHERE there to drop a term of (the line
        # after it would go), while the SQL it sends is mutated as any
        text = (
            "def client(t: str) -> str:\n"
            '    return f"""  // nothing for another reason, such as a WHERE with more than the key\n'
            "  if (why === null) throw new NotFound({t});\n"
            '  db.query("SELECT 1 FROM x WHERE a = 1 AND b = 2");\n"""\n'
        )
        dropped = [m.old for m in self.made(text, "devtools.py") if m.op == "sql WHERE term dropped"]
        self.assertEqual(len(dropped), 2, dropped)
        self.assertTrue(all("NotFound" not in old for old in dropped), dropped)

    def test_an_id_is_the_one_results_were_kept_by(self) -> None:
        # results carry over between runs by id, and survivors.txt names them: made another way, every one is lost
        ids = {m.id: m.op for m in self.made(self.SAMPLE)}
        self.assertEqual(ids.get("g8e0a29e4cd"), "sql AND->OR")
        self.assertEqual(ids.get("gb5cd43d52d"), "py ==->!=")
        self.assertEqual(len(ids), 10)

    def test_an_id_stays_while_its_line_does(self) -> None:
        before = {m.id: m.line for m in self.made(self.SAMPLE)}
        edited = "import os\n\n" + self.SAMPLE.replace("if x == 1:", "if x == 3:")
        after = {m.id: m.line for m in self.made(edited)}
        self.assertEqual({i for i, ln in before.items() if ln == 11}, {i for i, ln in after.items() if ln == 13})
        self.assertEqual({i for i, ln in before.items() if ln == 9} & set(after), set())  # the line changed
        self.assertEqual(len(after), len(before))

    def test_sql_mistakes_leave_fields_messages_and_comments(self) -> None:
        made = self.made(self.SAMPLE)
        sql = [m for m in made if m.op.startswith("sql ")]
        self.assertEqual(
            sorted(m.op for m in sql),
            [
                "sql =-><>",
                "sql AND->OR",
                "sql IS NULL->IS NOT NULL",
                "sql WHERE term dropped",
                "sql WHERE term dropped",
            ],
        )
        self.assertEqual({m.line for m in sql}, {11})
        for m in made:
            text = self.SAMPLE.replace(m.old, m.new, 1)
            for kept in (
                '"""Rows for a view: WHERE a = b AND c IS NULL',
                'fail("WHERE a = b AND c")',
                "-- c = d AND e",
            ):
                self.assertIn(kept, text, m.what)
            if m.op.startswith("sql ") and m.op != "sql WHERE term dropped":  # a term goes whole, its field too
                self.assertIn("{x == 2}", text, m.what)  # the field is Python: only Python's operators touch it
        self.assertIn("py ==->!=", {m.op for m in made if m.line == 11})

    def test_shards_get_the_longest_first(self) -> None:
        self.assertEqual(sweep.deal({"a": 100, "b": 60, "c": 50, "d": 10}, 2), {"a": 1, "b": 2, "c": 2, "d": 1})
        dealt = sweep.deal({f"m{i}": float(i % 7) for i in range(50)}, 8)
        self.assertEqual(sorted(dealt), sorted(f"m{i}" for i in range(50)))
        load = [sum(i % 7 for i in range(50) if dealt[f"m{i}"] == s) for s in range(1, 9)]
        self.assertLessEqual(max(load) - min(load), 6)
        self.assertEqual(sweep.deal({}, 3), {})

    def test_a_spread_takes_every_kind_first(self) -> None:
        made = self.made(self.SAMPLE)
        order = mutants.spread(made, 1)
        self.assertEqual(sorted(m.id for m in order), sorted(m.id for m in made))
        self.assertEqual([m.id for m in order], [m.id for m in mutants.spread(made, 1)])
        groups = {(m.op, m.file) for m in made}
        self.assertEqual(len({(m.op, m.file) for m in order[: len(groups)]}), len(groups))

    def test_what_carries_over(self) -> None:
        rows = [
            {"id": "ga", "result": "scenario"},
            {"id": "gb", "result": "MISSED"},
            {"id": "gc", "result": "MISSED"},
            {"id": "gd", "result": "not run"},
            {"id": "ge", "result": "scenario"},
        ]
        with tempfile.TemporaryDirectory() as d:
            sweep.write_jsonl(os.path.join(d, "results.jsonl"), rows)
            got = sweep.carried_over(d, {"ga", "gb", "gc", "gd"}, {"gc": ("equivalent", "why"), "gb": ("lead", "")})
        # a lead runs again (its check may be written by now); ge's line changed
        self.assertEqual([r["id"] for r in got], ["ga", "gc"])

    def test_the_survivors_file(self) -> None:
        listed = sweep.read_survivors(sweep.SURVIVORS)
        self.assertTrue(listed)
        with open(sweep.SURVIVORS, encoding="utf-8") as fh:
            for line in fh:
                m = sweep.SURVIVOR.fullmatch(line.rstrip("\n"))
                if m:
                    with open(os.path.join(ROOT, "authzlib", m.group(3)), encoding="utf-8") as src:
                        names = {name for _, _, name in mutants.Source(m.group(3), src.read()).defs}
                    self.assertIn(m.group(4), names | {"<module>"}, line)
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "survivors.txt")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("# fine\ng0123456789 maybe output.py f: why\n")
            with self.assertRaisesRegex(ValueError, "survivors.txt:2: not"):
                sweep.read_survivors(path)

    def test_a_new_survivor_fails_the_run(self) -> None:
        def row(i: str, result: str) -> sweep.Record:
            return {"id": i, "what": f"x.py:1 f: op: {i}", "result": result, "kind": "sql", "seconds": 60}

        rows = [row("ga", "scenario"), row("gb", "MISSED"), row("gc", "MISSED"), row("gd", "MISSED")]
        survivors = {"gb": ("lead", "a check"), "gd": ("equivalent", "why")}
        queue = {"commit": "abc1234", "calls": "none", "mutants": [{"id": r["id"]} for r in rows]}
        text, new = sweep.report(queue, rows, {str(r["id"]): r for r in rows}, survivors, [], 100, 4, 8)
        self.assertEqual(new, ["gc"])
        self.assertIn("**Score: 1 of 3 caught", text)
        self.assertIn("| `gc` | **new** |", text)

    def test_lines_run_on_import_are_not_judged_by_the_outputs(self) -> None:
        # a module's constant runs on any import: an output unchanged says nothing of the command that reads it
        # later (REMOVE_SQL), so its mutants go to the suites that ran its line; a function's are `same`
        text = "REMOVE = 'DROP x WHERE a AND b'\n\n\ndef view(t: str) -> str:\n    return f'SELECT 1 WHERE {t} AND b'\n"
        made = {m.func: m for m in self.made(text) if m.op == "sql AND->OR"}
        group = sweep_plan.Group("spec.json", {"migration 0 (x)": "SQL"}, {"view.py": {1, 5}})
        base = sweep_plan.Base(self.REPO, sweep_plan.Group("", {}, {}), [group])
        calls = sweep_plan.Calls({}, {"authzlib/view.py": {"cli": [[1, 1]], "apply": [[5, 5]]}}, "test")
        planner = sweep_plan.Planner(base, calls)
        with mock.patch.object(sweep_plan, "compile_outputs", return_value={"migration 0 (x)": "SQL"}):
            on_import = planner.classify(made["<module>"], text, "core")
            in_function = planner.classify(made["view"], text, "core")
        self.assertEqual((on_import.kind, on_import.selected), ("python", ["cli"]))
        self.assertEqual((in_function.kind, in_function.selected), ("same", ["apply"]))

    def test_the_suites_and_steps_are_there(self) -> None:
        names = [s for s, _ in sweep_plan.SUITES]
        self.assertEqual(len(names), len(set(names)))
        for name, cmd in sweep_plan.SUITES:
            for path in re.findall(r"\btests/[\w.]+\.(?:py|sh|sql)|\bexample/[\w.]+", cmd):
                self.assertTrue(os.path.isfile(os.path.join(ROOT, path)), f"{name}: {path}")
        for label, path, _ in sweep_plan.POLICIES:
            self.assertTrue(os.path.isfile(os.path.join(self.REPO, path)), label)
        chosen = [s for _, ss in sweep_plan.STEP_SUITES for s in ss]
        chosen += [s for ss in [*sweep_plan.POLICY_SUITES.values(), *sweep_plan.POLICY_APPLIED.values()] for s in ss]
        self.assertEqual(sorted(set(chosen) - set(names)), [])
        # a step renamed in run_tests.sh would select nothing: its calls would count for no suite
        steps = re.findall(r'^\s*step "([^"]+)"', read("run_tests.sh"), re.M)
        for prefix, _ in sweep_plan.STEP_SUITES:
            self.assertTrue(any(s.startswith(prefix) for s in steps), prefix)
        # and a new step stands for a suite of the sweep, or says why not: else its calls choose no suite
        for step in steps:
            step = re.sub(r"\$(?:1|gen)\b", "docs", step)
            self.assertTrue(sweep_plan.suites_of_step(step) or step.startswith(sweep_plan.NOT_SWEPT), step)
        with open(sweep.SEED_STATS, encoding="utf-8") as fh:
            self.assertEqual(sorted(json.load(fh)["suites"]), sorted(names))

    def test_call_data_names_only_suites_of_the_sweep(self) -> None:
        # a step the data's run had and no suite stands for: it chose a name the stats don't have, and the
        # sweep's first job stopped on it
        data = {
            "source": "a run",
            "functions": {"authz.can": ["scenario", "(upgrading)"]},
            "lines": {"authzlib/output.py": {"scenario": [[1, 3]], "(upgrading)": [[2, 2]]}},
        }
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "calls.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(data, fh)
            calls = sweep_plan.Calls.load(path)
        self.assertEqual(calls.functions, {"authz.can": {"scenario"}})
        self.assertEqual(calls.ran("authzlib/output.py", 2), {"scenario"})

    def test_the_workflow(self) -> None:
        text = read("../.github/workflows/mutants.yml")
        on = search(r"^on:\n(.*?)^\S", text, re.S | re.M).group(1)
        self.assertEqual(re.findall(r"^  (\w+):", on, re.M), ["schedule", "workflow_dispatch"])  # never on a push
        sweep = search(r"^  sweep:\n(.*?)(?=^  [a-z-]+:\n)", text, re.S | re.M).group(1)
        self.assertIn("      max-parallel: 8\n", sweep)  # pull requests keep runners
        self.assertIn("      fail-fast: false\n", sweep)
        timeout = int(search(r"timeout-minutes: (\d+)", sweep).group(1))
        budget = int(search(r"--budget (\d+)", sweep).group(1))
        self.assertLess(timeout, 360)  # GitHub's runners stop a job at six hours
        self.assertLessEqual(budget + 60, timeout)  # the mutant in flight when the budget is used up still ends
        self.assertEqual(set(re.findall(r"sweep\.py (\w+)", text)), {"calls", "prepare", "run", "collect"})
        # the next run resumes from what collect keeps: every run's results, but a run of some mutants only that
        # didn't carry the latest ones (it holds only its own) keeps them under another name
        self.assertIn("-n mutants-results ", text)
        name = search(r"^          name: (.*mutants-results.*)$", text, re.M).group(1)
        self.assertEqual(
            name,
            "${{ (inputs.only || inputs.since || inputs.limit) && (inputs.resume || 'latest') != 'latest'"
            " && 'mutants-results-partial' || 'mutants-results' }}",
        )


class Editors(unittest.TestCase):
    """Zed reads its queries from the extension's folder: they are the grammar's (editor/tree-sitter-authz),
    copied. The grammar itself is tested by editor/test.sh (it needs the Tree-sitter CLI). The VS Code extension
    asks for a VS Code its language client runs on, and the paths the editors' page gives exist."""

    REPO = os.path.dirname(ROOT)

    def test_vscode_engine_is_what_the_client_needs(self) -> None:
        # The Marketplace offers the extension to every VS Code engines.vscode allows: no locked dependency may ask
        # for a newer one. @types/vscode is the engine's version (vsce refuses types newer than the engine)
        def least(spec: str) -> tuple[int, int, int]:
            m = search(r"^[\^~]?(\d+)\.(\d+)\.(\d+)$", spec)
            return int(m.group(1)), int(m.group(2)), int(m.group(3))

        with open(os.path.join(self.REPO, "editor", "package.json"), encoding="utf-8") as fh:
            package = json.load(fh)
        with open(os.path.join(self.REPO, "editor", "package-lock.json"), encoding="utf-8") as fh:
            lock = json.load(fh)
        engine = least(package["engines"]["vscode"])
        newer = {
            name: entry["engines"]["vscode"]
            for name, entry in lock["packages"].items()
            if name
            and isinstance(entry.get("engines"), dict)
            and "vscode" in entry["engines"]
            and least(entry["engines"]["vscode"]) > engine
        }
        self.assertEqual(newer, {}, f"editor/package.json: engines.vscode {package['engines']['vscode']} is older")
        self.assertEqual(least(package["devDependencies"]["@types/vscode"])[:2], engine[:2], "@types/vscode")

    def test_the_paths_the_editors_page_gives_exist(self) -> None:
        # paths in a checkout: `core/cli/lsp.py` (from the repository's root or editor/), and /path/to/rowstile/...
        # in the examples and in the setting's description, which VS Code shows
        missing: list[str] = []
        for rel in ("editor/README.md", "editor/package.json"):
            with open(os.path.join(self.REPO, rel), encoding="utf-8") as fh:
                text = fh.read()
            paths = re.findall(r"/path/to/rowstile/([\w./-]+)", text)
            paths += re.findall(r"`([\w-]+(?:/[\w.-]+)+\.(?:py|js|json|md|scm))`", text)
            for path in paths:
                if not any(os.path.exists(os.path.join(self.REPO, base, path)) for base in ("", "editor")):
                    missing.append(f"{rel}: {path}")
        self.assertEqual(missing, [])

    def test_zed_has_the_grammars_queries(self) -> None:
        grammar = os.path.join(self.REPO, "editor", "tree-sitter-authz", "queries")
        zed = os.path.join(self.REPO, "editor", "zed", "languages", "authz")
        names = sorted(f for f in os.listdir(grammar) if f.endswith(".scm"))
        self.assertEqual(names, sorted(f for f in os.listdir(zed) if f.endswith(".scm")))
        for name in names:
            with (
                open(os.path.join(grammar, name), encoding="utf-8") as a,
                open(os.path.join(zed, name), encoding="utf-8") as b,
            ):
                self.assertEqual(
                    a.read(), b.read(), f"editor/zed/languages/authz/{name}: copy it from the grammar's queries"
                )

    def test_the_textmate_grammar_reads_a_test_lines_scopes_whole(self) -> None:
        # a scope's name may go on with - and : (files:write, read-only), in a test's `with scope` as where it is
        # declared
        with open(os.path.join(self.REPO, "editor", "syntaxes", "authz.tmLanguage.json"), encoding="utf-8") as fh:
            patterns = [p["match"] for p in json.load(fh)["repository"]["test"]["patterns"] if "scope" in p["match"]]
        for line, group in (
            ("  as user $ann with scope read, files:write refused {DELETE FROM app.files}", 4),
            ("  user 3 with scope read-only, files:write cannot edit file 11", 3),
        ):
            got = [m.group(group) for p in patterns if (m := re.match(p, line))]
            self.assertEqual(got, [line.split("with scope ")[1].split(" refused")[0].split(" cannot")[0]], line)

    def test_the_textmate_grammar_colours_a_test_name_in_double_quotes_only(self) -> None:
        with open(os.path.join(self.REPO, "editor", "syntaxes", "authz.tmLanguage.json"), encoding="utf-8") as fh:
            [header] = [
                p["match"] for p in json.load(fh)["repository"]["test"]["patterns"] if p["match"].startswith("^(test)")
            ]
        for line, name in (
            ('test "owners see their folders"', '"owners see their folders"'),
            ('test "a -- b"  -- the comment', '"a -- b"'),
            ('test "user 2 cannot share team \'(1,"a b")\'"', '"user 2 cannot share team \'(1,"a b")\'"'),
            ("test owners see", None),
            ("test 'owners'", None),
        ):
            m = re.match(header, line)
            self.assertEqual(m.group(2) if m else None, name, line)

    def test_zed_builds_this_grammar(self) -> None:
        # extension.toml names the commit Zed fetches the grammar from: its grammar must be this one
        with open(os.path.join(self.REPO, "editor", "zed", "extension.toml"), encoding="utf-8") as fh:
            rev = search(r'^rev = "([0-9a-f]{40})"', fh.read(), re.M).group(1)
        try:
            known = (
                subprocess.run(
                    ["git", "cat-file", "-e", f"{rev}^{{commit}}"], cwd=self.REPO, capture_output=True
                ).returncode
                == 0
            )
        except OSError:
            known = False
        if not known:
            shallow = subprocess.run(
                ["git", "rev-parse", "--is-shallow-repository"], cwd=self.REPO, capture_output=True, text=True
            ).stdout.strip()
            if shallow != "false":
                self.skipTest(f"commit {rev[:7]} isn't in this shallow checkout")
        # an ancestor: a rebase or squash merge would leave it out of main, and Zed couldn't fetch it
        self.assertEqual(
            subprocess.run(["git", "merge-base", "--is-ancestor", rev, "HEAD"], cwd=self.REPO).returncode,
            0,
            f"commit {rev[:7]} (editor/zed/extension.toml) isn't in this branch's history: merge the "
            "grammar's commit with a merge commit, or set rev to a commit that is",
        )
        # Zed builds the parser from src/ (editor/test.sh checks src/ is what grammar.js generates): a change to
        # grammar.js that generates the same src/, a comment, needs no new rev
        diff = subprocess.run(
            ["git", "diff", "--stat", rev, "--", "editor/tree-sitter-authz/src"],
            cwd=self.REPO,
            capture_output=True,
            text=True,
        ).stdout
        self.assertEqual(
            diff,
            "",
            "the grammar changed since the commit editor/zed/extension.toml names: "
            "commit it, then set rev to that commit",
        )


class Layout(unittest.TestCase):
    """One Ruff lays the Python out: the version CI checks with is the one the pre-commit hook runs and the one
    the rules for contributors name, so a commit the hook lets through passes CI's layout check. And the commits
    that only laid code out, which `git blame` skips, are commits of this history."""

    REPO = os.path.dirname(ROOT)
    NAMED_IN = (".github/workflows/ci.yml", ".githooks/pre-commit", "CONTRIBUTING.md", "CLAUDE.md", "ruff.toml")

    def test_one_ruff_everywhere(self) -> None:
        versions: dict[str, set[str]] = {}
        for path in self.NAMED_IN:
            with open(os.path.join(self.REPO, path), encoding="utf-8") as fh:
                versions[path] = set(re.findall(r"ruff@(\d+(?:\.\d+)+)", fh.read()))
        ci = versions[".github/workflows/ci.yml"]
        self.assertEqual(len(ci), 1, "CI runs one version of Ruff")
        self.assertEqual({path: found for path, found in versions.items() if found != ci}, {})

    def test_blame_skips_commits_of_main(self) -> None:
        # .git-blame-ignore-revs: git stops at a line that isn't a full hash, and skips one it doesn't know in silence
        with open(os.path.join(self.REPO, ".git-blame-ignore-revs"), encoding="utf-8") as fh:
            revs = [line.strip() for line in fh if line.strip() and not line.startswith("#")]
        self.assertTrue(revs)
        self.assertEqual([rev for rev in revs if not re.fullmatch(r"[0-9a-f]{40}", rev)], [], "full hashes only")
        try:
            shallow = subprocess.run(
                ["git", "rev-parse", "--is-shallow-repository"], cwd=self.REPO, capture_output=True, text=True
            ).stdout.strip()
        except OSError:
            shallow = ""
        if shallow != "false":
            self.skipTest("the history isn't all here")
        # an ancestor: a rebase or squash merge gives the commit another hash, and blame would skip nothing
        lost = [
            rev
            for rev in revs
            if subprocess.run(
                ["git", "merge-base", "--is-ancestor", rev, "HEAD"], cwd=self.REPO, capture_output=True
            ).returncode
        ]
        self.assertEqual(lost, [], "not in this branch's history: name commits that are on main already")


class Executable(unittest.TestCase):
    """A script that starts with #! is executable in git, or the suite that runs it directly fails (`chmod +x`, or
    `git update-index --chmod=+x`)."""

    REPO = os.path.dirname(ROOT)

    def test_scripts_are_executable(self) -> None:
        try:
            out = subprocess.run(
                ["git", "ls-files", "-s"], cwd=self.REPO, capture_output=True, text=True, check=True
            ).stdout
        except (OSError, subprocess.CalledProcessError):
            self.skipTest("not a git checkout")
        missing = []
        for line in out.splitlines():
            meta, path = line.split("\t", 1)
            if meta.startswith("100644") and os.path.isfile(os.path.join(self.REPO, path)):
                with open(os.path.join(self.REPO, path), "rb") as fh:
                    if fh.read(2) == b"#!":
                        missing.append(path)
        self.assertEqual(missing, [])


class Private(unittest.TestCase):
    """Decisions and plans are kept out of this repository: no file points at them, so no reader meets a link
    they can't follow. (The patterns are split so this file doesn't match itself.)"""

    REPO = os.path.dirname(ROOT)
    SKIP: ClassVar[set[str]] = {"node_modules", "generated", "__pycache__", "dist", "out", "grammars"}
    # folders whose name starts with a dot are a tool's own (git's, an editor's, a cache), but for these two
    DOTTED: ClassVar[set[str]] = {".github", ".vitepress"}
    # (two names that stay out of the repository too, in a file or a pull request; the conventions file keeps its own)
    WORDS = re.compile(
        r"\bADRs?" + r" ?\d{4}|docs/" + r"adr\b|\b(roadmap|v1-design|developer-experience|"
        r"language-review)" + r"\.md\b|rowstile-" + r"internal|(?i:cl" + r"aude(?!\.md\b)|anth" + r"ropic)"
    )

    def test_nothing_points_at_them(self) -> None:
        self.assertFalse(
            os.path.isdir(os.path.join(self.REPO, "docs", "adr")), "decisions are kept outside this repository"
        )
        found = []
        for d, dirs, files in os.walk(self.REPO):
            dirs[:] = [x for x in dirs if x not in self.SKIP and (not x.startswith(".") or x in self.DOTTED)]
            for f in files:
                path = os.path.join(d, f)
                if os.path.getsize(path) > 4_000_000:
                    continue
                with open(path, encoding="utf-8", errors="ignore") as fh:
                    for n, line in enumerate(fh, 1):
                        if self.WORDS.search(line):
                            found.append(f"{os.path.relpath(path, self.REPO)}:{n}: {line.strip()[:100]}")
        self.assertEqual(found, [])


class Version(unittest.TestCase):
    REPO = os.path.dirname(ROOT)

    def test_semver(self) -> None:
        self.assertTrue(VERSION.fullmatch(authzlib.__version__), authzlib.__version__)

    def test_changelog_has_the_version(self) -> None:
        # a release's notes are its changelog section (packaging/changelog.py); main, at X.Y.Z-dev, needs none yet
        sys.path.insert(0, os.path.join(self.REPO, "packaging"))
        try:
            import changelog
        finally:
            sys.path.pop(0)
        text = changelog.read()
        self.assertTrue(text.startswith("# Changelog\n"), "CHANGELOG.md starts with its title")
        self.assertIn("\n## Unreleased\n", text)
        if not authzlib.__version__.endswith("-dev"):
            self.assertTrue(changelog.section(authzlib.__version__, text).strip(), authzlib.__version__)

    def test_a_dev_build_names_its_sources(self) -> None:
        # apply trusts "same version, same policy": two builds of main must not look the same
        if authzlib.__version__.endswith("-dev"):
            self.assertRegex(authzlib.BUILD, r"^\d+\.\d+\.\d+-dev\+[0-9a-f]{12}$")
        else:
            self.assertEqual(authzlib.BUILD, authzlib.__version__)
        # a release's is its version alone; the hash reads the compiler's .py files only (a machine that writes
        # bytecode has __pycache__ beside them)
        for release in ("0.2.0", "0.2.0-rc.1"):
            with mock.patch.object(authzlib, "__version__", release):
                self.assertEqual(authzlib._build(), release)
        names = os.listdir(os.path.dirname(os.path.abspath(authzlib.__file__)))
        with mock.patch("os.listdir", return_value=[*names, "__pycache__", "notes.txt"]):
            self.assertEqual(authzlib._build(), authzlib.BUILD)
        # and each of them counts: one source fewer is another build
        if authzlib.__version__.endswith("-dev"):
            with mock.patch("os.listdir", return_value=[n for n in names if n != "fmt.py"]):
                self.assertNotEqual(authzlib._build(), authzlib.BUILD)

    def test_one_version(self) -> None:
        # the packages and the review for CI carry the compiler's version (packaging/version.py sets them all)
        sys.path.insert(0, os.path.join(self.REPO, "packaging"))
        try:
            import version
        finally:
            sys.path.pop(0)
        self.assertEqual(list(version.found()), [authzlib.__version__])

    def test_npms_latest_follows_next_until_a_release(self) -> None:
        # while only alphas and candidates are published, a plain `npm i rowstile` gets the newest: each release
        # moves `latest` to where `next` is (packaging/npm_latest.py); a final release ends that
        sys.path.insert(0, os.path.join(self.REPO, "packaging"))
        try:
            import npm_latest
        finally:
            sys.path.pop(0)
        target = npm_latest.target
        alphas = ["0.1.0-alpha.5", "0.1.0-alpha.6"]
        self.assertEqual(target({"next": "0.1.0-alpha.6", "latest": "0.1.0-alpha.5"}, alphas)[0], "0.1.0-alpha.6")
        self.assertEqual(target({"next": "0.1.0-alpha.6"}, alphas)[0], "0.1.0-alpha.6")
        self.assertEqual(
            target({"next": "0.1.0-rc.1", "latest": "0.1.0-alpha.6"}, [*alphas, "0.1.0-rc.1"])[0], "0.1.0-rc.1"
        )
        for tags, versions, why in (
            ({"next": "0.1.0-alpha.6", "latest": "0.1.0-alpha.6"}, alphas, "latest is 0.1.0-alpha.6 already"),
            ({"latest": "0.1.0-alpha.5"}, alphas, "nothing is published under next"),
            # once released, `latest` is a release's: an alpha of the next version stays under `next`
            ({"next": "0.2.0-alpha.1", "latest": "0.1.0"}, [*alphas, "0.1.0", "0.2.0-alpha.1"], "0.1.0 is released"),
            ({"next": "0.1.0-rc.1", "latest": "0.1.0-alpha.6"}, [*alphas, "0.1.0-rc.1", "0.1.0"], "0.1.0 is released"),
        ):
            version, said = target(tags, versions)
            self.assertIsNone(version, said)
            self.assertIn(why, said)
        # every package the release publishes: the launcher, one per platform it knows, the SDK's
        names = npm_latest.names()
        launcher = search(
            r"const PLATFORMS = \[(.*?)\];", read("../packaging/npm/rowstile/bin/rowstile.js"), re.S
        ).group(1)
        platforms = [f"@rowstile/cli-{p}" for p in re.findall(r'"([a-z0-9-]+)"', launcher)]
        sdk = glob.glob(os.path.join(self.REPO, "sdk", "typescript", "*", "package.json"))
        self.assertEqual(names[0], "rowstile")
        self.assertEqual(sorted(names[1 : 1 + len(platforms)]), sorted(platforms))
        self.assertEqual(len(names), 1 + len(platforms) + len(sdk))
        self.assertEqual(len(set(names)), len(names))
        self.assertIn("@rowstile/prisma", names)
        # moving a tag by trusted publishing takes a newer npm than Node brings: both jobs install one, by version,
        # its tarball checked by its hash
        for npm, enough in (("11.19.0", False), ("11.21.0", True), ("11.30.1", True), ("12.0.0", False)):
            self.assertEqual(npm_latest.new_enough(npm), enough, npm)
        self.assertTrue(npm_latest.new_enough("12.2.0") and npm_latest.new_enough("13.0.0"))
        release = read("../.github/workflows/release.yml")
        self.assertEqual(
            len(re.findall(r"^      - run: bash packaging/npm/install_npm.sh$", release, re.M)),
            2,
            "the npm job and the latest job",
        )
        self.assertNotIn("npm install --global", release)
        script = read("../packaging/npm/install_npm.sh")
        npm = search(r"^VERSION=(\d+\.\d+\.\d+)$", script, re.M).group(1)
        self.assertTrue(npm_latest.new_enough(npm), npm)
        self.assertRegex(script, r"(?m)^SHA256=[0-9a-f]{64}$")
        self.assertIn(f"npm view npm@{npm} dist.integrity", script)
        self.assertIn("sha256sum -c --quiet -\n", script)
        # the release's own run says which version it published and waits for the registry to show it; by hand,
        # later, the registry is read as it is
        self.assertEqual(release.count("        run: python3 packaging/npm_latest.py --move\n"), 1)
        self.assertEqual(
            release.count('        run: python3 packaging/npm_latest.py --move --published "$VERSION"\n'), 1
        )
        self.assertRegex(release, r"(?m)^  npm:\n(?:    .*\n|\n)*?    env:\n(?:      .*\n)*?      VERSION: ")
        # the registry shows a publish late: read right after it, `next` is still the release before and `latest`
        # is there already, so nothing would move (0.1.0-alpha.7's own run moved nothing on sixteen packages)
        stale = ({"next": "0.1.0-alpha.6", "latest": "0.1.0-alpha.6"}, alphas)
        fresh = ({"next": "0.1.0-alpha.7", "latest": "0.1.0-alpha.6"}, [*alphas, "0.1.0-alpha.7"])
        self.assertIsNone(target(*stale)[0])
        answers = [stale, stale, fresh]
        slept: list[float] = []
        found = npm_latest.shown(
            "rowstile", "0.1.0-alpha.7", 100.0, lambda _: answers.pop(0), slept.append, lambda: float(sum(slept))
        )
        self.assertEqual(found, fresh)
        self.assertEqual(slept, [npm_latest.EVERY] * 2)
        self.assertEqual(target(*fresh)[0], "0.1.0-alpha.7")
        # a package the registry never shows in time is given up, not moved to what it showed
        slept.clear()
        self.assertIsNone(
            npm_latest.shown(
                "rowstile", "0.1.0-alpha.7", 40.0, lambda _: stale, slept.append, lambda: float(sum(slept))
            )
        )
        self.assertEqual(len(slept), 3)
        # a release is published as `latest` itself: its run moves nothing, whatever the registry shows
        out = io.StringIO()
        with (
            mock.patch.object(npm_latest, "published", side_effect=AssertionError("the registry was read")),
            mock.patch("sys.stdout", out),
        ):
            npm_latest.main(["--move", "--published", "0.1.0"])
        self.assertIn("0.1.0 is a release", out.getvalue())
        for bad in (["--published", "0.1.0-alpha.7"], ["--move", "--published"], ["--move", "0.1.0-alpha.7"]):
            with self.assertRaises(SystemExit):
                npm_latest.main(bad)
        # by hand with latest=true nothing else runs: every other job needs `check`, which is skipped
        self.assertIn("  check:\n    if: ${{ !inputs.latest }}\n", release)
        self.assertIn("  latest:\n    if: ${{ github.event_name == 'workflow_dispatch' && inputs.latest }}\n", release)
        jobs = re.findall(r"^  ([a-z-]+):\n((?:    .*\n|\n)*)", release.split("\njobs:\n", 1)[1], re.M)
        for job, body in jobs:
            if job not in ("check", "latest"):
                self.assertRegex(body, r"    needs: (check|\[check, )", job)

    def test_the_mcp_registrys_entry_names_the_npm_package(self) -> None:
        # the registry takes server.json only if the npm package it names says the same name back (`mcpName`), and
        # refuses a description over 100 characters; `rowstile mcp` is how the package starts the server
        with open(os.path.join(self.REPO, "server.json"), encoding="utf-8") as fh:
            entry = json.load(fh)
        with open(os.path.join(self.REPO, "packaging", "npm", "rowstile", "package.json"), encoding="utf-8") as fh:
            package = json.load(fh)
        self.assertEqual(entry["name"], package["mcpName"])
        self.assertLessEqual(len(entry["description"]), 100)
        (npm,) = entry["packages"]
        self.assertEqual((npm["registryType"], npm["identifier"]), ("npm", package["name"]))
        self.assertEqual(npm["packageArguments"], [{"type": "positional", "value": "mcp"}])
        self.assertEqual(npm["version"], entry["version"])

    def test_npm_packages_name_the_repository(self) -> None:
        # npm refuses a package published with provenance unless repository.url is the repository it came from;
        # the extension's is its Marketplace page's link
        url = "git+https://github.com/rowstile/rowstile.git"
        sdks = sorted(glob.glob(os.path.join(self.REPO, "sdk", "typescript", "*", "")))
        self.assertLessEqual(
            {"client", "pg", "postgres", "prisma", "drizzle", "next", "react", "vitest"},
            {os.path.basename(os.path.dirname(d)) for d in sdks},
            "the SDK's packages aren't found",
        )
        for d in sdks + [os.path.join(self.REPO, "packaging", "npm", "rowstile"), os.path.join(self.REPO, "editor")]:
            with open(os.path.join(d, "package.json"), encoding="utf-8") as fh:
                repo = json.load(fh).get("repository", {})
            self.assertEqual(
                (repo.get("url"), repo.get("directory")), (url, os.path.relpath(d, self.REPO).replace(os.sep, "/")), d
            )
        with open(os.path.join(self.REPO, "packaging", "npm", "build.mjs"), encoding="utf-8") as fh:
            self.assertIn(f'url: "{url}"', fh.read())

    def test_applying_records_it(self) -> None:
        self.assertIn("version text NOT NULL", compiled("docs"))


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0]] + [a for a in sys.argv[1:] if a != "--update"], verbosity=1)
