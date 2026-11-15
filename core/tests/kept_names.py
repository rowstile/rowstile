#!/usr/bin/env python3
"""kept_names.py: the names the functions of a compiled policy keep for themselves.

    python3 compile_policy.py POLICY | python3 tests/kept_names.py          # one name a line, sorted
    python3 compile_policy.py POLICY | python3 tests/kept_names.py --by     # and the functions that keep each

A function keeps its parameters and, written in PL/pgSQL, what it declares, its loop variables, and what PL/pgSQL
gives every function (found) or every trigger function (new, old, the tg_ names). A table's columns may have any
name, one of these too. Where a statement of the function has such a table in scope, Postgres takes the bare name
for the column in a function written in SQL, without a word, and calls it ambiguous in PL/pgSQL (42702): the
function must write its own name so that no column can be meant (`$1` for a parameter). `OwnNames` in
unit_test.py reads the functions here.
A name too many does no harm (a column more to try); one too few would hide a clash.
"""

import os
import re
import sys
from typing import NamedTuple

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from authzlib import statements
from authzlib.sqlutil import sql_code

EVERY_FUNCTION = ("found",)
EVERY_TRIGGER = (
    *("new", "old", "tg_name", "tg_when", "tg_level", "tg_op", "tg_relid", "tg_relname", "tg_table_name"),
    *("tg_table_schema", "tg_nargs", "tg_argv"),
)
NAME = r"[A-Za-z_][A-Za-z0-9_]*"
HEAD = re.compile(r"CREATE (?:OR REPLACE )?FUNCTION\s+((?:\"[^\"]*\"|[\w.])+)\(", re.I)
BODY = re.compile(r"\bAS\s+(\$\w*\$)(.*?)\1", re.S)
MODES = {"in", "out", "inout", "variadic"}
# a declaration: a name, then its type, CONSTANT, ALIAS FOR, or CURSOR (never `:=`, which assigns)
DECLARED = re.compile(rf"(?:^|;)\s*({NAME})\s+(?=[A-Za-z_\"])")


class Function(NamedTuple):
    name: str  # as its statement writes it: authz_int."doc__parent__edit__links"
    plpgsql: bool  # written in PL/pgSQL; else in SQL
    parameters: tuple[str, ...]  # the names of its parameters that have one, in lower case
    names: frozenset[str]  # every name it keeps: its parameters and, in PL/pgSQL, the rest
    statement: str  # the whole CREATE FUNCTION
    body: str  # its body's code: strings and comments left out, quoted names kept

    def bare(self, name: str) -> bool:
        """Whether the body writes this name by itself: not after a dot (a column of something), not quoted, not
        before `=>` (an argument's name in a call) or `(` (a function)."""
        return re.search(rf"(?<![.\w\"$]){re.escape(name)}(?![\w\"]|\s*(?:=>|\())", self.body, re.I) is not None


def code_of(text: str) -> str:
    """A text's code: without its strings and comments, so a `;` or a name inside one isn't read."""
    return "".join(piece if is_code else " '' " for is_code, piece in sql_code(text))


def top_level(text: str) -> list[str]:
    """text split at its commas outside parentheses."""
    parts, depth, start = [], 0, 0
    for i, c in enumerate(text):
        depth += (c == "(") - (c == ")")
        if c == "," and depth == 0:
            parts.append(text[start:i])
            start = i + 1
    return [*parts, text[start:]]


def parameters(statement: str, at: int) -> str:
    """What is between the parenthesis at `at` and the one that closes it."""
    depth = 0
    for i in range(at, len(statement)):
        depth += (statement[i] == "(") - (statement[i] == ")")
        if depth == 0:
            return statement[at + 1 : i]
    return statement[at + 1 :]


def functions(sql: str) -> list[Function]:
    """Every function the SQL makes, in its order."""
    out: list[Function] = []
    for _, statement in statements.split(sql):
        head = HEAD.match(statement)
        if not head:
            continue
        listed = parameters(statement, head.end() - 1)
        after = head.end() + len(listed) + 1
        quoted = BODY.search(statement, after)
        # the clauses around the body say the language; a body that isn't a string (BEGIN ATOMIC, RETURN) is SQL
        clauses = statement[after : quoted.start()] + statement[quoted.end() :] if quoted else statement[after:]
        plpgsql = re.search(r"\bLANGUAGE\s+plpgsql\b", clauses, re.I) is not None
        named: list[str] = []
        for param in top_level(code_of(listed)):
            words = param.split()
            while words and words[0].lower() in MODES:
                words = words[1:]
            if len(words) >= 2 and re.fullmatch(NAME, words[0]):  # (a parameter without a name is its type alone)
                named.append(words[0].lower())
        body = code_of(quoted.group(2) if quoted else statement[after:])
        names = set(named)
        if plpgsql:
            names.update(EVERY_FUNCTION)
            if re.search(r"\bRETURNS\s+trigger\b", clauses, re.I):
                names.update(EVERY_TRIGGER)
            for block in re.finditer(r"\bDECLARE\b(.*?)\bBEGIN\b", body, re.S | re.I):
                names.update(n.lower() for n in DECLARED.findall(block.group(1)))
            names.update(n.lower() for n in re.findall(rf"\bFOR(?:EACH)?\s+({NAME})\s+(?:IN|SLICE)\b", body, re.I))
        out.append(Function(head.group(1), plpgsql, tuple(named), frozenset(names), statement, body))
    return out


def kept(sql: str) -> dict[str, set[str]]:
    """Each kept name -> the functions that keep it."""
    out: dict[str, set[str]] = {}
    for f in functions(sql):
        for name in f.names:
            out.setdefault(name, set()).add(f.name)
    return out


def main() -> int:
    names = kept(sys.stdin.read())
    if not names:
        print("kept_names.py: no function in what was read", file=sys.stderr)
        return 1
    for name in sorted(names):
        print(name + (": " + ", ".join(sorted(names[name])) if "--by" in sys.argv else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
