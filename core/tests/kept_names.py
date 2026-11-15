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

A row has the same trouble. `to_jsonb(n)` with `FROM new_rows n` is the row only while the table has no column
called n: `rows_by_alias` finds, in a statement's code, each row of the app's named by its alias alone.

And so has every word the SQL writes by itself: a column of rowstile's own tables or of a query (`x`, `id`) is the
app's column of that name where a table that has one is in scope nearer. What is printed is all three: the names
the functions keep, what the SQL calls a row by, and every word it writes by itself (`written`).
`tests/hand_answers.sh --kept-names` gives the tables a column of each.

In PL/pgSQL a name is looked up in the piece it is written in (a statement, an IF's condition): `pieces` cuts a
body into them, `columns_in_scope` says which may read the app's columns, and `bare` whether one writes a name by
itself. There a function writes a parameter by position and a variable by its block's label (`authz__.v_n`).
"""

import os
import re
import sys
from typing import NamedTuple

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from authzlib import statements
from authzlib.sqlutil import APP_COLUMNS, ROW_SOURCE, pieces, plain_code, reads_app_columns

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
        """Whether the body writes this name by itself somewhere (see `bare`)."""
        return bare(self.body, name)


code_of = plain_code


# The pieces PL/pgSQL hands to SQL one by one (`pieces`), and whether one may have the app's columns in scope
# (`columns_in_scope`), are the compiler's own reading: it says a column wins in the functions that have such
# a piece (authzlib.sqlutil.column_wins).
columns_in_scope = reads_app_columns


# where a statement puts a value into a variable, the name is the variable's whatever the columns: `v :=`, INTO v,
# FOR v IN, GET DIAGNOSTICS v
TARGETS = (
    r"\bINTO\s+(?:STRICT\s+)?(?:[\w.]+\s*,\s*)*{n}\b",
    r"\bFOR\s+(?:[\w.]+\s*,\s*)*{n}\s*(?:,\s*[\w.]+\s*)*\s+IN\b",
    r"\bFOREACH\s+{n}\b",
    r"\bGET\s+(?:CURRENT\s+|STACKED\s+)?DIAGNOSTICS\s+{n}\b",
    r"(?:^|(?<=\s)){n}\s*:=",
)


def bare(text: str, name: str) -> bool:
    """Whether the text writes this name by itself, where a column of that name would be meant too: not after a dot
    (a column of something), not before one (`new.id`: a record's field, a table's column; never the column `new`),
    not quoted, not before `=>` (an argument's name in a call) or `(` (a function), and not where a statement puts
    a value into it."""
    n = re.escape(name)
    for target in TARGETS:
        text = re.sub(target.format(n=n), " ", text, flags=re.I)
    # (the dots of a range, `1..n`, are no qualifier)
    return re.search(rf"(?<![\w\"$])(?<![^.][.]){n}(?![\w\"]|\s*(?:=>|\(|[.](?![.])))", text, re.I) is not None


def own_names_bare(f: Function) -> list[tuple[str, list[str]]]:
    """The pieces of a PL/pgSQL function's body that may have the app's columns in scope and write a name of the
    function's by itself: (the piece, those names)."""
    out: list[tuple[str, list[str]]] = []
    for piece in pieces(f.body):
        names = sorted(n for n in f.names if bare(piece, n)) if columns_in_scope(piece) else []
        if names:
            out.append((piece, names))
    return out


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
    """Every function the SQL makes, in its order, and every DO block it runs (PL/pgSQL too: named DO, with the
    names it declares)."""
    out: list[Function] = []
    for _, statement in statements.split(sql):
        head = HEAD.match(statement)
        block = None if head else DO.match(statement)
        if block:
            body = code_of(block.group(2))
            names = {
                *EVERY_FUNCTION,
                *(n.lower() for n in re.findall(rf"\bFOR(?:EACH)?\s+({NAME})\s+(?:IN|SLICE)\b", body, re.I)),
            }
            for declared in re.finditer(r"\bDECLARE\b(.*?)\bBEGIN\b", body, re.S | re.I):
                names.update(n.lower() for n in DECLARED.findall(declared.group(1)))
            out.append(Function("DO", True, (), frozenset(names), statement, body))
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


# --- a row named by its alias alone ---------------------------------------------------------------------------
# `to_jsonb(n)` with `FROM new_rows n` is the row n, unless the table has a column called n: Postgres takes a bare
# name for a column of a table in scope before it takes it for a row, and says nothing. `to_jsonb(n.*)` is the row
# whatever the columns are called.

ALIAS = rf'"(?:[^"]|"")+"|{NAME}'
GIVEN = re.compile(rf"\b(?:FROM|JOIN|UPDATE|INTO|USING)\s+(?:ONLY\s+)?({ROW_SOURCE})(?:\s+(?:AS\s+)?({ALIAS}))?", re.I)
# what may follow a table that is given no alias
NO_ALIAS = {
    *("where", "on", "join", "cross", "left", "right", "inner", "full", "natural", "group", "order", "limit"),
    *("union", "except", "intersect", "set", "using", "returning", "window", "having", "offset", "fetch", "for"),
    *("loop", "values", "select", "then", "else", "end", "and", "or", "default", "with", "do"),
}
MADE_ON = re.compile(rf"^\s*CREATE\s+(POLICY|TRIGGER)\b.*?\bON\s+({ROW_SOURCE})", re.I | re.S)


def own_name(table: str) -> str:
    """The alias a table has where none is given: its name, without its schema."""
    return table[table.index('"."') + 2 :] if '"."' in table else table


DO = re.compile(r"\s*DO\s+(\$\w*\$)(.*?)\1", re.S | re.I)
EXECUTED = re.compile(r"\bEXECUTE\s+'((?:[^']|'')*)'", re.I)


def read_apart(statement: str) -> list[str]:
    """The code of a statement of compiled SQL, in the pieces whose names are read apart: the statement itself, or,
    of a function or a DO block, each statement of its body, and each one the body runs from a string (a trigger
    made by EXECUTE '...')."""
    body = BODY.search(statement) if HEAD.match(statement) else DO.match(statement)
    if body is None:
        return [code_of(statement)]
    run = [code_of(m.group(1).replace("''", "'")) for m in EXECUTED.finditer(body.group(2))]
    return [*code_of(body.group(2)).split(";"), *run]


WORD = re.compile(rf'"(?:[^"]|"")*"|{NAME}|::|\S')
# the words an expression may follow: a name after one of them is read, not given to a table before it
BEFORE_A_VALUE = {
    *("select", "where", "and", "or", "not", "on", "by", "then", "else", "when", "in", "returning", "distinct"),
    *("all", "any", "some", "case", "is", "like", "ilike", "between", "having", "return", "if", "elsif", "while"),
    *("perform", "using", "limit", "offset", "values"),
}


def row_aliases(code: str) -> set[str]:
    """The names a piece of code calls the app's rows by: the alias it gives a table of the app's or a statement's
    rows, the table's own name where it gives none, and for a trigger NEW and OLD."""
    aliases: set[str] = set()
    made = MADE_ON.match(code)
    if made:
        aliases.add(own_name(made.group(2)))
        aliases.update(("new", "old") if made.group(1).upper() == "TRIGGER" else ())
    for m in GIVEN.finditer(code):
        alias = m.group(2)
        aliases.add(own_name(m.group(1)) if alias is None or alias.lower() in NO_ALIAS else alias)
    return aliases | derived_aliases(code)


def derived_aliases(code: str) -> set[str]:
    """The names a piece of code gives a query in FROM whose rows are the app's: `FROM (SELECT mr.* FROM ...) x` hands
    on whole rows (a `.*`), so x has their columns. (A function in FROM is no query: `unnest($1) x` is its value.)"""
    words = [(m.group(0), m.start()) for m in WORD.finditer(code)]
    out: set[str] = set()
    opened: list[int] = []
    for i, (word, _) in enumerate(words):
        if word == "(":
            opened.append(i)
        elif word == ")" and opened:
            start = opened.pop()
            before = words[start - 1][0].lower() if start else ""
            alias = [w for w, _ in words[i + 1 : i + 3] if w.lower() != "as"][:1]
            inside = code[words[start][1] : words[i][1]]
            if before not in ("from", "join", "lateral", ",") or not alias or not re.fullmatch(ALIAS, alias[0]):
                continue
            if alias[0].lower() not in NO_ALIAS and re.search(r"[.]\s*[*]", inside) and APP_COLUMNS.search(inside):
                out.add(alias[0])
    return out


def rows_by_alias(code: str) -> list[tuple[str, str]]:
    """Where a piece of code (one statement: code_of's) writes the alias of a row of the app's by itself, so that the
    row is meant and a column of that name would be taken: (the alias, the code around it). Not before a dot (`n.id`,
    `n.*`) or a parenthesis, and not where an alias is given (after a table, a query or AS). A policy's and a
    trigger's table is called by its name, and the rows of a trigger's WHEN are NEW and OLD."""
    aliases = row_aliases(code)
    made = MADE_ON.match(code)
    if made and made.group(1).upper() == "TRIGGER":
        when = re.search(r"\bWHEN\b(.*)\bEXECUTE\b", code, re.I | re.S)
        code = when.group(1) if when else ""  # (REFERENCING OLD TABLE AS ... names no row)
    # "docs" is docs too, written without its quotes; a name without quotes in any case
    forms = {a if a.startswith('"') else a.lower(): a for a in aliases}
    forms.update({a[1:-1]: a for a in aliases if re.fullmatch(r'"[a-z_][a-z0-9_]*"', a)})
    words = [(m.group(0), m.start()) for m in WORD.finditer(code)]
    out: list[tuple[str, str]] = []
    for i, (word, at) in enumerate(words):
        alias = forms.get(word if word.startswith('"') else word.lower())
        if alias is None:
            continue
        before = words[i - 1][0].lower() if i else ""
        after = words[i + 1][0] if i + 1 < len(words) else ""
        if after in (".", "(", "'") or after.lower() == "as" or before in (".", "::", ")", "as"):
            continue  # (before AS: a query's name, `WITH f AS (...)`; before a quote: the E of a string, e'...')
        if before == "from":  # `IS DISTINCT FROM n` reads n; `FROM n` otherwise names a table
            if i < 2 or words[i - 2][0].lower() != "distinct":
                continue
        elif (before[:1] == '"' or re.fullmatch(NAME, before)) and before not in BEFORE_A_VALUE:
            continue  # given: `FROM app.marks o`, `"app"."docs" r`
        out.append((alias, " ".join(code[max(0, at - 60) : at + 40].split())))
    return out


def kept(sql: str) -> dict[str, set[str]]:
    """Each kept name -> the functions that keep it."""
    out: dict[str, set[str]] = {}
    for f in functions(sql):
        for name in f.names:
            out.setdefault(name, set()).add(f.name)
    return out


def given(sql: str) -> set[str]:
    """Every name the SQL calls a row of the app's by, without its quotes."""
    out: set[str] = set()
    for _, statement in statements.split(sql):
        for part in read_apart(statement):
            out.update(a[1:-1].replace('""', '"') if a.startswith('"') else a.lower() for a in row_aliases(part))
    return out


def written(sql: str) -> set[str]:
    """Every word the SQL writes by itself somewhere, in lower case: a name without quotes, not after a dot or `::`
    (a column of something, a type), not before a dot or a parenthesis (what a column is of, a function). A column
    of rowstile's own tables, a query's column (`x`, `id`), a keyword: where a table of the app's is in scope and
    has a column of that name, the word may be read as that column."""
    out: set[str] = set()
    for _, statement in statements.split(sql):
        for part in read_apart(statement):
            words = [m.group(0) for m in WORD.finditer(part)]
            for i, word in enumerate(words):
                if not re.fullmatch(NAME, word) or (i and words[i - 1] in (".", "::")):
                    continue
                if i + 1 == len(words) or words[i + 1] not in (".", "("):
                    out.add(word.lower())
    return out


def main() -> int:
    sql = sys.stdin.read()
    names = kept(sql)
    if not names:
        print("kept_names.py: no function in what was read", file=sys.stderr)
        return 1
    for alias in given(sql):
        names.setdefault(alias, set()).add("(a row is called so)")
    for word in written(sql):
        names.setdefault(word, set()).add("(written by itself)")
    for name in sorted(names):
        print(name + (": " + ", ".join(sorted(names[name])) if "--by" in sys.argv else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
