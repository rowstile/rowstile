"""Splitting generated SQL into statements, and naming the object each one makes.

The migration writer (migrate.py) works on objects: a function, a view, a trigger, a policy, a table and
the rows it holds. The compiler writes SQL text; this reads it back, the way psql does: quotes, dollar
quotes, comments and BEGIN ATOMIC bodies (whose semicolons don't end the statement).
"""

from __future__ import annotations

import re
from functools import cache

# What a name may start with: Postgres takes any character past ASCII as a letter (archivé, année, ñ)
LETTER = r"A-Za-z_\x80-\U0010ffff"
WORD = re.compile(rf"[{LETTER}][{LETTER}0-9$]*")
DOLLAR = re.compile(rf"\$([{LETTER}][{LETTER}0-9]*)?\$")


def split(sql: str) -> list[tuple[str, str]]:
    """[(comments, statement)]: each statement with the comment lines just above it, without its final ';'.
    Comments between statements that no statement follows are dropped."""
    out: list[tuple[str, str]] = []
    i, n = 0, len(sql)
    start: int | None = None
    comments: list[str] = []
    atomic, depth = False, 0  # inside a BEGIN ATOMIC body, and how many BEGIN/CASE are open in it
    first: str | None = None  # the statement's first word, and the last one (to spot CREATE ... BEGIN ATOMIC)
    prev: str | None = None
    word = (-1, -1)  # where the last word starts and ends
    while i < n:
        c = sql[i]
        if c in " \t\r\n":
            i += 1
            continue
        if sql.startswith("--", i):
            j = sql.find("\n", i)
            j = n if j < 0 else j
            if start is None:
                comments.append(sql[i:j])
            i = j
            continue
        if sql.startswith("/*", i):
            j, level = i + 2, 1
            while j < n and level:
                if sql.startswith("/*", j):
                    level, j = level + 1, j + 2
                elif sql.startswith("*/", j):
                    level, j = level - 1, j + 2
                else:
                    j += 1
            if start is None:
                comments.append(sql[i:j])
            i = j
            continue
        if start is None:
            start = i
        if c == "'":
            # E'...': the word just before is E alone (not a name that ends in E, →E'...', nor a number's, 1E'...')
            escapes = word == (i - 1, i) and sql[i - 1] in "eE" and not (i > 1 and sql[i - 2].isdigit())
            j = i + 1
            while j < n:
                if escapes and sql[j] == "\\":
                    j += 2
                    continue
                if sql[j] == "'":
                    if j + 1 < n and sql[j + 1] == "'":
                        j += 2
                        continue
                    break
                j += 1
            i = j + 1
            continue
        if c == '"':
            j = i + 1
            while j < n:
                if sql[j] == '"':
                    if j + 1 < n and sql[j + 1] == '"':
                        j += 2
                        continue
                    break
                j += 1
            i = j + 1
            continue
        if c == "$":
            m = DOLLAR.match(sql, i)
            if m and not (i > 0 and (sql[i - 1].isalnum() or sql[i - 1] == "_")):
                end = sql.find(m.group(0), m.end())
                if end < 0:
                    raise ValueError(f"unterminated dollar quote {m.group(0)}")
                i = end + len(m.group(0))
                continue
            i += 1
            continue
        if c.isalpha() or c == "_" or c >= "\x80":
            m = WORD.match(sql, i)
            assert m is not None  # a letter, _ or any character past ASCII starts a word
            w = m.group(0).upper()
            if first is None:
                first = w
            if atomic:
                if w in ("BEGIN", "CASE"):
                    depth += 1
                elif w == "END":
                    depth -= 1
            elif w == "ATOMIC" and prev == "BEGIN" and first == "CREATE":
                atomic, depth = True, 1
            prev = w
            word = m.span()
            i = m.end()
            continue
        if c == ";" and not (atomic and depth > 0):
            assert start is not None
            out.append(("\n".join(comments), sql[start:i].rstrip()))
            start, comments, atomic, depth, first, prev = None, [], False, 0, None, None
            i += 1
            continue
        i += 1
    if start is not None and sql[start:].strip():
        out.append(("\n".join(comments), sql[start:].rstrip()))
    return out


# --- what a statement makes --------------------------------------------------------------------------
NAME = rf'(?:"(?:[^"]|"")*"|[{LETTER}][{LETTER}0-9$]*)'
QNAME = rf"{NAME}(?:\s*\.\s*{NAME})?"


def _args(text: str, start: int) -> tuple[str, int]:
    """The argument list starting at text[start] == '(': (its text, the index after ')')."""
    depth, i = 0, start
    while i < len(text):
        ch = text[i]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return text[start + 1 : i], i + 1
        elif ch == "'":
            i = text.index("'", i + 1)
        elif ch == '"':
            i = text.index('"', i + 1)
        i += 1
    raise ValueError("unbalanced parentheses in a function's arguments")


def _split_top(text: str, sep: str = ",") -> list[str]:
    parts: list[str] = []
    cur: list[str] = []
    depth, i = 0, 0
    while i < len(text):
        ch = text[i]
        if ch in "([":
            depth += 1
        elif ch in ")]":
            depth -= 1
        elif ch in "'\"":
            j = text.index(ch, i + 1)
            cur.append(text[i : j + 1])
            i = j + 1
            continue
        if ch == sep and depth == 0:
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
        i += 1
    if "".join(cur).strip():
        parts.append("".join(cur))
    return parts


def signature(args: str) -> str:
    """A function's argument list as DROP FUNCTION takes it: names and types, no defaults."""
    out: list[str] = []
    for a in _split_top(args):
        a = re.split(r"\s+DEFAULT\s+|\s*=\s*", a.strip(), maxsplit=1, flags=re.IGNORECASE)[0]
        out.append(" ".join(a.split()))
    return ", ".join(out)


def norm(name: str) -> str:
    """A qualified name as the compiler writes it, with spaces around the dot removed."""
    return re.sub(r"\s*\.\s*", ".", name.strip())


# made()'s patterns (and references()'s), each compiled when first used (_rx): compiling them all costs every command
# ~5 ms, and one that compiles a policy without migrating it uses one or two
CREATE_FN = rf"(?i)CREATE\s+(?:OR\s+REPLACE\s+)?FUNCTION\s+({QNAME})\s*\("
CREATE_VIEW = rf"(?i)CREATE\s+(?:OR\s+REPLACE\s+)?VIEW\s+({QNAME})"
CREATE_TABLE = rf"(?i)CREATE\s+(?:UNLOGGED\s+)?TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?({QNAME})"
CREATE_TRIGGER = rf"(?is)CREATE\s+(?:OR\s+REPLACE\s+)?(?:CONSTRAINT\s+)?TRIGGER\s+({NAME})\s.*?\bON\s+({QNAME})"
CREATE_POLICY = rf"(?i)CREATE\s+POLICY\s+({NAME})\s+ON\s+({QNAME})"
CREATE_INDEX = (
    rf"(?i)CREATE\s+(?:UNIQUE\s+)?INDEX\s+(?:CONCURRENTLY\s+)?(?:IF\s+NOT\s+EXISTS\s+)?({QNAME})?\s*ON\s+({QNAME})"
)
CREATE_TYPE = rf"(?i)CREATE\s+TYPE\s+({QNAME})"
CREATE_SCHEMA = rf"(?i)CREATE\s+SCHEMA\s+(?:IF\s+NOT\s+EXISTS\s+)?({NAME})"
RLS = rf"(?i)ALTER\s+TABLE\s+({QNAME})\s+ENABLE\s+ROW\s+LEVEL\s+SECURITY"
MARK = r"(?m)^--\s*@object\s+(\w+)\s+(.+?)\s*$"


@cache
def _rx(source: str) -> re.Pattern[str]:
    return re.compile(source)


def made(statement: str, comments: str = "") -> tuple[str, str] | None:
    """(kind, key) of the object a statement makes, or None: 'function' with its DROP signature, 'view',
    'table', 'trigger' ('name ON table'), 'policy' ('name ON table'), 'index', 'type', 'schema', 'rls'.
    A statement that makes one indirectly (a DO block) says so in a comment: -- @object view mt.docs_visible"""
    m = _rx(MARK).search(comments)
    if m:
        return m.group(1), m.group(2)
    s = statement.lstrip()
    # each pattern starts with its own words, so the order they are tried in changes nothing: triggers first, as
    # compiling a policy asks about triggers alone (governance.py) and then compiles no other pattern
    m = _rx(CREATE_TRIGGER).match(s)
    if m:
        return "trigger", f"{m.group(1)} ON {norm(m.group(2))}"
    m = _rx(CREATE_FN).match(s)
    if m:
        args, _ = _args(s, m.end() - 1)
        return "function", f"{norm(m.group(1))}({signature(args)})"
    for kind, rx in (("view", CREATE_VIEW), ("table", CREATE_TABLE), ("type", CREATE_TYPE), ("schema", CREATE_SCHEMA)):
        m = _rx(rx).match(s)
        if m:
            return kind, norm(m.group(1))
    m = _rx(CREATE_POLICY).match(s)
    if m:
        return "policy", f"{m.group(1)} ON {norm(m.group(2))}"
    m = _rx(CREATE_INDEX).match(s)
    if m:
        return ("index", norm(m.group(1))) if m.group(1) else None  # unnamed: goes with its table
    m = _rx(RLS).match(s)
    if m:
        return "rls", norm(m.group(1))
    return None


def drop_sql(kind: str, key: str) -> str | None:
    """What undoes an object (None: nothing to undo, or kept on purpose)."""
    return {
        "function": f"DROP FUNCTION IF EXISTS {key};",
        "view": f"DROP VIEW IF EXISTS {key};",
        "table": f"DROP TABLE IF EXISTS {key};",
        "trigger": f"DROP TRIGGER IF EXISTS {key};",
        "policy": f"DROP POLICY IF EXISTS {key};",
        "index": f"DROP INDEX IF EXISTS {key};",
        "type": f"DROP TYPE IF EXISTS {key};",
    }.get(kind)


REF = rf"\b(authz|authz_int|authz_gen)\s*\.\s*({NAME})"


def references(text: str) -> set[str]:
    """The authz* names a piece of SQL mentions: {'authz_int.x', ...} (quotes removed)."""
    return {
        f"{s}.{n[1:-1].replace(chr(34) * 2, chr(34)) if n.startswith(chr(34)) else n}"
        for s, n in _rx(REF).findall(text)
    }


def unquoted(key: str) -> str:
    """'authz_int."x"(a int)' -> 'authz_int.x': the name references() gives."""
    name = key.split("(")[0].split(" ON ")[0].strip()
    parts = re.findall(NAME, name)
    return ".".join(p[1:-1].replace('""', '"') if p.startswith('"') else p for p in parts)
