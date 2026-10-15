"""Parsing .authz policy files into a small model."""

from __future__ import annotations

import os
import posixpath
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Literal, NamedTuple, NoReturn, TypeAlias

IDENT = r"[A-Za-z_][A-Za-z0-9_]*"
QNAME = rf"{IDENT}\.{IDENT}"
COMMANDS = ("select", "insert", "update", "delete")
# words that stand for a condition in permissions and rules: a user signed in, anyone signed in or not, nobody
KEYWORDS = {"signed_in": "authz.uid() IS NOT NULL", "anyone": "true", "nobody": "false"}
# words that join expressions or continue a line: never a name
RESERVED = ("or", "and", "not", "if", "where")
# in a permission, where a custom role that includes it gives it: `can edit = editor or roles`
ROLES = "roles"


class PolicyError(Exception):
    """A mistake in a policy: 'line 12: message [AZ201]'. code is the mistake's stable code (authzlib/errors.py,
    a page in docs/errors/, `rowstile help AZ201`)."""

    def __init__(self, message: str, code: str | None = None) -> None:
        super().__init__(f"{message} [{code}]" if code else message)
        self.code = code


class Loc:
    """Where something was written: 'line 12', or 'roles.authz line 3' for included files."""

    def __init__(self, file: str | None, line: int) -> None:
        self.file, self.line = file, line

    def __str__(self) -> str:
        return f"line {self.line}" if self.file is None else f"{self.file} line {self.line}"

    def __lt__(self, other: Loc) -> bool:
        return (self.file or "", self.line) < (other.file or "", other.line)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Loc) and (self.file, self.line) == (other.file, other.line)

    def __hash__(self) -> int:
        return hash((self.file, self.line))


def fail(loc: Loc | int | str, msg: str, code: str) -> NoReturn:
    raise PolicyError(f"{loc if isinstance(loc, Loc) else f'line {loc}'}: {msg}", code)


# --- expressions: what a permission, a rule or an invariant says -----------------------------------
# Each is a tuple whose first item names its kind, so code may still take one apart by index; new code
# matches on the class.
class Or(NamedTuple):
    kind: Literal["or"]
    items: list[Expr]


class And(NamedTuple):
    kind: Literal["and"]
    items: list[Expr]


class Not(NamedTuple):
    kind: Literal["not"]
    item: Expr


class Cond(NamedTuple):
    """{sql}: a condition on the row, or a keyword standing for one (signed_in, anyone, nobody)."""

    kind: Literal["cond"]
    sql: str


class Ref(NamedTuple):
    """A relation or permission of the same object."""

    kind: Literal["ref"]
    name: str


class Arrow(NamedTuple):
    """relation.permission: the permission on what the relation links to."""

    kind: Literal["arrow"]
    rel: str
    perm: str


class ArrowOn(NamedTuple):
    """An arrow followed only to some of the relation's subject types (made by the compiler)."""

    kind: Literal["arrow_on"]
    rel: str
    perm: str
    types: tuple[str, ...]


Expr: TypeAlias = "Or | And | Not | Cond | Ref | Arrow | ArrowOn"
# a source's column: one, or the columns of a composite key
Cols: TypeAlias = "str | tuple[str, ...]"
# who a relation links to: (type, relation or None); ('user', '*') is any principal of the type, and
# ('anyone', None) and ('link', None) stand alone
Subject: TypeAlias = "tuple[str, str | None]"


@dataclass
class Source:
    kind: str  # column | table | shared | roles
    subjects: list[Subject]
    loc: Loc
    column: Cols | None = None  # column source: the id column (a tuple for [a, b]: a composite key)
    type_col: str | None = None  # polymorphic: the column holding the subject's type name
    table: str | None = None  # table source
    obj_col: Cols | None = None
    subj_col: Cols | None = None
    where: str | None = None
    shared_by: str | None = None  # shared: the permission needed to share it (default: share)
    shared_if: str | None = None  # shared: extra SQL condition on each share
    perm: str | None = None  # roles: the permission these role assignments grant
    owner: str | None = None  # roles: the relation naming the object's owner, whose roles alone count here


@dataclass
class Relation:
    name: str
    loc: Loc
    sources: list[Source] = field(default_factory=list)
    synthetic: bool = False  # made by the compiler (custom roles)

    def subjects(self) -> list[Subject]:
        return list(dict.fromkeys(s for src in self.sources for s in src.subjects))


@dataclass
class Perm:
    name: str
    expr: Expr
    src: str
    loc: Loc
    hidden: bool = False  # made by the compiler (the inheritance of a permission with a deny)
    base: str | None = None  # for such a permission: the hidden one holding its inheritance


# custom roles: (who may hold them, the permissions that write `roles`, where the roles line is)
Roles: TypeAlias = "tuple[list[Subject], list[str], Loc]"


@dataclass
class Type:
    name: str
    table: str
    pk: str | None  # the key column; None for a composite key
    pktype: str  # its type; text for a composite key (ids are its canonical row text)
    loc: Loc
    where: str | None = None  # rows that fail it hold nothing, and nothing passes through them
    relations: dict[str, Relation] = field(default_factory=dict)
    perms: dict[str, Perm] = field(default_factory=dict)
    roles: Roles | None = None
    roles_from: str | None = None  # `roles : ... from org`: only roles owned by the object's org count
    key: list[tuple[str, str]] = field(default_factory=list)  # [(column, type)]: several for a composite key
    principal: bool = False  # signs in and holds access itself (the user type, and `principal` types)

    @property
    def composite(self) -> bool:
        return len(self.key) > 1

    @property
    def keytype(self) -> str:
        """What a text id is parsed as: the key's type, or the row type made for a composite key."""
        return f'authz_gen."{self.name}__key"' if self.composite else self.pktype


def cols(c: Cols) -> tuple[str, ...]:
    """A source's column(s) as a tuple."""
    return c if isinstance(c, tuple) else (c,)


@dataclass
class Rule:
    table: str
    command: str  # select | insert | update | update check (written "after") | delete | mask
    expr: Expr
    src: str
    loc: Loc
    columns: tuple[str, ...] = ()  # update rules on changed columns; mask rules: the masked columns


@dataclass
class Step:
    """One line of a named test: given (data), check (can/cannot) or as (a statement as someone)."""

    kind: str  # given | check | as
    text: str
    loc: Loc
    var: str | None = None  # given: the $name it binds
    sql: str | None = None  # given, as: the statement
    ptype: str | None = None  # check, as: the principal type, or 'anyone'
    who: str | None = None  # check, as: an id or a $name
    expect: bool | str | int | None = None  # check: True (can) / False; as: 'allowed' | 'refused' | a row count
    perm: str | None = None
    type: str | None = None
    obj: str | None = None  # check: an id or a $name
    scopes: tuple[str, ...] = ()  # check, as: `with scope a, b`: signed in limited to them, as a key with them is


@dataclass
class Scenario:
    """test "name": its own data (given), then checks; rolled back when it ends."""

    name: str
    loc: Loc | None  # None: the unnamed test section, gathered from its lines
    steps: list[Step] = field(default_factory=list)


# a scope's item: ('cmd' | 'perm', qualifier or None, name)
ScopeItem: TypeAlias = "tuple[str, str | None, str]"


@dataclass
class Scope:
    name: str
    items: list[ScopeItem]
    loc: Loc


@dataclass
class Caveat:
    name: str
    sql: str
    loc: Loc


@dataclass
class Invariant:
    type: str
    expr: Expr
    src: str
    loc: Loc


@dataclass
class Policy:
    role: str | None = None  # the app role (`app role app_user`): the Postgres role the rules apply to
    types: dict[str, Type] = field(default_factory=dict)
    rules: list[Rule] = field(default_factory=list)
    tests: list[Step] = field(default_factory=list)  # the unnamed test section: checks of the data there
    scenarios: list[Scenario] = field(default_factory=list)
    scopes: dict[str, Scope] = field(default_factory=dict)
    caveats: dict[str, Caveat] = field(default_factory=dict)
    invariants: list[Invariant] = field(default_factory=list)
    views: dict[str, str] = field(default_factory=dict)  # rules table -> masked view name
    view_locs: dict[str, Loc] = field(default_factory=dict)  # rules table -> where the view was named


# ----------------------------------------------------------------------
# Lines and expressions
# ----------------------------------------------------------------------
def strip_comment(line: str) -> str:
    """Drop a trailing -- comment, but not inside quotes ('...' or "..."). Inside {...} it is an SQL comment,
    which also runs to the end of the line: dropped too, as the lines of a condition are joined into one."""
    quote = ""
    for i, c in enumerate(line):
        if quote:
            if c == quote:
                quote = ""
        elif c in "'\"":
            quote = c
        elif c == "-" and line[i : i + 2] == "--":
            return line[:i]
    return line


Token: TypeAlias = "tuple[str, str]"


def tokenize(s: str, loc: Loc) -> list[Token]:
    toks: list[Token] = []
    i = 0
    while i < len(s):
        c = s[i]
        if c.isspace():
            i += 1
        elif c == "{":
            depth, j, quote = 0, i, False
            while j < len(s):
                ch = s[j]
                if quote:
                    if ch == "'":
                        quote = False
                elif ch == "'":
                    quote = True
                elif ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
                    if depth == 0:
                        break
                j += 1
            else:
                fail(loc, "a { condition is missing its closing }", "AZ102")
            sql = s[i + 1 : j].strip()
            if not sql:
                fail(loc, "empty {} condition", "AZ102")
            toks.append(("cond", sql))
            i = j + 1
        elif c in "()":
            toks.append((c, c))
            i += 1
        else:
            m = re.match(rf"{IDENT}(\.{IDENT})?", s[i:])
            if not m:
                # a character that doesn't print (a stray control character) is shown escaped, or the message
                # would show nothing between its quotes
                shown = c if c.isprintable() else c.encode("unicode_escape").decode("ascii")
                fail(loc, f"unexpected '{shown}' in expression", "AZ102")
            w = m.group(0)
            toks.append((w, w) if w in ("or", "and", "not") else ("name", w))
            i += len(w)
    return toks


def written(node: Expr, top: bool = True) -> str:
    """An expression as a policy writes it, with parentheses around each `and` and `or` inside another."""
    match node:
        case Or(items=items) | And(items=items):
            s = f" {node.kind} ".join(written(x, False) for x in items)
            return s if top else f"({s})"
        case Not(item=item):
            return "not " + written(item, False)
        case Cond(sql=sql):
            return next((w for w, s in KEYWORDS.items() if s == sql), "{" + sql + "}")
        case Ref(name=name):
            return name
        case _:  # an arrow, or one the compiler narrowed to some of its types
            return f"{node.rel}.{node.perm}"


class ExprParser:
    """or  <  and  <  not  <  ( ) / name / rel.perm / {sql}. Where `and` and `or` meet, parentheses say which
    goes first: `a or b and c` is refused, `a or (b and c)` is not."""

    def __init__(self, text: str, loc: Loc) -> None:
        self.toks, self.i, self.loc = tokenize(text, loc), 0, loc
        self.joined = False  # whether the last `and` read joined two items or more, outside parentheses

    def peek(self) -> str | None:
        return self.toks[self.i][0] if self.i < len(self.toks) else None

    def take(self) -> Token:
        tok = self.toks[self.i]
        self.i += 1
        return tok

    def parse(self) -> Expr:
        # (never given an empty one: the lines it reads end in what follows `=` or `:`, which isn't blank)
        e = self.or_()
        if self.i < len(self.toks):
            fail(self.loc, f"unexpected '{self.toks[self.i][1]}'", "AZ102")
        return e

    def or_(self) -> Expr:
        items = [self.and_()]
        mixed = self.joined
        while self.peek() == "or":
            self.take()
            items.append(self.and_())
            mixed = mixed or self.joined
        if len(items) == 1:
            return items[0]
        node = Or("or", items)
        if mixed:
            fail(
                self.loc,
                f"`and` and `or` meet without parentheses, which reads two ways: write {written(node)}",
                "AZ102",
            )
        return node

    def and_(self) -> Expr:
        items = [self.unary()]
        while self.peek() == "and":
            self.take()
            items.append(self.unary())
        self.joined = len(items) > 1
        return items[0] if len(items) == 1 else And("and", items)

    def unary(self) -> Expr:
        kind = self.peek()
        if kind is None:
            fail(self.loc, "expression ends too early", "AZ102")
        if kind == "not":
            self.take()
            return Not("not", self.unary())
        if kind == "(":
            self.take()
            e = self.or_()
            if self.peek() != ")":
                fail(self.loc, "missing )", "AZ102")
            self.take()
            return e
        if kind == "cond":
            return Cond("cond", self.take()[1])
        if kind == "name":
            w = self.take()[1]
            if w in KEYWORDS:
                return Cond("cond", KEYWORDS[w])
            if "__" in w:
                fail(self.loc, f"'{w}': names with '__' are generated ones, which a policy can't refer to", "AZ107")
            if "." in w:
                rel, perm = w.split(".")
                return Arrow("arrow", rel, perm)
            return Ref("ref", w)
        fail(self.loc, f"unexpected '{self.toks[self.i][1]}'", "AZ102")


def check_name(name: str, loc: Loc) -> str:
    if "__" in name:
        fail(loc, f"'{name}': names can't contain '__' (generated names use it as a separator)", "AZ107")
    if name in RESERVED or name in KEYWORDS:
        fail(loc, f"'{name}' is a word of the language; choose another name", "AZ107")
    return name


Line: TypeAlias = "tuple[Loc, int, str]"
# an include line, as the readers of included files see it (at the start of a line, maybe a comment after)
INCLUDE = re.compile(r'include\s+"([^"]+)"\s*(?:--.*)?')


def include_name(including: str, name: str) -> str | None:
    """An included file's name relative to the policy's folder ('sub/roles.authz'), from the name written in
    the file that includes it; None when it would leave the policy's folder (an absolute path, a drive, a
    backslash, '..' out of the folder). Nothing outside the policy's folder is ever read."""
    if name.startswith("/") or "\\" in name or re.match(r"[A-Za-z]:", name):
        return None
    key = posixpath.normpath(posixpath.join(posixpath.dirname(including), name))
    return None if key == ".." or key.startswith("../") else key


def collect_includes(text: str, read: Callable[[str], str | None]) -> dict[str, str]:
    """Every file the policy includes (name relative to its folder -> text), each read once with read(name),
    None when it is missing. Names that leave the policy's folder are never read: the compiler refuses them."""
    files: dict[str, str] = {}
    todo = [("", text)]
    while todo:
        including, body = todo.pop()
        for line in body.split("\n"):
            m = INCLUDE.fullmatch(line.rstrip())
            key = include_name(including, m.group(1)) if m else None
            if key is None or key in files:
                continue  # the compiler reports files included twice, with the line
            got = read(key)
            if got is None:
                continue  # ... and files that are missing
            files[key] = got
            todo.append((key, got))
    return files


def within(top: str, path: str) -> bool:
    """Whether a resolved path is the folder top or inside it. A path on another drive (Windows: a link or a
    junction to D:) is outside: commonpath raises for two drives."""
    try:
        return os.path.commonpath([top, path]) == top
    except ValueError:
        return False


def disk_reader(folder: str) -> Callable[[str], str | None]:
    """read(name) for collect_includes: the file in folder (UTF-8), None when it is missing or, through a
    symbolic link, outside the folder."""
    top = os.path.realpath(folder)

    def read(name: str) -> str | None:
        path = os.path.join(top, *name.split("/"))
        if not within(top, os.path.realpath(path)):
            return None
        try:
            with open(path, encoding="utf-8") as fh:
                return fh.read()
        except (OSError, UnicodeDecodeError):
            return None

    return read


def read_lines(
    path: str | None, text: str, seen: set[str] | None = None, top: bool = True, files: dict[str, str] | None = None
) -> list[Line]:
    """Logical lines (loc, indent, text), with includes expanded. A line starting
    with 'or'/'and' continues the previous one. Includes are looked up in `files` (name -> text),
    relative to the including file, and never on disk."""
    seen = seen or set()
    files = files or {}
    name = None if top else path
    out: list[Line] = []
    for n, raw in enumerate(text.removeprefix("﻿").split("\n"), 1):
        loc = Loc(name, n)
        line = strip_comment(raw).rstrip()
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip())
        s = line.strip()
        m = re.fullmatch(r'include\s+"([^"]+)"', s)
        if m and indent == 0:
            inc = include_name(name or "", m.group(1))
            if inc is None:
                fail(
                    loc,
                    f"{m.group(1)}: an included file is in the policy's folder or below it, "
                    f"named with / and without .. out of the folder",
                    "AZ108",
                )
            if inc in seen:
                fail(loc, f"{m.group(1)} is included twice (or includes itself)", "AZ108")
            if inc not in files:
                fail(
                    loc,
                    f'can\'t find {m.group(1)}: pass it in the files argument, e.g. \'{{"{inc}": "..."}}\'',
                    "AZ108",
                )
            seen.add(inc)
            out += read_lines(inc, files[inc], seen, top=False, files=files)
            continue
        # ('where : user = ...' declares a relation named where, which check_name refuses: not a continuation)
        if out and (re.match(r"(or|and|if|where)\b(?!\s*:)", s) or open_braces(out[-1][2]) > 0):
            last = out[-1]
            out[-1] = (last[0], last[1], last[2] + " " + s)
        else:
            out.append((loc, indent, s))
    return out


def meaning_lines(policy: str, files: dict[str, str] | None) -> list[str]:
    """The policy's declarations, one per line, whitespace and comments aside; lines in a block say
    which block ('type folder: can edit = owner or parent.edit'). Tests are left out: they make nothing.
    What the lock file holds (migrate.py), and what rowstile fmt must not change (here: fmt imports no compiler)."""
    out: list[str] = []
    block: str | None = None
    skip = False
    for _, indent, s in read_lines(None, policy, files=files or {}):
        s = " ".join(s.split())
        if indent == 0:
            skip = s == "test" or s.startswith("test ")
            m = re.match(r"(type\s+\w+|rules\s+\S+|invariants)", s)
            block = m.group(1) if m else None
            if not skip:
                out.append(s)
        elif not skip:
            out.append(f"{block}: {s}" if block else s)
    return out


def braced(text: str) -> list[str]:
    """The SQL inside each top-level {...} of a line (quoted strings kept whole)."""
    out: list[str] = []
    depth, quote, cur = 0, False, ""
    for c in text:
        if depth and not (c == "}" and depth == 1 and not quote):
            cur += c
        if quote:
            quote = c != "'"
        elif c == "'":
            quote = True
        elif c == "{":
            depth += 1
        elif c == "}" and depth:
            depth -= 1
            if not depth:
                out.append(cur)
                cur = ""
    return out


# a dollar-quote tag ($f$, $body$): the generated functions' bodies are quoted with such tags, so one in a
# condition would end the body it is placed in ('$$' is fine: no body uses it around a condition)
DOLLAR_TAG = re.compile(r"\$[A-Za-z_][A-Za-z0-9_]*\$")


def open_braces(text: str) -> int:
    """How many { are still open at the end of text (ignoring quoted strings)."""
    depth, quote = 0, False
    for c in text:
        if quote:
            quote = c != "'"
        elif c == "'":
            quote = True
        elif c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
    return depth


# ----------------------------------------------------------------------
# The policy file
# ----------------------------------------------------------------------
TYPE_RE = re.compile(
    rf"type\s+({IDENT})\s*=\s*({QNAME})(?:\s*\(([^)]*)\))?(\s+principal)?"
    rf"(?:\s+where\s*\{{(.*)\}})?"
)
# one column, or [a, b] for the columns of a composite key
COLS = rf"(?:{IDENT}|\[\s*{IDENT}(?:\s*,\s*{IDENT})*\s*\])"
# composite keys are compared as text: only types whose text form is canonical
KEY_TYPES = ("bigint", "int8", "integer", "int", "int4", "smallint", "int2", "text", "uuid", "varchar")


def parse_key(text: str | None, loc: Loc) -> list[tuple[str, str]]:
    """(id uuid) or (org_id, id) or (org_id bigint, id uuid) -> [(column, type)]"""
    if text is None:
        return [("id", "bigint")]
    key: list[tuple[str, str]] = []
    for part in text.split(","):
        m = re.fullmatch(rf"\s*({IDENT})(?:\s+({IDENT}))?\s*", part)
        if not m:
            fail(loc, "write the key as (column [type]), or (col1 [type], col2 [type]) for a composite key", "AZ206")
        key.append((m.group(1), (m.group(2) or "bigint").lower()))
    if len({c for c, _ in key}) != len(key):
        fail(loc, "a key column is named twice", "AZ206")
    if len(key) > 1:
        for c, ty in key:
            if ty not in KEY_TYPES:
                fail(
                    loc,
                    f"{c} is {ty}: a composite key's columns must be integers, text or uuid "
                    f"(ids are compared as text, which must not depend on settings)",
                    "AZ206",
                )
    return key


def parse_cols(text: str) -> Cols:
    """'col' -> 'col'; '[a, b]' -> ('a', 'b')"""
    text = text.strip()
    if text.startswith("["):
        return tuple(c.strip() for c in text[1:-1].split(","))
    return text


def parse_subjects(text: str, loc: Loc) -> list[Subject]:
    subjects: list[Subject] = []
    for part in [p.strip() for p in text.split(",")]:
        if part in ("anyone", "link"):
            subjects.append((part, None))
            continue
        wild = re.fullmatch(rf"({IDENT}):\*", part)
        if wild:  # any signed-in principal of that type (user:*, service:*)
            subjects.append((wild.group(1), "*"))
            continue
        sm = re.fullmatch(rf"({IDENT})(?:#({IDENT}))?", part)
        if not sm:
            fail(
                loc,
                f"bad subject '{part}' (use a type, type#relation, user:* or another type:*, anyone or link)",
                "AZ103",
            )
        if sm.group(1) in ("anyone", "link"):
            fail(loc, f"bad subject '{part}': {sm.group(1)} stands alone, without #relation", "AZ204")
        subjects.append((sm.group(1), sm.group(2)))
    return subjects


def parse_source(text: str, subjects: list[Subject], loc: Loc) -> Source:
    """= column | (type_col, id_col) | schema.table(obj -> subj) | schema.table(object: obj, subject: subj) [where {sql}]
    | schema.table(obj -> (type_col, id_col)) [where {sql}]; a column may be [a, b], the columns of a composite key"""
    text = text.strip()
    if re.fullmatch(COLS, text):
        return Source("column", subjects, loc, column=parse_cols(text))
    m = re.fullmatch(rf"\(\s*({IDENT})\s*,\s*({COLS})\s*\)", text)
    if m:
        return Source("column", subjects, loc, type_col=m.group(1), column=parse_cols(m.group(2)))
    m = re.fullmatch(
        rf"({QNAME})\s*\(\s*({COLS})\s*->\s*(?:({COLS})|\(\s*({IDENT})\s*,\s*({COLS})\s*\))\s*\)"
        rf"\s*(?:where\s*\{{(.*)\}})?",
        text,
    )
    if m:
        return Source(
            "table",
            subjects,
            loc,
            table=m.group(1),
            obj_col=parse_cols(m.group(2)),
            subj_col=parse_cols(m.group(3) or m.group(5)),
            type_col=m.group(4),
            where=m.group(6),
        )
    # the same with the columns named, in either order: schema.table(object: col, subject: col)
    side = rf"(object|subject)\s*:\s*(?:({COLS})|\(\s*({IDENT})\s*,\s*({COLS})\s*\))"
    m = re.fullmatch(rf"({QNAME})\s*\(\s*{side}\s*,\s*{side}\s*\)\s*(?:where\s*\{{(.*)\}})?", text)
    if m:
        sides = {m.group(2): m.group(3, 4, 5), m.group(6): m.group(7, 8, 9)}
        if set(sides) != {"object", "subject"}:
            fail(
                loc,
                "name one 'object' column and one 'subject' column: schema.table(object: col, subject: col)",
                "AZ103",
            )
        obj, subj = sides["object"], sides["subject"]
        if obj[0] is None:
            fail(loc, "the object side is one column: schema.table(object: col, subject: (type_col, id_col))", "AZ103")
        return Source(
            "table",
            subjects,
            loc,
            table=m.group(1),
            obj_col=parse_cols(obj[0]),
            subj_col=parse_cols(subj[0] or subj[2]),
            type_col=subj[1],
            where=m.group(10),
        )
    fail(
        loc,
        "a source is a column, (type_col, id_col), schema.table(this_col -> subject_col) "
        "or schema.table(object: col, subject: col) [where {sql}], or 'shared'",
        "AZ103",
    )


def parse_policy(text: str, path: str | None = None, files: dict[str, str] | None = None) -> Policy:
    pol = Policy()
    section: str | None = None
    # the block the indented lines below belong to
    cur_type: Type | None = None
    cur_table: str | None = None
    cur_test: Scenario | None = None
    if files is None:  # included files read from disk, next to the policy file (or here)
        files = collect_includes(text, disk_reader(os.path.dirname(path) if path else "."))
    for loc, indent, s in read_lines(path, text, files=files):
        for sql in braced(s):
            tag = DOLLAR_TAG.search(sql)
            if tag:
                fail(
                    loc,
                    f"{{{sql.strip()}}} contains {tag.group(0)}, which ends the generated function it goes "
                    f"in: write the text another way ('$' || 'f$')",
                    "AZ110",
                )
        if indent == 0:
            m_type = TYPE_RE.fullmatch(s)
            m_rules = re.fullmatch(rf"rules\s+({QNAME})(?:\s+view\s+({QNAME}))?", s)
            m_role = re.fullmatch(rf"app\s+role\s+({IDENT})", s)
            m_scope = re.fullmatch(rf"scope\s+({IDENT}(?:[-:]{IDENT})*)\s*=\s*(.+)", s)
            m_caveat = re.fullmatch(rf"caveat\s+({IDENT})\s*=\s*\{{(.*)\}}", s)
            if m_type:
                name = m_type.group(1)
                if name in ("anyone", "link"):
                    fail(
                        loc,
                        f"'{name}' is a subject of its own (shared with {name}); name the type differently",
                        "AZ204",
                    )
                check_name(name, loc)
                if name in pol.types:
                    fail(loc, f"type {name} is defined twice", "AZ109")
                key = parse_key(m_type.group(3), loc)
                composite = len(key) > 1
                cur_type = pol.types[name] = Type(
                    name,
                    m_type.group(2),
                    None if composite else key[0][0],
                    "text" if composite else key[0][1],
                    loc,
                    where=m_type.group(5),
                    key=key,
                    principal=bool(m_type.group(4)) or name == "user",
                )
                section = "type"
            elif m_rules:
                section, cur_table = "rules", m_rules.group(1)
                if m_rules.group(2):
                    if cur_table in pol.views and pol.views[cur_table] != m_rules.group(2):
                        fail(loc, f"{cur_table} already has the view {pol.views[cur_table]}", "AZ109")
                    pol.views[cur_table] = m_rules.group(2)
                    pol.view_locs[cur_table] = loc
            elif s == "test":
                section = "test"
            elif re.fullmatch(r"test\s+\S.*", s):
                name = s[4:].strip()
                if len(name) > 1 and name[0] == name[-1] and name[0] in "\"'":
                    name = name[1:-1]
                if any(sc.name == name for sc in pol.scenarios):
                    fail(loc, f"there is already a test named {name!r}", "AZ109")
                cur_test = Scenario(name, loc)
                pol.scenarios.append(cur_test)
                section = "scenario"
            elif s == "invariants":
                section = "invariants"
            elif m_role:
                role = m_role.group(1)
                if pol.role is not None:
                    fail(loc, f"the app role is named twice ({pol.role} and {role}): a policy applies to one", "AZ109")
                if role.lower() == "public":
                    fail(
                        loc,
                        "the app role is the one role your app connects as, not PUBLIC (every role in the "
                        "database could then sign in as anyone)",
                        "AZ111",
                    )
                pol.role = role
                section = None
            elif m_scope:
                pol.scopes[m_scope.group(1)] = Scope(m_scope.group(1), parse_scope_items(m_scope.group(2), loc), loc)
                section = None
            elif m_caveat:
                if m_caveat.group(1) in pol.caveats:
                    fail(loc, f"caveat {m_caveat.group(1)} is defined twice", "AZ109")
                pol.caveats[m_caveat.group(1)] = Caveat(m_caveat.group(1), m_caveat.group(2).strip(), loc)
                section = None
            else:
                fail(
                    loc,
                    f"expected 'app role', 'type', 'rules', 'scope', 'caveat', 'invariants', 'test', "
                    f"'test \"name\"' or 'include', got: {s}",
                    "AZ101",
                )
            continue

        if section == "type" and cur_type is not None:
            parse_type_line(cur_type, s, loc)
        elif section == "rules" and cur_table is not None:
            parse_rule_line(pol, cur_table, s, loc)
        elif section == "test":
            # the same checks as a named test's: user 3 can view file 11, service 2 cannot ..., anyone can ...
            step = parse_step(s, loc) if re.match(r"(given|as)\b", s) is None else None
            if step is None or step.kind != "check":
                fail(
                    loc,
                    "the test section checks the data already there, as: user 3 can view file 11 (a test "
                    'that brings its own data, or runs a statement, is named: test "...")',
                    "AZ106",
                )
            pol.tests.append(step)
        elif section == "scenario" and cur_test is not None:
            cur_test.steps.append(parse_step(s, loc))
        elif section == "invariants":
            m = re.fullmatch(rf"never\s+({IDENT})\s*:\s*(.+)", s)
            if not m:
                fail(loc, "write invariants as: never file: view and not folder.in_org", "AZ106")
            pol.invariants.append(Invariant(m.group(1), ExprParser(m.group(2), loc).parse(), m.group(2), loc))
        else:
            fail(loc, "indented line outside a type, rules, invariants or test block", "AZ101")
    for sc in pol.scenarios:
        if not sc.steps:
            fail(sc.loc or 0, f"test {sc.name!r} has no lines", "AZ106")
    for t in pol.types.values():
        if t.roles:
            t.roles = (t.roles[0], granted_by_roles(t), t.roles[2])
    return pol


VALUE = r"(\$[A-Za-z_][A-Za-z0-9_]*|'(?:[^']|'')*'|[^\s{}']+)"
# after who a line is about: `with scope read` or `with scope read, files`
WITH_SCOPE = rf"(?:\s+with\s+scope\s+({IDENT}(?:\s*,\s*{IDENT})*))?"


def value(v: str) -> str:
    """A test's id: $name as written, a quoted literal unquoted, anything else as is."""
    return v[1:-1].replace("''", "'") if v.startswith("'") else v


def scopes_of(text: str | None) -> tuple[str, ...]:
    return tuple(x.strip() for x in text.split(",")) if text else ()


def parse_step(s: str, loc: Loc) -> Step:
    m = re.fullmatch(rf"given\s+(?:({IDENT})\s*=\s*)?\{{(.*)\}}", s, re.S)
    if m:
        if not m.group(2).strip():
            fail(loc, "given {...} needs a statement", "AZ106")
        return Step("given", s, loc, var=m.group(1), sql=m.group(2).strip())
    m = re.fullmatch(
        rf"as\s+(?:(anyone)|({IDENT})\s+{VALUE}{WITH_SCOPE})\s+(allowed|refused|sees\s+(\d+))\s*\{{(.*)\}}", s, re.S
    )
    if m:
        expect: str | int = int(m.group(6)) if m.group(6) else m.group(5)
        if not m.group(7).strip():
            fail(loc, "as ... {...} needs a statement", "AZ106")
        # `sees N` counts the rows of a query, which a write can't be put inside: at run time that was a bare
        # "syntax error" from Postgres
        if isinstance(expect, int) and re.match(r"\s*(insert|update|delete|merge)\b", m.group(7), re.I):
            fail(
                loc,
                "`sees N` counts the rows of a SELECT, and this statement writes: for a write that must change "
                "no row, write `as ... refused {...}` (a write that changes no row is refused)",
                "AZ106",
            )
        return Step(
            "as",
            s,
            loc,
            ptype=m.group(1) or m.group(2),
            who=None if m.group(1) else value(m.group(3)),
            expect=expect,
            sql=m.group(7).strip(),
            scopes=scopes_of(m.group(4)),
        )
    m = re.fullmatch(
        rf"(?:(anyone)|({IDENT})\s+{VALUE}{WITH_SCOPE})\s+(can|cannot)\s+({IDENT})\s+({IDENT})\s+{VALUE}", s
    )
    if m:
        return Step(
            "check",
            s,
            loc,
            ptype=m.group(1) or m.group(2),
            who=None if m.group(1) else value(m.group(3)),
            expect=m.group(5) == "can",
            perm=m.group(6),
            type=m.group(7),
            obj=value(m.group(8)),
            scopes=scopes_of(m.group(4)),
        )
    if re.match(r"(?:as\s+)?anyone\s+with\b", s):
        fail(
            loc,
            "`anyone` is nobody signed in, and a scope limits someone who is: write `user 3 with scope read ...`",
            "AZ106",
        )
    fail(
        loc,
        "a test's lines are: given name = {INSERT ... RETURNING id}, user $name can view file $f, "
        "or as user $name allowed|refused|sees N {SQL} (after who: `with scope read`, to check as a key limited "
        "to a scope)",
        "AZ106",
    )


def parse_scope_items(text: str, loc: Loc) -> list[ScopeItem]:
    items: list[ScopeItem] = []
    for part in [p.strip() for p in text.split(",")]:
        m = re.fullmatch(rf"(?:({QNAME}|{IDENT})\.)?({IDENT})", part)
        if not m:
            fail(loc, f"bad scope item '{part}' (use select, view, app.files.update or file.edit)", "AZ404")
        qual, word = m.group(1), m.group(2)
        if "__" in word:
            fail(loc, f"'{part}': names with '__' are generated ones, which a policy can't refer to", "AZ107")
        kind = "cmd" if word in COMMANDS else "perm"
        if kind == "cmd" and qual and "." not in qual:
            fail(loc, f"'{part}': commands are qualified by a table, e.g. app.files.{word}", "AZ404")
        if kind == "perm" and qual and "." in qual:
            fail(loc, f"'{part}': permissions are qualified by a type, e.g. file.{word}", "AZ404")
        items.append((kind, qual, word))
    return items


def parse_roles_line(t: Type, s: str, loc: Loc) -> None:
    """`roles : user, team#member [from org]`: who may hold the type's custom roles, and with `from`, whose roles
    count on an object. Which permissions a role may give is where the permissions write `roles`."""
    if re.fullmatch(r"roles\s*:\s*[^=]*(=|\s+shared\b).*", s):
        fail(loc, "`roles : ...` says who may hold custom roles; name the relation something else", "AZ107")
    m = re.fullmatch(rf"roles\s*:\s*(.+?)(?:\s+from\s+({IDENT}))?", s)
    if not m:
        fail(loc, "write custom roles as: roles : user, team#member [from org]", "AZ103")
    if t.roles:
        fail(loc, f"{t.name} declares custom roles twice", "AZ109")
    t.roles_from = m.group(2)
    t.roles = (parse_subjects(m.group(1), loc), [], loc)


def names_roles(node: Expr, under_not: bool = False) -> list[bool]:
    """For each `roles` in an expression: whether a `not` is above it."""
    match node:
        case Ref(name=name) if name == ROLES:
            return [under_not]
        case Not(item=item):
            return names_roles(item, True)
        case Or(items=items) | And(items=items):
            return [x for item in items for x in names_roles(item, under_not)]
    return []


def granted_by_roles(t: Type) -> list[str]:
    """The permissions of t a custom role may give: those that write `roles` (not under a `not`)."""
    return [name for name, p in t.perms.items() if any(not neg for neg in names_roles(p.expr))]


def parse_type_line(t: Type, s: str, loc: Loc) -> None:
    if s.startswith("can "):
        m = re.fullmatch(rf"can\s+({IDENT})\s*=\s*(.+)", s)
        if not m:
            fail(loc, "write permissions as: can name = expression", "AZ104")
        name = check_name(m.group(1), loc)
        if name in t.perms or name in t.relations:
            fail(loc, f"{t.name}.{name} is defined twice", "AZ109")
        if name in COMMANDS:
            fail(loc, f"'{name}' is a command name; call the permission something else", "AZ107")
        if name == ROLES:
            fail(
                loc,
                f"'{ROLES}' is where custom roles give a permission (`can edit = editor or roles`); call the "
                f"permission something else",
                "AZ107",
            )
        t.perms[name] = Perm(name, ExprParser(m.group(2), loc).parse(), m.group(2), loc)
        return
    if re.match(r"roles\s*:", s):
        parse_roles_line(t, s, loc)
        return
    m = re.fullmatch(
        rf"({IDENT})\s*:\s*([^=]+?)\s*(?:=\s*(.+)|\s+shared(?:\s+by\s+({IDENT}))?(?:\s+if\s*\{{(.*)\}})?)", s
    )
    if not m:
        fail(
            loc,
            "write relations as: name : subject = source   (or: name : subjects shared [by perm] [if {sql}])",
            "AZ103",
        )
    name, subj_txt, source = check_name(m.group(1), loc), m.group(2), m.group(3)
    if name in t.perms:
        fail(loc, f"{t.name}.{name} is already a permission", "AZ109")
    subjects = parse_subjects(subj_txt, loc)
    if source is None:
        src = Source("shared", subjects, loc, shared_by=m.group(4), shared_if=m.group(5))
    else:
        src = parse_source(source, subjects, loc)
        if any(sr == "*" or st in ("anyone", "link") for st, sr in subjects):
            fail(loc, "user:* (or another type:*), anyone and link can only be used with 'shared'", "AZ204")
        if src.type_col is None and len(subjects) != 1:
            fail(
                loc,
                "a column or table source links to exactly one kind of subject; "
                "for several, add a type column: (type_col, id_col)",
                "AZ205",
            )
        if src.type_col is not None and any(sr for _, sr in subjects):
            fail(loc, "a (type_col, id_col) source links to objects, not groups", "AZ205")
    t.relations.setdefault(name, Relation(name, loc)).sources.append(src)


def parse_rule_line(pol: Policy, table: str, s: str, loc: Loc) -> None:
    head, sep, expr = s.partition(":")
    words = head.split(None, 1)
    if not sep or not words or words[0] not in COMMANDS + ("mask",) or not expr.strip():
        fail(loc, "write rules as: select|insert|update|delete|mask [cols] [before|after] : expression", "AZ105")
    command, rest = words[0], (words[1] if len(words) > 1 else "").strip()
    # which row an update rule checks: the row before the change (the default), or after it
    when = rest.rsplit(None, 1)[-1] if rest else ""
    if when == "check":
        fail(
            loc,
            f"write 'after' instead of 'check' (checked on the row after the change): "
            f"{head.strip()[: -len('check')].strip()} after : ...",
            "AZ105",
        )
    if when == "before" and rest == when:
        fail(
            loc,
            "a plain update rule is checked on the row before and after the change: write 'update : ...' "
            "(a column named before: update before before : ...)",
            "AZ105",
        )
    if when in ("before", "after"):
        rest = rest[: -len(when)].strip()
    else:
        when = ""
    check = when == "after"
    columns = tuple(c.strip() for c in rest.split(",")) if rest else ()
    if command == "mask":
        if not columns or when:
            fail(loc, "write masks as: mask col1, col2 : expression", "AZ105")
    elif (when or columns) and command != "update":
        fail(loc, f"only update rules can name columns, 'before' or 'after' (got: {head.strip()})", "AZ105")
    if any(not re.fullmatch(IDENT, c) for c in columns):
        fail(
            loc, "write column rules as: update col1, col2 : expression   (or: update col after : expression)", "AZ105"
        )
    pol.rules.append(
        Rule(
            table,
            "update check" if check else command,
            ExprParser(expr.strip(), loc).parse(),
            expr.strip(),
            loc,
            columns,
        )
    )
