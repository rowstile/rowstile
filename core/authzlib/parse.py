"""Parsing .authz policy files into a small model."""

from __future__ import annotations

import os
import posixpath
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Literal, NamedTuple, NoReturn, TypeAlias, TypeVar

IDENT = r"[A-Za-z_][A-Za-z0-9_]*"
QNAME = rf"{IDENT}\.{IDENT}"
COMMANDS = ("select", "insert", "update", "delete")
# words that stand for a condition in permissions and rules: a user signed in, anyone signed in or not, nobody
KEYWORDS = {"signed_in": "authz.uid() IS NOT NULL", "anyone": "true", "nobody": "false"}
# words that join expressions or continue a line: never a name
RESERVED = ("or", "and", "not", "if", "where")
# in a permission, where a custom role that includes it gives it: `can edit = editor or roles`
ROLES = "roles"


# where in its file a mistake is: (line, column, end line, end column), lines from 1, columns from 0, the end's
# column after its last character
Span: TypeAlias = "tuple[int, int, int, int]"


class PolicyError(Exception):
    """A mistake in a policy: 'line 12: message [AZ201]'. code is the mistake's stable code (authzlib/errors.py,
    a page in docs/errors/, `rowstile help AZ201`); span, when the parser knows it, the words the mistake is
    about (an editor underlines them; the message names the line alone)."""

    def __init__(self, message: str, code: str | None = None, span: Span | None = None) -> None:
        super().__init__(f"{message} [{code}]" if code else message)
        self.code, self.span = code, span
        # every mistake the parser found in the policy, this one first (it reads on after one)
        self.errors: list[PolicyError] = [self]


class Loc:
    """Where something was written: 'line 12', or 'roles.authz line 3' for included files. For a line the parser
    read, text is the line as it read it, and origin where each of its parts starts, (index in text, line,
    column): a line that goes on over several (`or ...`, an open `{`) is read as one, its parts joined by a space."""

    def __init__(
        self, file: str | None, line: int, text: str = "", origin: list[tuple[int, int, int]] | None = None
    ) -> None:
        self.file, self.line, self.text = file, line, text
        self.origin = origin or []

    def at(self, offset: int) -> tuple[int, int]:
        """The line and column (from 0) in the file of the character at offset in text."""
        line, col = self.line, offset
        for start, n, c in self.origin:
            if start <= offset:
                line, col = n, c + offset - start
        return line, col

    def span(self, start: int, end: int) -> Span | None:
        """Where text[start:end] is in the file; None for a place the parser didn't read."""
        if not self.origin:
            return None
        if end <= start:  # a place, not words (an empty item between two commas): the character there
            start, end = (start, start + 1) if start < len(self.text) else (max(0, start - 1), max(1, start))
        last = self.at(end - 1)
        return (*self.at(start), last[0], last[1] + 1)

    def __str__(self) -> str:
        return f"line {self.line}" if self.file is None else f"{self.file} line {self.line}"

    def __lt__(self, other: Loc) -> bool:
        return (self.file or "", self.line) < (other.file or "", other.line)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Loc) and (self.file, self.line) == (other.file, other.line)

    def __hash__(self) -> int:
        return hash((self.file, self.line))


def fail(loc: Loc | int, msg: str, code: str, at: tuple[int, int] | None = None, span: Span | None = None) -> NoReturn:
    """Raise a policy's mistake, at a line. at: where in the line's text it is (start, end); span: where in the
    file, for words the parser read before (a name the compiler looks up keeps where it was written)."""
    if span is None and at and isinstance(loc, Loc):
        span = loc.span(*at)
    raise PolicyError(f"{loc if isinstance(loc, Loc) else f'line {loc}'}: {msg}", code, span)


def head(span: Span | None, n: int) -> Span | None:
    """The first n characters of words written on one line (`parent` in `parent.view`, `team` in `team#member`)."""
    return None if span is None else (span[0], span[1], span[0], span[1] + n)


def tail(span: Span | None, n: int) -> Span | None:
    """The last n characters of words written on one line (`view` in `parent.view`)."""
    return None if span is None else (span[2], span[3] - n, span[2], span[3])


# --- expressions: what a permission, a rule or an invariant says -----------------------------------
# A class for each kind, which code takes apart with match or isinstance; two of different kinds are never equal.
# A name keeps where it was written (span: None for one the compiler made), which no comparison looks at.
@dataclass(frozen=True)
class Or:
    items: list[Expr]


@dataclass(frozen=True)
class And:
    items: list[Expr]


@dataclass(frozen=True)
class Not:
    item: Expr


@dataclass(frozen=True)
class Cond:
    """{sql}: a condition on the row, or a keyword standing for one (signed_in, anyone, nobody)."""

    sql: str


@dataclass(frozen=True)
class Ref:
    """A relation or permission of the same object."""

    name: str
    span: Span | None = field(default=None, compare=False, repr=False)


@dataclass(frozen=True)
class Arrow:
    """relation.permission: the permission on what the relation links to."""

    rel: str
    perm: str
    span: Span | None = field(default=None, compare=False, repr=False)


@dataclass(frozen=True)
class ArrowOn:
    """An arrow followed only to some of the relation's subject types (made by the compiler)."""

    rel: str
    perm: str
    types: tuple[str, ...]
    span: Span | None = field(default=None, compare=False, repr=False)


Expr: TypeAlias = "Or | And | Not | Cond | Ref | Arrow | ArrowOn"
# a source's column: one, or the columns of a composite key
Cols: TypeAlias = "str | tuple[str, ...]"
# who a relation links to: (type, relation or None); ('user', '*') is any principal of the type, and
# ('anyone', None) and ('link', None) stand alone
Subject: TypeAlias = "tuple[str, str | None]"


# where a relation's links come from: a source of each kind is its own class, told apart by kind (`src.kind ==
# "table"` narrows a Source to a TableSource); spans: where each subject was written, which no comparison looks at
@dataclass(frozen=True)
class ColumnSource:
    """`= owner_id`, or `= (owner_type, owner_id)`: the row's own column says who it links to."""

    subjects: list[Subject]
    loc: Loc
    column: Cols  # the id column (a tuple for [a, b]: a composite key)
    type_col: str | None = None  # polymorphic: the column holding the subject's type name
    spans: tuple[Span | None, ...] = field(default=(), compare=False, repr=False)
    kind: Literal["column"] = field(default="column", init=False)


@dataclass(frozen=True)
class TableSource:
    """`= schema.table(object_col -> subject_col) [where {sql}]`: the rows of a link table."""

    subjects: list[Subject]
    loc: Loc
    table: str
    obj_col: Cols
    subj_col: Cols
    type_col: str | None = None  # polymorphic: the column holding the subject's type name
    where: str | None = None
    spans: tuple[Span | None, ...] = field(default=(), compare=False, repr=False)
    kind: Literal["table"] = field(default="table", init=False)


@dataclass(frozen=True)
class SharedSource:
    """`shared [by perm] [if {sql}]`: the shares made at run time (authz.shares)."""

    subjects: list[Subject]
    loc: Loc
    shared_by: str | None = None  # the permission needed to share it (default: share)
    shared_if: str | None = None  # an SQL condition on each share
    spans: tuple[Span | None, ...] = field(default=(), compare=False, repr=False)
    kind: Literal["shared"] = field(default="shared", init=False)


@dataclass(frozen=True)
class RolesSource:
    """Made by the compiler: the custom roles that give a permission."""

    subjects: list[Subject]
    loc: Loc
    perm: str  # the permission these role assignments give
    owner: str | None = None  # the relation naming the object's owner, whose roles alone count here
    spans: tuple[Span | None, ...] = field(default=(), compare=False, repr=False)  # the roles line's
    kind: Literal["roles"] = field(default="roles", init=False)


Source: TypeAlias = "ColumnSource | TableSource | SharedSource | RolesSource"
# a source whose rows name the subjects in columns (the others are shares)
Link: TypeAlias = "ColumnSource | TableSource"


def subject_spans(src: Source) -> list[Span | None]:
    """Where each of a source's subjects is written (None for a source the compiler made)."""
    return list(src.spans) or [None] * len(src.subjects)


def conditions_of(src: Source) -> list[str]:
    """The SQL conditions a source writes: a link table's `where`, a share's `if`."""
    sql = src.where if src.kind == "table" else src.shared_if if src.kind == "shared" else None
    return [sql] if sql else []


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
    key: list[tuple[str, str]]  # [(column, type)]: several for a composite key
    loc: Loc
    where: str | None = None  # rows that fail it hold nothing, and nothing passes through them
    relations: dict[str, Relation] = field(default_factory=dict)
    perms: dict[str, Perm] = field(default_factory=dict)
    roles: Roles | None = None
    roles_from: str | None = None  # `roles : ... from org`: only roles owned by the object's org count
    roles_spans: tuple[Span | None, ...] = field(default=(), compare=False, repr=False)  # where roles' subjects are
    principal: bool = False  # signs in and holds access itself (the user type, and `principal` types)

    @property
    def composite(self) -> bool:
        return len(self.key) > 1

    @property
    def pk(self) -> str | None:
        """The key column; None for a composite key."""
        return None if self.composite else self.key[0][0]

    @property
    def pktype(self) -> str:
        """The key's type; text for a composite key (ids are its canonical row text)."""
        return "text" if self.composite else self.key[0][1]

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
    command: str  # select | insert | update | update after | delete | mask
    expr: Expr
    src: str
    loc: Loc
    columns: tuple[str, ...] = ()  # update rules on changed columns; mask rules: the masked columns


# the lines of a test: each kind its own class, told apart by kind (`step.kind == "check"` narrows a Step)
@dataclass(frozen=True)
class GivenStep:
    """`given ann = {INSERT ... RETURNING id}`: data a named test brings, and the $name it binds."""

    text: str
    loc: Loc
    sql: str
    var: str | None = None
    kind: Literal["given"] = field(default="given", init=False)


@dataclass(frozen=True)
class CheckStep:
    """`user 3 can view file 11`: whether someone holds a permission on an object."""

    text: str
    loc: Loc
    ptype: str  # the principal type, or 'anyone'
    who: str | None  # an id or a $name (None for anyone)
    expect: bool  # can, or cannot
    perm: str
    type: str
    obj: str  # an id or a $name
    scopes: tuple[str, ...] = ()  # `with scope a, b`: signed in limited to them, as a key with them is
    kind: Literal["check"] = field(default="check", init=False)


@dataclass(frozen=True)
class AsStep:
    """`as user $ann refused {UPDATE ...}`: a statement run as someone, and what it does."""

    text: str
    loc: Loc
    ptype: str  # the principal type, or 'anyone'
    who: str | None  # an id or a $name (None for anyone)
    expect: str | int  # 'allowed', 'refused', or how many rows the SELECT sees
    sql: str
    scopes: tuple[str, ...] = ()  # `with scope a, b`: signed in limited to them, as a key with them is
    kind: Literal["as"] = field(default="as", init=False)


Step: TypeAlias = "GivenStep | CheckStep | AsStep"


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
    spans: list[Span | None] = field(default_factory=list, compare=False, repr=False)  # where each item is


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
    type_span: Span | None = field(default=None, compare=False, repr=False)


@dataclass
class Policy:
    role: str | None = None  # the app role (`app role app_user`): the Postgres role the rules apply to
    types: dict[str, Type] = field(default_factory=dict)
    rules: list[Rule] = field(default_factory=list)
    tests: list[CheckStep] = field(default_factory=list)  # the unnamed test section: checks of the data there
    scenarios: list[Scenario] = field(default_factory=list)
    scopes: dict[str, Scope] = field(default_factory=dict)
    caveats: dict[str, Caveat] = field(default_factory=dict)
    invariants: list[Invariant] = field(default_factory=list)
    views: dict[str, str] = field(default_factory=dict)  # rules table -> masked view name
    view_locs: dict[str, Loc] = field(default_factory=dict)  # rules table -> where the view was named


# ----------------------------------------------------------------------
# Quotes, braces and comments
# ----------------------------------------------------------------------
class Mark(NamedTuple):
    """What a character of a line is."""

    quoted: bool
    depth: int  # how many {braces} are open around it (a condition's own `{` and `}` are outside it)
    comment: bool  # in a -- comment, which runs to the end of the line


# a dollar quote's tag in SQL: $$, or $name$
DOLLAR_QUOTE = re.compile(r"\$(?:[A-Za-z_][A-Za-z0-9_]*)?\$")
# what may start a quote, open or close a brace, or start a comment: the text between is read in one step
SPECIAL = re.compile(r"""['"{}$]|--""")
# what may start a quote or a brace: a line with none, outside braces, ends its code where -- starts
QUOTE_OR_BRACE = re.compile(r"""['"{}$]""")
# what may start a quote or a comment: braces in a line with none of these pair up as they come
QUOTE_OR_COMMENT = re.compile(r"""['"$]|--""")
BRACE = re.compile(r"[{}]")


def quote_end(line: str, i: int, quote: str) -> int:
    """Where a quote open before line[i] ends: the index after its closing mark, or -1 if the line ends first.
    A quote doubled ('it''s', "a""b") is part of the text; in E'...' a backslash escapes the next character."""
    if quote.startswith("$"):
        j = line.find(quote, i)
        return -1 if j < 0 else j + len(quote)
    close = quote[-1]
    while i < len(line):
        if (quote == "E'" and line[i] == "\\") or line.startswith(close * 2, i):
            i += 2
        elif line[i] == close:
            return i + 1
        else:
            i += 1
    return -1


@dataclass
class Scanner:
    """How the lines of a policy read, one after another: which characters are quoted, inside how many {braces},
    in a comment. The one reading the parser, rowstile fmt and the editors' helpers share.

    Outside braces, the policy's own text: '...' and "..." are quotes when they close on the same line (an
    apostrophe in a test's name opens none), and -- starts a comment. Inside braces, SQL: '...' (E'...' with its
    backslashes), "names", $$...$$ and $tag$...$tag$ are quotes, which may go on to the next line, and -- starts an
    SQL comment, which also runs to the end of the line (the lines of a condition are joined into one). Braces
    nest; one inside quotes opens nothing, and a `}` with none open is text."""

    depth: int = 0
    quote: str = ""  # a quote inside braces the last line left open: ', ", E' or a dollar quote's tag

    def code_end(self, line: str) -> int:
        """Where the line's code ends (where its comment starts, else its length), read as marks() reads it: the
        lines of a policy, most of them without a quote or a brace, in one step each."""
        if not self.quote and not self.depth and QUOTE_OR_BRACE.search(line) is None:
            c = line.find("--")
            return len(line) if c < 0 else c
        return comment_at(line, self.marks(line))

    def marks(self, line: str) -> list[Mark]:
        out: list[Mark] = []
        i = 0
        while i < len(line):
            if self.quote:
                end = quote_end(line, i, self.quote)
                stop = len(line) if end < 0 else end
                out += [Mark(True, self.depth, False)] * (stop - i)
                self.quote, i = (self.quote if end < 0 else ""), stop
                continue
            special = SPECIAL.search(line, i)
            stop = special.start() if special else len(line)
            if stop > i:
                out += [Mark(False, self.depth, False)] * (stop - i)
                i = stop
                continue
            c = line[i]
            if line.startswith("--", i):
                out += [Mark(False, self.depth, True)] * (len(line) - i)
                break
            if c in "'\"" and self.depth == 0:
                end = quote_end(line, i + 1, c)
                if end < 0:
                    out.append(Mark(False, 0, False))  # (an apostrophe)
                    i += 1
                else:
                    out += [Mark(True, 0, False)] * (end - i)
                    i = end
                continue
            dollar = DOLLAR_QUOTE.match(line, i) if c == "$" and self.depth else None
            if c in "'\"" or dollar:
                tag = dollar.group(0) if dollar else c
                if (
                    c == "'"
                    and i
                    and line[i - 1] in "Ee"
                    and not (i > 1 and (line[i - 2].isalnum() or line[i - 2] == "_"))
                ):
                    tag = "E'"
                out += [Mark(True, self.depth, False)] * (len(tag) if dollar else 1)
                self.quote, i = tag, i + (len(tag) if dollar else 1)
                continue
            if c == "}" and self.depth:
                self.depth -= 1
            out.append(Mark(False, self.depth, False))
            if c == "{":
                self.depth += 1
            i += 1
        return out


def comment_at(line: str, marks: list[Mark]) -> int:
    """Where a line's comment starts (its length when it has none)."""
    return next((i for i, m in enumerate(marks) if m.comment), len(line))


def strip_comment(line: str) -> str:
    """A line without its -- comment (one line read alone: strip_comments reads several)."""
    return line[: comment_at(line, Scanner().marks(line))]


def strip_comments(text: str) -> str:
    """Each line of text without its -- comment, a quote or a brace left open on one going on to the next."""
    scan = Scanner()
    return "\n".join(line[: comment_at(line, scan.marks(line))] for line in text.split("\n"))


def braced_at(text: str) -> list[tuple[int, int]]:
    """Where each top-level {...} of a line is: the index of its `{`, and the one after its `}` (-1 for one left
    open)."""
    out: list[tuple[int, int]] = []
    if "{" not in text:
        return out
    start = -1
    if QUOTE_OR_COMMENT.search(text) is None:  # no quote or comment hides a brace: they pair up as they come
        depth = 0
        for b in BRACE.finditer(text):
            if b.group() == "{":
                if not depth:
                    start = b.start()
                depth += 1
            elif depth:
                depth -= 1
                if not depth:
                    out.append((start, b.end()))
                    start = -1
        return out + ([(start, -1)] if start >= 0 else [])
    for i, m in enumerate(Scanner().marks(text)):
        if m.quoted or m.comment or m.depth:
            continue
        if text[i] == "{":
            start = i
        elif text[i] == "}" and start >= 0:
            out.append((start, i + 1))
            start = -1
    return out + ([(start, -1)] if start >= 0 else [])


def braced(text: str) -> list[str]:
    """The SQL inside each top-level {...} of a line, closed."""
    return [text[a + 1 : b - 1] for a, b in braced_at(text) if b > 0]


class Token(NamedTuple):
    kind: str  # or | and | not | ( | ) | cond | name
    text: str  # a condition's SQL, a name, or the word itself
    start: int  # where it is in the line's text
    end: int


def tokenize(s: str, loc: Loc, base: int = 0) -> list[Token]:
    """An expression's words; base: where it starts in the line's text (for the places of its mistakes)."""
    toks: list[Token] = []
    i = 0
    while i < len(s):
        c = s[i]
        if c.isspace():
            i += 1
        elif c == "{":
            end = braced_at(s[i:])[0][1]
            if end < 0:
                fail(loc, "a { condition is missing its closing }", "AZ102", at=(base + i, base + i + 1))
            j = i + end - 1
            sql = s[i + 1 : j].strip()
            if not sql:
                fail(loc, "empty {} condition", "AZ102", at=(base + i, base + j + 1))
            toks.append(Token("cond", sql, base + i, base + j + 1))
            i = j + 1
        elif c in "()":
            toks.append(Token(c, c, base + i, base + i + 1))
            i += 1
        else:
            m = re.match(rf"{IDENT}(\.{IDENT})?", s[i:])
            if not m:
                # a character that doesn't print (a stray control character) is shown escaped, or the message
                # would show nothing between its quotes
                shown = c if c.isprintable() else c.encode("unicode_escape").decode("ascii")
                fail(loc, f"unexpected '{shown}' in expression", "AZ102", at=(base + i, base + i + 1))
            w = m.group(0)
            toks.append(Token(w if w in ("or", "and", "not") else "name", w, base + i, base + i + len(w)))
            i += len(w)
    return toks


def written(node: Expr, top: bool = True) -> str:
    """An expression as a policy writes it, with parentheses around each `and` and `or` inside another."""
    match node:
        case Or(items=items) | And(items=items):
            s = (" or " if isinstance(node, Or) else " and ").join(written(x, False) for x in items)
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
    goes first: `a or b and c` is refused, `a or (b and c)` is not. base: where text starts in the line's."""

    def __init__(self, text: str, loc: Loc, base: int = 0) -> None:
        self.toks, self.i, self.loc = tokenize(text, loc, base), 0, loc
        self.joined = False  # whether the last `and` read joined two items or more, outside parentheses

    def peek(self) -> str | None:
        return self.toks[self.i].kind if self.i < len(self.toks) else None

    def take(self) -> Token:
        tok = self.toks[self.i]
        self.i += 1
        return tok

    def unexpected(self) -> NoReturn:
        tok = self.toks[self.i]
        fail(self.loc, f"unexpected '{tok.text}'", "AZ102", at=(tok.start, tok.end))

    def parse(self) -> Expr:
        # (never given an empty one: the lines it reads end in what follows `=` or `:`, which isn't blank)
        e = self.or_()
        if self.i < len(self.toks):
            self.unexpected()
        return e

    def or_(self) -> Expr:
        first = self.i
        items = [self.and_()]
        mixed = self.joined
        while self.peek() == "or":
            self.take()
            items.append(self.and_())
            mixed = mixed or self.joined
        if len(items) == 1:
            return items[0]
        node = Or(items)
        if mixed:
            fail(
                self.loc,
                f"`and` and `or` meet without parentheses, which reads two ways: write {written(node)}",
                "AZ102",
                at=(self.toks[first].start, self.toks[self.i - 1].end),
            )
        return node

    def and_(self) -> Expr:
        items = [self.unary()]
        while self.peek() == "and":
            self.take()
            items.append(self.unary())
        self.joined = len(items) > 1
        return items[0] if len(items) == 1 else And(items)

    def unary(self) -> Expr:
        kind = self.peek()
        if kind is None:
            last = self.toks[-1] if self.toks else None
            fail(self.loc, "expression ends too early", "AZ102", at=(last.start, last.end) if last else None)
        if kind == "not":
            self.take()
            return Not(self.unary())
        if kind == "(":
            opened = self.take()
            e = self.or_()
            if self.peek() != ")":
                fail(self.loc, "missing )", "AZ102", at=(opened.start, opened.end))
            self.take()
            return e
        if kind == "cond":
            return Cond(self.take().text)
        if kind == "name":
            tok = self.take()
            w = tok.text
            if w in KEYWORDS:
                return Cond(KEYWORDS[w])
            not_generated(w, self.loc, (tok.start, tok.end))
            span = self.loc.span(tok.start, tok.end)
            if "." in w:
                rel, perm = w.split(".")
                return Arrow(rel, perm, span)
            return Ref(w, span)
        self.unexpected()


def not_generated(name: str, loc: Loc, at: tuple[int, int] | None = None) -> None:
    """Generated names hold '__' (`view__base`, `folder__key`): a policy can neither name nor declare one."""
    if "__" in name:
        fail(loc, f"'{name}': names with '__' are generated ones, which a policy can't use", "AZ107", at=at)


def check_name(name: str, loc: Loc, at: tuple[int, int] | None = None) -> str:
    not_generated(name, loc, at)
    if name in RESERVED or name in KEYWORDS:
        fail(loc, f"'{name}' is a word of the language; choose another name", "AZ107", at=at)
    return name


class Line(NamedTuple):
    """A line as the parser reads it: where it starts, its indent, and its text without comments, the lines it goes
    on over joined to it."""

    loc: Loc
    indent: int
    text: str


# a byte order mark, which some editors put at the start of a UTF-8 file: not part of the policy
BOM = "\ufeff"
# an include line (at the start of a line)
INCLUDE = re.compile(r'include\s+"([^"]+)"')
# a line that goes on from the one before ('where : user = ...' declares a relation named where, which check_name
# refuses)
CONTINUES = re.compile(r"(or|and|if|where)\b(?!\s*:)")


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
        for line in file_lines(including or None, body):
            m = INCLUDE.fullmatch(line.text) if line.indent == 0 else None
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


def file_lines(name: str | None, text: str) -> list[Line]:
    """A file's lines as the parser reads them, without comments or blank lines: a line starting with or, and, if
    or where goes on from the one before, as does each line while a { is open."""
    scan = Scanner()
    out: list[Line] = []
    for n, raw in enumerate(text.removeprefix(BOM).split("\n"), 1):
        open_before = scan.depth > 0
        code = raw[: scan.code_end(raw)].rstrip()
        s = code.strip()
        if not s:
            continue
        indent = len(code) - len(code.lstrip())
        if out and (open_before or CONTINUES.match(s)):
            last = out[-1]
            last.loc.origin.append((len(last.text) + 1, n, indent))
            last.loc.text = last.text + " " + s
            out[-1] = last._replace(text=last.loc.text)
        else:
            out.append(Line(Loc(name, n, s, [(0, n, indent)]), indent, s))
    return out


def read_lines(
    name: str | None, text: str, files: dict[str, str] | None = None, seen: set[str] | None = None
) -> list[Line]:
    """The lines of a policy (name None) or of a file it includes, with includes expanded. Includes are looked up
    in `files` (name -> text), relative to the including file, and never on disk."""
    files = files or {}
    seen = set() if seen is None else seen
    out: list[Line] = []
    for line in file_lines(name, text):
        loc, m = line.loc, INCLUDE.fullmatch(line.text) if line.indent == 0 else None
        if m is None:
            out.append(line)
            continue
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
            fail(loc, f"can't find {inc} in the policy's folder", "AZ108")
        seen.add(inc)
        out += read_lines(inc, files[inc], files, seen)
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


# a dollar-quote tag ($f$, $body$): the generated functions' bodies are quoted with such tags, so one in a
# condition would end the body it is placed in ('$$' is fine: no body uses it around a condition)
DOLLAR_TAG = re.compile(r"\$[A-Za-z_][A-Za-z0-9_]*\$")


# ----------------------------------------------------------------------
# A line's pieces
# ----------------------------------------------------------------------
class Piece(NamedTuple):
    """A piece of a line, as the line's reader takes it: a name, a number, a {condition} (open: one left open,
    which runs to the line's end), a quote ('...' or "...", closed on the line), or a mark (any other character;
    -> is one)."""

    kind: str  # name | number | cond | open | quote | mark
    text: str  # a condition's SQL, between its braces; anything else as written
    start: int  # where it is in the line's text
    end: int


# a name or a number: what runs on without a space or a mark
RUN = re.compile(r"[A-Za-z0-9_]+")
NOT_SPACE = re.compile(r"\S")


def piece_at(text: str, i: int) -> Piece:
    """The piece that starts at text[i], which isn't a space."""
    c = text[i]
    if c == "{":
        end = braced_at(text[i:])[0][1]
        if end < 0:
            return Piece("open", text[i + 1 :], i, len(text))
        return Piece("cond", text[i + 1 : i + end - 1], i, i + end)
    if c in "'\"" and (end := quote_end(text, i + 1, c)) > 0:
        return Piece("quote", text[i:end], i, end)
    if m := RUN.match(text, i):
        return Piece("number" if c.isdigit() else "name", m.group(0), i, m.end())
    mark = "->" if text.startswith("->", i) else c
    return Piece("mark", mark, i, i + len(mark))


# a line's pieces, as Words lexes them: the place read from -> where the next piece starts, and the piece
Pieces: TypeAlias = "dict[int, tuple[int, Piece | None]]"

# a piece after spaces, as piece_at reads it: a name or a number, ->, a quote closed on the line (a doubled quote
# inside it; possessive, so that an unclosed one is a mark as there), a { (piece_at reads the condition), a mark
LINE_PIECE = re.compile(r"""\s*(?:([A-Za-z0-9_]+)|(->)|('(?:[^']|'')*+'|"(?:[^"]|"")*+")|(\{)|(\S))""")


def lex_line(text: str, pieces: Pieces) -> None:
    """Each piece of a line, read once from its start (what Words would lex at each piece's end, in one pass)."""
    pos, n = 0, len(text)
    while True:
        m = LINE_PIECE.match(text, pos)
        if m is None:
            pieces[pos] = (n, None)
            return
        run, arrow, quote, brace, _ = m.groups()
        i = m.start(m.lastindex or 0)
        if run is not None:
            piece = Piece("number" if run[0].isdigit() else "name", run, i, m.end())
        elif arrow is not None:
            piece = Piece("mark", "->", i, i + 2)
        elif quote is not None:
            piece = Piece("quote", quote, i, m.end())
        elif brace is not None:
            piece = piece_at(text, i)
        else:
            piece = Piece("mark", text[i], i, i + 1)
        pieces[pos] = (i, piece)
        pos = piece.end


class Unread(Exception):
    """A line isn't the form being read: where reading stopped, (start, end) in its text."""

    def __init__(self, at: tuple[int, int]) -> None:
        super().__init__(at)
        self.at = at


T = TypeVar("T")


class Words:
    """A line's pieces, taken in order from start. A line form's reader takes the pieces it expects, and where
    another is, stops (Unread, at that piece). Spaces matter only where the form says: `app.users` is written
    without any, `principal` after one."""

    def __init__(self, text: str, start: int = 0, pieces: Pieces | None = None) -> None:
        self.text, self.pos = text, start  # pos: after the piece taken last
        # the piece after each place read from, and where it starts: each is lexed once, however many forms are
        # tried on the line (pass the same dict to each)
        self.pieces = {} if pieces is None else pieces
        if not self.pieces:
            lex_line(text, self.pieces)

    def copy(self) -> Words:
        return Words(self.text, self.pos, self.pieces)

    def after(self) -> tuple[int, Piece | None]:
        # (the readers call this hundreds of times a policy: the lexed piece is looked up first, inline where it is
        # called most, take)
        return self.pieces.get(self.pos) or self.lex()

    def lex(self) -> tuple[int, Piece | None]:
        """The next piece, lexed and kept for the forms tried next on the line."""
        m = NOT_SPACE.search(self.text, self.pos)
        i = m.start() if m else len(self.text)
        got = self.pieces[self.pos] = (i, piece_at(self.text, i) if i < len(self.text) else None)
        return got

    def next_start(self) -> int:
        return self.after()[0]

    def peek(self) -> Piece | None:
        return (self.pieces.get(self.pos) or self.lex())[1]

    def spaced(self) -> bool:
        """Whether a space comes before the next piece."""
        return self.next_start() > self.pos

    def take(self, kind: str, *texts: str, spaced: bool = False, glued: bool = False) -> Piece | None:
        """The next piece if it is of that kind (and one of those texts), after a space if spaced, right after the
        last if glued; None, and nothing taken, if not."""
        start, p = self.pieces.get(self.pos) or self.lex()
        if p is None or p.kind != kind or (texts and p.text not in texts):
            return None
        if (spaced and start == self.pos) or (glued and start > self.pos):
            return None
        self.pos = p.end
        return p

    def name(self, *texts: str, spaced: bool = False, glued: bool = False) -> Piece | None:
        start, p = self.pieces.get(self.pos) or self.lex()
        if p is None or p.kind != "name" or (texts and p.text not in texts):
            return None
        if (spaced and start == self.pos) or (glued and start > self.pos):
            return None
        self.pos = p.end
        return p

    def mark(self, text: str, glued: bool = False) -> Piece | None:
        return self.take("mark", text, glued=glued)

    def here(self) -> tuple[int, int]:
        """Where the next piece is: where reading stops if it isn't what the form expects (the line's end, after
        the last)."""
        p = self.peek()
        return (p.start, p.end) if p else (len(self.text), len(self.text))

    def need(self, piece: T | None) -> T:
        """What a form must have here."""
        if piece is None:
            raise Unread(self.here())
        return piece

    def must(self, ok: bool) -> None:
        if not ok:
            raise Unread(self.here())

    def end(self) -> None:
        """The line ends here."""
        self.must(self.peek() is None)

    def rest(self) -> tuple[str, int]:
        """The text from the next piece to the line's end (an expression, a list), and where it starts; there must
        be some."""
        i = self.next_start()
        self.must(i < len(self.text))
        self.pos = len(self.text)
        return self.text[i:], i

    def until(self, c: str) -> tuple[str, int]:
        """The text up to the next c, not read as pieces (a type's key, up to its `)`), and where it starts."""
        j = self.text.find(c, self.pos)
        self.must(j >= 0)
        start, self.pos = self.pos, j + 1
        return self.text[start:j], start

    def all(self) -> list[Piece]:
        """Every piece left."""
        out: list[Piece] = []
        while (p := self.peek()) is not None:
            self.pos = p.end
            out.append(p)
        return out


def reading(loc: Loc, msg: str, code: str, read: Callable[[], T]) -> T:
    """What read() reads of a line; where it stops, the mistake msg, about the piece there."""
    try:
        return read()
    except Unread as stop:
        raise PolicyError(f"{loc}: {msg}", code, loc.span(*stop.at)) from None


def qname(w: Words) -> Piece:
    """schema.name, written without spaces."""
    first = w.need(w.name())
    w.need(w.mark(".", glued=True))
    second = w.need(w.name(glued=True))
    return Piece("name", f"{first.text}.{second.text}", first.start, second.end)


def read_cols(w: Words) -> Cols:
    """A column, or [a, b]: the columns of a composite key."""
    if w.mark("[") is None:
        return w.need(w.name()).text
    names = [w.need(w.name()).text]
    while w.mark(","):
        names.append(w.need(w.name()).text)
    w.need(w.mark("]"))
    return tuple(names)


# ----------------------------------------------------------------------
# The policy file
# ----------------------------------------------------------------------
# composite keys are compared as text: only types whose text form is canonical
KEY_TYPES = ("bigint", "int8", "integer", "int", "int4", "smallint", "int2", "text", "uuid", "varchar")


def parse_key(key: tuple[str, int] | None, loc: Loc) -> list[tuple[str, str]]:
    """(id uuid) or (org_id, id) or (org_id bigint, id uuid) -> [(column, type)]; key: the text between the
    parentheses, and where it starts."""
    if key is None:
        return [("id", "bigint")]
    out: list[tuple[str, str, tuple[int, int]]] = []
    for part, at in parts(*key):
        m = re.fullmatch(rf"({IDENT})(?:\s+({IDENT}))?", part)
        if not m:
            fail(
                loc,
                "write the key as (column [type]), or (col1 [type], col2 [type]) for a composite key",
                "AZ206",
                at=at,
            )
        if any(c == m.group(1) for c, _, _ in out):
            fail(loc, "a key column is named twice", "AZ206", at=at)
        out.append((m.group(1), (m.group(2) or "bigint").lower(), at))
    if len(out) > 1:
        for c, ty, at in out:
            if ty not in KEY_TYPES:
                fail(
                    loc,
                    f"{c} is {ty}: a composite key's columns must be integers, text or uuid "
                    f"(ids are compared as text, which must not depend on settings)",
                    "AZ206",
                    at=at,
                )
    return [(c, ty) for c, ty, _ in out]


def parts(text: str, base: int = 0) -> list[tuple[str, tuple[int, int]]]:
    """A list written with commas: each item without the spaces around it, and where it is (base: where text
    starts in the line's)."""
    return [(m.group(1), (base + m.start(1), base + m.end(1))) for m in re.finditer(r"\s*([^,]*?)\s*(?:,|$)", text)][
        : text.count(",") + 1
    ]


def parse_subjects(text: str, loc: Loc, base: int = 0) -> tuple[list[Subject], tuple[Span | None, ...]]:
    """Who a relation links to, and where each is written."""
    subjects: list[Subject] = []
    spans: list[Span | None] = []
    for part, at in parts(text, base):
        spans.append(loc.span(*at))
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
                at=at,
            )
        if sm.group(1) in ("anyone", "link"):
            fail(loc, f"bad subject '{part}': {sm.group(1)} stands alone, without #relation", "AZ204", at=at)
        subjects.append((sm.group(1), sm.group(2)))
    return subjects, tuple(spans)


SOURCE = (
    "a source is a column, (type_col, id_col), schema.table(this_col -> subject_col) "
    "or schema.table(object: col, subject: col) [where {sql}], or 'shared'"
)


def read_side(w: Words) -> tuple[Cols, str | None]:
    """A link table's side: col, [a, b], or (type_col, id_col) -> (the id column(s), the type column)."""
    if w.mark("(") is None:
        return read_cols(w), None
    type_col = w.need(w.name()).text
    w.need(w.mark(","))
    column = read_cols(w)
    w.need(w.mark(")"))
    return column, type_col


def read_where(w: Words) -> str | None:
    """`where {sql}` after a link table's columns, and the line's end."""
    where = w.need(w.take("cond")).text if w.name("where") else None
    w.end()
    return where


def parse_source(w: Words, subjects: list[Subject], spans: tuple[Span | None, ...], loc: Loc) -> Link:
    """= column | (type_col, id_col) | schema.table(obj -> subj) | schema.table(object: obj, subject: subj) [where {sql}]
    | schema.table(obj -> (type_col, id_col)) [where {sql}]; a column may be [a, b], the columns of a composite key"""

    def read() -> Link:
        ahead = w.copy()
        if not (ahead.name() and ahead.mark(".", glued=True)):  # a column of the row: col, [a, b], (type_col, id_col)
            column, type_col = read_side(w)
            w.end()
            return ColumnSource(subjects, loc, column, type_col=type_col, spans=spans)
        table = qname(w).text
        w.need(w.mark("("))
        ahead = w.copy()
        if not (ahead.name("object", "subject") and ahead.mark(":")):  # schema.table(obj -> subj)
            obj = read_cols(w)
            w.need(w.mark("->"))
            subj, type_col = read_side(w)
            w.need(w.mark(")"))
            return TableSource(subjects, loc, table, obj, subj, type_col=type_col, where=read_where(w), spans=spans)
        # the same with the columns named, in either order: schema.table(object: col, subject: col)
        sides: dict[str, tuple[Cols, str | None]] = {}
        for i in range(2):
            if i:
                w.need(w.mark(","))
            side = w.need(w.name("object", "subject")).text
            w.need(w.mark(":"))
            sides[side] = read_side(w)
        w.need(w.mark(")"))
        return finish_named_sides(table, sides, read_where(w))

    def finish_named_sides(table: str, sides: dict[str, tuple[Cols, str | None]], where: str | None) -> Link:
        if set(sides) != {"object", "subject"}:
            fail(
                loc,
                "name one 'object' column and one 'subject' column: schema.table(object: col, subject: col)",
                "AZ103",
            )
        (obj, obj_type), (subj, type_col) = sides["object"], sides["subject"]
        if obj_type is not None:
            fail(loc, "the object side is one column: schema.table(object: col, subject: (type_col, id_col))", "AZ103")
        return TableSource(subjects, loc, table, obj, subj, type_col=type_col, where=where, spans=spans)

    return reading(loc, SOURCE, "AZ103", read)


def parse_policy(text: str, path: str | None = None, files: dict[str, str] | None = None) -> Policy:
    """A policy's text read into a Policy; path: where it is, for its includes when files (name -> text) isn't
    given. A mistake raises a PolicyError: the first one, with every mistake found in .errors."""
    if files is None:  # included files read from disk, next to the policy file (or here)
        files = collect_includes(text, disk_reader(os.path.dirname(path) if path else "."))
    return Reader().read(read_lines(None, text, files))


# a block's indented lines: what reads each
Block: TypeAlias = "Callable[[Line], None]"


def skip(_: Line) -> None:
    """The lines of a block whose first line has a mistake (each would be one of its own)."""


# what a line at the left margin starts with, and what it is if it starts with none of them
TOP_WORDS = ("type", "rules", "test", "invariants", "app", "scope", "caveat")


def expected_top(s: str) -> str:
    return (
        f"expected 'app role', 'type', 'rules', 'scope', 'caveat', 'invariants', 'test', "
        f"'test \"name\"' or 'include', got: {s}"
    )


class Reader:
    """Reads a policy's lines: one at the left margin starts a block (type, rules, test, invariants) or is one on
    its own (app role, scope, caveat); the indented lines below belong to the block. A mistake ends its line, not
    the reading: the lines after it are read too, each mistake kept, and read() raises the first."""

    def __init__(self) -> None:
        self.pol = Policy()
        self.block: Block | None = None  # what reads the indented lines below; None: they belong to nothing
        self.errors: list[PolicyError] = []

    def read(self, lines: list[Line]) -> Policy:
        for line in lines:
            try:
                if line.indent == 0:
                    self.block = skip  # (until the line says which block it starts)
                    no_dollar_tags(line)
                    self.block = self.top(line)
                    continue
                no_dollar_tags(line)
                if self.block is None:
                    self.block = skip  # (once for the lines together)
                    fail(line.loc, "indented line outside a type, rules, invariants or test block", "AZ101")
                else:
                    self.block(line)
            except PolicyError as e:
                self.errors.append(e)
        self.finish()
        if self.errors:
            first = self.errors[0]
            first.errors = self.errors
            raise first
        return self.pol

    def top(self, line: Line) -> Block | None:
        """Reads a line at the left margin; returns what reads the block's lines (None: it starts no block). Each
        form is read whole before what it says is checked."""
        s, loc = line.text, line.loc
        w = Words(s)
        first = w.name(*TOP_WORDS)
        if first is None:
            fail(loc, expected_top(s), "AZ101", at=w.here())
        word = first.text

        def read() -> Block | None:
            match word:
                case "type":
                    return self.type(w, loc)
                case "rules":
                    return self.rules(w, loc)
                case "test":
                    if w.peek() is None:
                        return self.test_section
                    w.must(w.spaced())
                    return self.test(s[w.next_start() :], w.next_start(), loc)
                case "invariants":
                    w.end()
                    return self.invariant
                case "app":
                    w.need(w.name("role"))
                    role = w.need(w.name())
                    w.end()
                    self.app_role(role.text, loc)
                case "scope":
                    self.scope(w, loc)
                case _:
                    self.caveat(w, loc)
            return None

        return reading(loc, expected_top(s), "AZ101", read)

    def type(self, w: Words, loc: Loc) -> Block:
        """type name = schema.table [(key)] [principal] [where {sql}]"""
        name = w.need(w.name())
        w.need(w.mark("="))
        table = qname(w).text
        key = w.until(")") if w.mark("(") else None
        principal = w.name("principal", spaced=True) is not None
        where = w.need(w.take("cond")).text if w.name("where", spaced=True) else None
        w.end()
        at = (name.start, name.end)
        if name.text in ("anyone", "link"):
            fail(
                loc,
                f"'{name.text}' is a subject of its own (shared with {name.text}); name the type differently",
                "AZ204",
                at=at,
            )
        check_name(name.text, loc, at)
        if name.text in self.pol.types:
            fail(loc, f"type {name.text} is defined twice", "AZ109", at=at)
        t = self.pol.types[name.text] = Type(
            name.text, table, parse_key(key, loc), loc, where=where, principal=principal or name.text == "user"
        )
        return lambda line: parse_type_line(t, line.text, line.loc)

    def rules(self, w: Words, loc: Loc) -> Block:
        """rules schema.table [view schema.view]"""
        table = qname(w).text
        view = qname(w) if w.name("view") else None
        w.end()
        if view:
            if table in self.pol.views and self.pol.views[table] != view.text:
                fail(loc, f"{table} already has the view {self.pol.views[table]}", "AZ109", at=(view.start, view.end))
            self.pol.views[table] = view.text
            self.pol.view_locs[table] = loc
        return lambda line: parse_rule_line(self.pol, table, line.text, line.loc)

    def scope(self, w: Words, loc: Loc) -> None:
        """scope name = items (a name may go on with - or :, read-only, files:read)"""
        first = w.need(w.name())
        name, end = first.text, first.end
        while (sep := w.peek()) and sep.kind == "mark" and sep.text in ("-", ":") and not w.spaced():
            w.pos = sep.end
            more = w.need(w.name(glued=True))
            name, end = name + sep.text + more.text, more.end
        w.need(w.mark("="))
        text, start = w.rest()
        if name in self.pol.scopes:
            fail(loc, f"scope {name} is defined twice", "AZ109", at=(first.start, end))
        items, spans = parse_scope_items(text, loc, start)
        self.pol.scopes[name] = Scope(name, items, loc, spans)

    def caveat(self, w: Words, loc: Loc) -> None:
        """caveat name = {sql}"""
        name = w.need(w.name())
        w.need(w.mark("="))
        sql = w.need(w.take("cond")).text
        w.end()
        if name.text in self.pol.caveats:
            fail(loc, f"caveat {name.text} is defined twice", "AZ109", at=(name.start, name.end))
        self.pol.caveats[name.text] = Caveat(name.text, sql.strip(), loc)

    def test_section(self, line: Line) -> None:
        # the same checks as a named test's: user 3 can view file 11, service 2 cannot ..., anyone can ...
        pieces: Pieces = {}
        step = None if Words(line.text, 0, pieces).name("given", "as") else parse_step(line.text, line.loc, pieces)
        if step is None or step.kind != "check":
            fail(
                line.loc,
                "the test section checks the data already there, as: user 3 can view file 11 (a test "
                'that brings its own data, or runs a statement, is named: test "...")',
                "AZ106",
            )
        self.pol.tests.append(step)

    def test(self, name: str, start: int, loc: Loc) -> Block:
        """test name, or test "name" (start: where the name is in the line)"""
        at = (start, start + len(name))
        if name[0] in "\"'":
            if len(name) < 2 or name[-1] != name[0]:
                fail(loc, f"the test's name has no closing {name[0]}: test {name}{name[0]}", "AZ106", at=at)
            name = name[1:-1]
        if any(sc.name == name for sc in self.pol.scenarios):
            fail(loc, f"there is already a test named {name!r}", "AZ109", at=at)
        test = Scenario(name, loc)
        self.pol.scenarios.append(test)
        return lambda line: test.steps.append(parse_step(line.text, line.loc))

    def invariant(self, line: Line) -> None:
        """never type: expression"""
        w = Words(line.text)

        def read() -> tuple[Piece, tuple[str, int]]:
            w.need(w.name("never"))
            t = w.need(w.name())
            w.need(w.mark(":"))
            return t, w.rest()

        t, (text, start) = reading(
            line.loc, "write invariants as: never file: view and not folder.in_org", "AZ106", read
        )
        expr = ExprParser(text, line.loc, start).parse()
        self.pol.invariants.append(Invariant(t.text, expr, text, line.loc, line.loc.span(t.start, t.end)))

    def app_role(self, role: str, loc: Loc) -> None:
        if self.pol.role is not None:
            fail(loc, f"the app role is named twice ({self.pol.role} and {role}): a policy applies to one", "AZ109")
        if role.lower() == "public":
            fail(
                loc,
                "the app role is the one role your app connects as, not PUBLIC (every role in the database could "
                "then sign in as anyone)",
                "AZ111",
            )
        self.pol.role = role

    def finish(self) -> None:
        """What the whole policy says: each test has lines, and the permissions custom roles may give."""
        for sc in self.pol.scenarios:
            if not sc.steps:
                try:
                    fail(sc.loc or 0, f"test {sc.name!r} has no lines", "AZ106")
                except PolicyError as e:
                    self.errors.append(e)
        for t in self.pol.types.values():
            if t.roles:
                t.roles = (t.roles[0], granted_by_roles(t), t.roles[2])


def no_dollar_tags(line: Line) -> None:
    """A condition with a dollar quote's tag ($f$) would end the generated function it goes in."""
    for a, b in braced_at(line.text):
        tag = DOLLAR_TAG.search(line.text, a, b) if b > 0 else None
        if tag:
            fail(
                line.loc,
                f"{{{line.text[a + 1 : b - 1].strip()}}} contains {tag.group(0)}, which ends the generated function "
                f"it goes in: write the text another way ('$' || 'f$')",
                "AZ110",
                at=tag.span(),
            )


# a test's id: a 'quoted' literal, or anything up to the next space ($ann, 11, a uuid)
VALUE = re.compile(r"'(?:[^']|'')*'|[^\s{}']+")


def test_value(w: Words) -> str:
    """A test's id, after a space and before one: $name as written, a quoted literal unquoted, anything else as
    is."""
    i = w.next_start()
    m = VALUE.match(w.text, i) if i > w.pos else None
    w.must(m is not None and (m.end() == len(w.text) or w.text[m.end()].isspace()))
    assert m is not None
    w.pos = m.end()
    v = m.group(0)
    return v[1:-1].replace("''", "'") if v.startswith("'") else v


def principal(w: Words, anyone: bool) -> tuple[str, str | None, tuple[str, ...]]:
    """Who a test's line is about: anyone (nobody signed in), or a type and an id, then `with scope a, b` (signed
    in limited to them, as a key with them is)."""
    if anyone:
        w.need(w.name("anyone"))
        return "anyone", None, ()
    ptype = w.need(w.name()).text
    who = test_value(w)
    scopes: list[str] = []
    if w.name("with"):
        w.need(w.name("scope"))
        scopes.append(w.need(w.name()).text)
        while w.mark(","):
            scopes.append(w.need(w.name()).text)
    return ptype, who, tuple(scopes)


def either(w: Words, read: Callable[[Words, bool], T]) -> T:
    """read(w, anyone) of a test's line: about anyone, or else about a principal (`anyone 3` is one of type
    anyone, which the compiler refuses); stopping, where the reading that got further stopped."""
    try:
        return read(w.copy(), True)
    except Unread as first:
        try:
            return read(w.copy(), False)
        except Unread as second:
            raise Unread(max(first.at, second.at)) from None


def given_step(s: str, loc: Loc, w: Words) -> GivenStep:
    """given [name =] {INSERT ... RETURNING id}"""
    w.need(w.name("given"))
    w.must(w.spaced())
    var = w.name()
    if var:
        w.need(w.mark("="))
    sql = w.need(w.take("cond")).text
    w.end()
    if not sql.strip():
        fail(loc, "given {...} needs a statement", "AZ106")
    return GivenStep(s, loc, sql.strip(), var=var.text if var else None)


def as_step(s: str, loc: Loc, w: Words) -> AsStep:
    """as who allowed|refused|sees N {SQL}"""

    def read(w: Words, anyone: bool) -> tuple[tuple[str, str | None, tuple[str, ...]], str | int, str]:
        w.need(w.name("as"))
        who = principal(w, anyone)
        verb = w.need(w.name("allowed", "refused", "sees"))
        expect: str | int = verb.text
        if verb.text == "sees":
            n = w.need(w.take("number"))
            if not n.text.isdigit():
                raise Unread((n.start, n.end))
            expect = int(n.text)
        sql = w.need(w.take("cond")).text
        w.end()
        return who, expect, sql

    (ptype, who, scopes), expect, sql = either(w, read)
    if not sql.strip():
        fail(loc, "as ... {...} needs a statement", "AZ106")
    # `sees N` counts the rows of a query, which a write can't be put inside: at run time that was a bare
    # "syntax error" from Postgres
    if isinstance(expect, int) and re.match(r"\s*(insert|update|delete|merge)\b", sql, re.I):
        fail(
            loc,
            "`sees N` counts the rows of a SELECT, and this statement writes: for a write that must change "
            "no row, write `as ... refused {...}` (a write that changes no row is refused)",
            "AZ106",
        )
    return AsStep(s, loc, ptype, who, expect, sql.strip(), scopes=scopes)


def check_step(s: str, loc: Loc, w: Words) -> CheckStep:
    """who can|cannot perm type id"""

    def read(w: Words, anyone: bool) -> CheckStep:
        ptype, who, scopes = principal(w, anyone)
        can = w.need(w.name("can", "cannot")).text == "can"
        perm = w.need(w.name()).text
        type_ = w.need(w.name()).text
        obj = test_value(w)
        w.end()
        return CheckStep(s, loc, ptype, who, can, perm, type_, obj, scopes=scopes)

    return either(w, read)


def parse_step(s: str, loc: Loc, pieces: Pieces | None = None) -> Step:
    stops: list[tuple[int, int]] = []
    pieces = {} if pieces is None else pieces
    for form in (given_step, as_step, check_step):
        try:
            return form(s, loc, Words(s, 0, pieces))
        except Unread as stop:
            stops.append(stop.at)
    w = Words(s, 0, pieces)
    w.name("as")
    if w.name("anyone") and w.name("with"):
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
        at=max(stops),
    )


def parse_scope_items(text: str, loc: Loc, base: int = 0) -> tuple[list[ScopeItem], list[Span | None]]:
    """A scope's items, and where each is written."""
    items: list[ScopeItem] = []
    spans: list[Span | None] = []
    for part, at in parts(text, base):
        m = re.fullmatch(rf"(?:({QNAME}|{IDENT})\.)?({IDENT})", part)
        if not m:
            fail(loc, f"bad scope item '{part}' (use select, view, app.files.update or file.edit)", "AZ404", at=at)
        qual, word = m.group(1), m.group(2)
        not_generated(part, loc, at)
        kind = "cmd" if word in COMMANDS else "perm"
        if kind == "cmd" and qual and "." not in qual:
            fail(loc, f"'{part}': commands are qualified by a table, e.g. app.files.{word}", "AZ404", at=at)
        if kind == "perm" and qual and "." in qual:
            fail(loc, f"'{part}': permissions are qualified by a type, e.g. file.{word}", "AZ404", at=at)
        items.append((kind, qual, word))
        spans.append(loc.span(*at))
    return items, spans


def parse_roles_line(t: Type, s: str, loc: Loc) -> None:
    """`roles : user, team#member [from org]`: who may hold the type's custom roles, and with `from`, whose roles
    count on an object. Which permissions a role may give is where the permissions write `roles`."""
    w = Words(s)
    w.name("roles")
    colon = w.need(w.mark(":"))
    pieces = w.all()
    for i, p in enumerate(pieces):
        after = pieces[i - 1].end if i else colon.end
        if (p.kind, p.text) == ("mark", "=") or ((p.kind, p.text) == ("name", "shared") and p.start > after):
            fail(
                loc,
                "`roles : ...` says who may hold custom roles; name the relation something else",
                "AZ107",
                at=(p.start, p.end),
            )
    if not pieces:
        fail(loc, "write custom roles as: roles : user, team#member [from org]", "AZ103", at=w.here())
    end, owner = pieces[-1].end, None
    frm = pieces[-2] if len(pieces) >= 3 else None
    if frm and (frm.kind, frm.text) == ("name", "from") and frm.start > pieces[-3].end and pieces[-1].kind == "name":
        end, owner = pieces[-3].end, pieces[-1].text
    if t.roles:
        fail(loc, f"{t.name} declares custom roles twice", "AZ109")
    subjects, t.roles_spans = parse_subjects(s[pieces[0].start : end], loc, pieces[0].start)
    t.roles_from, t.roles = owner, (subjects, [], loc)


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


def shared_tail(w: Words) -> tuple[str | None, str | None] | Unread:
    """What follows `shared` in a relation: [by perm] [if {sql}], to the line's end; where reading stopped if
    something else does."""
    try:
        by = w.need(w.name()).text if w.name("by") else None
        cond = w.need(w.take("cond")).text if w.name("if") else None
        w.end()
    except Unread as stop:
        return stop
    return by, cond


RELATION = "write relations as: name : subject = source   (or: name : subjects shared [by perm] [if {sql}])"


def parse_type_line(t: Type, s: str, loc: Loc) -> None:
    pieces: Pieces = {}
    if s.startswith("can "):
        w = Words(s, len("can"), pieces)

        def read() -> tuple[Piece, tuple[str, int]]:
            name = w.need(w.name())
            w.need(w.mark("="))
            return name, w.rest()

        name_p, (text, start) = reading(loc, "write permissions as: can name = expression", "AZ104", read)
        name = check_name(name_p.text, loc, (name_p.start, name_p.end))
        if name in t.perms or name in t.relations:
            fail(loc, f"{t.name}.{name} is defined twice", "AZ109", at=(name_p.start, name_p.end))
        if name in COMMANDS:
            fail(loc, f"'{name}' is a command name; call the permission something else", "AZ107")
        if name == ROLES:
            fail(
                loc,
                f"'{ROLES}' is where custom roles give a permission (`can edit = editor or roles`); call the "
                f"permission something else",
                "AZ107",
            )
        t.perms[name] = Perm(name, ExprParser(text, loc, start).parse(), text, loc)
        return
    probe = Words(s, 0, pieces)
    if probe.name("roles") and probe.mark(":"):
        parse_roles_line(t, s, loc)
        return
    parse_relation_line(t, s, loc, pieces)


def parse_relation_line(t: Type, s: str, loc: Loc, pieces: Pieces) -> None:
    """name : subjects = source, or name : subjects shared [by perm] [if {sql}]. The subjects end where `shared`
    starts what may follow it, or else at the first `=`."""
    w = Words(s, 0, pieces)

    def read() -> tuple[Piece, Piece]:
        name = w.need(w.name())
        return name, w.need(w.mark(":"))

    name_p, colon = reading(loc, RELATION, "AZ103", read)
    after_colon = w.all()
    eq = next((i for i, p in enumerate(after_colon) if (p.kind, p.text) == ("mark", "=")), len(after_colon))
    stops: list[tuple[int, int]] = []  # where what followed each `shared` stopped being what may follow it
    shared: tuple[str | None, str | None] | None = None
    end = colon.end
    for k in range(eq):
        p, after = after_colon[k], after_colon[k - 1].end if k else colon.end
        # `shared` after the subjects and a space
        if (p.kind, p.text) != ("name", "shared") or p.start == after or p.start - colon.end < 2:
            continue
        got = shared_tail(Words(s, p.end, pieces))
        if isinstance(got, Unread):
            stops.append(got.at)
            continue
        shared, end = got, p.start
        break
    if shared is None:
        if eq == len(after_colon) or eq + 1 == len(after_colon) or after_colon[eq].start == colon.end:
            fail(loc, RELATION, "AZ103", at=max(stops) if stops else (len(s), len(s)))
        end = after_colon[eq].start
    name = check_name(name_p.text, loc, (name_p.start, name_p.end))
    if name in t.perms:
        fail(loc, f"{t.name}.{name} is already a permission", "AZ109", at=(name_p.start, name_p.end))
    subjects, spans = parse_subjects(s[colon.end : end].rstrip(), loc, colon.end)
    if shared is not None:
        src: Source = SharedSource(subjects, loc, shared_by=shared[0], shared_if=shared[1], spans=spans)
    else:
        src = link = parse_source(Words(s, after_colon[eq].end, pieces), subjects, spans, loc)
        if any(sr == "*" or st in ("anyone", "link") for st, sr in subjects):
            fail(loc, "user:* (or another type:*), anyone and link can only be used with 'shared'", "AZ204")
        if link.type_col is None and len(subjects) != 1:
            fail(
                loc,
                "a column or table source links to exactly one kind of subject; "
                "for several, add a type column: (type_col, id_col)",
                "AZ205",
            )
        if link.type_col is not None and any(sr for _, sr in subjects):
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
            "update after" if check else command,
            ExprParser(expr.strip(), loc, len(s) - len(expr.lstrip())).parse(),
            expr.strip(),
            loc,
            columns,
        )
    )
