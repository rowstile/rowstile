#!/usr/bin/env python3
"""coverage_plpgsql: what the suites run of rowstile's PL/pgSQL, statement by statement and branch by branch.

    psql ... | python3 tests/coverage_plpgsql.py save DIR STEP DB     (tests/coverage_functions.sh does it)

core/ci.sh --coverage starts Postgres with plpgsql_check's profiler preloaded (the coverage image has the package;
rowstile itself needs no extension): every PL/pgSQL function any session runs has its statements counted, in
shared memory, for the whole server. Before a database is dropped, tests/coverage_functions.sh makes the extension
in it as the superuser, inside a transaction it rolls back (nothing a suite checks ever sees it), reads each of
rowstile's PL/pgSQL functions (schemas authz, authz_int, authz_gen): its source and how often each of its statements
ran, and forgets the counts it read. `save` adds them to DIR/plpgsql.jsonl, one line per function and database,
and the source of each function body once (one line per body, by its md5).

tests/coverage_report.py reads that file (`measured`, `report`): the statements and branches no suite ran, grouped
by kind of generated function (`coverage_report.kind`: the policy's own names taken out), each RAISE never run
first. A branch is what plpgsql_check calls one: each arm of an IF (an IF without ELSE has one more: no arm
taken), each WHEN and ELSE of a CASE, a loop's body, and the body and each handler of a block with EXCEPTION; it is
taken when its first statement ran. The profiler reports statements, not arms, so the source is read here to know
which statements begin which arm (`read_body`); each function's share of statements and of branches is then compared
with plpgsql_check's own (`plpgsql_coverage_statements`, `_branches`), and the report says where they differ.

A never-run statement or branch that can't run says why in tests/coverage_plpgsql.txt: `KIND | WORDS | WHY`, for
the statement (or the arm's first) whose line, the policy's names taken out, holds WORDS, in functions of that kind.
"""

from __future__ import annotations

import fcntl
import json
import os
import re
import sys
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any

HERE = os.path.dirname(os.path.abspath(__file__))
REASONS = os.path.join(HERE, "coverage_plpgsql.txt")
DATA = "plpgsql.jsonl"
SCHEMAS = ("authz", "authz_int", "authz_gen")

Answer = Any  # a line of plpgsql.jsonl, as read


# --- saving what one database ran ------------------------------------------------------------------------------


def save(directory: str, step: str, db: str, lines: Iterable[str]) -> int:
    """What psql printed (a JSON object a function, other lines ignored) as lines of DIR/plpgsql.jsonl: a body's
    source and statements once (a marker file in DIR/plpgsql-bodies says it is there), and what ran of it in this
    database; and a line saying the database couldn't be read when psql connected but didn't get to the end ("read");
    nothing when psql says "off" (the server doesn't run the profiler). Returns the functions saved."""
    bodies = os.path.join(directory, "plpgsql-bodies")
    os.makedirs(bodies, exist_ok=True)
    out: list[str] = []
    read = connected = False
    for line in lines:
        if line.strip() == "off":  # the server doesn't run the profiler
            return 0
        connected = connected or line.strip() == "connected"  # (not: the database was dropped already)
        read = read or line.strip() == "read"  # psql got to the end
        if not line.startswith("{"):
            continue
        f: Answer = json.loads(line)
        md5 = str(f["md5"])
        statements = f["statements"] or []
        try:
            os.close(os.open(os.path.join(bodies, md5), os.O_CREAT | os.O_EXCL | os.O_WRONLY))
            body = {"body": md5, "source": f["source"], "statements": [s[:5] for s in statements]}
            out.append(json.dumps(body, separators=(",", ":")))
        except FileExistsError:
            pass
        ran = {str(s[0]): [s[5] or 0, s[6] or 0] for s in statements if s[5] or s[6]}
        run = {"step": step, "db": db, "schema": f["schema"], "name": f["name"], "args": f["args"], "md5": md5}
        out.append(json.dumps({**run, "ran": ran, "ratios": f["ratios"]}, separators=(",", ":")))
    saved = sum(1 for line in out if not line.startswith('{"body"'))
    if not out and read:  # a database without rowstile's functions
        return 0
    if connected and not read:
        out.append(json.dumps({"step": step, "db": db, "unread": True}))
    if not out:
        return 0
    with open(os.path.join(directory, DATA), "a", encoding="utf-8") as fh:
        fcntl.flock(fh, fcntl.LOCK_EX)  # run_tests.sh's lanes drop databases at the same time
        fh.write("\n".join(out) + "\n")
    return saved


# --- reading a function's source: which statements begin which arm ---------------------------------------------


@dataclass
class Token:
    word: str  # a keyword or name, upper case; a symbol; "'" for a literal or a quoted name
    line: int


TOKEN = re.compile(
    r"(?P<space>\s+)|(?P<comment>--[^\n]*)|(?P<block>/\*)|(?P<dollar>\$(?:[A-Za-z_][A-Za-z0-9_]*)?\$)"
    r"|(?P<string>[eE]?'(?:[^']|'')*')|(?P<ident>\"(?:[^\"]|\"\")*\")|(?P<word>[A-Za-z_][A-Za-z0-9_$]*)"
    r"|(?P<param>\$\d+)|(?P<sym><<|>>|::|:=|\.\.|.)",
    re.S,
)
ESTRING = re.compile(r"[eE]'(?:[^'\\]|\\.|'')*'", re.S)  # E'...': a backslash escapes the next character


def tokens(source: str) -> list[Token]:
    """The source's tokens, without comments; strings, dollar-quoted strings and quoted names as one "'"."""
    out: list[Token] = []
    i, line = 0, 1
    while i < len(source):
        m = TOKEN.match(source, i)
        if not m:  # (TOKEN's last choice matches any character)
            break
        kind, text = m.lastgroup, m.group()
        end = m.end()
        if kind == "block":  # /* ... */, nested
            depth, end = 1, i + 2
            while end < len(source) and depth:
                if source.startswith("/*", end):
                    depth, end = depth + 1, end + 2
                elif source.startswith("*/", end):
                    depth, end = depth - 1, end + 2
                else:
                    end += 1
        elif kind == "dollar":
            close = source.find(text, end)
            end = len(source) if close < 0 else close + len(text)
            out.append(Token("'", line))
        elif kind == "string" and text[0] in "eE":
            m2 = ESTRING.match(source, i)
            end = m2.end() if m2 else end
            out.append(Token("'", line))
        elif kind in ("string", "ident"):
            out.append(Token("'", line))
        elif kind == "word":
            out.append(Token(text.upper(), line))
        elif kind in ("param", "sym"):
            out.append(Token(text, line))
        line += source.count("\n", i, end)
        i = end
    return out


@dataclass
class Arm:
    """One way through a statement: an IF's THEN, ELSIF or ELSE, a CASE's WHEN or ELSE, a loop's body, a block's body
    or one of its handlers."""

    label: str  # then, elsif, else, when, body, handler
    line: int  # where it starts
    body: list[Node]


@dataclass
class Node:
    """A statement of the source, as plpgsql_check counts them."""

    kind: str  # if, case, loop, block, other
    line: int
    arms: list[Arm] = field(default_factory=list)
    branches: bool = False  # whether its arms are branches (a block's are only when it has handlers)
    implicit: bool = False  # an IF without ELSE: one more branch, taken when none of its arms was


class Unreadable(Exception):
    pass


class Parser:
    """Just enough of PL/pgSQL's grammar to know where each statement starts and which arm holds it."""

    def __init__(self, source: str) -> None:
        self.t = tokens(source)
        self.i = 0

    def peek(self) -> str:
        return self.t[self.i].word if self.i < len(self.t) else ""

    def take(self, *words: str) -> Token:
        if self.i >= len(self.t) or (words and self.t[self.i].word not in words):
            raise Unreadable(f"expected {' or '.join(words) or 'more'} at token {self.i}: {self.peek()!r}")
        self.i += 1
        return self.t[self.i - 1]

    def skip_until(self, *words: str) -> None:
        """Past an expression or a statement's text, to the first of words outside parentheses and CASE ... END."""
        parens = cases = 0
        while self.i < len(self.t):
            w = self.t[self.i].word
            if parens == 0 and cases == 0 and w in words:
                return
            if w == "(":
                parens += 1
            elif w == ")":
                parens -= 1
            elif w == "CASE":
                cases += 1
            elif w == "END" and cases:
                cases -= 1
            self.i += 1
        raise Unreadable(f"no {' or '.join(words)} before the end")

    def function(self) -> Node:
        while self.peek() == "#":  # a compiler option: #variable_conflict use_column
            line = self.take().line
            while self.i < len(self.t) and self.t[self.i].line == line:
                self.i += 1
        node = self.statement()
        if node is None:
            raise Unreadable("no block")
        if self.peek() == ";":
            self.take()
        if self.i != len(self.t):
            raise Unreadable(f"more after the function's block, at token {self.i}: {self.peek()!r}")
        return node

    def statements(self, *stop: str) -> list[Node]:
        out: list[Node] = []
        while self.peek() not in stop:
            if not self.peek():
                raise Unreadable(f"no {' or '.join(stop)} before the end")
            node = self.statement()
            if node is not None:
                out.append(node)
        return out

    def statement(self) -> Node | None:
        """The statement here; None for NULL, which PL/pgSQL drops."""
        while self.peek() == "<<":  # a label
            self.skip_until(">>")
            self.take(">>")
        w = self.peek()
        if w in ("DECLARE", "BEGIN"):
            return self.block()
        if w == "IF":
            return self.if_()
        if w == "CASE":
            return self.case()
        if w in ("LOOP", "WHILE", "FOR", "FOREACH"):
            return self.loop()
        if w == "NULL" and self.i + 1 < len(self.t) and self.t[self.i + 1].word == ";":
            self.i += 2
            return None
        line = self.take().line
        self.skip_until(";")
        self.take(";")
        return Node("other", line)

    def end(self, *words: str) -> None:
        """END, then the words (IF, LOOP, CASE), a label perhaps, and the semicolon (but after the function's
        block)."""
        self.take("END")
        for w in words:
            self.take(w)
        if self.peek() not in (";", ""):
            self.take()  # the label
        if self.peek() == ";":
            self.take()

    def block(self) -> Node:
        if self.peek() == "DECLARE":
            self.skip_until("BEGIN")
        node = Node("block", self.take("BEGIN").line)
        node.arms.append(Arm("body", node.line, self.statements("EXCEPTION", "END")))
        if self.peek() == "EXCEPTION":
            self.take()
            node.branches = True
            while self.peek() == "WHEN":
                line = self.take().line
                self.skip_until("THEN")
                self.take("THEN")
                node.arms.append(Arm("handler", line, self.statements("WHEN", "END")))
        self.end()
        return node

    def if_(self) -> Node:
        node = Node("if", self.take("IF").line, branches=True, implicit=True)
        self.skip_until("THEN")
        self.take("THEN")
        node.arms.append(Arm("then", node.line, self.statements("ELSIF", "ELSEIF", "ELSE", "END")))
        while self.peek() in ("ELSIF", "ELSEIF"):
            line = self.take().line
            self.skip_until("THEN")
            self.take("THEN")
            node.arms.append(Arm("elsif", line, self.statements("ELSIF", "ELSEIF", "ELSE", "END")))
        if self.peek() == "ELSE":
            line = self.take().line
            node.arms.append(Arm("else", line, self.statements("END")))
            node.implicit = False
        self.end("IF")
        return node

    def case(self) -> Node:
        node = Node("case", self.take("CASE").line, branches=True)
        self.skip_until("WHEN")
        while self.peek() == "WHEN":
            line = self.take().line
            self.skip_until("THEN")
            self.take("THEN")
            node.arms.append(Arm("when", line, self.statements("WHEN", "ELSE", "END")))
        if self.peek() == "ELSE":
            line = self.take().line
            node.arms.append(Arm("else", line, self.statements("END")))
        self.end("CASE")
        return node

    def loop(self) -> Node:
        node = Node("loop", self.t[self.i].line, branches=True)
        self.skip_until("LOOP")
        self.take("LOOP")
        node.arms.append(Arm("body", node.line, self.statements("END")))
        self.end("LOOP")
        return node


def preorder(node: Node) -> list[Node]:
    """The statements in the order plpgsql_check numbers them: each, then its arms' statements."""
    out = [node]
    for arm in node.arms:
        for child in arm.body:
            out += preorder(child)
    return out


@dataclass
class Statement:
    id: int  # plpgsql_check's stmtid (from 1, in the order of `preorder`)
    parent: int  # 0: none
    line: int
    name: str  # plpgsql_check's: RAISE, IF, assignment, statement block, FOR over SELECT rows, ...


@dataclass
class Branch:
    statement: int  # the id of the statement it belongs to
    label: str  # then, elsif, else, when, body, handler, "no arm" (an IF without ELSE)
    line: int  # its first statement's line, or the IF's for "no arm", or where an empty arm starts
    first: int  # the id of its first statement; 0 when it has none ("no arm", or an arm with no statement)
    # the other arms' first statements: an arm without one was taken when its statement ran more often than they
    # did, if it is the only one (an IF's or a CASE's; inferable)
    others: list[int] = field(default_factory=list)
    inferable: bool = False


@dataclass
class Body:
    """A function's source, its statements, and its branches (None: the source couldn't be read here)."""

    md5: str
    source: list[str]  # its lines
    statements: list[Statement]
    branches: list[Branch] | None
    why: str = ""  # why the branches are None


def read_body(md5: str, source: str, rows: Sequence[Sequence[Any]]) -> Body:
    """A body from what the profiler says of its statements ([stmtid, parent_stmtid, block_num, lineno, stmtname])
    and its source, read to know which statements begin which arm."""
    statements = [Statement(int(r[0]), int(r[1] or 0), int(r[3]), str(r[4])) for r in sorted(rows, key=lambda r: r[0])]
    body = Body(md5, source.split("\n"), statements, None)
    try:
        top = Parser(source).function()
    except Unreadable as e:
        body.why = str(e)
        return body
    nodes = preorder(top)
    if len(nodes) != len(statements):
        body.why = f"{len(nodes)} statements read, the profiler counts {len(statements)}"
        return body
    ids = {id(n): s.id for n, s in zip(nodes, statements, strict=True)}
    for n, s in zip(nodes, statements, strict=True):
        if n.line != s.line:
            body.why = f"statement {s.id} read on line {n.line}, the profiler says {s.line}"
            return body
        for arm in n.arms:
            for child in arm.body:
                if next(x for x in statements if x.id == ids[id(child)]).parent != s.id:
                    body.why = f"statement {ids[id(child)]} read inside {s.id}, the profiler says otherwise"
                    return body
    branches: list[Branch] = []
    for n in nodes:
        if not n.branches:
            continue
        s = ids[id(n)]
        firsts = [ids[id(a.body[0])] for a in n.arms if a.body]
        empty = sum(1 for a in n.arms if not a.body) + n.implicit
        for arm in n.arms:
            first = ids[id(arm.body[0])] if arm.body else 0
            inferable = not arm.body and empty == 1 and n.kind in ("if", "case")
            branches.append(Branch(s, arm.label, arm.body[0].line if arm.body else arm.line, first, firsts, inferable))
        if n.implicit:
            branches.append(Branch(s, "no arm", n.line, 0, firsts, empty == 1))
    body.branches = branches
    return body


def taken(b: Branch, ran: dict[int, int]) -> bool | None:
    """Whether a branch was taken, given how often each statement ran (by id): its first statement ran; without
    one, its statement ran more often than the other arms' first statements did (None: that can't be told)."""
    if b.first:
        return ran.get(b.first, 0) > 0
    if not b.inferable:
        return None
    return ran.get(b.statement, 0) - sum(ran.get(f, 0) for f in b.others) > 0


def taken_as_plpgsql_check(b: Branch, ran: dict[int, int]) -> bool:
    """Whether plpgsql_check counts a branch taken: as `taken`, but an arm without a statement never is, and
    "no arm" is when the IF ran more often than its arms' first statements did."""
    if b.label == "no arm":
        return ran.get(b.statement, 0) - sum(ran.get(f, 0) for f in b.others) > 0
    return ran.get(b.first, 0) > 0 if b.first else False


# --- what the suites ran, all databases together ----------------------------------------------------------------


@dataclass
class Run:
    """One function in one database, and what ran of it."""

    step: str
    db: str
    schema: str
    name: str
    args: str
    md5: str
    ran: dict[int, int]  # statement id -> how often it ran (0: not there)
    ratios: tuple[float | None, float | None]  # plpgsql_check's own: statements and branches run, of 1


@dataclass
class Measured:
    bodies: dict[str, Body]
    runs: list[Run]
    unread: list[tuple[str, str]]  # databases the profile couldn't be read in: (step, db)


def measured(paths: Sequence[str]) -> Measured:
    """What coverage_plpgsql.py save wrote (plpgsql.jsonl) beside each measured DIR or data file."""
    sources: dict[str, tuple[str, list[list[Any]]]] = {}
    runs: dict[tuple[str, str, str, str, str, str], Run] = {}
    unread: list[tuple[str, str]] = []
    for p in paths:
        path = os.path.join(p if os.path.isdir(p) else os.path.dirname(p), DATA)
        if not os.path.isfile(path):
            continue
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                if not line.strip():
                    continue
                d: Answer = json.loads(line)
                if "body" in d:
                    sources[d["body"]] = (d["source"], d["statements"])
                elif d.get("unread"):
                    unread.append((d["step"], d["db"]))
                else:
                    # a database measured twice (before applying a policy again, and when it is dropped) is one
                    # database: what was read the first time was forgotten, so the counts add up
                    key = (d["step"], d["db"], d["schema"], d["name"], d["args"], d["md5"])
                    ratios = (d["ratios"][0], d["ratios"][1])
                    if key in runs:  # measured twice: plpgsql_check's figures were each for a part
                        ratios = (None, None)
                    r = runs.setdefault(key, Run(*key, {}, ratios))
                    r.ratios = ratios
                    for k, (n, _) in d["ran"].items():  # (how often it ran, errors among them)
                        r.ran[int(k)] = r.ran.get(int(k), 0) + int(n)
    bodies = {md5: read_body(md5, src, rows) for md5, (src, rows) in sources.items()}
    return Measured(bodies, [r for r in runs.values() if r.md5 in bodies], unread)


def names(name: str) -> list[tuple[str, str]]:
    """The policy's own names in a generated function's name, longest first, each with what the report says
    instead: app.files:update:refuse -> app.files (and files) as <table>; folder__view__has -> folder as <type>,
    view as <name>."""
    out: list[tuple[str, str]] = []
    if ":" in name and "__" not in name.split(":", 1)[0]:
        table = name.split(":", 1)[0]
        out += [(table, "<table>"), (table.rsplit(".", 1)[-1], "<table>")]
    elif "__" in name:
        parts = name.split("__")
        out.append((parts[0], "<type>"))
        out += [(p, "<name>") for p in parts[1:-1] if p]
    return sorted({p for p in out if len(p[0]) > 1}, key=lambda p: -len(p[0]))


def plain(text: str, own: Sequence[tuple[str, str]]) -> str:
    """A line of a function, its policy's own names taken out (`names`: those its name holds, longest first),
    spaces squeezed: the same statement in two databases' functions of a kind reads the same."""
    for n, instead in own:
        text = re.sub(rf"(?<![A-Za-z0-9_]){re.escape(n)}(?![A-Za-z0-9_])", instead, text)
    text = " ".join(text.split())
    return text if len(text) <= 110 else text[:107] + "..."


@dataclass
class Seen:
    """A statement (or branch) of a kind of function, all databases together."""

    schema: str
    kind: str
    what: str  # the statement's name (RAISE, IF, ...) or the branch's label
    text: str  # its line, the policy's names taken out
    made: int = 0  # in how many functions (each database's its own)
    ran: int = 0  # how many of them ran it
    raise_: bool = False
    called: bool = False  # whether any function holding it was called at all
    bare: bool = False  # a branch with no statement of its own (no arm of an IF taken, an arm without a statement)


@dataclass
class Totals:
    statements: dict[tuple[str, ...], Seen] = field(default_factory=dict)
    branches: dict[tuple[str, ...], Seen] = field(default_factory=dict)
    differ: dict[str, int] = field(default_factory=dict)  # kind -> functions whose shares plpgsql_check gives otherwise
    unreadable: dict[str, str] = field(default_factory=dict)  # kind -> why its source couldn't be read here
    untold: int = 0  # arms without a statement, which can't be told taken or not (WHEN others THEN NULL)
    called: set[str] = field(default_factory=set)  # the kinds of function called in some database


def totals(m: Measured, kind: Callable[[str, str, str], str]) -> Totals:
    """Each statement and branch, all databases together; `kind` names what made a function, from its schema,
    name and arguments (coverage_report.kind)."""
    out = Totals()
    # the policy's tables and types, from the names of its functions (app.files:update:refuse, folder__view__has):
    # every function of the database may name them (changing owner_id of app.files needs ...; WHEN 'folder' THEN),
    # a table by its schema and name (quoted or not), a type as a string
    tables: dict[tuple[str, str], set[tuple[str, str]]] = {}
    for r in m.runs:
        mine = tables.setdefault((r.step, r.db), set())
        for n, instead in names(r.name):
            if instead == "<table>" and "." in n:
                mine.add((n, instead))
                mine.add(('"' + n.replace(".", '"."', 1) + '"', instead))  # "app"."files"
            elif instead == "<type>":
                mine.add((f"'{n}'", "'<type>'"))
    for r in m.runs:
        body = m.bodies[r.md5]
        k = kind(r.schema, r.name, r.args)
        own = sorted(set(names(r.name)) | tables[(r.step, r.db)], key=lambda n: -len(n[0]))
        text = {
            s.id: plain(body.source[s.line - 1] if 0 < s.line <= len(body.source) else "", own) for s in body.statements
        }
        called = any(r.ran.values())
        if called:
            out.called.add(k)
        # a statement is known by its kind of function and its line's text: the same line twice in a function (a
        # guard the generator writes for each permission) is one, run when either ran
        ran: dict[tuple[str, ...], bool] = {}
        for s in body.statements:
            key = (k, s.name, text[s.id])
            ran[key] = ran.get(key, False) or r.ran.get(s.id, 0) > 0
            if key not in out.statements:
                out.statements[key] = Seen(r.schema, k, s.name, text[s.id], raise_=s.name == "RAISE")
        for key, went in ran.items():
            x = out.statements[key]
            x.made += 1
            x.ran += went
            x.called = x.called or called
        if body.branches is None:
            out.unreadable.setdefault(k, body.why)
            continue
        ran = {}
        for b in body.branches:
            first = text[b.first] if b.first else ""
            parent = text[b.statement]
            went = taken(b, r.ran)
            if went is None:
                out.untold += 1
                continue
            label = b.label if b.first or b.label == "no arm" else f"{b.label}, no statement"
            key = (k, parent, b.label, first)
            ran[key] = ran.get(key, False) or went
            if key not in out.branches:
                what = f"{parent} -> {first or '(' + label + ')'}"
                out.branches[key] = Seen(r.schema, k, label, what, bare=not b.first)
        for key, went in ran.items():
            x = out.branches[key]
            x.made += 1
            x.ran += went
            x.called = x.called or called
        mine = share(body, r.ran)
        if r.ratios[0] is not None and any(
            theirs is not None and abs(ours - theirs) > 1e-9 for ours, theirs in zip(mine, r.ratios, strict=True)
        ):
            out.differ[k] = out.differ.get(k, 0) + 1
    return out


def share(body: Body, ran: dict[int, int]) -> tuple[float, float]:
    """The share of statements run and of branches taken, of 1, as plpgsql_check's functions give them."""
    statements = (
        sum(1 for s in body.statements if ran.get(s.id, 0) > 0) / len(body.statements) if body.statements else 1.0
    )
    branches = body.branches or []
    return statements, sum(1 for b in branches if taken_as_plpgsql_check(b, ran)) / len(branches) if branches else 1.0


@dataclass
class Reason:
    kind: str
    words: str
    why: str
    used: bool = False


def reasons(path: str = REASONS) -> list[Reason]:
    """tests/coverage_plpgsql.txt: what can't run, and why (KIND | WORDS | WHY)."""
    out: list[Reason] = []
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                if line.strip() and not line.lstrip().startswith("#"):
                    parts = [p.strip() for p in line.split(" | ", 2)]  # (WORDS may hold ||)
                    if len(parts) == 3:
                        out.append(Reason(parts[0], parts[1], parts[2]))
    except OSError:
        pass
    return out


def why(x: Seen, rs: Sequence[Reason]) -> str:
    for r in rs:
        if r.kind == x.kind and r.words in x.text:
            r.used = True
            return r.why
    return ""


def pct(part: int, whole: int) -> str:
    return f"{100 * part / whole:.1f}%" if whole else "-"


def summary(t: Totals) -> str:
    """The totals, in a line."""
    s, b = list(t.statements.values()), list(t.branches.values())
    rs, rb = sum(1 for x in s if x.ran), sum(1 for x in b if x.ran)
    return f"PL/pgSQL: {rs} of {len(s)} statements ({pct(rs, len(s))}), {rb} of {len(b)} branches ({pct(rb, len(b))})"


def memory(paths: Sequence[str]) -> list[str]:
    """What the profiler said of its memory at the end of each run (run_tests.sh wrote plpgsql-memory.txt): a
    warning for each run that filled it, whose statements were counted only in part."""
    out: list[str] = []
    for p in paths:
        path = os.path.join(p if os.path.isdir(p) else os.path.dirname(p), "plpgsql-memory.txt")
        try:
            with open(path, encoding="utf-8") as fh:
                said = fh.read()
        except OSError:
            continue
        m = re.search(r"allocated stats: (\d+) .*used stats: (\d+)", said)
        if m and int(m.group(2)) > 0.9 * int(m.group(1)):
            out.append(
                f"WARNING: the profiler's memory was {pct(int(m.group(2)), int(m.group(1)))} full at the end of a run "
                f"({path}): once full, functions called for the first time are not counted (raise "
                "plpgsql_check.max_stats_size in core/ci.sh)"
            )
    return out


def report(m: Measured, t: Totals, paths: Sequence[str] = (), why_path: str = REASONS) -> list[str]:
    """What `measured` read and `totals` made of it, as the report says it; `paths`: where the memory was said."""
    rs = reasons(why_path)
    out = [
        "What the database runs, statement by statement: rowstile's PL/pgSQL functions in the suites' databases,",
        "by what made them (plpgsql_check's profiler; a statement or a branch counts once for each kind of function",
        "and each line it is on, the policy's own names taken out, however many databases had it).",
        *memory(paths),
        "",
        f"{'':12}{'statements':>24}{'branches':>24}",
        f"{'':12}{'run':>8}{'of':>8}{'%':>8}{'run':>8}{'of':>8}{'%':>8}",
    ]
    for schema in (*SCHEMAS, None):
        s = [x for x in t.statements.values() if schema is None or x.schema == schema]
        b = [x for x in t.branches.values() if schema is None or x.schema == schema]
        rs_, rb = sum(1 for x in s if x.ran), sum(1 for x in b if x.ran)
        out.append(
            f"{schema or 'total':12}{rs_:>8}{len(s):>8}{pct(rs_, len(s)):>8}{rb:>8}{len(b):>8}{pct(rb, len(b)):>8}"
        )
    out.append(
        f"({len(m.runs)} functions read in {len({(r.step, r.db) for r in m.runs})} databases"
        + (f"; {len(m.unread)} databases couldn't be read" if m.unread else "")
        + ")"
    )
    never_s = sorted((x for x in t.statements.values() if not x.ran), key=lambda x: (x.kind, x.text))
    never_b = sorted((x for x in t.branches.values() if not x.ran), key=lambda x: (x.kind, x.text))

    explained: list[str] = []

    def listed(xs: Sequence[Seen]) -> list[str]:
        """By kind of function, each with what never ran in it; what is only in functions of a kind called elsewhere
        (a policy's own lines, in a database that never called that function) is counted, not listed."""
        lines: list[str] = []
        kinds: dict[str, list[Seen]] = {}
        for x in xs:
            kinds.setdefault(x.kind, []).append(x)
        for k, these in sorted(kinds.items()):
            mine: list[str] = []
            elsewhere = 0
            for x in these:
                said = f"      {x.text}  ({x.what}; in {x.made} function(s))"
                r = why(x, rs)
                if r:
                    explained.extend([f"  {k}", f"{said}: {r}"])
                elif x.called or k not in t.called:
                    mine.append(said)
                else:
                    elsewhere += 1
            if elsewhere:
                mine.append(f"      and {elsewhere} more only in functions of this kind that no suite called")
            lines += [f"  {k}", *mine] if mine else []
        return lines or ["  (none)"]

    out += ["", "RAISE never run (every guard should be met by some suite):"]
    out += listed([x for x in never_s if x.raise_])
    rest = [x for x in never_s if not x.raise_]
    uncalled: dict[str, int] = {}
    for x in rest:
        if x.kind not in t.called:
            uncalled[x.kind] = uncalled.get(x.kind, 0) + 1
    out += ["", "Kinds of function no suite calls, and how many other statements that leaves never run:"]
    out += [f"  {k}  {n} statement(s)" for k, n in sorted(uncalled.items())] or ["  (none)"]
    out += ["", "Other statements never run, in the kinds of function some suite calls:"]
    out += listed([x for x in rest if x.kind in t.called])
    out += [
        "",
        "Branches never taken without a statement of their own, in the kinds of function some suite calls (an arm",
        "whose first statement never ran is listed above with it):",
    ]
    out += listed([x for x in never_b if x.kind in t.called and x.bare])
    out += ["", "Never run, and why (tests/coverage_plpgsql.txt):"]
    out += explained or ["  (none)"]
    stale = [r for r in rs if not r.used]
    if stale:
        out += ["", "Reasons in tests/coverage_plpgsql.txt that nothing never run matches (remove them):"]
        out += [f"  {r.kind} | {r.words}" for r in stale]
    if t.unreadable:
        out += ["", "Sources not read here (their branches aren't counted):"]
        out += [f"  {k}: {w}" for k, w in sorted(t.unreadable.items())]
    if t.differ:
        out += ["", "Functions whose shares of statements and branches plpgsql_check gives otherwise than read here:"]
        out += [f"  {k}  ({n} function(s))" for k, n in sorted(t.differ.items())]
    return out


def main(argv: Sequence[str]) -> int:
    if len(argv) == 4 and argv[0] == "save":
        save(argv[1], argv[2], argv[3], sys.stdin)
        return 0
    print("usage: psql ... | python3 tests/coverage_plpgsql.py save DIR STEP DB", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
