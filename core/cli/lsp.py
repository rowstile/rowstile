"""The rowstile language server: `rowstile lsp`, the Language Server Protocol over stdin and stdout.

For .authz files: errors while typing (from the compiler), hover, go to definition, find references, an outline,
and completion. It needs nothing but Python's standard library and the compiler next to it. With a database in
rowstile.toml it also completes table and column names (read once from the catalog; a database it can't reach is
tried again later), a column inside { } as SQL names it.

rowstile.toml is read again at each message, so that a change to it is taken at once. A mistake in it is shown on
it (and in a message), and the server goes on without its settings until the mistake is fixed.

A file of named tests (no types, only `test "..."` blocks) is checked against the policy rowstile.toml names, and
again each time the policy changes. Find references searches the policy's files and the open test files.

Columns are counted as the protocol counts them, in UTF-16 code units.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import re
import sys
import time
import urllib.parse
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, NotRequired, TypedDict, cast

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
from authzlib import Compiler, PolicyError, parse_policy  # noqa: E402
from authzlib.connection import Value as Json  # noqa: E402
from authzlib.errors import split as split_code  # noqa: E402
from authzlib.parse import (  # noqa: E402
    IDENT,
    QNAME,
    And,
    Arrow,
    ArrowOn,
    Cond,
    Expr,
    Loc,
    Not,
    Or,
    Policy,
    Type,
    collect_includes,
    disk_reader,
    strip_comment,
)

if TYPE_CHECKING:
    from rowstile_cli import Config

Message = dict[str, Json]


class Position(TypedDict):
    line: int
    character: int


class Range(TypedDict):
    start: Position
    end: Position


class Location(TypedDict):
    uri: str
    range: Range


class Diagnostic(TypedDict):
    range: Range
    severity: int
    source: str
    message: str
    code: NotRequired[str]


class Symbol_(TypedDict):
    """An LSP DocumentSymbol."""

    name: str
    kind: int
    range: Range
    selectionRange: Range
    detail: NotRequired[str]
    children: NotRequired[list[Symbol_]]


class Completion(TypedDict):
    label: str
    kind: int
    detail: str


@dataclass(frozen=True)
class Symbol:
    """What a name in the policy is: a type, or one of its relations and permissions."""

    type: Type
    member: str | None = None


def obj(value: Json) -> Message:
    """A JSON object from a message (anything else: empty)."""
    return value if isinstance(value, dict) else {}


def text(message: Message, key: str) -> str:
    value = message.get(key)
    if not isinstance(value, str):
        raise ValueError(f"{key}: text expected")
    return value


def number(message: Message, key: str) -> int:
    value = message.get(key)
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"{key}: a number expected")
    return value


THIS = "(this-file)"  # what a test file is called while it is checked
WORD = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*")
ERROR = re.compile(r"^(?:(\S+?) )?line (\d+): (.*)$", re.S)
TOP_WORDS = [
    "app role",
    "type",
    "rules",
    "include",
    "scope",
    "caveat",
    "sync role",
    "sync after commit",
    "sync",
    "invariants",
    "test",
]
EXPR_WORDS = ["or", "and", "not", "signed_in", "anyone", "nobody"]
RULE_WORDS = ["select", "insert", "update", "delete", "mask", "after", "before", "cascade", "from"]
TYPE_WORDS = ["can", "shared", "by", "if", "where", "roles", "from", "principal"]
SHARE_FIELDS = ["object_id", "subject_type", "subject_id", "subject_relation"]  # what `shared if {...}` reads
KIND_CLASS, KIND_FIELD, KIND_METHOD, KIND_NAMESPACE = 5, 8, 6, 3  # SymbolKind
C_KEYWORD, C_FIELD, C_METHOD, C_CLASS, C_MODULE = 14, 5, 2, 7, 9  # CompletionItemKind
SETTINGS_FILE = re.compile(r"(.*?rowstile\.toml): (.*)", re.S)  # a mistake in it, as the command says it
RETRY, RETRY_MOST = 5, 60  # seconds before a database that couldn't be read is tried again: 5, 10, 20, ... 60


# Path.from_uri is Python 3.13's; the command runs on 3.11. The URIs must stay as they are: they are matched
# against the ones the editor sends (file:///C:/a%20b on Windows, file:///a%20b elsewhere).
def uri_path(uri: str) -> str:
    p = urllib.parse.unquote(urllib.parse.urlparse(uri).path)
    if sys.platform == "win32" and re.match(r"/[A-Za-z]:", p):
        p = p[1:]  # /C:/a -> C:/a
    return os.path.normpath(p)


def path_uri(path: str) -> str:
    return Path(os.path.abspath(path)).as_uri()


def same_file(path: str) -> str:
    """A path as a key: editors spell one file's URI in several ways (file:///c%3A/Users, file:///C:/Users)."""
    return os.path.normcase(os.path.abspath(path))


class Server:
    def __init__(self, settings: Callable[[], Config]) -> None:
        self.settings = settings  # rowstile.toml as it is now
        self.cfg: Config | None = None  # its settings; None while it has a mistake
        self.mistake: tuple[str, str] | None = None  # (rowstile.toml, the mistake in it)
        self.read: object = None  # what rowstile.toml held when last read, to see it change
        self.marked: str | None = None  # the uri of the rowstile.toml its mistake is shown on
        self.docs: dict[str, str] = {}  # uri -> text
        self.open: dict[str, str] = {}  # the open files: same_file(path) -> the uri the editor calls it by
        self.sent: dict[str, set[str]] = {}  # uri checked -> the uris its last check published problems for
        # uri -> last policy that parsed: (pol, files, main path)
        self.models: dict[str, tuple[Policy, dict[str, str], str]] = {}
        # {schema.table: [columns]} from the database, when there is one
        self.catalog: dict[str, list[str]] | None = None
        self.failed, self.tried = 0, 0.0  # reads of the catalog that failed in a row, and when the last was tried
        self.said = ""  # what the log said last of the database
        self.running = True

    # --- rowstile.toml ---------------------------------------------------------------------------
    def load(self) -> None:
        """rowstile.toml as it is now. A change is taken at once: its mistake shown, or cleared, and the catalog read
        again from the database it names; the open files are checked again."""
        said = io.StringIO()
        cfg: Config | None = None
        try:
            with contextlib.redirect_stderr(said):
                cfg = self.settings()
        except SystemExit:
            pass
        now = (cfg.path, cfg.data) if cfg else said.getvalue().strip()
        if now == self.read:
            return
        first, self.read = self.read is None, now
        self.cfg, self.catalog, self.failed, self.tried = cfg, None, 0, 0.0
        self.clear()
        if cfg is None:
            self.show(said.getvalue().strip())
        if not first:
            for uri in list(self.docs):
                self.check(uri)

    def clear(self) -> None:
        """The mistake in rowstile.toml shown last, cleared: the file was fixed, or has another one."""
        if self.marked is not None:
            self.notify("textDocument/publishDiagnostics", {"uri": self.marked, "diagnostics": []})
            self.marked = None
        self.mistake = None

    def show(self, mistake: str) -> None:
        """A mistake in rowstile.toml, as the command says it: on the file (its line), and in a message, for an
        editor that shows only the open files' problems."""
        m = SETTINGS_FILE.match(mistake)
        assert m, mistake  # the command names the file first in each mistake it finds in it
        path, words = m.group(1), m.group(2)
        self.mistake = (path, words)
        line, width = settings_line(path, words)
        self.marked = self.uri_of(path)
        diag: Diagnostic = {"range": rng(line, 0, line, width), "severity": 1, "source": "rowstile", "message": words}
        self.notify("textDocument/publishDiagnostics", {"uri": self.marked, "diagnostics": cast(Json, [diag])})
        message = f"{os.path.basename(path)}: {words} (until it is fixed, the policy is checked without it)"
        self.notify("window/showMessage", {"type": 1, "message": message})

    # --- files -----------------------------------------------------------------------------------
    def uri_of(self, path: str) -> str:
        """The file's URI: as the editor spells it when the file is open there."""
        return self.open.get(same_file(path)) or path_uri(path)

    def text_of(self, path: str) -> str:
        uri = self.uri_of(path)
        if uri in self.docs:
            return self.docs[uri]
        with open(path, encoding="utf-8") as fh:
            return fh.read()

    def includes(self, path: str, text: str) -> dict[str, str]:
        """Included files (name relative to the policy's folder -> text), open buffers first."""
        folder = os.path.dirname(path)
        disk = disk_reader(folder)

        def read(key: str) -> str | None:
            uri = self.uri_of(os.path.join(folder, *key.split("/")))
            return self.docs[uri] if uri in self.docs else disk(key)

        return collect_includes(text, read)

    def named_policy(self) -> str | None:
        """The policy rowstile.toml names. One the command refuses (outside rowstile.toml's folder) is a mistake to
        show on the file being checked: the command stops on it, after saying why on stderr."""
        if self.cfg is None:
            assert (
                self.mistake is not None
            )  # no settings: rowstile.toml has a mistake (read before any file is checked)
            path, words = self.mistake
            raise PolicyError(f"line 1: {os.path.basename(path)}: {words}")
        said = io.StringIO()
        try:
            with contextlib.redirect_stderr(said):
                return self.cfg.policy
        except SystemExit:
            raise PolicyError(f"line 1: {said.getvalue().strip()}") from None

    def included_by(self, path: str) -> tuple[str, str] | None:
        """The policy rowstile.toml names, and its text, when it includes this file: the file is a part of it, not
        a policy."""
        try:
            policy = self.named_policy()
            if not policy or same_file(policy) == same_file(path):
                return None
            folder = os.path.dirname(policy)
            text = self.text_of(policy)
            names = self.includes(policy, text)
        except Exception:
            return None
        part = any(same_file(os.path.join(folder, *n.split("/"))) == same_file(path) for n in names)
        return (policy, text) if part else None

    @staticmethod
    def is_test_file(text: str) -> bool:
        lines = [ln for ln in text.split("\n") if ln.strip() and not ln.lstrip().startswith("--")]
        tops = [ln for ln in lines if not ln[:1].isspace()]
        return bool(tops) and all(re.match(r"test\s+\S", ln) for ln in tops)

    # --- checking --------------------------------------------------------------------------------
    def check(self, uri: str) -> None:
        path, text = uri_path(uri), self.docs[uri]
        diags: dict[str, list[Diagnostic]] = {uri: []}
        main: str | None = None
        against: str | None = None  # for a test file, the policy it is checked against, once it is read
        part = self.included_by(path)
        if part is not None:
            # a file the policy includes is checked as the part of the policy it is: its mistakes land on it
            main, text = part
            path = main
            diags = {uri: [], self.uri_of(main): []}
        try:
            if main is None and self.is_test_file(text):
                policy = self.named_policy()
                if not policy:
                    raise PolicyError('line 1: to check tests, name the policy in rowstile.toml: policy = "..."')
                try:
                    ptext = self.text_of(policy)
                except OSError as e:
                    named = self.cfg.setting(None, "policy") if self.cfg else policy
                    raise PolicyError(f'line 1: rowstile.toml: policy = "{named}": {e.strerror or e}') from None
                against, files = policy, self.includes(policy, ptext)
                c = Compiler(parse_policy(ptext, None, files=files))
                c.add_test_files({THIS: text})
                c.tests_function_sql()
                self.models[uri] = (c.pol, files, policy)
            else:
                files = self.includes(path, text)
                pol = parse_policy(text, None, files=files)
                self.models[uri] = (pol, files, path)
                c = Compiler(pol)
                c.compile("the policy", transaction=False)
                c.tests_function_sql()  # the policy's own test lines, as rowstile test reads them
        except PolicyError as e:
            for mistake in e.errors:  # (every one the parser found; the compiler stops at its first)
                m = ERROR.match(split_code(str(mistake))[0])
                name, line, msg = (
                    (m.group(1), int(m.group(2)), m.group(3)) if m else (None, 1, split_code(str(mistake))[0])
                )
                target = uri if main is None else self.uri_of(main)
                span = mistake.span
                if against is not None and name != THIS:
                    # the policy's own mistake, seen from its test file: said on the test file's first line, with
                    # the policy's file and line (the policy, when it is open, shows it where it is)
                    msg = f"{name or os.path.basename(against)} line {line}: {msg}"
                    line, span = 1, None
                elif name and name != THIS:
                    target = self.uri_of(os.path.join(os.path.dirname(path), *name.split("/")))
                    diags.setdefault(target, [])
                lines = (self.docs.get(target) or "").split("\n")
                width = len(lines[line - 1]) if 0 < line <= len(lines) else 200
                indent = len(lines[line - 1]) - len(lines[line - 1].lstrip()) if 0 < line <= len(lines) else 0
                # the words the mistake is about when the parser knows them, else the line
                where = rng(line - 1, indent, line - 1, width)
                if span:
                    where = rng(span[0] - 1, span[1], span[2] - 1, span[3])
                diag: Diagnostic = {
                    "range": encoded(lines, where),
                    "severity": 1,
                    "source": "rowstile",
                    "message": msg,
                }
                if mistake.code:
                    diag["code"] = mistake.code  # rowstile help AZ201
                diags[target].append(diag)
        except Exception as e:  # a compiler bug must not take the editor down
            diags[uri].append(
                {
                    "range": rng(0, 0, 0, 1),
                    "severity": 2,
                    "source": "rowstile",
                    "message": f"the checker failed: {type(e).__name__}: {e}",
                }
            )
        # a file this check marked last time and doesn't now is cleared: its mistake was fixed
        for target in self.sent.get(uri, set()) - set(diags):
            diags[target] = []
        self.sent[uri] = {target for target, items in diags.items() if items}
        for target, items in diags.items():
            self.notify("textDocument/publishDiagnostics", {"uri": target, "diagnostics": cast(Json, items)})

    def feeds_tests(self, uri: str) -> bool:
        """Whether the file is the policy rowstile.toml names, or a part of it: what test files are checked against."""
        try:
            policy = self.named_policy()
        except PolicyError:
            return False
        if not policy:
            return False
        path = uri_path(uri)
        return same_file(policy) == same_file(path) or self.included_by(path) is not None

    def check_with_tests(self, uri: str) -> None:
        """The file checked, and the open test files with it when they are checked against it."""
        self.check(uri)
        tests = [other for other, body in self.docs.items() if self.is_test_file(body)]
        if tests and self.feeds_tests(uri):
            for other in tests:
                self.check(other)

    def close(self, uri: str) -> None:
        """A file closed: what its checks marked, and no other open file's did, is cleared (an editor keeps the
        last diagnostics it was sent); the open files are checked again if the policy was read from it."""
        self.docs.pop(uri, None)
        self.open.pop(same_file(uri_path(uri)), None)
        self.models.pop(uri, None)
        marked = self.sent.pop(uri, set()) | {uri}
        for target in marked - set().union(*self.sent.values()):
            self.notify("textDocument/publishDiagnostics", {"uri": target, "diagnostics": []})
        if self.feeds_tests(uri):
            for other in list(self.docs):
                self.check(other)

    # --- understanding a position -----------------------------------------------------------------
    @staticmethod
    def block(lines: list[str], line: int) -> tuple[str, str] | tuple[None, None]:
        """('type', type) / ('rules', table) / ('test', None) / (None, None) for the block around a line."""
        for i in range(min(line, len(lines) - 1), -1, -1):
            s = lines[i]
            if not s.strip() or s.lstrip().startswith("--") or s[:1].isspace():
                continue
            m = re.match(r"type\s+([A-Za-z_]\w*)", s)
            if m:
                return "type", m.group(1)
            m = re.match(r"rules\s+([A-Za-z_]\w*\.[A-Za-z_]\w*)", s)
            if m:
                return "rules", m.group(1)
            if s.startswith("test"):
                return "test", ""
            return None, None
        return None, None

    def model(self, uri: str) -> Policy | None:
        got = self.models.get(uri)
        return got[0] if got else None

    @staticmethod
    def home_type(pol: Policy | None, lines: list[str], line: int) -> Type | None:
        kind, name = Server.block(lines, line)
        if not pol:
            return None
        if kind == "type" and name:
            return pol.types.get(name)
        if kind == "rules":
            return next((t for t in pol.types.values() if t.table == name), None)
        return None

    @staticmethod
    def targets(pol: Policy, t: Type, rel: str) -> list[Type]:
        r = t.relations.get(rel)
        if not r:
            return []
        return [pol.types[st] for st, _ in r.subjects() if st in pol.types]

    @staticmethod
    def word_at(lines: list[str], line: int, col: int) -> tuple[list[str] | None, int, str]:
        if line >= len(lines):
            return None, 0, ""
        s = lines[line]
        for m in WORD.finditer(s):
            if m.start() <= col <= m.end():
                # which dotted part the cursor is in: as many as the dots before it (just before a dot: the part
                # it ends)
                return m.group(0).split("."), s[m.start() : col].count("."), s
        return None, 0, s

    def resolve(self, uri: str, line: int, col: int) -> Symbol | None:
        """What the name under the cursor is: a type, one of its members, or None."""
        return self.meaning(self.model(uri), self.docs[uri].split("\n"), line, col)

    def meaning(self, pol: Policy | None, lines: list[str], line: int, col: int) -> Symbol | None:
        """What the name at a place in these lines is, in this policy."""
        parts, i, s = self.word_at(lines, line, col)
        if not pol or not parts:
            return None
        if len(parts) == 2:
            # a relation followed by a permission, or schema.table
            t = self.home_type(pol, lines, line)
            if t and parts[0] in t.relations:
                if i == 0:
                    return Symbol(t, parts[0])
                for target in self.targets(pol, t, parts[0]):
                    if parts[1] in target.perms or parts[1] in target.relations:
                        return Symbol(target, parts[1])
            table = ".".join(parts)
            for t2 in pol.types.values():
                if t2.table == table:
                    return Symbol(t2)
            return None
        name = parts[i]
        stripped = s.strip()
        # a test line: user $x can PERM TYPE ID
        m = re.match(
            r"(?:anyone|\S+\s+\S+(?:\s+with\s+scope\s+[\w:-]+(?:\s*,\s*[\w:-]+)*)?)\s+(?:can|cannot)\s+(\w+)\s+(\w+)",
            stripped,
        )
        if m and self.block(lines, line)[0] == "test" and name in (m.group(1), m.group(2)):
            t = pol.types.get(m.group(2))
            if name == m.group(2) and t:
                return Symbol(t)
            if t and name in t.perms:
                return Symbol(t, name)
        # a sync line (a preview): sync schema.table : PERM
        m = re.match(r"sync\s+(\S+)\s*:\s*(\w+)", stripped)
        if m and name == m.group(2):
            t = next((x for x in pol.types.values() if x.table == m.group(1)), None)
            return Symbol(t, name) if t and name in t.perms else None
        if re.match(r"type\s+" + re.escape(name) + r"\b", stripped) or (
            name in pol.types
            and not stripped.startswith(("can ",))
            and self.block(lines, line)[0] != "rules"
            and self.home_type(pol, lines, line) is None
        ):
            return Symbol(pol.types[name]) if name in pol.types else None
        t = self.home_type(pol, lines, line)
        if t and (name in t.perms or name in t.relations):
            return Symbol(t, name)
        if name in pol.types:
            return Symbol(pol.types[name])
        return None

    # --- answers ---------------------------------------------------------------------------------
    def location(self, uri: str, loc: Loc) -> Location:
        main = self.models[uri][2]
        path = main if loc.file is None else os.path.join(os.path.dirname(main), *loc.file.split("/"))
        return {"uri": self.uri_of(path), "range": rng(loc.line - 1, 0, loc.line - 1, 0)}

    def source_line(self, uri: str, loc: Loc) -> str:
        target = self.location(uri, loc)["uri"]
        try:
            text = self.docs.get(target) or self.text_of(uri_path(target))
            return text.split("\n")[loc.line - 1].strip()
        except (OSError, IndexError):
            return ""

    def hover(self, uri: str, line: int, col: int) -> str | None:
        sym = self.resolve(uri, line, col)
        if not sym:
            return None
        t = sym.type
        if sym.member is None:
            key = ", ".join(f"{c} {ty}" for c, ty in t.key)
            parts = [
                f"**type {t.name}** = `{t.table}` (key {key})"
                + (" — signs in (a principal)" if t.principal and t.name != "user" else "")
            ]
            if t.where:
                parts.append(f"rows hold nothing unless `{t.where}`")
            relations = [r.name for r in t.relations.values() if not r.synthetic]
            if relations:
                parts.append("relations: " + ", ".join(f"`{r}`" for r in relations))
            perms = [p for p in t.perms.values() if not p.hidden]
            if perms:
                parts.append("permissions: " + ", ".join(f"`{p.name}`" for p in perms))
            return "\n\n".join(parts)
        name = sym.member
        pol = self.model(uri)
        if name in t.perms:
            p = t.perms[name]
            inherits = sorted(
                {rel for rel, _ in arrows(p.expr) if pol and any(x.name == t.name for x in self.targets(pol, t, rel))}
            )
            out = f"```authz\n{t.name}.{name} = {p.src}\n```"
            if inherits:
                out += f"\n\ninherits through {', '.join('`' + r + '`' for r in inherits)}: as deep as it goes"
            if denies(p.expr):
                out += "\n\nhas a deny (`not ...`): it holds only where the deny doesn't"
            return out + f"\n\n{t.name}, {p.loc}"
        r = t.relations[name]
        lines = [self.source_line(uri, src.loc) for src in r.sources]
        subjects = ", ".join(st if not sr else f"{st}#{sr}" if sr != "*" else f"{st}:*" for st, sr in r.subjects())
        return (
            f"**{t.name}.{name}**: relation to {subjects}\n\n```authz\n"
            + "\n".join(dict.fromkeys(lines))
            + f"\n```\n\n{t.name}, {r.loc}"
        )

    def definition(self, uri: str, line: int, col: int) -> Location | None:
        sym = self.resolve(uri, line, col)
        if not sym:
            return None
        t, name = sym.type, sym.member
        if name is None:
            return self.location(uri, t.loc)
        perm = t.perms.get(name)
        return self.location(uri, perm.loc if perm else t.relations[name].loc)

    def references(self, uri: str, line: int, col: int) -> list[Location]:
        """Where the name under the cursor is used: in the policy's files (open, or as saved) and its open test
        files."""
        sym = self.resolve(uri, line, col)
        if not sym:
            return []
        key = (sym.type.name, sym.member)
        pol, files, main = self.models[uri]
        paths = [main] + [os.path.join(os.path.dirname(main), *name.split("/")) for name in files]
        uris = [self.uri_of(path) for path in paths]
        for other, body in self.docs.items():
            got = self.models.get(other)
            if got and self.is_test_file(body) and same_file(got[2]) == same_file(main):
                uris.append(other)
        out: list[Location] = []
        for target in uris:
            try:
                lines = self.text_of(uri_path(target)).split("\n")
            except OSError:  # a file it included, gone since: none there
                continue
            for n, s in enumerate(lines):
                code = s.split("--")[0]
                for m in WORD.finditer(code):
                    start = m.start()
                    for part in m.group(0).split("."):
                        other = self.meaning(pol, lines, n, start + 1) if part else None
                        if other and (other.type.name, other.member) == key:
                            out.append({"uri": target, "range": encoded(lines, rng(n, start, n, start + len(part)))})
                        start += len(part) + 1
        return out

    def symbols(self, uri: str) -> list[Symbol_]:
        pol = self.model(uri)
        if not pol:
            return []
        out: list[Symbol_] = []
        lines = self.docs[uri].split("\n")
        if self.is_test_file(self.docs[uri]):
            # a test file's outline is its tests (its model is the policy's, whose types are in another file)
            for n, s in enumerate(lines):
                m = re.match(r'test\s+"?(.*?)"?\s*(?:--.*)?$', s)
                if m and not s[:1].isspace():
                    out.append(
                        {
                            "name": m.group(1) or "test",
                            "kind": KIND_METHOD,
                            "range": rng(n, 0, n, units(s)),
                            "selectionRange": rng(n, 0, n, units(s)),
                        }
                    )
            return out
        for t in pol.types.values():
            if t.loc.file is not None:
                continue
            kids: list[Symbol_] = [
                {
                    "name": r.name,
                    "detail": "relation",
                    "kind": KIND_FIELD,
                    "range": rng(r.loc.line - 1, 0, r.loc.line - 1, 200),
                    "selectionRange": rng(r.loc.line - 1, 0, r.loc.line - 1, 200),
                }
                for r in t.relations.values()
                if not r.synthetic and r.loc.file is None
            ]
            kids += [
                {
                    "name": p.name,
                    "detail": p.src,
                    "kind": KIND_METHOD,
                    "range": rng(p.loc.line - 1, 0, p.loc.line - 1, 200),
                    "selectionRange": rng(p.loc.line - 1, 0, p.loc.line - 1, 200),
                }
                for p in t.perms.values()
                if not p.hidden and p.loc.file is None
            ]
            last = max([t.loc.line] + [k["range"]["end"]["line"] + 1 for k in kids])
            out.append(
                {
                    "name": t.name,
                    "detail": t.table,
                    "kind": KIND_CLASS,
                    "children": kids,
                    "range": rng(t.loc.line - 1, 0, last - 1, 200),
                    "selectionRange": rng(t.loc.line - 1, 0, t.loc.line - 1, 200),
                }
            )
        for n, s in enumerate(self.docs[uri].split("\n")):
            m = re.match(r"rules\s+(\S+)", s)
            if m:
                out.append(
                    {
                        "name": "rules " + m.group(1),
                        "kind": KIND_NAMESPACE,
                        "range": rng(n, 0, n, units(s)),
                        "selectionRange": rng(n, 0, n, units(s)),
                    }
                )
        return out

    def completion(self, uri: str, line: int, col: int) -> list[Completion]:
        pol, lines = self.model(uri), self.docs[uri].split("\n")
        s = lines[line] if line < len(lines) else ""
        before = s[:col]
        items: list[Completion] = []

        def add(names: Iterable[str], kind: int, detail: str = "") -> None:
            for n in names:
                items.append({"label": n, "kind": kind, "detail": detail})

        if not before:
            add(TOP_WORDS, C_KEYWORD)
            return items
        if strip_comment(before) != before:
            return items  # in a comment (an editor asks again at every space typed)
        m = re.search(r"([A-Za-z_]\w*)\.(\w*)$", before)
        in_braces = before.count("{") > before.count("}")
        if m and not in_braces:
            first = m.group(1)
            t = self.home_type(pol, lines, line)
            if t and pol and first in t.relations:
                for target in self.targets(pol, t, first):
                    add([p for p, x in target.perms.items() if not x.hidden], C_METHOD, f"{target.name} permission")
                    add([r for r, x in target.relations.items() if not x.synthetic], C_FIELD, f"{target.name} relation")
                return dedupe(items)
            for table in self.tables():
                schema, _, name = table.partition(".")
                if schema == first:
                    add([name], C_MODULE, "table")
            return items
        if in_braces:
            # the columns of the row the condition is about: a link table's in its where, the share being made in
            # `shared if`, else the type's (in the type, or in the rules of its table)
            ahead = before[: before.rfind("{")]
            link = re.search(rf"({QNAME})\s*\(.*\)\s*where\s*$", ahead)
            if link:
                add(self.tables().get(link.group(1), []), C_FIELD, f"column of {link.group(1)}")
            elif re.search(r"\bshared\b.*\bif\s*$", ahead):
                add(SHARE_FIELDS, C_FIELD, "of the share being made")
            elif t := self.home_type(pol, lines, line):
                add(self.tables().get(t.table, []), C_FIELD, f"column of {t.table}")
            add(["authz.uid()", "authz.ctx('')", "now()"], C_KEYWORD)
            return items
        kind, _ = self.block(lines, line)
        if not s[:1].isspace():
            # a line that begins a block: its first word, then the table after `type x =` and `rules`
            synced = re.match(rf"sync\s+({QNAME})\s*:\s*\w*$", before)
            if re.match(rf"sync\s+{QNAME}(?:\s*:\s*\w+)?\s+by\s+\w*$", before):
                # the type a sync line's readers are keyed by: one whose permission inherits (parent.view)
                if pol:
                    add(
                        sorted(n for n, t in pol.types.items() if any(inherits(t, p) for p in t.perms)), C_CLASS, "type"
                    )
            elif synced:  # a sync line's permission: one of its type's
                t = next((x for x in pol.types.values() if x.table == synced.group(1)), None) if pol else None
                if t:
                    add([p for p, x in t.perms.items() if not x.hidden], C_METHOD, f"{t.name} permission")
            elif re.match(r"sync\s+(?!role\b)\S*$", before):  # the table a sync line names: a type's
                if pol:
                    add(sorted({t.table for t in pol.types.values()}), C_MODULE, "a type's table")
            elif re.match(r"(type\s+\w+\s*=|rules\s)\s*\S*$", before):
                add(self.tables(), C_MODULE, "table")
            elif not re.search(r"\s", before):
                add(TOP_WORDS, C_KEYWORD)
            return items
        if kind == "rules" and re.match(r"\s+cascade\s+from\s+\S*$", before):
            add(self.tables(), C_MODULE, "table")  # the table a foreign key points to
            return items
        t = self.home_type(pol, lines, line)
        if t:
            add([r for r, x in t.relations.items() if not x.synthetic], C_FIELD, "relation")
            add([p for p, x in t.perms.items() if not x.hidden], C_METHOD, "permission")
        if pol:
            add(pol.types, C_CLASS, "type")
        add(EXPR_WORDS, C_KEYWORD)
        add(
            RULE_WORDS
            if kind == "rules"
            else TYPE_WORDS
            if kind == "type"
            else ["given", "as", "can", "cannot", "allowed", "refused", "sees", "with", "scope"],
            C_KEYWORD,
        )
        return dedupe(items)

    def tables(self) -> dict[str, list[str]]:
        """{schema.table: [columns]} from the database in rowstile.toml; empty without one. Only the tables a
        policy can name (no space in the name, say), and each column as a condition names it: quoted where SQL
        needs it ("parentId", "user"). Read once; a database that couldn't be read (not started yet, say) is tried
        again at a completion some seconds later (5, then 10, 20, up to a minute: a try may wait 3 seconds)."""
        if self.catalog is not None:
            return self.catalog
        wait = min(RETRY_MOST, RETRY * 2 ** (self.failed - 1)) if self.failed else 0
        if self.cfg is None or time.monotonic() < self.tried + wait:
            return {}
        catalog: dict[str, list[str]] = {}
        said = io.StringIO()
        try:
            import pgwire

            with contextlib.redirect_stderr(said):
                database = self.cfg.database  # stops the command when it names a variable that isn't set
            if database:
                args = pgwire.parse_dsn(database)
                args["timeout"] = 3
                conn = pgwire.connect(**args)
                try:
                    rows = conn.query(
                        "SELECT c.table_schema, c.table_name, pg_catalog.quote_ident(c.column_name) "
                        "FROM information_schema.columns c "
                        "WHERE c.table_schema NOT IN ('pg_catalog', 'information_schema', 'authz', 'authz_gen', "
                        "'authz_int') ORDER BY 1, 2, c.ordinal_position"
                    )
                finally:
                    conn.close()
                for schema, table, column in rows:
                    if re.fullmatch(IDENT, str(schema)) and re.fullmatch(IDENT, str(table)):
                        catalog.setdefault(f"{schema}.{table}", []).append(str(column))
        except SystemExit:  # its variable isn't set: what the command says of it
            self.failing(said.getvalue().strip())
            return {}
        except Exception as e:  # no database there, or it refused: complete without it, and try again later
            self.failing(f"rowstile lsp: no table or column names to complete: {e}")
            return {}
        self.catalog = catalog
        return catalog

    def failing(self, why: str) -> None:
        """A read of the catalog failed: tried again later, and its log says why (once while the reason stays)."""
        self.failed, self.tried = self.failed + 1, time.monotonic()
        if why != self.said:
            print(why, file=sys.stderr)
            self.said = why

    # --- the protocol ----------------------------------------------------------------------------
    def notify(self, method: str, params: Json) -> None:
        send({"jsonrpc": "2.0", "method": method, "params": params})

    def handle(self, msg: Message) -> None:
        method, params, mid = msg.get("method"), obj(msg.get("params")), msg.get("id")
        result: Json = None
        if method not in ("initialize", "shutdown", "exit"):
            self.load()  # nothing may be sent before initialize is answered
        if method == "initialize":
            result = {
                "capabilities": {
                    "positionEncoding": "utf-16",  # the protocol's own: columns are turned into characters
                    "textDocumentSync": 1,
                    "hoverProvider": True,
                    "definitionProvider": True,
                    "referencesProvider": True,
                    "documentSymbolProvider": True,
                    "completionProvider": {"triggerCharacters": [".", " "]},
                },
                "serverInfo": {"name": "rowstile"},
            }
        elif method == "shutdown":
            result = None
        elif method == "exit":
            self.running = False
            return
        elif method == "textDocument/didOpen":
            doc = obj(params.get("textDocument"))
            self.docs[text(doc, "uri")] = text(doc, "text")
            self.open[same_file(uri_path(text(doc, "uri")))] = text(doc, "uri")
            self.check_with_tests(text(doc, "uri"))
        elif method == "textDocument/didChange":
            uri = text(obj(params.get("textDocument")), "uri")
            changes = params.get("contentChanges")
            if isinstance(changes, list) and changes:
                self.docs[uri] = text(obj(changes[-1]), "text")
            self.check_with_tests(uri)
        elif method == "textDocument/didSave":
            self.check_with_tests(text(obj(params.get("textDocument")), "uri"))
        elif method == "textDocument/didClose":
            self.close(text(obj(params.get("textDocument")), "uri"))
        elif method in (
            "textDocument/hover",
            "textDocument/definition",
            "textDocument/references",
            "textDocument/completion",
        ):
            uri, pos = text(obj(params.get("textDocument")), "uri"), obj(params.get("position"))
            if uri in self.docs:
                line = number(pos, "line")
                lines = self.docs[uri].split("\n")
                col = char_index(lines[line] if 0 <= line < len(lines) else "", number(pos, "character"))
                if method == "textDocument/hover":
                    shown = self.hover(uri, line, col)
                    result = {"contents": {"kind": "markdown", "value": shown}} if shown else None
                elif method == "textDocument/definition":
                    result = cast(Json, self.definition(uri, line, col))
                elif method == "textDocument/references":
                    result = cast(Json, self.references(uri, line, col))
                else:
                    result = cast(Json, self.completion(uri, line, col))
        elif method == "textDocument/documentSymbol":
            uri = text(obj(params.get("textDocument")), "uri")
            result = cast(Json, self.symbols(uri) if uri in self.docs else [])
        elif mid is not None and method is not None:
            send({"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": f"not supported: {method}"}})
            return
        if mid is not None and method is not None:
            send({"jsonrpc": "2.0", "id": mid, "result": result})


def denies(node: Expr) -> bool:
    """Whether the expression takes something away: a `not` over a relation or a permission (a {condition} with
    the word in it is no deny)."""
    match node:
        case Not(Cond(_)):
            return False
        case Not(_):
            return True
        case And(items) | Or(items):
            return any(denies(x) for x in items)
    return False


def arrows(node: Expr) -> list[tuple[str, str]]:
    """(relation, permission) for every rel.perm in an expression."""
    match node:
        case Arrow(rel, perm) | ArrowOn(rel, perm, _):
            return [(rel, perm)]
        case Not(item):
            return arrows(item)
        case And(items) | Or(items):
            return [a for x in items for a in arrows(x)]
    return []


def inherits(t: Type, perm: str) -> bool:
    """Whether a permission inherits through a relation to its own type, as written (`parent.view`): what a sync line
    may be keyed by."""
    p = t.perms[perm]
    return any(
        t.relations.get(rel) is not None and any(st == t.name for st, _ in t.relations[rel].subjects())
        for rel, _ in arrows(p.expr)
    )


def dedupe(items: list[Completion]) -> list[Completion]:
    seen: set[str] = set()
    out: list[Completion] = []
    for i in items:
        if i["label"] not in seen:
            seen.add(i["label"])
            out.append(i)
    return out


def settings_line(path: str, words: str) -> tuple[int, int]:
    """(line, its width) of the mistake in rowstile.toml: the line TOML names, else the setting's, else the first."""
    try:
        with open(path, encoding="utf-8-sig") as fh:
            lines = fh.read().split("\n")
    except (OSError, ValueError):
        return 0, 1
    at = re.search(r"\(at line (\d+), column \d+\)", words)
    found = 0
    if at:
        found = min(int(at.group(1)), len(lines)) - 1
    elif m := re.match(r"(?:\[([\w-]+)\] )?([\w-]+) is |\[([\w-]+)\] is ", words):
        table, key = (m.group(1), m.group(2)) if m.group(2) else (None, m.group(3))
        section = None
        for n, line in enumerate(lines):
            header = re.match(r"\s*\[\s*([\w-]+)\s*\]", line)
            if header:
                section = header.group(1)
            elif section == table and re.match(rf'\s*"?{re.escape(key)}"?\s*=', line):
                found = n
                break
    return found, max(1, units(lines[found]))


def rng(l1: int, c1: int, l2: int, c2: int) -> Range:
    return {"start": {"line": l1, "character": c1}, "end": {"line": l2, "character": c2}}


# The protocol counts a line's columns in UTF-16 code units (a character past U+FFFF, an emoji, is two); the server
# counts characters. Columns are turned into characters as they come, and back as they go.
def units(s: str) -> int:
    """How long s is as the protocol counts columns."""
    return len(s.encode("utf-16-le")) // 2


def char_index(s: str, col: int) -> int:
    """The index in s of a column as the protocol counts it (past its end: as far past)."""
    code = s.encode("utf-16-le")
    return len(code[: 2 * col].decode("utf-16-le", "ignore")) + max(0, col - len(code) // 2)


def encoded(lines: Sequence[str], r: Range) -> Range:
    """A range on these lines, its columns counted in characters, as the protocol counts them."""

    def at(p: Position) -> Position:
        s = lines[p["line"]] if 0 <= p["line"] < len(lines) else ""
        return {"line": p["line"], "character": units(s[: p["character"]]) + max(0, p["character"] - len(s))}

    return {"start": at(r["start"]), "end": at(r["end"])}


def send(message: Message) -> None:
    body = json.dumps(message).encode()
    sys.stdout.buffer.write(b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)
    sys.stdout.buffer.flush()


def read() -> Message | None:
    """The next message; None at the end of the input. One that can't be read (a Content-Length that isn't a number,
    a body that isn't JSON) is answered with a parse error, as JSON-RPC says, and the next one is read."""
    while True:
        headers: dict[str, str] = {}
        while line := sys.stdin.buffer.readline():
            if not line.strip():
                break
            k, _, v = line.decode("latin-1").partition(":")
            headers[k.strip().lower()] = v.strip()
        if not line:
            return None
        length = headers.get("content-length", "0")
        if not re.fullmatch("[0-9]+", length):
            unread("Content-Length is not a number")
            continue
        size = int(length)
        try:
            got = json.loads(sys.stdin.buffer.read(size)) if size else {}
        except (ValueError, RecursionError):  # (nested too deep to read is no JSON this server takes either)
            unread("not JSON")
            continue
        return {str(k): v for k, v in got.items()} if isinstance(got, dict) else {}


def unread(why: str) -> None:
    send({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": why}})


def serve(settings: Callable[[], Config]) -> None:
    server = Server(settings)
    while server.running:
        msg = read()
        if msg is None:
            break
        try:
            server.handle(msg)
        except Exception as e:  # answer and carry on: an editor can't do much with a dead server
            if msg.get("id") is not None:
                send(
                    {
                        "jsonrpc": "2.0",
                        "id": msg["id"],
                        "error": {"code": -32603, "message": f"{type(e).__name__}: {e}"},
                    }
                )
