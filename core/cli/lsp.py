"""The rowstile language server: `rowstile lsp`, the Language Server Protocol over stdin and stdout.

For .authz files: errors while typing (from the compiler), hover, go to definition, find references, an outline,
and completion. It needs nothing but Python's standard library and the compiler next to it. With a database in
rowstile.toml it also completes table and column names (read once from the catalog; a database it can't reach is
tried again later), a column inside { } as SQL names it.

rowstile.toml is read again at each message, so that a change to it is taken at once. A mistake in it is shown on
it (and in a message), and the server goes on without its settings until the mistake is fixed.

A file of named tests (no types, only `test "..."` blocks) is checked against the policy rowstile.toml names.
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
from collections.abc import Callable, Iterable
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
    Expr,
    Loc,
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
TOP_WORDS = ["app role", "type", "rules", "include", "scope", "caveat", "invariants", "test"]
EXPR_WORDS = ["or", "and", "not", "signed_in", "anyone", "nobody"]
RULE_WORDS = ["select", "insert", "update", "delete", "mask", "after", "before"]
TYPE_WORDS = ["can", "shared", "by", "if", "where", "roles", "from", "principal"]
SHARE_FIELDS = ["object_id", "subject_type", "subject_id", "subject_relation"]  # what `shared if {...}` reads
KIND_CLASS, KIND_FIELD, KIND_METHOD, KIND_NAMESPACE = 5, 8, 6, 3  # SymbolKind
C_KEYWORD, C_FIELD, C_METHOD, C_CLASS, C_MODULE = 14, 5, 2, 7, 9  # CompletionItemKind
SETTINGS_FILE = re.compile(r"(.*?(?:rowstile|rowfence)\.toml): (.*)", re.S)  # a mistake in it, as the command says it
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
        self.mistake: tuple[str | None, str] | None = None  # (rowstile.toml, the mistake in it)
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
        if cfg is not None and said.getvalue():
            print(said.getvalue(), end="", file=sys.stderr)  # a note (rowfence.toml is read for now)
        self.cfg, self.catalog, self.failed, self.tried = cfg, None, 0, 0.0
        self.show(None if cfg else said.getvalue().strip() or "rowstile.toml can't be read")
        if not first:
            for uri in list(self.docs):
                self.check(uri)

    def show(self, mistake: str | None) -> None:
        """A mistake in rowstile.toml: on the file (its line), and in a message, for an editor that shows only the
        open files' problems. None: the mistake shown last is cleared."""
        if self.marked is not None:
            self.notify("textDocument/publishDiagnostics", {"uri": self.marked, "diagnostics": []})
            self.marked = None
        self.mistake = None
        if mistake is None:
            return
        m = SETTINGS_FILE.match(mistake)
        path, words = (m.group(1), m.group(2)) if m else (None, mistake)
        self.mistake = (path, words)
        if path is not None:
            line, width = settings_line(path, words)
            self.marked = self.uri_of(path)
            diag: Diagnostic = {
                "range": rng(line, 0, line, width),
                "severity": 1,
                "source": "rowstile",
                "message": words,
            }
            self.notify("textDocument/publishDiagnostics", {"uri": self.marked, "diagnostics": cast(Json, [diag])})
        name = os.path.basename(path) if path else "rowstile.toml"
        message = f"{name}: {words} (until it is fixed, the policy is checked without it)"
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
            if self.mistake is None:
                return None
            path, words = self.mistake
            raise PolicyError(f"line 1: {os.path.basename(path or 'rowstile.toml')}: {words}")
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
                c = Compiler(parse_policy(ptext, None, files=self.includes(policy, ptext)))
                c.add_test_files({THIS: text})
                c.tests_function_sql()
                self.models[uri] = (c.pol, {}, policy)
            else:
                files = self.includes(path, text)
                pol = parse_policy(text, None, files=files)
                self.models[uri] = (pol, files, path)
                Compiler(pol).compile("the policy", transaction=False)
        except PolicyError as e:
            m = ERROR.match(split_code(str(e))[0])
            name, line, msg = (m.group(1), int(m.group(2)), m.group(3)) if m else (None, 1, split_code(str(e))[0])
            target = uri if main is None else self.uri_of(main)
            if name and name != THIS:
                target = self.uri_of(os.path.join(os.path.dirname(path), *name.split("/")))
                diags.setdefault(target, [])
            lines = (self.docs.get(target) or "").split("\n")
            width = len(lines[line - 1]) if 0 < line <= len(lines) else 200
            indent = len(lines[line - 1]) - len(lines[line - 1].lstrip()) if 0 < line <= len(lines) else 0
            diag: Diagnostic = {
                "range": rng(line - 1, indent, line - 1, width),
                "severity": 1,
                "source": "rowstile",
                "message": msg,
            }
            if e.code:
                diag["code"] = e.code  # rowstile help AZ201
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

    # --- understanding a position -----------------------------------------------------------------
    def block(self, uri: str, line: int) -> tuple[str, str] | tuple[None, None]:
        """('type', type) / ('rules', table) / ('test', None) / (None, None) for the block around a line."""
        lines = self.docs[uri].split("\n")
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

    def home_type(self, uri: str, line: int) -> Type | None:
        pol = self.model(uri)
        kind, name = self.block(uri, line)
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

    def word_at(self, uri: str, line: int, col: int) -> tuple[list[str] | None, int, str]:
        lines = self.docs[uri].split("\n")
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
        pol = self.model(uri)
        parts, i, s = self.word_at(uri, line, col)
        if not pol or not parts:
            return None
        if len(parts) == 2:
            # a relation followed by a permission, or schema.table
            t = self.home_type(uri, line)
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
            r"(?:anyone|\S+\s+\S+(?:\s+with\s+scope\s+\w+(?:\s*,\s*\w+)*)?)\s+(?:can|cannot)\s+(\w+)\s+(\w+)",
            stripped,
        )
        if m and self.block(uri, line)[0] == "test" and name in (m.group(1), m.group(2)):
            t = pol.types.get(m.group(2))
            if name == m.group(2) and t:
                return Symbol(t)
            if t and name in t.perms:
                return Symbol(t, name)
        if re.match(r"type\s+" + re.escape(name) + r"\b", stripped) or (
            name in pol.types
            and not stripped.startswith(("can ",))
            and self.block(uri, line)[0] != "rules"
            and self.home_type(uri, line) is None
        ):
            return Symbol(pol.types[name]) if name in pol.types else None
        t = self.home_type(uri, line)
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
            if t.relations:
                parts.append("relations: " + ", ".join(f"`{r}`" for r in t.relations))
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
        sym = self.resolve(uri, line, col)
        if not sym:
            return []
        key = (sym.type.name, sym.member)
        out: list[Location] = []
        for n, s in enumerate(self.docs[uri].split("\n")):
            code = s.split("--")[0]
            for m in WORD.finditer(code):
                start = m.start()
                for part in m.group(0).split("."):
                    other = self.resolve(uri, n, start + 1) if part else None
                    if other and (other.type.name, other.member) == key:
                        out.append({"uri": uri, "range": rng(n, start, n, start + len(part))})
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
                            "range": rng(n, 0, n, len(s)),
                            "selectionRange": rng(n, 0, n, len(s)),
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
                        "range": rng(n, 0, n, len(s)),
                        "selectionRange": rng(n, 0, n, len(s)),
                    }
                )
        return out

    def completion(self, uri: str, line: int, col: int) -> list[Completion]:
        pol = self.model(uri)
        s = self.docs[uri].split("\n")[line] if line < len(self.docs[uri].split("\n")) else ""
        before = s[:col]
        items: list[Completion] = []

        def add(names: Iterable[str], kind: int, detail: str = "") -> None:
            for n in names:
                items.append({"label": n, "kind": kind, "detail": detail})

        if not before.strip() and not before:
            add(TOP_WORDS, C_KEYWORD)
            return items
        if strip_comment(before) != before:
            return items  # in a comment (an editor asks again at every space typed)
        m = re.search(r"([A-Za-z_]\w*)\.(\w*)$", before)
        in_braces = before.count("{") > before.count("}")
        if m and not in_braces:
            first = m.group(1)
            t = self.home_type(uri, line) if pol else None
            if t and pol and first in t.relations:
                for target in self.targets(pol, t, first):
                    add([p for p, x in target.perms.items() if not x.hidden], C_METHOD, f"{target.name} permission")
                    add(target.relations, C_FIELD, f"{target.name} relation")
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
            elif t := self.home_type(uri, line):
                add(self.tables().get(t.table, []), C_FIELD, f"column of {t.table}")
            add(["authz.uid()", "authz.ctx('')", "now()"], C_KEYWORD)
            return items
        kind, _ = self.block(uri, line)
        if not s[:1].isspace():
            # a line that begins a block: its first word, then the table after `type x =` and `rules`
            if re.match(r"(type\s+\w+\s*=|rules\s)\s*\S*$", before):
                add(self.tables(), C_MODULE, "table")
            elif not re.search(r"\s", before):
                add(TOP_WORDS, C_KEYWORD)
            return items
        t = self.home_type(uri, line)
        if t:
            add(t.relations, C_FIELD, "relation")
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
            self.check(text(doc, "uri"))
        elif method == "textDocument/didChange":
            uri = text(obj(params.get("textDocument")), "uri")
            changes = params.get("contentChanges")
            if isinstance(changes, list) and changes:
                self.docs[uri] = text(obj(changes[-1]), "text")
            self.check(uri)
        elif method == "textDocument/didSave":
            self.check(text(obj(params.get("textDocument")), "uri"))
        elif method == "textDocument/didClose":
            closed = text(obj(params.get("textDocument")), "uri")
            self.docs.pop(closed, None)
            self.open.pop(same_file(uri_path(closed)), None)
        elif method in (
            "textDocument/hover",
            "textDocument/definition",
            "textDocument/references",
            "textDocument/completion",
        ):
            uri, pos = text(obj(params.get("textDocument")), "uri"), obj(params.get("position"))
            if uri in self.docs:
                line, col = number(pos, "line"), number(pos, "character")
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
        case ("not", ("cond", _)):
            return False
        case ("not", _):
            return True
        case ("and", items) | ("or", items):
            return any(denies(x) for x in items)
    return False


def arrows(node: Expr) -> list[tuple[str, str]]:
    """(relation, permission) for every rel.perm in an expression."""
    match node:
        case ("arrow", rel, perm) | ("arrow_on", rel, perm, _):
            return [(rel, perm)]
        case ("not", item):
            return arrows(item)
        case ("and", items) | ("or", items):
            return [a for x in items for a in arrows(x)]
    return []


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
    return found, max(1, len(lines[found]))


def rng(l1: int, c1: int, l2: int, c2: int) -> Range:
    return {"start": {"line": l1, "character": c1}, "end": {"line": l2, "character": c2}}


def send(message: Message) -> None:
    body = json.dumps(message).encode()
    sys.stdout.buffer.write(b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)
    sys.stdout.buffer.flush()


def read() -> Message | None:
    length: int | None = None
    while True:
        line = sys.stdin.buffer.readline()
        if not line:
            return None
        line = line.strip()
        if not line:
            break
        k, _, v = line.decode().partition(":")
        if k.lower() == "content-length":
            length = int(v)
    got = json.loads(sys.stdin.buffer.read(length)) if length else {}
    return {str(k): v for k, v in got.items()} if isinstance(got, dict) else {}


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
