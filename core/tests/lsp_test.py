#!/usr/bin/env python3
"""lsp_test.py: the language server (`rowstile lsp`) over its protocol, as an editor would use it.
No database needed; where one is (createdb works: the PG* variables), also the completion of its tables and
columns.   python3 tests/lsp_test.py"""

import json
import os
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
fails = 0
# an answer from the server: its shape is what the checks check
Answer = Any


def ok(what: str, cond: object, got: Answer = None) -> None:
    global fails
    if cond:
        print(f"ok    {what}")
    else:
        fails += 1
        print(f"FAIL  {what}{': ' + json.dumps(got)[:400] if got is not None else ''}")


class Client:
    def __init__(self, cwd: str) -> None:
        self.p = subprocess.Popen(
            [sys.executable, os.path.join(ROOT, "cli", "rowstile_cli.py"), "lsp"],
            cwd=cwd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,  # the editor's log for the server
        )
        assert self.p.stdin is not None and self.p.stdout is not None and self.p.stderr is not None
        self.stdin, self.stdout, self.stderr = self.p.stdin, self.p.stdout, self.p.stderr
        self.n = 0
        self.notes: list[Answer] = []

    def send(self, obj: object, headers: bytes = b"") -> None:
        body = json.dumps(obj).encode()
        try:
            self.stdin.write(headers + b"Content-Length: %d\r\n\r\n" % len(body) + body)
            self.stdin.flush()
        except OSError:
            pass  # the server ended: the answer that doesn't come says so

    def read(self) -> Answer:
        """The next message, None once the server has ended (then poll() says so)."""
        length = -1
        while True:
            line = self.stdout.readline()
            if not line:
                self.p.wait(timeout=10)
                return None
            if not line.strip():
                break
            if line.lower().startswith(b"content-length:"):
                length = int(line.split(b":")[1])
        return json.loads(self.stdout.read(length))

    def request(self, method: str, params: object, headers: bytes = b"") -> Answer:
        self.n += 1
        self.send({"jsonrpc": "2.0", "id": self.n, "method": method, "params": params}, headers)
        while True:
            msg = self.read()
            if msg is None:
                return None
            if msg.get("id") == self.n:
                return msg.get("result", msg.get("error"))
            self.notes.append(msg)

    def notify(self, method: str, params: object) -> None:
        self.send({"jsonrpc": "2.0", "method": method, "params": params})

    def diagnostics(self, uri: str) -> Answer:
        """The next diagnostics published for uri (a request in between flushes them)."""
        self.request("textDocument/documentSymbol", {"textDocument": {"uri": uri}})
        found = [
            m for m in self.notes if m.get("method") == "textDocument/publishDiagnostics" and m["params"]["uri"] == uri
        ]
        self.notes.clear()
        return found[-1]["params"]["diagnostics"] if found else None

    def close(self) -> str:
        """Ends the server as an editor does; what it wrote on stderr."""
        if self.p.poll() is None:
            self.request("shutdown", None)
            self.notify("exit", None)
            self.p.wait(timeout=10)
        return self.stderr.read().decode()


def rng(l1: int, c1: int, l2: int, c2: int) -> Answer:
    return {"start": {"line": l1, "character": c1}, "end": {"line": l2, "character": c2}}


def uri(path: str) -> str:
    return Path(os.path.abspath(path)).as_uri()


def labels_of(answer: Answer) -> list[str]:
    """A completion's labels, in order (an error, or no answer, says so instead)."""
    return [i["label"] for i in answer] if isinstance(answer, list) else [f"no list: {answer}"]


def pos(text: str, needle: str, offset: int = 0, nth: int = 0) -> dict[str, int]:
    """(line, character) of the nth occurrence of needle, plus offset characters."""
    start = -1
    for _ in range(nth + 1):
        start = text.index(needle, start + 1)
    line = text.count("\n", 0, start)
    return {"line": line, "character": start - (text.rfind("\n", 0, start) + 1) + offset}


class Editor:
    """A file open in the editor, being typed: each question is asked once the file reads the text given (which
    may not parse, as while typing)."""

    def __init__(self, c: Client, path: str, text: str) -> None:
        self.c, self.u, self.shown = c, uri(path), text
        c.notify(
            "textDocument/didOpen", {"textDocument": {"uri": self.u, "languageId": "authz", "version": 1, "text": text}}
        )

    def ask(self, method: str, text: str, needle: str, offset: int, nth: int = 0) -> Answer:
        """method at needle + offset (its nth occurrence) in text."""
        if text != self.shown:
            change = {"textDocument": {"uri": self.u, "version": 2}, "contentChanges": [{"text": text}]}
            self.c.notify("textDocument/didChange", change)
            self.shown = text
        return self.c.request(method, {"textDocument": {"uri": self.u}, "position": pos(text, needle, offset, nth)})

    def offered(self, text: str, needle: str, offset: int, nth: int = 0) -> list[str]:
        return labels_of(self.ask("textDocument/completion", text, needle, offset, nth))


def value(hover: Answer) -> str:
    return hover["contents"]["value"] if isinstance(hover, dict) and "contents" in hover else ""


with tempfile.TemporaryDirectory() as d:
    with open(os.path.join(ROOT, "example", "docs.authz"), encoding="utf-8") as fh:
        policy = fh.read()
    path = os.path.join(d, "policy.authz")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(policy)
    with open(os.path.join(d, "rowstile.toml"), "w", encoding="utf-8") as fh:
        fh.write('policy = "policy.authz"\n')
    u = uri(path)
    c = Client(d)
    caps = c.request("initialize", {"processId": None, "rootUri": uri(d), "capabilities": {}})
    ok(
        "initialize says what it can do",
        caps["capabilities"].get("hoverProvider") and caps["capabilities"].get("completionProvider"),
        caps,
    )
    c.notify("textDocument/didOpen", {"textDocument": {"uri": u, "languageId": "authz", "version": 1, "text": policy}})
    ok("a good policy has no errors", c.diagnostics(u) == [], c.diagnostics(u))

    broken = policy.replace("can edit  = share or editor", "can edit  = share or edtor", 1)
    c.notify("textDocument/didChange", {"textDocument": {"uri": u, "version": 2}, "contentChanges": [{"text": broken}]})
    d1 = c.diagnostics(u)
    want = pos(broken, "edtor")["line"]
    ok(
        "a mistake shows up while typing, on its line",
        d1 and d1[0]["range"]["start"]["line"] == want and "edtor" in d1[0]["message"],
        d1,
    )
    ok(
        "... the name it is about underlined, not the whole line",
        d1 and d1[0]["range"] == {"start": pos(broken, "edtor"), "end": pos(broken, "edtor", 5)},
        d1,
    )
    ok(
        "... with its code beside the message (rowstile help AZ203)",
        d1 and d1[0].get("code") == "AZ203" and not d1[0]["message"].endswith("]"),
        d1,
    )
    c.notify("textDocument/didChange", {"textDocument": {"uri": u, "version": 3}, "contentChanges": [{"text": policy}]})
    ok("... and goes away when fixed", c.diagnostics(u) == [])

    def at(needle: str, offset: int = 1, nth: int = 0) -> dict[str, object]:
        return {"textDocument": {"uri": u}, "position": pos(policy, needle, offset, nth)}

    h = c.request("textDocument/hover", at("parent.share", len("parent.") + 1))
    ok(
        "hover on parent.share shows folder.share",
        h and "folder.share = owner or org.admin" in h["contents"]["value"],
        h,
    )
    ok("... and that it inherits through parent", h and "inherits through `parent`" in h["contents"]["value"], h)
    h = c.request("textDocument/hover", at("folder.edit and owner", 1))
    ok("hover on a relation in rules shows where it comes from", h and "folder_id" in h["contents"]["value"], h)
    h = c.request("textDocument/hover", at("type team", 6))
    ok(
        "hover on a type shows its table and key",
        h and "app.teams" in h["contents"]["value"] and "id bigint" in h["contents"]["value"],
        h,
    )

    dfn = c.request("textDocument/definition", at("org.admin", len("org.") + 1))
    ok(
        "definition of org.admin is the admin line of org",
        dfn and dfn["range"]["start"]["line"] == pos(policy, "admin  : user")["line"],
        dfn,
    )
    rule = "  select                            : view"
    dfn = c.request("textDocument/definition", at(rule, rule.index("view")))
    ok(
        "definition of a permission in rules goes to the type's",
        dfn and dfn["range"]["start"]["line"] == pos(policy, "can view  = edit or viewer", 0, 1)["line"],
        dfn,
    )

    refs = c.request("textDocument/references", at("can share = owner or org.admin", 5))
    lines = sorted({r["range"]["start"]["line"] for r in refs or []})
    ok("references of folder.share include parent.share and the rules", len(lines) >= 4, refs)

    line = pos(policy, "  can edit  = share or editor")["line"]
    comp = c.request(
        "textDocument/completion",
        {
            "textDocument": {"uri": u},
            "position": {"line": line, "character": len("  can edit  = share or editor or (parent.")},
        },
    )
    labels = {i["label"] for i in comp or []}
    ok("completion after parent. offers folder's permissions", {"share", "edit", "view"} <= labels, sorted(labels))
    comp = c.request(
        "textDocument/completion", {"textDocument": {"uri": u}, "position": {"line": line, "character": 4}}
    )
    labels = {i["label"] for i in comp or []}
    ok(
        "completion inside a type offers its relations and permissions",
        {"owner", "parent", "view"} <= labels,
        sorted(labels),
    )

    syms = c.request("textDocument/documentSymbol", {"textDocument": {"uri": u}})
    folder = next((s for s in syms if s["name"] == "folder"), None)
    ok(
        "the outline lists types with their permissions",
        folder and {"share", "edit", "view"} <= {k["name"] for k in folder["children"]},
        syms,
    )

    tests = os.path.join(d, "policy.test.authz")
    good = "test \"owner\"\n  given ann = {INSERT INTO app.users (id, name) VALUES (1, 'Ann') RETURNING id}\n  user $ann cannot view file 1\n"
    tu = uri(tests)
    c.notify("textDocument/didOpen", {"textDocument": {"uri": tu, "languageId": "authz", "version": 1, "text": good}})
    ok("a test file is checked against the policy in rowstile.toml", c.diagnostics(tu) == [], c.diagnostics(tu))
    bad = good.replace("cannot view file", "cannot vew file")
    c.notify("textDocument/didChange", {"textDocument": {"uri": tu, "version": 2}, "contentChanges": [{"text": bad}]})
    d2 = c.diagnostics(tu)
    ok(
        "... and a permission that doesn't exist is marked on its line",
        d2 and d2[0]["range"]["start"]["line"] == 2 and "vew" in d2[0]["message"],
        d2,
    )
    c.close()

    # rowstile.toml names a variable for the database that the editor's environment doesn't have, a database the
    # connection refuses before it starts, or one that never answers (something listens there and says nothing):
    # completion goes on without it, waiting a few seconds at most, and the server's log says why
    silent = socket.socket()
    silent.bind(("127.0.0.1", 0))
    silent.listen()
    for label, setting, why in (
        (
            "a variable the editor's environment doesn't have",
            '"env:ROWSTILE_LSP_TEST_NOT_SET"',
            "ROWSTILE_LSP_TEST_NOT_SET is not set",
        ),
        (
            "a connection the command can't make (client certificates)",
            '"dbname=authz_lsp sslcert=client.crt"',
            "rowstile lsp: no table or column names to complete: the connection asks for client certificates",
        ),
        (
            "a database that never answers",
            f'"host=127.0.0.1 port={silent.getsockname()[1]} dbname=authz_lsp"',
            f"rowstile lsp: no table or column names to complete: 127.0.0.1 port {silent.getsockname()[1]}: no answer "
            "in 3 s (connect_timeout)",
        ),
    ):
        with open(os.path.join(d, "rowstile.toml"), "w", encoding="utf-8") as fh:
            fh.write(f'policy = "policy.authz"\ndatabase = {setting}\n')
        c = Client(d)
        c.request("initialize", {"capabilities": {}})
        c.notify(
            "textDocument/didOpen", {"textDocument": {"uri": u, "languageId": "authz", "version": 1, "text": policy}}
        )
        line = pos(policy, "  can edit  = share or editor")["line"]
        names = c.request(
            "textDocument/completion", {"textDocument": {"uri": u}, "position": {"line": line, "character": 4}}
        )
        typed = policy + "\ntype extra = app.\n"
        c.notify(
            "textDocument/didChange", {"textDocument": {"uri": u, "version": 2}, "contentChanges": [{"text": typed}]}
        )
        after_dot = {"textDocument": {"uri": u}, "position": pos(typed, "type extra = app.", len("type extra = app."))}
        start = time.monotonic()
        tables = c.request("textDocument/completion", after_dot)
        waited = time.monotonic() - start
        again = c.request("textDocument/completion", after_dot)  # the database is tried once, and said once
        alive = c.p.poll() is None
        said = c.close()
        ok(
            f"database in rowstile.toml, {label}: no tables after app., the policy's names, the server goes on",
            tables == [] and again == [] and alive and {"owner", "view"} <= {i["label"] for i in names or []},
            [tables, again, names],
        )
        ok(
            "... its log says why, once, and the completion that tried waited 3 seconds at most",
            said.count(why) == 1 and waited < 6,
            [said, f"waited {waited:.1f}s"],
        )
    silent.close()


def flushed(c: Client, u: str) -> tuple[dict[str, Answer], list[Answer]]:
    """What the server sent since the last question, once it has answered one: the last diagnostics for each file,
    and its messages (window/showMessage)."""
    c.request("textDocument/documentSymbol", {"textDocument": {"uri": u}})
    diags = {m["params"]["uri"]: m["params"]["diagnostics"] for m in c.notes if m.get("method").endswith("Diagnostics")}
    shown = [m["params"] for m in c.notes if m.get("method") == "window/showMessage"]
    c.notes.clear()
    return diags, shown


# a mistake in rowstile.toml: the server starts all the same, shows it on rowstile.toml (its line) and in a message,
# checks the policy without the file's settings, and takes the file again once it is fixed
with tempfile.TemporaryDirectory() as d:
    path = os.path.join(d, "policy.authz")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(policy)
    toml = os.path.join(d, "rowstile.toml")
    with open(toml, "w", encoding="utf-8") as fh:
        fh.write('policy = "policy.authz"\npolcy_tests = ["t.authz"]\n')
    u, tu, mu = uri(path), uri(os.path.join(d, "t.authz")), uri(toml)
    c = Client(d)
    caps = c.request("initialize", {"processId": None, "rootUri": uri(d), "capabilities": {}})
    c.notify("initialized", {})
    diags, shown = flushed(c, u)
    unknown = (
        "polcy_tests is not a setting rowstile knows (policy, tests, database, and the tables [clients], "
        "[migrations], [review])"
    )
    ok(
        "a setting rowstile.toml shouldn't have: the server starts all the same",
        isinstance(caps, dict) and caps["capabilities"].get("completionProvider") and c.p.poll() is None,
        caps,
    )
    ok(
        "... the mistake shown on rowstile.toml, on its line, and in a message",
        diags.get(mu) == [{"range": rng(1, 0, 1, 25), "severity": 1, "source": "rowstile", "message": unknown}]
        and shown
        == [{"type": 1, "message": f"rowstile.toml: {unknown} (until it is fixed, the policy is checked without it)"}],
        [diags, shown],
    )
    c.notify("textDocument/didOpen", {"textDocument": {"uri": u, "languageId": "authz", "version": 1, "text": broken}})
    diags, shown = flushed(c, u)
    ok(
        "... the open policy checked without it: its own mistake shown, nothing said again",
        [x["message"].startswith("folder has no relation or permission 'edtor'") for x in diags.get(u, [])] == [True]
        and mu not in diags
        and shown == [],
        [diags, shown],
    )
    c.notify("textDocument/didOpen", {"textDocument": {"uri": tu, "languageId": "authz", "version": 1, "text": good}})
    diags, _ = flushed(c, u)
    ok(
        "... a test file, which needs the policy rowstile.toml names: the mistake at its line 1",
        diags.get(tu)
        == [
            {
                "range": rng(0, 0, 0, len(good.split("\n")[0])),
                "severity": 1,
                "source": "rowstile",
                "message": f"rowstile.toml: {unknown}",
            }
        ],
        diags,
    )
    with open(toml, "w", encoding="utf-8") as fh:
        fh.write('policy = "policy.authz\n')
    c.notify("textDocument/didChange", {"textDocument": {"uri": u, "version": 2}, "contentChanges": [{"text": policy}]})
    diags, shown = flushed(c, u)
    ok(
        "a mistake in TOML: shown on the line TOML names, and said once more",
        [(x["range"], "(at line 1, column 23)" in x["message"]) for x in diags.get(mu, [])]
        == [(rng(0, 0, 0, 22), True)]
        and len(shown) == 1
        and "(at line 1, column 23)" in shown[0]["message"],
        [diags, shown],
    )
    # the line of each kind of mistake: the setting's under its [table]; the first line for one it can't find (a
    # name in quotes, a table written inline) or a file it can't read (not UTF-8)
    lines = []
    for text in (
        b'policy = "policy.authz"\n[migrations]\ntool = "alembic"\ntol = "x"\n',
        b'policy = "policy.authz"\n"my key" = 1\n',
        b'policy = "policy.authz"\nclients = { py = 3 }\n',
        b'policy = "\xff"\n',
    ):
        with open(toml, "wb") as fh:
            fh.write(text)
        c.notify("textDocument/didSave", {"textDocument": {"uri": u}})
        diags, shown = flushed(c, u)
        lines += [(x["range"], x["message"][:40]) for x in diags.get(mu, [])]
    ok(
        "each mistake on its line: the setting's under its [table], else the first line",
        lines
        == [
            (rng(3, 0, 3, 9), "[migrations] tol is not a setting rowsti"),
            (rng(0, 0, 0, 23), "my key is not a setting rowstile knows ("),
            (rng(0, 0, 0, 23), "[clients] py is text: py = ..."),
            (rng(0, 0, 0, 1), "'utf-8' codec can't decode byte 0xff in "),
        ],
        lines,
    )
    with open(toml, "w", encoding="utf-8") as fh:
        fh.write('policy = "policy.authz"\n')
    c.notify("textDocument/didSave", {"textDocument": {"uri": u}})
    diags, shown = flushed(c, u)
    ok(
        "rowstile.toml fixed: its mistake cleared at the next message, and its settings taken (the test file checks)",
        diags.get(mu) == [] and diags.get(tu) == [] and diags.get(u) == [] and shown == [],
        [diags, shown],
    )
    said = c.close()
    ok("... and the server's log has nothing of it", said == "", said)
    # the old name, read for now: the note the command gives, in the server's log, once
    os.rename(toml, os.path.join(d, "rowfence.toml"))
    c = Client(d)
    c.request("initialize", {"capabilities": {}})
    c.notify("initialized", {})
    c.notify("textDocument/didOpen", {"textDocument": {"uri": tu, "languageId": "authz", "version": 1, "text": good}})
    diags, shown = flushed(c, u)
    said = c.close()
    ok(
        "rowfence.toml (the old name): read, and its log says to rename it, once",
        diags.get(tu) == [] and shown == [] and said.count("rowfence.toml: rowstile was called rowfence") == 1,
        [diags, shown, said],
    )

# a policy split into files: the included file is a part of the policy, opened alone or not
with tempfile.TemporaryDirectory() as d:
    main_text = (
        'app role app_user\ninclude "org.authz"\ntype user = app.users\ntype doc = app.docs\n  org   : org = org_id\n'
        "  owner : user = owner_id\n  can view = owner or org.see\n  can edit = owner and {deleted_at is not null}\n"
        "rules app.docs\n  select : view\n"
    )
    org_text = "type org = app.orgs\n  member : user = app.org_members(org_id -> user_id)\n  can see = member\n"
    tests_text = 'test "first"\n  user 1 can view doc 1\n\ntest "second"\n  user 1 can view doc 1\n'
    for name, body in (
        ("policy.authz", main_text),
        ("org.authz", org_text),
        ("t.authz", tests_text),
        ("rowstile.toml", 'policy = "policy.authz"\n'),
    ):
        with open(os.path.join(d, name), "w", encoding="utf-8") as fh:
            fh.write(body)
    # the included file's URI as an editor may spell it: not the way the server would (VS Code on Windows: c%3A)
    pu, ou, tu = (
        uri(os.path.join(d, "policy.authz")),
        uri(os.path.join(d, "org.authz")).replace("org.authz", "org%2Eauthz"),
        uri(os.path.join(d, "t.authz")),
    )
    c = Client(d)
    c.request("initialize", {"capabilities": {}})

    def opened(u: str, body: str) -> None:
        c.notify(
            "textDocument/didOpen", {"textDocument": {"uri": u, "languageId": "authz", "version": 1, "text": body}}
        )

    def changed(u: str, body: str) -> None:
        c.notify(
            "textDocument/didChange", {"textDocument": {"uri": u, "version": 2}, "contentChanges": [{"text": body}]}
        )

    opened(ou, org_text)
    ok(
        "an included file opened alone is checked as part of its policy: no mistake",
        c.diagnostics(ou) == [],
        c.diagnostics(ou),
    )
    opened(pu, main_text)
    changed(ou, org_text.replace("can see = member", "can see = nosuch"))
    found = c.diagnostics(ou)
    ok(
        "a mistake typed into it is marked on it, on its line",
        found
        and found[0]["range"]["start"]["line"] == 2
        and "org has no relation or permission 'nosuch'" in found[0]["message"],
        found,
    )
    changed(pu, main_text + "\n")
    found = c.diagnostics(ou)
    ok(
        "... and seen from the policy while it is not saved (the open buffer, whatever its URI's spelling)",
        found and "no relation or permission 'nosuch'" in found[0]["message"],
        found,
    )
    changed(ou, org_text)
    ok("fixed: its mistake is cleared", c.diagnostics(ou) == [], c.diagnostics(ou))
    c.notify("textDocument/didClose", {"textDocument": {"uri": ou}})
    with open(os.path.join(d, "org.authz"), "w", encoding="utf-8") as fh:
        fh.write(org_text.replace("can see = member", "can see = nosuch"))
    changed(pu, main_text)
    on_disk = uri(os.path.join(d, "org.authz"))
    found = c.diagnostics(on_disk)
    ok(
        "a mistake in an included file that is not open is published for it",
        found and "no relation or permission 'nosuch'" in found[0]["message"],
        found,
    )
    with open(os.path.join(d, "org.authz"), "w", encoding="utf-8") as fh:
        fh.write(org_text)
    changed(pu, main_text + "\n")
    ok("... and cleared when the file is fixed", c.diagnostics(on_disk) == [], c.diagnostics(on_disk))
    opened(tu, tests_text)
    syms = c.request("textDocument/documentSymbol", {"textDocument": {"uri": tu}})
    ok(
        "a test file's outline is its tests",
        [(s["name"], s["range"]["start"]["line"]) for s in syms] == [("first", 0), ("second", 3)],
        syms,
    )
    h = c.request(
        "textDocument/hover", {"textDocument": {"uri": pu}, "position": pos(main_text, "can edit = owner and", 5)}
    )
    ok("'is not null' in a condition is no deny", h and "has a deny" not in h["contents"]["value"], h)
    c.close()

# what an editor asks less often: a type with a where, a deny, completion at the start of a line, after a schema
# and inside braces, a save, a request the server doesn't know, a parameter of the wrong kind, questions about
# nothing, and a test file when no policy is named (no rowstile.toml here)
with tempfile.TemporaryDirectory() as d:
    small = (
        "app role app_user\ntype user = app.users\n\n"
        "type doc = app.docs where {deleted_at is null}\n"
        "  owner  : user = owner_id\n"
        "  banned : user = app.bans(doc_id -> user_id)\n"
        "  can view = owner and not banned\n\n"
        "rules app.docs\n  select : view\n"
    )
    path = os.path.join(d, "policy.authz")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(small)
    u = uri(path)
    c = Client(d)
    c.request("initialize", {"capabilities": {}})
    c.notify("textDocument/didOpen", {"textDocument": {"uri": u, "languageId": "authz", "version": 1, "text": small}})
    ok("a policy with a type's where and a deny has no errors", c.diagnostics(u) == [], c.diagnostics(u))
    blank = {"textDocument": {"uri": u}, "position": {"line": 2, "character": 0}}  # the empty line

    def where(needle: str, offset: int) -> dict[str, object]:
        return {"textDocument": {"uri": u}, "position": pos(small, needle, offset)}

    def labels(needle: str, offset: int) -> set[str]:
        return {i["label"] for i in c.request("textDocument/completion", where(needle, offset)) or []}

    h = c.request("textDocument/hover", where("type doc", 6))
    ok(
        "hover on a type says what its where leaves out",
        h and "rows hold nothing unless `deleted_at is null`" in h["contents"]["value"],
        h,
    )
    h = c.request("textDocument/hover", where("can view", 5))
    ok("hover on a permission with a deny says so", h and "has a deny" in h["contents"]["value"], h)
    ok("hover on nothing answers nothing", c.request("textDocument/hover", blank) is None)
    ok("references of nothing: none", c.request("textDocument/references", blank) == [])
    dfn = c.request("textDocument/definition", where("owner  : user", len("owner  : ") + 1))
    ok("definition of a type named in a relation is the type", dfn and dfn["range"]["start"]["line"] == 1, dfn)

    got = c.request("textDocument/completion", blank)
    ok(
        "completion on an empty line offers what a line begins with",
        {"type", "rules", "include"} <= {i["label"] for i in got or []},
        got,
    )
    ok(
        "... and so does a line begun without indent, up to its first word's end",
        {"type", "rules"} <= labels("rules app.docs", 3) and "rules" in labels("rules app.docs", 5),
    )
    ok("completion after a schema's dot, with no database: no tables, and no error", labels("= app.bans", 6) == set())
    ok(
        "completion inside braces offers the functions a condition may call",
        {"authz.uid()", "now()"} <= labels("{deleted_at", 4),
        sorted(labels("{deleted_at", 4)),
    )

    c.notify("textDocument/didSave", {"textDocument": {"uri": u}})
    ok("saving checks the file again", c.diagnostics(u) == [])
    e = c.request("textDocument/rename", {"textDocument": {"uri": u}})
    ok("a request it doesn't know is answered: not supported", e and e.get("code") == -32601, e)
    e = c.request("textDocument/hover", {"textDocument": {"uri": 5}, "position": {"line": 0, "character": 0}})
    ok("a parameter of the wrong kind is answered with an error", e and "uri: text expected" in e.get("message", ""), e)
    e = c.request("textDocument/hover", {"textDocument": {"uri": u}, "position": {"line": "0", "character": 0}})
    ok("... and a position that isn't a number", e and "a number expected" in e.get("message", ""), e)
    ok("... and the server goes on", c.request("textDocument/hover", where("type doc", 6)) is not None)

    tests = os.path.join(d, "t.authz")
    tu = uri(tests)
    body = 'test "first"\n  user 1 can view doc 1\n'
    c.notify("textDocument/didOpen", {"textDocument": {"uri": tu, "languageId": "authz", "version": 1, "text": body}})
    d3 = c.diagnostics(tu)
    ok(
        "a test file with no policy named says where to name it",
        d3 and "name the policy in rowstile.toml" in d3[0]["message"],
        d3,
    )
    c.notify("textDocument/didClose", {"textDocument": {"uri": tu}})
    ok(
        "a closed file's outline is empty",
        c.request("textDocument/documentSymbol", {"textDocument": {"uri": tu}}) == [],
    )
    said = c.close()
    ok("with no database in rowstile.toml it tries none (not the PG* variables): nothing in its log", said == "", said)


# what an editor meets while the docs policy is being typed: a comment, a line's first word, a condition on a
# share, names misspelled or half typed, a line or a block out of place, a file that never parsed or is nested
# too deep to read, a change that sends no text
FUNCTIONS = ["authz.uid()", "authz.ctx('')", "now()"]  # what a condition may call, offered after its columns
with tempfile.TemporaryDirectory() as d:
    path = os.path.join(d, "policy.authz")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(policy)
    with open(os.path.join(d, "rowstile.toml"), "w", encoding="utf-8") as fh:
        fh.write('policy = "policy.authz"\n')
    c = Client(d)
    c.request("initialize", {"capabilities": {}})
    e = Editor(c, path, policy)

    noted = policy + "\n-- who may see what \n"
    in_comments = [
        e.offered(noted, "-- type      maps", len("-- type ")),
        e.offered(noted, "  -- support: an org admin", len("  -- support: ")),
        e.offered(noted, "-- also shown inside these", len("-- also shown inside these")),
        e.offered(noted, "-- who may see what ", len("-- who may see what ")),
    ]
    ok("inside a comment nothing is offered (an editor asks at each space typed)", in_comments == [[]] * 4, in_comments)
    begun = policy + "\ntype extra = \n"
    after_first = [
        e.offered(begun, "type extra = ", len("type ")),
        e.offered(begun, "app role app_user", len("app role ")),
        e.offered(begun, "type extra = ", len("type extra = ")),
    ]
    ok(
        "after a line's first word nothing is offered: a name comes next (no database: no table after `type x =`)",
        after_first == [[]] * 3,
        after_first,
    )
    shared = policy.replace(
        "  editor      : user, team#member shared\n", "  editor      : user, team#member shared if {\n"
    )
    got = e.offered(shared, "shared if {", len("shared if {"))
    ok(
        "inside `shared if { }`: what the share being made has, then the functions",
        got == ["object_id", "subject_type", "subject_id", "subject_relation", *FUNCTIONS],
        got,
    )

    h = e.ask("textDocument/hover", policy, "can view  = edit or viewer", len("can v"), nth=1)
    ok(
        "hover on file.view: `not {confidential}` is a condition, no deny",
        "{confidential}" in value(h) and "deny" not in value(h),
        h,
    )
    h = e.ask("textDocument/hover", policy, "type user", len("type u"))
    ok(
        "hover on a type with no relations: its table and permissions, no relations line",
        "**type user** = `app.users`" in value(h)
        and "permissions: `impersonate`" in value(h)
        and "relations" not in value(h),
        h,
    )
    blank = policy.split("\n").index("")
    got = c.request(
        "textDocument/definition", {"textDocument": {"uri": e.u}, "position": {"line": blank, "character": 0}}
    )
    ok("definition of nothing: none", got is None and c.p.poll() is None, got)
    past = {"textDocument": {"uri": e.u}, "position": {"line": len(policy.split("\n")) + 3, "character": 0}}
    got = c.request("textDocument/hover", past)
    ok("hover past the last line (a file that just got shorter): none", got is None and c.p.poll() is None, got)

    typo = policy.replace(
        "can edit  = share or editor or (parent.edit and {inherit})",
        "can edit  = share or editor or (parent.edt and {inherit}) or nosuch.view",
    ).replace("  user 3 can view file 11", "  user 3 can vew file 11")
    got = e.ask("textDocument/hover", typo, "parent.edt", len("parent.e"))
    ok("hover on a permission misspelled after rel.: none", got is None and c.p.poll() is None, got)
    h = e.ask("textDocument/hover", typo, "can edit  = share or editor or (parent.edt", len("can e"))
    ok(
        "hover on a permission that follows a relation the type doesn't have: it inherits through the one it has",
        "or nosuch.view" in value(h) and "inherits through `parent`: as deep" in value(h),
        h,
    )
    got = e.ask("textDocument/hover", typo, "user 3 can vew file 11", len("user 3 can v"))
    ok("hover on a permission a test misspells: none", got is None and c.p.poll() is None, got)
    stray = policy.replace("app role app_user", "  owner : user = owner_id\napp role app_user")
    got = e.offered(stray, "  owner : user = owner_id", len("  owner : "))
    ok(
        "an indented line before any block: the types, no type's relations, no rule's words",
        "folder" in got and "parent" not in got and "select" not in got,
        got,
    )
    loose = policy + "\nrules app.notes\n  delete : view\n"
    got = e.offered(loose, "  delete : view", len("  delete : "))
    ok(
        "in the rules of a table no type maps to (yet): a rule's words, no type's relations or permissions",
        "select" in got and "owner" not in got and "impersonate" not in got,
        got,
    )
    # cut short and not parsing: the policy that last parsed still says what a name is, though its line is gone
    short = policy.split("type folder = app.folders")[0] + "type file = app.files\n  can view = viewer or\n"
    h = e.ask("textDocument/hover", short, "can view = viewer", len("can view = v"))
    ok(
        "hover on a relation while the policy doesn't parse and the relation's line is gone: what it is",
        "**file.viewer**: relation to user, team#member" in value(h) and c.p.poll() is None,
        h,
    )
    got = e.offered(policy, "  user 3 can view file 11", len("  user 3 can "))
    ok(
        "in a test: a test's words, no type's relations",
        {"given", "allowed", "refused", "sees"} <= set(got) and "parent" not in got,
        got,
    )

    draft = "type doc = app.docs\n  can see = {\n"
    fresh = Editor(c, os.path.join(d, "fresh.authz"), draft)
    mistake = c.diagnostics(fresh.u)
    inside = fresh.offered(draft, "{", 1)
    begin = fresh.offered(draft, "{", 0)
    ok(
        "a file that never parsed: the functions inside braces, a type's words in it, no names from a policy",
        inside == FUNCTIONS and {"or", "can"} <= set(begin) and "doc" not in begin,
        [inside, begin],
    )
    c.notify("textDocument/didChange", {"textDocument": {"uri": fresh.u, "version": 3}, "contentChanges": []})
    again = c.diagnostics(fresh.u)
    ok("a change that sends no text: the file is checked again as it was", mistake and again == mistake, again)
    deep = "app role app_user\ntype user = app.users\n  can view = " + "(" * 3000 + "{true}" + ")" * 3000 + "\n"
    nested = Editor(c, os.path.join(d, "deep.authz"), deep)
    found = c.diagnostics(nested.u)
    ok(
        "a policy nested too deep to read: a warning that the checker failed, and the server goes on",
        found
        and found[0]["severity"] == 2
        and found[0]["message"].startswith("the checker failed: RecursionError")
        and c.p.poll() is None,
        found,
    )
    c.close()

# rowstile.toml names a policy outside its folder (which the command refuses), or one that isn't there
with tempfile.TemporaryDirectory() as top:
    d = os.path.join(top, "app")
    os.mkdir(d)
    test_text = 'test "first"\n  user 3 can view file 11\n'
    for name, body in (
        (os.path.join(top, "outside.authz"), policy),
        (os.path.join(d, "policy.authz"), policy),
        (os.path.join(d, "t.authz"), test_text),
        (os.path.join(d, "rowstile.toml"), 'policy = "../outside.authz"\n'),
    ):
        with open(name, "w", encoding="utf-8") as fh:
            fh.write(body)
    c = Client(d)
    c.request("initialize", {"capabilities": {}})
    tests = Editor(c, os.path.join(d, "t.authz"), test_text)
    found = c.diagnostics(tests.u)
    ok(
        "a test file, while rowstile.toml's policy is outside its folder: why, on its first line; the server goes on",
        found
        and len(found) == 1
        and found[0]["range"]["start"]["line"] == 0
        and found[0]["severity"] == 1
        and 'policy = "../outside.authz" is outside the folder rowstile.toml is in' in found[0]["message"]
        and c.p.poll() is None,
        found,
    )
    beside = Editor(c, os.path.join(d, "policy.authz"), policy)
    beside.ask("textDocument/hover", policy + "\n", "type user", 6)  # a change: checked once more
    found = c.diagnostics(beside.u)
    said = c.close()
    ok(
        "... a policy beside it is checked as itself, and the server's log isn't written at each check",
        found == [] and said == "",
        [found, said],
    )
    with open(os.path.join(d, "rowstile.toml"), "w", encoding="utf-8") as fh:
        fh.write('policy = "db/policy.authz"\n')
    c = Client(d)
    c.request("initialize", {"capabilities": {}})
    tests = Editor(c, os.path.join(d, "t.authz"), test_text)
    found = c.diagnostics(tests.u)
    ok(
        "a test file, while the policy rowstile.toml names isn't there: says so on its first line",
        found
        and found[0]["severity"] == 1
        and found[0]["message"] == 'rowstile.toml: policy = "db/policy.authz": No such file or directory',
        found,
    )
    c.close()

# the protocol as editors speak it: notifications the server has no use for, a header besides Content-Length, a
# file it doesn't have, a notification it can't read, and the end of its input without `exit`
with tempfile.TemporaryDirectory() as d:
    c = Client(d)
    c.request("initialize", {"capabilities": {}})
    for method, params in (("initialized", {}), ("$/setTrace", {"value": "off"}), ("$/cancelRequest", {"id": 1})):
        c.notify(method, params)
    missing = uri(os.path.join(d, "not-open.authz"))
    nowhere = {"textDocument": {"uri": missing}, "position": {"line": 0, "character": 0}}
    got = c.request("textDocument/hover", nowhere)
    ok("hover in a file that isn't open: none", got is None and c.p.poll() is None, got)
    ok(
        "notifications it has no use for (initialized, $/setTrace, $/cancelRequest) go unanswered",
        c.notes == [],
        c.notes,
    )
    typed = b"Content-Type: application/vscode-jsonrpc; charset=utf-8\r\n"
    got = c.request("textDocument/documentSymbol", {"textDocument": {"uri": missing}}, typed)
    ok("a message with a Content-Type header too is answered", got == [], got)
    c.notify("textDocument/didOpen", {"textDocument": {"uri": 5, "text": ""}})
    got = c.request("textDocument/hover", nowhere)
    ok(
        "a notification it can't read goes unanswered, and the server goes on",
        got is None and c.notes == [] and c.p.poll() is None,
        [got, c.notes],
    )
    c.stdin.close()
    try:
        code = c.p.wait(timeout=10)
    except subprocess.TimeoutExpired:
        c.p.kill()
        code = None
    ok("the end of its input ends the server, without `exit`", code == 0, code)


def made_database() -> str | None:
    """A database to complete from: the docs app with its policy applied, and tables named as an app may name
    them. None where there is no Postgres to make one in (no createdb, or no server)."""
    db = "authz_lsp"
    try:
        subprocess.run(["dropdb", "--if-exists", db], capture_output=True)
        made = subprocess.run(["createdb", db], capture_output=True)
    except OSError:
        return None
    if made.returncode:
        return None
    env = dict(os.environ, PGOPTIONS="-c client_min_messages=error")
    psql = ["psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", "-d", db]
    for step in (
        [*psql, "-f", os.path.join(ROOT, "example", "app_schema.sql")],
        [sys.executable, os.path.join(ROOT, "cli", "rowstile_cli.py"), "--db", f"dbname={db}", "apply"]
        + [os.path.join(ROOT, "example", "docs.authz")],
        # capitals, as Prisma makes them; words SQL keeps; a name a policy can't write
        [*psql, "-c", 'CREATE TABLE public."Folder" (id serial PRIMARY KEY, "parentId" int, "ownerId" int, name text)'],
        [*psql, "-c", 'CREATE TABLE app."order" (id bigint PRIMARY KEY, "user" bigint, "select" int)'],
        [*psql, "-c", 'CREATE SCHEMA "My Schema"; CREATE TABLE "My Schema"."Odd Table" (id int)'],
    ):
        r = subprocess.run(step, capture_output=True, text=True, env=env)
        if r.returncode:
            raise SystemExit(f"{' '.join(step)}\n{r.stdout}{r.stderr}")
    return db


# with a database in rowstile.toml: its tables, and the columns of the row a condition is about, as the policy
# and SQL name them
db = made_database()
if db is None:
    print("(no database here: the completion of its tables and columns isn't checked)")
else:
    with tempfile.TemporaryDirectory() as d:
        known = (
            policy
            + "\ntype fol = public.Folder (id int)\n  can see = {true}\n\ntype ord = app.order\n  can look = {true}\n"
        )
        path = os.path.join(d, "policy.authz")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(known)
        with open(os.path.join(d, "rowstile.toml"), "w", encoding="utf-8") as fh:
            fh.write(f'policy = "policy.authz"\ndatabase = "dbname={db}"\n')
        c = Client(d)
        c.request("initialize", {"capabilities": {}})
        e = Editor(c, path, known)
        app = ["files", "folder_links", "folder_team_access", "folders", "order", "org_members", "orgs", "team_members"]
        app += ["teams", "users"]
        typed = known + "\ntype extra = app.\n"
        got = e.offered(typed, "type extra = app.", len("type extra = app."))
        ok("after app.: the tables of the schema app, from the database", sorted(got) == app, got)
        named = sorted(["app." + t for t in app] + ["public.Folder"])
        listed = [sorted(e.offered(typed, "type extra = app.", len("type extra = ")))]
        listed.append(sorted(e.offered(typed + "rules \n", "rules \n", len("rules "))))
        ok(
            "after `type x =` and `rules`: every table a policy can name, with its schema (none of rowstile's own)",
            listed == [named, named],
            listed,
        )
        inside = known.replace("type folder = app.folders\n", "type folder = app.folders\n  can zz = {\n")
        got = e.offered(inside, "  can zz = {", len("  can zz = {"))
        ok(
            "inside { } in a type: its table's columns, in its order, then the functions",
            got == ["id", "org_id", "parent_id", "owner_id", "name", "inherit", *FUNCTIONS],
            got,
        )
        inside = known.replace("rules app.files\n", "rules app.files\n  insert : {\n")
        got = e.offered(inside, "  insert : {", len("  insert : {"))
        ok(
            "... in the rules of a table: that table's",
            got == ["id", "folder_id", "owner_id", "name", "confidential", "body", *FUNCTIONS],
            got,
        )
        fol = e.offered(known.replace("  can see = {true}", "  can see = {"), "  can see = {", len("  can see = {"))
        order = e.offered(
            known.replace("  can look = {true}", "  can look = {"), "  can look = {", len("  can look = {")
        )
        ok(
            '... each named as SQL names it: quoted where it must be (capitals: "parentId", words SQL keeps: "user")',
            fol[:4] == ["id", '"parentId"', '"ownerId"', "name"] and order[:3] == ["id", '"user"', '"select"'],
            [fol, order],
        )
        inside = known.replace("where {role = 'admin'}", "where {")
        got = e.offered(inside, "where {", len("where {"))
        ok(
            "... in a link table's where: the link table's (the row the condition is about)",
            got == ["org_id", "user_id", "role", *FUNCTIONS],
            got,
        )
        inside = known.replace(
            "  editor      : user, team#member shared\n", "  editor      : user, team#member shared if {\n"
        )
        got = e.offered(inside, "shared if {", len("shared if {"))
        ok(
            "... in `shared if`: what the share being made has, not the folder's columns",
            got == ["object_id", "subject_type", "subject_id", "subject_relation", *FUNCTIONS],
            got,
        )
        got = e.offered(known + "\n-- see app.\n", "-- see app.", len("-- see app."))
        ok("a comment that names a schema: nothing, though the database has its tables", got == [], got)
        c.close()

        # the database in a variable that .env beside rowstile.toml holds, as apps keep it (the editor's environment
        # doesn't have it); then one the server refuses
        with open(os.path.join(d, "rowstile.toml"), "w", encoding="utf-8") as fh:
            fh.write('policy = "policy.authz"\ndatabase = "env:ROWSTILE_LSP_TEST_DB"\n')
        results: list[tuple[list[str], bool, str]] = []  # (tables offered, alive after, what its log says)
        for name in (db, "authz_lsp_nosuch"):
            with open(os.path.join(d, ".env"), "w", encoding="utf-8") as fh:
                fh.write(f"ROWSTILE_LSP_TEST_DB=dbname={name}\n")
            c = Client(d)
            c.request("initialize", {"capabilities": {}})
            e = Editor(c, path, typed)
            got = e.offered(typed, "type extra = app.", len("type extra = app."))
            e.offered(typed, "type extra = app.", len("type extra = app."))  # asked again: the database tried once
            alive = c.p.poll() is None
            results.append((got, alive, c.close()))
        (got, alive, log), (refused, still, why) = results
        ok(
            'database = "env:NAME", NAME in .env beside rowstile.toml: the tables',
            sorted(got) == app and alive and log == "",
            results[0],
        )
        ok(
            "a database the server refuses (it doesn't exist): no tables, the server goes on, its log says why once",
            refused == []
            and still
            and why.count("rowstile lsp: no table or column names to complete: ") == 1
            and 'database "authz_lsp_nosuch" does not exist' in why,
            results[1],
        )

        # a database that isn't there yet at the first completion (its container still starting, say): tried again
        # some seconds later, and its tables offered then; rowstile.toml naming another: read at the next completion
        later = "authz_lsp_later"
        subprocess.run(["dropdb", "--if-exists", later], capture_output=True)
        with open(os.path.join(d, "rowstile.toml"), "w", encoding="utf-8") as fh:
            fh.write(f'policy = "policy.authz"\ndatabase = "dbname={later}"\n')
        c = Client(d)
        c.request("initialize", {"capabilities": {}})
        e = Editor(c, path, typed)
        first = e.offered(typed, "type extra = app.", len("type extra = app."))
        # rowstile.toml naming it another way (a URL): tried again at once, and failing the same way, not said again
        with open(os.path.join(d, "rowstile.toml"), "w", encoding="utf-8") as fh:
            fh.write(f'policy = "policy.authz"\ndatabase = "postgresql:///{later}"\n')
        first += e.offered(typed, "type extra = app.", len("type extra = app."))
        tried = time.monotonic()
        subprocess.run(["createdb", later], check=True)
        subprocess.run(
            [
                "psql",
                "-X",
                "-q",
                "-v",
                "ON_ERROR_STOP=1",
                "-d",
                later,
                "-f",
                os.path.join(ROOT, "example", "app_schema.sql"),
            ],
            check=True,
            capture_output=True,
            env=dict(os.environ, PGOPTIONS="-c client_min_messages=error"),
        )
        time.sleep(max(0.0, tried + 5.5 - time.monotonic()))  # the first wait after a failure: 5 seconds
        then = e.offered(typed, "type extra = app.", len("type extra = app."))
        with open(os.path.join(d, "rowstile.toml"), "w", encoding="utf-8") as fh:
            fh.write(f'policy = "policy.authz"\ndatabase = "dbname={db}"\n')
        other = e.offered(typed, "type extra = app.", len("type extra = app."))
        said = c.close()
        ok(
            "a database not there at the first completion: its tables some seconds later, in the same server",
            first == [] and sorted(then) == [t for t in app if t != "order"],
            [first, then],
        )
        ok(
            "... and rowstile.toml naming another database: its tables at the next completion",
            sorted(other) == app,
            other,
        )
        ok(
            "... its log said why the reads failed, once for the same reason twice",
            said == f'rowstile lsp: no table or column names to complete: 3D000: database "{later}" does not exist\n',
            said,
        )
        subprocess.run(["dropdb", "--if-exists", later], capture_output=True)
    subprocess.run(["dropdb", "--if-exists", db], capture_output=True)

print("lsp: all passed" if not fails else f"lsp: {fails} failed")
sys.exit(1 if fails else 0)
