#!/usr/bin/env python3
"""tools_test: the diagram, the generated clients and the editor grammar.

    PGHOST=... PGUSER=postgres python3 tests/tools_test.py [--db authz_tools]

Needs only the standard library (the Python client talks to Postgres with cli/pgwire.py);
the TypeScript client is type-checked when tsc is installed.
"""

import atexit
import importlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Sequence

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "cli"))
import client_types  # noqa: E402
import compile_policy  # noqa: E402
import pgwire  # noqa: E402

fails = 0


class Ran:
    """What a driver hands back for a statement: its rowcount (psycopg's cursor, as conn.execute returns it)."""

    def __init__(self, rowcount: int) -> None:
        self.rowcount = rowcount


class Cursor:
    """Just enough DB-API (psycopg's) over the command's Postgres client for the generated Python client: %s
    placeholders (%% for a percent sign), fetchone, fetchall, description."""

    def __init__(self, conn: pgwire.Connection) -> None:
        self.conn = conn
        self.rows: list[tuple[pgwire.Value, ...]] = []
        self.description: list[tuple[str, None, None, None, None, None, None]] | None = None

    def __enter__(self) -> "Cursor":
        return self

    def __exit__(self, *exc: object) -> bool:
        return False

    def execute(self, sql: str, args: Sequence[object] = (), /) -> None:
        parts = re.split("(%%|%s)", sql)
        if parts.count("%s") != len(args):
            raise ValueError("the number of %s placeholders and arguments differ")
        n = iter(range(1, len(args) + 1))
        text = "".join("%" if p == "%%" else f"${next(n)}" if p == "%s" else p for p in parts)
        self.rows, names = self.conn.query_described(text, list(args))
        self.description = [(name, None, None, None, None, None, None) for name in names]

    def fetchone(self) -> tuple[pgwire.Value, ...] | None:
        return self.rows.pop(0) if self.rows else None

    def fetchall(self) -> list[tuple[pgwire.Value, ...]]:
        rows, self.rows = self.rows, []
        return rows


class Driver:
    """The command's Postgres client, with a cursor as the generated Python client takes it."""

    def __init__(self, conn: pgwire.Connection) -> None:
        self.conn = conn

    def cursor(self) -> Cursor:
        return Cursor(self.conn)


def check(label: str, ok: object, detail: object = "") -> None:
    global fails
    if ok:
        print(f"ok    {label}")
    else:
        fails += 1
        print(f"FAIL  {label}{': ' + str(detail) if detail else ''}")


def statements(client: str) -> int:
    """How many strings of a generated client start with SELECT, in any quotes: its statements, each of which the
    checks below must find (a change of quotes would leave them checking fewer, or none)."""
    return len(re.findall(r"[\"'`]SELECT\b", client))


def psql(db: str, *cmds: str, check_rc: bool = True) -> str:
    args = ["psql", "-X", "-q", "-At", "-v", "ON_ERROR_STOP=1", "-d", db]
    for c in cmds:
        args += ["-c", c]
    r = subprocess.run(
        args, capture_output=True, text=True, env=dict(os.environ, PGOPTIONS="-c client_min_messages=error")
    )
    if check_rc and r.returncode:
        raise SystemExit(f"psql failed: {r.stderr}")
    return r.stdout.strip()


def main() -> None:
    db = sys.argv[sys.argv.index("--db") + 1] if "--db" in sys.argv else "authz_tools"
    host = os.environ.get("PGHOST", "/var/run/postgresql")
    port = int(os.environ.get("PGPORT", "5432"))
    subprocess.run(["dropdb", "--if-exists", db], capture_output=True)
    subprocess.run(["createdb", db], check=True)
    # dropped when the suite ends, however it ends (a check that raises, a psql that fails)
    atexit.register(subprocess.run, ["dropdb", "--if-exists", db], capture_output=True)
    policy = os.path.join(ROOT, "example", "docs.authz")
    compiler = compile_policy.load(policy)
    sql = compiler.compile(policy)
    for f in (os.path.join(ROOT, "example", "app_schema.sql"),):
        subprocess.run(
            ["psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", "-d", db, "-f", f], check=True, capture_output=True
        )
    subprocess.run(
        ["psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", "-d", db],
        input=sql,
        text=True,
        check=True,
        capture_output=True,
        env=dict(os.environ, PGOPTIONS="-c client_min_messages=error"),
    )
    psql(db, "SET ROLE app_user; SET authz.user_id = 5; SELECT authz.share('folder', 1, 'viewer', 'org', 1, 'member')")

    print("-- the diagram (--graph)")
    for name in ("example/docs.authz", "tests/multi.authz", "tests/alt.authz", "tests/composite.authz"):
        c = compile_policy.load(os.path.join(ROOT, name))
        c.compile(name)
        g = c.graph()
        declared = set(re.findall(r"^\s+([A-Za-z0-9_]+)(?:\[|\(|\(\()", g, re.M))
        declared |= set(re.findall(r"^\s+subgraph ([A-Za-z0-9_]+)\[", g, re.M))
        used = set()
        for a, b in re.findall(r"^\s+([A-Za-z0-9_]+) [-=.]+>(?:\|[^|]*\|)? ([A-Za-z0-9_]+)$", g, re.M):
            used |= {a, b}
        check(f"{name}: every node an arrow uses is declared", used <= declared, sorted(used - declared))
        # every relation draws an arrow to who it holds
        relations = set(re.findall(r"^\s+([A-Za-z0-9_]+)\[[^\n]*:::rel$", g, re.M))
        froms = {a for a, _ in re.findall(r"^\s+([A-Za-z0-9_]+) [-=.]+>(?:\|[^|]*\|)? ([A-Za-z0-9_]+)$", g, re.M)}
        check(f"{name}: an arrow from every relation", relations and relations <= froms, sorted(relations - froms))

    print("-- the Python client (--client py)")
    tmp = tempfile.mkdtemp()
    atexit.register(shutil.rmtree, tmp, ignore_errors=True)
    with open(os.path.join(tmp, "authz_client.py"), "w", encoding="utf-8") as fh:
        fh.write(compiler.client("py", "docs.authz"))
    sys.path.insert(0, tmp)
    authz_client = importlib.import_module("authz_client")  # written above, for this database
    conn = pgwire.connect(host=host, port=port, user=os.environ.get("PGUSER", "postgres"), database=db)
    conn.execute("BEGIN")
    conn.execute("SET LOCAL ROLE app_user")
    a = authz_client.Authz(Driver(conn))
    a.sign_in(3)
    check("can: carol may view file 11", a.can("file", 11, "view") is True)
    cur = Cursor(conn)
    cur.execute("UPDATE app.files SET name = name WHERE id = %s", (12,))  # file 12 is hidden from carol: no row changes
    for label, given in (("a count of 0", 0), ("no rows", []), ("the cursor that ran it", Ran(0))):
        try:
            a.expect(given, "app.files", "update", 12)
            check(f"expect, given {label}: NotFound", False, "it returned")
        except authz_client.NotFound:
            check(f"expect, given {label}: NotFound", True)
    check(
        "expect, given a cursor that changed a row: returned",
        isinstance(a.expect(Ran(1), "app.files", "update", 11), Ran),
    )
    try:
        a.expect(Ran(0), "app.files", "update", 11)  # carol sees file 11 and may not edit it
        check("expect, a row the user may not change: Refused", False, "it returned")
    except authz_client.Refused as e:
        check(
            "expect, a row the user may not change: Refused, with why", bool(e.why) and e.why[0].startswith("no"), e.why
        )
        check(
            "... worded as the database words a refused insert: who, the command, the row, the table",
            str(e) == "permission denied: user 3 may not update row 11 of app.files",
            str(e),
        )
    shown = [authz_client._shown(k) for k in (7, (1, 2), ("a b", "x,y"), ("", 'q"t'), ("b\\s", "(1)"))]
    check(
        "a key in a message is as the database writes it: quoted only where Postgres would",
        shown == ["7", "(1,2)", '("a b","x,y")', '("","q""t")', '("b\\\\s","(1)")'],
        shown,
    )
    check("can: carol may not edit it", a.can("file", 11, "edit") is False)
    check(
        "list: the files carol may view", sorted(a.list("file", "view")) == ["10", "11", "16"], a.list("file", "view")
    )
    check("perms: on folder 1", a.perms("folder", 1) == ["view", "break_glass"], a.perms("folder", 1))
    try:
        a.can("file", 11, "fly")
        check("an unknown permission is refused before asking the database", False)
    except ValueError:
        check("an unknown permission is refused before asking the database", True)
    rid = a.request_access("folder", 2, "viewer", "need it", "1 day")
    check("request_access returns the request's id", isinstance(rid, int) and rid > 0, rid)
    other = a.request_access("folder", 2, "editor", "maybe", "1 day")
    check(
        "pending_requests: the requester sees their own",
        {r["id"] for r in a.pending_requests() if r["mine"]} >= {rid, other},
        a.pending_requests(),
    )
    a.cancel_request(other)
    check("cancel_request", other not in {r["id"] for r in a.pending_requests()})
    conn.execute("COMMIT")
    conn.execute("BEGIN")
    conn.execute("SET LOCAL ROLE app_user")
    a.sign_in(5)
    # erin may edit file 12: an UPDATE of it that matched nothing (a WHERE with more than the key) is no refusal
    check("erin may edit file 12", a.can("file", 12, "edit") is True)
    try:
        a.expect(Ran(0), "app.files", "update", 12)
        check("expect, when the rule allows the write: NotFound", False, "it returned")
    except authz_client.NotFound:
        check("expect, when the rule allows the write: NotFound", True)
    except authz_client.Refused as e:
        check("expect, when the rule allows the write: NotFound", False, e.why)
    why = a.explain("file", 12, "view")
    check(
        "explain: says yes, then the rule it follows",
        why[:2]
        == [
            "yes  user 5 holds view on file 12",
            "  file.view = edit or viewer or (folder.view and not {confidential})",
        ],
        why[:2],
    )
    a.decide_request(rid, True, "fine")
    made = [r for r in a.list_shares("folder", 2) if r["subject_type"] == "user" and r["subject_id"] == "3"]
    check(
        "decide_request: approving makes carol's share, until the time she asked for",
        [(r["relation"], r["expires_at"] is not None) for r in made] == [("viewer", True)],
        made,
    )
    a.share("file", 11, "viewer", "user", 4)
    check("share, then who", "4" in a.who("file", 11, "view"), a.who("file", 11, "view"))
    shares = a.list_shares("file", 11)
    check(
        "list_shares: rows as dicts", any(r["subject_id"] == "4" and r["relation"] == "viewer" for r in shares), shares
    )
    everything = a.list("folder", "view")
    first = a.list("folder", "view", limit=2)
    rest = a.list("folder", "view", after=first[-1])
    check("list in pages, in key order", first + rest == sorted(everything, key=int), (first, rest, everything))
    a.unshare("file", 11, "viewer", "user", 4)
    check("unshare", "4" not in a.who("file", 11, "view"))
    try:
        a.create_link("file", 11, "owner")
        check("create_link refuses a relation that isn't shared, before asking the database", False)
    except ValueError:
        check("create_link refuses a relation that isn't shared, before asking the database", True)
    check(
        "list_links: erin may share file 11, which has none",
        list(a.list_links("file", 11)) == [],
        a.list_links("file", 11),
    )
    conn.execute("COMMIT")
    conn.execute("BEGIN")
    conn.execute("SET LOCAL ROLE app_user")
    a.sign_in(3)
    a.use_links(["not-a-token"])
    presented = conn.query("SELECT current_setting('authz_ctx.links')")
    check("use_links: the request presents the tokens", presented == [("not-a-token",)], presented)
    check(
        "use_links: a token that is no link gives nothing (carol still can't view file 12)",
        a.can("file", 12, "view") is False,
    )
    a.use_links([])
    presented = conn.query("SELECT current_setting('authz_ctx.links')")
    check("use_links, none: the request presents none", presented == [("",)], presented)
    conn.execute("COMMIT")
    # link tokens are for the transaction that presents them: none are left after it
    conn.execute("BEGIN")
    a.use_links(["a-token"])
    conn.execute("COMMIT")
    left = conn.query("SELECT coalesce(current_setting('authz_ctx.links', true), '')")
    check("use_links: the tokens are for the transaction, none left after it", left == [("",)], left)
    py = compiler.client("py", "docs.authz")
    client_sql = re.findall(r'"(SELECT [^"]+)"', py)
    bad = []
    for i, text in enumerate(client_sql):
        n = text.count("%s")
        text = text.replace("%s", "$@")
        for k in range(1, n + 1):
            text = text.replace("$@", f"${k}", 1)
        try:
            conn.query(f"PREPARE py_{i} AS {text}")
        except pgwire.PgError as e:
            bad.append((text, e.message))
    # each statement is found: as many as the client has strings that start with SELECT, whatever their quotes
    found = len(client_sql) == statements(py) > 20
    check(
        f"every statement of the Python client prepares ({len(client_sql)})", found and not bad, (statements(py), bad)
    )

    print("-- the TypeScript client (--client ts)")
    ts = compiler.client("ts", "docs.authz")
    ts_sql = re.findall(r'"(SELECT [^"]+)"', ts)
    bad = []
    for i, text in enumerate(ts_sql):
        try:
            conn.query(f"PREPARE ts_{i} AS {text}")
        except pgwire.PgError as e:
            bad.append((text, e.message))
    found = len(ts_sql) == statements(ts) > 20
    check(
        f"every statement of the TypeScript client prepares ({len(ts_sql)})", found and not bad, (statements(ts), bad)
    )
    links = re.search(r'useLinks: [^\n]*db\.query\("([^"]+)"', ts)
    if links:
        conn.execute("BEGIN")
        conn.query(links.group(1), ["a-token"])
        conn.execute("COMMIT")
        left = conn.query("SELECT coalesce(current_setting('authz_ctx.links', true), '')")
        check("useLinks: the tokens are for the transaction, none left after it", left == [("",)], left)
    else:
        check("useLinks: the tokens are for the transaction, none left after it", False, "its statement isn't found")
    typed = client_types.type_check(ts)
    if typed:
        check("tsc --strict accepts correct calls and rejects wrong names", typed[0], typed[1])
    else:
        print("skip  tsc not installed (tests/client_types.py is the same check, and CI's javascript job runs it)")
    conn.close()

    print("-- the editor grammar (../editor/)")
    gram = os.path.join(ROOT, "..", "editor", "syntaxes", "authz.tmLanguage.json")
    try:
        with open(gram, encoding="utf-8") as fh:
            g = json.load(fh)
        pats: list[str] = []

        def walk(x: object) -> None:
            if isinstance(x, dict):
                for k, v in x.items():
                    if k in ("match", "begin", "end") and isinstance(v, str):
                        pats.append(v)
                    walk(v)
            elif isinstance(x, list):
                for v in x:
                    walk(v)

        walk(g)
        bad = []
        for p in pats:
            try:
                re.compile(p.replace("(?<", "(?P<") if "(?<!" not in p and "(?<=" not in p else p)
            except re.error as e:
                bad.append((p, str(e)))
        check(f"the grammar's patterns compile ({len(pats)})", len(pats) > 20 and not bad, bad or "too few found")
        with open(os.path.join(ROOT, "..", "editor", "package.json"), encoding="utf-8") as fh:
            pkg = json.load(fh)
        check(
            "the extension declares the .authz language",
            any(".authz" in lang.get("extensions", []) for lang in pkg["contributes"]["languages"]),
        )
    except FileNotFoundError as e:
        check("the editor grammar exists", False, e)

    shutil.rmtree(tmp, ignore_errors=True)
    subprocess.run(["dropdb", db], capture_output=True)
    print("tools: all passed" if not fails else f"tools: {fails} failed")
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
