#!/usr/bin/env python3
"""studio_test: rowstile why (the smallest changes that would grant a permission) and Studio's API, on the
docs example: read-only by default (nothing it does stays, and it refuses to change shares), able to write
with --write (shares and decisions made as the person it views as, so the database decides), and only for the
page that has the token, on localhost. And rowstile studio, the command: what it prints, and what stops it.

    PGHOST=... PGUSER=... python3 tests/studio_test.py [--db authz_studio]
"""

import contextlib
import http.client
import io
import json
import os
import select
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Sequence
from typing import Any, NamedTuple
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CLI = os.path.join(ROOT, "cli", "rowstile_cli.py")
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "cli"))
import pgwire  # noqa: E402
import rowstile_cli  # noqa: E402
import studio  # noqa: E402
from authzlib import database, grant  # noqa: E402
from authzlib.parse import Type  # noqa: E402

fails = 0
# an answer from Studio's API: its shape is what the checks check
Answer = Any


def check(label: str, ok: object, detail: object = "") -> None:
    global fails
    if ok:
        print(f"ok    {label}")
    else:
        fails += 1
        print(f"FAIL  {label}{': ' + str(detail)[:600] if detail else ''}")


def psql(db: str, sql: str) -> str:
    r = subprocess.run(
        ["psql", "-X", "-q", "-At", "-v", "ON_ERROR_STOP=1", "-d", db, "-c", sql],
        capture_output=True,
        text=True,
        env=dict(os.environ, PGOPTIONS="-c client_min_messages=error"),
    )
    if r.returncode:
        raise SystemExit(f"psql failed: {r.stderr}")
    return r.stdout.strip()


def cli(db: str, *args: str) -> tuple[int, str]:
    return command(f"dbname={db}", *args)


def command(dsn: str, *args: str) -> tuple[int, str]:
    """The command run with --db DSN: its exit code, and what it printed."""
    r = subprocess.run([sys.executable, CLI, "--db", dsn, *args], capture_output=True, text=True, timeout=120)
    return r.returncode, r.stdout + r.stderr


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Served(NamedTuple):
    """A Studio the command started: where it listens, and the token it printed."""

    port: int
    token: str


def serving(db: str, *flags: str) -> tuple[subprocess.Popen[str], str, Served]:
    """rowstile studio, started as in a terminal: the process, the line it printed first (its error, if it
    didn't start), and where it is."""
    port = free_port()
    p = subprocess.Popen(
        [sys.executable, CLI, "--db", f"dbname={db}", "studio", "--port", str(port), *flags],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    assert p.stdout is not None
    ready, _, _ = select.select([p.stdout], [], [], 60)
    line = p.stdout.readline() if ready else ""
    return p, line, Served(port, line.split("token=", 1)[1].split()[0] if "token=" in line else "")


def stopped(p: subprocess.Popen[str]) -> int | None:
    """Ctrl-C, as in a terminal: the exit code (None: still running after 20 seconds, so killed)."""
    p.send_signal(signal.SIGINT)
    try:
        p.communicate(timeout=20)
        return p.returncode
    except subprocess.TimeoutExpired:
        p.kill()
        p.communicate()
        return None


def made_and_copied(db: str, named: str, var: str, table: str, where: str) -> tuple[str, str]:
    """The row a named test's `given <var>` makes (in a transaction rolled back), and the row it copies, each
    as JSON without its key: the same when the copy is faithful. Or what the database said of the given."""
    given = named.split(f"given {var} = {{", 1)[-1].split("}\n", 1)[0].replace(' RETURNING "id"', " RETURNING *")
    r = subprocess.run(
        [
            "psql",
            "-X",
            "-q",
            "-At",
            "-d",
            db,
            "-c",
            f"BEGIN; WITH n AS ({given}) SELECT to_jsonb(n) - 'id' FROM n; ROLLBACK",
        ],
        capture_output=True,
        text=True,
    )
    return (r.stdout + r.stderr).strip(), psql(db, f"SELECT to_jsonb(r) - 'id' FROM {table} r WHERE {where}")


class Client:
    def __init__(self, s: studio.Studio | Served, token: str | None = None) -> None:
        self.base, self.token = f"http://127.0.0.1:{s.port}", s.token if token is None else token

    def call(self, path: str, body: object = None, host: str | None = None) -> tuple[int, Answer]:
        headers: dict[str, str] = {"X-Studio-Token": self.token}
        if host:
            headers["Host"] = host
        data = None
        if body is not None:
            data = body if isinstance(body, bytes) else json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(
            self.base + path, data=data, headers=headers, method="POST" if body is not None else "GET"
        )
        try:
            with urllib.request.urlopen(req) as r:
                raw = r.read()
                return r.status, json.loads(raw) if path.startswith("/api/") else raw.decode()
        except urllib.error.HTTPError as e:
            raw = e.read()
            try:
                return e.code, json.loads(raw)
            except ValueError:
                return e.code, raw.decode()


class Raw(NamedTuple):
    """What Studio answered a request sent by hand: its status (0: no answer), its answer, and the seconds it took."""

    status: int
    answer: Answer
    seconds: float


def by_hand(
    s: studio.Studio, head: dict[str, str], body: bytes = b"", path: str = "/api/share", wait: float = 8
) -> Raw:
    """A POST as no browser sends it: these headers (the token's and the host's besides), then this much of the
    body, the connection left open. Read until Studio closes it, or `wait` seconds pass."""
    headers = {"Host": f"127.0.0.1:{s.port}", "X-Studio-Token": s.token, **head}
    request = f"POST {path} HTTP/1.1\r\n" + "".join(f"{k}: {v}\r\n" for k, v in headers.items()) + "\r\n"
    started = time.monotonic()
    got = b""
    with socket.create_connection(("127.0.0.1", s.port), timeout=wait) as conn:
        conn.sendall(request.encode() + body)
        with contextlib.suppress(OSError):  # the wait over (no answer), or the connection reset
            while data := conn.recv(65536):
                got += data
    seconds = time.monotonic() - started
    status, _, rest = got.partition(b"\r\n")
    answer = rest.partition(b"\r\n\r\n")[2]
    try:
        return Raw(int(status.split()[1]) if status else 0, json.loads(answer) if answer else None, seconds)
    except ValueError:
        return Raw(0, got.decode(errors="replace"), seconds)


def waiting(db: str, s: studio.Studio, path: str, body: object, lock: str, then: Callable[[str], object]) -> Answer:
    """(status, answer, what Studio printed meanwhile) for a request to Studio that waits behind a lock the test
    holds (LOCK TABLE <lock>), once then(the waiting session's process id) has run. A request that never waits
    goes through when the test lets the lock go."""
    locker = pgwire.connect(**pgwire.parse_dsn(f"dbname={db}"))
    locker.execute("BEGIN")
    locker.execute(f"LOCK TABLE {lock}")
    got: list[tuple[int, Answer]] = []
    logged = io.StringIO()
    with contextlib.redirect_stderr(logged):
        asked = threading.Thread(target=lambda: got.append(Client(s).call(path, body)))
        asked.start()
        for _ in range(240):
            pid = psql(
                db,
                "SELECT pid FROM pg_stat_activity WHERE datname = current_database() AND wait_event_type = 'Lock'",
            )
            if pid:
                then(pid)
                break
            time.sleep(0.25)
        asked.join(30)
        locker.execute("ROLLBACK")
        asked.join()
    locker.close()
    return (*got[0], logged.getvalue())


def pump(a: socket.socket, b: socket.socket) -> None:
    with contextlib.suppress(OSError):
        while data := a.recv(65536):
            b.sendall(data)


class Between:
    """A go-between Studio connects through, to the server the environment names (PGHOST, PGPORT). It closes the
    connections it holds without a word from the server, as a server that goes away or a network that drops does
    (hang_up); and stops answering, then answers again on the same port, as a server that restarts does."""

    def __init__(self) -> None:
        self.held: list[socket.socket] = []
        self.port = 0
        self.lis = self.listen()

    def listen(self) -> socket.socket:
        lis = socket.socket()
        lis.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        lis.bind(("127.0.0.1", self.port))
        lis.listen()
        self.port = lis.getsockname()[1]
        threading.Thread(target=self.serve, args=(lis,), daemon=True).start()
        return lis

    def serve(self, lis: socket.socket) -> None:
        host, port = os.environ.get("PGHOST") or "/var/run/postgresql", int(os.environ.get("PGPORT") or 5432)
        while True:
            try:
                c, _ = lis.accept()
            except OSError:
                return  # stopped
            up = socket.socket(socket.AF_UNIX) if host.startswith("/") else socket.socket()
            up.connect(f"{host}/.s.PGSQL.{port}" if host.startswith("/") else (host, port))
            self.held += [c, up]
            for a, b in ((c, up), (up, c)):
                threading.Thread(target=pump, args=(a, b), daemon=True).start()

    def hang_up(self, reset: bool = False) -> None:
        """Closes the connections it holds without a word from the server: as a server that goes away does, or
        (reset) as a dropped connection is, the other end told it was reset."""
        for s in self.held:
            with contextlib.suppress(OSError):
                if reset:  # closed at once, with a reset: no lingering (and the pump reading it let go first)
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
                s.shutdown(socket.SHUT_RD if reset else socket.SHUT_RDWR)
            s.close()
        self.held.clear()

    def stop(self) -> None:
        self.hang_up()
        with contextlib.suppress(OSError):
            self.lis.shutdown(socket.SHUT_RDWR)  # wakes the accept that waits
        self.lis.close()

    def again(self) -> None:
        self.lis = self.listen()


def main() -> None:
    db = sys.argv[sys.argv.index("--db") + 1] if "--db" in sys.argv else "authz_studio"
    subprocess.run(["dropdb", "--if-exists", db], capture_output=True)
    subprocess.run(["createdb", db], check=True)
    subprocess.run(
        ["psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", "-d", db, "-f", os.path.join(ROOT, "example", "app_schema.sql")],
        check=True,
        capture_output=True,
    )
    policy = os.path.join(ROOT, "example", "docs.authz")
    rc, out = cli(db, "apply", policy)
    if rc:
        raise SystemExit(out)
    # carol and the others are members of Acme (org 1): erin shares Company with them
    psql(db, "SELECT authz.act_as('user', '5'); SELECT authz.share('folder', '1', 'viewer', 'org', '1', 'member')")
    shares = lambda: psql(db, "SELECT count(*) FROM authz.shares")

    print("-- rowstile why")
    rc, out = cli(db, "why", "--as", "user:3", "folder", "3", "edit")
    lines = out.splitlines()
    ways = (
        [x.strip() for x in lines[lines.index("would be granted by:") + 1 :]] if "would be granted by:" in lines else []
    )
    check("no, and why not", rc == 0 and lines[0] == "no: user:3 does not hold edit on folder 3", out)
    check(
        "the smallest change first: a share on the folder itself",
        ways and ways[0].startswith("share editor on folder 3 with user 3"),
        out,
    )
    check(
        "... with what else it grants, and the policy line it adds to",
        ways and "(also gives edit on" in ways[0] and "[line " in ways[0],
        out,
    )
    check(
        "a group the object is linked to: join it",
        any(w.startswith("add user 3 to app.team_members for team") for w in ways),
        out,
    )

    def granted_by(*question: str) -> tuple[list[str], str]:
        _, said = cli(db, "why", *question)
        after = said.splitlines()
        return (
            [x.strip() for x in after[after.index("would be granted by:") + 1 :]]
            if "would be granted by:" in after
            else []
        ), said

    asked, out = granted_by("--as", "user:6", "folder", "2", "view")
    check(
        "the way that gives the least comes first: a viewer (and the file in the folder), before an editor",
        asked
        and asked[0] == "share viewer on folder 2 with user 6 (also gives view on 1 more file for user:6)  [line 43]"
        and any(w.startswith("share editor on folder 2 with user 6 (also gives edit on it") for w in asked),
        out,
    )
    check(
        "... with all it gives: an editor's share higher up gives edit on the folders and the files below too",
        "share editor on folder 1 with user 6 (also gives edit on it, and view, edit on 3 more folders, and view, "
        "edit on 3 more files for user:6)  [line 45]" in asked,
        out,
    )
    asked, out = granted_by("--as", "user:3", "folder", "3", "share")
    ways_of_share, said_of_share = asked, out
    owner = next((w for w in asked if w.startswith("set owner_id of folder 3 to 3")), "")
    check(
        "a column: the folder's owner, with the other permissions it gives and whom it takes it from",
        "(also gives edit" in owner and "(takes share on it from 1 person)" in owner,
        out,
    )
    asked, out = granted_by("--as", "user:6", "folder", "2", "share")
    check(
        "a relation with a where: the row, with the column the condition asks",
        any(w.startswith("add user 6 to app.org_members for org 1, with role = 'admin'") for w in asked),
        out,
    )
    check(
        "... and when the row is there, left out by the condition, its column changes",
        any(w.startswith("set role = 'admin' on user 3's row of app.org_members for org 1") for w in ways_of_share),
        said_of_share,
    )
    check(
        "... with all it gives: every folder and file of the org, and its members to impersonate",
        "set role = 'admin' on user 3's row of app.org_members for org 1 (also gives edit on it, and share, edit on "
        "5 more folders, and view on 2 more folders, and impersonate on 4 more users, and share, edit on 5 more files, "
        "and view on 3 more files for user:3)  [line 32]" in ways_of_share,
        said_of_share,
    )
    asked, out = granted_by("--as", "user:2", "folder", "5", "edit")
    check(
        "... for a group's link too",
        any(w.startswith("set access = 'edit' on team 11's row of app.folder_team_access for folder 5") for w in asked),
        out,
    )
    check(
        "... and nothing of it stays",
        psql(db, "SELECT role FROM app.org_members WHERE org_id = 1 AND user_id = 3") == "member"
        and psql(db, "SELECT count(*) FROM app.org_members WHERE user_id = 6 AND org_id = 1") == "0"
        and psql(db, "SELECT access FROM app.folder_team_access WHERE folder_id = 5") == "view",
    )
    rc, out = cli(db, "why", "--as", "user:1", "folder", "3", "edit")
    check("yes, and why", rc == 0 and out.startswith("yes: user:1 holds edit on folder 3") and "owner" in out, out)
    rc, out = cli(db, "why", "--as", "user:2", "folder", "3", "fly")
    check(
        "a permission the type doesn't have: refused in authz.can's words, with its code, exit 1",
        (rc, out) == (1, "no permission folder.fly in the policy\nHINT: rowstile help AZ707\n"),
        out,
    )
    before = shares()
    rc, out = cli(db, "why", "--as", "user:7", "file", "10", "view")
    check("nothing it tried stays", shares() == before and "share viewer on file 10 with user 7" in out, out)
    # JIT: off while it counts what each person holds, back as it was when its transaction ends
    jit_conn = pgwire.connect(**pgwire.parse_dsn(f"dbname={db}"))
    jit_db = rowstile_cli.Db(jit_conn)
    jit_db.script("SET jit = on")
    jit_seen: list[str] = []
    held_now = grant.Grants.held

    def counting(g: grant.Grants, who: grant.Person, kinds: Sequence[grant.Part], t: Type, oid: str) -> grant.Held:
        jit_seen.append(str(g.db.rows("SELECT current_setting('jit') AS jit")[0]["jit"]))
        return held_now(g, who, kinds, t, oid)

    jit_conn.execute("BEGIN")
    with mock.patch.object(grant.Grants, "held", counting):
        database.why(jit_db, "user", "7", "file", "10", "view")
    jit_conn.execute("COMMIT")  # (what it tried is undone: committed, a setting made for the session would stay)
    jit_after = str(jit_db.rows("SELECT current_setting('jit') AS jit")[0]["jit"])
    jit_conn.close()
    check(
        "JIT is off while it counts what each one holds, and as the session had it once its transaction ends",
        jit_seen and set(jit_seen) == {"off"} and jit_after == "on",
        (jit_seen, jit_after),
    )

    print("-- Studio, read-only")
    dsn = f"dbname={db}"
    ro = studio.Studio(dsn, None, policy, writable=False, port=0, read_policy=rowstile_cli.read_policy)
    ro.start()
    c = Client(ro)
    try:
        status, page = c.call("/")
        check("the page, without the token (it carries no data)", status == 200 and "rowstile Studio" in page, status)
        check("the API needs the token", Client(ro, token="wrong").call("/api/overview")[0] == 401)
        # a page left open from Studio's run before holds that run's token: the answer says what happened
        check(
            "a token from an earlier start of Studio: 401, saying Studio was started again and which address to open",
            Client(ro, token="wrong").call("/api/overview")
            == (
                401,
                {
                    "title": "Unauthorized",
                    "status": 401,
                    "detail": "this page's token isn't this Studio's: Studio was started again since the page was "
                    "opened, and each start makes a new token. Open the address rowstile printed last",
                },
            ),
            Client(ro, token="wrong").call("/api/overview"),
        )
        check(
            "no token at all: 401, saying where to find it",
            Client(ro, token="").call("/api/overview")
            == (
                401,
                {
                    "title": "Unauthorized",
                    "status": 401,
                    "detail": "no token: open Studio from the address rowstile printed (it carries the token)",
                },
            ),
            Client(ro, token="").call("/api/overview"),
        )
        check(
            "... and a request for localhost (not a DNS name pointed here)",
            c.call("/api/overview", host="evil.example:4983")[0] == 403,
        )
        check(
            "... a page opened at localhost by hand is answered too",
            c.call("/api/overview", host=f"localhost:{ro.port}")[0] == 200,
        )
        check("no file outside the page's folder", c.call("/..%2fstudio.py")[0] == 404 and c.call("/.hidden")[0] == 404)
        # a path as no browser sends it: backslashes, a drive letter (on Windows these named any file on the disk)
        for raw in ("/x\\..\\..\\studio.py", "/C:\\Windows\\win.ini", "/\\Windows\\win.ini", "/studio.py"):
            conn = http.client.HTTPConnection("127.0.0.1", ro.port, timeout=10)
            conn.putrequest("GET", raw, skip_host=True)
            conn.putheader("Host", f"localhost:{ro.port}")
            conn.endheaders()
            got = conn.getresponse()
            got.read()
            check(f"... nor {raw}", got.status == 404, got.status)
            conn.close()
        check(
            "a token that isn't ASCII is a wrong token",
            Client(ro, token="caf\u00e9".encode().decode("latin-1")).call("/api/overview")[0] == 401,
        )
        status, o = c.call("/api/overview")
        check(
            "the overview: the database, the types, the tables",
            status == 200
            and not o["writable"]
            and "app.folders" in o["tables"]
            and any(t["name"] == "folder" and any(p["name"] == "edit" for p in t["perms"]) for t in o["types"]),
            o,
        )
        status, r = c.call("/api/rows?table=app.folders&as=user:2")
        hidden = [x for x in r["rows"] if not x["visible"]]
        check(
            "the rows as bob: some hidden, each with his permissions",
            status == 200
            and 0 < r["visible_total"] < r["total"]
            and hidden
            and all(x["perms"] == [] for x in hidden)
            and any("view" in x["perms"] for x in r["rows"] if x["visible"]),
            r,
        )
        status, r2 = c.call("/api/rows?table=app.folders&as=anyone")
        check("... and as nobody", status == 200 and r2["visible_total"] < r["visible_total"], r2)
        status, same = c.call("/api/rows?table=app.folders&as=2")
        check("someone written without a type is a user: as=2 sees what user:2 sees", status == 200 and same == r, same)
        check("only tables the policy governs", c.call("/api/rows?table=pg_catalog.pg_authid&as=user:2")[0] == 404)
        before = shares()
        status, w = c.call("/api/why?as=user:3&type=folder&id=3&perm=edit")
        check(
            "why not, and the changes that might grant it, none tried (read-only)",
            status == 200
            and w["holds"] is False
            and w["tried"] is False
            and w["ways"]
            and w["ways"][0]["text"] == "share editor on folder 3 with user 3"
            and shares() == before,
            w,
        )
        status, w = c.call("/api/why?as=user:1&type=folder&id=5&perm=share")
        check(
            "... and none that changes nothing: alice owns folder 3, above it, already (folder 5 doesn't inherit)",
            status == 200
            and [x["text"] for x in w["ways"]]
            == [
                "set role = 'admin' on user 1's row of app.org_members for org 1",
                "set owner_id of folder 5 to 1",
                "set owner_id of folder 1 to 1",
            ],
            w,
        )
        status, e = c.call(
            "/api/share",
            {
                "as": "user:1",
                "type": "folder",
                "id": "3",
                "relation": "editor",
                "subject_type": "user",
                "subject_id": "2",
            },
        )
        check("read-only: no shares made", status == 403 and "read-only" in e["detail"] and shares() == before, e)
        # read-only, a change is refused before its body is read: none of it sent here, and Studio answers at once
        refused = "Studio is read-only here: start it with --write (or use rowstile dev) to change shares"
        for length in ("300", str(64 * 1024 * 1024)):
            r = by_hand(ro, {"Content-Type": "application/json", "Content-Length": length})
            check(
                f"read-only: a change of {length} bytes refused before its body is read: 403, at once",
                r.status == 403 and r.answer["detail"] == refused and r.seconds < 5,
                r,
            )
        # a client that sends its whole body before it reads (as urllib does) still gets the answer: Studio reads and
        # drops what comes after it, rather than closing on bytes unread, which resets the connection under it
        try:
            got = c.call("/api/share", b'{"as": "user:1"' + b" " * (1 << 20) + b"}")
        except OSError as e:
            got = (0, repr(e))
        check(
            "... and a client that sends its whole body (1 MB) first still gets that answer, not a reset",
            got == (403, {"title": "Problem", "status": 403, "detail": refused}),
            got,
        )
        # ... for a while only: a client that goes on sending after the answer is cut off once that time is over
        with (
            mock.patch.object(studio, "LINGER_SECONDS", 0.5),
            socket.create_connection(("127.0.0.1", ro.port), timeout=10) as conn,
        ):
            conn.sendall(
                f"POST /api/share HTTP/1.1\r\nHost: 127.0.0.1:{ro.port}\r\nX-Studio-Token: {ro.token}\r\n"
                "Content-Length: 300\r\n\r\n".encode()
            )
            cut: list[float] = []  # when the connection stopped taking bytes

            def flood() -> None:
                with contextlib.suppress(OSError):
                    while True:
                        conn.sendall(b" " * 1024)
                cut.append(time.monotonic())

            flooding = threading.Thread(target=flood, daemon=True)
            flooding.start()
            answer = b""
            with contextlib.suppress(OSError):
                while data := conn.recv(65536):
                    answer += data
            answered = time.monotonic()
            flooding.join(10)
        took = cut[0] - answered if cut else None
        check(
            "... and a client that goes on sending after that answer is let go once the wait is over",
            answer.startswith(b"HTTP/1.0 403 ")
            and json.loads(answer.partition(b"\r\n\r\n")[2])["detail"] == refused
            and took is not None
            and 0.3 < took < 4,
            (answer[:300], took),
        )
        status, t = c.call("/api/test?as=user:3&type=folder&id=3&perm=edit&expect=cannot")
        check(
            "a test from what should hold: the check on the data there now",
            status == 200 and t["check"] == "user 3 cannot edit folder 3",
            t,
        )
        check(
            "... and a named test with its own rows (the key left to the table)",
            'given it = {INSERT INTO "app"."folders" (' in t["named"]
            and "user $who cannot edit folder $it" in t["named"]
            and '("id",' not in t["named"].split('"app"."folders"', 1)[1].split(")")[0],
            t["named"],
        )
        check(
            "... the person's row copied with a key of its own (the table doesn't fill it)",
            'given who = {INSERT INTO "app"."users" ("id", "name") VALUES ((SELECT coalesce(max("id"), 0) + 1 FROM "app"."users"), '
            in t["named"],
            t["named"],
        )
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, "made.authz"), "w", encoding="utf-8") as fh:
                fh.write(t["named"])
            rc, out = cli(db, "test", os.path.join(tmp, "made.authz"))
        made = out.split("user 3 cannot edit folder 3", 1)[-1].split("invariants", 1)[0]
        check(
            "... and the test runs as it is: its rows are made, its check passes",
            "user 3 cannot edit folder 3" in out
            and "ok    " in made
            and "FAIL" not in made
            and "duplicate key" not in out,
            out[-800:],
        )
        status, t = c.call("/api/test?as=user:3&type=folder&id=1&perm=view&expect=cannot")
        made, row = made_and_copied(db, t.get("named", ""), "it", "app.folders", "id = 1")
        check(
            "a copy of a row with a NULL (folder 1 has no parent): every column the same, the key aside",
            status == 200 and made == row and '"parent_id": null' in row,
            (made, row),
        )
        # a test names what isn't there as it is, and brings no copy of it
        for label, path, givens, last in (
            (
                "an object that isn't there",
                "as=user:3&type=folder&id=999&perm=view",
                ["who"],
                "user $who can view folder 999",
            ),
            (
                "someone who isn't there",
                "as=user:999&type=folder&id=1&perm=view",
                ["it"],
                "user 999 can view folder $it",
            ),
            (
                "nobody signed in",
                "as=anyone&type=folder&id=1&perm=view&expect=cannot",
                ["it"],
                "anyone cannot view folder $it",
            ),
        ):
            status, t = c.call(f"/api/test?{path}")
            lines = [x.strip() for x in t.get("named", "").splitlines()]
            check(
                f"a test for {label}: named as it is, with no copy of it",
                status == 200
                and [x.split(" = {", 1)[0].removeprefix("given ") for x in lines if x.startswith("given ")] == givens
                and lines[-1] == last,
                (status, t),
            )
        status, g = c.call("/api/graph")
        check("the graph", status == 200 and g["mermaid"].startswith("%%") and "flowchart" in g["mermaid"], g)
        status, d = c.call("/api/diff")
        check(
            "the access diff: the file is the policy in force",
            status == 200 and d["same_text"] and d["summary"] == [],
            d,
        )
        status, sh = c.call("/api/shares?type=folder&id=1")
        check(
            "the shares on an object, as an administrator",
            status == 200 and any(x["subject_type"] == "org" for x in sh["shares"]),
            sh,
        )
        owner = psql(db, "SELECT owner_id FROM app.folders WHERE id = 1")
        status, w = c.call(f"/api/why?as=user:{owner}&type=folder&id=1&perm=edit")
        check(
            "why for someone who holds it: yes, and nothing to grant", status == 200 and w["holds"] and not w["ways"], w
        )
        # what a page asks wrongly is answered with a problem: its status, and words that say what to change
        for label, path, want, words in (
            ("someone to view as, written wrongly", "/api/rows?table=app.folders&as=user:", 400, "as whom? 'user:'"),
            ("why for nobody", "/api/why?as=anyone&type=folder&id=3&perm=edit", 400, "why for nobody"),
            (
                "why on a type the policy doesn't have",
                "/api/why?as=user:3&type=nothing&id=3&perm=edit",
                400,
                "no type nothing in the policy (rowstile help AZ707)",
            ),
            (
                "why on a permission the type doesn't have",
                "/api/why?as=user:3&type=folder&id=3&perm=nope",
                400,
                "no permission folder.nope in the policy (rowstile help AZ707)",
            ),
            (
                "why on a relation, which authz.can and authz.explain don't take",
                "/api/why?as=user:3&type=folder&id=3&perm=viewer",
                400,
                "no permission folder.viewer in the policy (rowstile help AZ707)",
            ),
            ("a test expecting neither", "/api/test?as=user:3&type=folder&id=3&perm=edit&expect=maybe", 400, "expect:"),
            # a test is refused what why refuses, in its words: rowstile test would refuse the test it wrote
            (
                "a test on a type the policy doesn't have",
                "/api/test?as=user:3&type=nothing&id=3&perm=edit",
                400,
                "no type nothing in the policy (rowstile help AZ707)",
            ),
            (
                "a test on a permission the type doesn't have",
                "/api/test?as=user:3&type=folder&id=3&perm=nope",
                400,
                "no permission folder.nope in the policy (rowstile help AZ707)",
            ),
            (
                "a test on a relation, which a test's line doesn't take",
                "/api/test?as=user:3&type=folder&id=3&perm=viewer",
                400,
                "no permission folder.viewer in the policy (rowstile help AZ707)",
            ),
            ("an address it doesn't answer", "/api/nothing", 404, "nothing"),
        ):
            status, p = c.call(path)
            check(f"{label}: {want}, and says so", status == want and words in str(p.get("detail", "")), (status, p))
    finally:
        ro.stop()

    with tempfile.TemporaryDirectory() as tmp:
        changed = os.path.join(tmp, "docs.authz")
        with open(policy, encoding="utf-8") as fh:
            text = fh.read()
        with open(changed, "w", encoding="utf-8") as fh:
            fh.write(
                text.replace(
                    "  can edit  = share or editor or (parent.edit and {inherit})",
                    "  can edit  = share or editor or viewer or (parent.edit and {inherit})",
                )
            )
        s = studio.Studio(dsn, None, changed, writable=False, port=0, read_policy=rowstile_cli.read_policy)
        s.start()
        try:
            status, d = Client(s).call("/api/diff")
            check(
                "read-only: no access diff of a changed file (it would lock the app's tables), and why",
                status == 409 and "locks the app's tables" in d["detail"],
                d,
            )
        finally:
            s.stop()
        s = studio.Studio(dsn, None, changed, writable=True, port=0, read_policy=rowstile_cli.read_policy)
        s.start()
        try:
            before = psql(db, "SELECT count(*) FROM authz.policy_versions")
            status, d = Client(s).call("/api/diff")
            check(
                "the access diff of a changed file: who gains what, on this data, and nothing applied",
                status == 200
                and not d["same_text"]
                and any(
                    x["change"] == "gains" and x["what"] == "permission edit" and x["type"] == "folder"
                    for x in d["summary"]
                )
                and psql(db, "SELECT count(*) FROM authz.policy_versions") == before,
                d,
            )
        finally:
            s.stop()
        # what the access diff can't compare with: said on the page's tab
        broken = os.path.join(tmp, "broken.authz")
        edit = "  can edit  = share or editor or (parent.edit and {inherit})"
        with open(broken, "w", encoding="utf-8") as fh:
            fh.write(text.replace(edit, edit.replace("editor", "editr")))
        line = text.splitlines().index(edit) + 1
        deep = os.path.join(tmp, "deep.authz")
        with open(deep, "w", encoding="utf-8") as fh:
            fh.write(text.replace(edit, "  can edit  = " + "(" * 3000 + "share" + ")" * 3000))
        for label, path, writable, want, starts, ends in (
            ("no policy file", None, False, 404, "no policy file to compare with (rowstile.toml's policy)", ""),
            (
                "a policy file that isn't there",
                "/nowhere/p.authz",
                False,
                404,
                "/nowhere/p.authz: No such file or directory",
                "",
            ),
            # on a Studio that may build it: the file's mistake, with its line
            (
                "a policy file with a mistake",
                broken,
                True,
                400,
                f"policy line {line}: folder has no relation or permission 'editr' (it has: ",
                ") [AZ203]",
            ),
            # as the command says it, where Python's words came back (500), and a traceback where Studio runs
            (
                "an expression nested too deep",
                deep,
                True,
                400,
                f"{deep}: an expression in the policy is nested too deep to read",
                "",
            ),
        ):
            s = studio.Studio(dsn, None, path, writable=writable, port=0, read_policy=rowstile_cli.read_policy)
            s.start()
            try:
                status, d = Client(s).call("/api/diff")
                said = str(d.get("detail", ""))
                check(
                    f"the access diff with {label}: {want}, and says so",
                    status == want
                    and (said == starts if not ends else said.startswith(starts) and said.endswith(ends)),
                    (status, d),
                )
            finally:
                s.stop()

    print("-- Studio, able to write (rowstile dev, or --write)")
    rw = studio.Studio(dsn, None, policy, writable=True, port=0, read_policy=rowstile_cli.read_policy)
    rw.start()
    c = Client(rw)
    try:
        before = shares()
        status, w = c.call("/api/why?as=user:3&type=folder&id=3&perm=edit")
        check(
            "why not: each change tried and undone",
            status == 200
            and w["tried"]
            and all(x["grants"] for x in w["ways"])
            and w["ways"][0]["more_objects"] > 0
            and shares() == before,
            w,
        )
        check(
            "... each with all it gives: the editor's share on the folder gives edit on the file inside too",
            w["ways"][0]["text"] == "share editor on folder 3 with user 3"
            and w["ways"][0].get("elsewhere") == [{"type": "file", "perm": "edit", "n": 1}],
            w,
        )
        body = {"type": "folder", "id": "3", "relation": "editor", "subject_type": "user", "subject_id": "3"}
        status, e = c.call("/api/share", {**body, "as": "user:3"})
        check(
            "a share as someone who may not: refused, with the database's reason",
            status == 403 and "cannot share" in e["detail"],
            e,
        )
        # the folder's owner may share it: what stops these is Studio
        status, e = c.call("/api/share", {**body, "as": "user:1"}, host="evil.example:4983")
        check(
            "a share asked for another host (a DNS name pointed here): refused, and nothing changes",
            status == 403 and e["detail"] == "Studio answers on localhost only" and shares() == before,
            e,
        )
        status, e = c.call("/api/share", body)
        check(
            "a share with nobody to make it: refused, and says to pick someone",
            status == 400
            and e["detail"] == "as whom? pick someone to view as: they make the change"
            and shares() == before,
            e,
        )
        for label, path, sent, words in (
            ("a share that names no type", "/api/share", {"as": "user:1", "id": "3"}, "'type'"),
            (
                "a body that isn't JSON",
                "/api/share",
                b"as=user:1&type=folder",
                "Expecting value: line 1 column 1 (char 0)",
            ),
            (
                "an offset that isn't a number",
                "/api/rows?table=app.folders&as=user:1&offset=two",
                None,
                "invalid literal for int() with base 10: 'two'",
            ),
        ):
            status, e = c.call(path, sent)
            check(f"{label}: 400, missing or wrong", status == 400 and e["detail"] == f"missing or wrong: {words}", e)
        # a body nested deeper than Python's JSON reader goes, or a field nested deeper than the command's client
        # sends to the database (each within the cap on a body's size): the caller's mistake, said as a body that
        # isn't JSON is, and no traceback
        for label, sent in (
            ("a body nested deeper than JSON's reader goes", b"[" * 30000 + b"]" * 30000),
            (
                "a body with a field nested too deep to send",
                b'{"as": "user:1", "type": '
                + b"[" * 600
                + b"]" * 600
                + b', "id": "3", "relation": "editor", "subject_type": "user", "subject_id": "3"}',
            ),
        ):
            logged = io.StringIO()
            with contextlib.redirect_stderr(logged):
                status, e = c.call("/api/share", sent)
            check(
                f"{label}: 400, missing or wrong, and no traceback",
                status == 400
                and e["detail"] == "missing or wrong: the body is nested too deep to read"
                and not logged.getvalue(),
                (status, e, logged.getvalue()[-300:]),
            )
        # what Studio didn't foresee: 500, with what went wrong, the traceback where Studio runs, and the server goes
        # on. No request the checks know of reaches it (a body nested too deep did), so a fault is put in the code
        # the graph's tab runs
        logged = io.StringIO()
        with (
            mock.patch.object(studio.database, "graph", side_effect=RuntimeError("a fault the test put in")),
            contextlib.redirect_stderr(logged),
        ):
            status, e = c.call("/api/graph")
        check(
            "a request Studio didn't foresee: 500, and what went wrong",
            status == 500 and e["title"] == "Error" and e["detail"] == "a fault the test put in",
            (status, e),
        )
        check(
            "... its traceback where Studio runs, and the server goes on",
            "RuntimeError: a fault the test put in" in logged.getvalue() and c.call("/api/graph")[0] == 200,
            logged.getvalue()[-300:],
        )
        status, e = c.call("/api/why?as=user:3&type=folder&id=3&perm=fly")
        check(
            "why, trying changes, on a permission the type doesn't have: says so, as the command does",
            status == 400 and e["detail"] == "no permission folder.fly in the policy (rowstile help AZ707)",
            (status, e),
        )
        status, _ = c.call("/api/share", {**body, "as": "user:1"})
        _, r = c.call("/api/rows?table=app.folders&as=user:3")
        check(
            "a share as the folder's owner, and carol can edit it",
            status == 200 and any(x["id"] == "3" and "edit" in x["perms"] for x in r["rows"]),
            (status, r),
        )
        status, _ = c.call("/api/unshare", {**body, "as": "user:1"})
        check("... and unsharing it", status == 200 and shares() == before)
        # a body's size: the changes the page sends are a few hundred bytes. One over the cap is refused unread, one
        # that doesn't come whole is given up on, and either way the thread is let go
        json_head = {"Content-Type": "application/json"}
        limit = studio.BODY_LIMIT
        for label, head, sent, want in (
            (
                "a body over the cap, refused before it is read: 413",
                {"Content-Length": str(1 << 30)},
                b"{}",
                (413, f"the body is {1 << 30} bytes: Studio takes {limit} at most"),
            ),
            (
                "a body one byte over the cap: 413",
                {"Content-Length": str(limit + 1)},
                b"",
                (413, f"the body is {limit + 1} bytes: Studio takes {limit} at most"),
            ),
            (
                "a length that isn't one: 400",
                {"Content-Length": "-1"},
                b"{}",
                (400, "Content-Length '-1' is not a length"),
            ),
            (
                "no length: 411",
                {},
                b"{}",
                (411, "a change needs its body's Content-Length"),
            ),
            (
                "a body sent in chunks: 411",
                {"Transfer-Encoding": "chunked"},
                b"2\r\n{}\r\n0\r\n\r\n",
                (411, "a change needs its body's Content-Length"),
            ),
        ):
            r = by_hand(rw, {**json_head, **head}, sent)
            check(
                f"{label}, and says so, at once",
                (r.status, r.answer and r.answer["detail"]) == want and r.seconds < 5 and shares() == before,
                r,
            )
        try:
            got = c.call("/api/share", b'{"as": "user:1"' + b" " * (1 << 20) + b"}")
        except OSError as e:
            got = (0, repr(e))
        check(
            "a client that sends its whole body (1 MB) first still gets the 413, not a reset",
            got
            == (
                413,
                {
                    "title": "Problem",
                    "status": 413,
                    "detail": f"the body is {(1 << 20) + 16} bytes: Studio takes {limit} at most",
                },
            ),
            got,
        )
        with mock.patch.object(studio, "WAIT_SECONDS", 1.0):
            r = by_hand(rw, {**json_head, "Content-Length": "100"}, b'{"as": "user:1",')
            check(
                "a body that doesn't come whole: 408 once the wait is over, and the thread let go",
                (r.status, r.answer and r.answer["detail"])
                == (408, "the body didn't come: 16 of its 100 bytes in 1 seconds")
                and r.seconds < 5,
                r,
            )
            with socket.create_connection(("127.0.0.1", rw.port), timeout=8) as idle:
                started = time.monotonic()
                with contextlib.suppress(OSError):
                    idle.recv(1)
                check("a connection that sends nothing is closed once the wait is over", time.monotonic() - started < 5)
        # the body ends (the client closes its side) before its length
        with socket.create_connection(("127.0.0.1", rw.port), timeout=8) as conn:
            conn.sendall(
                f"POST /api/share HTTP/1.1\r\nHost: 127.0.0.1:{rw.port}\r\nX-Studio-Token: {rw.token}\r\n"
                'Content-Length: 50\r\n\r\n{"as": "user:1"}'.encode()
            )
            conn.shutdown(socket.SHUT_WR)
            got = b""
            while data := conn.recv(65536):
                got += data
        check(
            "a body shorter than its length: 400, and says so",
            got.startswith(b"HTTP/1.0 400 ")
            and json.loads(got.partition(b"\r\n\r\n")[2])["detail"] == "the body ended after 16 of its 50 bytes",
            got,
        )
        # the largest body the cap takes is read, and answered as any change is
        padded = b'{"as": "user:1"' + b" " * (limit - 16) + b"}"
        r = by_hand(rw, {**json_head, "Content-Length": str(len(padded))}, padded)
        check(
            f"a body of {limit} bytes, the cap, is read: answered as a change (here one that names nothing)",
            len(padded) == limit and (r.status, r.answer["detail"]) == (400, "missing or wrong: 'type'"),
            r,
        )
        psql(
            db,
            "SELECT authz.act_as('user', '2'); SELECT authz.request_access('folder', '5', 'viewer', 'for the audit')",
        )
        status, sh = c.call("/api/shares")
        req = [x for x in sh["requests"] if x["object_id"] == "5"]
        check("a pending access request", status == 200 and req and req[0]["requester"] == "2", sh)
        status, e = c.call("/api/decide", {"as": "user:2", "request": req[0]["id"], "approve": True})
        check("deciding your own request is refused", status == 403, e)
        status, _ = c.call("/api/decide", {"as": "user:5", "request": req[0]["id"], "approve": True})
        check(
            "... the owner approves it, and it is a share",
            status == 200
            and psql(db, "SELECT count(*) FROM authz.shares WHERE object_id = '5' AND subject_id = '2'") == "1",
        )
    finally:
        rw.stop()

    print("-- a test's copy of a row: each value as the column holds it")
    psql(
        db,
        "ALTER TABLE app.folders ADD COLUMN tags text[], ADD COLUMN meta jsonb, ADD COLUMN size numeric, "
        "ADD COLUMN label text GENERATED ALWAYS AS (upper(name)) STORED; "
        'UPDATE app.folders SET tags = \'{plans,"q3 review"}\', meta = \'{"color": "red"}\', '
        "size = 12345678901234567.89 WHERE id = 5",
    )
    s = studio.Studio(dsn, None, policy, writable=False, port=0, read_policy=rowstile_cli.read_policy)
    s.start()
    try:
        # Secrets doesn't inherit, where the column's default does: the policy reads the row's value
        status, t = Client(s).call("/api/test?as=user:3&type=folder&id=5&perm=edit&expect=cannot")
        made, row = made_and_copied(db, t.get("named", ""), "it", "app.folders", "id = 5")
        check(
            "a column with a default, an array, json, a number with a fraction, a column the table makes: the copy "
            "is the row",
            status == 200 and made == row and '"inherit": false' in row and '"tags": ["plans", "q3 review"]' in row,
            (made, row),
        )
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, "made.authz"), "w", encoding="utf-8") as fh:
                fh.write(t.get("named", ""))
            _, out = cli(db, "test", os.path.join(tmp, "made.authz"))
        ran = out.split("user 3 cannot edit folder 5", 1)[-1].split("invariants", 1)[0]
        check(
            "... and the test runs as it is",
            "user 3 cannot edit folder 5" in out and "ok    " in ran and "FAIL" not in ran,
            out[-800:],
        )
    finally:
        s.stop()

    print("-- rowstile studio, the command")
    p, line, at = serving(db)
    check(
        "it says where it is (the address it listens on), with a token, and that it is read-only",
        line == f"rowstile studio: http://127.0.0.1:{at.port}/?token={at.token}  (read-only; Ctrl-C stops it)\n"
        and len(at.token) >= 20,
        line,
    )
    status, o = Client(at).call("/api/overview")
    check("... answers the page that has the token", status == 200 and o["writable"] is False, (status, o))
    check("... and Ctrl-C stops it", stopped(p) == 0)
    p, line, at = serving(db, "--write")
    status, o = Client(at).call("/api/overview")
    stopped(p)
    check(
        "with --write it says it can write, and does",
        line.endswith(f"/?token={at.token}  (can write: shares and requests; Ctrl-C stops it)\n")
        and status == 200
        and o["writable"] is True,
        (line, status, o),
    )
    with socket.socket() as held:
        held.bind(("127.0.0.1", 0))
        held.listen()
        rc, out = cli(db, "studio", "--port", str(held.getsockname()[1]))
    check(
        "a port another program listens on: it didn't start, and how to pick another, exit 2",
        rc == 2
        and out.startswith("Studio didn't start (")
        and out.endswith("): rowstile studio --port N for another port\n"),
        (rc, out),
    )
    rc, out = cli(db, "studio", "--port", "99999")
    check(
        "... a port there can't be: refused before Studio starts, as a mistake in the command line",
        (rc, out) == (2, "--port needs a port, a whole number from 1 to 65535, not '99999'\n"),
        (rc, out),
    )
    for label, target, said in (
        ("a database that isn't there", f"dbname={db}_nowhere", f': 3D000: database "{db}_nowhere" does not exist'),
        (
            "a server that isn't there",
            "host=/nowhere dbname=x",
            " to the socket /nowhere/.s.PGSQL.5432: no such file or directory",
        ),
        (
            "an address it can't read",
            "postgres://a@localhost:port/x",
            ": the URL's port isn't a number: a #, ? or / in the password must be written %23, %3F, %2F",
        ),
        (
            "a setting it doesn't know",
            "colour=blue",
            ": unknown connection setting 'colour' (use host, port, user, password, dbname, sslmode)",
        ),
    ):
        rc, out = command(target, "studio", "--port", str(free_port()))
        check(
            f"{label}: can't connect, as the other commands say it, exit 2",
            (rc, out) == (2, f"can't connect{said}\n"),
            (rc, out),
        )
    # a role that may log in and read nothing of rowstile's (an app's own DATABASE_URL, say)
    # (roles are the server's, not a database's: named after this run's database, so two runs side by side differ)
    login = f"{db}_login"
    psql(db, f"DROP ROLE IF EXISTS {login}; CREATE ROLE {login} LOGIN")
    rc, out = command(f"dbname={db} user={login}", "studio", "--port", str(free_port()))
    psql(db, f"DROP ROLE {login}")
    check(
        "connected as a role that can't read rowstile's tables: the database's words, exit 1",
        (rc, out) == (1, "rowstile studio: permission denied for schema authz\n"),
        (rc, out),
    )

    print("-- Studio when the database can't be reached")
    gone = studio.Studio(
        "host=/nowhere dbname=x", None, None, writable=False, port=0, read_policy=rowstile_cli.read_policy
    )
    gone.start()
    try:
        status, e = Client(gone).call("/api/overview")
        check(
            "the page is told it can't connect, as the command says it (503)",
            status == 503
            and e["detail"] == "can't connect to the socket /nowhere/.s.PGSQL.5432: no such file or directory",
            (status, e),
        )
    finally:
        gone.stop()

    print("-- Studio losing the database as a request waits")
    terminate: Callable[[str], object] = lambda pid: psql(db, f"SELECT pg_terminate_backend({pid})")
    lost = "lost the database: terminating connection due to administrator command"
    ro = studio.Studio(dsn, None, policy, writable=False, port=0, read_policy=rowstile_cli.read_policy)
    ro.start()
    try:
        status, e, logged = waiting(db, ro, "/api/overview", None, "authz.policy_versions", terminate)
        check(
            "the server ends Studio's session as a request waits: 503, lost the database in the server's words, and "
            "no traceback",
            (status, e, logged) == (503, {"title": "Problem", "status": 503, "detail": lost}, ""),
            (status, e, logged[-600:]),
        )
        check("... and the next request connects again", Client(ro).call("/api/overview")[0] == 200)
    finally:
        ro.stop()
    rw = studio.Studio(dsn, None, policy, writable=True, port=0, read_policy=rowstile_cli.read_policy)
    rw.start()
    try:
        body = {"type": "folder", "id": "3", "relation": "editor", "subject_type": "user", "subject_id": "3"}
        before = shares()
        # the share waits to write (SHARE mode lets it read the table, not write it)
        status, e, logged = waiting(
            db, rw, "/api/share", {**body, "as": "user:1"}, "authz.shares IN SHARE MODE", terminate
        )
        check(
            "... as it writes a share (--write): the same, and nothing written",
            (status, e["detail"], logged) == (503, lost, "") and shares() == before,
            (status, e, logged[-600:]),
        )
        status, _ = Client(rw).call("/api/share", {**body, "as": "user:1"})
        check(
            "... and the share asked again is made",
            status == 200
            and shares() == str(int(before) + 1)
            and Client(rw).call("/api/unshare", {**body, "as": "user:1"})[0] == 200,
            status,
        )
    finally:
        rw.stop()
    between = Between()
    via = studio.Studio(
        f"host=127.0.0.1 port={between.port} dbname={db}",
        None,
        policy,
        writable=False,
        port=0,
        read_policy=rowstile_cli.read_policy,
    )
    via.start()
    try:
        status, e, logged = waiting(
            db, via, "/api/overview", None, "authz.policy_versions", lambda _: between.hang_up()
        )
        check(
            "the connection closed under a request without a word from the server: 503, lost the database, and no "
            "traceback",
            (status, e["detail"], logged) == (503, "lost the database: the server closed the connection", ""),
            (status, e, logged[-600:]),
        )
        check("... and the next request connects again", Client(via).call("/api/overview")[0] == 200)
        status, e, logged = waiting(
            db, via, "/api/overview", None, "authz.policy_versions", lambda _: between.hang_up(reset=True)
        )
        check(
            "the connection reset under a request: 503, lost the database, and no traceback",
            (status, e["detail"], logged) == (503, "lost the database: [Errno 104] Connection reset by peer", ""),
            (status, e, logged[-600:]),
        )
        check("... and the next request connects again", Client(via).call("/api/overview")[0] == 200)
        # the server restarts between two requests: Studio holds no connection while none waits
        between.stop()
        status, e = Client(via).call("/api/overview")
        check(
            "the server gone between two requests: 503, can't connect",
            (status, e["detail"]) == (503, f"can't connect to 127.0.0.1 port {between.port}: connection refused"),
            (status, e),
        )
        between.again()
        check("... and back: the next request connects", Client(via).call("/api/overview")[0] == 200)
    finally:
        via.stop()
        between.stop()

    print("-- the policy taken out while Studio runs (rowstile remove)")
    rc, out = cli(db, "remove", "--yes")
    if rc:
        raise SystemExit(out)
    ro = studio.Studio(dsn, None, policy, writable=False, port=0, read_policy=rowstile_cli.read_policy)
    rw = studio.Studio(dsn, None, policy, writable=True, port=0, read_policy=rowstile_cli.read_policy)
    ro.start()
    rw.start()
    try:
        for label, s, path in (
            ("the overview", ro, "/api/overview"),
            ("the graph", ro, "/api/graph"),
            ("the rows", ro, "/api/rows?table=app.folders&as=user:2"),
            ("the shares and requests", ro, "/api/shares"),
            ("why", ro, "/api/why?as=user:3&type=folder&id=3&perm=edit"),
            ("why, trying changes", rw, "/api/why?as=user:3&type=folder&id=3&perm=edit"),
            ("the access diff", rw, "/api/diff"),
            ("a test", ro, "/api/test?as=user:3&type=folder&id=3&perm=edit"),
        ):
            status, e = Client(s).call(path)
            check(
                f"{label}: no policy is applied, and how to apply one",
                status == 400 and e.get("detail") == "no policy is applied [AZ609] (rowstile apply db/policy.authz)",
                (status, e),
            )
    finally:
        ro.stop()
        rw.stop()
    rc, out = cli(db, "studio", "--port", str(free_port()))
    check(
        "rowstile studio on a database with no policy in force: says so, and how to apply one, exit 1",
        (rc, out) == (1, "rowstile studio: no policy is applied [AZ609]\nHINT: rowstile apply db/policy.authz\n"),
        (rc, out),
    )

    print("-- Studio on a table with a masked column (tests/multi.authz: mask body : edit)")
    masks = f"{db}_masks"
    subprocess.run(["dropdb", "--if-exists", masks], capture_output=True)
    subprocess.run(["createdb", masks], check=True)
    subprocess.run(
        ["psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", "-d", masks, "-f", os.path.join(HERE, "multi_schema.sql")],
        check=True,
        capture_output=True,
    )
    lead, bob, carol = (f"00000000-0000-4000-8000-00000000000{n}" for n in (1, 2, 3))
    plain, bobs = "10000000-0000-4000-8000-000000000001", "10000000-0000-4000-8000-000000000002"
    psql(
        masks,
        f"INSERT INTO mt.users VALUES ('{lead}'), ('{bob}'), ('{carol}'); INSERT INTO mt.orgs VALUES (1); "
        f"INSERT INTO mt.projects (id, org_id, lead_id) VALUES (1, 1, '{lead}'); "
        f"INSERT INTO mt.docs VALUES ('{plain}', 'project', 1, NULL, 'secret text'), ('{bobs}', 'project', 1, '{bob}', 'bob wrote this')",
    )
    rc, out = cli(masks, "apply", os.path.join(HERE, "multi.authz"))
    if rc:
        raise SystemExit(out)
    psql(masks, f"SELECT authz.act_as('user', '{lead}'); SELECT authz.share('project', '1', 'viewer', 'user', '{bob}')")
    ms = studio.Studio(
        f"dbname={masks}",
        None,
        os.path.join(HERE, "multi.authz"),
        writable=False,
        port=0,
        read_policy=rowstile_cli.read_policy,
    )
    ms.start()
    c = Client(ms)
    try:

        def docs(who: str) -> tuple[int, Answer, dict[str, Answer]]:
            status, r = c.call(f"/api/rows?table=mt.docs&as={who}")
            return status, r, {x["id"]: x for x in r["rows"]} if status == 200 else {}

        status, r, by = docs(f"user:{lead}")
        check(
            "the project's lead may edit: both rows, the masked column in full",
            status == 200
            and r["visible_total"] == 2
            and by[plain]["values"]["body"] == "secret text"
            and by[plain]["masked"] == []
            and by[bobs]["masked"] == [],
            r,
        )
        status, r, by = docs(f"user:{bob}")
        check(
            "a viewer sees the rows, and the masked column as they get it: empty, and named",
            status == 200
            and r["visible_total"] == 2
            and by[plain]["visible"]
            and by[plain]["values"]["body"] is None
            and by[plain]["masked"] == ["body"],
            r,
        )
        check(
            "... but in full on the document they wrote (the mask's rule holds there)",
            status == 200 and by[bobs]["values"]["body"] == "bob wrote this" and by[bobs]["masked"] == [],
            r,
        )
        status, r, by = docs(f"user:{carol}")
        check(
            "someone with no access: every row hidden",
            status == 200
            and r["visible_total"] == 0
            and r["total"] == 2
            and not any(x["visible"] for x in r["rows"])
            and all(x["masked"] == [] for x in r["rows"]),
            r,
        )
        # why on a policy with a container of two types and custom roles: the ways through the project the doc
        # sits in, and its own author; a custom role is no way rowstile why offers (roles are made at run time)
        _, said = cli(masks, "why", "--as", f"user:{carol}", "doc", plain, "edit")
        lines = said.splitlines()
        ways = (
            [x.strip() for x in lines[lines.index("would be granted by:") + 1 :]]
            if "would be granted by:" in lines
            else []
        )
        check(
            "why through a container of two types: the project's lead, or the doc's author",
            any(w.startswith(f"set lead_id of project 1 to {carol}") for w in ways)
            and any(w.startswith(f"set author_id of doc {plain} to {carol}") for w in ways)
            and not any("role:" in w or "custom role" in w for w in ways),
            said,
        )
        # rows keyed by uuid: the copies a test brings get keys of their own, and the rest as the rows hold it
        status, t = c.call(f"/api/test?as=user:{bob}&type=doc&id={plain}&perm=edit&expect=cannot")
        named = t.get("named", "") if status == 200 else ""
        made, row = made_and_copied(masks, named, "it", "mt.docs", f"id = '{plain}'")
        check(
            "a test on rows keyed by uuid: new keys for the copies, and the copy is the row",
            status == 200
            and 'given who = {INSERT INTO "mt"."users" ("id", "active") VALUES (gen_random_uuid(), true) RETURNING "id"}'
            in named
            and made == row
            and '"body": "secret text"' in row,
            (status, t, made, row),
        )
    finally:
        ms.stop()
    subprocess.run(["dropdb", "--if-exists", masks], capture_output=True)

    print("-- a test on a key of several columns, and on text in a key (tests/composite.authz)")
    keys = f"{db}_keys"
    subprocess.run(["dropdb", "--if-exists", keys], capture_output=True)
    subprocess.run(["createdb", keys], check=True)
    subprocess.run(
        ["psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", "-d", keys, "-f", os.path.join(HERE, "composite_schema.sql")],
        check=True,
        capture_output=True,
    )
    psql(
        keys,
        "INSERT INTO cx.users VALUES (1, NULL), (2, 1); INSERT INTO cx.orgs VALUES (1); "
        "INSERT INTO cx.teams (org_id, slug, lead_id) VALUES (1, 'a b', 1), (1, 'it''s', 1); "
        "INSERT INTO cx.projects VALUES (1, 5, 1, NULL)",
    )
    rc, out = cli(keys, "apply", os.path.join(HERE, "composite.authz"))
    if rc:
        raise SystemExit(out)
    ks = studio.Studio(
        f"dbname={keys}", None, os.path.join(HERE, "composite.authz"), port=0, read_policy=rowstile_cli.read_policy
    )
    ks.start()
    try:
        for label, ask, written in (
            ("a key of several columns", "type=project&id=(1,5)&perm=edit", "edit project (1,5)"),
            (
                "a key with a space in its text: quoted",
                "type=team&id=(1,%22a%20b%22)&perm=share",
                "share team '(1,\"a b\")'",
            ),
            (
                "... and an apostrophe: quoted, and doubled",
                "type=team&id=(1,it%27s)&perm=share",
                "share team '(1,it''s)'",
            ),
        ):
            status, t = Client(ks).call(f"/api/test?as=user:2&{ask}&expect=cannot")
            rc, out = -1, ""
            if status == 200:
                with tempfile.TemporaryDirectory() as tmp:
                    with open(os.path.join(tmp, "made.authz"), "w", encoding="utf-8") as fh:
                        fh.write(f'test "on the data there"\n  {t["check"]}\n\n{t["named"]}')
                    rc, out = cli(keys, "test", os.path.join(tmp, "made.authz"))
            check(
                f"a test on {label}: no copy of the row, and the check and the test run as written",
                status == 200
                and t["check"] == f"user 2 cannot {written}"
                and "given it" not in t["named"]
                and rc == 0
                and out.count("ok    ") == 2,
                (status, t, out[-600:]),
            )
    finally:
        ks.stop()
    subprocess.run(["dropdb", "--if-exists", keys], capture_output=True)

    print("-- a test on tables named with capitals, as Prisma names them (tests/prisma.authz)")
    caps = f"{db}_caps"
    subprocess.run(["dropdb", "--if-exists", caps], capture_output=True)
    subprocess.run(["createdb", caps], check=True)
    subprocess.run(
        ["psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", "-d", caps, "-f", os.path.join(HERE, "prisma_schema.sql")],
        check=True,
        capture_output=True,
    )
    psql(caps, 'UPDATE "Note" SET locked = true WHERE id = 2')  # its managers' only: the policy reads it
    rc, out = cli(caps, "apply", os.path.join(HERE, "prisma.authz"))
    if rc:
        raise SystemExit(out)
    s = studio.Studio(
        f"dbname={caps}", None, os.path.join(HERE, "prisma.authz"), port=0, read_policy=rowstile_cli.read_policy
    )
    s.start()
    try:
        status, t = Client(s).call("/api/test?as=user:2&type=note&id=2&perm=edit&expect=cannot")
    finally:
        s.stop()
    named = t.get("named", "") if status == 200 else ""
    made, row = made_and_copied(caps, named, "it", 'public."Note"', "id = 2")
    check(
        "a test on tables named with capitals: the person's key left to its sequence, the locked note's copy is the row",
        status == 200
        and 'given who = {INSERT INTO "public"."User" ("name") VALUES (\'bo\') RETURNING "id"}' in named
        and made == row
        and '"locked": true' in row,
        (status, t, made, row),
    )
    with tempfile.TemporaryDirectory() as tmp:
        with open(os.path.join(tmp, "made.authz"), "w", encoding="utf-8") as fh:
            fh.write(named)
        _, out = cli(caps, "test", os.path.join(tmp, "made.authz"))
    ran = out.split("user 2 cannot edit note 2", 1)[-1].split("invariants", 1)[0]
    check(
        "... and the test runs as it is",
        "user 2 cannot edit note 2" in out and "ok    " in ran and "FAIL" not in ran,
        out[-800:],
    )
    subprocess.run(["dropdb", "--if-exists", caps], capture_output=True)

    print("-- Studio through an app role the owner may not take, with no rules, and users keyed by text")
    # since PostgreSQL 16 a role that makes another gets ADMIN on it, not SET (the suites' owner has
    # createrole_self_grant, which would hide it): as on managed Postgres until the owner grants itself the role
    plain, app = f"{db}_plain", f"{db}_plain_app"
    subprocess.run(["dropdb", "--if-exists", plain], capture_output=True)
    psql("postgres", f"DROP ROLE IF EXISTS {app}")
    subprocess.run(["createdb", plain], check=True)
    subprocess.run(
        [
            "psql",
            "-X",
            "-q",
            "-v",
            "ON_ERROR_STOP=1",
            "-d",
            plain,
            "-c",
            f"CREATE ROLE {app}",
            "-c",
            "CREATE SCHEMA app; CREATE TABLE app.users (id text PRIMARY KEY); "
            "CREATE TABLE app.notes (id bigint PRIMARY KEY, owner_id text NOT NULL REFERENCES app.users, body text); "
            f"GRANT USAGE ON SCHEMA app TO {app}; GRANT SELECT ON app.users TO {app}; "
            f"GRANT SELECT, UPDATE ON app.notes TO {app}; "
            "INSERT INTO app.users VALUES ('1'), ('o''brien'); INSERT INTO app.notes VALUES (1, '1', 'mine')",
        ],
        env=dict(os.environ, PGOPTIONS="-c createrole_self_grant= -c client_min_messages=error"),
        check=True,
        capture_output=True,
    )
    me = psql(plain, "SELECT current_user")
    types = f"app role {app}\ntype user = app.users (id text)\ntype note = app.notes\n  owner : user = owner_id\n  can edit = owner\n"
    with tempfile.TemporaryDirectory() as tmp:
        for label, text, want, said in (
            (
                "the rows, through an app role the owner may not take: what to grant, as the other commands say it",
                types + "rules app.notes\n  select : edit\n  update : edit\n",
                400,
                f"{me} may not switch to the app role {app} (SET ROLE), and this looks at the data as the app does "
                f'[AZ618] (once, as {me} if it made {app}, else as the role that did or a superuser: GRANT "{app}" TO "{me}")',
            ),
            (
                "a policy with no rules: no app role to look through, and says so",
                types,
                409,
                "no policy with rules is applied, so there is no app role to look through",
            ),
        ):
            path = os.path.join(tmp, "plain.authz")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(text)
            rc, out = cli(plain, "apply", path)
            if rc:
                raise SystemExit(out)
            s = studio.Studio(f"dbname={plain}", None, path, port=0, read_policy=rowstile_cli.read_policy)
            s.start()
            try:
                status, e = Client(s).call("/api/rows?table=app.notes&as=user:1")
                check(f"{label} ({want})", status == want and e.get("detail") == said, (status, e))
            finally:
                s.stop()
        # its users are keyed by text: a test as someone whose id isn't one word
        s = studio.Studio(f"dbname={plain}", None, path, port=0, read_policy=rowstile_cli.read_policy)
        s.start()
        try:
            status, t = Client(s).call("/api/test?as=user:o%27brien&type=note&id=1&perm=edit&expect=cannot")
        finally:
            s.stop()
        rc, out = -1, ""
        if status == 200:
            with open(os.path.join(tmp, "made.authz"), "w", encoding="utf-8") as fh:
                fh.write(f'test "on the data there"\n  {t["check"]}\n\n{t["named"]}')
            rc, out = cli(plain, "test", os.path.join(tmp, "made.authz"))
        check(
            "a test as someone whose id isn't one word: quoted, and the check and the test run as written",
            status == 200
            and t["check"] == "user 'o''brien' cannot edit note 1"
            and rc == 0
            and out.count("ok    ") == 2,
            (status, t, out[-600:]),
        )
    subprocess.run(["dropdb", "--if-exists", plain], capture_output=True)
    psql("postgres", f"DROP ROLE IF EXISTS {app}")

    print("-- rowstile why through a table that names its rows' type (tests/cross.authz: a project's backers)")
    cross = db + "_cross"
    subprocess.run(["dropdb", "--if-exists", cross], capture_output=True)
    subprocess.run(["createdb", cross], check=True)
    subprocess.run(
        [
            "psql",
            "-X",
            "-q",
            "-v",
            "ON_ERROR_STOP=1",
            "-d",
            cross,
            "-f",
            os.path.join(ROOT, "tests", "cross_schema.sql"),
        ],
        check=True,
        capture_output=True,
    )
    rc, out = cli(cross, "apply", os.path.join(ROOT, "tests", "cross.authz"))
    if rc:
        raise SystemExit(out)
    # bo leads project 1, which region 2 backs; folder 2, which has the same id, doesn't back it. Ann funds the
    # project through its backer: the region's chief, not the folder's owner (a row's type, read as it is written)
    psql(
        cross,
        "INSERT INTO cx.users VALUES (1, 'ann'), (2, 'bo'); INSERT INTO cx.folders (id, owner_id) VALUES (2, 2); "
        "INSERT INTO cx.regions (id, chief_id) VALUES (2, 2); INSERT INTO cx.projects (id, lead_id) VALUES (1, 2); "
        "INSERT INTO cx.backings VALUES (1, 'region', 2)",
    )
    rc, said = cli(cross, "why", "--as", "user:1", "project", "1", "fund")
    after = said.splitlines()
    ways = (
        [x.strip() for x in after[after.index("would be granted by:") + 1 :]] if "would be granted by:" in after else []
    )
    check(
        "the backer of the type its row names: the region's chief, and nothing of the folder of the same id",
        rc == 0
        and any(w.startswith(("set chief_id of region 2 to 1", "share chief on region 2 with user 1")) for w in ways)
        and not any("folder 2" in w for w in ways),
        said,
    )
    check("... and nothing of it stays", psql(cross, "SELECT chief_id FROM cx.regions WHERE id = 2") == "2")
    subprocess.run(["dropdb", "--if-exists", cross], capture_output=True)

    corners(db + "_why")

    subprocess.run(["dropdb", "--if-exists", db], capture_output=True)
    print("studio: all passed" if not fails else f"studio: {fails} failed")
    sys.exit(1 if fails else 0)


# rowstile why on what the docs example doesn't have: groups in groups through a permission, a table naming its
# rows' type, a share that expired, `shared if`, a link table with a column no change fills, a chain of five, a
# service that signs in, a deny, a condition, a key of two columns, a type's where, a `shared if` that reads who
# shares, and a share that takes away (a deny on what it gives)
WHY_SCHEMA = """
CREATE SCHEMA cn;
CREATE TABLE cn.clubs (id bigint PRIMARY KEY);
CREATE TABLE cn.users (id bigint PRIMARY KEY, active boolean NOT NULL DEFAULT true, club_id bigint REFERENCES cn.clubs);
CREATE TABLE cn.bots (id bigint PRIMARY KEY, owner_id bigint REFERENCES cn.users);
CREATE TABLE cn.groups (id bigint PRIMARY KEY, parent_id bigint REFERENCES cn.groups);
CREATE TABLE cn.group_members (group_id bigint REFERENCES cn.groups, member_type text NOT NULL, member_id bigint,
  PRIMARY KEY (group_id, member_type, member_id));
CREATE TABLE cn.docs (id bigint PRIMARY KEY, parent_id bigint REFERENCES cn.docs, owner_id bigint REFERENCES cn.users,
  archived boolean NOT NULL DEFAULT false);
CREATE TABLE cn.doc_editors (doc_id bigint REFERENCES cn.docs, user_id bigint REFERENCES cn.users,
  added_by bigint NOT NULL REFERENCES cn.users, PRIMARY KEY (doc_id, user_id));
CREATE TABLE cn.doc_groups (doc_id bigint REFERENCES cn.docs, group_id bigint REFERENCES cn.groups,
  until timestamptz NOT NULL, PRIMARY KEY (doc_id, group_id));
CREATE TABLE cn.pages (id bigint PRIMARY KEY, parent_id bigint REFERENCES cn.pages, hidden boolean NOT NULL);
CREATE TABLE cn.page_readers (page_id bigint REFERENCES cn.pages, user_id bigint REFERENCES cn.users,
  PRIMARY KEY (page_id, user_id));
CREATE TABLE cn.projects (org_id bigint, id bigint, lead_id bigint REFERENCES cn.users, PRIMARY KEY (org_id, id));
CREATE TABLE cn.project_members (org_id bigint, project_id bigint, user_id bigint REFERENCES cn.users,
  PRIMARY KEY (org_id, project_id, user_id), FOREIGN KEY (org_id, project_id) REFERENCES cn.projects);
CREATE TABLE cn.project_groups (org_id bigint, project_id bigint, group_id bigint REFERENCES cn.groups,
  PRIMARY KEY (org_id, project_id, group_id), FOREIGN KEY (org_id, project_id) REFERENCES cn.projects);
CREATE TABLE cn.shelves (id bigint PRIMARY KEY, closed boolean);
CREATE TABLE cn.shelf_keepers (shelf_id bigint REFERENCES cn.shelves, user_id bigint REFERENCES cn.users,
  since date NOT NULL, PRIMARY KEY (shelf_id, user_id));
CREATE TABLE cn.teams (id bigint PRIMARY KEY);
CREATE TABLE cn.team_members (team_id bigint REFERENCES cn.teams, user_id bigint REFERENCES cn.users,
  PRIMARY KEY (team_id, user_id));
CREATE TABLE cn.rooms (id bigint PRIMARY KEY, owner_id bigint REFERENCES cn.users);
CREATE TABLE cn.room_mics (room_id bigint REFERENCES cn.rooms, user_id bigint REFERENCES cn.users,
  PRIMARY KEY (room_id, user_id));
CREATE TABLE cn."Stage" (id bigint PRIMARY KEY, "ownerId" bigint REFERENCES cn.users);
CREATE TABLE cn."StageMic" ("stageId" bigint REFERENCES cn."Stage", "userId" bigint REFERENCES cn.users,
  "isOn" boolean NOT NULL DEFAULT false, PRIMARY KEY ("stageId", "userId"));
CREATE TABLE cn.orgs (id bigint PRIMARY KEY);
CREATE TABLE cn.org_members (org_id bigint REFERENCES cn.orgs, user_id bigint REFERENCES cn.users, role text NOT NULL,
  PRIMARY KEY (org_id, user_id));
CREATE TABLE cn.desks (id bigint PRIMARY KEY, org_id bigint REFERENCES cn.orgs);
CREATE TABLE cn.chairs (id bigint PRIMARY KEY, desk_id bigint REFERENCES cn.desks);
GRANT USAGE ON SCHEMA cn TO app_user;
GRANT SELECT ON ALL TABLES IN SCHEMA cn TO app_user;
-- ann (1) owns docs 1 to 5, each inside the one before, and doc 6, archived; bo (2) is in group 2, which is in
-- group 1, as group 3 is; dee (4) is no longer active; bot 1 may view doc 4; ann leads project (1,5) and is one of
-- its members, and group 3's members are its members too; cy is in club 2; shelf 1 is closed, shelf 2 open,
-- and whether shelf 3 is closed isn't known (NULL: the type's where doesn't hold); bo and eve (5) are team 7; ann
-- owns rooms 1 and 3, nobody room 2; bo has the mic in room 1; groups 4 to 7 are each inside the one before; ann
-- owns doc 7, and stage 1, where bo's mic is off (its tables named in capitals, as Prisma names them)
INSERT INTO cn.clubs VALUES (1), (2);
INSERT INTO cn.users VALUES (1, true, NULL), (2, true, NULL), (3, true, 2), (4, false, NULL), (5, true, NULL);
INSERT INTO cn.bots VALUES (1, 1);
INSERT INTO cn.groups VALUES (1, NULL), (2, 1), (3, 1);
INSERT INTO cn.group_members VALUES (2, 'user', 2);
INSERT INTO cn.docs VALUES (1, NULL, 1, false), (2, 1, 1, false), (3, 2, 1, false), (4, 3, 1, false),
  (5, 4, 1, false), (6, NULL, 1, true);
INSERT INTO cn.pages VALUES (1, NULL, true), (2, 1, false);
INSERT INTO cn.projects VALUES (1, 5, 1);
INSERT INTO cn.project_members VALUES (1, 5, 1);
INSERT INTO cn.project_groups VALUES (1, 5, 3);
INSERT INTO cn.shelves VALUES (1, true), (2, false), (3, NULL);
INSERT INTO cn.teams VALUES (7);
INSERT INTO cn.team_members VALUES (7, 2), (7, 5);
INSERT INTO cn.rooms VALUES (1, 1), (2, NULL), (3, 1);
INSERT INTO cn.room_mics VALUES (1, 2);
INSERT INTO cn.groups VALUES (4, NULL), (5, 4), (6, 5), (7, 6);
INSERT INTO cn.docs VALUES (7, NULL, 1, false);
INSERT INTO cn."Stage" VALUES (1, 1);
INSERT INTO cn."StageMic" VALUES (1, 2, false);
-- ann is org 1's admin and eve one of its members; bo is org 2's admin; desk 1 is org 1's, chairs 1 and 2 at it
INSERT INTO cn.orgs VALUES (1), (2);
INSERT INTO cn.org_members VALUES (1, 1, 'admin'), (1, 5, 'member'), (2, 2, 'admin');
INSERT INTO cn.desks VALUES (1, 1);
INSERT INTO cn.chairs VALUES (1, 1), (2, 1);
"""
WHY_POLICY = """app role app_user

type user = cn.users
type bot = cn.bots principal
  owner : user = owner_id
  can manage_keys = owner

type grp = cn.groups
  member : user, bot  = cn.group_members(group_id -> (member_type, member_id))
  member : grp#member = cn.groups(parent_id -> id)
  can belong = member

type doc = cn.docs
  parent : doc  = parent_id
  owner  : user = owner_id
  editor : user = cn.doc_editors(doc_id -> user_id)
  viewer : user, user:*, bot, grp#belong shared if {subject_type <> 'user' or subject_id in (select id::text from cn.users where active)}
  reader : grp#member = cn.doc_groups(doc_id -> group_id) where {until > now()}
  can share   = owner
  can edit    = owner or editor
  can view    = edit or viewer or reader or parent.view
  can archive = owner and not {archived}

type page = cn.pages
  parent : page = parent_id
  reader : user = cn.page_readers(page_id -> user_id)
  reader : user, user:* shared by read
  can hidden = {hidden} or parent.hidden
  can read   = (reader or parent.read) and not hidden

type project = cn.projects (org_id, id)
  lead   : user = lead_id
  member : user = cn.project_members([org_id, project_id] -> user_id)
  member : grp#member = cn.project_groups([org_id, project_id] -> group_id)
  editor : user, grp#member shared if {subject_type = 'user'}
  can share = lead
  can edit  = lead or member or editor

type club = cn.clubs
  member : user = cn.users(club_id -> id)
  can enter = member

type shelf = cn.shelves where {not closed}
  keeper : user = cn.shelf_keepers(shelf_id -> user_id)
  can use = keeper

type team = cn.teams
  member : user = cn.team_members(team_id -> user_id)

type room = cn.rooms
  owner : user = owner_id
  mic   : user = cn.room_mics(room_id -> user_id)
  host  : user, team#member shared
  guest : user, team#member shared if {subject_id <> authz.uid()::text}
  can share   = owner
  can enter   = owner or host or guest
  can speak   = (owner or host) and not guest
  can present = owner and mic

type stage = cn.Stage
  owner : user = ownerId
  mic   : user = cn.StageMic(stageId -> userId) where {"isOn"}
  star  : user shared
  can share   = owner
  can tune    = star
  can light   = star
  can bow     = star
  can perform = (owner and mic) or star
type org = cn.orgs
  admin : user = cn.org_members(org_id -> user_id) where {role = 'admin'}

type desk = cn.desks
  keeper : org#admin = org_id
  can keep = keeper
  can sit  = {exists (select 1 from cn.org_members m where m.org_id = this.org_id and m.user_id = authz.uid())}

type chair = cn.chairs
  desk : desk = desk_id
  can use = desk.sit
  can rest = desk.keep
"""


def corners(db: str) -> None:
    print("-- rowstile why on the shapes the docs example doesn't have")
    subprocess.run(["dropdb", "--if-exists", db], capture_output=True)
    subprocess.run(["createdb", db], check=True)
    psql(db, WHY_SCHEMA)
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "why.authz")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(WHY_POLICY)
        rc, out = cli(db, "apply", path)
    if rc:
        raise SystemExit(out)
    # cy (3) could view doc 3 until yesterday; bot 1 may view doc 4; eve hosts room 1, and room 3 as its guest too;
    # page 2 was shared with every user before page 1, above it, was hidden; doc 7 is shared with group 4's members
    psql(
        db,
        "SELECT authz.act_as('user', '1'); "
        "SELECT authz.share('doc', '3', 'viewer', 'user', '3', '', now() - interval '1 day'); "
        "SELECT authz.share('doc', '4', 'viewer', 'bot', '1'); "
        "SELECT authz.share('room', '1', 'host', 'user', '5'); "
        "SELECT authz.share('room', '3', 'host', 'user', '5'); SELECT authz.share('room', '3', 'guest', 'user', '5'); "
        "INSERT INTO authz.shares (object_type, object_id, relation, subject_type, subject_id) "
        "VALUES ('page', '2', 'reader', 'user', '*'); "
        "SELECT authz.share('doc', '7', 'viewer', 'grp', '4', 'belong')",
    )
    data = "SELECT (SELECT string_agg(s::text, ' ' ORDER BY s::text) FROM authz.shares s), " + ", ".join(
        f"(SELECT string_agg(x::text, ' ' ORDER BY x::text) FROM {t} x)"
        for t in (
            "cn.users",
            "cn.groups",
            "cn.group_members",
            "cn.docs",
            "cn.doc_editors",
            "cn.projects",
            "cn.project_members",
            "cn.project_groups",
            "cn.shelf_keepers",
            "cn.rooms",
            "cn.room_mics",
            'cn."Stage"',
            'cn."StageMic"',
        )
    )
    before = psql(db, data)

    def why(*question: str) -> tuple[int, str, list[str], list[str]]:
        """The exit code, what it printed, the ways that grant it, and the lines after them."""
        rc, said = cli(db, "why", *question)
        lines = said.splitlines()
        ways = lines[lines.index("would be granted by:") + 1 :] if "would be granted by:" in lines else []
        return rc, said, [x.strip() for x in ways if x.startswith("  ")], [x for x in ways if not x.startswith("  ")]

    rc, said, ways, _ = why("--as", "user:2", "doc", "5", "view")
    check(
        "a group whose membership is a permission: a share with each group the person belongs to, the one above "
        "through the one below too",
        rc == 0
        and "share viewer on doc 5 with grp#belong 2  [line 17]" in ways
        and "share viewer on doc 5 with grp#belong 1  [line 17]" in ways,
        said,
    )
    rc, said, ways, _ = why("--as", "user:3", "grp", "2", "belong")
    check(
        "a table that names its rows' type: the row it adds names the person's",
        rc == 0
        and ways[:1]
        == ["add user 3 to cn.group_members for grp 2 (also gives belong on 1 more grp for user:3)  [line 9]"],
        said,
    )
    rc, said, ways, _ = why("--as", "user:3", "doc", "3", "view")
    check(
        "a share that expired: made again, as authz.share makes it, first",
        rc == 0
        and ways[:1] == ["share viewer on doc 3 with user 3 (also gives view on 2 more docs for user:3)  [line 17]"],
        said,
    )
    rc, said, ways, _ = why("--as", "user:4", "doc", "5", "view")
    check(
        "a share the relation's `shared if` refuses (dee isn't active) is no way, as authz.share would refuse it",
        rc == 0
        and ways
        and not any("with user 4" in w for w in ways)
        and any(w.startswith("set owner_id of doc 5 to 4") for w in ways),
        said,
    )
    check(
        "the owner of the doc above gives all an owner holds there, and takes all ann holds there as its owner: "
        "after the doc's own owner, which gives less",
        ways[:2]
        == [
            "set owner_id of doc 5 to 4 (also gives archive, edit, share on it) (takes archive, edit, share on it "
            "from 1 person)  [line 15]",
            "set owner_id of doc 4 to 4 (also gives view, archive, edit, share on 1 more doc for user:4) (takes "
            "archive, edit, share on 1 other doc from 1 person)  [line 15]",
        ],
        said,
    )
    rc, said, _, after = why("--as", "user:3", "doc", "5", "view")
    check(
        "a row the table refuses (a column no change fills): said, with the database's reason; for the doc and the "
        "three above it, and no higher",
        rc == 0
        and [x for x in after if x.startswith("could not be tried")]
        == [
            f"could not be tried: add user 3 to cn.doc_editors for doc {n} (null value in column "
            '"added_by" of relation "doc_editors" violates not-null constraint)'
            for n in (5, 4, 3, 2)
        ],
        said,
    )
    rc, said, ways, _ = why("--as", "user:3", "shelf", "2", "use")
    check(
        "a permission only a row the table refuses would give: no change that could be tried grants it, and why",
        rc == 0
        and said.endswith(
            "use = keeper  (line 45)\n"
            "no single change that could be tried grants it\n"
            'could not be tried: add user 3 to cn.shelf_keepers for shelf 2 (null value in column "since" of '
            'relation "shelf_keepers" violates not-null constraint)\n'
        ),
        said,
    )
    rc, said, ways, _ = why("--as", "bot:1", "doc", "2", "view")
    check(
        "as a service that signs in: why not, as the database explains it to the service, and a share with it",
        rc == 0
        and said.splitlines()[1] == "  no   bot 1 does not hold view on doc 2"
        and ways[:1] == ["share viewer on doc 2 with bot 1 (also gives view on 1 more doc for bot:1)  [line 17]"],
        said,
    )
    rc, said, ways, after = why("--as", "user:2", "project", "(1,5)", "edit")
    check(
        "a key of two columns: a row of the link table, and the column, each from the key's fields",
        rc == 0
        and "add user 2 to cn.project_members for project (1,5)  [line 33]" in ways
        and any(w.startswith("set lead_id of project (1,5) to 2 (also gives share on it)") for w in ways),
        said,
    )
    check(
        "... a share with the person, and none with the group they are in: `shared if` takes people only",
        "share editor on project (1,5) with user 2  [line 35]" in ways and not any("grp#member" in w for w in ways),
        said,
    )
    check(
        "two ways that each give one other permission: the one that takes nothing from anyone first (group 3: "
        "belonging to it; lead: share on the project, which ann, its lead, loses)",
        ways[3:]
        == [
            "add user 2 to cn.group_members for grp 3 (also gives belong on 1 more grp for user:2)  [line 9]",
            "set lead_id of project (1,5) to 2 (also gives share on it) (takes share on it from 1 person)  [line 32]",
        ],
        said,
    )
    check(
        "a group inside a group is said by the group's own row: no row of cn.groups to add for bo's group 2 (it is "
        "there), and nothing that couldn't be tried",
        after == [],
        said,
    )
    rc, said, ways, after = why("--as", "user:3", "club", "1", "enter")
    check(
        "... nor a row of cn.users for cy, whose own row names her club: the note says changing it would move her",
        rc == 0
        and said.endswith(
            "no single change to shares or links grants it\n"
            "note: club.member wasn't tried: user 3's own row of cn.users says it, and changing that row would move "
            "user 3\n"
        ),
        said,
    )
    rc, said, ways, after = why("--as", "user:3", "page", "2", "read")
    check(
        "a deny above it, on a page shared with every user: no change grants it, and the note says what may stop it",
        rc == 0
        and said.endswith(
            "no single change to shares or links grants it\n"
            "note: a deny on page 2 (not ...) may be what stops it: no share or link removes it\n"
        ),
        said,
    )
    rc, said, ways, after = why("--as", "user:1", "doc", "6", "archive")
    check(
        "a condition: no change grants it, and the note names it",
        rc == 0
        and said.endswith(
            "no single change to shares or links grants it\n"
            "note: doc 6 must not meet {archived}: no share or link changes that\n"
        ),
        said,
    )
    # a `shared if` that reads who shares: judged as authz.share judges it, as someone who may share the room (ann)
    rc, said, ways, _ = why("--as", "user:2", "room", "1", "enter")
    made = psql(
        db,
        "BEGIN; SELECT authz.act_as('user', '1'); SELECT authz.share('room', '1', 'guest', 'user', '2'); "
        "SELECT authz.act_as('user', '2'); SELECT authz.can('room', '1', 'enter'); ROLLBACK",
    )
    check(
        "a `shared if` that reads who shares is judged as one who may share (ann): the share is offered, as "
        "authz.share run as ann makes it and it grants",
        rc == 0 and ways[:1] == ["share guest on room 1 with user 2  [line 54]"] and made.splitlines()[-1] == "t",
        (said, made),
    )
    check(
        "a share that a deny reads: what it takes from the others in the team (eve, a host, can no longer speak)",
        "share guest on room 1 with team#member 7 (takes speak on it from 1 person)  [line 54]" in ways,
        said,
    )
    check(
        "a column that changes hands: all the owner it replaces loses on it",
        "set owner_id of room 1 to 2 (also gives present, share, speak on it) (takes enter, share, speak on it from 1 "
        "person)  [line 51]" in ways,
        said,
    )
    # a column naming org 1's admins: moving the desk to org 2 replaces them (ann), not every row of cn.org_members
    # (eve's, a member's, whose sit and chair a condition gives: not the people the change unlinks)
    rc, said, ways, _ = why("--as", "user:2", "desk", "1", "keep")
    check(
        "a column naming a group a where narrows: what it takes from others is from the group's people only",
        rc == 0
        and "set org_id of desk 1 to 2 (also gives sit on it, and rest, use on 2 more chairs for user:2) (takes keep, "
        "sit on it from 1 person, and rest, use on 2 other chairs from 1 person)  [line 73]"
        in ways,
        said,
    )
    rc, said, ways, _ = why("--as", "user:2", "chair", "1", "rest")
    check(
        "what a way takes from others on other objects: the type asked about first, then the policy's order",
        rc == 0
        and "set org_id of desk 1 to 2 (also gives use on it, and rest, use on 1 more chair, and keep, sit on 1 more desk "
        "for user:2) (takes rest, use on it from 1 person, and rest, use on 1 other chair from 1 person, and keep, sit "
        "on 1 other desk from 1 person)  [line 73]"
        in ways,
        said,
    )
    rc, said, ways, _ = why("--as", "user:2", "room", "2", "enter")
    check(
        "two ways that each give one other permission: the one that gives this one to fewer people first",
        rc == 0
        and ways[:2]
        == [
            "share host on room 2 with user 2 (also gives speak on it)  [line 53]",
            "share host on room 2 with team#member 7 (also gives speak on it, and enter on it to 1 more person)  "
            "[line 53]",
        ],
        said,
    )
    # a change that changes nothing (a column holding what it would set, a link's row that is there) is no way, alone
    # or beside another: not tried, and not refused
    rc, said, ways, after = why("--as", "user:1", "room", "1", "present")
    check(
        "the owner who needs the mic: the mic alone, not the owner she is already beside it",
        rc == 0 and ways == ["add user 1 to cn.room_mics for room 1  [line 52]"] and after == [],
        said,
    )
    rc, said, ways, after = why("--as", "user:2", "room", "1", "present")
    check(
        "the mic's holder who needs the room: the owner alone, and no row of cn.room_mics he has already (refused as "
        "a duplicate)",
        rc == 0
        and ways
        == [
            "set owner_id of room 1 to 2 (also gives enter, share, speak on it) (takes enter, share, speak on it "
            "from 1 person)  [line 51]"
        ]
        and after == [],
        said,
    )
    # tables and columns named in capitals: a row added, and a row there whose column the link's where reads changed
    rc, said, ways, after = why("--as", "user:1", "stage", "1", "perform")
    check(
        "a link table named in capitals: the row it adds, its columns quoted, with the column its where asks",
        rc == 0
        and ways
        == [
            "add user 1 to cn.StageMic for stage 1, with isOn = true  [line 62]",
            "share star on stage 1 with user 1 (also gives bow, light, tune on it)  [line 63]",
        ]
        and after == [],
        said,
    )
    rc, said, ways, after = why("--as", "user:2", "stage", "1", "perform")
    check(
        "... and the row there (bo's mic, off): its column set, beside the owner; one change before two, though the "
        "share gives more",
        rc == 0
        and ways
        == [
            "share star on stage 1 with user 2 (also gives bow, light, tune on it)  [line 63]",
            "set ownerId of stage 1 to 2 and set isOn = true on user 2's row of cn.StageMic for stage 1 (also gives "
            "share on it) (takes share on it from 1 person)  [line 61, line 62]",
        ]
        and after == [],
        said,
    )
    rc, said, ways, after = why("--as", "user:3", "doc", "7", "view")
    check(
        "groups inside groups: joining one three deep at most (4, 5 and 6, not 7, inside 6), the fewest others first",
        rc == 0
        and ways
        == [
            "share viewer on doc 7 with user 3  [line 17]",
            *(
                f"add user 3 to cn.group_members for grp {g} (also gives belong on {n} more grp{'s' * (n > 1)} for "
                "user:3)  [line 9]"
                for g, n in ((4, 1), (5, 2), (6, 3))
            ),
            "set owner_id of doc 7 to 3 (also gives archive, edit, share on it) (takes view, archive, edit, share on "
            "it from 1 person)  [line 15]",
        ],
        said,
    )
    # what no change makes count: an object or a person that isn't there (as authz.share says of a subject), or a row
    # the type's where leaves out. Said, and nothing tried
    rc, said, ways, _ = why("--as", "user:3", "doc", "999", "view")
    check(
        "an object that isn't there: no, why not, and that there is no such doc; nothing tried",
        rc == 0 and said.endswith("view = edit or viewer or reader or parent.view  (line 21)\nthere is no doc 999\n"),
        said,
    )
    rc, said, ways, _ = why("--as", "user:3", "doc", "five", "view")
    check(
        "an id its key can't hold: no, and there is no such doc",
        rc == 0
        and said
        == "no: user:3 does not hold view on doc five\n  no   user 3 does not hold view on doc five\n"
        "view = edit or viewer or reader or parent.view  (line 21)\nthere is no doc five\n",
        said,
    )
    for who, there_is_no in (("user:999", "user 999"), ("user:abc", "user abc"), ("bot:9", "bot 9")):
        rc, said, ways, _ = why("--as", who, "doc", "5", "view")
        check(
            f"as someone who isn't there ({who}): there is no {there_is_no}; nothing tried",
            rc == 0 and said.endswith(f"(line 21)\nthere is no {there_is_no}\n"),
            said,
        )
    rc, said, ways, _ = why("--as", "user:999", "doc", "999", "view")
    check(
        "... and neither of them there: both said",
        rc == 0 and said.endswith("(line 21)\nthere is no user 999\nthere is no doc 999\n"),
        said,
    )
    for shelf, which in (("1", "a closed shelf"), ("3", "a shelf not known to be open: the where is NULL")):
        rc, said, ways, _ = why("--as", "user:3", "shelf", shelf, "use")
        check(
            f"a row the type's where leaves out ({which}) holds nothing: said, and nothing tried",
            rc == 0
            and said.endswith(
                f"use = keeper  (line 45)\nshelf {shelf} fails the type's where {{not closed}}: no share or link "
                "changes that\n"
            ),
            said,
        )
    # what isn't a permission of the policy (a type it doesn't have, a permission, a relation, one the compiler made
    # for a deny): refused as authz.can and authz.explain refuse it
    for question in (
        ("nothing", "3", "view"),
        ("doc", "5", "fly"),
        ("doc", "5", "editor"),
        ("page", "2", "read__base"),
    ):
        rc, said = cli(db, "why", "--as", "user:3", *question)
        check(
            f"why on {' '.join(question)}: refused in authz.can's words, with its code, exit 1",
            rc == 1
            and said.endswith("HINT: rowstile help AZ707\n")
            and (rc, said) == cli(db, "can", "--as", "user:3", *question),
            said,
        )
    # Studio, where it may write: the changes the database refused to try, said as the command says them
    s = studio.Studio(f"dbname={db}", None, None, writable=True, port=0)
    s.start()
    try:
        status, w = Client(s).call("/api/why?as=user:3&type=shelf&id=2&perm=use")
        check(
            "Studio says what couldn't be tried, with the database's reason, as the command does",
            status == 200
            and w["tried"]
            and w["ways"] == []
            and w.get("untried")
            == [
                {
                    "text": "add user 3 to cn.shelf_keepers for shelf 2",
                    "error": 'null value in column "since" of relation "shelf_keepers" violates not-null constraint',
                    "lines": ["line 44"],
                    "kinds": ["link"],
                }
            ],
            (status, w),
        )
        status, w = Client(s).call("/api/why?as=user:3&type=doc&id=5&perm=view")
        check(
            "... beside the changes that grant it",
            status == 200
            and w["ways"]
            and [(u["text"], u["error"]) for u in w.get("untried", [])]
            == [
                (
                    f"add user 3 to cn.doc_editors for doc {n}",
                    'null value in column "added_by" of relation "doc_editors" violates not-null constraint',
                )
                for n in (5, 4, 3, 2)
            ],
            (status, w),
        )
        status, w = Client(s).call("/api/why?as=user:2&type=room&id=1&perm=enter")
        check(
            "Studio says what a change takes from others, as the command does",
            status == 200
            and [x["takes"] for x in w["ways"] if x["text"] == "share guest on room 1 with team#member 7"]
            == [[{"type": "room", "perm": "speak", "n": 0, "people": 1}]],
            (status, w),
        )
        status, w = Client(s).call("/api/why?as=user:4&type=doc&id=5&perm=view")
        check(
            "... on the object asked about, and on others",
            status == 200
            and [x["takes"] for x in w["ways"][1:2]]
            == [[{"type": "doc", "perm": p, "n": 1, "people": 1} for p in ("share", "edit", "archive")]],
            (status, w),
        )
        status, w = Client(s).call("/api/why?as=user:3&type=doc&id=999&perm=view")
        check(
            "Studio says there is no such doc, as the command does, and tries nothing",
            status == 200 and w.get("stops") == ["there is no doc 999"] and w["ways"] == [] and w["untried"] == [],
            (status, w),
        )
    finally:
        s.stop()
    # read-only, the same answer, the changes listed and none tried
    s = studio.Studio(f"dbname={db}", None, None, port=0)
    s.start()
    try:
        status, w = Client(s).call("/api/why?as=user:3&type=doc&id=999&perm=view")
        check(
            "... and where it may not write, lists no change for it either",
            status == 200 and not w["tried"] and w.get("stops") == ["there is no doc 999"] and w["ways"] == [],
            (status, w),
        )
        status, w = Client(s).call("/api/why?as=bot:1&type=doc&id=2&perm=view")
        check(
            "... and as a service that signs in, why not as the database explains it to the service",
            status == 200 and not w["tried"] and w["explain"][:1] == ["no   bot 1 does not hold view on doc 2"],
            (status, w),
        )
        status, w = Client(s).call("/api/why?as=user:3&type=doc&id=5&perm=view")
        check(
            "... the changes that might grant it, the five that change least, as the command shows five",
            status == 200
            and not w["tried"]
            and len(w["ways"]) == 5
            and w["ways"][0]["text"] == "share viewer on doc 5 with user 3",
            (status, w),
        )
        status, w = Client(s).call("/api/why?as=user:1&type=doc&id=6&perm=archive")
        check(
            "... and what no change to the data would do, said beside them (nothing tried, nothing is known to grant)",
            status == 200 and w["notes"] == ["doc 6 must not meet {archived}: no share or link changes that"],
            (status, w),
        )
        check("... and no change that changes nothing (ann owns doc 6 already)", w["ways"] == [], w)
        status, w = Client(s).call("/api/why?as=user:5&type=room&id=3&perm=speak")
        check(
            "... nor a share there already (eve hosts room 3): only what would change something is listed",
            status == 200
            and [x["text"] for x in w["ways"]]
            == ["share host on room 3 with team#member 7", "set owner_id of room 3 to 5"],
            (status, w),
        )
        # a `shared if` why can't judge, or that no one who may share passes: said
        status, w = Client(s).call("/api/why?as=user:2&type=room&id=2&perm=enter")
        check(
            "a `shared if` on an object nobody may share: not offered, and said",
            status == 200
            and "room.guest wasn't tried with user 2: nobody may share room 2, and its shared if "
            "{subject_id <> authz.uid()::text} is judged as the one who shares"
            in w["notes"]
            and not any("guest" in x["text"] for x in w["ways"]),
            (status, w),
        )
        status, w = Client(s).call("/api/why?as=user:4&type=doc&id=5&perm=view")
        check(
            "a `shared if` no one who may share passes (dee isn't active): not offered, and said",
            status == 200
            and "doc.viewer wasn't tried with user 4: its shared if {subject_type <> 'user' or subject_id in (select "
            "id::text from cn.users where active)} refuses it to everyone who may share doc 5"
            in w["notes"]
            and not any("viewer" in x["text"] for x in w["ways"]),
            (status, w),
        )
    finally:
        s.stop()
    check("... and nothing it tried stays", psql(db, data) == before, (before, psql(db, data)))
    subprocess.run(["dropdb", "--if-exists", db], capture_output=True)

    # a condition this session can't read: its function is on the search path the policy was applied with, not on
    # this one. Why goes on with the changes, as where nothing stops it
    other = db + "_path"
    subprocess.run(["dropdb", "--if-exists", other], capture_output=True)
    subprocess.run(["createdb", other], check=True)
    psql(
        other,
        "CREATE SCHEMA px; CREATE SCHEMA fx; "
        "CREATE FUNCTION fx.open_now(c boolean) RETURNS boolean LANGUAGE sql IMMUTABLE AS 'SELECT NOT c'; "
        "CREATE TABLE px.users (id bigint PRIMARY KEY); "
        "CREATE TABLE px.shelves (id bigint PRIMARY KEY, closed boolean NOT NULL, keeper_id bigint REFERENCES px.users); "
        "INSERT INTO px.users VALUES (1), (2); INSERT INTO px.shelves VALUES (1, true, 1); "
        "GRANT USAGE ON SCHEMA px, fx TO app_user; GRANT SELECT ON ALL TABLES IN SCHEMA px TO app_user",
    )
    on_path = f"dbname={other} options='-c search_path=fx,public'"
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "path.authz")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(
                "app role app_user\n\ntype user = px.users\n\n"
                "type shelf = px.shelves where {open_now(closed)}\n  keeper : user = keeper_id\n  can use = keeper\n"
            )
        rc, out = command(on_path, "apply", path)
    if rc:
        raise SystemExit(out)
    rc, said = cli(other, "why", "--as", "user:2", "shelf", "1", "use")
    check(
        "a type's where this session can't read (its function is on the path the policy was applied with): no stop "
        "said, and the changes tried",
        rc == 0 and said.endswith("use = keeper  (line 7)\nno single change to shares or links grants it\n"),
        said,
    )
    rc, said = command(on_path, "why", "--as", "user:2", "shelf", "1", "use")
    check(
        "... and on that path, the stop",
        rc == 0 and said.endswith("shelf 1 fails the type's where {open_now(closed)}: no share or link changes that\n"),
        said,
    )
    subprocess.run(["dropdb", "--if-exists", other], capture_output=True)


if __name__ == "__main__":
    main()
