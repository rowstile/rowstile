#!/usr/bin/env python3
"""interrupt: the command and a migration cut half way, after each statement.

`rowstile apply` (on a database with no policy, and over one), `rowstile push`, `rowstile reapply --force` and a
migration that builds an inheritance table beside the one in use (both of its two) are each run on the docs app and
cut after statement N: the server ends the session (pg_terminate_backend, from a session of the test's own, on the
process the run started, found in its own database), or the connection is closed under it without a word. The
command runs in this process, its connection sending the statements one at a time (the compiled policy too, which
the command sends in one message), so that the cut falls between the same two statements each time; a migration
is sent as `psql -1 -f` sends it. After each cut:

- the command says it lost the database (exit 2), never a traceback;
- the database is as it was before the run: what tests/migrate_test.py compares a migration with applying whole by
  (functions, views, triggers, row-level security policies, rowstile's tables and their rows), and the columns and
  rows of the tables in schema authz;
- the app, as the app role and signed in, read the old policy's answers just before the cut (from a session of its
  own; a read that waits for the run's locks is let through by the cut) and after it: whole, never a mix;
- after some cuts, the next run finishes: it leaves what the uncut run left, authz.verify() is true, and the app
  reads the new policy's answers.

Between a migration's two, the database is as the docs say: the old policy in force, its inheritance tables
exact, the lock the first recorded; while the first runs, the app's reads never wait. A cut in the second, the app's
writes, then the second again: what applying the new policy whole after the same writes leaves.

Then the cuts the command doesn't make: the command itself (its compiled policy in one message), ended by the
server while a statement of it waits for a lock another session holds, or stopped by statement_timeout there.

    PGHOST=... PGUSER=... python3 tests/interrupt.py            # a sample of the cuts (each push)
    PGHOST=... PGUSER=... python3 tests/interrupt.py --every    # after every statement (nightly)
    PGHOST=... PGUSER=... python3 tests/interrupt.py --others --seed N
        # other policies' first apply, cut at statements the seed draws (the soak): the random-change runs' fixed
        # policies, and random ones (genpolicy's, from seed N * 1000)
"""

from __future__ import annotations

import argparse
import contextlib
import io
import os
import random
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import traceback
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass, field
from typing import NamedTuple
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "cli"))
import pgwire  # noqa: E402
import rowstile_cli  # noqa: E402
from authzlib import database, migrate, statements  # noqa: E402
from migrate_test import CHANGES, ROWS, SNAPSHOT, compare, edit, psql, sh, snapshot  # noqa: E402

DB = "authz_interrupt"
TEMPLATE = DB + "_from"  # the database as the run finds it, which DB is made again from
WHOLE = DB + "_whole"


def read(rel: str) -> str:
    with open(os.path.join(ROOT, rel), encoding="utf-8") as fh:
        return fh.read()


OLD = read("example/docs.authz")
# the new policy answers otherwise on the docs app: a folder that breaks inheritance passes view on all the same
# (the inheritance table view follows is built again: beside the one in use, when it is a migration)
NEW = edit(
    OLD, ("can view  = edit or viewer or (parent.view and {inherit})", "can view  = edit or viewer or parent.view")
)
SCHEMA = read("example/app_schema.sql")
# a move made with the triggers off: the inheritance tables are stale, and reapply --force builds them again
STALE = (
    "ALTER TABLE app.folders DISABLE TRIGGER USER; UPDATE app.folders SET parent_id = 3 WHERE id = 6; "
    "ALTER TABLE app.folders ENABLE TRIGGER USER;"
)
# what the command says when it loses its session, last, after any warnings it printed before: exit 2, never a
# traceback; then why, in the server's words when the server ended the session (read after a send that failed too,
# as libpq reads them), else that the connection closed
LOST = re.compile(r"(?:.*\n)?lost the database: ([^\n]+)\n", re.S)
WHY = {
    "terminate": "terminating connection due to administrator command",
    "close": "the server closed the connection",
}
# the tables kept across applies (schema authz): their columns and their rows, besides what migrate_test compares
KEPT = r"""
SELECT 'column ' || c.oid::regclass::text || ' ' || string_agg(a.attname || ' ' || format_type(a.atttypid, a.atttypmod),
       ', ' ORDER BY a.attnum)
FROM pg_class c JOIN pg_attribute a ON a.attrelid = c.oid
WHERE c.relnamespace = to_regnamespace('authz') AND c.relkind IN ('r', 'p') AND a.attnum > 0 AND NOT a.attisdropped
GROUP BY c.oid
ORDER BY 1;
"""
# (as JSON: a stored policy's lines would read as objects' first lines), without the columns $1 names
KEPT_ROWS = r"""
SELECT format('SELECT %L || E''\n'' || coalesce(string_agg(x, E''\n'' ORDER BY x), '''') FROM (SELECT (to_jsonb(t) - %L::text[])::text AS x FROM %s t) s',
              'rows ' || c.oid::regclass::text, $1::text, c.oid::regclass)
FROM pg_class c WHERE c.relnamespace = to_regnamespace('authz') AND c.relkind IN ('r', 'p')
ORDER BY 1
"""
# what two runs of the same thing write differently: when, the ids sequences give; a snapshot's transaction ids,
# the key sessions are signed with (drawn when the first apply makes it)
VOLATILE = "{id,at}"
SESSION_KEY = (re.compile(r'("session_key", "value": )"\w+"'), r"\1(a key)")
# a tree built beside: (name, hash, the snapshot it was built from, the change feed's position)
NEXT_TREE = (re.compile(r"(?m)^\(([^,]+),([0-9a-f]+),.*,(-?\d+)\)$"), r"(\1,\2,(a snapshot),\3)")
# what the app reads as each user, and as someone not signed in: the folders and files they see
USERS: list[str | None] = ["1", "2", "3", "4", "5", "6", "7", None]
SEES = (
    "SELECT (SELECT coalesce(string_agg(id::text, ',' ORDER BY id), '-') FROM app.folders) || ' / ' || "
    "(SELECT coalesce(string_agg(id::text, ',' ORDER BY id), '-') FROM app.files)"
)

failures = 0


def ok(label: str) -> None:
    print(f"ok    {label}", flush=True)


def bad(label: str, why: str) -> None:
    global failures
    failures += 1
    print(f"FAIL  {label}: {why}", flush=True)


def report(checks: list[tuple[str, list[str]]]) -> None:
    for label, problems in checks:
        if problems:
            bad(label, f"{len(problems)} cuts:\n  " + "\n  ".join(problems[:4]))
        else:
            ok(label)


def dsn(db: str) -> str:
    return f"dbname={db}"


CONNECTION = pgwire.Connection


def connect(db: str) -> pgwire.Connection:
    """A connection of the test's own (never cut)."""
    conn = pgwire.connect(**pgwire.parse_dsn(dsn(db)))
    assert type(conn) is CONNECTION, "a connection of the test's own is made while a run's are cut"
    return conn


# --- cutting a run after statement N ----------------------------------------------------------------
@dataclass
class Plan:
    """Where to cut a run: after its statement `at` (0: as soon as it has signed in; None: never), and how: the
    server ends the session ('terminate'), or the connection is closed under it ('close')."""

    at: int | None = None
    how: str = "terminate"
    cut: Callable[[pgwire.Connection, Plan], None] | None = None
    sent: list[str] = field(default_factory=list)  # each statement sent, named
    done: bool = False


PLAN = Plan()


def named(sql: str, comments: str = "") -> str:
    """A statement as a person finds it: the object it makes, else its first words."""
    try:
        made = statements.made(sql, comments)
    except ValueError:
        made = None
    return f"{made[0]} {made[1]}" if made else " ".join(sql.split())[:80]


class Cutting(pgwire.Connection):
    """A connection that sends one statement at a time, and cuts as PLAN says."""

    def _cut_if(self, sent: int) -> None:
        if PLAN.at == sent and not PLAN.done and PLAN.cut:
            PLAN.done = True
            PLAN.cut(self, PLAN)

    def _send_one(self, name: str, send: Callable[[], None]) -> None:
        self._cut_if(0)  # as soon as it signed in: before its first statement
        try:
            send()
        finally:
            PLAN.sent.append(name)
            self._cut_if(len(PLAN.sent))

    def query_described(
        self, sql: str, args: Sequence[object] = (), text: bool = False
    ) -> tuple[list[tuple[pgwire.Value, ...]], list[str]]:
        got: list[tuple[list[tuple[pgwire.Value, ...]], list[str]]] = []
        self._send_one(named(sql), lambda: got.append(super(Cutting, self).query_described(sql, args, text)))
        return got[0]

    def script(self, sql: str) -> None:
        for comments, st in statements.split(sql):
            self._send_one(named(st, comments), lambda st=st: super(Cutting, self).script(st))


@contextlib.contextmanager
def cutting(plan: Plan) -> Iterator[None]:
    """The connections made inside are Cutting ones, following plan."""
    global PLAN
    PLAN = plan
    try:
        with mock.patch.object(pgwire, "Connection", Cutting):  # connect() makes one by its name in the module
            yield
    finally:
        PLAN = Plan()


class Outcome(NamedTuple):
    code: int
    out: str
    err: str


def command(argv: list[str], plan: Plan) -> Outcome:
    """The rowstile command, run here (its connection Cutting): exit code, what it printed. A traceback is 99."""
    out, err = io.StringIO(), io.StringIO()
    code = 0
    with cutting(plan), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            rowstile_cli.main(argv)
        except SystemExit as e:
            code = e.code if isinstance(e.code, int) else 1
        except BaseException:  # what a person would see as a traceback
            code = 99
            err.write(traceback.format_exc())
    return Outcome(code, out.getvalue(), err.getvalue())


def migration(db: str, sql: str, plan: Plan) -> Outcome:
    """A migration's file, as `psql -1 -v ON_ERROR_STOP=1 -f` runs it: BEGIN, each statement, COMMIT."""
    with cutting(plan):
        try:
            conn = pgwire.connect(**pgwire.parse_dsn(dsn(db)))
        except (pgwire.PgError, pgwire.ProtocolError, OSError) as e:
            return Outcome(2, "", str(e))
        try:
            conn.execute("BEGIN")
            conn.script("SET client_min_messages = error;\n" + sql)
            conn.execute("COMMIT")
        except (pgwire.PgError, pgwire.ProtocolError, OSError) as e:
            return Outcome(2, "", str(e))
        finally:
            conn.close()
    return Outcome(0, "", "")


# --- what is compared -----------------------------------------------------------------------------
LOOKS: dict[str, pgwire.Connection] = {}


def look(db: str) -> pgwire.Connection:
    """A session of the test's own in db, as its owner: kept until the database is made again."""
    if db not in LOOKS:
        LOOKS[db] = connect(db)
    return LOOKS[db]


def forget(*dbs: str) -> None:
    for db in dbs:
        if db in LOOKS:
            LOOKS.pop(db).close()


def lines(conn: pgwire.Connection, sql: str, args: Sequence[object] = ()) -> list[str]:
    """Each row's first value, as psql -At prints it."""
    return ["" if r[0] is None else str(r[0]) for r in conn.query(sql, args)]


def state(db: str, alike: bool = False) -> str:
    """What migrate_test compares (its queries, here over a session of the test's own), and the tables in schema
    authz: their columns and their rows. alike: without what two runs of the same thing write differently."""
    conn = look(db)
    out = lines(conn, SNAPSHOT)
    for sql in [*lines(conn, ROWS), *lines(conn, KEPT_ROWS, [VOLATILE if alike else "{}"])]:
        for rows in lines(conn, sql):
            if alike and rows.startswith("rows authz_int.next_trees\n"):
                rows = NEXT_TREE[0].sub(NEXT_TREE[1], rows)
            out.append(SESSION_KEY[0].sub(SESSION_KEY[1], rows) if alike else rows)
    return "\n".join([*out, *lines(conn, KEPT)])


def differences(was: str, now: str) -> str:
    # (in migrate_test's words, "migrated" is this database now, "whole" what it was)
    return "\n".join(
        x.replace("only after applying whole", "gone").replace("only after migrating", "new")
        for x in compare(now, was)[:8]
    )


def reads(conn: pgwire.Connection) -> str:
    """What the app reads, as the app role, signed in as each user in turn: one transaction."""
    out: list[str] = []
    try:
        conn.execute("BEGIN")
        conn.execute("SET LOCAL ROLE app_user")
        for u in USERS:
            conn.query("SELECT authz.act_as($1, $2)", [None if u is None else "user", u])
            out.append(f"{u or 'nobody'}: {conn.query(SEES)[0][0]}")
        conn.execute("COMMIT")
    except pgwire.PgError as e:
        with contextlib.suppress(pgwire.PgError):
            conn.execute("ROLLBACK")
        return f"error: {e.message}"
    return "; ".join(out)


def verify(db: str) -> bool:
    return look(db).query("SELECT authz.verify()") == [(True,)]


def recreate(db: str, template: str | None = None) -> None:
    forget(db, *([template] if template else []))
    sh("dropdb", "--if-exists", db)
    sh("createdb", *(["--template", template] if template else []), db)


# --- one case, cut after each statement (or a sample) -------------------------------------------------
@dataclass
class Case:
    name: str
    setup: Callable[[str], None]  # the database as the run finds it
    run: Callable[[str, Plan], Outcome]
    command: bool = True  # the rowstile command (else a migration run as psql runs it): what it says is checked
    reads: bool = True  # the app's reads are asked (the docs app's users)
    waits: bool = True  # the app's reads may wait for the run's locks


@dataclass
class Result:
    """A case's uncut run: its statements, the state and the app's reads before and after it."""

    sent: list[str]
    before: str
    after: str
    read_before: str
    read_after: str


class Lab:
    """The runs, on DB made again from TEMPLATE for each case, with a session of the test's own (on postgres) that
    ends the run's sessions, and the app's session in DB."""

    def __init__(self) -> None:
        self.control = connect("postgres")
        self.app: pgwire.Connection | None = None
        self.during, self.waited = "", False  # what the app read just before the last cut, and if it waited

    def close(self) -> None:
        if self.app:
            self.app.close()
            self.app = None

    def reset(self, case: Case) -> None:
        self.close()
        recreate(DB, TEMPLATE)
        self.app = connect(DB) if case.reads else None

    def app_reads(self) -> str:
        return reads(self.app) if self.app else ""

    def gone(self, pid: int, wait: float = 10) -> bool:
        """Whether the session pid of DB has ended (waiting for it up to wait seconds)."""
        end = time.monotonic() + wait
        while time.monotonic() < end:
            if not self.control.query("SELECT 1 FROM pg_stat_activity WHERE pid = $1 AND datname = $2", [pid, DB]):
                return True
            time.sleep(0.005)
        return False

    def terminate(self, pid: int) -> None:
        """The server ends a session of the run's: its process, found by its own database's name."""
        rows = self.control.query(
            "SELECT pg_terminate_backend(pid, 10000) FROM pg_stat_activity WHERE pid = $1 AND datname = $2", [pid, DB]
        )
        assert rows == [(True,)], f"the run's session {pid} in {DB}: {rows}"

    def end(self, conn: pgwire.Connection, how: str) -> None:
        """Ends the run's session, the server's way or by closing its connection; waits until the server let it go."""
        assert conn.backend is not None
        pid = conn.backend[0]
        if how == "close":
            conn.sock.shutdown(socket.SHUT_RDWR)
        else:
            self.terminate(pid)
        assert self.gone(pid), f"the run's session {pid} in {DB} is still there"

    def cut(self, read: bool) -> Callable[[pgwire.Connection, Plan], None]:
        """A plan's cut: the app reads (from its own session; a read that waits for the run's locks is let
        through by the cut), and the run's session is ended."""

        def cut(conn: pgwire.Connection, plan: Plan) -> None:
            self.during, self.waited = "", False
            app = self.app
            if not read or app is None:
                self.end(conn, plan.how)
                return
            answer: list[str] = []
            reader = threading.Thread(target=lambda: answer.append(reads(app)))
            reader.start()
            assert app.backend is not None
            limit = time.monotonic() + 30
            while reader.is_alive() and time.monotonic() < limit:
                if self.control.query(
                    "SELECT 1 FROM pg_stat_activity WHERE pid = $1 AND datname = $2 AND wait_event_type = 'Lock'",
                    [app.backend[0], DB],
                ):
                    self.waited = True
                    break
                time.sleep(0.002)
            self.end(conn, plan.how)
            reader.join(30)
            self.during = answer[0] if answer else "(no answer)"

        return cut

    def first(self, case: Case, quiet: bool = False) -> Result | None:
        """The case's start (TEMPLATE), and its run uncut: what it sends, the state and reads before and after."""
        self.close()
        recreate(TEMPLATE)
        case.setup(TEMPLATE)
        before = state(TEMPLATE)
        self.reset(case)
        read_before = self.app_reads()
        plan = Plan()
        got = case.run(DB, plan)
        if got.code != 0:
            if not quiet:
                bad(f"{case.name}: the uncut run", f"exit {got.code}\n{got.out}{got.err}")
            return None
        return Result(plan.sent, before, state(DB, alike=True), read_before, self.app_reads())

    def cuts(
        self, case: Case, r: Result, at: list[int], again: set[int], closed: set[int]
    ) -> list[tuple[str, list[str]]]:
        """Cuts the case's run after each statement in `at` (by closing the connection at those in `closed`);
        after those in `again`, runs it again whole. The checks, each with what broke it."""
        problems: dict[str, list[str]] = {"said": [], "state": [], "reads": [], "again": []}
        total = len(r.sent)

        def problem(kind: str, n: int, why: str) -> None:
            where = "as soon as it signed in" if n == 0 else r.sent[n - 1]
            problems[kind].append(f"cut after statement {n} of {total} ({where}): {why}")

        started, waited, dirty = time.monotonic(), 0, True
        words: set[str] = set()  # what the command said after "lost the database: "
        for n in at:
            if dirty:
                self.reset(case)
            dirty = False
            plan = Plan(at=n, how="close" if n in closed else "terminate", cut=self.cut(case.reads))
            got = case.run(DB, plan)
            lost = LOST.fullmatch(got.err) if "Traceback" not in got.err else None
            if case.command and (got.code != 2 or not lost or got.out or lost.group(1) != WHY[plan.how]):
                problem("said", n, f"{plan.how}: exit {got.code}, {(got.out + got.err).strip()[-1500:]!r}")
            elif lost:
                words.add(lost.group(1))
            if not plan.done or plan.sent[:n] != r.sent[:n]:
                problem("said", n, "the run sent other statements than the uncut run did")
            now = state(DB)
            if now != r.before:
                problem("state", n, "the database is not as it was:\n" + differences(r.before, now))
                dirty = True
            if case.reads:
                waited += self.waited
                for when, answer in (("just before the cut", self.during), ("after it", self.app_reads())):
                    if answer != r.read_before:
                        problem("reads", n, f"{when} the app read {kind_of(answer, r)}: {answer}")
                if self.waited and not case.waits:
                    problem("reads", n, "the app's read waited for the run's locks")
            if n in again:
                dirty = True
                got = case.run(DB, Plan())
                now = state(DB, alike=True) if got.code == 0 else ""
                if got.code != 0:
                    problem("again", n, f"the next run: exit {got.code}, {(got.out + got.err).strip()[-1500:]}")
                elif now != r.after:
                    problem("again", n, "the next run leaves another state:\n" + differences(r.after, now))
                elif not verify(DB):
                    problem("again", n, "after the next run, authz.verify() is false")
                elif case.reads and (answer := self.app_reads()) != r.read_after:
                    problem("again", n, f"after the next run the app reads {kind_of(answer, r)}: {answer}")
        took = time.monotonic() - started
        if words:
            print(f"      {case.name}: lost the database: {' | '.join(sorted(words))}")
        cuts = (
            f"after each of its {total} statements" if len(at) == total else f"at {len(at)} of its {total} statements"
        )
        how = f" ({len(closed)} by closing the connection)" if closed else ""
        checks = [
            (
                f"{case.name}: cut {cuts}{how}"
                + (", it says it lost the database and why (the server's words), exit 2" if case.command else "")
                + f" ({took:.0f}s)",
                problems["said"],
            ),
            (f"{case.name}: after each cut, the database is as it was", problems["state"]),
        ]
        if case.reads:
            read_how = "never waiting for the run" if not case.waits else f"{waited} of them let through by the cut"
            checks.append(
                (
                    f"{case.name}: the app read the old policy's answers, whole, before each cut ({read_how}) "
                    "and after it",
                    problems["reads"],
                )
            )
        checks.append(
            (
                f"{case.name}: after {len(again)} of the cuts, the next run finishes: what the uncut run leaves, "
                "authz.verify() true" + (", the new policy's answers" if case.reads else ""),
                problems["again"],
            )
        )
        return checks


def kind_of(answer: str, r: Result) -> str:
    if answer == r.read_before:
        return "the old policy's answers"
    if answer == r.read_after:
        return "the new policy's answers"
    return "neither policy's answers whole"


def sample(total: int, n: int, rng: random.Random) -> list[int]:
    """Cut points for a sample: as soon as it signs in, after the first two, before the last two (the end of its
    transaction), and n drawn between."""
    middle = rng.sample(range(3, total - 2), min(n, max(0, total - 5))) if total > 5 else []
    return sorted({x for x in {0, 1, 2, total - 2, total - 1, *middle} if 0 <= x < total})


# --- the docs app ----------------------------------------------------------------------------------
class Files:
    """The policies, as files the command reads."""

    def __init__(self) -> None:
        self.dir = tempfile.mkdtemp(prefix="authz_interrupt_")
        self.old = self.write("old.authz", OLD)
        self.new = self.write("new.authz", NEW)

    def write(self, name: str, text: str) -> str:
        path = os.path.join(self.dir, name)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
        return path


def run_cli(*argv: str) -> Callable[[str, Plan], Outcome]:
    return lambda db, plan: command(["--db", dsn(db), *argv], plan)


def run_sql(sql: str) -> Callable[[str, Plan], Outcome]:
    return lambda db, plan: migration(db, sql, plan)


def setup(*argv: str, then: str = "", schema: str = SCHEMA) -> Callable[[str], None]:
    """The app's schema, then the command with argv (if any), then the SQL `then`."""

    def make(db: str) -> None:
        psql(db, "SET client_min_messages = error;\n" + schema)
        if argv:
            got = command(["--db", dsn(db), *argv], Plan())
            assert got.code == 0, f"setting up: rowstile {' '.join(argv)}: {got.out}{got.err}"
        if then:
            psql(db, then)

    return make


@dataclass
class Docs:
    files: Files
    ms: list[migrate.Migration]
    cases: list[Case]


def docs_cases() -> Docs:
    f = Files()
    lock = migrate.lock_of(database.migratable(OLD, {})[1])
    ms = database.migrations(NEW, {}, lock, "interrupt")
    assert len(ms) == 2, "the docs app's change builds a tree beside the one in use: two migrations"

    def between(db: str) -> None:
        setup("apply", f.old)(db)
        got = migration(db, ms[0].sql, Plan())
        assert got.code == 0, f"setting up: the migration's first: {got.err}"

    cases = [
        Case("the first apply", setup(), run_cli("apply", f.old)),
        Case("apply", setup("apply", f.old), run_cli("apply", f.new)),
        Case("push", setup("push", f.old), run_cli("push", f.new)),
        Case("reapply --force", setup("apply", f.old, then=STALE), run_cli("reapply", "--force")),
        Case("a migration's first (builds beside)", setup("apply", f.old), run_sql(ms[0].sql), False, waits=False),
        Case("a migration's second (swaps in)", between, run_sql(ms[1].sql), False),
    ]
    return Docs(f, ms, cases)


def docs(lab: Lab, d: Docs, every: bool, rng: random.Random) -> None:
    done: dict[str, Result] = {}
    for case in d.cases:
        r = lab.first(case)
        if r is None:
            continue
        done[case.name] = r
        total = len(r.sent)
        if every:
            at = list(range(total))
            again = {n for n in at if n % 40 == 20} | {total - 1}  # the next run: after every 40th, and the last
            closed = {n for n in at if n % 7 == 3}  # the connection closed under it without a word: one in seven
        else:
            at = sample(total, 5, rng)
            again, closed = {at[len(at) // 2], total - 1}, {at[2]}
        if case.name == "reapply --force" and verify(TEMPLATE):
            bad("reapply --force: before", "the inheritance tables are not stale: reapply --force builds nothing")
        report(lab.cuts(case, r, at, again, closed))
        if case.name.startswith("a migration's second") and "apply" in done:
            between(lab, case, d, r, done["apply"].read_before)
            after_writes(lab, case, d)


def between(lab: Lab, case: Case, d: Docs, r: Result, old: str) -> None:
    """Between a migration's two, as docs/reference/migrations.md says (old: what the app reads under the old
    policy applied whole)."""
    lab.reset(case)
    lock = lines(look(DB), "SELECT lock FROM authz.policy_versions ORDER BY id DESC LIMIT 1")[0]
    answers, exact = lab.app_reads(), verify(DB)
    label = (
        "between a migration's two: the old policy in force (the app reads its answers), its inheritance tables "
        "exact, the lock the first recorded"
    )
    if answers == old and exact and lock == migrate.digest(d.ms[0].lock, 16):
        ok(label)
    else:
        bad(label, f"authz.verify() {exact}, lock {lock}, the app reads {kind_of(answers, r)}: {answers}")


def after_writes(lab: Lab, case: Case, d: Docs) -> None:
    """A cut in the second, the app's writes, then the second again: what applying whole after them leaves."""
    lab.reset(case)
    plan = Plan(at=len(statements.split(d.ms[1].sql)) // 2, cut=lab.cut(False))
    got = migration(DB, d.ms[1].sql, plan)
    psql(DB, CHANGES["docs"])
    again = migration(DB, d.ms[1].sql, Plan())
    recreate(WHOLE)
    setup("apply", d.files.old, then=CHANGES["docs"])(WHOLE)
    whole = command(["--db", dsn(WHOLE), "apply", d.files.new], Plan())
    diffs = compare(snapshot(DB), snapshot(WHOLE)) if again.code == 0 and whole.code == 0 else ["a run failed"]
    label = (
        "a cut in a migration's second, the app's writes, then the second again: what applying the new policy "
        "whole after the same writes leaves"
    )
    if got.code == 2 and plan.done and not diffs and verify(DB):
        ok(label)
    else:
        bad(label, f"{got}; {again}; {whole}\n" + "\n".join(diffs[:8]))
    sh("dropdb", "--if-exists", WHOLE)


# --- the cuts the command doesn't make ---------------------------------------------------------------
# a session holding a lock a statement of the command waits for: the advisory lock two commands take (before
# anything), the app's tables (inside the compiled policy), the record of applied policies (rowstile's own tables)
BLOCKERS = [
    ("the lock two commands share", "SELECT pg_advisory_xact_lock(1919905638, 0)"),
    ("app.folders", "LOCK TABLE app.folders IN ACCESS SHARE MODE"),
    ("app.files", "LOCK TABLE app.files IN ACCESS SHARE MODE"),
    ("authz.policy_versions", "LOCK TABLE authz.policy_versions IN SHARE MODE"),
]
TIMEOUT = 1500  # ms: statement_timeout, for the command stopped by it while it waits for app.files


def waiting(lab: Lab, blocker: int, wait: float = 30) -> int | None:
    """The process in DB that waits for the blocker's lock."""
    end = time.monotonic() + wait
    while time.monotonic() < end:
        rows = lab.control.query(
            "SELECT pid FROM pg_stat_activity WHERE datname = $1 AND $2 = ANY (pg_blocking_pids(pid))", [DB, blocker]
        )
        if rows:
            return int(str(rows[0][0]))
        time.sleep(0.01)
    return None


ARGV = {
    "the first apply": ["apply", "old.authz"],
    "apply": ["apply", "new.authz"],
    "push": ["push", "new.authz"],
    "reapply --force": ["reapply", "--force"],
}


def stopped(lab: Lab, d: Docs, every: bool) -> None:
    """The command itself, ended by the server while a statement waits for a lock, or by statement_timeout: apply
    (every: each command)."""
    for case in d.cases:
        if not case.command or (not every and case.name != "apply"):
            continue
        argv = [os.path.join(d.files.dir, a) if a.endswith(".authz") else a for a in ARGV[case.name]]
        lab.close()
        recreate(TEMPLATE)
        case.setup(TEMPLATE)
        before = state(TEMPLATE)
        problems: list[str] = []
        words: set[str] = set()
        blockers = [(w, lk) for w, lk in BLOCKERS if case.name != "the first apply" or "authz." not in lk]
        timed = (f"app.files, until statement_timeout ({TIMEOUT} ms)", "LOCK TABLE app.files IN ACCESS SHARE MODE")
        for what, lock in [*blockers, timed]:
            timeout = what == timed[0]
            lab.reset(case)
            blocker = connect(DB)
            blocker.execute("BEGIN")
            blocker.execute(lock)
            assert blocker.backend is not None
            env = dict(os.environ, PGOPTIONS=f"-c statement_timeout={TIMEOUT}") if timeout else None
            p = subprocess.Popen(
                [sys.executable, os.path.join(ROOT, "cli", "rowstile_cli.py"), "--db", dsn(DB), *argv],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=env,
            )
            pid = waiting(lab, blocker.backend[0])
            if pid is None:
                problems.append(f"{what}: the command never waited for it")
            elif not timeout:
                lab.terminate(pid)
            try:
                out, err = p.communicate(timeout=60)
            finally:
                blocker.execute("ROLLBACK")
                blocker.close()
            if timeout:
                held = (p.returncode, err) == (1, "canceling statement due to statement timeout\n")
            else:
                lost = LOST.fullmatch(err) if "Traceback" not in err else None
                held = p.returncode == 2 and lost is not None and lost.group(1) == WHY["terminate"]
                if lost:
                    words.add(f"{lost.group(1)} ({what})")
            if not held or out:
                problems.append(f"{what}: exit {p.returncode}, {(out + err).strip()[-1500:]!r}")
            if (now := state(DB)) != before:
                problems.append(f"{what}: the database is not as it was:\n" + differences(before, now))
        print(f"      {case.name}, the command itself: lost the database: {' | '.join(sorted(words))}")
        label = (
            f"{case.name}, the command itself: ended by the server while a statement waits for a lock (on "
            f"{', '.join(w for w, _ in blockers)}), it says it lost the database in the server's words, exit 2; stopped by "
            "statement_timeout, it says so, exit 1; the database is as it was"
        )
        if problems:
            bad(label, "\n  ".join(problems[:6]))
        else:
            ok(label)


def reviewed(lab: Lab, d: Docs) -> None:
    """rowstile review --db, its session ended by the server as soon as it signed in (before its BEGIN)."""
    repo = tempfile.mkdtemp(prefix="authz_interrupt_review_")
    os.makedirs(os.path.join(repo, "db"))
    shutil.copy(d.files.old, os.path.join(repo, "db", "policy.authz"))
    with open(os.path.join(repo, "rowstile.toml"), "w", encoding="utf-8") as fh:
        fh.write('policy = "db/policy.authz"\n')
    for argv in (
        ["init", "-q"],
        ["add", "-A"],
        ["-c", "user.name=t", "-c", "user.email=t@example.com", "commit", "-qm", "base"],
    ):
        subprocess.run(["git", "-C", repo, *argv], check=True, capture_output=True)
    shutil.copy(d.files.new, os.path.join(repo, "db", "policy.authz"))
    lab.close()
    recreate(DB)
    here = os.getcwd()
    os.chdir(repo)
    try:
        got = command(["--db", dsn(DB), "review", "--base", "HEAD"], Plan(at=0, cut=lab.cut(False)))
    finally:
        os.chdir(here)
        shutil.rmtree(repo, ignore_errors=True)
    label = (
        "rowstile review --db, ended by the server as soon as it signed in: it says it lost the database, why, exit 2"
    )
    if (got.code, got.out, got.err) == (2, "", f"lost the database: {WHY['terminate']}\n"):
        ok(label)
    else:
        bad(label, f"exit {got.code}, {(got.out + got.err).strip()[-1500:]!r}")


# --- other policies (the soak) ------------------------------------------------------------------------
FIXED = ["alt", "multi", "composite", "loop", "cross"]


def others(lab: Lab, seed: int, cuts: int, policies: int) -> None:
    """The first apply of other policies, cut at statements the seed draws: the random-change runs' fixed policies,
    and random ones (genpolicy's, from seed * 1000). One line for them all: their number doesn't change the count."""
    import genpolicy

    rng = random.Random(f"interrupt/{seed}")
    d = tempfile.mkdtemp(prefix="authz_interrupt_")
    todo = [(g, os.path.join(ROOT, f"tests/{g}.authz"), read(f"tests/{g}_schema.sql")) for g in FIXED]
    for k in range(policies):
        s = seed * 1000 + k
        spec = genpolicy.make(s)
        path = os.path.join(d, f"p{s}", "policy.authz")
        os.makedirs(os.path.dirname(path))
        genpolicy.write_policy(path, genpolicy.policy_text(spec), spec.include)
        todo.append((f"genpolicy {s}", path, genpolicy.schema_text(spec)))
    done, skipped, failed = [], [], []
    for name, path, schema in todo:
        case = Case(f"{name}: the first apply", setup(schema=schema), run_cli("apply", path), reads=False)
        r = lab.first(case, quiet=name.startswith("genpolicy"))
        if r is None:  # a random policy the compiler refuses: not this check's (a fixed one's uncut run fails above)
            skipped.append(name)
            continue
        at = sample(len(r.sent), cuts, rng)
        checks = lab.cuts(case, r, at, {at[len(at) // 2], at[-1]}, {at[1]})
        for label, problems in checks:
            if problems:
                bad(label, "\n  ".join(problems[:4]))
        if any(p for _, p in checks):
            failed.append(name)
        done.append(f"{name} ({len(at)} of {len(r.sent)})")
    shutil.rmtree(d, ignore_errors=True)
    label = (
        f"other policies, the first apply cut at statements seed {seed} draws, the database as it was after each and "
        f"the next run finishing: {', '.join(done)}"
        + (f"; left out, failing uncut: {', '.join(skipped)}" if skipped else "")
    )
    if failed:
        bad(label, f"failed: {', '.join(failed)}")
    else:
        ok(label)


def main() -> None:
    ap = argparse.ArgumentParser(description=(__doc__ or "").split("\n\n")[0])
    ap.add_argument("--every", action="store_true", help="cut after every statement (else a sample)")
    ap.add_argument("--others", action="store_true", help="other policies' first apply, a sample (the soak)")
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--cuts", type=int, default=6, help="--others: the cuts drawn for each policy")
    ap.add_argument("--policies", type=int, default=6, help="--others: how many random policies")
    a = ap.parse_args()
    started = time.monotonic()
    os.chdir(tempfile.gettempdir())  # no rowstile.toml or .env of anyone's read by the command
    lab = Lab()
    d: Docs | None = None
    try:
        if a.others:
            others(lab, a.seed, a.cuts, a.policies)
        else:
            d = docs_cases()
            docs(lab, d, a.every, random.Random(f"interrupt/{a.seed}"))
            stopped(lab, d, a.every)
            reviewed(lab, d)
    finally:
        lab.close()
        lab.control.close()
        forget(*list(LOOKS))
        for db in (DB, TEMPLATE, WHOLE):
            sh("dropdb", "--if-exists", db, check=False)
        if d:
            shutil.rmtree(d.files.dir, ignore_errors=True)
    print(f"interrupt: {'all passed' if not failures else f'{failures} failed'} ({time.monotonic() - started:.0f}s)")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
