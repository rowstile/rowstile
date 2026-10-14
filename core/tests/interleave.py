#!/usr/bin/env python3
"""interleave: every order of the steps of two tree writes, each session at each isolation level.

    python3 tests/interleave.py [--levels "read committed,repeatable read,serializable"] [--db authz_interleave]
                                [--pairs create-move,share-delete]

Two sessions each run one transaction on a small subtree of the docs app (core/example/): a read, which takes the
snapshot (of a table no write touches, so that what SERIALIZABLE notices is the writes' own doing; the BEGIN goes
with it: a BEGIN takes no snapshot and no lock, so where it sits changes nothing the server does), one write, and
the commit. The writes are the ones that change the folder tree, or that the tree's rows decide: a folder created,
moved, linked into another, unlinked, deleted, its id changed, and a folder shared and unshared, which
`authz.share` and the forgetting of a deleted row's shares must get right while the row goes. Each of the 36 pairs
of them (a kind with itself included) runs in every order of its six steps the server allows, with each session
at each of the levels asked for (the nine pairs of the three by default: one session in READ COMMITTED beside one
in SERIALIZABLE too, which SERIALIZABLE's own checks can't see).

The orders: the scheduler sends one step at a time and waits until every session is either done with its statement
or waiting for a lock, which a third connection tells by `pg_blocking_pids`. A waiting session can't be sent its
next step, so of the 20 ways to interleave two sessions of three steps, those in which a session goes on past a
step the server makes it wait at don't happen; the rest are found by trying each choice at each point where both
sessions could go (a search that runs the schedule again from the start for each choice: a step's answer decides
nothing the next run could choose differently, or the run says so).

After each schedule, as the owner:
  - every error was the write's own refusal that the other write can cause (a loop, a parent gone, a share on a
    row gone, each by its words), or 40001 or 40P01, to retry, in a session that isn't in READ COMMITTED: READ
    COMMITTED never needs a retry;
  - authz.verify(): the inheritance tables match a rebuild;
  - no folder sits inside itself through its parents;
  - no share is left on a folder or file that isn't there;
  - what authz.list says the users the subtree concerns may do with each folder and file equals the reference
    evaluator's answer (authzlib/evaluate.py) on the rows the schedule left (asked once for each set of rows the
    schedules leave: the same rows, with the inheritance tables exact, give the same answers);
  - both in SERIALIZABLE, the rows are what running the transactions that committed one after the other, in some
    order, leaves (those orders are among the schedules; a session alone runs once more for each pair).
Every schedule has a time limit: a session that neither finishes nor waits, or sessions waiting with nothing to
let them go, fail with the schedule printed, and their connections are cancelled.
"""

from __future__ import annotations

import argparse
import itertools
import os
import queue
import subprocess
import sys
import threading
import time
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import NamedTuple

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "cli"))
import compile_policy  # noqa: E402
import pgwire  # noqa: E402
from authzlib import evaluate  # noqa: E402
from difftest import Reference  # noqa: E402

LEVELS = ("read committed", "repeatable read", "serializable")
KINDS = ("create", "move", "link", "unlink", "delete", "rekey", "share", "unshare")
RETRY = ("40001", "40P01")  # a serialization failure, a deadlock: what an app retries
# the users whose rights on the subtree its shape decides: alice and bob own parts of it, dave and frank are given
# shares on it, gina views through her team and a share (carol owns it all, erin administers it)
USERS = ["1", "2", "4", "6", "7"]
PERMS = [("folder", "view"), ("folder", "edit"), ("folder", "share"), ("file", "view"), ("file", "edit")]
SETTLE = 20.0  # seconds a statement may run without waiting for a lock
STUCK = 10.0  # seconds beyond deadlock_timeout that sessions may all wait, with nothing left to run

# The subtree each schedule starts from, under Company (folder 1, org 1):
#   r 1000 (carol)
#   ├── a 1001 (alice)
#   │   └── c 1003 (alice)    also linked into b; shared with gina
#   └── b 1002 (bob)          Platform (gina's team) may view
#       └── l 1004 (bob)      also linked into a; file 1000
R, A, B, C, L = 1000, 1001, 1002, 1003, 1004
RESET = f"""
DELETE FROM app.files WHERE id >= 1000;
DELETE FROM app.folders WHERE id >= 1000;
DELETE FROM authz.shares WHERE object_type IN ('folder', 'file') AND object_id::bigint >= 1000;
INSERT INTO app.folders (id, org_id, parent_id, owner_id, name) VALUES
  ({R}, 1, 1, 3, 'r'), ({A}, 1, {R}, 1, 'a'), ({B}, 1, {R}, 2, 'b'), ({C}, 1, {A}, 1, 'c'), ({L}, 1, {B}, 2, 'l');
INSERT INTO app.folder_links VALUES ({C}, {B}), ({L}, {A});
INSERT INTO app.folder_team_access VALUES ({B}, 12, 'view');
INSERT INTO app.files (id, folder_id, owner_id, name) VALUES (1000, {L}, 2, 'f.md');
INSERT INTO authz.shares (object_type, object_id, relation, subject_type, subject_id)
  VALUES ('folder', '{C}', 'viewer', 'user', '7');
"""
# What a schedule leaves of the subtree's rows (the rest of the docs app's never changes): everything authz.list's
# answers are made of, but the inheritance tables, which authz.verify() holds to these rows; to compare with the
# transactions one after the other, and to ask the answers of each set of rows once
ROWS = """SELECT json_build_array(
  (SELECT json_agg(json_build_array(id, org_id, parent_id, owner_id, name, inherit) ORDER BY id) FROM app.folders
   WHERE id >= 1000),
  (SELECT json_agg(json_build_array(folder_id, parent_id) ORDER BY folder_id, parent_id) FROM app.folder_links
   WHERE folder_id >= 1000 OR parent_id >= 1000),
  (SELECT json_agg(json_build_array(folder_id, team_id, access) ORDER BY folder_id, team_id)
   FROM app.folder_team_access WHERE folder_id >= 1000),
  (SELECT json_agg(json_build_array(id, folder_id, owner_id, confidential) ORDER BY id) FROM app.files WHERE id >= 1000),
  (SELECT json_agg(json_build_array(object_type, object_id, relation, subject_type, subject_id, subject_relation,
                                    expires_at, starts_at, caveat)
                   ORDER BY object_type, object_id, relation, subject_type, subject_id, subject_relation)
   FROM authz.shares WHERE object_type IN ('folder', 'file') AND object_id::bigint >= 1000))::text"""
LOOPS = """WITH RECURSIVE up(start, id) AS (
  SELECT id, parent_id FROM app.folders WHERE parent_id IS NOT NULL
  UNION
  SELECT up.start, f.parent_id FROM up JOIN app.folders f ON f.id = up.id WHERE f.parent_id IS NOT NULL)
SELECT coalesce(string_agg(DISTINCT start::text, ', '), '') FROM up WHERE start = id"""
ORPHANS = """SELECT coalesce(string_agg(g.object_type || ' ' || g.object_id, ', '), '') FROM authz.shares g
WHERE (g.object_type = 'folder' AND NOT EXISTS (SELECT 1 FROM app.folders x WHERE x.id::text = g.object_id))
   OR (g.object_type = 'file' AND NOT EXISTS (SELECT 1 FROM app.files x WHERE x.id::text = g.object_id))"""
ANSWERS = "SELECT json_build_array({})".format(
    ", ".join(f"(SELECT coalesce(json_agg(x), '[]') FROM authz.list('{t}', '{p}') x)" for t, p in PERMS)
)
REBUILD = 'SELECT authz_int."folder__parent__tree_rebuild"(), authz_int."folder__linked_into_parent__tree_rebuild"()'


class Refusal(NamedTuple):
    """An error a write may end with when the other write gets there first: its code, words of its message, and the
    kinds of write that can cause it."""

    code: str
    words: str
    by: frozenset[str]


class Op(NamedTuple):
    kind: str
    sql: str
    who: str  # '': the owner (the app role may not write link tables); else the app role, signed in as this user
    refusals: tuple[Refusal, ...] = ()


def refusal(code: str, words: str, *by: str) -> Refusal:
    return Refusal(code, words, frozenset(by))


GONE = ("delete", "rekey")  # what takes c's id away


def op(kind: str, s: int) -> Op:
    """Session s's write of a kind. Each write changes what lies above c or l, or c itself, so that in most pairs
    one write changes the ancestors of what the other writes, and the inheritance rows each one computes depend on
    the other's: the first session's create puts a folder under c, which the second session's writes move, link,
    unlink, delete or renumber; the two moves cross (l under c, c under l: one after the other, a loop), as do the
    two links (a loop through links, which is allowed); the deletes, renumberings, shares and unshares are all of c."""
    first = s == 1
    # c gone, refused by the foreign key, or first by the rule (parent.edit, on a parent that isn't there)
    parent_gone = refusal("23503", 'violates foreign key constraint "folders_parent_id_fkey"', *GONE)
    no_insert = refusal("42501", "permission denied: user 5 may not insert this row into app.folders", *GONE)
    no_move = refusal("42501", f"changing parent_id of app.folders {L} needs: parent.edit", *GONE)
    match kind:
        case "create":
            new, parent = (1010, C) if first else (1011, L)
            sql = (
                f"INSERT INTO app.folders (id, org_id, parent_id, owner_id, name) VALUES ({new}, 1, {parent}, 5, 'new')"
            )
            return Op(kind, sql, "5", (parent_gone, no_insert) if first else ())
        case "move":
            moved, parent = (L, C) if first else (C, L)
            loop = refusal("23514", "cannot be moved inside itself", "move")
            sql = f"UPDATE app.folders SET parent_id = {parent} WHERE id = {moved}"
            return Op(kind, sql, "5", (loop, parent_gone, no_move) if first else (loop,))
        case "link":
            child, parent = (L, C) if first else (C, L)
            gone = refusal("23503", 'violates foreign key constraint "folder_links_parent_id_fkey"', *GONE)
            return Op(kind, f"INSERT INTO app.folder_links VALUES ({child}, {parent})", "", (gone,) if first else ())
        case "unlink":
            child, parent = (L, A) if first else (C, B)
            return Op(kind, f"DELETE FROM app.folder_links WHERE folder_id = {child} AND parent_id = {parent}", "")
        case "delete":  # c, which the first session's create and move put a folder in
            in_it = refusal("23503", 'update or delete on table "folders" violates foreign key', "create", "move")
            return Op(kind, f"DELETE FROM app.folders WHERE id = {C}", "5", () if first else (in_it,))
        case "rekey":
            return Op(kind, f"UPDATE app.folders SET id = {1013 if first else 1023} WHERE id = {C}", "5")
        case "share":  # with frank, with dave
            gone = refusal("42501", f"you cannot share folder {C}", *GONE)
            return Op(kind, f"SELECT authz.share('folder', {C}, 'viewer', 'user', {6 if first else 4})", "1", (gone,))
        case _:
            assert kind == "unshare", kind
            gone = refusal("42501", f"you cannot unshare viewer on folder {C}", *GONE)
            return Op(kind, f"SELECT authz.unshare('folder', {C}, 'viewer', 'user', 7)", "1", (gone,))


class Outcome(NamedTuple):
    tag: str  # the last statement's, in the server's words (COMMIT, ROLLBACK, INSERT 0 1)
    code: str  # the error's SQLSTATE, or ''
    message: str


class Session:
    """A connection with a thread of its own, so that a statement can be sent without waiting for its answer."""

    def __init__(self, n: int, db: str) -> None:
        self.n, self.db = n, db
        self.conn = pgwire.connect(**pgwire.parse_dsn(f"dbname={db}"))
        assert self.conn.backend is not None
        self.pid = self.conn.backend[0]
        self.jobs: queue.Queue[list[str] | None] = queue.Queue()
        self.done = threading.Event()
        self.outcome: Outcome | None = None
        self.busy = False  # a step sent and its answer not yet taken
        self.thread = threading.Thread(target=self.work, daemon=True)
        self.thread.start()

    def work(self) -> None:
        while (job := self.jobs.get()) is not None:
            out = Outcome("", "", "")
            try:
                for sql in job:
                    self.conn.query(sql)
                out = Outcome(self.conn.tag, "", "")
            except pgwire.PgError as e:
                out = Outcome("", e.code, e.message)
            except (pgwire.ProtocolError, OSError) as e:
                out = Outcome("", "08006", f"the connection broke: {e}")
            self.outcome = out
            self.done.set()

    def send(self, statements: list[str]) -> None:
        self.done.clear()
        self.outcome = None
        self.busy = True
        self.jobs.put(statements)

    def run(self, statements: list[str], timeout: float = SETTLE) -> Outcome:
        """Statements that never wait (the set-up between schedules), to the end."""
        self.send(statements)
        if not self.done.wait(timeout):
            raise TimeoutError(f"session {self.n}: {statements} took over {timeout}s")
        return self.take()

    def take(self) -> Outcome:
        self.busy = False
        assert self.outcome is not None
        return self.outcome

    def close(self, cancel: bool = False) -> None:
        self.jobs.put(None)  # the thread ends once its statement does
        if cancel:
            self.conn.cancel()  # this session's own backend, which this run started: its transaction is rolled back
        else:
            self.conn.close()


@dataclass
class Run:
    """One schedule: the order its steps were sent in, what each answered, and what was checked after."""

    choices: list[int] = field(default_factory=list)  # the session sent a step at each point where two could go
    points: list[list[int]] = field(default_factory=list)  # the sessions that could go, at each such point
    events: list[str] = field(default_factory=list)
    outcomes: dict[tuple[int, str], Outcome] = field(default_factory=dict)
    waited: bool = False
    waiting: set[int] = field(default_factory=set)  # the sessions whose step waits for a lock
    order: list[int] = field(default_factory=list)  # the session of each step, in the order sent
    problems: list[str] = field(default_factory=list)
    rows: str = ""
    committed: frozenset[int] = frozenset()

    def text(self) -> str:
        return " ".join(self.events)


class Scheduler:
    def __init__(self, db: str, deadlock_timeout: float) -> None:
        self.db = db
        self.owner = pgwire.connect(**pgwire.parse_dsn(f"dbname={db}"))
        self.sessions = [Session(1, db), Session(2, db)]
        self.stuck = deadlock_timeout + STUCK
        with open(os.path.join(ROOT, "example", "docs.authz"), encoding="utf-8") as fh:
            self.ref = Reference(compile_policy.parse_policy(fh.read(), "docs.authz"))
        queries = self.ref.data_queries()
        self.data_keys = [k for k, _ in queries]
        self.data_sql = "SELECT json_build_array({})".format(", ".join(f"({sql})" for _, sql in queries))
        self.owner.script(RESET)
        self.initial = str(self.owner.query(ROWS)[0][0])
        self.judged: set[str] = set()  # the rows whose answers were the evaluator's
        self.refused: dict[str, int] = {}  # how often each refusal a write may meet was met

    def blocked(self, sessions: Sequence[Session]) -> set[int]:
        rows = self.owner.query(
            "SELECT p FROM unnest($1::int[]) p WHERE cardinality(pg_blocking_pids(p)) > 0", [[s.pid for s in sessions]]
        )
        return {int(str(r[0])) for r in rows}

    def collect(self, run: Run, s: Session, step: str) -> None:
        out = s.take()
        run.outcomes[(s.n, step)] = out
        if out.code:
            run.events.append(f"[{s.n} {step}: {out.code} {out.message}]")
        elif s.n in run.waiting:
            run.events.append(f"[{s.n} {step} done]")
        run.waiting.discard(s.n)

    def settle(self, run: Run, current: dict[int, str]) -> None:
        """Until every session is done with its statement or waits for a lock: the answers that came in are
        recorded, each in its turn."""
        deadline = time.monotonic() + SETTLE
        while True:
            for s in self.sessions:
                if s.busy and s.done.is_set():
                    self.collect(run, s, current[s.n])
            busy = [s for s in self.sessions if s.busy]
            if not busy:
                return
            waiting = self.blocked(busy)
            running = [s for s in busy if s.pid not in waiting]
            if not running:
                return
            if time.monotonic() > deadline:
                raise TimeoutError(f"stuck: session {running[0].n} ran its {current[running[0].n]} for over {SETTLE}s")
            running[0].done.wait(0.002)

    def reconnect(self) -> None:
        for s in self.sessions:
            s.close(cancel=True)
        self.sessions = [Session(1, self.db), Session(2, self.db)]

    def schedule(self, levels: Sequence[str], ops: Sequence[Op | None], prefix: Sequence[int]) -> Run:
        """Runs the two transactions, choosing as prefix says at each point where both sessions could go, and the
        first session after it; then checks what they left."""
        run = Run()
        self.owner.script(RESET)
        steps: dict[int, list[tuple[str, list[str]]]] = {}
        for s, o, level in zip(self.sessions, ops, levels, strict=True):
            who = (
                ["RESET ROLE", "RESET authz.user_id"]
                if o is None or not o.who
                else ["SET ROLE app_user", f"SELECT set_config('authz.user_id', '{o.who}', false)"]
            )
            out = s.run(who)
            if out.code:
                raise RuntimeError(f"session {s.n} couldn't sign in: {out.code} {out.message}")
            steps[s.n] = (
                []
                if o is None
                else [
                    ("read", [f"BEGIN ISOLATION LEVEL {level}", "SELECT count(*) FROM app.orgs"]),
                    ("write", [o.sql]),
                    ("commit", ["COMMIT"]),
                ]
            )
        current: dict[int, str] = {}
        try:
            while True:
                self.settle(run, current)
                ready = [s for s in self.sessions if not s.busy and steps[s.n]]
                if not ready:
                    busy = [s for s in self.sessions if s.busy]
                    if not busy:
                        break
                    # each waits for the other: the server's deadlock check ends it
                    run.events.append("(all waiting)")
                    deadline = time.monotonic() + self.stuck
                    while not any(s.done.is_set() for s in busy):
                        if time.monotonic() > deadline:
                            raise TimeoutError(f"stuck: sessions {[s.n for s in busy]} all waited over {self.stuck}s")
                        busy[0].done.wait(0.01)
                    continue
                if len(ready) > 1:
                    k = len(run.choices)
                    pick = prefix[k] if k < len(prefix) else ready[0].n
                    if pick not in [s.n for s in ready]:
                        raise TimeoutError(f"ran differently on replay: session {pick} can't go at point {k + 1}")
                    run.choices.append(pick)
                    run.points.append([s.n for s in ready])
                    s = next(x for x in ready if x.n == pick)
                else:
                    s = ready[0]
                step, statements = steps[s.n].pop(0)
                current[s.n] = step
                run.order.append(s.n)
                run.events.append(f"{s.n} {step}")
                s.send(statements)
                if not s.done.wait(0.005):
                    self.settle(run, current)
                    if s.busy:
                        run.events[-1] += " (waits)"
                        run.waited = True
                        run.waiting.add(s.n)
        except TimeoutError as e:
            run.problems.append(str(e))
            self.reconnect()
            self.owner.script(REBUILD)
            return run
        run.committed = frozenset(
            n for (n, step), out in run.outcomes.items() if step == "commit" and out.tag == "COMMIT"
        )
        self.check(run, levels, ops)
        return run

    def check(self, run: Run, levels: Sequence[str], ops: Sequence[Op | None]) -> None:
        for (n, step), out in sorted(run.outcomes.items()):
            if not out.code:
                continue
            o, other = ops[n - 1], ops[2 - n]
            if out.code in RETRY and levels[n - 1] != "read committed":
                continue
            met = [
                r
                for r in (o.refusals if step == "write" and o is not None and other is not None else ())
                if r.code == out.code and r.words in out.message and other is not None and other.kind in r.by
            ]
            if met:
                self.refused[f"{met[0].code} {met[0].words}"] = self.refused.get(f"{met[0].code} {met[0].words}", 0) + 1
                continue
            run.problems.append(f"session {n}'s {step}: {out.code} {out.message}")
        if self.owner.query("SELECT authz.verify()") != [(True,)]:
            run.problems.append("the inheritance tables don't match a rebuild")
            self.owner.script(REBUILD)
        loops = str(self.owner.query(LOOPS)[0][0])
        if loops:
            run.problems.append(f"folders inside themselves: {loops}")
        orphans = str(self.owner.query(ORPHANS)[0][0])
        if orphans:
            run.problems.append(f"shares left on rows that aren't there: {orphans}")
        run.rows = str(self.owner.query(ROWS)[0][0])
        # the same rows, with the inheritance tables exact (verify), give the same answers: asked once per rows
        if run.rows not in self.judged:
            answers = self.answers()
            run.problems += answers
            if not answers and not run.problems:
                self.judged.add(run.rows)

    def answers(self) -> list[str]:
        """authz.list for each user and permission, against the reference evaluator on the rows there are."""
        raw = self.owner.query(self.data_sql)[0][0]
        assert isinstance(raw, list), raw
        given: dict[tuple[object, ...], list[object]] = {}
        for key, v in zip(self.data_keys, raw, strict=True):
            assert isinstance(v, list), (key, v)
            given[key] = list(v)
        data = evaluate.Data.of(given)
        problems: list[str] = []
        try:
            for u in USERS:
                self.owner.query("SELECT set_config('authz.user_id', $1, false)", [u])
                got = self.owner.query(ANSWERS)[0][0]
                assert isinstance(got, list), got
                state = self.ref.evaluate(data, u)
                for (t, p), ids in zip(PERMS, got, strict=True):
                    assert isinstance(ids, list), ids
                    db, want = {str(i) for i in ids}, set(state[(t, p)])
                    if db != want:
                        problems.append(
                            f"user {u}, {t} {p}: authz.list says {sorted(db)}, the evaluator {sorted(want)}"
                        )
        finally:
            self.owner.query("RESET authz.user_id")
        return problems

    def every_order(self, levels: Sequence[str], ops: Sequence[Op | None]) -> list[Run]:
        """Every schedule the server allows: each run follows a prefix of choices, then takes the first session;
        each point it passed beyond the prefix where the other session could have gone is tried in a run of its
        own."""
        runs: list[Run] = []
        todo: list[list[int]] = [[]]
        while todo:
            prefix = todo.pop()
            run = self.schedule(levels, ops, prefix)
            runs.append(run)
            for k in range(len(prefix), len(run.choices)):
                for other in run.points[k]:
                    if other != run.choices[k]:
                        todo.append(run.choices[:k] + [other])
        return runs


def serial(runs: Sequence[Run], alone: dict[int, Run], initial: str) -> list[str]:
    """The SERIALIZABLE schedules whose rows are not those of the transactions that committed run one after the
    other in some order: the schedules in which one session went through before the other started, a session alone
    (alone[n]), or neither (initial: the rows a schedule starts from)."""
    allowed: dict[frozenset[int], set[str]] = {frozenset(): {initial}}
    for run in alone.values():
        allowed.setdefault(run.committed, set()).add(run.rows)
    for run in runs:
        if run.order in ([1, 1, 1, 2, 2, 2], [2, 2, 2, 1, 1, 1]):
            allowed.setdefault(run.committed, set()).add(run.rows)
    return [
        f"{run.text()}: the rows are none that the transactions committed ({sorted(run.committed)}) leave one after "
        f"the other: {run.rows}"
        for run in runs
        if not run.problems and run.rows not in allowed.get(run.committed, set())
    ]


def setup(db: str) -> float:
    """A database with the docs app and its policy; returns the server's deadlock_timeout, in seconds."""
    subprocess.run(["dropdb", "--if-exists", db], capture_output=True)
    subprocess.run(["createdb", db], check=True)
    env = {**os.environ, "PGOPTIONS": "-c client_min_messages=error"}
    psql = ["psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", "-d", db]
    subprocess.run([*psql, "-f", os.path.join(ROOT, "example", "app_schema.sql")], check=True, env=env)
    sql = compile_policy.load(os.path.join(ROOT, "example", "docs.authz")).compile("docs.authz")
    conn = pgwire.connect(**pgwire.parse_dsn(f"dbname={db}"))
    try:
        conn.script("SET client_min_messages = error;\n" + sql)
        ms = conn.query("SELECT setting::int FROM pg_settings WHERE name = 'deadlock_timeout'")[0][0]
    finally:
        conn.close()
    assert isinstance(ms, int), ms
    return ms / 1000


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--db", default="authz_interleave")
    ap.add_argument(
        "--levels", default=",".join(LEVELS), help="comma-separated isolation levels: each session at each of them"
    )
    ap.add_argument("--pairs", default="", help="comma-separated pairs, as create-move (default: all 36)")
    args = ap.parse_args()
    chosen = [x.strip() for x in args.levels.split(",") if x.strip()]
    for x in chosen:
        if x not in LEVELS:
            ap.error(f"no isolation level {x!r}: {', '.join(LEVELS)}")
    pairs = [(a, b) for i, a in enumerate(KINDS) for b in KINDS[i:]]
    if args.pairs:
        wanted = {tuple(p.split("-")) for p in args.pairs.split(",")}
        pairs = [p for p in pairs if p in wanted or p[::-1] in wanted]
    started = time.monotonic()
    sched = Scheduler(args.db, setup(args.db))
    fails = 0
    try:
        for levels in itertools.product(chosen, repeat=2):
            both = levels[0] if levels[0] == levels[1] else " and ".join(levels)
            n = waited = retried = deadlocks = refused = 0
            sched.judged.clear()
            level_started = time.monotonic()
            for k1, k2 in pairs:
                ops = [op(k1, 1), op(k2, 2)]
                runs = sched.every_order(levels, ops)
                problems = [f"{run.text()}: {p}" for run in runs for p in run.problems]
                if levels == ("serializable", "serializable"):
                    alone = {
                        1: sched.schedule(levels, [ops[0], None], []),
                        2: sched.schedule(levels, [None, ops[1]], []),
                    }
                    problems += [f"{alone[s].text()}: {p}" for s in alone for p in alone[s].problems]
                    problems += serial(runs, alone, sched.initial)
                n += len(runs)
                waited += sum(run.waited for run in runs)
                codes = [out.code for run in runs for out in run.outcomes.values()]
                retried += sum(c in RETRY for c in codes)
                deadlocks += codes.count("40P01")
                refused += sum(bool(c) and c not in RETRY for c in codes)
                what = f"{both}, {k1} and {k2}"
                if problems:
                    fails += 1
                    print(f"FAIL  {what}: {len(problems)} problems in {len(runs)} orders")
                    for p in problems[:6]:
                        print(f"        {p}")
                else:
                    extra = {
                        "read committed": ", none needing a retry",
                        "serializable": ", each as one transaction after the other",
                    }.get(both, "")
                    print(f"ok    {what}: every order ({len(runs)}), inheritance tables exact after each{extra}")
                sys.stdout.flush()
            print(
                f"info  {both}: {n} schedules over {len(pairs)} pairs in {time.monotonic() - level_started:.0f}s; "
                f"{waited} with a write waiting for the other, {retried} retryable errors ({deadlocks} deadlocks), "
                f"{refused} writes refused by the other's; {len(sched.judged)} sets of rows left, each judged "
                "against the evaluator"
            )
    finally:
        for s in sched.sessions:
            s.close()
        sched.owner.close()
    subprocess.run(["dropdb", "--if-exists", args.db], capture_output=True)
    print(
        "info  writes refused by the other's, by why: "
        + "; ".join(f"{k} ({v})" for k, v in sorted(sched.refused.items()))
    )
    print(f"info  {time.monotonic() - started:.0f}s in all")
    if fails:
        print(f"interleave: {fails} failed")
        sys.exit(1)
    print("interleave: all passed")


if __name__ == "__main__":
    main()
