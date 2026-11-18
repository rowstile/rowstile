#!/usr/bin/env python3
"""interleave: every order of the steps of two tree writes, each session at each isolation level.

    python3 tests/interleave.py [--levels "read committed,repeatable read,serializable"] [--db authz_interleave]
                                [--worlds docs,cross,parts,boxes,docs_by,docs_after,docs_plain,docs_few,shown]
                                [--pairs create-move]

Two sessions each run one transaction on a small subtree: a read, which takes the snapshot (of a table no write
touches, so that what SERIALIZABLE notices is the writes' own doing; the BEGIN goes with it: a BEGIN takes no
snapshot and no lock, so where it sits changes nothing the server does), one write, and the commit. Each write is
one that changes a tree, or that the tree's rows decide, and is written so that in most pairs one write changes
what lies above what the other writes. Every pair of a world's kinds (a kind with itself included) runs in every
order of its six steps the server allows, with each session at each of the levels asked for (the nine pairs of
the three by default: one session in READ COMMITTED beside one in SERIALIZABLE too, which SERIALIZABLE's own
checks can't see). Nine worlds, each in a database of its own, so that every way a tree is kept is written by two
transactions at once:
  - docs: the docs app (core/example/), a tree of one type on plain tables: a folder created, moved, linked into
    another, unlinked, deleted, its id changed, and a folder shared and unshared, which `authz.share` and the
    forgetting of a deleted row's shares must get right while the row goes (36 pairs);
  - cross: tests/cross.authz, a tree of two types (folders inside folders or projects, projects placed in folders
    by a table or by sharing), whose condition reads another table: a folder created, moved, archived (its type's
    where), a project placed in a folder and a placement turned off (a link table's where), a folder frozen (a row
    in the table the condition reads: the tree checks its conditions again) and a project shared to a folder
    (21 pairs);
  - parts: a tree of one type on a partitioned table, its links in a table with a table that inherits from it, and
    a condition that reads another table, which a table inherits from too: a topic created (one straight into a
    partition), moved, linked (one into the table that inherits), unlinked, held, and its id changed so that it
    moves to the other partition (21 pairs);
  - boxes: a tree of two types through their own columns alone (boxes on shelves, shelves in boxes), whose
    condition reads the tree's own table: a box or a shelf created, the two moved (a loop through both), a box
    sealed (a write to the tree's own table that changes what the condition says of other rows), and a box's id
    changed (10 pairs);
  - docs_plain: the docs app without its sync index, which takes lock rows of its own at each commit (all of them
    at a stricter level): here a write fails or waits only by the trees' own locks. The docs world's creates, moves,
    links and unlinks, and a move of a folder that has the other session's folder below it (15 pairs);
  - docs_few: the same, where a write of more than one folder takes its whole type (the setting
    tree_lock_limit): the moves of what is above do, the other writes lock what they touch (15 pairs);
  - shown: two trees of one type that differ, one through a column whose condition a seal changes, one through
    that column and a share that is a link (`authz.share` of a node into a node): a node created, moved,
    moved aside (into a part no other write is of: neither waits), sealed, shown in another and hidden from one,
    the last two by users whom a seal may take the right from (21 pairs);
  - docs_by and docs_after: the docs world with its sync index keyed by folder (a move writes what the folders below
    inherit, and no file's readers nor keys), and kept after commit by a worker, which runs after each schedule (36
    pairs each).

The orders: the scheduler sends one step at a time and waits until every session is either done with its statement
or waiting for a lock, which a third connection tells by `pg_blocking_pids`. A waiting session can't be sent its
next step, so of the 20 ways to interleave two sessions of three steps, those in which a session goes on past a
step the server makes it wait at don't happen; the rest are found by trying each choice at each point where both
sessions could go (a search that runs the schedule again from the start for each choice: a step's answer decides
nothing the next run could choose differently, or the run says so).

After each schedule, as the owner:
  - every error was the write's own refusal that the other write can cause (a loop, a parent gone, a share on a
    row gone, each by its words), once that write committed (its COMMIT sent before the refusal came), or 40001
    or 40P01, to retry, in a session that isn't in READ COMMITTED: READ COMMITTED never needs a retry;
  - authz.verify(): the inheritance tables match a rebuild (and the conditions noted for them, where they read
    other rows, are what the rows say now); in docs, authz.sync_verify() too: the sync index (a preview) does;
  - no row sits inside itself through its parents;
  - no share is left on a row that isn't there;
  - for the pairs a world names apart (writes to different parts of the tree), neither write waited for the
    other, unless a session is in SERIALIZABLE: there every tree write takes its whole type (trees.TREE_LOCK_MOST);
  - what authz.list says the users the subtree concerns may do with each row equals the reference evaluator's
    answer (authzlib/evaluate.py) on the rows the schedule left (asked once for each set of rows the schedules
    leave: the same rows, with the inheritance tables exact, give the same answers);
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
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field, replace
from typing import NamedTuple

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "cli"))
import compile_policy  # noqa: E402
import pgwire  # noqa: E402
from authzlib import Compiler, evaluate  # noqa: E402
from difftest import Reference  # noqa: E402

LEVELS = ("read committed", "repeatable read", "serializable")
RETRY = ("40001", "40P01")  # a serialization failure, a deadlock: what an app retries
SETTLE = 20.0  # seconds a statement may run without waiting for a lock
STUCK = 10.0  # seconds beyond deadlock_timeout that sessions may all wait, with nothing left to run


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


def core_file(path: str) -> str:
    with open(os.path.join(ROOT, path), encoding="utf-8") as fh:
        return fh.read()


@dataclass(frozen=True)
class World:
    """A policy, its tables, the subtree each schedule starts from, and the writes to it of each kind."""

    name: str
    policy: tuple[str, str]  # the name its messages give it, and its text
    schema: tuple[str, ...]  # the files that make the app's tables (psql runs them), from core/
    setup: str  # then this, before the policy
    reset: str  # the subtree each schedule starts from
    rows: str  # what a schedule leaves of the subtree: everything authz.list's answers are made of, as text
    loops: str  # the rows inside themselves through their parents, or ''
    orphans: str  # the shares left on rows that aren't there, or ''
    read: str  # the snapshot's read: of a table no write touches
    users: tuple[str, ...]  # the users whose rights on the subtree its shape decides
    perms: tuple[tuple[str, str], ...]
    kinds: tuple[str, ...]
    op: Callable[[str, int], Op]  # session s's write of a kind
    # the pairs whose two writes are to different parts of the tree: neither may wait for the other
    apart: frozenset[tuple[str, str]] = frozenset()

    def answers_sql(self) -> str:
        return "SELECT json_build_array({})".format(
            ", ".join(f"(SELECT coalesce(json_agg(x), '[]') FROM authz.list('{t}', '{p}') x)" for t, p in self.perms)
        )

    def pairs(self) -> list[tuple[str, str]]:
        return [(a, b) for i, a in enumerate(self.kinds) for b in self.kinds[i:]]


# --- docs: the docs app's folders, one type on plain tables ---------------------------------------------------
# The subtree each schedule starts from, under Company (folder 1, org 1):
#   r 1000 (carol)
#   ├── a 1001 (alice)
#   │   └── c 1003 (alice)    also linked into b; shared with gina
#   └── b 1002 (bob)          Platform (gina's team) may view
#       └── l 1004 (bob)      also linked into a; file 1000
R, A, B, C, L = 1000, 1001, 1002, 1003, 1004
DOCS_RESET = f"""
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
DOCS_ROWS = """SELECT json_build_array(
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
DOCS_LOOPS = """WITH RECURSIVE up(start, id) AS (
  SELECT id, parent_id FROM app.folders WHERE parent_id IS NOT NULL
  UNION
  SELECT up.start, f.parent_id FROM up JOIN app.folders f ON f.id = up.id WHERE f.parent_id IS NOT NULL)
SELECT coalesce(string_agg(DISTINCT start::text, ', '), '') FROM up WHERE start = id"""
DOCS_ORPHANS = """SELECT coalesce(string_agg(g.object_type || ' ' || g.object_id, ', '), '') FROM authz.shares g
WHERE (g.object_type = 'folder' AND NOT EXISTS (SELECT 1 FROM app.folders x WHERE x.id::text = g.object_id))
   OR (g.object_type = 'file' AND NOT EXISTS (SELECT 1 FROM app.files x WHERE x.id::text = g.object_id))"""

GONE = ("delete", "rekey")  # what takes c's id away


def docs_op(kind: str, s: int) -> Op:
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


# (with the sync index, a preview: its readers and keys are kept at each commit, under lock rows of their own, and
# must match a rebuild after every schedule; the role the lines name is made by the setup)
SYNC_LINES = "\nsync role authz_sync_engine\nsync app.files : view\nsync app.folders\n"
MAKE_SYNC_ROLE = "DO $r$ BEGIN CREATE ROLE authz_sync_engine; EXCEPTION WHEN duplicate_object OR unique_violation THEN NULL; END $r$;"
DOCS = World(
    name="docs",
    policy=("docs.authz", core_file("example/docs.authz") + SYNC_LINES),
    schema=("example/app_schema.sql",),
    setup=MAKE_SYNC_ROLE,
    reset=DOCS_RESET,
    rows=DOCS_ROWS,
    loops=DOCS_LOOPS,
    orphans=DOCS_ORPHANS,
    read="SELECT count(*) FROM app.orgs",
    # alice and bob own parts of the subtree, dave and frank are given shares on it, gina views through her team
    # and a share (carol owns it all, erin administers it)
    users=("1", "2", "4", "6", "7"),
    perms=(("folder", "view"), ("folder", "edit"), ("folder", "share"), ("file", "view"), ("file", "edit")),
    kinds=("create", "move", "link", "unlink", "delete", "rekey", "share", "unshare"),
    op=docs_op,
    # the two creates are under c and under l, and nothing is below either new folder; the two unlinks take l out
    # of a and c out of b, and neither is above the other
    apart=frozenset({("create", "create"), ("unlink", "unlink")}),
)

# --- cross: folders and projects, one tree of two types (tests/cross.authz) ------------------------------------
# The subtree each schedule starts from (cross_schema.sql has no rows; users 1 to 4 are made with it):
#   folder r 1000 (alice)
#   ├── folder a 1001 (bob)
#   │   └── project p 2000 (carol leads it)    placed in a
#   │       └── folder c 1003                  in p, by its column
#   └── folder b 1002
#       └── folder l 1004 (dave)
#           └── project q 2001                 placed in l; hosted by c (a share to a folder)
# A folder's edit comes down from its parent unless it is frozen (a row of cx.frozen: the tree checks its
# conditions again when that table changes); an archived folder (its type's where) holds nothing
X_P, X_Q = 2000, 2001
CROSS_RESET = f"""
DELETE FROM authz.shares;
DELETE FROM cx.frozen;
DELETE FROM cx.placements;
DELETE FROM cx.folders;
DELETE FROM cx.projects;
INSERT INTO cx.projects (id, lead_id) VALUES ({X_P}, 3), ({X_Q}, NULL);
INSERT INTO cx.folders (id, parent_type, parent_id, owner_id) VALUES
  ({R}, NULL, NULL, 1), ({A}, 'folder', {R}, 2), ({B}, 'folder', {R}, NULL), ({C}, 'project', {X_P}, NULL),
  ({L}, 'folder', {B}, 4);
INSERT INTO cx.placements (project_id, folder_id) VALUES ({X_P}, {A}), ({X_Q}, {L});
INSERT INTO authz.shares (object_type, object_id, relation, subject_type, subject_id)
  VALUES ('project', '{X_Q}', 'host', 'folder', '{C}');
"""
CROSS_ROWS = """SELECT json_build_array(
  (SELECT json_agg(json_build_array(id, parent_type, parent_id, owner_id, archived) ORDER BY id) FROM cx.folders),
  (SELECT json_agg(json_build_array(id, lead_id) ORDER BY id) FROM cx.projects),
  (SELECT json_agg(json_build_array(project_id, folder_id, active) ORDER BY project_id, folder_id) FROM cx.placements),
  (SELECT json_agg(folder_id ORDER BY folder_id) FROM cx.frozen),
  (SELECT json_agg(json_build_array(object_type, object_id, relation, subject_type, subject_id)
                   ORDER BY object_type, object_id, relation, subject_type, subject_id) FROM authz.shares))::text"""
CROSS_LOOPS = """WITH RECURSIVE up(start, id) AS (
  SELECT id, parent_id FROM cx.folders WHERE parent_type = 'folder'
  UNION
  SELECT up.start, f.parent_id FROM up JOIN cx.folders f ON f.id = up.id WHERE f.parent_type = 'folder')
SELECT coalesce(string_agg(DISTINCT start::text, ', '), '') FROM up WHERE start = id"""


def cross_op(kind: str, s: int) -> Op:
    """Session s's write of a kind, each of c, of l, or of what lies above them: the first session's create puts a
    folder under c, which the second session freezes; the two moves cross (l under c, through the project c is in,
    and c under l: one after the other, a loop); the first session places p in l too, the second turns p's
    placement in a off; the archives and the freezes are of b and c, above l and below p."""
    first = s == 1
    match kind:
        case "create":  # under c (in a project); under q (a project)
            new, ptype, parent = (1010, "folder", C) if first else (1011, "project", X_Q)
            sql = f"INSERT INTO cx.folders (id, parent_type, parent_id) VALUES ({new}, '{ptype}', {parent})"
            return Op(kind, sql, "")
        case "move":
            moved, parent = (L, C) if first else (C, L)
            loop = refusal("23514", "cannot be moved inside itself", "move")
            sql = f"UPDATE cx.folders SET parent_type = 'folder', parent_id = {parent} WHERE id = {moved}"
            return Op(kind, sql, "", (loop,))
        case "place":
            if first:
                return Op(kind, f"INSERT INTO cx.placements (project_id, folder_id) VALUES ({X_P}, {L})", "")
            sql = f"UPDATE cx.placements SET active = false WHERE project_id = {X_P} AND folder_id = {A}"
            return Op(kind, sql, "")
        case "freeze":  # c; the folder the first session's create makes (a row of cx.frozen may name one not there)
            return Op(kind, f"INSERT INTO cx.frozen VALUES ({C if first else 1010})", "")
        case "archive":
            return Op(kind, f"UPDATE cx.folders SET archived = true WHERE id = {B if first else C}", "")
        case _:  # q hosted by a, by dave (who edits q through l); p hosted by l, by carol (who leads p)
            assert kind == "host", kind
            project, folder, who = (X_Q, A, "4") if first else (X_P, L, "3")
            return Op(kind, f"SELECT authz.share('project', {project}, 'host', 'folder', {folder})", who)


CROSS = World(
    name="cross",
    policy=("cross.authz", core_file("tests/cross.authz")),
    schema=("tests/cross_schema.sql",),
    setup="INSERT INTO cx.users VALUES (1, 'alice'), (2, 'bob'), (3, 'carol'), (4, 'dave');",
    reset=CROSS_RESET,
    rows=CROSS_ROWS,
    loops=CROSS_LOOPS,
    orphans="",  # no write deletes a folder or a project
    read="SELECT count(*) FROM cx.users",
    users=("1", "2", "3", "4"),
    perms=(
        ("folder", "view"),
        ("folder", "edit"),
        ("folder", "file"),
        ("folder", "fund"),
        ("folder", "tidy"),
        ("project", "view"),
        ("project", "edit"),
        ("project", "fund"),
        ("project", "judge"),
    ),
    kinds=("create", "move", "place", "freeze", "archive", "host"),
    op=cross_op,
)

# --- parts: topics, a tree of one type on a partitioned table --------------------------------------------------
# The only tree of its type (in the docs app two trees share the folders, and the first to refresh takes the lock
# before the other checks for a loop: here the lock the row triggers take is all that keeps two moves from making
# one). Topics are partitioned by their id (below 2000, from 2000), so a topic given an id from 2000 moves to the
# other partition; their links are stored in pt.links and in pt.links_old, which inherits from it; a topic inherits
# from its parent unless it is held (a row of pt.holds or of pt.holds_old, which inherits from it: a write there
# checks the tree's conditions again). The subtree each schedule starts from:
#   r 1000 (alice)
#   ├── a 1001 (bob)
#   │   └── c 1003          also linked into b (a row of pt.links_old)
#   └── b 1002
#       └── l 1004 (carol)  also linked into a (a row of pt.links)
PARTS_POLICY = """app role app_user

type user = pt.users

type topic = pt.topics
  owner  : user  = owner_id
  parent : topic = parent_id
  linked : topic = pt.links(topic_id -> parent_id)
  can view = owner or linked.view
          or (parent.view and {not exists (select 1 from pt.holds h where h.topic_id = this.id)})
"""
PARTS_SETUP = """
CREATE SCHEMA pt;
CREATE TABLE pt.users (id bigint PRIMARY KEY);
CREATE TABLE pt.topics (id bigint PRIMARY KEY, parent_id bigint, owner_id bigint) PARTITION BY RANGE (id);
CREATE TABLE pt.topics_low PARTITION OF pt.topics FOR VALUES FROM (0) TO (2000);
CREATE TABLE pt.topics_high PARTITION OF pt.topics FOR VALUES FROM (2000) TO (4000);
CREATE INDEX ON pt.topics (parent_id);
CREATE TABLE pt.links (topic_id bigint NOT NULL, parent_id bigint NOT NULL);
CREATE TABLE pt.links_old () INHERITS (pt.links);
CREATE TABLE pt.holds (topic_id bigint NOT NULL);
CREATE TABLE pt.holds_old () INHERITS (pt.holds);
INSERT INTO pt.users VALUES (1), (2), (3);
"""
PARTS_RESET = f"""
DELETE FROM pt.holds;
DELETE FROM pt.links;
DELETE FROM pt.topics;
INSERT INTO pt.topics (id, parent_id, owner_id) VALUES
  ({R}, NULL, 1), ({A}, {R}, 2), ({B}, {R}, NULL), ({C}, {A}, NULL), ({L}, {B}, 3);
INSERT INTO pt.links_old VALUES ({C}, {B});
INSERT INTO pt.links VALUES ({L}, {A});
"""
PARTS_ROWS = """SELECT json_build_array(
  (SELECT json_agg(json_build_array(id, parent_id, owner_id) ORDER BY id) FROM pt.topics),
  (SELECT json_agg(json_build_array(tableoid::regclass::text, topic_id, parent_id)
                   ORDER BY tableoid::regclass::text, topic_id, parent_id) FROM pt.links),
  (SELECT json_agg(json_build_array(tableoid::regclass::text, topic_id) ORDER BY tableoid::regclass::text, topic_id)
   FROM pt.holds))::text"""
PARTS_LOOPS = """WITH RECURSIVE up(start, id) AS (
  SELECT id, parent_id FROM pt.topics WHERE parent_id IS NOT NULL
  UNION
  SELECT up.start, t.parent_id FROM up JOIN pt.topics t ON t.id = up.id WHERE t.parent_id IS NOT NULL)
SELECT coalesce(string_agg(DISTINCT start::text, ', '), '') FROM up WHERE start = id"""


def parts_op(kind: str, s: int) -> Op:
    """Session s's write of a kind: the first session's create puts a topic under c, which the second session
    holds; the second's goes straight into a partition, under l. The two moves cross (l under c, c under l: a
    loop), as do the two links (one into the table that inherits). The unlinks take c's link out through the table
    above the one it is stored in, and l's from its own table alone; the first session holds c (in the table that
    inherits). The ids changed are of l and b, each to the other partition, which no other write changes."""
    first = s == 1
    match kind:
        case "create":
            table, new, parent = ("pt.topics", 1010, C) if first else ("pt.topics_high", 2011, L)
            return Op(kind, f"INSERT INTO {table} (id, parent_id) VALUES ({new}, {parent})", "")
        case "move":
            moved, parent = (L, C) if first else (C, L)
            loop = refusal("23514", "cannot be moved inside itself", "move")
            return Op(kind, f"UPDATE pt.topics SET parent_id = {parent} WHERE id = {moved}", "", (loop,))
        case "link":
            table, child, parent = ("pt.links_old", L, C) if first else ("pt.links", C, L)
            return Op(kind, f"INSERT INTO {table} VALUES ({child}, {parent})", "")
        case "unlink":
            table, child = ("pt.links", C) if first else ("ONLY pt.links", L)
            return Op(kind, f"DELETE FROM {table} WHERE topic_id = {child}", "")
        case "hold":
            table, held = ("pt.holds_old", C) if first else ("pt.holds", 1010)
            return Op(kind, f"INSERT INTO {table} VALUES ({held})", "")
        case _:
            assert kind == "rekey", kind
            old, new = (L, 2014) if first else (B, 2012)
            return Op(kind, f"UPDATE pt.topics SET id = {new} WHERE id = {old}", "")


PARTS = World(
    name="parts",
    policy=("parts.authz", PARTS_POLICY),
    schema=(),
    setup=PARTS_SETUP,
    reset=PARTS_RESET,
    rows=PARTS_ROWS,
    loops=PARTS_LOOPS,
    orphans="",  # topics have no shares
    read="SELECT count(*) FROM pt.users",
    users=("1", "2", "3"),
    perms=(("topic", "view"),),
    kinds=("create", "move", "link", "unlink", "hold", "rekey"),
    op=parts_op,
)

# --- boxes: boxes on shelves and shelves in boxes, a tree of two types through their columns alone --------------
# A box sits in a box or on a shelf, a shelf in a box, each by its own columns: the only tree of either type, so
# the lock its row triggers take is all that keeps two moves from making a loop through both. A shelf inherits
# from its box unless that box is sealed: a condition that reads the tree's own table (a write there checks the
# conditions again). The subtree each schedule starts from:
#   box r 1000 (alice)
#   ├── shelf s 1100
#   │   └── box a 1001 (bob)
#   │       └── shelf t 1101
#   │           └── box c 1003
#   └── box l 1004
BOXES_POLICY = """app role app_user

type user = bx.users

type shelf = bx.shelves
  box : box = box_id
  can view = box.view and {not exists (select 1 from bx.boxes b where b.id = this.box_id and b.sealed)}

type box = bx.boxes
  parent : box, shelf = (parent_type, parent_id)
  owner  : user = owner_id
  can view = owner or parent.view
"""
BOXES_SETUP = """
CREATE SCHEMA bx;
CREATE TABLE bx.users (id bigint PRIMARY KEY);
CREATE TABLE bx.boxes (id bigint PRIMARY KEY, parent_type text, parent_id bigint, owner_id bigint,
                       sealed boolean NOT NULL DEFAULT false);
CREATE TABLE bx.shelves (id bigint PRIMARY KEY, box_id bigint);
INSERT INTO bx.users VALUES (1), (2);
"""
X_S, X_T = 1100, 1101
BOXES_RESET = f"""
DELETE FROM bx.shelves;
DELETE FROM bx.boxes;
INSERT INTO bx.boxes (id, parent_type, parent_id, owner_id) VALUES
  ({R}, NULL, NULL, 1), ({A}, 'shelf', {X_S}, 2), ({C}, 'shelf', {X_T}, NULL), ({L}, 'box', {R}, NULL);
INSERT INTO bx.shelves VALUES ({X_S}, {R}), ({X_T}, {A});
"""
BOXES_ROWS = """SELECT json_build_array(
  (SELECT json_agg(json_build_array(id, parent_type, parent_id, owner_id, sealed) ORDER BY id) FROM bx.boxes),
  (SELECT json_agg(json_build_array(id, box_id) ORDER BY id) FROM bx.shelves))::text"""
BOXES_LOOPS = """WITH RECURSIVE up(start, t, id) AS (
  SELECT 'box ' || id, parent_type, parent_id FROM bx.boxes WHERE parent_id IS NOT NULL
  UNION
  SELECT up.start, coalesce(b.parent_type, 'box'), coalesce(b.parent_id, s.box_id)
  FROM up LEFT JOIN bx.boxes b ON up.t = 'box' AND b.id = up.id
  LEFT JOIN bx.shelves s ON up.t = 'shelf' AND s.id = up.id
  WHERE coalesce(b.parent_id, s.box_id) IS NOT NULL)
SELECT coalesce(string_agg(DISTINCT start, ', '), '') FROM up WHERE start = t || ' ' || id"""


def boxes_op(kind: str, s: int) -> Op:
    """Session s's write of a kind: the first session's create puts a shelf in c, which the second session seals;
    the second's puts a box in l. The two moves cross through both tables (l onto t, t into l: a loop through a
    box and a shelf); the first session seals a (above t). The ids changed are of c and of a."""
    first = s == 1
    match kind:
        case "create":
            if first:
                return Op(kind, f"INSERT INTO bx.shelves VALUES (1110, {C})", "")
            return Op(kind, f"INSERT INTO bx.boxes (id, parent_type, parent_id) VALUES (1011, 'box', {L})", "")
        case "move":
            loop = refusal("23514", "cannot be moved inside itself", "move")
            if first:
                sql = f"UPDATE bx.boxes SET parent_type = 'shelf', parent_id = {X_T} WHERE id = {L}"
            else:
                sql = f"UPDATE bx.shelves SET box_id = {L} WHERE id = {X_T}"
            return Op(kind, sql, "", (loop,))
        case "seal":
            return Op(kind, f"UPDATE bx.boxes SET sealed = true WHERE id = {A if first else C}", "")
        case _:
            assert kind == "rekey", kind
            return Op(kind, f"UPDATE bx.boxes SET id = {1013 if first else 1021} WHERE id = {C if first else A}", "")


BOXES = World(
    name="boxes",
    policy=("boxes.authz", BOXES_POLICY),
    schema=(),
    setup=BOXES_SETUP,
    reset=BOXES_RESET,
    rows=BOXES_ROWS,
    loops=BOXES_LOOPS,
    orphans="",  # boxes and shelves have no shares
    read="SELECT count(*) FROM bx.users",
    users=("1", "2"),
    perms=(("box", "view"), ("shelf", "view")),
    kinds=("create", "move", "seal", "rekey"),
    op=boxes_op,
)

# the docs app with its index keyed by folder (a move writes what is inherited, not readers), and kept after commit by
# a worker, which runs after each schedule before the index is compared with a rebuild
DOCS_BY = replace(
    DOCS,
    name="docs_by",
    policy=(
        "docs.authz",
        core_file("example/docs.authz")
        + SYNC_LINES.replace("sync app.files : view\n", "sync app.files : view by folder\n").replace(
            "sync app.folders\n", "sync app.folders by folder\n"
        ),
    ),
)
DOCS_AFTER = replace(
    DOCS, name="docs_after", policy=("docs.authz", core_file("example/docs.authz") + SYNC_LINES + "sync after commit\n")
)


def plain_op(kind: str, s: int) -> Op:
    """Session s's write of a kind, in the docs world without its sync index: the docs world's creates, moves, links
    and unlinks, and a move of what is above the other session's folder. The first session takes a (which has c
    below it, and l through a link) into Handbook; the second takes b (l below it, c through a link) into Design
    docs. So a create under c, or a move, a link or an unlink of c, meets the move of b only through what is below
    b: a write that locked what it changed and not what is below it would let them pass each other."""
    if kind != "above":
        return docs_op(kind, s)
    moved, parent = (A, 2) if s == 1 else (B, 4)
    return Op(kind, f"UPDATE app.folders SET parent_id = {parent} WHERE id = {moved}", "5")


# The docs world as an app without the sync index has it: nothing is kept at commit, so a commit takes no lock, and a
# write at REPEATABLE READ fails only on what the trees' own locks see (with the sync index, whose commit takes all
# its lock rows at the stricter levels, any write since the snapshot fails it; at SERIALIZABLE a tree write takes its
# whole type, so any tree write since the snapshot does). The pairs to different
# parts are held to their commits too, and this world is where a build without one of the trees' locks is caught.
DOCS_PLAIN = replace(
    DOCS,
    name="docs_plain",
    policy=("docs.authz", core_file("example/docs.authz")),
    setup="",
    kinds=("create", "above", "move", "link", "unlink"),
    op=plain_op,
    # (the two moves of what is above take a into Handbook and b into Design docs: each has the other's folder
    # below it through a link, so they are not apart)
    apart=frozenset({("create", "create"), ("unlink", "unlink")}),
)
# The docs world without its sync index again, where a write of more than one folder takes its whole type (the
# setting tree_lock_limit, which each schedule's start writes): the moves of what is above do (a with c below it
# and l through a link; b likewise), the other writes lock what they touch. So a write to the whole type runs
# beside a write to a part of it, in every order and at every level: each waits for the other where they meet,
# and the pairs to different parts (each of one folder) still never wait. One, not two: at two the folders' second
# tree, which stores a and c alone below a, would take that move by stripes and update them, and a stale writer
# at a stricter level would fail on a stripe; at one the type's row alone tells it that the whole type was written.
DOCS_FEW = replace(
    DOCS_PLAIN,
    name="docs_few",
    reset=DOCS_RESET
    + "INSERT INTO authz.settings VALUES ('tree_lock_limit', '1') ON CONFLICT (key) DO UPDATE SET value = '1';\n",
)

# --- shown: nodes shown in other nodes by sharing, two trees of one type that differ ------------------------------
# A node's edit comes down from its parent unless the node is sealed; its view comes down from its parent and from
# the nodes it is shown in, which a share says (`authz.share('node', c, 'via', 'node', b)`: a share that is a link).
# So the type has two trees: one through parent, whose condition makes a seal a write to it, and one through
# parent and via, which a seal doesn't write. Each has triggers on sh.nodes, the first tree's first (by their
# names): a statement there must ask both times for the lock rows of the two together, or the second trigger would
# ask for rows the first didn't take. The subtree each schedule starts from:
#   r 1000 (alice)
#   ├── a 1001 (bob)
#   │   └── c 1003          also shown in b
#   └── b 1002
#       └── l 1004 (carol)  also shown in a
# and beside it two nodes with nothing below them, x 1005 and y 1006, which the moves aside take into a and into b
X_X, X_Y = 1005, 1006
SHOWN_POLICY = """app role app_user

type user = sh.users

type node = sh.nodes
  owner  : user = owner_id
  parent : node = parent_id
  via    : node  shared by edit
  can edit = owner or (parent.edit and {not sealed})
  can view = edit or parent.view or via.view

rules sh.nodes
  select : view
"""
SHOWN_SETUP = """
CREATE SCHEMA sh;
CREATE TABLE sh.users (id bigint PRIMARY KEY);
CREATE TABLE sh.nodes (id bigint PRIMARY KEY, parent_id bigint, owner_id bigint, sealed boolean NOT NULL DEFAULT false);
CREATE INDEX ON sh.nodes (parent_id);
INSERT INTO sh.users VALUES (1), (2), (3);
DO $r$ BEGIN CREATE ROLE app_user NOLOGIN; EXCEPTION WHEN duplicate_object OR unique_violation THEN NULL; END $r$;
GRANT USAGE ON SCHEMA sh TO app_user;
GRANT SELECT ON ALL TABLES IN SCHEMA sh TO app_user;
"""
SHOWN_RESET = f"""
DELETE FROM authz.shares;
DELETE FROM sh.nodes;
INSERT INTO sh.nodes (id, parent_id, owner_id) VALUES
  ({R}, NULL, 1), ({A}, {R}, 2), ({B}, {R}, NULL), ({C}, {A}, NULL), ({L}, {B}, 3), ({X_X}, NULL, 3),
  ({X_Y}, NULL, 2);
INSERT INTO authz.shares (object_type, object_id, relation, subject_type, subject_id)
  VALUES ('node', '{C}', 'via', 'node', '{B}'), ('node', '{L}', 'via', 'node', '{A}');
"""
SHOWN_ROWS = """SELECT json_build_array(
  (SELECT json_agg(json_build_array(id, parent_id, owner_id, sealed) ORDER BY id) FROM sh.nodes),
  (SELECT json_agg(json_build_array(object_type, object_id, relation, subject_type, subject_id)
                   ORDER BY object_type, object_id, relation, subject_type, subject_id) FROM authz.shares))::text"""
SHOWN_LOOPS = """WITH RECURSIVE up(start, id) AS (
  SELECT id, parent_id FROM sh.nodes WHERE parent_id IS NOT NULL
  UNION
  SELECT up.start, n.parent_id FROM up JOIN sh.nodes n ON n.id = up.id WHERE n.parent_id IS NOT NULL)
SELECT coalesce(string_agg(DISTINCT start::text, ', '), '') FROM up WHERE start = id"""


def shown_op(kind: str, s: int) -> Op:
    """Session s's write of a kind: the first session's create puts a node under c, the second's under l. The two
    moves cross (l under c, c under l: a loop), as do the two shows (l shown in c by carol, who owns it; c shown in
    l by bob, who edits it through a: a loop through shares, which is allowed). The hides take l out of a and c out
    of b. The first session seals c, which bob then may not show or hide; the second seals l. The moves aside
    take x into a and y into b: nothing is below either, and no other write is of x, of y, or hangs anything
    under a or b that falls on their lock rows (the ids are chosen so: a row hung under a node updates one of
    four lock rows of that node, by the hung row's id), so a move aside and another write never wait for each
    other."""
    first = s == 1
    # bob edits c through a, unless c is sealed: then he may neither show it nor hide it
    no_show = refusal("42501", f"you cannot share node {C}", "seal")
    no_hide = refusal("42501", f"you cannot unshare via on node {C}", "seal")
    match kind:
        case "create":
            new, parent = (1010, C) if first else (1011, L)
            return Op(kind, f"INSERT INTO sh.nodes (id, parent_id) VALUES ({new}, {parent})", "")
        case "move":
            moved, parent = (L, C) if first else (C, L)
            loop = refusal("23514", "cannot be moved inside itself", "move")
            return Op(kind, f"UPDATE sh.nodes SET parent_id = {parent} WHERE id = {moved}", "", (loop,))
        case "aside":
            moved, parent = (X_X, A) if first else (X_Y, B)
            return Op(kind, f"UPDATE sh.nodes SET parent_id = {parent} WHERE id = {moved}", "")
        case "show":
            node, into, who = (L, C, "3") if first else (C, L, "2")
            return Op(
                kind, f"SELECT authz.share('node', {node}, 'via', 'node', {into})", who, () if first else (no_show,)
            )
        case "hide":
            node, out_of, who = (L, A, "3") if first else (C, B, "2")
            sql = f"SELECT authz.unshare('node', {node}, 'via', 'node', {out_of})"
            return Op(kind, sql, who, () if first else (no_hide,))
        case _:
            assert kind == "seal", kind
            return Op(kind, f"UPDATE sh.nodes SET sealed = true WHERE id = {C if first else L}", "")


SHOWN = World(
    name="shown",
    policy=("shown.authz", SHOWN_POLICY),
    schema=(),
    setup=SHOWN_SETUP,
    reset=SHOWN_RESET,
    rows=SHOWN_ROWS,
    loops=SHOWN_LOOPS,
    orphans="",  # no write deletes a node
    read="SELECT count(*) FROM sh.users",
    users=("1", "2", "3"),
    perms=(("node", "view"), ("node", "edit")),
    kinds=("create", "move", "aside", "seal", "show", "hide"),
    op=shown_op,
    # the two creates are under c and under l, with nothing below either new node; the two hides take l out of a
    # and c out of b; the two seals are of c and of l: in each pair neither node is above the other. A move aside
    # is to a part no other write is of: beside a create, a move (the first session's, of l into c: it leaves b,
    # which y goes into), a seal, a show or a hide, and beside the other move aside
    apart=frozenset(
        {
            ("create", "create"),
            ("hide", "hide"),
            ("seal", "seal"),
            ("create", "aside"),
            ("move", "aside"),
            ("aside", "aside"),
            ("aside", "seal"),
            ("aside", "show"),
            ("aside", "hide"),
        }
    ),
)
# The shown world where the seal stops a node's view coming down, not its edit: a seal is then a write to the
# second tree alone (through parent and via), which the type's trigger runs after the first. The first tree's
# refresh, with none of its own rows to write, still takes the lock rows of the rows sealed, for both: a seal beside
# a move asks for them as a move does. (Bob still edits c through a once it is sealed: his show and hide go through)
SHOWN_SECOND = replace(
    SHOWN,
    name="shown_second",
    policy=(
        "shown_second.authz",
        SHOWN_POLICY.replace(
            "  can edit = owner or (parent.edit and {not sealed})\n", "  can edit = owner or parent.edit\n"
        ).replace(
            "  can view = edit or parent.view or via.view\n",
            "  can view = edit or (parent.view and {not sealed}) or via.view\n",
        ),
    ),
)
assert SHOWN_SECOND.policy[1].count("sealed") == 1 and "(parent.view and {not sealed})" in SHOWN_SECOND.policy[1]
WORLDS = {
    w.name: w for w in (DOCS, CROSS, PARTS, BOXES, DOCS_BY, DOCS_AFTER, DOCS_PLAIN, DOCS_FEW, SHOWN, SHOWN_SECOND)
}


class Outcome(NamedTuple):
    tag: str  # the last statement's, in the server's words (COMMIT, ROLLBACK, INSERT 0 1)
    code: str  # the error's SQLSTATE, or ''
    message: str
    at: float = 0.0  # when the answer came (time.monotonic())


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
            self.outcome = out._replace(at=time.monotonic())
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
    sent: dict[tuple[int, str], float] = field(default_factory=dict)  # when each step was sent (time.monotonic())
    waited: bool = False
    waiting: set[int] = field(default_factory=set)  # the sessions whose step waits for a lock
    order: list[int] = field(default_factory=list)  # the session of each step, in the order sent
    problems: list[str] = field(default_factory=list)
    rows: str = ""
    committed: frozenset[int] = frozenset()

    def text(self) -> str:
        return " ".join(self.events)


class Scheduler:
    def __init__(self, world: World, db: str, deadlock_timeout: float) -> None:
        self.world, self.db = world, db
        self.owner = pgwire.connect(**pgwire.parse_dsn(f"dbname={db}"))
        self.sessions = [Session(1, db), Session(2, db)]
        self.stuck = deadlock_timeout + STUCK
        self.ref = Reference(compile_policy.parse_policy(world.policy[1], world.policy[0]))
        queries = self.ref.data_queries()
        self.data_keys = [k for k, _ in queries]
        self.data_sql = "SELECT json_build_array({})".format(", ".join(f"({sql})" for _, sql in queries))
        self.answers_sql = world.answers_sql()
        # every tree's rebuild, to start again from exact trees after a schedule that left them wrong
        rebuilds = self.owner.query(
            "SELECT p.oid::regproc::text FROM pg_proc p WHERE p.pronamespace = 'authz_int'::regnamespace "
            "AND p.proname LIKE '%\\_\\_tree\\_rebuild' ORDER BY 1"
        )
        self.rebuild = "SELECT " + ", ".join(f"{r[0]}()" for r in rebuilds)
        self.owner.script(world.reset)
        self.initial = str(self.owner.query(world.rows)[0][0])
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
        self.owner.script(self.world.reset)
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
                    ("read", [f"BEGIN ISOLATION LEVEL {level}", self.world.read]),
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
                run.sent[(s.n, step)] = time.monotonic()
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
            self.owner.script(self.rebuild)
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
            # the other write causes a refusal only once it is there to see: committed, its COMMIT sent before the
            # refusal came (Postgres shows no write before its commit)
            seen = (3 - n) in run.committed and run.sent[(3 - n, "commit")] < out.at
            met = [
                r
                for r in (o.refusals if step == "write" and o is not None and other is not None and seen else ())
                if r.code == out.code and r.words in out.message and other is not None and other.kind in r.by
            ]
            if met:
                self.refused[f"{met[0].code} {met[0].words}"] = self.refused.get(f"{met[0].code} {met[0].words}", 0) + 1
                continue
            run.problems.append(f"session {n}'s {step}: {out.code} {out.message}")
        if self.owner.query("SELECT authz.verify()") != [(True,)]:
            run.problems.append("the inheritance tables don't match a rebuild")
            self.owner.script(self.rebuild)
        if "\nsync after commit\n" in self.world.policy[1]:
            self.owner.query("SELECT authz.sync_work()")
        if "\nsync role " in self.world.policy[1] and self.owner.query("SELECT authz.sync_verify()") != [(True,)]:
            run.problems.append("the sync index doesn't match a rebuild")
            self.owner.script("SELECT authz_int.sync_refresh(NULL, true)")
        loops = str(self.owner.query(self.world.loops)[0][0])
        if loops:
            run.problems.append(f"rows inside themselves: {loops}")
        orphans = str(self.owner.query(self.world.orphans)[0][0]) if self.world.orphans else ""
        if orphans:
            run.problems.append(f"shares left on rows that aren't there: {orphans}")
        run.rows = str(self.owner.query(self.world.rows)[0][0])
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
            for u in self.world.users:
                self.owner.query("SELECT set_config('authz.user_id', $1, false)", [u])
                got = self.owner.query(self.answers_sql)[0][0]
                assert isinstance(got, list), got
                state = self.ref.evaluate(data, u)
                for (t, p), ids in zip(self.world.perms, got, strict=True):
                    assert isinstance(ids, list), ids
                    db, want = {str(i) for i in ids}, self.ref.answers(state, self.ref.types[t], p)
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


def together(runs: Sequence[Run], steps: Sequence[str]) -> list[str]:
    """Two writes to different parts of a tree, in every order: the schedules in which one waited for the other, or
    failed on what the other wrote, at one of the steps judged. The write: a tree's locks are taken there. The
    commit too, in a world that keeps nothing at commit (where the sync index is kept then, under lock rows of its
    own, which a stricter level takes all of, a commit may wait or fail). Two SERIALIZABLE transactions may still
    fail by that level's own check, which sees that both read and wrote one table: its words are others."""
    problems: list[str] = []
    for run in runs:
        for n, step in itertools.product((1, 2), steps):
            if f"{n} {step} (waits)" in run.events:
                problems.append(f"{run.text()}: session {n}'s {step} waited for a write to another part of the tree")
            out = run.outcomes.get((n, step))
            if out and (out.code == "40P01" or (out.code == "40001" and "concurrent update" in out.message)):
                problems.append(
                    f"{run.text()}: session {n}'s {step} failed on a write to another part of the tree: {out.code} "
                    f"{out.message}"
                )
    return problems


def setup(world: World, db: str) -> float:
    """A database with the world's tables and its policy; returns the server's deadlock_timeout, in seconds."""
    subprocess.run(["dropdb", "--if-exists", db], capture_output=True)
    subprocess.run(["createdb", db], check=True)
    env = {**os.environ, "PGOPTIONS": "-c client_min_messages=error"}
    psql = ["psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", "-d", db]
    for path in world.schema:
        subprocess.run([*psql, "-f", os.path.join(ROOT, path)], check=True, env=env)
    name, text = world.policy
    sql = Compiler(compile_policy.parse_policy(text, name)).compile(name)
    conn = pgwire.connect(**pgwire.parse_dsn(f"dbname={db}"))
    try:
        conn.script("SET client_min_messages = error;\n" + world.setup + "\n" + sql)
        ms = conn.query("SELECT setting::int FROM pg_settings WHERE name = 'deadlock_timeout'")[0][0]
    finally:
        conn.close()
    assert isinstance(ms, int), ms
    return ms / 1000


def interleave(world: World, db: str, pairs: Sequence[tuple[str, str]], chosen: Sequence[str]) -> int:
    """Every pair of the world's writes, in every order, at each pair of the levels: how many pairs failed."""
    sched = Scheduler(world, db, setup(world, db))
    fails = 0
    try:
        for levels in itertools.product(chosen, repeat=2):
            both = levels[0] if levels[0] == levels[1] else " and ".join(levels)
            n = waited = retried = deadlocks = refused = 0
            sched.judged.clear()
            level_started = time.monotonic()
            for k1, k2 in pairs:
                ops = [world.op(k1, 1), world.op(k2, 2)]
                runs = sched.every_order(levels, ops)
                problems = [f"{run.text()}: {p}" for run in runs for p in run.problems]
                if levels == ("serializable", "serializable"):
                    alone = {
                        1: sched.schedule(levels, [ops[0], None], []),
                        2: sched.schedule(levels, [None, ops[1]], []),
                    }
                    problems += [f"{alone[s].text()}: {p}" for s in alone for p in alone[s].problems]
                    problems += serial(runs, alone, sched.initial)
                if (k1, k2) in world.apart and "serializable" not in levels:
                    problems += together(runs, ("write",) if "\nsync role " in world.policy[1] else ("write", "commit"))
                n += len(runs)
                waited += sum(run.waited for run in runs)
                codes = [out.code for run in runs for out in run.outcomes.values()]
                retried += sum(c in RETRY for c in codes)
                deadlocks += codes.count("40P01")
                refused += sum(bool(c) and c not in RETRY for c in codes)
                what = f"{world.name}: {both}, {k1} and {k2}"
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
                f"info  {world.name}: {both}: {n} schedules over {len(pairs)} pairs in "
                f"{time.monotonic() - level_started:.0f}s; {waited} with a write waiting for the other, {retried} "
                f"retryable errors ({deadlocks} deadlocks), {refused} writes refused by the other's; "
                f"{len(sched.judged)} sets of rows left, each judged against the evaluator"
            )
    finally:
        for s in sched.sessions:
            s.close()
        sched.owner.close()
    subprocess.run(["dropdb", "--if-exists", db], capture_output=True)
    print(
        f"info  {world.name}: writes refused by the other's, by why: "
        + ("; ".join(f"{k} ({v})" for k, v in sorted(sched.refused.items())) or "none")
    )
    return fails


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--db", default="authz_interleave", help="the docs world's database; the others' add their name")
    ap.add_argument(
        "--levels", default=",".join(LEVELS), help="comma-separated isolation levels: each session at each of them"
    )
    ap.add_argument("--worlds", default=",".join(WORLDS), help="comma-separated worlds (default: all nine)")
    ap.add_argument("--pairs", default="", help="comma-separated pairs, as create-move (default: every one)")
    args = ap.parse_args()
    chosen = [x.strip() for x in args.levels.split(",") if x.strip()]
    for x in chosen:
        if x not in LEVELS:
            ap.error(f"no isolation level {x!r}: {', '.join(LEVELS)}")
    worlds = [x.strip() for x in args.worlds.split(",") if x.strip()]
    for x in worlds:
        if x not in WORLDS:
            ap.error(f"no world {x!r}: {', '.join(WORLDS)}")
    wanted = {tuple(p.strip().split("-")) for p in args.pairs.split(",") if p.strip()}
    known = {p for name in worlds for p in WORLDS[name].pairs()}
    for p in sorted(wanted):
        if p not in known and p[::-1] not in known:
            ap.error(f"no pair {'-'.join(p)!r} in the worlds {', '.join(worlds)}: each is two of a world's kinds")
    started = time.monotonic()
    fails = 0
    for name in worlds:
        world = WORLDS[name]
        pairs = [p for p in world.pairs() if not wanted or p in wanted or p[::-1] in wanted]
        if pairs:
            fails += interleave(world, args.db if name == "docs" else f"{args.db}_{name}", pairs, chosen)
    print(f"info  {time.monotonic() - started:.0f}s in all")
    if fails:
        print(f"interleave: {fails} failed")
        sys.exit(1)
    print("interleave: all passed")


if __name__ == "__main__":
    main()
