#!/usr/bin/env python3
"""confidence_test: rowstile prove, test --coverage, snapshot, indexes, plans and bench, on the docs example; and
the plans of lookups through keys of two columns (tests/composite.authz); and that a list runs each starting point of a
permission once, on a random policy (genpolicy's seed 3).

PGHOST=... PGUSER=... python3 tests/confidence_test.py [--db authz_confidence]
"""

import json
import os
import re
import subprocess
import sys
import tempfile
from collections.abc import Callable
from typing import TypeVar
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "cli"))
sys.path.insert(0, HERE)
import pgwire  # noqa: E402
import rowstile_cli  # noqa: E402
from authzlib import database, perf  # noqa: E402
from authzlib.connection import Db, Value  # noqa: E402

T = TypeVar("T")

fails = 0

TESTS = """test "an owner edits their folder, a stranger doesn't"
  given ann  = {INSERT INTO app.users (id, name) VALUES (901, 'ann') RETURNING id}
  given bo   = {INSERT INTO app.users (id, name) VALUES (902, 'bo') RETURNING id}
  given acme = {INSERT INTO app.orgs (id, name) VALUES (901, 'Acme') RETURNING id}
  given f    = {INSERT INTO app.folders (org_id, owner_id, name) VALUES ($acme, $ann, 'F') RETURNING id}
  user $ann can edit folder $f
  user $bo cannot view folder $f
"""

# a deny inside inheritance: view is compiled as a hidden permission (its `or` part) and the deny on it
DENY_SCHEMA = """CREATE SCHEMA app;
CREATE TABLE app.users (id bigint PRIMARY KEY);
CREATE TABLE app.folders (id bigint PRIMARY KEY, parent_id bigint REFERENCES app.folders, owner_id bigint, viewer_id bigint,
                          blocked boolean NOT NULL DEFAULT false);
GRANT USAGE ON SCHEMA app TO app_user;
GRANT SELECT ON ALL TABLES IN SCHEMA app TO app_user;
"""
DENY_POLICY = """app role app_user
type user = app.users
type folder = app.folders
  parent : folder = parent_id
  owner  : user   = owner_id
  viewer : user   = viewer_id
  can hidden = {blocked} or parent.hidden
  can view   = (owner or viewer or parent.view) and not hidden
  can see    = signed_in
"""
# a table that holds only its key and its owner
TAGS_SCHEMA = """CREATE SCHEMA app;
CREATE TABLE app.users (id bigint PRIMARY KEY);
CREATE TABLE app.tags (id bigint PRIMARY KEY, owner_id bigint NOT NULL REFERENCES app.users);
CREATE INDEX ON app.tags (owner_id);
GRANT USAGE ON SCHEMA app TO app_user;
GRANT SELECT, UPDATE ON ALL TABLES IN SCHEMA app TO app_user;
INSERT INTO app.users VALUES (1), (2);
INSERT INTO app.tags VALUES (1, 1), (2, 2);
"""
TAGS_POLICY = """app role app_user
type user = app.users
type tag = app.tags
  owner : user = owner_id
  can edit = owner
rules app.tags
  select : edit
  update : edit
  update owner_id : nobody
"""
# tests/composite_schema.sql's tables, a few thousand rows: users in teams, teams in teams, folders in folders and
# in projects, files in folders (each row in the org of what it points at)
KEYS_ROWS = """INSERT INTO cx.orgs SELECT i FROM generate_series(1, 5) i;
INSERT INTO cx.users SELECT i, NULL FROM generate_series(1, 500) i;
INSERT INTO cx.teams (org_id, slug, lead_id) SELECT i % 5 + 1, 't' || i, i % 500 + 1 FROM generate_series(1, 500) i;
INSERT INTO cx.team_members SELECT org_id, slug, (substr(slug, 2)::int * 3) % 500 + 1 FROM cx.teams;
INSERT INTO cx.projects SELECT i % 5 + 1, i, i % 500 + 1, NULL FROM generate_series(1, 200) i;
INSERT INTO cx.folders SELECT i % 5 + 1, i, i % 500 + 1, NULL, NULL FROM generate_series(1, 2000) i;
UPDATE cx.folders SET parent_type = 'folder', parent_id = id - 5 WHERE id > 50 AND id % 3 = 0;
UPDATE cx.folders SET parent_type = 'project', parent_id = id % 200 WHERE id > 50 AND id % 3 = 1 AND id % 200 > 0;
INSERT INTO cx.folder_teams SELECT f.org_id, f.id, 't' || (f.id % 500) FROM cx.folders f WHERE f.id % 4 = 0 AND f.id % 500 > 0;
INSERT INTO cx.files SELECT ((i % 2000) + 1) % 5 + 1, i, (i % 2000) + 1, i % 500 + 1, NULL FROM generate_series(1, 4000) i;
ANALYZE cx.users, cx.teams, cx.team_members, cx.projects, cx.folders, cx.folder_teams, cx.files;
"""
# tests/cross_schema.sql's tables, a few thousand rows: folders in projects (the first 200), in folders (those whose
# id over ten is above 200) or in nothing, and backings by the folders not in projects (so that nothing loops back
# through them) and by regions, and the index on the backings' (type, id) pair
PAIRS_ROWS = """INSERT INTO cx.users SELECT i, 'u' || i FROM generate_series(1, 500) i;
INSERT INTO cx.projects SELECT i, i % 500 + 1 FROM generate_series(1, 200) i;
INSERT INTO cx.regions SELECT i, i % 500 + 1 FROM generate_series(1, 20) i;
INSERT INTO cx.folders (id, parent_type, parent_id, owner_id)
  SELECT i, CASE WHEN i <= 200 THEN 'project' WHEN i / 10 > 200 THEN 'folder' END,
         CASE WHEN i <= 200 THEN i WHEN i / 10 > 200 THEN i / 10 END, i % 500 + 1 FROM generate_series(1, 4000) i;
INSERT INTO cx.backings SELECT i % 200 + 1, 'folder', i FROM generate_series(201, 4000) i;
INSERT INTO cx.backings SELECT i % 200 + 1, 'region', i FROM generate_series(1, 20) i;
CREATE INDEX ON cx.backings (backer_type, backer_id);
ANALYZE cx.users, cx.projects, cx.regions, cx.folders, cx.backings;
"""
DENY_TESTS = """test "the owner"
  given u = {INSERT INTO app.users VALUES (1) RETURNING id}
  given f = {INSERT INTO app.folders (id, owner_id) VALUES (1, $u) RETURNING id}
  given g = {INSERT INTO app.folders (id, parent_id) VALUES (2, $f) RETURNING id}
  user $u can view folder $f
"""


def check(label: str, ok: object, detail: object = "") -> None:
    global fails
    if ok:
        print(f"ok    {label}")
    else:
        fails += 1
        print(f"FAIL  {label}{': ' + str(detail)[:800] if detail else ''}")


def cli(db: str | None, *args: str, cwd: str | None = None) -> tuple[int, str]:
    r = subprocess.run(
        [
            sys.executable,
            os.path.join(ROOT, "cli", "rowstile_cli.py"),
            *(["--db", f"dbname={db}"] if db else []),
            *args,
        ],
        capture_output=True,
        text=True,
        cwd=cwd,
    )
    return r.returncode, r.stdout + r.stderr


def plan_scans(raw: Value) -> list[tuple[str, str]]:
    """(node, index or table) of each scan in a plan (EXPLAIN's JSON)."""
    found: list[tuple[str, str]] = []

    def walk(node: Value) -> None:
        if isinstance(node, dict):
            kind, where = node.get("Node Type"), node.get("Index Name") or node.get("Relation Name")
            if isinstance(kind, str) and "Scan" in kind and isinstance(where, str):
                found.append((kind, where))
            for child in node.values():
                walk(child)
        elif isinstance(node, list):
            for child in node:
                walk(child)

    walk(json.loads(raw) if isinstance(raw, str) else raw)
    return found


def index_conds(raw: Value) -> list[tuple[str, str]]:
    """(index, its condition) of each scan through an index in a plan (EXPLAIN's JSON)."""
    found: list[tuple[str, str]] = []

    def walk(node: Value) -> None:
        if isinstance(node, dict):
            index, cond = node.get("Index Name"), node.get("Index Cond")
            if isinstance(index, str) and isinstance(cond, str):
                found.append((index, cond))
            for child in node.values():
                walk(child)
        elif isinstance(node, list):
            for child in node:
                walk(child)

    walk(json.loads(raw) if isinstance(raw, str) else raw)
    return found


def main() -> None:
    db = sys.argv[sys.argv.index("--db") + 1] if "--db" in sys.argv else "authz_confidence"
    subprocess.run(["dropdb", "--if-exists", db], capture_output=True)
    subprocess.run(["createdb", db], check=True)
    subprocess.run(
        ["psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", "-d", db, "-f", os.path.join(ROOT, "example", "app_schema.sql")],
        check=True,
        capture_output=True,
    )
    policy = os.path.join(ROOT, "example", "docs.authz")
    # the policy without its test section (it needs the scenario's data): coverage counts this file's tests only
    with open(policy, encoding="utf-8") as fh:
        bare = re.sub(r"\ntest\n(  .*\n)+", "\n", fh.read())
    tmp_policy = os.path.join(tempfile.mkdtemp(), "docs.authz")
    with open(tmp_policy, "w", encoding="utf-8") as fh:
        fh.write(bare)
    rc, out = cli(db, "apply", tmp_policy)
    if rc:
        raise SystemExit(out)
    conn = pgwire.connect(**pgwire.parse_dsn(f"dbname={db}"))

    def work(fn: Callable[[Db], T], keep: bool = False) -> T:
        return rowstile_cli.transaction(conn, fn, keep=keep)

    print("-- rowstile prove")
    rc, out = cli(None, "prove", policy)
    check(
        "an invariant the policy doesn't guarantee: exit 1, and the smallest counterexample",
        rc == 1 and "no   user 1 holds it on folder 1" in out and "folder.owner: folder 1 -> user 1" in out,
        out,
    )
    with tempfile.TemporaryDirectory() as tmp:
        ok = os.path.join(tmp, "p.authz")
        with open(policy, encoding="utf-8") as fh:
            text = fh.read()
        with open(ok, "w", encoding="utf-8") as fh:
            fh.write(text.replace("never folder: share and not org.member", "never folder: edit and not view"))
        rc, out = cli(None, "prove", ok, "--worlds", "60")
        # the 60 drawn, and the corners (each condition true on every row or none) 3 times at each of the 4 sizes
        tried = re.search(r"ok   holds in every world tried \((\d+) worlds", out)
        check("one it does: exit 0", rc == 0 and tried is not None and (int(tried.group(1)) - 60) % 12 == 0, out)
        with open(ok, "w", encoding="utf-8") as fh:
            fh.write(
                text.replace(
                    "can view  = edit or viewer or (parent.view and {inherit})",
                    "can view  = edit or viewer or (parnt.view and {inherit})",
                )
            )
        rc, out = cli(None, "prove", ok)
        check(
            "a policy check refuses: its message, line and code, no traceback",
            rc == 1 and "[AZ" in out and "line " in out and "Traceback" not in out,
            out,
        )
        rc, out = cli(None, "prove", ok, "--worlds", "abc")
        check(
            "--worlds that isn't a number: a usage error",
            rc == 2 and "--worlds needs a whole number" in out and "Traceback" not in out,
            out,
        )

    print("-- coverage")
    rows, report = work(lambda d: database.coverage(d, {"t.authz": TESTS}))
    check("the tests pass", rows and all(r[2] for r in rows), rows)
    missing = {(name, item) for _, name, item in report["missing"]}
    check(
        "the branches a passing check made true are covered",
        ("folder.edit", "share") not in missing and ("folder.share", "owner") not in missing,
        report,
    )
    check(
        "... and those none did are named, with their lines",
        ("folder.edit", "editor") in missing and all(line.startswith("line ") for line, _, _ in report["missing"]),
        report,
    )
    check("a check that someone cannot adds nothing", ("folder.view", "viewer") in missing, report)
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "t.authz")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(TESTS)
        rc, out = cli(db, "test", "--coverage", path)
        check(
            "rowstile test --coverage",
            rc == 0 and "coverage: " in out and 'branches made true by a test; no "can" check reaches:' in out,
            out,
        )

    with tempfile.TemporaryDirectory() as tmp:
        subprocess.run(["dropdb", "--if-exists", db + "_deny"], capture_output=True)
        subprocess.run(["createdb", db + "_deny"], check=True)
        subprocess.run(
            ["psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", "-d", db + "_deny", "-c", DENY_SCHEMA],
            check=True,
            capture_output=True,
        )
        pol, tests = os.path.join(tmp, "p.authz"), os.path.join(tmp, "t.authz")
        for path, text in ((pol, DENY_POLICY), (tests, DENY_TESTS)):
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(text)
        rc, out = cli(db + "_deny", "apply", pol)
        rc, out = cli(db + "_deny", "test", "--coverage", tests) if rc == 0 else (rc, out)
        check(
            "a deny inside inheritance: the branches are those of its `or` part, in the policy's words",
            rc == 0
            and "coverage: 1 of 6 branches" in out
            and "folder.view: owner" not in out
            and all(x in out for x in ("folder.view: viewer", "folder.view: parent.view", "folder.see: signed_in")),
            out,
        )
        with open(tests, "a", encoding="utf-8") as fh:
            fh.write("  user $u can view folder $g\n")
        rc, out = cli(db + "_deny", "test", "--coverage", tests)
        check(
            "... and the inherited one is covered by a check on what is below",
            rc == 0 and "coverage: 2 of 6 branches" in out and "folder.view: parent.view" not in out,
            out,
        )
        # a policy without rules, on tables without rows: plans has no app role to read as; bench lists, as
        # nobody signed in, and checks nothing on a type that has no row
        rc, out = cli(db + "_deny", "plans")
        check(
            "rowstile plans with no rules applied: no app role to read as, exit 1",
            rc == 1 and out == "no policy with rules is applied, so there is no app role to read as\n",
            out,
        )
        rc, out = cli(db + "_deny", "bench", "--people", "1", "--rounds", "1")
        check(
            "rowstile bench with no rows: lists only, as nobody signed in",
            rc == 0
            and out.startswith("1 rounds as 1 people")
            and "  authz.list folder view " in out
            and "authz.can" not in out
            and "read " not in out,
            out,
        )
        subprocess.run(["dropdb", "--if-exists", db + "_deny"], capture_output=True)

    print("-- snapshot")
    lines = work(database.snapshot)
    check(
        "who holds what, one sorted line per object and permission",
        lines and all(": " in x for x in lines) and any(x.startswith("folder 1 view: ") for x in lines),
        lines[:5],
    )
    try:
        work(lambda d: database.snapshot(d, limit=3))
        refused = ""
    except database.Error as e:
        refused = str(e)
    check(
        "more people in the data than a snapshot is for: refused, saying how many",
        re.fullmatch(r"\d+ people and principals: a snapshot is for small review data \(at most 3\)", refused),
        refused,
    )
    with tempfile.TemporaryDirectory() as tmp:
        snap = os.path.join(tmp, "access.snapshot")
        rc, out = cli(db, "snapshot", "--out", snap)
        rc2, out2 = cli(db, "snapshot", "--check", "--out", snap)
        check(
            "rowstile snapshot writes it, and --check finds it up to date",
            rc == 0 and rc2 == 0 and "up to date" in out2,
            out + out2,
        )
        subprocess.run(
            [
                "psql",
                "-X",
                "-q",
                "-d",
                db,
                "-c",
                "BEGIN; SELECT authz.act_as('user', '5'); SELECT authz.share('folder', '2', 'editor', 'user', '6'); COMMIT",
            ],
            capture_output=True,
            check=True,
        )
        rc, out = cli(db, "snapshot", "--check", "--out", snap)
        check(
            "... a change of access makes it out of date, and says what changed",
            rc == 1 and "+ folder 2 edit: 5, 6" in out,
            out,
        )

    print("-- indexes")
    check(
        "the example's tables have every index the policy needs",
        work(lambda d: perf.missing_indexes(d, database.policy_compiler(*database.applied(d)))) == [],
    )

    def without(d: Db) -> list[perf.Missing]:
        d.script("DROP INDEX app.team_members_user_id_idx")
        return perf.missing_indexes(d, database.policy_compiler(*database.applied(d)))

    missing = work(without)
    check(
        "a dropped index is named, with why",
        [(m[0], m[1]) for m in missing] == [("app.team_members", ("user_id",))] and "team.member" in missing[0][2],
        missing,
    )
    check(
        "... and the line to add, for the app's tool",
        perf.advice("app.team_members", ("user_id",), "prisma").startswith("@@index([user_id])")
        and perf.advice("app.team_members", ("user_id",), "sql").startswith("CREATE INDEX CONCURRENTLY"),
    )

    def behind_an_expression(d: Db) -> list[perf.Missing]:
        d.script(
            "DROP INDEX app.team_members_user_id_idx; "
            "CREATE INDEX team_members_expr ON app.team_members ((team_id + 0), user_id)"
        )
        return perf.missing_indexes(d, database.policy_compiler(*database.applied(d)))

    check(
        "an index that starts with an expression serves no lookup by its later columns",
        [(m[0], m[1]) for m in work(behind_an_expression)] == [("app.team_members", ("user_id",))],
    )

    def partial(d: Db) -> list[perf.Missing]:
        # the policy's lookups are joins, which an index with a condition doesn't serve (Postgres scans the table)
        d.script(
            "DROP INDEX app.team_members_user_id_idx; "
            "CREATE INDEX team_members_some ON app.team_members (user_id) WHERE user_id > 0"
        )
        return perf.missing_indexes(d, database.policy_compiler(*database.applied(d)))

    check(
        "an index with a condition (a partial one) serves no lookup",
        [(m[0], m[1]) for m in work(partial)] == [("app.team_members", ("user_id",))],
    )
    # nor does one a failed CREATE INDEX CONCURRENTLY left unfinished (here a unique one, on a duplicate)
    sql = lambda *s: subprocess.run(
        ["psql", "-X", "-q", "-d", db, *(x for c in s for x in ("-c", c))], capture_output=True
    )
    sql("DROP INDEX app.team_members_user_id_idx", "INSERT INTO app.team_members VALUES (11, 1)")
    sql("CREATE UNIQUE INDEX CONCURRENTLY team_members_user_id_idx ON app.team_members (user_id)")
    check(
        "... nor one a failed build left unfinished",
        [(m[0], m[1]) for m in work(lambda d: perf.missing_indexes(d, database.policy_compiler(*database.applied(d))))]
        == [("app.team_members", ("user_id",))],
    )
    # ...which holds the name the line to add gives it: dropped first, or that line fails ("already exists")
    rc, out = cli(db, "indexes")
    check(
        "... and the line to add says to drop it first",
        "\n  first, drop what a CREATE INDEX CONCURRENTLY that failed left unfinished: DROP INDEX CONCURRENTLY "
        'app.team_members_user_id_idx;\n  add: CREATE INDEX CONCURRENTLY "team_members_user_id_idx" ON '
        '"app"."team_members" ("user_id");' in out,
        out,
    )
    sql(
        "DROP INDEX app.team_members_user_id_idx",
        "DELETE FROM app.team_members WHERE (team_id, user_id) = (11, 1)",
        "CREATE INDEX team_members_user_id_idx ON app.team_members (user_id)",
    )

    def capitals(d: Db) -> list[tuple[str, ...]]:
        # names with capital letters, as Prisma writes them: the table is looked up by its quoted name
        d.script(
            'CREATE TABLE app."TeamMember" ("teamId" bigint, "userId" bigint, PRIMARY KEY ("teamId", "userId")); '
            'CREATE INDEX ON app."TeamMember" ("userId")'
        )
        return sorted(perf.table_indexes(d, "app.TeamMember"))

    check(
        "a table whose name has capital letters: its indexes are found",
        work(capitals) == [("teamId", "userId"), ("userId",)],
    )

    def through_a_view(d: Db) -> list[perf.Missing]:
        # team members read through a view, and the folders' owner index gone: a view can't have an index (the
        # tables under it answer its lookups), so only the table is named
        d.script(
            "CREATE VIEW app.team_members_v AS SELECT team_id, user_id FROM app.team_members; "
            "DROP INDEX app.folders_owner_id_idx"
        )
        text, files = database.applied(d)
        policy = text.replace("app.team_members(team_id -> user_id)", "app.team_members_v(team_id -> user_id)")
        return perf.missing_indexes(d, database.policy_compiler(policy, files))

    found = work(through_a_view)
    check(
        "a relation read from a view: no index asked of the view, the table's still named",
        [(m[0], m[1]) for m in found] == [("app.folders", ("owner_id",))],
        found,
    )

    def partitioned(d: Db) -> tuple[str, str, list[perf.Missing]]:
        # a governed table may be partitioned: Postgres makes no index on it concurrently, so the line to add says
        # CREATE INDEX alone there; made, it serves the lookup
        d.script(
            "CREATE TABLE app.events (id bigint, owner_id bigint, at date NOT NULL, PRIMARY KEY (id, at)) "
            "PARTITION BY RANGE (at); "
            "CREATE TABLE app.events_2026 PARTITION OF app.events FOR VALUES FROM ('2026-01-01') TO ('2027-01-01')"
        )
        text, files = database.applied(d)
        c = database.policy_compiler(
            text + "\ntype event = app.events\n  owner : user = owner_id\n  can view = owner\n", files
        )
        said = perf.describe_missing(perf.missing_indexes(d, c), "sql")
        refused = ""
        try:
            with database.savepoint(d, "authz_index"):
                d.script(said.partition("\n  add: ")[2])
        except d.errors as e:
            refused = str(getattr(e, "message", e))
        return said, refused, perf.missing_indexes(d, c)

    said, refused, after = work(partitioned)
    check(
        "a partitioned table: the index to add without CONCURRENTLY, which Postgres refuses there; made, it serves",
        re.fullmatch(
            r"app\.events has no index on \(owner_id\): finding the events by their event\.owner \(lists, select "
            r'rules\) \(line \d+\)\n  add: CREATE INDEX "events_owner_id_idx" ON "app"\."events" \("owner_id"\);',
            said,
        )
        is not None
        and (refused, after) == ("", [])
        # (no transaction to leave either, for goose: Postgres builds it inside one)
        and perf.advice("app.events", ("owner_id",), "goose", True)
        == 'CREATE INDEX "events_owner_id_idx" ON "app"."events" ("owner_id");',
        (said, refused, after),
    )

    def keyed_by_its_user(d: Db) -> tuple[list[perf.Missing], list[perf.Missing]]:
        # a table keyed by its user's id, and a relation that reads that key: lists find the profiles by it, a lookup
        # like any other (authz.lint() names it too), which its primary key serves, and without one nothing does
        d.script("CREATE TABLE app.profiles (user_id bigint NOT NULL, bio text)")
        text, files = database.applied(d)
        c = database.policy_compiler(
            text + "\ntype profile = app.profiles (user_id)\n  owner : user = user_id\n  can edit = owner\n", files
        )
        no_key = perf.missing_indexes(d, c)
        d.script("ALTER TABLE app.profiles ADD PRIMARY KEY (user_id)")
        return no_key, perf.missing_indexes(d, c)

    no_key, with_key = work(keyed_by_its_user)
    check(
        "a relation that reads the row's own key: its lookup named while no index serves it, not once a primary key does",
        [(m[0], m[1]) for m in no_key] == [("app.profiles", ("user_id",))]
        and no_key[0][2] == "finding the profiles by their profile.owner (lists, select rules)"
        and with_key == [],
        (no_key, with_key),
    )

    def keyed_without_an_index(d: Db) -> tuple[str, list[perf.Missing], list[perf.Missing]]:
        # each check on one object (authz.can, a write rule) finds its row by the type's key: on a table with no
        # primary key, nor any index on the key, each check scans the table. Named like any other lookup, with the
        # line to add; an index whose first columns are the key's, in any order (a unique one here), serves it
        d.script(
            "CREATE TABLE app.labels (org_id bigint NOT NULL, name text NOT NULL, owner_id bigint); "
            "CREATE INDEX ON app.labels (owner_id)"
        )
        text, files = database.applied(d)
        c = database.policy_compiler(
            text + "\ntype label = app.labels (org_id, name text)\n  owner : user = owner_id\n  can edit = owner\n",
            files,
        )
        said = perf.describe_missing(perf.missing_indexes(d, c), "sql")
        found = perf.missing_indexes(d, c)
        d.script("CREATE UNIQUE INDEX ON app.labels (name, org_id)")
        return said, found, perf.missing_indexes(d, c)

    said, key_only, unique = work(keyed_without_an_index)
    check(
        "a type's key no index serves (a composite one): named, why, and the index to add; a unique index serves it",
        re.fullmatch(
            r"app\.labels has no index on \(org_id, name\): finding one label by its key \(checks, write rules\) "
            r'\(line \d+\)\n  add: CREATE INDEX CONCURRENTLY "labels_org_id_name_idx" ON "app"\."labels" '
            r'\("org_id", "name"\);',
            said,
        )
        is not None
        and len(key_only) == 1
        and unique == [],
        (said, key_only, unique),
    )
    # the line to add in the words of the tool rowstile.toml names, and --check exits 1 while a lookup has no index
    subprocess.run(["psql", "-X", "-q", "-d", db, "-c", "DROP INDEX app.team_members_user_id_idx"], check=True)
    with tempfile.TemporaryDirectory() as tmp:
        for tool, line in (
            ("drizzle", "index('team_members_user_id_idx').on(t.user_id) in the table for app.team_members"),
            (
                "alembic",
                "Index('team_members_user_id_idx', 'user_id') in app.team_members's model (or index=True on the "
                "column), then alembic revision --autogenerate",
            ),
            # goose and dbmate run a migration in a transaction, where Postgres builds no index concurrently
            (
                "goose",
                'CREATE INDEX CONCURRENTLY "team_members_user_id_idx" ON "app"."team_members" ("user_id"); in a '
                "migration of its own that starts with -- +goose NO TRANSACTION",
            ),
            (
                "dbmate",
                'CREATE INDEX CONCURRENTLY "team_members_user_id_idx" ON "app"."team_members" ("user_id"); in a '
                "migration of its own that starts with -- migrate:up transaction:false",
            ),
        ):
            with open(os.path.join(tmp, "rowstile.toml"), "w", encoding="utf-8") as fh:
                fh.write(f'[migrations]\ntool = "{tool}"\n')
            rc, out = cli(db, "indexes", "--check", cwd=tmp)
            check(
                f"rowstile indexes --check: the lookup with no index, the line to add for {tool}, exit 1",
                rc == 1
                and out.startswith("app.team_members has no index on (user_id): finding the teams by their team.member")
                and f"\n  add: {line}\n" in out,
                out,
            )
    subprocess.run(
        ["psql", "-X", "-q", "-d", db, "-c", "CREATE INDEX team_members_user_id_idx ON app.team_members (user_id)"],
        check=True,
    )

    print("-- plans and bench")
    p = work(lambda d: perf.plans(d, database.policy_compiler(*database.applied(d)), ("user", "1")))
    tables = {t["table"]: t for t in p["tables"]}
    check(
        "each governed table read as someone, with its time",
        set(tables) == {"app.folders", "app.files"}
        and all(t["ms"] is not None and t["ms"] >= 0 for t in tables.values()),
        p,
    )
    rc, out = cli(db, "plans", "--as", "user:1")
    check("rowstile plans", rc == 0 and "as user:1:" in out and "app.folders:" in out, out)
    check("no warning on the example's few rows", all(t["warnings"] == [] for t in tables.values()), p)
    rc, out = cli(db, "plans")
    check("without --as, as the first user in the data", rc == 0 and out.startswith("as user:1:\n"), out)

    def nobody(d: Db) -> perf.Plans:
        d.script("TRUNCATE app.users CASCADE")
        return perf.plans(d, database.policy_compiler(*database.applied(d)))

    alone = work(nobody)
    check("... and as anyone when there is no user", alone["as"] == "anyone" and len(alone["tables"]) == 2, alone)

    def unreadable(d: Db) -> perf.Plans:
        d.script("REVOKE SELECT ON app.files FROM app_user")
        return perf.plans(d, database.policy_compiler(*database.applied(d)), ("user", "1"))

    failed = {t["table"]: (t["ms"], t["rows"], t["warnings"]) for t in work(unreadable)["tables"]}
    check(
        "a table the app role may not read: the read failed, and why; the others are read",
        failed.get("app.files") == (None, None, ["failed: permission denied for table files"])
        and failed.get("app.folders", (None, None, []))[0] is not None,
        failed,
    )
    with mock.patch.object(perf, "SLOW_MS", -1):  # every read is slower than that
        slower = work(lambda d: perf.plans(d, database.policy_compiler(*database.applied(d)), ("user", "1")))
    check(
        "a read slower than the limit: its time is the first warning",
        all(t["warnings"] and re.fullmatch(r"took \d+(\.\d+)? ms", t["warnings"][0]) for t in slower["tables"]),
        slower,
    )

    def grown(d: Db) -> perf.Plans:
        # a link table grown past what a scan should read, and the index its lookup needs gone
        d.script(
            "INSERT INTO app.users (id, name) SELECT i, 'u' || i FROM generate_series(1000, 13000) i; "
            "INSERT INTO app.org_members SELECT 2, i, 'member' FROM generate_series(1000, 13000) i; "
            "DROP INDEX app.org_members_user_id_idx; ALTER TABLE app.org_members DROP CONSTRAINT org_members_pkey; "
            "ANALYZE app.org_members"
        )  # the key too: Postgres 18 can skip through (org_id, user_id)
        return perf.plans(d, database.policy_compiler(*database.applied(d)), ("user", "7"))

    slow = work(grown)
    check(
        "a scan that reads a big table and keeps little is named (a missing index)",
        any("reads all of app.org_members" in w for t in slow["tables"] for w in t["warnings"]),
        slow,
    )
    count: Callable[[], str] = lambda: subprocess.run(
        ["psql", "-X", "-At", "-d", db, "-c", "SELECT count(*), sum(length(name)) FROM app.folders"],
        capture_output=True,
        text=True,
    ).stdout.strip()
    before = count()
    b = work(lambda d: perf.bench(d, database.policy_compiler(*database.applied(d)), people=3, rounds=3))
    paths = {x["path"]: x for x in b["paths"]}
    check(
        "bench: reads, lists, checks and updates, p50 and p95",
        {"read app.folders", "authz.list folder view", "authz.can folder edit", "update app.folders"} <= set(paths)
        and all(x["p50"] is not None for x in paths.values()),
        b,
    )
    rc, out = cli(db, "bench", "--rounds", "2", "--people", "2")
    check("rowstile bench", rc == 0 and "p50" in out and "read app.files" in out, out)
    check("... and nothing it did stays", count() == before, (before, count()))
    # a table whose columns are all its key and what its relations read: nothing to write back unchanged, so no
    # update is timed
    subprocess.run(["dropdb", "--if-exists", db + "_tags"], capture_output=True)
    subprocess.run(["createdb", db + "_tags"], check=True)
    subprocess.run(["psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", "-d", db + "_tags", "-c", TAGS_SCHEMA], check=True)
    with tempfile.TemporaryDirectory() as tmp:
        with open(os.path.join(tmp, "p.authz"), "w", encoding="utf-8") as fh:
            fh.write(TAGS_POLICY)
        rc, out = cli(db + "_tags", "apply", os.path.join(tmp, "p.authz"))
        rc, out = cli(db + "_tags", "bench", "--people", "1", "--rounds", "1") if rc == 0 else (rc, out)
        check(
            "bench: no update timed on a table with no column to write back unchanged",
            rc == 0 and "  read app.tags " in out and "  authz.can tag edit " in out and "update" not in out,
            out,
        )
    subprocess.run(["dropdb", "--if-exists", db + "_tags"], capture_output=True)

    def bench_unreadable(d: Db) -> perf.Bench:
        d.script("REVOKE SELECT ON app.files FROM app_user")
        return perf.bench(d, database.policy_compiler(*database.applied(d)), people=1, rounds=1)

    b = work(bench_unreadable)
    ran = {x["path"]: (x["n"], x["p50"], x["failed"]) for x in b["paths"]}
    said = perf.describe_bench(b)
    check(
        "bench: a path that fails is there with why, not left out",
        ran.get("read app.files") == ran.get("update app.files") == (0, None, "permission denied for table files")
        and ran.get("read app.folders", (0, None, "missing"))[::2] == (1, None)
        and re.search(r"\n  read app\.files +- +-  <- failed: permission denied for table files\n", said) is not None,
        said,
    )

    print("-- lookups through keys of two columns")
    # tests/composite.authz's tables, a few thousand rows: a lookup through a key of two columns goes column by
    # column, so the index on the columns serves it. With sequential scans off, the plan takes the index; a key
    # compared as its row's text could only be read row by row
    keys = db + "_keys"
    subprocess.run(["dropdb", "--if-exists", keys], capture_output=True)
    subprocess.run(["createdb", keys], check=True)
    for sql in (["-f", os.path.join(HERE, "composite_schema.sql")], ["-c", KEYS_ROWS]):
        subprocess.run(["psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", "-d", keys, *sql], check=True, capture_output=True)
    rc, out = cli(keys, "apply", os.path.join(HERE, "composite.authz"))
    if rc:
        raise SystemExit(out)
    kconn = pgwire.connect(**pgwire.parse_dsn(f"dbname={keys}"))

    def scans(view: str) -> list[tuple[str, str]]:
        """(node, table or index) of each scan in the plan of a read of view, as the app role signed in as user 7."""

        def plan(d: Db) -> Value:
            d.rows("SELECT authz.act_as('user', '7')")
            d.script("SET LOCAL ROLE app_user; SET LOCAL enable_seqscan = off")
            return next(iter(d.rows(f'EXPLAIN (FORMAT JSON) SELECT count(*) FROM authz_gen."{view}"')[0].values()))

        return plan_scans(rowstile_cli.transaction(kconn, plan, keep=False))

    for view, table, index in (
        ("file__folder__edit", "files", "files_org_id_folder_id_idx"),  # files in the folders user 7 edits
        ("folder__editor", "folder_teams", "folder_teams_org_id_team_slug_idx"),  # folders of the teams 7 is in
        ("folder__parent__edit__on_project", "folders", "folders_org_id_parent_id_idx"),  # (type, [org_id, id])
    ):
        found = scans(view)
        check(
            f"{view}: {table} looked up through {index}, not read row by row",
            any(where == index for _, where in found) and ("Seq Scan", table) not in found,
            found,
        )

    def named(d: Db) -> tuple[set[str], set[str]]:
        """The lookups no index serves, as rowstile indexes names them and as authz.lint() does."""
        missing = perf.missing_indexes(d, database.policy_compiler(*database.applied(d)))
        linted = d.rows("SELECT object FROM authz.lint() WHERE problem LIKE 'no index starts with%'")
        return {f"{m[0]}.{', '.join(m[1])}" for m in missing}, {str(r["object"]) for r in linted}

    def without_it(d: Db) -> tuple[set[str], set[str]]:
        d.script("DROP INDEX cx.folders_org_id_parent_id_idx")
        return named(d)

    # a (type, [org_id, id]) pair is looked up by its three columns, and an index on the two ids serves it as well
    both = rowstile_cli.transaction(kconn, named, keep=False)
    gone = rowstile_cli.transaction(kconn, without_it, keep=False)
    check(
        "indexes and lint name the same lookups: a (type, id) pair served by an index on its ids, and named once it "
        "is gone, with its type",
        both[0] == both[1]
        and "cx.folders.parent_type, org_id, parent_id" not in both[0]
        and gone[0] == gone[1]
        and gone[0] - both[0] == {"cx.folders.parent_type, org_id, parent_id"},
        (both, gone),
    )
    # teams in teams with no shares among them: user 34, in t11 only, is a member of t6 above it and of t1 above
    # that, found a step at a time by the teams' key
    with tempfile.TemporaryDirectory() as tmp:
        with open(os.path.join(HERE, "composite.authz"), encoding="utf-8") as fh:
            text = fh.read().replace("  member : team#member  shared\n", "")
        with open(os.path.join(tmp, "p.authz"), "w", encoding="utf-8") as fh:
            fh.write(text)
        rc, out = cli(keys, "apply", os.path.join(tmp, "p.authz"))

    def nested(d: Db) -> tuple[list[str], list[tuple[str, str]]]:
        d.script(
            "UPDATE cx.teams SET parent_slug = 't1' WHERE slug = 't6'; UPDATE cx.teams SET parent_slug = 't6' WHERE slug = 't11'"
        )
        d.rows("SELECT authz.act_as('user', '34')")
        d.script("SET LOCAL ROLE app_user; SET LOCAL enable_seqscan = off")
        ids = sorted(str(r["id"]) for r in d.rows('SELECT id FROM authz_gen."team__member"'))
        return ids, plan_scans(
            next(iter(d.rows('EXPLAIN (FORMAT JSON) SELECT count(*) FROM authz_gen."team__member"')[0].values()))
        )

    ids, steps = rowstile_cli.transaction(kconn, nested, keep=False) if rc == 0 else ([], [])
    check(
        "teams in teams keyed by two columns: a sub-team's member is a member above it, found by the teams' key",
        ids == ["(2,t1)", "(2,t11)", "(2,t6)"]
        and ("Seq Scan", "teams") not in steps
        and any(where == "teams_pkey" for _, where in steps),
        (out, ids, steps),
    )
    kconn.close()
    subprocess.run(["dropdb", "--if-exists", keys], capture_output=True)

    print("-- lookups through (type, id) pairs")
    # tests/cross.authz's tables: folders in folders or projects, a column pair (parent_type, parent_id); projects
    # backed by folders or regions, a table's pair (backer_type, backer_id). An id of one column is compared through
    # a CASE on the type, which no index serves: the type's own condition beside it is what one serves, so the index
    # on (type, id) reads the rows of that type only, not every row
    pairs = db + "_pairs"
    subprocess.run(["dropdb", "--if-exists", pairs], capture_output=True)
    subprocess.run(["createdb", pairs], check=True)
    for sql in (["-f", os.path.join(HERE, "cross_schema.sql")], ["-c", PAIRS_ROWS]):
        subprocess.run(
            ["psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", "-d", pairs, *sql], check=True, capture_output=True
        )
    rc, out = cli(pairs, "apply", os.path.join(HERE, "cross.authz"))
    if rc:
        raise SystemExit(out)
    pconn = pgwire.connect(**pgwire.parse_dsn(f"dbname={pairs}"))

    def conds(view: str) -> list[tuple[str, str]]:
        """(index, its condition) of each index scan in the plan of a read of view, as the app role, user 7."""

        def plan(d: Db) -> Value:
            d.rows("SELECT authz.act_as('user', '7')")
            d.script("SET LOCAL ROLE app_user; SET LOCAL enable_seqscan = off")
            return next(iter(d.rows(f'EXPLAIN (FORMAT JSON) SELECT count(*) FROM authz_gen."{view}"')[0].values()))

        return index_conds(rowstile_cli.transaction(pconn, plan, keep=False))

    for view, index, cond in (
        ("folder__parent__file__on_project", "folders_parent_type_parent_id_idx", "(parent_type = 'project'::text)"),
        ("project__backer__fund__on_region", "backings_backer_type_backer_id_idx", "(backer_type = 'region'::text)"),
    ):
        found = conds(view)
        check(f"{view}: the rows of that type found through {index}, by the type", (index, cond) in found, found)

    def served(d: Db) -> tuple[set[str], set[str]]:
        """The (type, id) pairs' lookups no index serves, as rowstile indexes names them and as authz.lint() does."""
        missing = perf.missing_indexes(d, database.policy_compiler(*database.applied(d)))
        linted = d.rows("SELECT object FROM authz.lint() WHERE problem LIKE 'no index starts with%'")
        both = {f"{m[0]}.{', '.join(m[1])}" for m in missing}, {str(r["object"]) for r in linted}
        return {x for x in both[0] if "_type" in x}, {x for x in both[1] if "_type" in x}

    def by(index: str) -> Callable[[Db], tuple[set[str], set[str]]]:
        def run(d: Db) -> tuple[set[str], set[str]]:
            d.script(
                f"DROP INDEX cx.folders_parent_type_parent_id_idx; DROP INDEX cx.backings_backer_type_backer_id_idx; {index}"
            )
            return served(d)

        return run

    pair = {"cx.folders.parent_type, parent_id", "cx.backings.backer_type, backer_id"}
    on_type = by("CREATE INDEX ON cx.folders (parent_type); CREATE INDEX ON cx.backings (backer_type)")
    on_id = by("CREATE INDEX ON cx.folders (parent_id); CREATE INDEX ON cx.backings (backer_id)")
    found = [rowstile_cli.transaction(pconn, f, keep=False) for f in (served, on_type, on_id)]
    check(
        "indexes and lint: a (type, id) pair is served by an index on (type, id) or on its type, not by one on its id",
        found[0] == (set(), set()) and found[1] == (set(), set()) and found[2] == (pair, pair),
        found,
    )
    pconn.close()
    subprocess.run(["dropdb", "--if-exists", pairs], capture_output=True)

    conn.close()
    subprocess.run(["dropdb", "--if-exists", db], capture_output=True)
    starting_points(db + "_start")
    print("confidence: all passed" if not fails else f"confidence: {fails} failed")
    sys.exit(1 if fails else 0)


def starting_points(name: str) -> None:
    """A recursive permission's starting points are a set-returning function (`authz_int.<type>__<perm>__start()`),
    read in FROM: when a nested loop scans it again, it rereads the rows the function gave. Called in a select list,
    it ran again for each outer row: on genpolicy's seed 3, `authz.list('t3', 'p3')` on seven rows called them
    10,768 times and took over a second (76 calls and 10 ms read in FROM, PostgreSQL 16). The calls are counted
    (track_functions, which only a superuser may set)."""
    print("-- a list runs each starting point once")
    su = os.environ.get("PGSUPERUSER")
    if not su:
        print("skip  the starting points' calls: they are counted as a superuser (PGSUPERUSER)")
        return
    import random

    import genpolicy
    from difftest import DB

    spec = genpolicy.make(3)
    db = DB(name)
    with tempfile.TemporaryDirectory() as tmp:
        pp, sp = os.path.join(tmp, "gen.authz"), os.path.join(tmp, "gen_schema.sql")
        genpolicy.write_policy(pp, genpolicy.policy_text(spec), False)
        with open(sp, "w", encoding="utf-8") as fh:
            fh.write(genpolicy.schema_text(spec))
        gen = genpolicy.gen_class(spec, pp, sp)(random.Random(spec.seed))
        compiled = subprocess.run(
            [sys.executable, os.path.join(ROOT, "compile_policy.py"), pp], capture_output=True, text=True, check=True
        )
        db.recreate()
        db.run(genpolicy.schema_text(spec))
        # initial() draws each user's active flag with random(): the first three active, as when it was seen slow
        db.run(gen.initial() + "\nUPDATE gp.users SET active = id <= 3;")
        db.run(compiled.stdout)
        db.run(gen.grants())
    script = (
        "SET track_functions = 'pl'; SET authz.user_id = '1'; SET ROLE app_user; BEGIN;\n"
        "SELECT string_agg(id, ' ' ORDER BY id) FROM authz.list('t3', 'p3') id;\n"
        "SELECT coalesce(sum(calls), 0) FROM pg_stat_xact_user_functions WHERE funcname LIKE '%\\_\\_start';\n"
        "COMMIT;"
    )
    out = subprocess.run(
        ["psql", "-X", "-q", "-At", "-v", "ON_ERROR_STOP=1", "-U", su, "-d", name],
        input=script,
        capture_output=True,
        text=True,
    )
    lines = out.stdout.split()
    listed, calls = " ".join(lines[:-1]), int(lines[-1]) if lines and lines[-1].isdigit() else -1
    check("a list on genpolicy's seed 3: its rows", listed == "(1,2) (1,4) (1,6) (2,7)", out.stdout + out.stderr)
    # each call site runs once for each run of the statement or function it is in: a bound the rows don't move
    check("... its starting points run once where they are read, not for each row", 0 < calls <= 200, calls)
    subprocess.run(["dropdb", "--if-exists", name], capture_output=True)


if __name__ == "__main__":
    main()
