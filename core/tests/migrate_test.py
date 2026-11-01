#!/usr/bin/env python3
"""migrate_test: a migration leaves the database as applying the new policy from scratch would.

For each change to a policy: one database gets the old policy, then the migration the lock file of the
old policy gives; another gets the old policy, then the new one, each applied whole. Everything rowstile made in them must be the
same: functions (with their privileges), views, triggers, row-level security policies, the catalog
tables and the inheritance tables' rows. Then the migration back, which must give the old policy again. Each
change needs a migration but lines that only move: there the database must already be what applying whole makes.

And what a new version of rowstile changes alone, the policy the same (RELEASES): the database and the lock made as an
older version would have made them; the migration must bring what this version makes.

    PGHOST=... PGUSER=... python3 tests/migrate_test.py [--keep] [case ...]
"""

import os
import re
import subprocess
import sys
import tempfile
from collections.abc import Callable

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from authzlib import database, migrate  # noqa: E402

KEEP = "--keep" in sys.argv
ONLY = [a for a in sys.argv[1:] if not a.startswith("--")]


def read(rel: str) -> str:
    with open(os.path.join(ROOT, rel), encoding="utf-8") as fh:
        return fh.read()


def edit(text: str, *pairs: tuple[str, str]) -> str:
    for a, b in pairs:
        if a not in text:
            raise SystemExit(f"test setup: {a!r} is not in the policy")
        text = text.replace(a, b, 1)
    return text


DOCS, MULTI, COMPOSITE = read("example/docs.authz"), read("tests/multi.authz"), read("tests/composite.authz")
CHILDREN = read("tests/children.authz")
# the docs app with a relation whose name makes the tree of view's links longer than Postgres's names (63 bytes):
# its tables, functions, triggers and indexes are named with a hash
LONG = DOCS.replace("linked_into", "also_shown_inside_these_other_folders_of_the_org")
FROZEN = "{not exists (select 1 from app.files x where x.folder_id = this.id and x.confidential)}"
SCHEMAS = {
    "docs": "example/app_schema.sql",
    "multi": "tests/multi_schema.sql",
    "composite": "tests/composite_schema.sql",
    "children": "tests/children_schema.sql",
}

REORDERED_COLUMN_RULES = "column rules written in another order"  # (whose migration must make no trigger again)
LOST_RULES = "a table with no rules any more"  # (whose migration warns that row-level security stays on)
LINES_MOVE = "lines that only move"  # (the one change that needs no migration: the database stays as it is)
# (name, schema, old policy, new policy): a kind of change each, both ways. The kinds held so far: a permission, a
# relation (shared, shared if, from a table with a where), a type (its line, moved, added as a principal, removed),
# inheritance (changed, removed, with a deny), rules (changed, gone, on columns), a scope, a caveat, custom roles, an
# invariant, masks, lines that move; over composite keys and tables with tables under them. A new language form
# gets its case here.
CASES: list[tuple[str, str, str, str]] = [
    (
        "a new permission",
        "docs",
        DOCS,
        edit(
            DOCS,
            (
                "  can share = owner or folder.share\n",
                "  can share = owner or folder.share\n  can comment = folder.view\n",
            ),
        ),
    ),
    (
        "a type's line changes: a where added (views on its key are made again, not emptied in place)",
        "docs",
        DOCS,
        edit(DOCS, ("type file = app.files\n", "type file = app.files where {not confidential}\n")),
    ),
    (
        "a tree's type line changes: a where added (the trees that read its views are built again)",
        "docs",
        DOCS,
        edit(DOCS, ("type folder = app.folders\n", "type folder = app.folders where {name <> ''}\n")),
    ),
    (
        "a new shared relation used by a permission",
        "docs",
        DOCS,
        edit(
            DOCS,
            (
                "  viewer : user, team#member shared\n\n  can share = owner or folder.share",
                "  viewer : user, team#member shared\n  editor : user  shared\n\n  can share = owner or folder.share",
            ),
            ("can edit  = share or folder.edit", "can edit  = share or editor or folder.edit"),
        ),
    ),
    (
        "inheritance that changes (a tree rebuilt)",
        "docs",
        DOCS,
        edit(
            DOCS,
            ("can view  = edit or viewer or (parent.view and {inherit})", "can view  = edit or viewer or parent.view"),
        ),
    ),
    (
        "inheritance that changes, in a tree whose name is too long (built beside, swapped in)",
        "docs",
        LONG,
        edit(LONG, ("(parent.view and {inherit})", "parent.view")),
    ),
    # its conditions read another table: the tree is rebuilt, and the triggers it made on that table go first
    (
        "a condition that reads another table changes, in a tree whose name is too long",
        "docs",
        edit(LONG, ("(parent.view and {inherit})", f"(parent.view and {FROZEN})")),
        edit(
            LONG,
            ("(parent.view and {inherit})", f"(parent.view and {FROZEN.replace('x.confidential', 'x.body IS NULL')})"),
        ),
    ),
    (
        "a link that stops passing view on (a tree removed)",
        "docs",
        DOCS,
        edit(
            DOCS,
            (
                "can view  = edit or viewer or (parent.view and {inherit})\n           or linked_into.view",
                "can view  = edit or viewer or (parent.view and {inherit})",
            ),
            (
                "  linked_into : folder      = app.folder_links(folder_id -> parent_id)  -- also shown inside these\n",
                "",
            ),
        ),
    ),
    (
        "a rule that changes",
        "docs",
        DOCS,
        edit(DOCS, ("  delete                            : edit", "  delete                            : share")),
    ),
    ("a rule that goes", "docs", DOCS, edit(DOCS, ("  delete                            : edit\n", ""))),
    # the rule's refusal functions (BEGIN ATOMIC) read the relation's view: they go first, then the view
    (
        "a relation and the rule that reads it go",
        "docs",
        edit(
            DOCS,
            ("  viewer : user, team#member shared\n", "  viewer : user, team#member shared\n  purger : user shared\n"),
            ("  delete                            : edit\n", "  delete                            : purger\n"),
        ),
        edit(DOCS, ("  delete                            : edit\n", "")),
    ),
    ("a column rule that goes", "docs", DOCS, edit(DOCS, ("  update id, owner_id, confidential : share\n", ""))),
    # a rule on columns, its functions and its trigger are named after its head: another column is another name
    # (the old trigger goes), and the rules in another order are the same triggers
    (
        "a column rule on other columns",
        "docs",
        DOCS,
        edit(DOCS, ("  update id, owner_id, confidential : share\n", "  update id, owner_id : share\n")),
    ),
    (
        REORDERED_COLUMN_RULES,
        "docs",
        DOCS,
        edit(
            DOCS,
            (
                "  update folder_id after            : folder.edit\n  update id, owner_id, confidential : share\n",
                "  update id, owner_id, confidential : share\n  update folder_id after            : folder.edit\n",
            ),
        ),
    ),
    (
        LOST_RULES,
        "docs",
        DOCS,
        edit(
            DOCS,
            (
                "rules app.files\n  select                            : view\n  insert                            : folder.edit and owner\n"
                "  update                            : edit\n  update folder_id after            : folder.edit\n"
                "  update id, owner_id, confidential : share\n  delete                            : edit\n",
                "",
            ),
        ),
    ),
    (
        "a scope",
        "docs",
        DOCS,
        edit(DOCS, ("scope read  = select, view\n", "scope read  = select, view\nscope audit = select, file.view\n")),
    ),
    (
        "an invariant that goes",
        "docs",
        DOCS,
        edit(DOCS, ("  never folder: share and not org.member  -- only members of its org manage a folder\n", "")),
    ),
    (
        LINES_MOVE,
        "docs",
        DOCS,
        edit(DOCS, ("app role app_user\n", "app role app_user\n\n\n-- a comment\n")),
    ),
    # a deny inside inheritance: the hidden permissions (split_denies) are views of their own, and two trees change
    (
        "a deny inside inheritance",
        "docs",
        DOCS,
        edit(
            DOCS,
            (
                "  can view  = edit or viewer or (parent.view and {inherit})\n"
                "           or linked_into.view  -- links pass on view, not edit\n",
                "  can hidden = {name = 'secret'} or parent.hidden or linked_into.hidden\n"
                "  can view  = (edit or viewer or (parent.view and {inherit}) or linked_into.view) and not hidden\n",
            ),
        ),
    ),
    (
        "a caveat",
        "docs",
        DOCS,
        edit(DOCS, ("scope read ", "caveat from_ip = {authz.ctx('ip') = arg('ip')}\nscope read ")),
    ),
    (
        "custom roles",
        "docs",
        DOCS,
        edit(
            DOCS,
            (
                "  admin  : user = app.org_members(org_id -> user_id) where {role = 'admin'}\n",
                "  admin  : user = app.org_members(org_id -> user_id) where {role = 'admin'}\n"
                "  can manage_roles = admin\n",
            ),
            (
                "  editor      : team#member = app.folder_team_access(folder_id -> team_id) where {access = 'edit'}\n",
                "  editor      : team#member = app.folder_team_access(folder_id -> team_id) where {access = 'edit'}\n"
                "  roles       : user, team#member from org\n",
            ),
            (
                "  can edit  = share or editor or (parent.edit and {inherit})\n",
                "  can edit  = share or editor or roles or (parent.edit and {inherit})\n",
            ),
        ),
    ),
    (
        "a principal type",
        "docs",
        DOCS,
        edit(DOCS, ("type org = app.orgs\n", "type bot = app.teams principal\n\ntype org = app.orgs\n")),
    ),
    (
        "a relation shared if",
        "docs",
        DOCS,
        edit(
            DOCS,
            (
                "  viewer : user, team#member shared\n\n  can share = owner or folder.share",
                "  viewer : user, team#member shared if {subject_type = 'user'}\n\n  can share = owner or folder.share",
            ),
        ),
    ),
    (
        "a link table's where",
        "docs",
        DOCS,
        edit(DOCS, ("where {access = 'edit'}\n", "where {access in ('edit', 'own')}\n")),
    ),
    (
        "a type added",
        "docs",
        DOCS,
        DOCS + "\ntype label = app.teams\n  owner : user shared by see\n  can see = owner\n",
    ),
    (
        "a mask that goes",
        "multi",
        MULTI,
        "\n".join(line for line in MULTI.split("\n") if "mask body" not in line).replace(" view mt.docs_visible", ""),
    ),
    # the masked view is what the app reads: a view of the app's built on it must not stop a migration, or an apply
    (
        "a mask that changes, under a view of the app's",
        "multi",
        MULTI,
        edit(MULTI, ("  mask body : edit", "  mask body : view")),
    ),
    (
        "a permission the masked view reads changes, under a view of the app's",
        "multi",
        MULTI,
        edit(
            MULTI,
            (
                "  can edit = author or container.edit or roles\n  can view = edit or container.view",
                "  can edit = author or roles\n  can view = edit or container.view",
            ),
        ),
    ),
    # the views on a type's key are made again when its line changes: the masked view reads them, and stays (emptied
    # in place while they go) under the app's view
    (
        "a type's line changes under the masked view, under a view of the app's",
        "multi",
        MULTI,
        edit(MULTI, ("type project = mt.projects\n", "type project = mt.projects where {id > 0}\n")),
    ),
    # the masked view's own type: the view changes (its where) and keeps its columns, so it is replaced in place,
    # the app's view on it kept; the generated views on the type's key are made again
    (
        "the masked type's line changes, under a view of the app's",
        "multi",
        MULTI,
        edit(
            MULTI, ("type doc = mt.docs (id uuid)\n", "type doc = mt.docs (id uuid) where {container_id is not null}\n")
        ),
    ),
    # a type moved to a table whose key is of another type: the views on its key can't be replaced in place
    (
        "a type moved to a table keyed by a uuid",
        "multi",
        MULTI + "\ntype tally = mt.orgs\n  can count = nobody\n",
        MULTI + "\ntype tally = mt.users (id uuid)\n  can count = nobody\n",
    ),
    (
        "a new permission on composite keys",
        "composite",
        COMPOSITE,
        edit(
            COMPOSITE,
            (
                "  can edit = owner or uploader or folder.edit\n",
                "  can edit = owner or uploader or folder.edit\n  can comment = folder.view\n",
            ),
        ),
    ),
    (
        "inheritance on composite keys that goes (a tree removed)",
        "composite",
        COMPOSITE,
        edit(COMPOSITE, ("  can edit  = share or editor or parent.edit\n", "  can edit  = share or editor\n")),
    ),
    # tables with tables under them: a table that inherits has copies of its table's row triggers, which a
    # migration drops with what they call and makes again (the step every migration runs)
    (
        "a rule on a column that changes, with a table that inherits and partitions",
        "children",
        CHILDREN,
        edit(CHILDREN, ("  update owner_id : own\n", "  update owner_id, title : own\n")),
    ),
    (
        "a new rule on a column of a partitioned table",
        "children",
        CHILDREN,
        edit(
            CHILDREN,
            ("  update owner_id : manage\n  delete ", "  update owner_id : manage\n  update title : manage\n  delete "),
        ),
    ),
]
# the sync index (a preview): sync lines added (and back: removed, the index dropped), and the permission a synced
# table's readers hold changed (its rows worked out again, by difference). The role the lines name needs only to be
# there (main makes it)
SYNC_ROLE = "authz_sync_engine"
SYNCED = DOCS + f"\nsync role {SYNC_ROLE}\nsync app.files : view\nsync app.folders\n"
CASES += [
    ("sync lines added", "docs", DOCS, SYNCED),
    (
        "a synced table's permission changed",
        "docs",
        SYNCED,
        edit(SYNCED, ("sync app.files : view\n", "sync app.files : edit\n")),
    ),
    (
        "a synced table keyed by folder",
        "docs",
        SYNCED,
        edit(SYNCED, ("sync app.files : view\n", "sync app.files : view by folder\n")),
    ),
    ("the sync index kept after commit", "docs", SYNCED, SYNCED + "sync after commit\n"),
]
# functions made with another search path than the migration's (the schemas on it changed since: one made, one
# dropped); a migration changes only some functions, and the others must take the path the migration runs with
OTHER_PATHS = "functions made with another search path (they take the migration's)"
CASES.insert(1, (OTHER_PATHS, "docs", DOCS, CASES[0][3]))
OLD_PATHS = r"""DO $o$
DECLARE f record;
BEGIN
  FOR f IN SELECT p.oid::regprocedure AS fn FROM pg_proc p
           WHERE p.pronamespace IN (SELECT oid FROM pg_namespace WHERE nspname IN ('authz', 'authz_gen', 'authz_int'))
             AND EXISTS (SELECT 1 FROM unnest(p.proconfig) c WHERE c ^@ 'search_path=' AND c <> 'search_path=pg_catalog, pg_temp') LOOP
    EXECUTE format('ALTER FUNCTION %s SET search_path = app, public, pg_temp', f.fn);
  END LOOP;
END $o$;"""


def reworded(fn: str, old: str, new: str) -> str:
    """SQL that makes the function `fn` (a regprocedure) say `new` where it says `old`: what an older release made."""
    return f"""DO $d$
DECLARE d text := pg_get_functiondef({migrate.sql_lit(fn)}::regprocedure);
BEGIN
  IF strpos(d, {migrate.sql_lit(old)}) = 0 THEN RAISE EXCEPTION 'test setup: % does not say %', {migrate.sql_lit(fn)}, {migrate.sql_lit(old)}; END IF;
  EXECUTE replace(d, {migrate.sql_lit(old)}, {migrate.sql_lit(new)});
END $d$;"""


# A release that makes something differently, with the policy the same: no policy change shows it, so the database
# and the lock are made as an older release would have made them (the database changed after applying, the lock's
# line for what changed given another hash). The migration must bring what this version makes.
# (name, schema, policy, the older release's database, its lock from this version's, the trees the migration rebuilds)
TREE_FN = 'authz_int."folder__parent__tree_check_loops"'
RELEASES: list[tuple[str, str, str, str, Callable[[str], str], list[str]]] = [
    (
        "a release changes a message of an inheritance tree's function (replaced in place, the tree's rows kept)",
        "docs",
        DOCS,
        reworded(f"{TREE_FN}(bigint[])", "cannot be moved", "may not be moved"),
        lambda lock: older_lock(lock, f"function {TREE_FN}("),
        [],
    ),
    (
        "a release changes a message of a function outside the trees",
        "docs",
        DOCS,
        reworded("authz.trim_audit(interval)", "say how long to keep", "say for how long to keep"),
        lambda lock: older_lock(lock, "function authz.trim_audit("),
        [],
    ),
    (
        "a release grants the app role another function, and nothing else",
        "docs",
        DOCS,
        "REVOKE EXECUTE ON FUNCTION authz.perms(text, text) FROM app_user;",
        lambda lock: older_lock(lock, "step grant_api "),
        [],
    ),
    # a tree whose hash is the same, but whose objects can't all be replaced in place: it is rebuilt
    (
        "a release made one more function in an inheritance tree (the tree rebuilt, the function gone)",
        "docs",
        DOCS,
        "CREATE FUNCTION authz_int.\"folder__parent__tree_old\"() RETURNS void LANGUAGE sql AS '';",
        lambda lock: (
            lock
            + 'function authz_int."folder__parent__tree_old"() | 000000000000 shape=00000000 tree=folder__parent__tree\n'
        ),
        ["folder__parent__tree"],
    ),
    (
        "a release made an inheritance tree's function with another result (the tree rebuilt)",
        "docs",
        DOCS,
        f"DROP FUNCTION {TREE_FN}(bigint[]);\n"
        f"CREATE FUNCTION {TREE_FN}(p_ids bigint[]) RETURNS integer LANGUAGE sql AS 'SELECT 1';",
        lambda lock: older_lock(lock, f"function {TREE_FN}(", shape="00000000"),
        ["folder__parent__tree"],
    ),
]


def older_lock(lock: str, line: str, shape: str | None = None) -> str:
    """The lock with the line that starts with `line` given another hash (and shape), as an older release would have
    written it."""
    found = [x for x in lock.split("\n") if x.startswith(line)]
    if len(found) != 1:
        raise SystemExit(f"test setup: {len(found)} lines of the lock start with {line!r}")
    head, _, attrs = found[0].partition(" | ")
    rest = [f"shape={shape}" if shape and w.startswith("shape=") else w for w in attrs.split()[1:]]
    return lock.replace(found[0], f"{head} | {' '.join(['000000000000'] + rest)}", 1)


# what the app built on what rowstile made, for the cases that say so
APP_VIEW = (
    "CREATE VIEW mt.my_docs AS SELECT id FROM mt.docs_visible;\n"
    "CREATE FUNCTION mt.count_docs() RETURNS bigint LANGUAGE sql BEGIN ATOMIC SELECT count(*) FROM mt.docs_visible; END;"
)


def sh(*args: str, stdin: str | None = None, check: bool = True) -> str:
    p = subprocess.run(args, input=stdin, capture_output=True, text=True)
    if check and p.returncode:
        raise RuntimeError(f"{' '.join(args[:4])} failed:\n{p.stderr[-3000:]}")
    return p.stdout


def psql(db: str, sql: str) -> str:
    return sh("psql", "-X", "-q", "-At", "-v", "ON_ERROR_STOP=1", "-d", db, stdin=sql)


def fresh(db: str, schema: str) -> None:
    sh("dropdb", "--if-exists", db)
    sh("createdb", db)
    sh(
        "psql",
        "-X",
        "-q",
        "-v",
        "ON_ERROR_STOP=1",
        "-d",
        db,
        "-c",
        "SET client_min_messages = error",
        "-f",
        os.path.join(ROOT, schema),
    )


def apply_whole(db: str, policy: str) -> None:
    with tempfile.NamedTemporaryFile("w", suffix=".authz", delete=False, encoding="utf-8") as fh:
        fh.write(policy)
    try:
        sh(
            sys.executable,
            os.path.join(ROOT, "cli", "rowstile_cli.py"),
            "--db",
            f"dbname={db}",
            "apply",
            fh.name,
            "--force",
        )
    finally:
        os.unlink(fh.name)


def run_migration(db: str, sql: str) -> str:
    """What the migration's run says (its warnings: the notices below them are left out)."""
    p = subprocess.run(
        ["psql", "-X", "-q", "-1", "-v", "ON_ERROR_STOP=1", "-d", db],
        input="SET client_min_messages = warning;\n" + sql,
        capture_output=True,
        text=True,
    )
    if p.returncode:
        raise RuntimeError(f"psql -1 failed:\n{p.stderr[-3000:]}")
    return p.stderr


SNAPSHOT = r"""
SELECT 'function ' || p.oid::regprocedure::text || E'\n' || pg_get_functiondef(p.oid)
       || E'\nacl ' || coalesce(p.proacl::text, '')
FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
WHERE n.nspname IN ('authz', 'authz_int', 'authz_gen') AND p.prokind = 'f'
UNION ALL
-- (a view's privileges as its owner's alone, written out, are what none written says: a grant to the app role taken
-- back leaves them written)
SELECT 'view ' || c.oid::regclass::text || E'\n' || pg_get_viewdef(c.oid) || E'\nacl '
       || coalesce(nullif(c.relacl, acldefault('r', c.relowner))::text, '')
       || E'\ncomment ' || coalesce(obj_description(c.oid, 'pg_class'), '')
FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE c.relkind = 'v' AND (n.nspname IN ('authz_int', 'authz_gen') OR obj_description(c.oid, 'pg_class') = 'rowstile masked view')
UNION ALL
SELECT 'trigger ' || t.tgname || ' ON ' || t.tgrelid::regclass::text || E'\n' || pg_get_triggerdef(t.oid)
       || ' ' || t.tgenabled::text
FROM pg_trigger t WHERE NOT t.tgisinternal
UNION ALL
SELECT 'policy ' || p.polname || ' ON ' || p.polrelid::regclass::text || E'\n' || p.polcmd::text || ' ' || p.polpermissive
       || ' ' || p.polroles::regrole[]::text || E'\nusing ' || coalesce(pg_get_expr(p.polqual, p.polrelid), '')
       || E'\ncheck ' || coalesce(pg_get_expr(p.polwithcheck, p.polrelid), '')
       || E'\ncomment ' || coalesce(obj_description(p.oid, 'pg_policy'), '')
FROM pg_policy p
UNION ALL
SELECT 'table ' || c.oid::regclass::text || ' ' || c.relrowsecurity || ' ' || c.relforcerowsecurity || E'\n'
       || coalesce(c.relacl::text, '')
FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE c.relkind IN ('r', 'p') AND n.nspname NOT IN ('pg_catalog', 'information_schema', 'pg_toast', 'authz_int', 'authz_gen')
UNION ALL
SELECT 'column ' || c.oid::regclass::text || '.' || a.attname || ' ' || format_type(a.atttypid, a.atttypmod)
       || ' ' || coalesce(a.attacl::text, '')
FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace JOIN pg_attribute a ON a.attrelid = c.oid
WHERE c.relkind IN ('r', 'p', 'v', 'c') AND a.attnum > 0 AND NOT a.attisdropped
  AND (n.nspname IN ('authz_int', 'authz_gen') OR a.attacl IS NOT NULL)
UNION ALL
SELECT 'index ' || i.indexrelid::regclass::text || E'\n' || pg_get_indexdef(i.indexrelid)
FROM pg_index i JOIN pg_class c ON c.oid = i.indrelid JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname IN ('authz', 'authz_int')
UNION ALL
SELECT 'type ' || t.oid::regtype::text FROM pg_type t JOIN pg_namespace n ON n.oid = t.typnamespace
WHERE n.nspname IN ('authz_int', 'authz_gen') AND t.typtype = 'c' AND NOT EXISTS (SELECT 1 FROM pg_class c WHERE c.oid = t.typrelid AND c.relkind <> 'c')
UNION ALL
SELECT 'schema ' || nspname || ' ' || coalesce(nspacl::text, '') FROM pg_namespace WHERE nspname LIKE 'authz%'
ORDER BY 1;
"""

ROWS = r"""
SELECT format('SELECT %L || E''\n'' || coalesce(string_agg(x, E''\n'' ORDER BY x), '''') FROM (SELECT %s AS x FROM %s t) s;',
              'rows ' || c.oid::regclass::text,
              CASE WHEN c.relname = 'trees' THEN 't.name || '' '' || t.hash' ELSE 't::text' END, c.oid::regclass)
FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname IN ('authz_int', 'authz_sync') AND c.relkind = 'r' AND c.relname NOT IN ('locks', 'session_key', 'row_marks')
ORDER BY 1;
"""
# (row_marks holds a row for each row shared on or to, written as shares, keys and requests are made: a migration keeps
# it, applying whole starts it empty, and either way the marks only serve to conflict, whatever rows are there)


def snapshot(db: str) -> str:
    out = psql(db, SNAPSHOT).split("\n")
    queries = psql(db, ROWS)
    return "\n".join(out) + "\n" + (psql(db, queries) if queries.strip() else "")


def objects(text: str) -> dict[str, str]:
    """The snapshot as {first line: the rest}."""
    out: dict[str, list[str]] = {}
    cur: str | None = None
    for line in text.split("\n"):
        if line.startswith(
            ("function ", "view ", "trigger ", "policy ", "table ", "column ", "index ", "type ", "schema ", "rows ")
        ):
            cur = line
            out[cur] = []
        elif cur:
            out[cur].append(line)
    return {k: "\n".join(v) for k, v in out.items()}


def compare(a: str, b: str) -> list[str]:
    """The differences between two snapshots, as lines to print."""
    oa, ob = objects(a), objects(b)
    out: list[str] = []
    for k in sorted(set(oa) | set(ob)):
        if k not in oa:
            out.append(f"  only after applying whole: {k}")
        elif k not in ob:
            out.append(f"  only after migrating: {k}")
        elif oa[k] != ob[k]:
            la, lb = oa[k].split("\n"), ob[k].split("\n")
            i = next((i for i, (x, y) in enumerate(zip(la, lb, strict=False)) if x != y), min(len(la), len(lb)))
            out.append(
                f"  differs: {k}\n    migrated: {la[i] if i < len(la) else '(end)'}\n"
                f"    whole:    {lb[i] if i < len(lb) else '(end)'}"
            )
    return out


# what the app changes while a migration waits (between the two of a tree built beside): moves, a condition,
# links, a new row, deleted rows; the other database gets the same changes before the new policy
CHANGES = {
    "docs": """
UPDATE app.folders SET parent_id = 1 WHERE id = 4;
UPDATE app.folders SET inherit = true WHERE id = 5;
INSERT INTO app.folders (id, org_id, parent_id, owner_id, name) VALUES (30, 1, 6, 5, 'New');
INSERT INTO app.folder_links VALUES (6, 20);
DELETE FROM app.folder_links WHERE folder_id = 21 AND parent_id = 1;
DELETE FROM app.files WHERE folder_id = 2;
DELETE FROM app.folders WHERE id = 2;
""",
    "multi": """
INSERT INTO mt.users (id) VALUES ('00000000-0000-0000-0000-000000000001'), ('00000000-0000-0000-0000-000000000002');
INSERT INTO mt.orgs (id) VALUES (1);
INSERT INTO mt.folders (id, parent_type, parent_id, owner_id, org_id)
VALUES (1, NULL, NULL, '00000000-0000-0000-0000-000000000001', 1), (2, 'folder', 1, '00000000-0000-0000-0000-000000000002', 1);
INSERT INTO mt.projects (id, org_id, folder_id, lead_id) VALUES (1, 1, 2, '00000000-0000-0000-0000-000000000002');
INSERT INTO mt.folders (id, parent_type, parent_id, owner_id, org_id)
VALUES (3, 'project', 1, '00000000-0000-0000-0000-000000000001', 1);
INSERT INTO mt.docs (id, container_type, container_id, author_id)
VALUES ('00000000-0000-0000-0000-00000000000a', 'folder', 3, '00000000-0000-0000-0000-000000000002');
UPDATE mt.folders SET parent_id = NULL, parent_type = NULL WHERE id = 2;
""",
    "composite": """
INSERT INTO cx.users VALUES (1, NULL), (2, 1);
INSERT INTO cx.orgs VALUES (1);
INSERT INTO cx.folders VALUES (1, 1, 1, NULL, NULL), (1, 2, 2, 'folder', 1), (1, 3, 2, 'folder', 2);
INSERT INTO cx.folder_links VALUES (1, 3, 1);
INSERT INTO cx.files VALUES (1, 1, 3, 2, 2);
UPDATE cx.folders SET parent_id = 1 WHERE org_id = 1 AND id = 3;
DELETE FROM cx.folders WHERE org_id = 1 AND id = 2;
""",
    "children": """
INSERT INTO ch.shelves_old VALUES (53, 2, 51);
UPDATE ch.topics SET parent_id = 150 WHERE id = 3;
INSERT INTO ch.notes VALUES (5, 1, 2, 'deeper');
DELETE FROM ch.notes WHERE id = 4;
""",
}


def check(label: str, name: str, schema: str, ms: list[migrate.Migration], new: str, before: str = "") -> bool:
    """Run the migrations on authz_mig_m, as it is, and apply the new policy whole on a copy of it made first:
    whether both leave the same. `before`: SQL run on the migrated database alone, once the copy is made."""
    db_m, db_w = "authz_mig_m", "authz_mig_w"
    changes = CHANGES.get(schema, "")
    app = APP_VIEW if "a view of the app's" in name else ""
    # the database applied whole starts as this one is now: a copy (the same as building it again, sooner)
    sh("dropdb", "--if-exists", db_w)
    sh("createdb", "--template", db_m, db_w)
    if before:
        psql(db_m, before)
    try:
        if len(ms) == 1:
            psql(db_m, changes)
            said = run_migration(db_m, ms[0].sql) if not ms[0].empty else ""
        else:
            run_migration(db_m, ms[0].sql)  # built beside ...
            psql(db_m, changes)  # ... while the app writes ...
            said = run_migration(db_m, ms[1].sql)  # ... then swapped in
    except RuntimeError as e:
        print(f"FAIL  {label}: the migration fails\n{e}")
        return False
    psql(db_w, changes)
    try:
        apply_whole(db_w, new)
    except RuntimeError as e:
        print(f"FAIL  {label}: applying whole fails\n{e}")
        return False
    diffs = compare(snapshot(db_m), snapshot(db_w))
    lost = 'WARNING:  "app"."files" has no rules any more, and row-level security is still on, so the app role sees'
    if name == LOST_RULES and not label.endswith("(and back)") and lost not in said:
        diffs.append(f"  the migration doesn't warn that app.files keeps row-level security on: {said[-300:]!r}")
    # what it takes back with a warning is a grant made since: never one the old policy gave
    if "took back" in said:
        diffs.append(f"  the migration takes back privileges: {said[-300:]!r}")
    if app and not diffs:
        # the app's view is still there, and reads the view as it is now (not the emptied one)
        for db in (db_m, db_w):
            left = psql(
                db,
                "SELECT count(*) FROM pg_views WHERE schemaname = 'mt' AND viewname = 'my_docs';"
                "SELECT pg_get_viewdef('mt.docs_visible'::regclass) ~ 'WHERE false';"
                "SELECT mt.count_docs() >= 0;",
            ).split()
            if left != ["1", "f", "t"]:
                diffs.append(f"  {db}: the app's view after: {left}")
    if ms[0].empty:
        size = "no migration needed"
    else:
        size = " + ".join(f"{len(m.sql) // 1024} KB" for m in ms)
        size += (
            f", {'builds beside and swaps in' if len(ms) == 2 else 'rebuilds'} {', '.join(ms[-1].rebuilt)}"
            if ms[-1].rebuilt
            else ""
        )
    if diffs:
        print(
            f"FAIL  {label} ({size}):\n"
            + "\n".join(diffs[:12])
            + (f"\n  ... {len(diffs) - 12} more" if len(diffs) > 12 else "")
        )
        return False
    print(f"ok    {label} ({size})")
    return True


def main() -> None:
    failed = 0
    psql(
        "postgres",
        f"DO $r$ BEGIN CREATE ROLE {SYNC_ROLE}; EXCEPTION WHEN duplicate_object OR unique_violation THEN NULL; END $r$;",
    )
    for name, schema, old, new in CASES:
        if ONLY and not any(o in name for o in ONLY):
            continue
        for direction, a, b in (("", old, new), (" (and back)", new, old)):
            label = name + direction
            fresh("authz_mig_m", SCHEMAS[schema])
            apply_whole("authz_mig_m", a)
            psql("authz_mig_m", APP_VIEW if "a view of the app's" in name else "")
            lock = migrate.lock_of(database.migratable(a, {})[1])
            ms = database.migrations(b, {}, lock, label)
            if name == REORDERED_COLUMN_RULES and any(re.search(r"(?m)^(CREATE|DROP) TRIGGER", m.sql) for m in ms):
                failed += 1
                print(f"FAIL  {label}: the migration makes a column rule's trigger again")
                continue
            # lines that only move are the one change that needs no migration (the database stays as it is, and is
            # what applying the new policy whole makes all the same); every other one needs one
            if (len(ms) == 1 and ms[0].empty) != (name == LINES_MOVE):
                failed += 1
                print(
                    f"FAIL  {label}: {'no migration' if ms[0].empty else 'a migration'}, where the change needs "
                    f"{'one' if ms[0].empty else 'none'}"
                )
                continue
            if not check(label, name, schema, ms, b, OLD_PATHS if name == OTHER_PATHS else ""):
                failed += 1
    for name, schema, policy, older, made, rebuilds in RELEASES:
        if ONLY and not any(o in name for o in ONLY):
            continue
        fresh("authz_mig_m", SCHEMAS[schema])
        apply_whole("authz_mig_m", policy)
        lock = made(migrate.lock_of(database.migratable(policy, {})[1]))
        # (the SQL checks that the database said what the release changes); the database holds the older lock
        psql(
            "authz_mig_m",
            older + "\nUPDATE authz.policy_versions SET lock = "
            f"{migrate.sql_lit(migrate.parse_lock(lock).hash)} WHERE id = (SELECT max(id) FROM authz.policy_versions);",
        )
        ms = database.migrations(policy, {}, lock, name)
        if len(ms) == 1 and ms[0].empty:
            failed += 1
            print(f"FAIL  {name}: no migration, and the database keeps what the older release made")
            continue
        if ms[-1].rebuilt != rebuilds:
            failed += 1
            print(
                f"FAIL  {name}: the migration rebuilds {', '.join(ms[-1].rebuilt) or 'no tree'}, "
                f"where it must rebuild {', '.join(rebuilds) or 'none'}"
            )
            continue
        if not check(name, name, schema, ms, policy):
            failed += 1
    if not KEEP:
        for db in ("authz_mig_m", "authz_mig_w"):
            sh("dropdb", "--if-exists", db, check=False)
    print("migrations: all passed" if not failed else f"migrations: {failed} failed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
