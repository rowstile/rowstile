#!/usr/bin/env python3
"""migrate_test: a migration leaves the database as applying the new policy from scratch would.

For each change to a policy: one database gets the old policy, then the migration the lock file of the
old policy gives; another gets the old policy, then the new one, each applied whole. Everything rowstile made in them must be the
same: functions (with their privileges), views, triggers, row-level security policies, the catalog
tables and the inheritance tables' rows. Then the migration back, which must give the old policy again.

    PGHOST=... PGUSER=... python3 tests/migrate_test.py [--keep] [case ...]
"""

import os
import re
import subprocess
import sys
import tempfile

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
SCHEMAS = {
    "docs": "example/app_schema.sql",
    "multi": "tests/multi_schema.sql",
    "composite": "tests/composite_schema.sql",
    "children": "tests/children_schema.sql",
}

REORDERED_COLUMN_RULES = "column rules written in another order"  # (whose migration must make no trigger again)
# (name, schema, old policy, new policy)
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
        "a table with no rules any more",
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
        "lines that only move",
        "docs",
        DOCS,
        edit(DOCS, ("app role app_user\n", "app role app_user\n\n\n-- a comment\n")),
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
# functions an older build made kept "$user" on their search path; a migration changes only some functions, and
# the others must take the path the migration runs with
OLDER_BUILD = 'functions an older build made ("$user" on their search path)'
CASES.insert(1, (OLDER_BUILD, "docs", DOCS, CASES[0][3]))
OLD_PATHS = r"""DO $o$
DECLARE f record;
BEGIN
  FOR f IN SELECT p.oid::regprocedure AS fn FROM pg_proc p
           WHERE p.pronamespace IN (SELECT oid FROM pg_namespace WHERE nspname IN ('authz', 'authz_gen', 'authz_int'))
             AND EXISTS (SELECT 1 FROM unnest(p.proconfig) c WHERE c ^@ 'search_path=' AND c <> 'search_path=pg_catalog, pg_temp') LOOP
    EXECUTE format('ALTER FUNCTION %s SET search_path = "$user", public, pg_temp', f.fn);
  END LOOP;
END $o$;"""
# an older build turned row-level security on for the tables with rules alone, with other statements: the lock's
# lines for them hold another hash, and the partitions and the table that inherits are left without it. The next
# migration runs those statements again, and drops nothing: what reads the tables stays where it is
OLDER_RLS = "row-level security as an older build turned it on (its statements run again, nothing dropped)"
CASES.append((OLDER_RLS, "children", CHILDREN, CHILDREN))
RLS_OFF = "ALTER TABLE ch.notes_low DISABLE ROW LEVEL SECURITY; ALTER TABLE ch.docs_old DISABLE ROW LEVEL SECURITY;"


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
    return sh(
        "psql", "-X", "-q", "-1", "-v", "ON_ERROR_STOP=1", "-d", db, stdin="SET client_min_messages = error;\n" + sql
    )


SNAPSHOT = r"""
SELECT 'function ' || p.oid::regprocedure::text || E'\n' || pg_get_functiondef(p.oid)
       || E'\nacl ' || coalesce(p.proacl::text, '')
FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
WHERE n.nspname IN ('authz', 'authz_int', 'authz_gen') AND p.prokind = 'f'
UNION ALL
SELECT 'view ' || c.oid::regclass::text || E'\n' || pg_get_viewdef(c.oid) || E'\nacl ' || coalesce(c.relacl::text, '')
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
WHERE c.relkind IN ('r', 'p', 'v') AND a.attnum > 0 AND NOT a.attisdropped
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
WHERE n.nspname = 'authz_int' AND c.relkind = 'r' AND c.relname NOT IN ('locks', 'session_key')
ORDER BY 1;
"""


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
"""
}


def main() -> None:
    failed = 0
    for name, schema, old, new in CASES:
        if ONLY and not any(o in name for o in ONLY):
            continue
        for direction, a, b in (("", old, new), (" (and back)", new, old)):
            if name == OLDER_RLS and direction:
                continue  # the same policy both ways
            label = name + direction
            db_m, db_w = "authz_mig_m", "authz_mig_w"
            changes = CHANGES.get(schema, "")
            app = APP_VIEW if "a view of the app's" in name else ""
            fresh(db_m, SCHEMAS[schema])
            apply_whole(db_m, a)
            psql(db_m, app)
            lock = migrate.lock_of(database.migratable(a, {})[1])
            if name == OLDER_RLS:  # the lock the older build wrote, and its hash, which its migration recorded
                lock = re.sub(r"(?m)^(rls .*) \| \w+$", r"\1 | 000000000000", lock)
            ms = database.migrations(b, {}, lock, label)
            if name == OLDER_RLS and (all(m.empty for m in ms) or any(re.search(r"(?m)^DROP ", m.sql) for m in ms)):
                failed += 1
                print(
                    f"FAIL  {label}: {'no migration' if all(m.empty for m in ms) else 'the migration drops something'}"
                )
                continue
            if name == REORDERED_COLUMN_RULES and any(re.search(r"(?m)^(CREATE|DROP) TRIGGER", m.sql) for m in ms):
                failed += 1
                print(f"FAIL  {label}: the migration makes a column rule's trigger again")
                continue
            if len(ms) == 1 and ms[0].empty:
                print(f"ok    {label}: no migration needed")
                continue
            # the database applied whole starts as this one is now: a copy (the same as building it again, sooner)
            sh("dropdb", "--if-exists", db_w)
            sh("createdb", "--template", db_m, db_w)
            if name == OLDER_BUILD:
                psql(db_m, OLD_PATHS)
            if name == OLDER_RLS:
                psql(
                    db_m,
                    RLS_OFF + f"UPDATE authz.policy_versions SET lock = '{migrate.digest(lock, 16)}' "
                    "WHERE id = (SELECT max(id) FROM authz.policy_versions);",
                )
            try:
                if len(ms) == 1:
                    psql(db_m, changes)
                    run_migration(db_m, ms[0].sql)
                else:
                    run_migration(db_m, ms[0].sql)  # built beside ...
                    psql(db_m, changes)  # ... while the app writes ...
                    run_migration(db_m, ms[1].sql)  # ... then swapped in
            except RuntimeError as e:
                failed += 1
                print(f"FAIL  {label}: the migration fails\n{e}")
                continue
            psql(db_w, changes)
            try:
                apply_whole(db_w, b)
            except RuntimeError as e:
                failed += 1
                print(f"FAIL  {label}: applying whole fails\n{e}")
                continue
            diffs = compare(snapshot(db_m), snapshot(db_w))
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
            size = " + ".join(f"{len(m.sql) // 1024} KB" for m in ms)
            size += (
                f", {'builds beside and swaps in' if len(ms) == 2 else 'rebuilds'} {', '.join(ms[-1].rebuilt)}"
                if ms[-1].rebuilt
                else ""
            )
            if diffs:
                failed += 1
                print(
                    f"FAIL  {label} ({size}):\n"
                    + "\n".join(diffs[:12])
                    + (f"\n  ... {len(diffs) - 12} more" if len(diffs) > 12 else "")
                )
            else:
                print(f"ok    {label} ({size})")
    if not KEEP:
        for db in ("authz_mig_m", "authz_mig_w"):
            sh("dropdb", "--if-exists", db, check=False)
    print("migrations: all passed" if not failed else f"migrations: {failed} failed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
