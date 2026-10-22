-- The experiment behind "Why a recursive row-level security policy is slow, and what fixes it".
-- Folders in a tree, files in folders, and one rule: you see a file if you own its folder or any folder above
-- it. The rule is written four ways, and the same three queries are timed through each.
--
--   createdb rls_tree && psql -X -d rls_tree -v folders=20000 -f experiment.sql
--
-- PostgreSQL 16 or later, as a superuser or as any role with CREATEROLE that may create a schema in the
-- database (createdb makes you its owner). It first drops any earlier schema `demo` and role `demo_app`, then
-- makes them and leaves both at the end. Each query runs three times; read the middle "Execution Time" of each.

\set ON_ERROR_STOP on
\if :{?folders} \else \set folders 20000 \endif
\timing off
SET client_min_messages = warning;

DROP SCHEMA IF EXISTS demo CASCADE;
DROP ROLE IF EXISTS demo_app;
CREATE ROLE demo_app;
-- so that SET ROLE demo_app works for a role that isn't a superuser too
GRANT demo_app TO CURRENT_USER;
CREATE SCHEMA demo;
GRANT USAGE ON SCHEMA demo TO demo_app;

CREATE TABLE demo.folders (
  id        bigint PRIMARY KEY,
  parent_id bigint REFERENCES demo.folders,
  owner_id  bigint NOT NULL,
  name      text   NOT NULL
);
CREATE TABLE demo.files (
  id        bigint PRIMARY KEY,
  folder_id bigint NOT NULL REFERENCES demo.folders,
  name      text   NOT NULL
);

-- 100 workspaces at the top, each owned by its own user (1 to 100). Below them a tree four wide: folders 101
-- to 104 are inside folder 1, 105 to 108 inside folder 2, and so on. Every folder below a workspace belongs to
-- one of 900 other users. Ten files in each folder.
INSERT INTO demo.folders
SELECT i, CASE WHEN i <= 100 THEN NULL ELSE (i - 101) / 4 + 1 END,
       CASE WHEN i <= 100 THEN i ELSE 101 + (i * 7919) % 900 END, 'folder ' || i
FROM generate_series(1, :folders) i;
INSERT INTO demo.files
SELECT (f.id - 1) * 10 + n, f.id, 'file ' || md5(((f.id - 1) * 10 + n)::text)
FROM demo.folders f, generate_series(1, 10) n;
CREATE INDEX ON demo.folders (parent_id);
CREATE INDEX ON demo.folders (owner_id);
CREATE INDEX ON demo.files (folder_id);
CREATE INDEX ON demo.files (name);
ANALYZE demo.folders;
ANALYZE demo.files;
GRANT SELECT ON demo.folders, demo.files TO demo_app;
ALTER TABLE demo.files ENABLE ROW LEVEL SECURITY;

SELECT count(*) AS folders, (SELECT count(*) FROM demo.files) AS files,
       (WITH RECURSIVE d AS (SELECT id, 1 AS depth FROM demo.folders WHERE parent_id IS NULL
                             UNION ALL SELECT f.id, d.depth + 1 FROM demo.folders f JOIN d ON f.parent_id = d.id)
        SELECT max(depth) FROM d) AS deepest
FROM demo.folders;

-- The three queries, as the app's role and as user 7, who owns workspace 7 and so sees what is inside it.
-- JIT is off: on small rows it costs more to compile these plans than to run them.
\set as_user 'SET ROLE demo_app; SET demo.user_id = ''7''; SET jit = off;'
\set count_all 'EXPLAIN (ANALYZE, COSTS OFF, TIMING OFF, BUFFERS OFF) SELECT count(*) FROM demo.files;'
\set first_page 'EXPLAIN (ANALYZE, COSTS OFF, TIMING OFF, BUFFERS OFF) SELECT id, name FROM demo.files ORDER BY name LIMIT 50;'
\set one_file 'EXPLAIN (ANALYZE, COSTS OFF, TIMING OFF, BUFFERS OFF) SELECT id, name FROM demo.files WHERE id = 61;'

\echo
\echo '=== 1. a recursive query in the policy ==='
CREATE POLICY files_select ON demo.files FOR SELECT TO demo_app USING (
  EXISTS (
    WITH RECURSIVE up AS (
      SELECT f.id, f.parent_id, f.owner_id FROM demo.folders f WHERE f.id = files.folder_id
      UNION ALL
      SELECT p.id, p.parent_id, p.owner_id FROM demo.folders p JOIN up ON p.id = up.parent_id
    )
    SELECT 1 FROM up WHERE up.owner_id = current_setting('demo.user_id')::bigint));
:as_user
SELECT count(*) AS files_user_7_sees FROM demo.files;
:count_all
:count_all
:count_all
:first_page
:first_page
:first_page
:one_file
:one_file
:one_file
RESET ROLE;
DROP POLICY files_select ON demo.files;

\echo
\echo '=== 2. the walk in a function, called for each row ==='
CREATE FUNCTION demo.owns_above(p_folder bigint) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $$
  WITH RECURSIVE up AS (
    SELECT f.id, f.parent_id, f.owner_id FROM demo.folders f WHERE f.id = p_folder
    UNION ALL
    SELECT p.id, p.parent_id, p.owner_id FROM demo.folders p JOIN up ON p.id = up.parent_id
  )
  SELECT EXISTS (SELECT 1 FROM up WHERE up.owner_id = current_setting('demo.user_id')::bigint) $$;
CREATE POLICY files_select ON demo.files FOR SELECT TO demo_app USING (demo.owns_above(folder_id));
:as_user
:count_all
:count_all
:count_all
:first_page
:first_page
:first_page
:one_file
:one_file
:one_file
RESET ROLE;
DROP POLICY files_select ON demo.files;

\echo
\echo '=== 3. a table of every folder with each folder above it, looked up for each row ==='
CREATE TABLE demo.folder_tree (
  descendant bigint NOT NULL REFERENCES demo.folders ON DELETE CASCADE,
  ancestor   bigint NOT NULL REFERENCES demo.folders ON DELETE CASCADE,
  PRIMARY KEY (descendant, ancestor)
);
INSERT INTO demo.folder_tree
WITH RECURSIVE up AS (
  SELECT id AS descendant, id AS ancestor, parent_id FROM demo.folders
  UNION ALL
  SELECT up.descendant, p.id, p.parent_id FROM up JOIN demo.folders p ON p.id = up.parent_id
)
SELECT descendant, ancestor FROM up;
CREATE INDEX ON demo.folder_tree (ancestor);
ANALYZE demo.folder_tree;
GRANT SELECT ON demo.folder_tree TO demo_app;
SELECT count(*) AS rows_in_the_tree_table, pg_size_pretty(pg_total_relation_size('demo.folder_tree')) AS its_size
FROM demo.folder_tree;

CREATE POLICY files_select ON demo.files FOR SELECT TO demo_app USING (
  EXISTS (SELECT 1 FROM demo.folder_tree t JOIN demo.folders a ON a.id = t.ancestor
          WHERE t.descendant = files.folder_id AND a.owner_id = current_setting('demo.user_id')::bigint));
:as_user
:count_all
:count_all
:count_all
:first_page
:first_page
:first_page
:one_file
:one_file
:one_file
RESET ROLE;
DROP POLICY files_select ON demo.files;

\echo
\echo '=== 4. the same table, asked once: the set of folders the user may see ==='
CREATE POLICY files_select ON demo.files FOR SELECT TO demo_app USING (
  folder_id IN (SELECT t.descendant FROM demo.folder_tree t JOIN demo.folders a ON a.id = t.ancestor
                WHERE a.owner_id = current_setting('demo.user_id')::bigint));
:as_user
:count_all
:count_all
:count_all
:first_page
:first_page
:first_page
:one_file
:one_file
:one_file
RESET ROLE;

\echo
\echo '=== what a move costs with the table: folder 7''s first child, with all below it, moved under workspace 8 ==='
SELECT min(id) AS moved FROM demo.folders WHERE parent_id = 7 \gset
SELECT count(*) AS folders_below_it_and_itself FROM demo.folder_tree WHERE ancestor = :moved;
BEGIN;
\timing on
UPDATE demo.folders SET parent_id = 8 WHERE id = :moved;
-- the rows that tied the moved folders to what was above the old place go; rows for what is above the new
-- place come
DELETE FROM demo.folder_tree t
USING demo.folder_tree below, demo.folder_tree above
WHERE below.ancestor = :moved AND t.descendant = below.descendant
  AND above.descendant = :moved AND above.ancestor <> :moved AND t.ancestor = above.ancestor;
INSERT INTO demo.folder_tree
SELECT below.descendant, above.ancestor
FROM demo.folder_tree below, demo.folder_tree above
WHERE below.ancestor = :moved AND above.descendant = 8;
\timing off
-- the table against a fresh build, row by row: both differences must be empty
WITH RECURSIVE up AS (
  SELECT id AS descendant, id AS ancestor, parent_id FROM demo.folders
  UNION ALL
  SELECT up.descendant, p.id, p.parent_id FROM up JOIN demo.folders p ON p.id = up.parent_id
), fresh AS (SELECT descendant, ancestor FROM up)
SELECT (SELECT count(*) FROM demo.folder_tree) AS rows_now,
       (SELECT count(*) FROM fresh) AS rows_if_built_again,
       (SELECT count(*) FROM (SELECT * FROM demo.folder_tree EXCEPT SELECT * FROM fresh) x) AS rows_only_in_the_table,
       (SELECT count(*) FROM (SELECT * FROM fresh EXCEPT SELECT * FROM demo.folder_tree) x) AS rows_only_in_a_fresh_build;
ROLLBACK;

\echo
\echo '=== the same recursive policy on the folders themselves: Postgres refuses it ==='
-- a policy on a table that reads that table through the policy again
ALTER TABLE demo.folders ENABLE ROW LEVEL SECURITY;
CREATE POLICY folders_select ON demo.folders FOR SELECT TO demo_app USING (
  EXISTS (
    WITH RECURSIVE up AS (
      SELECT f.id, f.parent_id, f.owner_id FROM demo.folders f WHERE f.id = folders.id
      UNION ALL
      SELECT p.id, p.parent_id, p.owner_id FROM demo.folders p JOIN up ON p.id = up.parent_id
    )
    SELECT 1 FROM up WHERE up.owner_id = current_setting('demo.user_id')::bigint));
:as_user
\set ON_ERROR_STOP off
SELECT count(*) FROM demo.folders;
\set ON_ERROR_STOP on
RESET ROLE;
DROP POLICY folders_select ON demo.folders;
ALTER TABLE demo.folders DISABLE ROW LEVEL SECURITY;
