-- The experiment behind "Why a query through row-level security runs on one CPU".
-- Files with an owner, and shares that give a file to another user. The rule: you see a file you own, or one
-- shared with you. It is written six ways, and the same three queries are timed through each; then a user with
-- many shares meets two of them.
--
--   createdb rls_parallel && psql -X -d rls_parallel -v files=2000000 -f experiment.sql
--
-- It makes a schema `demo` and a role `demo_app`, and drops neither. PostgreSQL 16 or later, default settings
-- but for JIT, which is off. Each query runs three times; read the middle "Execution Time" of each.

\set ON_ERROR_STOP on
\if :{?files} \else \set files 2000000 \endif
\timing off
SET client_min_messages = warning;

DROP SCHEMA IF EXISTS demo CASCADE;
DROP ROLE IF EXISTS demo_app;
CREATE ROLE demo_app;
CREATE SCHEMA demo;
GRANT USAGE ON SCHEMA demo TO demo_app;

CREATE TABLE demo.files (
  id       bigint PRIMARY KEY,
  owner_id bigint NOT NULL,
  name     text   NOT NULL
);
CREATE TABLE demo.shares (
  file_id bigint NOT NULL REFERENCES demo.files,
  user_id bigint NOT NULL,
  PRIMARY KEY (file_id, user_id)
);

-- A thousand users, each owning a thousandth of the files. Every fourth file is shared with one of users 1 to
-- 999. User 1000 is the support team: every fiftieth file is shared with it as well. User 1001, an auditor,
-- has every fifth file shared with it, and appears only in the last section.
INSERT INTO demo.files
SELECT i, 1 + (i * 7919) % 1000, 'file ' || md5(i::text)
FROM generate_series(1, :files::bigint) i;
INSERT INTO demo.shares
SELECT i, 1 + (i * 104729) % 999 FROM generate_series(4, :files::bigint, 4) i
UNION ALL
SELECT i, 1000 FROM generate_series(50, :files::bigint, 50) i
UNION ALL
SELECT i, 1001 FROM generate_series(5, :files::bigint, 5) i;
CREATE INDEX ON demo.files (owner_id);
CREATE INDEX ON demo.shares (user_id);
VACUUM ANALYZE demo.files;
VACUUM ANALYZE demo.shares;
GRANT SELECT ON demo.files, demo.shares TO demo_app;
ALTER TABLE demo.files ENABLE ROW LEVEL SECURITY;

SELECT version();
SELECT (SELECT count(*) FROM demo.files) AS files, (SELECT count(*) FROM demo.shares) AS shares,
       pg_size_pretty(pg_table_size('demo.files')) AS files_size,
       current_setting('max_parallel_workers_per_gather') AS max_parallel_workers_per_gather,
       current_setting('work_mem') AS work_mem, current_setting('hash_mem_multiplier') AS hash_mem_multiplier;

-- The three queries: the count of what user 7 sees (a user with a few shares), the same for user 1000 (the
-- support team, with many), and one file opened by user 1000.
\set as_7 'SET ROLE demo_app; SET demo.user_id = ''7''; SET jit = off;'
\set as_1000 'SET ROLE demo_app; SET demo.user_id = ''1000''; SET jit = off;'
\set count_all 'EXPLAIN (ANALYZE, COSTS OFF, TIMING OFF, BUFFERS OFF) SELECT count(*) FROM demo.files;'
\set one_file 'EXPLAIN (ANALYZE, COSTS OFF, TIMING OFF, BUFFERS OFF) SELECT id, name FROM demo.files WHERE id = 100;'

\echo
\echo '=== 0. no policy: the table''s owner counts every file ==='
SET jit = off;
:count_all
:count_all
:count_all

\echo
\echo '=== 1. IN, the user from a setting ==='
CREATE POLICY files_select ON demo.files FOR SELECT TO demo_app USING (
  owner_id = current_setting('demo.user_id')::bigint
  OR id IN (SELECT s.file_id FROM demo.shares s WHERE s.user_id = current_setting('demo.user_id')::bigint));
:as_7
SELECT count(*) AS files_user_7_sees FROM demo.files;
:count_all
:count_all
:count_all
:as_1000
SELECT count(*) AS files_user_1000_sees FROM demo.files;
:count_all
:count_all
:count_all
:one_file
:one_file
:one_file
RESET ROLE;
DROP POLICY files_select ON demo.files;

\echo
\echo '=== 2. IN, the user from a function ==='
-- the usual way to name the user in a policy: a small function, which CREATE FUNCTION marks PARALLEL UNSAFE
-- unless told otherwise
CREATE FUNCTION demo.uid() RETURNS bigint LANGUAGE sql STABLE AS $$
  SELECT current_setting('demo.user_id')::bigint $$;
CREATE POLICY files_select ON demo.files FOR SELECT TO demo_app USING (
  owner_id = demo.uid()
  OR id IN (SELECT s.file_id FROM demo.shares s WHERE s.user_id = demo.uid()));
:as_7
:count_all
:count_all
:count_all
:as_1000
:count_all
:count_all
:count_all
:one_file
:one_file
:one_file
RESET ROLE;
DROP POLICY files_select ON demo.files;

\echo
\echo '=== 3. IN, the function marked parallel safe ==='
ALTER FUNCTION demo.uid() PARALLEL SAFE;
CREATE POLICY files_select ON demo.files FOR SELECT TO demo_app USING (
  owner_id = demo.uid()
  OR id IN (SELECT s.file_id FROM demo.shares s WHERE s.user_id = demo.uid()));
:as_7
:count_all
:count_all
:count_all
:as_1000
:count_all
:count_all
:count_all
:one_file
:one_file
:one_file
RESET ROLE;
DROP POLICY files_select ON demo.files;

\echo
\echo '=== 4. EXISTS, the function marked parallel safe ==='
CREATE POLICY files_select ON demo.files FOR SELECT TO demo_app USING (
  owner_id = demo.uid()
  OR EXISTS (SELECT 1 FROM demo.shares s WHERE s.file_id = files.id AND s.user_id = demo.uid()));
:as_7
:count_all
:count_all
:count_all
:as_1000
:count_all
:count_all
:count_all
:one_file
:one_file
:one_file
RESET ROLE;
DROP POLICY files_select ON demo.files;

\echo
\echo '=== 5. IN, the user read once: (SELECT demo.uid()) ==='
CREATE POLICY files_select ON demo.files FOR SELECT TO demo_app USING (
  owner_id = (SELECT demo.uid())
  OR id IN (SELECT s.file_id FROM demo.shares s WHERE s.user_id = (SELECT demo.uid())));
:as_7
:count_all
:count_all
:count_all
:as_1000
:count_all
:count_all
:count_all
:one_file
:one_file
:one_file
RESET ROLE;
DROP POLICY files_select ON demo.files;

\echo
\echo '=== 6. IN, the user read once outside the subquery only ==='
CREATE POLICY files_select ON demo.files FOR SELECT TO demo_app USING (
  owner_id = (SELECT demo.uid())
  OR id IN (SELECT s.file_id FROM demo.shares s WHERE s.user_id = demo.uid()));
:as_7
:count_all
:count_all
:count_all
:as_1000
:count_all
:count_all
:count_all
:one_file
:one_file
:one_file
RESET ROLE;
DROP POLICY files_select ON demo.files;

\echo
\echo '=== 7. user 1001, the auditor: IN, then EXISTS ==='
CREATE POLICY files_select ON demo.files FOR SELECT TO demo_app USING (
  owner_id = demo.uid()
  OR id IN (SELECT s.file_id FROM demo.shares s WHERE s.user_id = demo.uid()));
SET ROLE demo_app; SET demo.user_id = '1001'; SET jit = off;
EXPLAIN (COSTS OFF) SELECT count(*) FROM demo.files;
-- with two million files the auditor's shares are too many to hash: the list is searched for each file, and
-- the count doesn't end in thirty seconds
SET statement_timeout = '30s';
\set ON_ERROR_STOP off
SELECT count(*) AS files_user_1001_sees FROM demo.files;
\set ON_ERROR_STOP on
RESET statement_timeout;
RESET ROLE;
DROP POLICY files_select ON demo.files;
CREATE POLICY files_select ON demo.files FOR SELECT TO demo_app USING (
  owner_id = demo.uid()
  OR EXISTS (SELECT 1 FROM demo.shares s WHERE s.file_id = files.id AND s.user_id = demo.uid()));
SET ROLE demo_app; SET demo.user_id = '1001'; SET jit = off;
SELECT count(*) AS files_user_1001_sees FROM demo.files;
:count_all
:count_all
:count_all
:one_file
:one_file
:one_file
RESET ROLE;
DROP POLICY files_select ON demo.files;
