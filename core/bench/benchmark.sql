-- =====================================================================
-- benchmark.sql — the compiled policy on a bigger copy of the example app
--   python3 compile_policy.py example/docs.authz > /tmp/docs.sql
--   psql -v ON_ERROR_STOP=1 -d scratch -f example/app_schema.sql
--   psql -v ON_ERROR_STOP=1 -v docs_sql=/tmp/docs.sql -d scratch -f bench/benchmark.sql
-- Loads 2,000 users, 200 nested teams, 10,000 folders (500 also linked
-- into a second folder) and 200,000 files first,
-- then applies docs.sql to that existing data, then times reads as five
-- users through RLS. "no RLS" runs the same queries as the table owner (not authz.can:
-- it reads the policy whoever calls it).
-- Then a big move, what the audit trail and the change feed cost on writes, and
-- nested teams (20,000 more, in chains ten deep and one deep).
-- =====================================================================
\set ON_ERROR_STOP on
\o /dev/null
SET client_min_messages = warning;
SET jit = off;   -- as in a signed-in transaction (authz.act_as turns it off): JIT spends ~0.3 s compiling big RLS reads

TRUNCATE app.folder_links, app.folder_team_access, app.files, app.folders, app.team_members, app.teams,
         app.org_members, app.orgs, app.users CASCADE;
SELECT setseed(0.42);
INSERT INTO app.users SELECT i, 'user_' || i FROM generate_series(1, 2000) i;
INSERT INTO app.orgs VALUES (1, 'Acme');
INSERT INTO app.org_members SELECT 1, i, CASE WHEN i <= 10 THEN 'admin' ELSE 'member' END
FROM generate_series(1, 2000) i;
-- 200 teams: the first 20 are top level, the rest nest under a lower-numbered team
INSERT INTO app.teams SELECT i, 1, CASE WHEN i > 20 THEN 1 + floor(random() * (i - 1))::int END, 'team_' || i
FROM generate_series(1, 200) i;
INSERT INTO app.team_members SELECT DISTINCT 1 + floor(random() * 200)::int, u
FROM generate_series(1, 2000) u, generate_series(1, 3);
INSERT INTO app.folders (id, org_id, parent_id, owner_id, name, inherit)
SELECT i, 1, CASE WHEN i > 1 THEN 1 + floor(random() * (i - 1))::int END,
       1 + floor(random() * 2000)::int, 'folder_' || i, i = 1 OR random() > 0.02
FROM generate_series(1, 10000) i;
INSERT INTO app.files (id, folder_id, owner_id, name, confidential)
SELECT i, 1 + floor(random() * 10000)::int, 1 + floor(random() * 2000)::int,
       'file_' || i, random() < 0.05
FROM generate_series(1, 200000) i;
INSERT INTO app.folder_team_access
SELECT DISTINCT ON (f, t) f, t, CASE WHEN random() < 0.5 THEN 'view' ELSE 'edit' END
FROM (SELECT 1 + floor(random() * 10000)::int f, 1 + floor(random() * 200)::int t
      FROM generate_series(1, 1000)) x;
-- 500 folders also appear inside a second folder
INSERT INTO app.folder_links
SELECT DISTINCT f, p FROM (SELECT 1 + floor(random() * 10000)::int f, 1 + floor(random() * 10000)::int p
                           FROM generate_series(1, 500)) x
WHERE f <> p;
DO $$ BEGIN
  PERFORM setval(pg_get_serial_sequence('app.folders', 'id'), 1000000);
  PERFORM setval(pg_get_serial_sequence('app.files', 'id'), 1000000);
END $$;

-- apply the policy to the data that is already there (closure backfill included)
CREATE TEMP TABLE timing (what text, ms numeric);
INSERT INTO timing SELECT 'start', extract(epoch FROM clock_timestamp()) * 1000;
\i :docs_sql
INSERT INTO timing SELECT 'apply docs.sql (incl. backfill of 10,000 folders)',
  round(extract(epoch FROM clock_timestamp()) * 1000 - (SELECT ms FROM timing WHERE what = 'start'), 1);

-- shares people made in the app: 3,000 on folders, 5,000 on files
TRUNCATE authz.shares;
INSERT INTO authz.shares (object_type, object_id, relation, subject_type, subject_id, subject_relation)
SELECT 'folder', x.f, x.rel, x.st,
       CASE WHEN x.st = 'team' THEN 1 + floor(x.r * 200)::int ELSE 1 + floor(x.r * 2000)::int END,
       CASE WHEN x.st = 'team' THEN 'member' ELSE '' END
FROM (SELECT 1 + floor(random() * 10000)::int AS f,
             CASE WHEN random() < 0.5 THEN 'viewer' ELSE 'editor' END AS rel,
             CASE WHEN random() < 0.6 THEN 'team' ELSE 'user' END AS st,
             random() AS r
      FROM generate_series(1, 3000)) x
ON CONFLICT DO NOTHING;
INSERT INTO authz.shares (object_type, object_id, relation, subject_type, subject_id)
SELECT 'file', 1 + floor(random() * 200000)::int, 'viewer', 'user', 1 + floor(random() * 2000)::int
FROM generate_series(1, 5000) ON CONFLICT DO NOTHING;
VACUUM ANALYZE;

-- harness: $1 = a random folder, $2 = a random file; same sequence for every variant
CREATE SCHEMA bench;
GRANT USAGE ON SCHEMA bench TO app_user;
CREATE TABLE bench.results (variant text, query text, user_id bigint, ms numeric, n bigint);
GRANT INSERT ON bench.results TO app_user;
CREATE FUNCTION bench.run(p_variant text, p_query text, p_sql text, p_reps int) RETURNS void
LANGUAGE plpgsql AS $$
DECLARE u bigint; i int; t0 timestamptz; n bigint;
BEGIN
  PERFORM setseed(0.7);
  FOREACH u IN ARRAY ARRAY[1, 11, 500, 1000, 1500] LOOP   -- user 1 is an org admin
    PERFORM set_config('authz.user_id', u::text, true);
    FOR i IN 1..p_reps LOOP
      t0 := clock_timestamp();
      EXECUTE p_sql INTO n USING (1 + floor(random() * 10000))::bigint, (1 + floor(random() * 200000))::bigint;
      INSERT INTO bench.results VALUES (p_variant, p_query, u,
        (extract(epoch FROM clock_timestamp() - t0) * 1000)::numeric, n);
    END LOOP;
  END LOOP;
END $$;
CREATE FUNCTION bench.run_all(p_variant text) RETURNS void LANGUAGE plpgsql AS $$
BEGIN
  PERFORM bench.run(p_variant, '1. list visible files (of 200,000)', 'SELECT count(*) FROM app.files', 5);
  PERFORM bench.run(p_variant, '2. open a folder',
    'SELECT count(*) FROM (SELECT id, name FROM app.files WHERE folder_id = $1) s', 50);
  PERFORM bench.run(p_variant, '3. open one file',
    'SELECT count(*) FROM (SELECT * FROM app.files WHERE id = $2) s', 200);
  -- authz.can evaluates the policy whoever calls it: as the owner it would be the same call, so it runs once
  IF p_variant <> 'no RLS' THEN
    PERFORM bench.run(p_variant, '4. app check: authz.can(file, edit)',
      'SELECT authz.can(''file'', $2, ''edit'')::int', 200);
  END IF;
END $$;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA bench TO app_user;

-- the same point queries with cached plans (what prepared statements get)
CREATE FUNCTION bench.run_cached(p_variant text) RETURNS void LANGUAGE plpgsql AS $$
DECLARE u bigint; i int; t0 timestamptz; n bigint; x bigint;
BEGIN
  PERFORM setseed(0.7);
  FOREACH u IN ARRAY ARRAY[1, 11, 500, 1000, 1500] LOOP
    PERFORM set_config('authz.user_id', u::text, true);
    FOR i IN 1..200 LOOP
      x := 1 + floor(random() * 200000)::bigint;
      t0 := clock_timestamp();
      SELECT count(*) INTO n FROM app.files WHERE id = x;
      INSERT INTO bench.results VALUES (p_variant, '3b. open one file (cached plan)', u,
        (extract(epoch FROM clock_timestamp() - t0) * 1000)::numeric, n);
    END LOOP;
    FOR i IN 1..50 LOOP
      x := 1 + floor(random() * 10000)::bigint;
      t0 := clock_timestamp();
      SELECT count(*) INTO n FROM app.files WHERE folder_id = x;
      INSERT INTO bench.results VALUES (p_variant, '2b. open a folder (cached plan)', u,
        (extract(epoch FROM clock_timestamp() - t0) * 1000)::numeric, n);
    END LOOP;
  END LOOP;
END $$;
GRANT EXECUTE ON FUNCTION bench.run_cached(text) TO app_user;

SELECT bench.run_all('no RLS');
SELECT bench.run_cached('no RLS');
SET ROLE app_user;
SELECT bench.run_all('compiled policy');
SELECT bench.run_cached('compiled policy');
RESET ROLE;

-- structural writes on the loaded data
DO $$
DECLARE t0 timestamptz; big bigint; sub bigint[]; dest bigint;
BEGIN
  SELECT f.id, s.ids INTO big, sub FROM app.folders f
  CROSS JOIN LATERAL (WITH RECURSIVE t(id) AS (
    SELECT f.id UNION ALL SELECT c.id FROM app.folders c JOIN t ON c.parent_id = t.id)
    SELECT array_agg(id) AS ids FROM t) s
  WHERE f.parent_id = 1 ORDER BY cardinality(s.ids) DESC LIMIT 1;
  SELECT max(id) INTO dest FROM app.folders WHERE id <> ALL (sub);
  t0 := clock_timestamp();
  UPDATE app.folders SET parent_id = dest WHERE id = big;
  INSERT INTO timing VALUES (format('move a folder holding %s subfolders', cardinality(sub)),
    round((extract(epoch FROM clock_timestamp() - t0) * 1000)::numeric, 1));
END $$;

-- what the audit trail and the change feed cost on writes: 10,000 owner changes with their triggers, then without
DO $$
DECLARE t0 timestamptz; r record;
BEGIN
  t0 := clock_timestamp();
  UPDATE app.files SET owner_id = owner_id % 2000 + 1 WHERE id <= 10000;
  INSERT INTO timing VALUES ('change owner_id of 10,000 files, with the audit trail and the change feed',
    round((extract(epoch FROM clock_timestamp() - t0) * 1000)::numeric, 1));
  FOR r IN SELECT tgname FROM pg_trigger WHERE tgrelid = 'app.files'::regclass AND tgname LIKE 'authz\_%audit%' LOOP
    EXECUTE format('ALTER TABLE app.files DISABLE TRIGGER %I', r.tgname);
  END LOOP;
  t0 := clock_timestamp();
  UPDATE app.files SET owner_id = owner_id % 2000 + 1 WHERE id <= 10000;
  INSERT INTO timing VALUES ('... the same without them',
    round((extract(epoch FROM clock_timestamp() - t0) * 1000)::numeric, 1));
  FOR r IN SELECT tgname FROM pg_trigger WHERE tgrelid = 'app.files'::regclass AND tgname LIKE 'authz\_%audit%' LOOP
    EXECUTE format('ALTER TABLE app.files ENABLE TRIGGER %I', r.tgname);
  END LOOP;
END $$;

-- nested groups are expanded per query (limits.md): 20,000 more teams in 2,000 chains ten deep, a user in the bottom
-- team of three chains, a folder given to the top team of one of them; then the same with chains one team deep
CREATE FUNCTION bench.chains(p_depth int) RETURNS void LANGUAGE plpgsql AS $$
BEGIN
  DELETE FROM app.folder_team_access WHERE team_id >= 100000;
  DELETE FROM app.team_members WHERE team_id >= 100000;
  DELETE FROM app.teams WHERE id >= 100000;
  INSERT INTO app.teams (id, org_id, parent_id, name)
  SELECT 100000 + i, 1, CASE WHEN i % p_depth = 0 THEN NULL ELSE 100000 + i - 1 END, 'chain_' || i
  FROM generate_series(0, 19999) i ORDER BY i;
  INSERT INTO app.users VALUES (99999, 'chained') ON CONFLICT DO NOTHING;
  INSERT INTO app.team_members (team_id, user_id)
  SELECT 100000 + c * p_depth + p_depth - 1, 99999 FROM unnest(ARRAY[7, 500, 1999]) c WHERE c * p_depth + p_depth - 1 < 20000;
  INSERT INTO app.folder_team_access VALUES (3, 100000 + 500 * p_depth, 'view');
  ANALYZE app.teams; ANALYZE app.team_members; ANALYZE app.folder_team_access;
END $$;
CREATE FUNCTION bench.chained(p_depth int) RETURNS void LANGUAGE plpgsql AS $$
DECLARE t0 timestamptz; n bigint; q text;
BEGIN
  PERFORM set_config('authz.user_id', '99999', true);
  FOREACH q IN ARRAY ARRAY['SELECT authz.can(''folder'', ''3'', ''view'')::int', 'SELECT count(*) FROM app.files WHERE folder_id = 3',
                           'SELECT authz.can(''folder'', ''4'', ''view'')::int'] LOOP
    FOR i IN 1..300 LOOP
      t0 := clock_timestamp();
      EXECUTE q INTO n;
      INSERT INTO bench.results VALUES (format('teams %s deep', p_depth), q, 99999,
        (extract(epoch FROM clock_timestamp() - t0) * 1000)::numeric, n);
    END LOOP;
  END LOOP;
END $$;
GRANT EXECUTE ON FUNCTION bench.chained(int) TO app_user;
SELECT bench.chains(10);
SET ROLE app_user;
SELECT bench.chained(10);
RESET ROLE;
SELECT bench.chains(1);
SET ROLE app_user;
SELECT bench.chained(1);
RESET ROLE;

\o
\echo '== Applying the policy and writes (ms) =='
SELECT what, ms FROM timing WHERE what <> 'start';
\echo '== Reads through RLS (ms) =='
SELECT query, variant, count(*) AS runs,
       round(percentile_cont(0.5) WITHIN GROUP (ORDER BY ms)::numeric, 2) AS median_ms,
       round(avg(ms), 2) AS avg_ms, round(max(ms), 2) AS max_ms, round(avg(n)) AS avg_rows
FROM bench.results WHERE variant NOT LIKE 'teams %' GROUP BY query, variant ORDER BY query, variant DESC;
\echo '== Nested teams: 20,000 more, in chains; a user in three bottom teams, folder 3 given to one top (ms) =='
SELECT variant AS chains, CASE WHEN query LIKE '%''3'', ''view''%' THEN 'authz.can on the folder'
                               WHEN query LIKE '%''4'', ''view''%' THEN 'authz.can on a folder it can''t see'
                               ELSE 'open the folder (its files)' END AS what,
       round(percentile_cont(0.5) WITHIN GROUP (ORDER BY ms)::numeric, 2) AS median_ms
FROM bench.results WHERE variant LIKE 'teams %' GROUP BY 1, 2 ORDER BY 2, 1 DESC;
\echo '== Per user, compiled policy (median ms; user 1 is an org admin) =='
SELECT user_id,
       max(n) FILTER (WHERE query LIKE '1.%') AS files_visible,
       round(percentile_cont(0.5) WITHIN GROUP (ORDER BY ms) FILTER (WHERE query LIKE '1.%')::numeric, 1) AS list,
       round(percentile_cont(0.5) WITHIN GROUP (ORDER BY ms) FILTER (WHERE query LIKE '2b.%')::numeric, 2) AS open_folder,
       round(percentile_cont(0.5) WITHIN GROUP (ORDER BY ms) FILTER (WHERE query LIKE '3b.%')::numeric, 2) AS open_file,
       round(percentile_cont(0.5) WITHIN GROUP (ORDER BY ms) FILTER (WHERE query LIKE '4.%')::numeric, 2) AS can
FROM bench.results WHERE variant = 'compiled policy'
GROUP BY user_id ORDER BY files_visible DESC;
