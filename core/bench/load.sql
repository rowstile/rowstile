-- load.sql: the example app at scale, for bench/scale.sh.
--   psql -v files=400000 -v folders=20000 -v levels=20 -v users=1000 -v teams=100 -f bench/load.sql
--   (scale.sh sets them for each size; these are its dev size)
-- Folders form a tree exactly `levels` deep: level 1 holds a few roots and each level is about 1.5
-- times wider than the one above, so most folders sit deep down, as in real file trees. Folder ids
-- are contiguous per level (bench.levels), which lets the write workload pick targets that can't
-- make a loop. Files are spread evenly over all folders.
\set ON_ERROR_STOP on
SET client_min_messages = warning;
SELECT set_config('bench.files', :'files', false), set_config('bench.folders', :'folders', false),
       set_config('bench.levels', :'levels', false), set_config('bench.users', :'users', false),
       set_config('bench.teams', :'teams', false);
SELECT setseed(0.42);

-- app_schema.sql comes with a little sample data
TRUNCATE app.folder_links, app.folder_team_access, app.files, app.folders, app.team_members, app.teams,
         app.org_members, app.orgs, app.users CASCADE;
INSERT INTO app.users SELECT i, 'user_' || i FROM generate_series(1, :users) i;
INSERT INTO app.orgs VALUES (1, 'Acme');
-- users 1..10 are org admins (they may edit every folder); everyone is a member
INSERT INTO app.org_members SELECT 1, i, CASE WHEN i <= 10 THEN 'admin' ELSE 'member' END FROM generate_series(1, :users) i;
-- teams: a tenth are top level, the rest nest under a lower-numbered team; 3 teams per user
INSERT INTO app.teams SELECT i, 1, CASE WHEN i > :teams / 10 THEN 1 + floor(random() * (i - 1))::int END, 'team_' || i
FROM generate_series(1, :teams) i;
INSERT INTO app.team_members SELECT DISTINCT 1 + floor(random() * :teams)::int, u FROM generate_series(1, :users) u, generate_series(1, 3);

CREATE SCHEMA bench;
CREATE TABLE bench.levels (level int PRIMARY KEY, first_id bigint, last_id bigint);
DO $$
DECLARE
  n bigint := current_setting('bench.folders')::bigint;
  depth int := current_setting('bench.levels')::int;
  users int := current_setting('bench.users')::int;
  r numeric := 1.5;
  roots numeric := n * (r - 1) / (power(r, depth) - 1);
  first bigint := 1; size bigint; k int;
  up_first bigint; up_size bigint;          -- the level above (a subquery here would run once, not per row)
BEGIN
  FOR k IN 1..depth LOOP
    size := CASE WHEN k = depth THEN n - first + 1 ELSE greatest(1, round(roots * power(r, k - 1))) END;
    INSERT INTO app.folders (id, org_id, parent_id, owner_id, name, inherit)
    SELECT i, 1,
           CASE WHEN k > 1 THEN up_first + floor(random() * up_size)::bigint END,
           1 + floor(random() * users)::int, 'folder_' || i, k = 1 OR random() > 0.02
    FROM generate_series(first, first + size - 1) i;
    INSERT INTO bench.levels VALUES (k, first, first + size - 1);
    up_first := first; up_size := size;
    first := first + size;
  END LOOP;
END $$;

INSERT INTO app.files (id, folder_id, owner_id, name, confidential)
SELECT i, 1 + floor(random() * :folders)::bigint, 1 + floor(random() * :users)::int, 'file_' || i, random() < 0.05
FROM generate_series(1, :files) i;
-- a tenth of the folders give a team access; a twentieth also appear inside a second folder
INSERT INTO app.folder_team_access
SELECT DISTINCT ON (f, t) f, t, CASE WHEN random() < 0.5 THEN 'view' ELSE 'edit' END
FROM (SELECT 1 + floor(random() * :folders)::bigint f, 1 + floor(random() * :teams)::int t
      FROM generate_series(1, :folders / 10)) x;
-- ...into a folder nearer the top (ids below its level's), so no folder ends up inside itself: apps refuse
-- such links, and a random link would often put a whole top folder inside one of its own descendants
INSERT INTO app.folder_links
SELECT DISTINCT x.f, 1 + floor(random() * (l.first_id - 1))::bigint
FROM (SELECT 1 + floor(random() * :folders)::bigint f FROM generate_series(1, :folders / 20)) x
JOIN bench.levels l ON x.f BETWEEN l.first_id AND l.last_id
WHERE l.level > 1;
-- runs one write of the workload; a move that would put a folder inside itself, or a link that exists,
-- is refused (as an app's UI would refuse it) and counts as done
CREATE FUNCTION bench.try(stmt text) RETURNS void LANGUAGE plpgsql AS $$
BEGIN
  EXECUTE stmt;
EXCEPTION WHEN check_violation OR unique_violation THEN NULL;
END $$;
GRANT USAGE ON SCHEMA bench TO app_user;
GRANT EXECUTE ON FUNCTION bench.try(text) TO app_user;
-- new rows made by the write workload get ids far above the loaded ones
SELECT setval(pg_get_serial_sequence('app.folders', 'id'), :folders * 10);
SELECT setval(pg_get_serial_sequence('app.files', 'id'), :files * 10);
