-- parts.sql: the parts of the tree step 7 writes in (bench/run.sh), made when the steps before it are over.
--   psql -v parts=50 -v levels=20 -f bench/parts.sql
-- A part is 85 folders that nothing else in the benchmark writes to, and no folder of one part is inside
-- another's: writers who each keep to a part of their own write nothing in common. In a part:
--   the top, under a folder of the loaded tree's middle level (those never move, so a part stays where it is);
--   four folders in it. These five stay where they are;
--   eight folders that move among those five, each with three folders inside and two inside each of those: a
--   move rewrites ten folders, every time.
-- No links, so a part is in nothing but the folders above its top.
-- Ids: a part has a hundred of its own, taken from the folders' sequence, so no row made before or after has one.
-- The workload works a folder's id out from the part's first, without a query: the top is the first itself, the
-- four in it the first + 1 to 4, the eight that move the first + 5, 15, ... 75, each with its nine right after it.
\set ON_ERROR_STOP on
SET client_min_messages = warning;
CREATE TABLE bench.parts AS
SELECT nextval(pg_get_serial_sequence('app.folders', 'id')) AS first_id, :parts AS parts;
SELECT setval(pg_get_serial_sequence('app.folders', 'id'), first_id + parts * 100) FROM bench.parts;
SELECT first_id AS first FROM bench.parts \gset

-- One statement for each level, the level above first. k: the part; s: one of the four that stay beside the top;
-- m: one of the eight that move; c: one of the three inside it; g: one of the two inside each of those.
INSERT INTO app.folders (id, org_id, parent_id, owner_id, name)
SELECT :first + k * 100, 1, l.first_id + k % (l.last_id - l.first_id + 1), 1, 'part'
FROM generate_series(0, :parts - 1) k, bench.levels l
WHERE l.level = greatest(1, :levels / 2);
INSERT INTO app.folders (id, org_id, parent_id, owner_id, name)
SELECT :first + k * 100 + s, 1, :first + k * 100, 1, 'stays'
FROM generate_series(0, :parts - 1) k, generate_series(1, 4) s;
INSERT INTO app.folders (id, org_id, parent_id, owner_id, name)
SELECT :first + k * 100 + 5 + 10 * m, 1, :first + k * 100 + 1 + m % 4, 1, 'moves'
FROM generate_series(0, :parts - 1) k, generate_series(0, 7) m;
INSERT INTO app.folders (id, org_id, parent_id, owner_id, name)
SELECT :first + k * 100 + 5 + 10 * m + c, 1, :first + k * 100 + 5 + 10 * m, 1, 'inside'
FROM generate_series(0, :parts - 1) k, generate_series(0, 7) m, generate_series(1, 3) c;
INSERT INTO app.folders (id, org_id, parent_id, owner_id, name)
SELECT :first + k * 100 + 5 + 10 * m + 2 + 2 * c + g, 1, :first + k * 100 + 5 + 10 * m + c, 1, 'inside'
FROM generate_series(0, :parts - 1) k, generate_series(0, 7) m, generate_series(1, 3) c, generate_series(0, 1) g;
