-- shares.sql: shares people made in the app, loaded after the policy is applied (bench/scale.sh):
-- 3 per 10 folders (to users or teams, viewer or editor) and 1 per 40 files (to users, viewer).
\set ON_ERROR_STOP on
SET client_min_messages = warning;
INSERT INTO authz.shares (object_type, object_id, relation, subject_type, subject_id, subject_relation)
SELECT 'folder', x.f, x.rel, x.st,
       CASE WHEN x.st = 'team' THEN 1 + floor(x.r * :teams)::int ELSE 1 + floor(x.r * :users)::int END,
       CASE WHEN x.st = 'team' THEN 'member' ELSE '' END
FROM (SELECT 1 + floor(random() * :folders)::bigint AS f,
             CASE WHEN random() < 0.5 THEN 'viewer' ELSE 'editor' END AS rel,
             CASE WHEN random() < 0.6 THEN 'team' ELSE 'user' END AS st,
             random() AS r
      FROM generate_series(1, :folders * 3 / 10)) x
ON CONFLICT DO NOTHING;
INSERT INTO authz.shares (object_type, object_id, relation, subject_type, subject_id)
SELECT 'file', 1 + floor(random() * :files)::bigint, 'viewer', 'user', 1 + floor(random() * :users)::int
FROM generate_series(1, :files / 40) ON CONFLICT DO NOTHING;
-- step 6's first three readers (load.sql's members past :users): shared 100, 1,000 and 4,000 folders each, as
-- viewer, anywhere in the tree (as many as there are, where the tree has fewer)
INSERT INTO authz.shares (object_type, object_id, relation, subject_type, subject_id, subject_relation)
SELECT 'folder', x.id, 'viewer', 'user', :users + h.k, ''
FROM (VALUES (1, 100), (2, 1000), (3, 4000)) h(k, n)
CROSS JOIN LATERAL (SELECT f.id FROM app.folders f WHERE f.id <= :folders ORDER BY random() LIMIT h.n) x
ON CONFLICT DO NOTHING;
