-- two tree writes in one part of the tree (step 7; bench/parts.sql makes the parts): an org admin makes a folder
-- inside any of the part's 85 folders, through row-level security, then deletes it in a transaction of its own.
-- So a part keeps its size however long the step runs and however many write to it. The part is the client's own
-- (apart = 1) or the first one, everybody's (apart = 0).
\set a random(1, 10)
\set part :part_first + (:client_id % :parts) * :apart * 100
\set p :part + random(0, 84)
BEGIN;
SET LOCAL ROLE app_user;
SELECT authz.act_as('user', :a::text);
INSERT INTO app.folders (org_id, parent_id, owner_id, name) VALUES (1, :p, :a, 'bench') RETURNING id AS made \gset
COMMIT;
BEGIN;
SET LOCAL ROLE app_user;
SELECT authz.act_as('user', :a::text);
DELETE FROM app.folders WHERE id = :made;
COMMIT;
