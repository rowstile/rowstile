-- tree write in one part of the tree (step 7; bench/parts.sql makes the parts): an org admin moves one of the
-- part's eight folders that move, with the nine below it, to another of the five that stay, through row-level
-- security. The new parent is never the old one and never inside a folder that moves: every move rewrites ten
-- folders, and none makes a loop. The part is the client's own (apart = 1) or the first one, everybody's (0).
\set a random(1, 10)
\set part :part_first + (:client_id % :parts) * :apart * 100
\set m :part + 5 + 10 * random(0, 7)
\set by random(1, 4)
BEGIN;
SET LOCAL ROLE app_user;
SELECT authz.act_as('user', :a::text);
UPDATE app.folders SET parent_id = :part + (parent_id - :part + :by) % 5 WHERE id = :m;
COMMIT;
