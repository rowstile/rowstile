-- open a folder (list its files) as one user (-D u=<id>), through row-level security: step 6's readers, who hold
-- many folders directly
\set d random(1, :nfolders)
BEGIN;
SET LOCAL ROLE app_user;
SELECT authz.act_as('user', :u::text);
SELECT id, name FROM app.files WHERE folder_id = :d;
COMMIT;
