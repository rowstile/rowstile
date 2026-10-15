-- =====================================================================
-- scenario.sql — end-to-end checks of the compiled policy, through RLS
--   python3 compile_policy.py example/docs.authz > /tmp/docs.sql
--   python3 compile_policy.py example/docs.authz --tests > /tmp/docs_tests.sql
--   psql -v ON_ERROR_STOP=1 -d scratch -f example/app_schema.sql
--   psql -v ON_ERROR_STOP=1 -d scratch -f /tmp/docs.sql
--   psql -v ON_ERROR_STOP=1 -v docs_tests=/tmp/docs_tests.sql -d scratch -f tests/scenario.sql
-- =====================================================================
\set ON_ERROR_STOP on
\o /dev/null
SET client_min_messages = notice;

CREATE SCHEMA test;
GRANT USAGE ON SCHEMA test TO app_user;
CREATE FUNCTION test.ok(label text, pass boolean) RETURNS void LANGUAGE plpgsql AS $$
BEGIN
  IF pass IS NOT TRUE THEN RAISE EXCEPTION 'FAIL  %', label; END IF;
  RAISE NOTICE 'ok    %', label;
END $$;
CREATE FUNCTION test.files() RETURNS text LANGUAGE sql AS $$
  SELECT coalesce(string_agg(name, ', ' ORDER BY name), '-') FROM app.files $$;
CREATE FUNCTION test.try(stmt text) RETURNS text LANGUAGE plpgsql AS $$
BEGIN EXECUTE stmt; RETURN 'ok'; EXCEPTION WHEN OTHERS THEN RETURN SQLSTATE; END $$;
CREATE FUNCTION test.rows(stmt text) RETURNS bigint LANGUAGE plpgsql AS $$
DECLARE n bigint; BEGIN EXECUTE stmt; GET DIAGNOSTICS n = ROW_COUNT; RETURN n; END $$;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA test TO app_user;

-- ---------------------------------------------------------------------
-- Sharing through the API (the policy decides who may share what)
-- ---------------------------------------------------------------------
SET ROLE app_user;
SET authz.user_id = 5;   -- erin owns Company
SELECT test.ok('erin shares Company with every Acme member',
  test.try($$SELECT authz.share('folder', 1, 'viewer', 'org', 1, 'member')$$) = 'ok');
SELECT test.ok('erin shares offer-letter.pdf with dave, for one day',
  test.try($$SELECT authz.share('file', 13, 'viewer', 'user', 4, '', now() + interval '1 day')$$) = 'ok');
SELECT test.ok('shares the policy does not declare are refused',
  test.try($$SELECT authz.share('folder', 1, 'owner', 'user', 3)$$) = 'P0001');
SET authz.user_id = 3;   -- carol
SELECT test.ok('carol cannot share Company',
  test.try($$SELECT authz.share('folder', 1, 'viewer', 'user', 4)$$) = '42501');
SELECT test.ok('the raw shares table is off limits',
  test.try($$SELECT * FROM authz.shares$$) = '42501');
RESET ROLE;
RESET authz.user_id;

-- the tests written at the bottom of the policy file
\i :docs_tests

-- ---------------------------------------------------------------------
-- Reads through RLS
-- ---------------------------------------------------------------------
SET ROLE app_user;
SET authz.user_id = 3;
SELECT test.ok('carol: Company tree, minus Secrets and the confidential file, plus the linked Joint project',
  test.files() = 'architecture.md, handbook.pdf, joint-plan.md');
SET authz.user_id = 1;
SELECT test.ok('alice: same, her ownership of Engineering stops at Secrets',
  test.files() = 'architecture.md, handbook.pdf, joint-plan.md');
SET authz.user_id = 2;
SELECT test.ok('bob: plus Secrets and Keys through the Backend team (app table)',
  test.files() = 'architecture.md, handbook.pdf, joint-plan.md, offer-letter.pdf, prod-keys.txt');
SET authz.user_id = 5;
SELECT test.ok('erin (Acme admin): every Acme file, confidential included',
  test.files() = 'architecture.md, handbook.pdf, joint-plan.md, offer-letter.pdf, prod-keys.txt, salaries.xlsx');
SET authz.user_id = 4;
SELECT test.ok('dave (guest): only the file shared with him',
  test.files() = 'offer-letter.pdf');
SET authz.user_id = 6;
SELECT test.ok('frank (Globex): only Globex', test.files() = 'globex-plan.md, joint-plan.md');
SET authz.user_id = 7;
SELECT test.ok('gina (only in Platform, inside Backend, inside Engineering): both teams'' folders',
  test.files() = 'architecture.md, offer-letter.pdf, prod-keys.txt');
SET authz.user_id = 1;
SELECT test.ok('alice is a member of Engineering only (membership flows up, not down)',
  (SELECT array_agg(id ORDER BY id) FROM authz_gen.team__member) = '{10}');
SET authz.user_id = 7;
SELECT test.ok('gina counts as a member of Platform, Backend and Engineering',
  (SELECT array_agg(id ORDER BY id) FROM authz_gen.team__member) = '{10,11,12}');
-- who has access, and why
SET authz.user_id = 1;
SELECT test.ok('alice (can share architecture.md) sees who can view it: alice, bob, carol, erin, gina',
  (SELECT array_agg(x ORDER BY x) FROM authz.who('file', 11, 'view') x) = '{1,2,3,5,7}');
SELECT test.ok('... and who can edit it (carol only views)',
  (SELECT array_agg(x ORDER BY x) FROM authz.who('file', 11, 'edit') x) = '{1,2,5,7}');
SELECT test.ok('explain: gina edits it through Platform, inside Backend, inside Engineering',
  (SELECT count(*) FROM authz.explain('file', 11, 'edit', '7') e WHERE e LIKE '%through team 12%') = 1
  AND (SELECT e FROM authz.explain('file', 11, 'edit', '7') e LIMIT 1) = 'yes  user 7 holds edit on file 11');
SET authz.user_id = 3;
SELECT test.ok('carol (viewer) cannot list who has access', test.try($$SELECT authz.who('file', 11, 'view')$$) = '42501');
SELECT test.ok('... nor ask about other people', test.try($$SELECT authz.explain('file', 11, 'view', '4')$$) = '42501');
SELECT test.ok('... but can ask why she may not edit it',
  (SELECT e FROM authz.explain('file', 11, 'edit') e LIMIT 1) = 'no   user 3 does not hold edit on file 11');
SET authz.user_id = 4;
SELECT test.ok('dave, with no access to file 11, learns nothing about it',
  (SELECT array_agg(e) FROM authz.explain('file', 11, 'view') e) = '{"no   you have no access to file 11"}');
SET authz.user_id = 5;
SELECT test.ok('erin sees Company''s shares, including the one to Acme members',
  (SELECT count(*) FROM authz.list_shares('folder', 1) WHERE subject_type = 'org' AND subject_relation = 'member') = 1);
SELECT test.ok('authz.perms: erin holds everything on Company', authz.perms('folder', 1) = '{share,edit,view,break_glass}');
RESET authz.user_id;
SELECT test.ok('no user: nothing', test.files() = '-');
RESET ROLE;

-- a second place for Keys: linked into Handbook, which carol can view
INSERT INTO app.folder_links VALUES (6, 2);
SET ROLE app_user;
SET authz.user_id = 3;
SELECT test.ok('Keys linked into Handbook: carol reaches prod-keys.txt although Secrets blocks it',
  test.files() = 'architecture.md, handbook.pdf, joint-plan.md, prod-keys.txt');
RESET ROLE;
DELETE FROM app.folder_links WHERE folder_id = 6 AND parent_id = 2;
SET ROLE app_user;
SELECT test.ok('link removed: prod-keys.txt is gone again',
  test.files() = 'architecture.md, handbook.pdf, joint-plan.md');

-- ---------------------------------------------------------------------
-- Writes through RLS
-- ---------------------------------------------------------------------
SET authz.user_id = 1;   -- alice, owner of Engineering
SELECT test.ok('alice adds a file to Design docs, as its owner',
  test.try($$INSERT INTO app.files (folder_id, owner_id, name) VALUES (4, 1, 'api-spec.md') RETURNING id$$) = 'ok');
SELECT test.ok('alice cannot add a file claiming carol owns it',
  test.try($$INSERT INTO app.files (folder_id, owner_id, name) VALUES (4, 3, 'x.md')$$) = '42501');
SELECT test.ok('alice creates a subfolder and reads it back (RETURNING)',
  test.try($$INSERT INTO app.folders (org_id, parent_id, owner_id, name) VALUES (1, 4, 1, 'Drafts') RETURNING id$$) = 'ok');
SELECT test.ok('alice renames Design docs',
  test.rows($$UPDATE app.folders SET name = 'Design' WHERE id = 4$$) = 1);
SELECT test.ok('alice cannot move Design docs into Secrets (no edit there)',
  test.try($$UPDATE app.folders SET parent_id = 5 WHERE id = 4$$) = '42501');
SELECT test.ok('app code can ask directly: authz.can(''file'', 11, ''edit'')',
  authz.can('file', 11, 'edit'));
SELECT test.ok('... and list: authz.list(''folder'', ''edit'') = Engineering, Design, Drafts',
  (SELECT count(*) FROM authz.list('folder', 'edit')) = 3);
SELECT test.ok('... or in pages, in key order: two, then the rest after the last one seen',
  (SELECT array_agg(x) FROM authz.list('folder', 'edit', NULL, 2) x)
  || (SELECT array_agg(x) FROM authz.list('folder', 'edit',
        (SELECT max(x::bigint)::text FROM authz.list('folder', 'edit', NULL, 2) x), 2) x)
  = (SELECT array_agg(x ORDER BY x::bigint) FROM authz.list('folder', 'edit') x));
SET authz.user_id = 3;   -- carol, viewer
SELECT test.ok('carol cannot add files to Design docs',
  test.try($$INSERT INTO app.files (folder_id, owner_id, name) VALUES (4, 3, 'x.md')$$) = '42501');
SELECT test.ok('carol cannot edit architecture.md (update skips it)',
  test.rows($$UPDATE app.files SET body = 'x' WHERE id = 11$$) = 0);
SET authz.user_id = 2;   -- bob, viewer of Secrets
SELECT test.ok('bob cannot delete prod-keys.txt',
  test.rows($$DELETE FROM app.files WHERE id = 12$$) = 0);
RESET ROLE;
RESET authz.user_id;

-- ---------------------------------------------------------------------
-- Changes to your own tables apply at once (nothing to sync)
-- ---------------------------------------------------------------------
DELETE FROM app.team_members WHERE team_id = 11 AND user_id = 2;   -- bob leaves Backend
SET ROLE app_user;
SET authz.user_id = 2;
SELECT test.ok('bob leaves the Backend team: Secrets and Engineering edit rights are gone',
  test.files() = 'api-spec.md, architecture.md, handbook.pdf, joint-plan.md'
  AND NOT authz.can('file', 11, 'edit'));
RESET ROLE;

UPDATE authz.shares SET expires_at = now() - interval '1 minute'
WHERE object_type = 'file' AND object_id = '13' AND subject_id = '4';
SET ROLE app_user;
SET authz.user_id = 4;
SELECT test.ok('dave''s share expires: nothing left', test.files() = '-');
RESET ROLE;

UPDATE app.folders SET parent_id = 5 WHERE id = 4;    -- admin moves Design into Secrets
SET ROLE app_user;
SET authz.user_id = 3;
SELECT test.ok('Design moved under Secrets: carol loses it', test.files() = 'handbook.pdf, joint-plan.md');
RESET ROLE;

UPDATE app.folders SET inherit = true WHERE id = 5;   -- Secrets inherits again
SET ROLE app_user;
SET authz.user_id = 3;
SELECT test.ok('Secrets inherits again: carol sees all but the confidential file',
  test.files() = 'api-spec.md, architecture.md, handbook.pdf, joint-plan.md, offer-letter.pdf, prod-keys.txt');
RESET ROLE;
RESET authz.user_id;

SELECT test.ok('moving Engineering into its own subfolder is refused',
  test.try($$UPDATE app.folders SET parent_id = 6 WHERE id = 3$$) = '23514');
SELECT test.ok('... also when two new folders point at each other in one statement',
  test.try($$INSERT INTO app.folders (id, org_id, parent_id, owner_id, name)
             VALUES (92, 1, 93, 1, 'a'), (93, 1, 92, 1, 'b')$$) = '23514');

-- a loop in the team nesting: Engineering placed inside Platform
UPDATE app.teams SET parent_id = 12 WHERE id = 10;
SET ROLE app_user;
SET authz.user_id = 1;
SELECT test.ok('a loop in team nesting does not hang: the three teams now share members',
  (SELECT array_agg(id ORDER BY id) FROM authz_gen.team__member) = '{10,11,12}');
RESET ROLE;
UPDATE app.teams SET parent_id = NULL WHERE id = 10;
SET ROLE app_user;
SELECT test.ok('loop removed: alice is back to Engineering only',
  (SELECT array_agg(id ORDER BY id) FROM authz_gen.team__member) = '{10}');
RESET ROLE;

DELETE FROM app.folder_links WHERE folder_id = 21;
SET ROLE app_user;
SET authz.user_id = 3;
SELECT test.ok('Joint project unlinked from Company: carol loses it',
  test.files() = 'api-spec.md, architecture.md, handbook.pdf, offer-letter.pdf, prod-keys.txt');
RESET ROLE;

-- ---------------------------------------------------------------------
-- Things an independent review found, kept as regression tests
-- ---------------------------------------------------------------------
-- shares die with their row: a new row that reuses the id starts clean
SET ROLE app_user;
SET authz.user_id = 1;
SELECT test.ok('alice makes folder 150 and shares it with herself as editor',
  test.try($$INSERT INTO app.folders (id, org_id, parent_id, owner_id, name) VALUES (150, 1, 4, 1, 'tmp')$$) = 'ok'
  AND test.try($$SELECT authz.share('folder', 150, 'editor', 'user', 1)$$) = 'ok');
SELECT test.ok('sharing with someone who does not exist is refused',
  test.try($$SELECT authz.share('folder', 150, 'viewer', 'user', 999)$$) = 'P0001');
SELECT test.ok('alice deletes it', test.rows($$DELETE FROM app.folders WHERE id = 150$$) = 1);
RESET ROLE;
INSERT INTO app.folders (id, org_id, parent_id, owner_id, name) VALUES (150, 2, 20, 6, 'Globex board');
SET ROLE app_user;
SELECT test.ok('a new Globex folder that reuses id 150 does not inherit her old share',
  NOT authz.can('folder', 150, 'view') AND (SELECT count(*) FROM app.folders WHERE id = 150) = 0);
RESET ROLE;
DELETE FROM app.folders WHERE id = 150;
-- ... also a share written directly, with its ids as someone typed them
INSERT INTO app.folders (id, org_id, parent_id, owner_id, name) VALUES (150, 1, 4, 1, 'tmp');
INSERT INTO authz.shares (object_type, object_id, relation, subject_type, subject_id, subject_relation)
VALUES ('folder', '0150', 'viewer', 'user', ' 4', '');
SELECT test.ok('a share written directly is stored with canonical ids',
  EXISTS (SELECT 1 FROM authz.shares WHERE object_type = 'folder' AND object_id = '150' AND subject_id = '4'));
DELETE FROM app.folders WHERE id = 150;
INSERT INTO app.folders (id, org_id, parent_id, owner_id, name) VALUES (150, 2, 20, 6, 'Globex board');
SET ROLE app_user;
SET authz.user_id = 4;
SELECT test.ok('... so it goes with its row, and the new folder 150 is not dave''s to see',
  NOT authz.can('folder', 150, 'view') AND NOT EXISTS (SELECT 1 FROM app.folders WHERE id = 150));
RESET ROLE;
DELETE FROM app.folders WHERE id = 150;

-- changing who owns something, or where it lives, needs more than edit
SET ROLE app_user;
SET authz.user_id = 7;   -- gina: edit on Engineering through her teams, no share
SELECT test.ok('gina can rename Design (edit is enough)',
  test.rows($$UPDATE app.folders SET name = 'Design!' WHERE id = 4$$) = 1);
SELECT test.ok('gina cannot make herself owner of Design (needs share)',
  test.try($$UPDATE app.folders SET owner_id = 7 WHERE id = 4$$) = '42501');
SELECT test.ok('gina cannot switch off inheritance on Design (needs share)',
  test.try($$UPDATE app.folders SET inherit = false WHERE id = 4$$) = '42501');
SELECT test.ok('gina cannot make herself owner of architecture.md',
  test.try($$UPDATE app.files SET owner_id = 7 WHERE id = 11$$) = '42501');
SELECT test.ok('gina cannot move architecture.md into Globex (no edit there)',
  test.try($$UPDATE app.files SET folder_id = 20 WHERE id = 11$$) = '42501');
SELECT test.ok('gina can move it between folders she edits',
  test.rows($$UPDATE app.files SET folder_id = 3 WHERE id = 11$$) = 1
  AND test.rows($$UPDATE app.files SET folder_id = 4 WHERE id = 11$$) = 1);
RESET ROLE;
UPDATE app.folders SET name = 'Design' WHERE id = 4;

-- deleting a folder does not take hidden contents with it
SET ROLE app_user;
SET authz.user_id = 1;   -- alice can share Engineering, but cannot see inside Secrets
SELECT test.ok('alice cannot delete Engineering while it has contents',
  test.try($$DELETE FROM app.folders WHERE id = 3$$) = '23503'
  AND (SELECT count(*) FROM app.files WHERE folder_id = 4) > 0);
RESET ROLE;

-- TRUNCATE is tracked like DELETE
INSERT INTO app.folder_links VALUES (21, 1);
TRUNCATE app.folder_links;
SET ROLE app_user;
SET authz.user_id = 3;
SELECT test.ok('TRUNCATE of the link table: carol loses the Joint project at once',
  NOT authz.can('folder', 21, 'view'));
RESET ROLE;
SELECT test.ok('... and the inheritance tables still match a rebuild', authz.verify());

-- ids can change: the tree follows, shares on the old id are dropped
INSERT INTO authz.shares VALUES ('folder', 4, 'viewer', 'user', 4, '', NULL, NULL);
UPDATE app.folders SET id = 44 WHERE id = 4;
SET ROLE app_user;
SET authz.user_id = 1;
SELECT test.ok('Design renumbered 4 -> 44: alice still edits it and its file',
  authz.can('folder', 44, 'edit') AND authz.can('file', 11, 'edit'));
SET authz.user_id = 4;
SELECT test.ok('... and dave''s share on the old id is gone', NOT authz.can('folder', 44, 'view'));
RESET ROLE;
SELECT test.ok('... while the share to user 4 on offer-letter.pdf stays: the folder that was 4 is not him',
  EXISTS (SELECT 1 FROM authz.shares WHERE object_type = 'file' AND object_id = '13' AND subject_type = 'user'
          AND subject_id = '4'));
SELECT test.ok('... and the inheritance tables still match a rebuild', authz.verify());
UPDATE app.folders SET id = 4 WHERE id = 44;

-- swapping two ids in one statement does not move a share onto the other row
SET ROLE app_user;
SET authz.user_id = 1;
SELECT test.ok('alice shares architecture.md with dave', test.try($$SELECT authz.share('file', 11, 'viewer', 'user', 4)$$) = 'ok');
SET authz.user_id = 7;
SELECT test.ok('gina (edit, no share) cannot renumber files', test.try($$UPDATE app.files SET id = 900 WHERE id = 11$$) = '42501');
RESET ROLE;
INSERT INTO app.files (id, folder_id, owner_id, name) VALUES (30, 4, 1, 'roadmap-secret.md');
UPDATE app.files SET id = CASE id WHEN 11 THEN 900 WHEN 30 THEN 11 END WHERE id IN (11, 30);
SET ROLE app_user;
SET authz.user_id = 4;
SELECT test.ok('ids swapped in one statement: dave''s share on 11 does not land on the other file',
  NOT authz.can('file', 11, 'view') AND NOT authz.can('file', 900, 'view'));
RESET ROLE;
DELETE FROM app.files WHERE id = 11;
UPDATE app.files SET id = 11 WHERE id = 900;

-- editors of one folder can rename it even if they cannot edit its parent
SET authz.user_id = 5;
SET ROLE app_user;
SELECT test.ok('erin shares Keys with dave as editor', test.try($$SELECT authz.share('folder', 6, 'editor', 'user', 4)$$) = 'ok');
SET authz.user_id = 4;
SELECT test.ok('dave renames Keys (no edit on Secrets needed)', test.rows($$UPDATE app.folders SET name = 'Keys!' WHERE id = 6$$) = 1);
SELECT test.ok('... but cannot move it anywhere he cannot edit', test.try($$UPDATE app.folders SET parent_id = 2 WHERE id = 6$$) = '42501');
RESET ROLE;
RESET authz.user_id;

-- a loop through the link table: Engineering also shown inside Keys, its own subfolder
INSERT INTO app.folder_links VALUES (3, 6);
SET ROLE app_user;
SET authz.user_id = 3;
SELECT test.ok('a loop through links does not hang and changes nothing for carol',
  test.files() = 'api-spec.md, architecture.md, handbook.pdf, offer-letter.pdf, prod-keys.txt');
RESET ROLE;
RESET authz.user_id;
SELECT test.ok('every inheritance table matches a from-scratch rebuild', authz.verify());

-- ---------------------------------------------------------------------
-- explain in full: each line, as the user asks it
-- ---------------------------------------------------------------------
CREATE FUNCTION test.explained(p_type text, p_id text, p_perm text, p_user text DEFAULT NULL) RETURNS text
LANGUAGE sql AS $$ SELECT string_agg(e, E'\n' ORDER BY n) FROM authz.explain(p_type, p_id, p_perm, p_user) WITH ORDINALITY x(e, n) $$;
GRANT EXECUTE ON FUNCTION test.explained(text, text, text, text) TO app_user;
SET ROLE app_user;
SET authz.user_id = 3;
SELECT test.ok('explain: carol views Company through its share with Acme''s members, and the row that makes her one',
  test.explained('folder', '1', 'view') = $e$yes  user 3 holds view on folder 1
  folder.view = edit or viewer or (parent.view and {inherit}) or linked_into.view
  no   edit
  yes  viewer
    yes  viewer: shared with org 1, and you are member there
      yes  member: a row in app.org_members names you
  no   (parent.view and {inherit})
    no   parent.view
    yes  {inherit}
  no   linked_into.view$e$);
SET authz.user_id = 1;
SELECT test.ok('explain: alice edits Engineering as its owner, and what she lacks is followed down to the relation she doesn''t hold',
  test.explained('folder', '3', 'edit') = $e$yes  user 1 holds edit on folder 3
  folder.edit = share or editor or (parent.edit and {inherit})
  yes  share
    folder.share = owner or org.admin or (parent.share and {inherit})
    yes  owner
      yes  owner: owner_id is you
    no   org.admin
      no   org is org 1, without admin
        no   you do not hold org.admin
    no   (parent.share and {inherit})
      no   parent.share
        no   parent is folder 1, without share
          folder.share = owner or org.admin or (parent.share and {inherit})
          no   owner
          no   org.admin
            no   org is org 1, without admin
          no   (parent.share and {inherit})
            no   parent.share
            yes  {inherit}
      yes  {inherit}
  yes  editor
  no   (parent.edit and {inherit})
    no   parent.edit
      no   parent is folder 1, without edit
        folder.edit = share or editor or (parent.edit and {inherit})
        no   share
        no   editor
        no   (parent.edit and {inherit})
          no   parent.edit
          yes  {inherit}
    yes  {inherit}$e$);
RESET ROLE;
BEGIN;
-- a team with two sub-teams: dave is in the second one only
INSERT INTO app.teams VALUES (13, 1, 10, 'Design');
INSERT INTO app.team_members VALUES (13, 4);
SELECT test.ok('explain: dave edits Engineering through the sub-team he is in, not the first one',
  (SELECT array_agg(ltrim(e)) FROM authz.explain('folder', '3', 'edit', '4') e WHERE e LIKE '%through team%')
  = '{"yes  through team 13, whose member count here too"}');
-- a share to a group gina is in, made before the one asked about: the group named is the share's own
SET authz.user_id = 5;
SELECT authz.share('folder', 6, 'viewer', 'team', 10, 'member');
SELECT authz.share('folder', 2, 'viewer', 'team', 12, 'member');
SELECT test.ok('explain: gina views Handbook through its share with Platform, and is in Platform',
  (SELECT array_agg(ltrim(e)) FROM authz.explain('folder', '2', 'view', '7') e WHERE e LIKE '%you are member there%')
  = '{"yes  viewer: shared with team 12, and you are member there"}');
-- 19 folders in a chain under Engineering: alice may view the last one as Engineering's owner, 60 steps down
-- (view, edit, share, then share on each folder above, three steps each)
INSERT INTO app.folders (id, org_id, parent_id, owner_id, name, inherit)
  SELECT 200 + i, 1, CASE WHEN i = 1 THEN 3 ELSE 199 + i END, 5, 'deep ' || i, true FROM generate_series(1, 19) i;
SELECT test.ok('explain goes 60 steps deep, and stops after: ... only past it',
  (SELECT string_agg(DISTINCT ((length(e) - length(ltrim(e))) / 2)::text, ',') FROM authz.explain('folder', '219', 'view', '1') e
   WHERE ltrim(e) = '...') = '61');
ROLLBACK;
-- a new session, where nobody has signed in yet: an administrator's explain says nobody holds it
\c
\o /dev/null
SELECT test.ok('explain in a new session, nobody signed in: nobody holds it',
  (SELECT e FROM authz.explain('folder', '1', 'view') e LIMIT 1) = 'no   nobody does not hold view on folder 1');
