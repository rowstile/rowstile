-- =====================================================================
-- multi_scenario.sql: the share API and the newer policy features, on tests/multi.authz
--   psql -d db -f tests/multi_schema.sql; psql -d db -f <compiled multi.authz>; psql -d db -f tests/multi_scenario.sql
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
CREATE FUNCTION test.try(stmt text) RETURNS text LANGUAGE plpgsql AS $$
BEGIN EXECUTE stmt; RETURN 'ok'; EXCEPTION WHEN OTHERS THEN RETURN SQLSTATE; END $$;
-- a refusal by its words, 'SQLSTATE: message', as tests/words.sh reads them: the code alone can't say which guard
-- refused, where two answer with the same one
CREATE FUNCTION test.error(stmt text) RETURNS text LANGUAGE plpgsql AS $$
BEGIN EXECUTE stmt; RETURN 'ok'; EXCEPTION WHEN OTHERS THEN RETURN SQLSTATE || ': ' || SQLERRM; END $$;
-- the code an error's HINT names, 'SQLSTATE: rowstile help AZ705': what the SDKs read to answer it
CREATE FUNCTION test.hint(stmt text) RETURNS text LANGUAGE plpgsql AS $$
DECLARE h text;
BEGIN EXECUTE stmt; RETURN 'ok';
EXCEPTION WHEN OTHERS THEN GET STACKED DIAGNOSTICS h = PG_EXCEPTION_HINT; RETURN SQLSTATE || ': ' || h; END $$;
CREATE FUNCTION test.rows(stmt text) RETURNS bigint LANGUAGE plpgsql AS $$
DECLARE n bigint; BEGIN EXECUTE stmt; GET DIAGNOSTICS n = ROW_COUNT; RETURN n; END $$;
CREATE FUNCTION test.docs() RETURNS text LANGUAGE sql AS $$
  SELECT coalesce(string_agg(right(id::text, 2), ', ' ORDER BY id), '-') FROM mt.docs $$;
CREATE FUNCTION test.as(u int) RETURNS void LANGUAGE sql AS $$
  SELECT set_config('authz.user_id', CASE WHEN u IS NULL THEN '' ELSE '00000000-0000-4000-8000-' || lpad(u::text, 12, '0') END, false) $$;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA test TO app_user;

-- users 1 alice, 2 bob, 3 carol, 4 dave (guest), 5 erin (Acme admin), 6 frank (inactive), 7 gina (Globex admin)
INSERT INTO mt.users SELECT ('00000000-0000-4000-8000-' || lpad(i::text, 12, '0'))::uuid, i <> 6 FROM generate_series(1, 7) i;
INSERT INTO mt.orgs VALUES (1, false), (2, false);
INSERT INTO mt.org_members VALUES
  (1, '00000000-0000-4000-8000-000000000001', 'member'), (1, '00000000-0000-4000-8000-000000000002', 'member'),
  (1, '00000000-0000-4000-8000-000000000003', 'member'), (1, '00000000-0000-4000-8000-000000000005', 'admin'),
  (2, '00000000-0000-4000-8000-000000000007', 'admin');
INSERT INTO mt.teams VALUES (1), (2);
INSERT INTO mt.team_members VALUES (1, '00000000-0000-4000-8000-000000000001'), (1, '00000000-0000-4000-8000-000000000002'),
  (2, '00000000-0000-4000-8000-000000000003');
-- folder 1 (alice) > folder 2 > project 1 (Acme, lead bob) > folder 3 > doc 01; doc 02 sits in project 1
-- folder 4 belongs to frank (inactive); project 2 (Globex) holds doc 03
INSERT INTO mt.folders VALUES (1, NULL, NULL, '00000000-0000-4000-8000-000000000001', false, false),
                              (2, 'folder', 1, NULL, false, false),
                              (4, NULL, NULL, '00000000-0000-4000-8000-000000000006', false, false);
INSERT INTO mt.projects VALUES (1, 1, 2, '00000000-0000-4000-8000-000000000002'), (2, 2, NULL, NULL);
INSERT INTO mt.folders VALUES (3, 'project', 1, NULL, false, false);
UPDATE mt.folders SET org_id = 1 WHERE id IN (1, 2, 3);
INSERT INTO mt.docs VALUES ('10000000-0000-4000-8000-000000000001', 'folder', 3, NULL),
                           ('10000000-0000-4000-8000-000000000002', 'project', 1, NULL),
                           ('10000000-0000-4000-8000-000000000003', 'project', 2, NULL);

SET ROLE app_user;
-- ---------------------------------------------------------------------
-- Inheritance across types, UUID keys
-- ---------------------------------------------------------------------
SELECT test.as(1);
SELECT test.ok('alice owns folder 1: edits the whole chain folder > folder > project > folder > doc',
  authz.can('project', 1, 'edit') AND authz.can('folder', 3, 'edit') AND test.docs() = '01, 02');
SELECT test.ok('authz.perms lists everything she holds on folder 3', authz.perms('folder', 3) = '{edit,view,share,peek}');
SELECT test.ok('uuid ids work as text, and malformed ids are simply not allowed',
  authz.can('doc', '10000000-0000-4000-8000-000000000001', 'edit') AND NOT authz.can('doc', 'not-a-uuid', 'view'));
SELECT test.as(2);
SELECT test.ok('bob leads project 1: its folder and both its docs, not folder 1',
  authz.can('folder', 3, 'edit') AND test.docs() = '01, 02' AND NOT authz.can('folder', 1, 'view'));
SELECT test.as(5);
SELECT test.ok('erin (Acme admin) edits project 1 and below through org.admin', test.docs() = '01, 02');
SELECT test.as(7);
SELECT test.ok('gina (Globex admin) sees Globex''s doc only', test.docs() = '03');
RESET ROLE;

UPDATE mt.folders SET locked = true WHERE id = 3;
SET ROLE app_user;
SELECT test.as(2);
SELECT test.ok('folder 3 locked: bob still views it, but edit no longer flows down into it',
  authz.can('folder', 3, 'view') AND NOT authz.can('folder', 3, 'edit'));
RESET ROLE;
UPDATE mt.folders SET locked = false WHERE id = 3;

UPDATE mt.folders SET archived = true WHERE id = 2;
SET ROLE app_user;
SELECT test.as(1);
SELECT test.ok('folder 2 archived: nothing passes through it, so alice loses project 1 and below',
  NOT authz.can('folder', 2, 'view') AND NOT authz.can('project', 1, 'view') AND test.docs() = '-');
SELECT test.as(5);
SELECT test.ok('... while erin keeps it through her org', test.docs() = '01, 02');
RESET ROLE;
UPDATE mt.folders SET archived = false WHERE id = 2;

UPDATE mt.orgs SET suspended = true WHERE id = 1;
SET ROLE app_user;
SELECT test.as(5);
SELECT test.ok('Acme suspended: erin''s admin rights there are gone', test.docs() = '-');
RESET ROLE;
UPDATE mt.orgs SET suspended = false WHERE id = 1;

SET ROLE app_user;
SELECT test.as(6);
SELECT test.ok('frank is inactive: he counts as nobody, even for his own folder',
  authz.uid() IS NULL AND NOT authz.can('folder', 4, 'view'));
RESET ROLE;
UPDATE mt.users SET active = true WHERE id = '00000000-0000-4000-8000-000000000006';
SET ROLE app_user;
SELECT test.ok('reactivated: his folder is back', authz.can('folder', 4, 'edit'));
RESET ROLE;
-- a tree across two types may not loop: folder 1 into project 1, which sits inside it through folder 2
SELECT test.ok('moving a folder inside itself through a project is refused, by its words and its code',
  test.error('UPDATE mt.folders SET parent_type = ''project'', parent_id = 1 WHERE id = 1')
    = '23514: folder 1 cannot be moved inside itself'
  AND test.hint('UPDATE mt.folders SET parent_type = ''project'', parent_id = 1 WHERE id = 1') = '23514: rowstile help AZ713'
  AND (SELECT parent_id IS NULL FROM mt.folders WHERE id = 1) AND authz.verify());
SET ROLE app_user;

-- ---------------------------------------------------------------------
-- Sharing: who may share, and what
-- ---------------------------------------------------------------------
SELECT test.as(1);
SELECT test.ok('alice shares folder 1 with carol as viewer',
  test.try($$SELECT authz.share('folder', '1', 'viewer', 'user', '00000000-0000-4000-8000-000000000003')$$) = 'ok');
SELECT test.as(3);
SELECT test.ok('carol now sees folder 1''s documents', test.docs() = '01, 02');
SELECT test.ok('carol (viewer) cannot share folder 1: viewer is shared by edit (she may share nothing there)',
  test.error($$SELECT authz.share('folder', '1', 'viewer', 'user', '00000000-0000-4000-8000-000000000004')$$)
    = '42501: you cannot share folder 1');
RESET ROLE;
UPDATE mt.users SET active = false WHERE id = '00000000-0000-4000-8000-000000000006';
SET ROLE app_user;
SELECT test.as(1);
SELECT test.ok('shared if: no sharing with inactive users',
  test.error($$SELECT authz.share('folder', '1', 'viewer', 'user', '00000000-0000-4000-8000-000000000006')$$)
    LIKE '42501: the policy does not allow this share (line %)');
SELECT test.ok('... a refusal of this share (AZ705, a 403), not a share the policy lacks (AZ706)',
  test.hint($$SELECT authz.share('folder', '1', 'viewer', 'user', '00000000-0000-4000-8000-000000000006')$$)
    = '42501: rowstile help AZ705');
SELECT test.ok('sharing with someone who does not exist is refused',
  test.error($$SELECT authz.share('folder', '1', 'viewer', 'user', '00000000-0000-4000-8000-000000000099')$$)
    = 'P0001: there is no user 00000000-0000-4000-8000-000000000099');
SELECT test.ok('a share names a caveat the policy has',
  test.error($$SELECT authz.share('folder', '1', 'viewer', 'user', '00000000-0000-4000-8000-000000000004', '', NULL, NULL,
                                  'nosuch', '{}')$$) = 'P0001: no caveat nosuch in the policy');
SELECT test.ok('shares the policy does not declare are refused (anyone on folders)',
  test.error($$SELECT authz.share('folder', '1', 'viewer', 'anyone', '*')$$)
    = 'P0001: the policy does not allow sharing folder.viewer with anyone');

-- every signed-in user; anyone at all
SELECT test.ok('alice shares folder 2 with every signed-in user',
  test.try($$SELECT authz.share('folder', '2', 'viewer', 'user', '*')$$) = 'ok');
SELECT test.as(4);
SELECT test.ok('dave (signed in) sees folder 2''s documents', test.docs() = '01, 02');
SELECT test.as(NULL);
SELECT test.ok('nobody signed in: nothing', test.docs() = '-');
SELECT test.as(2);
SELECT test.ok('bob (edit on project 1) makes project 1 public to anyone',
  test.try($$SELECT authz.share('project', '1', 'viewer', 'anyone', '*')$$) = 'ok');
SELECT test.as(NULL);
SELECT test.ok('now even nobody signed in sees project 1''s documents', test.docs() = '01, 02');
SELECT test.as(2);
SELECT authz.unshare('project', '1', 'viewer', 'anyone', '*');
SELECT test.as(1);
SELECT authz.unshare('folder', '2', 'viewer', 'user', '*');

-- links
SELECT set_config('test.token', authz.create_link('folder', '2', 'viewer'), false);
SELECT test.as(4);
SELECT test.ok('dave without the link: nothing', test.docs() = '-');
SELECT set_config('authz_ctx.links', current_setting('test.token'), false);
SELECT test.ok('dave with the link token: folder 2 and below', test.docs() = '01, 02');
SELECT set_config('authz_ctx.links', 'wrong-token', false);
SELECT test.ok('a wrong token does nothing', test.docs() = '-');
RESET authz_ctx.links;

-- the links on an object, and turning one off
SELECT test.as(1);
SELECT test.ok('alice lists folder 2''s links: one, named by an id that is not its token',
  (SELECT count(*) = 1 AND bool_and(l.relation = 'viewer' AND l.created_by = '00000000-0000-4000-8000-000000000001'
                                    AND l.expires_at IS NULL AND l.created_at <= now() AND length(l.id) = 16
                                    AND position(l.id in current_setting('test.token')) = 0)
   FROM authz.list_links('folder', 2) l));
SELECT test.ok('the shares still show it as (link)',
  (SELECT count(*) = 1 FROM authz.list_shares('folder', 2) WHERE subject_type = 'link' AND subject_id = '(link)'));
SELECT set_config('test.link', (SELECT id FROM authz.list_links('folder', 2)), false);
SELECT test.as(4);
SELECT test.ok('dave may not list them, nor those of a folder that isn''t there',
  test.try($$SELECT * FROM authz.list_links('folder', 2)$$) = '42501'
  AND test.try($$SELECT * FROM authz.list_links('folder', 999)$$) = '42501');
SELECT test.ok('nor turn one off, whether its id names a link or not',
  test.try(format('SELECT authz.revoke_link(''folder'', 2, %L)', current_setting('test.link'))) = '42501'
  AND test.try($$SELECT authz.revoke_link('folder', 2, 'nothing')$$) = '42501');
SELECT test.as(1);
SELECT set_config('test.token2', authz.create_link('folder', 2, 'viewer', now() + interval '1 day'), false);
SELECT test.ok('a second link, until tomorrow: both listed, the older first',
  (SELECT array_agg(l.expires_at IS NULL) FROM authz.list_links('folder', 2) l) = '{t,f}');
-- why dave may view: the link he presented, never another one (its end is that link's)
SELECT test.as(4);
SELECT set_config('authz_ctx.links', current_setting('test.token2'), false);
SELECT test.ok('dave, with the second link, is told of that one: until tomorrow',
  (SELECT ltrim(l) FROM authz.explain('folder', 2, 'view') l WHERE l LIKE '%link you presented%')
  LIKE 'yes  viewer: shared by a link you presented (by 00000000-0000-4000-8000-000000000001, until %)');
SELECT set_config('authz_ctx.links', current_setting('test.token'), false);
SELECT test.ok('... and with the first, of the first: no end',
  (SELECT ltrim(l) FROM authz.explain('folder', 2, 'view') l WHERE l LIKE '%link you presented%')
  = 'yes  viewer: shared by a link you presented (by 00000000-0000-4000-8000-000000000001)');
RESET authz_ctx.links;
SELECT test.as(1);
SELECT test.ok('an id that names no link there is said',
  test.try($$SELECT authz.revoke_link('folder', 2, 'nothing')$$) = 'P0001'
  AND test.try(format('SELECT authz.revoke_link(''folder'', 1, %L)', current_setting('test.link'))) = 'P0001');
SELECT authz.revoke_link('folder', 2, current_setting('test.link'));
SELECT test.ok('alice turns the first off: the other is left',
  (SELECT count(*) = 1 AND bool_and(l.expires_at IS NOT NULL) FROM authz.list_links('folder', 2) l));
SELECT test.as(4);
SELECT set_config('authz_ctx.links', current_setting('test.token'), false);
SELECT test.ok('its token opens nothing any more', test.docs() = '-');
SELECT set_config('authz_ctx.links', current_setting('test.token2'), false);
SELECT test.ok('the other link still does', test.docs() = '01, 02');
RESET authz_ctx.links;
-- project has no share permission: its links are listed and turned off by who may make them (shared by edit)
SELECT test.as(2);
SELECT set_config('test.token3', authz.create_link('project', 1, 'viewer'), false);
SELECT test.ok('bob (edit on project 1) lists its link',
  (SELECT count(*) = 1 AND bool_and(l.relation = 'viewer') FROM authz.list_links('project', 1) l));
SELECT test.as(4);
SELECT test.ok('dave may not', test.try($$SELECT * FROM authz.list_links('project', 1)$$) = '42501');
SELECT test.as(2);
SELECT authz.revoke_link('project', 1, (SELECT id FROM authz.list_links('project', 1)));
SELECT test.ok('bob turns it off', (SELECT count(*) = 0 FROM authz.list_links('project', 1)));

-- shares that start later, and caveats
SELECT test.as(1);
SELECT test.ok('alice shares folder 1 with dave from tomorrow',
  test.try($$SELECT authz.share('folder', '1', 'viewer', 'user', '00000000-0000-4000-8000-000000000004', '', NULL, now() + interval '1 day')$$) = 'ok');
SELECT test.as(4);
SELECT test.ok('... not yet', test.docs() = '-');
SELECT test.as(1);
SELECT test.ok('alice re-shares it for business hours only (a caveat)',
  test.try($$SELECT authz.share('folder', '1', 'viewer', 'user', '00000000-0000-4000-8000-000000000004', '', NULL, NULL, 'business_hours')$$) = 'ok');
SELECT test.as(4);
SELECT set_config('authz_ctx.mode', 'night', false);
SELECT test.ok('at night: nothing', test.docs() = '-');
SELECT set_config('authz_ctx.mode', 'business', false);
SELECT test.ok('in business hours: folder 1 and below', test.docs() = '01, 02');
RESET authz_ctx.mode;
SELECT test.as(1);
SELECT test.ok('a caveat the policy does not define is refused',
  test.try($$SELECT authz.share('folder', '1', 'viewer', 'user', '00000000-0000-4000-8000-000000000004', '', NULL, NULL, 'full_moon')$$) = 'P0001');
SELECT test.ok('a parameterised caveat: only from the office IP',
  test.try($$SELECT authz.share('folder', '1', 'viewer', 'user', '00000000-0000-4000-8000-000000000004', '', NULL, NULL, 'from_ip', '{"ip": "10.1.2.3"}')$$) = 'ok');
SELECT test.as(4);
SELECT set_config('authz_ctx.ip', '10.9.9.9', false);
SELECT test.ok('from elsewhere: nothing', test.docs() = '-');
SELECT set_config('authz_ctx.ip', '10.1.2.3', false);
SELECT test.ok('from the office: folder 1 and below', test.docs() = '01, 02');
RESET authz_ctx.ip;
SELECT test.as(1);
SELECT authz.unshare('folder', '1', 'viewer', 'user', '00000000-0000-4000-8000-000000000004');

-- ---------------------------------------------------------------------
-- Custom roles
-- ---------------------------------------------------------------------
SELECT test.as(1);
SELECT test.ok('alice is no Acme admin: she cannot define roles for Acme',
  test.error($$SELECT authz.create_role('org', '1', 'folder', 'reviewer', ARRAY['view'])$$)
    = '42501: you cannot manage roles of org 1');
SELECT test.ok('... nor for a type that has no manage_roles',
  test.error($$SELECT authz.create_role('project', '1', 'folder', 'reviewer', ARRAY['view'])$$)
    = 'P0001: project has no manage_roles permission in the policy');
SELECT test.ok('... and a team''s roles (alice is in team 1) are for projects, not for folders, which take theirs from orgs',
  test.error($$SELECT authz.create_role('team', '1', 'folder', 'reviewer', ARRAY['view'])$$)
    = 'P0001: custom roles on folder belong to a org (the policy says where they come from), not to a team');
SELECT test.as(5);
SELECT test.ok('erin (Acme admin) defines "reviewer" (view) and "writer" (view, edit) for folders',
  test.try($$SELECT authz.create_role('org', '1', 'folder', 'reviewer', ARRAY['view'])$$) = 'ok'
  AND test.try($$SELECT authz.create_role('org', '1', 'folder', 'writer', ARRAY['view', 'edit'])$$) = 'ok');
SELECT test.ok('a role cannot include what the policy does not let roles grant (share)',
  test.error($$SELECT authz.create_role('org', '1', 'folder', 'boss', ARRAY['share'])$$)
    = 'P0001: custom roles on folder cannot grant share');
SELECT test.ok('... and there are none for a type without custom roles, even granting nothing, nor for a type the policy doesn''t have',
  test.error($$SELECT authz.create_role('org', '1', 'team', 'nothing', ARRAY[]::text[])$$)
    = 'P0001: no custom roles on team in the policy'
  AND test.error($$SELECT authz.create_role('org', '1', 'foldr', 'reviewer', ARRAY['view'])$$)
    = 'P0001: no custom roles on foldr in the policy');
SELECT test.ok('Acme''s roles are listed for Acme members', (SELECT count(*) FROM authz.roles_of('org', '1')) = 2);
SELECT set_config('test.reviewer', (SELECT id::text FROM authz.roles_of('org', '1') WHERE name = 'reviewer'), false);
SELECT set_config('test.writer', (SELECT id::text FROM authz.roles_of('org', '1') WHERE name = 'writer'), false);
SELECT test.as(3);
SELECT test.ok('carol asks for the writer role on folder 1, and may withdraw it',
  test.try(format($$SELECT authz.cancel_request(authz.request_access('folder', '1', 'role:%s', 'to write the spec'))$$,
                  current_setting('test.writer'))) = 'ok');
SELECT test.ok('... but not for a role that doesn''t exist',
  test.error($$SELECT authz.request_access('folder', '1', 'role:999999', 'to write the spec')$$)
    = 'P0001: the policy does not allow sharing folder.role:999999 with a user');
SELECT test.as(1);
SELECT test.ok('alice gives dave the reviewer role on folder 1',
  test.try(format($$SELECT authz.share('folder', '1', 'role:%s', 'user', '00000000-0000-4000-8000-000000000004')$$,
                  current_setting('test.reviewer'))) = 'ok');
SELECT test.as(4);
SELECT test.ok('dave views folder 1 and below, but cannot edit',
  test.docs() = '01, 02' AND NOT authz.can('folder', 1, 'edit'));
SELECT test.as(3);
SELECT test.ok('carol (a viewer) cannot hand out the writer role: she may not share folder 1',
  test.error(format($$SELECT authz.share('folder', '1', 'role:%s', 'user', '00000000-0000-4000-8000-000000000004')$$,
                    current_setting('test.writer'))) = '42501: you cannot share folder 1');
SELECT test.as(1);
SELECT test.ok('a role is given to whom the policy says (user, team#member), not to a team itself',
  test.error(format($$SELECT authz.share('folder', '1', 'role:%s', 'team', '1')$$, current_setting('test.writer')))
    = 'P0001: custom roles on folder cannot be given to team');
SELECT test.ok('... and only a role that exists, for its type',
  test.error($$SELECT authz.share('folder', '1', 'role:999999', 'user', '00000000-0000-4000-8000-000000000004')$$)
    = 'P0001: no role role:999999 for folder');
SELECT test.ok('alice (no Acme admin) cannot change Acme''s role, nor delete it',
  test.error(format($$SELECT authz.set_role_permissions(%s, ARRAY['view'])$$, current_setting('test.reviewer')))
    = '42501: you cannot manage role ' || current_setting('test.reviewer')
  AND test.error(format($$SELECT authz.delete_role(%s)$$, current_setting('test.reviewer')))
    = '42501: you cannot manage role ' || current_setting('test.reviewer'));
SELECT test.as(5);
SELECT test.ok('erin may, but a role cannot be given what roles may not grant',
  test.error(format($$SELECT authz.set_role_permissions(%s, ARRAY['view', 'share'])$$, current_setting('test.reviewer')))
    = 'P0001: custom roles on folder cannot grant share');
SELECT test.ok('erin adds edit to reviewer: dave can now edit',
  test.try(format($$SELECT authz.set_role_permissions(%s, ARRAY['view', 'edit'])$$, current_setting('test.reviewer'))) = 'ok');
SELECT test.as(4);
SELECT test.ok('... and he can', authz.can('folder', 3, 'edit'));
SELECT test.as(5);
SELECT test.ok('erin deletes the role: its assignments go with it',
  test.try(format($$SELECT authz.delete_role(%s)$$, current_setting('test.reviewer'))) = 'ok');
SELECT test.as(4);
SELECT test.ok('dave has nothing left', test.docs() = '-');
RESET ROLE;
SELECT test.ok('the audit trail has the roles made, the permissions they were given and lost, and the one deleted',
  (SELECT array_agg(DISTINCT action ORDER BY action) FROM authz.audit
   WHERE action IN ('insert_role', 'delete_role', 'role_permission_added', 'role_permission_removed'))
  = ARRAY['delete_role', 'insert_role', 'role_permission_added', 'role_permission_removed']);
SET ROLE app_user;
-- folders' roles come from their org (roles ... from org): another org's role counts for nothing there
SELECT test.as(7);
SELECT test.ok('gina (Globex admin) defines "auditor" (view) for Globex''s folders',
  test.try($$SELECT authz.create_role('org', '2', 'folder', 'auditor', ARRAY['view'])$$) = 'ok');
SELECT set_config('test.auditor', (SELECT id::text FROM authz.roles_of('org', '2') WHERE name = 'auditor'), false);
SELECT test.as(1);
SELECT test.ok('alice cannot give Globex''s role on Acme''s folder 1',
  test.error(format($$SELECT authz.share('folder', '1', 'role:%s', 'user', '00000000-0000-4000-8000-000000000004')$$,
                    current_setting('test.auditor'))) = 'P0001: role auditor belongs to org 2, which doesn''t own folder 1');
RESET ROLE;
INSERT INTO authz.shares (object_type, object_id, relation, subject_type, subject_id)
VALUES ('folder', '1', 'role:' || current_setting('test.auditor'), 'user', '00000000-0000-4000-8000-000000000004');
SET ROLE app_user;
SELECT test.as(4);
SELECT test.ok('... and one written into authz.shares gives dave nothing while folder 1 is Acme''s', test.docs() = '-');
RESET ROLE;
UPDATE mt.folders SET org_id = 2 WHERE id = 1;
SET ROLE app_user;
SELECT test.ok('... until folder 1 moves to Globex', test.docs() = '01, 02' AND authz.can('folder', 1, 'view'));
RESET ROLE;
UPDATE mt.folders SET org_id = 1 WHERE id = 1;
DELETE FROM authz.shares WHERE relation = 'role:' || current_setting('test.auditor');
SET ROLE app_user;
-- a role may give what one who may share doesn't hold (archive: owners only): giving it is refused
SELECT test.as(5);
SELECT set_config('test.archivist', authz.create_role('org', '1', 'folder', 'archivist', ARRAY['archive'])::text, false);
SELECT test.as(1);
SELECT authz.share('folder', '1', 'editor', 'user', '00000000-0000-4000-8000-000000000002');
SELECT test.as(2);
SELECT test.ok('bob (an editor: he may share folder 1) cannot give the archivist role, for he does not hold archive',
  test.error(format($$SELECT authz.share('folder', '1', 'role:%s', 'user', '00000000-0000-4000-8000-000000000004')$$,
                    current_setting('test.archivist')))
    = '42501: you cannot give role archivist on folder 1: you do not hold archive');
SELECT test.as(1);
SELECT authz.unshare('folder', '1', 'editor', 'user', '00000000-0000-4000-8000-000000000002');
SELECT test.as(5);
SELECT authz.delete_role(current_setting('test.archivist')::bigint);

-- ---------------------------------------------------------------------
-- Writes through RLS on documents
-- ---------------------------------------------------------------------
SELECT test.as(3);
SELECT test.ok('carol (viewer) cannot edit doc 01',
  test.rows($$UPDATE mt.docs SET author_id = author_id WHERE id = '10000000-0000-4000-8000-000000000001'$$) = 0);
SELECT test.as(2);
SELECT test.ok('bob (lead of project 1) can',
  test.rows($$UPDATE mt.docs SET author_id = author_id WHERE id = '10000000-0000-4000-8000-000000000001'$$) = 1);

-- ---------------------------------------------------------------------
-- Masked columns (rules mt.docs view mt.docs_visible / mask body : edit)
-- ---------------------------------------------------------------------
SELECT test.as(3);
SELECT test.ok('carol (viewer) sees doc 01 in the masked view, but not its text',
  (SELECT body IS NULL FROM mt.docs_visible WHERE id = '10000000-0000-4000-8000-000000000001'));
SELECT test.ok('the view has exactly the rows she may select',
  (SELECT count(*) FROM mt.docs_visible) = (SELECT count(*) FROM mt.docs));
SELECT test.as(2);
SELECT test.ok('bob (editor) sees the text',
  (SELECT body FROM mt.docs_visible WHERE id = '10000000-0000-4000-8000-000000000001') = 'the text');
SELECT test.ok('the text cannot be read from the table directly', test.try('SELECT body FROM mt.docs') = '42501');
SELECT test.ok('... nor with SELECT *', test.try('SELECT * FROM mt.docs') = '42501');
SELECT test.ok('the view cannot be written to', test.try($$UPDATE mt.docs_visible SET author_id = author_id$$) = '42501');
SELECT test.ok('editors still write the text through the table',
  test.rows($$UPDATE mt.docs SET body = 'new text' WHERE id = '10000000-0000-4000-8000-000000000001'$$) = 1);
SELECT test.as(NULL);
SELECT test.ok('nobody signed in sees no rows in the view', (SELECT count(*) FROM mt.docs_visible) = 0);
RESET ROLE;
SELECT test.ok('every inheritance table matches a rebuild', authz.verify());
