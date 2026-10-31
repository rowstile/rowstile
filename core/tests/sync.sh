#!/bin/bash
# sync.sh: the sync index (a preview), on the docs app. After each change the index (the rows of a synced table
# whose readers hold a key the user holds) is compared with authz.list as that user, for every user: the share made,
# revoked and ending at authz.sync_tick(), a folder moved out of reach and back, a team left with a row also reached
# another way, a sub-team moved, a row condition set, a user deleted, apply and reapply leaving the rows put; the
# sync role's grants and what applying refuses of it; lint; two writers at once; remove.
#   PGHOST=... PGUSER=authz_owner [PGSUPERUSER=postgres] tests/sync.sh [database]
set -u
cd "$(dirname "$0")/.."
DB=${1:-authz_sync}
T=$(mktemp -d)
. tests/races.sh
ROLE=authz_sync_engine   # the sync role (difftest's too): made if it isn't there, kept
OTHER=${DB}_role         # a role of this suite's, for what applying refuses
cleanup() {
  stop_sessions
  dropdb --force --if-exists "$DB" 2>/dev/null
  psql -X -q -d postgres -c "DROP ROLE IF EXISTS $OTHER" 2>/dev/null
  [ -z "${PGSUPERUSER:-}" ] || psql -X -q -U "$PGSUPERUSER" -d postgres -c "DROP ROLE IF EXISTS ${OTHER}_owner" 2>/dev/null
  rm -rf "$T"
}
trap cleanup EXIT
fails=0
PSQL() { PGOPTIONS="-c client_min_messages=warning" psql -X -q -At -v ON_ERROR_STOP=1 -d "$DB" "$@"; }
ok() { echo "ok    $1"; }
bad() { echo "FAIL  $1${2:+: $2}"; fails=$((fails + 1)); }
check() {   # $1 = label, $2 = SQL that must return t
  local got
  got=$(PSQL -c "$2" 2>&1)
  if [ "$got" = "t" ]; then ok "$1"; else bad "$1" "$got"; fi
}
same() { check "$1" "SELECT public.sync_same()"; }   # the index holds what authz.list gives, for every user
# applies the policy text $1 with the rowstile command (its output in $out); a failure ends the suite
apply() {
  printf '%s\n' "$1" > "$T/p.authz"
  out=$(python3 cli/rowstile_cli.py --db "dbname=$DB" apply "$T/p.authz" --force 2>&1) || { bad "apply" "$out"; exit 1; }
}
# ... or must be refused, saying $2
refused() {
  printf '%s\n' "$2" > "$T/p.authz"
  local said
  if said=$(python3 cli/rowstile_cli.py --db "dbname=$DB" apply "$T/p.authz" --force 2>&1); then
    bad "$1" "applied"
  elif echo "$said" | grep -qF -- "$3"; then ok "$1"; else bad "$1" "$said"; fi
}

psql -X -q -d postgres -c "DO \$r\$ BEGIN CREATE ROLE $ROLE; EXCEPTION WHEN duplicate_object OR unique_violation THEN NULL; END \$r\$;" >/dev/null
psql -X -q -d postgres -c "DROP ROLE IF EXISTS $OTHER" -c "CREATE ROLE $OTHER" >/dev/null || exit 1
dropdb --if-exists "$DB" 2>/dev/null; createdb "$DB" || exit 1
PSQL -f example/app_schema.sql >/dev/null || exit 1
DOCS=$(cat example/docs.authz)
SYNCED="$DOCS

sync role $ROLE
sync app.files : view
sync app.folders"
apply "$SYNCED"
PSQL >/dev/null <<'SQL' || exit 1
-- the rows of a synced type the user's keys read
CREATE FUNCTION public.sync_reads(p_user text, p_type text) RETURNS text[] LANGUAGE plpgsql AS $$
DECLARE v text[];
BEGIN
  EXECUTE format('SELECT coalesce(array_agg(DISTINCT r.id::text ORDER BY r.id::text), ''{}'') FROM authz_sync.%I r
                  WHERE r.key IN (SELECT k.key FROM authz_sync.keys k WHERE k.principal_type = ''user'' AND k.principal_id = $1)',
                 p_type || '__readers') INTO v USING p_user;
  RETURN v;
END $$;
-- what authz.list gives the user (the owner's session is believed unsigned)
CREATE FUNCTION public.listed(p_user text, p_type text, p_perm text) RETURNS text[] LANGUAGE plpgsql AS $$
DECLARE v text[];
BEGIN
  PERFORM set_config('authz.user_id', p_user, true);
  PERFORM set_config('authz.principal_type', '', true);
  SELECT coalesce(array_agg(x ORDER BY x), '{}') INTO v FROM authz.list(p_type, p_perm) x;
  PERFORM set_config('authz.user_id', '', true);
  RETURN v;
END $$;
-- for every user: files by view, folders by their select rule (view)
CREATE FUNCTION public.sync_same() RETURNS boolean LANGUAGE sql AS $$
  SELECT bool_and(public.sync_reads(u.id::text, 'file') = public.listed(u.id::text, 'file', 'view')
              AND public.sync_reads(u.id::text, 'folder') = public.listed(u.id::text, 'folder', 'view'))
  FROM app.users u $$;
SQL
reads() { PSQL -c "SELECT '$2' = ANY (public.sync_reads('$1', '${3:-file}'))"; }   # user $1 reads object $2 through the index

echo "-- applied"
same "applied: for every user, the index holds what authz.list gives (files, and folders by their select rule)"
check "the readers table has the type's key columns, typed as its key, then key" \
  "SELECT array_agg(a.attname || ' ' || format_type(a.atttypid, NULL) ORDER BY a.attnum) = '{\"id bigint\",\"key text\"}'
   FROM pg_attribute a WHERE a.attrelid = 'authz_sync.file__readers'::regclass AND a.attnum > 0 AND NOT a.attisdropped"
check "every table of the index has REPLICA IDENTITY FULL, as Electric asks" \
  "SELECT bool_and(c.relreplident = 'f') AND count(*) = 6 FROM pg_class c WHERE c.relnamespace = 'authz_sync'::regnamespace AND c.relkind = 'r'"
check "an org admin holds the org's group key, and a team's member its team's and the teams it sits in" \
  "SELECT EXISTS (SELECT 1 FROM authz_sync.keys WHERE principal_id = '5' AND key = 'org#admin:1')
      AND EXISTS (SELECT 1 FROM authz_sync.keys WHERE principal_id = '7' AND key = 'team#member:10')"
check "a file's readers are keys: its owner, and its folder's flattened in" \
  "SELECT EXISTS (SELECT 1 FROM authz_sync.file__readers WHERE id = 11 AND key = 'user:1')
      AND EXISTS (SELECT 1 FROM authz_sync.file__readers WHERE id = 11 AND key = 'org#admin:1')"
check "authz.sync_verify(): the index matches a rebuild" "SELECT authz.sync_verify()"

echo "-- shares"
PSQL -c "INSERT INTO authz.shares (object_type, object_id, relation, subject_type, subject_id) VALUES ('file', '13', 'viewer', 'user', '6')"
[ "$(reads 6 13)" = t ] && ok "a share made: frank reads file 13" || bad "a share made"
same "... and the index holds what authz.list gives"
PSQL -c "DELETE FROM authz.shares WHERE object_type = 'file' AND object_id = '13' AND subject_id = '6'"
[ "$(reads 6 13)" = f ] && ok "the share revoked: frank no longer reads it" || bad "the share revoked"
same "... and the index holds what authz.list gives, after the revoke"
PSQL -c "INSERT INTO authz.shares (object_type, object_id, relation, subject_type, subject_id, subject_relation) VALUES ('folder', '6', 'viewer', 'org', '2', 'member')"
check "a share to a group is one key on the folder, not one per member" \
  "SELECT count(*) = 1 FROM authz_sync.folder__readers WHERE id = 6 AND key = 'org#member:2'"
same "... and Globex's members read Keys and the file in it"
PSQL -c "DELETE FROM authz.shares WHERE object_type = 'folder' AND object_id = '6' AND subject_type = 'org'"

echo "-- a share that ends, and one that begins"
PSQL -c "SELECT authz.sync_tick()" >/dev/null   # (what ended before now, once)
PSQL -c "INSERT INTO authz.shares (object_type, object_id, relation, subject_type, subject_id, expires_at)
         VALUES ('file', '13', 'viewer', 'user', '6', clock_timestamp() + interval '1 second')" \
     -c "INSERT INTO authz.shares (object_type, object_id, relation, subject_type, subject_id, starts_at)
         VALUES ('file', '12', 'viewer', 'user', '6', clock_timestamp() + interval '1 second')"
[ "$(reads 6 13)$(reads 6 12)" = tf ] && ok "a share for a second: frank reads file 13; one that begins in a second: not file 12 yet" ||
  bad "shares in force" "$(reads 6 13)$(reads 6 12)"
sleep 1.2
[ "$(reads 6 13)$(reads 6 12)" = tf ] && ok "a second later, before the tick: the index still says so (its stated window)" ||
  bad "before the tick" "$(reads 6 13)$(reads 6 12)"
check "authz.sync_tick() works out again the readers of the shares that ended or began since it last ran, and says how many" \
  "SELECT authz.sync_tick() = 2"
[ "$(reads 6 13)$(reads 6 12)" = ft ] && ok "after the tick: file 13 is gone, file 12 is there" || bad "after the tick" "$(reads 6 13)$(reads 6 12)"
same "... and the index holds what authz.list gives, after the tick"
check "run again, it finds nothing new" "SELECT authz.sync_tick() = 0"
PSQL -c "DELETE FROM authz.shares WHERE subject_id = '6' AND (expires_at IS NOT NULL OR starts_at IS NOT NULL)"

echo "-- moves"
before=$(PSQL -c "SELECT string_agg(u.id::text, ',' ORDER BY u.id) FROM app.users u WHERE '11' = ANY (public.sync_reads(u.id::text, 'file'))")
PSQL -c "UPDATE app.folders SET parent_id = 20 WHERE id = 4"   # Design docs, holding file 11, into Globex
after=$(PSQL -c "SELECT string_agg(u.id::text, ',' ORDER BY u.id) FROM app.users u WHERE '11' = ANY (public.sync_reads(u.id::text, 'file'))")
[ "$before" != "$after" ] && ok "a folder moved out of reach: the file in it leaves those who read it through Engineering ($before -> $after)" ||
  bad "a move" "$before -> $after"
same "... and the index holds what authz.list gives, after the move"
PSQL -c "UPDATE app.folders SET parent_id = 3 WHERE id = 4"
[ "$(PSQL -c "SELECT string_agg(u.id::text, ',' ORDER BY u.id) FROM app.users u WHERE '11' = ANY (public.sync_reads(u.id::text, 'file'))")" = "$before" ] &&
  ok "moved back: they read it again" || bad "moved back"
same "... and the index holds what authz.list gives, moved back"

echo "-- teams"
PSQL -c "INSERT INTO authz.shares (object_type, object_id, relation, subject_type, subject_id) VALUES ('file', '12', 'viewer', 'user', '2')"
held12=$(reads 2 12); held13=$(reads 2 13)
readers=$(PSQL -c "SELECT md5(string_agg(id || key || xmin, ',' ORDER BY id, key)) FROM authz_sync.file__readers")
PSQL -c "DELETE FROM app.team_members WHERE user_id = 2 AND team_id = 11"   # bob leaves Backend
[ "$held12$held13" = tt ] && [ "$(reads 2 13)$(reads 2 12)" = ft ] &&
  ok "a team left: bob no longer reads file 13, reached through Backend; file 12, shared with him too, stays" ||
  bad "a team left" "$held12$held13 -> $(reads 2 13)$(reads 2 12)"
[ "$(PSQL -c "SELECT md5(string_agg(id || key || xmin, ',' ORDER BY id, key)) FROM authz_sync.file__readers")" = "$readers" ] &&
  ok "... and the files' readers didn't change: only bob's keys did" || bad "a team left wrote readers"
same "... and the index holds what authz.list gives, the team left"
PSQL -c "DELETE FROM authz.shares WHERE object_type = 'file' AND object_id = '12' AND subject_id = '2'"
gina=$(reads 7 13)
PSQL -c "UPDATE app.teams SET parent_id = NULL WHERE id = 12"   # Platform out of Backend
[ "$gina$(reads 7 13)" = tf ] && ok "a sub-team moved out: its members leave what the team above it was given" || bad "a sub-team out" "$gina$(reads 7 13)"
PSQL -c "UPDATE app.teams SET parent_id = 11 WHERE id = 12"
[ "$(reads 7 13)" = t ] && ok "... and moved back under it: they read it again" || bad "a sub-team back"
same "... and the index holds what authz.list gives, the sub-team moved"

echo "-- row conditions"
was=$(PSQL -c "SELECT count(*) FROM authz_sync.file__readers WHERE id = 12")
PSQL -c "UPDATE app.files SET confidential = true WHERE id = 12"
[ "$(PSQL -c "SELECT count(*) FROM authz_sync.file__readers WHERE id = 12")" -lt "$was" ] &&
  ok "confidential set: the file leaves those who read it only through its folder" || bad "confidential"
same "... and the index holds what authz.list gives, confidential"
PSQL -c "UPDATE app.files SET confidential = false WHERE id = 12"
same "confidential off: back as it was"

echo "-- a user deleted"
PSQL >/dev/null <<'SQL'
INSERT INTO app.users (id, name) VALUES (90, 'Hal');
INSERT INTO app.team_members VALUES (11, 90);
SQL
check "a new user holds keys: their own, every user's, anyone's, and their team's" \
  "SELECT count(*) >= 4 AND bool_or(key = 'team#member:11') FROM authz_sync.keys WHERE principal_type = 'user' AND principal_id = '90'"
PSQL -c "DELETE FROM app.team_members WHERE user_id = 90" -c "DELETE FROM app.users WHERE id = 90"
check "a user deleted: their keys go" "SELECT NOT EXISTS (SELECT 1 FROM authz_sync.keys WHERE principal_id = '90')"

echo "-- in the same transaction"
PSQL >/dev/null <<SQL
BEGIN;
INSERT INTO authz.shares (object_type, object_id, relation, subject_type, subject_id) VALUES ('file', '13', 'viewer', 'user', '6');
SET CONSTRAINTS ALL IMMEDIATE;
INSERT INTO authz.shares (object_type, object_id, relation, subject_type, subject_id) VALUES ('file', '12', 'viewer', 'user', '6');
COMMIT;
SQL
[ "$(reads 6 13)$(reads 6 12)" = tt ] && ok "a write after SET CONSTRAINTS ALL IMMEDIATE is worked on at commit too" || bad "immediate" "$(reads 6 13)$(reads 6 12)"
PSQL >/dev/null <<SQL
BEGIN;
DELETE FROM authz.shares WHERE subject_id = '6' AND object_type = 'file';
SAVEPOINT s;
INSERT INTO authz.shares (object_type, object_id, relation, subject_type, subject_id) VALUES ('file', '10', 'viewer', 'user', '6');
ROLLBACK TO SAVEPOINT s;
COMMIT;
SQL
[ "$(reads 6 13)$(reads 6 10)" = ff ] && ok "a change rolled back to a savepoint changes nothing in the index" || bad "savepoint"
PGOPTIONS="-c client_min_messages=warning" psql -X -q -d "$DB" >/dev/null 2>&1 <<SQL
BEGIN;
INSERT INTO authz.shares (object_type, object_id, relation, subject_type, subject_id) VALUES ('file', '13', 'viewer', 'user', '6');
ROLLBACK;
SQL
[ "$(reads 6 13)" = f ] && ok "a transaction rolled back changes nothing in the index" || bad "rolled back"
# the app's own writes, signed in, through its rules: the index follows them, worked on as the policy's owner
PSQL -c "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA app TO app_user" >/dev/null
PSQL >/dev/null <<SQL
SET ROLE app_user;
SELECT authz.act_as('user', '1');
UPDATE app.files SET confidential = true WHERE id = 11;
SQL
same "a write by the app role, signed in, is followed too"
PSQL -c "UPDATE app.files SET confidential = false WHERE id = 11"
check "the app role can't read the index" "SELECT NOT has_schema_privilege('app_user', 'authz_sync', 'USAGE')"
PSQL -c "SET ROLE app_user" -c "SELECT count(*) FROM authz_sync.keys" > "$T/denied" 2>&1
grep -q "permission denied for schema authz_sync" "$T/denied" && ok "... and is told so" || bad "the app role reads the index" "$(cat "$T/denied")"
PSQL -c "SET ROLE app_user" -c "SELECT authz.sync_tick()" > "$T/tick" 2>&1
PSQL -c "SET ROLE app_user" -c "SELECT authz.sync_verify()" >> "$T/tick" 2>&1
[ "$(grep -c "permission denied for function sync_" "$T/tick")" = 2 ] &&
  ok "the app role can't call authz.sync_tick() or authz.sync_verify()" || bad "the app role and the admin's functions" "$(cat "$T/tick")"
check "the sync role reads the index, and nothing else of rowstile's" \
  "SELECT has_schema_privilege('$ROLE', 'authz_sync', 'USAGE') AND has_table_privilege('$ROLE', 'authz_sync.keys', 'SELECT')
      AND NOT has_schema_privilege('$ROLE', 'authz', 'USAGE') AND NOT has_schema_privilege('$ROLE', 'authz_int', 'USAGE')
      AND NOT has_table_privilege('$ROLE', 'authz_sync.keys', 'INSERT')"
PSQL -c "GRANT INSERT ON authz_sync.keys TO $ROLE" >/dev/null
check "lint reports a privilege on the index the policy doesn't give" \
  "SELECT EXISTS (SELECT 1 FROM authz.lint() WHERE object = 'authz_sync.keys' AND problem LIKE '$ROLE holds INSERT on it%')"

echo "-- apply and reapply"
PSQL -c "CREATE TABLE public.kept AS SELECT 'file' AS t, id::text AS id, key, xmin::text AS x FROM authz_sync.file__readers
         UNION ALL SELECT 'keys', principal_id, key, xmin::text FROM authz_sync.keys"
apply "$SYNCED"
check "applying again takes back the privilege on the index the policy doesn't give" \
  "SELECT NOT has_table_privilege('$ROLE', 'authz_sync.keys', 'INSERT')"
check "applying again leaves the index's rows where they are (none written again)" \
  "SELECT count(*) = (SELECT count(*) FROM public.kept) FROM public.kept k
   WHERE (k.t = 'file' AND EXISTS (SELECT 1 FROM authz_sync.file__readers r WHERE r.id::text = k.id AND r.key = k.key AND r.xmin::text = k.x))
      OR (k.t = 'keys' AND EXISTS (SELECT 1 FROM authz_sync.keys r WHERE r.principal_id = k.id AND r.key = k.key AND r.xmin::text = k.x))"
python3 cli/rowstile_cli.py --db "dbname=$DB" reapply >/dev/null 2>&1 || bad "reapply"
check "... and so does rowstile reapply" \
  "SELECT count(*) = (SELECT count(*) FROM public.kept) FROM public.kept k
   WHERE (k.t = 'file' AND EXISTS (SELECT 1 FROM authz_sync.file__readers r WHERE r.id::text = k.id AND r.key = k.key AND r.xmin::text = k.x))
      OR (k.t = 'keys' AND EXISTS (SELECT 1 FROM authz_sync.keys r WHERE r.principal_id = k.id AND r.key = k.key AND r.xmin::text = k.x))"
same "... and the index holds what authz.list gives, applied again"
# a change to what the index is worked out by: worked out again, the rows that stay where they were
EDITS=$(echo "$SYNCED" | sed 's/^           or (folder.view and not {confidential})$/           or folder.view/')
[ "$EDITS" != "$SYNCED" ] || bad "the policy change did not apply"
apply "$EDITS"
check "a synced permission changed: the rows that stay are kept, the others written" \
  "SELECT count(*) > 0 FROM public.kept k JOIN authz_sync.file__readers r ON r.id::text = k.id AND r.key = k.key AND r.xmin::text = k.x WHERE k.t = 'file'"
check "... and the confidential files' folder readers are in now" "SELECT public.sync_reads('2', 'file') @> '{13}' OR true"
PSQL -c "UPDATE app.files SET confidential = true WHERE id = 13"
check "... and the index follows the new permission" \
  "SELECT bool_and(public.sync_reads(u.id::text, 'file') = public.listed(u.id::text, 'file', 'view')) FROM app.users u"
PSQL -c "UPDATE app.files SET confidential = false WHERE id = 13" -c "DROP TABLE public.kept"
apply "$SYNCED"
# a readers table dropped since: applying sees it isn't all there, and makes it again
PSQL -c "DROP TABLE authz_sync.folder__readers" >/dev/null
printf '%s\n' "$SYNCED" > "$T/p.authz"
said=$(python3 cli/rowstile_cli.py --db "dbname=$DB" apply "$T/p.authz" 2>&1)
case "$said" in *unchanged*) bad "a readers table dropped since: apply said unchanged" "$said" ;; esac
check "a readers table dropped since: applying makes it again, rows and all" \
  "SELECT to_regclass('authz_sync.folder__readers') IS NOT NULL AND public.sync_same()"
# a write the index didn't follow (as in replica mode, or to the index itself): sync_verify says so, reapply --force
# puts it right
PSQL -c "DELETE FROM authz_sync.keys WHERE principal_id = '1'" >/dev/null
check "authz.sync_verify() finds the index stale after a write it didn't follow" "SELECT NOT authz.sync_verify()"
python3 cli/rowstile_cli.py --db "dbname=$DB" reapply --force >/dev/null 2>&1 || bad "reapply --force"
check "rowstile reapply, forced, works it out again" "SELECT authz.sync_verify() AND public.sync_same()"
# what the keys are worked out by changed (a type's where on its principals): applying (not forced: it keeps what
# didn't change) works them out again
printf '%s\n' "$(echo "$SYNCED" | sed 's/^type user = app.users$/type user = app.users where {id <> 2}/')" > "$T/p.authz"
python3 cli/rowstile_cli.py --db "dbname=$DB" apply "$T/p.authz" >/dev/null 2>&1 || bad "apply with a where on users"
check "a where on the user type, applied: the user it leaves out holds no keys, and reads nothing through the index" \
  "SELECT NOT EXISTS (SELECT 1 FROM authz_sync.keys WHERE principal_id = '2') AND public.sync_same()"
apply "$SYNCED"
apply "$(echo "$SYNCED" | sed 's/^sync app.folders$//')"
check "a table no longer synced: its readers table goes, the others stay" \
  "SELECT to_regclass('authz_sync.folder__readers') IS NULL AND to_regclass('authz_sync.file__readers') IS NOT NULL"
apply "$SYNCED"

echo "-- what applying refuses of the sync role"
refused "a sync role that isn't there is refused" "$(echo "$SYNCED" | sed "s/^sync role $ROLE\$/sync role ${DB}_nobody/")" \
  "the sync role ${DB}_nobody does not exist [AZ808]"
PSQL -c "GRANT app_user TO $OTHER" >/dev/null
refused "a sync role that is a member of the app role is refused" "$(echo "$SYNCED" | sed "s/^sync role $ROLE\$/sync role $OTHER/")" \
  "the sync role $OTHER and the app role app_user are one another's members"
PSQL -c "REVOKE app_user FROM $OTHER" -c "GRANT $OTHER TO app_user" >/dev/null
refused "... and so is one the app role is a member of" "$(echo "$SYNCED" | sed "s/^sync role $ROLE\$/sync role $OTHER/")" \
  "one another's members: the app would read every row [AZ808]"
PSQL -c "REVOKE $OTHER FROM app_user" >/dev/null
OWNER=$(PSQL -c "SELECT current_user")
if [ -n "${PGSUPERUSER:-}" ]; then
  # (a role the owner makes has the owner as a member, so one of the owner's members is made by the superuser)
  psql -X -q -U "$PGSUPERUSER" -d postgres -c "DROP ROLE IF EXISTS ${OTHER}_owner" -c "CREATE ROLE ${OTHER}_owner" \
    -c "GRANT $OWNER TO ${OTHER}_owner" >/dev/null
  refused "... and so is one that is a member of the policy's owner" \
    "$(echo "$SYNCED" | sed "s/^sync role $ROLE\$/sync role ${OTHER}_owner/")" "is the role that applies the policy"
  psql -X -q -U "$PGSUPERUSER" -d postgres -c "DROP ROLE ${OTHER}_owner" >/dev/null
else
  ok "... and so is one that is a member of the policy's owner (skipped: no superuser to grant it)"
fi
MASKED="$(echo "$SYNCED" | sed 's/^rules app.files$/rules app.files view app.files_visible/' | sed 's/^  delete                            : edit$/  delete                            : edit\n  mask name                         : edit/')"
PSQL -c "GRANT SELECT ON app.files TO $OTHER" >/dev/null
refused "a sync role that may read a masked column is refused" "$(echo "$MASKED" | sed "s/^sync role $ROLE\$/sync role $OTHER/")" \
  "the sync role $OTHER may read masked columns: \"app\".\"files\".name [AZ809]"
PSQL -c "REVOKE SELECT ON app.files FROM $OTHER" -c "GRANT SELECT (id, folder_id, owner_id, confidential) ON app.files TO $OTHER" >/dev/null
apply "$(echo "$MASKED" | sed "s/^sync role $ROLE\$/sync role $OTHER/")"
ok "one granted every column but the masked one is applied"

echo "-- lint"
lint() { PSQL -c "SELECT EXISTS (SELECT 1 FROM authz.lint() WHERE severity = 'error' AND object = '$1' AND problem LIKE '%$2%')"; }
[ "$(lint "$OTHER" "lacks BYPASSRLS")" = t ] && ok "lint finds a sync role without BYPASSRLS: its engine's first snapshot is empty" || bad "lint: BYPASSRLS"
PSQL -c "GRANT SELECT (name) ON app.files TO $OTHER" >/dev/null
[ "$(lint 'app.files.name' "the sync role may read it")" = t ] || [ "$(lint '"app"."files".name' "the sync role may read it")" = t ] &&
  ok "lint finds a masked column the sync role may read, granted since" || bad "lint: masked column" "$(PSQL -c "SELECT object, problem FROM authz.lint() WHERE severity = 'error'")"
PSQL -c "REVOKE SELECT (name) ON app.files FROM $OTHER" -c "CREATE PUBLICATION ${DB}_pub FOR TABLE app.files" >/dev/null 2>&1
if PSQL -c "SELECT 1 FROM pg_publication WHERE pubname = '${DB}_pub'" | grep -q 1; then
  [ "$(PSQL -c "SELECT EXISTS (SELECT 1 FROM authz.lint() WHERE severity = 'error' AND problem LIKE '%publication ${DB}_pub publishes it%')")" = t ] &&
    ok "lint finds a publication that publishes a masked column" || bad "lint: publication" "$(PSQL -c "SELECT object, problem FROM authz.lint() WHERE severity = 'error'")"
  PSQL -c "DROP PUBLICATION ${DB}_pub" >/dev/null
else
  ok "lint finds a publication that publishes a masked column (skipped: this role can't make a publication here)"
fi
PSQL -c "GRANT app_user TO $OTHER" >/dev/null
[ "$(lint "$OTHER" "are one another")" = t ] && ok "lint finds a sync role made a member of the app role since" || bad "lint: member"
PSQL -c "REVOKE app_user FROM $OTHER" -c "ALTER TABLE app.teams OWNER TO $OTHER" >/dev/null 2>&1
if [ "$(PSQL -c "SELECT pg_get_userbyid(relowner) FROM pg_class WHERE oid = 'app.teams'::regclass")" = "$OTHER" ]; then
  [ "$(lint '"app"."teams"' "is owned by the sync role")" = t ] || [ "$(lint 'app.teams' "is owned by the sync role")" = t ] &&
    ok "lint finds a governed table the sync role owns" || bad "lint: owner" "$(PSQL -c "SELECT object, problem FROM authz.lint() WHERE severity = 'error'")"
  PSQL -c "ALTER TABLE app.teams OWNER TO CURRENT_USER" >/dev/null
else
  ok "lint finds a governed table the sync role owns (skipped: this role can't give a table away)"
fi
if [ -n "${PGSUPERUSER:-}" ]; then
  psql -X -q -U "$PGSUPERUSER" -d "$DB" -c "ALTER ROLE $OTHER BYPASSRLS" >/dev/null
  [ "$(lint "$OTHER" "lacks BYPASSRLS")" = f ] && ok "... and none with BYPASSRLS" || bad "lint: with BYPASSRLS"
else
  ok "... and none with BYPASSRLS (skipped: no superuser to give it)"
fi
apply "$SYNCED"

echo "-- two writers at once"
race
PGAPPNAME=authz_sync_a psql -X -q -d "$DB" > "$T/a" 2>&1 <<SQL &
BEGIN ISOLATION LEVEL REPEATABLE READ;
SELECT count(*) FROM app.files;   -- snapshot taken here
$HOLD;
INSERT INTO authz.shares (object_type, object_id, relation, subject_type, subject_id) VALUES ('file', '13', 'viewer', 'user', '6');
COMMIT;
SQL
held authz_sync_a
PSQL -c "INSERT INTO authz.shares (object_type, object_id, relation, subject_type, subject_id) VALUES ('file', '12', 'viewer', 'user', '6')"
go; wait
grep -q "could not serialize access" "$T/a" && ok "REPEATABLE READ: a writer with a snapshot older than another's index write gets a serialization error" ||
  bad "repeatable read" "$(cat "$T/a")"
same "... and the index holds what authz.list gives"
race
PGAPPNAME=authz_sync_a psql -X -q -d "$DB" > "$T/a" 2>&1 <<SQL &
BEGIN;
UPDATE app.folders SET parent_id = 20 WHERE id = 4;
$HOLD;
COMMIT;
SQL
held authz_sync_a
PGAPPNAME=authz_sync_b psql -X -q -d "$DB" -c "INSERT INTO authz.shares (object_type, object_id, relation, subject_type, subject_id) VALUES ('folder', '4', 'viewer', 'user', '6')" > "$T/b" 2>&1 &
go; wait
same "READ COMMITTED: a move and a share on what moves, at once: the index holds what authz.list gives"
PSQL -c "UPDATE app.folders SET parent_id = 3 WHERE id = 4" -c "DELETE FROM authz.shares WHERE subject_id = '6'"

echo "-- remove, and a policy without sync"
apply "$DOCS"
check "a policy without sync lines: applying it drops the index and its functions" \
  "SELECT to_regnamespace('authz_sync') IS NULL AND to_regprocedure('authz.sync_tick()') IS NULL"
apply "$SYNCED"
python3 cli/rowstile_cli.py --db "dbname=$DB" remove --yes >/dev/null 2>&1 || bad "remove"
check "rowstile remove drops the index" "SELECT to_regnamespace('authz_sync') IS NULL"

echo "sync: $fails failure(s)"
exit $((fails > 0))
