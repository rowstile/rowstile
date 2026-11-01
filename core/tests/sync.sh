#!/bin/bash
# sync.sh: the sync index (a preview), on the docs app. After each change the index (the rows of a synced table
# whose readers hold a key the user holds) is compared with authz.list as that user, for every user: the share made,
# revoked and ending at authz.sync_tick(), a folder moved out of reach and back, a team left with a row also reached
# another way, a sub-team moved, a row condition set, a user deleted, apply and reapply leaving the rows put; the
# sync role's grants and what applying refuses of it; lint; two writers at once; the forms the docs app doesn't use
# (a group that isn't monotone, custom roles given to it, an arrow through shares, a deny on its own, nobody), changed
# one by one; remove.
#   PGHOST=... PGUSER=authz_owner [PGSUPERUSER=postgres] tests/sync.sh [database]
set -u
cd "$(dirname "$0")/.."
DB=${1:-authz_sync}
T=$(mktemp -d)
. tests/races.sh
ROLE=authz_sync_engine   # the sync role (difftest's too): made if it isn't there, kept
OTHER=${DB}_role         # a role of this suite's, for what applying refuses
FORMS=${DB}_forms        # the other forms' world
KEYED=${DB}_keyed        # ... keyed by inheritance
cleanup() {
  stop_sessions
  dropdb --force --if-exists "$DB" 2>/dev/null
  dropdb --force --if-exists "$FORMS" 2>/dev/null
  dropdb --force --if-exists "$KEYED" 2>/dev/null
  psql -X -q -d postgres -c "DROP ROLE IF EXISTS $OTHER" -c "DROP ROLE IF EXISTS ${OTHER}_away" 2>/dev/null
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
# the command on the database; one that applies makes rowstile's functions anew, and Postgres's counts of their calls
# go with the old ones, so while the run measures what the suites run they are kept first (tests/coverage_functions.sh)
CLI() {
  case "$1" in apply|reapply|remove) bash tests/coverage_functions.sh "$DB";; esac
  python3 cli/rowstile_cli.py --db "dbname=$DB" "$@"
}
# applies the policy text $1 with the rowstile command (its output in $out); a failure ends the suite
apply() {
  printf '%s\n' "$1" > "$T/p.authz"
  out=$(CLI apply "$T/p.authz" --force 2>&1) || { bad "apply" "$out"; exit 1; }
}
# ... or must be refused, saying $2
refused() {
  printf '%s\n' "$2" > "$T/p.authz"
  local said
  if said=$(CLI apply "$T/p.authz" --force 2>&1); then
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
-- the rows of a synced type the user's keys read, as the engines' filter reads them: the readers hold a key the user
-- holds, or, keyed by folder, a key that inherits from a folder that gives the user one
CREATE FUNCTION public.sync_reads(p_user text, p_type text) RETURNS text[] LANGUAGE plpgsql AS $$
DECLARE v text[];
BEGIN
  EXECUTE format('SELECT coalesce(array_agg(DISTINCT r.id::text ORDER BY r.id::text), ''{}'') FROM authz_sync.%I r
                  WHERE r.key IN (SELECT k.key FROM authz_sync.keys k WHERE k.principal_type = ''user'' AND k.principal_id = $1)%s',
                 p_type || '__readers',
                 CASE WHEN to_regclass('authz_sync.inherits') IS NOT NULL THEN
                   ' OR r.key IN (SELECT i.key FROM authz_sync.inherits i WHERE i.source IN (SELECT g.source FROM authz_sync.given g
                     WHERE g.key IN (SELECT k.key FROM authz_sync.keys k WHERE k.principal_type = ''user'' AND k.principal_id = $1)))'
                 ELSE '' END) INTO v USING p_user;
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
# gina in Backend herself too, then not: she keeps Backend through Platform, and Engineering through Backend, which
# what she keeps gives her only once Backend is found given again
PSQL -c "INSERT INTO app.team_members VALUES (11, 7)" -c "DELETE FROM app.team_members WHERE team_id = 11 AND user_id = 7"
check "a member who leaves a team she is also in through a sub-team keeps it, and the teams above it" \
  "SELECT count(*) = 2 FROM authz_sync.keys WHERE principal_id = '7' AND key IN ('team#member:11', 'team#member:10')"
same "... and the index holds what authz.list gives"

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
PSQL -c "SET ROLE app_user" -c "SELECT authz.sync_work()" >> "$T/tick" 2>&1
PSQL -c "SET ROLE app_user" -c "SELECT authz.sync_behind()" >> "$T/tick" 2>&1
[ "$(grep -c "permission denied for function sync_" "$T/tick")" = 4 ] &&
  ok "the app role can't call authz.sync_tick(), authz.sync_verify(), authz.sync_work() or authz.sync_behind()" ||
  bad "the app role and the admin's functions" "$(cat "$T/tick")"
check "in the same transaction, nothing waits: authz.sync_work() has nothing to do, and authz.sync_behind() is null" \
  "SELECT authz.sync_work() = 0 AND authz.sync_behind() IS NULL"
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
CLI reapply >/dev/null 2>&1 || bad "reapply"
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
printf '%s\n' "$SYNCED" > "$T/p.authz"
said=$(CLI apply "$T/p.authz" 2>&1)
case "$said" in *unchanged*) ok "applying the same policy again, the index all there: unchanged" ;; *) bad "an unchanged apply" "$said" ;; esac
# a readers table dropped since: applying sees it isn't all there, and makes it again
PSQL -c "DROP TABLE authz_sync.folder__readers" >/dev/null
printf '%s\n' "$SYNCED" > "$T/p.authz"
said=$(CLI apply "$T/p.authz" 2>&1)
case "$said" in *unchanged*) bad "a readers table dropped since: apply said unchanged" "$said" ;; esac
check "a readers table dropped since: applying makes it again, rows and all" \
  "SELECT to_regclass('authz_sync.folder__readers') IS NOT NULL AND public.sync_same()"
# a write the index didn't follow (as in replica mode, or to the index itself): sync_verify says so, reapply --force
# puts it right
# (it says the first part that differs: the groups, then the keys, then each table's readers)
verify() { PGOPTIONS="-c client_min_messages=notice" psql -X -q -At -d "$DB" -c "SELECT authz.sync_verify()" 2>&1 | tr '\n' ' '; }
PSQL -c "DELETE FROM authz_sync.file__readers WHERE id = 11 AND key = 'user:1'" >/dev/null
stale=$(verify)
PSQL -c "DELETE FROM authz_sync.keys WHERE principal_id = '1'" >/dev/null
stale="$stale| $(verify)"
PSQL -c "DELETE FROM authz_sync.groups WHERE grp = 'team#member:10'" >/dev/null
stale="$stale| $(verify)"
case "$stale" in
  *"differs from a rebuild: file's readers, and what they were worked out from"*" f | "*"differs from a rebuild: keys"*" f | "*"differs from a rebuild: groups"*" f ") \
    ok "authz.sync_verify() finds the index stale after a write it didn't follow, and says which part: readers, keys, groups" ;;
  *) bad "authz.sync_verify() and a stale index" "$stale" ;;
esac
CLI reapply --force >/dev/null 2>&1 || bad "reapply --force"
check "rowstile reapply, forced, works it out again" "SELECT authz.sync_verify() AND public.sync_same()"
# what the keys are worked out by changed (a type's where on its principals): applying (not forced: it keeps what
# didn't change) works them out again
printf '%s\n' "$(echo "$SYNCED" | sed 's/^type user = app.users$/type user = app.users where {id <> 2}/')" > "$T/p.authz"
CLI apply "$T/p.authz" >/dev/null 2>&1 || bad "apply with a where on users"
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
  [ "$(PSQL -c "SELECT EXISTS (SELECT 1 FROM authz.lint() WHERE severity = 'error' AND problem LIKE '%publication ${DB}_pub publishes it%Give the publication a column list without it')")" = t ] &&
    ok "... and says to give the publication a column list without it" || bad "lint: publication's advice" "$(PSQL -c "SELECT object, problem FROM authz.lint() WHERE severity = 'error'")"
  # a FULL replica identity, as Electric asks: Postgres refuses the table's updates with a column list that leaves one out
  PSQL -c "ALTER TABLE app.files REPLICA IDENTITY FULL" >/dev/null
  [ "$(PSQL -c "SELECT EXISTS (SELECT 1 FROM authz.lint() WHERE severity = 'error' AND problem LIKE '%publication ${DB}_pub publishes it%replica identity is FULL%a table of its own%')")" = t ] &&
    ok "... and, for a table whose replica identity is FULL, to keep the column in a table of its own" || bad "lint: publication, FULL" "$(PSQL -c "SELECT object, problem FROM authz.lint() WHERE severity = 'error'")"
  PSQL -c "ALTER TABLE app.files REPLICA IDENTITY DEFAULT" >/dev/null
  PSQL -c "DROP PUBLICATION ${DB}_pub" >/dev/null
else
  ok "lint finds a publication that publishes a masked column (skipped: this role can't make a publication here)"
fi
PSQL -c "ALTER ROLE $OTHER RENAME TO ${OTHER}_away" >/dev/null
[ "$(lint "$OTHER" "the sync role does not exist")" = t ] && ok "lint finds a sync role that is gone since" || bad "lint: gone"
PSQL -c "ALTER ROLE ${OTHER}_away RENAME TO $OTHER" >/dev/null
PSQL -c "GRANT app_user TO $OTHER" >/dev/null
[ "$(lint "$OTHER" "are one another")" = t ] && ok "lint finds a sync role made a member of the app role since" || bad "lint: member"
PSQL -c "REVOKE app_user FROM $OTHER" >/dev/null
# a table given to the sync role, and back (by the superuser where there is one: the owner may give a table only to
# a role it may act as)
owner_of_teams() {
  if [ -n "${PGSUPERUSER:-}" ]; then psql -X -q -U "$PGSUPERUSER" -d "$DB" -c "ALTER TABLE app.teams OWNER TO $1"
  else PSQL -c "ALTER TABLE app.teams OWNER TO $1"; fi >/dev/null 2>&1
}
owner_of_teams "$OTHER"
if [ "$(PSQL -c "SELECT pg_get_userbyid(relowner) FROM pg_class WHERE oid = 'app.teams'::regclass")" = "$OTHER" ]; then
  [ "$(lint '"app"."teams"' "is owned by the sync role")" = t ] || [ "$(lint 'app.teams' "is owned by the sync role")" = t ] &&
    ok "lint finds a governed table the sync role owns" || bad "lint: owner" "$(PSQL -c "SELECT object, problem FROM authz.lint() WHERE severity = 'error'")"
  owner_of_teams "$OWNER"
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

echo "-- writers whose work doesn't meet don't wait"
# a share on Design docs (folder 4) whose commit's work is done (SET CONSTRAINTS ALL IMMEDIATE) and held: what it
# wrote and read keeps its lock rows until it commits
share() { echo "INSERT INTO authz.shares (object_type, object_id, relation, subject_type, subject_id) VALUES ('$1', '$2', 'viewer', 'user', '$3')"; }
race
PGAPPNAME=authz_sync_a psql -X -q -d "$DB" > "$T/a" 2>&1 <<SQL &
BEGIN;
$(share folder 4 6);
SET CONSTRAINTS ALL IMMEDIATE;
$HOLD;
COMMIT;
SQL
held authz_sync_a
if PGOPTIONS="-c lock_timeout=20s -c client_min_messages=warning" psql -X -q -At -v ON_ERROR_STOP=1 -d "$DB" -c "$(share file 15 3)" > "$T/b" 2>&1; then
  ok "a share on a Globex file doesn't wait for a share on Design docs to commit: their work meets nowhere"
else
  bad "a writer whose work meets no other's waited" "$(cat "$T/b")"
fi
PGAPPNAME=authz_sync_b psql -X -q -d "$DB" -c "$(share file 11 3)" > "$T/b" 2>&1 &
blocked authz_sync_b && ok "... one on a file in Design docs waits: its work writes what the other's does"
go; wait
same "... and the index holds what authz.list gives, after both"
PSQL -c "DELETE FROM authz.shares WHERE subject_id IN ('3', '6')"
# a move holds the folder it moves into as what its work reads: a share on that folder, which doesn't see the move
# yet (its work would leave the moved folder out), waits for it, then sees it
race
PGAPPNAME=authz_sync_a psql -X -q -d "$DB" > "$T/a" 2>&1 <<SQL &
BEGIN;
UPDATE app.folders SET parent_id = 20 WHERE id = 4;
SET CONSTRAINTS ALL IMMEDIATE;
$HOLD;
COMMIT;
SQL
held authz_sync_a
PGAPPNAME=authz_sync_b psql -X -q -d "$DB" -c "$(share folder 20 3)" > "$T/b" 2>&1 &
blocked authz_sync_b && ok "a share on the folder another one moves into waits for the move: the move's work reads it"
go; wait
[ "$(reads 3 11)" = t ] && ok "... then its work sees the move: carol reads the file in the moved folder" || bad "the share after the move" "$(reads 3 11)"
same "... and the index holds what authz.list gives"
PSQL -c "UPDATE app.folders SET parent_id = 3 WHERE id = 4" -c "DELETE FROM authz.shares WHERE subject_id = '3'"
same "... and put back"

echo "-- keyed by folder"
BY=$(echo "$SYNCED" | sed 's/^sync app.files : view$/sync app.files : view by folder/; s/^sync app.folders$/sync app.folders by folder/')
[ "$BY" != "$SYNCED" ] || bad "the keyed policy is the same as the other"
apply "$BY"
same "keyed by folder, applied: for every user, the index holds what authz.list gives"
check "keyed by folder: a file's readers are its own keys and its folder's keys, not the readers of each folder above" \
  "SELECT array_agg(key ORDER BY key) = '{folder#edit:4,folder#view:4,user:1}' FROM authz_sync.file__readers WHERE id = 11"
check "... a folder's, its own key" \
  "SELECT bool_and(key = 'folder#view:' || id) AND count(*) = (SELECT count(*) FROM app.folders) FROM authz_sync.folder__readers"
check "... and no principal holds a folder's key: each holds its own and its groups', as copied in" \
  "SELECT NOT EXISTS (SELECT 1 FROM authz_sync.keys WHERE key LIKE 'folder#%')
      AND EXISTS (SELECT 1 FROM authz_sync.keys WHERE principal_id = '7' AND key = 'team#member:10')"
check "... Design docs' view inherits the own keys of Design docs, Engineering and Company: the folders above it" \
  "SELECT array_agg(source ORDER BY source) = '{folder#view:1,folder#view:3,folder#view:4}' FROM authz_sync.inherits WHERE key = 'folder#view:4'"
check "... and Engineering gives view itself to its owner, the org's admins, and the team that may edit it" \
  "SELECT array_agg(key ORDER BY key) = '{org#admin:1,team#member:10,user:1}' FROM authz_sync.given WHERE source = 'folder#view:3'"
check "... Secrets doesn't inherit: its view takes its own keys only" \
  "SELECT array_agg(source) = '{folder#view:5}' FROM authz_sync.inherits WHERE key = 'folder#view:5'"
check "authz.sync_verify(): the keyed index matches a rebuild" "SELECT authz.sync_verify()"
# the engines' filter, as rowstile client electric writes it ($1, the user's id), against authz.list for every user
filter() {
  python3 -c "import sys; sys.path.insert(0, '.'); from authzlib import Compiler, parse_policy
c = Compiler(parse_policy(open('$T/p.authz').read(), 'p.authz')); c.compile('p.authz')
print(c.electric_shapes()['app.$1']['where']['user'].replace('\$1', 'u.id::text'))"
}
check "keyed by folder: the engines' filter, as rowstile client electric writes it, gives every user what authz.list gives" \
  "SELECT bool_and(ARRAY(SELECT x.id::text FROM app.files x WHERE $(filter files) ORDER BY 1) = public.listed(u.id::text, 'file', 'view')
              AND ARRAY(SELECT x.id::text FROM app.folders x WHERE $(filter folders) ORDER BY 1) = public.listed(u.id::text, 'folder', 'view'))
   FROM app.users u"
files() { PSQL -c "SELECT md5(string_agg(id || key || xmin, ',' ORDER BY id, key)) FROM authz_sync.file__readers"; }
# what a write wrote of the index's other tables: keys, groups, given, inherits (their rows and versions)
wrote() { PSQL -c "SELECT md5(string_agg(t || ':' || r, ',' ORDER BY t, r)) FROM (
  SELECT 'keys' AS t, principal_id || key || xmin AS r FROM authz_sync.keys UNION ALL SELECT 'groups', grp || key || xmin FROM authz_sync.groups
  UNION ALL SELECT 'given', source || key || xmin FROM authz_sync.given UNION ALL SELECT 'inherits', key || source || xmin FROM authz_sync.inherits) z
  WHERE t = ANY (string_to_array('$1', ','))"; }
readers=$(files)
others=$(wrote keys,groups,given)
before=$(PSQL -c "SELECT string_agg(u.id::text, ',' ORDER BY u.id) FROM app.users u WHERE '11' = ANY (public.sync_reads(u.id::text, 'file'))")
PSQL -c "UPDATE app.folders SET parent_id = 20 WHERE id = 4"
after=$(PSQL -c "SELECT string_agg(u.id::text, ',' ORDER BY u.id) FROM app.users u WHERE '11' = ANY (public.sync_reads(u.id::text, 'file'))")
[ "$before" != "$after" ] && ok "keyed by folder: a folder moved out of reach: the file in it leaves those who read it through Engineering ($before -> $after)" ||
  bad "a keyed move" "$before -> $after"
[ "$(files)" = "$readers" ] && ok "... and the move rewrote no file's readers" || bad "a keyed move wrote files' readers"
[ "$(wrote keys,groups,given)" = "$others" ] && ok "... nor any key, group or folder's own keys: only what the folders below inherit" ||
  bad "a keyed move wrote keys, groups or given"
check "... Design docs' view now inherits from Globex's folders" \
  "SELECT array_agg(source ORDER BY source) = '{folder#view:20,folder#view:4}' FROM authz_sync.inherits WHERE key = 'folder#view:4'"
same "... and the index holds what authz.list gives, after the move"
PSQL -c "UPDATE app.folders SET parent_id = 3 WHERE id = 4"
[ "$(PSQL -c "SELECT string_agg(u.id::text, ',' ORDER BY u.id) FROM app.users u WHERE '11' = ANY (public.sync_reads(u.id::text, 'file'))")" = "$before" ] &&
  [ "$(files)" = "$readers" ] && ok "keyed by folder: moved back: they read it again, and no file's readers were written" || bad "keyed: moved back"
same "... and the index holds what authz.list gives, moved back"
inherited=$(wrote keys,groups,inherits)
PSQL -c "$(share folder 6 6)"
[ "$(reads 6 12)" = t ] && [ "$(files)" = "$readers" ] &&
  ok "keyed by folder: a share on Keys: frank reads the file in it, and no file's readers were written" || bad "a keyed share"
[ "$(wrote keys,groups,inherits)" = "$inherited" ] && check "... nor any key, group or inheritance: one row of what Keys gives itself" \
  "SELECT EXISTS (SELECT 1 FROM authz_sync.given WHERE source = 'folder#view:6' AND key = 'user:6')" || bad "a keyed share wrote keys or inherits"
same "... and the index holds what authz.list gives, the folder shared"
PSQL -c "DELETE FROM authz.shares WHERE subject_id = '6'"
same "... and revoked"
others=$(wrote given,inherits)
PSQL -c "DELETE FROM app.team_members WHERE user_id = 2 AND team_id = 11"
same "keyed by folder: a team left: the index holds what authz.list gives"
[ "$(wrote given,inherits)" = "$others" ] && [ "$(files)" = "$readers" ] &&
  check "... and it wrote the team's members and bob's keys alone: no readers, nor what folders give or inherit" \
    "SELECT NOT EXISTS (SELECT 1 FROM authz_sync.keys WHERE principal_id = '2' AND key LIKE 'team#%')" || bad "a keyed team left wrote more than keys"
PSQL -c "INSERT INTO app.team_members VALUES (11, 2)" -c "UPDATE app.teams SET parent_id = NULL WHERE id = 12"
same "keyed by folder: a sub-team moved out: the index holds what authz.list gives"
PSQL -c "UPDATE app.teams SET parent_id = 11 WHERE id = 12" -c "UPDATE app.files SET confidential = true WHERE id = 12"
same "keyed by folder: confidential set: the index holds what authz.list gives"
PSQL -c "UPDATE app.files SET confidential = false WHERE id = 12" -c "UPDATE app.folders SET inherit = false WHERE id = 3"
same "keyed by folder: a folder that stops inheriting: the index holds what authz.list gives"
PSQL -c "UPDATE app.folders SET inherit = true WHERE id = 3" -c "DELETE FROM app.folder_links"
same "keyed by folder: a link taken away: the index holds what authz.list gives"
PSQL >/dev/null <<'SQL'
INSERT INTO app.folder_links VALUES (21, 1);
INSERT INTO app.folders (id, org_id, parent_id, owner_id, name, inherit) VALUES (30, 1, 4, 2, 'New', true);
INSERT INTO app.files (id, folder_id, owner_id, name, confidential) VALUES (30, 30, 3, 'new.md', false);
SQL
same "keyed by folder: a folder made, with a file in it: the index holds what authz.list gives"
PSQL -c "DELETE FROM app.files WHERE id = 30" -c "DELETE FROM app.folders WHERE id = 30"
same "keyed by folder: and deleted"
check "keyed by folder: after them all, authz.sync_verify() finds the index matches a rebuild" "SELECT authz.sync_verify()"
# (what each folder gives itself, then whose own keys each inherits, then the readers)
PSQL -c "DELETE FROM authz_sync.inherits WHERE key = 'folder#view:4' AND source = 'folder#view:3'" >/dev/null
stale=$(verify)
PSQL -c "DELETE FROM authz_sync.given WHERE source = 'folder#view:3' AND key = 'user:1'" >/dev/null
stale="$stale| $(verify)"
case "$stale" in
  *"differs from a rebuild: whose own keys each object inherits"*" f | "*"differs from a rebuild: what each object gives itself"*" f ") \
    ok "keyed by folder: authz.sync_verify() finds what a folder inherits or gives itself stale, and says which" ;;
  *) bad "authz.sync_verify() and a stale keyed index" "$stale" ;;
esac
CLI reapply --force >/dev/null 2>&1 || bad "reapply --force, keyed"
check "... and rowstile reapply, forced, works them out again" "SELECT authz.sync_verify() AND public.sync_same()"
# an index keyed by folder as the earlier layout left it: each principal held the key of every folder it may read, and
# the groups the keys of each folder's readers; there was no inherits or given, and it was worked out by other functions
PSQL >/dev/null <<'SQL'
DROP TABLE authz_sync.inherits, authz_sync.given;
INSERT INTO authz_sync.groups SELECT 'folder#view:' || f.id, 'user:' || f.owner_id FROM app.folders f;
INSERT INTO authz_sync.keys SELECT 'user', f.owner_id::text, 'folder#view:' || f.id FROM app.folders f ON CONFLICT DO NOTHING;
UPDATE authz_sync.definitions SET hash = 'the earlier layout';
SQL
kept=$(PSQL -c "SELECT string_agg(c.oid::text, ',' ORDER BY c.relname) FROM pg_class c WHERE c.relnamespace = 'authz_sync'::regnamespace AND c.relkind = 'r'")
apply "$BY"
check "an index the earlier layout made (every folder's key among each principal's keys): applying works it out again, no folder's key or group left" \
  "SELECT NOT EXISTS (SELECT 1 FROM authz_sync.keys WHERE key LIKE 'folder#%')
      AND NOT EXISTS (SELECT 1 FROM authz_sync.groups WHERE grp LIKE 'folder#%') AND authz.sync_verify()"
same "... and the index holds what authz.list gives"
[ "$(PSQL -c "SELECT string_agg(c.oid::text, ',' ORDER BY c.relname) FROM pg_class c WHERE c.relnamespace = 'authz_sync'::regnamespace
              AND c.relkind = 'r' AND c.relname NOT IN ('given', 'inherits')")" = "$kept" ] &&
  ok "... and kept its tables, the engines' shapes on them: inherits and given are made beside them" || bad "the earlier layout's tables kept"
apply "$SYNCED"
same "copied again: the index holds what authz.list gives"

echo "-- after commit"
AFTER="$SYNCED
sync after commit"
apply "$AFTER"
same "after commit, applied: the index holds what authz.list gives"
check "after commit: nothing waits" "SELECT authz.sync_behind() IS NULL AND authz.sync_work() = 0"
PSQL -c "$(share file 13 6)"
[ "$(reads 6 13)" = f ] && ok "after commit: a share made isn't in the index before the worker runs" || bad "after commit, before the worker"
check "... authz.sync_behind() says how long it has waited" "SELECT authz.sync_behind() >= interval '0'"
behind=$(verify)
case "$behind" in
  *"the sync index is behind: 1 changes wait for authz.sync_work()"*" f "*) ok "... and authz.sync_verify() says the index is behind, and is false" ;;
  *) bad "authz.sync_verify() and a lagging index" "$behind" ;;
esac
check "authz.sync_work() works the change into the index, and says how many objects it worked on" "SELECT authz.sync_work() = 1"
[ "$(reads 6 13)" = t ] && ok "... then frank reads file 13" || bad "after commit, after the worker"
same "... and the index holds what authz.list gives, after the worker"
check "... and nothing waits" "SELECT authz.sync_behind() IS NULL AND authz.sync_work() = 0 AND authz.sync_verify()"
readers=$(files)
PSQL -c "DELETE FROM authz.shares WHERE subject_id = '6'" -c "UPDATE app.folders SET parent_id = 20 WHERE id = 4" \
     -c "DELETE FROM app.team_members WHERE user_id = 2 AND team_id = 11" -c "UPDATE app.files SET confidential = true WHERE id = 12"
[ "$(files)" = "$readers" ] && ok "after commit: a revoke, a move, a team left and a row condition write nothing of the index" ||
  bad "after commit: writers wrote the index"
PSQL -c "SELECT authz.sync_work()" >/dev/null
same "... and one run of the worker after them: the index holds what authz.list gives"
PSQL -c "UPDATE app.folders SET parent_id = 3 WHERE id = 4" -c "INSERT INTO app.team_members VALUES (11, 2)" \
     -c "UPDATE app.files SET confidential = false WHERE id = 12" -c "$(share file 13 6)"
PSQL >/dev/null <<'SQL'
BEGIN;
SELECT authz.sync_work();
ROLLBACK;
SQL
[ "$(reads 6 13)" = f ] && ok "after commit: a run rolled back (one that fails, or is stopped) leaves the changes waiting" || bad "a run rolled back"
PSQL -c "SELECT authz.sync_work()" >/dev/null
[ "$(reads 6 13)" = t ] && ok "... and the next run works them in" || bad "the run after one rolled back"
same "... and the index holds what authz.list gives, all put back"
race
PGAPPNAME=authz_sync_a psql -X -q -d "$DB" > "$T/a" 2>&1 <<SQL &
BEGIN;
SELECT authz.sync_work();
$HOLD;
COMMIT;
SQL
held authz_sync_a
if PGOPTIONS="-c lock_timeout=20s -c client_min_messages=warning" psql -X -q -At -v ON_ERROR_STOP=1 -d "$DB" -c "$(share file 12 6)" > "$T/b" 2>&1; then
  ok "after commit: a writer doesn't wait for a worker at work"
else
  bad "after commit: a writer waited for the worker" "$(cat "$T/b")"
fi
check "... and while one works, another does nothing" "SELECT authz.sync_work() = 0"
go; wait
check "... then the next works in what waited" "SELECT authz.sync_work() = 1"
same "... and the index holds what authz.list gives"
PSQL -c "DELETE FROM authz.shares WHERE subject_id = '6'"
PSQL -c "SELECT authz.sync_tick()" >/dev/null
PSQL -c "INSERT INTO authz.shares (object_type, object_id, relation, subject_type, subject_id, expires_at)
         VALUES ('file', '13', 'viewer', 'user', '6', clock_timestamp() + interval '1 second')"
PSQL -c "SELECT authz.sync_work()" >/dev/null
sleep 1.2
check "after commit: authz.sync_tick() notes the shares whose end passed, for the worker" "SELECT authz.sync_tick() = 1"
[ "$(reads 6 13)" = t ] && ok "... and until the worker runs, the index still says so" || bad "the tick, before the worker"
check "... which works them in" "SELECT authz.sync_work() = 1"
[ "$(reads 6 13)" = f ] && ok "... then frank no longer reads file 13" || bad "the tick, after the worker"
PSQL -c "DELETE FROM authz.shares WHERE subject_id = '6'"
apply "$AFTER"
check "applying works in what waits" "SELECT authz.sync_behind() IS NULL AND authz.sync_verify()"
same "... and the index holds what authz.list gives"
apply "$SYNCED"
check "a policy back in the same transaction: the table of what waits goes" "SELECT to_regclass('authz_sync.pending') IS NULL"
same "... and the index holds what authz.list gives"

echo "-- the forms the docs app doesn't use"
# a group whose relation isn't monotone (its readers copied in, not a key), shares and custom roles given to it, a
# relation to users or boxes named on its own and followed, an arrow through shares, a deny on its own, a condition
# and a deny, nobody: applied, then changed one by one, the index compared with authz.list for every user and type
dropdb --if-exists "$FORMS" 2>/dev/null; createdb "$FORMS" || exit 1
FPSQL() { PGOPTIONS="-c client_min_messages=warning" psql -X -q -At -v ON_ERROR_STOP=1 -d "$FORMS" "$@"; }
FPSQL >/dev/null <<'SQL' || exit 1
CREATE SCHEMA f;
CREATE TABLE f.users (id bigint PRIMARY KEY);
CREATE TABLE f.crews (id bigint PRIMARY KEY);
CREATE TABLE f.crew_members (crew_id bigint NOT NULL REFERENCES f.crews, user_id bigint NOT NULL REFERENCES f.users,
  banned boolean NOT NULL DEFAULT false, PRIMARY KEY (crew_id, user_id));
CREATE TABLE f.boxes (id bigint PRIMARY KEY, owner_id bigint REFERENCES f.users);
CREATE TABLE f.docs (id bigint PRIMARY KEY, owner_id bigint REFERENCES f.users, holder_type text, holder_id bigint);
CREATE TABLE f.notes (id bigint PRIMARY KEY, owner_id bigint REFERENCES f.users);
CREATE TABLE f.note_blocks (note_id bigint NOT NULL REFERENCES f.notes, user_id bigint NOT NULL REFERENCES f.users);
CREATE TABLE f.memos (id bigint PRIMARY KEY, published boolean NOT NULL DEFAULT false);
CREATE TABLE f.memo_blocks (memo_id bigint NOT NULL REFERENCES f.memos, user_id bigint NOT NULL REFERENCES f.users);
CREATE TABLE f.vaults (id bigint PRIMARY KEY);
INSERT INTO f.users SELECT generate_series(1, 5);
INSERT INTO f.crews VALUES (1), (2);
INSERT INTO f.crew_members VALUES (1, 1, false), (1, 2, true), (1, 3, false), (2, 4, false);
INSERT INTO f.boxes VALUES (1, 1), (2, 2);
INSERT INTO f.docs VALUES (1, 5, NULL, NULL), (2, 5, NULL, NULL), (3, 5, NULL, NULL), (4, 5, 'box', 2), (5, 5, 'user', 4);
INSERT INTO f.notes VALUES (1, 1), (2, 2);
INSERT INTO f.note_blocks VALUES (1, 3), (2, 4);
INSERT INTO f.memos VALUES (1, true), (2, false);
INSERT INTO f.memo_blocks VALUES (1, 2);
INSERT INTO f.vaults VALUES (1);
SQL
cat > "$T/forms.authz" <<EOF
app role app_user

type user = f.users
  can view = nobody

type crew = f.crews
  member : user = f.crew_members(crew_id -> user_id)
  banned : user = f.crew_members(crew_id -> user_id) where {banned}
  can active = member and not banned

type box = f.boxes
  owner : user = owner_id
  can view = owner
  can manage_roles = owner

type doc = f.docs
  owner    : user = owner_id
  holder   : user, box = (holder_type, holder_id)
  shortcut : user, box shared
  viewer   : user, crew#active shared
  roles    : user, crew#active
  can share = owner
  can view = owner or viewer or roles or holder or holder.view or shortcut or shortcut.view

type note = f.notes
  owner   : user = owner_id
  blocked : user = f.note_blocks(note_id -> user_id)
  can view = owner or not blocked

type memo = f.memos
  blocked : user = f.memo_blocks(memo_id -> user_id)
  can view = {published} and not blocked

type vault = f.vaults
  can view = nobody

sync role $ROLE
sync f.docs : view
sync f.notes : view
sync f.memos : view
sync f.vaults : view
EOF
said=$(python3 cli/rowstile_cli.py --db "dbname=$FORMS" apply "$T/forms.authz" 2>&1) || { bad "apply the other forms" "$said"; exit 1; }
FPSQL >/dev/null <<'SQL' || exit 1
-- (type, user) where the index and authz.list differ
CREATE FUNCTION public.forms_diff() RETURNS TABLE(type text, usr text, idx text[], listed text[]) LANGUAGE plpgsql AS $$
DECLARE t text; u text; a text[]; b text[];
BEGIN
  FOREACH t IN ARRAY ARRAY['doc', 'note', 'memo', 'vault'] LOOP
    FOR u IN SELECT id::text FROM f.users ORDER BY id LOOP
      EXECUTE format('SELECT coalesce(array_agg(DISTINCT r.id::text ORDER BY r.id::text), ''{}'') FROM authz_sync.%I r
                      WHERE r.key IN (SELECT k.key FROM authz_sync.keys k WHERE k.principal_type = ''user'' AND k.principal_id = $1)',
                     t || '__readers') INTO a USING u;
      PERFORM set_config('authz.user_id', u, true);
      PERFORM set_config('authz.principal_type', '', true);
      SELECT coalesce(array_agg(x ORDER BY x), '{}') INTO b FROM authz.list(t, 'view') x;
      PERFORM set_config('authz.user_id', '', true);
      IF a IS DISTINCT FROM b THEN type := t; usr := u; idx := a; listed := b; RETURN NEXT; END IF;
    END LOOP;
  END LOOP;
END $$;
SQL
# $1 = label, $2 = the change: then the index must hold what authz.list gives
change() {
  FPSQL -c "$2" >/dev/null || { bad "$1" "the change failed"; return; }
  local diff
  diff=$(FPSQL -c "SELECT string_agg(type || ' ' || usr || ': ' || idx::text || ' in the index, ' || listed::text || ' listed', '; ') FROM public.forms_diff()")
  [ -z "$diff" ] && ok "$1: the index holds what authz.list gives" || bad "$1" "$diff"
}
# whether user $1 reads $2 $3 through the index
freads() {
  FPSQL -c "SELECT EXISTS (SELECT 1 FROM authz_sync.${2}__readers r JOIN authz_sync.keys k ON k.key = r.key
            WHERE r.id = $3 AND k.principal_type = 'user' AND k.principal_id = '$1')"
}
change "the other forms, applied" "SELECT 1"
check_f() { local got; got=$(FPSQL -c "$2" 2>&1); [ "$got" = t ] && ok "$1" || bad "$1" "$got"; }
check_f "a group that isn't monotone gives no key: what is given to it copies its members in" \
  "SELECT NOT EXISTS (SELECT 1 FROM authz_sync.groups) AND NOT EXISTS (SELECT 1 FROM authz_sync.keys WHERE key LIKE 'crew#%')"
change "doc 1 shared with crew 1's active members" \
  "INSERT INTO authz.shares (object_type, object_id, relation, subject_type, subject_id, subject_relation) VALUES ('doc', '1', 'viewer', 'crew', '1', 'active')"
was=$(freads 3 doc 1)
change "a member of crew 1 banned" "UPDATE f.crew_members SET banned = true WHERE crew_id = 1 AND user_id = 3"
[ "$was$(freads 3 doc 1)" = tf ] && ok "... and they no longer read doc 1" || bad "banned" "$was$(freads 3 doc 1)"
change "a custom role giving view on doc 2, given to crew 1's active members" \
  "WITH r AS (INSERT INTO authz.roles (owner_type, owner_id, object_type, name) VALUES ('box', '1', 'doc', 'reader') RETURNING id),
        p AS (INSERT INTO authz.role_permissions SELECT id, 'view' FROM r)
   INSERT INTO authz.shares (object_type, object_id, relation, subject_type, subject_id, subject_relation)
   SELECT 'doc', '2', 'role:' || id, 'crew', '1', 'active' FROM r"
was=$(freads 2 doc 2)
change "a banned member of crew 1 let back" "UPDATE f.crew_members SET banned = false WHERE crew_id = 1 AND user_id = 2"
[ "$was$(freads 2 doc 2)" = ft ] && ok "... and they read doc 2, through the role" || bad "let back" "$was$(freads 2 doc 2)"
change "doc 3 shared with box 1, whose owner reads it through shortcut.view" \
  "INSERT INTO authz.shares (object_type, object_id, relation, subject_type, subject_id) VALUES ('doc', '3', 'shortcut', 'box', '1')"
change "doc 5 held by box 1" "UPDATE f.docs SET holder_type = 'box', holder_id = 1 WHERE id = 5"
was=$(freads 4 doc 3)$(freads 1 doc 3)
change "box 1 given to another owner" "UPDATE f.boxes SET owner_id = 4 WHERE id = 1"
[ "$was$(freads 4 doc 3)$(freads 1 doc 3)$(freads 4 doc 5)" = fttft ] &&
  ok "... and docs 3 and 5 follow the box: through the share and through holder.view" || bad "the box moved" "$was$(freads 4 doc 3)$(freads 1 doc 3)$(freads 4 doc 5)"
change "box 2, doc 4's holder, given to another owner" "UPDATE f.boxes SET owner_id = 3 WHERE id = 2"
change "a user blocked from a note they don't own" "INSERT INTO f.note_blocks VALUES (2, 1)"
change "a note's block lifted" "DELETE FROM f.note_blocks WHERE note_id = 1"
change "a memo published" "UPDATE f.memos SET published = true WHERE id = 2"
change "a user blocked from the published memo" "INSERT INTO f.memo_blocks VALUES (2, 5)"
change "the role no longer gives view" "DELETE FROM authz.role_permissions"
change "a member leaves crew 1" "DELETE FROM f.crew_members WHERE crew_id = 1 AND user_id = 1"
change "a new user, blocked from nothing" "INSERT INTO f.users VALUES (6)"
check_f "nobody reads the vault, and authz.sync_verify() finds the index matches a rebuild" \
  "SELECT NOT EXISTS (SELECT 1 FROM authz_sync.vault__readers) AND authz.sync_verify()"
# the runtime's other answers about the same forms, for every type, permission, object and user: authz.list in
# pages, authz.can, authz.perms, authz.who and authz.explain say what authz.list says
FPSQL >/dev/null <<'SQL' || exit 1
CREATE FUNCTION public.forms_api() RETURNS SETOF text LANGUAGE plpgsql AS $$
DECLARE t record; u text; o text; listed text[]; yes boolean; page text[]; pages text[]; after text;
BEGIN
  FOR t IN SELECT p.type, p.perm, ty.tbl FROM authz_int.perms p JOIN authz_int.types ty ON ty.name = p.type ORDER BY 1, 2 LOOP
    FOR u IN SELECT id::text FROM f.users ORDER BY id LOOP
      PERFORM set_config('authz.user_id', u, true);
      PERFORM set_config('authz.principal_type', '', true);
      SELECT coalesce(array_agg(x), '{}') INTO listed FROM authz.list(t.type, t.perm) x;
      -- (and two at a time, after the last one given: the same rows)
      pages := '{}'; after := NULL;
      LOOP
        SELECT coalesce(array_agg(x), '{}') INTO page FROM authz.list(t.type, t.perm, after, 2) x;
        EXIT WHEN cardinality(page) = 0;
        pages := pages || page; after := page[cardinality(page)];
      END LOOP;
      IF (SELECT array_agg(x ORDER BY x) FROM unnest(pages) x) IS DISTINCT FROM (SELECT array_agg(x ORDER BY x) FROM unnest(listed) x) THEN
        RETURN NEXT format('list, two at a time: %s %s, user %s', t.type, t.perm, u);
      END IF;
      IF (SELECT array_agg(x ORDER BY x) FROM authz.list(t.type, t.perm, '0', NULL) x)
         IS DISTINCT FROM (SELECT array_agg(x ORDER BY x) FROM unnest(listed) x) THEN
        RETURN NEXT format('list, after 0: %s %s, user %s', t.type, t.perm, u);
      END IF;
      FOR o IN EXECUTE format('SELECT id::text FROM %s ORDER BY id', t.tbl) LOOP
        yes := o = ANY (listed);
        IF authz.can(t.type, o, t.perm) IS DISTINCT FROM yes THEN RETURN NEXT format('can: %s %s %s, user %s', t.type, o, t.perm, u); END IF;
        IF (t.perm = ANY (authz.perms(t.type, o))) IS DISTINCT FROM yes THEN RETURN NEXT format('perms: %s %s %s, user %s', t.type, o, t.perm, u); END IF;
        IF EXISTS (SELECT 1 FROM authz.who(t.type, o, t.perm) w WHERE w = u) IS DISTINCT FROM yes THEN
          RETURN NEXT format('who: %s %s %s, user %s', t.type, o, t.perm, u);
        END IF;
        IF ((SELECT e FROM authz.explain(t.type, o, t.perm, u) e LIMIT 1) LIKE 'yes %') IS DISTINCT FROM yes THEN
          RETURN NEXT format('explain: %s %s %s, user %s', t.type, o, t.perm, u);
        END IF;
      END LOOP;
    END LOOP;
  END LOOP;
  PERFORM set_config('authz.user_id', '', true);
END $$;
SQL
api=$(FPSQL -c "SELECT string_agg(x, '; ') FROM public.forms_api() x")
[ -z "$api" ] && [ "$(FPSQL -c "SELECT count(*) FROM authz.check_invariants()")" = 0 ] &&
  ok "... and authz.list two at a time, authz.can, authz.perms, authz.who and authz.explain answer as authz.list does, for every type, permission, object and user" ||
  bad "the runtime's other answers" "$api"
dropdb --force "$FORMS"

echo "-- keyed by inheritance, the other forms"
# a recursion through two types (a space sits in a page, a page in a space), keyed by each, a type's where, and a
# note whose view denies (an and / not, copied in there): the engines' filter, as rowstile client electric writes it,
# against authz.list for every user and table, after each change
dropdb --if-exists "$KEYED" 2>/dev/null; createdb "$KEYED" || exit 1
KPSQL() { PGOPTIONS="-c client_min_messages=warning" psql -X -q -At -v ON_ERROR_STOP=1 -d "$KEYED" "$@"; }
KPSQL >/dev/null <<'SQL' || exit 1
CREATE SCHEMA k;
CREATE TABLE k.users (id bigint PRIMARY KEY);
CREATE TABLE k.spaces (id bigint PRIMARY KEY, owner_id bigint REFERENCES k.users, home_id bigint, hidden boolean NOT NULL DEFAULT false);
CREATE TABLE k.pages (id bigint PRIMARY KEY, space_id bigint REFERENCES k.spaces, owner_id bigint REFERENCES k.users);
CREATE TABLE k.notes (id bigint PRIMARY KEY, space_id bigint REFERENCES k.spaces);
CREATE TABLE k.mutes (note_id bigint NOT NULL REFERENCES k.notes, user_id bigint NOT NULL REFERENCES k.users);
INSERT INTO k.users SELECT generate_series(1, 5);
INSERT INTO k.spaces VALUES (1, 1, NULL, false), (2, 2, 10, false), (3, 3, 20, false);
INSERT INTO k.pages VALUES (10, 1, 4), (20, 2, NULL), (30, 3, 5);
INSERT INTO k.notes VALUES (1, 2), (2, 3);
INSERT INTO k.mutes VALUES (1, 1);
SQL
cat > "$T/keyed.authz" <<EOF
app role app_user

type user = k.users
  can view = nobody

type space = k.spaces where {not hidden}
  owner : user = owner_id
  home  : page = home_id
  can view = owner or home.view

type page = k.pages
  space  : space = space_id
  owner  : user = owner_id
  viewer : user shared
  can share = owner
  can view = owner or viewer or space.view

type note = k.notes
  space : space = space_id
  muted : user = k.mutes(note_id -> user_id)
  can view = space.view and not muted

sync role $ROLE
sync k.spaces : view by space
sync k.pages : view by page
sync k.notes : view by space
EOF
said=$(python3 cli/rowstile_cli.py --db "dbname=$KEYED" apply "$T/keyed.authz" 2>&1) || { bad "apply the keyed forms" "$said"; exit 1; }
python3 -c "import sys; sys.path.insert(0, '.'); from authzlib import Compiler, parse_policy
c = Compiler(parse_policy(open('$T/keyed.authz').read(), 'keyed.authz')); c.compile('keyed.authz')
shapes = c.electric_shapes()
for s in c.pol.syncs.values(): print(c.sync_type(s).name + '|' + s.table + '|' + shapes[s.table]['where']['user'].replace('\$1', 'u.id::text'))" > "$T/filters"
KPSQL >/dev/null <<'SQL' || exit 1
CREATE FUNCTION public.klisted(p_user text, p_type text) RETURNS text[] LANGUAGE plpgsql AS $$
DECLARE v text[];
BEGIN
  PERFORM set_config('authz.user_id', p_user, true);
  PERFORM set_config('authz.principal_type', '', true);
  SELECT coalesce(array_agg(x ORDER BY x), '{}') INTO v FROM authz.list(p_type, 'view') x;
  PERFORM set_config('authz.user_id', '', true);
  RETURN v;
END $$;
SQL
# $1 = label, $2 = the change: then each user's rows through the filter must be what authz.list gives
kchange() {
  KPSQL -c "$2" >/dev/null || { bad "$1" "the change failed"; return; }
  local diff="" ty tbl where
  while IFS='|' read -r ty tbl where; do
    diff+=$(KPSQL -c "SELECT string_agg('$ty, user ' || u.id || ': ' || ARRAY(SELECT x.id::text FROM $tbl x WHERE $where ORDER BY 1)::text
                        || ' through the filter, ' || public.klisted(u.id::text, '$ty')::text || ' listed', '; ') FROM k.users u
                      WHERE ARRAY(SELECT x.id::text FROM $tbl x WHERE $where ORDER BY 1) IS DISTINCT FROM public.klisted(u.id::text, '$ty')")
  done < "$T/filters"
  [ -z "$diff" ] && ok "$1: the index holds what authz.list gives" || bad "$1" "$diff"
}
kchange "keyed by inheritance through two types, a type's where and a deny, applied" "SELECT 1"
check_k() { local got; got=$(KPSQL -c "$2" 2>&1); [ "$got" = t ] && ok "$1" || bad "$1" "$got"; }
check_k "... a space's view inherits from the pages and spaces above it, through both types" \
  "SELECT array_agg(source ORDER BY source) = '{page#view:10,page#view:20,space#view:1,space#view:2,space#view:3}'
   FROM authz_sync.inherits WHERE key = 'space#view:3'"
check_k "... a note's readers, under the deny, are copied in: they name no key that inherits" \
  "SELECT NOT EXISTS (SELECT 1 FROM authz_sync.note__readers WHERE key LIKE 'space#%' OR key LIKE 'page#%')"
kchange "a page shared with a user: one row of what it gives itself" \
  "INSERT INTO authz.shares (object_type, object_id, relation, subject_type, subject_id) VALUES ('page', '10', 'viewer', 'user', '2')"
check_k "... page 10 gives view to user 2" "SELECT EXISTS (SELECT 1 FROM authz_sync.given WHERE source = 'page#view:10' AND key = 'user:2')"
kchange "a space moved to another page" "UPDATE k.spaces SET home_id = 10 WHERE id = 3"
kchange "a space hidden (its type's where)" "UPDATE k.spaces SET hidden = true WHERE id = 2"
kchange "... and shown again" "UPDATE k.spaces SET hidden = false WHERE id = 2"
kchange "a user muted from a note" "INSERT INTO k.mutes VALUES (2, 3)"
kchange "a note moved to another space" "UPDATE k.notes SET space_id = 1 WHERE id = 1"
kchange "a page's owner changed" "UPDATE k.pages SET owner_id = 3 WHERE id = 20"
check_k "authz.sync_verify(): the keyed index matches a rebuild" "SELECT authz.sync_verify()"
# the runtime's other answers about the same forms, as for the forms above
KPSQL >/dev/null <<'SQL' || exit 1
CREATE FUNCTION public.forms_api() RETURNS SETOF text LANGUAGE plpgsql AS $$
DECLARE t record; u text; o text; listed text[]; yes boolean; page text[]; pages text[]; after text;
BEGIN
  FOR t IN SELECT p.type, p.perm, ty.tbl FROM authz_int.perms p JOIN authz_int.types ty ON ty.name = p.type ORDER BY 1, 2 LOOP
    FOR u IN SELECT id::text FROM k.users ORDER BY id LOOP
      PERFORM set_config('authz.user_id', u, true);
      PERFORM set_config('authz.principal_type', '', true);
      SELECT coalesce(array_agg(x), '{}') INTO listed FROM authz.list(t.type, t.perm) x;
      -- (and two at a time, after the last one given: the same rows)
      pages := '{}'; after := NULL;
      LOOP
        SELECT coalesce(array_agg(x), '{}') INTO page FROM authz.list(t.type, t.perm, after, 2) x;
        EXIT WHEN cardinality(page) = 0;
        pages := pages || page; after := page[cardinality(page)];
      END LOOP;
      IF (SELECT array_agg(x ORDER BY x) FROM unnest(pages) x) IS DISTINCT FROM (SELECT array_agg(x ORDER BY x) FROM unnest(listed) x) THEN
        RETURN NEXT format('list, two at a time: %s %s, user %s', t.type, t.perm, u);
      END IF;
      IF (SELECT array_agg(x ORDER BY x) FROM authz.list(t.type, t.perm, '0', NULL) x)
         IS DISTINCT FROM (SELECT array_agg(x ORDER BY x) FROM unnest(listed) x) THEN
        RETURN NEXT format('list, after 0: %s %s, user %s', t.type, t.perm, u);
      END IF;
      FOR o IN EXECUTE format('SELECT id::text FROM %s ORDER BY id', t.tbl) LOOP
        yes := o = ANY (listed);
        IF authz.can(t.type, o, t.perm) IS DISTINCT FROM yes THEN RETURN NEXT format('can: %s %s %s, user %s', t.type, o, t.perm, u); END IF;
        IF (t.perm = ANY (authz.perms(t.type, o))) IS DISTINCT FROM yes THEN RETURN NEXT format('perms: %s %s %s, user %s', t.type, o, t.perm, u); END IF;
        IF EXISTS (SELECT 1 FROM authz.who(t.type, o, t.perm) w WHERE w = u) IS DISTINCT FROM yes THEN
          RETURN NEXT format('who: %s %s %s, user %s', t.type, o, t.perm, u);
        END IF;
        IF ((SELECT e FROM authz.explain(t.type, o, t.perm, u) e LIMIT 1) LIKE 'yes %') IS DISTINCT FROM yes THEN
          RETURN NEXT format('explain: %s %s %s, user %s', t.type, o, t.perm, u);
        END IF;
      END LOOP;
    END LOOP;
  END LOOP;
  PERFORM set_config('authz.user_id', '', true);
END $$;
SQL
api=$(KPSQL -c "SELECT string_agg(x, '; ') FROM public.forms_api() x")
[ -z "$api" ] && ok "... and authz.list two at a time, authz.can, authz.perms, authz.who and authz.explain answer as authz.list does, keyed by inheritance" ||
  bad "the runtime's other answers, keyed" "$api"
dropdb --force "$KEYED"

echo "-- remove, and a policy without sync"
apply "$DOCS"
check "a policy without sync lines: applying it drops the index and its functions" \
  "SELECT to_regnamespace('authz_sync') IS NULL AND to_regprocedure('authz.sync_tick()') IS NULL"
apply "$SYNCED"
CLI remove --yes >/dev/null 2>&1 || bad "remove"
check "rowstile remove drops the index" "SELECT to_regnamespace('authz_sync') IS NULL"

echo "sync: $fails failure(s)"
exit $((fails > 0))
