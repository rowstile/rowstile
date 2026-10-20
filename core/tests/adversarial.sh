#!/bin/bash
# adversarial.sh: the app role trying every way around the policy (docs/threat-model.md).
#   PGHOST=... PGUSER=postgres tests/adversarial.sh [database]
# The attacker logs in as its own role, a member of app_user (so it can't RESET ROLE its way out),
# signs in as carol (who may view Company but not Secrets, Keys or confidential files) with authz.act_as(),
# and tries to read, change, share or learn about what it may not. Each attempt is one transaction, since a
# sign-in lasts one. Identity itself (choosing another user, widening scopes) is tests/identity.sh's and
# tests/sessions.sh's.
set -u
cd "$(dirname "$0")/.."
DB=${1:-authz_adversarial}
ATTACKER=authz_attacker
dropdb --if-exists "$DB" 2>/dev/null; createdb "$DB" || exit 1
fails=0
PSQL() { psql -X -q -At -v ON_ERROR_STOP=1 -d "$DB" "$@"; }
# signs in as user $1 (empty: nobody), printing nothing
sign() { if [ -n "$1" ]; then echo "DO \$\$ BEGIN PERFORM authz.act_as('user', '$1'); END \$\$"; else echo "DO \$\$ BEGIN PERFORM authz.act_as(NULL, NULL); END \$\$"; fi; }
# as the attacker, in one transaction signed in as $AS (default carol); prints the last line of output (or of the error)
as() { psql -X -q -At -1 -U "$ATTACKER" -d "$DB" -v VERBOSITY=sqlstate -c "$(sign "${AS-3}")" "$@" 2>&1 | tail -n 1; }
# the same without the transaction and the sign-in, for attempts that span transactions
bare() { psql -X -q -At -U "$ATTACKER" -d "$DB" -v VERBOSITY=sqlstate "$@" 2>&1 | tail -n 1; }
. tests/words.sh
expect() {   # $1 label, $2 expected output (for an error, "SQLSTATE: the message's words"), rest: psql arguments
  local label=$1 want=$2; shift 2
  local got; got=$(error_of "$(psql -X -q -At -1 -U "$ATTACKER" -d "$DB" -v VERBOSITY=verbose -c "$(sign "${AS-3}")" "$@" 2>&1)")
  if agrees "$label" "$want" "$got"; then echo "ok    $label"; else echo "FAIL  $label: expected '$want', got '$got'"; fails=$((fails + 1)); fi
}

python3 compile_policy.py example/docs.authz > /tmp/authz_adversarial.sql || exit 1
PGOPTIONS="-c client_min_messages=error" psql -X -q -v ON_ERROR_STOP=1 -d "$DB" -f example/app_schema.sql >/dev/null &&
PGOPTIONS="-c client_min_messages=error" psql -X -q -v ON_ERROR_STOP=1 -d "$DB" -f /tmp/authz_adversarial.sql >/dev/null || exit 1
PSQL -c "SET ROLE app_user; SET authz.user_id = 5; SELECT authz.share('folder', 1, 'viewer', 'org', 1, 'member')" >/dev/null
psql -X -q -d postgres -c "DROP ROLE IF EXISTS $ATTACKER" -c "CREATE ROLE $ATTACKER LOGIN IN ROLE app_user" >/dev/null 2>&1
visible=$(as -c "SELECT count(*) FROM app.files")
erin=$(AS=5 as -c "SELECT count(*) FROM app.files")
all=$(PSQL -c "SELECT count(*) FROM app.files")
[ "$visible" -gt 0 ] && [ "$visible" -lt "$all" ] && echo "ok    carol sees $visible of $all files" || { echo "FAIL  setup: $visible of $all"; fails=$((fails + 1)); }

echo "-- reading what the policy hides"
expect "a hidden file by id" "0" -c "SELECT count(*) FROM app.files WHERE id = 12"
expect "a confidential file" "0" -c "SELECT count(*) FROM app.files WHERE id = 14"
n=$(psql -X -q -At -1 -U "$ATTACKER" -d "$DB" -c "$(sign 3)" -c "\\copy app.files TO STDOUT" 2>&1 | wc -l)
[ "$n" = "$visible" ] && echo "ok    COPY returns only visible rows" || { echo "FAIL  COPY returned $n rows"; fails=$((fails + 1)); }
got=$(psql -X -q -At -1 -U "$ATTACKER" -d "$DB" -c "$(sign 3)" -c "\\copy app.files (name) TO STDOUT" 2>&1)
case "$got" in *prod-keys*|*salaries*) echo "FAIL  COPY showed a hidden name"; fails=$((fails + 1));; *) echo "ok    ...and no hidden names";; esac
# a function in WHERE that prints what it sees: row-level security runs first, so it sees visible rows only
got=$(psql -X -q -At -1 -U "$ATTACKER" -d "$DB" -c "$(sign 3)" \
  -c "CREATE FUNCTION pg_temp.leak(text) RETURNS boolean LANGUAGE plpgsql COST 0.0000001 AS \$\$ BEGIN RAISE NOTICE 'saw %', \$1; RETURN false; END \$\$" \
  -c "SELECT * FROM app.files WHERE pg_temp.leak(name)" \
  -c "SELECT * FROM app.folders WHERE pg_temp.leak(name)" 2>&1)
case "$got" in *prod-keys*|*salaries*|*Secrets*|*Keys*) echo "FAIL  a cheap leaky function saw hidden rows: $got"; fails=$((fails + 1));;
  *saw*) echo "ok    a cheap leaky function in WHERE sees only visible rows";;
  *) echo "FAIL  leaky function test didn't run: $got"; fails=$((fails + 1));; esac
expect "table statistics of governed tables are hidden" "0" \
  -c "SELECT count(*) FROM pg_stats WHERE schemaname = 'app' AND tablename IN ('files', 'folders')"
expect "row_security = off is refused, not obeyed" "42501: query would be affected by row-level security policy for table \"files\"" -c "SET row_security = off" -c "SELECT count(*) FROM app.files"
expect "a prepared statement follows the signed-in user" "$erin" \
  -c "PREPARE q AS SELECT count(*) FROM app.files" -c "EXECUTE q" -c "EXECUTE q" -c "EXECUTE q" -c "EXECUTE q" -c "EXECUTE q" \
  -c "EXECUTE q" -c "$(sign 5)" -c "EXECUTE q"
expect "...and signed out, nothing" "0" -c "PREPARE q AS SELECT count(*) FROM app.files" -c "EXECUTE q" -c "$(sign '')" \
  -c "EXECUTE q"
got=$(bare -c "BEGIN" -c "$(sign 5)" -c "COMMIT" -c "SELECT count(*) FROM app.files")
[ "$got" = "ERROR:  28000" ] && echo "ok    a transaction's sign-in ends with it: after it, nobody is signed in (an error, not rows)" ||
  { echo "FAIL  a transaction's sign-in ends with it: got '$got'"; fails=$((fails + 1)); }

echo "-- choosing another user"
expect "setting authz.user_id after signing in is refused" "28000: who is signed in was changed after signing in" -c "SET LOCAL authz.user_id = 1" -c "SELECT count(*) FROM app.files"
expect "...and so is setting it instead of signing in" "28000: authz.user_id was set directly, so it is not believed" -c "$(sign '')" -c "SELECT set_config('authz.session', '', true)" \
  -c "SET LOCAL authz.user_id = 1" -c "SELECT count(*) FROM app.files"
expect "sharing as a user chosen by a setting" "28000: who is signed in was changed after signing in" -c "SET LOCAL authz.user_id = 5" \
  -c "SELECT authz.share('folder', 5, 'viewer', 'user', 3)"
expect "asking can() as a user chosen by a setting" "28000: who is signed in was changed after signing in" -c "SET LOCAL authz.user_id = 5" -c "SELECT authz.can('folder', 5, 'view')"

echo "-- rowstile's own tables and functions"
expect "internal views" "42501: permission denied for schema authz_int" -c "SELECT count(*) FROM authz_int.\"folder__view\""
expect "the closure tables" "42501: permission denied for schema authz_int" -c "SELECT count(*) FROM authz_int.\"folder__parent__tree\""
expect "the shares table" "42501: permission denied for table shares" -c "SELECT count(*) FROM authz.shares"
expect "writing a share directly" "42501: permission denied for table shares" \
  -c "INSERT INTO authz.shares (object_type, object_id, relation, subject_type, subject_id) VALUES ('folder', '5', 'viewer', 'user', '3')"
expect "the audit trail" "42501: permission denied for table audit" -c "SELECT count(*) FROM authz.audit"
expect "the change feed" "42501: permission denied for table changes" -c "SELECT count(*) FROM authz.changes"
expect "the lock rows" "42501: permission denied for schema authz_int" -c "UPDATE authz_int.locks SET n = 0"
expect "a closure's refresh function" "42501: permission denied for schema authz_int" -c "SELECT authz_int.\"folder__parent__tree_rebuild\"()"
expect "announcing fake changes" "42501: permission denied for schema authz_int" -c "SELECT authz_int.changed('folder', ARRAY['1'], 'x')"
expect "the public views return only carol's own ids" "0" \
  -c "SELECT count(*) FROM authz_gen.\"folder__view\" WHERE id IN (5, 6)"

echo "-- the catalog: every function, table and schema rowstile made, against the rules (tests/catalog.sql)"
# $1 database, $2 compiled policy, $3 app role: prints what breaks a rule
catalog() {
  local api; api=$(awk '/^GRANT EXECUTE ON FUNCTION$/{f=1; next} f && /^  TO /{f=0} f' "$2" | sed 's/^ *//; s/,$//' | paste -sd'|')
  [ -n "$api" ] || { echo "no GRANT EXECUTE list in $2"; return; }
  psql -X -q -At -d "$1" -v role="$3" -v api="$api" -f tests/catalog.sql 2>&1
}
got=$(catalog "$DB" /tmp/authz_adversarial.sql app_user)
[ -z "$got" ] &&
  echo "ok    docs: definer functions set their search_path; the app role executes the API and nothing else; no grants to PUBLIC or others; none parallel safe" ||
  { echo "FAIL  the catalog: $got"; fails=$((fails + 1)); }
for p in "multi tests/multi_schema.sql tests/multi.authz app_user" "alt tests/alt_schema.sql tests/alt.authz app_user"          "composite tests/composite_schema.sql tests/composite.authz app_user"          "patterns tests/patterns_schema.sql tests/patterns.authz cb_app"          "cross tests/cross_schema.sql tests/cross.authz app_user"; do
  set -- $p; C="${DB}_catalog"
  dropdb --if-exists "$C" 2>/dev/null; createdb "$C" || exit 1
  python3 compile_policy.py "$3" > /tmp/authz_adversarial_catalog.sql &&
  PGOPTIONS="-c client_min_messages=error" psql -X -q -v ON_ERROR_STOP=1 -d "$C" -f "$2" -f /tmp/authz_adversarial_catalog.sql >/dev/null ||
    { echo "FAIL  applying $3"; fails=$((fails + 1)); continue; }
  got=$(catalog "$C" /tmp/authz_adversarial_catalog.sql "$4"); dropdb "$C"
  [ -z "$got" ] && echo "ok    ... and $1" || { echo "FAIL  the catalog of $1: $got"; fails=$((fails + 1)); }
done

echo "-- a table keyed by several columns (tests/composite.authz): the rule on a column holds there too"
C="${DB}_composite"
dropdb --if-exists "$C" 2>/dev/null; createdb "$C" || exit 1
python3 compile_policy.py tests/composite.authz > /tmp/authz_adversarial_composite.sql &&
PGOPTIONS="-c client_min_messages=error" psql -X -q -v ON_ERROR_STOP=1 -d "$C" -f tests/composite_schema.sql \
  -f /tmp/authz_adversarial_composite.sql -c "INSERT INTO cx.users (id) VALUES (1), (2)" -c "INSERT INTO cx.orgs VALUES (1)" \
  -c "INSERT INTO cx.folders (org_id, id, owner_id) VALUES (1, 1, 1), (1, 2, 2)" >/dev/null || exit 1
# alice owns folder (1,1), not (1,2): she may change her folder, not move it under bob's
got=$(error_of "$(psql -X -q -At -1 -U "$ATTACKER" -d "$C" -v VERBOSITY=verbose -c "$(sign 1)" \
  -c "UPDATE cx.folders SET parent_type = 'folder', parent_id = 2 WHERE org_id = 1 AND id = 1" 2>&1)")
agrees "composite" "42501: changing parent_type, parent_id of cx.folders (1,1) needs: parent.edit or {parent_id is null}" "$got" &&
  echo "ok    alice can't move her folder under one she may not edit: the refusal names the row by its key" ||
  { echo "FAIL  the rule on a composite key's column: $got"; fails=$((fails + 1)); }
dropdb "$C"

echo "-- a deny split from what a permission inherits (tests/alt.authz): sharing what feeds the part before it"
C="${DB}_alt"
dropdb --if-exists "$C" 2>/dev/null; createdb "$C" || exit 1
python3 compile_policy.py tests/alt.authz > /tmp/authz_adversarial_alt.sql &&
PGOPTIONS="-c client_min_messages=error" psql -X -q -v ON_ERROR_STOP=1 -d "$C" -f tests/alt_schema.sql \
  -f /tmp/authz_adversarial_alt.sql -c "INSERT INTO alt.users (id) VALUES (1), (2), (3)" \
  -c "INSERT INTO alt.docs (doc_no, owner_id) VALUES (1, 1)" >/dev/null || exit 1
# user 1 owns doc 1: she may share it (share = owner) and view it. view is (owner or reader ...) and not hidden,
# so sharing reader gives view, and needs it
alt_as_1() { error_of "$(psql -X -q -At -1 -U "$ATTACKER" -d "$C" -v VERBOSITY=verbose -c "$(sign 1)" "$@" 2>&1)"; }
got=$(alt_as_1 -c "SELECT authz.share('doc', '1', 'reader', 'user', '2')" -c "SELECT 'shared'")
agrees "alt" "shared" "$got" && echo "ok    the owner of a doc may share reader on it, as she may view it" ||
  { echo "FAIL  the owner sharing reader: $got"; fails=$((fails + 1)); }
# banned (sharing banned feeds only the deny, so it needs share alone), she may no longer view it, nor give it
got=$(alt_as_1 -c "SELECT authz.share('doc', '1', 'banned', 'user', '1')" -c "SELECT authz.can('doc', '1', 'view')")
agrees "alt" "f" "$got" && echo "ok    ... and once she bans herself from it she may not view it" ||
  { echo "FAIL  the owner banned: $got"; fails=$((fails + 1)); }
got=$(alt_as_1 -c "SELECT authz.share('doc', '1', 'reader', 'user', '3')")
agrees "alt" "42501: you cannot grant doc.reader on doc 1: you do not hold view" "$got" &&
  echo "ok    ... nor share reader: it feeds view before the deny, which she no longer holds" ||
  { echo "FAIL  a banned owner sharing reader: $got"; fails=$((fails + 1)); }
dropdb "$C"

echo "-- grants the policy doesn't give, and schemas on the search path others may create in"
C="${DB}_grants"
CP() { psql -X -q -At -v ON_ERROR_STOP=1 -d "$C" "$@"; }
apply_c() { PGOPTIONS="-c client_min_messages=error" psql -X -q -v ON_ERROR_STOP=1 -v VERBOSITY=verbose -d "$C" -f /tmp/authz_adversarial.sql 2>&1 >/dev/null; }
lint_c() { CP -c "SELECT count(*) FROM authz.lint() WHERE severity = 'error' AND object = '$1'"; }
dropdb --if-exists "$C" 2>/dev/null; createdb "$C" || exit 1
PGOPTIONS="-c client_min_messages=error" CP -f example/app_schema.sql >/dev/null || exit 1
# a common migration setup: the owner's new tables, sequences, functions and schemas come with grants to the app role
CP -c "ALTER DEFAULT PRIVILEGES GRANT ALL ON TABLES TO app_user" -c "ALTER DEFAULT PRIVILEGES GRANT ALL ON SEQUENCES TO app_user" \
   -c "ALTER DEFAULT PRIVILEGES GRANT ALL ON FUNCTIONS TO app_user" -c "ALTER DEFAULT PRIVILEGES GRANT ALL ON SCHEMAS TO app_user" >/dev/null
out=$(apply_c) || { echo "FAIL  applying under the owner's default privileges: $out"; fails=$((fails + 1)); }
got=$(catalog "$C" /tmp/authz_adversarial.sql app_user)
[ -z "$got" ] && echo "ok    the owner's default privileges: apply leaves the app role only what the policy gives" ||
  { echo "FAIL  default privileges survive apply ($(echo "$got" | wc -l) lines): $(echo "$got" | head -n 3 | paste -sd';')"; fails=$((fails + 1)); }
CP -c "ALTER DEFAULT PRIVILEGES REVOKE ALL ON TABLES FROM app_user" -c "ALTER DEFAULT PRIVILEGES REVOKE ALL ON SEQUENCES FROM app_user" \
   -c "ALTER DEFAULT PRIVILEGES REVOKE ALL ON FUNCTIONS FROM app_user" -c "ALTER DEFAULT PRIVILEGES REVOKE ALL ON SCHEMAS FROM app_user" >/dev/null
CP -c "GRANT SELECT ON authz.shares TO app_user" -c "GRANT EXECUTE ON FUNCTION authz.trim_audit(interval) TO app_user" >/dev/null
[ "$(lint_c authz.shares)" = 1 ] && [ "$(lint_c 'authz.trim_audit(interval)')" = 1 ] &&
  echo "ok    lint reports a grant on rowstile's objects made after apply" || { echo "FAIL  lint misses later grants"; fails=$((fails + 1)); }
out=$(apply_c); got=$(catalog "$C" /tmp/authz_adversarial.sql app_user)
[ -z "$got" ] && echo "ok    ... and the next apply takes it back" || { echo "FAIL  a later grant survives apply: $got $out"; fails=$((fails + 1)); }
# a schema on the search path the app role may create in: a function there could take the place of a built-in
# one in the functions that run as the owner
CP -c "GRANT CREATE ON SCHEMA public TO app_user" >/dev/null
[ "$(lint_c public)" = 1 ] && echo "ok    lint reports a schema on the functions' search path the app role may create in" ||
  { echo "FAIL  lint misses CREATE on public"; fails=$((fails + 1)); }
out=$(apply_c); rc=$?
case "$out" in *AZ612*) [ $rc -ne 0 ] && echo "ok    ... and apply refuses it" || { echo "FAIL  apply went on: $out"; fails=$((fails + 1)); };;
  *) echo "FAIL  apply with CREATE on public for the app role: $out"; fails=$((fails + 1));; esac
CP -c "REVOKE CREATE ON SCHEMA public FROM app_user" -c "CREATE SCHEMA app_ext" -c "GRANT USAGE, CREATE ON SCHEMA app_ext TO app_user" >/dev/null
out=$(PGOPTIONS="-c client_min_messages=error -c search_path=app_ext,public" psql -X -q -v ON_ERROR_STOP=1 -d "$C" -f /tmp/authz_adversarial.sql 2>&1 >/dev/null)
case "$out" in *AZ612*) echo "ok    ... whichever schema of the applying session's path it is";;
  *) echo "FAIL  apply with app_ext on the path: $out"; fails=$((fails + 1));; esac
out=$(apply_c) && echo "ok    ... and applies once the schema is closed or off the path" || { echo "FAIL  apply after the revoke: $out"; fails=$((fails + 1)); }
dropdb "$C"

echo "-- turning the policy off"
expect "disabling row-level security" "42501: must be owner of table files" -c "ALTER TABLE app.files DISABLE ROW LEVEL SECURITY"
expect "dropping a policy" "42501: must be owner of relation files" -c "DROP POLICY authz_select ON app.files"
expect "adding a permissive policy" "42501: must be owner of table files" -c "CREATE POLICY mine ON app.files FOR SELECT USING (true)"
expect "dropping a closure trigger" "42501: must be owner of relation folders" -c "DROP TRIGGER \"authz_folder__parent__tree_upd\" ON app.folders"
expect "replacing a generated function" "42501: permission denied for schema authz" \
  -c "CREATE OR REPLACE FUNCTION authz.can(p_type text, p_id text, p_perm text) RETURNS boolean LANGUAGE sql AS 'SELECT true'"

echo "-- changing what the policy protects"
expect "updating a hidden row changes nothing" "UPDATE 0" -c "\\set QUIET off" -c "UPDATE app.files SET name = 'x' WHERE id = 12"
expect "deleting a hidden row changes nothing" "DELETE 0" -c "\\set QUIET off" -c "DELETE FROM app.files WHERE id = 12"
expect "an upsert onto a hidden row" "42501: permission denied: user 3 may not insert this row into app.files" \
  -c "INSERT INTO app.files (id, folder_id, owner_id, name) VALUES (12, 4, 3, 'x') ON CONFLICT (id) DO UPDATE SET name = 'pwned'"
[ "$(PSQL -c "SELECT name FROM app.files WHERE id = 12")" = "prod-keys.txt" ] && echo "ok    the hidden file is untouched" ||
  { echo "FAIL  the hidden file changed"; fails=$((fails + 1)); }
expect "a file claiming someone else as owner" "42501: permission denied: user 3 may not insert this row into app.files" \
  -c "INSERT INTO app.files (folder_id, owner_id, name) VALUES (4, 1, 'x')"
AS=2 expect "bob (may edit, not share) can't take ownership" "42501: changing id, owner_id, confidential of app.files 11 needs: share" -c "UPDATE app.files SET owner_id = 2 WHERE id = 11"
AS=2 expect "...or move a file where he can't edit" "42501: changing folder_id of app.files 11 needs: folder.edit" -c "UPDATE app.files SET folder_id = 2 WHERE id = 11"
# both at once: the rule on the row before the change speaks first, though `folder_id after` sorts first by its column
AS=2 expect "...and both at once: the rule on the row before the change says why" "42501: changing id, owner_id, confidential of app.files 11 needs: share" -c "UPDATE app.files SET folder_id = 2, owner_id = 2 WHERE id = 11"
AS=1 expect "alice can't move her folder under a folder she may not edit" "42501: changing parent_id of app.folders 4 needs: parent.edit or ({parent_id is null} and share)" -c "UPDATE app.folders SET parent_id = 20 WHERE id = 4"
AS=2 expect "bob (may edit Design docs, not share it) can't cut it off from the folders above" "42501: changing id, owner_id, org_id, inherit of app.folders 4 needs: share" \
  -c "UPDATE app.folders SET inherit = false WHERE id = 4"

echo "-- sharing and asking"
expect "sharing a hidden file with herself" "42501: you cannot share file 12" -c "SELECT authz.share('file', 12, 'viewer', 'user', 3)"
expect "sharing what she may only view" "42501: you cannot share file 11" -c "SELECT authz.share('file', 11, 'viewer', 'user', 4)"
AS=1 expect "sharing a relation the policy doesn't share" "P0001: the policy does not allow sharing file.owner with user" -c "SELECT authz.share('file', 11, 'owner', 'user', 3)"
AS=1 expect "... or unsharing one" "42501: you cannot unshare owner on file 11" -c "SELECT authz.unshare('file', 11, 'owner', 'user', 3)"
expect "breaking the glass (as she may on Acme's folders) into a relation the policy doesn't share with users" \
  "P0001: the policy does not allow sharing folder.owner with a user" -c "SELECT authz.break_glass('folder', '6', 'owner', 'curious', '1 hour')"
# every way of asking to share a hidden object (file 12) answers as for a missing one: message and context
said() { psql -X -q -At -1 -U "$ATTACKER" -d "$DB" -c "$(sign 3)" -c "$1" 2>&1 | sed "s/$2/<id>/g"; }
for call in "share('file', ID, 'viewer', 'user', '4')" "share('file', ID, 'viewer', 'user', '424242')" \
            "share('file', ID, 'owner', 'user', '4')" "create_link('file', ID, 'viewer', NULL)" \
            "list_links('file', ID)" "revoke_link('file', ID, 'abc')" \
            "request_access('file', ID, 'viewer', 'curious') IS NOT NULL"; do
  hidden=$(said "SELECT authz.${call/ID/12}" "file 12"); missing=$(said "SELECT authz.${call/ID/999999}" "file 999999")
  [ "$hidden" = "$missing" ] && [ -n "$hidden" ] && echo "ok    authz.${call/ID/12} answers as for a missing file" ||
    { echo "FAIL  authz.$call tells hidden from missing: '$hidden' / '$missing'"; fails=$((fails + 1)); }
done
expect "listing the shares of a hidden object" "42501: you cannot see the shares of folder 5" -c "SELECT count(*) FROM authz.list_shares('folder', '5')"
expect "...is refused as for a missing one" "42501: you cannot see the shares of folder 999999" -c "SELECT count(*) FROM authz.list_shares('folder', '999999')"
expect "listing the links of a hidden object" "42501: you cannot see the links of folder 5" -c "SELECT count(*) FROM authz.list_links('folder', '5')"
expect "...is refused as for a missing one" "42501: you cannot see the links of folder 999999" -c "SELECT count(*) FROM authz.list_links('folder', '999999')"
expect "turning off a link of a hidden object" "42501: you cannot turn off the links of folder 5" -c "SELECT authz.revoke_link('folder', '5', 'abc')"
for cursor in "'12abc'" "''" "'99999999999999999999999'"; do
  expect "a page cursor that isn't an id ($cursor) is the caller's mistake, not a failed query" "22023: the page cursor $cursor is not a file id" \
    -c "SELECT count(*) FROM authz.list('file', 'view', $cursor, 5)"
done
expect "... and so is a negative page size" "22023: the page size must not be negative (got -1)" -c "SELECT count(*) FROM authz.list('file', 'view', NULL, -1)"
expect "... while a page of none is no mistake: no row" "0" -c "SELECT count(*) FROM authz.list('file', 'view', NULL, 0)"
expect "who may see a hidden object" "42501: you cannot see who has access to folder 5" -c "SELECT count(*) FROM authz.who('folder', '5', 'view')"
expect "...is refused as for a missing one" "42501: you cannot see who has access to folder 999999" -c "SELECT count(*) FROM authz.who('folder', '999999', 'view')"
expect "asking why for someone else" "42501: you cannot inspect access to file 11" -c "SELECT authz.explain('file', '11', 'view', '2')"
# explaining never walks into what carol can't see, whatever else she holds there (break_glass on every Acme folder),
# whether she asks for herself or names her own id (as written, or as another text of it)
for call in "explain('folder', 'ID', 'edit')" "explain('folder', 'ID', 'edit', '3')" "explain('folder', 'ID', 'edit', '03')"; do
  hidden=$(said "SELECT authz.${call/ID/6}" "folder 6"); missing=$(said "SELECT authz.${call/ID/999999}" "folder 999999")
  [ "$hidden" = "$missing" ] && [ "$hidden" = "no   you have no access to <id>" ] &&
    echo "ok    authz.${call/ID/6}: explaining a folder she can't see (but may break the glass on) reads as a missing one" ||
    { echo "FAIL  authz.$call tells hidden folder 6 from a missing one: '$hidden' / '$missing'"; fails=$((fails + 1)); }
  got=$(said "SELECT authz.${call/ID/21}" "@")
  case "$got" in *"folder 20"*|*"folder 5"*) false;; *"parent is a folder you can't see"*) ;; *) false;; esac &&
    echo "ok    ... and the walk up from one she sees stops at a parent she can't see" ||
    { echo "FAIL  authz.${call/ID/21} walks past a hidden parent: $got"; fails=$((fails + 1)); }
done
# why she may view a file shared with her: her own share, never another user's (who made it, until when). Bob's,
# made by alice an hour before hers and ending tomorrow, is the older
PSQL -c "INSERT INTO authz.shares (object_type, object_id, relation, subject_type, subject_id, expires_at, created_by, created_at)
         VALUES ('file', '13', 'viewer', 'user', '2', now() + interval '1 day', '1', now() - interval '1 hour'),
                ('file', '13', 'viewer', 'user', '3', NULL, '5', now())" >/dev/null
expect "explaining her share on a file shows hers, not another user's" "yes  viewer: shared with you (by 5)" \
  -c "SELECT ltrim(l) FROM authz.explain('file', '13', 'view') l WHERE l LIKE '%shared with you%'"
PSQL -c "DELETE FROM authz.shares WHERE object_type = 'file' AND object_id = '13'" >/dev/null
hidden=$(said "INSERT INTO app.files (folder_id, owner_id, name) VALUES (6, 3, 'x')" "folder 6")
missing=$(said "INSERT INTO app.files (folder_id, owner_id, name) VALUES (999999, 3, 'x')" "folder 999999")
[ "$hidden" = "$missing" ] && case "$hidden" in *"permission denied: user 3 may not insert this row into app.files"*) true;; *) false;; esac &&
  case "$hidden" in *"no   you have no access to <id>"*) true;; *) false;; esac &&
  echo "ok    a write refused in a hidden folder explains as for a missing one" ||
  { echo "FAIL  the refusal tells hidden folder 6 from a missing one: '$hidden' / '$missing'"; fails=$((fails + 1)); }
expect "a hidden file and a missing one look the same to can()" "false|false" \
  -c "SELECT authz.can('file', 12, 'view') || '|' || authz.can('file', 999999, 'view')"
rid=$(as -c "SELECT authz.request_access('folder', 5, 'viewer', 'let me in')")
expect "approving her own request" "42501: you cannot decide your own request" -c "SELECT authz.decide_request($rid, true)"

echo "-- partitions and inheritance children, which row-level security on the table above doesn't cover"
PSQL -c "CREATE TABLE app.files_old () INHERITS (app.files)" -c "GRANT SELECT, INSERT, UPDATE, DELETE ON app.files_old TO app_user" \
     -c "INSERT INTO app.files_old (id, folder_id, owner_id, name) VALUES (9001, 5, 1, 'old-secret.txt')" >/dev/null
# (two errors: the app role may use it directly, and it lacks its table's row triggers; tests/children.sh)
[ "$(PSQL -c "SELECT count(*) FROM authz.lint() WHERE severity = 'error' AND object = 'app.files_old'")" = 2 ] &&
  echo "ok    lint reports a table made after apply that inherits from a governed one" ||
  { echo "FAIL  lint misses app.files_old"; fails=$((fails + 1)); }
# (applying makes rowstile's functions anew, and the statements the run measures go with the old ones: they are kept
# first; tests/coverage_functions.sh)
bash tests/coverage_functions.sh "$DB"
PGOPTIONS="-c client_min_messages=error" psql -X -q -v ON_ERROR_STOP=1 -d "$DB" -f /tmp/authz_adversarial.sql >/dev/null || exit 1
expect "reading it directly, once applied again" "0" -c "SELECT count(*) FROM app.files_old"
expect "... changing it directly" "0" -c "WITH u AS (UPDATE app.files_old SET name = 'mine' RETURNING 1) SELECT count(*) FROM u"
expect "... adding to it directly" "42501: new row violates row-level security policy for table \"files_old\"" -c "INSERT INTO app.files_old (id, folder_id, owner_id, name) VALUES (9002, 1, 3, 'x')"
expect "... while through the table above the policy still decides" "0" -c "SELECT count(*) FROM app.files WHERE id = 9001"
# a row stored there, in a folder bob may edit: written through the table above, where the table's own rule on a
# column has to be checked too (Postgres runs a table's row triggers for its own rows only)
PSQL -c "INSERT INTO app.files_old (id, folder_id, owner_id, name) VALUES (9003, 4, 1, 'old-design.md')" >/dev/null
AS=2 expect "bob renames a file stored there, through the table above" "1" \
  -c "WITH u AS (UPDATE app.files SET name = 'old-design-2.md' WHERE id = 9003 RETURNING 1) SELECT count(*) FROM u"
AS=2 expect "... and can't take its ownership (the rule on the column)" "42501: changing id, owner_id, confidential of app.files 9003 needs: share" -c "UPDATE app.files SET owner_id = 2 WHERE id = 9003"
[ "$(PSQL -c "SELECT count(*) FROM authz.lint() WHERE severity = 'error' AND object = 'app.files_old'")" = 0 ] &&
  echo "ok    ... and lint has nothing more to say about it" || { echo "FAIL  lint after apply"; fails=$((fails + 1)); }

psql -X -q -d postgres -c "DROP OWNED BY $ATTACKER" -d "$DB" >/dev/null 2>&1
dropdb "$DB"
psql -X -q -d postgres -c "DROP ROLE IF EXISTS $ATTACKER" >/dev/null
[ $fails -eq 0 ] && echo "adversarial: all passed" || { echo "adversarial: $fails failed"; exit 1; }
