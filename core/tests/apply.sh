#!/bin/bash
# apply.sh: what applying a policy with the rowstile command does to a database: no extension,
# no superuser needed, only-if-changed, included files, previews, tests, backup and restore, applying
# again after an upgrade, and removing.
#   PGHOST=... PGUSER=postgres tests/apply.sh
set -u
cd "$(dirname "$0")/.."
DB=authz_apply
fails=0
PSQL() { psql -X -q -At -v ON_ERROR_STOP=1 -d "$DB" "$@"; }
ok() { echo "ok    $1"; }
bad() { echo "FAIL  $1${2:+: $2}"; fails=$((fails + 1)); }
quiet() { PGOPTIONS="-c client_min_messages=error" psql -X -q -v ON_ERROR_STOP=1 "$@"; }
fresh() { dropdb --if-exists "$1" 2>/dev/null; createdb "$1" || exit 1; }
CLI() { python3 cli/rowstile_cli.py --db "dbname=$DB" "$@"; }
run() { out=$(CLI "$@" 2>&1); rc=$?; }
T=$(mktemp -d)
# the end-to-end scenario, with the tests at the bottom of the policy file
python3 compile_policy.py example/docs.authz --tests > "$T/docs_tests.sql" || exit 1
scenario() { psql -X -q -v ON_ERROR_STOP=1 -v docs_tests="$T/docs_tests.sql" -d "$DB" -f tests/scenario.sql; }

# (user, readable files, files it may view): what access looks like, to compare databases
access() {
  for u in $(psql -X -At -d "$1" -c "SELECT id FROM app.users ORDER BY id"); do
    psql -X -At -d "$1" -c "SELECT set_config('authz.user_id', '$u', false)" \
         -c "SELECT '$u', (SELECT count(*) FROM authz.list('file', 'view')), (SELECT count(*) FROM authz.list('folder', 'edit'))" \
         -c "SET ROLE app_user" -c "SELECT count(*) FROM app.files" | tail -n 2 | tr '\n' ' '
    echo
  done
}

echo "-- applying the example policy"
fresh "$DB"
quiet -d "$DB" -f example/app_schema.sql >/dev/null || exit 1
run apply example/docs.authz
[ "$out" = "example/docs.authz: applied" ] && ok "rowstile apply, on a database with no extension" || bad "apply" "$out"
[ "$(PSQL -c "SELECT count(*) FROM pg_extension WHERE extname <> 'plpgsql'")" = 0 ] &&
  ok "... which needs nothing installed but plpgsql" || bad "extensions" "$(PSQL -c "SELECT string_agg(extname, ',') FROM pg_extension")"
# a table never analyzed is planned as ten pages of rows (JIT then compiles reads of a few rows): applying
# analyzes the types' tables and its own that were never analyzed
unanalyzed() { PSQL -c "SELECT count(*) FROM pg_class c WHERE c.relkind = 'r' AND c.reltuples < 0
  AND (c.oid IN (SELECT to_regclass(tbl) FROM authz_int.types)
       OR c.relnamespace IN (SELECT oid FROM pg_namespace WHERE nspname IN ('authz', 'authz_int')))"; }
[ "$(unanalyzed)" = 0 ] && ok "... and leaves none of the tables the policy reads, nor of its own, never analyzed" ||
  bad "never analyzed after apply" "$(unanalyzed)"
run apply example/docs.authz; [ "$out" = "example/docs.authz: unchanged" ] && ok "... again: unchanged" || bad "apply unchanged" "$out"
cp example/docs.authz "$T/docs.authz"; echo "-- a comment" >> "$T/docs.authz"
run apply "$T/docs.authz"; [ "$out" = "$T/docs.authz: applied" ] && ok "... a changed text is applied" || bad "apply changed" "$out"
run apply "$T/docs.authz" --force; [ "$out" = "$T/docs.authz: applied" ] && ok "... and --force applies the same text again" || bad "apply --force" "$out"
PSQL -c "DROP POLICY authz_select ON app.files" >/dev/null
run apply "$T/docs.authz"
[ "$out" = "$T/docs.authz: applied" ] && [ "$(PSQL -c "SELECT count(*) FROM pg_policy WHERE polrelid = 'app.files'::regclass AND polname = 'authz_select'")" = 1 ] &&
  ok "... and so is the same text when something it made is gone" || bad "apply after a dropped policy" "$out"
PSQL -c "ALTER TABLE app.files DISABLE ROW LEVEL SECURITY" >/dev/null
run apply "$T/docs.authz"
[ "$out" = "$T/docs.authz: applied" ] && [ "$(PSQL -c "SELECT relrowsecurity FROM pg_class WHERE oid = 'app.files'::regclass")" = t ] &&
  ok "... or row-level security turned off on a table with rules" || bad "apply after RLS off" "$out"
PSQL -c "DROP TRIGGER authz_folder__linked_into_parent__tree_del ON app.folders" >/dev/null
run apply "$T/docs.authz"
[ "$out" = "$T/docs.authz: applied" ] && [ "$(PSQL -c "SELECT count(*) FROM pg_trigger WHERE tgname = 'authz_folder__linked_into_parent__tree_del'")" = 1 ] &&
  ok "... or a trigger it made on an app table dropped" || bad "apply after a dropped trigger" "$out"
PSQL -c "ALTER TABLE app.files DISABLE TRIGGER authz_file_forget_del" >/dev/null
run apply "$T/docs.authz"
[ "$out" = "$T/docs.authz: applied" ] && [ "$(PSQL -c "SELECT tgenabled FROM pg_trigger WHERE tgname = 'authz_file_forget_del'")" = O ] &&
  ok "... or disabled" || bad "apply after a disabled trigger" "$out"
# what lint says the next apply takes back, an apply of the same text has to take back
PSQL -c "GRANT SELECT ON authz.shares TO app_user" -c "GRANT EXECUTE ON FUNCTION authz.trim_audit(interval) TO PUBLIC" >/dev/null
run apply "$T/docs.authz"
case "$out" in *"took back 1 privileges on rowstile's schemas"*"$T/docs.authz: applied") true;; *) false;; esac &&
  [ "$(PSQL -c "SELECT has_table_privilege('app_user', 'authz.shares', 'SELECT'), has_function_privilege('public', 'authz.trim_audit(interval)', 'EXECUTE')")" = "f|f" ] &&
  ok "... or a privilege on rowstile's own schemas given since, which it takes back" || bad "apply after a grant" "$out"
PSQL -c "GRANT SELECT (subject_id) ON authz.shares TO app_user" >/dev/null
got=$(PSQL -c "SELECT object || '|' || problem FROM authz.lint() WHERE object LIKE 'authz.shares%'")
[ "$got" = "authz.shares (subject_id)|app_user holds SELECT on it, which the policy doesn't give (a default privilege of the owner, or a grant made since the last apply): the next apply takes it back, or REVOKE SELECT (subject_id) ON authz.shares FROM app_user CASCADE" ] &&
  ok "lint names a privilege on one column of rowstile's tables, and the REVOKE that takes it back" || bad "lint, a column's privilege" "$got"
run apply "$T/docs.authz"
case "$out" in *"took back 1 privileges on rowstile's schemas"*"$T/docs.authz: applied") true;; *) false;; esac &&
  [ "$(PSQL -c "SELECT has_column_privilege('app_user', 'authz.shares', 'subject_id', 'SELECT')")" = f ] &&
  ok "... and applying takes it back" || bad "apply after a column's grant" "$out"
# (tables made under one with rules since, partitions and tables that inherit: tests/children.sh)
run apply "$T/docs.authz"; [ "$out" = "$T/docs.authz: unchanged" ] && ok "... and then it is unchanged again" || bad "unchanged after repairs" "$out"
# the app's own views and functions may call the authz.* functions: applying replaces those in place
PSQL -c "CREATE VIEW app.my_files AS SELECT f.id, authz.can('file', f.id::text, 'edit') AS editable FROM app.files f" >/dev/null
run apply "$T/docs.authz" --force
[ "$out" = "$T/docs.authz: applied" ] && [ "$(PSQL -c "SET authz.user_id = '1'; SELECT count(*) > 0 FROM app.my_files WHERE editable")" = t ] &&
  ok "applying again keeps an app view that calls authz.can(), and the view works" || bad "apply with a view on authz.can()" "$out"
PSQL -c "CREATE FUNCTION authz.can(p_type text) RETURNS boolean LANGUAGE sql AS 'SELECT true'" \
     -c "CREATE VIEW app.old_view AS SELECT authz.can('file') AS x" >/dev/null
run apply "$T/docs.authz" --force
case "$out" in *"no longer makes a function that something in the database uses: authz.can(text) ("*"app.old_view"*"[AZ614]"*)
  ok "a function this policy doesn't make, with something that uses it: refused, both named";; *) bad "a stale function in use" "$out";; esac
PSQL -c "DROP VIEW app.old_view" >/dev/null
run apply "$T/docs.authz" --force
[ "$out" = "$T/docs.authz: applied" ] && [ "$(PSQL -c "SELECT to_regprocedure('authz.can(text)') IS NULL")" = t ] &&
  ok "... and once nothing uses it, applying drops it" || bad "apply after dropping the view" "$out"
PSQL -c "DROP VIEW app.my_files" >/dev/null
PSQL -c "UPDATE authz.policy_versions SET version = '0.0.1' WHERE id = (SELECT max(id) FROM authz.policy_versions)" >/dev/null
run apply "$T/docs.authz"; [ "$out" = "$T/docs.authz: applied" ] && ok "... and so is a policy another version of rowstile applied" || bad "apply after upgrade" "$out"
[ "$(PSQL -c "SELECT version FROM authz.policy_versions ORDER BY id DESC LIMIT 1")" = "$(python3 -c 'import authzlib; print(authzlib.BUILD)')" ] &&
  ok "the history records which version applied it" || bad "version in history"
# the other way round: a database a newer rowstile wrote is not put back to this version's work
PSQL -c "UPDATE authz.policy_versions SET version = '99.0.0' WHERE id = (SELECT max(id) FROM authz.policy_versions)" >/dev/null
run apply "$T/docs.authz"
case "$out" in *"last written by rowstile 99.0.0, which is newer than this command"*"[AZ616]"*"--downgrade"*) [ $rc -ne 0 ] &&
  ok "a policy a newer version applied is refused, naming both versions" || bad "apply over a newer version: rc" "$rc";;
  *) bad "apply over a newer version" "$out";; esac
[ "$(PSQL -c "SELECT version FROM authz.policy_versions ORDER BY id DESC LIMIT 1")" = 99.0.0 ] && ok "... and nothing is changed" || bad "the refused apply changed the history"
run apply "$T/docs.authz" --downgrade; [ "$out" = "$T/docs.authz: applied" ] && ok "... unless asked: --downgrade" || bad "apply --downgrade" "$out"
scenario > /tmp/authz_apply_scenario.log 2>&1
rc=$?; n=$(grep -c 'ok  ' /tmp/authz_apply_scenario.log)
[ $rc -eq 0 ] && ok "the end-to-end scenario passes ($n checks)" || bad "scenario" "$(grep 'FAIL\|ERROR' /tmp/authz_apply_scenario.log | head -3)"
nshares=$(PSQL -c "SELECT count(*) FROM authz.shares")
CLI reapply >/dev/null 2>&1; CLI reapply >/dev/null 2>&1
[ "$(PSQL -c "SELECT count(*) FROM authz.shares")" = "$nshares" ] && [ "$(PSQL -c "SELECT authz.verify()")" = t ] &&
  ok "applying again keeps the $nshares shares and the trees stay consistent" || bad "reapply"
# shares stored before every write was made canonical (as an earlier version could): two spellings of one
# share, and one alone
PSQL -c "ALTER TABLE authz.shares DISABLE TRIGGER authz_shares_canon" \
     -c "INSERT INTO authz.shares (object_type, object_id, relation, subject_type, subject_id, subject_relation) VALUES
           ('file', '012', 'viewer', 'user', '04', ''), ('file', '12', 'viewer', 'user', '004', ''), ('file', '0013', 'viewer', 'user', '03', '')" \
     -c "ALTER TABLE authz.shares ENABLE TRIGGER authz_shares_canon" >/dev/null
CLI reapply >/dev/null 2>&1
[ "$(PSQL -c "SELECT count(*) FILTER (WHERE object_id IN ('012', '0013') OR subject_id IN ('04', '004', '03')) || ' '
                     || count(*) FILTER (WHERE (object_id, subject_id) IN (('12', '4'), ('13', '3')))
              FROM authz.shares WHERE object_type = 'file' AND relation = 'viewer'")" = "0 2" ] &&
  ok "applying makes the ids of shares stored as written canonical, keeping one of two spellings" ||
  bad "canonical ids" "$(PSQL -c "SELECT string_agg(object_id || '>' || subject_id, ' ') FROM authz.shares WHERE object_type = 'file' AND relation = 'viewer'")"
# applying again warns of what the policy can't make safe: a foreign key that deletes rows of a governed table by
# cascade (which skips row-level security), and a table that lost its rules (its row-level security stays on)
PSQL -c "ALTER TABLE app.files ADD CONSTRAINT files_folder_cascade FOREIGN KEY (folder_id) REFERENCES app.folders ON DELETE CASCADE" >/dev/null
run apply "$T/docs.authz" --force
case "$out" in *"foreign key files_folder_cascade on app.files is ON DELETE CASCADE: deleting a row of app.folders also deletes rows of app.files, and cascades skip row-level security"*"$T/docs.authz: applied")
  ok "re-applying warns of a foreign key that deletes a governed table's rows by cascade";; *) bad "a cascading foreign key" "$out";; esac
PSQL -c "ALTER TABLE app.files DROP CONSTRAINT files_folder_cascade" >/dev/null
sed '/^rules app.files$/,/^$/d' "$T/docs.authz" > "$T/nofiles.authz"
run apply "$T/nofiles.authz"
case "$out" in *"app.files has no rules any more, and row-level security is still on, so the app role sees none of its rows"*"$T/nofiles.authz: applied")
  [ "$(PSQL -c "SELECT relrowsecurity FROM pg_class WHERE oid = 'app.files'::regclass")" = t ] &&
    ok "re-applying warns of a table that lost its rules, whose row-level security stays on" || bad "row-level security after the rules went";;
  *) bad "a table that lost its rules" "$out";; esac
# a policy for another app role: the role it named before keeps no row and none of rowstile's functions
psql -X -q -d postgres -c "DROP ROLE IF EXISTS authz_apply_web" -c "CREATE ROLE authz_apply_web" >/dev/null 2>&1
sed 's/^app role app_user$/app role authz_apply_web/' "$T/docs.authz" > "$T/web.authz"
run apply "$T/web.authz"
[ $rc -eq 0 ] && [ "$(PSQL -c "SET ROLE app_user" -c "SET authz.user_id = 1" -c "SELECT count(*) FROM app.files")" = 0 ] &&
  [ "$(PSQL -c "SELECT has_schema_privilege('app_user', 'authz', 'USAGE') OR has_schema_privilege('app_user', 'authz_gen', 'USAGE')")" = f ] &&
  ok "re-applying for another app role takes the old one's access away: no row, none of rowstile's functions" ||
  bad "the app role the policy no longer names" "$out"
# lint looks at the app role itself and at the roles it is a member of: row-level security doesn't hold for a role
# with BYPASSRLS, nor for one that inherits it (only a superuser may give BYPASSRLS; the role is this suite's own)
if [ -n "${PGSUPERUSER:-}" ]; then
  SU() { psql -X -q -U "$PGSUPERUSER" -d postgres "$@" >/dev/null 2>&1; }
  applint() { PSQL -c "SELECT severity || '|' || object || '|' || problem FROM authz.lint() WHERE object = 'authz_apply_web' ORDER BY problem"; }
  [ -z "$(applint)" ] && ok "lint finds nothing to say of an app role without BYPASSRLS" || bad "lint, the app role" "$(applint)"
  SU -c "DROP ROLE IF EXISTS authz_apply_bypass" -c "CREATE ROLE authz_apply_bypass NOLOGIN BYPASSRLS" \
    -c "GRANT authz_apply_bypass TO authz_apply_web"
  [ "$(applint)" = "error|authz_apply_web|is a member of authz_apply_bypass, which bypasses row-level security" ] &&
    ok "lint reports an app role that is a member of a role with BYPASSRLS: an error" || bad "lint, a member of a BYPASSRLS role" "$(applint)"
  SU -c "REVOKE authz_apply_bypass FROM authz_apply_web" -c "DROP ROLE authz_apply_bypass" -c "ALTER ROLE authz_apply_web BYPASSRLS"
  [ "$(applint)" = "error|authz_apply_web|is a superuser or has BYPASSRLS: row-level security does not apply to it at all" ] &&
    ok "... and one that has BYPASSRLS itself" || bad "lint, an app role with BYPASSRLS" "$(applint)"
  SU -c "ALTER ROLE authz_apply_web NOBYPASSRLS"
else
  echo "skip  lint on an app role with BYPASSRLS: only a superuser may give it (PGSUPERUSER)"
fi
run apply "$T/docs.authz"; [ $rc -eq 0 ] || bad "applying for app_user again" "$out"
psql -X -q -d postgres -c "DROP ROLE authz_apply_web" >/dev/null || bad "dropping the role the policy named for a while"
psql -X -q -d "$DB" -c "BEGIN" -c "LOCK app.files IN ACCESS SHARE MODE" -c "SELECT pg_sleep(20)" -c "COMMIT" >/dev/null 2>&1 &
sleep 1; t=$SECONDS
run apply "$T/docs.authz" --force
# (the holder outlasts apply's 10 s; once apply has given up, it lets go)
PSQL -c "SELECT pg_cancel_backend(pid) FROM pg_stat_activity WHERE datname = '$DB' AND query = 'SELECT pg_sleep(20)'" >/dev/null
case "$out" in *"lock timeout"*) [ $((SECONDS - t)) -lt 18 ] && [ $rc -eq 1 ] && ok "a table in use makes applying give up after 10 s instead of queueing everyone" ||
  bad "lock_timeout" "took $((SECONDS - t)) s, exit $rc";; *) bad "applying while a table is in use" "$out";; esac
wait
[ "$(PSQL -c "SELECT authz.verify()")" = t ] && ok "... and the policy in force is untouched" || bad "state after lock timeout"
[ "$(PSQL -c "SELECT count(*) FROM authz.policy_versions WHERE action = 'apply'")" -ge 6 ] &&
  ok "every apply is kept in authz.policy_versions" || bad "policy_versions"

echo "-- tests"
# the policy's test section expects the data as it is before the scenario, plus the two shares it makes first
TDB=${DB}_tests
fresh "$TDB"
quiet -d "$TDB" -f example/app_schema.sql >/dev/null || exit 1
TCLI() { python3 cli/rowstile_cli.py --db "dbname=$TDB" "$@"; }
TCLI apply example/docs.authz >/dev/null 2>&1
psql -X -q -d "$TDB" -c "SET ROLE app_user" -c "SET authz.user_id = 5" -c "SELECT authz.share('folder', 1, 'viewer', 'org', 1, 'member')" \
     -c "SELECT authz.share('file', 13, 'viewer', 'user', 4, '', now() + interval '1 day')" >/dev/null
out=$(TCLI test 2>&1); rc=$?
[ $rc -eq 0 ] && echo "$out" | grep -q "policy tests passed" && ok "rowstile test passes ($(echo "$out" | grep -c 'ok '))" || bad "test" "$out"
sed 's/user 3 can view file 11/user 3 cannot view file 11/' example/docs.authz > "$T/failing.authz"
printf '\ntest "one that fails too"\n  user 3 cannot view file 11\n' >> "$T/failing.authz"
applied=$(TCLI apply "$T/failing.authz" 2>&1); arc=$?
out=$(TCLI test 2>&1); rc=$?
case "$out" in *"FAIL"*"user 3 cannot view file 11"*) [ $rc -eq 1 ] && ok "... and a failing test fails it" || bad "test exit" "$rc";; *) bad "failing test" "$out";; esac
# applying runs none of a policy's tests (named ones write): the one whose tests fail above applied
[ $arc -eq 0 ] && [ "$applied" = "$T/failing.authz: applied" ] &&
  ok "apply runs no test: that policy applied, its tests failing (the section's and a named one)" || bad "applying a policy whose tests fail" "$applied"
[ "$(psql -X -At -d "$TDB" -c "SELECT count(*) FROM pg_proc WHERE proname = 'authz_policy_tests'")" = 0 ] && ok "testing leaves nothing behind" || bad "test function left"
dropdb "$TDB"
# a policy without rules makes no row-level security policy to find the app role by: the tests switch to the
# policy's own, and an owner that only administers it (it made the role, as on managed Postgres) is told what to
# grant first. A switch refused while the tests run would pass a check that a statement is refused, unrun
N=${DB}_plain; R=${DB}_plain_app
dropdb --if-exists "$N" 2>/dev/null; psql -X -q -d postgres -c "DROP ROLE IF EXISTS $R" >/dev/null 2>&1
createdb "$N" || exit 1
PGOPTIONS="-c createrole_self_grant= -c client_min_messages=error" psql -X -q -v ON_ERROR_STOP=1 -d "$N" \
  -c "CREATE ROLE $R" -c "CREATE SCHEMA app" -c "CREATE TABLE app.users (id bigint PRIMARY KEY)" \
  -c "CREATE TABLE app.notes (id bigint PRIMARY KEY, owner_id bigint NOT NULL REFERENCES app.users)" \
  -c "GRANT USAGE ON SCHEMA app TO $R" -c "GRANT SELECT ON ALL TABLES IN SCHEMA app TO $R" \
  -c "INSERT INTO app.users VALUES (1), (2)" -c "INSERT INTO app.notes VALUES (1, 1)" >/dev/null || exit 1
printf 'app role %s\ntype user = app.users\ntype note = app.notes\n  owner : user = owner_id\n  viewer : user shared\n  can share = owner\n  can view = owner or viewer\n' "$R" > "$T/norules.authz"
# a check that is false: user 1 owns note 1, and may share it
printf 'test "the owner may share"\n  as user 1 refused {SELECT authz.share(%s, %s, %s, %s, %s)}\n' "'note'" "'1'" "'viewer'" "'user'" "'2'" > "$T/norules.test.authz"
NCLI() { python3 cli/rowstile_cli.py --db "dbname=$N" "$@"; }
NCLI apply "$T/norules.authz" >/dev/null 2>&1 || bad "apply a policy without rules"
for flag in "" --coverage; do
  out=$(NCLI test $flag "$T/norules.test.authz" 2>&1); rc=$?
  case "$out" in *"may not switch to the app role $R (SET ROLE)"*"[AZ618]"*"GRANT \"$R\" TO"*) [ $rc -eq 1 ] &&
    ok "test${flag:+ $flag} on a policy without rules, as an owner that may not switch to the app role: what to grant, no check passed" ||
    bad "test${flag:+ $flag} without rules: exit" "$rc";; *) bad "test${flag:+ $flag} without rules, as a plain owner" "$out";; esac
done
psql -X -q -d "$N" -c "GRANT $R TO $PGUSER" >/dev/null
out=$(NCLI test "$T/norules.test.authz" 2>&1); rc=$?
case "$out" in *"FAIL"*"as user 1 refused"*"allowed (1 row(s))"*"1 policy test(s) failed"*) [ $rc -eq 1 ] &&
  ok "... and once it may, the check runs as the app role, and fails: the owner's share is allowed" || bad "test after the grant: exit" "$rc";;
  *) bad "test without rules, after the grant" "$out";; esac
dropdb "$N"; psql -X -q -d postgres -c "DROP ROLE IF EXISTS $R" >/dev/null 2>&1

echo "-- includes"
mkdir -p "$T/sub"
cp example/docs.authz "$T/sub/b.authz"
printf 'include "b.authz"\n' > "$T/sub/a.authz"
printf 'include "sub/a.authz"\n' > "$T/main.authz"
run apply "$T/main.authz"; [ "$out" = "$T/main.authz: applied" ] && ok "an include is relative to the file that includes it" || bad "nested include" "$out"
[ "$(PSQL -c "SELECT string_agg(k, ',' ORDER BY k) FROM jsonb_object_keys((SELECT files FROM authz.policy_versions ORDER BY id DESC LIMIT 1)) k")" = "sub/a.authz,sub/b.authz" ] &&
  ok "... and the included files are stored with it" || bad "stored files"
printf 'include "nothere.authz"\n' > "$T/missing.authz"
run apply "$T/missing.authz"; case "$out" in *"line 1: can't find nothere.authz"*) ok "a missing include names the line";; *) bad "missing include" "$out";; esac
printf 'app role app_user\nthis is not valid\n' > "$T/sub/bad.authz"; printf 'include "sub/bad.authz"\n' > "$T/bad.authz"
run apply "$T/bad.authz"; case "$out" in *"sub/bad.authz line 2"*) ok "a mistake in an included file names that file and line";; *) bad "error location" "$out";; esac
printf 'app role app_user\n' > "$T/x.authz"; printf 'include "x.authz"\ninclude "x.authz"\n' > "$T/twice.authz"
run apply "$T/twice.authz"; case "$out" in *"included twice"*) ok "including a file twice is refused";; *) bad "double include" "$out";; esac
[ "$(PSQL -c "SELECT authz.verify()")" = t ] && ok "... and a refused policy changes nothing" || bad "state after refused policies"

echo "-- previewing a change"
state() { PSQL -c "SELECT md5(string_agg(policyname || tablename || coalesce(qual, '') || coalesce(with_check, ''), ',' ORDER BY policyname, tablename)) FROM pg_policies" \
               -c "SELECT count(*) FROM authz.policy_versions" -c "SELECT count(*) FROM pg_proc WHERE pronamespace = 'authz_gen'::regnamespace OR pronamespace = 'authz_int'::regnamespace" | tr '\n' ' '; }
before=$(state)
sed -e '/or linked_into.view/d' -e '/^  linked_into : folder/d' example/docs.authz > "$T/nolinks.authz"
run diff "$T/nolinks.authz"; case "$out" in *" changes"*"loses"*) ok "diff: without links, people lose access";; *) bad "diff" "$out";; esac
[ "$(state)" = "$before" ] && [ "$(PSQL -c "SELECT authz.verify()")" = t ] && ok "... and nothing changed" || bad "diff changed something" "$(state) vs $before"
run diff example/docs.authz; case "$out" in *"0 changes (nobody gains"*) ok "diff of the policy in force: no changes";; *) bad "diff same policy" "$out";; esac
sed 's/not {confidential}/not {confidentail}/' example/docs.authz > "$T/bad_cond.authz"
run diff "$T/bad_cond.authz"
case "$out" in "policy line 63: the condition {confidentail} doesn't run: column \"confidentail\" does not exist [AZ613]"*)
  [ $rc -eq 1 ] && [ "$(state)" = "$before" ] && ok "diff names a condition Postgres refuses with its line, as applying does, and changes nothing" ||
  bad "diff with a condition that doesn't run: exit or state" "$rc";; *) bad "diff with a condition that doesn't run" "$out";; esac

echo "-- who may apply"
PSQL -c "DROP ROLE IF EXISTS authz_apply_other" -c "CREATE ROLE authz_apply_other LOGIN" -c "GRANT CREATE ON DATABASE $DB TO authz_apply_other" \
     -c "GRANT USAGE, CREATE ON SCHEMA authz TO authz_apply_other" >/dev/null
out=$(python3 cli/rowstile_cli.py --db "dbname=$DB user=authz_apply_other" apply example/docs.authz --force 2>&1)
case "$out" in *"must be owner"*|*"permission denied"*) ok "a role that doesn't own the tables can't apply: Postgres refuses";; *) bad "non-owner apply" "$out";; esac
[ "$(PSQL -c "SELECT authz.verify()")" = t ] && ok "... and nothing changed" || bad "state after refused apply"
out=$(PSQL -c "SET ROLE app_user" -c "SELECT count(*) FROM authz.policy_versions" 2>&1)
case "$out" in *"permission denied"*) ok "the app role can't read or change the stored policies";; *) bad "policy_versions access" "$out";; esac
PSQL -c "REVOKE ALL ON SCHEMA authz FROM authz_apply_other" -c "REVOKE ALL ON DATABASE $DB FROM authz_apply_other" -c "DROP ROLE authz_apply_other" >/dev/null

echo "-- backup and restore"
access "$DB" > /tmp/authz_apply_access_before
counts="SELECT (SELECT count(*) FROM authz.shares), (SELECT count(*) FROM authz.audit), (SELECT count(*) FROM authz.policy_versions), (SELECT count(*) FROM authz.changes)"
orig=$(PSQL -c "$counts")
pg_dump -Fc -f /tmp/authz_apply.dump "$DB" || bad "pg_dump"
fresh "${DB}_restored"
out=$(pg_restore --exit-on-error -d "${DB}_restored" /tmp/authz_apply.dump 2>&1); [ -z "$out" ] && ok "pg_restore runs without errors" || bad "pg_restore" "$out"
[ "$(psql -X -At -d "${DB}_restored" -c "$counts")" = "$orig" ] &&
  ok "shares, audit trail, policy history and change feed are all restored ($orig)" || bad "restored rows" "$(psql -X -At -d "${DB}_restored" -c "$counts") vs $orig"
[ "$(psql -X -At -d "${DB}_restored" -c "SELECT authz.verify()")" = t ] && ok "the restored inheritance tables match a rebuild" || bad "verify after restore"
access "${DB}_restored" > /tmp/authz_apply_access_after
cmp -s /tmp/authz_apply_access_before /tmp/authz_apply_access_after &&
  ok "every user sees the same files and folders after the restore ($(wc -l < /tmp/authz_apply_access_after) users)" ||
  bad "access differs after restore" "$(diff /tmp/authz_apply_access_before /tmp/authz_apply_access_after | head -4)"
[ "$(psql -X -At -d "${DB}_restored" -c "SELECT nextval('authz.audit_id_seq') > (SELECT max(id) FROM authz.audit) AND nextval('authz.policy_versions_id_seq') > (SELECT max(id) FROM authz.policy_versions)")" = t ] &&
  ok "sequences carry on after the restore" || bad "sequences restart"
out=$(python3 cli/rowstile_cli.py --db "dbname=${DB}_restored" reapply 2>&1 && psql -X -At -d "${DB}_restored" -c "SELECT authz.verify()")
case "$out" in *t) ok "the restored database can apply its policy again";; *) bad "reapply after restore" "$out";; esac
# writes made with the triggers off (a bulk load) are not followed: verify() says so, and --force computes the trees again
R() { psql -X -q -At -d "${DB}_restored" "$@"; }
R -c "ALTER TABLE app.folders DISABLE TRIGGER USER" -c "UPDATE app.folders SET parent_id = 2 WHERE id = 4" -c "ALTER TABLE app.folders ENABLE TRIGGER USER" >/dev/null
[ "$(R -c "SELECT authz.verify()")" = f ] && ok "a move made with the triggers off leaves the inheritance tables behind: verify() is false" || bad "verify after a write without triggers"
out=$(python3 cli/rowstile_cli.py --db "dbname=${DB}_restored" reapply 2>&1 && R -c "SELECT authz.verify()")
case "$out" in *f) ok "... applying again keeps them as they are (unchanged tables are kept)";; *) bad "reapply rebuilt a kept tree" "$out";; esac
out=$(python3 cli/rowstile_cli.py --db "dbname=${DB}_restored" reapply --force 2>&1 && R -c "SELECT authz.verify()")
case "$out" in *t) ok "... reapply --force computes them again";; *) bad "reapply --force" "$out";; esac
# a delete with the triggers off leaves the gone folder's rows behind: verify() looks for them too
R -c "INSERT INTO app.folders (id, org_id, parent_id, name) SELECT 9001, org_id, 4, 'gone' FROM app.folders WHERE id = 4" \
  -c "ALTER TABLE app.folders DISABLE TRIGGER USER" -c "DELETE FROM app.folders WHERE id = 9001" \
  -c "ALTER TABLE app.folders ENABLE TRIGGER USER" >/dev/null
[ "$(R -c "SELECT authz.verify()")" = f ] && ok "a delete made with the triggers off leaves rows of a gone folder: verify() is false" ||
  bad "verify after a delete without triggers"
out=$(python3 cli/rowstile_cli.py --db "dbname=${DB}_restored" reapply --force 2>&1 && R -c "SELECT authz.verify()")
case "$out" in *t) ok "... and reapply --force takes them out";; *) bad "reapply --force after a delete" "$out";; esac
R -c "ALTER TABLE app.folders DISABLE TRIGGER USER" -c "UPDATE app.folders SET parent_id = 3 WHERE id = 4" -c "ALTER TABLE app.folders ENABLE TRIGGER USER" >/dev/null
R -c "SELECT policy FROM authz.policy_versions ORDER BY id DESC LIMIT 1" > "$T/in_force.authz"
out=$(python3 cli/rowstile_cli.py --db "dbname=${DB}_restored" apply "$T/in_force.authz" --force 2>&1 && R -c "SELECT authz.verify()")
case "$out" in *t) ok "... and so does apply --force";; *) bad "apply --force" "$out";; esac
dropdb "${DB}_restored"

echo "-- removing"
nshares=$(PSQL -c "SELECT count(*) FROM authz.shares")
run remove --yes
case "$out" in *"app.files was governed by the removed policy, and row-level security is still on"*) ok "remove warns that row-level security stays on";;
  *) bad "remove warning" "$out";; esac
[ "$(PSQL -c "SELECT count(*) FROM pg_namespace WHERE nspname IN ('authz_gen', 'authz_int')")" = 0 ] && ok "its schemas are gone" || bad "schemas left"
[ "$(PSQL -c "SELECT count(*) FROM pg_policy p JOIN pg_class c ON c.oid = p.polrelid WHERE c.relnamespace = 'app'::regnamespace")" = 0 ] && ok "its row-level security policies are gone" || bad "policies left"
[ "$(PSQL -c "SELECT count(*) FROM pg_trigger t JOIN pg_proc p ON p.oid = t.tgfoid WHERE NOT t.tgisinternal AND p.pronamespace IN (SELECT oid FROM pg_namespace WHERE nspname LIKE 'authz%')")" = 0 ] &&
  ok "its triggers on app tables are gone" || bad "triggers left"
[ "$(PSQL -c "SELECT count(*) FROM pg_event_trigger WHERE evtname LIKE 'authz%'")" = 0 ] && ok "its event triggers are gone" || bad "event triggers left"
[ "$(PSQL -c "SELECT string_agg(proname, ',' ORDER BY proname) FROM pg_proc WHERE pronamespace = 'authz'::regnamespace")" = "ctx,link_hashes" ] &&
  ok "only the base functions are left in authz" || bad "functions left" "$(PSQL -c "SELECT string_agg(proname, ',') FROM pg_proc WHERE pronamespace = 'authz'::regnamespace")"
[ "$(PSQL -c "SELECT count(*) FROM authz.shares")" = "$nshares" ] && ok "the $nshares shares are kept" || bad "shares lost"
run test; case "$out" in *"no policy is applied"*) ok "nothing to test once removed";; *) bad "test after remove" "$out";; esac
out=$(CLI apply example/docs.authz 2>&1 && PSQL -c "SELECT authz.verify()" && CLI remove --yes 2>/dev/null)
case "$out" in *"applied"*t*removed) ok "a removed policy can be applied again, and removed again";; *) bad "apply after remove" "$out";; esac

echo "-- the second policy: masks, UUIDs, caveats"
fresh "$DB"
quiet -d "$DB" -f tests/multi_schema.sql >/dev/null || exit 1
run apply tests/multi.authz; case "$out" in *"tests/multi.authz: applied") ok "rowstile apply multi.authz";; *) bad "apply multi" "$out";; esac
psql -X -q -v ON_ERROR_STOP=1 -d "$DB" -f tests/multi_scenario.sql > /tmp/authz_apply_multi.log 2>&1
rc=$?; n=$(grep -c 'ok  ' /tmp/authz_apply_multi.log)
[ $rc -eq 0 ] && ok "its scenario passes ($n checks)" || bad "multi scenario" "$(grep 'FAIL\|ERROR' /tmp/authz_apply_multi.log | head -3)"
[ "$(PSQL -c "SELECT has_column_privilege('app_user', 'mt.docs', 'body', 'SELECT')")" = f ] && ok "the masked column isn't readable from the table" || bad "mask"
# a share to user:* names no row ('*' is every signed-in user): applying again must not sweep it away
PSQL -c "INSERT INTO authz.shares (object_type, object_id, relation, subject_type, subject_id)
         SELECT 'project', id::text, 'viewer', 'user', '*' FROM mt.projects ORDER BY id LIMIT 1 ON CONFLICT DO NOTHING" >/dev/null
stars=$(PSQL -c "SELECT count(*) FROM authz.shares WHERE subject_id = '*'")
run apply tests/multi.authz --force
[ "$stars" -gt 0 ] && [ "$(PSQL -c "SELECT count(*) FROM authz.shares WHERE subject_id = '*'")" = "$stars" ] &&
  ok "applying again keeps the $stars shares to every signed-in user (user:*)" ||
  bad "user:* shares after applying again" "$stars before, $(PSQL -c "SELECT count(*) FROM authz.shares WHERE subject_id = '*'") after"
# the masked view is what the app reads, so the app may build on it: applying replaces it in place
PSQL -c "CREATE VIEW mt.my_docs AS SELECT id FROM mt.docs_visible" >/dev/null
run apply tests/multi.authz --force
case "$out" in *": applied") [ "$(PSQL -c "SELECT pg_get_viewdef('mt.docs_visible'::regclass) ~ 'WHERE false'")" = f ] &&
  [ "$(PSQL -c "SELECT count(*) FROM pg_views WHERE schemaname = 'mt' AND viewname = 'my_docs'")" = 1 ] &&
  ok "applying with a view of the app's on the masked view: replaced in place, the app's view stays" || bad "masked view after apply" "$out";;
  *) bad "apply with a view on the masked view" "$out";; esac
sed 's/  mask body : edit/  mask body : view/' tests/multi.authz > "$T/mask.authz"
run apply "$T/mask.authz"
case "$out" in *": applied") [ "$(PSQL -c "SELECT count(*) FROM pg_views WHERE schemaname = 'mt' AND viewname = 'my_docs'")" = 1 ] &&
  ok "... also when the mask changes" || bad "the app's view after a mask change";; *) bad "a mask change under the app's view" "$out";; esac
PSQL -c "ALTER TABLE mt.docs ADD COLUMN note text" >/dev/null
run apply "$T/mask.authz" --force
case "$out" in *": applied") [ "$(PSQL -c "SELECT count(*) FROM information_schema.columns WHERE table_schema = 'mt' AND table_name = 'docs_visible' AND column_name = 'note'")" = 1 ] &&
  ok "... and when the table gets a column (the view gets it too)" || bad "new column in the masked view";; *) bad "a new column under the app's view" "$out";; esac
PSQL -c "ALTER TABLE mt.docs RENAME COLUMN note TO remark" >/dev/null
run apply "$T/mask.authz" --force
case "$out" in *"the masked view mt.docs_visible can't be replaced in place: the columns of mt.docs changed"*"[AZ617]"*"mt.my_docs"*)
  ok "a column renamed under the app's view: refused, naming what is built on the masked view";; *) bad "a renamed column under the app's view" "$out";; esac
PSQL -c "ALTER TABLE mt.docs RENAME COLUMN remark TO note" >/dev/null
grep -v "mask body" tests/multi.authz | sed 's/ view mt.docs_visible//' > "$T/nomask.authz"
before=$(PSQL -c "SELECT pg_get_viewdef('mt.docs_visible'::regclass)")
run apply "$T/nomask.authz"
case "$out" in *"no longer makes a masked view that something in the database is built on: mt.docs_visible ("*"mt.my_docs"*"[AZ617]"*)
  [ "$(PSQL -c "SELECT pg_get_viewdef('mt.docs_visible'::regclass)")" = "$before" ] &&
  ok "a policy without the masked view, while the app's view is on it: refused, naming it, nothing changed" || bad "the masked view after a refused apply";;
  *) bad "a masked view that goes under the app's view" "$out";; esac
PSQL -c "DROP VIEW mt.my_docs" -c "ALTER TABLE mt.docs DROP COLUMN note CASCADE" >/dev/null 2>&1
run apply tests/multi.authz --force
case "$out" in *": applied") ok "... and once the app's view is gone, a dropped column is no trouble";; *) bad "apply after the app's view is gone" "$out";; esac
CLI remove --yes >/dev/null 2>&1
[ "$(PSQL -c "SELECT has_table_privilege('app_user', 'mt.docs', 'SELECT')")" = t ] && ok "remove gives back the table-wide SELECT the mask replaced" || bad "mask privileges after remove"
cols="FROM pg_attribute WHERE attrelid = 'mt.docs'::regclass AND attnum > 0 AND NOT attisdropped AND attacl IS NOT NULL"
[ "$(PSQL -c "SELECT count(*) $cols")" = 0 ] && ok "... and takes back the SELECT on its other columns the mask gave instead" ||
  bad "column privileges after remove" "$(PSQL -c "SELECT string_agg(attname || ' ' || attacl::text, ', ') $cols")"
out=$(PSQL -c "GRANT SELECT ON mt.docs TO app_user" 2>&1); [ -z "$out" ] && ok "... and later grants aren't refused any more" || bad "mask guard left" "$out"

echo "-- a condition Postgres refuses"
# rowstile check can't see these (they need the tables): applying names the condition's line
fresh "$DB"
quiet -d "$DB" -f example/app_schema.sql >/dev/null || exit 1
for cond in "confidential or nme = 'x'|column \"nme\" does not exist" "confidential or name = |syntax error at or near \")\"" "confidential or nosuchfn(name)|function nosuchfn(text) does not exist"; do
  sed "s/not {confidential}/not {${cond%%|*}}/" example/docs.authz > "$T/bad_cond.authz"
  run apply "$T/bad_cond.authz"
  case "$out" in "policy line 63: the condition {confidential or "*"} doesn't run: ${cond#*|} [AZ613]"*)
    ok "a condition that doesn't run names its line: {${cond%%|*}}";; *) bad "bad condition {${cond%%|*}}" "$out";; esac
done
# a condition with authz.uid() is written another way in the compiled SQL: it is still the one named, not another one
sed "s/: folder.edit and owner$/: folder.edit and {ownr_id = authz.uid()}/" example/docs.authz > "$T/bad_cond.authz"
grep -q "ownr_id" "$T/bad_cond.authz" || bad "the example has no files insert rule (folder.edit and owner) to break"
run apply "$T/bad_cond.authz"
case "$out" in "policy line "*": the condition {ownr_id = authz.uid()} doesn't run: column \"ownr_id\" does not exist [AZ613]"*)
  ok "... also one that asks who is signed in";; *) bad "bad condition with authz.uid()" "$out";; esac
# in a select rule the error comes from row-level security's own expression, where Postgres says no position
sed "79s/: view$/: view and {nme = 'x'}/" example/docs.authz > "$T/bad_cond.authz"
grep -q "nme = 'x'" "$T/bad_cond.authz" || bad "the example's files select rule moved: line 79 is no longer it"
run apply "$T/bad_cond.authz"
case "$out" in "policy line 79: the condition {nme = 'x'} doesn't run: column \"nme\" does not exist [AZ613]"*)
  ok "... also one in a select rule, where Postgres says no position";; *) bad "bad condition in a select rule" "$out";; esac
# Postgres points into a condition whose text holds another's: the one that fails is named, not the other ({inherit},
# lines 48 and 49, begins {inherit =}; and files have no column inherit)
sed 's/(parent.view and {inherit})/(parent.view and {inherit =})/' example/docs.authz > "$T/bad_cond.authz"
run apply "$T/bad_cond.authz"
case "$out" in "policy line 50: the condition {inherit =} doesn't run: syntax error at or near \")\" [AZ613]"*)
  ok "a condition another one's text begins: the one that fails is named, not the other";; *) bad "a condition another begins" "$out";; esac
sed 's/not {confidential}/not {confidential or inherit}/' example/docs.authz > "$T/bad_cond.authz"
run apply "$T/bad_cond.authz"
case "$out" in "policy line 63: the condition {confidential or inherit} doesn't run: column \"inherit\" does not exist [AZ613]"*)
  ok "... nor one whose text it holds";; *) bad "a condition that holds another" "$out";; esac
# a condition that isn't true or false: Postgres points before it, at what holds it, and it is the only one there (a
# test whose name has {} in it holds no condition)
{ sed 's/not {confidential}/not {name}/' example/docs.authz; printf '%s\n' 'test "a {} in its name"' '  user 1 can edit file 11'; } > "$T/bad_cond.authz"
run apply "$T/bad_cond.authz"
case "$out" in "policy line 63: the condition {name} doesn't run: COALESCE types text and boolean cannot be matched [AZ613]"*)
  ok "a condition that isn't true or false is named, where Postgres points before it";; *) bad "a condition that isn't true or false" "$out";; esac
# a parenthesis left open reads on into the SQL around the condition, where Postgres finds the syntax error
sed 's/({parent_id is null} and share)/({parent_id is null or (true} and share)/' example/docs.authz > "$T/bad_cond.authz"
run apply "$T/bad_cond.authz"
case "$out" in "policy line 74: the condition {parent_id is null or (true} doesn't run: syntax error at or near "*"[AZ613]"*)
  ok "... and one with a parenthesis left open, the error found after it";; *) bad "a parenthesis left open" "$out";; esac
[ "$(PSQL -c "SELECT to_regnamespace('authz_int') IS NULL")" = t ] && ok "... and nothing of it stays" || bad "a failed apply left something"
dropdb "$DB"

echo "-- conditions only a function reads"
# Postgres reads a PL/pgSQL function's queries when they first run: the where of a type that signs in (authz.uid(),
# authz_int."<type>__me"()) and a `shared ... if` (authz.share) are read when applying all the same, and one that
# doesn't run is refused with its line, not left to fail the app's every query, or every share
fresh "$DB"
quiet -d "$DB" -f tests/multi_schema.sql >/dev/null || exit 1
sed 's/^type user = mt.users (id uuid) where {this.active}/type user = mt.users (id uuid) where {this.activ}/' tests/multi.authz > "$T/bad_cond.authz"
grep -q '{this.activ}' "$T/bad_cond.authz" || bad "multi.authz's user type has no where {this.active} to break"
run apply "$T/bad_cond.authz"
case "$out" in "policy line 5: the condition {this.activ} doesn't run: column u.activ does not exist [AZ613]"*'Perhaps you meant to reference the column "u.active"'*)
  [ $rc -eq 1 ] && [ "$(PSQL -c "SELECT to_regnamespace('authz_int') IS NULL")" = t ] &&
  ok "the user type's where that doesn't run (authz.uid() alone reads it): refused with its line, nothing applied" ||
  bad "a user type's where that doesn't run: exit or state" "$rc";;
  *) bad "a user type's where that doesn't run" "$out";; esac
sed "s/or subject_id = '\*'/or subject_idd = '*'/" tests/multi.authz > "$T/bad_cond.authz"
grep -q "subject_idd = '\*'" "$T/bad_cond.authz" || bad "multi.authz has no shared if with subject_id = '*' to break"
run apply "$T/bad_cond.authz"
case "$out" in "policy line 33: the condition {subject_type <> 'user' or subject_idd = '*' or exists "*"} doesn't run: column \"subject_idd\" does not exist [AZ613]"*)
  ok "... a shared if that doesn't run (authz.share alone reads it), named by its relation's line";;
  *) bad "a shared if that doesn't run" "$out";; esac
# a caveat that reads what its share was made with (arg('ip'), which the compiled SQL writes another way): the
# caveat's own line, not the other caveat's, the one whose text the failing statement shows as written
sed "s/= arg('ip')}/= arg('ip') and ip_ok}/" tests/multi.authz > "$T/bad_cond.authz"
grep -q "arg('ip') and ip_ok" "$T/bad_cond.authz" || bad "multi.authz has no caveat = arg('ip') to break"
run apply "$T/bad_cond.authz"
case "$out" in "policy line 54: the condition {authz.ctx('ip') = arg('ip') and ip_ok} doesn't run: column \"ip_ok\" does not exist [AZ613]"*)
  ok "a caveat that doesn't run, reading arg(): named by its own line";; *) bad "a caveat that doesn't run" "$out";; esac
fresh "$DB"
quiet -d "$DB" -f example/app_schema.sql -c "CREATE TABLE app.bots (id bigint PRIMARY KEY, active boolean)" >/dev/null || exit 1
{ cat example/docs.authz; printf '\ntype bot = app.bots principal where {activ}\n'; } > "$T/bad_cond.authz"
run apply "$T/bad_cond.authz"
case "$out" in "policy line $(grep -c '' "$T/bad_cond.authz"): the condition {activ} doesn't run: column \"activ\" does not exist [AZ613]"*)
  ok "... and the where of another type that signs in";; *) bad "a bot type's where that doesn't run" "$out";; esac
sed -i 's/{activ}/{active}/' "$T/bad_cond.authz"
run apply "$T/bad_cond.authz"
[ $rc -eq 0 ] && ok "... which once right applies" || bad "a bot type's where" "$out"
# nothing depends on what such a condition reads, so the app may drop a column only it reads: apply reads them again
# and refuses it with its line, where it would say unchanged (and the app's every query, or share, fails)
PSQL -c "ALTER TABLE app.bots DROP COLUMN active" >/dev/null
run apply "$T/bad_cond.authz"
case "$out" in "policy line $(grep -c '' "$T/bad_cond.authz"): the condition {active} doesn't run: column \"active\" does not exist [AZ613]"*)
  [ $rc -eq 1 ] && ok "... a column it reads that the app dropped since: apply refuses it with its line, not unchanged" ||
  bad "apply after the app dropped a column a bot's where reads: exit" "$rc";;
  *) bad "apply after the app dropped a column a bot's where reads" "$out";; esac
PSQL -c "ALTER TABLE app.bots ADD COLUMN active boolean, ADD COLUMN note text" >/dev/null
printf '  helper : user shared if {exists (select 1 from app.bots b where b.id::text = subject_id and b.note is null)}\n  can use = helper\n  can share = use\n' >> "$T/bad_cond.authz"
run apply "$T/bad_cond.authz"
[ $rc -eq 0 ] || bad "a bot type's shared if" "$out"
PSQL -c "ALTER TABLE app.bots DROP COLUMN note" >/dev/null
run apply "$T/bad_cond.authz"
case "$out" in "policy line $(grep -n '^  helper : ' "$T/bad_cond.authz" | cut -d: -f1): the condition {exists (select 1 from app.bots b where b.id::text = subject_id and b.note is null)} doesn't run: column b.note does not exist [AZ613]"*)
  [ $rc -eq 1 ] && ok "... and a shared if's, the same" || bad "apply after the app dropped a column a shared if reads: exit" "$rc";;
  *) bad "apply after the app dropped a column a shared if reads" "$out";; esac
# a signing-in type's where whose subquery calls its table w, as the type's row is called where it is read: this.
# is still the row (app.users has no owner_id)
PSQL -c "CREATE TABLE app.agents (id bigint PRIMARY KEY, owner_id bigint)" >/dev/null
{ cat example/docs.authz; printf '\ntype agent = app.agents principal where {exists (select 1 from app.users w where w.id = this.owner_id)}\n'; } > "$T/agent.authz"
run apply "$T/agent.authz"; first=$out
run apply "$T/agent.authz"
case "$first|$out" in *"agent.authz: applied|"*"agent.authz: unchanged") ok "a signing-in type's where whose subquery calls its table w: applies, then is unchanged";;
  *) bad "a where whose subquery calls its table w" "$first | $out";; esac
dropdb "$DB"

echo "-- conditions naming a function without its schema"
# resolved on the search path in effect when applying, by the rules and by authz.can, list, perms, who, explain
fresh "$DB"
quiet -d "$DB" -f example/app_schema.sql >/dev/null || exit 1
PSQL -c "CREATE SCHEMA helpers" -c "GRANT USAGE ON SCHEMA helpers TO app_user" \
     -c "CREATE FUNCTION helpers.is_secret(boolean) RETURNS boolean LANGUAGE sql IMMUTABLE AS 'SELECT \$1'" \
     -c "CREATE FUNCTION helpers.inherits(boolean) RETURNS boolean LANGUAGE sql IMMUTABLE AS 'SELECT \$1'" \
     -c "ALTER DATABASE $DB SET search_path = public, helpers"
sed -e 's/not {confidential}/not {is_secret(confidential)}/' -e 's/(parent.view and {inherit})/(parent.view and {inherits(inherit)})/' \
    example/docs.authz > "$T/helpers.authz"
run apply "$T/helpers.authz"
[ "$out" = "$T/helpers.authz: applied" ] && ok "a policy whose conditions call helpers.is_secret(...) as is_secret(...) applies" || bad "apply with helpers" "$out"
got=$(psql -X -At -d "$DB" -c "SET authz.user_id = 1" \
  -c "SELECT authz.can('file', 11, 'view'), (SELECT count(*) FROM authz.list('file', 'view')), authz.perms('file', 11),
             (SELECT count(*) FROM authz.who('folder', 3, 'view')) > 0, (SELECT count(*) FROM authz.explain('file', 11, 'view')) > 0" \
  -c "SET ROLE app_user" -c "SELECT count(*) FROM app.files" 2>&1 | grep -v "^SET$" | tr '\n' ' ')
[ "$got" = "t|1|{share,edit,view}|t|t 1 " ] && ok "... and authz.can, list, perms, who and explain run them, agreeing with the rules" || bad "helpers at run time" "$got"
dropdb "$DB"

echo "-- applying as the tables' owner, not a superuser (as on managed Postgres)"
psql -X -q -d postgres -c "DROP ROLE IF EXISTS authz_apply_owner" -c "CREATE ROLE authz_apply_owner LOGIN NOSUPERUSER NOBYPASSRLS" >/dev/null
# a database with the example's tables, owned by authz_apply_owner
owned() {
  fresh "$1"
  quiet -d "$1" -f example/app_schema.sql >/dev/null || exit 1
  psql -X -q -d "$1" -c "GRANT CREATE ON DATABASE $1 TO authz_apply_owner" -c "ALTER SCHEMA app OWNER TO authz_apply_owner" \
       -c "DO \$o\$ DECLARE r record; BEGIN
             FOR r IN SELECT c.oid::regclass AS t FROM pg_class c WHERE c.relnamespace = 'app'::regnamespace AND c.relkind IN ('r', 'v', 'p') LOOP
               EXECUTE format('ALTER TABLE %s OWNER TO authz_apply_owner', r.t);
             END LOOP; END \$o\$" >/dev/null
}
OWNER() { db=$1; shift; python3 cli/rowstile_cli.py --db "dbname=$db user=authz_apply_owner" "$@"; }
owned "$DB"
out=$(OWNER "$DB" apply example/docs.authz 2>&1); rc=$?
case "$out" in *"example/docs.authz: applied"*) [ $rc -eq 0 ] && ok "the owner applies the policy, with no superuser" || bad "owner apply exit" "$rc";; *) bad "owner apply" "$out";; esac
[ "$(PSQL -c "SELECT authz.verify()")" = t ] && [ "$(PSQL -c "SELECT nspowner::regrole FROM pg_namespace WHERE nspname = 'authz_int'")" = authz_apply_owner ] &&
  ok "... and owns what it made" || bad "owner's objects"
scenario > /tmp/authz_apply_owner.log 2>&1
rc=$?; n=$(grep -c 'ok  ' /tmp/authz_apply_owner.log)
[ $rc -eq 0 ] && ok "the end-to-end scenario passes on it ($n checks)" || bad "owner scenario" "$(grep 'FAIL\|ERROR' /tmp/authz_apply_owner.log | head -3)"
dropdb "$DB"
owned "$TDB"
OWNER "$TDB" apply example/docs.authz >/dev/null 2>&1
psql -X -q -d "$TDB" -c "SET ROLE app_user" -c "SET authz.user_id = 5" -c "SELECT authz.share('folder', 1, 'viewer', 'org', 1, 'member')" \
     -c "SELECT authz.share('file', 13, 'viewer', 'user', 4, '', now() + interval '1 day')" >/dev/null
out=$(OWNER "$TDB" test 2>&1); rc=$?
[ $rc -eq 0 ] && ok "the owner runs the policy's tests" || bad "owner test" "$(echo "$out" | grep -A 3 FAIL | head -12)"
out=$(OWNER "$TDB" remove --yes 2>&1); rc=$?
[ $rc -eq 0 ] && ok "... and removes it" || bad "owner remove" "$out"
dropdb "$TDB"
psql -X -q -d postgres -c "DROP ROLE authz_apply_owner" >/dev/null

echo "-- a condition names its row: this.column"
# memberships have an id of their own, as most tables do: a bare `id` in the subquery is the membership's
CDB=authz_apply_this
fresh "$CDB"
quiet -d "$CDB" -c "CREATE SCHEMA app" -c "CREATE TABLE app.users (id bigint PRIMARY KEY)" \
  -c "CREATE TABLE app.projects (id bigint PRIMARY KEY, owner_id bigint)" \
  -c "CREATE TABLE app.memberships (id bigint PRIMARY KEY, project_id bigint, user_id bigint)" \
  -c "GRANT USAGE ON SCHEMA app TO app_user" -c "GRANT SELECT ON ALL TABLES IN SCHEMA app TO app_user" \
  -c "INSERT INTO app.users VALUES (1), (2)" -c "INSERT INTO app.projects VALUES (10, 1), (11, 1)" \
  -c "INSERT INTO app.memberships VALUES (1, 10, 2), (7, 7, 2)" >/dev/null || exit 1
members() {  # the policy, its condition naming the project's id as $1
  printf '%s\n' "app role app_user" "type user = app.users" "type project = app.projects" "  owner : user = owner_id" \
    "  can view = owner or {exists (select 1 from app.memberships m where m.project_id = $1 and m.user_id = authz.uid())}" \
    "rules app.projects" "  select : view" > "$T/members.authz"
}
seen() { psql -X -q -At -d "$CDB" -c "SET ROLE app_user" -c "SET authz.user_id = 2" \
           -c "SELECT coalesce(string_agg(id::text, ',' ORDER BY id), '') FROM app.projects" | tail -n 1; }
members id
out=$(python3 cli/rowstile_cli.py --db "dbname=$CDB" apply "$T/members.authz" 2>&1)
case "$out" in *"names id, a column of app.projects's rows, but reads it from another table"*"this.id"*)
  ok "a bare column a subquery's table takes is warned about when applying, with this.id to write" ;;
  *) bad "the capture warning" "$out";; esac
members this.id
out=$(python3 cli/rowstile_cli.py --db "dbname=$CDB" apply "$T/members.authz" 2>&1)
case "$out" in *"names id"*) bad "this.id is warned about" "$out";;
  *) [ "$(seen)" = 10 ] && ok "this.id is the row's: user 2 sees the project they are a member of, and only that" ||
       bad "this.id" "user 2 sees $(seen)";; esac
members projects.id
out=$(python3 cli/rowstile_cli.py --db "dbname=$CDB" apply "$T/members.authz" 2>&1); rc=$?
case "$out" in *"[AZ613]"*"for the row the condition is about, write this.id"*) [ $rc -ne 0 ] &&
  ok "the table's name for the row is refused, saying to write this.id" || bad "projects.id exit" "$rc";;
  *) bad "projects.id" "$out";; esac

echo "-- a condition reads with the policy's rights, wherever it is checked"
# the memberships have rules: the app role sees only its own, the policy sees them all
printf '%s\n' "app role app_user" "type user = app.users" "type project = app.projects" "  owner : user = owner_id" \
  "  can view = owner or {exists (select 1 from app.memberships m where m.project_id = this.id)}" \
  "type membership = app.memberships" "rules app.projects" "  select : view" \
  "rules app.memberships" "  select : {user_id = authz.uid()}" > "$T/members.authz"
quiet -d "$CDB" -c "INSERT INTO app.projects VALUES (12, 1)" -c "INSERT INTO app.memberships VALUES (12, 12, 1)" >/dev/null
out=$(python3 cli/rowstile_cli.py --db "dbname=$CDB" apply "$T/members.authz" 2>&1)
listed=$(psql -X -q -At -d "$CDB" -c "SET ROLE app_user" -c "SET authz.user_id = 2" \
  -c "SELECT coalesce(string_agg(x, ',' ORDER BY x), '') FROM authz.list('project', 'view') x" | tail -n 1)
[ "$(seen)" = "10,12" ] && [ "$listed" = "10,12" ] &&
  ok "a condition in a permission sees every membership in its table's rules too: SELECT says what authz.list says" ||
  bad "the condition's rights" "select $(seen), list $listed: $out"
# ... and so does a function the condition calls, however its name is written
quiet -d "$CDB" -c "CREATE FUNCTION app.\"Member\"(p bigint) RETURNS boolean LANGUAGE sql STABLE
  AS 'SELECT exists (SELECT 1 FROM app.memberships m WHERE m.project_id = p)'" \
  -c "GRANT EXECUTE ON FUNCTION app.\"Member\"(bigint) TO app_user" \
  -c "CREATE OPERATOR public.=!= (FUNCTION = app.\"Member\", RIGHTARG = bigint)" >/dev/null || exit 1
for call in 'app."Member"(this.id)' '"app"."Member"(this.id)' 'app . "Member" /* c */ (this.id)' '=!= this.id'; do
  sed "s|{exists .*}|{$call}|" "$T/members.authz" > "$T/members_fn.authz"
  out=$(python3 cli/rowstile_cli.py --db "dbname=$CDB" apply "$T/members_fn.authz" 2>&1)
  [ "$(seen)" = "10,12" ] && ok "... and a function it calls by a quoted name or as an operator: {$call}" ||
    bad "a quoted function's rights" "{$call}: select $(seen): $out"
done
dropdb "$CDB"
# a write rule that follows a relation kept in shares or a link table: the app role may not read authz.shares
fresh "$CDB"
quiet -d "$CDB" -f tests/alt_schema.sql >/dev/null || exit 1
python3 cli/rowstile_cli.py --db "dbname=$CDB" apply tests/alt.authz >/dev/null 2>&1
quiet -d "$CDB" -c "INSERT INTO alt.users VALUES (1), (2)" -c "INSERT INTO alt.docs (doc_no, owner_id) VALUES (10, 1)" >/dev/null
out=$(psql -X -q -At -d "$CDB" -c "SET ROLE app_user" -c "SET authz.user_id = 1" \
        -c "UPDATE alt.docs SET locked = true WHERE doc_no = 10 RETURNING doc_no" 2>&1)
[ "$out" = 10 ] && ok "an update whose rule follows shares and link tables passes for the doc's owner" ||
  bad "an update through shares" "$out"
out=$(psql -X -q -At -d "$CDB" -c "SET ROLE app_user" -c "SET authz.user_id = 2" \
        -c "UPDATE alt.docs SET locked = false WHERE doc_no = 10 RETURNING doc_no" 2>&1)
[ -z "$out" ] && ok "... and changes nothing for someone else" || bad "an update by someone else" "$out"
dropdb "$CDB"

echo "-- a group that fails its type's where passes nothing on, nor through the group it is in"
# team 911 is inside team 910, which may view folder 9100; user 902 is in team 911 only, user 901 in team 910. The walk
# through sub-teams is written two ways: through tables alone, and with shares among its sources
fresh "$CDB"
quiet -d "$CDB" -f example/app_schema.sql -c "INSERT INTO app.users VALUES (901, 'a'), (902, 'b')" \
  -c "INSERT INTO app.orgs VALUES (901, 'o')" -c "INSERT INTO app.teams VALUES (910, 901, NULL, 'top'), (911, 901, 910, 'sub')" \
  -c "INSERT INTO app.team_members VALUES (910, 901), (911, 902)" -c "INSERT INTO app.folders (id, org_id, name) VALUES (9100, 901, 'f')" \
  -c "INSERT INTO app.folder_team_access VALUES (9100, 910, 'view')" >/dev/null || exit 1
printf '%s\n' "app role app_user" "type user = app.users" "type team = app.teams where {name <> 'disbanded'}" \
  "  member : user        = app.team_members(team_id -> user_id)" "  member : team#member = app.teams(parent_id -> id)" \
  "type folder = app.folders" "  viewer : team#member = app.folder_team_access(folder_id -> team_id)" \
  "  can view = viewer" "rules app.folders" "  select : view" > "$T/teams.authz"
sed 's|^type folder|  member : team#member  shared\n  can share = member\ntype folder|' "$T/teams.authz" > "$T/teams_shared.authz"
sees() { psql -X -q -At -d "$CDB" -c "SET ROLE app_user" -c "SET authz.user_id = $1" \
           -c "SELECT coalesce(string_agg(id::text, ','), '') FROM app.folders" | tail -n 1; }
for policy in teams teams_shared; do
  quiet -d "$CDB" -c "UPDATE app.teams SET name = 'sub' WHERE id = 911" >/dev/null
  out=$(python3 cli/rowstile_cli.py --db "dbname=$CDB" apply "$T/$policy.authz" 2>&1)
  before="$(sees 902)"
  quiet -d "$CDB" -c "UPDATE app.teams SET name = 'disbanded' WHERE id = 911" >/dev/null
  [ "$before" = 9100 ] && [ "$(sees 902)" = "" ] && [ "$(sees 901)" = 9100 ] &&
    ok "$policy.authz: a member of a disbanded sub-team no longer sees what the team above it may; its own members still do" ||
    bad "$policy.authz: a disbanded sub-team" "user 902 saw '$before', then '$(sees 902)'; user 901 '$(sees 901)': $out"
done
dropdb "$CDB"

echo "-- a policy whose user ids have another type than the one applied before (bigint, then uuid)"
UDB="${DB}_uid"
fresh "$UDB"
quiet -d "$UDB" -f example/app_schema.sql -f tests/multi_schema.sql >/dev/null &&
  python3 compile_policy.py example/docs.authz | quiet -d "$UDB" >/dev/null || bad "applying the docs policy"
out=$(python3 compile_policy.py tests/multi.authz | psql -X -q -v ON_ERROR_STOP=1 -d "$UDB" 2>&1)
case "$out" in *"authz.uid() returns another type than this policy's user ids (uuid); drop it first"*"[AZ606]"*)
  ok "applying is refused, and says what to drop first";; *) bad "user ids of another type" "$out";; esac
dropdb "$UDB"

rm -rf "$T"
if [ $fails -eq 0 ]; then echo "apply: all passed"; else echo "apply: $fails failed"; exit 1; fi
