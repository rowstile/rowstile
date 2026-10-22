#!/bin/bash
# sessions.sh: signed sessions: authz.user_id and the other settings are plain settings anyone
# may set. Only the signature authz.act_as(), the logins and authz.view_as() make keeps the app role from
# choosing its own user by setting them, widening its scopes, or reusing a sign-in in another transaction or on
# another connection.
#   PGHOST=... PGUSER=postgres tests/sessions.sh [database]
set -u
cd "$(dirname "$0")/.."
DB=${1:-authz_sessions}
APP=authz_sess_app          # logs in, a member of app_user
OTHER=authz_sess_other      # logs in, not a member of app_user
fails=0
ok() { echo "ok    $1"; }
bad() { echo "FAIL  $1${2:+: $2}"; fails=$((fails + 1)); }
PSQL() { psql -X -q -At -v ON_ERROR_STOP=1 -d "$DB" "$@"; }
# as $APP (or $ROLE), in one transaction: the last line of output, or the error's SQLSTATE
as() { psql -X -q -At -1 -U "${ROLE:-$APP}" -d "$DB" -v VERBOSITY=sqlstate "$@" 2>&1 | tail -n 1; }
. tests/words.sh
expect() {   # $1 label, $2 expected (for an error, "SQLSTATE: the message's words"), rest: psql arguments
  local label=$1 want=$2; shift 2
  local got; got=$(error_of "$(psql -X -q -At -1 -U "${ROLE:-$APP}" -d "$DB" -v VERBOSITY=verbose "$@" 2>&1)")
  agrees "$label" "$want" "$got" && ok "$label" || bad "$label" "expected '$want', got '$got'"
}
ACT() { echo "DO \$\$ BEGIN PERFORM authz.act_as($1); END \$\$"; }
T=$(mktemp -d)
# whatever way the suite ends: its databases, its roles, its files
cleanup() {
  for d in "$DB" "${DB}_half"; do dropdb --force --if-exists "$d" 2>/dev/null; done
  for r in $APP $OTHER; do psql -X -q -d postgres -c "DROP ROLE IF EXISTS $r" >/dev/null 2>&1; done
  [ -z "${PGSUPERUSER:-}" ] || psql -X -q -U "$PGSUPERUSER" -d postgres -c "DROP ROLE IF EXISTS authz_sess_bypass" >/dev/null 2>&1
  rm -rf "$T"
}
trap cleanup EXIT

dropdb --if-exists "$DB" 2>/dev/null; createdb "$DB" || exit 1
PGOPTIONS="-c client_min_messages=error" psql -X -q -v ON_ERROR_STOP=1 -d "$DB" -f example/app_schema.sql >/dev/null || exit 1
python3 cli/rowstile_cli.py --db "dbname=$DB" apply example/docs.authz >/dev/null 2>&1 || { bad "apply"; exit 1; }
for r in $APP $OTHER; do psql -X -q -d postgres -c "DROP ROLE IF EXISTS $r" >/dev/null 2>&1; done
psql -X -q -d postgres -c "CREATE ROLE $APP LOGIN IN ROLE app_user" -c "ALTER ROLE $APP SET jit = on" \
     -c "CREATE ROLE $OTHER LOGIN" >/dev/null
# a login that is neither the app role nor a member of it has nothing of rowstile's, connection_check() included
ROLE=$OTHER expect "a login outside the app role can't call connection_check() at all" "42501: permission denied for schema authz" \
  -c "SELECT count(*) FROM authz.connection_check()"
# (given the schema and the function, as below, it says what is wrong instead)
PSQL -c "GRANT USAGE ON SCHEMA app, authz TO $OTHER" -c "GRANT EXECUTE ON FUNCTION authz.connection_check() TO $OTHER" >/dev/null
# erin shares the Company folder with the org, as in tests/adversarial.sh
PSQL -c "SET ROLE app_user; SET authz.user_id = 5; SELECT authz.share('folder', 1, 'viewer', 'org', 1, 'member')" >/dev/null
# what carol (user 3) sees, as the owner says it: the owner's and superusers' sessions may set it
carol=$(PSQL -c "SET ROLE app_user" -c "SET authz.user_id = 3" -c "SELECT count(*) FROM app.files")
all=$(PSQL -c "SELECT count(*) FROM app.files")
[ "$carol" -gt 0 ] && [ "$carol" -lt "$all" ] && ok "the owner's session sets authz.user_id and is believed (carol sees $carol of $all)" ||
  bad "setup" "$carol of $all"

echo "-- the settings are anyone's to set"
expect "the app's login role sets authz.user_id, and Postgres doesn't stop it" "t" -c "SET LOCAL authz.user_id = 1" \
  -c "SELECT current_setting('authz.user_id') = '1'"
expect "... but nobody signed in is an error, not an empty result" "28000: nobody signed in in this transaction" -c "SELECT count(*) FROM app.files"
expect "... and so is a user set directly" "28000: authz.user_id was set directly, so it is not believed" -c "SET LOCAL authz.user_id = 1" -c "SELECT count(*) FROM app.files"

echo "-- signing in"
expect "authz.act_as signs carol in: she sees her files" "$carol" -c "$(ACT "'user', '3'")" -c "SELECT count(*) FROM app.files"
# JIT on, as most servers have it: signing in turns it off for the transaction (the rules' estimates are high)
expect "signing in turns JIT off until the transaction ends" "off" -c "$(ACT "'user', '3'")" -c "SELECT current_setting('jit')"
got=$(psql -X -q -At -U "$APP" -d "$DB" -c "BEGIN" -c "$(ACT "'user', '3'")" -c "COMMIT" -c "SELECT current_setting('jit')" 2>&1)
[ "$got" = on ] && ok "... and the next transaction has the session's own setting" || bad "JIT after the transaction" "$got"
expect "... which the app may turn back on after signing in" "on" -c "$(ACT "'user', '3'")" -c "SET LOCAL jit = on" -c "SELECT current_setting('jit')"
expect "view_as signs who it shows: erin, viewing as carol, sees what carol sees" "$carol|3" -c "$(ACT "'user', '5'")" \
  -c "DO \$\$ BEGIN PERFORM authz.view_as('3', 'ticket 7'); END \$\$" -c "SELECT count(*) || '|' || authz.uid() FROM app.files"
expect "... and leaving view-as by clearing who views is an error, not a way to write as carol" "28000: who is signed in was changed after signing in" \
  -c "$(ACT "'user', '5'")" -c "DO \$\$ BEGIN PERFORM authz.view_as('3', 'ticket 7'); END \$\$" -c "SET LOCAL authz.acting_user = ''" \
  -c "UPDATE app.files SET name = name WHERE id = 11"
expect "... nor by clearing its scopes" "28000: who is signed in was changed after signing in" \
  -c "$(ACT "'user', '5'")" -c "DO \$\$ BEGIN PERFORM authz.view_as('3', 'ticket 7'); END \$\$" -c "SET LOCAL authz.scopes = ''" \
  -c "UPDATE app.files SET name = name WHERE id = 11"
expect "act_as(NULL, NULL): nobody, on purpose, no error" "0" -c "$(ACT "NULL, NULL")" -c "SELECT count(*) FROM app.files WHERE id = 12"
expect "changing authz.user_id after signing in is an error" "28000: who is signed in was changed after signing in" -c "$(ACT "'user', '3'")" -c "SET LOCAL authz.user_id = 1" \
  -c "SELECT count(*) FROM app.files"
expect "... authz.principal_type too" "28000: who is signed in was changed after signing in" -c "$(ACT "'user', '3'")" -c "SET LOCAL authz.principal_type = 'user'" \
  -c "SELECT count(*) FROM app.files"
expect "... authz.acting_user too" "28000: who is signed in was changed after signing in" -c "$(ACT "'user', '3'")" -c "SET LOCAL authz.acting_user = 'x'" \
  -c "SELECT authz.share('file', 11, 'viewer', 'user', 4)"
expect "a forged signature is an error" "28000: who is signed in was changed after signing in" -c "SET LOCAL authz.user_id = 1" -c "SET LOCAL authz.session = 'deadbeef'" \
  -c "SELECT count(*) FROM app.files"
expect "sharing as a chosen user is refused" "28000: who is signed in was changed after signing in" -c "$(ACT "'user', '3'")" -c "SET LOCAL authz.user_id = 1" \
  -c "SELECT authz.share('folder', 1, 'viewer', 'user', 3)"
expect "... and so is asking can() as one" "28000: who is signed in was changed after signing in" -c "$(ACT "'user', '3'")" -c "SET LOCAL authz.user_id = 1" \
  -c "SELECT authz.can('folder', 5, 'view')"

echo "-- a signature is good for one transaction on one connection"
got=$(error_of "$(psql -X -q -At -U "$APP" -d "$DB" -v VERBOSITY=verbose 2>&1 <<'SQL'
BEGIN;
SELECT authz.act_as('user', '1');
SELECT current_setting('authz.session') AS sig \gset
COMMIT;
BEGIN;
SET LOCAL authz.user_id = 1;
SELECT set_config('authz.session', :'sig', true);
SELECT count(*) FROM app.files;
COMMIT;
SQL
)")
[ "$got" = "28000: who is signed in was changed after signing in" ] && ok "a signature from an earlier transaction is refused in the next one" || bad "replay in the next transaction" "$got"
sig=$(psql -X -q -At -U "$APP" -d "$DB" -c "BEGIN" -c "SELECT authz.act_as('user', '1')" -c "SELECT current_setting('authz.session')" -c "COMMIT" | tail -n 1)
expect "... and one from another connection too" "28000: who is signed in was changed after signing in" -c "SET LOCAL authz.user_id = 1" -c "SELECT set_config('authz.session', '$sig', true)" \
  -c "SELECT count(*) FROM app.files"
got=$(psql -X -q -At -U "$APP" -d "$DB" -v VERBOSITY=sqlstate 2>&1 <<'SQL' | tail -n 1
BEGIN;
SELECT authz.act_as('user', '3');
SAVEPOINT s;
SELECT authz.act_as('user', '1');
ROLLBACK TO SAVEPOINT s;
SELECT count(*) FROM app.files;
COMMIT;
SQL
)
[ "$got" = "$carol" ] && ok "a sign-in rolled back with a savepoint gives back the one before it" || bad "savepoint" "$got"

echo "-- keys and scopes"
key=$(PSQL -c "SET authz.user_id = 3" -c "SELECT authz.create_api_key('sessions test', 'read')" | tail -n 1)
expect "a read-only key signs carol in" "$carol" -c "SELECT authz.login_key('$key') IS NOT NULL" -c "SELECT count(*) FROM app.files"
expect "a key's sign-in turns JIT off too" "off" -c "SELECT authz.login_key('$key') IS NOT NULL" -c "SELECT current_setting('jit')"
expect "... and can't write" "UPDATE 0" -c "SELECT authz.login_key('$key') IS NOT NULL" -c "\\set QUIET off" \
  -c "UPDATE app.files SET name = name WHERE id = 11"
expect "clearing its scopes is an error, not a way to write" "28000: who is signed in was changed after signing in" -c "SELECT authz.login_key('$key') IS NOT NULL" \
  -c "SET LOCAL authz.scopes = ''" -c "UPDATE app.files SET name = name WHERE id = 11"
expect "who_among isn't a way out of a key's scopes" "42501: authz.who_among() signs people in, which a session limited by scopes or view-as may not" -c "SELECT authz.login_key('$key') IS NOT NULL" \
  -c "SELECT count(*) FROM authz.who_among('file', '11', 'view', ARRAY['1', '2'])"

echo "-- rowstile's own functions switch users and sign again"
alice=$(as -c "$(ACT "'user', '1'")" -c "SELECT count(*) FROM app.files")
expect "who checks each person, and alice is still signed in afterwards" "$alice" -c "$(ACT "'user', '1'")" \
  -c "SELECT count(*) > 0 FROM authz.who('file', '11', 'view')" -c "SELECT count(*) FROM app.files"
expect "explain for carol, then alice again" "$alice" -c "$(ACT "'user', '1'")" \
  -c "SELECT count(*) > 0 FROM authz.explain('file', '11', 'view', '3')" -c "SELECT count(*) FROM app.files"
want=$(for u in 1 2 3 4 5; do [ "$(as -c "$(ACT "'user', '$u'")" -c "SELECT authz.can('file', 11, 'view')")" = t ] && printf '%s,' $u; done)
expect "who_among asks each one in turn" "${want%,}" -c "$(ACT "'user', '3'")" \
  -c "SELECT string_agg(x, ',' ORDER BY x) FROM authz.who_among('file', '11', 'view', ARRAY['1', '2', '3', '4', '5']) x"
expect "... and leaves carol signed in" "$carol" -c "$(ACT "'user', '3'")" \
  -c "SELECT count(*) FROM authz.who_among('file', '11', 'view', ARRAY['1', '2'])" -c "SELECT count(*) FROM app.files"

echo "-- ... and when they fail half way, signed in as someone else, who is signed in is as it was"
# A policy whose condition fails for user 3 (as one reading a broken row would): who, explain, who_among and
# check_invariants, asked as user 3 after others, fail with its error, in the middle of switching users. Caught (a
# savepoint, an exception block), the transaction goes on signed in exactly as before: the same settings and
# signature, the same rows seen and changed. They have no handler of their own: Postgres undoes what was set
# since the savepoint or the block, the settings and the signature among it.
H=${DB}_half
dropdb --if-exists "$H" 2>/dev/null; createdb "$H" || exit 1
PGOPTIONS="-c client_min_messages=warning" psql -X -q -v ON_ERROR_STOP=1 -d "$H" >/dev/null <<'SQL' || exit 1
CREATE SCHEMA sh;
CREATE TABLE sh.users (id bigint PRIMARY KEY);
CREATE TABLE sh.bots (id bigint PRIMARY KEY);
CREATE TABLE sh.docs (id bigint PRIMARY KEY, owner_id bigint, bot_id bigint, title text);
INSERT INTO sh.users VALUES (1), (2), (3), (4);
INSERT INTO sh.bots VALUES (1);
INSERT INTO sh.docs VALUES (1, 1, 1, 'one'), (2, 2, NULL, 'two'), (3, 3, NULL, 'three'), (4, 4, NULL, 'four');
CREATE FUNCTION sh.trips() RETURNS boolean LANGUAGE plpgsql STABLE AS $f$
BEGIN
  IF current_setting('authz.user_id', true) = '3' AND coalesce(current_setting('authz.principal_type', true), '') = '' THEN
    RAISE EXCEPTION 'sh.trips() fails for user 3';
  END IF;
  RETURN false;
END $f$;
GRANT USAGE ON SCHEMA sh TO app_user;
GRANT SELECT, UPDATE ON ALL TABLES IN SCHEMA sh TO app_user;
SQL
cat > "$T/half.authz" <<'POLICY'
app role app_user
type user = sh.users
type bot = sh.bots principal
type doc = sh.docs
  owner  : user = owner_id
  keeper : bot  = bot_id
  viewer : user shared
  can share = owner or keeper
  can edit  = share
  can view  = edit or viewer or {sh.trips()}
scope look = select, view, share
rules sh.docs
  select                 : view
  update                 : edit
  update owner_id, bot_id : share
invariants
  never doc: view and not edit and not viewer
POLICY
python3 compile_policy.py "$T/half.authz" > "$T/half.sql" &&
  PGOPTIONS="-c client_min_messages=error" psql -X -q -v ON_ERROR_STOP=1 -d "$H" -f "$T/half.sql" >/dev/null ||
  { bad "apply the policy that fails half way"; exit 1; }
psql -X -q -d "$H" -c "SET authz.user_id = 1" -c "SELECT authz.share('doc', 1, 'viewer', 'user', 2)" \
  -c "SELECT authz.share('doc', 1, 'viewer', 'user', 3)" >/dev/null
look=$(psql -X -q -At -d "$H" -c "SET authz.user_id = 1" -c "SELECT authz.create_api_key('half way', 'look')")
OWNER=$(PSQL -c "SELECT current_user")
SETTINGS="concat_ws('|', current_setting('authz.user_id', true), current_setting('authz.principal_type', true),
  current_setting('authz.scopes', true), current_setting('authz.acting_user', true), current_setting('authz.session', true))"
# who is signed in, what they see, and what an update changes (nothing, for a read-only key)
SIGNED="WITH u AS (UPDATE sh.docs SET title = title RETURNING 1)
  SELECT concat_ws('|', authz.uid(), (SELECT principal_type || ':' || principal_id FROM authz.principal()),
    current_setting('authz.scopes', true), (SELECT count(*) FROM sh.docs), (SELECT count(*) FROM u))"
half() {   # $1 label, $2 the sign-in, $3 the call that fails half way; as $ROLE (else $APP), a role RLS applies to
  local label=$1 signin=$2 call=$3 want out err
  want=$(psql -X -q -At -U "${ROLE:-$APP}" -d "$H" -1 -c "$signin" -c "SET LOCAL ROLE app_user" -c "$SIGNED" 2>&1 | tail -n 1)
  out=$(psql -X -q -At -U "${ROLE:-$APP}" -d "$H" -v VERBOSITY=verbose 2>&1 <<SQL
BEGIN;
$signin;
SELECT $SETTINGS AS before \gset
SAVEPOINT s;
$call;
ROLLBACK TO SAVEPOINT s;
SET LOCAL ROLE app_user;
SELECT ($SETTINGS) = :'before';
$SIGNED;
COMMIT;
SQL
)
  err=$(printf '%s\n' "$out" | grep '^ERROR:  ' | head -n 1)
  out=$(printf '%s\n' "$out" | tail -n 2 | paste -sd '|')
  if [ "$err" = "ERROR:  P0001: sh.trips() fails for user 3" ] && [ "$out" = "t|$want" ] && [ -n "$want" ]; then ok "$label"
  else bad "$label" "error '$err', then '$out' (signed in before: '$want')"; fi
}
half "who fails half way: its error, and the same user signed in, seeing and changing the same" \
  "SELECT authz.act_as('user', '1')" "SELECT count(*) FROM authz.who('doc', '1', 'view')"
half "... signed in as a service: the same service" "SELECT authz.act_as('bot', '1')" \
  "SELECT count(*) FROM authz.who('doc', '1', 'view')"
half "... with a key's scopes, which who clears while it asks: the same scopes, still read-only" \
  "SELECT authz.login_key('$look')" "SELECT count(*) FROM authz.who('doc', '1', 'view')"
half "explain for user 3 fails: the same user signed in" "SELECT authz.act_as('user', '1')" \
  "SELECT count(*) FROM authz.explain('doc', '1', 'view', '3')"
half "... signed in as a service" "SELECT authz.act_as('bot', '1')" "SELECT count(*) FROM authz.explain('doc', '1', 'view', '3')"
half "who_among fails at user 3: the same user signed in" "SELECT authz.act_as('user', '1')" \
  "SELECT count(*) FROM authz.who_among('doc', '1', 'view', ARRAY['2', '3', '4'])"
half "... signed in as a service" "SELECT authz.act_as('bot', '1')" \
  "SELECT count(*) FROM authz.who_among('doc', '1', 'view', ARRAY['2', '3', '4'])"
ROLE=$OWNER half "check_invariants fails at user 3: the same user signed in" "SELECT authz.act_as('user', '1')" \
  "SELECT count(*) FROM authz.check_invariants()"
ROLE=$OWNER half "... with a key's scopes, which it clears while it asks: the same scopes" "SELECT authz.login_key('$look')" \
  "SELECT count(*) FROM authz.check_invariants()"
# caught by an exception block instead of a savepoint
got=$(psql -X -q -At -U "$APP" -d "$H" -1 -c "$(ACT "'user', '1'")" -c "DO \$\$ BEGIN
    PERFORM count(*) FROM authz.who('doc', '1', 'view');
  EXCEPTION WHEN OTHERS THEN RAISE NOTICE 'caught: %', SQLERRM;
  END \$\$" -c "SELECT concat_ws('|', authz.uid(), (SELECT count(*) FROM sh.docs))" 2>&1)
[ "$got" = "$(printf 'NOTICE:  caught: sh.trips() fails for user 3\n1|1')" ] &&
  ok "... caught by an exception block: the same user signed in" || bad "who caught by an exception block" "$got"
# not caught: the transaction fails, and the next one on the connection has nobody signed in, not user 3
got=$(error_of "$(psql -X -q -At -U "$APP" -d "$H" -v VERBOSITY=verbose -c "BEGIN" -c "SELECT authz.act_as('user', '1')" \
  -c "SELECT count(*) FROM authz.who('doc', '1', 'view')" -c "COMMIT" -c "SELECT count(*) FROM sh.docs" 2>&1)")
[ "$got" = "28000: nobody signed in in this transaction" ] && ok "... not caught: the next transaction has nobody signed in" || bad "who not caught" "$got"

echo "-- ... and when they answer, who is signed in is as it was for the rest of the transaction"
# doc 5: user 2 owns it and bot 1 keeps it, so bot 1 may ask who has access, and the answer is someone else
psql -X -q -d "$H" -c "INSERT INTO sh.docs VALUES (5, 2, 1, 'five')" >/dev/null
AFTER="SELECT concat_ws('|', coalesce(authz.uid()::text, 'no user'),
  (SELECT principal_type || ':' || principal_id FROM authz.principal()), current_setting('authz.scopes', true))"
got=$(psql -X -q -At -U "$APP" -d "$H" -1 -v VERBOSITY=sqlstate -c "$(ACT "'bot', '1'")" \
  -c "SELECT string_agg(x, ',') FROM authz.who('doc', '5', 'edit') x" -c "$AFTER" 2>&1 | paste -sd ' ')
[ "$got" = "2 no user|bot:1|" ] && ok "a service asks who may edit (user 2), and is still the service afterwards" ||
  bad "a service after who" "$got"
# an id that isn't the type's: who has no one to ask about, explain nothing more to say, and both put back the
# caller's settings (only an administrator gets that far: the app role may not inspect such an id)
got=$(psql -X -q -At -U "$OWNER" -d "$H" -1 -v VERBOSITY=sqlstate -c "$(ACT "'bot', '1'")" \
  -c "SELECT count(*) FROM authz.who('doc', 'abc', 'view')" -c "SELECT count(*) FROM authz.explain('doc', 'abc', 'view', '2')" \
  -c "$AFTER" 2>&1 | paste -sd ' ')
[ "$got" = "0 1 no user|bot:1|" ] && ok "who and explain on an id that isn't a doc's: still the service afterwards" ||
  bad "a service after who on a bad id" "$got"
got=$(psql -X -q -At -U "$OWNER" -d "$H" -1 -v VERBOSITY=sqlstate -c "SELECT authz.login_key('$look') IS NOT NULL" \
  -c "SELECT count(*) FROM authz.who('doc', 'abc', 'view')" -c "$AFTER" 2>&1 | paste -sd ' ')
[ "$got" = "t 0 1|user:1|look" ] && ok "... and a key's scopes, which who clears while it asks, are the key's again" ||
  bad "a key's scopes after who on a bad id" "$got"

echo "-- what is wrong with a connection (authz.connection_check)"
expect "the app's role: nothing to report" "0" -c "SELECT count(*) FROM authz.connection_check()"
got=$(PSQL -c "SELECT string_agg(severity || ': ' || problem, '; ') FROM authz.connection_check()")
case "$got" in *"error: $(PSQL -c "SELECT current_user") owns app."*" an owner skips row-level security, and may turn it off"*|"error: "*" is a superuser"*)
  ok "the owner's connection: an error";; *) bad "owner connection" "$got";; esac
case "$got" in *"error: $(PSQL -c "SELECT current_user") is the policy's owner, or a member of it: who is signed in is believed without a signature, and it may turn row-level security off. Log in as an app role of its own"*|"error: "*" is a superuser"*)
  ok "... that says it is the policy's owner, whose sessions are believed unsigned";; *) bad "owner connection, the policy's owner" "$got";; esac
if [ -n "${PGSUPERUSER:-}" ]; then
  got=$(PSQL -U "$PGSUPERUSER" -c "SELECT string_agg(severity || ': ' || problem, '; ') FROM authz.connection_check()")
  case "$got" in "error: $PGSUPERUSER is a superuser"*) ok "a superuser's connection: an error";; *) bad "superuser connection" "$got";; esac
fi
ROLE=$OTHER expect "a role the policy doesn't govern: an error" "t" \
  -c "SELECT bool_or(severity = 'error' AND problem LIKE '%is not the policy''s app role app_user%') FROM authz.connection_check()"
got=$(PSQL -c "SET ROLE app_user" -c "SELECT string_agg(problem, '; ') FROM authz.connection_check() WHERE severity = 'error'")
case "$got" in "this connection logs in as $(PSQL -c "SELECT current_user"), a superuser, BYPASSRLS or the policy's owner, and switched to app_user: RESET ROLE leaves row-level security"*)
  ok "the owner's login, switched to the app role: an error (RESET ROLE, and settings believed unsigned)";; *) bad "owner as app role" "$got";; esac
if [ -n "${PGSUPERUSER:-}" ]; then
  got=$(PSQL -U "$PGSUPERUSER" -c "SET ROLE app_user" -c "SELECT count(*) FROM authz.connection_check() WHERE problem LIKE 'this connection logs in as $PGSUPERUSER, %'")
  [ "$got" = 1 ] && ok "... and a superuser's" || bad "superuser as app role" "$got"
  # (only a superuser may make a role with BYPASSRLS)
  psql -X -q -U "$PGSUPERUSER" -d postgres -c "DROP ROLE IF EXISTS authz_sess_bypass" \
    -c "CREATE ROLE authz_sess_bypass LOGIN BYPASSRLS IN ROLE app_user" >/dev/null 2>&1
  ROLE=authz_sess_bypass expect "a login in the app role with BYPASSRLS: an error, and the only one" \
    "error: authz_sess_bypass has BYPASSRLS: row-level security does not apply to it" \
    -c "SELECT string_agg(severity || ': ' || problem, '; ') FROM authz.connection_check()"
  # BYPASSRLS without being a superuser is enough to be an administrator after SET ROLE
  ROLE=authz_sess_bypass expect "... and after SET ROLE app_user, that it logs in as an administrator" "1" -c "SET ROLE app_user" \
    -c "SELECT count(*) FROM authz.connection_check() WHERE problem LIKE 'this connection logs in as authz_sess_bypass, %'"
  psql -X -q -U "$PGSUPERUSER" -d postgres -c "DROP ROLE IF EXISTS authz_sess_bypass" >/dev/null 2>&1
fi
expect "a login in the app role: no errors" "0" -c "SELECT count(*) FROM authz.connection_check() WHERE severity = 'error'"
expect "... nor after SET ROLE app_user" "0" -c "SET ROLE app_user" -c "SELECT count(*) FROM authz.connection_check() WHERE severity = 'error'"
# a login in the app role that owns a governed table: FORCE ROW LEVEL SECURITY or not, it may turn it off
PSQL -c "GRANT CREATE ON SCHEMA app TO app_user" -c "ALTER TABLE app.files OWNER TO app_user" -c "ALTER TABLE app.files FORCE ROW LEVEL SECURITY" >/dev/null
expect "a login in the app role that owns a table with rules: an error, FORCE ROW LEVEL SECURITY or not" \
  "$APP owns app.files (or has its owner's rights): an owner skips row-level security, and may turn it off" \
  -c "SELECT string_agg(problem, '; ') FROM authz.connection_check() WHERE severity = 'error'"
# (the owner's privileges go with the table, the app role's own grants with them: given back as app_schema.sql gives them)
PSQL -c "ALTER TABLE app.files NO FORCE ROW LEVEL SECURITY" -c "ALTER TABLE app.files OWNER TO CURRENT_USER" -c "REVOKE CREATE ON SCHEMA app FROM app_user" \
     -c "GRANT SELECT, INSERT, UPDATE, DELETE ON app.files TO app_user" >/dev/null
PSQL -c "ALTER TABLE app.files DISABLE ROW LEVEL SECURITY"
expect "row-level security off on a table with rules: an error" "row-level security is off on app.files: the policy's rules don't apply to it"   -c "SELECT problem FROM authz.connection_check() WHERE severity = 'error'"
PSQL -c "ALTER TABLE app.files ENABLE ROW LEVEL SECURITY"

echo "-- what a function sets lasts its transaction"
# each sets the settings for its own transaction only: the next one has what the session had before (in the
# owner's session, where a setting the session made itself is believed)
after() {   # $1 the settings the session makes, $2 what runs in a transaction: the four settings after it
  PSQL -c "$1" -c "BEGIN" -c "$2" -c "COMMIT" -c "SELECT format('%s|%s|%s|%s|%s', current_setting('authz.user_id', true),
    current_setting('authz.principal_type', true), current_setting('authz.scopes', true),
    current_setting('authz.acting_user', true), current_setting('authz_debug.logging', true))" 2>&1 | tail -n 1
}
SESSION="SET authz.user_id = '9'; SET authz.principal_type = ''; SET authz.scopes = 'read'; SET authz.acting_user = '8'"
KEY=$(PSQL -c "SET authz.user_id = 1" -c "SELECT authz.create_api_key('sessions', 'files')")
while IFS='|' read -r label what; do
  got=$(after "$SESSION" "$what")
  [ "$got" = "9||read|8|" ] && ok "$label: the next transaction has the session's own settings" || bad "$label: after" "$got"
done <<EOF2
act_as|SELECT authz.act_as('user', '3')
login_key|SELECT authz.login_key('$KEY')
check_invariants, signed in as a bot|SET LOCAL authz.user_id = '1'; SET LOCAL authz.principal_type = 'bot'; SELECT count(*) FROM authz.check_invariants()
EOF2
# who, explain and the policy tests switch who is signed in while they ask, then put back the transaction's own: in a
# session signed in as a service and a transaction as a user, the next transaction is the service's again
# (the policy tests' function alone: the block that reports them raises when one fails, which undoes everything)
python3 compile_policy.py example/docs.authz --tests | sed '/^DO \$t\$/,$d' > "$T/tests.sql" || exit 1
BOT="SET authz.user_id = '9'; SET authz.principal_type = 'bot'; SET authz.scopes = 'read'; SET authz.acting_user = '8'"
AS_ERIN="SET LOCAL authz.user_id = '5'; SET LOCAL authz.principal_type = ''; SET LOCAL authz.scopes = ''"
while IFS='|' read -r label what; do
  got=$(after "$BOT" "$AS_ERIN; $what")
  [ "$got" = "9|bot|read|8|" ] && ok "$label: the next transaction has the session's own settings" || bad "$label: after" "$got"
done <<EOF2
who|SELECT count(*) FROM authz.who('folder', '1', 'view')
explain, for another user|SELECT count(*) FROM authz.explain('folder', '1', 'view', '3')
EOF2
got=$(PSQL -c "$BOT" -c "BEGIN" -c "$AS_ERIN" -f "$T/tests.sql" \
  -c "SELECT count(*) FROM pg_temp.authz_policy_tests()" -c "COMMIT" -c "SELECT format('%s|%s|%s|%s',
  current_setting('authz.user_id', true), current_setting('authz.principal_type', true), current_setting('authz.scopes', true),
  current_setting('authz.acting_user', true))" 2>/dev/null | tail -n 1)
[ "$got" = "9|bot|read|8" ] && ok "the policy tests: the next transaction has the session's own settings" ||
  bad "the policy tests: after" "$got"
# ... and the transaction itself goes on as it was: the same principal, scopes and acting user
got=$(PSQL -c "$BOT" -c "BEGIN" -c "SET LOCAL authz.user_id = '1'; SET LOCAL authz.scopes = 'files'" \
  -c "SELECT count(*) FROM authz.check_invariants()" -c "SELECT format('%s|%s|%s|%s', current_setting('authz.user_id', true),
  current_setting('authz.principal_type', true), current_setting('authz.scopes', true),
  current_setting('authz.acting_user', true))" -c "COMMIT" 2>&1 | tail -n 1)
[ "$got" = "1|bot|files|8" ] && ok "check_invariants, signed in as a service: the transaction goes on as that service" ||
  bad "check_invariants: within" "$got"
got=$(PSQL -c "$BOT" -c "BEGIN" -c "$AS_ERIN" -c "SELECT count(*) > 0 FROM authz.explain('folder', '1', 'view', '3')" \
  -c "SELECT format('%s|%s', current_setting('authz.user_id', true), current_setting('authz.principal_type', true))" \
  -c "SELECT count(*) FROM authz.who('folder', '1', 'view') WHERE false" \
  -c "SELECT format('%s|%s', current_setting('authz.user_id', true), current_setting('authz.principal_type', true))" -c "COMMIT" 2>&1 |
  paste -sd' ')
[ "$got" = "t 5| 0 5|" ] && ok "explain for another user, then who: the transaction goes on as its own user" || bad "explain and who: within" "$got"
got=$(after "SET authz_debug.log_decisions = on" "SELECT authz.can('file', '11', 'view')")
[ "${got##*|}" != on ] && ok "the decision log: the next transaction's decisions are logged too" || bad "decision log after" "$got"
# a session that never set any: nobody acted, and a refused write says so
got=$(PSQL -c "SELECT authz_int.actor() IS NULL" -c "SET authz.principal_type = 'bot'" -c "SELECT authz_int.actor() IS NULL")
[ "$got" = "$(printf 't\nt')" ] && ok "nothing set in the session (or a principal type alone): nobody acted, and no error" ||
  bad "actor, nothing set" "$got"
got=$(PSQL -c "SET ROLE app_user" -c "INSERT INTO app.files (folder_id, name) VALUES (1, 'x')" 2>&1 | head -n 1)
[ "$got" = "ERROR:  permission denied: someone not signed in may not insert this row into app.files" ] &&
  ok "... and an insert refused says someone not signed in may not" || bad "a refusal, nothing set" "$got"

echo "-- who may sign in whom"
expect "the key is out of the app role's reach" "42501: permission denied for table settings" -c "SELECT value FROM authz.settings WHERE key = 'session_key'"
expect "... and so is the signing" "42501: permission denied for schema authz_int" -c "SELECT authz_int.session_sig()"
ROLE=$OTHER expect "a role that isn't the app role can't act_as" "42501: permission denied for function act_as" -c "$(ACT "'user', '1'")"
expect "act_as names only types that sign in" "P0001: folder is not a type that signs in" -c "$(ACT "'folder', '1'")"

# (taking the grant back makes the function's catalog row anew, and with it the statements the run measures: they
# are kept first; tests/coverage_functions.sh)
bash tests/coverage_functions.sh "$DB"
PSQL -c "REVOKE ALL ON SCHEMA app, authz FROM $OTHER" -c "REVOKE ALL ON FUNCTION authz.connection_check() FROM $OTHER" >/dev/null 2>&1
[ $fails -eq 0 ] && echo "sessions: all passed" || { echo "sessions: $fails failed"; exit 1; }
