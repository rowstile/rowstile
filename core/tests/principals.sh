#!/bin/bash
# principals.sh: services that sign in as themselves: principal types, their keys and
# JWTs, service:* next to user:*, signed_in staying about users, and what the audit trail records.
#   PGHOST=... PGPORT=... PGUSER=authz_owner tests/principals.sh [database]
set -u
cd "$(dirname "$0")/.."
DB=${1:-authz_principals}
MDB="${DB}_marks" IDB="${DB}_ids"
T=$(mktemp -d)
. tests/races.sh
# whatever way the suite ends: the sessions it left running, its databases, its role, its files
cleanup() {
  stop_sessions
  if [ -z "${KEEP:-}" ]; then
    for d in "$DB" "$MDB" "$IDB"; do dropdb --force --if-exists "$d" 2>/dev/null; done
    psql -X -q -d postgres -c "DROP ROLE IF EXISTS authz_principals_other" >/dev/null 2>&1
  fi
  rm -rf "$T"
}
trap cleanup EXIT
dropdb --if-exists "$DB" 2>/dev/null; createdb "$DB" || exit 1
fails=0
PSQL() { psql -X -q -At -v ON_ERROR_STOP=1 -d "$DB" "$@"; }
check() {   # $1 label, $2 expected, $3 SQL (run as app_user)
  got=$(PSQL -c "SET ROLE app_user;" -c "$3" 2>&1 | tail -n 1)
  if [ "$got" = "$2" ]; then echo "ok    $1"; else echo "FAIL  $1: expected '$2', got '$got'"; fails=$((fails + 1)); fi
}
state() { psql -X -q -At -d "$DB" -c "SET ROLE app_user;" "$@" 2>&1 | tail -n 1; }
. tests/words.sh
expect_code() {  # $1 label, $2 expected "SQLSTATE: the message's words" (or ok), rest: -c statements
  local label=$1 want=$2; shift 2
  got=$(psql -X -q -At -d "$DB" -v VERBOSITY=verbose -c "SET ROLE app_user;" "$@" 2>&1 | grep '^ERROR:  ' | tail -n 1)
  got=${got#ERROR:  }; got=${got:-ok}
  if agrees "$label" "$want" "$got"; then echo "ok    $label"; else echo "FAIL  $label: expected $want, got $got"; fails=$((fails + 1)); fi
}
# $1 label, $2 the sign-in, $3 a call that fails after it switched who is signed in, $4 its error ("SQLSTATE: words"):
# caught at a savepoint, the transaction goes on signed in exactly as before (Postgres undoes what the call set)
SETTINGS="concat_ws('|', current_setting('authz.user_id', true), current_setting('authz.principal_type', true),
  current_setting('authz.scopes', true), current_setting('authz.acting_user', true), current_setting('authz.session', true))"
caught() {
  local out err
  out=$(psql -X -q -At -d "$DB" -v VERBOSITY=verbose 2>&1 <<SQL
BEGIN;
$2;
SELECT $SETTINGS AS before \gset
SAVEPOINT s;
$3;
ROLLBACK TO SAVEPOINT s;
SELECT ($SETTINGS) = :'before' AND authz.uid() IS NOT NULL;
COMMIT;
SQL
)
  err=$(printf '%s\n' "$out" | grep '^ERROR:  ' | head -n 1)
  if agrees "$1" "$4" "${err#ERROR:  }" && [ "$(printf '%s\n' "$out" | tail -n 1)" = t ]; then echo "ok    $1"
  else echo "FAIL  $1: $out"; fails=$((fails + 1)); fi
}
AS_SVC="SET authz.user_id = '7'; SET authz.principal_type = 'service';"
AS_USER="SET authz.user_id = '1'; SET authz.principal_type = '';"

PGOPTIONS="-c client_min_messages=warning" PSQL <<'SQL' >/dev/null || exit 1
DO $$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'app_user') THEN CREATE ROLE app_user NOLOGIN; END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'authz_principals_other') THEN CREATE ROLE authz_principals_other NOLOGIN; END IF;
END $$;
CREATE SCHEMA ps;
CREATE TABLE ps.users (id bigint PRIMARY KEY, support_id bigint);
CREATE TABLE ps.services (id bigint PRIMARY KEY, owner_id bigint REFERENCES ps.users, active boolean NOT NULL DEFAULT true);
CREATE TABLE ps.teams (id bigint PRIMARY KEY);
CREATE TABLE ps.team_members (team_id bigint REFERENCES ps.teams, user_id bigint REFERENCES ps.users, PRIMARY KEY (team_id, user_id));
CREATE TABLE ps.team_services (team_id bigint REFERENCES ps.teams, service_id bigint REFERENCES ps.services,
  PRIMARY KEY (team_id, service_id));
CREATE TABLE ps.docs (id bigint PRIMARY KEY, owner_id bigint, bot_id bigint, body text);
CREATE TABLE ps.albums (id bigint PRIMARY KEY, owner_id bigint, keeper_type text, keeper_id bigint);
INSERT INTO ps.users VALUES (1), (2), (3);
INSERT INTO ps.services VALUES (7, 1, true), (8, 2, true), (9, 1, false);
INSERT INTO ps.teams VALUES (1);
INSERT INTO ps.team_services VALUES (1, 8);
INSERT INTO ps.docs VALUES (1, 1, 7, 'bot 7 keeps this'), (2, 2, NULL, 'shared with team 1'),
  (3, 2, NULL, 'shared with every service'), (4, 2, NULL, 'shared with every user'), (5, 3, NULL, 'nobody else');
INSERT INTO ps.albums VALUES (1, 2, 'service', 7), (2, 2, 'user', 3);
GRANT USAGE ON SCHEMA ps TO app_user, authz_principals_other;
GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA ps TO app_user;
SQL
cat > $T/principals.authz <<'POLICY'
app role app_user
type user = ps.users
  support : service = support_id         -- a service the policy lets view as this user
  can impersonate = support
type service = ps.services principal where {active}
  owner : user = owner_id
  can manage_keys = owner
type team = ps.teams
  member : user    = ps.team_members(team_id -> user_id)
  member : service = ps.team_services(team_id -> service_id)
  can manage_roles = member              -- service 8 is a member: the roles API is still for users
type doc = ps.docs
  owner  : user    = owner_id
  bot    : service = bot_id
  reader : user, service, team#member, user:*, service:*  shared
  can share = owner or bot
  can edit  = owner or bot
  roles  : user
  can view  = edit or reader or roles
  can break_glass = bot
  helper : user  shared by view          -- any viewer may name a helper, if they may assist themselves
  can assist = owner or helper
type album = ps.albums                   -- custom roles, and no share permission: nobody may give them but an admin
  owner : user = owner_id
  keeper : user, service = (keeper_type, keeper_id)   -- a user or a service, by a pair of columns
  fan    : user  shared by view          -- shared by whoever views it: it has no share permission still
  roles : user
  can view = owner or roles or keeper
rules ps.docs
  select : view
  update : edit
  update owner_id : bot                  -- the doc's bot hands it over: a rule on a column that names a service
  insert : signed_in and {owner_id = authz.uid()}
invariants
  never doc: edit and not owner
  never doc: not view             -- everyone, signed in or not, lacks view on something: broken on purpose
POLICY
python3 compile_policy.py $T/principals.authz > $T/principals.sql || exit 1
PGOPTIONS="-c client_min_messages=error" psql -X -q -v ON_ERROR_STOP=1 -d "$DB" -f $T/principals.sql >/dev/null || exit 1
PSQL -c "SET authz.user_id = '2'" -c "SELECT authz.share('doc', 2, 'reader', 'team', 1, 'member')" \
     -c "SELECT authz.share('doc', 3, 'reader', 'service', '*')" -c "SELECT authz.share('doc', 4, 'reader', 'user', '*')" >/dev/null

echo "-- signed in as a service"
check "authz.uid() is no one; authz.principal() is service 7" "|service|7" \
  "$AS_SVC SELECT authz.uid() || '', (SELECT principal_type || '|' || principal_id FROM authz.principal());"
check "a column naming it, every service, not users' shares" "1,3" \
  "$AS_SVC SELECT string_agg(id::text, ',' ORDER BY id) FROM ps.docs;"
check "through a team it is a member of" "2,3" \
  "SET authz.user_id = '8'; SET authz.principal_type = 'service'; SELECT string_agg(x, ',' ORDER BY x) FROM authz.list('doc', 'view') x;"
check "a service failing the type's where is nobody" "0|" \
  "SET authz.user_id = '9'; SET authz.principal_type = 'service'; SELECT (SELECT count(*) FROM ps.docs) || '|' || coalesce((SELECT principal_id FROM authz.principal()), '');"
check "users keep user:* and don't get service:*" "1,4" "$AS_USER SELECT string_agg(id::text, ',' ORDER BY id) FROM ps.docs;"
check "the same id as another type is someone else" "f" \
  "SET authz.user_id = '1'; SET authz.principal_type = 'service'; SELECT authz.can('doc', 1, 'view');"
expect_code "signed_in stays about users: a service can't insert" "42501: permission denied: service 7 may not insert this row into ps.docs" -c "$AS_SVC" \
  -c "INSERT INTO ps.docs VALUES (10, NULL, NULL, 'x')"
check "it edits what it may edit" "1" "$AS_SVC WITH u AS (UPDATE ps.docs SET body = 'edited by bot' WHERE id = 1 RETURNING 1) SELECT count(*) FROM u;"
check "explain names it" "yes  service 7 holds edit on doc 1" "$AS_SVC SELECT e FROM authz.explain('doc', 1, 'edit') e LIMIT 1;"
expect_code "it can't have user 7's access explained on what it can't share (the same id, another type)" "42501: you cannot inspect access to doc 5" \
  -c "$AS_SVC" -c "SELECT authz.explain('doc', 5, 'view', '7')"
check "a user may have their own explained, by id" "yes  user 1 holds view on doc 1" \
  "$AS_USER SELECT e FROM authz.explain('doc', 1, 'view', '1') e LIMIT 1;"
check "... and by id, a doc they can't see reads as a missing one" "no   you have no access to doc 5" \
  "$AS_USER SELECT string_agg(e, ' / ') FROM authz.explain('doc', 5, 'view', '1') e;"
# a relation held by a pair of columns: explain names both, the type's column first
check "explain names both columns of a pair that holds a service, as you" "yes  keeper: (keeper_type, keeper_id) is you" \
  "$AS_SVC SELECT btrim(e) FROM authz.explain('album', 1, 'view') e WHERE e LIKE '%keeper:%';"
check "... and of one that holds a user" "yes  keeper: (keeper_type, keeper_id) is you" \
  "SET authz.user_id = '3'; SET authz.principal_type = ''; SELECT btrim(e) FROM authz.explain('album', 2, 'view') e WHERE e LIKE '%keeper:%';"
check "it shares as itself: created_by says so" "service:7" \
  "$AS_SVC SELECT authz.share('doc', 1, 'reader', 'user', 3); SELECT created_by FROM authz.list_shares('doc', 1) WHERE subject_id = '3';"
check "the audit trail says so too" "service:7" \
  "RESET ROLE; SELECT user_id FROM authz.audit WHERE action = 'share' AND object_id = '1' ORDER BY id DESC LIMIT 1;"
got=$(PSQL -c "SET ROLE app_user; SET client_min_messages = log; SET authz_debug.log_decisions = on; $AS_SVC SELECT authz.can('doc', 1, 'view');" 2>&1 |
      grep -o 'authz decision: .*')
[ "$got" = 'authz decision: user="service:7" type="doc" id="1" perm="view" -> true' ] &&
  echo "ok    the decision log names it as the audit trail does, not as user 7" ||
  { echo "FAIL  the decision log names a service: $got"; fails=$((fails + 1)); }
check "authz.who lists users" "1,3" "RESET ROLE; SELECT string_agg(x, ',' ORDER BY x) FROM authz.who('doc', 1, 'view') x;"
expect_code "a role the policy doesn't govern can't sign in as a service" "42501: permission denied for schema authz" -c "RESET ROLE" -c "SET ROLE authz_principals_other" \
  -c "SELECT authz.act_as('service', '7')"

check "invariants are asked as each service too, named as the audit trail names it" "service:7|{1}"   "RESET ROLE; SELECT string_agg(user_id || '|' || object_ids::text, ' ') FROM authz.check_invariants() WHERE invariant LIKE 'never doc: edit and not owner%';"
check "... and as nobody: the row with no user" "1"   "RESET ROLE; SELECT count(*) FROM authz.check_invariants() WHERE user_id IS NULL AND invariant LIKE 'never doc: not view%';"
check "... in that order: nobody, the users, then the other principals" "nobody 1 2 3 service:7 service:8 service:9" \
  "RESET ROLE; SELECT string_agg(coalesce(user_id, 'nobody'), ' ') FROM authz.check_invariants() WHERE invariant LIKE 'never doc: not view%';"
# a rule on a column is checked by a trigger, which runs as the app role and reads its text then: the signed-in
# service (authz_int."service__me") is not the app role's to name, so the rule is behind a function made once
check "a rule on a column that names a service: the service it names changes the column" "1" \
  "$AS_SVC BEGIN; WITH u AS (UPDATE ps.docs SET owner_id = 2 WHERE id = 1 RETURNING 1) SELECT count(*) FROM u; ROLLBACK;"
got=$(psql -X -q -At -d "$DB" -c "SET ROLE app_user" -c "SET authz.user_id = '1'" -c "UPDATE ps.docs SET owner_id = 2 WHERE id = 1" 2>&1)
case "$got" in *"changing owner_id of ps.docs 1 needs: bot"*) echo "ok    ... and the owner, who may update the doc, is refused by the rule, in its words";;
  *) echo "FAIL  the rule on owner_id, as the owner: $got"; fails=$((fails + 1));; esac
# sharing gives what the relation grants: the sharer must hold it, beside the permission to share
got=$(psql -X -q -At -d "$DB" -c "SET ROLE app_user" -c "SET authz.user_id = '3'" -c "SELECT authz.share('doc', 1, 'helper', 'user', 2)" 2>&1)
case "$got" in *"you cannot grant doc.helper on doc 1: you do not hold assist"*) echo "ok    a viewer may share helper, but not grant assist, which they don't hold";;
  *) echo "FAIL  sharing what the sharer doesn't hold: $got"; fails=$((fails + 1));; esac
check "the owner holds it, and may" "1" "$AS_USER SELECT authz.share('doc', 1, 'helper', 'user', 2); SELECT count(*) FROM authz.list_shares('doc', 1) WHERE relation = 'helper';"
# each relation is shared by its own permission: this viewer holds the one that shares helper (view) and
# everything reader gives, and still may not share reader, which takes share
got=$(psql -X -q -At -d "$DB" -c "SET ROLE app_user" -c "SET authz.user_id = '3'" -c "SELECT authz.share('doc', 1, 'reader', 'user', 2)" 2>&1)
case "$got" in *"you cannot share doc 1 (needs share)"*) echo "ok    ... and may not share reader, which another permission shares";;
  *) echo "FAIL  sharing a relation by the permission that shares another: $got"; fails=$((fails + 1));; esac
got=$(psql -X -q -At -d "$DB" -f <(python3 compile_policy.py $T/principals.authz --tests) 2>&1)
case "$got" in *"FAIL  invariant never doc: edit and not owner"*": service 7 can reach {1}"*) echo "ok    ... and the policy tests say which service";;
  *) echo "FAIL  the policy tests on a service breaking an invariant: $got"; fails=$((fails + 1));; esac

echo "-- what is for users: a service is refused, saying so, though the policy gives it the permission"
PSQL -c "INSERT INTO ps.team_members VALUES (1, 2)" -c "UPDATE ps.users SET support_id = 7 WHERE id = 3" >/dev/null
AS_SVC8="SET authz.user_id = '8'; SET authz.principal_type = 'service';"
check "service 8 holds manage_roles on team 1" "t" "$AS_SVC8 SELECT authz.can('team', 1, 'manage_roles');"
check "service 7 holds break_glass and share on doc 1, and impersonate on user 3" "t|t|t" \
  "$AS_SVC SELECT authz.can('doc', 1, 'break_glass'), authz.can('doc', 1, 'share'), authz.can('user', 3, 'impersonate');"
ROLE=$(state -c "SET authz.user_id = '2'" -c "SELECT authz.create_role('team', 1, 'doc', 'reviewer', ARRAY['view'])")
REQ=$(state -c "SET authz.user_id = '3'" -c "SELECT authz.request_access('doc', 1, 'reader', 'to read it')")
check "a user who holds manage_roles makes a role; another asks for access" "1|1" "SELECT '$ROLE|$REQ';"
expect_code "authz.create_role is for users: a service is told so" \
  "42501: authz.create_role is for users, not services (service 8 is signed in)" -c "$AS_SVC8" -c "SELECT authz.create_role('team', 1, 'doc', 'mine', ARRAY['view'])"
expect_code "authz.set_role_permissions is for users: a service is told so" \
  "42501: authz.set_role_permissions is for users, not services (service 8 is signed in)" -c "$AS_SVC8" -c "SELECT authz.set_role_permissions($ROLE, ARRAY['view'])"
expect_code "authz.delete_role is for users: a service is told so" \
  "42501: authz.delete_role is for users, not services (service 8 is signed in)" -c "$AS_SVC8" -c "SELECT authz.delete_role($ROLE)"
expect_code "authz.roles_of is for users: a service is told so" \
  "42501: authz.roles_of is for users, not services (service 8 is signed in)" -c "$AS_SVC8" -c "SELECT * FROM authz.roles_of('team', 1)"
expect_code "authz.request_access is for users: a service is told so" \
  "42501: authz.request_access is for users, not services (service 7 is signed in)" -c "$AS_SVC" -c "SELECT authz.request_access('doc', 5, 'reader', 'to read it')"
expect_code "authz.pending_requests is for users: a service is told so" \
  "42501: authz.pending_requests is for users, not services (service 7 is signed in)" -c "$AS_SVC" -c "SELECT * FROM authz.pending_requests()"
expect_code "authz.decide_request is for users: a service is told so" \
  "42501: authz.decide_request is for users, not services (service 7 is signed in)" -c "$AS_SVC" -c "SELECT authz.decide_request($REQ, true)"
expect_code "authz.cancel_request is for users: a service is told so" \
  "42501: authz.cancel_request is for users, not services (service 7 is signed in)" -c "$AS_SVC" -c "SELECT authz.cancel_request($REQ)"
expect_code "authz.break_glass is for users: a service is told so" \
  "42501: authz.break_glass is for users, not services (service 7 is signed in)" -c "$AS_SVC" -c "SELECT authz.break_glass('doc', 1, 'reader', 'an outage')"
expect_code "authz.create_api_key for oneself is for users: a service is told so" \
  "42501: authz.create_api_key for oneself is for users, not services (service 7 is signed in)" -c "$AS_SVC" -c "SELECT authz.create_api_key('mine')"
expect_code "authz.view_as is for users: a service is told so" \
  "42501: authz.view_as is for users, not services (service 7 is signed in)" -c "$AS_SVC" -c "SELECT authz.view_as('3', 'ticket 12')"
REV=$(state -c "$AS_USER" -c "SELECT authz.start_review('doc', 1)")
check "its owner starts a review of doc 1 and reads its items" "$REV|2" \
  "$AS_USER SELECT '$REV|' || (SELECT count(*) FROM authz.review_items($REV));"
check "... and service 7 may share doc 1 too" "t" "$AS_SVC SELECT authz.can('doc', 1, 'share');"
expect_code "authz.review_items is for users: a service is told so" \
  "42501: authz.review_items is for users, not services (service 7 is signed in)" -c "$AS_SVC" -c "SELECT * FROM authz.review_items($REV)"
expect_code "authz.start_review is for users: a service is told so" \
  "42501: authz.start_review is for users, not services (service 7 is signed in)" -c "$AS_SVC" -c "SELECT authz.start_review('doc', 1)"
expect_code "authz.review_decide is for users: a service is told so" \
  "42501: authz.review_decide is for users, not services (service 7 is signed in)" -c "$AS_SVC" -c "SELECT authz.review_decide($REV, 1, false)"
expect_code "authz.close_review is for users: a service is told so" \
  "42501: authz.close_review is for users, not services (service 7 is signed in)" -c "$AS_SVC" -c "SELECT authz.close_review($REV, true)"
check "... and the review is as it was: one, open, nothing decided, every share still there" "1|open|0|2" \
  "RESET ROLE; SELECT (SELECT count(*) FROM authz.reviews) || '|' || (SELECT CASE WHEN closed_at IS NULL THEN 'open' ELSE 'closed' END
     FROM authz.reviews WHERE id = $REV) || '|' || (SELECT count(*) FROM authz.review_items WHERE review_id = $REV AND keep IS NOT NULL)
     || '|' || (SELECT count(*) FROM authz.shares WHERE object_type = 'doc' AND object_id = '1');"
got=$(PSQL -v VERBOSITY=verbose -c "SET ROLE app_user" -c "$AS_SVC" -c "SELECT authz.break_glass('doc', 1, 'reader', 'an outage')" 2>&1)
case "$got" in *"HINT:  rowstile help AZ715"*) echo "ok    ... with its code, AZ715";;
  *) echo "FAIL  the code of a call that is for users: $got"; fails=$((fails + 1));; esac
check "... and nothing changed: the role and the request are as they were, no key, no break-glass or view-as" \
  "reviewer {view}|pending|1|0|0" \
  "RESET ROLE; SELECT (SELECT name || ' ' || (SELECT array_agg(permission)::text FROM authz.role_permissions WHERE role_id = $ROLE)
       FROM authz.roles WHERE id = $ROLE) || '|' || (SELECT status FROM authz.requests WHERE id = $REQ)
     || '|' || (SELECT count(*) FROM authz.requests) || '|' || (SELECT count(*) FROM authz.api_keys WHERE name = 'mine')
     || '|' || (SELECT count(*) FROM authz.audit WHERE action IN ('view_as', 'break_glass'));"
check "a user still decides the request" "approved" \
  "SET authz.user_id = '1'; SELECT authz.decide_request($REQ, true); RESET ROLE; SELECT status FROM authz.requests WHERE id = $REQ;"

echo "-- a custom role, given"
# alice, doc 1's owner, gives the team's reviewer role to user 2: explain says which role the view comes through
PSQL -c "SET ROLE app_user" -c "SET authz.user_id = '1'" -c "SELECT authz.share('doc', 1, 'role:$ROLE', 'user', 2)" >/dev/null
check "explain names the custom role a permission comes through" "yes  a custom role given to you (by 1) (role reviewer)" \
  "SET authz.user_id = '2'; SELECT btrim(e) FROM authz.explain('doc', 1, 'view') e WHERE e LIKE '%custom role given%';"
expect_code "viewing as someone, the role's permissions can't be changed" \
  "42501: this session is read-only (viewing as someone else, or a read-only token)" \
  -c "SET authz.user_id = '2'; SET authz.acting_user = '9'" -c "SELECT authz.set_role_permissions($ROLE, ARRAY['view'])"
PSQL -c "SET ROLE app_user" -c "SET authz.user_id = '1'" -c "SELECT authz.unshare('doc', 1, 'role:$ROLE', 'user', 2)" >/dev/null
# a role on albums, which have no share permission, though docs do: nobody may ask for it
AROLE=$(state -c "SET authz.user_id = '2'" -c "SELECT authz.create_role('team', 1, 'album', 'looker', ARRAY['view'])")
expect_code "a role on a type with no share permission can't be asked for" \
  "P0001: the policy does not allow sharing album.role:$AROLE with a user" \
  -c "SET authz.user_id = '3'" -c "SELECT authz.request_access('album', 1, 'role:$AROLE', 'to look')"
expect_code "... nor given, even by the album's owner, who may share its fans: nobody holds a share permission the type hasn't" \
  "42501: you cannot share album 1" -c "SET authz.user_id = '2'" -c "SELECT authz.share('album', 1, 'role:$AROLE', 'user', 3)"

echo "-- whoever signs in is a row of their type"
PSQL -c "INSERT INTO ps.docs VALUES (20, 99, 77, 'its owner and its bot are gone')" >/dev/null
AS_GONE="SET authz.user_id = '99'; SET authz.principal_type = '';"
check "an id the user table doesn't have is nobody: no uid, no principal" "|"   "$AS_GONE SELECT coalesce(authz.uid()::text, '') || '|' || coalesce((SELECT principal_id FROM authz.principal()), '');"
check "... so a column that still names it grants nothing, nor does user:*" "false|0"   "$AS_GONE SELECT authz.can('doc', 20, 'edit')::text || '|' || (SELECT count(*) FROM ps.docs);"
check "... and the same for a service its table doesn't have" "false|0"   "SET authz.user_id = '77'; SET authz.principal_type = 'service'; SELECT authz.can('doc', 20, 'edit')::text || '|' || (SELECT count(*) FROM ps.docs);"
PSQL -c "INSERT INTO ps.users VALUES (99)" >/dev/null
check "once the row is there, they are someone" "99|true" "$AS_GONE SELECT authz.uid() || '|' || authz.can('doc', 20, 'edit')::text;"
check "an administrator whose session names a service the table doesn't have views as a user: as that user" "3|user:3" \
  "RESET ROLE; BEGIN; SET LOCAL authz.user_id = '77'; SET LOCAL authz.principal_type = 'service';
   SELECT authz.view_as('3', 'ticket 13');
   SELECT authz.uid() || '|' || (SELECT principal_type || ':' || principal_id FROM authz.principal()); ROLLBACK;"
# view_as signs in for its transaction only: a session set to the service names it again once that one ends
got=$(PSQL -c "SET authz.user_id = '77'" -c "SET authz.principal_type = 'service'" -c "BEGIN" \
  -c "SELECT authz.view_as('3', 'ticket 14')" -c "COMMIT" \
  -c "SELECT current_setting('authz.principal_type') || ':' || current_setting('authz.user_id')" 2>&1 | tail -n 1)
[ "$got" = "service:77" ] && echo "ok    ... and once its transaction ends, the session names the service again" ||
  { echo "FAIL  the session after a view_as transaction: $got"; fails=$((fails + 1)); }
# a share to someone goes with their row: a new row with the same id later must not find it
PSQL -c "SET authz.user_id = '1'" -c "SELECT authz.share('doc', 1, 'reader', 'user', 99)" >/dev/null
before=$(PSQL -c "SELECT count(*) FROM authz.shares WHERE subject_type = 'user' AND subject_id = '99'")
PSQL -c "DELETE FROM ps.docs WHERE id = 20" -c "DELETE FROM ps.users WHERE id = 99" >/dev/null
[ "$before" = 1 ] && [ "$(PSQL -c "SELECT count(*) FROM authz.shares WHERE subject_type = 'user' AND subject_id = '99'")" = 0 ] &&
  echo "ok    deleting a user deletes the shares to them" || { echo "FAIL  shares to a deleted user: $before before"; fails=$((fails + 1)); }

echo "-- keys for services"
KEY=$(state -c "$AS_USER" -c "SELECT authz.create_api_key('deploy', '', NULL, 'service', '7')")
case "$KEY" in ak_*) echo "ok    its owner makes service 7 a key";; *) echo "FAIL  key: $KEY"; fails=$((fails + 1));; esac
check "the key signs in as the service" "service:7|service|7|" \
  "BEGIN; SELECT authz.login_key('$KEY') || '|' || (SELECT principal_type || '|' || principal_id FROM authz.principal()) || '|' || coalesce(authz.uid()::text, ''); COMMIT;"
expect_code "someone else may not" "42501: you cannot manage the keys of service 7" -c "SET authz.user_id = '2'" -c "SELECT authz.create_api_key('x', '', NULL, 'service', '7')"
expect_code "nor for a type that doesn't sign in" "P0001: no type doc that signs in (type ... principal) in the policy" -c "$AS_USER" -c "SELECT authz.create_api_key('x', '', NULL, 'doc', '1')"
check "the owner lists its keys" "deploy" "$AS_USER SELECT string_agg(name, ',') FROM authz.list_api_keys('service', '7');"
check "the service lists its own" "deploy" "$AS_SVC SELECT string_agg(name, ',') FROM authz.list_api_keys();"
PSQL -c "UPDATE ps.services SET active = true WHERE id = 9" >/dev/null
KEY9=$(state -c "$AS_USER" -c "SELECT authz.create_api_key('old', '', NULL, 'service', '9')")
PSQL -c "UPDATE ps.services SET active = false WHERE id = 9" >/dev/null
check "a key was made while it was active" "ak_" "SELECT left('$KEY9', 3);"
expect_code "a key of an inactive service doesn't sign in" "28000: invalid API key" -c "BEGIN" -c "SELECT authz.login_key('$KEY9')"
caught "... caught at a savepoint: who was signed in before still is" "SELECT authz.act_as('user', '1')" \
  "SELECT authz.login_key('$KEY9')" "28000: invalid API key"
KID=$(state -c "$AS_USER" -c "SELECT id FROM authz.list_api_keys('service', '7')")
PSQL -c "SET ROLE app_user; $AS_USER SELECT authz.revoke_api_key($KID)" >/dev/null
expect_code "the owner revoked it" "28000: invalid API key" -c "BEGIN" -c "SELECT authz.login_key('$KEY')"

echo "-- a principal's keys go with its row"
PSQL -c "INSERT INTO ps.users VALUES (98), (94), (97)" -c "INSERT INTO ps.services VALUES (97, 1, true), (96, 1, true), (93, 1, true)" >/dev/null
K98=$(state -c "SET authz.user_id = '98'" -c "SELECT authz.create_api_key('mine')")
state -c "SET authz.user_id = '97'" -c "SELECT authz.create_api_key('mine')" >/dev/null   # user 97, beside service 97
K97=$(state -c "$AS_USER" -c "SELECT authz.create_api_key('deploy', '', NULL, 'service', '97')")
K96=$(state -c "$AS_USER" -c "SELECT authz.create_api_key('deploy', '', NULL, 'service', '96')")
keys() { echo "RESET ROLE; SELECT count(*) FROM authz.api_keys WHERE principal_type = '$1' AND user_id = '$2';"; }
check "user 97 lists its own keys, not service 97's" "mine" "SET authz.user_id = '97'; SELECT string_agg(name, ',') FROM authz.list_api_keys();"
PSQL -c "DELETE FROM ps.users WHERE id = 98" -c "DELETE FROM ps.services WHERE id = 97" -c "UPDATE ps.services SET id = 95 WHERE id = 96" >/dev/null
check "... and user 97 keeps its key when service 97 goes" "1" "$(keys user 97)"
check "deleting a user deletes their keys" "0" "$(keys user 98)"
check "... and deleting a service, its keys" "0" "$(keys service 97)"
check "a service given a new id loses its keys, as its shares" "0|0" \
  "RESET ROLE; SELECT (SELECT count(*) FROM authz.api_keys WHERE principal_type = 'service' AND user_id = '96') || '|' || (SELECT count(*) FROM authz.api_keys WHERE principal_type = 'service' AND user_id = '95');"
check "... each in the audit trail" "user 98|service 96|service 97" \
  "RESET ROLE; SELECT string_agg(object_type || ' ' || object_id, '|' ORDER BY object_type DESC, object_id) FROM authz.audit WHERE action = 'delete_api_key';"
PSQL -c "INSERT INTO ps.users VALUES (98)" -c "INSERT INTO ps.services VALUES (97, 1, true), (96, 1, true)" >/dev/null
expect_code "a new user with the old one's id signs in with none of its keys" "28000: invalid API key" -c "BEGIN" -c "SELECT authz.login_key('$K98')"
expect_code "... nor a new service with a deleted one's id" "28000: invalid API key" -c "BEGIN" -c "SELECT authz.login_key('$K97')"
expect_code "... nor one with the id another left" "28000: invalid API key" -c "BEGIN" -c "SELECT authz.login_key('$K96')"
# a key made while its principal is deleted: it waits for the delete, then there is no one to make it for
race
PGAPPNAME=authz_principals_a psql -X -q -d "$DB" -c "BEGIN" -c "DELETE FROM ps.users WHERE id = 94" -c "$HOLD" -c "COMMIT" >/dev/null 2>&1 &
held authz_principals_a
PGAPPNAME=authz_principals_b psql -X -q -At -d "$DB" -v VERBOSITY=verbose -c "SET ROLE app_user" -c "SET authz.user_id = '94'" \
  -c "SELECT authz.create_api_key('late')" > "$T/late.out" 2>&1 &
blocked authz_principals_b
go; wait
got=$(error_of "$(cat "$T/late.out")")
if agrees "a key made while its user is deleted" "42501: sign in to create an API key" "$got"; then
  echo "ok    a key made while its user is deleted waits for the delete, then is refused"
else echo "FAIL  a key made while its user is deleted: expected 42501: sign in to create an API key, got $got"; fails=$((fails + 1)); fi
check "... and no key is left behind" "0" "$(keys user 94)"
# REPEATABLE READ: a delete whose snapshot is older than a key made for the row fails to serialize
race
PGAPPNAME=authz_principals_a psql -X -q -d "$DB" > $T/principals_rr.out 2>&1 <<SQL &
BEGIN ISOLATION LEVEL REPEATABLE READ;
SELECT count(*) FROM ps.teams;
$HOLD;
DELETE FROM ps.services WHERE id = 93;
COMMIT;
SQL
held authz_principals_a
state -c "$AS_USER" -c "SELECT left(authz.create_api_key('deploy', '', NULL, 'service', '93'), 3)" >/dev/null
go; wait
if grep -q "could not serialize access due to concurrent update" $T/principals_rr.out; then
  echo "ok    a delete with an older snapshot than a key made for the service gets a serialization error"
else echo "FAIL  a delete with an older snapshot than a key: $(tr '\n' ' ' < $T/principals_rr.out)"; fails=$((fails + 1)); fi
check "... and the service and its key are both still there" "1|1" \
  "RESET ROLE; SELECT (SELECT count(*) FROM ps.services WHERE id = 93) || '|' || (SELECT count(*) FROM authz.api_keys WHERE principal_type = 'service' AND user_id = '93');"
rm -f $T/principals_rr.out

echo "-- JWTs naming a principal type"
PSQL -c "INSERT INTO authz.settings VALUES ('jwt_secret', 's3cret'), ('jwt_type_claim', 'kind')" >/dev/null
jwt() { python3 - "$@" <<'PY'
import base64, hashlib, hmac, json, sys, time
claims = dict(json.loads(sys.argv[1]), exp=int(time.time()) + 300)
b = lambda d: base64.urlsafe_b64encode(json.dumps(d, separators=(",", ":")).encode()).rstrip(b"=").decode()
msg = b({"alg": "HS256", "typ": "JWT"}) + "." + b(claims)
sig = base64.urlsafe_b64encode(hmac.new(b"s3cret", msg.encode(), hashlib.sha256).digest()).rstrip(b"=").decode()
print(msg + "." + sig)
PY
}
TOKEN=$(jwt '{"sub": "8", "kind": "service"}')
check "a token for service 8" "service:8|2,3" \
  "BEGIN; SELECT authz.login_jwt('$TOKEN') || '|' || (SELECT string_agg(id::text, ',' ORDER BY id) FROM ps.docs); COMMIT;"
TOKEN=$(jwt '{"sub": "1"}')
check "a token without the claim is a user's" "1" "BEGIN; SELECT authz.login_jwt('$TOKEN'); COMMIT;"
TOKEN=$(jwt '{"sub": "1", "kind": "doc"}')
expect_code "a token naming a type that doesn't sign in" "28000: the token names a type that does not sign in" -c "BEGIN" -c "SELECT authz.login_jwt('$TOKEN')"

echo "-- the policy"
bad() {  # $1 label, $2 expected piece of the error, $3 policy
  got=$(printf '%s\n' "$3" | python3 compile_policy.py --check /dev/stdin 2>&1)
  case "$got" in *"$2"*) echo "ok    $1";; *) echo "FAIL  $1: $got"; fails=$((fails + 1));; esac
}
bad "type:* needs a principal type" "doc:* means any signed-in doc, but doc doesn't sign in" \
  "$(sed 's/  reader : user, service, team#member, user:\*, service:\*  shared/  reader : user, doc:*  shared/' $T/principals.authz)"
bad "a principal's key is one column" "the service type signs in, so it needs a key of one column" \
  "$(sed 's/type service = ps.services principal/type service = ps.services (owner_id, id) principal/' $T/principals.authz)"
# a change that reaches only a service is in the preview, named as the audit trail names it
sed 's/^  can assist = owner or helper$/  can assist = owner or helper or bot/' $T/principals.authz > $T/principals_bot.authz
out=$(python3 compile_policy.py $T/principals_bot.authz --diff | PGOPTIONS="-c client_min_messages=error" psql -X -q -At -d "$DB" 2>&1)
case "$out" in *"gains|service:7|doc|permission assist|1"*) echo "ok    the preview lists what a service gains";;
  *) echo "FAIL  the preview of a change for a service: $out"; fails=$((fails + 1));; esac
out=$(python3 compile_policy.py $T/principals_bot.authz --diff --users 1,2 | PGOPTIONS="-c client_min_messages=error" psql -X -q -At -d "$DB" 2>&1)
case "$out" in *service:*|*ERROR*) echo "FAIL  --users 1,2 shows a service: $out"; fails=$((fails + 1));;
  *"== Details (first 200) =="*) echo "ok    ... and --users leaves it out when it names users only";;
  *) echo "FAIL  --users 1,2 gives no preview: $out"; fails=$((fails + 1));; esac
check "lint has no note on a principal type someone can make keys for" "0" \
  "RESET ROLE; SELECT count(*) FROM authz.lint() WHERE object = 'service' AND problem LIKE '%manage_keys%';"

# the keys of a user deleted while no trigger watched (after rowstile remove, before the next apply): applying
# deletes them
PSQL -c "INSERT INTO authz.api_keys (user_id, principal_type, name, prefix, hash) VALUES ('90', 'user', 'left', 'ak_', 'left over')" >/dev/null
# (applying makes rowstile's functions anew, and Postgres's counts of their calls go with the old ones: while the run
# measures what the suites run, they are kept first; tests/coverage_functions.sh)
bash tests/coverage_functions.sh "$DB"
PGOPTIONS="-c client_min_messages=error" psql -X -q -v ON_ERROR_STOP=1 -d "$DB" -f $T/principals.sql >/dev/null
check "applying the policy deletes the keys of a principal whose row is gone" "0" \
  "RESET ROLE; SELECT count(*) FROM authz.api_keys WHERE principal_type = 'user' AND user_id = '90';"
PSQL -c "TRUNCATE ps.services CASCADE" >/dev/null
check "emptying the services' table deletes every service's keys" "0" \
  "RESET ROLE; SELECT count(*) FROM authz.api_keys WHERE principal_type = 'service';"
# teams are named by shares only (a doc given to team 1's members): deleting one takes the shares that name it
check "a doc is shared with team 1's members" "1" "RESET ROLE; SELECT count(*) FROM authz.shares WHERE subject_type = 'team';"
PSQL -c "DELETE FROM ps.team_members WHERE team_id = 1" -c "DELETE FROM ps.teams WHERE id = 1" >/dev/null
check "... and deleting the team takes that share" "0" "RESET ROLE; SELECT count(*) FROM authz.shares WHERE subject_type = 'team';"

echo "-- a row's marks go with it, and only its own"
# A share, a key or a request marks each row it names (authz_int.row_marks), so a delete with an older snapshot fails
# to serialize; the marks go with the row. Here the ids repeat across types, and nothing is shared with a bot: only
# its keys mark its rows, so its keys' trigger alone forgets them.

dropdb --if-exists "$MDB" 2>/dev/null; createdb "$MDB" || exit 1
MPSQL() { psql -X -q -At -v ON_ERROR_STOP=1 -d "$MDB" "$@"; }
PGOPTIONS="-c client_min_messages=warning" MPSQL <<'SQL' >/dev/null || exit 1
CREATE SCHEMA pm;
CREATE TABLE pm.users (id bigint PRIMARY KEY);
CREATE TABLE pm.bots (id bigint PRIMARY KEY, owner_id bigint);
CREATE TABLE pm.notes (id bigint PRIMARY KEY, owner_id bigint);
CREATE TABLE pm.pages (id bigint PRIMARY KEY, owner_id bigint);
INSERT INTO pm.users VALUES (1), (2);
INSERT INTO pm.bots VALUES (1, 1), (2, 1), (3, 1), (4, 1);
INSERT INTO pm.notes VALUES (1, 1), (2, 1);
INSERT INTO pm.pages VALUES (1, 1), (2, 1);
GRANT USAGE ON SCHEMA pm TO app_user;
GRANT SELECT ON ALL TABLES IN SCHEMA pm TO app_user;
SQL
cat > $T/principals_marks.authz <<'POLICY'
app role app_user
type user = pm.users
type bot = pm.bots principal             -- nothing is shared with a bot
  owner : user = owner_id
  can manage_keys = owner
type note = pm.notes
  owner  : user = owner_id
  reader : user shared
  can share = owner
  can view  = owner or reader
type page = pm.pages
  owner  : user = owner_id
  reader : user shared
  can share = owner
  can view  = owner or reader
POLICY
python3 compile_policy.py $T/principals_marks.authz > $T/principals_marks.sql || exit 1
PGOPTIONS="-c client_min_messages=error" MPSQL -f $T/principals_marks.sql >/dev/null || exit 1
MPSQL -c "SET ROLE app_user" -c "SET authz.user_id = '1'" -c "SELECT authz.share('note', 1, 'reader', 'user', 2)" \
  -c "SELECT authz.share('note', 2, 'reader', 'user', 2)" -c "SELECT authz.share('page', 1, 'reader', 'user', 2)" \
  -c "SELECT authz.create_api_key('a', '', NULL, 'bot', '1')" -c "SELECT authz.create_api_key('b', '', NULL, 'bot', '2')" >/dev/null
marks() {   # $1 label, $2 the marks expected, "type id" in order
  got=$(MPSQL -c "SELECT string_agg(type || ' ' || id, ',' ORDER BY type, id) FROM authz_int.row_marks" 2>&1)
  if [ "$got" = "$2" ]; then echo "ok    $1"; else echo "FAIL  $1: expected '$2', got '$got'"; fails=$((fails + 1)); fi
}
marks "a share marks its object and its subject; a key, its principal" "bot 1,bot 2,note 1,note 2,page 1,user 2"
MPSQL -c "DELETE FROM pm.notes WHERE id = 1" >/dev/null
marks "deleting a note takes its marks, not the other notes', nor another type's with its id" "bot 1,bot 2,note 2,page 1,user 2"
MPSQL -c "DELETE FROM pm.bots WHERE id = 1" >/dev/null
marks "deleting a bot (its keys' trigger) takes its marks, not the other bots'" "bot 2,note 2,page 1,user 2"
MPSQL -c "TRUNCATE pm.notes" >/dev/null
marks "emptying the notes takes every note's marks, and no other type's" "bot 2,page 1,user 2"
MPSQL -c "TRUNCATE pm.bots" >/dev/null
marks "emptying the bots (their keys' trigger) takes every bot's marks, and no other type's" "page 1,user 2"
MPSQL -c "INSERT INTO pm.bots VALUES (3, 1), (4, 1)" >/dev/null
# REPEATABLE READ: a delete whose snapshot is older than a key made for the bot fails to serialize, as for a service,
# though no share trigger writes the bot's mark first
RACE_DB=$MDB race
PGAPPNAME=authz_principals_a MPSQL > "$T/marks_rr.out" 2>&1 <<SQL &
BEGIN ISOLATION LEVEL REPEATABLE READ;
SELECT count(*) FROM pm.users;
$HOLD;
DELETE FROM pm.bots WHERE id = 3;
COMMIT;
SQL
RACE_DB=$MDB held authz_principals_a
MPSQL -c "SET ROLE app_user" -c "SET authz.user_id = '1'" -c "SELECT authz.create_api_key('c', '', NULL, 'bot', '3')" >/dev/null 2>&1
RACE_DB=$MDB go; wait
if grep -q "could not serialize access due to concurrent update" "$T/marks_rr.out"; then
  echo "ok    a delete with an older snapshot than a key made for a bot nothing is shared with gets a serialization error"
else echo "FAIL  a bot deleted with an older snapshot than its key: $(tr '\n' ' ' < "$T/marks_rr.out")"; fails=$((fails + 1)); fi
got=$(MPSQL -c "SELECT (SELECT count(*) FROM pm.bots WHERE id = 3) || '|' || (SELECT count(*) FROM authz.api_keys WHERE principal_type = 'bot' AND user_id = '3')")
[ "$got" = "1|1" ] && echo "ok    ... and the bot and its key are both still there" ||
  { echo "FAIL  the bot and its key after the delete: expected 1|1, got $got"; fails=$((fails + 1)); }
rm -f "$T/marks_rr.out"
# READ COMMITTED: a key made for another principal while it is deleted waits for the delete (its row is locked
# first), then there is no one to make it for
RACE_DB=$MDB race
PGAPPNAME=authz_principals_a psql -X -q -d "$MDB" -c "BEGIN" -c "DELETE FROM pm.bots WHERE id = 4" -c "$HOLD" -c "COMMIT" >/dev/null 2>&1 &
RACE_DB=$MDB held authz_principals_a
PGAPPNAME=authz_principals_b psql -X -q -At -d "$MDB" -v VERBOSITY=verbose -c "SET ROLE app_user" -c "SET authz.user_id = '1'" \
  -c "SELECT authz.create_api_key('late', '', NULL, 'bot', '4')" > "$T/late.out" 2>&1 &
RACE_DB=$MDB blocked authz_principals_b
RACE_DB=$MDB go; wait
got=$(grep '^ERROR:  ' "$T/late.out" | tail -n 1)
got=${got#ERROR:  }
if agrees "a key made for a bot while it is deleted waits for the delete, then is refused" \
  "42501: you cannot manage the keys of bot 4" "${got:-ok}"; then
  echo "ok    a key made for a bot while it is deleted waits for the delete, then is refused"
else echo "FAIL  a key made for a bot while it is deleted: expected 42501: you cannot manage the keys of bot 4, got ${got:-ok}"; fails=$((fails + 1)); fi
got=$(MPSQL -c "SELECT count(*) FROM authz.api_keys WHERE principal_type = 'bot' AND user_id = '4'")
[ "$got" = 0 ] && echo "ok    ... and no key is left on the bot that is gone" ||
  { echo "FAIL  keys left on a deleted bot: $got"; fails=$((fails + 1)); }
# a user's key, where users have no manage_keys though bots do: another user can't revoke it
MPSQL -c "SET ROLE app_user" -c "SET authz.user_id = '1'" -c "SELECT authz.create_api_key('mine')" >/dev/null
UKEY=$(MPSQL -c "SELECT id FROM authz.api_keys WHERE name = 'mine'")
got=$(psql -X -q -At -d "$MDB" -v VERBOSITY=verbose -c "SET ROLE app_user" -c "SET authz.user_id = '2'" \
  -c "SELECT authz.revoke_api_key($UKEY)" 2>&1 | grep '^ERROR:  ' | tail -n 1)
got=${got#ERROR:  }
if agrees "a user can't revoke another's key" "P0001: no API key $UKEY of yours" "${got:-ok}"; then
  echo "ok    a user can't revoke another's key, where only bots' keys have a manage_keys permission"
else echo "FAIL  revoking another user's key: expected no API key $UKEY of yours, got ${got:-ok}"; fails=$((fails + 1)); fi
[ -n "${KEEP:-}" ] || dropdb "$MDB"

echo "-- who acted, as the SDKs write it: a user whose id reads like another principal, or like nobody"
# A user is written by their id ('42'), or user:<id> when the id holds ':' or is 'nobody', so the user whose id is
# service:1 is never written as service 1 is, nor the user whose id is nobody as nobody: the audit trail, every
# created_by and decided_by, what the logins return, the invariants and the preview all name them so.

dropdb --if-exists "$IDB" 2>/dev/null; createdb "$IDB" || exit 1
IPSQL() { psql -X -q -At -v ON_ERROR_STOP=1 -d "$IDB" "$@"; }
icheck() {  # $1 label, $2 expected, $3 SQL (as app_user, in one transaction)
  got=$(IPSQL -c "SET ROLE app_user; $3" 2>&1 | tail -n 1)
  if [ "$got" = "$2" ]; then echo "ok    $1"; else echo "FAIL  $1: expected '$2', got '$got'"; fails=$((fails + 1)); fi
}
AS_COLON="SELECT authz.act_as('user', 'service:1');"
AS_NOBODY="SELECT authz.act_as('user', 'nobody');"
AS_42="SELECT authz.act_as('user', '42');"
AS_S1="SELECT authz.act_as('service', '1');"
PGOPTIONS="-c client_min_messages=warning" IPSQL <<'SQL' >/dev/null || exit 1
CREATE SCHEMA pi;
CREATE TABLE pi.users (id text PRIMARY KEY, support_id text);
CREATE TABLE pi.services (id bigint PRIMARY KEY);
CREATE TABLE pi.teams (id bigint PRIMARY KEY, admin_id text);
CREATE TABLE pi.docs (id bigint PRIMARY KEY, owner_id text, oncall_id text);
INSERT INTO pi.users VALUES ('42', 'service:1'), ('service:1', NULL), ('nobody', NULL);
INSERT INTO pi.services VALUES (1);
INSERT INTO pi.teams VALUES (1, 'service:1');
INSERT INTO pi.docs VALUES (1, 'service:1', 'nobody'), (2, 'nobody', 'service:1'), (3, '42', NULL);
GRANT USAGE ON SCHEMA pi TO app_user;
GRANT SELECT ON ALL TABLES IN SCHEMA pi TO app_user;
SQL
cat > $T/principals_ids.authz <<'POLICY'
app role app_user
type user = pi.users (id text)
  support : user = support_id
  can impersonate = support
type service = pi.services principal
type team = pi.teams
  admin : user = admin_id
  can manage_roles = admin
type doc = pi.docs
  owner  : user = owner_id
  oncall : user = oncall_id
  reader : user, service shared
  roles  : user
  can share = owner or reader
  can view  = owner or reader or roles
  can break_glass = oncall
rules pi.docs
  select : view
invariants
  never doc: reader and not owner
POLICY
python3 compile_policy.py $T/principals_ids.authz > $T/principals_ids.sql || exit 1
PGOPTIONS="-c client_min_messages=error" psql -X -q -v ON_ERROR_STOP=1 -d "$IDB" -f $T/principals_ids.sql >/dev/null || exit 1
IPSQL -c "SET ROLE app_user; $AS_42 SELECT authz.share('doc', 3, 'reader', 'service', '1')" >/dev/null
L=$(grep -n '^type service = pi.services principal$' $T/principals_ids.authz | cut -d: -f1)
icheck "lint notes a principal type nobody can make keys for, with its line" \
  "info|service|signs in, but has no manage_keys permission, so nobody can make API keys for it: add can manage_keys = ... (line $L)" \
  "RESET ROLE; SELECT severity || '|' || object || '|' || problem FROM authz.lint() WHERE problem LIKE '%manage_keys%';"
icheck "the user whose id is service:1 shares: created_by says user:service:1" "user:service:1" \
  "$AS_COLON SELECT authz.share('doc', 1, 'reader', 'user', '42'); SELECT created_by FROM authz.list_shares('doc', 1) WHERE subject_id = '42';"
icheck "... and the user whose id is nobody: user:nobody" "user:nobody" \
  "$AS_NOBODY SELECT authz.share('doc', 2, 'reader', 'user', '42'); SELECT created_by FROM authz.list_shares('doc', 2) WHERE subject_id = '42';"
icheck "... a user whose id is plain stays their id: 42" "42" \
  "$AS_42 SELECT authz.share('doc', 3, 'reader', 'user', 'nobody'); SELECT created_by FROM authz.list_shares('doc', 3) WHERE subject_id = 'nobody';"
icheck "... and service 1 is still service:1" "service:1" \
  "$AS_S1 SELECT authz.share('doc', 3, 'reader', 'user', 'service:1'); SELECT created_by FROM authz.list_shares('doc', 3) WHERE subject_type = 'user' AND subject_id = 'service:1';"
icheck "the audit trail names them the same way, each as itself" "42 user:service:1 user:nobody 42 service:1" \
  "RESET ROLE; SELECT string_agg(user_id, ' ' ORDER BY id) FROM authz.audit WHERE action = 'share';"
got=$(IPSQL -c "SET ROLE app_user; SET client_min_messages = log; SET authz_debug.log_decisions = on; $AS_COLON SELECT authz.can('doc', 1, 'view');" 2>&1 |
      grep -o 'authz decision: .*')
[ "$got" = 'authz decision: user="user:service:1" type="doc" id="1" perm="view" -> true' ] &&
  echo "ok    the decision log names them the same way: user:service:1" ||
  { echo "FAIL  the decision log names the user whose id is service:1: $got"; fails=$((fails + 1)); }
icheck "explain says who shared it the same way" "1" \
  "$AS_42 SELECT count(*) FROM authz.explain('doc', 1, 'view') e WHERE e LIKE '%(by user:service:1)%';"
icheck "a login with a key returns who signed in the same way" "user:service:1" \
  "$AS_COLON SELECT authz.login_key(authz.create_api_key('mine'));"
icheck "view-as records who is looking as acting_user, the same way" "view_as 42 user:service:1" \
  "$AS_COLON SELECT authz.view_as('42', 'ticket 7'); RESET ROLE; SELECT action || ' ' || user_id || ' ' || acting_user FROM authz.audit WHERE action = 'view_as';"
REQ=$(IPSQL -c "SET ROLE app_user; $AS_42 SELECT authz.request_access('doc', 1, 'reader', 'to help', '1 day');" | tail -n 1)
icheck "a request decided by the user whose id is service:1: decided_by says user:service:1" "approved user:service:1" \
  "$AS_COLON SELECT authz.decide_request($REQ, true); RESET ROLE; SELECT status || ' ' || decided_by FROM authz.requests WHERE id = $REQ;"
REV=$(IPSQL -c "SET ROLE app_user; $AS_NOBODY SELECT authz.start_review('doc', 2);" | tail -n 1)
icheck "a review started and decided by the user whose id is nobody: user:nobody, both" "user:nobody user:nobody" \
  "$AS_NOBODY SELECT authz.review_decide($REV, 1, true); RESET ROLE; SELECT r.created_by || ' ' || i.decided_by FROM authz.reviews r JOIN authz.review_items i ON i.review_id = r.id WHERE r.id = $REV;"
icheck "the glass broken by the user whose id is service:1: its share's created_by says user:service:1" "user:service:1" \
  "$AS_COLON SELECT authz.break_glass('doc', 2, 'reader', 'INC-1'); RESET ROLE; SELECT created_by FROM authz.shares WHERE object_id = '2' AND subject_id = 'service:1';"
icheck "a custom role made by the user whose id is service:1: created_by says user:service:1" "user:service:1" \
  "$AS_COLON SELECT authz.create_role('team', 1, 'doc', 'helper', ARRAY['view']); RESET ROLE; SELECT created_by FROM authz.roles WHERE name = 'helper';"
icheck "invariants name each the same way" "42 service:1 user:nobody user:service:1" \
  "RESET ROLE; SELECT string_agg(user_id, ' ' ORDER BY user_id) FROM authz.check_invariants();"
got=$(psql -X -q -At -d "$IDB" -f <(python3 compile_policy.py $T/principals_ids.authz --tests) 2>&1)
for who in "user service:1" "user nobody" "user 42" "service 1"; do
  case "$got" in *"FAIL  invariant never doc: reader and not owner"*": $who can reach "*) echo "ok    ... and the policy tests say $who";;
    *) echo "FAIL  the policy tests on $who breaking an invariant: $got"; fails=$((fails + 1));; esac
done
case "$got" in *": user user:"*) echo "FAIL  the policy tests say user user:...: $got"; fails=$((fails + 1));;
  *) echo "ok    ... and never user user:<id>";; esac
sed 's/^  can break_glass = oncall$/  can break_glass = oncall\n  can page = oncall/' $T/principals_ids.authz > $T/principals_ids_page.authz
out=$(python3 compile_policy.py $T/principals_ids_page.authz --diff | PGOPTIONS="-c client_min_messages=error" psql -X -q -At -d "$IDB" 2>&1 | grep -E '^gains\|[^|]*\|doc\|' | sort | tr '\n' ' ')
if [ "$out" = "gains|user:nobody|doc|permission page|1 gains|user:service:1|doc|permission page|2 " ]; then
  echo "ok    the preview names them the same way"
else echo "FAIL  the preview of who may page: $out"; fails=$((fails + 1)); fi
out=$(python3 compile_policy.py $T/principals_ids_page.authz --diff --users user:service:1 | PGOPTIONS="-c client_min_messages=error" psql -X -q -At -d "$IDB" 2>&1 | grep -E '^gains\|[^|]*\|doc\|' | tr '\n' ' ')
if [ "$out" = "gains|user:service:1|doc|permission page|2 " ]; then
  echo "ok    ... and the users asked for are named so: user:service:1 is that user alone"
else echo "FAIL  the preview for --users user:service:1: $out"; fails=$((fails + 1)); fi
[ -n "${KEEP:-}" ] || dropdb "$IDB"

[ -n "${KEEP:-}" ] || dropdb "$DB"
echo "principals: $fails failure(s)"
exit $((fails > 0))
