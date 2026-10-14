#!/bin/bash
# principals.sh: services that sign in as themselves: principal types, their keys and
# JWTs, service:* next to user:*, signed_in staying about users, and what the audit trail records.
#   PGHOST=... PGPORT=... PGUSER=postgres tests/principals.sh [database]
set -u
cd "$(dirname "$0")/.."
DB=${1:-authz_principals}
dropdb --if-exists "$DB" 2>/dev/null; createdb "$DB" || exit 1
fails=0
PSQL() { psql -X -q -At -v ON_ERROR_STOP=1 -d "$DB" "$@"; }
check() {   # $1 label, $2 expected, $3 SQL (run as app_user)
  got=$(PSQL -c "SET ROLE app_user;" -c "$3" 2>&1 | tail -n 1)
  if [ "$got" = "$2" ]; then echo "ok    $1"; else echo "FAIL  $1: expected '$2', got '$got'"; fails=$((fails + 1)); fi
}
state() { psql -X -q -At -d "$DB" -c "SET ROLE app_user;" "$@" 2>&1 | tail -n 1; }
code() {    # the SQLSTATE of the last statement, or ok
  psql -X -q -At -d "$DB" -v VERBOSITY=sqlstate -c "SET ROLE app_user;" "$@" 2>&1 | grep -o '^ERROR:  [0-9A-Z]*' | tail -n 1 | cut -c9- || true
}
. tests/words.sh
expect_code() {  # $1 label, $2 expected "SQLSTATE: the message's words" (or ok), rest: -c statements
  local label=$1 want=$2; shift 2
  got=$(psql -X -q -At -d "$DB" -v VERBOSITY=verbose -c "SET ROLE app_user;" "$@" 2>&1 | grep '^ERROR:  ' | tail -n 1)
  got=${got#ERROR:  }; got=${got:-ok}
  if agrees "$label" "$want" "$got"; then echo "ok    $label"; else echo "FAIL  $label: expected $want, got $got"; fails=$((fails + 1)); fi
}
AS_SVC="SET authz.user_id = '7'; SET authz.principal_type = 'service';"
AS_USER="SET authz.user_id = '1'; SET authz.principal_type = '';"

PGOPTIONS="-c client_min_messages=warning" PSQL <<'SQL' >/dev/null || exit 1
DO $$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'app_user') THEN CREATE ROLE app_user NOLOGIN; END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'other_app') THEN CREATE ROLE other_app NOLOGIN; END IF;
END $$;
CREATE SCHEMA ps;
CREATE TABLE ps.users (id bigint PRIMARY KEY);
CREATE TABLE ps.services (id bigint PRIMARY KEY, owner_id bigint REFERENCES ps.users, active boolean NOT NULL DEFAULT true);
CREATE TABLE ps.teams (id bigint PRIMARY KEY);
CREATE TABLE ps.team_members (team_id bigint REFERENCES ps.teams, user_id bigint REFERENCES ps.users, PRIMARY KEY (team_id, user_id));
CREATE TABLE ps.team_services (team_id bigint REFERENCES ps.teams, service_id bigint REFERENCES ps.services,
  PRIMARY KEY (team_id, service_id));
CREATE TABLE ps.docs (id bigint PRIMARY KEY, owner_id bigint, bot_id bigint, body text);
INSERT INTO ps.users VALUES (1), (2), (3);
INSERT INTO ps.services VALUES (7, 1, true), (8, 2, true), (9, 1, false);
INSERT INTO ps.teams VALUES (1);
INSERT INTO ps.team_services VALUES (1, 8);
INSERT INTO ps.docs VALUES (1, 1, 7, 'bot 7 keeps this'), (2, 2, NULL, 'shared with team 1'),
  (3, 2, NULL, 'shared with every service'), (4, 2, NULL, 'shared with every user'), (5, 3, NULL, 'nobody else');
GRANT USAGE ON SCHEMA ps TO app_user, other_app;
GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA ps TO app_user;
SQL
cat > /tmp/authz_principals.authz <<'POLICY'
app role app_user
type user = ps.users
type service = ps.services principal where {active}
  owner : user = owner_id
  can manage_keys = owner
type team = ps.teams
  member : user    = ps.team_members(team_id -> user_id)
  member : service = ps.team_services(team_id -> service_id)
type doc = ps.docs
  owner  : user    = owner_id
  bot    : service = bot_id
  reader : user, service, team#member, user:*, service:*  shared
  can share = owner or bot
  can edit  = owner or bot
  can view  = edit or reader
  helper : user  shared by view          -- any viewer may name a helper, if they may assist themselves
  can assist = owner or helper
rules ps.docs
  select : view
  update : edit
  update owner_id : bot                  -- the doc's bot hands it over: a rule on a column that names a service
  insert : signed_in and {owner_id = authz.uid()}
invariants
  never doc: edit and not owner
  never doc: not view             -- everyone, signed in or not, lacks view on something: broken on purpose
POLICY
python3 compile_policy.py /tmp/authz_principals.authz > /tmp/authz_principals.sql || exit 1
PGOPTIONS="-c client_min_messages=error" psql -X -q -v ON_ERROR_STOP=1 -d "$DB" -f /tmp/authz_principals.sql >/dev/null || exit 1
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
check "a user may have their own explained, by id" "no   user 1 does not hold view on doc 5" \
  "$AS_USER SELECT e FROM authz.explain('doc', 5, 'view', '1') e LIMIT 1;"
check "it shares as itself: created_by says so" "service:7" \
  "$AS_SVC SELECT authz.share('doc', 1, 'reader', 'user', 3); SELECT created_by FROM authz.list_shares('doc', 1) WHERE subject_id = '3';"
check "the audit trail says so too" "service:7" \
  "RESET ROLE; SELECT user_id FROM authz.audit WHERE action = 'share' AND object_id = '1' ORDER BY id DESC LIMIT 1;"
check "authz.who lists users" "1,3" "RESET ROLE; SELECT string_agg(x, ',' ORDER BY x) FROM authz.who('doc', 1, 'view') x;"
expect_code "a role the policy doesn't govern can't sign in as a service" "42501: permission denied for schema authz" -c "RESET ROLE" -c "SET ROLE other_app" \
  -c "SELECT authz.act_as('service', '7')"

check "invariants are asked as each service too, named as the audit trail names it" "service:7|{1}"   "RESET ROLE; SELECT string_agg(user_id || '|' || object_ids::text, ' ') FROM authz.check_invariants() WHERE invariant LIKE 'never doc: edit and not owner%';"
check "... and as nobody: the row with no user" "1"   "RESET ROLE; SELECT count(*) FROM authz.check_invariants() WHERE user_id IS NULL AND invariant LIKE 'never doc: not view%';"
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
got=$(psql -X -q -At -d "$DB" -f <(python3 compile_policy.py /tmp/authz_principals.authz --tests) 2>&1)
case "$got" in *"FAIL  invariant never doc: edit and not owner"*": service 7 can reach {1}"*) echo "ok    ... and the policy tests say which service";;
  *) echo "FAIL  the policy tests on a service breaking an invariant: $got"; fails=$((fails + 1));; esac

echo "-- whoever signs in is a row of their type"
PSQL -c "INSERT INTO ps.docs VALUES (20, 99, 77, 'its owner and its bot are gone')" >/dev/null
AS_GONE="SET authz.user_id = '99'; SET authz.principal_type = '';"
check "an id the user table doesn't have is nobody: no uid, no principal" "|"   "$AS_GONE SELECT coalesce(authz.uid()::text, '') || '|' || coalesce((SELECT principal_id FROM authz.principal()), '');"
check "... so a column that still names it grants nothing, nor does user:*" "false|0"   "$AS_GONE SELECT authz.can('doc', 20, 'edit')::text || '|' || (SELECT count(*) FROM ps.docs);"
check "... and the same for a service its table doesn't have" "false|0"   "SET authz.user_id = '77'; SET authz.principal_type = 'service'; SELECT authz.can('doc', 20, 'edit')::text || '|' || (SELECT count(*) FROM ps.docs);"
PSQL -c "INSERT INTO ps.users VALUES (99)" >/dev/null
check "once the row is there, they are someone" "99|true" "$AS_GONE SELECT authz.uid() || '|' || authz.can('doc', 20, 'edit')::text;"
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
KID=$(state -c "$AS_USER" -c "SELECT id FROM authz.list_api_keys('service', '7')")
PSQL -c "SET ROLE app_user; $AS_USER SELECT authz.revoke_api_key($KID)" >/dev/null
expect_code "the owner revoked it" "28000: invalid API key" -c "BEGIN" -c "SELECT authz.login_key('$KEY')"

echo "-- a principal's keys go with its row"
PSQL -c "INSERT INTO ps.users VALUES (98), (94)" -c "INSERT INTO ps.services VALUES (97, 1, true), (96, 1, true), (93, 1, true)" >/dev/null
K98=$(state -c "SET authz.user_id = '98'" -c "SELECT authz.create_api_key('mine')")
K97=$(state -c "$AS_USER" -c "SELECT authz.create_api_key('deploy', '', NULL, 'service', '97')")
K96=$(state -c "$AS_USER" -c "SELECT authz.create_api_key('deploy', '', NULL, 'service', '96')")
keys() { echo "RESET ROLE; SELECT count(*) FROM authz.api_keys WHERE principal_type = '$1' AND user_id = '$2';"; }
PSQL -c "DELETE FROM ps.users WHERE id = 98" -c "DELETE FROM ps.services WHERE id = 97" -c "UPDATE ps.services SET id = 95 WHERE id = 96" >/dev/null
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
psql -X -q -d "$DB" -c "BEGIN" -c "DELETE FROM ps.users WHERE id = 94" -c "SELECT pg_sleep(1.5)" -c "COMMIT" >/dev/null 2>&1 &
sleep 0.5
expect_code "a key made while its user is deleted waits for the delete, then is refused" \
  "42501: sign in to create an API key" -c "SET authz.user_id = '94'" -c "SELECT authz.create_api_key('late')"
wait
check "... and no key is left behind" "0" "$(keys user 94)"
# REPEATABLE READ: a delete whose snapshot is older than a key made for the row fails to serialize
psql -X -q -d "$DB" > /tmp/authz_principals_rr.out 2>&1 <<'SQL' &
BEGIN ISOLATION LEVEL REPEATABLE READ;
SELECT count(*) FROM ps.teams;
SELECT pg_sleep(1.5);
DELETE FROM ps.services WHERE id = 93;
COMMIT;
SQL
sleep 0.5
state -c "$AS_USER" -c "SELECT left(authz.create_api_key('deploy', '', NULL, 'service', '93'), 3)" >/dev/null
wait
if grep -q "could not serialize access due to concurrent update" /tmp/authz_principals_rr.out; then
  echo "ok    a delete with an older snapshot than a key made for the service gets a serialization error"
else echo "FAIL  a delete with an older snapshot than a key: $(tr '\n' ' ' < /tmp/authz_principals_rr.out)"; fails=$((fails + 1)); fi
check "... and the service and its key are both still there" "1|1" \
  "RESET ROLE; SELECT (SELECT count(*) FROM ps.services WHERE id = 93) || '|' || (SELECT count(*) FROM authz.api_keys WHERE principal_type = 'service' AND user_id = '93');"
rm -f /tmp/authz_principals_rr.out

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
T=$(jwt '{"sub": "8", "kind": "service"}')
check "a token for service 8" "service:8|2,3" \
  "BEGIN; SELECT authz.login_jwt('$T') || '|' || (SELECT string_agg(id::text, ',' ORDER BY id) FROM ps.docs); COMMIT;"
T=$(jwt '{"sub": "1"}')
check "a token without the claim is a user's" "1" "BEGIN; SELECT authz.login_jwt('$T'); COMMIT;"
T=$(jwt '{"sub": "1", "kind": "doc"}')
expect_code "a token naming a type that doesn't sign in" "28000: the token names a type that does not sign in" -c "BEGIN" -c "SELECT authz.login_jwt('$T')"

echo "-- the policy"
bad() {  # $1 label, $2 expected piece of the error, $3 policy
  got=$(printf '%s\n' "$3" | python3 compile_policy.py --check /dev/stdin 2>&1)
  case "$got" in *"$2"*) echo "ok    $1";; *) echo "FAIL  $1: $got"; fails=$((fails + 1));; esac
}
bad "type:* needs a principal type" "doc:* means any signed-in doc, but doc doesn't sign in" \
  "$(sed 's/  reader : user, service, team#member, user:\*, service:\*  shared/  reader : user, doc:*  shared/' /tmp/authz_principals.authz)"
bad "a principal's key is one column" "the service type signs in, so it needs a key of one column" \
  "$(sed 's/type service = ps.services principal/type service = ps.services (owner_id, id) principal/' /tmp/authz_principals.authz)"
# a change that reaches only a service is in the preview, named as the audit trail names it
sed 's/^  can assist = owner or helper$/  can assist = owner or helper or bot/' /tmp/authz_principals.authz > /tmp/authz_principals_bot.authz
out=$(python3 compile_policy.py /tmp/authz_principals_bot.authz --diff | PGOPTIONS="-c client_min_messages=error" psql -X -q -At -d "$DB" 2>&1)
case "$out" in *"gains|service:7|doc|permission assist|1"*) echo "ok    the preview lists what a service gains";;
  *) echo "FAIL  the preview of a change for a service: $out"; fails=$((fails + 1));; esac
out=$(python3 compile_policy.py /tmp/authz_principals_bot.authz --diff --users 1,2 | PGOPTIONS="-c client_min_messages=error" psql -X -q -At -d "$DB" 2>&1)
case "$out" in *service:*) echo "FAIL  --users 1,2 shows a service: $out"; fails=$((fails + 1));; *) echo "ok    ... and --users leaves it out when it names users only";; esac
check "lint notes a principal type nobody can make keys for" "0" \
  "RESET ROLE; SELECT count(*) FROM authz.lint() WHERE object = 'service' AND problem LIKE '%manage_keys%';"

# keys stored before keys went with their principal's row, of a user deleted since: applying deletes them
PSQL -c "INSERT INTO authz.api_keys (user_id, principal_type, name, prefix, hash) VALUES ('90', 'user', 'left', 'ak_', 'left over')" >/dev/null
PGOPTIONS="-c client_min_messages=error" psql -X -q -v ON_ERROR_STOP=1 -d "$DB" -f /tmp/authz_principals.sql >/dev/null
check "applying the policy deletes the keys of a principal whose row is gone" "0" \
  "RESET ROLE; SELECT count(*) FROM authz.api_keys WHERE principal_type = 'user' AND user_id = '90';"
PSQL -c "TRUNCATE ps.services CASCADE" >/dev/null
check "emptying the services' table deletes every service's keys" "0" \
  "RESET ROLE; SELECT count(*) FROM authz.api_keys WHERE principal_type = 'service';"

[ -n "${KEEP:-}" ] || dropdb "$DB"
echo "principals: $fails failure(s)"
exit $((fails > 0))
