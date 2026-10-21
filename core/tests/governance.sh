#!/bin/bash
# governance.sh: the audit trail, the change feed, access requests, emergency access,
# access reviews, invariants, decision logs and previewing a policy change.
#   PGHOST=... PGPORT=... PGUSER=postgres tests/governance.sh [database]
set -u
cd "$(dirname "$0")/.."
DB=${1:-authz_governance}
dropdb --if-exists "$DB" 2>/dev/null; createdb "$DB" || exit 1
fails=0
PSQL() { psql -X -q -At -v ON_ERROR_STOP=1 -d "$DB" "$@"; }
check() {   # $1 label, $2 expected, $3 SQL (run as app_user)
  got=$(PSQL -c "SET ROLE app_user;" -c "$3" 2>&1 | tail -n 1)
  if [ "$got" = "$2" ]; then echo "ok    $1"; else echo "FAIL  $1: expected '$2', got '$got'"; fails=$((fails + 1)); fi
}
admin() {   # $1 label, $2 expected, $3 SQL (run as the administrator)
  got=$(PSQL -c "$3" 2>&1 | tail -n 1)
  if [ "$got" = "$2" ]; then echo "ok    $1"; else echo "FAIL  $1: expected '$2', got '$got'"; fails=$((fails + 1)); fi
}
as() { local u=$1; shift; PSQL -c "SET ROLE app_user; SET authz.user_id = '$u';" "$@" 2>&1 | tail -n 1; }
code() {
  psql -X -q -At -d "$DB" -v VERBOSITY=sqlstate "$@" 2>&1 | grep -o '^ERROR:  [0-9A-Z]*' | tail -n 1 | cut -c9- || true
}
. tests/words.sh
expect_code() {  # $1 label, $2 expected "SQLSTATE: the message's words" (or ok), rest: -c statements (as app_user unless the first is RESET ROLE)
  local label=$1 want=$2; shift 2
  got=$(psql -X -q -At -d "$DB" -v VERBOSITY=verbose -c "SET ROLE app_user" "$@" 2>&1 | grep '^ERROR:  ' | tail -n 1)
  got=${got#ERROR:  }; got=${got:-ok}
  if agrees "$label" "$want" "$got"; then echo "ok    $label"; else echo "FAIL  $label: expected $want, got $got"; fails=$((fails + 1)); fi
}

# applies a policy again: it makes rowstile's functions anew, and Postgres's counts of the calls go with the old
# ones, so while the run measures what the suites run they are kept first (tests/coverage_functions.sh)
reapply() {
  bash tests/coverage_functions.sh "$DB"
  PGOPTIONS="-c client_min_messages=error" psql -X -q -v ON_ERROR_STOP=1 -d "$DB" -f "$1" >/dev/null
}

python3 compile_policy.py example/docs.authz > /tmp/authz_governance.sql || exit 1
PGOPTIONS="-c client_min_messages=error" psql -X -q -v ON_ERROR_STOP=1 -d "$DB" -f example/app_schema.sql >/dev/null &&
PGOPTIONS="-c client_min_messages=error" psql -X -q -v ON_ERROR_STOP=1 -d "$DB" -f /tmp/authz_governance.sql >/dev/null || exit 1

echo "-- the audit trail"
as 5 -c "SELECT authz.share('folder', 2, 'viewer', 'user', 4)" >/dev/null
admin "a share is recorded, with who made it" "share|5|folder|2|viewer|user|4" \
  "SELECT action || '|' || user_id || '|' || object_type || '|' || object_id || '|' || relation || '|' || subject_type || '|' || subject_id
   FROM authz.audit ORDER BY id DESC LIMIT 1"
as 5 -c "SELECT authz.unshare('folder', 2, 'viewer', 'user', 4)" >/dev/null
admin "... and so is taking it back" "unshare|5" "SELECT action || '|' || user_id FROM authz.audit ORDER BY id DESC LIMIT 1"
PSQL -c "BEGIN" -c "SET LOCAL ROLE app_user" -c "SELECT authz.act_as('user', ' 05')" \
     -c "SELECT authz.share('folder', 2, 'viewer', 'user', 4)" -c "COMMIT" >/dev/null
admin "an id signed in as ' 05' is recorded as 5, as ids are stored" "share|5|5" \
  "SELECT a.action || '|' || a.user_id || '|' || s.created_by FROM authz.audit a, authz.shares s
   WHERE s.object_type = 'folder' AND s.object_id = '2' AND s.subject_id = '4' ORDER BY a.id DESC LIMIT 1"
as 5 -c "SELECT authz.unshare('folder', 2, 'viewer', 'user', 4)" >/dev/null
PSQL -c "INSERT INTO app.team_members VALUES (11, 3)" >/dev/null
admin "memberships kept in your tables are recorded too" "relate|team|11|member|user|3" \
  "SELECT action || '|' || object_type || '|' || object_id || '|' || relation || '|' || subject_type || '|' || subject_id
   FROM authz.audit ORDER BY id DESC LIMIT 1"
PSQL -c "DELETE FROM app.team_members WHERE team_id = 11 AND user_id = 3" >/dev/null
admin "... and their removal" "unrelate|team|11|3" \
  "SELECT action || '|' || object_type || '|' || object_id || '|' || subject_id FROM authz.audit ORDER BY id DESC LIMIT 1"
PSQL -c "BEGIN; SET LOCAL authz_ctx.reason = 'reorg'; UPDATE app.folders SET owner_id = 3 WHERE id = 4; COMMIT;" >/dev/null
admin "a changed owner column is recorded, with what it was and why" "relate|folder|4|owner|3|1|reorg" \
  "SELECT action || '|' || object_type || '|' || object_id || '|' || relation || '|' || subject_id || '|' || (detail->>'was') || '|' || reason
   FROM authz.audit ORDER BY id DESC LIMIT 1"
PSQL -c "UPDATE app.folders SET owner_id = 1 WHERE id = 4" >/dev/null
admin "an unrelated column change adds nothing" "0" \
  "WITH b AS (SELECT max(id) m FROM authz.audit), u AS (UPDATE app.folders SET name = 'Design' WHERE id = 4 RETURNING 1)
   SELECT count(*) FROM authz.audit, b WHERE id > b.m"
PSQL -c "UPDATE app.folders SET id = 40, owner_id = 3 WHERE id = 4" >/dev/null
admin "an owner change in the same UPDATE as a new key is recorded" "relate|40|owner|3" \
  "SELECT action || '|' || object_id || '|' || relation || '|' || subject_id FROM authz.audit
   WHERE object_type = 'folder' AND relation = 'owner' ORDER BY id DESC LIMIT 1"
PSQL -c "UPDATE app.folders SET id = 4, owner_id = 1 WHERE id = 40" >/dev/null
# a team given a folder in app.folder_team_access: viewer for any access, editor only where {access = 'edit'}
# holds (access may be NULL here, where the condition is neither true nor false)
B=$(PSQL -c "SELECT max(id) FROM authz.audit")
since() { echo "SELECT string_agg(action || '|' || object_id || '|' || relation || '|' || subject_type || '|' || subject_id || '|' || subject_relation, ', ' ORDER BY id)
   FROM authz.audit WHERE id > $B"; }
PSQL -c "ALTER TABLE app.folder_team_access ALTER COLUMN access DROP NOT NULL" \
     -c "INSERT INTO app.folder_team_access VALUES (6, 11, 'view'), (6, 12, NULL)" >/dev/null
admin "a team given a folder in your table is recorded as its members (team#member), under the relations whose where holds" \
  "relate|6|viewer|team|11|member, relate|6|viewer|team|12|member" "$(since)"
B=$(PSQL -c "SELECT max(id) FROM authz.audit")
PSQL -c "UPDATE app.folder_team_access SET access = 'edit' WHERE folder_id = 6 AND team_id = 11" >/dev/null
admin "... a change of access records the relation it adds, and nothing for the one it keeps" "relate|6|editor|team|11|member" "$(since)"
PSQL -c "DELETE FROM app.folder_team_access WHERE folder_id = 6" \
     -c "ALTER TABLE app.folder_team_access ALTER COLUMN access SET NOT NULL" >/dev/null
POS=$(PSQL -c "SELECT coalesce(max(pos), 0) FROM authz.changes")
PSQL -c "TRUNCATE app.folder_links" -c "INSERT INTO app.folder_links VALUES (21, 1)" >/dev/null
admin "emptying a link table is recorded" "truncate|folder" \
  "SELECT action || '|' || object_type FROM authz.audit WHERE action = 'truncate' ORDER BY id DESC LIMIT 1"
admin "... and announced for every folder" "{*}" \
  "SELECT object_ids::text FROM authz.changes WHERE pos > $POS AND object_type = 'folder' ORDER BY pos LIMIT 1"
PSQL -c "INSERT INTO authz.shares (object_type, object_id, relation, subject_type, subject_id) VALUES ('folder', '999', 'viewer', 'user', '4')" >/dev/null
reapply /tmp/authz_governance.sql
admin "shares dropped when the policy is applied (their row is gone) are recorded, with why" \
  "unshare|applying the policy: the row was deleted" \
  "SELECT action || '|' || reason FROM authz.audit WHERE object_id = '999' ORDER BY id DESC LIMIT 1"
expect_code "the trail cannot be edited, even by an administrator" "42501: the audit trail cannot be changed" -c "RESET ROLE" -c "DELETE FROM authz.audit"
expect_code "... or emptied" "42501: the audit trail cannot be changed" -c "RESET ROLE" -c "TRUNCATE authz.audit"
expect_code "... or an entry changed" "42501: the audit trail cannot be changed" -c "RESET ROLE" -c "UPDATE authz.audit SET reason = 'nothing happened'"
# the guard holds in every replication role: session_replication_role = replica (a superuser's to set) turns
# ordinary triggers off, not these
if [ -n "${PGSUPERUSER:-}" ]; then
  REPLICA=(-U "$PGSUPERUSER" -c "RESET ROLE" -c "SET session_replication_role = replica")
  expect_code "... nor by a superuser in replica role: an entry deleted" "42501: the audit trail cannot be changed" "${REPLICA[@]}" -c "DELETE FROM authz.audit"
  expect_code "... an entry changed" "42501: the audit trail cannot be changed" "${REPLICA[@]}" -c "UPDATE authz.audit SET reason = 'nothing happened'"
  expect_code "... or the trail emptied" "42501: the audit trail cannot be changed" "${REPLICA[@]}" -c "TRUNCATE authz.audit"
fi
expect_code "the app role cannot read it" "42501: permission denied for table audit" -c "SELECT count(*) FROM authz.audit"

echo "-- the change feed"
POS=$(PSQL -c "SELECT coalesce(max(pos), 0) FROM authz.changes")
PSQL -c "UPDATE app.folders SET parent_id = 2 WHERE id = 4" >/dev/null
admin "moving a folder announces it (and what sits below it)" "t" \
  "SELECT bool_or(object_type = 'folder' AND '4' = ANY (object_ids)) FROM authz.changes_since($POS)"
admin "... with inheritance as the cause" "t" \
  "SELECT bool_or(cause = 'inheritance') FROM authz.changes_since($POS)"
admin "reading from a position gives what came after it, not the entry at it" "0|1" \
  "SELECT (SELECT count(*) FROM authz.changes_since(m)) || '|' || (SELECT count(*) FROM authz.changes_since(m - 1))
   FROM (SELECT max(pos) AS m FROM authz.changes) x"
PSQL -c "UPDATE app.folders SET parent_id = 3 WHERE id = 4" >/dev/null
# a file added and taken away: both announced, each with what happened to it
POS=$(PSQL -c "SELECT coalesce(max(pos), 0) FROM authz.changes")
PSQL -c "INSERT INTO app.files (id, folder_id, owner_id, name) VALUES (98, 2, 5, 'for the feed')" -c "DELETE FROM app.files WHERE id = 98" >/dev/null
admin "a file added, then deleted: the feed has both" "insert,delete" \
  "SELECT string_agg(cause, ',' ORDER BY pos) FROM authz.changes_since($POS) WHERE object_type = 'file' AND '98' = ANY (object_ids)"
got=$(psql -X -q -At -d "$DB" -c "LISTEN authz_changes" -c "SET ROLE app_user" -c "SET authz.user_id = 5" \
       -c "SELECT authz.share('file', 11, 'viewer', 'user', 4)" -c "SELECT 1" 2>&1)
case "$got" in *'notification "authz_changes"'*) echo "FAIL  the feed notified without notify_changes: $got"; fails=$((fails + 1));;
  *) echo "ok    by default the feed doesn't NOTIFY (it would queue every commit): consumers poll";; esac
PSQL -c "INSERT INTO authz.settings VALUES ('notify_changes', 'on')" >/dev/null
got=$(psql -X -q -At -d "$DB" -c "LISTEN authz_changes" -c "SET ROLE app_user" -c "SET authz.user_id = 5" \
       -c "SELECT authz.unshare('file', 11, 'viewer', 'user', 4)" -c "SELECT 1" 2>&1)
case "$got" in *'notification "authz_changes"'*) echo "ok    with notify_changes on, listeners hear of a change (NOTIFY authz_changes)";;
  *) echo "FAIL  notify: $got"; fails=$((fails + 1));; esac
PSQL -c "DELETE FROM authz.settings WHERE key = 'notify_changes'" >/dev/null
expect_code "the app role cannot read the feed" "42501: permission denied for function changes_since" -c "SELECT * FROM authz.changes_since(0)"
# a share moved to another object (an administrator's UPDATE): the object it left is announced too
PSQL -c "INSERT INTO authz.shares (object_type, object_id, relation, subject_type, subject_id) VALUES ('file', '11', 'viewer', 'user', '4')" >/dev/null
POS=$(PSQL -c "SELECT coalesce(max(pos), 0) FROM authz.changes")
PSQL -c "UPDATE authz.shares SET object_id = '12' WHERE object_type = 'file' AND object_id = '11' AND subject_id = '4'" >/dev/null
admin "a share moved to another file: both files are announced" "11,12" \
  "SELECT string_agg(DISTINCT x, ',' ORDER BY x) FROM authz.changes_since($POS), unnest(object_ids) x WHERE object_type = 'file'"
PSQL -c "DELETE FROM authz.shares WHERE object_type = 'file' AND object_id = '12' AND subject_id = '4'" >/dev/null
# folders and projects inside each other through links people share (one inheritance table for the two types): a new
# link announces what it moves, and only that
X="${DB}_across"
XSQL() { psql -X -q -At -v ON_ERROR_STOP=1 -d "$X" "$@"; }
dropdb --if-exists "$X" 2>/dev/null; createdb "$X" || exit 1
cat > /tmp/authz_governance_across.authz <<'EOF'
app role app_user
type user = x.users
type folder = x.folders
  owner  : user = owner_id
  parent : project shared
  can share = owner
  can view  = owner or parent.view
type project = x.projects
  owner  : user = owner_id
  parent : folder shared
  can share = owner
  can view  = owner or parent.view
EOF
XSQL >/dev/null <<'SQL' || exit 1
CREATE SCHEMA x;
CREATE TABLE x.users (id bigint PRIMARY KEY);
CREATE TABLE x.folders (id bigint PRIMARY KEY, owner_id bigint);
CREATE TABLE x.projects (id bigint PRIMARY KEY, owner_id bigint);
INSERT INTO x.users VALUES (1);
INSERT INTO x.folders VALUES (1, 1), (2, 1), (3, NULL);
INSERT INTO x.projects VALUES (10, NULL), (20, NULL);
SQL
python3 compile_policy.py /tmp/authz_governance_across.authz > /tmp/authz_governance_across.sql &&
  PGOPTIONS="-c client_min_messages=error" psql -X -q -v ON_ERROR_STOP=1 -d "$X" -f /tmp/authz_governance_across.sql >/dev/null || exit 1
XSQL -c "INSERT INTO authz.shares (object_type, object_id, relation, subject_type, subject_id) VALUES
  ('project', '10', 'parent', 'folder', '1'), ('project', '20', 'parent', 'folder', '2')" >/dev/null
POS=$(XSQL -c "SELECT coalesce(max(pos), 0) FROM authz.changes")
XSQL -c "INSERT INTO authz.shares (object_type, object_id, relation, subject_type, subject_id) VALUES ('folder', '3', 'parent', 'project', '10')" >/dev/null
got=$(XSQL -c "SELECT string_agg(object_type || ' ' || array_to_string(object_ids, ','), '; ' ORDER BY pos)
               FROM authz.changes_since($POS) WHERE cause = 'inheritance'")
[ "$got" = "folder 3" ] && [ "$(XSQL -c "SET authz.user_id = 1" -c "SELECT authz.can('folder', 3, 'view')")" = t ] &&
  echo "ok    a folder put inside a project by a share: the feed announces it, and nothing else, with inheritance as the cause" ||
  { echo "FAIL  the feed after a link across types: expected 'folder 3', got '$got'"; fails=$((fails + 1)); }
dropdb "$X"; rm -f /tmp/authz_governance_across.authz /tmp/authz_governance_across.sql


echo "-- emergency access (break glass)"
check "carol cannot see the prod keys" "f" "SET authz.user_id = 3; SELECT authz.can('file', 12, 'view')"
expect_code "a reason is required" "22023: say why (it is kept in the audit trail)" -c "SET authz.user_id = 3" -c "SELECT authz.break_glass('folder', '6', 'viewer', '')"
expect_code "it lasts one day at most" "22023: emergency access lasts more than nothing and one day at most" -c "SET authz.user_id = 3" \
  -c "SELECT authz.break_glass('folder', '6', 'viewer', 'outage', '2 days')"
expect_code "... and a duration must be given" "22023: emergency access lasts more than nothing and one day at most" -c "SET authz.user_id = 3" \
  -c "SELECT authz.break_glass('folder', '6', 'viewer', 'outage', NULL)"
expect_code "... a positive one" "22023: emergency access lasts more than nothing and one day at most" -c "SET authz.user_id = 3" \
  -c "SELECT authz.break_glass('folder', '6', 'viewer', 'outage', '-1 hour')"
expect_code "... more than nothing: none at all is refused too" "22023: emergency access lasts more than nothing and one day at most" \
  -c "SET authz.user_id = 3" -c "SELECT authz.break_glass('folder', '6', 'viewer', 'outage', '0')"
expect_code "frank (Globex) cannot break the glass on an Acme folder" "42501: you cannot break the glass on folder 6" -c "SET authz.user_id = 6" \
  -c "SELECT authz.break_glass('folder', '6', 'viewer', 'outage')"
expect_code "... nor anyone on a file, which has no break_glass permission" "42501: you cannot break the glass on file 11" \
  -c "SET authz.user_id = 3" -c "SELECT authz.break_glass('file', '11', 'viewer', 'outage')"
expect_code "... nor on an id that is no folder's" "42501: you cannot break the glass on folder abc" -c "SET authz.user_id = 3" \
  -c "SELECT authz.break_glass('folder', 'abc', 'viewer', 'outage')"
got=$(psql -X -q -At -d "$DB" -c "LISTEN authz_alerts" -c "SET ROLE app_user" -c "SET authz.user_id = 3" \
       -c "SELECT authz.break_glass('folder', '6', 'viewer', 'prod outage INC-7')" -c "SELECT 1" 2>&1)
case "$got" in *'notification "authz_alerts"'*) echo "ok    carol breaks the glass, and the alert goes out";;
  *) echo "FAIL  break glass: $got"; fails=$((fails + 1));; esac
check "... so she can see the keys" "t" "SET authz.user_id = 3; SELECT authz.can('file', 12, 'view')"
# (five minutes either way: the clock in a container may step back a few seconds between the two statements)
admin "... for an hour" "t" \
  "SELECT expires_at BETWEEN now() + interval '55 minutes' AND now() + interval '65 minutes' FROM authz.shares WHERE object_type = 'folder' AND object_id = '6' AND subject_id = '3'"
admin "the trail has it, with the reason" "break_glass|3|prod outage INC-7" \
  "SELECT action || '|' || user_id || '|' || reason FROM authz.audit WHERE action = 'break_glass' ORDER BY id DESC LIMIT 1"
# as the reference writes them, the id a number (docs/reference/app-code.md)
expect_code "the id may be a number, as for authz.can" ok -c "SET authz.user_id = 3" \
  -c "SELECT authz.break_glass('folder', 6, 'viewer', 'INC-7 outage', '1 hour')"
expect_code "... for a review too" ok -c "SET authz.user_id = 5" -c "BEGIN" -c "SELECT authz.start_review('folder', 3)" -c "ROLLBACK"
expect_code "... and for an owner's roles (the docs policy has none: refused, not unknown)" "42501: you cannot see roles of org 1" -c "SET authz.user_id = 5" \
  -c "SELECT * FROM authz.roles_of('org', 1)"
# in a transaction rolled back after it: carol's shares on Keys taken away and rows put in as the owner ($1), then
# carol breaks the glass on Keys (viewer, an hour), then what the owner reads ($2)
glass() {
  PSQL -c "BEGIN" -c "DELETE FROM authz.shares WHERE object_type = 'folder' AND object_id = '6' AND subject_id = '3'; $1" \
       -c "SET LOCAL ROLE app_user" -c "SET LOCAL authz.user_id = 3" -c "SELECT authz.break_glass('folder', '6', 'viewer', 'INC-8', '1 hour')" \
       -c "RESET ROLE" -c "$2" -c "ROLLBACK" 2>&1 | tail -n 1
}
SHARE="INSERT INTO authz.shares (object_type, object_id, relation, subject_type, subject_id, starts_at, expires_at) VALUES"
got=$(glass "$SHARE ('folder', '6', 'viewer', 'user', '4', NULL, NULL)" \
  "SELECT string_agg(subject_id || ':' || (expires_at IS NOT NULL), ',' ORDER BY subject_id) FROM authz.shares WHERE object_type = 'folder' AND object_id = '6'")
[ "$got" = "3:true,4:false" ] && echo "ok    breaking the glass beside someone else's share on the folder gives her one of her own, and leaves theirs" ||
  { echo "FAIL  break glass beside another share: $got"; fails=$((fails + 1)); }
got=$(glass "$SHARE ('folder', '6', 'viewer', 'user', '3', now(), NULL)" \
  "SELECT coalesce(expires_at::text, 'no end') || '|' || (starts_at = now()) FROM authz.shares WHERE object_type = 'folder' AND object_id = '6' AND subject_id = '3'")
[ "$got" = "no end|true" ] && echo "ok    a share of hers that starts this very moment already lets her in: it is left as it is" ||
  { echo "FAIL  break glass over a share starting now: $got"; fails=$((fails + 1)); }
got=$(glass "$SHARE ('folder', '6', 'viewer', 'user', '3', NULL, now() + interval '1 hour')" \
  "SELECT count(*) FROM authz.audit WHERE action = 'share_changed' AND txid = txid_current()")
[ "$got" = 0 ] && echo "ok    ... and so is one that ends just when the emergency access would: nothing changed, nothing recorded" ||
  { echo "FAIL  break glass over a share ending at the same time: $got"; fails=$((fails + 1)); }
got=$(glass "$SHARE ('folder', '6', 'viewer', 'user', '3', NULL, now() + interval '5 minutes'), ('folder', '6', 'editor', 'user', '3', NULL, now() + interval '10 minutes')" \
  "SELECT string_agg(relation || '|' || (expires_at - now()), ', ' ORDER BY relation) FROM authz.shares WHERE object_type = 'folder' AND object_id = '6' AND subject_id = '3'")
[ "$got" = "editor|00:10:00, viewer|01:00:00" ] && echo "ok    one ending sooner is made to last the hour, and her shares of other relations are left as they are" ||
  { echo "FAIL  break glass over shares ending sooner: $got"; fails=$((fails + 1)); }
got=$(glass "$SHARE ('folder', '6', 'viewer', 'user', '3', now() + interval '1 day', NULL), ('folder', '6', 'viewer', 'org', '3', now() + interval '1 day', NULL)" \
  "SELECT string_agg(subject_type || '|' || coalesce((starts_at > now())::text, 'now') || '|' || (expires_at IS NOT NULL), ', ' ORDER BY subject_type) FROM authz.shares WHERE object_type = 'folder' AND object_id = '6' AND subject_id = '3'")
[ "$got" = "org|true|false, user|now|true" ] && echo "ok    one of hers that starts tomorrow lets her in now, for the hour; another kind of subject's share, with her id, is left" ||
  { echo "FAIL  break glass over a share starting later: $got"; fails=$((fails + 1)); }
got=$(glass "$SHARE ('file', '6', 'viewer', 'user', '3', now() + interval '1 day', NULL)" \
  "SELECT count(*) FROM authz.shares WHERE object_type = 'folder' AND object_id = '6' AND subject_id = '3' AND starts_at IS NULL")
[ "$got" = 1 ] && echo "ok    a share of hers on another type's object with the same id is not the folder's: she gets the folder's" ||
  { echo "FAIL  break glass beside a share of another type: $got"; fails=$((fails + 1)); }
expect_code "one day exactly is allowed" ok -c "SET authz.user_id = 3" -c "BEGIN" \
  -c "SELECT authz.break_glass('folder', '6', 'viewer', 'outage', '1 day')" -c "ROLLBACK"

echo "-- access requests"
REQ=$(as 3 -c "SELECT authz.request_access('folder', 5, 'viewer', 'need the offer letter template', '7 days')")
[ -n "$REQ" ] && [ "$REQ" -gt 0 ] 2>/dev/null && echo "ok    carol asks to view Secrets" || { echo "FAIL  request: $REQ"; fails=$((fails + 1)); }
check "carol sees her own request" "t" "SET authz.user_id = 3; SELECT mine FROM authz.pending_requests() WHERE id = $REQ"
check "erin (who may share Secrets) sees it to decide" "1" "SET authz.user_id = 5; SELECT count(*) FROM authz.pending_requests() WHERE id = $REQ"
check "alice (who may not) does not" "0" "SET authz.user_id = 1; SELECT count(*) FROM authz.pending_requests() WHERE id = $REQ"
expect_code "alice cannot decide it" "42501: you cannot decide request 1" -c "SET authz.user_id = 1" -c "SELECT authz.decide_request($REQ, true)"
expect_code "alice cannot deny it either" "42501: you cannot decide request 1" -c "SET authz.user_id = 1" -c "SELECT authz.decide_request($REQ, false)"
expect_code "carol cannot approve her own request" "42501: you cannot decide your own request" -c "SET authz.user_id = 3" -c "SELECT authz.decide_request($REQ, true)"
expect_code "nobody signed in is told to sign in, not that the request is theirs" "42501: sign in to decide a request" \
  -c "SELECT authz.decide_request($REQ, true)"
expect_code "... and so is an administrator with nobody signed in" "42501: sign in to decide a request" -c "RESET ROLE" \
  -c "SELECT authz.decide_request($REQ, true)"
expect_code "an answer is yes or no" "22023: approve (true) or deny (false)" -c "SET authz.user_id = 5" -c "SELECT authz.decide_request($REQ, NULL)"
expect_code "... for a request still pending" "P0001: no pending request 999" -c "SET authz.user_id = 5" -c "SELECT authz.decide_request(999, true)"
expect_code "dave cannot withdraw carol's request" "P0001: no pending request $REQ of yours" -c "SET authz.user_id = 4" -c "SELECT authz.cancel_request($REQ)"
expect_code "a request says why" "22023: say why you need it" -c "SET authz.user_id = 4" \
  -c "SELECT authz.request_access('folder', 6, 'viewer', '  ')"
expect_code "... and how long it may last is more than nothing" "22023: the duration must be positive" -c "SET authz.user_id = 4" \
  -c "SELECT authz.request_access('folder', 6, 'viewer', 'please', '-1 day')"
expect_code "... none at all is refused too" "22023: the duration must be positive" -c "SET authz.user_id = 4" \
  -c "SELECT authz.request_access('folder', 6, 'viewer', 'please', '0')"
expect_code "nobody signed in asks for nothing" "42501: sign in first" -c "SELECT authz.request_access('folder', 6, 'viewer', 'please')"
said=$(psql -X -q -At -d "$DB" -c "SET ROLE app_user" -c "SELECT authz.request_access('folder', 6, 'viewer', 'please')" 2>&1 | grep '^HINT:  ')
[ "$said" = "HINT:  rowstile help AZ714" ] && echo "ok    ... and its code is sign in first (AZ714, a 401), not a refusal" ||
  { echo "FAIL  sign in first's code: $said"; fails=$((fails + 1)); }
check "before approval carol cannot view the offer letter" "f" "SET authz.user_id = 3; SELECT authz.can('file', 13, 'view')"
as 5 -c "SELECT authz.decide_request($REQ, true, 'ok for a week')" >/dev/null
check "after erin approves, she can" "t" "SET authz.user_id = 3; SELECT authz.can('file', 13, 'view')"
admin "the share ends after the requested week" "t" \
  "SELECT expires_at BETWEEN now() + interval '7 days' - interval '1 minute' AND now() + interval '7 days'
   FROM authz.shares WHERE object_type = 'folder' AND object_id = '5' AND subject_id = '3'"
admin "the request is closed, and says who approved it" "approved|5" "SELECT status || '|' || decided_by FROM authz.requests WHERE id = $REQ"
REQ2=$(as 4 -c "SELECT authz.request_access('folder', 6, 'viewer', 'curious')")
as 5 -c "SELECT authz.decide_request($REQ2, false, 'no')" >/dev/null
check "a denied request grants nothing" "f" "SET authz.user_id = 4; SELECT authz.can('folder', 6, 'view')"
REQ3=$(as 4 -c "SELECT authz.request_access('folder', 6, 'viewer', 'please')")
as 4 -c "SELECT authz.cancel_request($REQ3)" >/dev/null
admin "requests can be withdrawn" "cancelled" "SELECT status FROM authz.requests WHERE id = $REQ3"
expect_code "only relations the policy lets people share can be requested" "P0001: the policy does not allow sharing folder.owner with a user" -c "SET authz.user_id = 4" \
  -c "SELECT authz.request_access('folder', 6, 'owner', 'mine now')"
expect_code "... on types the policy has" "P0001: no type nosuchtype in the policy" -c "SET authz.user_id = 4" \
  -c "SELECT authz.request_access('nosuchtype', '1', 'role:1', 'boom')"
expect_code "... and roles that exist" "P0001: the policy does not allow sharing folder.role:999 with a user" -c "SET authz.user_id = 4" \
  -c "SELECT authz.request_access('folder', '6', 'role:999', 'boom')"
R999=$(as 4 -c "SELECT authz.request_access('folder', '999', 'viewer', 'boom')")
check "a request for a missing object reaches no approver" "0" "SET authz.user_id = 5; SELECT count(*) FROM authz.pending_requests() WHERE id = $R999"
as 4 -c "SELECT authz.cancel_request($R999)" >/dev/null
check "approvers can still list requests" "0" "SET authz.user_id = 5; SELECT count(*) FROM authz.pending_requests() WHERE requester = '4'"

echo "-- a pending request goes with its requester's row, and with its object's"
PSQL -c "INSERT INTO app.users VALUES (8, 'hal'), (9, 'ida')" \
     -c "INSERT INTO app.folders (id, org_id, parent_id, owner_id, name) VALUES (41, 1, 4, 1, 'doomed'), (42, 1, 4, 1, 'doomed too')" >/dev/null
RQH=$(as 8 -c "SELECT authz.request_access('folder', 6, 'viewer', 'hal needs it')")
RQO=$(as 4 -c "SELECT authz.request_access('folder', 41, 'viewer', 'dave needs the old one')")
RQK=$(as 4 -c "SELECT authz.request_access('folder', 42, 'viewer', 'dave needs this one too')")
RQD=$(as 8 -c "SELECT authz.request_access('folder', 2, 'viewer', 'hal asked before')")
as 5 -c "SELECT authz.decide_request($RQD, false, 'no')" >/dev/null
PSQL -c "DELETE FROM app.users WHERE id = 8" -c "DELETE FROM app.folders WHERE id = 41" -c "UPDATE app.folders SET id = 43 WHERE id = 42" >/dev/null
admin "a pending request is cancelled when its requester is deleted, its object is, or its object gets a new id, and says why" \
  "cancelled|its requester is gone|cancelled|its object is gone|cancelled|its object is gone" \
  "SELECT string_agg(status || '|' || note, '|' ORDER BY id) FROM authz.requests WHERE id IN ($RQH, $RQO, $RQK)"
admin "... a decided one stays as it was" "denied|no" "SELECT status || '|' || note FROM authz.requests WHERE id = $RQD"
PSQL -c "INSERT INTO app.users VALUES (8, 'someone else')" \
     -c "INSERT INTO app.folders (id, org_id, parent_id, owner_id, name) VALUES (41, 1, 4, 1, 'new'), (42, 1, 4, 1, 'new too')" >/dev/null
check "a later user with the id has none of the old one's requests" "0" "SET authz.user_id = 8; SELECT count(*) FROM authz.pending_requests()"
expect_code "approving the old request for a later folder with the id is refused" "P0001: no pending request $RQO" \
  -c "SET authz.user_id = 5" -c "SELECT authz.decide_request($RQO, true)"
expect_code "... and so is approving the request of a requester who is gone" "P0001: no pending request $RQH" \
  -c "SET authz.user_id = 5" -c "SELECT authz.decide_request($RQH, true)"
admin "... so nothing is shared with the later folder" "0" "SELECT count(*) FROM authz.shares WHERE object_type = 'folder' AND object_id IN ('41', '42')"
# a request made while its requester is deleted: it waits for the delete, then there is nobody to make it
psql -X -q -d "$DB" -c "BEGIN" -c "DELETE FROM app.users WHERE id = 9" -c "SELECT pg_sleep(1.5)" -c "COMMIT" >/dev/null 2>&1 &
sleep 0.5
expect_code "a request made while its requester is deleted waits for the delete, then is refused" "42501: sign in first" \
  -c "SET authz.user_id = 9" -c "SELECT authz.request_access('folder', 6, 'viewer', 'too late')"
wait
admin "... and leaves no request behind" "0" "SELECT count(*) FROM authz.requests WHERE requester = '9'"
# REPEATABLE READ: a delete of the object whose snapshot is older than a request on it fails to serialize
psql -X -q -d "$DB" > /tmp/authz_governance_rr.out 2>&1 <<'SQL' &
BEGIN ISOLATION LEVEL REPEATABLE READ;
SELECT count(*) FROM app.orgs;
SELECT pg_sleep(1.5);
DELETE FROM app.folders WHERE id = 41;
COMMIT;
SQL
sleep 0.5
as 4 -c "SELECT authz.request_access('folder', 41, 'viewer', 'dave needs the new one')" >/dev/null
wait
if grep -q "could not serialize access due to concurrent update" /tmp/authz_governance_rr.out; then
  echo "ok    a delete with an older snapshot than a request on the folder gets a serialization error"
else echo "FAIL  a delete with an older snapshot than a request: $(tr '\n' ' ' < /tmp/authz_governance_rr.out)"; fails=$((fails + 1)); fi
admin "... and the folder and the request are both still there" "1|1" \
  "SELECT (SELECT count(*) FROM app.folders WHERE id = 41) || '|' || (SELECT count(*) FROM authz.requests WHERE object_id = '41' AND status = 'pending')"
rm -f /tmp/authz_governance_rr.out
PSQL -c "DELETE FROM app.folders WHERE id IN (41, 42, 43)" >/dev/null
# a request whose requester was deleted while no trigger watched (after rowstile remove, before the next apply):
# applying the policy cancels it
PSQL -c "INSERT INTO authz.requests (object_type, object_id, relation, requester, reason) VALUES ('folder', '6', 'viewer', '77', 'left over')" >/dev/null
RQS=$(as 4 -c "SELECT authz.request_access('folder', 6, 'viewer', 'dave still needs it')")
reapply /tmp/authz_governance.sql
admin "applying the policy cancels the pending requests of requesters whose row is gone" "cancelled|its requester is gone" \
  "SELECT status || '|' || note FROM authz.requests WHERE requester = '77'"
admin "... and keeps the pending requests of requesters who are there" "pending|" \
  "SELECT status || '|' || coalesce(note, '') FROM authz.requests WHERE id = $RQS"

echo "-- access reviews"
as 5 -c "SELECT authz.share('folder', 5, 'viewer', 'user', 4)" >/dev/null
expect_code "carol cannot review Secrets" "42501: you cannot review folder 5" -c "SET authz.user_id = 3" -c "SELECT authz.start_review('folder', '5')"
# another review, of Company, left open beside it (and opened first): closing one closes that one only
as 5 -c "SELECT authz.share('folder', 1, 'viewer', 'user', 4)" >/dev/null
OTHER=$(as 5 -c "SELECT authz.start_review('folder', '1')")
REV=$(as 5 -c "SELECT authz.start_review('folder', '5')")
check "erin's review lists every share on Secrets" "2" "SET authz.user_id = 5; SELECT count(*) FROM authz.review_items($REV)"
ITEM=$(as 5 -c "SELECT item FROM authz.review_items($REV) WHERE subject_id = '3'")
as 5 -c "SELECT authz.review_decide($REV, $ITEM, false)" >/dev/null
expect_code "carol cannot decide in it" "42501: you cannot decide in review $REV" -c "SET authz.user_id = 3" -c "SELECT authz.review_decide($REV, $ITEM, true)"
expect_code "... nor read its items" "42501: you cannot see review $REV" -c "SET authz.user_id = 3" -c "SELECT * FROM authz.review_items($REV)"
expect_code "... nor close it" "42501: you cannot close review $REV" -c "SET authz.user_id = 3" -c "SELECT authz.close_review($REV)"
expect_code "erin decides on the items it has" "P0001: no item 999 in review $REV" -c "SET authz.user_id = 5" -c "SELECT authz.review_decide($REV, 999, false)"
# a share on a file with the folder's id, relation and subject is no item of the folder's review
PSQL -c "INSERT INTO authz.shares (object_type, object_id, relation, subject_type, subject_id) VALUES ('file', '5', 'viewer', 'user', '3')" >/dev/null
check "closing the review revokes what was marked" "1" "SET authz.user_id = 5; SELECT authz.close_review($REV)"
admin "... on the folder only: a file's share like it stays" "1" \
  "SELECT count(*) FROM authz.shares WHERE object_type = 'file' AND object_id = '5' AND relation = 'viewer' AND subject_id = '3'"
PSQL -c "DELETE FROM authz.shares WHERE object_type = 'file' AND object_id = '5' AND subject_id = '3'" >/dev/null
check "... carol lost the offer letter" "f" "SET authz.user_id = 3; SELECT authz.can('file', 13, 'view')"
check "... dave (not decided) kept it" "t" "SET authz.user_id = 4; SELECT authz.can('file', 13, 'view')"
expect_code "... and the other review is still open: erin decides in it" ok -c "SET authz.user_id = 5" -c "BEGIN" \
  -c "SELECT authz.review_decide($OTHER, (SELECT min(item) FROM authz.review_items($OTHER)), true)" -c "ROLLBACK"
expect_code "... but not while viewing as someone: read-only" "42501: this session is read-only (viewing as someone else, or a read-only token)" \
  -c "SET authz.user_id = 5" -c "SET authz.acting_user = '1'" -c "SELECT authz.review_decide($OTHER, (SELECT min(item) FROM authz.review_items($OTHER)), true)"
check "closing it gives its reason to that transaction only: a share after it has none" "none" \
  "SET authz.user_id = 5; BEGIN; SELECT authz.close_review($OTHER); COMMIT; SELECT authz.share('folder', 3, 'viewer', 'user', 2);
   RESET ROLE; SELECT coalesce(reason, 'none') FROM authz.audit WHERE action = 'share' ORDER BY id DESC LIMIT 1"
as 5 -c "SELECT authz.unshare('folder', 3, 'viewer', 'user', 2)" -c "SELECT authz.unshare('folder', 1, 'viewer', 'user', 4)" >/dev/null
expect_code "a closed review cannot be changed" "42501: you cannot decide in review $REV" -c "SET authz.user_id = 5" -c "SELECT authz.review_decide($REV, 1, false)"
admin "the audit trail has the requests, their answers and the reviews" "approve_request|close_review|deny_request|request_access|start_review" \
  "SELECT string_agg(DISTINCT action, '|' ORDER BY action) FROM authz.audit
   WHERE action IN ('request_access', 'approve_request', 'deny_request', 'start_review', 'close_review')"

echo "-- reviews respect 'shared by'"
sed -e 's/^  editor      : user, team#member shared$/  editor      : user, team, team#member, link shared by manage_editors/' \
    -e 's/^  can share = owner or org.admin or (parent.share and {inherit})$/&\n  can manage_editors = owner/' \
    -e 's/^  viewer      : user, team#member, org#member shared$/&\n  viewer      : user:* shared by manage_editors/' \
    example/docs.authz > /tmp/authz_governance_by.authz
grep -q "can manage_editors = owner" /tmp/authz_governance_by.authz && grep -q "shared by manage_editors" /tmp/authz_governance_by.authz &&
  grep -q "user:\* shared by manage_editors" /tmp/authz_governance_by.authz ||
  { echo "FAIL  could not make the variant policy"; fails=$((fails + 1)); }
python3 compile_policy.py /tmp/authz_governance_by.authz > /tmp/authz_governance_by.sql && reapply /tmp/authz_governance_by.sql
as 1 -c "SELECT authz.share('folder', 3, 'editor', 'user', 4)" >/dev/null
expect_code "erin (share, but not manage_editors) cannot unshare dave's editor share" "42501: you cannot unshare editor on folder 3 (needs manage_editors)" -c "SET authz.user_id = 5" \
  -c "SELECT authz.unshare('folder', 3, 'editor', 'user', 4)"
REV2=$(as 5 -c "SELECT authz.start_review('folder', '3')")
ITEM2=$(as 5 -c "SELECT item FROM authz.review_items($REV2) WHERE subject_id = '4' AND relation = 'editor'")
expect_code "... nor revoke it in a review" "42501: you cannot decide on editor in review $REV2 (you could not unshare it)" -c "SET authz.user_id = 5" -c "SELECT authz.review_decide($REV2, $ITEM2, false)"
check "... nor by closing the review with undecided items revoked" "0" "SET authz.user_id = 5; SELECT authz.close_review($REV2, true)"
check "dave is still an editor" "t" "SET authz.user_id = 4; SELECT authz.can('folder', 3, 'edit')"
# a share with every user is shared by manage_editors, though a share with one user is shared by share
as 1 -c "SELECT authz.share('folder', 3, 'viewer', 'user', '*')" >/dev/null
expect_code "erin cannot unshare what alice shared with every user (needs manage_editors)" \
  "42501: you cannot unshare viewer on folder 3 (needs manage_editors)" -c "SET authz.user_id = 5" -c "SELECT authz.unshare('folder', 3, 'viewer', 'user', '*')"
as 1 -c "SELECT authz.unshare('folder', 3, 'viewer', 'user', '*')" >/dev/null
as 1 -c "SELECT authz.create_link('folder', 3, 'editor')" >/dev/null
LINK=$(as 1 -c "SELECT id FROM authz.list_links('folder', 3)")
check "erin (share) sees the editors' link alice made" "$LINK|editor|1"   "SET authz.user_id = 5; SELECT id || '|' || relation || '|' || created_by FROM authz.list_links('folder', 3)"
REV3=$(as 5 -c "SELECT authz.start_review('folder', '3')")
check "... and a review of the folder lists it as (link), as the audit trail does" "editor|link|(link)" \
  "SET authz.user_id = 5; SELECT relation || '|' || subject_type || '|' || subject_id FROM authz.review_items($REV3) WHERE subject_type = 'link'"
expect_code "... but cannot turn it off (not manage_editors)" "42501: you cannot turn off link " -c "SET authz.user_id = 5"   -c "SELECT authz.revoke_link('folder', 3, '$LINK')"
expect_code "a read-only session turns no link off" "42501: this session is read-only (viewing as someone else, or a read-only token)" -c "SET authz.user_id = 1" -c "SET authz.scopes = 'read'"   -c "SELECT authz.revoke_link('folder', 3, '$LINK')"
admin "the link is still there" "1" "SELECT count(*) FROM authz.shares WHERE object_type = 'folder' AND object_id = '3' AND subject_type = 'link'"
as 1 -c "SELECT authz.revoke_link('folder', 3, '$LINK')" >/dev/null
admin "alice (manage_editors) turns it off, and the audit trail has it as an unshare of hers" "unshare|1|folder|3|editor|link"   "SELECT action || '|' || user_id || '|' || object_type || '|' || object_id || '|' || relation || '|' || subject_type
   FROM authz.audit ORDER BY id DESC LIMIT 1"
as 1 -c "SELECT authz.create_link('folder', 3, 'editor')" >/dev/null
admin "an administrator lists a link and turns it off" "0"   "SELECT authz.revoke_link('folder', 3, (SELECT id FROM authz.list_links('folder', 3))); SELECT count(*) FROM authz.list_links('folder', 3)"
# a team itself and its members are two shares: a review revokes the one it was asked to
as 1 -c "SELECT authz.share('folder', 3, 'editor', 'team', 11)" -c "SELECT authz.share('folder', 3, 'editor', 'team', 11, 'member')" >/dev/null
editors() { echo "SELECT string_agg(subject_type || ':' || subject_id || ':' || subject_relation, ', ' ORDER BY subject_type, subject_relation)
   FROM authz.shares WHERE object_type = 'folder' AND object_id = '3' AND relation = 'editor'"; }
REV4=$(as 1 -c "SELECT authz.start_review('folder', '3')")
item() { as 1 -c "SELECT item FROM authz.review_items($1) WHERE subject_type = '$2' AND subject_relation = '$3'"; }
as 1 -c "SELECT authz.review_decide($REV4, $(item "$REV4" user ''), true)" -c "SELECT authz.review_decide($REV4, $(item "$REV4" team member), false)" >/dev/null
check "alice keeps dave, revokes team 11's members and leaves team 11 undecided: closing revokes one share" "1" \
  "SET authz.user_id = 1; SELECT authz.close_review($REV4)"
admin "... the members' one, not the team's own" "team:11:, user:4:" "$(editors)"
REV5=$(as 1 -c "SELECT authz.start_review('folder', '3')")
as 1 -c "SELECT authz.review_decide($REV5, $(item "$REV5" user ''), true)" >/dev/null
check "closing with undecided items revoked revokes the one nobody decided" "1" "SET authz.user_id = 1; SELECT authz.close_review($REV5, true)"
admin "... and keeps the one marked keep" "user:4:" "$(editors)"
reapply /tmp/authz_governance.sql
as 1 -c "SELECT authz.unshare('folder', 3, 'editor', 'user', 4)" >/dev/null

echo "-- invariants"
admin "the example data keeps the invariant" "0" "SELECT count(*) FROM authz.check_invariants()"
admin "checking them as everyone leaves the session signed in as it was" "5" \
  "BEGIN; SET LOCAL authz.user_id = '5'; SELECT count(*) FROM authz.check_invariants(); SELECT current_setting('authz.user_id'); COMMIT;"
PSQL -c "UPDATE app.folders SET owner_id = 6 WHERE id = 4" >/dev/null
admin "a Globex user owning an Acme folder breaks it" "6|{4}" \
  "SELECT user_id || '|' || object_ids::text FROM authz.check_invariants()"
got=$(psql -X -q -At -d "$DB" -f <(python3 compile_policy.py example/docs.authz --tests) 2>&1)
inv="invariant never folder: share and not org.member (line $(grep -n '^  never folder: ' example/docs.authz | cut -d: -f1))"
case "$got" in *"WARNING:  FAIL  $inv: $inv: user 6 can reach {4}"*"policy test(s) failed"*) echo "ok    the policy tests fail on it, naming the invariant, its line and who breaks it";;
  *) echo "FAIL  policy tests with a broken invariant: $got"; fails=$((fails + 1));; esac
# an invariant is checked in a view of its own: a permission of its type named never_1 takes nothing from it
sed 's/^  can break_glass = org.member$/&\n  can never_1 = owner/' example/docs.authz > /tmp/authz_governance_never.authz
grep -q "^  can never_1 = owner$" /tmp/authz_governance_never.authz || { echo "FAIL  could not make the policy with never_1"; fails=$((fails + 1)); }
python3 compile_policy.py /tmp/authz_governance_never.authz > /tmp/authz_governance_never.sql && reapply /tmp/authz_governance_never.sql
admin "... also beside a permission folder.never_1" "6|{4}" "SELECT user_id || '|' || object_ids::text FROM authz.check_invariants()"
reapply /tmp/authz_governance.sql
PSQL -c "UPDATE app.folders SET owner_id = 1 WHERE id = 4" >/dev/null
expect_code "the app role cannot run the invariant check" "42501: permission denied for function check_invariants" -c "SELECT * FROM authz.check_invariants()"

got=$(psql -X -q -At -d "$DB" -c "SET ROLE app_user" -c "SET client_min_messages = log" -c "SET authz_debug.log_decisions = on" \
       -c "SET authz.user_id = 1" -c "SELECT authz.can('file', E'11\\nauthz decision: forged', 'view')" 2>&1)
case "$got" in *$'\n'"authz decision: forged"*) echo "FAIL  a forged log line: $got"; fails=$((fails + 1));;
  *) echo "ok    ids cannot start a line of their own in the log";; esac
echo "-- decision logs"
got=$(psql -X -q -At -d "$DB" -c "SET ROLE app_user" -c "SET client_min_messages = log" -c "SET authz_debug.log_decisions = on" \
       -c "SET authz.user_id = 1" -c "SELECT authz.can('file', 11, 'view')" 2>&1)
case "$got" in *'authz decision: user="1" type="file" id="11" perm="view" -> true'*) echo "ok    each decision is logged when asked";;
  *) echo "FAIL  decision log: $got"; fails=$((fails + 1));; esac
got=$(psql -X -q -At -d "$DB" -c "SET ROLE app_user" -c "SET client_min_messages = log" -c "SET authz_debug.log_decisions = on" \
       -c "SET authz.user_id = 1" -c "SELECT authz.can('file', 11, 'view'), authz.can('folder', 6, 'view')" 2>&1 | grep -o 'authz decision: .*' | paste -sd'|')
[ "$got" = 'authz decision: user="1" type="file" id="11" perm="view" -> true|authz decision: user="1" type="folder" id="6" perm="view" -> false' ] &&
  echo "ok    ... every one, two in one statement too" || { echo "FAIL  two decisions in one statement: $got"; fails=$((fails + 1)); }
got=$(psql -X -q -At -d "$DB" -c "SET ROLE app_user" -c "SET client_min_messages = log" -c "SET authz_debug.log_decisions = on" \
       -c "SELECT authz.can('file', 11, 'view')" 2>&1)
case "$got" in *'authz decision: user=none type="file" id="11" perm="view" -> false'*) echo "ok    ... and in a session where nobody has signed in yet, as user none";;
  *) echo "FAIL  decision log with nobody signed in: $got"; fails=$((fails + 1));; esac

echo "-- previewing a policy change"
TMPD=$(mktemp -d)
sed -e 's/^           or linked_into.view .*$//' -e 's/^  linked_into : folder *= .*$//' example/docs.authz > "$TMPD/nolinks.authz"
grep -q "linked_into" "$TMPD/nolinks.authz" && { echo "FAIL  could not make the policy without links"; fails=$((fails + 1)); }
COUNTS="SELECT (SELECT count(*) FROM authz.shares) || '|' || (SELECT count(*) FROM authz.audit) || '|' || (SELECT count(*) FROM authz.changes)"
BEFORE=$(PSQL -c "$COUNTS")
python3 compile_policy.py "$TMPD/nolinks.authz" --diff > "$TMPD/diff.sql" &&
out=$(PGOPTIONS="-c client_min_messages=error" psql -X -q -d "$DB" -f "$TMPD/diff.sql" 2>&1)
case "$out" in *"loses  | 5       | file        | permission view | 16"*) echo "ok    without links, erin would lose joint-plan.md";;
  *) echo "FAIL  diff: $out"; fails=$((fails + 1));; esac
case "$out" in *"loses  | 5       | app.files   | rows readable   | 16"*) echo "ok    ...and could no longer read its row";;
  *) echo "FAIL  diff rows: $out"; fails=$((fails + 1));; esac
case "$out" in *gains*) echo "FAIL  the diff shows gains: $out"; fails=$((fails + 1));; *) echo "ok    ...and nobody gains anything";; esac
check "the preview changed nothing" "t" "SET authz.user_id = 5; SELECT authz.can('file', 16, 'view')"
admin "... not even the trail or the feed" "$BEFORE" "$COUNTS"
# the preview signs in as each user in turn, then signs back in whoever it found signed in
out=$(sed 's/^ROLLBACK;$/SELECT '"'"'signed in after the preview: '"'"' || current_setting('"'"'authz.user_id'"'"');/' "$TMPD/diff.sql" |
      PGOPTIONS="-c client_min_messages=error -c authz.user_id=5" psql -X -q -At -d "$DB" 2>&1 | tail -n 1)
[ "$out" = "signed in after the preview: 5" ] && echo "ok    the preview leaves signed in whoever it found" ||
  { echo "FAIL  who is signed in after the preview: $out"; fails=$((fails + 1)); }
out=$(python3 compile_policy.py "$TMPD/nolinks.authz" --diff --users 1,3 | PGOPTIONS="-c client_min_messages=error" psql -X -q -d "$DB" 2>&1)
case "$out" in *"| 5 "*|*ERROR*) echo "FAIL  --users 1,3 shows other users: $out"; fails=$((fails + 1));; *) echo "ok    --users limits the preview";; esac
rm -rf "$TMPD"

echo "-- ways around row-level security (authz.lint)"
admin "the example has no errors or warnings" "0" "SELECT count(*) FROM authz.lint() WHERE severity IN ('error', 'warning')"
# a rule for a command the app role has no privilege for never applies, and the statement fails with Postgres's
# own message: a warning that says what to grant. A privilege on one column is enough for an update
PSQL -c "REVOKE DELETE, UPDATE ON app.files FROM app_user" >/dev/null
admin "lint finds a delete rule the app role has no privilege for" "1" \
  "SELECT count(*) FROM authz.lint() WHERE severity = 'warning' AND object = 'app.files' AND problem LIKE 'the policy has a rule for delete, but app_user has no DELETE privilege%GRANT DELETE ON app.files TO app_user%'"
admin "... and an update rule" "1" \
  "SELECT count(*) FROM authz.lint() WHERE object = 'app.files' AND problem LIKE 'the policy has a rule for update,%'"
PSQL -c "GRANT UPDATE (name) ON app.files TO app_user" >/dev/null
admin "... not once it may update one column" "0" \
  "SELECT count(*) FROM authz.lint() WHERE object = 'app.files' AND problem LIKE 'the policy has a rule for update,%'"
PSQL -c "REVOKE UPDATE (name) ON app.files FROM app_user" -c "GRANT DELETE, UPDATE ON app.files TO app_user" >/dev/null
admin "... and none with the privileges back" "0" "SELECT count(*) FROM authz.lint() WHERE problem LIKE 'the policy has a rule for %'"
# a relation named like a type that doesn't sign in (file.folder, folder.org) is nobody's mistake: no note
admin "lint has no note on a relation named like a type that doesn't sign in" "0" \
  "SELECT count(*) FROM authz.lint() WHERE problem LIKE 'is named like the type%'"
# without its column rule, whoever may edit a file may make themselves its owner: lint asks for a rule, and
# suggests the type's own share
grep -v "update id, owner_id, confidential" example/docs.authz > /tmp/authz_no_column_rule.authz
python3 compile_policy.py /tmp/authz_no_column_rule.authz > /tmp/authz_no_column_rule.sql && reapply /tmp/authz_no_column_rule.sql
admin "lint finds a column that gives a relation and that an editor may change" "1" \
  "SELECT count(*) FROM authz.lint() WHERE object = 'app.files.owner_id' AND problem LIKE 'grants file.owner%add a rule such as \"update owner_id : share\"'"
# ...and has nothing to say when nobody may update the row at all
sed 's/^  update  *: edit$/  update : nobody/' /tmp/authz_no_column_rule.authz | grep -v "update folder_id after" > /tmp/authz_update_nobody.authz
python3 compile_policy.py /tmp/authz_update_nobody.authz > /tmp/authz_update_nobody.sql && reapply /tmp/authz_update_nobody.sql
admin "...and none where the rule is \"update : nobody\"" "0" \
  "SELECT count(*) FROM authz.lint() WHERE object LIKE 'app.files.%' AND problem LIKE 'grants %'"
reapply /tmp/authz_governance.sql
PSQL -c "GRANT TRUNCATE ON app.files TO app_user" \
     -c "CREATE VIEW app.all_files AS SELECT * FROM app.files" -c "GRANT SELECT ON app.all_files TO app_user" \
     -c "GRANT INSERT, TRUNCATE ON app.team_members TO app_user" \
     -c "CREATE UNIQUE INDEX files_name ON app.files (folder_id, name)" \
     -c "CREATE FUNCTION app.peek(bigint) RETURNS text LANGUAGE sql SECURITY DEFINER AS 'SELECT name FROM app.files WHERE id = \$1'" >/dev/null
lint() { PSQL -c "SELECT severity || ' ' || object FROM authz.lint() ORDER BY 1" | grep -c -- "$1"; }
for want in "error app.files" "error app.all_files" "error app.team_members" "info app.files_name" "info app.files_pkey" "warning app.peek(bigint)"; do
  [ "$(lint "^$want\$")" -ge 1 ] && echo "ok    lint finds: $want" || { echo "FAIL  lint misses: $want"; fails=$((fails + 1)); }
done
# (the link table's key the app role may insert into is no governed table's: its rows hide nothing)
[ "$(lint "^info app.team_members_pkey\$")" = 0 ] && echo "ok    ... and not the key of a table without rules" ||
  { echo "FAIL  lint names the key of a table without rules"; fails=$((fails + 1)); }
admin "... of the link table, that the app role may change it (an insert is enough)" "1" \
  "SELECT count(*) FROM authz.lint() WHERE object = 'app.team_members' AND problem LIKE '%may change it, and it decides who is in what%'"
admin "... and says of the function what it does" \
  "SECURITY DEFINER, callable by the app role, and seems to use a governed table: it reads rows without row-level security unless its owner is subject to it" \
  "SELECT problem FROM authz.lint() WHERE object = 'app.peek(bigint)'"
# a unique index on a table without rules tells nothing the app role may not read: only a governed table's is named
PSQL -c "CREATE UNIQUE INDEX gov_team_pairs ON app.team_members (user_id, team_id)" >/dev/null
admin "... and of the unique indexes the app role may insert against, those on tables with rules only" \
  "app.files_name|a unique index on app.files: inserting a duplicate fails even when the existing row is hidden, which tells the user it exists" \
  "SELECT string_agg(object || '|' || problem, ', ') FROM authz.lint() WHERE problem LIKE 'a unique index on %'"
PSQL -c "DROP INDEX app.gov_team_pairs" >/dev/null
# nor one on a governed table the app role may not insert into
PSQL -c "CREATE UNIQUE INDEX gov_folder_names ON app.folders (id, name)" -c "REVOKE INSERT ON app.folders FROM app_user" >/dev/null
admin "... nor of a table the app role may not insert into" "0" "SELECT count(*) FROM authz.lint() WHERE object = 'app.gov_folder_names'"
PSQL -c "GRANT INSERT ON app.folders TO app_user" -c "DROP INDEX app.gov_folder_names" >/dev/null
# a table beside the policy's that it doesn't name: said, while the app role may read it
PSQL -c "CREATE TABLE app.secrets (id int PRIMARY KEY, hash text)" -c "GRANT SELECT ON app.secrets TO app_user" >/dev/null
admin "lint finds a table the policy doesn't name, which the app role may read" "info" \
  "SELECT severity FROM authz.lint() WHERE object = 'app.secrets' AND problem LIKE '%the policy doesn''t name this table%'"
PSQL -c "REVOKE SELECT ON app.secrets FROM app_user" -c "GRANT SELECT (id) ON app.secrets TO app_user" >/dev/null
admin "... also when it may read one column of it" "1" "SELECT count(*) FROM authz.lint() WHERE object = 'app.secrets'"
PSQL -c "REVOKE SELECT (id) ON app.secrets FROM app_user" >/dev/null
admin "... and not once it may not" "0" "SELECT count(*) FROM authz.lint() WHERE object = 'app.secrets'"
admin "... nor a table the policy names (users has no rules: its own line)" "1" "SELECT count(*) FROM authz.lint() WHERE object = 'app.users'"
PSQL -c "DROP TABLE app.secrets" >/dev/null
# a policy made by hand on a governed table: Postgres joins permissive policies with OR, so it widens the rules
ALL=$(PSQL -c "SELECT count(*) FROM app.files"); SEES=$(as 4 -c "SELECT count(*) FROM app.files")
[ "$SEES" -lt "$ALL" ] && echo "ok    dave sees $SEES of the $ALL files" || { echo "FAIL  dave sees $SEES of $ALL files"; fails=$((fails + 1)); }
PGOPTIONS="-c client_min_messages=error" PSQL -c "DROP ROLE IF EXISTS authz_gov_other" -c "CREATE ROLE authz_gov_other" \
     -c "CREATE POLICY mine ON app.files FOR SELECT TO app_user USING (true)" \
     -c "CREATE POLICY everyone ON app.folders USING (true) WITH CHECK (true)" \
     -c "CREATE POLICY narrower ON app.folders AS RESTRICTIVE TO app_user USING (name <> 'x')" \
     -c "CREATE POLICY theirs ON app.files TO authz_gov_other USING (true)" >/dev/null
check "... and every file through a policy of the owner's making" "$ALL" "SET authz.user_id = 4; SELECT count(*) FROM app.files"
admin "lint finds it: an error, with the policy's name, why it widens the rules and how to drop it" \
  "error|the policy mine (select) on it is not rowstile's: Postgres joins a table's policies with OR, so it lets app_user through whatever the rules say. DROP POLICY mine ON app.files, and say what it allowed in the policy file" \
  "SELECT severity || '|' || problem FROM authz.lint() WHERE object = 'app.files' AND problem LIKE 'the policy mine %'"
admin "... one for PUBLIC and every command too" "error" \
  "SELECT severity FROM authz.lint() WHERE object = 'app.folders' AND problem LIKE 'the policy everyone (every command)%'"
admin "... a restrictive one is a note" "info" \
  "SELECT severity FROM authz.lint() WHERE object = 'app.folders' AND problem LIKE 'the restrictive policy narrower%'"
admin "... one for a role the app role isn't in is nobody's way around" "0" \
  "SELECT count(*) FROM authz.lint() WHERE problem LIKE '%theirs%'"
PSQL -c "DROP POLICY mine ON app.files" -c "DROP POLICY theirs ON app.files" -c "DROP POLICY everyone ON app.folders" \
     -c "DROP POLICY narrower ON app.folders" -c "DROP ROLE authz_gov_other" >/dev/null
admin "... rowstile's own policies are not reported" "0" "SELECT count(*) FROM authz.lint() WHERE problem LIKE '%not rowstile''s%'"
PSQL -c "GRANT CREATE ON SCHEMA app TO app_user" -c "ALTER TABLE app.files OWNER TO app_user" >/dev/null
[ "$(PSQL -c "SELECT count(*) FROM authz.lint() WHERE object = 'app.files' AND problem LIKE 'is owned by%'")" = "1" ] &&
  echo "ok    lint finds: a governed table owned by the app role" || { echo "FAIL  lint misses the owner"; fails=$((fails + 1)); }
PSQL -c "ALTER TABLE app.files OWNER TO CURRENT_USER" -c "REVOKE CREATE ON SCHEMA app FROM app_user" >/dev/null
# ...and by a role the app role is a member of, whose rights it has
PGOPTIONS="-c client_min_messages=error" PSQL -c "DROP ROLE IF EXISTS authz_gov_owners" -c "CREATE ROLE authz_gov_owners" \
     -c "GRANT authz_gov_owners TO app_user" -c "GRANT CREATE ON SCHEMA app TO authz_gov_owners" -c "ALTER TABLE app.files OWNER TO authz_gov_owners" >/dev/null
admin "... and one owned by a role the app role is a member of" \
  "error|is owned by app_user (or a role it belongs to): owners skip row-level security unless you ALTER TABLE app.files FORCE ROW LEVEL SECURITY" \
  "SELECT severity || '|' || problem FROM authz.lint() WHERE object = 'app.files' AND problem LIKE 'is owned by%'"
PSQL -c "ALTER TABLE app.files OWNER TO CURRENT_USER" -c "REVOKE CREATE ON SCHEMA app FROM authz_gov_owners" -c "DROP ROLE authz_gov_owners" >/dev/null
PSQL -c "ALTER TABLE app.files DISABLE ROW LEVEL SECURITY" >/dev/null
admin "lint finds row-level security off on a table with rules: an error" "1"   "SELECT count(*) FROM authz.lint() WHERE severity = 'error' AND object = 'app.files' AND problem LIKE 'row-level security is off%'"
PSQL -c "ALTER TABLE app.files ENABLE ROW LEVEL SECURITY" >/dev/null
expect_code "the app role cannot run lint" "42501: permission denied for function lint" -c "SELECT * FROM authz.lint()"
# without its 'after' rule, moving a folder isn't checked where it goes
grep -v "update parent_id after" example/docs.authz > /tmp/authz_no_after.authz
python3 compile_policy.py /tmp/authz_no_after.authz > /tmp/authz_no_after.sql && reapply /tmp/authz_no_after.sql
admin "lint finds a move nothing checks the destination of" "1" \
  "SELECT count(*) FROM authz.lint() WHERE object = 'app.folders.parent_id' AND problem LIKE 'moves a row under another%'"
# nor where nobody may update a folder at all (no update rule, so no 'after' rule nor column rule either)
grep -v -e "^  update parent_id after" -e "^  update                               : edit$" -e "^  update id, owner_id, org_id, inherit : share$" \
  example/docs.authz > /tmp/authz_no_update.authz
python3 compile_policy.py /tmp/authz_no_update.authz > /tmp/authz_no_update.sql && reapply /tmp/authz_no_update.sql
admin "... but none where nobody may update the row" "0" \
  "SELECT count(*) FROM authz.lint() WHERE problem LIKE 'moves a row under another%'"
rm -f /tmp/authz_no_update.authz /tmp/authz_no_update.sql
reapply /tmp/authz_governance.sql
admin "...and none with the rule back" "0" \
  "SELECT count(*) FROM authz.lint() WHERE problem LIKE 'moves a row under another%'"
# a row keyed by two columns, moved by the pair: lint names the pair and the rule to add (it failed on the pair as
# one column's name, and so did applying such a policy)
PSQL -c "CREATE TABLE app.gov_boxes (org_id bigint, id bigint, parent_id bigint, owner_id bigint, PRIMARY KEY (org_id, id))" \
     -c "GRANT SELECT, UPDATE ON app.gov_boxes TO app_user" >/dev/null
{ sed '/^test$/,$d' example/docs.authz
  printf 'type box = app.gov_boxes (org_id, id)\n  parent : box  = [org_id, parent_id]\n  owner  : user = owner_id\n  can edit = owner or parent.edit\n'
  printf 'rules app.gov_boxes\n  select : edit\n  update : edit\n'; } > /tmp/authz_boxes.authz
python3 compile_policy.py /tmp/authz_boxes.authz > /tmp/authz_boxes.sql &&
PGOPTIONS="-c client_min_messages=error" psql -X -q -v ON_ERROR_STOP=1 -d "$DB" -f /tmp/authz_boxes.sql >/dev/null
admin "lint finds a move by a pair of columns, and says the rule to add" "1" \
  "SELECT count(*) FROM authz.lint() WHERE object = 'app.gov_boxes.org_id, parent_id' AND problem LIKE '%add a rule such as \"update org_id, parent_id after : parent.edit\"'"
# each check on one box finds its row by the type's key (org_id, id): its primary key serves it; without one lint
# names it, with the index to add; an index whose first columns are the key's, in another order, serves it too
admin "lint: a type's key that its primary key serves is no finding" "0" \
  "SELECT count(*) FROM authz.lint() WHERE object = 'app.gov_boxes.org_id, id'"
PSQL -c "ALTER TABLE app.gov_boxes DROP CONSTRAINT gov_boxes_pkey" >/dev/null
admin "... without it, lint names the lookup by the key, and the index to add" "1" \
  "SELECT count(*) FROM authz.lint() WHERE object = 'app.gov_boxes.org_id, id' AND severity = 'performance' AND problem = 'no index starts with these columns (box: find one by its key, for checks and write rules): CREATE INDEX ON app.gov_boxes (org_id, id)'"
PSQL -c "CREATE INDEX ON app.gov_boxes (id, org_id, owner_id)" >/dev/null
admin "... and an index that starts with the key's columns, in another order, serves it" "0" \
  "SELECT count(*) FROM authz.lint() WHERE object = 'app.gov_boxes.org_id, id'"
PGOPTIONS="-c client_min_messages=error" psql -X -q -v ON_ERROR_STOP=1 -d "$DB" -f /tmp/authz_governance.sql >/dev/null
PSQL -c "DROP TABLE app.gov_boxes" >/dev/null
# a row placed under a node or a folder by a (type, id) pair of columns (named as no other table's are): both grant
# a relation, and the id moves the row; an 'after' rule on the whole row checks where it goes
PSQL -c "CREATE TABLE app.gov_nodes (id bigint PRIMARY KEY, node_kind text, node_above bigint, owner_id bigint)" \
     -c "GRANT SELECT, UPDATE ON app.gov_nodes TO app_user" >/dev/null
{ sed '/^test$/,$d' example/docs.authz
  printf 'type node = app.gov_nodes\n  above : node, folder = (node_kind, node_above)\n  owner : user = owner_id\n  can edit = owner or above.edit\n'
  printf 'rules app.gov_nodes\n  select : edit\n  update : edit\n'; } > /tmp/authz_nodes.authz
python3 compile_policy.py /tmp/authz_nodes.authz > /tmp/authz_nodes.sql && reapply /tmp/authz_nodes.sql
admin "lint finds both columns of a (type, id) pair that grant a relation an editor may change" \
  "app.gov_nodes.node_above,app.gov_nodes.node_kind,app.gov_nodes.owner_id" \
  "SELECT string_agg(object, ',' ORDER BY object) FROM authz.lint() WHERE object LIKE 'app.gov_nodes.%' AND problem LIKE 'grants %'"
L=$(grep -n '^  above : node, folder' /tmp/authz_nodes.authz | cut -d: -f1)
admin "... and the move by its id, which nothing checks the destination of" \
  "warning|moves a row under another (above, line $L), and nothing checks where it moves to, so anyone who may update a row may put it inside something they may not change: add a rule such as \"update node_above after : above.edit\"" \
  "SELECT severity || '|' || problem FROM authz.lint() WHERE object = 'app.gov_nodes.node_above' AND problem LIKE 'moves %'"
printf '  update after : edit\n' >> /tmp/authz_nodes.authz
python3 compile_policy.py /tmp/authz_nodes.authz > /tmp/authz_nodes.sql && reapply /tmp/authz_nodes.sql
admin "... and none with an 'after' rule for every column" "0" "SELECT count(*) FROM authz.lint() WHERE problem LIKE 'moves a row under another%'"
reapply /tmp/authz_governance.sql
PSQL -c "DROP TABLE app.gov_nodes" >/dev/null
rm -f /tmp/authz_nodes.authz /tmp/authz_nodes.sql
# a permission that names others more than once is slow to plan wherever it is checked, a rule or not: here no rule
# reads note.read, and authz.list and authz.can plan its 191 views (p6 names p5 twice, ... down to p0)
PSQL -c "CREATE TABLE app.gov_crowds (id bigint PRIMARY KEY, a boolean, b boolean)" \
     -c "CREATE TABLE app.gov_crowd_members (crowd_id bigint, user_id bigint)" \
     -c "CREATE TABLE app.gov_notes (id bigint PRIMARY KEY, crowd_id bigint)" \
     -c "INSERT INTO app.gov_crowds VALUES (1, true, false), (2, false, false)" \
     -c "INSERT INTO app.gov_crowd_members VALUES (1, 1), (2, 1)" -c "INSERT INTO app.gov_notes VALUES (1, 1), (2, 2), (3, 1)" >/dev/null
{ sed '/^test$/,$d' example/docs.authz
  printf 'type crowd = app.gov_crowds\n  member : user = app.gov_crowd_members(crowd_id -> user_id)\n  can p0 = member\n'
  for n in 1 2 3 4 5 6; do printf '  can p%s = (p%s and {a}) or (p%s and {b})\n' $n $((n - 1)) $((n - 1)); done
  printf 'type note = app.gov_notes\n  crowd : crowd = crowd_id\n  can read = crowd.p6\n'; } > /tmp/authz_crowds.authz
python3 compile_policy.py /tmp/authz_crowds.authz > /tmp/authz_crowds.sql &&
PGOPTIONS="-c client_min_messages=error" psql -X -q -v ON_ERROR_STOP=1 -d "$DB" -f /tmp/authz_crowds.sql >/dev/null
L=$(grep -n '^  can read = crowd.p6$' /tmp/authz_crowds.authz | cut -d: -f1)
admin "lint finds a permission no rule reads that is slow to plan, and says its line and how many views" \
  "warning|note.read|names permissions that name others more than once (line $L), and Postgres writes each one out again every time: 191 view definitions to plan each check of it (authz.list, authz.can, a rule that names it) before a row is read, which can take a tenth of a second and more, up to a second or two. Name each permission once on the way" \
  "SELECT severity || '|' || object || '|' || problem FROM authz.lint() WHERE object = 'note.read'"
admin "... and of the permissions it names, the one that names many (64), not those before it (32 and fewer)" "crowd.p6" \
  "SELECT string_agg(object, ',' ORDER BY object) FROM authz.lint() WHERE object LIKE 'crowd.%' AND problem LIKE '%view definitions to plan%'"
check "... and authz.list answers it" "1,3" \
  "SET authz.user_id = '1'; SELECT string_agg(l, ',' ORDER BY l::int) FROM authz.list('note', 'read') l"
PGOPTIONS="-c client_min_messages=error" psql -X -q -v ON_ERROR_STOP=1 -d "$DB" -f /tmp/authz_governance.sql >/dev/null
PSQL -c "DROP TABLE app.gov_notes, app.gov_crowd_members, app.gov_crowds" >/dev/null
rm -f /tmp/authz_crowds.authz /tmp/authz_crowds.sql
# the lookups are joins, which an index with a condition doesn't serve, nor one a failed CREATE INDEX CONCURRENTLY
# left unfinished: lint names the lookup there, as rowstile indexes does
PSQL -c "DROP INDEX app.team_members_user_id_idx" -c "CREATE INDEX team_members_some ON app.team_members (user_id) WHERE user_id > 0" >/dev/null
admin "lint finds a lookup an index with a condition doesn't serve" "1" \
  "SELECT count(*) FROM authz.lint() WHERE object = 'app.team_members.user_id' AND problem LIKE 'no index starts with this column%'"
PSQL -c "DROP INDEX app.team_members_some" -c "INSERT INTO app.team_members VALUES (11, 1)" >/dev/null
psql -X -q -d "$DB" -c "CREATE UNIQUE INDEX CONCURRENTLY team_members_user_id_idx ON app.team_members (user_id)" >/dev/null 2>&1
admin "... and one a failed build left unfinished doesn't" "1" \
  "SELECT count(*) FROM authz.lint() WHERE object = 'app.team_members.user_id' AND problem LIKE 'no index starts with this column%'"
PSQL -c "DROP INDEX app.team_members_user_id_idx" -c "DELETE FROM app.team_members WHERE (team_id, user_id) = (11, 1)" \
     -c "CREATE INDEX team_members_user_id_idx ON app.team_members (user_id)" >/dev/null
# the audit trail's guard back for ordinary sessions only, as ENABLE TRIGGER ALL leaves it (a data-only pg_restore
# --disable-triggers ends with it): lint says so, and rowstile reapply puts it back in every replication role
# (applied by the command first: reapply applies again what the command applied)
bash tests/coverage_functions.sh "$DB"
python3 cli/rowstile_cli.py --db "dbname=$DB" apply example/docs.authz >/dev/null 2>&1
PSQL -c "ALTER TABLE authz.audit ENABLE TRIGGER authz_audit_append_only" >/dev/null
admin "lint finds the audit trail's guard on in ordinary sessions only, and says what puts it back" "warning" \
  "SELECT severity FROM authz.lint() WHERE object = 'authz.audit'
     AND problem LIKE 'the trigger authz_audit_append_only guards it in ordinary sessions only:%. rowstile reapply puts it back, in every replication role'"
bash tests/coverage_functions.sh "$DB"
python3 cli/rowstile_cli.py --db "dbname=$DB" reapply >/dev/null 2>&1
admin "... and nothing once rowstile reapply has run" "0" "SELECT count(*) FROM authz.lint() WHERE object = 'authz.audit'"
PSQL -c "ALTER TABLE authz.audit ENABLE REPLICA TRIGGER authz_audit_append_only" >/dev/null
admin "... and on in replica sessions only: lint says ordinary sessions may change the trail" "warning" \
  "SELECT severity FROM authz.lint() WHERE object = 'authz.audit'
     AND problem = 'the trigger authz_audit_append_only guards it with session_replication_role = replica only: an ordinary session may change the trail. rowstile reapply puts it back, in every replication role'"
PSQL -c "ALTER TABLE authz.audit ENABLE ALWAYS TRIGGER authz_audit_append_only" >/dev/null

echo "-- explaining what a link table's rows, shares and the type's where give (authz.explain)"
# a shelf holds folders by the rows of a link table that are active (not those whose active is unknown), is hosted
# by folders by sharing, and is a shelf only while it is open (one whose open is unknown is none)
PSQL -c "CREATE TABLE app.gov_shelves (id bigint PRIMARY KEY, owner_id bigint, open boolean)" \
     -c "CREATE TABLE app.gov_shelf_folders (shelf_id bigint, folder_id bigint, active boolean)" \
     -c "INSERT INTO app.gov_shelves VALUES (1, 5, true), (2, 5, true), (3, 5, NULL)" \
     -c "INSERT INTO app.gov_shelf_folders VALUES (1, 3, true), (1, 4, NULL), (1, 2, false), (2, 4, true)" >/dev/null
{ sed '/^test$/,$d' example/docs.authz
  printf 'type shelf = app.gov_shelves where {open}\n  owner  : user   = owner_id\n'
  printf '  holder : folder = app.gov_shelf_folders(shelf_id -> folder_id) where {active}\n  host   : folder shared\n'
  printf '  can share = owner\n  can view  = holder.view or host.view\n'; } > /tmp/authz_shelves.authz
python3 compile_policy.py /tmp/authz_shelves.authz > /tmp/authz_shelves.sql && reapply /tmp/authz_shelves.sql
PSQL -c "SET authz.user_id = 5" -c "SELECT authz.share('shelf', 1, 'host', 'folder', 4)" -c "SELECT authz.share('shelf', 2, 'host', 'folder', 3)" >/dev/null
admin "explain lists the folders a shelf's active rows and its own shares name, and no others" \
  "yes  user 1 holds view on shelf 1|  shelf.view = holder.view or host.view|  yes  holder.view|    yes  holder is folder 3, which has view|  yes  host.view|    yes  host is folder 4, which has view" \
  "SELECT string_agg(e, '|' ORDER BY n) FROM authz.explain('shelf', '1', 'view', '1') WITH ORDINALITY x(e, n) WHERE e NOT LIKE '      %'"
admin "... and of a shelf whose where is unknown, that it fails it" \
  "no   user 1 does not hold view on shelf 3|  no   shelf 3 fails the type's where {open}" \
  "SELECT string_agg(e, '|' ORDER BY n) FROM authz.explain('shelf', '3', 'view', '1') WITH ORDINALITY x(e, n)"
reapply /tmp/authz_governance.sql
PSQL -c "DROP TABLE app.gov_shelves, app.gov_shelf_folders" >/dev/null
rm -f /tmp/authz_shelves.authz /tmp/authz_shelves.sql

echo "-- retention"
POS=$(PSQL -c "SELECT max(pos) FROM authz.changes")
PSQL -c "UPDATE authz.changes SET at = now() - interval '10 days'" -c "INSERT INTO app.folders (org_id, parent_id, owner_id, name) VALUES (1, 1, 5, 'kept')" >/dev/null
admin "the feed keeps 7 days by default: older entries are trimmed" "t" "SELECT authz.trim_changes() > 0"
admin "... all of them" "f" "SELECT EXISTS (SELECT 1 FROM authz.changes WHERE pos <= $POS)"
admin "... newer ones stay" "t" "SELECT EXISTS (SELECT 1 FROM authz.changes WHERE pos > $POS)"
expect_code "a reader behind the trimmed part is told to read everything again" "55000: the change feed up to position " -c "RESET ROLE" \
  -c "SELECT * FROM authz.changes_since(0)"
admin "... a reader past it goes on" "t" "SELECT count(*) > 0 FROM authz.changes_since($POS)"
PSQL -c "INSERT INTO authz.settings VALUES ('changes_keep', '1 hour')" >/dev/null
admin "how long the feed keeps entries is a setting" "0" "SELECT authz.trim_changes()"
# an entry exactly as old as the period (written an hour before this transaction began) is not older: it stays
PSQL -c "SELECT authz.trim_changes(interval '0')" >/dev/null
admin "an entry exactly as old as the period stays" "0" \
  "BEGIN; INSERT INTO app.folders (org_id, parent_id, owner_id, name) VALUES (1, 1, 5, 'now');
   UPDATE authz.changes SET at = now() - interval '1 hour' WHERE pos = (SELECT max(pos) FROM authz.changes);
   SELECT authz.trim_changes(interval '1 hour'); COMMIT"
expect_code "trimming the audit trail needs a period" "22023: say how long to keep the audit trail, e.g. authz.trim_audit(interval '2 years')" -c "RESET ROLE" -c "SELECT authz.trim_audit(NULL)"
admin "entries younger than the period stay" "0" "SELECT authz.trim_audit(interval '1 day')"
N=$(PSQL -c "SELECT count(*) FROM authz.audit")
admin "... older ones go" "$N" "SELECT authz.trim_audit(interval '0')"
admin "... and the trim is recorded" "trim_audit|$N" \
  "SELECT action || '|' || (detail ->> 'rows') FROM authz.audit ORDER BY id DESC LIMIT 1"
admin "... but not one exactly as old as the period: only older ones" "1" \
  "BEGIN; INSERT INTO authz.audit (db_role, action, at) VALUES (current_user, 'just kept', now() - interval '1 hour');
   SELECT authz.trim_audit(interval '1 hour'); SELECT count(*) FROM authz.audit WHERE action = 'just kept'; ROLLBACK"
expect_code "the trail still cannot be edited otherwise" "42501: the audit trail cannot be changed" -c "RESET ROLE" -c "DELETE FROM authz.audit"
expect_code "... whatever the session sets" "42501: the audit trail cannot be changed" -c "RESET ROLE" -c "SET authz_int.trim_before = '2999-01-01'" \
  -c "DELETE FROM authz.audit"
admin "... and the trigger is on again after a trim, in every replication role" "A" \
  "SELECT tgenabled FROM pg_trigger WHERE tgrelid = 'authz.audit'::regclass AND tgname = 'authz_audit_append_only'"
if [ -n "${PGSUPERUSER:-}" ]; then
  expect_code "... so a superuser in replica role still can't delete an entry" "42501: the audit trail cannot be changed" "${REPLICA[@]}" \
    -c "DELETE FROM authz.audit"
fi
expect_code "the app role cannot trim" "42501: permission denied for function trim_audit" -c "SELECT authz.trim_audit(interval '0')"
# emptying a governed table whose own columns hold relations (a file's folder and owner): last, the files are gone
POS=$(PSQL -c "SELECT coalesce(max(pos), 0) FROM authz.changes")
# a share on a file and one to a team's members, which emptying their tables takes away
as 5 -c "SELECT authz.share('file', 13, 'viewer', 'user', 4)" -c "SELECT authz.share('folder', 1, 'viewer', 'team', 10, 'member')" >/dev/null
SHARED="SELECT count(*) FILTER (WHERE object_type = 'file') || '|' || count(*) FILTER (WHERE subject_type = 'team') FROM authz.shares"
before=$(PSQL -c "$SHARED")
{ [ "${before%%|*}" -gt 0 ] && [ "${before##*|}" -gt 0 ]; } 2>/dev/null ||
  { echo "FAIL  a share on a file and one to a team, to empty their tables under: $before"; fails=$((fails + 1)); }
PSQL -c "TRUNCATE app.files" >/dev/null
admin "emptying a table whose columns hold relations is recorded" "truncate|app.files" \
  "SELECT action || '|' || (detail ->> 'table') FROM authz.audit WHERE action = 'truncate' AND object_type = 'file'"
admin "... and announced for every file" "1" \
  "SELECT count(*) FROM authz.changes WHERE pos > $POS AND object_type = 'file' AND object_ids = '{*}'"
admin "... and the shares on its rows go with them" "0" "SELECT count(*) FROM authz.shares WHERE object_type = 'file'"
PSQL -c "TRUNCATE app.teams CASCADE" >/dev/null
admin "emptying a table takes the shares to its rows too (to a team's members), and no other" "0|true" \
  "SELECT count(*) FILTER (WHERE subject_type = 'team') || '|' || (count(*) FILTER (WHERE subject_type = 'user') > 0) FROM authz.shares"
admin "inheritance tables still match a rebuild" "t" "SELECT authz.verify()"

echo "-- a logical replication subscription that copies the trail"
# it applies its publisher's rows in replica role, the trims made there among them: the guard lets its own worker
# through, and nothing else (within one server the slot is made by hand first: CREATE SUBSCRIPTION would wait for
# itself making it)
WAL=$(PSQL -c "SHOW wal_level")
if [ "$WAL" != logical ]; then
  echo "skip  a subscription that copies the trail needs wal_level = logical, and this server has $WAL (core/ci.sh starts Postgres with logical)"
elif [ -z "${PGSUPERUSER:-}" ]; then
  echo "skip  a subscription that copies the trail needs a superuser to make it (PGSUPERUSER)"
else
  COPY_DB="${DB}_copy"
  SU() { psql -X -q -At -U "$PGSUPERUSER" "$@"; }
  dropdb --if-exists "$COPY_DB" 2>/dev/null
  createdb "$COPY_DB" && PGOPTIONS="-c client_min_messages=error" psql -X -q -v ON_ERROR_STOP=1 -d "$COPY_DB" \
    -f example/app_schema.sql -f /tmp/authz_governance.sql >/dev/null || { echo "FAIL  the database that subscribes"; fails=$((fails + 1)); }
  SU -d "$DB" -c "CREATE PUBLICATION authz_governance_trail FOR TABLE authz.audit" \
     -c "SELECT pg_create_logical_replication_slot('authz_governance_trail', 'pgoutput')" >/dev/null
  SU -d "$COPY_DB" -c "CREATE SUBSCRIPTION authz_governance_trail
       CONNECTION 'dbname=$DB host=${PGHOST:-/var/run/postgresql} port=${PGPORT:-5432} user=$PGSUPERUSER'
       PUBLICATION authz_governance_trail WITH (create_slot = false, slot_name = 'authz_governance_trail')" >/dev/null
  TRAIL="SELECT count(*) || ': ' || coalesce(string_agg(coalesce(reason, '-'), ', ' ORDER BY id), '') FROM authz.audit"
  # waits (half a minute at most) until the copy holds what is published
  copied() { for _ in $(seq 60); do [ "$(psql -X -At -d "$COPY_DB" -c "$TRAIL")" = "$(PSQL -c "$TRAIL")" ] && return 0; sleep 0.5; done; return 1; }
  copied || echo "(the copy hasn't caught up yet: $(psql -X -At -d "$COPY_DB" -c "$TRAIL" | cut -c1-80))"
  # an entry changed where it is published: only by DDL there, the owner turning the guard off a moment
  PSQL -c "BEGIN" -c "ALTER TABLE authz.audit DISABLE TRIGGER authz_audit_append_only" \
       -c "UPDATE authz.audit SET reason = 'changed where published' WHERE id = (SELECT max(id) FROM authz.audit)" \
       -c "ALTER TABLE authz.audit ENABLE ALWAYS TRIGGER authz_audit_append_only" -c "COMMIT" >/dev/null
  copied && echo "ok    a subscription that copies the trail applies an entry changed where it is published" ||
    { echo "FAIL  the copy misses the change: $(psql -X -At -d "$COPY_DB" -c "$TRAIL" | cut -c1-120)"; fails=$((fails + 1)); }
  PSQL -c "SELECT authz.trim_audit(interval '0')" >/dev/null
  copied && echo "ok    ... and the deletes of authz.trim_audit there" ||
    { echo "FAIL  the copy misses the trim: $(psql -X -At -d "$COPY_DB" -c "$TRAIL" | cut -c1-120)"; fails=$((fails + 1)); }
  got=$(psql -X -q -At -d "$COPY_DB" -v VERBOSITY=verbose -c "DELETE FROM authz.audit" 2>&1 | grep '^ERROR:  ' | tail -n 1)
  [ "$got" = "ERROR:  42501: the audit trail cannot be changed" ] && echo "ok    ... while its own sessions still can't delete an entry" ||
    { echo "FAIL  a session where the trail is copied deletes an entry: $got"; fails=$((fails + 1)); }
  # the subscription and its slot go first: neither database can be dropped while they are there (the slot's
  # sender may take a moment to stop)
  SU -d "$COPY_DB" -c "ALTER SUBSCRIPTION authz_governance_trail DISABLE" \
     -c "ALTER SUBSCRIPTION authz_governance_trail SET (slot_name = NONE)" -c "DROP SUBSCRIPTION authz_governance_trail" >/dev/null
  for _ in $(seq 20); do SU -d "$DB" -c "SELECT pg_drop_replication_slot('authz_governance_trail')" >/dev/null 2>&1 && break; sleep 0.5; done
  SU -d "$DB" -c "DROP PUBLICATION authz_governance_trail" >/dev/null
  dropdb "$COPY_DB"
fi

echo "-- this. in a condition whose subquery calls its table as the row is called (tests/hand/conditions-this-alias.authz)"
TDB="${DB}_this"
dropdb --if-exists "$TDB" 2>/dev/null; createdb "$TDB" || exit 1
TQ() { psql -X -q -At -v ON_ERROR_STOP=1 -d "$TDB" "$@" 2>&1; }
# an invariant that the marked folder 3 breaks: its condition calls app.marks r, as the invariants' views call the row
{ cat tests/hand/conditions-this-alias.authz
  printf '\ninvariants\n  never folder: owner and not {not exists (select 1 from app.marks r where r.ref_id = this.id and r.kind = %s)}\n' "'folder'"
} > /tmp/authz_governance_this.authz
PGOPTIONS="-c client_min_messages=error" psql -X -q -v ON_ERROR_STOP=1 -d "$TDB" -f tests/hand/schema.sql >/dev/null &&
python3 cli/rowstile_cli.py --db "dbname=$TDB" apply /tmp/authz_governance_this.authz >/dev/null || exit 1
TQ -c "INSERT INTO app.users (id) VALUES (1), (2), (3)" -c "INSERT INTO app.projects (id) VALUES (1)" \
   -c "INSERT INTO app.folders (id, owner_id) VALUES (1, 1), (3, 1)" \
   -c "INSERT INTO app.marks VALUES (102, 3, 'folder', NULL), (103, 1, 'membership', NULL)" \
   -c "INSERT INTO app.memberships (id, project_id, user_id) VALUES (1, 1, 2), (2, 1, 3)" >/dev/null
got=$(TQ -c "SELECT string_agg(relation || ' ' || subject_id, ', ' ORDER BY relation, subject_id) FROM authz.audit WHERE action = 'relate'")
[ "$got" = "helper 3, member 3" ] && echo "ok    the audit trail relates only the link rows whose where holds, whatever its subquery calls its table" ||
  { echo "FAIL  the audit trail of link rows with a where: $got"; fails=$((fails + 1)); }
got=$(TQ -c "SELECT string_agg(user_id || ' ' || object_ids::text, ', ') FROM authz.check_invariants() WHERE invariant LIKE 'never folder: owner and%'")
[ "$got" = "1 {3}" ] && echo "ok    ... and an invariant's condition reads the folder it is about: the marked folder breaks it" ||
  { echo "FAIL  an invariant whose subquery calls its table r: $got"; fails=$((fails + 1)); }
dropdb "$TDB"; rm -f /tmp/authz_governance_this.authz
dropdb "$DB"
if [ $fails -eq 0 ]; then echo "governance: all passed"; else echo "governance: $fails failed"; exit 1; fi
