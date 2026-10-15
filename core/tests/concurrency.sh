#!/bin/bash
# concurrency.sh: two sessions changing the folder tree at the same time.
#   PGHOST=... PGPORT=... PGUSER=... tests/concurrency.sh [database]
# Each case resets the example app, races two psql sessions, then checks that
# the closure tables still match a rebuild and that no loop slipped through.
set -u
cd "$(dirname "$0")/.."
DB=${1:-authz_concurrency}
dropdb --if-exists "$DB" 2>/dev/null; createdb "$DB" || exit 1
fails=0
out=$(mktemp)
python3 compile_policy.py example/docs.authz > "/tmp/${DB}_docs.sql" || exit 1

reset() {
  psql -X -q -v ON_ERROR_STOP=1 -d "$DB" -f example/app_schema.sql >/dev/null 2>&1 &&
  psql -X -q -v ON_ERROR_STOP=1 -d "$DB" -f "/tmp/${DB}_docs.sql" >/dev/null 2>&1 || { echo "setup failed"; exit 1; }
}
check() {   # $1 = label, $2 = SQL that must return t
  if [ "$(psql -X -Atq -d "$DB" -c "$2")" = "t" ]; then echo "ok    $1"; else echo "FAIL  $1"; fails=$((fails + 1)); fi
}
expect_in_a() {   # $1 = label, $2 = text session A must have printed
  if grep -q "$2" "$out"; then echo "ok    $1"; else echo "FAIL  $1 (session A said: $(tr '\n' ' ' < "$out"))"; fails=$((fails + 1)); fi
}

echo "-- 1. REPEATABLE READ: add a folder under a folder someone else just moved"
reset
psql -X -q -d "$DB" > "$out" 2>&1 <<'SQL' &
BEGIN ISOLATION LEVEL REPEATABLE READ;
SELECT count(*) FROM app.folders;   -- snapshot taken here
SELECT pg_sleep(1.5);
INSERT INTO app.folders (id, org_id, parent_id, owner_id, name) VALUES (60, 1, 4, 1, 'under Design');
COMMIT;
SQL
sleep 0.5
psql -X -q -d "$DB" -c "UPDATE app.folders SET parent_id = 20 WHERE id = 4"   # Design into Globex
wait
expect_in_a "the late writer gets a serialization error (the app retries)" "could not serialize access"
check "inheritance tables match a rebuild" "SELECT authz.verify()"
check "no stale folder 60" "SELECT NOT EXISTS (SELECT 1 FROM app.folders WHERE id = 60)"

echo "-- 2. REPEATABLE READ: two moves that together would make a loop"
reset
psql -X -q -d "$DB" > "$out" 2>&1 <<'SQL' &
BEGIN ISOLATION LEVEL REPEATABLE READ;
SELECT count(*) FROM app.folders;
SELECT pg_sleep(1.5);
UPDATE app.folders SET parent_id = 2 WHERE id = 4;   -- Design into Handbook
COMMIT;
SQL
sleep 0.5
psql -X -q -d "$DB" -c "UPDATE app.folders SET parent_id = 4 WHERE id = 2"   # Handbook into Design
wait
expect_in_a "the late writer gets a serialization error" "could not serialize access"
check "inheritance tables match a rebuild" "SELECT authz.verify()"
check "no loop" "SELECT NOT (EXISTS (SELECT 1 FROM app.folders WHERE id = 4 AND parent_id = 2)
                             AND EXISTS (SELECT 1 FROM app.folders WHERE id = 2 AND parent_id = 4))"

echo "-- 3. READ COMMITTED: the same two moves"
reset
psql -X -q -d "$DB" > "$out" 2>&1 <<'SQL' &
BEGIN;
UPDATE app.folders SET parent_id = 2 WHERE id = 4;
SELECT pg_sleep(1.5);
COMMIT;
SQL
sleep 0.5
psql -X -q -d "$DB" -c "UPDATE app.folders SET parent_id = 4 WHERE id = 2" > "$out.b" 2>&1
wait
if grep -q "cannot be moved inside itself" "$out.b"; then echo "ok    the second move waits, then is refused"; else echo "FAIL  second move: $(cat "$out.b")"; fails=$((fails + 1)); fi
check "inheritance tables match a rebuild" "SELECT authz.verify()"

echo "-- 4. READ COMMITTED: unrelated moves at the same time both succeed"
reset
psql -X -q -d "$DB" > "$out" 2>&1 <<'SQL' &
BEGIN;
UPDATE app.folders SET parent_id = 2 WHERE id = 4;
SELECT pg_sleep(1);
COMMIT;
SQL
sleep 0.3
psql -X -q -d "$DB" -c "UPDATE app.folders SET parent_id = 20 WHERE id = 6" > "$out.b" 2>&1
wait
check "both moves are in" "SELECT (SELECT parent_id FROM app.folders WHERE id = 4) = 2 AND (SELECT parent_id FROM app.folders WHERE id = 6) = 20"
check "inheritance tables match a rebuild" "SELECT authz.verify()"

echo "-- 5. sharing a file while someone deletes it"
reset
psql -X -q -d "$DB" -c "INSERT INTO app.files (id, folder_id, owner_id, name) VALUES (40, 4, 1, 'doomed.md')"
psql -X -q -d "$DB" > "$out" 2>&1 <<'SQL' &
BEGIN;
DELETE FROM app.files WHERE id = 40;
SELECT pg_sleep(1.5);
COMMIT;
SQL
sleep 0.5
psql -X -q -d "$DB" -c "SET ROLE app_user; SET authz.user_id = 1; SELECT authz.share('file', 40, 'viewer', 'user', 4)" > "$out.b" 2>&1
wait
if grep -q "you cannot share file 40" "$out.b"; then echo "ok    the share waits for the delete, then is refused"; else echo "FAIL  share: $(cat "$out.b")"; fails=$((fails + 1)); fi
check "no share is left on the deleted id" "SELECT NOT EXISTS (SELECT 1 FROM authz.shares WHERE object_type = 'file' AND object_id = '40')"

# A transaction at level $1 takes its snapshot, then waits while another session runs $3 (and commits), then
# runs $2 and commits. Its snapshot can't see the other's share: it must fail to serialize (and change nothing), never
# commit and leave the share on a row that is gone. $4: what the check is called.
stale() {
  psql -X -q -d "$DB" > "$out" 2>&1 <<SQL &
BEGIN ISOLATION LEVEL $1;
SELECT count(*) FROM app.orgs;
SELECT pg_sleep(1.5);
$2;
COMMIT;
SQL
  sleep 0.5
  psql -X -q -v ON_ERROR_STOP=1 -d "$DB" -c "SET ROLE app_user" -c "SET authz.user_id = 1" -c "$3" > "$out.b" 2>&1 \
    || { echo "FAIL  $4: the share: $(tr '\n' ' ' < "$out.b")"; fails=$((fails + 1)); }
  wait
  expect_in_a "$4: the writer with the older snapshot gets a serialization error" "could not serialize access due to concurrent update"
  check "$4: no share is left on a row that is gone" "SELECT NOT EXISTS (SELECT 1 FROM authz.shares g
    WHERE (g.object_type = 'file' AND NOT EXISTS (SELECT 1 FROM app.files x WHERE x.id::text = g.object_id))
       OR (g.subject_type = 'user' AND NOT EXISTS (SELECT 1 FROM app.users x WHERE x.id::text = g.subject_id)))"
}

echo "-- 6. REPEATABLE READ: a file deleted while it is shared"
reset
psql -X -q -d "$DB" -c "INSERT INTO app.files (id, folder_id, owner_id, name) VALUES (40, 4, 1, 'doomed.md')"
stale "REPEATABLE READ" "DELETE FROM app.files WHERE id = 40" "SELECT authz.share('file', 40, 'viewer', 'user', 4)" \
  "a delete with an older snapshot"
check "the file and its share are both still there" "SELECT EXISTS (SELECT 1 FROM app.files WHERE id = 40)
  AND EXISTS (SELECT 1 FROM authz.shares WHERE object_type = 'file' AND object_id = '40' AND subject_id = '4')"

echo "-- 7. REPEATABLE READ: a file given a new id while it is shared"
reset
psql -X -q -d "$DB" -c "INSERT INTO app.files (id, folder_id, owner_id, name) VALUES (40, 4, 1, 'doomed.md')"
stale "REPEATABLE READ" "UPDATE app.files SET id = 41 WHERE id = 40" "SELECT authz.share('file', 40, 'viewer', 'user', 4)" \
  "a new id with an older snapshot"

echo "-- 8. SERIALIZABLE: a user deleted while a file is shared with them, by a session in READ COMMITTED"
reset
psql -X -q -d "$DB" -c "INSERT INTO app.users VALUES (8, 'hal')"
stale "SERIALIZABLE" "DELETE FROM app.users WHERE id = 8" "SELECT authz.share('file', 11, 'viewer', 'user', 8)" \
  "the user deleted with an older snapshot"

echo "-- 9. REPEATABLE READ: the files emptied while one is shared"
reset
stale "REPEATABLE READ" "TRUNCATE app.files" "SELECT authz.share('file', 11, 'viewer', 'user', 4)" \
  "TRUNCATE with an older snapshot"

echo "-- 10. READ COMMITTED: breaking the glass on a folder while it is deleted"
reset
psql -X -q -d "$DB" -c "INSERT INTO app.folders (id, org_id, parent_id, owner_id, name) VALUES (40, 1, 4, 1, 'doomed')"
psql -X -q -d "$DB" > "$out" 2>&1 <<'SQL' &
BEGIN;
DELETE FROM app.folders WHERE id = 40;
SELECT pg_sleep(1.5);
COMMIT;
SQL
sleep 0.5
psql -X -q -d "$DB" -c "SET ROLE app_user" -c "SET authz.user_id = 3" \
  -c "SELECT authz.break_glass('folder', 40, 'viewer', 'an outage')" > "$out.b" 2>&1
wait
if grep -q "you cannot break the glass on folder 40" "$out.b"; then echo "ok    breaking the glass waits for the delete, then is refused"; else echo "FAIL  break_glass: $(tr '\n' ' ' < "$out.b")"; fails=$((fails + 1)); fi
check "no share is left on the deleted folder" "SELECT NOT EXISTS (SELECT 1 FROM authz.shares WHERE object_type = 'folder' AND object_id = '40')"

echo "-- 11. REPEATABLE READ: a folder renamed while another is moved"
# a write that changes nothing the tree follows takes no tree lock: the older snapshot is no reason to fail
reset
psql -X -q -d "$DB" > "$out" 2>&1 <<'SQL' &
BEGIN ISOLATION LEVEL REPEATABLE READ;
SELECT count(*) FROM app.folders;   -- snapshot taken here
SELECT pg_sleep(1.5);
UPDATE app.folders SET name = 'Design 2' WHERE id = 4;
COMMIT;
SQL
sleep 0.5
psql -X -q -d "$DB" -c "UPDATE app.folders SET parent_id = 20 WHERE id = 6"
wait
check "the rename commits beside the move, with no serialization error" \
  "SELECT (SELECT name FROM app.folders WHERE id = 4) = 'Design 2' AND (SELECT parent_id FROM app.folders WHERE id = 6) = 20"
check "inheritance tables match a rebuild" "SELECT authz.verify()"

rm -f "$out" "$out.b"
dropdb "$DB"
if [ $fails -eq 0 ]; then echo "concurrency: all passed"; else echo "concurrency: $fails failed"; exit 1; fi
