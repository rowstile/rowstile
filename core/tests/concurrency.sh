#!/bin/bash
# concurrency.sh: two sessions changing the folder tree at the same time.
#   PGHOST=... PGPORT=... PGUSER=... tests/concurrency.sh [database]
# Each case resets the example app, races two psql sessions, then checks that
# the closure tables still match a rebuild and that no loop slipped through.
set -u
cd "$(dirname "$0")/.."
DB=${1:-authz_concurrency}
T=$(mktemp -d)
. tests/races.sh
# whatever way the suite ends: the sessions it left running, its databases and its files
cleanup() { stop_sessions; for d in "$DB" "${DB}_cross" "${DB}_two" "${DB}_self"; do dropdb --force --if-exists "$d" 2>/dev/null; done; rm -rf "$T"; }
trap cleanup EXIT
dropdb --if-exists "$DB" 2>/dev/null; createdb "$DB" || exit 1
fails=0
out=$T/out
python3 compile_policy.py example/docs.authz > "$T/docs.sql" || exit 1

reset() {
  psql -X -q -v ON_ERROR_STOP=1 -d "$DB" -f example/app_schema.sql >/dev/null 2>&1 &&
  psql -X -q -v ON_ERROR_STOP=1 -d "$DB" -f "$T/docs.sql" >/dev/null 2>&1 && race || { echo "setup failed"; exit 1; }
}
check() {   # $1 = label, $2 = SQL that must return t
  if [ "$(psql -X -Atq -d "$DB" -c "$2")" = "t" ]; then echo "ok    $1"; else echo "FAIL  $1"; fails=$((fails + 1)); fi
}
expect_in_a() {   # $1 = label, $2 = text session A must have printed
  if grep -q "$2" "$out"; then echo "ok    $1"; else echo "FAIL  $1 (session A said: $(tr '\n' ' ' < "$out"))"; fails=$((fails + 1)); fi
}

echo "-- 1. REPEATABLE READ: add a folder under a folder someone else just moved"
reset
PGAPPNAME=authz_conc_a psql -X -q -d "$DB" > "$out" 2>&1 <<SQL &
BEGIN ISOLATION LEVEL REPEATABLE READ;
SELECT count(*) FROM app.folders;   -- snapshot taken here
$HOLD;
INSERT INTO app.folders (id, org_id, parent_id, owner_id, name) VALUES (60, 1, 4, 1, 'under Design');
COMMIT;
SQL
held authz_conc_a
psql -X -q -d "$DB" -c "UPDATE app.folders SET parent_id = 20 WHERE id = 4"   # Design into Globex
go; wait
expect_in_a "the late writer gets a serialization error (the app retries)" "could not serialize access"
check "inheritance tables match a rebuild" "SELECT authz.verify()"
check "no stale folder 60" "SELECT NOT EXISTS (SELECT 1 FROM app.folders WHERE id = 60)"

echo "-- 2. REPEATABLE READ: two moves that together would make a loop"
reset
PGAPPNAME=authz_conc_a psql -X -q -d "$DB" > "$out" 2>&1 <<SQL &
BEGIN ISOLATION LEVEL REPEATABLE READ;
SELECT count(*) FROM app.folders;
$HOLD;
UPDATE app.folders SET parent_id = 2 WHERE id = 4;   -- Design into Handbook
COMMIT;
SQL
held authz_conc_a
psql -X -q -d "$DB" -c "UPDATE app.folders SET parent_id = 4 WHERE id = 2"   # Handbook into Design
go; wait
expect_in_a "the late writer gets a serialization error" "could not serialize access"
check "inheritance tables match a rebuild" "SELECT authz.verify()"
check "no loop" "SELECT NOT (EXISTS (SELECT 1 FROM app.folders WHERE id = 4 AND parent_id = 2)
                             AND EXISTS (SELECT 1 FROM app.folders WHERE id = 2 AND parent_id = 4))"

echo "-- 3. READ COMMITTED: the same two moves"
reset
PGAPPNAME=authz_conc_a psql -X -q -d "$DB" > "$out" 2>&1 <<SQL &
BEGIN;
UPDATE app.folders SET parent_id = 2 WHERE id = 4;
$HOLD;
COMMIT;
SQL
held authz_conc_a
PGAPPNAME=authz_conc_b psql -X -q -d "$DB" -c "UPDATE app.folders SET parent_id = 4 WHERE id = 2" > "$out.b" 2>&1 &
blocked authz_conc_b
go; wait
if grep -q "cannot be moved inside itself" "$out.b"; then echo "ok    the second move waits, then is refused"; else echo "FAIL  second move: $(cat "$out.b")"; fails=$((fails + 1)); fi
check "inheritance tables match a rebuild" "SELECT authz.verify()"

echo "-- 4. READ COMMITTED: unrelated moves at the same time both succeed"
reset
PGAPPNAME=authz_conc_a psql -X -q -d "$DB" > "$out" 2>&1 <<SQL &
BEGIN;
UPDATE app.folders SET parent_id = 2 WHERE id = 4;
$HOLD;
COMMIT;
SQL
held authz_conc_a
PGAPPNAME=authz_conc_b psql -X -q -d "$DB" -c "UPDATE app.folders SET parent_id = 20 WHERE id = 6" > "$out.b" 2>&1 &
blocked authz_conc_b
go; wait
check "both moves are in" "SELECT (SELECT parent_id FROM app.folders WHERE id = 4) = 2 AND (SELECT parent_id FROM app.folders WHERE id = 6) = 20"
check "inheritance tables match a rebuild" "SELECT authz.verify()"

echo "-- 5. sharing a file while someone deletes it"
reset
psql -X -q -d "$DB" -c "INSERT INTO app.files (id, folder_id, owner_id, name) VALUES (40, 4, 1, 'doomed.md')"
PGAPPNAME=authz_conc_a psql -X -q -d "$DB" > "$out" 2>&1 <<SQL &
BEGIN;
DELETE FROM app.files WHERE id = 40;
$HOLD;
COMMIT;
SQL
held authz_conc_a
PGAPPNAME=authz_conc_b psql -X -q -d "$DB" -c "SET ROLE app_user; SET authz.user_id = 1; SELECT authz.share('file', 40, 'viewer', 'user', 4)" > "$out.b" 2>&1 &
blocked authz_conc_b
go; wait
if grep -q "you cannot share file 40" "$out.b"; then echo "ok    the share waits for the delete, then is refused"; else echo "FAIL  share: $(cat "$out.b")"; fails=$((fails + 1)); fi
check "no share is left on the deleted id" "SELECT NOT EXISTS (SELECT 1 FROM authz.shares WHERE object_type = 'file' AND object_id = '40')"

# A transaction at level $1 takes its snapshot, then waits while another session runs $3 (and commits), then
# runs $2 and commits. Its snapshot can't see the other's share: it must fail to serialize (and change nothing), never
# commit and leave the share on a row that is gone. $4: what the check is called.
stale() {
  PGAPPNAME=authz_conc_a psql -X -q -d "$DB" > "$out" 2>&1 <<SQL &
BEGIN ISOLATION LEVEL $1;
SELECT count(*) FROM app.orgs;
$HOLD;
$2;
COMMIT;
SQL
  held authz_conc_a
  psql -X -q -v ON_ERROR_STOP=1 -d "$DB" -c "SET ROLE app_user" -c "SET authz.user_id = 1" -c "$3" > "$out.b" 2>&1 \
    || { echo "FAIL  $4: the share: $(tr '\n' ' ' < "$out.b")"; fails=$((fails + 1)); }
  go; wait
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
PGAPPNAME=authz_conc_a psql -X -q -d "$DB" > "$out" 2>&1 <<SQL &
BEGIN;
DELETE FROM app.folders WHERE id = 40;
$HOLD;
COMMIT;
SQL
held authz_conc_a
PGAPPNAME=authz_conc_b psql -X -q -d "$DB" -c "SET ROLE app_user" -c "SET authz.user_id = 3" \
  -c "SELECT authz.break_glass('folder', 40, 'viewer', 'an outage')" > "$out.b" 2>&1 &
blocked authz_conc_b
go; wait
if grep -q "you cannot break the glass on folder 40" "$out.b"; then echo "ok    breaking the glass waits for the delete, then is refused"; else echo "FAIL  break_glass: $(tr '\n' ' ' < "$out.b")"; fails=$((fails + 1)); fi
check "no share is left on the deleted folder" "SELECT NOT EXISTS (SELECT 1 FROM authz.shares WHERE object_type = 'folder' AND object_id = '40')"

echo "-- 11. REPEATABLE READ: a folder renamed while another is moved"
# a write that changes nothing the tree follows takes no tree lock: the older snapshot is no reason to fail
reset
PGAPPNAME=authz_conc_a psql -X -q -d "$DB" > "$out" 2>&1 <<SQL &
BEGIN ISOLATION LEVEL REPEATABLE READ;
SELECT count(*) FROM app.folders;   -- snapshot taken here
$HOLD;
UPDATE app.folders SET name = 'Design 2' WHERE id = 4;
COMMIT;
SQL
held authz_conc_a
psql -X -q -d "$DB" -c "UPDATE app.folders SET parent_id = 20 WHERE id = 6"
go; wait
check "the rename commits beside the move, with no serialization error" \
  "SELECT (SELECT name FROM app.folders WHERE id = 4) = 'Design 2' AND (SELECT parent_id FROM app.folders WHERE id = 6) = 20"
check "inheritance tables match a rebuild" "SELECT authz.verify()"

echo "-- a write to one tree doesn't wait for a write to another's (each takes its own types' lock)"
X="${DB}_cross"
dropdb --if-exists "$X" 2>/dev/null; createdb "$X" || exit 1
python3 compile_policy.py tests/cross.authz > "$T/cross.sql" &&
  PGOPTIONS="-c client_min_messages=error" psql -X -q -v ON_ERROR_STOP=1 -d "$X" -f tests/cross_schema.sql >/dev/null &&
  PGOPTIONS="-c client_min_messages=error" psql -X -q -v ON_ERROR_STOP=1 -d "$X" -f "$T/cross.sql" >/dev/null &&
  psql -X -q -v ON_ERROR_STOP=1 -d "$X" -c "INSERT INTO cx.users VALUES (1, 'a')" -c "INSERT INTO cx.regions (id, chief_id) VALUES (1, 1), (2, 1)" \
    -c "INSERT INTO cx.folders (id, owner_id) VALUES (1, 1), (2, 1)" >/dev/null || { echo "setup failed (cross)"; exit 1; }
# session A links region 2 under region 1 and holds its transaction open; B moves a folder meanwhile
RACE_DB=$X race
PGAPPNAME=authz_conc_a psql -X -q -d "$X" -c "BEGIN" -c "INSERT INTO cx.region_links VALUES (2, 1)" -c "$HOLD" -c "COMMIT" > "$out" 2>&1 &
RACE_DB=$X held authz_conc_a
got=$(psql -X -q -At -d "$X" -c "SET lock_timeout = '1s'" -c "UPDATE cx.folders SET parent_type = 'folder', parent_id = 1 WHERE id = 2" 2>&1)
RACE_DB=$X go; wait
if [ -z "$got" ]; then echo "ok    a folder moved while a region's link is written, without waiting"
else echo "FAIL  a folder moved while a region's link is written: $got"; fails=$((fails + 1)); fi
[ "$(psql -X -Atq -d "$X" -c "SELECT authz.verify()")" = t ] && echo "ok    ... and both trees match a rebuild" ||
  { echo "FAIL  the trees after the two writes"; fails=$((fails + 1)); }
# the folders' conditions read another table (cx.frozen), not cx.folders: a write to a folder that changes nothing
# the tree follows checks them again on no row, so it takes no lock of the tree
RACE_DB=$X race
PGAPPNAME=authz_conc_a psql -X -q -d "$X" -c "BEGIN" -c "UPDATE cx.folders SET parent_type = NULL, parent_id = NULL WHERE id = 2" -c "$HOLD" \
  -c "COMMIT" > "$out" 2>&1 &
RACE_DB=$X held authz_conc_a
got=$(psql -X -q -At -d "$X" -c "SET lock_timeout = '1s'" -c "UPDATE cx.folders SET owner_id = NULL WHERE id = 1" 2>&1)
RACE_DB=$X go; wait
if [ -z "$got" ]; then echo "ok    a folder given another owner while a folder's move is held open, without waiting"
else echo "FAIL  a folder given another owner while a folder's move is held open: $got"; fails=$((fails + 1)); fi
# a placement moved to another folder: one refresh of its old and new folders' contents, so one entry in the feed
# for each of the two trees the placements are links of
psql -X -q -v ON_ERROR_STOP=1 -d "$X" -c "INSERT INTO cx.projects (id, lead_id) VALUES (1, 1)" \
  -c "INSERT INTO cx.placements VALUES (1, 1)" >/dev/null
pos=$(psql -X -Atq -d "$X" -c "SELECT max(pos) FROM authz.changes")
psql -X -q -v ON_ERROR_STOP=1 -d "$X" -c "UPDATE cx.placements SET folder_id = 2 WHERE project_id = 1"
got=$(psql -X -Atq -d "$X" -c "SELECT string_agg(object_type || ' ' || array_to_string(object_ids, ','), '; ' ORDER BY pos)
                                FROM authz.changes WHERE pos > $pos AND cause = 'inheritance'")
[ "$got" = "project 1; project 1" ] && echo "ok    a placement moved to another folder: one feed entry for each tree" ||
  { echo "FAIL  a placement moved to another folder, the feed's entries: $got"; fails=$((fails + 1)); }
dropdb "$X"; rm -f "$T/cross.sql"

echo "-- a statement that changes no row of a tree of several types takes no lock of it"
# folders in folders or in projects, projects in folders: one tree of two types, and no other tree on them. A
# project updated by a statement that matches none doesn't wait for a folder's move held open
X="${DB}_two"
dropdb --if-exists "$X" 2>/dev/null; createdb "$X" || exit 1
cat > "$T/two.authz" <<'POLICY'
app role app_user
type user = ms.users
type project = ms.projects
  parent : folder = folder_id
  owner  : user   = owner_id
  can view = owner or parent.view
type folder = ms.folders
  parent : folder, project = (parent_type, parent_id)
  owner  : user = owner_id
  can view = owner or parent.view
rules ms.folders
  select : view
POLICY
python3 compile_policy.py "$T/two.authz" > "$T/two.sql" &&
  PGOPTIONS="-c client_min_messages=error" psql -X -q -v ON_ERROR_STOP=1 -d "$X" -c "CREATE SCHEMA ms" \
    -c "CREATE TABLE ms.users (id bigint PRIMARY KEY)" \
    -c "CREATE TABLE ms.folders (id bigint PRIMARY KEY, parent_type text, parent_id bigint, owner_id bigint)" \
    -c "CREATE TABLE ms.projects (id bigint PRIMARY KEY, folder_id bigint, owner_id bigint)" \
    -c "INSERT INTO ms.users VALUES (1)" -c "INSERT INTO ms.folders (id, owner_id) VALUES (1, 1), (2, 1)" \
    -c "INSERT INTO ms.projects VALUES (1, NULL, 1)" -f "$T/two.sql" >/dev/null || { echo "setup failed (two)"; exit 1; }
RACE_DB=$X race
PGAPPNAME=authz_conc_a psql -X -q -d "$X" -c "BEGIN" -c "UPDATE ms.folders SET parent_type = 'folder', parent_id = 1 WHERE id = 2" -c "$HOLD" \
  -c "COMMIT" > "$out" 2>&1 &
RACE_DB=$X held authz_conc_a
got=$(psql -X -q -At -d "$X" -c "SET lock_timeout = '1s'" -c "UPDATE ms.projects SET owner_id = owner_id WHERE id = 99" 2>&1)
RACE_DB=$X go; wait
if [ -z "$got" ]; then echo "ok    a project update that changes none doesn't wait for a folder's move"
else echo "FAIL  a project update that changes none, while a folder is moved: $got"; fails=$((fails + 1)); fi
dropdb "$X"; rm -f "$T/two.authz" "$T/two.sql"

echo "-- conditions that read their tree's own table: checked again after a statement there that writes a row"
# a folder inherits from the folder above unless that one is sealed; a shelf from its box unless the box is sealed,
# and boxes sit in boxes or on shelves (a tree of two types, whose condition reads the other type's table)
X="${DB}_self"
dropdb --if-exists "$X" 2>/dev/null; createdb "$X" || exit 1
cat > "$T/self.authz" <<'POLICY'
app role app_user
type user = sr.users
type folder = sr.folders
  parent : folder = parent_id
  owner  : user   = owner_id
  can view = owner or (parent.view and {not exists (select 1 from sr.folders p where p.id = this.parent_id and p.sealed)})
type shelf = sr.shelves
  box : box = box_id
  can view = box.view and {not exists (select 1 from sr.boxes b where b.id = this.box_id and b.sealed)}
type box = sr.boxes
  parent : box, shelf = (parent_type, parent_id)
  owner  : user = owner_id
  can view = owner or parent.view
POLICY
python3 compile_policy.py "$T/self.authz" > "$T/self.sql" &&
  PGOPTIONS="-c client_min_messages=error" psql -X -q -v ON_ERROR_STOP=1 -d "$X" -c "CREATE SCHEMA sr" \
    -c "CREATE TABLE sr.users (id bigint PRIMARY KEY)" \
    -c "CREATE TABLE sr.folders (id bigint PRIMARY KEY, parent_id bigint, owner_id bigint, sealed boolean NOT NULL DEFAULT false)" \
    -c "CREATE TABLE sr.boxes (id bigint PRIMARY KEY, parent_type text, parent_id bigint, owner_id bigint,
                               sealed boolean NOT NULL DEFAULT false)" \
    -c "CREATE TABLE sr.shelves (id bigint PRIMARY KEY, box_id bigint)" -c "INSERT INTO sr.users VALUES (1)" \
    -c "INSERT INTO sr.folders (id, parent_id, owner_id) VALUES (1, NULL, 1), (2, 1, NULL), (3, 2, NULL), (4, NULL, 1)" \
    -c "INSERT INTO sr.boxes (id, owner_id) VALUES (1, 1), (3, 1)" -c "INSERT INTO sr.shelves VALUES (1, 1)" \
    -c "INSERT INTO sr.boxes (id, parent_type, parent_id) VALUES (2, 'shelf', 1)" \
    -f "$T/self.sql" >/dev/null || { echo "setup failed (self)"; exit 1; }
F='authz_int."folder__parent__tree"'
B='authz_int."box_shelf__box_parent__tree"'
inx() {   # $1 = label, $2 = SQL that must return t, in the database $X
  if [ "$(psql -X -Atq -d "$X" -c "$2")" = "t" ]; then echo "ok    $1"; else echo "FAIL  $1"; fails=$((fails + 1)); fi
}
inx "below folder 1 and box 1, what inherits from them" \
  "SELECT (SELECT array_agg(descendant ORDER BY descendant) FROM $F WHERE ancestor = 1) = '{1,2,3}'
      AND (SELECT array_agg(dtype || ' ' || did ORDER BY dtype, did) FROM $B WHERE atype = 'box' AND aid = '1')
          = '{\"box 1\",\"box 2\",\"shelf 1\"}'"
psql -X -q -v ON_ERROR_STOP=1 -d "$X" -c "UPDATE sr.folders SET sealed = true WHERE id = 1" -c "UPDATE sr.boxes SET sealed = true WHERE id = 1"
inx "a folder sealed: the folders below it inherit from it no longer" \
  "SELECT (SELECT array_agg(descendant ORDER BY descendant) FROM $F WHERE ancestor = 1) = '{1}' AND authz.verify()"
inx "a box sealed: the shelf in it, and the box on that, inherit from it no longer (a tree of two types)" \
  "SELECT (SELECT array_agg(dtype || ' ' || did ORDER BY dtype, did) FROM $B WHERE atype = 'box' AND aid = '1') = '{\"box 1\"}'"
# a statement that writes no row checks nothing again: it doesn't wait for a move held open
RACE_DB=$X race
PGAPPNAME=authz_conc_a psql -X -q -d "$X" -c "BEGIN" -c "UPDATE sr.folders SET parent_id = 1 WHERE id = 4" \
  -c "UPDATE sr.boxes SET parent_type = 'box', parent_id = 1 WHERE id = 3" -c "$HOLD" -c "COMMIT" > "$out" 2>&1 &
RACE_DB=$X held authz_conc_a
got=$(psql -X -q -At -d "$X" -c "SET lock_timeout = '1s'" -c "UPDATE sr.folders SET sealed = false WHERE id = 99" 2>&1)
got2=$(psql -X -q -At -d "$X" -c "SET lock_timeout = '1s'" -c "UPDATE sr.boxes SET sealed = false WHERE id = 99" 2>&1)
RACE_DB=$X go; wait
if [ -z "$got" ]; then echo "ok    a folder update that writes none doesn't wait for a folder's move"
else echo "FAIL  a folder update that writes none, while a folder is moved: $got"; fails=$((fails + 1)); fi
if [ -z "$got2" ]; then echo "ok    a box update that writes none doesn't wait for a box's move"
else echo "FAIL  a box update that writes none, while a box is moved: $got2"; fails=$((fails + 1)); fi
dropdb "$X"; rm -f "$T/self.authz" "$T/self.sql"

rm -f "$out" "$out.b"
dropdb "$DB"
if [ $fails -eq 0 ]; then echo "concurrency: all passed"; else echo "concurrency: $fails failed"; exit 1; fi
