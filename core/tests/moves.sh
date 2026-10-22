#!/bin/bash
# moves.sh: moves and links of folders with many below them. Such changes shift the stored inheritance
# rows (trees.py, _shift) instead of recomputing everything below; this checks that the shift is taken
# (rows inside the moved part are left alone), that it falls back when a link loops back into the moved
# part, and that the inheritance tables match a rebuild after every change.
#   PGHOST=... PGPORT=... PGUSER=... tests/moves.sh [database]
set -u
cd "$(dirname "$0")/.."
DB=${1:-authz_moves}
L=${DB}_loop
W=$(mktemp -d)
# whatever way the suite ends: its databases, its files
cleanup() { for d in "$DB" "$L"; do dropdb --force --if-exists "$d" 2>/dev/null; done; rm -rf "$W"; }
trap cleanup EXIT
dropdb --if-exists "$DB" 2>/dev/null; createdb "$DB" || exit 1
fails=0
PSQL() { PGOPTIONS="-c client_min_messages=warning" psql -X -q -At -v ON_ERROR_STOP=1 -d "$DB" "$@"; }
check() {   # $1 = label, $2 = SQL that must return t
  if [ "$(PSQL -c "$2")" = "t" ]; then echo "ok    $1"; else echo "FAIL  $1"; fails=$((fails + 1)); fi
}
T='authz_int."folder__linked_into_parent__tree"'
# the rows between two folders both below $1, with the transaction that wrote each
snapshot() { PSQL -c "DROP TABLE IF EXISTS kept" -c "CREATE TABLE kept (d bigint, a bigint, x xid)" \
                  -c "INSERT INTO kept SELECT t.descendant, t.ancestor, t.xmin FROM $T t
                      WHERE t.descendant IN (SELECT descendant FROM $T WHERE ancestor = $1)
                        AND t.ancestor IN (SELECT descendant FROM $T WHERE ancestor = $1)"; }
# ...none of which a change since has rewritten
untouched() { echo "SELECT count(*) > 100 AND count(*) = count(*) FILTER (WHERE t.xmin = k.x)
                    FROM kept k JOIN $T t ON t.descendant = k.d AND t.ancestor = k.a"; }

python3 compile_policy.py example/docs.authz > "$W/docs.sql" || exit 1
PSQL -f example/app_schema.sql >/dev/null 2>&1 && PSQL -f "$W/docs.sql" >/dev/null 2>&1 || { echo "setup failed"; exit 1; }
# five levels below each of two roots (1000 and 2000), 4 children each; links point nearer the top
PSQL >/dev/null <<'SQL' || { echo "load failed"; exit 1; }
SET client_min_messages = warning;
INSERT INTO app.folders (id, org_id, parent_id, owner_id, name) VALUES (1000, 1, NULL, 5, 'root A'), (2000, 1, NULL, 5, 'root B');
DO $$
DECLARE lvl int; n bigint := 3000;
BEGIN
  CREATE TEMP TABLE lv (id bigint, level int);
  INSERT INTO lv VALUES (1000, 0), (2000, 0);
  FOR lvl IN 1..5 LOOP
    INSERT INTO app.folders (id, org_id, parent_id, owner_id, name, inherit)
    SELECT n + row_number() OVER (), 1, p.id, 1 + (p.id % 7), 'f', (p.id % 23) <> 0
    FROM lv p, generate_series(1, 4) WHERE p.level = lvl - 1;
    INSERT INTO lv SELECT id, lvl FROM app.folders WHERE id > n;
    n := (SELECT max(id) FROM app.folders);
  END LOOP;
  -- a folder in five hundred is also shown in a folder at a shallower level
  INSERT INTO app.folder_links
  SELECT f.id, (SELECT p.id FROM lv p WHERE p.level < f.level ORDER BY hashint8(f.id * 31 + p.id) LIMIT 1)
  FROM lv f WHERE f.level >= 2 AND f.id % 50 = 0;
END $$;
SQL
check "loaded: inheritance tables match a rebuild" "SELECT authz.verify()"
big=$(PSQL -c "SELECT id FROM app.folders WHERE parent_id = 1000 ORDER BY id LIMIT 1")
other=$(PSQL -c "SELECT id FROM app.folders WHERE parent_id = 1000 ORDER BY id DESC LIMIT 1")
echo "-- folder $big has $(PSQL -c "SELECT count(*) - 1 FROM $T WHERE ancestor = $big") below it"

echo "-- 1. a big move into the other root shifts rows instead of recomputing them"
snapshot "$big"
PSQL -c "UPDATE app.folders SET parent_id = 2000 WHERE id = $big"
check "rows inside the moved folder were left alone" "$(untouched)"
check "inheritance tables match a rebuild" "SELECT authz.verify()"
check "the moved folder's contents now sit under root B" \
  "SELECT count(*) = (SELECT count(*) FROM $T WHERE ancestor = $big) FROM $T WHERE ancestor = 2000 AND descendant IN (SELECT descendant FROM $T WHERE ancestor = $big)"
check "... and not under root A (no link leads there)" \
  "SELECT NOT EXISTS (SELECT 1 FROM $T WHERE ancestor = 1000 AND descendant = $big)"

echo "-- 2. moving it back, to the top, stopping inheritance, linking and unlinking it"
for sql in "UPDATE app.folders SET parent_id = 1000 WHERE id = $big" \
           "UPDATE app.folders SET parent_id = NULL WHERE id = $big" \
           "UPDATE app.folders SET parent_id = 2000 WHERE id = $big" \
           "UPDATE app.folders SET inherit = false WHERE id = $big" \
           "UPDATE app.folders SET inherit = true WHERE id = $big" \
           "INSERT INTO app.folder_links VALUES ($big, 1000)" \
           "UPDATE app.folder_links SET parent_id = $other WHERE folder_id = $big" \
           "DELETE FROM app.folder_links WHERE folder_id = $big"; do
  snapshot "$big"
  PSQL -c "$sql"
  check "$sql: inside left alone, tables match a rebuild" "SELECT ($(untouched)) AND authz.verify()"
done

echo "-- 3. changes the shift can't take recompute, and stay exact"
deep=$(PSQL -c "SELECT descendant FROM $T WHERE ancestor = $big AND descendant <> $big ORDER BY descendant DESC LIMIT 1")
mid=$(PSQL -c "SELECT id FROM app.folders WHERE parent_id = $big ORDER BY id LIMIT 1")
for sql in "INSERT INTO app.folder_links VALUES (2000, $deep)" \
           "UPDATE app.folders SET parent_id = 1000 WHERE id = $big" \
           "UPDATE app.folders SET parent_id = CASE id WHEN $big THEN 2000 ELSE 1000 END WHERE id IN ($big, $mid)" \
           "UPDATE app.folders SET parent_id = $deep WHERE id = $mid" \
           "DELETE FROM app.folder_links WHERE folder_id = 2000" \
           "UPDATE app.folders SET id = 99999 WHERE id = $mid" \
           "UPDATE app.folders SET parent_id = 1000 WHERE parent_id = 2000"; do
  PSQL -c "$sql" 2>&1 | grep -v "cannot be moved inside itself"
  check "$sql: tables match a rebuild" "SELECT authz.verify()"
done

echo "-- 4. several links in one statement"
PSQL -c "INSERT INTO app.folder_links SELECT id, 2000 FROM app.folders WHERE parent_id = 1000 ON CONFLICT DO NOTHING"
check "several links at once: tables match a rebuild" "SELECT authz.verify()"
PSQL -c "UPDATE app.folder_links SET parent_id = 1000 WHERE parent_id = 2000"
check "several links moved at once: tables match a rebuild" "SELECT authz.verify()"

echo "-- 5. a loop round four tables' keys (tests/loop.authz: a tree whose name is too long, shortened to a hash)"
dropdb --if-exists "$L" 2>/dev/null; createdb "$L" || exit 1
python3 compile_policy.py tests/loop.authz > "$W/loop.sql" || exit 1
PGOPTIONS="-c client_min_messages=warning" psql -X -q -At -v ON_ERROR_STOP=1 -d "$L" -f tests/loop_schema.sql -f "$W/loop.sql" \
  -c "INSERT INTO lp.users VALUES (1, 'u')" -c "INSERT INTO lp.orgs (id, owner_id) VALUES (1, 1)" \
  -c "INSERT INTO lp.settings (id) VALUES (1)" -c "INSERT INTO lp.emails (id) VALUES (1)" \
  -c "INSERT INTO lp.domains (id, org_id) VALUES (1, 1)" -c "UPDATE lp.emails SET domain_id = 1" \
  -c "UPDATE lp.settings SET email_id = 1" >/dev/null || { echo "FAIL  the loop's setup"; fails=$((fails + 1)); }
# the org's settings would name an address whose domain is the org's own
got=$(psql -X -q -At -d "$L" -v VERBOSITY=verbose -c "UPDATE lp.orgs SET settings_id = 1 WHERE id = 1" 2>&1 | grep '^ERROR:  \|^HINT:  ')
[ "$got" = "$(printf 'ERROR:  23514: org 1 cannot be moved inside itself\nHINT:  rowstile help AZ713')" ] &&
  [ "$(psql -X -q -At -d "$L" -c "SELECT settings_id IS NULL AND authz.verify() FROM lp.orgs")" = t ] &&
  echo "ok    the write that would close the loop is refused, by its words, and the tables match a rebuild" ||
  { echo "FAIL  a loop round four tables: $got"; fails=$((fails + 1)); }
[ $fails -eq 0 ] && echo "all move checks passed" || { echo "$fails move checks failed"; exit 1; }
